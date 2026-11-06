package inventory

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
	"github.com/thapr0digy/portwarden/internal/backend/bus"
	"github.com/thapr0digy/portwarden/internal/cloud"
)

// PublishFunc sends one backend event (bus.Publisher.Publish).
type PublishFunc func(ctx context.Context, subject, id string, msg proto.Message) error

// CloudLookup runs the level 3 look-up for hosts with a cloud identity: when a host's
// listeners or host block change (after Settle) and for every host each Refresh. A
// listener whose verdict changes (open ↔ not open, or the open evidence) gets an
// exposure.changed with origin "cloud"; the inventory folds it back in like any event.
// A failed look-up keeps the last verdicts (unknown is never closed) and records the
// error as the host's cloud_status.
type CloudLookup struct {
	State     CloudState
	Providers map[string]cloud.Provider
	Publish   PublishFunc
	RunID     string
	Refresh   time.Duration
	Settle    time.Duration
	Now       func() time.Time

	pending chan string
	// sent remembers the last verdict published per host/listener, so consumer lag (the
	// store not yet holding it) does not republish it.
	sent map[string]sentVerdict
}

type sentVerdict struct {
	open     bool
	evidence []string
}

// NewCloudLookup returns a look-up with GCP and Azure registered as unsupported unless
// providers holds their look-ups (cloud.gcp, cloud.azure enabled).
func NewCloudLookup(state CloudState, providers map[string]cloud.Provider, publish PublishFunc, runID string) *CloudLookup {
	all := map[string]cloud.Provider{"gcp": cloud.Unsupported{Name: "gcp"}, "azure": cloud.Unsupported{Name: "azure"}}
	for k, v := range providers {
		all[k] = v
	}
	return &CloudLookup{State: state, Providers: all, Publish: publish, RunID: runID,
		Refresh: 10 * time.Minute, Settle: 2 * time.Second, pending: make(chan string, 1024), sent: map[string]sentVerdict{}}
}

// Notify queues a host for a look-up; it never blocks (a full queue drops it: the next
// refresh covers the host).
func (l *CloudLookup) Notify(host string) {
	select {
	case l.pending <- host:
	default:
	}
}

// Run serves notifications and refreshes until ctx ends.
func (l *CloudLookup) Run(ctx context.Context) {
	refresh := time.NewTicker(l.Refresh)
	defer refresh.Stop()
	due := map[string]bool{}
	var settle <-chan time.Time
	l.sweep(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case h := <-l.pending:
			due[h] = true
			if settle == nil {
				settle = time.After(l.Settle)
			}
		case <-settle:
			settle = nil
			for h := range due {
				l.checkLogged(ctx, h)
			}
			clear(due)
		case <-refresh.C:
			l.sweep(ctx)
		}
	}
}

func (l *CloudLookup) sweep(ctx context.Context) {
	hosts, err := l.State.CloudHosts(ctx)
	if err != nil {
		slog.Warn("cloud look-up: listing hosts failed", "err", err)
		return
	}
	for _, h := range hosts {
		l.checkLogged(ctx, h)
	}
}

func (l *CloudLookup) checkLogged(ctx context.Context, host string) {
	if err := l.Check(ctx, host); err != nil && ctx.Err() == nil {
		slog.Warn("cloud look-up failed; keeping the last verdicts", "host", host, "err", err)
	}
}

// Check looks one host up now.
func (l *CloudLookup) Check(ctx context.Context, host string) error {
	h, ok, err := l.State.CloudHost(ctx, host)
	if err != nil || !ok || h.Cloud == "" {
		return err
	}
	now := l.now()
	prov, ok := l.Providers[h.Cloud]
	if !ok {
		prov = cloud.Unsupported{Name: h.Cloud}
	}
	var ports []cloud.Port
	var stale []CloudListener // cloud-open listeners no longer eligible
	for _, cl := range h.Listeners {
		if cl.AgentLevel >= cloud.LevelBound {
			ports = append(ports, cloud.Port{Key: cl.Key, Proto: cl.Proto, Addr: cl.Addr, Port: cl.Port, AgentLevel: cl.AgentLevel})
		} else if cl.CloudLevel >= cloud.LevelCloudOpen {
			stale = append(stale, cl)
		}
	}
	verdicts, err := prov.Evaluate(ctx, cloud.Host{ID: h.ID, Cloud: h.Cloud, InstanceID: h.InstanceID, Region: h.Region, Resource: h.Resource}, ports)
	if err != nil {
		status := "error: " + err.Error()
		if errors.Is(err, cloud.ErrUnsupported) {
			status = err.Error()
		}
		if serr := l.State.SetCloudStatus(ctx, host, status, now); serr != nil {
			return serr
		}
		if errors.Is(err, cloud.ErrUnsupported) {
			return nil
		}
		return err
	}
	byKey := map[string]CloudListener{}
	for _, cl := range h.Listeners {
		byKey[cl.Key] = cl
	}
	open, incomplete, undetermined := 0, 0, 0
	for _, v := range verdicts {
		cl := byKey[v.Key]
		if v.Open {
			open++
		}
		if !v.Complete {
			incomplete++
		}
		if !v.Open && slices.ContainsFunc(v.Evidence, func(e string) bool { return strings.HasPrefix(e, cloud.UndeterminedEvidence) }) {
			undetermined++
		}
		wasOpen, wasEvidence := cl.CloudLevel >= cloud.LevelCloudOpen, cl.CloudEvidence
		if s, ok := l.sent[host+"/"+v.Key]; ok {
			wasOpen, wasEvidence = s.open, s.evidence
		}
		if !v.Open && wasOpen && !v.Complete {
			continue // partial data may raise a verdict, never lower it
		}
		if v.Open == wasOpen && (!v.Open || slices.Equal(v.Evidence, wasEvidence)) {
			continue
		}
		if err := l.publish(ctx, host, cl, v.Open, v.Evidence, now); err != nil {
			return err
		}
	}
	for _, cl := range stale {
		if err := l.publish(ctx, host, cl, false, []string{"cloud: listener is no longer bound beyond loopback"}, now); err != nil {
			return err
		}
	}
	status := fmt.Sprintf("ok: %d listeners checked, %d open", len(verdicts), open)
	switch {
	case undetermined > 0:
		status = fmt.Sprintf("incomplete: %d listeners checked, %d open, %d undetermined (data not read in full or not decidable; nothing was raised or lowered by it)",
			len(verdicts), open, undetermined)
	case incomplete > 0:
		status = fmt.Sprintf("incomplete: %d listeners checked, %d open (data not read in full; nothing was lowered)", len(verdicts), open)
	}
	return l.State.SetCloudStatus(ctx, host, status, now)
}

func (l *CloudLookup) publish(ctx context.Context, host string, cl CloudListener, open bool, evidence []string, now time.Time) error {
	level := asmv1.ExposureLevel(cl.AgentLevel)
	if open {
		level = asmv1.ExposureLevel_EXPOSURE_CLOUD_OPEN
	}
	id := bus.NewEventID()
	ev := &asmv1.ExposureEvent{
		EventId: id, HostId: host, RunId: l.RunID, ObservedAt: timestamppb.New(now),
		Listener: &asmv1.Listener{Netns: cl.Netns, Proto: cl.Proto, Addr: cl.Addr, Port: uint32(cl.Port), Key: cl.Key},
		Exposure: &asmv1.Exposure{Level: level, Evidence: evidence},
		Previous: &asmv1.Exposure{Level: asmv1.ExposureLevel(max(cl.AgentLevel, cl.CloudLevel))},
		Trigger:  "cloud", Origin: "cloud",
	}
	slog.Info("cloud verdict changed", "host", host, "listener", cl.Key, "open", open, "evidence", evidence)
	if err := l.Publish(ctx, bus.CloudSubject(host), id, ev); err != nil {
		return err
	}
	l.sent[host+"/"+cl.Key] = sentVerdict{open: open, evidence: slices.Clone(evidence)}
	return nil
}

func (l *CloudLookup) now() time.Time {
	if l.Now != nil {
		return l.Now()
	}
	return time.Now()
}
