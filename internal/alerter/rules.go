// Package alerter turns exposure events and host silence into pages (design §1
// "Alerter", §6 "alert on anything newly reachable", "silence is a signal"). The rules
// are fixed code driven by a config file; delivery is a signed JSON webhook plus a log
// line per alert.
package alerter

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
	"github.com/thapr0digy/portwarden/internal/backend/liveness"
	"github.com/thapr0digy/portwarden/internal/model"
)

// Alert kinds.
const (
	KindNewlyReachable = "newly_reachable"
	KindConfirmed      = "confirmed"
	KindHostSilent     = "host_silent"
	KindHostRecovered  = "host_recovered"
	KindFeedStalled    = "backend_feed_stalled"
	KindFeedRecovered  = "backend_feed_recovered"
	KindTamper         = "tamper"
)

// Alert is the webhook payload.
type Alert struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	// Severity is "info" for informational alerts (agent_restarted_unclean); omitted on
	// pages.
	Severity      string     `json:"severity,omitempty"`
	Host          string     `json:"host,omitempty"`
	At            time.Time  `json:"at"`
	Summary       string     `json:"summary"`
	Listener      *Listener  `json:"listener,omitempty"`
	Level         string     `json:"level,omitempty"`
	PreviousLevel string     `json:"previous_level,omitempty"`
	Origin        string     `json:"origin,omitempty"`
	Evidence      []string   `json:"evidence,omitempty"`
	Processes     []Process  `json:"processes,omitempty"`
	PublicIPs     []string   `json:"public_ips,omitempty"`
	Probe         *Probe     `json:"probe,omitempty"`
	LastHeartbeat *time.Time `json:"last_heartbeat,omitempty"`
}

// Listener identifies the listener an alert is about.
type Listener struct {
	Key   string `json:"key"`
	Proto string `json:"proto"`
	Addr  string `json:"addr"`
	Port  uint32 `json:"port"`
	Netns uint32 `json:"netns,omitempty"`
}

// Process is the owner, abridged.
type Process struct {
	PID  uint32 `json:"pid"`
	Exe  string `json:"exe,omitempty"`
	Unit string `json:"unit,omitempty"`
}

// Probe is the outside checker's result.
type Probe struct {
	Target  string `json:"target"`
	Probe   string `json:"probe"`
	Banner  string `json:"banner,omitempty"`
	Checker string `json:"checker,omitempty"`
}

// Ignore suppresses alerts for matching listeners; empty fields match anything.
type Ignore struct {
	Host  string `json:"host"`
	Proto string `json:"proto"`
	Addr  string `json:"addr"`
	Port  uint32 `json:"port"`
}

// Rules configure the engine.
type Rules struct {
	// PageLevel: an exposure.changed whose level reaches it from below pages (default
	// host_firewall_open).
	PageLevel       string `json:"page_level"`
	PageOnConfirmed bool   `json:"page_on_confirmed"`
	PageOnSilence   bool   `json:"page_on_silence"`
	// PageOnTamper pages when an agent raises a tamper flag (asm.<host>.tamper or a
	// heartbeat's tamper status); TamperIgnore lists flag kinds that never page.
	PageOnTamper bool     `json:"page_on_tamper"`
	TamperIgnore []string `json:"tamper_ignore"`
	// PageOnUncleanRestart sends an informational agent_restarted_unclean alert when a
	// host's agent starts a new run without the previous run's clean-shutdown marker.
	PageOnUncleanRestart bool          `json:"page_on_unclean_restart"`
	DedupeWindow         time.Duration `json:"-"`
	Ignore               []Ignore      `json:"ignore"`
	pageLevelNumeric     int
}

// Validate fills defaults and checks the level name.
func (r *Rules) Validate() error {
	if r.PageLevel == "" {
		r.PageLevel = model.ExposureHostFirewallOpen.String()
	}
	for n := model.ExposureLocal; n <= model.ExposureConfirmed; n++ {
		if n.String() == r.PageLevel {
			r.pageLevelNumeric = int(n)
		}
	}
	if r.pageLevelNumeric == 0 {
		return fmt.Errorf("page_level %q is not local, bound, host_firewall_open, cloud_open or confirmed", r.PageLevel)
	}
	if r.DedupeWindow <= 0 {
		r.DedupeWindow = time.Hour
	}
	return nil
}

// State is the alerter's durable state: dedupe marks, the last probe result per
// listener, and the outbox of pages to deliver. Engine calls happen inside one State
// transaction, so a decision, its marks and its page are stored together (and the NATS
// message is acked only after that).
type State interface {
	LastPaged(ctx context.Context, key string) (time.Time, bool, error)
	SetPaged(ctx context.Context, key string, at time.Time) error
	ClearPaged(ctx context.Context, key string) error
	// PagedKeys lists the marks whose key starts with prefix.
	PagedKeys(ctx context.Context, prefix string) ([]string, error)
	ProbeResult(ctx context.Context, key string) (string, error)
	SetProbeResult(ctx context.Context, key, result string, at time.Time) error
	// ClearProbes drops the probe results whose key starts with prefix.
	ClearProbes(ctx context.Context, prefix string) error
	// SetForgotten records a forgotten host's mark (Back false); a mark of the same stream
	// with a higher sequence is kept, one of another stream replaced.
	SetForgotten(ctx context.Context, host string, mark ForgetMark) error
	// SetBack records that a forgotten host sent an agent message after its mark.
	SetBack(ctx context.Context, host string) error
	// ForgetMark returns a host's mark (ok false: never forgotten).
	ForgetMark(ctx context.Context, host string) (ForgetMark, bool, error)
	// Run returns a host's current agent run (ok false: none recorded); SetRun replaces
	// it; ClearRun drops it (a forgotten host).
	Run(ctx context.Context, host string) (Run, bool, error)
	SetRun(ctx context.Context, host string, r Run) error
	ClearRun(ctx context.Context, host string) error
	Enqueue(ctx context.Context, a *Alert) error
}

// Engine applies the rules. One page per listener per dedupe window covers both newly
// reachable and confirmed. A confirmation pages only when the listener's previous probe
// result was not confirmed (reprobes that keep the verdict never page). One page per host
// for silence, until the host is heard again. One page when the backend's own feed
// stalls. Stateless itself: everything lives in State.
type Engine struct {
	rules Rules
	newID func() string
}

// NewEngine returns an engine; rules must be validated.
func NewEngine(rules Rules, newID func() string) *Engine {
	return &Engine{rules: rules, newID: newID}
}

// DedupeWindow is the rules' window.
func (e *Engine) DedupeWindow() time.Duration { return e.rules.DedupeWindow }

// Decision is an engine outcome: an alert queued, or why none.
type Decision struct {
	Alert *Alert
	// Suppressed names the rule that held a matching alert back ("dedupe", "ignore",
	// "not a transition").
	Suppressed string
}

func (e *Engine) dedupe(ctx context.Context, st State, key string, now time.Time) (bool, error) {
	at, ok, err := st.LastPaged(ctx, key)
	if err != nil {
		return false, err
	}
	if ok && now.Sub(at) < e.rules.DedupeWindow {
		return true, nil
	}
	return false, st.SetPaged(ctx, key, now)
}

func (e *Engine) ignored(host string, l *asmv1.Listener) bool {
	for _, ig := range e.rules.Ignore {
		if (ig.Host == "" || ig.Host == host) && (ig.Proto == "" || ig.Proto == l.GetProto()) &&
			(ig.Addr == "" || ig.Addr == l.GetAddr()) && (ig.Port == 0 || ig.Port == l.GetPort()) {
			return true
		}
	}
	return false
}

func (e *Engine) queue(ctx context.Context, st State, a *Alert) (Decision, error) {
	if err := st.Enqueue(ctx, a); err != nil {
		return Decision{}, err
	}
	return Decision{Alert: a}, nil
}

// Exposure judges an exposure.changed event (agent) or cloud verdict (origin from the
// subject).
func (e *Engine) Exposure(ctx context.Context, st State, host, origin string, ev *asmv1.ExposureEvent, now time.Time) (Decision, error) {
	lvl, prev := int(ev.GetExposure().GetLevel()), int(ev.GetPrevious().GetLevel())
	if lvl < e.rules.pageLevelNumeric || prev >= e.rules.pageLevelNumeric {
		return Decision{}, nil
	}
	if e.ignored(host, ev.GetListener()) {
		return Decision{Suppressed: "ignore"}, nil
	}
	if dup, err := e.dedupe(ctx, st, "listener:"+host+"/"+ev.GetListener().GetKey(), now); err != nil || dup {
		return Decision{Suppressed: "dedupe"}, err
	}
	if origin == "" {
		origin = "agent"
	}
	a := &Alert{ID: e.newID(), Kind: KindNewlyReachable, Host: host, At: now, Listener: listener(ev.GetListener()),
		Level: model.ExposureLevel(lvl).String(), Origin: origin, Evidence: ev.GetExposure().GetEvidence(),
		Processes: processes(ev.GetProcesses()), PublicIPs: publicIPs(ev.GetHost())}
	if ev.GetPrevious() != nil {
		a.PreviousLevel = model.ExposureLevel(prev).String()
	}
	a.Summary = fmt.Sprintf("%s %s:%d on %s is newly reachable (%s)", a.Listener.Proto, a.Listener.Addr, a.Listener.Port, host, a.Level)
	return e.queue(ctx, st, a)
}

// Confirmation judges a verifier result. Every result is recorded; only a transition to
// confirmed can page.
func (e *Engine) Confirmation(ctx context.Context, st State, host string, ev *asmv1.ExposureConfirmation, now time.Time) (Decision, error) {
	key := host + "/" + ev.GetListener().GetKey()
	prev, err := st.ProbeResult(ctx, key)
	if err != nil {
		return Decision{}, err
	}
	if err := st.SetProbeResult(ctx, key, ev.GetResult(), now); err != nil {
		return Decision{}, err
	}
	if !e.rules.PageOnConfirmed || ev.GetResult() != "confirmed" {
		return Decision{}, nil
	}
	if prev == "confirmed" {
		return Decision{Suppressed: "not a transition"}, nil
	}
	if e.ignored(host, ev.GetListener()) {
		return Decision{Suppressed: "ignore"}, nil
	}
	if dup, err := e.dedupe(ctx, st, "listener:"+key, now); err != nil || dup {
		return Decision{Suppressed: "dedupe"}, err
	}
	a := &Alert{ID: e.newID(), Kind: KindConfirmed, Host: host, At: now, Listener: listener(ev.GetListener()),
		Level: model.ExposureConfirmed.String(), Origin: "verifier", Evidence: ev.GetExposure().GetEvidence(),
		Probe: &Probe{Target: ev.GetTarget(), Probe: ev.GetProbe(), Banner: ev.GetBanner(), Checker: ev.GetChecker()}}
	a.Summary = fmt.Sprintf("%s %s:%d on %s is reachable from outside (%s %s)", a.Listener.Proto, a.Listener.Addr, a.Listener.Port,
		host, ev.GetProbe(), ev.GetTarget())
	return e.queue(ctx, st, a)
}

// Silent judges a host going silent.
func (e *Engine) Silent(ctx context.Context, st State, t liveness.Transition) (Decision, error) {
	if !e.rules.PageOnSilence {
		return Decision{}, nil
	}
	// A host forgotten meanwhile (and not back) is not silent: it is gone.
	if m, ok, err := st.ForgetMark(ctx, t.Host); err != nil || (ok && !m.Back) {
		return Decision{Suppressed: "forgotten"}, err
	}
	key := "silent:" + t.Host
	if _, paged, err := st.LastPaged(ctx, key); err != nil || paged {
		return Decision{Suppressed: "dedupe"}, err
	}
	if err := st.SetPaged(ctx, key, t.At); err != nil {
		return Decision{}, err
	}
	last := t.LastSeen
	return e.queue(ctx, st, &Alert{ID: e.newID(), Kind: KindHostSilent, Host: t.Host, At: t.At, LastHeartbeat: &last,
		Summary: fmt.Sprintf("host %s is silent: no heartbeat since %s", t.Host, last.UTC().Format(time.RFC3339))})
}

// Heard judges a live heartbeat: it ends a paged silence (persisted, so this works across
// restarts) with a recovery page.
func (e *Engine) Heard(ctx context.Context, st State, host string, now time.Time) (Decision, error) {
	key := "silent:" + host
	_, paged, err := st.LastPaged(ctx, key)
	if err != nil || !paged {
		return Decision{}, err
	}
	if err := st.ClearPaged(ctx, key); err != nil {
		return Decision{}, err
	}
	return e.queue(ctx, st, &Alert{ID: e.newID(), Kind: KindHostRecovered, Host: host, At: now, LastHeartbeat: &now,
		Summary: fmt.Sprintf("host %s is sending heartbeats again", host)})
}

// Feed judges the backend's own feed: one page when it stalls (instead of one per host),
// one when it recovers.
func (e *Engine) Feed(ctx context.Context, st State, ev liveness.FeedEvent, now time.Time) (Decision, error) {
	const key = "feed"
	switch ev {
	case liveness.FeedStalled:
		if err := st.SetPaged(ctx, key, now); err != nil {
			return Decision{}, err
		}
		return e.queue(ctx, st, &Alert{ID: e.newID(), Kind: KindFeedStalled, At: now,
			Summary: "the alerter receives nothing from any host (NATS down, or the whole fleet silent); host silence is not judged until it recovers"})
	case liveness.FeedRecovered:
		if err := st.ClearPaged(ctx, key); err != nil {
			return Decision{}, err
		}
		return e.queue(ctx, st, &Alert{ID: e.newID(), Kind: KindFeedRecovered, At: now,
			Summary: "the alerter receives host messages again; host silence is judged again after one silent_after"})
	}
	return Decision{}, nil
}

// Tamper judges an agent's tamper status (from a tamper event or a heartbeat, in the
// host's order): one page per flag newly present, with a mark per flag
// ("tamper:<host>/<kind>/<subject>/<fingerprint>"), so a flag that stays raised never
// pages again but a new observation of the same subject (another edit, another tracer)
// does (ruling R-c); marks of flags no longer present are dropped. Informational flags
// (an upgrade by the package, drops below the agent's page rate) never page. A nil
// status (an agent without tamper checks) changes nothing.
func (e *Engine) Tamper(ctx context.Context, st State, host string, status *asmv1.TamperStatus, now time.Time) (Decision, error) {
	if status == nil {
		return Decision{}, nil
	}
	prefix := TamperPrefix(host)
	current := map[string]*asmv1.TamperFlag{}
	for _, f := range status.GetFlags() {
		if f.GetInfo() || slices.Contains(e.rules.TamperIgnore, f.GetKind()) {
			continue
		}
		current[prefix+f.GetKind()+"/"+f.GetSubject()+"/"+f.GetFingerprint()] = f
	}
	marked, err := st.PagedKeys(ctx, prefix)
	if err != nil {
		return Decision{}, err
	}
	have := map[string]bool{}
	for _, k := range marked {
		have[k] = true
		if current[k] == nil {
			if err := st.ClearPaged(ctx, k); err != nil {
				return Decision{}, err
			}
		}
	}
	var fresh []string
	for _, k := range slices.Sorted(maps.Keys(current)) {
		if have[k] {
			continue
		}
		if err := st.SetPaged(ctx, k, now); err != nil {
			return Decision{}, err
		}
		f := current[k]
		ev := f.GetKind() + ":" + f.GetSubject()
		if f.GetDetail() != "" {
			ev += ": " + f.GetDetail()
		}
		fresh = append(fresh, ev)
	}
	if len(fresh) == 0 || !e.rules.PageOnTamper {
		return Decision{}, nil
	}
	return e.queue(ctx, st, &Alert{ID: e.newID(), Kind: KindTamper, Host: host, At: now, Origin: "agent", Evidence: fresh,
		Summary: fmt.Sprintf("host %s: agent tamper signal: %s", host, strings.Join(fresh, "; "))})
}

// TamperPrefix is the prefix of a host's tamper marks.
func TamperPrefix(host string) string { return "tamper:" + host + "/" }

// TamperSignature identifies the pageable part of a status (sorted kind/subject/
// fingerprint of the non-informational flags): the alerter skips the database for a
// message whose signature equals the last one it stored for the host.
func TamperSignature(status *asmv1.TamperStatus) string {
	var keys []string
	for _, f := range status.GetFlags() {
		if !f.GetInfo() {
			keys = append(keys, f.GetKind()+"/"+f.GetSubject()+"/"+f.GetFingerprint())
		}
	}
	slices.Sort(keys)
	return strings.Join(keys, "\x00")
}

func listener(l *asmv1.Listener) *Listener {
	return &Listener{Key: l.GetKey(), Proto: l.GetProto(), Addr: l.GetAddr(), Port: l.GetPort(), Netns: l.GetNetns()}
}

func processes(ps []*asmv1.Process) []Process {
	var out []Process
	for _, p := range ps {
		out = append(out, Process{PID: p.GetPid(), Exe: p.GetExe(), Unit: p.GetUnit()})
	}
	return out
}

func publicIPs(h *asmv1.HostInfo) []string {
	var out []string
	for _, ip := range h.GetPublicIps() {
		if ip.GetDir() == model.DirIn {
			out = append(out, ip.GetIp())
		}
	}
	return out
}
