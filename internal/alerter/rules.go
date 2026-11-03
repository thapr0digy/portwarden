// Package alerter turns exposure events and host silence into pages (design §1
// "Alerter", §6 "alert on anything newly reachable", "silence is a signal"). The rules
// are fixed code driven by a config file; delivery is a signed JSON webhook plus a log
// line per alert.
package alerter

import (
	"fmt"
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
)

// Alert is the webhook payload.
type Alert struct {
	ID            string     `json:"id"`
	Kind          string     `json:"kind"`
	Host          string     `json:"host"`
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
	PageLevel        string        `json:"page_level"`
	PageOnConfirmed  bool          `json:"page_on_confirmed"`
	PageOnSilence    bool          `json:"page_on_silence"`
	DedupeWindow     time.Duration `json:"-"`
	Ignore           []Ignore      `json:"ignore"`
	pageLevelNumeric int
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

// Engine applies the rules. One page per listener per dedupe window covers both newly
// reachable and confirmed (a confirmation of a listener just paged for is logged as
// suppressed); one per host for silence, reset when the host recovers. Not safe for
// concurrent use.
type Engine struct {
	rules Rules
	paged map[string]time.Time
	newID func() string
}

// NewEngine returns an engine; rules must be validated.
func NewEngine(rules Rules, newID func() string) *Engine {
	return &Engine{rules: rules, paged: map[string]time.Time{}, newID: newID}
}

// Decision is an engine outcome: an alert to send, or why none.
type Decision struct {
	Alert *Alert
	// Suppressed names the rule that held a matching alert back ("dedupe", "ignore").
	Suppressed string
}

func (e *Engine) dedupe(key string, now time.Time) bool {
	if at, ok := e.paged[key]; ok && now.Sub(at) < e.rules.DedupeWindow {
		return true
	}
	e.paged[key] = now
	return false
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

// Exposure judges an exposure.changed event.
func (e *Engine) Exposure(host string, ev *asmv1.ExposureEvent, now time.Time) Decision {
	lvl, prev := int(ev.GetExposure().GetLevel()), int(ev.GetPrevious().GetLevel())
	if lvl < e.rules.pageLevelNumeric || prev >= e.rules.pageLevelNumeric {
		return Decision{}
	}
	if e.ignored(host, ev.GetListener()) {
		return Decision{Suppressed: "ignore"}
	}
	if e.dedupe("listener:"+host+"/"+ev.GetListener().GetKey(), now) {
		return Decision{Suppressed: "dedupe"}
	}
	origin := ev.GetOrigin()
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
	return Decision{Alert: a}
}

// Confirmation judges an exposure.confirmed event.
func (e *Engine) Confirmation(host string, ev *asmv1.ExposureConfirmation, now time.Time) Decision {
	if !e.rules.PageOnConfirmed || ev.GetResult() != "confirmed" {
		return Decision{}
	}
	if e.ignored(host, ev.GetListener()) {
		return Decision{Suppressed: "ignore"}
	}
	if e.dedupe("listener:"+host+"/"+ev.GetListener().GetKey(), now) {
		return Decision{Suppressed: "dedupe"}
	}
	a := &Alert{ID: e.newID(), Kind: KindConfirmed, Host: host, At: now, Listener: listener(ev.GetListener()),
		Level: model.ExposureConfirmed.String(), Origin: "verifier", Evidence: ev.GetExposure().GetEvidence(),
		Probe: &Probe{Target: ev.GetTarget(), Probe: ev.GetProbe(), Banner: ev.GetBanner(), Checker: ev.GetChecker()}}
	a.Summary = fmt.Sprintf("%s %s:%d on %s is reachable from outside (%s %s)", a.Listener.Proto, a.Listener.Addr, a.Listener.Port,
		host, ev.GetProbe(), ev.GetTarget())
	return Decision{Alert: a}
}

// Liveness judges a silent / recovered transition.
func (e *Engine) Liveness(t liveness.Transition) Decision {
	if !e.rules.PageOnSilence {
		return Decision{}
	}
	last := t.LastSeen
	key := "silent:" + t.Host
	if !t.Silent {
		if _, paged := e.paged[key]; !paged {
			return Decision{}
		}
		delete(e.paged, key)
		return Decision{Alert: &Alert{ID: e.newID(), Kind: KindHostRecovered, Host: t.Host, At: t.At, LastHeartbeat: &last,
			Summary: fmt.Sprintf("host %s is sending heartbeats again", t.Host)}}
	}
	if _, paged := e.paged[key]; paged {
		return Decision{Suppressed: "dedupe"}
	}
	e.paged[key] = t.At
	return Decision{Alert: &Alert{ID: e.newID(), Kind: KindHostSilent, Host: t.Host, At: t.At, LastHeartbeat: &last,
		Summary: fmt.Sprintf("host %s is silent: no heartbeat since %s", t.Host, last.UTC().Format(time.RFC3339))}}
}

// Expire forgets listener pages older than the dedupe window (bounded memory).
func (e *Engine) Expire(now time.Time) {
	for k, at := range e.paged {
		if strings.HasPrefix(k, "listener:") && now.Sub(at) >= e.rules.DedupeWindow {
			delete(e.paged, k)
		}
	}
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
