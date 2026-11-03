package exposure

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/thapr0digy/portwarden/internal/netif"
	"github.com/thapr0digy/portwarden/internal/state"
)

// fakeHost serves rulesets and interfaces that a test can change.
type fakeHost struct {
	mu    sync.Mutex
	rules string // iptables-save text
	ifs   []netif.Interface
	reads int
}

func (h *fakeHost) run(_ context.Context, name string, _ ...string) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if name == "iptables-save" {
		h.reads++
		return []byte(h.rules), nil
	}
	return nil, fmt.Errorf("%s: %w", name, ErrToolMissing)
}

func (h *fakeHost) interfaces() ([]netif.Interface, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]netif.Interface(nil), h.ifs...), nil
}

func (h *fakeHost) set(rules string, ifs []netif.Interface) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if rules != "" {
		h.rules = rules
	}
	if ifs != nil {
		h.ifs = ifs
	}
}

const (
	dropAll  = "*filter\n:INPUT DROP [0:0]\nCOMMIT\n"
	accept22 = "*filter\n:INPUT DROP [0:0]\n-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\nCOMMIT\n"
)

type harness struct {
	host  *fakeHost
	fwC   chan struct{}
	ifC   chan struct{}
	views chan *View
	stop  context.CancelFunc
	done  chan struct{}
}

func startWatcher(t *testing.T, fwErr error, recheck time.Duration) *harness {
	t.Helper()
	h := &harness{
		host:  &fakeHost{rules: dropAll, ifs: vmIfs()},
		fwC:   make(chan struct{}, 1),
		ifC:   make(chan struct{}, 1),
		views: make(chan *View, 16),
		done:  make(chan struct{}),
	}
	w := NewWatcher(WatchConfig{
		Config:   Config{HostNetNS: hostNS, Run: h.host.run, Interfaces: h.host.interfaces},
		Debounce: 20 * time.Millisecond,
		Poll:     30 * time.Millisecond,
		Recheck:  recheck,
		FirewallChanges: func(context.Context) (<-chan struct{}, error) {
			if fwErr != nil {
				return nil, fwErr
			}
			return h.fwC, nil
		},
		InterfaceChanges: func(context.Context) (<-chan struct{}, error) { return h.ifC, nil },
	})
	ctx, cancel := context.WithCancel(context.Background())
	h.stop = cancel
	initial := w.Initial(ctx)
	if initial.Trigger() != TriggerStart || initial.fw == nil {
		t.Fatalf("initial view: %+v", initial)
	}
	go func() {
		defer close(h.done)
		w.Run(ctx, initial, func(v *View) { h.views <- v })
	}()
	t.Cleanup(func() {
		cancel()
		<-h.done
	})
	return h
}

func (h *harness) next(t *testing.T) *View {
	t.Helper()
	select {
	case v := <-h.views:
		return v
	case <-time.After(2 * time.Second):
		t.Fatal("no view")
	}
	return nil
}

func (h *harness) none(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case v := <-h.views:
		t.Fatalf("unexpected view %q", v.Trigger())
	case <-time.After(d):
	}
}

func TestWatcherFirewallChange(t *testing.T) {
	h := startWatcher(t, nil, 0)
	// A notification with no actual change sends nothing.
	h.fwC <- struct{}{}
	h.none(t, 100*time.Millisecond)

	h.host.set(accept22, nil)
	h.fwC <- struct{}{}
	v := h.next(t)
	if v.Trigger() != TriggerFirewall {
		t.Fatalf("trigger %q", v.Trigger())
	}
	e := v.Judge([]state.Listener{lst(hostNS, "tcp", "0.0.0.0", 22)})
	if got := e[lst(hostNS, "tcp", "0.0.0.0", 22).Key].Level.String(); got != "host_firewall_open" {
		t.Fatalf("22 after the change: %s", got)
	}
}

func TestWatcherInterfaceChangeAndDebounce(t *testing.T) {
	h := startWatcher(t, nil, 0)
	reads := func() int { h.host.mu.Lock(); defer h.host.mu.Unlock(); return h.host.reads }
	before := reads()
	h.host.set("", vmIfs(netif.Interface{Name: "eth1", Up: true, Prefixes: []netip.Prefix{netip.MustParsePrefix("34.120.1.7/24")}}))
	for range 5 {
		select {
		case h.ifC <- struct{}{}:
		default:
		}
		time.Sleep(2 * time.Millisecond)
	}
	if v := h.next(t); v.Trigger() != TriggerInterfaces {
		t.Fatalf("trigger %q", v.Trigger())
	}
	if got := reads() - before; got != 1 {
		t.Fatalf("a burst of notifications read the firewall %d times", got)
	}
}

func TestWatcherPollsWithoutNotifications(t *testing.T) {
	h := startWatcher(t, errors.New("netlink join group 7: operation not permitted"), 0)
	h.none(t, 100*time.Millisecond) // polls, but nothing changed
	h.host.set(accept22, nil)
	if v := h.next(t); v.Trigger() != TriggerFirewall {
		t.Fatalf("trigger %q", v.Trigger())
	}
}

func TestWatcherRecheckAlwaysSends(t *testing.T) {
	h := startWatcher(t, nil, 50*time.Millisecond)
	if v := h.next(t); v.Trigger() != TriggerRecheck {
		t.Fatalf("trigger %q", v.Trigger())
	}
}

func TestWatcherClosedNotificationFallsBackToPolling(t *testing.T) {
	h := startWatcher(t, nil, 0)
	close(h.fwC)
	time.Sleep(20 * time.Millisecond)
	h.host.set(accept22, nil)
	if v := h.next(t); v.Trigger() != TriggerFirewall {
		t.Fatalf("trigger %q", v.Trigger())
	}
}
