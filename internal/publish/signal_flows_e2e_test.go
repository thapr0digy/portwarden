package publish_test

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"testing"

	"github.com/slidehq/signal/schema/eventsv1"
	"github.com/slidehq/signal/schema/ingesttest"

	"github.com/thapr0digy/portwarden/internal/flows"
	"github.com/thapr0digy/portwarden/internal/publish"
)

// runFlows runs the flows reader over events until stop returns, then stops it (sending the
// partial window) and closes the publisher.
func runFlows(t *testing.T, cfg flows.Config, events <-chan flows.Event, pub *publish.Publisher, stop func()) {
	t.Helper()
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		flows.Run(ctx, cfg, events, pub)
	}()
	stop()
	cancel()
	wg.Wait()
	if err := pub.Close(); err != nil {
		t.Fatal(err)
	}
}

// storedFlows returns the one flows window Signal stored, after checking nothing was refused
// and no gap was seen.
func storedFlows(t *testing.T, ref *ingesttest.Server) *eventsv1.HostFlows {
	t.Helper()
	var got []*eventsv1.HostFlows
	for _, e := range ref.Stored() {
		if e.GetType() == "asm.host.flows" {
			got = append(got, e.GetHostFlows())
		}
	}
	if len(ref.Quarantined()) != 0 || len(ref.Gaps()) != 0 {
		t.Fatalf("quarantined %v, gaps %v", ref.Quarantined(), ref.Gaps())
	}
	if len(got) != 1 {
		t.Fatalf("stored %d flows windows, want 1", len(got))
	}
	return got[0]
}

// flowRow finds the row of direction dir whose peer port (out) or local port (in) is port.
func flowRow(f *eventsv1.HostFlows, dir string, port uint32) *eventsv1.Flow {
	for _, r := range f.GetFlows() {
		if r.GetDirection() == dir && (r.GetRemotePort() == port || r.GetLocalPort() == port) {
			return r
		}
	}
	return nil
}

// The agent's flows reader, fed kernel records, sends a window Signal's door stores: a TLS
// connection named by its SNI, a silent one unnamed, and a public client summed.
func TestE2EHostFlowsAreStoredBySignal(t *testing.T) {
	ref, pub, _ := signalDoor(t, e2eHost)
	events := make(chan flows.Event)
	cfg := flows.Config{Identify: func(uint32, uint64) flows.Process {
		return flows.Process{Exe: "/opt/billing/bin/billing", Unit: "billing.service"}
	}}
	runFlows(t, cfg, events, pub, func() {
		for _, e := range []flows.Event{
			{Kind: flows.KindOut, Cookie: 1, TGID: 10, Comm: "billing", Remote: netip.MustParseAddrPort("10.0.0.9:443")},
			{Kind: flows.KindHead, Cookie: 1, App: flows.AppTLS, Service: "ledger.internal.example"},
			{Kind: flows.KindOut, Cookie: 2, TGID: 10, Comm: "billing", Remote: netip.MustParseAddrPort("10.0.0.10:5432")},
			{Kind: flows.KindIn, TGID: 10, Comm: "billing", LocalPort: 8443, Remote: netip.MustParseAddrPort("203.0.113.5:40000")},
			{Kind: flows.KindIn, TGID: 10, Comm: "billing", LocalPort: 8443, Remote: netip.MustParseAddrPort("198.51.100.7:40001")},
		} {
			events <- e
		}
	})
	f := storedFlows(t, ref)
	if !f.GetRead() || len(f.GetFlows()) != 3 {
		t.Fatalf("window %v", f)
	}
	if r := flowRow(f, "out", 443); r == nil || r.GetServiceName() != "ledger.internal.example" || r.GetAppProto() != "tls" || r.GetUnit() != "billing.service" {
		t.Errorf("tls row %v", r)
	}
	if r := flowRow(f, "out", 5432); r == nil || r.GetServiceName() != "" || r.GetAppProto() != "" {
		t.Errorf("silent row %v", r)
	}
	if r := flowRow(f, "in", 8443); r == nil || r.GetRemoteAddr() != "" || r.GetCount() != 2 {
		t.Errorf("public clients row %v", r)
	}
}
