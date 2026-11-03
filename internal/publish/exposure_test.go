package publish

import (
	"context"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
	"github.com/thapr0digy/portwarden/internal/model"
	"github.com/thapr0digy/portwarden/internal/state"
)

var (
	openExposure  = model.Exposure{Level: model.ExposureHostFirewallOpen, Evidence: []string{"bind:any", "nft: accept tcp/8080 from 0/0 (eth0, inet filter input)"}}
	boundExposure = model.Exposure{Level: model.ExposureBound, Evidence: []string{"bind:any", "nft: drop tcp/8080 from 0/0 (eth0, policy inet filter input)"}}
	testHostInfo  = model.HostInfo{Cloud: "aws", InstanceID: "i-0abc", PublicIPs: []model.PublicIP{
		{IP: netip.MustParseAddr("34.120.1.7"), Via: model.ViaIMDS, Dir: model.DirIn},
		{IP: netip.MustParseAddr("2600:1f18::15"), Via: model.ViaNetlink, Dir: model.DirIn, Iface: "eth0"},
	}}
)

func TestExposureOnEventsAndSnapshots(t *testing.T) {
	port := freePort(t)
	startServer(t, port, t.TempDir())
	p := newPublisher(t, port)

	p.SetHost(testHostInfo)
	snap := snapshotOf(22)
	snap[0].Exposure = boundExposure
	p.Snapshot(snap)
	c := openedChange(8080)
	c.Exposure = openExposure
	p.Changes([]state.Change{c})
	p.ExposureChanges([]state.ExposureChange{{Key: c.Key, Procs: c.Procs, Exposure: openExposure, Trigger: "opened", At: c.At}})
	p.ExposureChanges([]state.ExposureChange{{Key: c.Key, Procs: c.Procs, Exposure: boundExposure, Previous: openExposure, Trigger: "firewall"}})

	msgs := readStream(t, port, 4)
	var s asmv1.Snapshot
	mustUnmarshal(t, msgs[0].data, &s)
	if s.Listeners[0].Exposure.GetLevel() != asmv1.ExposureLevel_EXPOSURE_BOUND || s.Host.GetInstanceId() != "i-0abc" || len(s.Host.GetPublicIps()) != 2 {
		t.Fatalf("snapshot = %v", &s)
	}
	var ev asmv1.ListenerEvent
	mustUnmarshal(t, msgs[1].data, &ev)
	if ev.Exposure.GetLevel() != asmv1.ExposureLevel_EXPOSURE_HOST_FIREWALL_OPEN || !slices.Equal(ev.Exposure.GetEvidence(), openExposure.Evidence) ||
		ev.Host.GetPublicIps()[0].GetIp() != "34.120.1.7" || ev.Host.GetPublicIps()[1].GetIface() != "eth0" {
		t.Fatalf("opened = %v", &ev)
	}
	if msgs[2].subject != "asm."+testHost+".exposure.changed" {
		t.Fatalf("subject %q", msgs[2].subject)
	}
	var first, second asmv1.ExposureEvent
	mustUnmarshal(t, msgs[2].data, &first)
	mustUnmarshal(t, msgs[3].data, &second)
	if first.Seq != 3 || first.Trigger != "opened" || first.Previous != nil || first.Listener.GetPort() != 8080 ||
		first.Exposure.GetLevel() != asmv1.ExposureLevel_EXPOSURE_HOST_FIREWALL_OPEN || first.ObservedAt.AsTime().Unix() != 1700000000 ||
		len(first.Processes) != 1 || first.Host.GetCloud() != "aws" || msgs[2].msgID != first.EventId {
		t.Fatalf("first exposure event = %v", &first)
	}
	if second.Trigger != "firewall" || second.Previous.GetLevel() != asmv1.ExposureLevel_EXPOSURE_HOST_FIREWALL_OPEN ||
		second.Exposure.GetLevel() != asmv1.ExposureLevel_EXPOSURE_BOUND {
		t.Fatalf("second exposure event = %v", &second)
	}

	// A resnapshot shows the latest exposure.
	p.mu.Lock()
	cur := p.current[c.Key]
	p.mu.Unlock()
	if cur.Exposure.Level != model.ExposureBound {
		t.Fatalf("current = %+v", cur)
	}
}

func TestHostChanged(t *testing.T) {
	port := freePort(t)
	startServer(t, port, t.TempDir())
	p := newPublisher(t, port)

	p.SetHost(model.HostInfo{})     // first call: no event
	p.SetHost(model.HostInfo{})     // unchanged: no event
	p.SetHost(testHostInfo)         // changed: event
	p.SetHost(testHostInfo.Clone()) // unchanged
	p.Heartbeat(0)

	msgs := readStream(t, port, 2)
	if msgs[0].subject != "asm."+testHost+".host.changed" || msgs[1].subject != "asm."+testHost+".heartbeat" {
		t.Fatalf("subjects %q %q", msgs[0].subject, msgs[1].subject)
	}
	var ev asmv1.HostEvent
	mustUnmarshal(t, msgs[0].data, &ev)
	if ev.Seq != 1 || ev.Host.GetCloud() != "aws" || ev.Previous == nil || len(ev.Previous.GetPublicIps()) != 0 || ev.HostId != testHost {
		t.Fatalf("host event = %v", &ev)
	}
}

func TestUnsetExposureAndHostAreOmitted(t *testing.T) {
	port := freePort(t)
	startServer(t, port, t.TempDir())
	p := newPublisher(t, port)
	p.Changes([]state.Change{openedChange(9090)})
	msgs := readStream(t, port, 1)
	var ev asmv1.ListenerEvent
	mustUnmarshal(t, msgs[0].data, &ev)
	if ev.Exposure != nil || ev.Host != nil {
		t.Fatalf("unset exposure/host must be absent: %v", &ev)
	}
}

func TestLocalAddrReported(t *testing.T) {
	port := freePort(t)
	startServer(t, port, t.TempDir())
	var mu sync.Mutex
	var seen []netip.Addr
	p, err := New(context.Background(), Config{URL: natsURL(port), HostID: testHost, LocalAddr: func(a netip.Addr) {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, a)
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	p.Heartbeat(0)
	readStream(t, port, 1)
	deadlineAt := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := len(seen)
		mu.Unlock()
		if n > 0 || time.Now().After(deadlineAt) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) == 0 || seen[0] != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("local addresses %v", seen)
	}
}
