package baseline

import (
	"net/netip"
	"testing"
	"time"

	"github.com/thapr0digy/portwarden/internal/model"
)

const hostNetNS = 4026531840

var at = time.Unix(1700000000, 0)

func TestSnapshotKeepsOwnerlessListener(t *testing.T) {
	nfsd := diagSocket{Cookie: 7, Family: afInet, Addr: netip.IPv4Unspecified(), Port: 2049}
	shared := diagSocket{Cookie: 8, Family: afInet6, Addr: netip.MustParseAddr("::ffff:127.0.0.1"), Port: 80}
	sharedKey := model.NewKey(hostNetNS, model.ProtoTCP, shared.Addr, 80)
	parent := model.Process{PID: 10, UID: 0, Comm: "nginx", Exe: "/usr/sbin/nginx"}
	worker := model.Process{PID: 11, UID: 33, Comm: "nginx", Exe: "/usr/sbin/nginx"}
	owners := []owner{{Cookie: 8, Key: sharedKey, Proc: parent}, {Cookie: 8, Key: sharedKey, Proc: worker}}

	got := join(hostNetNS, []diagSocket{nfsd, shared}, nil, owners, at)

	checkObservations(t, got, []model.Observation{
		{Kind: model.Opened, Cookie: 7, Key: model.NewKey(hostNetNS, model.ProtoTCP, nfsd.Addr, 2049), At: at, Source: model.SourceBaseline},
		{Kind: model.Opened, Cookie: 8, Key: model.NewKey(hostNetNS, model.ProtoTCP, netip.MustParseAddr("127.0.0.1"), 80), Proc: parent, At: at, Source: model.SourceBaseline},
		{Kind: model.Opened, Cookie: 8, Key: model.NewKey(hostNetNS, model.ProtoTCP, netip.MustParseAddr("127.0.0.1"), 80), Proc: worker, At: at, Source: model.SourceBaseline},
	})
}

// A socket in another netns is not in the host dumps; its owner record carries its key.
func TestJoinForeignNetnsFromOwnerRecords(t *testing.T) {
	key := model.NewKey(99, model.ProtoTCP, netip.MustParseAddr("10.0.0.2"), 8080)
	app := model.Process{PID: 20, Comm: "app", CgroupID: 555}

	got := join(hostNetNS, nil, nil, []owner{{Cookie: 9, Key: key, Proc: app}}, at)

	checkObservations(t, got, []model.Observation{
		{Kind: model.Opened, Cookie: 9, Key: key, Proc: app, At: at, Source: model.SourceBaseline},
	})
	if got[0].Key.String() != "99/tcp/10.0.0.2:8080" {
		t.Errorf("key = %v, want 99/tcp/10.0.0.2:8080", got[0].Key)
	}
}

// A host owner record whose socket is in no dump closed before the dumps ran.
func TestJoinDropsHostOwnerMissingFromDumps(t *testing.T) {
	key := model.NewKey(hostNetNS, model.ProtoUDP, netip.IPv4Unspecified(), 53)

	got := join(hostNetNS, nil, nil, []owner{{Cookie: 3, Key: key, Proc: model.Process{PID: 1}}}, at)

	checkObservations(t, got, nil)
}

func TestJoinUDPOwnerless(t *testing.T) {
	vxlan := diagSocket{Cookie: 12, Family: afInet, Addr: netip.IPv4Unspecified(), Port: 4789}
	dns := diagSocket{Cookie: 13, Family: afInet, Addr: netip.MustParseAddr("127.0.0.53"), Port: 53}
	resolved := model.Process{PID: 30, Comm: "systemd-resolve"}
	dnsKey := model.NewKey(hostNetNS, model.ProtoUDP, dns.Addr, 53)

	got := join(hostNetNS, nil, []diagSocket{vxlan, dns}, []owner{{Cookie: 13, Key: dnsKey, Proc: resolved}}, at)

	checkObservations(t, got, []model.Observation{
		{Kind: model.Opened, Cookie: 12, Key: model.NewKey(hostNetNS, model.ProtoUDP, vxlan.Addr, 4789), At: at, Source: model.SourceBaseline},
		{Kind: model.Opened, Cookie: 13, Key: dnsKey, Proc: resolved, At: at, Source: model.SourceBaseline},
	})
}

func checkObservations(t *testing.T, got, want []model.Observation) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d observations, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if !sameObservation(got[i], want[i]) {
			t.Errorf("observation %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// sameObservation compares field by field, since Process holds a slice and is not comparable.
func sameObservation(a, b model.Observation) bool {
	return a.Kind == b.Kind && a.Cookie == b.Cookie && a.Key == b.Key &&
		a.Proc.Equal(b.Proc) && a.At.Equal(b.At) && a.Source == b.Source
}

// The dumps' IPV6_V6ONLY flag goes on every observation of the socket; a host socket
// whose dump record lacks it takes the owner record's, and a foreign-netns socket has
// only the owner record's.
func TestJoinCarriesV6Only(t *testing.T) {
	v6 := netip.IPv6Unspecified()
	app := model.Process{PID: 20, Comm: "app"}
	tcp := []diagSocket{
		{Cookie: 1, Family: afInet6, Addr: v6, Port: 8080, V6Only: model.V6OnlyOn},
		{Cookie: 2, Family: afInet6, Addr: v6, Port: 8081},
	}
	udp := []diagSocket{{Cookie: 3, Family: afInet6, Addr: v6, Port: 5353, V6Only: model.V6OnlyOff}}
	foreign := model.NewKey(4026532999, model.ProtoTCP, v6, 80)
	owners := []owner{
		{Cookie: 1, Key: model.NewKey(hostNetNS, model.ProtoTCP, v6, 8080), V6Only: model.V6OnlyOn, Proc: app},
		{Cookie: 2, Key: model.NewKey(hostNetNS, model.ProtoTCP, v6, 8081), V6Only: model.V6OnlyOff, Proc: app},
		{Cookie: 4, Key: foreign, V6Only: model.V6OnlyOn, Proc: app},
	}
	got := join(hostNetNS, tcp, udp, owners, at)
	checkObservations(t, got, []model.Observation{
		{Kind: model.Opened, Cookie: 1, Key: model.NewKey(hostNetNS, model.ProtoTCP, v6, 8080), Proc: app, At: at, Source: model.SourceBaseline, V6Only: model.V6OnlyOn},
		{Kind: model.Opened, Cookie: 2, Key: model.NewKey(hostNetNS, model.ProtoTCP, v6, 8081), Proc: app, At: at, Source: model.SourceBaseline, V6Only: model.V6OnlyOff},
		{Kind: model.Opened, Cookie: 3, Key: model.NewKey(hostNetNS, model.ProtoUDP, v6, 5353), At: at, Source: model.SourceBaseline, V6Only: model.V6OnlyOff},
		{Kind: model.Opened, Cookie: 4, Key: foreign, Proc: app, At: at, Source: model.SourceBaseline, V6Only: model.V6OnlyOn},
	})
}
