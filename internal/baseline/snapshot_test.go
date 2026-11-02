package baseline

import (
	"net/netip"
	"testing"
	"time"

	"github.com/thapr0digy/portwarden/internal/model"
)

func TestSnapshotKeepsOwnerlessListener(t *testing.T) {
	const netns = 4026531840
	at := time.Unix(1700000000, 0)
	nfsd := diagSocket{Cookie: 7, Family: afInet, Addr: netip.IPv4Unspecified(), Port: 2049}
	shared := diagSocket{Cookie: 8, Family: afInet6, Addr: netip.MustParseAddr("::ffff:127.0.0.1"), Port: 80}
	parent := model.Process{PID: 10, UID: 0, Comm: "nginx", Exe: "/usr/sbin/nginx"}
	worker := model.Process{PID: 11, UID: 33, Comm: "nginx", Exe: "/usr/sbin/nginx"}
	owners := map[uint64][]model.Process{shared.Cookie: {parent, worker}}

	got := join(netns, []diagSocket{nfsd, shared}, owners, at)

	want := []model.Observation{
		{Kind: model.Opened, Cookie: 7, Key: model.NewKey(netns, "tcp", nfsd.Addr, 2049), At: at, Source: model.SourceBaseline},
		{Kind: model.Opened, Cookie: 8, Key: model.NewKey(netns, "tcp", netip.MustParseAddr("127.0.0.1"), 80), Proc: parent, At: at, Source: model.SourceBaseline},
		{Kind: model.Opened, Cookie: 8, Key: model.NewKey(netns, "tcp", netip.MustParseAddr("127.0.0.1"), 80), Proc: worker, At: at, Source: model.SourceBaseline},
	}
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
