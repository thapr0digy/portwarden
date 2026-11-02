package baseline

import (
	"time"

	"github.com/thapr0digy/portwarden/internal/model"
)

// owner is one process holding one socket, from the owners iterator, with the socket's
// key as the kernel reports it (any netns).
type owner struct {
	Cookie uint64
	Key    model.ListenerKey
	Proc   model.Process
}

// join turns the host's dumped TCP listeners and bound UDP sockets, and the owner
// records, into baseline Opened observations: one per socket per owning process.
//
// Host-netns keys come from the dumps, joined to owners by cookie; a host owner record
// whose socket is in neither dump closed before the dump ran and is dropped. A socket
// with no owner (a kernel socket such as nfsd's, ksmbd's or a VXLAN device's, or one
// opened after the owners were read) still yields one observation, with an empty Proc.
// Keys in any other netns come from the owner records themselves, since the dumps see
// only the host's.
func join(hostNetNS uint32, tcp, udp []diagSocket, owners []owner, at time.Time) []model.Observation {
	procs := make(map[uint64][]model.Process, len(owners))
	for _, o := range owners {
		procs[o.Cookie] = append(procs[o.Cookie], o.Proc)
	}

	obs := make([]model.Observation, 0, len(tcp)+len(udp)+len(owners))
	emit := func(cookie uint64, key model.ListenerKey, holders []model.Process) {
		base := model.Observation{Kind: model.Opened, Cookie: cookie, Key: key, At: at, Source: model.SourceBaseline}
		if len(holders) == 0 {
			obs = append(obs, base)
			return
		}
		for _, p := range holders {
			o := base
			o.Proc = p
			obs = append(obs, o)
		}
	}
	for _, s := range tcp {
		emit(s.Cookie, model.NewKey(hostNetNS, model.ProtoTCP, s.Addr, s.Port), procs[s.Cookie])
	}
	for _, s := range udp {
		emit(s.Cookie, model.NewKey(hostNetNS, model.ProtoUDP, s.Addr, s.Port), procs[s.Cookie])
	}
	for _, o := range owners {
		if o.Key.NetNS != hostNetNS {
			emit(o.Cookie, o.Key, []model.Process{o.Proc})
		}
	}
	return obs
}
