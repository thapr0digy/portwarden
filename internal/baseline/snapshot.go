package baseline

import (
	"time"

	"github.com/thapr0digy/portwarden/internal/model"
)

// join turns the dumped listeners into baseline Opened observations: one per socket
// per owning process. A socket with no owner (a kernel listener such as nfsd or ksmbd,
// or one opened after the owners were read) still yields one observation, with an
// empty Proc.
func join(netns uint32, listeners []diagSocket, owners map[uint64][]model.Process, at time.Time) []model.Observation {
	obs := make([]model.Observation, 0, len(listeners))
	for _, l := range listeners {
		base := model.Observation{
			Kind:   model.Opened,
			Cookie: l.Cookie,
			Key:    model.NewKey(netns, "tcp", l.Addr, l.Port),
			At:     at,
			Source: model.SourceBaseline,
		}
		procs := owners[l.Cookie]
		if len(procs) == 0 {
			obs = append(obs, base)
			continue
		}
		for _, p := range procs {
			o := base
			o.Proc = p
			obs = append(obs, o)
		}
	}
	return obs
}
