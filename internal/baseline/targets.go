package baseline

import (
	_ "embed"

	"github.com/thapr0digy/portwarden/internal/bpftarget"
)

// The committed objects again, without bpf2go's linux build tag, so the target list
// (and its tests) build on every platform.
var (
	//go:embed owners_bpfel.o
	ownersObject []byte
	//go:embed udp_bpfel.o
	udpObject []byte
)

// AttachTargets returns the kernel iterators this package's programs attach to.
func AttachTargets() ([]bpftarget.Target, error) {
	var out []bpftarget.Target
	for _, obj := range []struct {
		name  string
		bytes []byte
	}{{"owners_bpfel.o", ownersObject}, {"udp_bpfel.o", udpObject}} {
		t, err := bpftarget.FromObject(obj.name, obj.bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, t...)
	}
	return out, nil
}
