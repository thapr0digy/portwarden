package probes

import (
	_ "embed"

	"github.com/thapr0digy/portwarden/internal/bpftarget"
)

// The committed objects again, without bpf2go's linux build tag, so the target list
// (and its tests) build on every platform.
var (
	//go:embed listen_bpfel.o
	listenObject []byte
	//go:embed proxyconn_bpfel.o
	proxyconnObject []byte
)

// AttachTargets returns the kernel functions this package's programs attach to.
func AttachTargets() ([]bpftarget.Target, error) {
	var out []bpftarget.Target
	for _, obj := range []struct {
		name  string
		bytes []byte
	}{{"listen_bpfel.o", listenObject}, {"proxyconn_bpfel.o", proxyconnObject}} {
		t, err := bpftarget.FromObject(obj.name, obj.bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, t...)
	}
	return out, nil
}
