package conf

import (
	"fmt"
	"strings"
)

// Render prints a result one route per block, for golden-file tests and debugging.
func Render(res Result) string {
	var b strings.Builder
	for _, r := range res.Routes {
		fmt.Fprintf(&b, "%s names=%s path=%q %s %q", strings.Join(r.Listen, ","), strings.Join(r.ServerNames, ","), r.Path, r.Kind, r.Target)
		if r.Upstream != "" {
			fmt.Fprintf(&b, " upstream=%s", r.Upstream)
		}
		if r.Root != "" {
			fmt.Fprintf(&b, " root=%s", r.Root)
		}
		for _, be := range r.Backends {
			fmt.Fprintf(&b, "\n    -> %s", be.Address)
			for _, a := range be.Addrs {
				fmt.Fprintf(&b, " %s", a)
			}
			if be.Unix != "" {
				fmt.Fprintf(&b, " unix=%s", be.Unix)
			}
			if be.Note != "" {
				fmt.Fprintf(&b, " (%s)", be.Note)
			}
		}
		for _, n := range r.Notes {
			fmt.Fprintf(&b, "\n    note: %s", n)
		}
		fmt.Fprintf(&b, "\n    @ %s\n", r.Source)
	}
	for _, n := range res.Notes {
		fmt.Fprintf(&b, "config note: %s\n", n)
	}
	return b.String()
}
