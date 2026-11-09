package main

import (
	"fmt"
	"slices"
	"strings"

	"github.com/thapr0digy/portwarden/internal/proxy/mapper"
)

// parseProxyAdmin reads --proxy-admin: "auto" (every kind the admin reader supports),
// "off" (none), or a comma list of kinds.
func parseProxyAdmin(v string) (map[string]bool, error) {
	kinds := make(map[string]bool)
	switch v = strings.TrimSpace(v); v {
	case "auto":
		for _, k := range mapper.AdminKinds {
			kinds[k] = true
		}
		return kinds, nil
	case "off":
		return kinds, nil
	}
	for _, k := range strings.Split(v, ",") {
		k = strings.TrimSpace(k)
		if !slices.Contains(mapper.AdminKinds, k) {
			return nil, fmt.Errorf("--proxy-admin must be auto, off or a comma list of %s, got %q", strings.Join(mapper.AdminKinds, ","), v)
		}
		kinds[k] = true
	}
	return kinds, nil
}
