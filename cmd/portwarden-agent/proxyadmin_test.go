package main

import (
	"maps"
	"slices"
	"testing"
)

func TestParseProxyAdmin(t *testing.T) {
	cases := map[string][]string{
		"auto":           {"caddy", "haproxy"},
		"off":            nil,
		"caddy":          {"caddy"},
		" haproxy,caddy": {"caddy", "haproxy"},
	}
	for in, want := range cases {
		got, err := parseProxyAdmin(in)
		if err != nil || !slices.Equal(slices.Sorted(maps.Keys(got)), want) {
			t.Errorf("%q: %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "envoy", "caddy,", "on"} {
		if _, err := parseProxyAdmin(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
