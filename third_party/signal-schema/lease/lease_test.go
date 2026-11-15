package lease_test

import (
	"strings"
	"testing"

	"github.com/slidehq/signal/schema/lease"
)

const digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestDecodersRefuseWhatTheContractDoesNotName(t *testing.T) {
	bad := map[string]func() error{
		"unknown field": func() error {
			_, err := lease.DecodeLeaseRequest([]byte(`{"runner_version":"1","image_digest":"` + digest + `","vantage":"v","x":1}`))
			return err
		},
		"trailing data": func() error {
			_, err := lease.DecodeLeaseRequest([]byte(`{"runner_version":"1","image_digest":"` + digest + `","vantage":"v"} {}`))
			return err
		},
		"bad digest": func() error {
			_, err := lease.DecodeLeaseRequest([]byte(`{"runner_version":"1","image_digest":"sha256:zz","vantage":"v"}`))
			return err
		},
		"control char": func() error {
			_, err := lease.DecodeLeaseRequest([]byte(`{"runner_version":"1\n","image_digest":"` + digest + `","vantage":"v"}`))
			return err
		},
		"oversize": func() error {
			_, err := lease.DecodeLeaseRequest([]byte(strings.Repeat(" ", lease.MaxBody+1)))
			return err
		},
		"hb bad phase":    func() error { _, err := lease.DecodeHeartbeat([]byte(`{"attempt":1,"phase":"sleeping"}`)); return err },
		"hb zero attempt": func() error { _, err := lease.DecodeHeartbeat([]byte(`{"attempt":0,"phase":"running"}`)); return err },
		"hb unknown drop": func() error {
			_, err := lease.DecodeHeartbeat([]byte(`{"attempt":1,"phase":"running","egress":{"mars":1}}`))
			return err
		},
		"hb negative": func() error {
			_, err := lease.DecodeHeartbeat([]byte(`{"attempt":1,"phase":"running","egress":{"private":-1}}`))
			return err
		},
		"finish outcome": func() error { _, err := lease.DecodeFinish([]byte(`{"attempt":1,"outcome":"shrug"}`)); return err },
		"offer no target": func() error {
			_, err := lease.DecodeOffer([]byte(`{"job_id":1,"attempt":1,"token":"` + strings.Repeat("A", 43) + `","targets":[],"profile":{}}`))
			return err
		},
		"offer bad addr": func() error {
			_, err := lease.DecodeOffer([]byte(`{"job_id":1,"attempt":1,"token":"` + strings.Repeat("A", 43) + `","targets":[{"address":"nope"}],"profile":{}}`))
			return err
		},
		"offer port 0": func() error {
			_, err := lease.DecodeOffer([]byte(`{"job_id":1,"attempt":1,"token":"` + strings.Repeat("A", 43) + `","targets":[{"address":"203.0.113.10","ports":[0]}],"profile":{}}`))
			return err
		},
		"offer bad token": func() error {
			_, err := lease.DecodeOffer([]byte(`{"job_id":1,"attempt":1,"token":"short","targets":[{"address":"203.0.113.10"}],"profile":{}}`))
			return err
		},
	}
	for name, f := range bad {
		if err := f(); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestGoodBodiesDecode(t *testing.T) {
	if _, err := lease.DecodeLeaseRequest([]byte(`{"runner_version":"1","image_digest":"` + digest + `","vantage":"scan-1"}`)); err != nil {
		t.Error(err)
	}
	if h, err := lease.DecodeHeartbeat([]byte(`{"attempt":2,"phase":"uploading","egress":{"private":3}}`)); err != nil || h.Egress["private"] != 3 {
		t.Error(h, err)
	}
	if _, err := lease.DecodeFinish([]byte(`{"attempt":1,"outcome":"complete"}`)); err != nil {
		t.Error(err)
	}
	if _, err := lease.DecodeOffer([]byte(`{"job_id":1,"attempt":1,"token":"` + strings.Repeat("A", 43) + `","targets":[{"address":"203.0.113.10","ports":[80]}],"profile":{"id":"x"}}`)); err != nil {
		t.Error(err)
	}
}

func FuzzDecodeLeaseBodies(f *testing.F) {
	f.Add([]byte(`{"runner_version":"1","image_digest":"` + digest + `","vantage":"v"}`))
	f.Add([]byte(`{"attempt":1,"phase":"running","egress":{"private":1}}`))
	f.Add([]byte(`{"attempt":1,"outcome":"failed","reason":"x"}`))
	f.Add([]byte(`{"job_id":1,"attempt":1,"token":"` + strings.Repeat("A", 43) + `","targets":[{"address":"::1"}],"profile":{}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		// None may panic; a body that decodes must satisfy the rules the decoder promises.
		if r, err := lease.DecodeLeaseRequest(b); err == nil && !lease.ValidImageDigest(r.ImageDigest) {
			t.Fatal("a request with a bad digest decoded")
		}
		if h, err := lease.DecodeHeartbeat(b); err == nil && (h.Attempt < 1 || h.Phase == "") {
			t.Fatal("a heartbeat decoded without attempt or phase")
		}
		if fn, err := lease.DecodeFinish(b); err == nil && fn.Outcome == "" {
			t.Fatal("a finish decoded without an outcome")
		}
		if o, err := lease.DecodeOffer(b); err == nil && (len(o.Targets) == 0 || !lease.ValidToken(o.Token)) {
			t.Fatal("an offer decoded without targets or with a bad token")
		}
	})
}

func FuzzValidToken(f *testing.F) {
	f.Add(strings.Repeat("A", 43))
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		if lease.ValidToken(s) && len(s) != 43 {
			t.Fatal("a token of the wrong length is valid")
		}
	})
}
