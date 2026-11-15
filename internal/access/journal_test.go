package access

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/slidehq/signal/schema/eventsv1"
)

// entryJSON is a journal record as journalctl --output=json prints it.
func entryJSON(unit, uid, msg string, at time.Time, cursor string) []byte {
	b, _ := json.Marshal(map[string]string{"MESSAGE": msg, "_SYSTEMD_UNIT": unit, "_UID": uid,
		"__REALTIME_TIMESTAMP": fmt.Sprint(at.UnixMicro()), "__CURSOR": cursor})
	return b
}

const (
	certLine = "Accepted publickey for pants from 192.0.2.10 port 51234 ssh2: ED25519-CERT " + underpantsFP +
		" ID oidc-ada@example.com (serial 7340021) CA ED25519 " + caVaultFP
	keyLine = "Accepted publickey for pants from ::ffff:192.0.2.20 port 22 ssh2: ED25519 " + underpantsFP
)

// Assumption: attribution comes from the key ID sshd logs (ID oidc-<email> (serial N) CA
// <alg> <fp>), not from a join; a plain key from its fingerprint.
func TestParseMessage(t *testing.T) {
	for line, want := range map[string]Login{
		certLine: {Account: "pants", Method: eventsv1.SignInGroup_CERTIFICATE, KeyID: "oidc-ada@example.com",
			Serial: "7340021", CAFingerprint: caVaultFP, FromIP: "192.0.2.10"},
		certLine + ", verified": {Account: "pants", Method: eventsv1.SignInGroup_CERTIFICATE, KeyID: "oidc-ada@example.com",
			Serial: "7340021", CAFingerprint: caVaultFP, FromIP: "192.0.2.10"},
		keyLine: {Account: "pants", Method: eventsv1.SignInGroup_KEY, KeyFingerprint: underpantsFP, FromIP: "192.0.2.20"},
		"Accepted password for root from 2001:db8::1 port 2 ssh2": {Account: "root", Method: eventsv1.SignInGroup_PASSWORD,
			FromIP: "2001:db8::1"},
		"Accepted keyboard-interactive/pam for ops from fe80::1%eth0 port 2 ssh2": {Account: "ops",
			Method: eventsv1.SignInGroup_OTHER, FromIP: "fe80::1"},
		// A key ID Signal would refuse (a space) is dropped, never sent: not tied to a person.
		strings.Replace(certLine, "oidc-ada@example.com", "oidc-ada x", 1): {Account: "pants",
			Method: eventsv1.SignInGroup_CERTIFICATE, Serial: "7340021", CAFingerprint: caVaultFP, FromIP: "192.0.2.10"},
		strings.Replace(certLine, "(serial 7340021)", "(serial -1)", 1): {Account: "pants",
			Method: eventsv1.SignInGroup_CERTIFICATE, KeyID: "oidc-ada@example.com", CAFingerprint: caVaultFP, FromIP: "192.0.2.10"},
		"Accepted publickey for pants from UNKNOWN port 65535 ssh2: ED25519 SHA256:short": {Account: "pants",
			Method: eventsv1.SignInGroup_KEY},
	} {
		got, ok := ParseMessage(line)
		if !ok || got != want {
			t.Errorf("%s\n got %+v %v\nwant %+v", line, got, ok, want)
		}
	}
	for _, line := range []string{
		"Failed password for root from 192.0.2.1 port 2 ssh2",
		"Failed publickey for invalid user admin from 192.0.2.1 port 2 ssh2",
		"Connection closed by 192.0.2.1 port 2",
		"Accepted publickey for pants",
		"Server listening on 0.0.0.0 port 22.",
	} {
		if l, ok := ParseMessage(line); ok {
			t.Errorf("%s: parsed as %+v", line, l)
		}
	}
}

// Assumption: only root's sshd unit can log a sign-in; a user's logger -t sshd cannot.
func TestParseEntryTrustsOnlySSHDsUnit(t *testing.T) {
	at := time.Date(2026, 11, 15, 10, 0, 0, 123000, time.UTC)
	cursor, l, ok := ParseEntry(entryJSON("ssh.service", "0", certLine, at, "s=1"))
	if !ok || cursor != "s=1" || !l.At.Equal(at) || l.KeyID != "oidc-ada@example.com" {
		t.Fatalf("%q %+v %v", cursor, l, ok)
	}
	if _, _, ok := ParseEntry(entryJSON("sshd.service", "0", certLine, at, "s=2")); !ok {
		t.Fatal("sshd.service is sshd's unit too")
	}
	for name, line := range map[string][]byte{
		"another unit":     entryJSON("user@1000.service", "0", certLine, at, "s=3"),
		"another uid":      entryJSON("ssh.service", "1000", certLine, at, "s=3"),
		"binary message":   []byte(`{"MESSAGE":[65,66],"_SYSTEMD_UNIT":"ssh.service","_UID":"0","__REALTIME_TIMESTAMP":"1","__CURSOR":"s=3"}`),
		"duplicated field": []byte(`{"MESSAGE":"x","_SYSTEMD_UNIT":["ssh.service","ssh.service"],"_UID":"0","__REALTIME_TIMESTAMP":"1","__CURSOR":"s=3"}`),
		"no time":          []byte(`{"MESSAGE":"` + certLine + `","_SYSTEMD_UNIT":"ssh.service","_UID":"0","__CURSOR":"s=3"}`),
		"year 292277":      []byte(`{"MESSAGE":"` + certLine + `","_SYSTEMD_UNIT":"ssh.service","_UID":"0","__REALTIME_TIMESTAMP":"9223372036854775807","__CURSOR":"s=3"}`),
	} {
		cursor, l, ok := ParseEntry(line)
		if ok || cursor != "s=3" {
			t.Errorf("%s: %q %+v %v", name, cursor, l, ok)
		}
	}
	if c, _, ok := ParseEntry([]byte("not json")); ok || c != "" {
		t.Error("garbage parsed")
	}
}

func TestWindowGroups(t *testing.T) {
	t0 := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)
	w := NewWindow(t0, SharedKeys{underpantsFP: "underpants"})
	cert, _ := ParseMessage(certLine)
	key, _ := ParseMessage(keyLine)
	other := key
	other.KeyFingerprint = caLocalFP // a person's own key: not on the reviewed list
	for i, l := range []Login{cert, cert, key, other} {
		l.At = t0.Add(time.Duration(i) * time.Minute)
		if i == 1 {
			l.Serial = "7340099"
		}
		w.Add(l)
	}
	bad := cert
	bad.Account, bad.At = "Admin", t0
	w.Add(bad)
	s := w.Flush(t0.Add(time.Hour))
	if len(s.GetGroups()) != 3 || s.GetDropped() != 1 {
		t.Fatalf("summary = %v", s)
	}
	g := s.GetGroups()[0]
	if g.GetCount() != 2 || g.GetSerial() != "7340099" || !g.GetFirstAt().AsTime().Equal(t0) ||
		!g.GetLastAt().AsTime().Equal(t0.Add(time.Minute)) {
		t.Fatalf("certificate group = %v", g)
	}
	if s.GetGroups()[1].GetKeyFingerprint() != underpantsFP || s.GetGroups()[2].GetKeyFingerprint() != "" {
		t.Fatalf("only the reviewed list's fingerprints leave the host: %v", s.GetGroups())
	}
	if !s.GetWindowStart().AsTime().Equal(t0) || !s.GetWindowEnd().AsTime().Equal(t0.Add(time.Hour)) {
		t.Fatalf("window = %v..%v", s.GetWindowStart().AsTime(), s.GetWindowEnd().AsTime())
	}
	if !w.Empty() {
		t.Fatal("flush starts a new window")
	}
	// A backlog sign-in older than the window, and a clock that stepped back.
	old := cert
	old.At = t0.Add(-time.Hour)
	w.Add(old)
	late := cert
	late.At = t0.Add(3 * time.Hour)
	w.Add(late)
	s = w.Flush(t0.Add(2 * time.Hour))
	if !s.GetWindowStart().AsTime().Equal(old.At) || !s.GetWindowEnd().AsTime().Equal(late.At) {
		t.Fatalf("window = %v..%v", s.GetWindowStart().AsTime(), s.GetWindowEnd().AsTime())
	}
}

// Assumption: memory is bounded however many distinct sign-ins a window sees.
func TestWindowCapsGroups(t *testing.T) {
	w := NewWindow(time.Unix(0, 0), nil)
	for i := range maxGroups + 10 {
		w.Add(Login{Account: "pants", Method: eventsv1.SignInGroup_PASSWORD, FromIP: fmt.Sprintf("10.0.%d.%d", i/256, i%256), At: time.Unix(1, 0)})
	}
	s := w.Flush(time.Unix(2, 0))
	if len(s.GetGroups()) != maxGroups || s.GetDropped() != 10 {
		t.Fatalf("groups %d dropped %d", len(s.GetGroups()), s.GetDropped())
	}
}

func TestTrustState(t *testing.T) {
	ca := []*eventsv1.TrustedKey{{Fingerprint: caVaultFP}}
	for _, c := range []struct {
		sshd    *eventsv1.Sshd
		cfg     SSHD
		keySeen bool
		want    string
	}{
		{&eventsv1.Sshd{}, SSHD{}, true, TrustUnknown},
		{&eventsv1.Sshd{Read: true, TrustedUserCaKeys: ca}, SSHD{}, true, TrustBoth},
		{&eventsv1.Sshd{Read: true, TrustedUserCaKeys: ca}, SSHD{}, false, TrustCertOrBoth},
		{&eventsv1.Sshd{Read: true, TrustedUserCaKeys: ca}, SSHD{AuthorizedKeysFile: "none"}, false, TrustCertOnly},
		{&eventsv1.Sshd{Read: true, TrustedUserCaKeys: ca}, SSHD{AuthorizedKeysFile: "none", AuthorizedKeysCommand: true}, false, TrustCertOrBoth},
		{&eventsv1.Sshd{Read: true}, SSHD{}, true, TrustKeyOnly},
		{&eventsv1.Sshd{Read: true}, SSHD{}, false, TrustKeyOnlyOrNot},
		{&eventsv1.Sshd{Read: true}, SSHD{AuthorizedKeysFile: "none"}, false, TrustNone},
		{&eventsv1.Sshd{Read: true}, SSHD{AuthorizedKeysFile: "none", AuthorizedKeysCommand: true}, false, TrustKeyOnlyOrNot},
	} {
		if got := TrustState(&eventsv1.HostAccess{Sshd: c.sshd}, c.cfg, c.keySeen); got != c.want {
			t.Errorf("%v %+v seen=%v: %s, want %s", c.sshd, c.cfg, c.keySeen, got, c.want)
		}
	}
}

// Assumption: journal reads are bounded: an over-long record is skipped whole and the
// next one still read.
func TestReadLinesSkipsLongLines(t *testing.T) {
	in := "a\n" + strings.Repeat("x", 3*maxLineBytes) + "\nb\nc"
	var got []string
	if err := readLines(strings.NewReader(in), func(l []byte) { got = append(got, string(l)) }); err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "a,b,c" {
		t.Fatalf("lines = %q", got)
	}
	var buf bytes.Buffer
	if err := readLines(&buf, func([]byte) { t.Fatal("no line") }); err != nil {
		t.Fatal(err)
	}
}
