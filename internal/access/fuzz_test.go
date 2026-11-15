package access

import (
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/slidehq/signal/schema/eventsv1"
	"github.com/slidehq/signal/schema/validate"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/thapr0digy/portwarden/internal/fuzzcheck"
)

const fuzzHost = "0123456789abcdef0123456789abcdef"

// signalCheck fails t unless Signal's own validator takes data as an agent's event.
func signalCheck(t *testing.T, typ string, data any) {
	t.Helper()
	ev := &eventsv1.Event{Id: ulid.Make().String(), Type: typ, Time: timestamppb.Now(),
		Source: "urn:asm:agent:" + fuzzHost, Subject: "host:" + fuzzHost,
		Producer: &eventsv1.Producer{Name: "portwarden-agent", Version: "v1.0.0"},
		Sequence: &eventsv1.Sequence{RunId: ulid.Make().String(), Seq: 1, BootId: "boot-1", RunNumber: 1}}
	switch d := data.(type) {
	case *eventsv1.HostAccess:
		ev.Data = &eventsv1.Event_HostAccess{HostAccess: d}
	case *eventsv1.SignInSummary:
		ev.Data = &eventsv1.Event_SignIns{SignIns: d}
	}
	if err := validate.Event(ev, validate.Options{}); err != nil {
		t.Fatalf("Signal refuses %s: %v\n%v", typ, err, data)
	}
}

// Assumption: what the agent builds passes Signal's validator (a refused event is lost).
func TestReportsPassSignalsValidator(t *testing.T) {
	a, _ := ReadHostAccess(ansibleHost(), []string{"root", "pants"})
	signalCheck(t, "asm.host.access", a)
	signalCheck(t, "asm.host.access", &eventsv1.HostAccess{Digest: a.GetDigest(), Unchanged: true})
	w := NewWindow(time.Now().Add(-time.Hour), SharedKeys{underpantsFP: "underpants"})
	for _, line := range []string{certLine, keyLine, "Accepted password for root from 192.0.2.1 port 2 ssh2"} {
		l, _ := ParseMessage(line)
		l.At = time.Now()
		w.Add(l)
	}
	signalCheck(t, "asm.host.sign_ins", w.Flush(time.Now()))
	signalCheck(t, "asm.host.sign_ins", &eventsv1.SignInSummary{WindowEnd: timestamppb.Now(), JournalUnreadable: true,
		Unreadable: clip(ErrJournalAccess.Error(), maxReasonBytes)})
}

// parseBudget bounds one parse of fuzzed configuration files (each at most 1 MiB).
var parseBudget = fuzzcheck.Budget{Time: 2 * time.Second, Base: 4 << 20, PerByte: 256}

// FuzzSSHDConfig feeds sshd_config, an included file, the CA keys file, a principals file
// and a sudoers drop-in, all host-controlled text, to the readers: they must never panic,
// stay bounded, and what they build must pass Signal's validator.
func FuzzSSHDConfig(f *testing.F) {
	h := ansibleHost()
	for _, name := range []string{"etc/ssh/sshd_config", "etc/ssh/sshd_config.d/10-vault.conf"} {
		f.Add(string(h.files[name].Data), string(h.files["etc/ssh/ssh_trusted_user_ca_keys"].Data), "pants\n", "pants ALL=(ALL) NOPASSWD: ALL\n")
	}
	f.Add("AuthorizedKeysFile = none\nAuthorizedPrincipalsFile= =x\nTrustedUserCAKeys = /etc/ssh/ca\n", "ssh-ed25519 AAAA\n", "pants\n", "ALL, !pants ALL = NOPASSWD: ALL\n")
	f.Add("Include x\nMatch all\nAuthorizedKeysFile \"a b\" c=d\n", "ssh-ed25519 AAAA\n", "from=\"x y\" p\n", "User_Alias A = %b, #1\nA ALL = ALL\n")
	f.Fuzz(func(t *testing.T, config, ca, principals, sudoers string) {
		h := fsOf(map[string]string{
			"etc/ssh/sshd_config":                   "Include /etc/ssh/sshd_config.d/*.conf\n" + config,
			"etc/ssh/sshd_config.d/10-a.conf":       "TrustedUserCAKeys /etc/ssh/ca\nAuthorizedPrincipalsFile /etc/ssh/p/%u\n" + config,
			"etc/ssh/ca":                            ca,
			"etc/ssh/p/pants":                       principals,
			"home/pants/.ssh/authorized_principals": principals,
			"etc/passwd":                            "root:x:0:0::/root:/bin/sh\npants:x:1000:1000::/home/pants:/bin/sh\n",
			"etc/group":                             "b:x:5:pants\n",
			"etc/sudoers.d/pants":                   sudoers,
		})
		var a *eventsv1.HostAccess
		fuzzcheck.Bounded(t, parseBudget, len(config)*2+len(ca)+2*len(principals)+len(sudoers), func() {
			a, _ = ReadHostAccess(h, []string{"root", "pants"})
		})
		signalCheck(t, "asm.host.access", a)
	})
}

// FuzzJournalEntry feeds journalctl's JSON lines (sshd's messages carry client-chosen text:
// the user name, the key ID) to the parser and the window: never a panic, and every
// summary passes Signal's validator.
func FuzzJournalEntry(f *testing.F) {
	now := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)
	for _, line := range []string{certLine, keyLine, "Accepted password for root from ::1 port 1 ssh2", "Accepted none for x from y port z"} {
		f.Add(entryJSON("ssh.service", "0", line, now, "s=1"))
	}
	f.Add([]byte(`{"MESSAGE":[1,2],"__CURSOR":7}`))
	f.Fuzz(func(t *testing.T, line []byte) {
		w := NewWindow(now.Add(-time.Hour), SharedKeys{underpantsFP: "underpants"})
		fuzzcheck.Bounded(t, parseBudget, len(line), func() {
			if _, l, ok := ParseEntry(line); ok {
				w.Add(l)
			}
		})
		signalCheck(t, "asm.host.sign_ins", w.Flush(now))
	})
}
