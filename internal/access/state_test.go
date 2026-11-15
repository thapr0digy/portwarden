package access

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/slidehq/signal/schema/eventsv1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func accountOf(t *testing.T, a *eventsv1.HostAccess, name string) *eventsv1.AccountAccess {
	t.Helper()
	for _, acc := range a.GetAccounts() {
		if acc.GetAccount() == name {
			return acc
		}
	}
	t.Fatalf("no account %s in %v", name, a)
	return nil
}

// The Ansible host, read without privileges: sshd's trust from its drop-in, pants's
// principals and sudo rule from 0644 files, no authorized_keys, root's sudo unknown.
func TestReadHostAccessOnAnAnsibleHost(t *testing.T) {
	a, sshd := ReadHostAccess(ansibleHost(), []string{"root", "pants", "nobody-here", "pants"})
	want := &eventsv1.Sshd{Read: true,
		TrustedUserCaKeys: []*eventsv1.TrustedKey{
			{Fingerprint: caVaultFP, Label: "vault ssh/prod"},
			{Fingerprint: caLocalFP, Label: "host-local"},
		},
		AuthorizedPrincipalsFile: "/etc/ssh/authorized_principals/%u",
	}
	if !proto.Equal(a.GetSshd(), want) {
		t.Fatalf("sshd = %v\nwant %v", a.GetSshd(), want)
	}
	if sshd.PasswordAuthentication || sshd.PermitRootLogin != "no" {
		t.Fatalf("the drop-in's settings come first: %+v", sshd)
	}
	if len(a.GetAccounts()) != 2 || a.GetAccounts()[0].GetAccount() != "pants" {
		t.Fatalf("accounts: each existing one once, sorted: %v", a.GetAccounts())
	}
	pants := accountOf(t, a, "pants")
	if !pants.GetPrincipalsRead() || strings.Join(pants.GetPrincipals(), ",") != "pants,deploy" {
		t.Fatalf("pants principals = %v", pants)
	}
	if pants.GetStaticKeysRead() || len(pants.GetStaticKeys()) != 0 {
		t.Fatalf("authorized_keys is never read: %v", pants)
	}
	if !pants.GetSudoRead() || !proto.Equal(pants.GetSudo(), &eventsv1.SudoRule{Present: true, Nopasswd: true, AllCommands: true}) {
		t.Fatalf("pants sudo = %v", pants)
	}
	root := accountOf(t, a, "root")
	if !root.GetPrincipalsRead() || len(root.GetPrincipals()) != 0 {
		t.Fatalf("no principals file for root is a known empty list: %v", root)
	}
	if root.GetSudoRead() || !strings.Contains(root.GetUnreadable(), "/etc/sudoers: permission denied") ||
		!strings.Contains(root.GetUnreadable(), "authorized_keys is not read") {
		t.Fatalf("root's sudo cannot be told while /etc/sudoers is unreadable: %v", root)
	}
	if a.GetDigest() != Digest(a) || len(a.GetDigest()) != 64 {
		t.Fatalf("digest = %q", a.GetDigest())
	}
}

// Assumption: nothing the report carries is a key, a rule's text or a principal file line
// other than the principal; checked on the JSON Signal would store.
func TestHostAccessCarriesNoKeyOrRuleText(t *testing.T) {
	a, _ := ReadHostAccess(ansibleHost(), []string{"root", "pants"})
	js, err := protojson.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"AAAAC3Nza", "AAAAB3Nza", "NOPASSWD", "ALL=", "from=", "10.0.0.0/8"} {
		if strings.Contains(string(js), secret) {
			t.Fatalf("the report carries %q: %s", secret, js)
		}
	}
}

// Assumption: the digest moves only when the access state does, and is the same for the
// same state whatever the order the accounts were asked in.
func TestDigestFollowsTheState(t *testing.T) {
	h := ansibleHost()
	a1, _ := ReadHostAccess(h, []string{"root", "pants"})
	a2, _ := ReadHostAccess(h, []string{"pants", "root"})
	if a1.GetDigest() != a2.GetDigest() {
		t.Fatal("same state, different digest")
	}
	h.write("etc/ssh/authorized_principals/pants", "pants\nintruder\n")
	a3, _ := ReadHostAccess(h, []string{"root", "pants"})
	if a3.GetDigest() == a1.GetDigest() {
		t.Fatal("a principal added, same digest")
	}
}

func TestUnreadableSSHDConfigIsNotNone(t *testing.T) {
	h := ansibleHost()
	h.deny["etc/ssh/ssh_trusted_user_ca_keys"] = true
	a, _ := ReadHostAccess(h, []string{"pants"})
	if a.GetSshd().GetRead() || !strings.Contains(a.GetSshd().GetUnreadable(), "permission denied") ||
		len(a.GetSshd().GetTrustedUserCaKeys()) != 0 {
		t.Fatalf("an unreadable CA file is an unread sshd: %v", a.GetSshd())
	}
	if p := accountOf(t, a, "pants"); p.GetPrincipalsRead() {
		t.Fatalf("principals cannot be told without sshd's configuration: %v", p)
	}
	h.deny["etc/ssh/sshd_config"] = true
	a, _ = ReadHostAccess(h, []string{"pants"})
	if a.GetSshd().GetRead() || !strings.Contains(a.GetSshd().GetUnreadable(), "/etc/ssh/sshd_config: permission denied") {
		t.Fatalf("sshd = %v", a.GetSshd())
	}
}

func TestUnreadablePasswdReportsEveryAccountUnread(t *testing.T) {
	h := ansibleHost()
	h.deny["etc/passwd"] = true
	a, _ := ReadHostAccess(h, []string{"pants"})
	p := accountOf(t, a, "pants")
	if p.GetPrincipalsRead() || p.GetSudoRead() || !strings.Contains(p.GetUnreadable(), "/etc/passwd") {
		t.Fatalf("pants = %v", p)
	}
}

func TestKeysOffAreKnown(t *testing.T) {
	h := ansibleHost()
	h.write("etc/ssh/sshd_config.d/20-nokeys.conf", "AuthorizedKeysFile none\n")
	a, _ := ReadHostAccess(h, []string{"pants"})
	if !accountOf(t, a, "pants").GetStaticKeysRead() || a.GetSshd().GetAuthorizedKeysFile() != "none" {
		t.Fatalf("keys off: %v", a)
	}
	h.write("etc/ssh/sshd_config.d/05-cmd.conf", "AuthorizedKeysCommand /usr/bin/keys %u\n")
	a, _ = ReadHostAccess(h, []string{"pants"})
	if accountOf(t, a, "pants").GetStaticKeysRead() {
		t.Fatal("an AuthorizedKeysCommand can still supply keys")
	}
}

func TestPrincipalsPath(t *testing.T) {
	u := user{name: "pants", uid: "1000", home: "/home/pants"}
	for setting, want := range map[string]string{
		"/etc/ssh/principals/%u":   "/etc/ssh/principals/pants",
		".ssh/principals":          "/home/pants/.ssh/principals",
		"%h/.p_%U%%":               "/home/pants/.p_1000%",
		"/etc/ssh/auth_principals": "/etc/ssh/auth_principals",
	} {
		if got, err := expandTokens(setting, u); err != nil || got != want {
			t.Errorf("%s: %q, %v; want %q", setting, got, err, want)
		}
	}
	for _, bad := range []string{"/etc/%x", "/etc/%"} {
		if _, err := expandTokens(bad, u); err == nil {
			t.Errorf("%s: want an error", bad)
		}
	}
}

func TestParsePrincipals(t *testing.T) {
	got := parsePrincipals("a\n\n  # c\nb\ncommand=\"echo x y\",from=\"1.2.3.4\" c\na\nbad\x01one\n")
	if strings.Join(got, ",") != "a,b,c" {
		t.Fatalf("principals = %q", got)
	}
	var many strings.Builder
	for i := range 300 {
		many.WriteString(strings.Repeat("p", i%5+1) + string(rune('a'+i%26)) + strings.Repeat("x", i) + "\n")
	}
	if n := len(parsePrincipals(many.String())); n != maxPrincipals {
		t.Fatalf("principals cut at %d, want %d", n, maxPrincipals)
	}
}

func TestFingerprint(t *testing.T) {
	keys := parseCAKeys(caVault + "\n" + caLocal + "\n")
	if len(keys) != 2 || keys[0].GetFingerprint() != caVaultFP || keys[1].GetFingerprint() != caLocalFP {
		t.Fatalf("keys = %v", keys)
	}
	f := strings.Fields(caVault)
	if _, err := Fingerprint("ssh-rsa", f[1]); err == nil {
		t.Fatal("a key blob of another type must not fingerprint")
	}
	if label(strings.Repeat("é", 40)+"\x07") != strings.Repeat("é", 32) {
		t.Fatalf("label = %q", label(strings.Repeat("é", 40)))
	}
}

func TestParseSharedKeys(t *testing.T) {
	keys, err := ParseSharedKeys("# reviewed 2026-11-14\nunderpants " + underpantsFP + "\n\npants " + caVaultFP + "\n")
	if err != nil || keys[underpantsFP] != "underpants" || keys[caVaultFP] != "pants" {
		t.Fatalf("keys = %v, %v", keys, err)
	}
	for _, bad := range []string{
		caVault,                                     // a public key, not a fingerprint
		"-----BEGIN OPENSSH PRIVATE KEY-----",       // private material
		"underpants " + underpantsFP + " extra",     // more than two words
		"a " + underpantsFP + "\nb " + underpantsFP, // one key, two names
		"bad/name " + underpantsFP,                  // a name outside the alphabet
	} {
		_, err := ParseSharedKeys(bad)
		if err == nil {
			t.Errorf("%q: want an error", bad)
			continue
		}
		if strings.Contains(err.Error(), "BEGIN") || strings.Contains(err.Error(), "AAAA") {
			t.Errorf("the error echoes the line: %v", err)
		}
	}
}

// fsOf is a host with only the given files.
func fsOf(files map[string]string) *hostFS {
	m := fstest.MapFS{}
	for k, v := range files {
		m[k] = &fstest.MapFile{Data: []byte(v)}
	}
	return &hostFS{files: m, deny: map[string]bool{}}
}
