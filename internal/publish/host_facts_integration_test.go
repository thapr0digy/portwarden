//go:build integration && linux

package publish_test

import (
	"os"
	"strings"
	"testing"

	"github.com/thapr0digy/portwarden/internal/access"
	"github.com/thapr0digy/portwarden/internal/dpkg"
)

// In the dev VM (make itest; README "Host packages"): the agent's host-fact readers on this
// host's own files send both host facts to Signal's reference door. Run it as an
// unprivileged user (sudo -u nobody, the binary and PORTWARDEN_SIGNAL_FIXTURES readable and
// writable by it) to see that no privilege is needed: the files are world-readable.
func TestHostFactsOfThisHostAreStoredBySignal(t *testing.T) {
	if _, err := os.Stat(dpkg.StatusFile); err != nil {
		t.Skipf("not a dpkg host: %v", err)
	}
	for _, name := range []string{dpkg.StatusFile, dpkg.OSRelease, access.SSHDConfig} {
		fi, err := os.Stat(name)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm()&0o004 == 0 {
			t.Errorf("%s is %v: the unprivileged agent cannot read it", name, fi.Mode().Perm())
		}
	}
	t.Logf("running as uid %d", os.Geteuid())

	ref, pub, sent := signalDoor(t, e2eHost)
	runHostFacts(t, os.DirFS("/"), ref, pub)
	acc, pkgs := storedHostFacts(t, ref)

	if !pkgs.GetRead() || pkgs.GetDistro().GetId() == "" || pkgs.GetTotal() < 100 || pkgs.GetTruncated() {
		t.Fatalf("packages: read %v, unreadable %q, distro %v, total %d, truncated %v",
			pkgs.GetRead(), pkgs.GetUnreadable(), pkgs.GetDistro(), pkgs.GetTotal(), pkgs.GetTruncated())
	}
	var ssh bool
	for _, p := range pkgs.GetPackages() {
		ssh = ssh || (p.GetName() == "openssh-server" && p.GetSource() == "openssh")
	}
	if !ssh {
		t.Error("openssh-server (source openssh) is not in the list")
	}
	s := acc.GetSshd()
	t.Logf("distro %v, %d packages; sshd read %v (%s), PasswordAuthentication %q, PermitRootLogin %q",
		pkgs.GetDistro(), len(pkgs.GetPackages()), s.GetRead(), s.GetUnreadable(), s.GetPasswordAuthentication(), s.GetPermitRootLogin())
	if s.GetRead() == (s.GetPasswordAuthentication() == "") || s.GetRead() == (s.GetPermitRootLogin() == "") {
		t.Fatalf("the settings are known exactly when sshd's configuration is read: %v", s)
	}
	recordSignalFixtures(t, "host-facts-"+pkgs.GetDistro().GetId()+"-"+strings.ReplaceAll(pkgs.GetDistro().GetVersionId(), ".", ""), sent)
}
