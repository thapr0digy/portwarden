package access

import (
	"errors"
	"strings"
	"testing"
)

func TestReadSSHDDefaults(t *testing.T) {
	cfg, err := ReadSSHD(fsOf(map[string]string{"etc/ssh/sshd_config": "# nothing set\n"}), SSHDConfig)
	if err != nil {
		t.Fatal(err)
	}
	if cfg != (SSHD{PasswordAuthentication: true, PermitRootLogin: "prohibit-password"}) {
		t.Fatalf("defaults = %+v", cfg)
	}
}

// Assumption: sshd's rules are first value wins, keywords in any case, "=" or spaces,
// quoted arguments, Include in place in glob order, Match blocks not global.
func TestReadSSHDFollowsSSHDsRules(t *testing.T) {
	h := fsOf(map[string]string{
		"etc/ssh/sshd_config": `authorizedKeysFile=".ssh/authorized_keys" .ssh/keys2
Include conf.d/*.conf
Match Address 10.0.0.0/8
  TrustedUserCAKeys /etc/ssh/match_ca
  PasswordAuthentication no
Match all
AuthorizedPrincipalsCommand /usr/bin/principals %u
AuthorizedPrincipalsCommandUser nobody
TrustedUserCAKeys /etc/ssh/late_ca
`,
		"etc/ssh/conf.d/20-b.conf": "TRUSTEDUSERCAKEYS /etc/ssh/b_ca\nPermitRootLogin Without-Password\n",
		"etc/ssh/conf.d/10-a.conf": "TrustedUserCAKeys \"/etc/ssh/a ca\"\nMatch User x\nPermitRootLogin yes\n",
	})
	cfg, err := ReadSSHD(h, SSHDConfig)
	if err != nil {
		t.Fatal(err)
	}
	want := SSHD{TrustedUserCAKeys: "/etc/ssh/a ca", AuthorizedKeysFile: ".ssh/authorized_keys .ssh/keys2",
		AuthorizedPrincipalsCommand: true, PasswordAuthentication: true, PermitRootLogin: "without-password"}
	if cfg != want {
		t.Fatalf("cfg = %+v\nwant  %+v", cfg, want)
	}
}

func TestReadSSHDRefusesWhatSSHDRefuses(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"no argument":   {"etc/ssh/sshd_config": "TrustedUserCAKeys\n"},
		"open quote":    {"etc/ssh/sshd_config": "TrustedUserCAKeys \"/x\n"},
		"include loop":  {"etc/ssh/sshd_config": "Include /etc/ssh/a\n", "etc/ssh/a": "Include /etc/ssh/sshd_config\n"},
		"include depth": {"etc/ssh/sshd_config": "Include /etc/ssh/sshd_config\n"},
	} {
		if _, err := ReadSSHD(fsOf(files), SSHDConfig); !errors.Is(err, ErrConfig) {
			t.Errorf("%s: err = %v, want ErrConfig", name, err)
		}
	}
	if _, err := ReadSSHD(fsOf(nil), SSHDConfig); err == nil || !strings.Contains(err.Error(), "/etc/ssh/sshd_config") {
		t.Errorf("missing config: err = %v", err)
	}
	big := fsOf(map[string]string{"etc/ssh/sshd_config": strings.Repeat("#", maxFileBytes+1)})
	if _, err := ReadSSHD(big, SSHDConfig); err == nil {
		t.Error("a config over the size bound must not be read")
	}
	// An Include that matches nothing is fine, as in sshd.
	if _, err := ReadSSHD(fsOf(map[string]string{"etc/ssh/sshd_config": "Include /etc/ssh/none.d/*.conf\n"}), SSHDConfig); err != nil {
		t.Errorf("empty include: %v", err)
	}
}

func TestSudoPolicy(t *testing.T) {
	pants := user{name: "pants", uid: "1000", gid: "1000"}
	ops := user{name: "ops", uid: "1001", gid: "1001"}
	groups := groupDB{"admin": {gid: "110", members: []string{"ops"}}, "pants": {gid: "1000"}}
	p := &sudoPolicy{aliases: map[string][]string{}}
	p.parse(`Defaults env_reset
Defaults:pants !requiretty
User_Alias DEPLOYERS = pants, \
    deploy
Cmnd_Alias RESTART = /bin/systemctl restart *
# pants ALL=(ALL) NOPASSWD: ALL   (a comment)
DEPLOYERS ALL = (root) NOPASSWD: RESTART , PASSWD: /bin/ls
%admin ALL=(ALL:ALL) TIMEOUT=10 ALL
#1000 ALL = SETENV: NOPASSWD: /bin/true
!ops ALL = ALL
`, func(bool, string) {})
	got, known := p.rule(pants, groups)
	if !known || !got.GetPresent() || !got.GetNopasswd() || got.GetAllCommands() {
		t.Fatalf("pants = %v %v", got, known)
	}
	got, known = p.rule(ops, groups)
	if !known || !got.GetPresent() || got.GetNopasswd() || !got.GetAllCommands() {
		t.Fatalf("ops = %v %v", got, known)
	}
	got, known = p.rule(user{name: "carol", uid: "1002", gid: "1002"}, groups)
	if !known || got.GetPresent() {
		t.Fatalf("carol = %v %v", got, known)
	}
	p.noteUnread(errors.New("/etc/sudoers: permission denied"))
	if _, known := p.rule(user{name: "carol"}, groups); known {
		t.Fatal("no rule seen while a file is unread is not none")
	}
	if _, known := p.rule(pants, groups); !known {
		t.Fatal("a rule seen is present whatever else is unread")
	}
}

func TestSudoIncludes(t *testing.T) {
	h := fsOf(map[string]string{
		"etc/sudoers":      "#includedir /etc/sudoers.d\n@include extra\n",
		"etc/extra":        "ops ALL = ALL\n",
		"etc/sudoers.d/a":  "pants ALL = NOPASSWD: ALL\n",
		"etc/sudoers.d/b.": "carol ALL = ALL\n",
	})
	p := readSudoPolicy(h)
	for name, want := range map[string]bool{"pants": true, "ops": true, "carol": false} {
		if got, known := p.rule(user{name: name}, groupDB{}); !known || got.GetPresent() != want {
			t.Errorf("%s: %v %v, want present %v", name, got, known, want)
		}
	}
}
