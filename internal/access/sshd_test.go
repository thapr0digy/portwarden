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

// Assumption: sshd's rules are first value wins, keywords in any case, "=" or spaces (and
// "Keyword = value", one "=" skipped as OpenSSH's strdelim does), quoted arguments, Include
// in place in glob order, Match blocks not global.
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
AuthorizedPrincipalsFile = /etc/ssh/principals/%u
PasswordAuthentication	=	no
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
		AuthorizedPrincipalsFile: "/etc/ssh/principals/%u", AuthorizedPrincipalsCommand: true,
		PermitRootLogin: "without-password"}
	if cfg != want {
		t.Fatalf("cfg = %+v\nwant  %+v", cfg, want)
	}
}

// Assumption: OpenSSH skips one "=" after the keyword, not a second one, and keeps an "=" in
// an argument: "AuthorizedKeysFile = none" turns keys off.
func TestSSHDWordsSkipOneEquals(t *testing.T) {
	for line, want := range map[string]string{
		"AuthorizedKeysFile = none":      "AuthorizedKeysFile|none",
		"AuthorizedKeysFile=none":        "AuthorizedKeysFile|none",
		"AuthorizedKeysFile =none a=b":   "AuthorizedKeysFile|none|a=b",
		"AuthorizedKeysFile = = none":    "AuthorizedKeysFile|=|none",
		"AuthorizedKeysFile= =none":      "AuthorizedKeysFile|=none",
		"TrustedUserCAKeys \"=/etc/ca\"": "TrustedUserCAKeys|=/etc/ca",
	} {
		got, err := sshdWords(line)
		if err != nil || strings.Join(got, "|") != want {
			t.Errorf("%q: %q %v, want %s", line, got, err, want)
		}
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

// Assumption: sudo reads a user list last match first, a matching !item excluding the user
// (sudoers(5), "User_List"), through aliases too.
func TestSudoNegationExcludes(t *testing.T) {
	alice := user{name: "alice", uid: "1003", gid: "1003"}
	bob := user{name: "bob", uid: "1004", gid: "1004"}
	groups := groupDB{"admin": {gid: "110", members: []string{"alice", "bob"}}}
	for spec, want := range map[string][2]bool{
		"ALL, !alice ALL = ALL\n":                         {false, true},
		"%admin, !alice ALL = ALL\n":                      {false, true},
		"!alice, %admin ALL = ALL\n":                      {true, true},
		"User_Alias OPS = %admin, !bob\nOPS ALL = ALL\n":  {true, false},
		"User_Alias OPS = %admin, !bob\n!OPS ALL = ALL\n": {false, true},
		"User_Alias OPS = !alice\nALL, OPS ALL = ALL\n":   {false, true},
		"User_Alias OPS = !alice\nALL, !OPS ALL = ALL\n":  {true, true},
	} {
		p := &sudoPolicy{aliases: map[string][]string{}}
		p.parse(spec, func(bool, string) {})
		for i, u := range []user{alice, bob} {
			if got, _ := p.rule(u, groups); got.GetPresent() != want[i] {
				t.Errorf("%q: %s present %v, want %v", spec, u.name, got.GetPresent(), want[i])
			}
		}
	}
}

// Assumption: while part of the policy is unread, an item that may exclude the user but is
// defined there (an undefined User_Alias, a %group with /etc/group unread) makes presence
// unknown, not "present": sudo would read that definition, the agent cannot.
func TestSudoUnresolvableExclusionIsUnknown(t *testing.T) {
	alice := user{name: "alice", uid: "1003", gid: "1003"}
	admin := groupDB{"admin": {gid: "110", members: []string{"alice"}}}
	for _, c := range []struct {
		spec           string
		groups         groupDB
		present, known bool
	}{
		{"ALL, !ADMINS ALL = ALL\n", admin, false, false},
		{"ALL, !%admin ALL = ALL\n", nil, false, false},
		{"ALL, !%#110 ALL = ALL\n", nil, false, false},
		{"!ADMINS, ALL ALL = ALL\n", admin, true, true},
		{"ALL, !bob ALL = ALL\n", admin, true, true},
		{"ALL, !%admin ALL = ALL\n", admin, false, false},
	} {
		p := &sudoPolicy{aliases: map[string][]string{}}
		p.parse(c.spec, func(bool, string) {})
		p.noteUnread(errors.New("/etc/sudoers: permission denied"))
		if got, known := p.rule(alice, c.groups); got.GetPresent() != c.present || known != c.known {
			t.Errorf("%q groups=%v: present %v known %v, want %v %v", c.spec, c.groups != nil, got.GetPresent(), known, c.present, c.known)
		}
	}
	p := &sudoPolicy{aliases: map[string][]string{}}
	p.parse("ALL, !ADMINS ALL = ALL\n", func(bool, string) {})
	if got, known := p.rule(alice, admin); !got.GetPresent() || !known {
		t.Errorf("with the whole policy read, an undefined alias names nobody: %v %v", got, known)
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
