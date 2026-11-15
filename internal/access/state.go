package access

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/slidehq/signal/schema/eventsv1"
	"google.golang.org/protobuf/proto"
)

const (
	passwdFile = "/etc/passwd"
	groupFile  = "/etc/group"
	// maxPrincipals is Signal's cap on an account's principals (AccountAccess.principals).
	maxPrincipals = 256
	// maxReasonBytes is Signal's cap on an unreadable reason.
	maxReasonBytes = 256
	// maxStringBytes is Signal's default cap on a string field.
	maxStringBytes = 1024
)

// MaxAccounts is Signal's cap on the accounts one access state reports.
const MaxAccounts = 64

// accountRe is a POSIX user name, as Signal checks it.
var accountRe = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)

// ValidAccount reports whether name is a user name Signal takes.
func ValidAccount(name string) bool { return accountRe.MatchString(name) }

// errKeysNotRead is why static keys are never read: authorized_keys lives in each user's
// home, readable by that user and root only, and the agent holds no capability to bypass
// file permissions.
var errKeysNotRead = errors.New("authorized_keys is not read: it needs a privilege the agent does not hold")

// ReadHostAccess reads the host's SSH access state from root (the host's file system,
// rooted at "/") for the named accounts (an account the host does not have is left out),
// with its digest set, and the sshd settings it read (the zero value when it could not).
// Every part says whether it could be read; nothing here fails.
func ReadHostAccess(root fs.FS, accounts []string) (*eventsv1.HostAccess, SSHD) {
	cfg, sshd := readSSHDState(root)
	out := &eventsv1.HostAccess{Sshd: sshd}
	users, usersErr := readUsers(root)
	groups, groupsErr := readGroups(root)
	policy := readSudoPolicy(root)
	if groupsErr != nil {
		policy.noteUnread(groupsErr) // a %group rule cannot be matched
	}
	for _, name := range accounts {
		if usersErr != nil {
			out.Accounts = append(out.Accounts, &eventsv1.AccountAccess{Account: name, Unreadable: reason(usersErr)})
			continue
		}
		u, ok := users[name]
		if !ok {
			continue
		}
		out.Accounts = append(out.Accounts, accountAccess(root, cfg, sshd.GetRead(), u, policy, groups))
	}
	slices.SortFunc(out.Accounts, func(a, b *eventsv1.AccountAccess) int { return strings.Compare(a.GetAccount(), b.GetAccount()) })
	out.Accounts = slices.CompactFunc(out.Accounts, func(a, b *eventsv1.AccountAccess) bool { return a.GetAccount() == b.GetAccount() })
	out.Digest = Digest(out)
	return out, cfg
}

// Digest is the lowercase hex SHA-256 of the deterministic encoding of a's sshd and
// accounts (Signal's HostAccess.digest).
func Digest(a *eventsv1.HostAccess) string {
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(&eventsv1.HostAccess{Sshd: a.GetSshd(), Accounts: a.GetAccounts()})
	if err != nil {
		// Marshalling a well-formed message cannot fail; an empty digest makes it a full send.
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// readSSHDState reads sshd's configuration and its CA keys.
func readSSHDState(root fs.FS) (SSHD, *eventsv1.Sshd) {
	cfg, err := ReadSSHD(root, SSHDConfig)
	if err != nil {
		return cfg, &eventsv1.Sshd{Unreadable: reason(err)}
	}
	out := &eventsv1.Sshd{
		Read:                        true,
		AuthorizedKeysFile:          clip(cfg.AuthorizedKeysFile, maxReasonBytes),
		AuthorizedPrincipalsFile:    clip(cfg.AuthorizedPrincipalsFile, maxReasonBytes),
		AuthorizedPrincipalsCommand: cfg.AuthorizedPrincipalsCommand,
	}
	if cfg.TrustedUserCAKeys != "" {
		keys, err := readCAKeys(root, cfg.TrustedUserCAKeys)
		if err != nil {
			return cfg, &eventsv1.Sshd{Unreadable: reason(fmt.Errorf("TrustedUserCAKeys %w", err))}
		}
		out.TrustedUserCaKeys = keys
	}
	return cfg, out
}

func accountAccess(root fs.FS, cfg SSHD, sshdRead bool, u user, policy *sudoPolicy, groups groupDB) *eventsv1.AccountAccess {
	a := &eventsv1.AccountAccess{Account: u.name}
	var why []string
	switch {
	case !sshdRead:
		why = append(why, "sshd's configuration could not be read")
	default:
		principals, err := readPrincipals(root, cfg.AuthorizedPrincipalsFile, u)
		if err != nil {
			why = append(why, err.Error())
		} else {
			a.PrincipalsRead, a.Principals = true, principals
		}
	}
	if sshdRead && cfg.AuthorizedKeysFile == "none" && !cfg.AuthorizedKeysCommand {
		a.StaticKeysRead = true // keys are off for everyone
	} else {
		why = append(why, errKeysNotRead.Error())
	}
	if rule, known := policy.rule(u, groups); known {
		a.SudoRead, a.Sudo = true, rule
	} else {
		why = append(why, "sudo: "+policy.unread.Error())
	}
	a.Unreadable = clip(strings.Join(why, "; "), maxReasonBytes)
	return a
}

// readPrincipals reads the account's AuthorizedPrincipalsFile. No file configured, or none
// at the path, is a known empty list (sshd then accepts no principal from a file).
func readPrincipals(root fs.FS, setting string, u user) ([]string, error) {
	if setting == "" || setting == "none" {
		return nil, nil
	}
	name, err := expandTokens(setting, u)
	if err != nil {
		return nil, err
	}
	data, err := readFile(root, name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return parsePrincipals(string(data)), nil
}

// expandTokens expands sshd's %%, %h, %u and %U in a per-user path; a relative result is
// relative to the user's home.
func expandTokens(setting string, u user) (string, error) {
	var b strings.Builder
	for i := 0; i < len(setting); i++ {
		if setting[i] != '%' {
			b.WriteByte(setting[i])
			continue
		}
		if i++; i == len(setting) {
			return "", fmt.Errorf("AuthorizedPrincipalsFile %q ends in %%", setting)
		}
		switch setting[i] {
		case '%':
			b.WriteByte('%')
		case 'h':
			b.WriteString(u.home)
		case 'u':
			b.WriteString(u.name)
		case 'U':
			b.WriteString(u.uid)
		default:
			return "", fmt.Errorf("AuthorizedPrincipalsFile %q: unknown token %%%c", setting, setting[i])
		}
	}
	p := b.String()
	if !strings.HasPrefix(p, "/") {
		p = strings.TrimSuffix(u.home, "/") + "/" + p
	}
	return p, nil
}

// parsePrincipals reads a principals file: one principal per line, optionally after
// authorized_keys-style options; "#" comments. At most 256, each once.
func parsePrincipals(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if rest := skipOptions(line); rest != "" {
			line = rest
		}
		if line == "" || len(line) > maxStringBytes || !utf8.ValidString(line) || strings.ContainsFunc(line, isControl) ||
			slices.Contains(out, line) {
			continue
		}
		if out = append(out, line); len(out) == maxPrincipals {
			break
		}
	}
	return out
}

// skipOptions returns what follows a leading options word (outside double quotes), or ""
// when the line is one word.
func skipOptions(line string) string {
	quoted := false
	for i := 0; i < len(line); i++ {
		switch c := line[i]; {
		case c == '\\' && quoted && i+1 < len(line):
			i++
		case c == '"':
			quoted = !quoted
		case !quoted && (c == ' ' || c == '\t'):
			return strings.TrimSpace(line[i:])
		}
	}
	return ""
}

func isControl(r rune) bool { return r < ' ' || r == 0x7f }

// user is one /etc/passwd entry.
type user struct{ name, uid, gid, home string }

func readUsers(root fs.FS) (map[string]user, error) {
	data, err := readFile(root, passwdFile)
	if err != nil {
		return nil, err
	}
	out := map[string]user{}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 7 || f[0] == "" {
			continue
		}
		if _, dup := out[f[0]]; !dup {
			out[f[0]] = user{name: f[0], uid: f[2], gid: f[3], home: f[5]}
		}
	}
	return out, nil
}

type group struct {
	gid     string
	members []string
}

// groupDB is /etc/group by name.
type groupDB map[string]group

func readGroups(root fs.FS) (groupDB, error) {
	data, err := readFile(root, groupFile)
	if err != nil {
		return groupDB{}, err
	}
	out := groupDB{}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 4 || f[0] == "" {
			continue
		}
		if _, dup := out[f[0]]; !dup {
			out[f[0]] = group{gid: f[2], members: strings.Split(f[3], ",")}
		}
	}
	return out, nil
}

// member reports whether u is in the named group (as its primary group or a listed member).
func (g groupDB) member(name string, u user) bool {
	grp, ok := g[name]
	return ok && (grp.gid == u.gid || slices.Contains(grp.members, u.name))
}

// gidsOf is the ids of the groups that list u as a member.
func (g groupDB) gidsOf(u user) []string {
	var out []string
	for _, grp := range g {
		if slices.Contains(grp.members, u.name) {
			out = append(out, grp.gid)
		}
	}
	return out
}

// reason is an error as an unreadable reason: at most 256 bytes.
func reason(err error) string { return clip(err.Error(), maxReasonBytes) }

// clip makes host-controlled text fit for Signal: valid UTF-8, each control character
// (NUL included) as "?", at most n bytes cut at a character boundary.
func clip(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if isControl(r) {
			return '?'
		}
		return r
	}, strings.ToValidUTF8(s, ""))
	for len(s) > n {
		_, size := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-size]
	}
	return s
}
