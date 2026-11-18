// Package access reads who may sign in to the host over SSH and who did, without new
// privileges, for Signal's asm.host.access and asm.host.sign_ins (README "Host identity
// facts"): sshd's effective trust from its configuration files (never by running sshd), each
// account's principals file and sudo rule from world-readable files, and sshd's journal
// lines for accepted sign-ins. It never reads authorized_keys, a private key, a sudo rule's
// text or a command line, and never sends a public key: keys are SHA-256 fingerprints.
package access

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strings"
)

const (
	// SSHDConfig is sshd's main configuration file.
	SSHDConfig = "/etc/ssh/sshd_config"
	// maxFileBytes bounds every configuration file read (sshd_config, an Include, the CA
	// keys, a principals file, a sudoers file, passwd, group).
	maxFileBytes = 1 << 20
	// maxIncludeDepth is sshd's own limit on nested Include directives.
	maxIncludeDepth = 16
	// maxIncludedFiles bounds the files one configuration may pull in.
	maxIncludedFiles = 256
)

// SSHD is what sshd's configuration says, as far as this package reads it (README "Host
// identity facts"): PasswordAuthentication and PermitRootLogin are the most permissive value
// sshd applies to any connection (global, or any Match block); the others are global, read
// outside Match blocks only.
type SSHD struct {
	// TrustedUserCAKeys is the CA keys file ("" when unset or "none").
	TrustedUserCAKeys string
	// AuthorizedKeysFile is the setting as written ("none" turns keys off; "" is sshd's
	// default, .ssh/authorized_keys .ssh/authorized_keys2).
	AuthorizedKeysFile string
	// AuthorizedKeysCommand is true when a command can supply keys too.
	AuthorizedKeysCommand bool
	// AuthorizedPrincipalsFile is the setting as written ("" or "none" when unset).
	AuthorizedPrincipalsFile string
	// AuthorizedPrincipalsCommand is true when a command decides the principals.
	AuthorizedPrincipalsCommand bool
	// PasswordAuthentication is sshd's most permissive setting: "yes" (its default) or "no".
	PasswordAuthentication string
	// PermitRootLogin is sshd's most permissive setting: "yes", "prohibit-password" (its
	// default, also written without-password), "forced-commands-only" or "no".
	PermitRootLogin string
}

// The values sshd takes for the two settings (sshd_config(5); any case), each as reported.
// sshd refuses to start on any other.
var (
	passwordAuthValues = map[string]string{"yes": "yes", "no": "no"}
	rootLoginValues    = map[string]string{"yes": "yes", "prohibit-password": "prohibit-password",
		"without-password": "prohibit-password", "forced-commands-only": "forced-commands-only", "no": "no"}
	// permissiveness orders the reported values of both settings, least permissive first.
	permissiveness = map[string]int{"no": 0, "forced-commands-only": 1, "prohibit-password": 2, "yes": 3}
)

// keysOff reports whether sshd takes no plain keys from any account: AuthorizedKeysFile
// none and no AuthorizedKeysCommand.
func (c SSHD) keysOff() bool {
	return c.AuthorizedKeysFile == "none" && !c.AuthorizedKeysCommand
}

// ErrConfig marks a configuration sshd itself would refuse (a keyword with no argument, an
// Include loop or too deep): the trust it implies cannot be told.
var ErrConfig = errors.New("sshd configuration")

// ReadSSHD reads the sshd configuration at name (an absolute path) from root, the host's
// file system with "/" as its root, following Include directives as sshd does (globs,
// relative to /etc/ssh, in place, inside a Match block too). The first global value of a
// keyword wins; a Match block's PasswordAuthentication or PermitRootLogin counts when it is
// more permissive.
func ReadSSHD(root fs.FS, name string) (SSHD, error) {
	r := sshdReader{root: root, seen: map[string]bool{}, set: map[string]bool{}, matched: map[string]string{}}
	r.cfg = SSHD{PasswordAuthentication: "yes", PermitRootLogin: "prohibit-password"}
	if err := r.file(name, 0, false); err != nil {
		return SSHD{}, err
	}
	r.cfg.PasswordAuthentication = morePermissive(r.cfg.PasswordAuthentication, r.matched["passwordauthentication"])
	r.cfg.PermitRootLogin = morePermissive(r.cfg.PermitRootLogin, r.matched["permitrootlogin"])
	if r.cfg.TrustedUserCAKeys == "none" {
		r.cfg.TrustedUserCAKeys = ""
	}
	return r.cfg, nil
}

type sshdReader struct {
	root    fs.FS
	cfg     SSHD
	set     map[string]bool   // keywords already given a global value (the first wins)
	matched map[string]string // the most permissive value a Match block gives each setting
	seen    map[string]bool   // files on the current Include path (a loop is an error)
	files   int
}

// morePermissive is b when a Match block's b is more permissive than a.
func morePermissive(a, b string) string {
	if b != "" && permissiveness[b] > permissiveness[a] {
		return b
	}
	return a
}

func (r *sshdReader) file(name string, depth int, inMatch bool) error {
	if depth > maxIncludeDepth {
		return fmt.Errorf("%w: Include nested deeper than %d at %s", ErrConfig, maxIncludeDepth, name)
	}
	if r.seen[name] {
		return fmt.Errorf("%w: Include loop at %s", ErrConfig, name)
	}
	if r.files++; r.files > maxIncludedFiles {
		return fmt.Errorf("%w: more than %d included files", ErrConfig, maxIncludedFiles)
	}
	data, err := readFile(r.root, name)
	if err != nil {
		return err
	}
	r.seen[name] = true
	defer delete(r.seen, name)
	return r.parse(name, string(data), depth, inMatch)
}

// parse applies one file's lines, starting inside a Match block when an Include in one
// pulled the file in. A Match block ends at the next Match line ("Match all" returns to the
// global settings) or at the end of the file.
func (r *sshdReader) parse(name, text string, depth int, inMatch bool) error {
	for n, line := range strings.Split(text, "\n") {
		words, err := sshdWords(line)
		if err != nil {
			return fmt.Errorf("%w: %s line %d: %v", ErrConfig, name, n+1, err)
		}
		if len(words) == 0 {
			continue
		}
		key, args := strings.ToLower(words[0]), words[1:]
		if key == "match" {
			inMatch = !(len(args) == 1 && strings.EqualFold(args[0], "all"))
			continue
		}
		if len(args) == 0 {
			return fmt.Errorf("%w: %s line %d: %s has no argument", ErrConfig, name, n+1, words[0])
		}
		if key == "include" {
			if err := r.include(args, depth, inMatch); err != nil {
				return err
			}
			continue
		}
		if err := r.setting(key, args, inMatch); err != nil {
			return fmt.Errorf("%w: %s line %d: %v", ErrConfig, name, n+1, err)
		}
	}
	return nil
}

func (r *sshdReader) include(patterns []string, depth int, inMatch bool) error {
	for _, p := range patterns {
		if !path.IsAbs(p) {
			p = path.Join("/etc/ssh", p)
		}
		matches, err := fs.Glob(r.root, fsPath(p))
		if err != nil {
			return fmt.Errorf("%w: Include %s: %v", ErrConfig, p, err)
		}
		// fs.Glob sorts its matches, as sshd's glob(3) does.
		for _, m := range matches {
			if err := r.file("/"+m, depth+1, inMatch); err != nil {
				return err
			}
		}
	}
	return nil
}

// setting applies the first global value of a keyword this package reads; inside a Match
// block it keeps only the most permissive PasswordAuthentication and PermitRootLogin. A
// value sshd does not take for either is an error, as it is for sshd, in every occurrence
// (a later one sshd ignores, or one in a Match block, still stops it).
func (r *sshdReader) setting(key string, args []string, inMatch bool) error {
	var value string
	switch key {
	case "passwordauthentication", "permitrootlogin":
		values := passwordAuthValues
		if key == "permitrootlogin" {
			values = rootLoginValues
		}
		v, ok := values[strings.ToLower(args[0])]
		if !ok {
			return fmt.Errorf("%s %q is not a value sshd takes", key, args[0])
		}
		value = v
	}
	if inMatch {
		if value != "" {
			r.matched[key] = morePermissive(r.matched[key], value)
		}
		return nil
	}
	if r.set[key] {
		return nil
	}
	switch key {
	case "trustedusercakeys":
		r.cfg.TrustedUserCAKeys = args[0]
	case "authorizedkeysfile":
		r.cfg.AuthorizedKeysFile = strings.Join(args, " ")
	case "authorizedkeyscommand":
		r.cfg.AuthorizedKeysCommand = !strings.EqualFold(args[0], "none")
	case "authorizedprincipalsfile":
		r.cfg.AuthorizedPrincipalsFile = args[0]
	case "authorizedprincipalscommand":
		r.cfg.AuthorizedPrincipalsCommand = !strings.EqualFold(args[0], "none")
	case "passwordauthentication":
		r.cfg.PasswordAuthentication = value
	case "permitrootlogin":
		r.cfg.PermitRootLogin = value
	default:
		return nil
	}
	r.set[key] = true
	return nil
}

// sshdWords splits a configuration line as sshd does: a keyword, then arguments separated
// by white space (and at most one "=" between the keyword and the first argument), double
// quotes grouping, "#" starting a comment outside quotes.
func sshdWords(line string) ([]string, error) {
	var words []string
	var cur strings.Builder
	inWord, quoted, equalsSeen := false, false, false
	for i := 0; i < len(line); i++ {
		c := line[i]
		keywordEquals := c == '=' && !quoted && !equalsSeen && (len(words) == 0 || (len(words) == 1 && !inWord))
		if keywordEquals && (inWord || len(words) == 1) {
			equalsSeen = true
		}
		switch {
		case quoted && c == '"':
			quoted = false
		case quoted:
			cur.WriteByte(c)
		case c == '"':
			quoted, inWord = true, true
		case c == '#' && !inWord:
			i = len(line)
		case c == ' ' || c == '\t' || c == '\r' || keywordEquals:
			if inWord {
				words = append(words, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			cur.WriteByte(c)
			inWord = true
		}
	}
	if quoted {
		return nil, errors.New("unterminated quote")
	}
	if inWord {
		words = append(words, cur.String())
	}
	return words, nil
}

// fsPath is an absolute path as an fs.FS rooted at "/" names it.
func fsPath(p string) string {
	p = strings.TrimPrefix(path.Clean(p), "/")
	if p == "" {
		return "."
	}
	return p
}

// readFile reads an absolute path from root, at most maxFileBytes.
func readFile(root fs.FS, name string) ([]byte, error) {
	f, err := root.Open(fsPath(name))
	if err != nil {
		return nil, pathError(name, err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return nil, pathError(name, err)
	}
	if len(data) > maxFileBytes {
		return nil, fmt.Errorf("%s: larger than %d bytes", name, maxFileBytes)
	}
	return data, nil
}

// pathError says what failed on name in words: "<name>: permission denied".
func pathError(name string, err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		err = pe.Err
	}
	return fmt.Errorf("%s: %w", name, err)
}
