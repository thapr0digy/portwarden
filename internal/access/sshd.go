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

// SSHD is what sshd's global configuration says, as far as this package reads it. Settings
// inside a Match block are not global and are left out (README "Host identity facts").
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
	// PasswordAuthentication is sshd's setting (default yes).
	PasswordAuthentication bool
	// PermitRootLogin is the setting as written, lowercased (default prohibit-password).
	PermitRootLogin string
}

// ErrConfig marks a configuration sshd itself would refuse (a keyword with no argument, an
// Include loop or too deep): the trust it implies cannot be told.
var ErrConfig = errors.New("sshd configuration")

// ReadSSHD reads the global settings of the sshd configuration at name (an absolute path)
// from root, the host's file system with "/" as its root, following Include directives as
// sshd does (globs, relative to /etc/ssh, in place). The first value of a keyword wins.
func ReadSSHD(root fs.FS, name string) (SSHD, error) {
	r := sshdReader{root: root, seen: map[string]bool{}, set: map[string]bool{}}
	r.cfg = SSHD{PasswordAuthentication: true, PermitRootLogin: "prohibit-password"}
	if err := r.file(name, 0); err != nil {
		return SSHD{}, err
	}
	if r.cfg.TrustedUserCAKeys == "none" {
		r.cfg.TrustedUserCAKeys = ""
	}
	return r.cfg, nil
}

type sshdReader struct {
	root  fs.FS
	cfg   SSHD
	set   map[string]bool // keywords already given a value (the first wins)
	seen  map[string]bool // files on the current Include path (a loop is an error)
	files int
}

func (r *sshdReader) file(name string, depth int) error {
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
	return r.parse(name, string(data), depth)
}

// parse applies one file's lines. A Match block ends at the next Match line ("Match all"
// returns to the global settings) or at the end of the file.
func (r *sshdReader) parse(name, text string, depth int) error {
	inMatch := false
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
		if inMatch {
			continue
		}
		if len(args) == 0 {
			return fmt.Errorf("%w: %s line %d: %s has no argument", ErrConfig, name, n+1, words[0])
		}
		if key == "include" {
			if err := r.include(args, depth); err != nil {
				return err
			}
			continue
		}
		r.setting(key, args)
	}
	return nil
}

func (r *sshdReader) include(patterns []string, depth int) error {
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
			if err := r.file("/"+m, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *sshdReader) setting(key string, args []string) {
	if r.set[key] {
		return
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
		r.cfg.PasswordAuthentication = strings.EqualFold(args[0], "yes")
	case "permitrootlogin":
		r.cfg.PermitRootLogin = strings.ToLower(args[0])
	default:
		return
	}
	r.set[key] = true
}

// sshdWords splits a configuration line as sshd does: a keyword, then arguments separated
// by white space (or one "=" after the keyword), double quotes grouping, "#" starting a
// comment outside quotes.
func sshdWords(line string) ([]string, error) {
	var words []string
	var cur strings.Builder
	inWord, quoted := false, false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quoted && c == '"':
			quoted = false
		case quoted:
			cur.WriteByte(c)
		case c == '"':
			quoted, inWord = true, true
		case c == '#' && !inWord:
			i = len(line)
		case c == ' ' || c == '\t' || c == '\r' || (c == '=' && len(words) == 0):
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
