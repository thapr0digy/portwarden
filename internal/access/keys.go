package access

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io/fs"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/slidehq/signal/schema/eventsv1"
)

// fingerprintRe is an SSH key's SHA-256 fingerprint as ssh-keygen -l and sshd print it.
var fingerprintRe = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)

// IsFingerprint reports whether s is an SSH SHA-256 fingerprint.
func IsFingerprint(s string) bool { return fingerprintRe.MatchString(s) }

const (
	// maxLabelBytes is Signal's cap on a trusted key's label (TrustedKey.label).
	maxLabelBytes = 64
	// maxCAKeys is Signal's cap on a repeated field (Sshd.trusted_user_ca_keys).
	maxCAKeys = 256
)

// Fingerprint is the SHA-256 fingerprint of a public key line's key ("<type> <base64>"):
// the key blob must decode and name the line's type.
func Fingerprint(keyType, b64 string) (string, error) {
	blob, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("key is not base64: %w", err)
	}
	if len(blob) < 4 {
		return "", fmt.Errorf("key blob too short")
	}
	n := binary.BigEndian.Uint32(blob)
	if uint64(n) > uint64(len(blob)-4) || !bytes.Equal(blob[4:4+n], []byte(keyType)) {
		return "", fmt.Errorf("key blob is not a %s key", keyType)
	}
	sum := sha256.Sum256(blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), nil
}

// readCAKeys reads a TrustedUserCAKeys file: one public key per line, "#" comments. A line
// that is not a key is skipped, as sshd skips it; each key once, its comment as the label.
func readCAKeys(root fs.FS, name string) ([]*eventsv1.TrustedKey, error) {
	data, err := readFile(root, name)
	if err != nil {
		return nil, err
	}
	return parseCAKeys(string(data)), nil
}

func parseCAKeys(text string) []*eventsv1.TrustedKey {
	var out []*eventsv1.TrustedKey
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || strings.HasPrefix(f[0], "#") {
			continue
		}
		fp, err := Fingerprint(f[0], f[1])
		if err != nil || seen[fp] {
			continue
		}
		seen[fp] = true
		if out = append(out, &eventsv1.TrustedKey{Fingerprint: fp, Label: label(strings.Join(f[2:], " "))}); len(out) == maxCAKeys {
			break
		}
	}
	return out
}

// label is a key comment fit for Signal: printable, valid UTF-8, at most 64 bytes, cut at
// a character boundary.
func label(s string) string {
	return clip(strings.Map(func(r rune) rune {
		if isControl(r) || r == utf8.RuneError {
			return -1
		}
		return r
	}, s), maxLabelBytes)
}

// sharedKeyNameRe is a shared key's name in the reviewed list.
var sharedKeyNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// SharedKeys is the reviewed list of shared plain keys: fingerprint to name. Only these
// fingerprints leave the host; a plain key not on it is sent without its fingerprint.
type SharedKeys map[string]string

// ParseSharedKeys reads the reviewed list: one "<name> SHA256:<fingerprint>" per line,
// "#" comments and blank lines allowed. Anything else (a public or private key, a second
// name for one fingerprint) is an error naming the line, never echoing it.
func ParseSharedKeys(text string) (SharedKeys, error) {
	out := SharedKeys{}
	for n, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 2 || !sharedKeyNameRe.MatchString(f[0]) || !IsFingerprint(f[1]) {
			return nil, fmt.Errorf("line %d: want \"<name> SHA256:<fingerprint>\"", n+1)
		}
		if _, dup := out[f[1]]; dup {
			return nil, fmt.Errorf("line %d: the fingerprint is listed twice", n+1)
		}
		out[f[1]] = f[0]
	}
	return out, nil
}
