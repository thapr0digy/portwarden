package access

import (
	"encoding/json"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/slidehq/signal/schema/eventsv1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// sshdUnits are the units whose journal lines are sshd's (Debian and Ubuntu name it
// ssh.service, others sshd.service). _SYSTEMD_UNIT and _UID are set by journald from the
// sending process, so another user cannot log a line that passes for sshd's.
var sshdUnits = []string{"ssh.service", "sshd.service"}

// maxKeyIDBytes is Signal's cap on a certificate key ID (SignInGroup.key_id).
const maxKeyIDBytes = 256

// Login is one sign-in sshd accepted, as its journal line records it.
type Login struct {
	At      time.Time
	Account string
	Method  eventsv1.SignInGroup_Method
	// KeyID, Serial and CAFingerprint describe a certificate; KeyFingerprint a plain key.
	KeyID, Serial, CAFingerprint, KeyFingerprint string
	// FromIP is the source address in canonical form ("" when sshd logged none).
	FromIP string
}

// journalEntry is one record as journalctl --output=json prints it. A field journald
// holds twice, or as bytes, is an array: it decodes as no string and the entry is skipped.
type journalEntry struct {
	Message  json.RawMessage `json:"MESSAGE"`
	Realtime json.RawMessage `json:"__REALTIME_TIMESTAMP"`
	Cursor   json.RawMessage `json:"__CURSOR"`
	Unit     json.RawMessage `json:"_SYSTEMD_UNIT"`
	UID      json.RawMessage `json:"_UID"`
}

// ParseEntry reads one journalctl JSON line: its cursor ("" when it has none) and the
// sign-in it records, if it is an accepted sign-in that root's sshd logged.
func ParseEntry(line []byte) (cursor string, login Login, ok bool) {
	var e journalEntry
	if json.Unmarshal(line, &e) != nil {
		return "", Login{}, false
	}
	cursor = jsonString(e.Cursor)
	unit := jsonString(e.Unit)
	if jsonString(e.UID) != "0" || !(unit == sshdUnits[0] || unit == sshdUnits[1]) {
		return cursor, Login{}, false
	}
	usec, err := strconv.ParseInt(jsonString(e.Realtime), 10, 64)
	at := time.UnixMicro(usec).UTC()
	if err != nil || usec <= 0 || timestamppb.New(at).CheckValid() != nil {
		return cursor, Login{}, false
	}
	login, ok = ParseMessage(jsonString(e.Message))
	login.At = at
	return cursor, login, ok
}

func jsonString(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

// ParseMessage reads sshd's "Accepted <method> for <user> from <ip> port <port> ssh2[: <key>]"
// (OpenSSH auth.c). A field that is not what Signal takes (a key ID with a space or over
// 256 bytes, a serial that is not a number, a malformed fingerprint) is left empty: the
// sign-in still counts, as one no person can be named for.
func ParseMessage(msg string) (Login, bool) {
	rest, ok := strings.CutPrefix(msg, "Accepted ")
	if !ok {
		return Login{}, false
	}
	method, rest, ok := strings.Cut(rest, " for ")
	if !ok {
		return Login{}, false
	}
	account, rest, ok := strings.Cut(rest, " from ")
	if !ok {
		return Login{}, false
	}
	from, rest, ok := strings.Cut(rest, " port ")
	if !ok {
		return Login{}, false
	}
	l := Login{Account: account, FromIP: canonicalIP(from)}
	_, key, _ := strings.Cut(rest, " ssh2: ")
	switch method {
	case "publickey":
		l.Method = eventsv1.SignInGroup_KEY
		parseKey(&l, key)
	case "password":
		l.Method = eventsv1.SignInGroup_PASSWORD
	default:
		l.Method = eventsv1.SignInGroup_OTHER
	}
	return l, true
}

// parseKey reads "<type> <fp>" for a plain key, or "<type>-CERT <fp> ID <key id> (serial
// <n>) CA <type> <ca fp>[, <more>]" for a certificate (OpenSSH auth2-pubkey.c).
func parseKey(l *Login, key string) {
	typ, rest, _ := strings.Cut(key, " ")
	if !strings.HasSuffix(typ, "-CERT") {
		l.KeyFingerprint = fingerprintOrEmpty(firstField(rest))
		return
	}
	l.Method = eventsv1.SignInGroup_CERTIFICATE
	_, rest, ok := strings.Cut(rest, " ID ")
	if !ok {
		return
	}
	i := strings.LastIndex(rest, " (serial ")
	if i < 0 {
		return
	}
	l.KeyID = keyID(rest[:i])
	serial, ca, ok := strings.Cut(rest[i+len(" (serial "):], ") CA ")
	if !ok {
		return
	}
	if _, err := strconv.ParseUint(serial, 10, 64); err == nil {
		l.Serial = serial
	}
	_, caFP, _ := strings.Cut(ca, " ")
	l.CAFingerprint = fingerprintOrEmpty(firstField(caFP))
}

func firstField(s string) string {
	f := strings.Fields(s)
	if len(f) == 0 {
		return ""
	}
	return strings.TrimSuffix(f[0], ",")
}

func fingerprintOrEmpty(s string) string {
	if IsFingerprint(s) {
		return s
	}
	return ""
}

// keyID is a key ID Signal takes (printable ASCII, no space, at most 256 bytes), else "".
func keyID(s string) string {
	if s == "" || len(s) > maxKeyIDBytes {
		return ""
	}
	for i := range len(s) {
		if s[i] <= ' ' || s[i] > '~' {
			return ""
		}
	}
	return s
}

// canonicalIP is addr in canonical form (an IPv4-mapped address as IPv4, no zone), or "".
func canonicalIP(addr string) string {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return ""
	}
	return a.Unmap().WithZone("").String()
}
