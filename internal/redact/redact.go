// Package redact masks the values of well-known secret arguments in a command line before
// the agent publishes it (M8). It is a fixed rule table, best effort: a secret passed in a
// form no rule knows (a positional argument, an unusual flag name) is published as is.
//
// The argv is read as a sequence of words. An argument holding whitespace that is not
// itself a masked value (a `sh -c` script, a conninfo, a header) is split into words at
// any whitespace outside quotes, the separators kept, and read the same way as a script of
// its own. Rules, per word:
//   - Secret flags, one or two dashes, as `--flag value` or `--flag=value`: the name
//     (lowercased, `_` read as `-`) is one of secretFlagNames or ends in `-<one of them>`
//     (--password, --passwd, --pass, --token, --secret, --api-key, --apikey, --access-key,
//     --secret-key, --private-key, --db-password, --auth-token, --client-secret …), plus
//     redis's --requirepass and --masterauth. The next word is masked unless it starts
//     with "-" (another flag). --password-file /path keeps its path.
//   - Per program (the first word of the argv or of each command in a script, after
//     sudo/env/exec/nohup/time/command and VAR=value words): mysql-family `-p<password>`;
//     redis-cli `-a <password>`; sshpass `-p <password>` and `-p<password>`; curl `-u`,
//     `--user`, `--proxy-user`, `-U` `user:password` (the password part).
//   - An `Authorization:` (or `Proxy-Authorization:`) header: the credentials after the
//     scheme (Bearer, Basic, Token, …), or the next word when no known scheme follows.
//   - Values, including a flag's `=value`: JSON-ish `"key": value` pairs, URL userinfo
//     (`scheme://user:***@host`, `scheme://***@host`), and `key=value` items, also in
//     lists separated by `;`, `&`, `,` or `?` (URL queries, JDBC and ODBC strings, helm
//     `--set a=1,b.password=x`, docker `--env=DB_PASSWORD=x`). A key is secret when its
//     last dotted segment has a word (split at `_` and `-`) ending in PASSWORD, PASSWD,
//     TOKEN, SECRET, APIKEY or AUTHORIZATION (any case, camelCase too), is PASS, a PWD
//     that is not the whole key (MYSQL_PWD; a bare PWD only inside a list or a URL), or
//     API_KEY/ACCESS_KEY/PRIVATE_KEY/SECRET_KEY; in a URL or list also a last word KEY,
//     and AUTH, SIG, SIGNATURE, CREDENTIAL(S). Not when its last word is FILE, PATH, DIR
//     or FD. Java `-D<property>=value` uses the same test on the property.
//
// Masked values become "***" (keeping surrounding quotes); the argument count never
// changes.
package redact

import (
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

// Mask replaces a secret value.
const Mask = "***"

var secretFlagNames = []string{"password", "passwd", "pass", "token", "secret", "api-key", "apikey",
	"access-key", "secret-key", "private-key"}

var exactSecretFlags = map[string]bool{"requirepass": true, "masterauth": true}

var mysqlPrograms = map[string]bool{
	"mysql": true, "mysqldump": true, "mysqladmin": true, "mysqlimport": true, "mysqlshow": true,
	"mysqlcheck": true, "mysqlpump": true, "mysqlslap": true, "mysqlbinlog": true, "mysqlsh": true,
	"mariadb": true, "mariadb-dump": true, "mariadb-admin": true, "mariadb-import": true,
	"mariadb-show": true, "mariadb-check": true, "mariadb-slap": true, "mariadb-binlog": true,
}

// commandPrefixes run the command that follows them.
var commandPrefixes = map[string]bool{"sudo": true, "env": true, "exec": true, "nohup": true, "time": true, "command": true}

var authSchemes = map[string]bool{"bearer": true, "basic": true, "token": true, "digest": true, "negotiate": true,
	"bot": true, "apikey": true, "key": true, "hmac": true, "aws4-hmac-sha256": true, "sso-key": true}

// Cmdline returns a copy of args with secret values masked (nil for nil).
func Cmdline(args []string) []string {
	if args == nil {
		return nil
	}
	out := make([]string, len(args))
	r := reader{start: true, top: true}
	for i, a := range args {
		out[i] = r.word(a)
	}
	return out
}

type pending int

const (
	none     pending = iota
	full             // mask the next word
	userPass         // mask the part after the first ':' of the next word
	authNext         // the next word is an auth scheme, or the credentials
)

// reader reads one word sequence (an argv, or the words of one argument).
type reader struct {
	top   bool // an argv: an argument holding whitespace is read as a script
	start bool // the next word may be a command
	prog  string
	next  pending
}

func (r *reader) word(w string) string {
	if p := r.next; p != none {
		r.next = none
		if !(strings.HasPrefix(w, "-") && len(w) > 1) {
			switch p {
			case full:
				return maskQuoted(w)
			case userPass:
				return maskAfterColon(w)
			case authNext:
				if authSchemes[strings.ToLower(w)] {
					r.next = full
					return w
				}
				return maskQuoted(w)
			}
		}
	}
	if r.top && strings.ContainsFunc(w, unicode.IsSpace) {
		if name, value, isFlag := flag(w); isFlag && value != nil && secretFlag(name) {
			return w[:len(w)-len(*value)] + maskQuoted(*value)
		}
		return script(jsonPairs(w))
	}
	if !r.top && quotedSpace(w) {
		// A quoted argument inside a script (a header, a JSON body, a nested script).
		return w[:1] + script(jsonPairs(w[1:len(w)-1])) + w[:1]
	}
	out := r.rules(w)
	if separator(w) {
		r.start, r.prog = true, ""
	}
	return out
}

func (r *reader) rules(w string) string {
	if strings.HasSuffix(strings.ToLower(w), "authorization:") {
		r.next = authNext
		return w
	}
	if r.start {
		switch {
		case commandPrefixes[filepath.Base(w)]:
			return w
		case assignment(w):
			return values(w)
		}
		r.start, r.prog = false, filepath.Base(strings.TrimRight(w, ";"))
		return w
	}
	name, value, isFlag := flag(w)
	if !isFlag {
		return values(w)
	}
	if secretFlag(name) {
		if value == nil {
			r.next = full
			return w
		}
		if *value == "" {
			return w
		}
		return w[:len(w)-len(*value)] + maskQuoted(*value)
	}
	if out, ok := r.programFlag(w, name, value); ok {
		return out
	}
	if value != nil {
		return w[:len(w)-len(*value)] + values(*value)
	}
	return w
}

// programFlag applies the per-program rules.
func (r *reader) programFlag(w, name string, value *string) (string, bool) {
	short := !strings.HasPrefix(w, "--")
	switch {
	case mysqlPrograms[r.prog]:
		if short && len(w) > 2 && strings.HasPrefix(w, "-p") {
			return "-p" + Mask, true
		}
	case r.prog == "redis-cli":
		if w == "-a" {
			r.next = full
			return w, true
		}
	case r.prog == "sshpass":
		if w == "-p" {
			r.next = full
			return w, true
		}
		if short && strings.HasPrefix(w, "-p") {
			return "-p" + Mask, true
		}
	case r.prog == "curl":
		switch {
		case w == "-u" || w == "-U" || w == "--user" || w == "--proxy-user":
			r.next = userPass
			return w, true
		case value != nil && (name == "user" || name == "proxy-user"):
			return w[:len(w)-len(*value)] + maskAfterColon(*value), true
		case short && len(w) > 2 && (strings.HasPrefix(w, "-u") || strings.HasPrefix(w, "-U")):
			return w[:2] + maskAfterColon(w[2:]), true
		}
	}
	return "", false
}

// script reads the words of one argument (whitespace outside quotes separates them).
func script(s string) string {
	r := reader{start: true}
	var b strings.Builder
	for _, t := range tokens(s) {
		if t.space {
			b.WriteString(t.text)
			continue
		}
		b.WriteString(r.word(t.text))
	}
	return b.String()
}

type token struct {
	text  string
	space bool
}

// tokens splits s into words and the whitespace between them; quotes (', ") keep
// whitespace inside a word. An unterminated quote runs to the end.
func tokens(s string) []token {
	var out []token
	var cur strings.Builder
	var quote rune
	inSpace := false
	flush := func(space bool) {
		if cur.Len() > 0 {
			out = append(out, token{text: cur.String(), space: space})
			cur.Reset()
		}
	}
	for _, c := range s {
		isSpace := quote == 0 && unicode.IsSpace(c)
		if isSpace != inSpace {
			flush(inSpace)
			inSpace = isSpace
		}
		if !isSpace {
			switch {
			case quote == 0 && (c == '"' || c == '\''):
				quote = c
			case c == quote:
				quote = 0
			}
		}
		cur.WriteRune(c)
	}
	flush(inSpace)
	return out
}

// quotedSpace reports whether w is one quoted string holding whitespace.
func quotedSpace(w string) bool {
	return len(w) >= 2 && (w[0] == '"' || w[0] == '\'') && w[len(w)-1] == w[0] && strings.ContainsFunc(w, unicode.IsSpace)
}

// separator reports whether a word ends a command in a script.
func separator(w string) bool {
	switch w {
	case ";", "&&", "||", "|", "&":
		return true
	}
	return strings.HasSuffix(w, ";")
}

// assignment is a VAR=value word before a command.
func assignment(w string) bool {
	k, _, ok := strings.Cut(w, "=")
	return ok && k != "" && envName(k)
}

// flag splits "-name", "--name" and "--name=value"; value is nil without "=". -D Java
// properties are not flags (they are values).
func flag(a string) (name string, value *string, ok bool) {
	rest, ok := strings.CutPrefix(a, "-")
	if !ok || strings.HasPrefix(a, "-D") {
		return "", nil, false
	}
	rest = strings.TrimPrefix(rest, "-")
	if rest == "" || strings.HasPrefix(rest, "-") {
		return "", nil, false
	}
	if n, v, found := strings.Cut(rest, "="); found {
		return n, &v, true
	}
	return rest, nil, true
}

func secretFlag(name string) bool {
	n := strings.ReplaceAll(strings.ToLower(name), "_", "-")
	if exactSecretFlags[n] {
		return true
	}
	for _, s := range secretFlagNames {
		if n == s || strings.HasSuffix(n, "-"+s) {
			return true
		}
	}
	return false
}

// values masks the secret parts of a value: JSON pairs, URL userinfo, key=value items.
func values(s string) string {
	s = jsonPairs(s)
	s = userinfo(s)
	return kvItems(s)
}

var jsonPair = regexp.MustCompile(`"([A-Za-z0-9_.\-]+)"(\s*:\s*)("(?:[^"\\]|\\.)*"|[^,}\]\s]+)`)

func jsonPairs(s string) string {
	if !strings.Contains(s, `"`) || !strings.Contains(s, ":") {
		return s
	}
	return jsonPair.ReplaceAllStringFunc(s, func(m string) string {
		sub := jsonPair.FindStringSubmatch(m)
		if !secretKey(sub[1], false) {
			return m
		}
		return `"` + sub[1] + `"` + sub[2] + `"` + Mask + `"`
	})
}

// kvItems masks secret key=value items, splitting at ; & , ? (lists, URL queries).
func kvItems(s string) string {
	if !strings.Contains(s, "=") {
		return s
	}
	urlish := strings.Contains(s, "://") || strings.HasPrefix(strings.ToLower(s), "jdbc:")
	items := splitKeep(s, ";&,?")
	broad := urlish || len(items) > 1
	var b strings.Builder
	for _, it := range items {
		if len(it) == 1 && strings.ContainsAny(it, ";&,?") {
			b.WriteString(it)
			continue
		}
		b.WriteString(keyValue(it, broad))
	}
	return b.String()
}

// splitKeep splits s at any byte of seps, keeping each separator as its own item.
func splitKeep(s, seps string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(seps, s[i]) >= 0 {
			if i > start {
				out = append(out, s[start:i])
			}
			out = append(out, s[i:i+1])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// keyValue masks one key=value item (or -Dproperty=value) with a secret key.
func keyValue(a string, broad bool) string {
	key, value, found := strings.Cut(a, "=")
	if !found || value == "" {
		return a
	}
	k := strings.TrimPrefix(key, "-D")
	if !keyName(k) || !secretKey(k, broad) {
		return a
	}
	return key + "=" + maskQuoted(value)
}

// secretKey reports whether a key names a secret; broad (a URL query or a list) also
// takes a last word KEY, AUTH, SIG and a bare PWD.
func secretKey(key string, broad bool) bool {
	last := key[strings.LastIndexByte(key, '.')+1:]
	ws := strings.FieldsFunc(strings.ToUpper(last), func(r rune) bool { return r == '_' || r == '-' })
	if len(ws) == 0 {
		return false
	}
	switch ws[len(ws)-1] {
	case "FILE", "PATH", "DIR", "FD":
		return false
	}
	for i, w := range ws {
		for _, s := range []string{"PASSWORD", "PASSWD", "TOKEN", "SECRET", "APIKEY", "AUTHORIZATION"} {
			if strings.HasSuffix(w, s) {
				return true
			}
		}
		switch w {
		case "PASS":
			return true
		case "PWD":
			if len(ws) > 1 || broad {
				return true
			}
		case "KEY":
			if i > 0 {
				switch ws[i-1] {
				case "API", "ACCESS", "PRIVATE", "SECRET":
					return true
				}
			}
			if broad && i == len(ws)-1 {
				return true
			}
		case "AUTH", "SIG", "SIGNATURE", "CREDENTIAL", "CREDENTIALS":
			if broad {
				return true
			}
		}
	}
	return false
}

// keyName: letters, digits, _ . - (a leading letter or _).
func keyName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r == '_', r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z':
		case (r >= '0' && r <= '9' || r == '.' || r == '-') && i > 0:
		default:
			return false
		}
	}
	return true
}

func envName(s string) bool {
	for i, r := range s {
		switch {
		case r == '_', r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// maskQuoted masks a value, keeping its quotes when it is quoted.
func maskQuoted(v string) string {
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		return v[:1] + Mask + v[:1]
	}
	return Mask
}

// maskAfterColon masks the part after the first ':' (user:password); nothing without one.
func maskAfterColon(v string) string {
	user, pw, ok := strings.Cut(v, ":")
	if !ok || pw == "" {
		return v
	}
	return user + ":" + Mask
}

// userinfo masks the userinfo of every scheme://userinfo@host in a.
func userinfo(a string) string {
	var b strings.Builder
	rest := a
	for {
		i := strings.Index(rest, "://")
		if i < 0 {
			b.WriteString(rest)
			return b.String()
		}
		start := i + 3
		if !scheme(rest[:i]) {
			b.WriteString(rest[:start])
			rest = rest[start:]
			continue
		}
		end := start + strings.IndexAny(rest[start:]+"/", "/?#")
		authority := rest[start:end]
		at := strings.LastIndexByte(authority, '@')
		if at <= 0 {
			b.WriteString(rest[:end])
			rest = rest[end:]
			continue
		}
		info := authority[:at]
		masked := Mask
		if user, _, hasPw := strings.Cut(info, ":"); hasPw {
			masked = user + ":" + Mask
		}
		b.WriteString(rest[:start])
		b.WriteString(masked)
		b.WriteString(authority[at:])
		rest = rest[end:]
	}
}

// scheme reports whether s ends in a URL scheme (a letter, then letters, digits, + - .).
func scheme(s string) bool {
	j := len(s)
	for j > 0 {
		c := s[j-1]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.' {
			j--
			continue
		}
		break
	}
	if j == len(s) {
		return false
	}
	c := s[j]
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}
