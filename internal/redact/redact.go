// Package redact masks the values of well-known secret arguments in a command line before
// the agent publishes it (M8). It is a fixed rule table, best effort: a secret passed in a
// form no rule knows (a positional argument, an unusual flag name) is published as is.
//
// Rules, applied to every argument and, for an argument holding spaces (a `sh -c` script,
// a libpq conninfo), to each space-separated word of it:
//   - Secret flags, one or two dashes, as `--flag value` or `--flag=value`: the name
//     (lowercased, `_` read as `-`) is one of secretFlagNames or ends in `-<one of them>`,
//     e.g. --password, --passwd, --pass, --token, --secret, --api-key, --apikey,
//     --access-key, --secret-key, --private-key, --db-password, --auth-token,
//     --client-secret, plus redis's --requirepass and --masterauth. A following value that
//     starts with "-" is another flag and is left alone. --password-file /path keeps its
//     path (the name does not end in a secret word).
//   - mysql-family `-p<password>` (only when the program is mysql, mysqldump, mariadb, …;
//     elsewhere -p<n> is a port or a pid).
//   - `KEY=value` words whose KEY (letters, digits, `_`) has a word ending in PASSWORD,
//     PASSWD, TOKEN, SECRET or APIKEY, a PWD or PASS word that is not the whole key
//     (MYSQL_PWD, not PWD), or the pairs API_KEY, ACCESS_KEY, PRIVATE_KEY; unless its last
//     word is FILE, PATH, DIR or FD (PASSWORD_FILE=/run/secrets/pw).
//   - Java `-D<property>=value` whose last dotted segment ends in password, passwd,
//     secret, token or apikey (case-insensitive).
//   - URL userinfo: `scheme://user:pw@host` → `scheme://user:***@host`, and
//     `scheme://token@host` → `scheme://***@host`.
//
// Masked values become "***"; the argument count never changes.
package redact

import (
	"path/filepath"
	"strings"
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

// Cmdline returns a copy of args with secret values masked (nil for nil).
func Cmdline(args []string) []string {
	if args == nil {
		return nil
	}
	return words(args, true)
}

// words applies the rules to a word list (a whole argv, or the words of one argument).
// split is false for the words inside one argument, which are not split again.
func words(args []string, split bool) []string {
	out := make([]string, len(args))
	copy(out, args)
	mysql := len(out) > 0 && mysqlPrograms[filepath.Base(out[0])]
	for i := 0; i < len(out); i++ {
		a := out[i]
		if split && strings.Contains(a, " ") {
			out[i] = strings.Join(words(strings.Split(a, " "), false), " ")
			continue
		}
		if name, value, isFlag := flag(a); isFlag && secretFlag(name) {
			switch {
			case value != nil && *value != "":
				out[i] = a[:len(a)-len(*value)] + Mask
			case value == nil && i+1 < len(out) && out[i+1] != "" && !strings.HasPrefix(out[i+1], "-"):
				out[i+1] = Mask
				i++
			}
			continue
		}
		if mysql && i > 0 && len(a) > 2 && strings.HasPrefix(a, "-p") {
			out[i] = "-p" + Mask
			continue
		}
		out[i] = userinfo(keyValue(a))
	}
	return out
}

// flag splits "-name", "--name" and "--name=value"; value is nil without "=".
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

// keyValue masks KEY=value and Java -Dprop=value words with a secret-like key.
func keyValue(a string) string {
	key, value, found := strings.Cut(a, "=")
	if !found || value == "" {
		return a
	}
	if prop, ok := strings.CutPrefix(key, "-D"); ok {
		if secretProperty(prop) {
			return key + "=" + Mask
		}
		return a
	}
	if secretKey(key) {
		return key + "=" + Mask
	}
	return a
}

func secretProperty(prop string) bool {
	if prop == "" {
		return false
	}
	last := strings.ToLower(prop[strings.LastIndexByte(prop, '.')+1:])
	for _, s := range []string{"password", "passwd", "secret", "token", "apikey"} {
		if strings.HasSuffix(last, s) {
			return true
		}
	}
	return false
}

func secretKey(key string) bool {
	if key == "" || !envName(key) {
		return false
	}
	ws := strings.Split(strings.ToUpper(key), "_")
	switch ws[len(ws)-1] {
	case "FILE", "PATH", "DIR", "FD":
		return false
	}
	for i, w := range ws {
		for _, s := range []string{"PASSWORD", "PASSWD", "TOKEN", "SECRET", "APIKEY"} {
			if strings.HasSuffix(w, s) {
				return true
			}
		}
		if (w == "PWD" || w == "PASS") && len(ws) > 1 {
			return true
		}
		if w == "KEY" && i > 0 {
			switch ws[i-1] {
			case "API", "ACCESS", "PRIVATE":
				return true
			}
		}
	}
	return false
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
