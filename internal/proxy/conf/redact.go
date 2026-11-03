package conf

import (
	"regexp"
	"strings"
)

// bareUserinfo matches "user:pass@" at the start of a scheme-less address.
var bareUserinfo = regexp.MustCompile(`^[^@/\s]*:[^@/\s]*@`)

// Redact strips secrets from config text before it is published: the userinfo of every
// URL (or "user:pass@host") becomes "***@", and query strings are dropped. Scheme,
// host, port and path are kept.
func Redact(s string) string {
	words := strings.Split(s, " ")
	for i, w := range words {
		if k := strings.Index(w, "://"); k >= 0 {
			head, rest := w[:k+3], w[k+3:]
			auth, tail := rest, ""
			if slash := strings.IndexByte(rest, '/'); slash >= 0 {
				auth, tail = rest[:slash], rest[slash:]
			}
			if at := strings.LastIndexByte(auth, '@'); at >= 0 {
				auth = "***@" + auth[at+1:]
			}
			w = head + auth + tail
			if q := strings.IndexByte(w, '?'); q >= 0 {
				w = w[:q]
			}
		} else if bareUserinfo.MatchString(w) {
			w = "***@" + w[strings.LastIndexByte(w, '@')+1:]
		}
		words[i] = w
	}
	return strings.Join(words, " ")
}

// RedactRoute applies Redact to every published text of a route.
func RedactRoute(r Route) Route {
	r.Target = Redact(r.Target)
	notes := make([]string, len(r.Notes))
	for i, n := range r.Notes {
		notes[i] = Redact(n)
	}
	r.Notes = notes
	bs := make([]Backend, len(r.Backends))
	for i, b := range r.Backends {
		b.Address, b.Note = Redact(b.Address), Redact(b.Note)
		bs[i] = b
	}
	r.Backends = bs
	return r
}
