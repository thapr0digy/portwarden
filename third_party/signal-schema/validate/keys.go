package validate

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/slidehq/signal/schema/eventsv1"
)

// IsULID reports whether s is a ULID: 26 Crockford base32 characters (upper case,
// no I, L, O or U), the first at most 7 so the timestamp fits 48 bits.
func IsULID(s string) bool {
	if len(s) != 26 || s[0] > '7' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'A' && c <= 'Z' && c != 'I' && c != 'L' && c != 'O' && c != 'U':
		default:
			return false
		}
	}
	return true
}

// IsHex reports whether s is exactly n lowercase hex characters.
func IsHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

const (
	hostIDLen  = 32 // a machine-id: 32 lowercase hex characters
	sha256Len  = 64
	maxKeyLen  = 1024
	maxDNSName = 253
)

var errNoScheme = errors.New("no known scheme")

// SchemeOf returns the scheme of a subject or AssetRef key.
func SchemeOf(key string) (eventsv1.SubjectScheme, bool) {
	i := strings.IndexByte(key, ':')
	if i <= 0 {
		return "", false
	}
	s := eventsv1.SubjectScheme(key[:i+1])
	if s == eventsv1.SchemeScan {
		return s, true
	}
	for _, a := range eventsv1.AssetSchemes {
		if s == a {
			return s, true
		}
	}
	return "", false
}

// Key checks the form of a subject or AssetRef key (common.proto, AssetRef) and
// returns its scheme.
func Key(key string) (eventsv1.SubjectScheme, error) {
	if key == "" {
		return "", errors.New("empty")
	}
	if len(key) > maxKeyLen {
		return "", fmt.Errorf("%d bytes > %d", len(key), maxKeyLen)
	}
	s, ok := SchemeOf(key)
	if !ok {
		return "", errNoScheme
	}
	rest := key[len(s):]
	if rest == "" {
		return "", fmt.Errorf("nothing after %q", s)
	}
	if !utf8.ValidString(rest) {
		return "", errors.New("not valid UTF-8")
	}
	for _, r := range rest {
		// Cf: bidi overrides and zero-width characters, which spoof how a key reads.
		if r <= ' ' || unicode.IsControl(r) || unicode.IsSpace(r) || unicode.Is(unicode.Cf, r) {
			return "", errors.New("space, control or format character")
		}
	}
	var err error
	switch s {
	case eventsv1.SchemeHost:
		if !IsHex(rest, hostIDLen) {
			err = fmt.Errorf("want %d lowercase hex characters", hostIDLen)
		}
	case eventsv1.SchemeScan:
		if !IsULID(rest) {
			err = errors.New("want a ULID")
		}
	case eventsv1.SchemeIP:
		err = canonicalIP(rest)
	case eventsv1.SchemeCIDR:
		err = canonicalPrefix(rest)
	case eventsv1.SchemeDNS:
		err = dnsName(rest)
	case eventsv1.SchemeURL:
		err = absoluteURL(rest)
	case eventsv1.SchemeSvc:
		err = serviceKey(rest)
	case eventsv1.SchemeCert:
		if h, ok := strings.CutPrefix(rest, "sha256:"); !ok || !IsHex(h, sha256Len) {
			err = errors.New("want sha256:<64 lowercase hex>")
		}
	case eventsv1.SchemeImage:
		if repo, h, ok := strings.Cut(rest, "@sha256:"); !ok || repo == "" || !IsHex(h, sha256Len) {
			err = errors.New("want <registry/repo>@sha256:<64 lowercase hex>")
		}
	case eventsv1.SchemeCloud, eventsv1.SchemeRepo, eventsv1.SchemePkg:
		// Provider-, host- and ecosystem-specific forms: bounded and printable
		// (checked above); their parts are the reader's to interpret.
	}
	if err != nil {
		return "", fmt.Errorf("%s: %w", strings.TrimSuffix(string(s), ":"), err)
	}
	return s, nil
}

func canonicalIP(s string) error {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return errors.New("not an IP address")
	}
	if a.Zone() != "" || a.Unmap().String() != s {
		return errors.New("not canonical (unmapped, compressed, no zone)")
	}
	return nil
}

func canonicalPrefix(s string) error {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return errors.New("not a CIDR prefix")
	}
	if p.Addr().Is4In6() {
		return errors.New("not canonical (IPv4-mapped; use the IPv4 prefix)")
	}
	if p.Masked().String() != s {
		return errors.New("not canonical (host bits set or not compressed)")
	}
	return nil
}

// dnsName accepts a lowercase name without a trailing dot; labels are letters,
// digits, hyphens and underscores (service labels such as _dmarc), 1 to 63 bytes,
// and a leading "*." wildcard. The last label is not all digits, so an IP address
// (or a zero-padded one) is never a DNS name.
func dnsName(s string) error {
	if len(s) > maxDNSName {
		return fmt.Errorf("%d bytes > %d", len(s), maxDNSName)
	}
	s = strings.TrimPrefix(s, "*.")
	labels := strings.Split(s, ".")
	if tld := labels[len(labels)-1]; strings.Trim(tld, "0123456789") == "" {
		return errors.New("last label is all digits")
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return errors.New("empty or long label")
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("label starts or ends with a hyphen")
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
				return errors.New("not lowercase letters, digits, hyphens or underscores")
			}
		}
	}
	return nil
}

// absoluteURL accepts one canonical form per web resource: http or https, lowercase
// scheme and host, no default port, no zone, no dot segments, no query, fragment or
// user info.
func absoluteURL(s string) error {
	u, err := url.Parse(s)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return errors.New("not an absolute URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("scheme is not http or https")
	}
	if strings.Contains(u.Host, "%") {
		return errors.New("has a zone")
	}
	if p := u.Port(); u.Host[len(u.Host)-1] == ':' || p == "80" && u.Scheme == "http" || p == "443" && u.Scheme == "https" {
		return errors.New("has an empty or default port")
	}
	for _, seg := range strings.Split(u.EscapedPath(), "/") {
		if seg == "." || seg == ".." {
			return errors.New("has a dot segment")
		}
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(s, "?#") {
		return errors.New("has a query or fragment")
	}
	if u.User != nil {
		return errors.New("has user info")
	}
	// One asset, one key: url.Parse lowercases the scheme, so check the raw text.
	if !strings.HasPrefix(s, u.Scheme+":") || u.Host != strings.ToLower(u.Host) {
		return errors.New("scheme or host not lowercase")
	}
	return nil
}

// serviceKey checks <ip-or-dns>:<proto>/<port>; an IPv6 address is bare
// (svc:2001:db8::1:tcp/53), so the split is on the last colon.
func serviceKey(s string) error {
	i := strings.LastIndexByte(s, ':')
	if i <= 0 {
		return errors.New("want <ip-or-dns>:<proto>/<port>")
	}
	host, pp := s[:i], s[i+1:]
	proto, port, ok := strings.Cut(pp, "/")
	if !ok {
		return errors.New("want <proto>/<port>")
	}
	if err := ProtoPort(proto, port); err != nil {
		return err
	}
	if canonicalIP(host) == nil {
		return nil
	}
	if dnsName(host) == nil {
		return nil
	}
	return errors.New("host is neither a canonical IP nor a DNS name")
}

// ProtoPort checks a transport name and a decimal port 1 to 65535.
func ProtoPort(proto, port string) error {
	if proto != "tcp" && proto != "udp" {
		return fmt.Errorf("proto %q is not tcp or udp", proto)
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 || strconv.FormatUint(n, 10) != port {
		return fmt.Errorf("port %q is not 1-65535", port)
	}
	return nil
}
