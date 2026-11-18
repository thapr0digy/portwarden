package dpkg

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/slidehq/signal/schema/eventsv1"
	"github.com/slidehq/signal/schema/validate"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

const (
	// Manager names the package manager the list comes from (HostPackages.manager).
	Manager = "dpkg"
	// OSRelease is the distribution's identification; osReleaseFallback is read when it is
	// missing (os-release(5)).
	OSRelease         = "/etc/os-release"
	osReleaseFallback = "/usr/lib/os-release"
	// maxOSReleaseBytes bounds the os-release read.
	maxOSReleaseBytes = 64 << 10
	// maxReasonBytes is Signal's cap on HostPackages.unreadable.
	maxReasonBytes = 256
	// envelopeRoom is what the event around the list may take of Signal's per-event cap
	// (id, type, subject, source, producer, run cursor: a few hundred bytes).
	envelopeRoom = 4 << 10
)

var (
	// maxPackages is Signal's cap on the list (HostPackages.packages, 6,000).
	maxPackages = validate.Default.Field["asm.events.v1.HostPackages.packages"].Items
	// maxListBytes keeps the encoded list, with its event, under Signal's 1 MiB per event.
	maxListBytes = validate.Default.MaxEventBytes - envelopeRoom
)

// The forms Signal's door holds a package list to (schema validate/rules.go: Debian Policy
// 5.6.1, 5.6.12 and os-release(5)). A package outside them is left out of the list (and
// counted in total) rather than costing the host its whole list at the door.
var (
	debPackageRe = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{1,127}$`)
	debVersionRe = regexp.MustCompile(`^[A-Za-z0-9.+~:-]{1,128}$`)
	debArchRe    = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	osReleaseRe  = regexp.MustCompile(`^[a-z0-9._-]{1,64}$`)
	osVersionRe  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
)

// ReadPackages reads the host's installed packages and its distribution from root (the
// host's file system, rooted at "/") as Signal's asm.host.packages full state, its digest
// set. A list it cannot read is read=false with the reason, never an empty list; skipped
// is how many installed packages were left out for a form Signal refuses. Nothing here
// fails.
func ReadPackages(root fs.FS) (list *eventsv1.HostPackages, skipped int) {
	distro, err := readDistro(root)
	if err != nil {
		return unreadable(err), 0
	}
	f, err := root.Open(fsPath(StatusFile))
	if err != nil {
		return unreadable(pathError(StatusFile, err)), 0
	}
	defer f.Close()
	var pkgs []*eventsv1.OSPackage
	total := 0
	err = Stanzas(f, func(s Stanza) bool {
		if !installed(s) {
			return true
		}
		total++
		if p := osPackage(s); p != nil {
			pkgs = append(pkgs, p)
		}
		return true
	})
	if err != nil {
		return unreadable(fmt.Errorf("%s: %w", StatusFile, err)), 0
	}
	slices.SortFunc(pkgs, func(a, b *eventsv1.OSPackage) int {
		return cmp.Or(strings.Compare(a.GetName(), b.GetName()), strings.Compare(a.GetArch(), b.GetArch()))
	})
	pkgs = slices.CompactFunc(pkgs, func(a, b *eventsv1.OSPackage) bool { return a.GetName() == b.GetName() && a.GetArch() == b.GetArch() })
	kept, truncated := capList(pkgs)
	list = &eventsv1.HostPackages{Read: true, Manager: Manager, Distro: distro, Packages: kept,
		Truncated: truncated, Total: uint32(total)} //nolint:gosec // a 64 MiB status file holds far fewer
	list.Digest = Digest(list)
	return list, total - len(pkgs)
}

// Digest is the lowercase hex SHA-256 of the deterministic encoding of l's distro and
// packages (Signal's HostPackages.digest).
func Digest(l *eventsv1.HostPackages) string {
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(&eventsv1.HostPackages{Distro: l.GetDistro(), Packages: l.GetPackages()})
	if err != nil {
		// Marshalling a well-formed message cannot fail; an empty digest makes it a full send.
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func unreadable(err error) *eventsv1.HostPackages {
	return &eventsv1.HostPackages{Unreadable: reason(err)}
}

// installed reports whether a stanza is an installed package: its Status's third word (the
// state) is "installed", whatever the selection (install, hold, deinstall) and error flag
// (a held package is as installed as any other).
func installed(s Stanza) bool {
	f := strings.Fields(s["Status"])
	return len(f) == 3 && f[2] == "installed"
}

// osPackage is an installed stanza as Signal's OSPackage, the source package and version
// as dpkg-query's ${source:Package} and ${source:Version} give them ("Source: name" or
// "Source: name (version)"; the binary's own when absent), or nil when a field is outside
// Signal's forms.
func osPackage(s Stanza) *eventsv1.OSPackage {
	p := &eventsv1.OSPackage{Name: s["Package"], Version: s["Version"], Arch: s["Architecture"],
		Source: s["Package"], SourceVersion: s["Version"]}
	if src := strings.Fields(s["Source"]); len(src) > 0 {
		p.Source = src[0]
		if len(src) == 2 && strings.HasPrefix(src[1], "(") && strings.HasSuffix(src[1], ")") {
			p.SourceVersion = strings.TrimSuffix(strings.TrimPrefix(src[1], "("), ")")
		} else if len(src) != 1 {
			return nil
		}
	}
	if !debPackageRe.MatchString(p.Name) || !debVersionRe.MatchString(p.Version) || !debArchRe.MatchString(p.Arch) ||
		!debPackageRe.MatchString(p.Source) || !debVersionRe.MatchString(p.SourceVersion) {
		return nil
	}
	return p
}

// capList keeps the first packages that fit Signal's count cap and, encoded, its per-event
// byte cap; truncated says some were left out.
func capList(pkgs []*eventsv1.OSPackage) ([]*eventsv1.OSPackage, bool) {
	size := 0
	for i, p := range pkgs {
		n := proto.Size(p)
		size += protowire.SizeTag(5) + protowire.SizeBytes(n)
		if i == maxPackages || size > maxListBytes {
			return pkgs[:i], true
		}
	}
	return pkgs, false
}

// readDistro reads ID, VERSION_ID and VERSION_CODENAME from os-release. Signal needs the
// first two in their os-release forms; a codename outside its form is left out.
func readDistro(root fs.FS) (*eventsv1.Distro, error) {
	name := OSRelease
	data, err := readFile(root, name)
	if errors.Is(err, fs.ErrNotExist) {
		name = osReleaseFallback
		data, err = readFile(root, name)
	}
	if err != nil {
		return nil, err
	}
	v := parseOSRelease(string(data))
	d := &eventsv1.Distro{Id: v["ID"], VersionId: v["VERSION_ID"], Codename: v["VERSION_CODENAME"]}
	switch {
	case !osReleaseRe.MatchString(d.GetId()):
		return nil, fmt.Errorf("%s: no ID in os-release's form", name)
	case !osVersionRe.MatchString(d.GetVersionId()):
		return nil, fmt.Errorf("%s: no VERSION_ID in os-release's form", name)
	}
	if !osReleaseRe.MatchString(d.GetCodename()) {
		d.Codename = ""
	}
	return d, nil
}

// parseOSRelease reads os-release's KEY=value lines: a value optionally in double or single
// quotes, a backslash escaping $ " \ ` inside double quotes (os-release(5)); comments and
// other lines ignored, the first assignment of a key kept.
func parseOSRelease(text string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.HasPrefix(line, "#") || key == "" {
			continue
		}
		if _, seen := out[key]; seen {
			continue
		}
		switch {
		case len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"':
			value = unescape(value[1 : len(value)-1])
		case len(value) >= 2 && value[0] == '\'' && value[len(value)-1] == '\'':
			value = value[1 : len(value)-1]
		}
		out[key] = value
	}
	return out
}

func unescape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && strings.IndexByte("$\"\\`", s[i+1]) >= 0 {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// fsPath is an absolute path as an fs.FS rooted at "/" names it.
func fsPath(p string) string { return strings.TrimPrefix(path.Clean(p), "/") }

// readFile reads an absolute path from root, at most maxOSReleaseBytes.
func readFile(root fs.FS, name string) ([]byte, error) {
	f, err := root.Open(fsPath(name))
	if err != nil {
		return nil, pathError(name, err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxOSReleaseBytes+1))
	if err != nil {
		return nil, pathError(name, err)
	}
	if len(data) > maxOSReleaseBytes {
		return nil, fmt.Errorf("%s: larger than %d bytes", name, maxOSReleaseBytes)
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

// reason is an error as an unreadable reason: valid UTF-8, at most 256 bytes. Its text is
// this package's and the file system's (fixed paths), never a host file's content.
func reason(err error) string {
	s := strings.ToValidUTF8(err.Error(), "?")
	for len(s) > maxReasonBytes {
		_, size := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-size]
	}
	return s
}
