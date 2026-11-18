package dpkg

import (
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/slidehq/signal/schema/eventsv1"
	"github.com/slidehq/signal/schema/validate"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const ubuntuOSRelease = `PRETTY_NAME="Ubuntu 24.04.1 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.1 LTS (Noble Numbat)"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
UBUNTU_CODENAME=noble
`

// ubuntuStatus is a status file as dpkg writes it on Ubuntu 24.04: multi-line fields, a
// binary package whose source has another name, one whose source has another version
// (a binNMU-style rebuild), a multi-arch library twice, and packages in every state.
const ubuntuStatus = `Package: openssh-server
Status: install ok installed
Priority: optional
Section: net
Installed-Size: 1983
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: openssh
Version: 1:9.6p1-3ubuntu13.5
Depends: libc6 (>= 2.38)
Conffiles:
 /etc/default/ssh 500e3cf069fe9a7b9936108eb9d9c035
 /etc/ssh/sshd_config.d newconffile
Description: secure shell (SSH) server, for secure access from remote machines
 This is the portable version of OpenSSH, a free implementation of
 the Secure Shell protocol as specified by the IETF secsh working
 group.
Homepage: https://www.openssh.com/

Package: libc6
Status: install ok installed
Architecture: amd64
Multi-Arch: same
Source: glibc
Version: 2.39-0ubuntu8.3
Description: GNU C Library: Shared libraries

Package: libc6
Status: hold ok installed
Architecture: i386
Multi-Arch: same
Source: glibc
Version: 2.39-0ubuntu8.3
Description: GNU C Library: Shared libraries

Package: python3-yaml
Status: install ok installed
Architecture: amd64
Source: pyyaml (6.0.1-2build2)
Version: 6.0.1-2build2+b1
Description: YAML parser and emitter for Python3

Package: bash
Status: install ok installed
Essential: yes
Architecture: amd64
Version: 5.2.21-2ubuntu4

Package: old-kernel-modules
Status: deinstall ok config-files
Architecture: amd64
Version: 6.8.0-31.31

Package: half-done
Status: install reinstreq half-installed
Architecture: amd64
Version: 1.0-1

Package: unpacked-only
Status: install ok unpacked
Architecture: amd64
Version: 1.0-1

Package: being-removed
Status: deinstall ok installed
Architecture: all
Version: 2.0-1
`

func host(status string) fstest.MapFS {
	return fstest.MapFS{
		"etc/os-release":       {Data: []byte(ubuntuOSRelease)},
		"var/lib/dpkg/status":  {Data: []byte(status)},
		"var/lib/dpkg/status-": {Data: []byte("Package: stale-backup\nStatus: install ok installed\n")},
	}
}

func names(l *eventsv1.HostPackages) string {
	var out []string
	for _, p := range l.GetPackages() {
		out = append(out, p.GetName()+":"+p.GetArch())
	}
	return strings.Join(out, " ")
}

// Assumption: "installed" is the Status's third word, whatever the selection (a held or
// marked-for-removal package is still on disk) and nothing else: config-files, unpacked
// and half-installed packages are not installed.
func TestReadPackagesInstalledOnly(t *testing.T) {
	l, skipped := ReadPackages(host(ubuntuStatus))
	if !l.GetRead() || skipped != 0 {
		t.Fatalf("list = %v, skipped %d", l, skipped)
	}
	if got := names(l); got != "bash:amd64 being-removed:all libc6:amd64 libc6:i386 openssh-server:amd64 python3-yaml:amd64" {
		t.Fatalf("installed, sorted by name then arch: %s", got)
	}
	if l.GetTotal() != 6 || l.GetTruncated() || l.GetManager() != "dpkg" {
		t.Fatalf("list = %v", l)
	}
	want := &eventsv1.Distro{Id: "ubuntu", VersionId: "24.04", Codename: "noble"}
	if !proto.Equal(l.GetDistro(), want) {
		t.Fatalf("distro = %v", l.GetDistro())
	}
}

// Assumption: dpkg-query's ${source:Package} and ${source:Version} are the Source field's
// name and parenthesised version, each defaulting to the binary package's own.
func TestReadPackagesSourceAsDpkgQueryPrintsIt(t *testing.T) {
	l, _ := ReadPackages(host(ubuntuStatus))
	byName := map[string]*eventsv1.OSPackage{}
	for _, p := range l.GetPackages() {
		byName[p.GetName()] = p
	}
	for name, want := range map[string][2]string{
		"openssh-server": {"openssh", "1:9.6p1-3ubuntu13.5"},
		"python3-yaml":   {"pyyaml", "6.0.1-2build2"},
		"bash":           {"bash", "5.2.21-2ubuntu4"},
	} {
		p := byName[name]
		if p.GetSource() != want[0] || p.GetSourceVersion() != want[1] {
			t.Errorf("%s: source %s %s, want %v", name, p.GetSource(), p.GetSourceVersion(), want)
		}
	}
	if byName["python3-yaml"].GetVersion() != "6.0.1-2build2+b1" {
		t.Errorf("the binary keeps its own version: %v", byName["python3-yaml"])
	}
}

// Assumption: every list ReadPackages builds is one Signal's door takes, in an event.
func TestReadPackagesListIsAcceptedBySignal(t *testing.T) {
	for name, l := range map[string]*eventsv1.HostPackages{
		"ubuntu":     first(ReadPackages(host(ubuntuStatus))),
		"unreadable": first(ReadPackages(fstest.MapFS{"etc/os-release": {Data: []byte(ubuntuOSRelease)}})),
		"capped":     first(ReadPackages(host(manyPackages(maxPackages+5, 8)))),
		"byte cap":   first(ReadPackages(host(manyPackages(maxPackages, 120)))),
	} {
		if err := validate.Event(packagesEvent(l), validate.Options{}); err != nil {
			t.Errorf("%s: the door would refuse it: %v", name, err)
		}
	}
}

func first(l *eventsv1.HostPackages, _ int) *eventsv1.HostPackages { return l }

func packagesEvent(l *eventsv1.HostPackages) *eventsv1.Event {
	const id = "0123456789abcdef0123456789abcdef"
	return &eventsv1.Event{
		Id: "01JC8Z6X4Q00000000000000S3", Type: "asm.host.packages",
		Source: "urn:asm:agent:" + id, Subject: "host:" + id, Time: timestamppb.Now(),
		Producer: &eventsv1.Producer{Name: "portwarden-agent", Version: "v1.0.0"},
		Sequence: &eventsv1.Sequence{RunId: "01JC8Z6X4P9QK2M3N5R7T8V0WA", Seq: 1, BootId: "6e0f9d1c-3b2a-4e8f-9c7d-5a4b3c2d1e0f", RunNumber: 1},
		Data:     &eventsv1.Event_HostPackages{HostPackages: l},
	}
}

// manyPackages is a status file of n installed packages with versions of about vlen bytes.
func manyPackages(n, vlen int) string {
	var b strings.Builder
	v := "1." + strings.Repeat("0", vlen-2)
	for i := range n {
		fmt.Fprintf(&b, "Package: pkg%05d\nStatus: install ok installed\nArchitecture: amd64\nSource: src%05d (%s)\nVersion: %s\n\n", i, i, v, v)
	}
	return b.String()
}

// Assumption: Signal takes at most 6,000 packages; past that the first 6,000 by name go,
// truncated set and total counting them all.
func TestReadPackagesCapsAtSignalsCount(t *testing.T) {
	l, _ := ReadPackages(host(manyPackages(maxPackages+5, 8)))
	if len(l.GetPackages()) != maxPackages || !l.GetTruncated() || l.GetTotal() != uint32(maxPackages+5) ||
		l.GetPackages()[maxPackages-1].GetName() != fmt.Sprintf("pkg%05d", maxPackages-1) {
		t.Fatalf("sent %d, truncated %v, total %d", len(l.GetPackages()), l.GetTruncated(), l.GetTotal())
	}
}

// Assumption: Signal refuses an event over 1 MiB, so long versions cut the list below
// 6,000 rather than lose the whole list at the door.
func TestReadPackagesCapsAtSignalsEventSize(t *testing.T) {
	l, _ := ReadPackages(host(manyPackages(maxPackages, 120)))
	ev := packagesEvent(l)
	if !l.GetTruncated() || len(l.GetPackages()) >= maxPackages || proto.Size(ev) > validate.Default.MaxEventBytes {
		t.Fatalf("sent %d, truncated %v, event %d bytes", len(l.GetPackages()), l.GetTruncated(), proto.Size(ev))
	}
}

// Assumption: a package outside Signal's forms (a name with capitals, a version with a
// space, a malformed Source) would make the door refuse the whole list: it is left out
// and counted.
func TestReadPackagesLeavesOutWhatSignalRefuses(t *testing.T) {
	status := ubuntuStatus + `
Package: Local_Tool
Status: install ok installed
Architecture: amd64
Version: 1.0

Package: spaced
Status: install ok installed
Architecture: amd64
Version: 1.0 beta

Package: weird-source
Status: install ok installed
Architecture: amd64
Source: a b c
Version: 1.0
`
	l, skipped := ReadPackages(host(status))
	if skipped != 3 || l.GetTotal() != 9 || len(l.GetPackages()) != 6 || l.GetTruncated() {
		t.Fatalf("skipped %d, total %d, sent %d", skipped, l.GetTotal(), len(l.GetPackages()))
	}
}

// Assumption: a list that cannot be read is "cannot tell" with the reason, never an empty
// list: no dpkg database (not a dpkg host), one the agent may not read, an os-release
// without the ID or VERSION_ID Signal needs.
func TestReadPackagesUnreadableIsNotEmpty(t *testing.T) {
	denied := denyFS{FS: host(ubuntuStatus), deny: "var/lib/dpkg/status"}
	noVersion := host(ubuntuStatus)
	noVersion["etc/os-release"] = &fstest.MapFile{Data: []byte("ID=debian\nPRETTY_NAME=\"Debian trixie/sid\"\n")}
	for name, c := range map[string]struct {
		root fs.FS
		want string
	}{
		"no dpkg":           {fstest.MapFS{"etc/os-release": {Data: []byte(ubuntuOSRelease)}}, "/var/lib/dpkg/status: file does not exist"},
		"denied":            {denied, "/var/lib/dpkg/status: permission denied"},
		"no os-release":     {fstest.MapFS{"var/lib/dpkg/status": {Data: []byte(ubuntuStatus)}}, "/usr/lib/os-release: file does not exist"},
		"no VERSION_ID":     {noVersion, "/etc/os-release: no VERSION_ID"},
		"status too large":  {host("Description: " + strings.Repeat("x", maxLineBytes+1) + "\n"), "/var/lib/dpkg/status: bufio.Scanner: token too long"},
		"os-release capped": {fstest.MapFS{"etc/os-release": {Data: make([]byte, maxOSReleaseBytes+1)}}, "larger than"},
	} {
		l, _ := ReadPackages(c.root)
		if l.GetRead() || len(l.GetPackages()) != 0 || !strings.Contains(l.GetUnreadable(), c.want) || l.GetDigest() != "" {
			t.Errorf("%s: %v, want unreadable %q", name, l, c.want)
		}
	}
}

type denyFS struct {
	fs.FS
	deny string
}

func (d denyFS) Open(name string) (fs.File, error) {
	if name == d.deny {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrPermission}
	}
	return d.FS.Open(name)
}

// Assumption: os-release's values may be double- or single-quoted with shell escapes, the
// file may live only in /usr/lib, and a codename outside os-release's form is left out
// rather than costing the list.
func TestReadDistro(t *testing.T) {
	d, err := readDistro(fstest.MapFS{"usr/lib/os-release": {Data: []byte("# comment\nID='debian'\nVERSION_ID=\"12\"\nVERSION_CODENAME=\"Book Worm\"\nID=ubuntu\n")}})
	if err != nil || !proto.Equal(d, &eventsv1.Distro{Id: "debian", VersionId: "12"}) {
		t.Fatalf("distro = %v, %v", d, err)
	}
	if v := parseOSRelease(`NAME="a \"quoted\" \$name"` + "\n"); v["NAME"] != `a "quoted" $name` {
		t.Fatalf("NAME = %q", v["NAME"])
	}
}

// Assumption: the digest covers what Signal reads (distro and packages) and only that, so
// an unchanged list confirms by digest and a new version changes it.
func TestDigest(t *testing.T) {
	a, _ := ReadPackages(host(ubuntuStatus))
	b, _ := ReadPackages(host(ubuntuStatus))
	if a.GetDigest() == "" || a.GetDigest() != b.GetDigest() || len(a.GetDigest()) != 64 {
		t.Fatalf("digests %s %s", a.GetDigest(), b.GetDigest())
	}
	c, _ := ReadPackages(host(strings.Replace(ubuntuStatus, "5.2.21-2ubuntu4", "5.2.21-2ubuntu5", 1)))
	if c.GetDigest() == a.GetDigest() {
		t.Fatal("a new version must change the digest")
	}
}

// Assumption: a status file is only cut by a line or file bound with an error, never read
// short (a short file would be a shorter list).
func TestStanzasFailPastTheBound(t *testing.T) {
	r := &boundedReader{r: strings.NewReader("Package: a\nStatus: install ok installed\n\nPackage: b\n"), left: 20}
	n := 0
	err := Stanzas(r, func(Stanza) bool { n++; return true })
	if err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("err = %v after %d stanzas", err, n)
	}
}

// Assumption: dpkg ends the file without a blank line, indents continuation lines, and a
// stanza's fields are read as written.
func TestStanzasReadTheLastStanzaAndSkipContinuations(t *testing.T) {
	var got []Stanza
	err := Stanzas(strings.NewReader("Package: a\nDescription: x\n Package: not-a-field\n\n\nPackage: b\nVersion: 1"), func(s Stanza) bool {
		got = append(got, s)
		return true
	})
	if err != nil || len(got) != 2 || got[0]["Package"] != "a" || len(got[0]) != 2 || got[1]["Version"] != "1" {
		t.Fatalf("stanzas = %v, %v", got, err)
	}
}

func TestReasonIsBounded(t *testing.T) {
	if r := reason(fmt.Errorf("%s", strings.Repeat("é", 200))); len(r) > maxReasonBytes || !strings.HasPrefix(r, "é") {
		t.Fatalf("reason = %d bytes", len(r))
	}
}
