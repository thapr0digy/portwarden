// Package dpkg reads dpkg's package database without new privileges: the status file's
// stanzas (shared with the tamper check's package lookup) and, for Signal's
// asm.host.packages, the host's installed packages and the distribution os-release names
// (README "Host packages"). /var/lib/dpkg/status and /etc/os-release are world-readable.
// It never runs dpkg-query: the status file is what dpkg-query reads, and the list built
// here is what `dpkg-query -W -f '${Package} ${Version} ${source:Package}
// ${source:Version} ${Architecture}'` prints for the installed packages.
package dpkg

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

const (
	// StatusFile is dpkg's database of every package it knows.
	StatusFile = "/var/lib/dpkg/status"
	// maxStatusBytes bounds the status file read (a host with 6,000 packages has about 10 MiB).
	maxStatusBytes = 64 << 20
	// maxLineBytes bounds one line of it.
	maxLineBytes = 1 << 20
)

// Stanza is one paragraph of the status file: its single-line fields by name, as written
// ("Package", "Status", "Version", ...). Continuation lines (a Description's body,
// Conffiles) are left out.
type Stanza map[string]string

// errTooLarge is a status file over maxStatusBytes.
var errTooLarge = fmt.Errorf("larger than %d bytes", maxStatusBytes)

// Stanzas calls fn with each stanza of the status file r, in file order, until fn returns
// false. It fails on a read error, a line over 1 MiB or a file over 64 MiB.
func Stanzas(r io.Reader, fn func(Stanza) bool) error {
	sc := bufio.NewScanner(&boundedReader{r: r, left: maxStatusBytes})
	sc.Buffer(make([]byte, 64<<10), maxLineBytes)
	cur := Stanza{}
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.TrimSpace(line) == "":
			if len(cur) > 0 && !fn(cur) {
				return nil
			}
			cur = Stanza{}
		case line[0] == ' ' || line[0] == '\t' || line[0] == '#':
			// A continuation line, or a comment (deb822).
		default:
			if name, value, ok := strings.Cut(line, ":"); ok {
				cur[name] = strings.TrimSpace(value)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if len(cur) > 0 {
		fn(cur)
	}
	return nil
}

// boundedReader fails, rather than stops, past its limit: a cut status file would read as
// a shorter package list.
type boundedReader struct {
	r    io.Reader
	left int64
}

func (b *boundedReader) Read(p []byte) (int, error) {
	if b.left <= 0 {
		var probe [1]byte
		if n, err := b.r.Read(probe[:]); n > 0 {
			return 0, errTooLarge
		} else if err != nil {
			return 0, err
		}
		return 0, nil
	}
	if int64(len(p)) > b.left {
		p = p[:b.left]
	}
	n, err := b.r.Read(p)
	b.left -= int64(n)
	return n, err
}
