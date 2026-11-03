package tamper

import (
	"bufio"
	"os"
	"strings"
	"time"
)

// Default locations for Dpkg.
const (
	UpgradeMarker    = "/run/portwarden-agent/upgrading"
	DpkgInfoDir      = "/var/lib/dpkg/info"
	DpkgStatus       = "/var/lib/dpkg/status"
	UpgradeMarkerAge = 10 * time.Minute
)

// Dpkg is Packages for the agent's .deb: its prerm writes Marker (the version being
// installed) on upgrade; a change is the upgrade's when the marker is younger than
// MaxAge, dpkg's status says that version of Package is (being) installed, and its
// md5sums list the file with that content.
type Dpkg struct {
	Package, Marker, InfoDir, Status string
	MaxAge                           time.Duration
	Now                              func() time.Time
}

// NewDpkg returns Dpkg for package pkg at the default paths.
func NewDpkg(pkg string) *Dpkg {
	return &Dpkg{Package: pkg, Marker: UpgradeMarker, InfoDir: DpkgInfoDir, Status: DpkgStatus,
		MaxAge: UpgradeMarkerAge, Now: time.Now}
}

// Upgrading implements Packages.
func (d *Dpkg) Upgrading() (string, bool) {
	fi, err := os.Stat(d.Marker)
	if err != nil || d.Now().Sub(fi.ModTime()) > d.MaxAge {
		return "", false
	}
	b, err := os.ReadFile(d.Marker)
	if err != nil {
		return "", false
	}
	v := strings.TrimSpace(string(b))
	return v, v != ""
}

// Ships implements Packages.
func (d *Dpkg) Ships(version, path, sum string) bool {
	if d.statusVersion() != version {
		return false
	}
	f, err := os.Open(d.InfoDir + "/" + d.Package + ".md5sums")
	if err != nil {
		return false
	}
	defer f.Close()
	rel := strings.TrimPrefix(path, "/")
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		got, file, ok := strings.Cut(sc.Text(), "  ")
		if ok && file == rel {
			return got == sum
		}
	}
	return false
}

// statusVersion is the Version of Package in dpkg's status file.
func (d *Dpkg) statusVersion() string {
	f, err := os.Open(d.Status)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	in := false
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			in = false
		case strings.HasPrefix(line, "Package: "):
			in = strings.TrimPrefix(line, "Package: ") == d.Package
		case in && strings.HasPrefix(line, "Version: "):
			return strings.TrimPrefix(line, "Version: ")
		}
	}
	return ""
}
