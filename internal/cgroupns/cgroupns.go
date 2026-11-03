// Package cgroupns turns the cgroup paths a process's /proc/<pid>/cgroup shows into host
// cgroup v2 paths. In the host's cgroup namespace they are the same. In a private one (a
// container: a Kubernetes DaemonSet gets one on cgroup v2, and no pod field turns it off)
// paths are relative to the namespace's root, so a host service reads as
// "/../../system.slice/nginx.service"; the agent then needs its namespace root's host path
// to rebuild "/system.slice/nginx.service" (its systemd unit, and the cgroup it attaches
// the proxy-connection programs to under the host's /sys/fs/cgroup).
package cgroupns

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

// Translator maps namespace-relative cgroup paths to host paths. The zero value is the
// identity (the host's namespace).
type Translator struct {
	// Root is the host path of the namespace's root ("" in the host's namespace).
	Root string
}

// Host returns the host path for p, a path from /proc/<pid>/cgroup.
func (t Translator) Host(p string) string {
	if t.Root == "" || p == "" {
		return p
	}
	return path.Join(t.Root, p)
}

// Detect finds the agent's cgroup namespace root. procRoot is "/proc" (with the host's
// PID namespace, so /proc/1 is the host's init); cgroupRoot is the host's cgroup v2 tree
// ("/sys/fs/cgroup", bind-mounted from the host in a container). In the host's namespace
// (or when /proc/1 is not the host's init) it returns the identity.
func Detect(procRoot, cgroupRoot string) (Translator, error) {
	self, err1 := os.Readlink(filepath.Join(procRoot, "self", "ns", "cgroup"))
	init, err2 := os.Readlink(filepath.Join(procRoot, "1", "ns", "cgroup"))
	if err1 != nil || err2 != nil {
		return Translator{}, fmt.Errorf("cgroup namespaces: %w", errors.Join(err1, err2))
	}
	if self == init {
		return Translator{}, nil
	}
	// Host init sits at the host root: seen from here it is "/.." once per level of our
	// namespace root's depth.
	initPath, err := v2Path(filepath.Join(procRoot, "1", "cgroup"))
	if err != nil {
		return Translator{}, err
	}
	depth := strings.Count(initPath, "..")
	if depth == 0 {
		return Translator{}, fmt.Errorf("init's cgroup %q does not leave the agent's namespace", initPath)
	}
	// Our namespace root is our cgroup, or an ancestor of it: our own path is relative
	// to the root ("/" when we sit at it). Look for the directory at that depth that
	// holds us, by our pid in cgroup.procs (a host pid with hostPID).
	ownPath, err := v2Path(filepath.Join(procRoot, "self", "cgroup"))
	if err != nil {
		return Translator{}, err
	}
	pid := strconv.Itoa(os.Getpid())
	if b, err := os.ReadFile(filepath.Join(procRoot, "self", "stat")); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			pid = f[0] // the pid as /proc shows it (the host's, with hostPID)
		}
	}
	own := path.Clean(ownPath)
	var found string
	walkErr := filepath.WalkDir(cgroupRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(cgroupRoot, p)
		if err != nil {
			return nil
		}
		level := 0
		if rel != "." {
			level = strings.Count(rel, string(filepath.Separator)) + 1
		}
		if level < depth {
			return nil
		}
		// rel is a candidate root at the right depth; we must be in root+own.
		candidate := path.Join(cgroupRoot, filepath.ToSlash(rel), own)
		if holds(filepath.Join(candidate, "cgroup.procs"), pid) {
			found = "/" + filepath.ToSlash(rel)
			return fs.SkipAll
		}
		return fs.SkipDir
	})
	if walkErr != nil {
		return Translator{}, walkErr
	}
	if found == "" {
		return Translator{}, fmt.Errorf("no cgroup at depth %d under %s holds pid %s", depth, cgroupRoot, pid)
	}
	return Translator{Root: found}, nil
}

// v2Path reads the "0::<path>" line of a /proc cgroup file.
func v2Path(file string) (string, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		if p, ok := strings.CutPrefix(sc.Text(), "0::"); ok {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s has no cgroup v2 line", file)
}

func holds(procsFile, pid string) bool {
	b, err := os.ReadFile(procsFile)
	if err != nil {
		return false
	}
	for _, l := range strings.Split(string(b), "\n") {
		if l == pid {
			return true
		}
	}
	return false
}
