// Package procinfo resolves a process's executable, command line, hash, systemd
// unit and container from /proc and the cgroup v2 filesystem.
package procinfo

import (
	"regexp"
	"strings"

	"github.com/thapr0digy/portwarden/internal/model"
)

// containerScope matches a systemd scope named after a container; libpod-conmon-
// scopes (the monitor) do not match because the id must follow the prefix directly.
var containerScope = regexp.MustCompile(`^(docker|cri-containerd|crio|libpod)-([0-9a-f]{64})\.scope$`)

var scopeRuntime = map[string]string{
	"docker":         "docker",
	"cri-containerd": "containerd",
	"crio":           "cri-o",
	"libpod":         "podman",
}

var hexID = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ParseCgroupPath derives the systemd unit and container from a cgroup v2 path
// such as "/system.slice/nginx.service".
func ParseCgroupPath(path string) (unit string, c model.Container) {
	elems := strings.FieldsFunc(path, func(r rune) bool { return r == '/' })
	// podman nests the workload in a "container" child of its scope
	if n := len(elems); n > 0 && elems[n-1] == "container" {
		elems = elems[:n-1]
	}
	if len(elems) == 0 {
		return "", model.Container{}
	}
	for i := len(elems) - 1; i >= 0; i-- {
		if isUnitName(elems[i]) {
			unit = elems[i]
			break
		}
	}
	last := elems[len(elems)-1]
	if m := containerScope.FindStringSubmatch(last); m != nil {
		return unit, model.Container{Runtime: scopeRuntime[m[1]], ID: m[2]}
	}
	if hexID.MatchString(last) {
		switch elems[0] {
		case "docker":
			c = model.Container{Runtime: "docker", ID: last}
		case "kubepods":
			c = model.Container{Runtime: "kubernetes", ID: last}
		}
	}
	return unit, c
}

func isUnitName(s string) bool {
	return strings.HasSuffix(s, ".service") || strings.HasSuffix(s, ".scope") || strings.HasSuffix(s, ".socket")
}
