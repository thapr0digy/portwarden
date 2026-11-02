package procinfo

import (
	"testing"

	"github.com/thapr0digy/portwarden/internal/model"
)

func TestParseCgroupPath(t *testing.T) {
	h := "abababababababababababababababababababababababababababababababab"
	cases := []struct {
		name, path, unit string
		c                model.Container
	}{
		{"service", "/system.slice/nginx.service", "nginx.service", model.Container{}},
		{"session scope", "/user.slice/user-1000.slice/session-3.scope", "session-3.scope", model.Container{}},
		{"docker systemd", "/system.slice/docker-" + h + ".scope", "docker-" + h + ".scope", model.Container{Runtime: "docker", ID: h}},
		{"k8s containerd besteffort", "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod1a2b_3c.slice/cri-containerd-" + h + ".scope", "cri-containerd-" + h + ".scope", model.Container{Runtime: "containerd", ID: h}},
		{"k8s containerd guaranteed", "/kubepods.slice/kubepods-pod1a2b_3c.slice/cri-containerd-" + h + ".scope", "cri-containerd-" + h + ".scope", model.Container{Runtime: "containerd", ID: h}},
		{"k8s cgroupfs", "/kubepods/besteffort/pod1a2b3c/" + h, "", model.Container{Runtime: "kubernetes", ID: h}},
		{"crio", "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1.slice/crio-" + h + ".scope", "crio-" + h + ".scope", model.Container{Runtime: "cri-o", ID: h}},
		{"podman", "/machine.slice/libpod-" + h + ".scope", "libpod-" + h + ".scope", model.Container{Runtime: "podman", ID: h}},
		{"podman rootless", "/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-" + h + ".scope", "libpod-" + h + ".scope", model.Container{Runtime: "podman", ID: h}},
		{"podman nested child", "/machine.slice/libpod-" + h + ".scope/container", "libpod-" + h + ".scope", model.Container{Runtime: "podman", ID: h}},
		{"podman conmon", "/machine.slice/libpod-conmon-" + h + ".scope", "libpod-conmon-" + h + ".scope", model.Container{}},
		{"docker cgroupfs", "/docker/" + h, "", model.Container{Runtime: "docker", ID: h}},
		{"init scope", "/init.scope", "init.scope", model.Container{}},
		{"root", "/", "", model.Container{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			unit, c := ParseCgroupPath(tc.path)
			if unit != tc.unit || c != tc.c {
				t.Fatalf("ParseCgroupPath(%q) = %q, %+v; want %q, %+v", tc.path, unit, c, tc.unit, tc.c)
			}
		})
	}
}
