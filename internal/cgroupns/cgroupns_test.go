package cgroupns

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func mk(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// fixture builds a /proc and a host cgroup tree for an agent in a private cgroup
// namespace rooted at /kubepods.slice/pod-a.slice/cri-containerd-abc.scope.
func fixture(t *testing.T, selfNS, initNS string) (proc, cg string) {
	t.Helper()
	dir := t.TempDir()
	proc, cg = filepath.Join(dir, "proc"), filepath.Join(dir, "cgroup")
	for who, ns := range map[string]string{"self": selfNS, "1": initNS} {
		if err := os.MkdirAll(filepath.Join(proc, who, "ns"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(ns, filepath.Join(proc, who, "ns", "cgroup")); err != nil {
			t.Fatal(err)
		}
	}
	mk(t, filepath.Join(proc, "1", "cgroup"), "0::/../../..\n")
	mk(t, filepath.Join(proc, "self", "cgroup"), "0::/\n")
	mk(t, filepath.Join(proc, "self", "stat"), "4242 (portwarden-agen) S 1\n")
	mk(t, filepath.Join(cg, "kubepods.slice", "pod-b.slice", "cri-containerd-def.scope", "cgroup.procs"), "77\n")
	mk(t, filepath.Join(cg, "kubepods.slice", "pod-a.slice", "cri-containerd-abc.scope", "cgroup.procs"), "4241\n4242\n")
	mk(t, filepath.Join(cg, "system.slice", "nginx.service", "cgroup.procs"), "100\n")
	return proc, cg
}

func TestDetectPrivateNamespace(t *testing.T) {
	proc, cg := fixture(t, "cgroup:[4026532999]", "cgroup:[4026531835]")
	tr, err := Detect(proc, cg)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Root != "/kubepods.slice/pod-a.slice/cri-containerd-abc.scope" {
		t.Fatalf("root = %q", tr.Root)
	}
	for in, want := range map[string]string{
		"/../../../system.slice/nginx.service": "/system.slice/nginx.service",
		"/":                                    "/kubepods.slice/pod-a.slice/cri-containerd-abc.scope",
		"/../../pod-b.slice/cri-containerd-def.scope": "/kubepods.slice/pod-b.slice/cri-containerd-def.scope",
		"": "",
	} {
		if got := tr.Host(in); got != want {
			t.Errorf("Host(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDetectHostNamespace(t *testing.T) {
	proc, cg := fixture(t, "cgroup:[4026531835]", "cgroup:[4026531835]")
	tr, err := Detect(proc, cg)
	if err != nil || tr.Root != "" || tr.Host("/system.slice/x.service") != "/system.slice/x.service" {
		t.Fatalf("host namespace: %+v %v", tr, err)
	}
}

func TestDetectNotFound(t *testing.T) {
	proc, cg := fixture(t, "cgroup:[4026532999]", "cgroup:[4026531835]")
	mk(t, filepath.Join(proc, "self", "stat"), strconv.Itoa(999999)+" (x) S 1\n")
	if _, err := Detect(proc, cg); err == nil {
		t.Fatal("a pid in no cgroup must be an error")
	}
}
