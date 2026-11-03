package tamper

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)

type fakeCheck struct {
	name  string
	flags []Flag
	err   error
}

func (f *fakeCheck) Name() string         { return f.name }
func (f *fakeCheck) Run() ([]Flag, error) { return f.flags, f.err }

func kinds(fs []Flag) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Kind+":"+f.Subject)
	}
	return out
}

func TestMonitorRaisesOnceAndClears(t *testing.T) {
	c := &fakeCheck{name: "ptrace"}
	m := NewMonitor(c)
	if tr := m.Pass(t0); tr.Changed() || !tr.Status.Clean() || !reflect.DeepEqual(tr.Status.Checks, []string{"ptrace"}) {
		t.Fatalf("clean first pass: %+v", tr)
	}
	c.flags = []Flag{{Kind: KindPtraced, Subject: "self", Detail: "pid 7"}}
	tr := m.Pass(t0.Add(time.Second))
	if got := kinds(tr.Raised); !reflect.DeepEqual(got, []string{"ptraced:self"}) || len(tr.Cleared) != 0 {
		t.Fatalf("raise: %+v", tr)
	}
	// Still traced, with another detail: same flag, nothing new, since kept.
	c.flags = []Flag{{Kind: KindPtraced, Subject: "self", Detail: "pid 8"}}
	tr = m.Pass(t0.Add(2 * time.Second))
	if tr.Changed() || len(tr.Status.Flags) != 1 || !tr.Status.Flags[0].Since.Equal(t0.Add(time.Second)) ||
		tr.Status.Flags[0].Detail != "pid 8" {
		t.Fatalf("held: %+v", tr)
	}
	c.flags = nil
	tr = m.Pass(t0.Add(3 * time.Second))
	if got := kinds(tr.Cleared); !reflect.DeepEqual(got, []string{"ptraced:self"}) || !tr.Status.Clean() {
		t.Fatalf("clear: %+v", tr)
	}
}

func TestMonitorUnknownKeepsFlags(t *testing.T) {
	c := &fakeCheck{name: "unit", flags: []Flag{{Kind: KindUnitChanged, Subject: "/etc/x.service"}}}
	m := NewMonitor(c)
	m.Pass(t0)
	c.flags, c.err = nil, errors.New("bus down")
	tr := m.Pass(t0.Add(time.Second))
	if tr.Changed() || len(tr.Status.Flags) != 1 || !reflect.DeepEqual(tr.Status.Unknown, []string{"unit: bus down"}) {
		t.Fatalf("unknown must keep the flag and be reported: %+v", tr)
	}
	// Unknown from the start never raises anything.
	m2 := NewMonitor(&fakeCheck{name: "unit", err: errors.New("no unit")})
	if tr := m2.Pass(t0); tr.Changed() || !tr.Status.Clean() || len(tr.Status.Unknown) != 1 {
		t.Fatalf("unknown at start: %+v", tr)
	}
}

func TestMonitorStatsHook(t *testing.T) {
	m := NewMonitor()
	m.Stats = func(s *Status) { s.RingbufDrops = 3; s.RunCounts = map[string]uint64{"on_listen": 9} }
	if st := m.Pass(t0).Status; st.RingbufDrops != 3 || st.RunCounts["on_listen"] != 9 {
		t.Fatalf("stats: %+v", st)
	}
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSelfExe(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "portwarden-agent")
	write(t, exe, "build 1")
	base, err := HashFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	c := NewSelfExe(exe, base)
	if flags, err := c.Run(); err != nil || len(flags) != 0 {
		t.Fatalf("unchanged: %v %v", flags, err)
	}
	// Replaced by rename (a package upgrade or an attacker): new inode, new content.
	write(t, exe+".new", "build 2")
	if err := os.Rename(exe+".new", exe); err != nil {
		t.Fatal(err)
	}
	flags, err := c.Run()
	if err != nil || len(flags) != 1 || flags[0].Kind != KindBinaryReplaced || !strings.Contains(flags[0].Detail, "on disk") {
		t.Fatalf("replaced: %+v %v", flags, err)
	}
	// Put back byte for byte (new inode, same content): no longer flagged.
	write(t, exe+".new", "build 1")
	if err := os.Rename(exe+".new", exe); err != nil {
		t.Fatal(err)
	}
	if flags, err := c.Run(); err != nil || len(flags) != 0 {
		t.Fatalf("restored: %v %v", flags, err)
	}
	if err := os.Remove(exe); err != nil {
		t.Fatal(err)
	}
	if flags, _ := c.Run(); len(flags) != 1 || flags[0].Kind != KindBinaryMissing {
		t.Fatalf("missing: %+v", flags)
	}
}

func TestFileSetUnit(t *testing.T) {
	dir := t.TempDir()
	unit := filepath.Join(dir, "portwarden-agent.service")
	dropin := filepath.Join(dir, "override.conf")
	write(t, unit, "[Service]\nExecStart=/usr/bin/portwarden-agent\n")
	paths := []string{unit}
	s, err := NewFileSet("unit", KindUnitChanged, func() ([]string, error) { return paths, nil })
	if err != nil {
		t.Fatal(err)
	}
	if flags, err := s.Run(); err != nil || len(flags) != 0 {
		t.Fatalf("unchanged: %v %v", flags, err)
	}
	// A drop-in appears (after a daemon-reload, systemd lists it).
	write(t, dropin, "[Service]\nExecStart=\nExecStart=/bin/true\n")
	paths = []string{unit, dropin}
	flags, _ := s.Run()
	if got := kinds(flags); !reflect.DeepEqual(got, []string{KindUnitChanged + ":" + dropin}) {
		t.Fatalf("drop-in added: %v", got)
	}
	// The unit file is edited in place.
	time.Sleep(10 * time.Millisecond)
	write(t, unit, "[Service]\nExecStart=/tmp/evil\n")
	flags, _ = s.Run()
	if len(flags) != 2 {
		t.Fatalf("edited and added: %+v", flags)
	}
	// A failing list is unknown.
	s2, _ := NewFileSet("unit", KindUnitChanged, StaticFiles(unit))
	s2.list = func() ([]string, error) { return nil, errors.New("bus") }
	if _, err := s2.Run(); err == nil {
		t.Fatal("a failing list must be unknown")
	}
}

func TestCounter(t *testing.T) {
	v := uint64(0)
	now := t0
	c := NewCounter("ringbuf_drops", func() (uint64, error) { return v, nil })
	c.now = func() time.Time { return now }
	c.PageRate = 100
	if flags, _ := c.Run(); len(flags) != 0 {
		t.Fatalf("zero: %v", flags)
	}
	now, v = now.Add(time.Minute), 5
	if flags, _ := c.Run(); len(flags) != 1 || flags[0].Kind != KindEventsDropped || !flags[0].Info {
		t.Fatalf("a few drops are informational: %+v", flags)
	}
	now, v = now.Add(30*time.Second), 105 // 200 per minute
	if flags, _ := c.Run(); len(flags) != 1 || flags[0].Info {
		t.Fatalf("drops at or above the page rate page: %+v", flags)
	}
	now = now.Add(time.Minute)
	if flags, _ := c.Run(); len(flags) != 0 {
		t.Fatalf("no new drops: %v", flags)
	}
	v = 2 // someone wrote the counters map
	flags, _ := c.Run()
	if len(flags) != 1 || flags[0].Kind != KindCounterReset || flags[0].Info || flags[0].Fingerprint != "105>2" {
		t.Fatalf("reset: %+v", flags)
	}
	// Raised for that pass only; the new value is the floor, so a second reset raises again.
	if flags, _ := c.Run(); len(flags) != 0 {
		t.Fatalf("after the reset: %v", flags)
	}
	v = 0
	if flags, _ := c.Run(); len(flags) != 1 || flags[0].Fingerprint != "2>0" {
		t.Fatalf("second reset: %+v", flags)
	}
}

// A second, different change to a flagged file is a new flag (a new page), not hidden by
// the first (ruling R-c).
func TestNewFingerprintIsNewFlag(t *testing.T) {
	dir := t.TempDir()
	unit := filepath.Join(dir, "x.service")
	write(t, unit, "a")
	s, err := NewFileSet("unit", KindUnitChanged, StaticFiles(unit))
	if err != nil {
		t.Fatal(err)
	}
	m := NewMonitor(s)
	m.Pass(t0)
	write(t, unit, "b")
	if tr := m.Pass(t0.Add(time.Second)); len(tr.Raised) != 1 {
		t.Fatalf("first edit: %+v", tr)
	}
	time.Sleep(10 * time.Millisecond)
	write(t, unit, "c")
	tr := m.Pass(t0.Add(2 * time.Second))
	if len(tr.Raised) != 1 || len(tr.Cleared) != 1 || tr.Raised[0].Fingerprint == tr.Cleared[0].Fingerprint {
		t.Fatalf("second edit must raise a new flag and clear the old: %+v", tr)
	}
}

type fakePkgs struct {
	version   string
	upgrading bool
	ships     map[string]string // path -> md5
}

func (f fakePkgs) Upgrading() (string, bool) { return f.version, f.upgrading }
func (f fakePkgs) Ships(version, path, sum string) bool {
	return version == f.version && f.ships[path] == sum
}

func TestUpgradeIsInfo(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "portwarden-agent")
	write(t, exe, "v1")
	base, _ := HashFile(exe)
	c := NewSelfExe(exe, base)
	pk := fakePkgs{version: "1.1.0", upgrading: true, ships: map[string]string{}}
	c.Packages = pk
	write(t, exe+".new", "v2")
	if err := os.Rename(exe+".new", exe); err != nil {
		t.Fatal(err)
	}
	// Mid-upgrade, before dpkg lists the new file: unknown, not tamper.
	if _, err := c.Run(); err == nil {
		t.Fatal("an unlisted change during an upgrade must be unknown")
	}
	sum, _ := md5File(exe)
	pk.ships[exe] = sum
	flags, err := c.Run()
	if err != nil || len(flags) != 1 || flags[0].Kind != KindUpgraded || !flags[0].Info {
		t.Fatalf("upgraded: %+v %v", flags, err)
	}
	// The same content with no upgrade in progress is tamper.
	c.Packages = fakePkgs{}
	if flags, _ := c.Run(); len(flags) != 1 || flags[0].Kind != KindBinaryReplaced || flags[0].Info {
		t.Fatalf("no marker: %+v", flags)
	}
	// Content the package does not ship, during an upgrade, is never "upgraded".
	pk.ships[exe] = "00"
	c.Packages = pk
	if _, err := c.Run(); err == nil {
		t.Fatal("foreign content during an upgrade must not pass as upgraded")
	}
}

func TestLazyRetriesUntilReady(t *testing.T) {
	ready := false
	l := &Lazy{CheckName: "unit", Init: func() (Check, error) {
		if !ready {
			return nil, errors.New("system bus not up")
		}
		return &fakeCheck{name: "unit"}, nil
	}}
	m := NewMonitor(l)
	if st := m.Pass(t0).Status; len(st.Unknown) != 1 || !strings.Contains(st.Unknown[0], "not started yet") || st.Checks[0] != "unit" {
		t.Fatalf("before the bus: %+v", st)
	}
	ready = true
	if st := m.Pass(t0.Add(time.Second)).Status; len(st.Unknown) != 0 {
		t.Fatalf("after: %+v", st)
	}
}

func TestAttachments(t *testing.T) {
	links := []Attachment{
		{Name: "on_listen", LinkID: 1, WantProg: 10, WantTag: "aa", Attached: true, Prog: 10},
		{Name: "on_connect4", Where: "/system.slice/nginx.service", LinkID: 2, WantProg: 11, WantTag: "bb", Attached: false, Prog: 11},
		{Name: "on_connect6", Where: "/system.slice/nginx.service", LinkID: 3, WantProg: 12, WantTag: "cc", Attached: true, Prog: 99},
	}
	flags, err := NewAttachments("probes", func() ([]Attachment, error) { return links, nil }).Run()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{KindProbeDetached + ":on_connect4@/system.slice/nginx.service", KindProgramReplaced + ":on_connect6@/system.slice/nginx.service"}
	if got := kinds(flags); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestTracer(t *testing.T) {
	proc := t.TempDir()
	task := filepath.Join(proc, "self", "task")
	for tid, tracer := range map[string]string{"100": "0", "101": "4242"} {
		if err := os.MkdirAll(filepath.Join(task, tid), 0o755); err != nil {
			t.Fatal(err)
		}
		write(t, filepath.Join(task, tid, "status"), "Name:\tportwarden\nState:\tS\nTracerPid:\t"+tracer+"\n")
	}
	if err := os.MkdirAll(filepath.Join(proc, "4242"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(proc, "4242", "comm"), "gdb\n")
	flags, err := (&Tracer{TaskDir: task}).Run()
	if err != nil || len(flags) != 1 || flags[0].Kind != KindPtraced || flags[0].Detail != "pid 4242 (gdb) traces thread(s) 101" {
		t.Fatalf("traced: %+v %v", flags, err)
	}
	write(t, filepath.Join(task, "101", "status"), "TracerPid:\t0\n")
	if flags, err := (&Tracer{TaskDir: task}).Run(); err != nil || len(flags) != 0 {
		t.Fatalf("untraced: %+v %v", flags, err)
	}
	if _, err := (&Tracer{TaskDir: filepath.Join(proc, "nope")}).Run(); err == nil {
		t.Fatal("an unreadable task dir must be unknown")
	}
}
