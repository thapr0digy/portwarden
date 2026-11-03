package tamper

import (
	"bufio"
	"crypto/md5" //nolint:gosec // dpkg's md5sums are MD5; this only matches them
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// MaxHashBytes bounds how much of a watched file is hashed; a larger file is unknown.
const MaxHashBytes = 512 << 20

// HashFile returns the hex SHA-256 of the file at path.
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, MaxHashBytes+1))
	if err != nil {
		return "", err
	}
	if n > MaxHashBytes {
		return "", fmt.Errorf("%s is larger than %d bytes", path, MaxHashBytes)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func short(hash string) string {
	if len(hash) > 12 {
		return hash[:12]
	}
	return hash
}

// watchedFile is one file with the hash it must keep. The file is re-hashed only when
// its stat signature (device, inode, size, mode, mtime and, on Linux, ctime) changes; a
// content change without a signature change needs raw disk writes or a clock change.
type watchedFile struct {
	path     string
	baseline string
	sig      string // "" until the first look, and after the file went missing
	got      string // the hash for sig
	// racy: the file was modified within racyWindow of being hashed, so a write in the
	// same timestamp tick could leave the signature unchanged; it is hashed again on the
	// next look (git's "racily clean" rule).
	racy bool
}

// racyWindow covers coarse file timestamps (one kernel tick) with a wide margin.
const racyWindow = 2 * time.Second

// fileState is what one look saw.
type fileState struct {
	missing, changed bool
	got              string // sha256 on disk (when present)
}

func (st fileState) detail(baseline string) string {
	if st.missing {
		return "removed"
	}
	return fmt.Sprintf("sha256 %s on disk, %s at start", short(st.got), short(baseline))
}

// fingerprint identifies what was seen: the new content's hash, or "removed". A new
// fingerprint for the same file is a new flag (a second edit pages again).
func (st fileState) fingerprint() string {
	if st.missing {
		return "removed"
	}
	return short(st.got)
}

func (w *watchedFile) look() (fileState, error) {
	fi, err := os.Stat(w.path)
	if errors.Is(err, fs.ErrNotExist) {
		w.sig = ""
		return fileState{missing: true, changed: true}, nil
	}
	if err != nil {
		return fileState{}, err
	}
	if sig := signature(fi); sig != w.sig || w.racy {
		got, err := HashFile(w.path)
		if err != nil {
			return fileState{}, err
		}
		w.sig, w.got = sig, got
		w.racy = time.Since(fi.ModTime()) < racyWindow
	}
	return fileState{changed: w.got != w.baseline, got: w.got}, nil
}

// Packages tells a package upgrade of the agent apart from tampering (ruling R-b).
type Packages interface {
	// Upgrading reports whether the agent's package is being upgraded (the marker its
	// prerm writes, recent enough), and the version being installed.
	Upgrading() (version string, ok bool)
	// Ships reports whether the installed package, at that version, ships the file at
	// path with this MD5 (dpkg's md5sums).
	Ships(version, path, md5 string) bool
}

// judgeUpgrade decides a changed file while an upgrade may be running: upgraded (an
// informational flag) when the package being installed ships exactly this content,
// unknown while the upgrade runs and the package database does not list it yet, and
// replaced (ok=false) otherwise.
func judgeUpgrade(pkgs Packages, path string, st fileState) (flag *Flag, err error, decided bool) {
	if pkgs == nil || st.missing {
		return nil, nil, false
	}
	version, upgrading := pkgs.Upgrading()
	if !upgrading {
		return nil, nil, false
	}
	sum, err := md5File(path)
	if err != nil {
		return nil, err, true
	}
	if pkgs.Ships(version, path, sum) {
		return &Flag{Kind: KindUpgraded, Subject: path, Info: true, Fingerprint: short(st.got),
			Detail: "replaced by the package upgrade to " + version}, nil, true
	}
	return nil, fmt.Errorf("%s changed during the upgrade to %s and is not (yet) what that package ships", path, version), true
}

func md5File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := md5.New()
	if _, err := io.Copy(h, io.LimitReader(f, MaxHashBytes)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// SelfExe checks the agent's executable: the file at path must hash like the running
// image (baseline, the hash of /proc/self/exe at start).
type SelfExe struct {
	f watchedFile
	// Packages, when set, turns a change that the package upgrade made into "upgraded".
	Packages Packages
}

// NewSelfExe watches path against baseline.
func NewSelfExe(path, baseline string) *SelfExe {
	return &SelfExe{f: watchedFile{path: path, baseline: baseline}}
}

// Name implements Check.
func (*SelfExe) Name() string { return "self_exe" }

// Run implements Check.
func (s *SelfExe) Run() ([]Flag, error) {
	st, err := s.f.look()
	if err != nil {
		return nil, err
	}
	if !st.changed {
		return nil, nil
	}
	if f, err, decided := judgeUpgrade(s.Packages, s.f.path, st); decided {
		if err != nil {
			return nil, err
		}
		return []Flag{*f}, nil
	}
	if st.missing {
		return []Flag{{Kind: KindBinaryMissing, Subject: s.f.path, Detail: "the executable was removed", Fingerprint: "removed"}}, nil
	}
	return []Flag{{Kind: KindBinaryReplaced, Subject: s.f.path, Detail: st.detail(s.f.baseline), Fingerprint: st.fingerprint()}}, nil
}

// FileSet checks a set of files that may itself change: a systemd unit's fragment and
// drop-ins (List re-reads which files make up the unit each pass), or a fixed list.
type FileSet struct {
	name, kind string
	list       func() ([]string, error)
	files      map[string]*watchedFile
	baseline   []string
	// Packages, when set, turns a change that the package upgrade made into "upgraded".
	Packages Packages
}

// NewFileSet records the files list returns now and their hashes. Each later Run flags
// (with kind) a file that changed or disappeared, and a file added to the list.
func NewFileSet(name, kind string, list func() ([]string, error)) (*FileSet, error) {
	paths, err := list()
	if err != nil {
		return nil, err
	}
	s := &FileSet{name: name, kind: kind, list: list, files: map[string]*watchedFile{}}
	for _, p := range paths {
		h, err := HashFile(p)
		if err != nil {
			return nil, fmt.Errorf("hash %s: %w", p, err)
		}
		s.files[p] = &watchedFile{path: p, baseline: h}
		s.baseline = append(s.baseline, p)
	}
	slices.Sort(s.baseline)
	return s, nil
}

// StaticFiles is a list function for a fixed set of paths.
func StaticFiles(paths ...string) func() ([]string, error) {
	return func() ([]string, error) { return paths, nil }
}

// Files returns the files recorded at start.
func (s *FileSet) Files() []string { return slices.Clone(s.baseline) }

// Name implements Check.
func (s *FileSet) Name() string { return s.name }

// Run implements Check.
func (s *FileSet) Run() ([]Flag, error) {
	paths, err := s.list()
	if err != nil {
		return nil, err
	}
	var flags []Flag
	listed := map[string]bool{}
	for _, p := range paths {
		listed[p] = true
		if _, ok := s.files[p]; !ok {
			fp := "added"
			if h, err := HashFile(p); err == nil {
				fp = short(h)
			}
			flags = append(flags, Flag{Kind: s.kind, Subject: p, Detail: "added since start", Fingerprint: fp})
		}
	}
	var errs []error
	for _, p := range s.baseline {
		w := s.files[p]
		st, err := w.look()
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if !st.changed {
			if !listed[p] {
				flags = append(flags, Flag{Kind: s.kind, Subject: p, Detail: "no longer part of it", Fingerprint: "unlisted"})
			}
			continue
		}
		if f, err, decided := judgeUpgrade(s.Packages, p, st); decided {
			if err != nil {
				errs = append(errs, err)
			} else {
				flags = append(flags, *f)
			}
			continue
		}
		flags = append(flags, Flag{Kind: s.kind, Subject: p, Detail: st.detail(w.baseline), Fingerprint: st.fingerprint()})
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return flags, nil
}

// Lazy is a check whose baseline cannot be taken yet (the system bus is not up early in
// boot): every pass retries init until it succeeds, and reports unknown until then, so
// the check is never dropped for the run (ruling R-d).
type Lazy struct {
	CheckName string
	Init      func() (Check, error)
	// OnReady, when set, is called once with the initialised check.
	OnReady func(Check)
	c       Check
}

// Name implements Check.
func (l *Lazy) Name() string { return l.CheckName }

// Run implements Check.
func (l *Lazy) Run() ([]Flag, error) {
	if l.c == nil {
		c, err := l.Init()
		if err != nil {
			return nil, fmt.Errorf("not started yet: %w", err)
		}
		l.c = c
		if l.OnReady != nil {
			l.OnReady(c)
		}
	}
	return l.c.Run()
}

// Counter checks that a kernel counter only rises: a decrease means its map was written
// (counter_reset, raised for the pass that saw it; the new value is the floor from then
// on, so a later reset raises again); a rise since the last pass is events_dropped,
// informational unless it reaches PageRate per minute.
type Counter struct {
	name string
	read func() (uint64, error)
	now  func() time.Time
	last uint64
	at   time.Time
	seen bool
	// PageRate: drops per minute at or above which events_dropped pages (0: never).
	PageRate float64
}

// NewCounter watches the counter read returns, named name (e.g. "ringbuf_drops").
func NewCounter(name string, read func() (uint64, error)) *Counter {
	return &Counter{name: name, read: read, now: time.Now}
}

// Name implements Check.
func (c *Counter) Name() string { return "counters" }

// Run implements Check.
func (c *Counter) Run() ([]Flag, error) {
	v, err := c.read()
	if err != nil {
		return nil, err
	}
	now := c.now()
	var flags []Flag
	switch {
	case !c.seen:
		if v > 0 {
			flags = append(flags, Flag{Kind: KindEventsDropped, Subject: c.name, Detail: fmt.Sprintf("%d dropped before the first pass", v),
				Info: true, Fingerprint: strconv.FormatUint(v, 10)})
		}
	case v < c.last:
		flags = append(flags, Flag{Kind: KindCounterReset, Subject: c.name,
			Detail: fmt.Sprintf("went down from %d to %d", c.last, v), Fingerprint: fmt.Sprintf("%d>%d", c.last, v)})
	case v > c.last:
		n := v - c.last
		f := Flag{Kind: KindEventsDropped, Subject: c.name, Detail: fmt.Sprintf("+%d (total %d)", n, v), Info: true,
			Fingerprint: strconv.FormatUint(v, 10)}
		if mins := now.Sub(c.at).Minutes(); c.PageRate > 0 && mins > 0 && float64(n)/mins >= c.PageRate {
			f.Info = false
			f.Detail += fmt.Sprintf(", %.0f per minute (page rate %.0f)", float64(n)/mins, c.PageRate)
		}
		flags = append(flags, f)
	}
	c.last, c.at, c.seen = v, now, true
	return flags, nil
}

// Attachment is one eBPF link the agent holds: what it attached and what the kernel
// reports for it now.
type Attachment struct {
	// Name is the program's name (on_listen, on_connect4, ...); Where qualifies it for
	// links of one program attached in several places (a cgroup path).
	Name, Where string
	LinkID      uint32
	// WantProg and WantTag are the program the agent loaded and attached.
	WantProg uint32
	WantTag  string
	// Attached is false when the kernel reports the link detached.
	Attached bool
	// Prog is the program the link runs now.
	Prog uint32
}

func (a Attachment) subject() string {
	if a.Where == "" {
		return a.Name
	}
	return a.Name + "@" + a.Where
}

// Attachments checks the links list returns.
type Attachments struct {
	name string
	list func() ([]Attachment, error)
}

// NewAttachments watches the links that list returns (e.g. probes.Probes.Attachments).
func NewAttachments(name string, list func() ([]Attachment, error)) *Attachments {
	return &Attachments{name: name, list: list}
}

// Name implements Check.
func (a *Attachments) Name() string { return a.name }

// Run implements Check.
func (a *Attachments) Run() ([]Flag, error) {
	links, err := a.list()
	if err != nil {
		return nil, err
	}
	var flags []Flag
	for _, l := range links {
		switch {
		case !l.Attached:
			flags = append(flags, Flag{Kind: KindProbeDetached, Subject: l.subject(),
				Detail:      fmt.Sprintf("link %d (program %d, tag %s) is detached", l.LinkID, l.WantProg, l.WantTag),
				Fingerprint: strconv.FormatUint(uint64(l.LinkID), 10)})
		case l.Prog != l.WantProg:
			flags = append(flags, Flag{Kind: KindProgramReplaced, Subject: l.subject(),
				Detail:      fmt.Sprintf("link %d runs program %d, loaded %d (tag %s)", l.LinkID, l.Prog, l.WantProg, l.WantTag),
				Fingerprint: strconv.FormatUint(uint64(l.Prog), 10)})
		}
	}
	return flags, nil
}

// Tracer checks that no thread of the process has a tracer.
type Tracer struct {
	// TaskDir is /proc/self/task (or a test fixture).
	TaskDir string
}

// Name implements Check.
func (*Tracer) Name() string { return "ptrace" }

// Run implements Check.
func (t *Tracer) Run() ([]Flag, error) {
	entries, err := os.ReadDir(t.TaskDir)
	if err != nil {
		return nil, err
	}
	tracers := map[int][]string{}
	read := 0
	for _, e := range entries {
		tid := e.Name()
		pid, err := tracerPid(filepath.Join(t.TaskDir, tid, "status"))
		if errors.Is(err, fs.ErrNotExist) {
			continue // the thread exited
		}
		if err != nil {
			return nil, err
		}
		read++
		if pid != 0 {
			tracers[pid] = append(tracers[pid], tid)
		}
	}
	if read == 0 {
		return nil, fmt.Errorf("no thread status readable under %s", t.TaskDir)
	}
	if len(tracers) == 0 {
		return nil, nil
	}
	var parts, pids []string
	for _, pid := range slices.Sorted(maps.Keys(tracers)) {
		pids = append(pids, strconv.Itoa(pid))
		tids := tracers[pid]
		slices.Sort(tids)
		parts = append(parts, fmt.Sprintf("pid %d%s traces thread(s) %s", pid, commOf(t.TaskDir, pid), strings.Join(tids, ",")))
	}
	return []Flag{{Kind: KindPtraced, Subject: "self", Detail: strings.Join(parts, "; "), Fingerprint: strings.Join(pids, ",")}}, nil
}

// commOf names the tracer, read from /proc/<pid>/comm next to the task dir's /proc.
func commOf(taskDir string, pid int) string {
	procRoot := filepath.Dir(filepath.Dir(taskDir)) // /proc/self/task -> /proc
	b, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "comm"))
	if err != nil {
		return ""
	}
	return " (" + strings.TrimSpace(string(b)) + ")"
}

func tracerPid(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "TracerPid:"); ok {
			return strconv.Atoi(strings.TrimSpace(v))
		}
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	return 0, fmt.Errorf("%s has no TracerPid line", path)
}
