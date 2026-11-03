package tamper

import (
	"bufio"
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
	detail   string // the verdict for sig: "" when the content matches the baseline
}

// look returns a non-empty detail when the file no longer matches its baseline, and
// whether it is missing.
func (w *watchedFile) look() (detail string, missing bool, err error) {
	fi, err := os.Stat(w.path)
	if errors.Is(err, fs.ErrNotExist) {
		w.sig = ""
		return "removed", true, nil
	}
	if err != nil {
		return "", false, err
	}
	sig := signature(fi)
	if sig == w.sig {
		return w.detail, false, nil
	}
	got, err := HashFile(w.path)
	if err != nil {
		return "", false, err
	}
	w.sig, w.detail = sig, ""
	if got != w.baseline {
		w.detail = fmt.Sprintf("sha256 %s on disk, %s at start", short(got), short(w.baseline))
	}
	return w.detail, false, nil
}

// SelfExe checks the agent's executable: the file at path must hash like the running
// image (baseline, the hash of /proc/self/exe at start).
type SelfExe struct {
	f watchedFile
}

// NewSelfExe watches path against baseline.
func NewSelfExe(path, baseline string) *SelfExe {
	return &SelfExe{f: watchedFile{path: path, baseline: baseline}}
}

// Name implements Check.
func (*SelfExe) Name() string { return "self_exe" }

// Run implements Check.
func (s *SelfExe) Run() ([]Flag, error) {
	detail, missing, err := s.f.look()
	switch {
	case err != nil:
		return nil, err
	case missing:
		return []Flag{{Kind: KindBinaryMissing, Subject: s.f.path, Detail: "the executable was removed"}}, nil
	case detail != "":
		return []Flag{{Kind: KindBinaryReplaced, Subject: s.f.path, Detail: detail}}, nil
	}
	return nil, nil
}

// FileSet checks a set of files that may itself change: a systemd unit's fragment and
// drop-ins (List re-reads which files make up the unit each pass), or a fixed list.
type FileSet struct {
	name, kind string
	list       func() ([]string, error)
	files      map[string]*watchedFile
	baseline   []string
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
			flags = append(flags, Flag{Kind: s.kind, Subject: p, Detail: "added since start"})
		}
	}
	var errs []error
	for _, p := range s.baseline {
		w := s.files[p]
		detail, _, err := w.look()
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if detail == "" && !listed[p] {
			detail = "no longer part of it"
		}
		if detail != "" {
			flags = append(flags, Flag{Kind: s.kind, Subject: p, Detail: detail})
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return flags, nil
}

// Counter checks that a kernel counter only rises: a decrease means its map was written
// (counter_reset); a rise since the last pass is reported as events_dropped.
type Counter struct {
	name string
	read func() (uint64, error)
	last uint64
	seen bool
	// Peak is the highest value read, the floor a reset is judged against.
	peak uint64
}

// NewCounter watches the counter read returns, named name (e.g. "ringbuf_drops").
func NewCounter(name string, read func() (uint64, error)) *Counter {
	return &Counter{name: name, read: read}
}

// Name implements Check.
func (c *Counter) Name() string { return "counters" }

// Run implements Check.
func (c *Counter) Run() ([]Flag, error) {
	v, err := c.read()
	if err != nil {
		return nil, err
	}
	var flags []Flag
	switch {
	case !c.seen:
		if v > 0 {
			flags = append(flags, Flag{Kind: KindEventsDropped, Subject: c.name, Detail: fmt.Sprintf("%d dropped", v)})
		}
	case v < c.peak:
		flags = append(flags, Flag{Kind: KindCounterReset, Subject: c.name,
			Detail: fmt.Sprintf("went down from %d to %d", c.peak, v)})
	case v > c.last:
		flags = append(flags, Flag{Kind: KindEventsDropped, Subject: c.name, Detail: fmt.Sprintf("+%d (total %d)", v-c.last, v)})
	}
	c.last, c.seen = v, true
	c.peak = max(c.peak, v)
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
				Detail: fmt.Sprintf("link %d (program %d, tag %s) is detached", l.LinkID, l.WantProg, l.WantTag)})
		case l.Prog != l.WantProg:
			flags = append(flags, Flag{Kind: KindProgramReplaced, Subject: l.subject(),
				Detail: fmt.Sprintf("link %d runs program %d, loaded %d (tag %s)", l.LinkID, l.Prog, l.WantProg, l.WantTag)})
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
	var parts []string
	for _, pid := range slices.Sorted(maps.Keys(tracers)) {
		tids := tracers[pid]
		slices.Sort(tids)
		parts = append(parts, fmt.Sprintf("pid %d%s traces thread(s) %s", pid, commOf(t.TaskDir, pid), strings.Join(tids, ",")))
	}
	return []Flag{{Kind: KindPtraced, Subject: "self", Detail: strings.Join(parts, "; ")}}, nil
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
