// Package preflight refuses to start the agent on a host it cannot work on.
package preflight

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/ebpf/btf"

	"github.com/thapr0digy/portwarden/internal/bpftarget"
)

const (
	minMajor, minMinor = 6, 8
	btfPath            = "/sys/kernel/btf/vmlinux"
	lockdownPath       = "/sys/kernel/security/lockdown"
)

// CheckKernelRelease fails when a `uname -r` string names a kernel older than 6.8.
func CheckKernelRelease(release string) error {
	major, minor, err := parseRelease(release)
	if err != nil {
		return err
	}
	if major < minMajor || (major == minMajor && minor < minMinor) {
		return fmt.Errorf("kernel %s is older than the supported floor %d.%d", release, minMajor, minMinor)
	}
	return nil
}

func parseRelease(release string) (major, minor int, err error) {
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return 0, 0, fmt.Errorf("cannot parse kernel release %q", release)
	}
	major, err = strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("cannot parse kernel release %q: %w", release, err)
	}
	minorDigits := parts[1]
	if end := strings.IndexFunc(minorDigits, func(r rune) bool { return r < '0' || r > '9' }); end >= 0 {
		minorDigits = minorDigits[:end]
	}
	minor, err = strconv.Atoi(minorDigits)
	if err != nil {
		return 0, 0, fmt.Errorf("cannot parse kernel release %q: %w", release, err)
	}
	return major, minor, nil
}

// CheckLockdown fails when the contents of the lockdown file (for example
// "none integrity [confidentiality]") show confidentiality mode, which stops BPF
// from reading kernel memory. Integrity mode is fine.
func CheckLockdown(contents string) error {
	if strings.Contains(contents, "[confidentiality]") {
		return errors.New("kernel lockdown is in confidentiality mode: BPF cannot read kernel memory")
	}
	return nil
}

func checkBTF(path string) error {
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("kernel BTF not available at %s: %w", path, err)
	}
	return nil
}

// checkLockdownFile treats a missing file as fine: the kernel has no lockdown LSM.
func checkLockdownFile(path string) error {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	return CheckLockdown(string(raw))
}

// MissingTargetsError reports every kernel function the agent's programs attach to that
// the running kernel's BTF lacks (or names more than once, which the loader refuses).
type MissingTargetsError struct {
	Release   string
	Missing   []bpftarget.Target
	Ambiguous []bpftarget.Target
}

func (e *MissingTargetsError) Error() string {
	n := len(e.Missing) + len(e.Ambiguous)
	var b strings.Builder
	fmt.Fprintf(&b, "kernel %s cannot attach %d kernel function", e.Release, n)
	if n != 1 {
		b.WriteString("s")
	}
	b.WriteString(" the agent traces:")
	if len(e.Missing) > 0 {
		b.WriteString(" missing " + joinTargets(e.Missing))
	}
	if len(e.Ambiguous) > 0 {
		if len(e.Missing) > 0 {
			b.WriteString(";")
		}
		b.WriteString(" ambiguous (several kernel symbols share the name) " + joinTargets(e.Ambiguous))
	}
	b.WriteString("; this kernel is not supported (the agent has no degraded mode)")
	return b.String()
}

func joinTargets(ts []bpftarget.Target) string {
	parts := make([]string, len(ts))
	for i, t := range ts {
		parts[i] = t.String()
	}
	return strings.Join(parts, ", ")
}

// CheckAttachTargets looks every target up in spec the way cilium/ebpf does when it
// loads the program: a function (a typedef for tp_btf) of exactly that name. A name that
// is absent or names another kind of type is missing; one that matches several is
// ambiguous, which the loader refuses too. All problems are reported in one
// *MissingTargetsError.
func CheckAttachTargets(spec *btf.Spec, targets []bpftarget.Target, release string) error {
	problems := &MissingTargetsError{Release: release}
	for _, t := range targets {
		var err error
		if t.IsTypedef() {
			var td *btf.Typedef
			err = spec.TypeByName(t.Func, &td)
		} else {
			var fn *btf.Func
			err = spec.TypeByName(t.Func, &fn)
		}
		switch {
		case err == nil:
		case errors.Is(err, btf.ErrNotFound):
			problems.Missing = append(problems.Missing, t)
		case errors.Is(err, btf.ErrMultipleMatches):
			problems.Ambiguous = append(problems.Ambiguous, t)
		default:
			return fmt.Errorf("look up %s in the kernel BTF: %w", t, err)
		}
	}
	if len(problems.Missing)+len(problems.Ambiguous) > 0 {
		return problems
	}
	return nil
}

// checkKernelTargets loads the kernel's BTF with load and checks targets against it. A
// BTF that cannot be read is reported apart from functions missing from it.
func checkKernelTargets(load func() (*btf.Spec, error), targets []bpftarget.Target, release string) error {
	spec, err := load()
	if err != nil {
		return fmt.Errorf("read kernel BTF at %s: %w", btfPath, err)
	}
	return CheckAttachTargets(spec, targets, release)
}

// Check runs every startup check against the live host, given the `uname -r` release
// and the kernel functions the agent's programs attach to. It runs before anything is
// attached.
func Check(kernelRelease string, targets []bpftarget.Target) error {
	if err := CheckKernelRelease(kernelRelease); err != nil {
		return err
	}
	if err := checkBTF(btfPath); err != nil {
		return err
	}
	if err := checkKernelTargets(btf.LoadKernelSpec, targets, kernelRelease); err != nil {
		return err
	}
	return checkLockdownFile(lockdownPath)
}
