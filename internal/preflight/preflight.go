// Package preflight refuses to start the agent on a host it cannot work on.
package preflight

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
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

// Check runs every startup check against the live host, given the `uname -r` release.
func Check(kernelRelease string) error {
	if err := CheckKernelRelease(kernelRelease); err != nil {
		return err
	}
	if err := checkBTF(btfPath); err != nil {
		return err
	}
	return checkLockdownFile(lockdownPath)
}
