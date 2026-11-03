package publish

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// BootIDPath is the kernel's per-boot random id.
const BootIDPath = "/proc/sys/kernel/random/boot_id"

const runCounterFile = "run-number"

// ReadBootID returns the boot id at path, or "" when it cannot be read.
func ReadBootID(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// NextRunNumber increments and persists the run counter in dir (the spool directory)
// and returns the new value. Consumers order a host's runs by (boot_id, run_number),
// which, unlike the run id's timestamp, does not depend on the clock being right at
// boot. dir "" (no spool) returns 0: consumers then fall back to run id order.
func NextRunNumber(dir string) (uint64, error) {
	if dir == "" {
		return 0, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return 0, err
	}
	path := filepath.Join(dir, runCounterFile)
	var n uint64
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return 0, err
	default:
		n, err = strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("run counter %s: %w", path, err)
		}
	}
	n++
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.FormatUint(n, 10)+"\n"), 0o600); err != nil {
		return 0, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return 0, err
	}
	return n, nil
}
