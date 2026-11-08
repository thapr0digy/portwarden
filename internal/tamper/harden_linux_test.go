//go:build linux

package tamper

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

// hardenChildEnv makes the test binary run hardenedChild instead of the tests: Harden is
// one-way for a process, so each assertion runs in a fresh child and the test binary
// itself stays dumpable.
const hardenChildEnv = "PORTWARDEN_TAMPER_HARDEN_CHILD"

func TestMain(m *testing.M) {
	if name := os.Getenv(hardenChildEnv); name != "" {
		if err := hardenedChild(name); err != nil {
			os.Stderr.WriteString(err.Error() + "\n")
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func runHardenedChild(t *testing.T, name string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), hardenChildEnv+"="+name)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s: %v\n%s", name, err, out)
	}
}

func hardenedChild(name string) error {
	if err := Harden(); err != nil {
		return err
	}
	switch name {
	case "flag":
		v, err := getDumpable()
		if err != nil {
			return err
		}
		if v != 0 {
			return errors.New("PR_GET_DUMPABLE is not 0 after Harden")
		}
		if _, err := SelfDumpable(nil).Run(); err != nil {
			return err
		}
	case "self-reads":
		if errs := SelfReadProbe(); len(errs) != 0 {
			return errors.Join(errs...)
		}
		if _, err := SelfExeCheck(); err != nil {
			return errors.New("self_exe baseline after Harden: " + err.Error())
		}
		if _, err := SelfTracer().Run(); err != nil {
			return errors.New("ptrace check after Harden: " + err.Error())
		}
		st := NewMonitor(SelfTracer(), SelfDumpable(nil)).Pass(t0).Status
		if len(st.Unknown) != 0 || len(st.Flags) != 0 {
			return errors.New("a self-check is degraded after Harden: " + strings.Join(st.Unknown, "; "))
		}
	case "owner":
		var st syscall.Stat_t
		if err := syscall.Stat("/proc/self/mem", &st); err != nil {
			return err
		}
		if st.Uid != 0 {
			return errors.New("/proc/self/mem is not owned by root after Harden")
		}
		if os.Geteuid() != 0 {
			// The agent's own uid lost DAC access to its 0400 files: the flag took effect.
			if _, err := os.ReadFile("/proc/self/environ"); !errors.Is(err, fs.ErrPermission) {
				return errors.New("/proc/self/environ is still readable to the process's uid: " + errString(err))
			}
		}
	default:
		return errors.New("unknown child " + name)
	}
	return nil
}

func errString(err error) string {
	if err == nil {
		return "no error"
	}
	return err.Error()
}

// Assumption: clearing the dumpable flag sticks, and the dumpable check then passes.
func TestHardenClearsDumpable(t *testing.T) { runHardenedChild(t, "flag") }

// Assumption: the agent still reaches its own /proc entries after Harden (its own thread
// group passes the ptrace-access check; the files it reads are world-readable), so
// self_exe, ptrace and dumpable take their baselines and pass without going unknown.
func TestHardenKeepsSelfReads(t *testing.T) { runHardenedChild(t, "self-reads") }

// Assumption: after Harden the kernel owns the agent's /proc files as root, and the
// agent's own (non-root) uid can no longer open its mode-0400 files.
func TestHardenOwnsProcFilesAsRoot(t *testing.T) { runHardenedChild(t, "owner") }

// The control for the above: before Harden the files belong to the process's uid.
func TestDumpableProcessOwnsItsProcFiles(t *testing.T) {
	var st syscall.Stat_t
	if err := syscall.Stat("/proc/self/mem", &st); err != nil {
		t.Fatal(err)
	}
	if int(st.Uid) != os.Geteuid() {
		t.Fatalf("/proc/self/mem owner %d, want %d", st.Uid, os.Geteuid())
	}
}
