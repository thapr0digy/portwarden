//go:build linux

package tamper

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
)

// SelfExeCheck watches the running executable: its baseline is the hash of
// /proc/self/exe (the image the kernel runs, even if the path was replaced since), and
// the path is where /proc/self/exe pointed at start.
func SelfExeCheck() (*SelfExe, error) {
	path, base, err := SelfExeHash()
	if err != nil {
		return nil, err
	}
	return NewSelfExe(path, base), nil
}

// SelfExeHash returns where /proc/self/exe points and the hex SHA-256 of the image the
// kernel runs. The agent calls it once at start and reuses the hash for its heartbeats
// and for its self_exe check (NewSelfExe), so the file is hashed once per run.
func SelfExeHash() (path, hash string, err error) {
	path, err = os.Readlink("/proc/self/exe")
	if err != nil {
		return "", "", err
	}
	if p, ok := strings.CutSuffix(path, " (deleted)"); ok {
		return "", "", fmt.Errorf("the executable %s was removed before the agent started", p)
	}
	hash, err = HashFile("/proc/self/exe")
	if err != nil {
		return "", "", err
	}
	return path, hash, nil
}

// SelfTracer checks the agent's own threads.
func SelfTracer() *Tracer { return &Tracer{TaskDir: "/proc/self/task"} }

const (
	systemdDest  = "org.freedesktop.systemd1"
	systemdPath  = dbus.ObjectPath("/org/freedesktop/systemd1")
	unitIface    = "org.freedesktop.systemd1.Unit"
	propertyGet  = "org.freedesktop.DBus.Properties.Get"
	getUnitByPID = "org.freedesktop.systemd1.Manager.GetUnitByPID"
	busTimeout   = 5 * time.Second
)

// ErrNoUnit means the process is not a systemd service (a terminal, a container).
var ErrNoUnit = errors.New("not running as a systemd service")

// UnitFiles returns the agent's own systemd unit name and a function listing the files
// that make it up now (the fragment and drop-ins, as systemd reports them after its last
// daemon-reload), both read over the system bus. ErrNoUnit when the process is not in a
// service unit.
func UnitFiles() (string, func() ([]string, error), error) {
	pid := uint32(os.Getpid())
	name, files, err := unitFiles(pid)
	if err != nil {
		return "", nil, err
	}
	if !strings.HasSuffix(name, ".service") || len(files) == 0 {
		return "", nil, fmt.Errorf("%w (unit %q)", ErrNoUnit, name)
	}
	return name, func() ([]string, error) {
		_, files, err := unitFiles(pid)
		return files, err
	}, nil
}

func unitFiles(pid uint32) (string, []string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), busTimeout)
	defer cancel()
	conn, err := dbus.ConnectSystemBus(dbus.WithContext(ctx))
	if err != nil {
		return "", nil, fmt.Errorf("connect system bus: %w", err)
	}
	defer conn.Close()
	var unitPath dbus.ObjectPath
	if err := conn.Object(systemdDest, systemdPath).CallWithContext(ctx, getUnitByPID, 0, pid).Store(&unitPath); err != nil {
		return "", nil, fmt.Errorf("unit of pid %d: %w", pid, err)
	}
	obj := conn.Object(systemdDest, unitPath)
	var id, fragment string
	var dropIns []string
	for _, p := range []struct {
		name string
		out  any
	}{{"Id", &id}, {"FragmentPath", &fragment}, {"DropInPaths", &dropIns}} {
		var v dbus.Variant
		if err := obj.CallWithContext(ctx, propertyGet, 0, unitIface, p.name).Store(&v); err != nil {
			return "", nil, fmt.Errorf("%s of %s: %w", p.name, unitPath, err)
		}
		if err := v.Store(p.out); err != nil {
			return "", nil, fmt.Errorf("%s of %s: %w", p.name, unitPath, err)
		}
	}
	var files []string
	if fragment != "" {
		files = append(files, fragment)
	}
	return id, append(files, dropIns...), nil
}

// BPFStatsEnabled reports whether kernel.bpf_stats_enabled is 1 (program run counts are
// then kept).
func BPFStatsEnabled() bool {
	b, err := os.ReadFile("/proc/sys/kernel/bpf_stats_enabled")
	return err == nil && strings.TrimSpace(string(b)) == "1"
}
