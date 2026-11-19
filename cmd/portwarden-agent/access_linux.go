//go:build linux

package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/thapr0digy/portwarden/internal/access"
	"github.com/thapr0digy/portwarden/internal/dpkg"
	"github.com/thapr0digy/portwarden/internal/exposure"
	"github.com/thapr0digy/portwarden/internal/flows"
	"github.com/thapr0digy/portwarden/internal/probes"
	"github.com/thapr0digy/portwarden/internal/procinfo"
)

// defaultSSHAccounts are the accounts whose SSH access is reported: Ansible's shared
// pants account, which Signal's identity join reads, and root.
const defaultSSHAccounts = "pants,root"

// parseSSHAccounts reads --ssh-accounts: a comma list of POSIX user names.
func parseSSHAccounts(list string) ([]string, error) {
	var out []string
	for _, a := range strings.Split(list, ",") {
		if a = strings.TrimSpace(a); a == "" {
			continue
		}
		if !access.ValidAccount(a) {
			return nil, fmt.Errorf("--ssh-accounts: %q is not a user name", a)
		}
		out = append(out, a)
	}
	if len(out) == 0 || len(out) > access.MaxAccounts {
		return nil, fmt.Errorf("--ssh-accounts: name 1 to %d accounts", access.MaxAccounts)
	}
	return out, nil
}

// hostAccessConfig is the host identity reader's configuration (README "Host identity
// facts"), or nil when it does not run: --ssh-access off, or no Signal door (the facts
// exist only in Signal's schema). The shared-key list is read here, at start: a bad one
// is a bad flag.
func hostAccessConfig(opts options) (*access.Config, error) {
	if opts.sshAccess == "off" || opts.ingestURL == "" {
		return nil, nil
	}
	var shared access.SharedKeys
	if opts.sharedKeys != "" {
		data, err := os.ReadFile(opts.sharedKeys)
		if err != nil {
			return nil, fmt.Errorf("--shared-keys: %w", err)
		}
		if shared, err = access.ParseSharedKeys(string(data)); err != nil {
			return nil, fmt.Errorf("--shared-keys %s: %w", opts.sharedKeys, err)
		}
	}
	var journal access.Journal
	if path, err := exposure.ToolPath("journalctl"); err == nil {
		journal = access.ExecJournal(path)
	} else {
		journal = func(context.Context, string) (io.ReadCloser, error) { return nil, err }
	}
	return &access.Config{
		Root:       os.DirFS("/"),
		Accounts:   opts.sshAccounts,
		SharedKeys: shared,
		Journal:    journal,
		CursorFile: filepath.Join(opts.ingestDir, "journal-cursor"),
		Poll:       access.DefaultPoll,
		Recheck:    opts.recheck,
		Flush:      access.DefaultFlush,
	}, nil
}

// hostPackagesConfig is the package list reader's configuration (README "Host packages"),
// or nil when it does not run: --host-packages off, no Signal door (the list exists only
// in Signal's schema), or in a container (any "/" checkHostRoot cannot show is the
// host's), whose dpkg database is the image's, not the host's.
func hostPackagesConfig(opts options, inContainer bool) *dpkg.Config {
	if opts.hostPackages == "off" || opts.ingestURL == "" || inContainer {
		return nil
	}
	return &dpkg.Config{Root: os.DirFS("/"), Poll: dpkg.DefaultPoll, Settle: dpkg.DefaultSettle, Recheck: dpkg.DefaultRecheck}
}

// hostFlowsEnabled reports whether the connection flows reader runs: --host-flows auto
// with Signal's door (the flows exist only in Signal's schema). Unlike the package list it
// also runs in a container: the probes watch the kernel's sockets, which are the host's.
func hostFlowsEnabled(opts options) bool {
	return opts.hostFlows == "auto" && opts.ingestURL != ""
}

// hostFlowsConfig starts the connection probes for the flows reader (README "Connection
// flows") and returns its configuration and their events. Probes that cannot start (an old
// kernel, a refused load) are not fatal: the reader then sends every window unread, with
// why, so Signal says "could not watch", never "no connections"; started is then nil.
func hostFlowsConfig(resolver *procinfo.Resolver, log *slog.Logger) (cfg flows.Config, events <-chan flows.Event, started *probes.Flows) {
	cfg = flows.Config{
		Window: flows.DefaultWindow,
		Identify: func(tgid uint32, cgroupID uint64) flows.Process {
			exe, unit := resolver.Identity(tgid, cgroupID)
			return flows.Process{Exe: exe, Unit: unit}
		},
		Log: log,
	}
	fp, err := probes.StartFlows()
	if err != nil {
		log.Warn("connection flows are not observed; windows are sent unread", "err", err.Error())
		cfg.Unreadable = "connection probes did not start: " + err.Error()
		return cfg, nil, nil
	}
	cfg.Drops = fp.Drops
	return cfg, fp.Events(), fp
}

// initPIDNamespace is how /proc names the host's PID namespace: the kernel's fixed inode
// for the initial one (PROC_PID_INIT_INO).
const initPIDNamespace = "pid:[4026531836]"

// checkHostRoot returns nil when root is the host's root directory, or why it cannot tell:
// the agent must share the host's PID namespace (so procRoot's 1 is the host's init) and
// root must be init's root directory, the same device and inode (the unit's own mount
// namespace binds the same "/"; a container's is the image's). Reading init's root needs
// CAP_SYS_PTRACE, which the agent holds. Any read that fails is a reason, never a pass.
func checkHostRoot(procRoot, root string) error {
	pidNS, err := os.Readlink(filepath.Join(procRoot, "self", "ns", "pid"))
	if err != nil {
		return fmt.Errorf("PID namespace: %w", err)
	}
	if pidNS != initPIDNamespace {
		return fmt.Errorf("PID namespace %s is not the host's", pidNS)
	}
	initRoot, err := os.Stat(filepath.Join(procRoot, "1", "root") + "/")
	if err != nil {
		return fmt.Errorf("init's root: %w", err)
	}
	ownRoot, err := os.Stat(root)
	if err != nil {
		return fmt.Errorf("own root: %w", err)
	}
	if !os.SameFile(initRoot, ownRoot) {
		return fmt.Errorf("%s is not init's root directory", root)
	}
	return nil
}
