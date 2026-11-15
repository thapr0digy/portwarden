//go:build linux

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/thapr0digy/portwarden/internal/access"
	"github.com/thapr0digy/portwarden/internal/exposure"
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
