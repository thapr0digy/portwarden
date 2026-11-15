package access

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	osuser "os/user"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	// maxLineBytes bounds one journal record; a longer one is skipped whole.
	maxLineBytes = 64 << 10
	// firstSince bounds the first read on a host with no saved cursor.
	firstSince = "-24h"
	// journalGroupNames may read the system journal (journald's rule).
	journalGroupNames = "systemd-journal adm wheel"
)

// Journal starts following sshd's journal records after cursor ("" starts a day back) and
// returns them as journalctl's JSON lines. Closing the stream stops the follow; its error
// says why the stream ended, if it ended on its own.
type Journal func(ctx context.Context, cursor string) (io.ReadCloser, error)

// ErrJournalAccess means the agent may not read the system journal: it is not root and in
// none of the groups journald lets read it.
var ErrJournalAccess = errors.New("the agent is in none of the groups systemd-journal, adm or wheel (the unit's SupplementaryGroups=systemd-journal)")

// ExecJournal follows the journal with the journalctl at path, as a child process (the
// way the agent already runs nft): only sshd's units, only the fields this package reads.
func ExecJournal(path string) Journal {
	return func(ctx context.Context, cursor string) (io.ReadCloser, error) {
		if err := journalAccess(); err != nil {
			return nil, err
		}
		args := []string{"--follow", "--output=json", "--output-fields=MESSAGE,_SYSTEMD_UNIT,_UID", "--quiet", "--no-pager"}
		if cursor != "" {
			args = append(args, "--after-cursor="+cursor)
		} else {
			args = append(args, "--since="+firstSince)
		}
		for _, u := range sshdUnits {
			args = append(args, "_SYSTEMD_UNIT="+u)
		}
		ctx, cancel := context.WithCancel(ctx)
		cmd := exec.CommandContext(ctx, path, args...)
		cmd.WaitDelay = time.Second
		stderr := &capped{max: 4096}
		cmd.Stderr = stderr
		out, err := cmd.StdoutPipe()
		if err != nil {
			cancel()
			return nil, fmt.Errorf("journalctl: %w", err)
		}
		if err := cmd.Start(); err != nil {
			cancel()
			return nil, fmt.Errorf("journalctl: %w", err)
		}
		return &journalProc{ReadCloser: out, cmd: cmd, cancel: cancel, stderr: stderr}, nil
	}
}

// journalAccess checks journald's read rule for the agent's own credentials.
func journalAccess() error {
	if os.Geteuid() == 0 {
		return nil
	}
	gids, err := os.Getgroups()
	if err != nil {
		return fmt.Errorf("supplementary groups: %w", err)
	}
	mine := map[int]bool{os.Getegid(): true}
	for _, g := range gids {
		mine[g] = true
	}
	for _, name := range strings.Fields(journalGroupNames) {
		g, err := osuser.LookupGroup(name)
		if err != nil {
			continue
		}
		var gid int
		if _, err := fmt.Sscan(g.Gid, &gid); err == nil && mine[gid] {
			return nil
		}
	}
	return ErrJournalAccess
}

// journalProc is a running journalctl.
type journalProc struct {
	io.ReadCloser
	cmd    *exec.Cmd
	cancel context.CancelFunc
	stderr *capped
	once   sync.Once
	err    error
}

// Close stops journalctl (if it still runs) and says how it ended: never nil, since a
// follow does not end on its own. A caller that stopped it ignores the error.
func (p *journalProc) Close() error {
	p.once.Do(func() {
		p.cancel()
		if err := p.cmd.Wait(); err != nil {
			p.err = p.exitError(err)
		} else {
			p.err = errors.New("journalctl exited")
		}
	})
	return p.err
}

func (p *journalProc) exitError(err error) error {
	msg := strings.TrimSpace(p.stderr.String())
	if i := strings.IndexByte(msg, '\n'); i >= 0 {
		msg = msg[:i]
	}
	if msg == "" {
		return fmt.Errorf("journalctl: %w", err)
	}
	return fmt.Errorf("journalctl: %s", msg)
}

// capped keeps the first max bytes written to it.
type capped struct {
	mu  sync.Mutex
	buf bytes.Buffer
	max int
}

func (c *capped) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if room := c.max - c.buf.Len(); room > 0 {
		c.buf.Write(b[:min(len(b), room)])
	}
	return len(b), nil
}

func (c *capped) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

// readLines calls fn with each line of r, skipping (whole) any line longer than
// maxLineBytes, until r ends; it returns r's error, nil at EOF.
func readLines(r io.Reader, fn func([]byte)) error {
	br := bufio.NewReaderSize(r, maxLineBytes)
	skipping := false
	for {
		line, err := br.ReadSlice('\n')
		switch {
		case errors.Is(err, bufio.ErrBufferFull):
			skipping = true
			continue
		case skipping:
			skipping = false
		case len(line) > 0 && (err == nil || errors.Is(err, io.EOF)):
			fn(slices.Clone(bytes.TrimSuffix(line, []byte("\n"))))
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}
