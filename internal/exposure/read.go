package exposure

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/thapr0digy/portwarden/internal/exposure/firewall"
	"github.com/thapr0digy/portwarden/internal/exposure/iptables"
	"github.com/thapr0digy/portwarden/internal/exposure/nft"
)

const (
	toolTimeout   = 5 * time.Second
	toolMaxOutput = 64 << 20
)

// Runner runs a tool and returns its standard output. ErrToolMissing means the tool is
// not installed.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// ErrToolMissing is returned by a Runner for a tool that is not installed.
var ErrToolMissing = errors.New("not installed")

// toolDirs are searched before PATH: the tools live there, and a service's PATH may
// lack /usr/sbin.
var toolDirs = []string{"/usr/sbin", "/sbin", "/usr/bin", "/bin"}

// ExecRunner runs the real tools, each bounded by a 5 s deadline and 64 MiB of output;
// a cut-off output is an error, never a partial ruleset.
func ExecRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	// The fixed system directories come first: the tool runs with the agent's
	// CAP_NET_ADMIN, so a same-named binary earlier in PATH must not win.
	path := ""
	for _, dir := range toolDirs {
		if p, e := exec.LookPath(dir + "/" + name); e == nil {
			path = p
			break
		}
	}
	if path == "" {
		p, err := exec.LookPath(name)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, ErrToolMissing)
		}
		path = p
	}
	ctx, cancel := context.WithTimeout(ctx, toolTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.WaitDelay = time.Second
	var stderr bytes.Buffer
	cmd.Stderr = &limitedWriter{w: &stderr, n: 4096}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	out, readErr := io.ReadAll(io.LimitReader(stdout, toolMaxOutput+1))
	if len(out) > toolMaxOutput {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("%s: output over %d bytes", name, toolMaxOutput)
	}
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("%s: timed out after %s", name, toolTimeout)
	}
	if waitErr != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = waitErr.Error()
		}
		return nil, fmt.Errorf("%s: %s", name, firstLine(msg))
	}
	if readErr != nil {
		return nil, fmt.Errorf("%s: %w", name, readErr)
	}
	return out, nil
}

type limitedWriter struct {
	w io.Writer
	n int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.n > 0 {
		k := min(len(p), l.n)
		l.n -= k
		_, _ = l.w.Write(p[:k])
	}
	return len(p), nil
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}

// Firewall is the host's merged ruleset and where it came from.
type Firewall struct {
	Rules *firewall.Ruleset
	// Sources names what was read, e.g. "nft+iptables(nf_tables)".
	Sources string
	// Notes lists read problems that did not stop the read (a tool missing, a
	// legacy dump that failed).
	Notes []string
	// Fingerprint changes when the rules do (counters and timestamps excluded).
	Fingerprint string
	// Legacy: an iptables-legacy ruleset is in use; it sends no change notifications.
	Legacy bool
	// Partial lists the sources that exist but could not be read or parsed
	// ("iptables-save: Permission denied"). The rules are then incomplete: verdicts
	// from them are not trusted (see View).
	Partial []string

	legacyPresent bool
}

// ReadFirewall reads nft and iptables, merges them (see Merge) and fails only when no
// source could be read at all.
func ReadFirewall(ctx context.Context, run Runner) (*Firewall, error) {
	var in MergeInput
	in.NFT, in.NFTErr = run(ctx, "nft", "-j", "list", "ruleset")
	in.IPT4, in.IPT4Err = run(ctx, "iptables-save")
	in.IPT6, in.IPT6Err = run(ctx, "ip6tables-save")
	fw, err := Merge(in)
	if err != nil {
		return nil, err
	}
	if fw.legacyPresent {
		// iptables-nft warned that legacy tables exist as well: both apply to packets.
		in.Legacy4, in.Legacy4Err = run(ctx, "iptables-legacy-save")
		in.Legacy6, in.Legacy6Err = run(ctx, "ip6tables-legacy-save")
		return Merge(in)
	}
	return fw, nil
}

// MergeInput is the raw output of each tool (nil with an error when it failed).
type MergeInput struct {
	NFT                    []byte
	NFTErr                 error
	IPT4, IPT6             []byte
	IPT4Err, IPT6Err       error
	Legacy4, Legacy6       []byte
	Legacy4Err, Legacy6Err error
}

// Merge builds one ruleset from the dumps.
//
// With the nf_tables iptables backend (Ubuntu 24.04's default) iptables-save and nft
// read the same kernel tables; nft -j hides xtables match and target details, so every
// table iptables-save printed replaces the nft table of the same family and name, and
// the other nft tables (native ones) are kept. With the legacy backend the iptables
// tables are separate kernel objects and both rule sets apply. Without nft, iptables
// alone; without either, an error.
func Merge(in MergeInput) (*Firewall, error) {
	fw := &Firewall{Rules: &firewall.Ruleset{}}
	var nftRS *nft.Ruleset
	if in.NFTErr == nil && in.NFT != nil {
		rs, err := nft.Parse(in.NFT)
		if err != nil {
			in.NFTErr = err
		} else {
			nftRS = rs
		}
	}
	if in.NFTErr != nil {
		fw.Notes = append(fw.Notes, in.NFTErr.Error())
		if !errors.Is(in.NFTErr, ErrToolMissing) {
			fw.Partial = append(fw.Partial, prefixed("nft", in.NFTErr))
		}
	}

	type iptDump struct {
		family firewall.Family
		data   []byte
		err    error
		origin string
	}
	replaced := map[string]bool{} // "<family> <table>" printed by iptables-nft
	var sources []string
	if nftRS != nil {
		sources = append(sources, "nft")
	}
	read := 0
	if nftRS != nil {
		read++
	}
	for _, d := range []iptDump{
		{firewall.FamilyIP, in.IPT4, in.IPT4Err, "iptables"},
		{firewall.FamilyIP6, in.IPT6, in.IPT6Err, "iptables"},
		{firewall.FamilyIP, in.Legacy4, in.Legacy4Err, "iptables-legacy"},
		{firewall.FamilyIP6, in.Legacy6, in.Legacy6Err, "iptables-legacy"},
	} {
		tool := map[firewall.Family]string{firewall.FamilyIP: "iptables-save", firewall.FamilyIP6: "ip6tables-save"}[d.family]
		if d.origin == "iptables-legacy" {
			tool = strings.Replace(tool, "tables-save", "tables-legacy-save", 1)
		}
		if d.err != nil {
			fw.Notes = append(fw.Notes, d.err.Error())
			// A missing iptables-save is fine (an nft-only host); a missing legacy tool
			// after iptables-nft warned that legacy tables exist is not.
			if !errors.Is(d.err, ErrToolMissing) || d.origin == "iptables-legacy" {
				fw.Partial = append(fw.Partial, prefixed(tool, d.err))
			}
			continue
		}
		if d.data == nil {
			continue
		}
		rs, err := iptables.Parse(d.data, d.family)
		if err != nil {
			fw.Notes = append(fw.Notes, err.Error())
			fw.Partial = append(fw.Partial, prefixed(tool, err))
			continue
		}
		read++
		fw.legacyPresent = fw.legacyPresent || rs.LegacyPresent
		legacy := d.origin == "iptables-legacy" || rs.Backend == "legacy"
		origin := d.origin
		if legacy {
			origin = "iptables-legacy"
			if len(rs.Tables) > 0 {
				fw.Legacy = true
			}
		}
		for _, c := range rs.Chains {
			c.Origin = origin
			fw.Rules.Chains = append(fw.Rules.Chains, c)
		}
		if !legacy {
			for _, t := range rs.Tables {
				replaced[d.family.String()+" "+t] = true
			}
		}
		if len(rs.Tables) > 0 {
			name := origin
			if !legacy && rs.Backend != "" {
				name += "(" + rs.Backend + ")"
			}
			if !slices.Contains(sources, name) {
				sources = append(sources, name)
			}
		}
	}
	if read == 0 {
		return nil, fmt.Errorf("no firewall source readable: %s", strings.Join(fw.Notes, "; "))
	}
	if nftRS != nil {
		var kept []*firewall.Chain
		for _, c := range nftRS.Chains {
			if !replaced[c.Family.String()+" "+c.Table] {
				kept = append(kept, c)
			}
		}
		fw.Rules.Chains = append(kept, fw.Rules.Chains...)
	}
	fw.Sources = strings.Join(sources, "+")
	if fw.Sources == "" {
		fw.Sources = "none"
	}
	fw.Fingerprint = fingerprint(fw.Rules) + "|" + strings.Join(fw.Partial, ";")
	return fw, nil
}

// prefixed is "<tool>: <err>" unless the error already names the tool.
func prefixed(tool string, err error) string {
	msg := err.Error()
	if strings.HasPrefix(msg, tool+":") || strings.HasPrefix(msg, strings.TrimSuffix(tool, "-save")+":") {
		return msg
	}
	return tool + ": " + msg
}

// fingerprint hashes the parsed rules, so counters and dump timestamps do not count.
func fingerprint(rs *firewall.Ruleset) string {
	h := sha256.New()
	for _, c := range rs.Chains {
		fmt.Fprintf(h, "%#v\n", *c)
	}
	return hex.EncodeToString(h.Sum(nil))
}
