package publish_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/slidehq/signal/schema/cejson"
	"github.com/slidehq/signal/schema/eventsv1"
	"github.com/slidehq/signal/schema/ingesttest"
	"github.com/slidehq/signal/schema/protocol"
	"github.com/slidehq/signal/schema/validate"

	"github.com/thapr0digy/portwarden/internal/access"
	"github.com/thapr0digy/portwarden/internal/dpkg"
	"github.com/thapr0digy/portwarden/internal/ingest"
	"github.com/thapr0digy/portwarden/internal/ingest/doortest"
	"github.com/thapr0digy/portwarden/internal/publish"
)

// fixturesEnv names a directory the host-fact runs write the events Signal stored to, as
// one cejson batch per run (<name>.batch.json): the recorded fixtures for Signal's
// ingesttest (testdata/signal holds the committed ones; README "Host packages").
const fixturesEnv = "PORTWARDEN_SIGNAL_FIXTURES"

// runHostFacts runs the agent's two host-fact readers (the access reader without a
// journal, the package list reader) on root, sending through pub, until both full states
// are stored by ref and a few rechecks have gone out, then closes pub.
func runHostFacts(t *testing.T, root fs.FS, ref *ingesttest.Server, pub *publish.Publisher) {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		access.Run(ctx, access.Config{Root: root, Accounts: []string{"pants", "root"},
			Poll: 20 * time.Millisecond, Recheck: 100 * time.Millisecond, Flush: time.Hour, Log: log}, pub)
	}()
	go func() {
		defer wg.Done()
		dpkg.Run(ctx, dpkg.Config{Root: root, Poll: 20 * time.Millisecond, Settle: 50 * time.Millisecond,
			Recheck: 100 * time.Millisecond, Log: log}, pub)
	}()
	waitFor(t, "asm.host.access", func() bool { return stored(ref, "asm.host.access", 0) != nil })
	waitFor(t, "asm.host.packages", func() bool { return stored(ref, "asm.host.packages", 0) != nil })
	time.Sleep(400 * time.Millisecond) // rechecks: unchanged, confirmed by the digest
	cancel()
	wg.Wait()
	if err := pub.Close(); err != nil {
		t.Fatal(err)
	}
}

// storedHostFacts checks what Signal stored of one host-fact run: each full state once (the
// rechecks confirmed by digest, never stored again), nothing refused, no gap. It returns
// the two full states.
func storedHostFacts(t *testing.T, ref *ingesttest.Server) (*eventsv1.HostAccess, *eventsv1.HostPackages) {
	t.Helper()
	count := map[string]int{}
	for _, e := range ref.Stored() {
		count[e.GetType()]++
	}
	if count["asm.host.access"] != 1 || count["asm.host.packages"] != 1 {
		t.Fatalf("stored %v: want each full state once, the unchanged rechecks confirmed by digest", count)
	}
	if len(ref.Quarantined()) != 0 || len(ref.Gaps()) != 0 {
		t.Fatalf("quarantined %v, gaps %v", ref.Quarantined(), ref.Gaps())
	}
	return stored(ref, "asm.host.access", 0).GetHostAccess(), stored(ref, "asm.host.packages", 0).GetHostPackages()
}

// recordSignalFixtures writes the events the agent sent (the whole run, in order: full
// states and their unchanged confirmations) as <dir>/<name>.batch.json when fixturesEnv
// names a directory.
func recordSignalFixtures(t *testing.T, name string, sent *sentLog) {
	t.Helper()
	dir := os.Getenv(fixturesEnv)
	if dir == "" {
		return
	}
	events := sent.all()
	body, err := cejson.EncodeBatch(&eventsv1.Batch{Events: events})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name+".batch.json")
	if err := os.WriteFile(path, body, 0o644); err != nil { //nolint:gosec // a test fixture, read by Signal's tests
		t.Fatal(err)
	}
	t.Logf("recorded %d events to %s", len(events), path)
}

// e2ePackagesRoot is e2eHostRoot with a dpkg database and os-release, and sshd's two
// settings set in the drop-in.
func e2ePackagesRoot() fstest.MapFS {
	root := e2eHostRoot()
	file := func(s string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(s)} }
	root["etc/ssh/sshd_config.d/10-vault.conf"] = file("TrustedUserCAKeys /etc/ssh/ca\nAuthorizedPrincipalsFile /etc/ssh/principals/%u\nPasswordAuthentication no\nPermitRootLogin without-password\n")
	root["etc/os-release"] = file("ID=ubuntu\nVERSION_ID=\"24.04\"\nVERSION_CODENAME=noble\n")
	root["var/lib/dpkg/status"] = file(`Package: openssh-server
Status: install ok installed
Architecture: amd64
Source: openssh
Version: 1:9.6p1-3ubuntu13.5
Description: secure shell (SSH) server
 for secure access from remote machines

Package: libc6
Status: install ok installed
Architecture: amd64
Source: glibc
Version: 2.39-0ubuntu8.3

Package: removed-long-ago
Status: deinstall ok config-files
Architecture: amd64
Version: 1.0-1
`)
	return root
}

// The task's acceptance proof for the package list and the two SSH settings: the agent's
// readers, on a host's files, send asm.host.packages and asm.host.access through the HTTPS
// sink, and Signal's reference door stores each once (rechecks confirmed by digest) with
// nothing refused and no gap.
func TestE2EHostPackagesAndSSHSettingsAreStoredBySignal(t *testing.T) {
	ref, pub, sent := signalDoor(t, e2eHost)
	runHostFacts(t, e2ePackagesRoot(), ref, pub)
	acc, pkgs := storedHostFacts(t, ref)
	if s := acc.GetSshd(); s.GetPasswordAuthentication() != "no" || s.GetPermitRootLogin() != "prohibit-password" {
		t.Fatalf("sshd = %v", s)
	}
	if !pkgs.GetRead() || pkgs.GetDistro().GetCodename() != "noble" || pkgs.GetTotal() != 2 || len(pkgs.GetPackages()) != 2 ||
		pkgs.GetPackages()[1].GetName() != "openssh-server" || pkgs.GetPackages()[1].GetSource() != "openssh" {
		t.Fatalf("packages = %v", pkgs)
	}
	recordSignalFixtures(t, "host-facts-fstest", sent)
}

// The recorded fixtures (testdata/signal: a real host's run, recorded in the dev VM) are
// what Signal's ingesttest is handed: each decodes strictly as JSON and, replayed as the
// recorded host, is stored by the reference door with nothing refused and no gap.
func TestRecordedSignalFixturesAreStoredBySignal(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "signal", "*.batch.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no recorded fixtures: %v", err)
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			body, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			els, err := cejson.DecodeBatch(body, validate.Options{})
			if err != nil {
				t.Fatal(err)
			}
			batch := &eventsv1.Batch{}
			types := map[string]bool{}
			for _, el := range els {
				if el.Problem != nil {
					t.Fatalf("element %d: %v", el.Index, el.Problem)
				}
				batch.Events = append(batch.Events, el.Event)
				types[el.Event.GetType()] = true
			}
			if !types["asm.host.packages"] || !types["asm.host.access"] {
				t.Fatalf("types %v: want both host facts", types)
			}
			host := strings.TrimPrefix(batch.GetEvents()[0].GetSubject(), "host:")
			pubKey, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			ref := ingesttest.New()
			ref.AddPrincipal(protocol.Principal{ID: "pr-1", Kind: eventsv1.ProducerAgent, HostID: host}, "ak-1", pubKey)
			ts, pin := doortest.Start(t, ref, 0)
			c, err := ingest.New(ingest.Config{URL: ts.URL, Pin: pin, Key: key})
			if err != nil {
				t.Fatal(err)
			}
			a, err := c.Batch(context.Background(), "ak-1", batch)
			if err != nil || a.Status != http.StatusOK {
				t.Fatalf("answer %+v, %v", a, err)
			}
			// The unchanged confirmations are answered by digest, not stored again.
			if len(a.Resp.GetRejected()) != 0 || len(ref.Quarantined()) != 0 || len(ref.Gaps()) != 0 ||
				a.Resp.GetCursor().GetSeq() != batch.GetEvents()[len(batch.GetEvents())-1].GetSequence().GetSeq() {
				t.Fatalf("answer %v, quarantined %v, gaps %v", a.Resp, ref.Quarantined(), ref.Gaps())
			}
			full := map[string]int{}
			for _, e := range ref.Stored() {
				full[e.GetType()]++
			}
			if full["asm.host.packages"] != 1 || full["asm.host.access"] != 1 {
				t.Fatalf("stored %v: want each full state once", full)
			}
		})
	}
}
