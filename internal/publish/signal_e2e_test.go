package publish_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/slidehq/signal/schema/eventsv1"
	"github.com/slidehq/signal/schema/ingesttest"
	"github.com/slidehq/signal/schema/protocol"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/thapr0digy/portwarden/internal/access"
	"github.com/thapr0digy/portwarden/internal/agent"
	"github.com/thapr0digy/portwarden/internal/ingest/doortest"
	"github.com/thapr0digy/portwarden/internal/model"
	"github.com/thapr0digy/portwarden/internal/natsauth"
	"github.com/thapr0digy/portwarden/internal/publish"
)

const e2eHost = "0123456789abcdef0123456789abcdef"

type events chan model.Observation

func (e events) Events() <-chan model.Observation { return e }

func listenerAt(port uint16) model.ListenerKey {
	return model.NewKey(4026531840, "tcp", netip.MustParseAddr("0.0.0.0"), port)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	end := time.Now().Add(30 * time.Second)
	for !cond() {
		if time.Now().After(end) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func stored(ref *ingesttest.Server, typ string, port uint32) *eventsv1.Event {
	for _, e := range ref.Stored() {
		if e.GetType() == typ && (port == 0 || e.GetListenerChange().GetListener().GetPort() == port) {
			return e
		}
	}
	return nil
}

// sentLog records the events of every batch sent to the door, in order.
type sentLog struct {
	mu     sync.Mutex
	events []*eventsv1.Event
}

func (l *sentLog) all() []*eventsv1.Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.events)
}

// recording reads each batch request's events into log before h serves it.
func recording(t *testing.T, log *sentLog, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		raw := body
		if r.Header.Get("Content-Encoding") == "gzip" {
			zr, err := gzip.NewReader(bytes.NewReader(body))
			if err == nil {
				raw, err = io.ReadAll(zr)
			}
			if err != nil {
				t.Error(err)
			}
		}
		if b := (&eventsv1.Batch{}); r.Header.Get("Content-Type") == "application/x-protobuf" && proto.Unmarshal(raw, b) == nil {
			log.mu.Lock()
			log.events = append(log.events, b.GetEvents()...)
			log.mu.Unlock()
		}
		h.ServeHTTP(w, r)
	})
}

// signalDoor is Signal's reference door (ingesttest: the product's own signature,
// validation, scope and run-cursor code, schema/protocol) behind pinned TLS, with host's key
// registered the way import-nkeys registers it (the seed natsauth mints), a publisher
// sending to it as that host, and the log of what was sent.
func signalDoor(t *testing.T, host string) (*ingesttest.Server, *publish.Publisher, *sentLog) {
	t.Helper()
	seed := filepath.Join(t.TempDir(), "host-"+host+".nk")
	kp, err := natsauth.CreateUserSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	kp.Wipe()
	key, err := natsauth.ReadUserKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	ref := ingesttest.New()
	ref.AddPrincipal(protocol.Principal{ID: "pr-1", Kind: eventsv1.ProducerAgent, HostID: host}, "ak-1", key.Public().(ed25519.PublicKey))
	sent := &sentLog{}
	ts, pin := doortest.Start(t, recording(t, sent, ref), 0)
	pub, err := publish.New(context.Background(), publish.Config{
		HostID: host, AgentVersion: "v1.0.0", BootID: "boot-1", RunNumber: 1,
		SpoolDir: t.TempDir(),
		Ingest:   &publish.IngestConfig{URL: ts.URL, Pin: pin, KeyFile: seed, KeyID: "ak-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return ref, pub, sent
}

// The task's acceptance proof: a listener opened on the agent (its real event loop, fed
// one kernel observation) is stored by Signal's reference door.
func TestE2EListenerOpenedOnTheAgentIsStoredBySignal(t *testing.T) {
	ref, pub, _ := signalDoor(t, e2eHost)
	pub.SetHost(model.HostInfo{Cloud: "aws", InstanceID: "i-0abc"})

	src := make(events)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	baseline := []model.Observation{{Kind: model.Opened, Cookie: 1, Key: listenerAt(22), Source: model.SourceBaseline,
		Proc: model.Process{PID: 10, Comm: "sshd"}}}
	go func() {
		done <- agent.Run(ctx, src, func() ([]model.Observation, error) { return baseline, nil }, pub, agent.Options{})
	}()
	waitFor(t, "the baseline snapshot", func() bool { return stored(ref, "asm.host.snapshot", 0) != nil })

	src <- model.Observation{Kind: model.Opened, Cookie: 2, Key: listenerAt(8080), At: time.Now(), Source: model.SourceEBPF,
		Proc: model.Process{PID: 42, Comm: "api", Cmdline: []string{"api", "--password=hunter2", "--port=8080"}}}
	pub.Heartbeat(0)
	waitFor(t, "asm.listener.opened for :8080", func() bool { return stored(ref, "asm.listener.opened", 8080) != nil })

	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	pub.Stopping()
	if err := pub.Close(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "asm.agent.stopping", func() bool { return stored(ref, "asm.agent.stopping", 0) != nil })

	opened := stored(ref, "asm.listener.opened", 8080)
	lc := opened.GetListenerChange()
	if lc.GetListener().GetKey() != listenerAt(8080).String() || lc.GetProcesses()[0].GetPid() != 42 ||
		lc.GetHost().GetInstanceId() != "i-0abc" || opened.GetSubject() != "host:"+e2eHost {
		t.Fatalf("opened = %v", opened)
	}
	if js, _ := protojson.Marshal(opened); strings.Contains(string(js), "hunter2") {
		t.Fatalf("a secret argument reached Signal: %s", js)
	}
	snap := stored(ref, "asm.host.snapshot", 0).GetHostSnapshot()
	if len(snap.GetListeners()) != 1 || snap.GetListeners()[0].GetListener().GetPort() != 22 {
		t.Fatalf("snapshot = %v", snap)
	}

	// One run, every seq once and in order, nothing refused, no gap.
	all := ref.Stored()
	run := all[0].GetSequence().GetRunId()
	var seqs []uint64
	for _, e := range all {
		if e.GetSequence().GetRunId() != run || e.GetSequence().GetBootId() != "boot-1" || e.GetSequence().GetRunNumber() != 1 {
			t.Fatalf("event of another run: %v", e.GetSequence())
		}
		seqs = append(seqs, e.GetSequence().GetSeq())
	}
	for i, s := range seqs {
		if s != uint64(i+1) {
			t.Fatalf("seqs %v are not 1..n", seqs)
		}
	}
	if !slices.IsSorted(seqs) || len(ref.Quarantined()) != 0 || len(ref.Gaps()) != 0 {
		t.Fatalf("quarantined %v, gaps %v", ref.Quarantined(), ref.Gaps())
	}
}

// e2eHostRoot is a host as Ansible's base role leaves it, as far as the agent reads it.
func e2eHostRoot() fstest.MapFS {
	file := func(s string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(s)} }
	return fstest.MapFS{
		"etc/ssh/sshd_config":                 file("Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication yes\n"),
		"etc/ssh/sshd_config.d/10-vault.conf": file("TrustedUserCAKeys /etc/ssh/ca\nAuthorizedPrincipalsFile /etc/ssh/principals/%u\n"),
		"etc/ssh/ca":                          file("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK0Xshq1p0+wDrYeS4zT9hvujKFEJ6y+ZqjTDE2B1iDT vault ssh/prod\n"),
		"etc/ssh/principals/pants":            file("pants\n"),
		"etc/passwd":                          file("root:x:0:0::/root:/bin/sh\npants:x:1000:1000::/home/pants:/bin/sh\n"),
		"etc/group":                           file("pants:x:1000:\n"),
		"etc/sudoers.d/pants":                 file("pants ALL=(ALL) NOPASSWD: ALL\n"),
	}
}

// e2eJournal serves sshd's records once, then follows (blocks) until the run ends.
func e2eJournal(lines ...string) access.Journal {
	return func(ctx context.Context, _ string) (io.ReadCloser, error) {
		r, w := io.Pipe()
		go func() {
			for _, l := range lines {
				if _, err := io.WriteString(w, l+"\n"); err != nil {
					return
				}
			}
			<-ctx.Done()
			_ = w.CloseWithError(ctx.Err())
		}()
		return r, nil
	}
}

func journalRecord(t *testing.T, msg, cursor string) string {
	t.Helper()
	b, err := json.Marshal(map[string]string{"MESSAGE": msg, "_SYSTEMD_UNIT": "ssh.service", "_UID": "0",
		"__REALTIME_TIMESTAMP": strconv.FormatInt(time.Now().Add(-time.Minute).UnixMicro(), 10), "__CURSOR": cursor})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The task's acceptance proof for the host identity facts: the agent's access reader, on a
// host's files and sshd's journal, sends asm.host.access (in full, then by its digest) and
// asm.host.sign_ins through the HTTPS sink, and Signal's reference door stores them with
// nothing refused and no gap.
func TestE2EHostIdentityFactsAreStoredBySignal(t *testing.T) {
	ref, pub, _ := signalDoor(t, e2eHost)

	const fp = "SHA256:I8mg+yasAvN5VKOREFoeN54OIuc1hm+LJL6KAGScwsI"
	shared, err := access.ParseSharedKeys("underpants " + fp + "\n")
	if err != nil {
		t.Fatal(err)
	}
	cert := "Accepted publickey for pants from 192.0.2.10 port 51234 ssh2: ED25519-CERT " + fp +
		" ID oidc-ada@example.com (serial 7340021) CA ED25519 SHA256:XwOh4qn0x9RTx0vJMDxDEA8QC1d4LRwshcnnBWIN0qQ"
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		access.Run(ctx, access.Config{Root: e2eHostRoot(), Accounts: []string{"pants", "root"}, SharedKeys: shared,
			Journal: e2eJournal(
				journalRecord(t, cert, "c1"),
				journalRecord(t, "Accepted publickey for pants from 192.0.2.20 port 22 ssh2: ED25519 "+fp, "c2"),
				journalRecord(t, "Failed password for root from 192.0.2.30 port 22 ssh2", "c3"),
			),
			CursorFile: filepath.Join(t.TempDir(), "journal-cursor"),
			Poll:       20 * time.Millisecond, Recheck: 100 * time.Millisecond, Flush: 100 * time.Millisecond,
			Log: slog.New(slog.NewTextHandler(io.Discard, nil))}, pub)
		close(done)
	}()
	signIns := func() *eventsv1.SignInSummary {
		for _, e := range ref.Stored() {
			if e.GetType() == "asm.host.sign_ins" && len(e.GetSignIns().GetGroups()) > 0 {
				return e.GetSignIns()
			}
		}
		return nil
	}
	waitFor(t, "asm.host.access", func() bool { return stored(ref, "asm.host.access", 0) != nil })
	waitFor(t, "asm.host.sign_ins with the sign-ins", func() bool { return signIns() != nil })
	time.Sleep(300 * time.Millisecond) // rechecks: unchanged, confirmed by the digest
	cancel()
	<-done
	if err := pub.Close(); err != nil {
		t.Fatal(err)
	}

	acc := stored(ref, "asm.host.access", 0)
	ha := acc.GetHostAccess()
	if acc.GetSubject() != "host:"+e2eHost || ha.GetUnchanged() || !ha.GetSshd().GetRead() ||
		ha.GetSshd().GetTrustedUserCaKeys()[0].GetLabel() != "vault ssh/prod" || len(ha.GetAccounts()) != 2 {
		t.Fatalf("access = %v", acc)
	}
	for _, e := range ref.Stored() {
		if e.GetType() == "asm.host.access" && e.GetId() != acc.GetId() {
			t.Fatalf("an unchanged access state was stored again (want it confirmed by digest): %v", e)
		}
	}
	groups := signIns().GetGroups()
	if len(groups) != 2 || groups[0].GetKeyId() != "oidc-ada@example.com" || groups[0].GetMethod() != eventsv1.SignInGroup_CERTIFICATE ||
		groups[1].GetKeyFingerprint() != fp || groups[1].GetMethod() != eventsv1.SignInGroup_KEY {
		t.Fatalf("groups = %v", groups)
	}
	if js, _ := protojson.Marshal(acc); strings.Contains(string(js), "AAAAC3Nza") || strings.Contains(string(js), "NOPASSWD") {
		t.Fatalf("a key or a rule's text reached Signal: %s", js)
	}
	if len(ref.Quarantined()) != 0 || len(ref.Gaps()) != 0 {
		t.Fatalf("quarantined %v, gaps %v", ref.Quarantined(), ref.Gaps())
	}
}
