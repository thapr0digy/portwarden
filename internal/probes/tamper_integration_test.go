//go:build linux && integration

package probes

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"

	"github.com/thapr0digy/portwarden/internal/tamper"
)

func attachmentFlags(t *testing.T, list func() ([]tamper.Attachment, error)) []tamper.Flag {
	t.Helper()
	flags, err := tamper.NewAttachments("probes", list).Run()
	if err != nil {
		t.Fatal(err)
	}
	return flags
}

// The listener links read attached and running the loaded programs. Tracing links have no
// detach operation on the fleet's kernels: an external BPF_LINK_DETACH (what `bpftool
// link detach` does) is refused, and they stay attached. Should a kernel accept it, the
// tamper check must see the link detached.
func TestTamperListenLinks(t *testing.T) {
	p, err := Start()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	got, err := p.Attachments()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("want 4 listener links, got %+v", got)
	}
	for _, a := range got {
		if !a.Attached || a.Prog != a.WantProg || a.WantTag == "" || a.LinkID == 0 {
			t.Fatalf("healthy link reads wrong: %+v", a)
		}
	}
	if flags := attachmentFlags(t, p.Attachments); len(flags) != 0 {
		t.Fatalf("healthy probes flagged: %+v", flags)
	}

	l, err := link.NewFromID(link.ID(got[0].LinkID))
	if err != nil {
		t.Fatalf("open link %d by id: %v", got[0].LinkID, err)
	}
	defer l.Close()
	derr := l.Detach()
	flags := attachmentFlags(t, p.Attachments)
	if derr != nil {
		t.Logf("kernel refuses an external detach of tracing link %s: %v", got[0].Name, derr)
		if len(flags) != 0 {
			t.Fatalf("refused detach still flagged: %+v", flags)
		}
		return
	}
	t.Logf("kernel accepted an external detach of tracing link %s", got[0].Name)
	if len(flags) != 1 || flags[0].Kind != tamper.KindProbeDetached {
		t.Fatalf("an externally detached tracing link must be flagged probe_detached, got %+v", flags)
	}
}

// A connect link detached from outside (bpftool link detach) is probe_detached; one whose
// program was swapped with BPF_LINK_UPDATE is program_replaced; one whose cgroup was
// removed is not tamper.
func TestTamperProxyConnLinks(t *testing.T) {
	p, err := StartProxyConns()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	rel := fmt.Sprintf("pw-itest-tamper-%d", os.Getpid())
	dir := filepath.Join(CgroupRoot, rel)
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(dir)
	if err := p.SetCgroups([]string{rel}); err != nil {
		t.Fatal(err)
	}
	got, err := p.Attachments()
	if err != nil || len(got) != 2 {
		t.Fatalf("attachments: %+v %v", got, err)
	}
	if flags := attachmentFlags(t, p.Attachments); len(flags) != 0 {
		t.Fatalf("healthy connect links flagged: %+v", flags)
	}
	byName := map[string]tamper.Attachment{}
	for _, a := range got {
		byName[a.Name] = a
	}

	// Detach connect4 from outside, as bpftool would.
	l4, err := link.NewFromID(link.ID(byName[proxyconnProgOnConnect4].LinkID))
	if err != nil {
		t.Fatal(err)
	}
	defer l4.Close()
	if err := l4.Detach(); err != nil {
		t.Fatalf("detach cgroup link: %v", err)
	}
	flags := attachmentFlags(t, p.Attachments)
	if len(flags) != 1 || flags[0].Kind != tamper.KindProbeDetached || flags[0].Subject != proxyconnProgOnConnect4+"@"+rel {
		t.Fatalf("want probe_detached for on_connect4@%s, got %+v", rel, flags)
	}

	// Swap connect6's program for one that allows every connect and counts nothing.
	nop, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.CGroupSockAddr, AttachType: ebpf.AttachCGroupInet6Connect, License: "GPL",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 1), asm.Return()},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer nop.Close()
	l6, err := link.NewFromID(link.ID(byName[proxyconnProgOnConnect6].LinkID))
	if err != nil {
		t.Fatal(err)
	}
	defer l6.Close()
	if err := l6.Update(nop); err != nil {
		t.Fatalf("update cgroup link: %v", err)
	}
	flags = attachmentFlags(t, p.Attachments)
	kinds := map[string]string{}
	for _, f := range flags {
		kinds[f.Kind] = f.Subject
	}
	if kinds[tamper.KindProgramReplaced] != proxyconnProgOnConnect6+"@"+rel || len(flags) != 2 {
		t.Fatalf("want program_replaced for on_connect6 too, got %+v", flags)
	}

	// The proxy's cgroup goes away (its unit stopped): its links read detached, which is
	// not tamper.
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		got, err := p.Attachments()
		if err != nil {
			t.Fatal(err)
		}
		if len(got) == 0 || !anyAttached(got) {
			if len(got) != 0 {
				t.Fatalf("links of a removed cgroup must be left out: %+v", got)
			}
			break
		}
		if time.Now().After(deadline) {
			// connect6 still reads attached (running nop) until the kernel releases the
			// cgroup; it must not be reported as anything but program_replaced.
			t.Logf("cgroup links not yet released after rmdir: %+v", got)
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := p.SetCgroups(nil); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Logf("detach after rmdir: %v", err)
	}
}

func anyAttached(as []tamper.Attachment) bool {
	for _, a := range as {
		if a.Attached {
			return true
		}
	}
	return false
}
