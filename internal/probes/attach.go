//go:build linux

package probes

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/thapr0digy/portwarden/internal/tamper"
)

// attachedLink is one link with what it was attached with: the program's kernel ID and
// tag (taken from the agent's own program fd, so they are the program it loaded), the
// link's ID and, for tracing links, the BTF ID of the kernel function it hooks.
type attachedLink struct {
	name, where string
	link        link.Link
	linkID      uint32
	prog        uint32
	tag         string
	targetBTF   uint32
	// cgIno is the cgroup directory's inode at attach (cgroup links).
	cgIno uint64
}

func newAttachedLink(name, where string, prog *ebpf.Program, l link.Link) (attachedLink, error) {
	pi, err := prog.Info()
	if err != nil {
		return attachedLink{}, fmt.Errorf("info of program %s: %w", name, err)
	}
	id, ok := pi.ID()
	if !ok {
		return attachedLink{}, fmt.Errorf("the kernel reports no ID for program %s", name)
	}
	li, err := l.Info()
	if err != nil {
		return attachedLink{}, fmt.Errorf("info of the %s link: %w", name, err)
	}
	a := attachedLink{name: name, where: where, link: l, linkID: uint32(li.ID), prog: uint32(id), tag: pi.Tag}
	if tr := li.Tracing(); tr != nil {
		a.targetBTF = uint32(tr.TargetBtfId)
	}
	return a, nil
}

// observe reads each link's current state from the kernel. gone, when set, reports
// whether a detached link's attach point itself is gone (a removed cgroup), which is not
// tamper: such links are left out.
func observe(links []attachedLink, gone func(attachedLink) bool) ([]tamper.Attachment, error) {
	out := make([]tamper.Attachment, 0, len(links))
	for _, a := range links {
		li, err := a.link.Info()
		if err != nil {
			return nil, fmt.Errorf("info of link %d (%s): %w", a.linkID, a.name, err)
		}
		attached := true
		if cg := li.Cgroup(); cg != nil && cg.CgroupId == 0 {
			attached = false
		}
		if tr := li.Tracing(); tr != nil && a.targetBTF != 0 && uint32(tr.TargetBtfId) != a.targetBTF {
			attached = false
		}
		if !attached && gone != nil && gone(a) {
			continue
		}
		out = append(out, tamper.Attachment{Name: a.name, Where: a.where, LinkID: a.linkID, WantProg: a.prog,
			WantTag: a.tag, Attached: attached, Prog: uint32(li.Program)})
	}
	return out, nil
}
