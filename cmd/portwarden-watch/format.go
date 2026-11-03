package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
)

const (
	timeLayout = "2006-01-02T15:04:05.000Z"
	hostWidth  = 8
	idWidth    = 12
	// initNetNS is the inode of the initial (host) network namespace: the first namespace
	// inode the kernel allocates (0xF0000000) on the kernels Portwarden supports. The
	// stream does not carry each host's own value, so the watcher compares against this.
	initNetNS = 4026531840
)

// parsed is one decoded message: the line to print plus what gap detection needs.
type parsed struct {
	line string
	run  string
	seq  uint64
}

// formatEvent renders one stream message as a single line. The subject's suffix
// (listener.opened/closed/owner_changed, exposure.changed, host.changed, snapshot,
// heartbeat) selects the payload type.
func formatEvent(subject string, data []byte) (string, error) {
	p, err := parseMessage(subject, data)
	return p.line, err
}

func parseMessage(subject string, data []byte) (parsed, error) {
	switch {
	case strings.HasSuffix(subject, ".exposure.changed"):
		var ev asmv1.ExposureEvent
		if err := proto.Unmarshal(data, &ev); err != nil {
			return parsed{}, fmt.Errorf("decode %s: %w", subject, err)
		}
		l := ev.GetListener()
		body := fmt.Sprintf("EXPOSURE %s %s %s->%s trigger=%s", l.GetProto(),
			net.JoinHostPort(l.GetAddr(), strconv.Itoa(int(l.GetPort()))),
			levelName(ev.GetPrevious()), levelName(ev.GetExposure()), ev.GetTrigger())
		if n := l.GetNetns(); n != 0 && n != initNetNS {
			body += fmt.Sprintf(" netns=%d", n)
		}
		if evd := ev.GetExposure().GetEvidence(); len(evd) > 0 {
			body += " evidence=" + strings.Join(evd, "; ")
		}
		return parsed{header(ev.GetObservedAt(), ev.GetHostId(), ev.GetSeq()) + " " + body, ev.GetRunId(), ev.GetSeq()}, nil
	case strings.HasSuffix(subject, ".host.changed"):
		var ev asmv1.HostEvent
		if err := proto.Unmarshal(data, &ev); err != nil {
			return parsed{}, fmt.Errorf("decode %s: %w", subject, err)
		}
		return parsed{header(ev.GetObservedAt(), ev.GetHostId(), ev.GetSeq()) + " HOST" + hostSuffix(ev.GetHost()), ev.GetRunId(), ev.GetSeq()}, nil
	}
	kind := subject[strings.LastIndexByte(subject, '.')+1:]
	switch kind {
	case "opened", "closed", "owner_changed":
		var ev asmv1.ListenerEvent
		if err := proto.Unmarshal(data, &ev); err != nil {
			return parsed{}, fmt.Errorf("decode %s: %w", subject, err)
		}
		l := ev.GetListener()
		body := fmt.Sprintf("%s %s %s", verb(ev.GetKind()), l.GetProto(), net.JoinHostPort(l.GetAddr(), strconv.Itoa(int(l.GetPort()))))
		body += processSuffix(ev.GetProcesses())
		body += contextSuffix(l.GetNetns(), ev.GetProcesses())
		if ev.GetKind() == asmv1.Kind_OWNER_CHANGED {
			body += " was=" + holders(ev.GetPreviousProcesses())
		}
		return parsed{header(ev.GetObservedAt(), ev.GetHostId(), ev.GetSeq()) + " " + body, ev.GetRunId(), ev.GetSeq()}, nil
	case "snapshot":
		var s asmv1.Snapshot
		if err := proto.Unmarshal(data, &s); err != nil {
			return parsed{}, fmt.Errorf("decode %s: %w", subject, err)
		}
		counts := map[string]int{}
		for _, ls := range s.GetListeners() {
			counts[ls.GetListener().GetProto()]++
		}
		body := fmt.Sprintf("SNAPSHOT n=%d tcp=%d udp=%d", len(s.GetListeners()), counts["tcp"], counts["udp"])
		return parsed{header(s.GetTakenAt(), s.GetHostId(), s.GetSeq()) + " " + body, s.GetRunId(), s.GetSeq()}, nil
	case "heartbeat":
		var h asmv1.Heartbeat
		if err := proto.Unmarshal(data, &h); err != nil {
			return parsed{}, fmt.Errorf("decode %s: %w", subject, err)
		}
		body := fmt.Sprintf("HEARTBEAT drops=%d/%d", h.GetRingbufDrops(), h.GetQueueDrops())
		return parsed{header(h.GetAt(), h.GetHostId(), h.GetSeq()) + " " + body, h.GetRunId(), h.GetSeq()}, nil
	}
	return parsed{}, fmt.Errorf("unrecognised subject %q", subject)
}

// header is "<time> <host> seq=<n>"; the host is the first 8 characters of host_id.
func header(ts *timestamppb.Timestamp, host string, seq uint64) string {
	if len(host) > hostWidth {
		host = host[:hostWidth]
	}
	return fmt.Sprintf("%s %s seq=%d", ts.AsTime().UTC().Format(timeLayout), host, seq)
}

// processSuffix prints the first holder as "pid=N exe" (comm when the exe is unreadable)
// and notes any further holders (SO_REUSEPORT workers).
func processSuffix(ps []*asmv1.Process) string {
	if len(ps) == 0 {
		return ""
	}
	p := ps[0]
	name := p.GetExe()
	if name == "" {
		name = p.GetComm()
	}
	s := fmt.Sprintf(" pid=%d %s", p.GetPid(), name)
	if len(ps) > 1 {
		s += fmt.Sprintf(" (+%d more)", len(ps)-1)
	}
	return s
}

// contextSuffix prints " netns=<n>" for a listener outside the host netns (0 is unset),
// then the first holder's " unit=<u> sock=<socket unit> ctr=<runtime>:<id12>", each
// omitted when empty.
func contextSuffix(netns uint32, ps []*asmv1.Process) string {
	var s string
	if netns != 0 && netns != initNetNS {
		s += fmt.Sprintf(" netns=%d", netns)
	}
	if len(ps) == 0 {
		return s
	}
	p := ps[0]
	if p.GetUnit() != "" {
		s += " unit=" + p.GetUnit()
	}
	if p.GetSocketUnit() != "" {
		s += " sock=" + p.GetSocketUnit()
	}
	if c := p.GetContainer(); c.GetId() != "" {
		id := c.GetId()
		if len(id) > idWidth {
			id = id[:idWidth]
		}
		s += fmt.Sprintf(" ctr=%s:%s", c.GetRuntime(), id)
	}
	return s
}

// holders lists processes as "<pid>/<comm>,…" (the comma-separated owners before an
// owner change); none is "-".
func holders(ps []*asmv1.Process) string {
	if len(ps) == 0 {
		return "-"
	}
	parts := make([]string, len(ps))
	for i, p := range ps {
		parts[i] = fmt.Sprintf("%d/%s", p.GetPid(), p.GetComm())
	}
	return strings.Join(parts, ",")
}

// levelName is an exposure's level without the enum prefix ("host_firewall_open"), or
// "new" when it is unset (a listener's first judgement).
func levelName(e *asmv1.Exposure) string {
	if e.GetLevel() == asmv1.ExposureLevel_EXPOSURE_LEVEL_UNSPECIFIED {
		return "new"
	}
	return strings.ToLower(strings.TrimPrefix(e.GetLevel().String(), "EXPOSURE_"))
}

// hostSuffix prints " cloud=<c> id=<instance> ips=<ip>/<via>/<dir>[/<iface>],…"; cloud
// and id are omitted when empty, no candidate is "ips=-".
func hostSuffix(h *asmv1.HostInfo) string {
	var s string
	if h.GetCloud() != "" {
		s += " cloud=" + h.GetCloud()
	}
	if h.GetInstanceId() != "" {
		s += " id=" + h.GetInstanceId()
	}
	var ips []string
	for _, ip := range h.GetPublicIps() {
		v := ip.GetIp() + "/" + ip.GetVia() + "/" + ip.GetDir()
		if ip.GetIface() != "" {
			v += "/" + ip.GetIface()
		}
		ips = append(ips, v)
	}
	if len(ips) == 0 {
		s += " ips=-"
	} else {
		s += " ips=" + strings.Join(ips, ",")
	}
	if c := h.GetConditions(); len(c) > 0 {
		s += " conditions=" + strings.Join(c, "; ")
	}
	return s
}

func verb(k asmv1.Kind) string {
	switch k {
	case asmv1.Kind_CLOSED:
		return "CLOSED"
	case asmv1.Kind_OWNER_CHANGED:
		return "OWNER_CHANGED"
	}
	return "OPENED"
}

// gapTracker remembers the last seq seen per run_id. The first message of a run, however
// late the consumer joined, sets the baseline and is never a gap.
type gapTracker struct {
	last map[string]uint64
}

// check returns a GAP line when seq skips ahead within a run, else "".
func (g *gapTracker) check(run string, seq uint64) string {
	if g.last == nil {
		g.last = map[string]uint64{}
	}
	prev, seen := g.last[run]
	if !seen || seq > prev {
		g.last[run] = seq
	}
	if seen && seq > prev+1 {
		return fmt.Sprintf("GAP run=%s expected=%d got=%d", run, prev+1, seq)
	}
	return ""
}
