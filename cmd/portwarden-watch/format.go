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
)

// parsed is one decoded message: the line to print plus what gap detection needs.
type parsed struct {
	line string
	run  string
	seq  uint64
}

// formatEvent renders one stream message as a single line. The subject's last token
// (opened, closed, snapshot, heartbeat) selects the payload type.
func formatEvent(subject string, data []byte) (string, error) {
	p, err := parseMessage(subject, data)
	return p.line, err
}

func parseMessage(subject string, data []byte) (parsed, error) {
	kind := subject[strings.LastIndexByte(subject, '.')+1:]
	switch kind {
	case "opened", "closed":
		var ev asmv1.ListenerEvent
		if err := proto.Unmarshal(data, &ev); err != nil {
			return parsed{}, fmt.Errorf("decode %s: %w", subject, err)
		}
		verb := "OPENED"
		if ev.GetKind() == asmv1.Kind_CLOSED {
			verb = "CLOSED"
		}
		l := ev.GetListener()
		body := fmt.Sprintf("%s %s %s", verb, l.GetProto(), net.JoinHostPort(l.GetAddr(), strconv.Itoa(int(l.GetPort()))))
		body += processSuffix(ev.GetProcesses())
		return parsed{header(ev.GetObservedAt(), ev.GetHostId(), ev.GetSeq()) + " " + body, ev.GetRunId(), ev.GetSeq()}, nil
	case "snapshot":
		var s asmv1.Snapshot
		if err := proto.Unmarshal(data, &s); err != nil {
			return parsed{}, fmt.Errorf("decode %s: %w", subject, err)
		}
		body := fmt.Sprintf("SNAPSHOT n=%d", len(s.GetListeners()))
		return parsed{header(s.GetTakenAt(), s.GetHostId(), s.GetSeq()) + " " + body, s.GetRunId(), s.GetSeq()}, nil
	case "heartbeat":
		var h asmv1.Heartbeat
		if err := proto.Unmarshal(data, &h); err != nil {
			return parsed{}, fmt.Errorf("decode %s: %w", subject, err)
		}
		body := fmt.Sprintf("HEARTBEAT drops=%d/%d/%d", h.GetRingbufDrops(), h.GetQueueDrops(), h.GetDroppedForeignNetns())
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
