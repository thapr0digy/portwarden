package validate

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/known/timestamppb"

	ev "github.com/slidehq/signal/schema/eventsv1"
)

var now = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)

func opts() Options { return Options{Now: func() time.Time { return now }} }

const (
	hostID = "4f1c2a9e7b3d4c5e8f9a0b1c2d3e4f5a"
	runID  = "01JC8Z6X4P9QK2M3N5R7T8V0WA"
	sha    = "ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d"
)

// finding is a valid tool event.
func finding() *ev.Event {
	return &ev.Event{
		Id: "01JC90AAAA0000000000000F01", Type: "asm.finding.reported",
		Source: "urn:asm:scanner:edge-1", Subject: "url:https://app.example.com/.git/config",
		Time: timestamppb.New(now.Add(-time.Minute)),
		Data: &ev.Event_FindingReported{FindingReported: &ev.FindingReport{
			Kind: ev.FindingReport_EXPOSURE, State: ev.FindingReport_PRESENT, RuleId: "git-config",
			Severity: &ev.Severity{Level: ev.Severity_MEDIUM, Score: 5.3, ScoreSystem: "cvss_v3.1"},
		}},
	}
}

// listener is a valid agent event.
func listenerEvent() *ev.Event {
	return &ev.Event{
		Id: "01JC8Z6X4Q00000000000000M1", Type: "asm.listener.opened",
		Source: "urn:asm:agent:" + hostID, Subject: "host:" + hostID,
		Time:     timestamppb.New(now),
		Sequence: &ev.Sequence{RunId: runID, Seq: 57},
		Data: &ev.Event_ListenerChange{ListenerChange: &ev.ListenerChange{
			Listener: &ev.Listener{Proto: "tcp", Addr: "0.0.0.0", Port: 6379},
		}},
	}
}

func toolOutputEvent(inline []byte) *ev.Event {
	return &ev.Event{
		Id: "01JC90AAAA0000000000000T01", Type: "asm.tool.output",
		Source: "urn:asm:scanner:edge-1", Subject: "scan:01JC90AAAA0000000000000S01",
		Time: timestamppb.New(now),
		Data: &ev.Event_ToolOutput{ToolOutput: &ev.ToolOutput{
			Tool: "nuclei", Format: "nuclei-jsonl", Body: &ev.ToolOutput_Inline{Inline: inline},
		}},
	}
}

const exampleFP = "SHA256:9Puo8/7xmKbG5DEoJXYw8dSkfzAUovRGBQCMFLPuQBM"

func signInEvent() *ev.Event {
	at := timestamppb.New(now.Add(-time.Minute))
	return &ev.Event{
		Id: "01JC8Z6X4Q00000000000000S1", Type: "asm.host.sign_ins",
		Source: "urn:asm:agent:" + hostID, Subject: "host:" + hostID,
		Time:     timestamppb.New(now),
		Sequence: &ev.Sequence{RunId: runID, Seq: 58},
		Data: &ev.Event_SignIns{SignIns: &ev.SignInSummary{
			WindowEnd: timestamppb.New(now),
			Groups: []*ev.SignInGroup{{Account: "pants", Method: ev.SignInGroup_CERTIFICATE, KeyId: "oidc-ada@example.com",
				CaFingerprint: exampleFP, Serial: "12", FromIp: "192.0.2.10", Count: 1, FirstAt: at, LastAt: at}},
		}},
	}
}

func accessEvent() *ev.Event {
	return &ev.Event{
		Id: "01JC8Z6X4Q00000000000000S2", Type: "asm.host.access",
		Source: "urn:asm:agent:" + hostID, Subject: "host:" + hostID,
		Time:     timestamppb.New(now),
		Sequence: &ev.Sequence{RunId: runID, Seq: 59},
		Data: &ev.Event_HostAccess{HostAccess: &ev.HostAccess{
			Sshd:     &ev.Sshd{Read: true, TrustedUserCaKeys: []*ev.TrustedKey{{Fingerprint: exampleFP, Label: "vault ssh/prod"}}},
			Accounts: []*ev.AccountAccess{{Account: "pants", StaticKeysRead: true, StaticKeys: []string{exampleFP}}},
		}},
	}
}

func packagesEvent() *ev.Event {
	return &ev.Event{
		Id: "01JC8Z6X4Q00000000000000S3", Type: "asm.host.packages",
		Source: "urn:asm:agent:" + hostID, Subject: "host:" + hostID,
		Time:     timestamppb.New(now),
		Sequence: &ev.Sequence{RunId: runID, Seq: 60},
		Data: &ev.Event_HostPackages{HostPackages: &ev.HostPackages{
			Read: true, Manager: "dpkg", Total: 2,
			Distro: &ev.Distro{Id: "ubuntu", VersionId: "22.04", Codename: "jammy"},
			Packages: []*ev.OSPackage{
				{Name: "openssh-server", Version: "1:8.9p1-3ubuntu0.6", Source: "openssh", SourceVersion: "1:8.9p1-3ubuntu0.6", Arch: "amd64"},
				{Name: "libc6", Version: "2.35-0ubuntu3.8", Source: "glibc", SourceVersion: "2.35-0ubuntu3.8", Arch: "amd64"},
			},
		}},
	}
}

func pkgs(e *ev.Event) *ev.HostPackages { return e.GetHostPackages() }

func grp(e *ev.Event) *ev.SignInGroup { return e.GetSignIns().GetGroups()[0] }

func fr(e *ev.Event) *ev.FindingReport { return e.GetFindingReported() }

func with(e *ev.Event, f func(*ev.Event)) *ev.Event { f(e); return e }

func TestValidateTable(t *testing.T) {
	cases := []struct {
		name string
		ev   *ev.Event
		code Code // "" = valid
		path string
	}{
		{"valid finding", finding(), "", ""},
		{"valid listener", listenerEvent(), "", ""},
		{"valid sign-ins", signInEvent(), "", ""},
		{"valid access state", accessEvent(), "", ""},
		{"sign-in without a method", with(signInEvent(), func(e *ev.Event) { grp(e).Method = ev.SignInGroup_METHOD_UNSPECIFIED }), CodeInvalidPayload, "sign_ins.groups[0].method"},
		{"sign-in with no count", with(signInEvent(), func(e *ev.Event) { grp(e).Count = 0 }), CodeInvalidPayload, "sign_ins.groups[0].count"},
		{"sign-in last before first", with(signInEvent(), func(e *ev.Event) { grp(e).FirstAt = timestamppb.New(now) }), CodeInvalidPayload, "sign_ins.groups[0].last_at"},
		{"sign-in after the window", with(signInEvent(), func(e *ev.Event) { e.GetSignIns().WindowEnd = timestamppb.New(now.Add(-time.Hour)) }), CodeInvalidPayload, "sign_ins.groups[0].last_at"},
		{"sign-in account not a user name", with(signInEvent(), func(e *ev.Event) { grp(e).Account = "Pants Root" }), CodeInvalidPayload, "sign_ins.groups[0].account"},
		{"sign-in key ID with a space", with(signInEvent(), func(e *ev.Event) { grp(e).KeyId = "oidc-a b" }), CodeInvalidPayload, "sign_ins.groups[0].key_id"},
		{"sign-in key ID over its cap", with(signInEvent(), func(e *ev.Event) { grp(e).KeyId = strings.Repeat("a", 257) }), CodeTooLarge, "sign_ins.groups[0].key_id"},
		{"sign-in CA not a fingerprint", with(signInEvent(), func(e *ev.Event) { grp(e).CaFingerprint = "MD5:aa" }), CodeInvalidPayload, "sign_ins.groups[0].ca_fingerprint"},
		{"sign-in from a non-canonical IP", with(signInEvent(), func(e *ev.Event) { grp(e).FromIp = "::ffff:192.0.2.1" }), CodeInvalidPayload, "sign_ins.groups[0].from_ip"},
		{"jump hop without a person", with(signInEvent(), func(e *ev.Event) {
			e.GetSignIns().Hops = []*ev.JumpHop{{Target: "box-1", Count: 1, FirstAt: grp(e).FirstAt, LastAt: grp(e).LastAt}}
		}), CodeInvalidPayload, "sign_ins.hops[0].person"},
		{"access key not a fingerprint", with(accessEvent(), func(e *ev.Event) { e.GetHostAccess().Accounts[0].StaticKeys = []string{"ssh-ed25519 AAAA"} }), CodeInvalidPayload, "host_access.accounts[0].static_keys[0]"},
		{"access trusted key label over its cap", with(accessEvent(), func(e *ev.Event) { e.GetHostAccess().Sshd.TrustedUserCaKeys[0].Label = strings.Repeat("a", 65) }), CodeTooLarge, "host_access.sshd.trusted_user_ca_keys[0].label"},
		{"access with both sshd settings", with(accessEvent(), func(e *ev.Event) {
			e.GetHostAccess().Sshd.PasswordAuthentication, e.GetHostAccess().Sshd.PermitRootLogin = "no", "prohibit-password"
		}), "", ""},
		{"access password setting not sshd's", with(accessEvent(), func(e *ev.Event) { e.GetHostAccess().Sshd.PasswordAuthentication = "true" }), CodeInvalidPayload, "host_access.sshd.password_authentication"},
		{"access root login setting not sshd's", with(accessEvent(), func(e *ev.Event) { e.GetHostAccess().Sshd.PermitRootLogin = "without-password" }), CodeInvalidPayload, "host_access.sshd.permit_root_login"},
		{"unread sshd with a setting", with(accessEvent(), func(e *ev.Event) {
			e.GetHostAccess().Sshd = &ev.Sshd{Unreadable: "denied", PasswordAuthentication: "yes"}
		}), CodeInvalidPayload, "host_access.sshd.read"},
		{"unchanged access with a body", with(accessEvent(), func(e *ev.Event) {
			e.GetHostAccess().Unchanged = true
			e.GetHostAccess().Digest = strings.Repeat("a", 64)
		}), CodeInvalidPayload, "host_access.unchanged"},
		{"valid package list", packagesEvent(), "", ""},
		{"valid unreadable package list", with(packagesEvent(), func(e *ev.Event) {
			e.Data = &ev.Event_HostPackages{HostPackages: &ev.HostPackages{Unreadable: "/var/lib/dpkg/status: permission denied"}}
		}), "", ""},
		{"package without its source", with(packagesEvent(), func(e *ev.Event) { pkgs(e).Packages[0].Source = "" }), CodeInvalidPayload, "host_packages.packages[0].source"},
		{"package name not Debian's", with(packagesEvent(), func(e *ev.Event) { pkgs(e).Packages[0].Name = "OpenSSH Server" }), CodeInvalidPayload, "host_packages.packages[0].name"},
		{"package version with a space", with(packagesEvent(), func(e *ev.Event) { pkgs(e).Packages[0].Version = "1.0 beta" }), CodeInvalidPayload, "host_packages.packages[0].version"},
		{"package listed twice", with(packagesEvent(), func(e *ev.Event) { pkgs(e).Packages[1] = pkgs(e).Packages[0] }), CodeInvalidPayload, "host_packages.packages[1]"},
		{"package list without a distro", with(packagesEvent(), func(e *ev.Event) { pkgs(e).Distro = nil }), CodeInvalidPayload, "host_packages.distro"},
		{"package list not from dpkg", with(packagesEvent(), func(e *ev.Event) { pkgs(e).Manager = "rpm" }), CodeInvalidPayload, "host_packages.manager"},
		{"package total below the list", with(packagesEvent(), func(e *ev.Event) { pkgs(e).Total = 1 }), CodeInvalidPayload, "host_packages.total"},
		{"unreadable list with packages", with(packagesEvent(), func(e *ev.Event) { pkgs(e).Read = false; pkgs(e).Unreadable = "denied" }), CodeInvalidPayload, "host_packages.packages"},
		{"unreadable list without a reason", with(packagesEvent(), func(e *ev.Event) { pkgs(e).Read = false; pkgs(e).Packages = nil }), CodeInvalidPayload, "host_packages.unreadable"},
		{"unchanged list with a body", with(packagesEvent(), func(e *ev.Event) { pkgs(e).Unchanged = true; pkgs(e).Digest = strings.Repeat("a", 64) }), CodeInvalidPayload, "host_packages.unchanged"},
		{"package list over its cap", with(packagesEvent(), func(e *ev.Event) {
			pkgs(e).Packages = make([]*ev.OSPackage, 6001)
			for i := range pkgs(e).Packages {
				pkgs(e).Packages[i] = &ev.OSPackage{Name: fmt.Sprintf("pkg%d", i), Version: "1", Source: "src", SourceVersion: "1", Arch: "all"}
			}
			pkgs(e).Total = 6001
		}), CodeTooLarge, "host_packages.packages"},
		{"inline at the cap", toolOutputEvent(make([]byte, 256<<10)), "", ""},
		{"inline over the cap", toolOutputEvent(make([]byte, 256<<10+1)), CodeTooLarge, "tool_output.inline"},
		{"tool output without a body", with(toolOutputEvent(nil), func(e *ev.Event) { e.GetToolOutput().Body = nil }), CodeInvalidPayload, "tool_output.body"},

		{"string at the default cap", with(finding(), func(e *ev.Event) { fr(e).Title = strings.Repeat("a", 1024) }), "", ""},
		{"string over the default cap", with(finding(), func(e *ev.Event) { fr(e).Title = strings.Repeat("a", 1025) }), CodeTooLarge, "finding_reported.title"},
		{"string at an override", with(finding(), func(e *ev.Event) { fr(e).Description = strings.Repeat("a", 8<<10) }), "", ""},
		{"string over an override", with(finding(), func(e *ev.Event) { fr(e).Description = strings.Repeat("a", 8<<10+1) }), CodeTooLarge, "finding_reported.description"},
		{"repeated at an override", with(finding(), func(e *ev.Event) { fr(e).Evidence = &ev.Evidence{Extracted: make([]string, 32)} }), "", ""},
		{"repeated at the default cap", with(finding(), func(e *ev.Event) { fr(e).Location = &ev.Location{}; fr(e).Tags = make([]string, 64) }), "", ""},
		{"repeated over an override", with(finding(), func(e *ev.Event) { fr(e).Evidence = &ev.Evidence{Extracted: make([]string, 33)} }), CodeTooLarge, "finding_reported.evidence.extracted"},
		{"repeated over the default cap", with(finding(), func(e *ev.Event) { fr(e).Severity = nil; fr(e).Ids = nil; fr(e).Tags = make([]string, 65) }), CodeTooLarge, "finding_reported.tags"},
		{"map over the cap", assetWithAttrs(65), CodeTooLarge, "asset_discovered.attributes"},
		{"map at the cap", assetWithAttrs(64), "", ""},
		{"NUL in a string", with(finding(), func(e *ev.Event) { fr(e).Title = "a\x00b" }), CodeInvalidPayload, "finding_reported.title"},
		{"invalid UTF-8", with(finding(), func(e *ev.Event) { fr(e).Title = "a\xffb" }), CodeInvalidPayload, "finding_reported.title"},
		{"NaN score", with(finding(), func(e *ev.Event) { fr(e).Severity.Score = math.NaN() }), CodeInvalidPayload, "finding_reported.severity.score"},
		{"CVSS over 10", with(finding(), func(e *ev.Event) { fr(e).Severity.Score = 10.1 }), CodeInvalidPayload, "finding_reported.severity.score"},
		{"confidence over 100", with(finding(), func(e *ev.Event) { fr(e).Confidence = 101 }), CodeInvalidPayload, "finding_reported.confidence"},
		{"finding without a rule", with(finding(), func(e *ev.Event) { fr(e).RuleId = "" }), CodeInvalidPayload, "finding_reported.rule_id"},

		{"bad ULID (has an L)", with(finding(), func(e *ev.Event) { e.Id = "01JC90AAAA0000000000000L01" }), CodeInvalidPayload, "id"},
		{"no id", with(finding(), func(e *ev.Event) { e.Id = "" }), CodeInvalidPayload, "id"},
		{"no source", with(finding(), func(e *ev.Event) { e.Source = "" }), CodeInvalidPayload, "source"},
		{"no time", with(finding(), func(e *ev.Event) { e.Time = nil }), CodeBadTime, "time"},
		{"time 10 min ahead", with(finding(), func(e *ev.Event) { e.Time = timestamppb.New(now.Add(10 * time.Minute)) }), "", ""},
		{"time 11 min ahead", with(finding(), func(e *ev.Event) { e.Time = timestamppb.New(now.Add(11 * time.Minute)) }), CodeBadTime, "time"},
		{"time years ago", with(finding(), func(e *ev.Event) { e.Time = timestamppb.New(now.AddDate(-3, 0, 0)) }), "", ""},
		{"unknown type", with(finding(), func(e *ev.Event) { e.Type = "asm.finding.invented" }), CodeUnknownType, "type"},
		{"type and payload disagree", with(finding(), func(e *ev.Event) { e.Type = "asm.service.observed" }), CodeTypeMismatch, "data"},
		{"wrong dataschema", with(finding(), func(e *ev.Event) { e.Dataschema = "asm.events.v1/ToolOutput" }), CodeTypeMismatch, "dataschema"},
		{"no payload", with(finding(), func(e *ev.Event) { e.Data = nil }), CodeInvalidPayload, "data"},
		{"subject scheme not allowed", with(listenerEvent(), func(e *ev.Event) { e.Subject = "ip:198.51.100.7" }), CodeForbiddenSubject, "subject"},
		{"host subject not a machine-id", with(listenerEvent(), func(e *ev.Event) { e.Subject = "host:web-1" }), CodeInvalidPayload, "subject"},
		{"subject over 1 KiB", with(finding(), func(e *ev.Event) { e.Subject = "url:https://a.example.com/" + strings.Repeat("a", 1024) }), CodeTooLarge, "subject"},
		{"non-canonical IP subject", with(finding(), func(e *ev.Event) { e.Subject = "ip:::ffff:198.51.100.7" }), CodeInvalidPayload, "subject"},
		{"URL subject with a query", with(finding(), func(e *ev.Event) { e.Subject = "url:https://app.example.com/?a=1" }), CodeInvalidPayload, "subject"},
		{"javascript URL subject", with(finding(), func(e *ev.Event) { e.Subject = "url:javascript://x/" }), CodeInvalidPayload, "subject"},
		{"URL with its default port", with(finding(), func(e *ev.Event) { e.Subject = "url:https://app.example.com:443/a" }), CodeInvalidPayload, "subject"},
		{"URL with a dot segment", with(finding(), func(e *ev.Event) { e.Subject = "url:https://app.example.com/a/../b" }), CodeInvalidPayload, "subject"},
		{"URL with a zone", with(finding(), func(e *ev.Event) { e.Subject = "url:https://[fe80::1%25eth0]/" }), CodeInvalidPayload, "subject"},
		{"zero-width character in a key", with(finding(), func(e *ev.Event) { e.Subject = "url:https://app.example.com/a\u200bb" }), CodeInvalidPayload, "subject"},
		{"IPv4-mapped CIDR subject", with(finding(), func(e *ev.Event) { e.Subject = "cidr:::ffff:10.0.0.0/104" }), CodeInvalidPayload, "subject"},
		{"upper-case URL subject", with(finding(), func(e *ev.Event) { e.Subject = "url:HTTPS://App.example.com/x" }), CodeInvalidPayload, "subject"},
		{"service key on a zero-padded IP", with(finding(), func(e *ev.Event) { e.Subject = "svc:01.2.3.4:tcp/80" }), CodeInvalidPayload, "subject"},
		{"producer version with a slash", with(finding(), func(e *ev.Event) { e.Producer = &ev.Producer{Name: "scan", Version: "1/2"} }), CodeInvalidPayload, "producer.version"},
		{"empty sequence on a tool event is absent", with(finding(), func(e *ev.Event) { e.Sequence = &ev.Sequence{} }), "", ""},
		{"agent event without a sequence", with(listenerEvent(), func(e *ev.Event) { e.Sequence = nil }), CodeInvalidPayload, "sequence"},
		{"agent event with an empty sequence", with(listenerEvent(), func(e *ev.Event) { e.Sequence = &ev.Sequence{} }), CodeInvalidPayload, "sequence"},
		{"agent seq 0", with(listenerEvent(), func(e *ev.Event) { e.Sequence.Seq = 0 }), CodeInvalidPayload, "sequence.seq"},
		{"listener port over 65535", with(listenerEvent(), func(e *ev.Event) { e.GetListenerChange().Listener.Port = 70000 }), CodeInvalidPayload, "listener_change.listener.port"},
		{"bad traceparent", with(finding(), func(e *ev.Event) { e.Traceparent = "00-zz" }), CodeInvalidPayload, "traceparent"},
		{"bad blob digest", with(toolOutputEvent(nil), func(e *ev.Event) {
			e.GetToolOutput().Body = &ev.ToolOutput_Blob{Blob: &ev.BlobRef{Sha256: "ABC", Size: 1, MediaType: "text/plain"}}
		}), CodeInvalidPayload, "tool_output.blob.sha256"},
		{"valid blob", with(toolOutputEvent(nil), func(e *ev.Event) {
			e.GetToolOutput().Body = &ev.ToolOutput_Blob{Blob: &ev.BlobRef{Sha256: sha, Size: 1, MediaType: "text/plain"}}
		}), "", ""},
		{"event over 1 MiB", with(listenerEvent(), func(e *ev.Event) {
			e.Type, e.Sequence = "asm.host.snapshot", &ev.Sequence{RunId: runID, Seq: 2}
			ls := make([]*ev.ListenerState, 16384)
			for i := range ls {
				ls[i] = &ev.ListenerState{Listener: &ev.Listener{Proto: "tcp", Addr: strings.Repeat("a", 64), Port: 1}}
			}
			e.Data = &ev.Event_HostSnapshot{HostSnapshot: &ev.HostSnapshot{Listeners: ls}}
		}), CodeTooLarge, ""},
		{"unchanged snapshot with listeners", with(listenerEvent(), func(e *ev.Event) {
			e.Type = "asm.host.snapshot"
			e.Data = &ev.Event_HostSnapshot{HostSnapshot: &ev.HostSnapshot{Unchanged: true, Digest: sha, Listeners: []*ev.ListenerState{{}}}}
		}), CodeInvalidPayload, "host_snapshot.unchanged"},
		{"route digest in Portwarden's 32-hex form", with(listenerEvent(), func(e *ev.Event) {
			e.Type = "asm.proxy.routes"
			e.Data = &ev.Event_ProxyRoutes{ProxyRoutes: &ev.ProxyRoutes{Unchanged: true, RoutesDigest: "a3f1c09e5b7d2e4f6a8b0c1d2e3f4a5b"}}
		}), "", ""},
		{"scan.completed subject not its scan", scanCompletedEvent("scan:01JC90AAAA0000000000000S02"), CodeInvalidPayload, "subject"},
		{"scan.completed", scanCompletedEvent("scan:01JC90AAAA0000000000000S01"), "", ""},
		{"AssetRef kind disagrees with key", with(assetWithAttrs(0), func(e *ev.Event) { e.GetAssetDiscovered().Asset.Kind = ev.AssetRef_IP }), CodeInvalidPayload, "asset_discovered.asset.kind"},
		{"nil event", nil, CodeInvalidPayload, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := Event(c.ev, opts())
			if c.code == "" {
				if err != nil {
					t.Fatalf("want valid, got %v", err)
				}
				return
			}
			var p *Problem
			if !errors.As(err, &p) {
				t.Fatalf("want %s, got %v", c.code, err)
			}
			if p.Code != c.code || p.Path != c.path {
				t.Fatalf("want %s at %q, got %s at %q (%s)", c.code, c.path, p.Code, p.Path, p.Reason)
			}
		})
	}
}

func assetWithAttrs(n int) *ev.Event {
	attrs := map[string]string{}
	for i := 0; i < n; i++ {
		attrs[strings.Repeat("k", i+1)] = "v"
	}
	return &ev.Event{
		Id: "01JC90BBBB0000000000000D01", Type: "asm.asset.discovered",
		Source: "urn:asm:scanner:edge-1", Subject: "dns:app.example.com",
		Time: timestamppb.New(now),
		Data: &ev.Event_AssetDiscovered{AssetDiscovered: &ev.AssetDiscovery{
			Asset: &ev.AssetRef{Kind: ev.AssetRef_DNS, Key: "dns:app.example.com"}, Attributes: attrs, Present: true,
		}},
	}
}

func scanCompletedEvent(subject string) *ev.Event {
	return &ev.Event{
		Id: "01JC90AAAA0000000000000C01", Type: "asm.scan.completed",
		Source: "urn:asm:scanner:edge-1", Subject: subject, Correlationid: "01JC90AAAA0000000000000S01",
		Time: timestamppb.New(now),
		Data: &ev.Event_ScanCompleted{ScanCompleted: &ev.ScanCompleted{Status: ev.ScanCompleted_COMPLETE}},
	}
}

// A newer producer's payload (an unknown data case) is unknown_type, not
// invalid_payload, and an unknown field inside a known payload is kept and fine.
func TestUnknownFieldsInBinary(t *testing.T) {
	known := listenerEvent()
	// Field 500 of Event: a data case this version does not know.
	newer := protowire.AppendTag(nil, 500, protowire.BytesType)
	newer = protowire.AppendBytes(newer, []byte{0x08, 0x01})
	withoutData := listenerEvent()
	withoutData.Data = nil
	base, err := proto.Marshal(withoutData)
	if err != nil {
		t.Fatal(err)
	}
	var got ev.Event
	if err := proto.Unmarshal(append(base, newer...), &got); err != nil {
		t.Fatal(err)
	}
	var p *Problem
	if err := Event(&got, opts()); !errors.As(err, &p) || p.Code != CodeUnknownType {
		t.Fatalf("unknown case: want unknown_type, got %v", err)
	}

	// Field 99 inside ListenerChange: unknown, kept, valid.
	extra := protowire.AppendTag(nil, 99, protowire.VarintType)
	extra = protowire.AppendVarint(extra, 7)
	lc, err := proto.Marshal(known.GetListenerChange())
	if err != nil {
		t.Fatal(err)
	}
	var change ev.ListenerChange
	if err := proto.Unmarshal(append(lc, extra...), &change); err != nil {
		t.Fatal(err)
	}
	known.Data = &ev.Event_ListenerChange{ListenerChange: &change}
	if err := Event(known, opts()); err != nil {
		t.Fatalf("unknown field in a known payload: %v", err)
	}
	if len(change.ProtoReflect().GetUnknown()) == 0 {
		t.Fatal("the unknown field was dropped")
	}
}

func TestBatchRules(t *testing.T) {
	seq := func(run string, n uint64) *ev.Event {
		e := listenerEvent()
		e.Sequence = &ev.Sequence{RunId: run, Seq: n}
		return e
	}
	const run2 = "01JC8Z6X4P9QK2M3N5R7T8V0WB"
	overflow := func(n, first, last uint64) *ev.Event {
		e := seq(runID, n)
		e.Id, e.Type = "01JC8Z6X4Q00000000000000S1", "asm.agent.spool_overflow"
		e.Data = &ev.Event_SpoolOverflow{SpoolOverflow: &ev.SpoolOverflow{RunId: runID, FirstSeq: first, LastSeq: last, Dropped: last - first + 1}}
		return e
	}
	cases := []struct {
		name string
		evs  []*ev.Event
		code Code
	}{
		{"contiguous", []*ev.Event{seq(runID, 1), seq(runID, 2), seq(run2, 1)}, ""},
		{"a gap inside a run", []*ev.Event{seq(runID, 1), seq(runID, 3)}, CodeInvalidBatch},
		{"a spool overflow explains its gap", []*ev.Event{seq(runID, 5), overflow(11, 6, 10), seq(runID, 12)}, ""},
		{"a spool overflow that does not match the gap", []*ev.Event{seq(runID, 5), overflow(11, 7, 10)}, CodeInvalidBatch},
		{"backwards", []*ev.Event{seq(runID, 2), seq(runID, 1)}, CodeInvalidBatch},
		{"a run split by another", []*ev.Event{seq(runID, 1), seq(run2, 1), seq(runID, 2)}, CodeInvalidBatch},
		{"empty", nil, CodeInvalidBatch},
		{"over 1000 events", make([]*ev.Event, 1001), CodeTooLarge},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ps := Batch(&ev.Batch{Events: c.evs}, opts())
			if c.code == "" {
				if len(ps) > 0 {
					t.Fatalf("want valid, got %v", ps)
				}
				return
			}
			if len(ps) == 0 || ps[0].Code != c.code || ps[0].Index != BatchIndex {
				t.Fatalf("want batch-level %s, got %v", c.code, ps)
			}
		})
	}
}

func TestDecodeBinaryBounds(t *testing.T) {
	small := Limits(Default)
	small.MaxBatchEvents = 2
	one, err := proto.Marshal(&ev.Batch{Events: []*ev.Event{listenerEvent()}})
	if err != nil {
		t.Fatal(err)
	}
	three := append(append(append([]byte{}, one...), one...), one...)
	if _, err := DecodeBinary(three, Options{Limits: &small}); !errors.Is(err, ErrBatchTooLarge) {
		t.Fatalf("3 events over a cap of 2: want ErrBatchTooLarge, got %v", err)
	}
	small.MaxBatchBytes = len(one) - 1
	if _, err := DecodeBinary(one, Options{Limits: &small}); !errors.Is(err, ErrBatchTooLarge) {
		t.Fatalf("body over the byte cap: want ErrBatchTooLarge, got %v", err)
	}
	for _, body := range [][]byte{{0xff}, {0x0a, 0x05, 0x01}, {0x08, 0x01}} {
		if _, err := DecodeBinary(body, Options{}); !errors.Is(err, ErrMalformed) {
			t.Fatalf("%x: want ErrMalformed, got %v", body, err)
		}
	}
	// An event that does not decode (a truncated field; invalid UTF-8 in a proto3
	// string, Event.source) is refused alone, not the batch.
	event := protowire.AppendTag(nil, 3, protowire.BytesType)
	event = protowire.AppendBytes(event, []byte("a\xffb"))
	for _, ev := range [][]byte{{0x0a, 0xff}, event} {
		raw := protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), ev)
		d, err := DecodeBinary(append(raw, one...), Options{Now: opts().Now})
		if err != nil {
			t.Fatalf("%x: want a per-event problem, got %v", ev, err)
		}
		if p := d.Elements[0].Problem; p == nil || p.Code != CodeInvalidPayload || d.Elements[1].Problem != nil {
			t.Fatalf("%x: want only element 0 refused, got %+v", ev, d.Elements)
		}
	}
	// Deep nesting is refused, not recursed into without bound. No message of the
	// schema nests deeper than its own shape, so a hostile depth can only come from
	// unknown groups; protowire stops those at 10,000 levels (DefaultRecursionLimit).
	const depth = 20000
	deep := []byte{}
	for i := 0; i < depth; i++ {
		deep = protowire.AppendTag(deep, 9, protowire.StartGroupType)
	}
	for i := 0; i < depth; i++ {
		deep = protowire.AppendTag(deep, 9, protowire.EndGroupType)
	}
	if _, err := DecodeBinary(deep, Options{}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("deep nesting: want ErrMalformed, got %v", err)
	}
}

// A body of cheap, empty submessages must not decode into a huge tree: an event
// over MaxEventBytes is refused before it is decoded, and a refused event keeps
// only its envelope (the security review's 944 MiB batch).
func TestDecodeBinaryAmplification(t *testing.T) {
	snapshot := func(n int) []byte {
		e := listenerEvent()
		e.Type, e.Data = "asm.host.snapshot", &ev.Event_HostSnapshot{HostSnapshot: &ev.HostSnapshot{}}
		b, err := proto.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < n; i++ { // HostSnapshot.listeners (field 6) inside Event.data
			b = protowire.AppendTag(b, protowire.Number(eventsv1CaseOf(t, "asm.host.snapshot")), protowire.BytesType)
			b = protowire.AppendBytes(b, protowire.AppendBytes(protowire.AppendTag(nil, 6, protowire.BytesType), nil))
		}
		return protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), b)
	}
	d, err := DecodeBinary(append(snapshot(300_000), snapshot(20_000)...), opts())
	if err != nil {
		t.Fatal(err)
	}
	big, over := d.Elements[0], d.Elements[1]
	if big.Problem == nil || big.Problem.Code != CodeTooLarge || big.Event != nil {
		t.Fatalf("event over 1 MiB: want too_large and no decode, got %+v", big.Problem)
	}
	if over.Problem == nil || over.Problem.Code != CodeTooLarge || over.Event == nil || over.Event.Data != nil || over.Event.GetSequence() == nil {
		t.Fatalf("20,000 listeners: want too_large with the envelope kept and data dropped, got %+v", over)
	}
}

func TestUnknownFieldBudget(t *testing.T) {
	e := finding()
	e.ProtoReflect().SetUnknown(protowire.AppendBytes(protowire.AppendTag(nil, 15, protowire.BytesType), make([]byte, 16<<10)))
	var p *Problem
	if err := Event(e, opts()); !errors.As(err, &p) || p.Code != CodeTooLarge {
		t.Fatalf("16 KiB of unknown fields: want too_large, got %v", err)
	}
}

func eventsv1CaseOf(t *testing.T, typ string) uint32 {
	t.Helper()
	info, ok := ev.Lookup(typ)
	if !ok {
		t.Fatalf("%s not in the registry", typ)
	}
	return uint32(info.Case)
}

// Every field the limits name exists: a typo would silently leave a field on the
// default cap.
func TestLimitFieldsExist(t *testing.T) {
	for name := range Default.Field {
		d, err := protoregistry.GlobalFiles.FindDescriptorByName(name)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if _, ok := d.(protoreflect.FieldDescriptor); !ok {
			t.Errorf("%s is not a field", name)
		}
	}
}
