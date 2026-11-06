package gcp

// Every judgement path, each with a handwritten getEffectiveFirewalls response (field
// names after docs.cloud.google.com/compute/docs/reference/rest/v1/instances/
// getEffectiveFirewalls, firewalls and firewallPolicies/getRule, read 2026-11-05; no
// real account was available). The instance is testdata/instance.json: nic0 has the
// external 34.68.10.20 and 2600:1900:4000:abcd::, nic1 no external address.

import (
	"encoding/json"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/thapr0digy/portwarden/internal/cloud"
	"github.com/thapr0digy/portwarden/internal/cloud/reach"
)

func loadInstance(t *testing.T) Instance {
	t.Helper()
	b, err := os.ReadFile("testdata/instance.json")
	if err != nil {
		t.Fatal(err)
	}
	var inst Instance
	if err := json.Unmarshal(b, &inst); err != nil {
		t.Fatal(err)
	}
	return inst
}

func ipv4Only(inst Instance) Instance {
	inst.Interfaces = append([]Interface(nil), inst.Interfaces...)
	inst.Interfaces[0].IPv6AccessConfigs = nil
	return inst
}

func parseEffective(t *testing.T, js string) Effective {
	t.Helper()
	var eff Effective
	if err := json.Unmarshal([]byte(js), &eff); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return eff
}

func tcp(port int) cloud.Port {
	return cloud.Port{Key: "k", Proto: "tcp", Addr: "0.0.0.0", Port: port, AgentLevel: cloud.LevelHostFirewallOpen}
}

type result int

const (
	isClosed result = iota
	isUndetermined
	isOpen
)

func (r result) String() string { return [...]string{"closed", "undetermined", "open"}[r] }

func classify(v cloud.Verdict) result {
	switch {
	case v.Open:
		return isOpen
	case !v.Complete:
		return isUndetermined
	}
	return isClosed
}

type judgement struct {
	inst Instance
	eff  string
	port cloud.Port
	vpn  []string
	// unconfirmed: cloud.gcp.hierarchy_confirmed is off.
	unconfirmed bool
}

func (j judgement) run(t *testing.T) cloud.Verdict {
	t.Helper()
	var vpn []netip.Prefix
	for _, c := range j.vpn {
		vpn = append(vpn, netip.MustParsePrefix(c))
	}
	// The same rules on every interface; hierarchical policies confirmed visible unless a
	// test says otherwise.
	d := HostData{Instance: j.inst, Effective: map[string]Effective{}, Policy: reach.NewPolicy(vpn), HierarchyConfirmed: !j.unconfirmed}
	for _, nic := range j.inst.Interfaces {
		d.Effective[nic.Name] = parseEffective(t, j.eff)
	}
	return Evaluate(d, []cloud.Port{j.port})[0]
}

func expect(t *testing.T, v cloud.Verdict, want result, evidence ...string) {
	t.Helper()
	if got := classify(v); got != want {
		t.Fatalf("got %s, want %s; evidence:\n%s", got, want, strings.Join(v.Evidence, "\n"))
	}
	all := strings.Join(v.Evidence, "\n")
	for _, e := range evidence {
		if !strings.Contains(all, e) {
			t.Errorf("evidence lacks %q:\n%s", e, all)
		}
	}
}

const allowHTTPS = `{"name":"allow-https","priority":1000,"direction":"INGRESS","sourceRanges":["0.0.0.0/0"],"allowed":[{"IPProtocol":"tcp","ports":["443"]}]}`

func vpcOnly(rules ...string) string {
	return `{"firewalls":[` + strings.Join(rules, ",") + `],"firewallPolicys":[]}`
}

func TestVPCAllowOpen(t *testing.T) {
	inst := ipv4Only(loadInstance(t))
	v := judgement{inst: inst, eff: vpcOnly(allowHTTPS), port: tcp(443)}.run(t)
	expect(t, v, isOpen, "nic0 (34.68.10.20): firewall allow-https (vpc, priority 1000) allows tcp/443 from 0.0.0.0/0", "reachable from 0.0.0.0/0")
}

func TestImpliedDeny(t *testing.T) {
	inst := ipv4Only(loadInstance(t))
	v := judgement{inst: inst, eff: vpcOnly(), port: tcp(443)}.run(t)
	expect(t, v, isClosed, "no rule allows tcp/443 from the internet (0.0.0.0/0); denied by implied deny")
}

func TestVPCPriorityOrder(t *testing.T) {
	inst := ipv4Only(loadInstance(t))
	deny := `{"name":"deny-all","priority":900,"sourceRanges":["0.0.0.0/0"],"denied":[{"IPProtocol":"all"}]}`
	expect(t, judgement{inst: inst, eff: vpcOnly(allowHTTPS, deny), port: tcp(443)}.run(t), isClosed, "firewall deny-all (vpc, priority 900)")
	later := `{"name":"deny-all","priority":1100,"sourceRanges":["0.0.0.0/0"],"denied":[{"IPProtocol":"all"}]}`
	expect(t, judgement{inst: inst, eff: vpcOnly(later, allowHTTPS), port: tcp(443)}.run(t), isOpen)
}

func TestVPCDenyWinsTie(t *testing.T) {
	inst := ipv4Only(loadInstance(t))
	deny := `{"name":"deny-https","priority":1000,"sourceRanges":["0.0.0.0/0"],"denied":[{"IPProtocol":"tcp","ports":["443"]}]}`
	expect(t, judgement{inst: inst, eff: vpcOnly(allowHTTPS, deny), port: tcp(443)}.run(t), isClosed, "deny-https")
}

func TestVPCDefaultPriorityAndSource(t *testing.T) {
	inst := ipv4Only(loadInstance(t))
	// No priority (1000) and no source field at all (0.0.0.0/0, the API default).
	bare := `{"name":"bare","allowed":[{"IPProtocol":"tcp","ports":["443"]}]}`
	deny := `{"name":"deny-999","priority":999,"sourceRanges":["0.0.0.0/0"],"denied":[{"IPProtocol":"tcp"}]}`
	expect(t, judgement{inst: inst, eff: vpcOnly(bare), port: tcp(443)}.run(t), isOpen, "firewall bare (vpc, priority 1000)")
	expect(t, judgement{inst: inst, eff: vpcOnly(bare, deny), port: tcp(443)}.run(t), isClosed)
}

func TestTargetTags(t *testing.T) {
	inst := ipv4Only(loadInstance(t))
	hit := `{"name":"t","sourceRanges":["0.0.0.0/0"],"targetTags":["web"],"allowed":[{"IPProtocol":"tcp"}]}`
	miss := `{"name":"t","sourceRanges":["0.0.0.0/0"],"targetTags":["db"],"allowed":[{"IPProtocol":"tcp"}]}`
	expect(t, judgement{inst: inst, eff: vpcOnly(hit), port: tcp(443)}.run(t), isOpen)
	expect(t, judgement{inst: inst, eff: vpcOnly(miss), port: tcp(443)}.run(t), isClosed)
}

func TestTargetServiceAccounts(t *testing.T) {
	inst := ipv4Only(loadInstance(t))
	hit := `{"name":"t","sourceRanges":["0.0.0.0/0"],"targetServiceAccounts":["web@acme-prod.iam.gserviceaccount.com"],"allowed":[{"IPProtocol":"tcp"}]}`
	miss := `{"name":"t","sourceRanges":["0.0.0.0/0"],"targetServiceAccounts":["db@acme-prod.iam.gserviceaccount.com"],"allowed":[{"IPProtocol":"tcp"}]}`
	expect(t, judgement{inst: inst, eff: vpcOnly(hit), port: tcp(443)}.run(t), isOpen)
	expect(t, judgement{inst: inst, eff: vpcOnly(miss), port: tcp(443)}.run(t), isClosed)
	pol := `{"firewalls":[],"firewallPolicys":[{"name":"p","type":"NETWORK","priority":1000,"rules":[
	  {"priority":10,"action":"allow","direction":"INGRESS","match":{"srcIpRanges":["0.0.0.0/0"],"layer4Configs":[{"ipProtocol":"tcp"}]},
	   "targetServiceAccounts":["web@acme-prod.iam.gserviceaccount.com"]}]}]}`
	expect(t, judgement{inst: inst, eff: pol, port: tcp(443)}.run(t), isOpen, "policy p rule 10 (network)")
}

func TestSourceTagsNeverInternet(t *testing.T) {
	inst := ipv4Only(loadInstance(t))
	tags := `{"name":"from-web","sourceTags":["web"],"sourceServiceAccounts":[],"allowed":[{"IPProtocol":"tcp"}]}`
	sa := `{"name":"from-sa","sourceServiceAccounts":["lb@acme-prod.iam.gserviceaccount.com"],"allowed":[{"IPProtocol":"tcp"}]}`
	expect(t, judgement{inst: inst, eff: vpcOnly(tags, sa), port: tcp(443)}.run(t), isClosed)
	// A source tag ORed with a range: the range still counts.
	both := `{"name":"both","sourceTags":["web"],"sourceRanges":["0.0.0.0/0"],"allowed":[{"IPProtocol":"tcp"}]}`
	expect(t, judgement{inst: inst, eff: vpcOnly(both), port: tcp(443)}.run(t), isOpen)
}

func TestReachRule(t *testing.T) {
	inst := ipv4Only(loadInstance(t))
	private := `{"name":"internal","sourceRanges":["10.0.0.0/8","35.191.0.0/16"],"allowed":[{"IPProtocol":"tcp"}]}`
	// 35.191.0.0/16 is public (Google's health checkers): open unless listed as VPN.
	expect(t, judgement{inst: inst, eff: vpcOnly(private), port: tcp(443)}.run(t), isOpen, "from 35.191.0.0/16")
	expect(t, judgement{inst: inst, eff: vpcOnly(private), port: tcp(443), vpn: []string{"35.191.0.0/16"}}.run(t), isClosed)
	rfc1918 := `{"name":"internal","sourceRanges":["10.0.0.0/8","192.168.0.0/16"],"allowed":[{"IPProtocol":"tcp"}]}`
	expect(t, judgement{inst: inst, eff: vpcOnly(rfc1918), port: tcp(443)}.run(t), isClosed)
	office := `{"name":"office","sourceRanges":["81.2.69.160/28"],"allowed":[{"IPProtocol":"tcp","ports":["22"]}]}`
	expect(t, judgement{inst: inst, eff: vpcOnly(office), port: tcp(22)}.run(t), isOpen, "from 81.2.69.160/28")
	expect(t, judgement{inst: inst, eff: vpcOnly(office), port: tcp(22), vpn: []string{"81.2.69.160/28"}}.run(t), isClosed)
}

func TestIPv6(t *testing.T) {
	inst := loadInstance(t)
	v6 := `{"name":"v6","sourceRanges":["::/0"],"allowed":[{"IPProtocol":"tcp","ports":["443"]}]}`
	expect(t, judgement{inst: inst, eff: vpcOnly(v6), port: tcp(443)}.run(t), isOpen, "nic0 (2600:1900:4000:abcd::)", "from ::/0")
	// The IPv4-only interface view never judges ::/0.
	expect(t, judgement{inst: ipv4Only(inst), eff: vpcOnly(v6), port: tcp(443)}.run(t), isClosed)
	// 0.0.0.0/0 does not reach the IPv6 address.
	v := judgement{inst: inst, eff: vpcOnly(allowHTTPS), port: tcp(443)}.run(t)
	expect(t, v, isOpen, "nic0 (34.68.10.20)")
}

func TestLayer4(t *testing.T) {
	inst := ipv4Only(loadInstance(t))
	cases := []struct {
		l4   string
		port cloud.Port
		want result
	}{
		{`{"IPProtocol":"all"}`, tcp(5432), isOpen},
		{`{"IPProtocol":"6","ports":["5432"]}`, tcp(5432), isOpen},
		{`{"IPProtocol":"tcp","ports":["5000-6000"]}`, tcp(5432), isOpen},
		{`{"IPProtocol":"tcp","ports":["5000-5400"]}`, tcp(5432), isClosed},
		{`{"IPProtocol":"udp","ports":["5432"]}`, tcp(5432), isClosed},
		{`{"IPProtocol":"17","ports":["53"]}`, cloud.Port{Key: "k", Proto: "udp", Port: 53, AgentLevel: cloud.LevelHostFirewallOpen}, isOpen},
		{`{"IPProtocol":"icmp"}`, tcp(5432), isClosed},
		{`{"IPProtocol":"tcp","ports":["fifty"]}`, tcp(5432), isUndetermined},
	}
	for _, c := range cases {
		fw := `{"name":"r","sourceRanges":["0.0.0.0/0"],"allowed":[` + c.l4 + `]}`
		v := judgement{inst: inst, eff: vpcOnly(fw), port: c.port}.run(t)
		if got := classify(v); got != c.want {
			t.Errorf("%s on %s/%d: got %s, want %s (%v)", c.l4, c.port.Proto, c.port.Port, got, c.want, v.Evidence)
		}
	}
}

func TestDisabledAndEgressSkipped(t *testing.T) {
	inst := ipv4Only(loadInstance(t))
	off := `{"name":"off","disabled":true,"sourceRanges":["0.0.0.0/0"],"allowed":[{"IPProtocol":"tcp"}]}`
	egress := `{"name":"out","direction":"EGRESS","destinationRanges":["0.0.0.0/0"],"allowed":[{"IPProtocol":"tcp"}]}`
	expect(t, judgement{inst: inst, eff: vpcOnly(off, egress), port: tcp(443)}.run(t), isClosed)
	pol := `{"firewalls":[` + allowHTTPS + `],"firewallPolicys":[{"name":"org","type":"HIERARCHY","rules":[
	  {"priority":1,"action":"deny","direction":"INGRESS","disabled":true,"match":{"srcIpRanges":["0.0.0.0/0"],"layer4Configs":[{"ipProtocol":"all"}]}},
	  {"priority":2,"action":"deny","direction":"EGRESS","match":{"destIpRanges":["0.0.0.0/0"],"layer4Configs":[{"ipProtocol":"all"}]}}]}]}`
	expect(t, judgement{inst: inst, eff: pol, port: tcp(443)}.run(t), isOpen)
}

func hierarchy(rules string) string {
	return `{"name":"123456","shortName":"org-baseline","type":"HIERARCHY","rules":[` + rules + `]}`
}

func TestHierarchicalAllowOverridesVPCDeny(t *testing.T) {
	inst := ipv4Only(loadInstance(t))
	eff := `{"firewalls":[{"name":"deny-all","priority":0,"sourceRanges":["0.0.0.0/0"],"denied":[{"IPProtocol":"all"}]}],
	 "firewallPolicys":[` + hierarchy(`{"priority":100,"action":"allow","direction":"INGRESS","match":{"srcIpRanges":["0.0.0.0/0"],"layer4Configs":[{"ipProtocol":"tcp","ports":["443"]}]}}`) + `]}`
	expect(t, judgement{inst: inst, eff: eff, port: tcp(443)}.run(t), isOpen, "policy org-baseline rule 100 (hierarchy) allows tcp/443 from 0.0.0.0/0")
}

func TestHierarchicalDenyBeatsVPCAllow(t *testing.T) {
	inst := ipv4Only(loadInstance(t))
	eff := `{"firewalls":[` + allowHTTPS + `],"firewallPolicys":[` + hierarchy(`{"priority":100,"action":"deny","direction":"INGRESS","match":{"srcIpRanges":["0.0.0.0/0"],"layer4Configs":[{"ipProtocol":"all"}]}}`) + `]}`
	expect(t, judgement{inst: inst, eff: eff, port: tcp(443)}.run(t), isClosed, "policy org-baseline rule 100 (hierarchy)")
}

func TestGotoNextFallsThrough(t *testing.T) {
	inst := ipv4Only(loadInstance(t))
	// goto_next at 100 passes the traffic past the deny at 200 to the VPC rules.
	eff := `{"firewalls":[` + allowHTTPS + `],"firewallPolicys":[` + hierarchy(`
	  {"priority":100,"action":"goto_next","direction":"INGRESS","match":{"srcIpRanges":["0.0.0.0/0"],"layer4Configs":[{"ipProtocol":"tcp"}]}},
	  {"priority":200,"action":"deny","direction":"INGRESS","match":{"srcIpRanges":["0.0.0.0/0"],"layer4Configs":[{"ipProtocol":"all"}]}}`) + `]}`
	expect(t, judgement{inst: inst, eff: eff, port: tcp(443)}.run(t), isOpen, "firewall allow-https")
	// Without the VPC allow the goto_next ends at the implied deny.
	noVPC := strings.Replace(eff, allowHTTPS, "", 1)
	expect(t, judgement{inst: inst, eff: noVPC, port: tcp(443)}.run(t), isClosed, "implied deny")
}

func TestHierarchicalOrderUnknown(t *testing.T) {
	inst := ipv4Only(loadInstance(t))
	allow := `{"name":"1","shortName":"org","type":"HIERARCHY","rules":[{"priority":10,"action":"allow","direction":"INGRESS","match":{"srcIpRanges":["0.0.0.0/0"],"layer4Configs":[{"ipProtocol":"all"}]}}]}`
	deny := `{"name":"2","shortName":"folder","type":"HIERARCHY","rules":[{"priority":10,"action":"deny","direction":"INGRESS","match":{"srcIpRanges":["0.0.0.0/0"],"layer4Configs":[{"ipProtocol":"all"}]}}]}`
	allow2 := strings.Replace(strings.Replace(allow, `"1"`, `"3"`, 1), `"org"`, `"folder2"`, 1)
	expect(t, judgement{inst: inst, eff: `{"firewallPolicys":[` + allow + `,` + deny + `]}`, port: tcp(443)}.run(t), isUndetermined, "disagree")
	expect(t, judgement{inst: inst, eff: `{"firewallPolicys":[` + allow + `,` + allow2 + `]}`, port: tcp(443)}.run(t), isOpen)
}

func TestTooManyHierarchical(t *testing.T) {
	inst := ipv4Only(loadInstance(t))
	var pols []string
	for range maxHierarchical + 1 {
		pols = append(pols, hierarchy(`{"priority":10,"action":"goto_next","direction":"INGRESS","match":{"srcIpRanges":["0.0.0.0/0"],"layer4Configs":[{"ipProtocol":"all"}]}}`))
	}
	eff := `{"firewalls":[` + allowHTTPS + `],"firewallPolicys":[` + strings.Join(pols, ",") + `]}`
	expect(t, judgement{inst: inst, eff: eff, port: tcp(443)}.run(t), isUndetermined, "6 hierarchical firewall policies")
}

func network(kind string, prio int, action string) string {
	return `{"name":"net-` + strings.ToLower(kind) + `","type":"` + kind + `","priority":` + itoa(prio) + `,"rules":[
	  {"priority":10,"action":"` + action + `","direction":"INGRESS","match":{"srcIpRanges":["0.0.0.0/0"],"layer4Configs":[{"ipProtocol":"tcp","ports":["443"]}]}}]}`
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func TestEnforcementOrder(t *testing.T) {
	inst := ipv4Only(loadInstance(t))
	// VPC allow and a network policy allow: both orders agree.
	agree := `{"firewalls":[` + allowHTTPS + `],"firewallPolicys":[` + network("NETWORK", 1000, "allow") + `]}`
	expect(t, judgement{inst: inst, eff: agree, port: tcp(443)}.run(t), isOpen)
	// VPC allow vs network-policy deny: AFTER_CLASSIC_FIREWALL allows, BEFORE denies.
	disagree := `{"firewalls":[` + allowHTTPS + `],"firewallPolicys":[` + network("NETWORK", 1000, "deny") + `]}`
	expect(t, judgement{inst: inst, eff: disagree, port: tcp(443)}.run(t), isUndetermined, "disagree")
	// Both deny: closed.
	deny := `{"firewalls":[{"name":"d","sourceRanges":["0.0.0.0/0"],"denied":[{"IPProtocol":"all"}]}],"firewallPolicys":[` + network("NETWORK", 1000, "deny") + `]}`
	expect(t, judgement{inst: inst, eff: deny, port: tcp(443)}.run(t), isClosed)
}

func TestRegionalAfterGlobal(t *testing.T) {
	inst := ipv4Only(loadInstance(t))
	// Global network policy allows before the regional one denies (regional has the lower
	// association priority number, but the global step comes first).
	eff := `{"firewallPolicys":[` + network("NETWORK_REGIONAL", 1, "deny") + `,` + network("NETWORK", 1000, "allow") + `]}`
	expect(t, judgement{inst: inst, eff: eff, port: tcp(443)}.run(t), isOpen, "policy net-network rule 10 (network)")
	// goto_next in the global policy hands over to the regional one.
	eff = `{"firewallPolicys":[` + network("NETWORK_REGIONAL", 1, "allow") + `,` + network("NETWORK", 1000, "goto_next") + `]}`
	expect(t, judgement{inst: inst, eff: eff, port: tcp(443)}.run(t), isOpen, "net-network_regional")
}

func TestSystemPolicies(t *testing.T) {
	inst := ipv4Only(loadInstance(t))
	eff := `{"firewalls":[` + allowHTTPS + `],"firewallPolicys":[` + network("SYSTEM_REGIONAL", 1, "deny") + `]}`
	expect(t, judgement{inst: inst, eff: eff, port: tcp(443)}.run(t), isClosed, "(system_regional)")
}

func policyRule(match string, extra string) string {
	return `{"firewalls":[],"firewallPolicys":[{"name":"p","type":"NETWORK","priority":1000,"rules":[
	  {"priority":10,"action":"allow","direction":"INGRESS","match":` + match + extra + `}]}]}`
}

func TestUnresolvableSources(t *testing.T) {
	inst := ipv4Only(loadInstance(t))
	for name, m := range map[string]string{
		"FQDN sources":                `{"srcFqdns":["example.com"],"layer4Configs":[{"ipProtocol":"tcp"}]}`,
		"geolocation sources":         `{"srcRegionCodes":["US"],"layer4Configs":[{"ipProtocol":"tcp"}]}`,
		"threat-intelligence sources": `{"srcThreatIntelligences":["iplist-public-clouds"],"layer4Configs":[{"ipProtocol":"tcp"}]}`,
		"address-group sources":       `{"srcAddressGroups":["projects/acme-prod/locations/global/addressGroups/partners"],"layer4Configs":[{"ipProtocol":"tcp"}]}`,
	} {
		expect(t, judgement{inst: inst, eff: policyRule(m, ""), port: tcp(443)}.run(t), isUndetermined, name)
	}
	// Shadowed by an earlier sure deny: decided.
	eff := `{"firewallPolicys":[` + hierarchy(`{"priority":1,"action":"deny","direction":"INGRESS","match":{"srcIpRanges":["0.0.0.0/0"],"layer4Configs":[{"ipProtocol":"all"}]}}`) + `,
	  {"name":"p","type":"NETWORK","priority":1000,"rules":[{"priority":10,"action":"allow","direction":"INGRESS","match":{"srcFqdns":["example.com"],"layer4Configs":[{"ipProtocol":"tcp"}]}}]}]}`
	expect(t, judgement{inst: inst, eff: eff, port: tcp(443)}.run(t), isClosed)
	// An unresolvable deny before a sure allow: the allow may not be reached.
	eff = `{"firewalls":[` + allowHTTPS + `],"firewallPolicys":[` + hierarchy(`{"priority":1,"action":"deny","direction":"INGRESS","match":{"srcRegionCodes":["CN"],"layer4Configs":[{"ipProtocol":"all"}]}}`) + `]}`
	expect(t, judgement{inst: inst, eff: eff, port: tcp(443)}.run(t), isUndetermined, "geolocation sources")
}

func TestSrcNetworkType(t *testing.T) {
	inst := ipv4Only(loadInstance(t))
	expect(t, judgement{inst: inst, eff: policyRule(`{"srcNetworkType":"INTERNET","layer4Configs":[{"ipProtocol":"tcp"}]}`, ""), port: tcp(443)}.run(t), isOpen)
	expect(t, judgement{inst: inst, eff: policyRule(`{"srcNetworkType":"NON_INTERNET","srcIpRanges":["0.0.0.0/0"],"layer4Configs":[{"ipProtocol":"tcp"}]}`, ""), port: tcp(443)}.run(t), isClosed)
	expect(t, judgement{inst: inst, eff: policyRule(`{"srcNetworkType":"VPC_NETWORKS","srcNetworks":["projects/acme-prod/global/networks/default"],"layer4Configs":[{"ipProtocol":"tcp"}]}`, ""), port: tcp(443)}.run(t), isClosed)
	expect(t, judgement{inst: inst, eff: policyRule(`{"srcNetworkType":"SOMETHING_NEW","srcIpRanges":["0.0.0.0/0"],"layer4Configs":[{"ipProtocol":"tcp"}]}`, ""), port: tcp(443)}.run(t), isUndetermined, "not understood")
	expect(t, judgement{inst: inst, eff: policyRule(`{"srcSecureTags":[{"name":"tagValues/1","state":"EFFECTIVE"}],"layer4Configs":[{"ipProtocol":"tcp"}]}`, ""), port: tcp(443)}.run(t), isClosed)
}

func TestUnparseableRange(t *testing.T) {
	inst := ipv4Only(loadInstance(t))
	bad := `{"name":"bad","sourceRanges":["10.0.0.0/33"],"allowed":[{"IPProtocol":"tcp"}]}`
	expect(t, judgement{inst: inst, eff: vpcOnly(bad), port: tcp(443)}.run(t), isUndetermined, `"10.0.0.0/33" do not parse`)
	single := `{"name":"one","sourceRanges":["81.2.69.161"],"allowed":[{"IPProtocol":"tcp"}]}`
	expect(t, judgement{inst: inst, eff: vpcOnly(single), port: tcp(443)}.run(t), isOpen, "from 81.2.69.161/32")
}

func TestTargetSecureTags(t *testing.T) {
	inst := ipv4Only(loadInstance(t))
	tagged := policyRule(`{"srcIpRanges":["0.0.0.0/0"],"layer4Configs":[{"ipProtocol":"tcp"}]}`, `,"targetSecureTags":[{"name":"tagValues/99","state":"EFFECTIVE"}]`)
	expect(t, judgement{inst: inst, eff: tagged, port: tcp(443)}.run(t), isUndetermined, "secure tags")
	ineffective := strings.Replace(tagged, `"EFFECTIVE"`, `"INEFFECTIVE"`, 1)
	expect(t, judgement{inst: inst, eff: ineffective, port: tcp(443)}.run(t), isClosed)
	// Not decisive: an earlier sure allow already decided.
	eff := `{"firewallPolicys":[` + hierarchy(`{"priority":1,"action":"allow","direction":"INGRESS","match":{"srcIpRanges":["0.0.0.0/0"],"layer4Configs":[{"ipProtocol":"tcp"}]}}`) + `,
	  {"name":"p","type":"NETWORK","priority":1000,"rules":[{"priority":10,"action":"deny","direction":"INGRESS","match":{"srcIpRanges":["0.0.0.0/0"],"layer4Configs":[{"ipProtocol":"tcp"}]},"targetSecureTags":[{"name":"tagValues/99","state":"EFFECTIVE"}]}]}]}`
	expect(t, judgement{inst: inst, eff: eff, port: tcp(443)}.run(t), isOpen)
}

func TestTargetResourcesAndType(t *testing.T) {
	inst := nic0Only(ipv4Only(loadInstance(t)))
	other := policyRule(`{"srcIpRanges":["0.0.0.0/0"],"layer4Configs":[{"ipProtocol":"tcp"}]}`, `,"targetResources":["https://www.googleapis.com/compute/v1/projects/acme-prod/global/networks/backend"]`)
	expect(t, judgement{inst: inst, eff: other, port: tcp(443)}.run(t), isClosed)
	same := policyRule(`{"srcIpRanges":["0.0.0.0/0"],"layer4Configs":[{"ipProtocol":"tcp"}]}`, `,"targetResources":["projects/acme-prod/global/networks/default"]`)
	expect(t, judgement{inst: inst, eff: same, port: tcp(443)}.run(t), isOpen)
	lb := policyRule(`{"srcIpRanges":["0.0.0.0/0"],"layer4Configs":[{"ipProtocol":"tcp"}]}`, `,"targetType":"INTERNAL_MANAGED_LB"`)
	expect(t, judgement{inst: inst, eff: lb, port: tcp(443)}.run(t), isClosed)
}

// U1: a target network reference that does not parse cleanly (a numeric id, another
// format) may name the interface's network: undetermined, never a clean "not mine".
func TestTargetResourcesUnclear(t *testing.T) {
	inst := nic0Only(ipv4Only(loadInstance(t)))
	for _, ref := range []string{"1234567890123", "networks/default", "projects/acme-prod/regions/us-central1/networks/default"} {
		eff := policyRule(`{"srcIpRanges":["0.0.0.0/0"],"layer4Configs":[{"ipProtocol":"tcp"}]}`, `,"targetResources":["`+ref+`"]`)
		expect(t, judgement{inst: inst, eff: eff, port: tcp(443)}.run(t), isUndetermined, "cannot be matched cleanly")
	}
	// The interface's own network reference unclear: likewise.
	odd := inst
	odd.Interfaces = []Interface{inst.Interfaces[0]}
	odd.Interfaces[0].Network = "12345"
	eff := policyRule(`{"srcIpRanges":["0.0.0.0/0"],"layer4Configs":[{"ipProtocol":"tcp"}]}`, `,"targetResources":["projects/acme-prod/global/networks/backend"]`)
	expect(t, judgement{inst: odd, eff: eff, port: tcp(443)}.run(t), isUndetermined)
}
func TestSecurityProfileGroupAllows(t *testing.T) {
	inst := ipv4Only(loadInstance(t))
	eff := strings.Replace(policyRule(`{"srcIpRanges":["0.0.0.0/0"],"layer4Configs":[{"ipProtocol":"tcp"}]}`, `,"securityProfileGroup":"//networksecurity.googleapis.com/organizations/1/locations/global/securityProfileGroups/ips"`),
		`"action":"allow"`, `"action":"apply_security_profile_group"`, 1)
	expect(t, judgement{inst: inst, eff: eff, port: tcp(443)}.run(t), isOpen)
}

func TestUnknownActionUndetermined(t *testing.T) {
	inst := ipv4Only(loadInstance(t))
	eff := strings.Replace(policyRule(`{"srcIpRanges":["0.0.0.0/0"],"layer4Configs":[{"ipProtocol":"tcp"}]}`, ""), `"action":"allow"`, `"action":"quarantine"`, 1)
	expect(t, judgement{inst: inst, eff: eff, port: tcp(443)}.run(t), isUndetermined, `"quarantine"`)
}

func TestUnknownPolicyType(t *testing.T) {
	inst := ipv4Only(loadInstance(t))
	eff := `{"firewalls":[` + allowHTTPS + `],"firewallPolicys":[` + network("SOMETHING_NEW", 1, "deny") + `]}`
	expect(t, judgement{inst: inst, eff: eff, port: tcp(443)}.run(t), isUndetermined, "not understood")
}

func TestPriorityTieInPolicy(t *testing.T) {
	inst := ipv4Only(loadInstance(t))
	eff := `{"firewallPolicys":[{"name":"p","type":"NETWORK","priority":1000,"rules":[
	  {"priority":10,"action":"allow","direction":"INGRESS","match":{"srcIpRanges":["0.0.0.0/0"],"layer4Configs":[{"ipProtocol":"tcp"}]}},
	  {"priority":10,"action":"deny","direction":"INGRESS","match":{"srcIpRanges":["0.0.0.0/0"],"layer4Configs":[{"ipProtocol":"tcp"}]}}]}]}`
	expect(t, judgement{inst: inst, eff: eff, port: tcp(443)}.run(t), isUndetermined, "equal priority 10")
}

func TestAgentLevelGate(t *testing.T) {
	inst := nic0Only(ipv4Only(loadInstance(t)))
	p := tcp(443)
	p.AgentLevel = cloud.LevelBound
	// Below host_firewall_open the direct path does not count, but the host firewall may
	// admit a load balancer's traffic: undetermined, not closed.
	v := judgement{inst: inst, eff: vpcOnly(allowHTTPS), port: p}.run(t)
	expect(t, v, isUndetermined, "direct path not counted", "load balancer or forwarding rule")
	// A firewall that blocks stays closed at any level.
	expect(t, judgement{inst: inst, eff: vpcOnly(), port: p}.run(t), isClosed)
}
func nic1Only(inst Instance) Instance {
	inst.Interfaces = []Interface{inst.Interfaces[1]} // no external address
	return inst
}

func nic0Only(inst Instance) Instance {
	inst.Interfaces = []Interface{inst.Interfaces[0]}
	return inst
}

// B1: an interface without an external address is still judged: a passthrough network
// load balancer or a forwarding rule can bring internet traffic (any source) to it.
func TestNoExternalAddressNLBBackend(t *testing.T) {
	inst := nic1Only(loadInstance(t))
	v := judgement{inst: inst, eff: vpcOnly(allowHTTPS), port: tcp(443)}.run(t)
	expect(t, v, isUndetermined, "nic1 (no external IPv4 address)", "only reachable via a load balancer or forwarding rule, not read")
}

// B1: a proxy load balancer's front ends (GFE, 35.191.0.0/16 and 130.211.0.0/22) are
// public under the reach rule: an allow from them alone is undetermined, not closed.
func TestNoExternalAddressGFEAllow(t *testing.T) {
	inst := nic1Only(loadInstance(t))
	gfe := `{"name":"allow-gfe","sourceRanges":["35.191.0.0/16","130.211.0.0/22"],"allowed":[{"IPProtocol":"tcp","ports":["443"]}]}`
	v := judgement{inst: inst, eff: vpcOnly(gfe), port: tcp(443)}.run(t)
	expect(t, v, isUndetermined, "only reachable via a load balancer")
}

// B1: complete closed is kept where the firewall itself blocks.
func TestNoExternalAddressFirewallDenies(t *testing.T) {
	inst := nic1Only(loadInstance(t))
	deny := `{"name":"deny-all","priority":0,"sourceRanges":["0.0.0.0/0"],"denied":[{"IPProtocol":"all"}]}`
	expect(t, judgement{inst: inst, eff: vpcOnly(deny, allowHTTPS), port: tcp(443)}.run(t), isClosed, "firewall deny-all")
	expect(t, judgement{inst: inst, eff: vpcOnly(), port: tcp(443)}.run(t), isClosed, "implied deny")
}

func TestNoExternalAddressNotRead(t *testing.T) {
	v := Evaluate(HostData{Instance: nic1Only(loadInstance(t))}, []cloud.Port{tcp(443)})[0]
	expect(t, v, isUndetermined, "getEffectiveFirewalls not read")
}

// U2: an instance without network interfaces, and U3: more than 8, are undetermined.
func TestInterfaceCount(t *testing.T) {
	inst := loadInstance(t)
	none := inst
	none.Interfaces = nil
	expect(t, Evaluate(HostData{Instance: none, HierarchyConfirmed: true}, []cloud.Port{tcp(443)})[0], isUndetermined, "no network interfaces")
	many := inst
	many.Interfaces = nil
	for i := range 9 {
		nic := inst.Interfaces[1]
		nic.Name = "nic" + itoa(i)
		many.Interfaces = append(many.Interfaces, nic)
	}
	expect(t, Evaluate(HostData{Instance: many, HierarchyConfirmed: true}, []cloud.Port{tcp(443)})[0], isUndetermined, "9 network interfaces (more than 8)")
}

// U4: Google does not document whether getEffectiveFirewalls leaves out hierarchical
// policies the caller cannot read. Without cloud.gcp.hierarchy_confirmed, a closed
// interface whose response holds none is undetermined; with one present, or confirmed,
// it stays closed. Open is never affected.
func TestHierarchyUnconfirmed(t *testing.T) {
	inst := nic0Only(ipv4Only(loadInstance(t)))
	expect(t, judgement{inst: inst, eff: vpcOnly(), port: tcp(443), unconfirmed: true}.run(t), isUndetermined, "no hierarchical firewall policy was returned")
	expect(t, judgement{inst: inst, eff: vpcOnly(allowHTTPS), port: tcp(443), unconfirmed: true}.run(t), isOpen)
	withHier := `{"firewalls":[],"firewallPolicys":[` + hierarchy(`{"priority":100,"action":"goto_next","direction":"INGRESS","match":{"srcIpRanges":["0.0.0.0/0"],"layer4Configs":[{"ipProtocol":"all"}]}}`) + `]}`
	expect(t, judgement{inst: inst, eff: withHier, port: tcp(443), unconfirmed: true}.run(t), isClosed)
	expect(t, judgement{inst: inst, eff: vpcOnly(), port: tcp(443)}.run(t), isClosed)
}
func TestBindToOtherInterface(t *testing.T) {
	inst := ipv4Only(loadInstance(t))
	p := tcp(443)
	p.Addr = "10.8.0.5" // nic1's internal address; nic1 has no external address
	expect(t, judgement{inst: inst, eff: vpcOnly(allowHTTPS), port: p}.run(t), isUndetermined, "nic1 (no external IPv4 address)")
	expect(t, judgement{inst: inst, eff: vpcOnly(), port: p}.run(t), isClosed)
	p.Addr = "10.128.0.5" // nic0's
	expect(t, judgement{inst: inst, eff: vpcOnly(allowHTTPS), port: p}.run(t), isOpen)
}
func TestMultiNIC(t *testing.T) {
	inst := ipv4Only(loadInstance(t))
	inst.Interfaces[1].AccessConfigs = []AccessConfig{{Type: "ONE_TO_ONE_NAT", NatIP: "34.68.10.21"}}
	d := HostData{Instance: inst, Policy: reach.NewPolicy(nil), HierarchyConfirmed: true, Effective: map[string]Effective{
		"nic0": parseEffective(t, vpcOnly()),
		"nic1": parseEffective(t, vpcOnly(allowHTTPS)),
	}}
	expect(t, Evaluate(d, []cloud.Port{tcp(443)})[0], isOpen, "nic1 (34.68.10.21)")
}

func TestEffectiveFirewallsFailedInterface(t *testing.T) {
	inst := ipv4Only(loadInstance(t))
	d := HostData{Instance: inst, Policy: reach.NewPolicy(nil), EffectiveErr: map[string]string{"nic0": "403 Forbidden"}}
	expect(t, Evaluate(d, []cloud.Port{tcp(443)})[0], isUndetermined, "getEffectiveFirewalls failed: 403 Forbidden")
	// Another interface open still makes the listener open.
	inst.Interfaces[1].AccessConfigs = []AccessConfig{{NatIP: "34.68.10.21"}}
	d.Instance = inst
	d.Effective = map[string]Effective{"nic1": parseEffective(t, vpcOnly(allowHTTPS))}
	expect(t, Evaluate(d, []cloud.Port{tcp(443)})[0], isOpen)
}

// Assumption (design): a VPC rule never carries both allowed and denied. If one does,
// its denied protocols deny and the others allow.
func TestAssumptionVPCRuleBothAllowedAndDenied(t *testing.T) {
	inst := ipv4Only(loadInstance(t))
	both := `{"name":"both","sourceRanges":["0.0.0.0/0"],"allowed":[{"IPProtocol":"tcp","ports":["443"]}],"denied":[{"IPProtocol":"tcp","ports":["22"]}]}`
	expect(t, judgement{inst: inst, eff: vpcOnly(both), port: tcp(443)}.run(t), isOpen)
	expect(t, judgement{inst: inst, eff: vpcOnly(both), port: tcp(22)}.run(t), isClosed, "firewall both")
}

// Assumption (design): getEffectiveFirewalls may return rules whose targets do not
// include the instance, so targets are matched here (harmless if Google already filters).
func TestAssumptionTargetsNotPrefiltered(t *testing.T) {
	inst := ipv4Only(loadInstance(t))
	notMine := `{"name":"db-only","sourceRanges":["0.0.0.0/0"],"targetTags":["db"],"allowed":[{"IPProtocol":"tcp"}]}`
	expect(t, judgement{inst: inst, eff: vpcOnly(notMine), port: tcp(443)}.run(t), isClosed)
}

// Assumption (design): the array order of hierarchical policies is not relied on: the
// same policies in either order give the same verdict.
func TestAssumptionHierarchicalArrayOrderIgnored(t *testing.T) {
	inst := ipv4Only(loadInstance(t))
	a := `{"name":"1","type":"HIERARCHY","rules":[{"priority":10,"action":"deny","direction":"INGRESS","match":{"srcIpRanges":["0.0.0.0/0"],"layer4Configs":[{"ipProtocol":"all"}]}}]}`
	b := `{"name":"2","type":"HIERARCHY","rules":[{"priority":10,"action":"allow","direction":"INGRESS","match":{"srcIpRanges":["0.0.0.0/0"],"layer4Configs":[{"ipProtocol":"all"}]}}]}`
	eff := func(x, y string) string {
		return `{"firewalls":[` + allowHTTPS + `],"firewallPolicys":[` + x + `,` + y + `]}`
	}
	v1 := judgement{inst: inst, eff: eff(a, b), port: tcp(443)}.run(t)
	v2 := judgement{inst: inst, eff: eff(b, a), port: tcp(443)}.run(t)
	if classify(v1) != classify(v2) || classify(v1) != isUndetermined {
		t.Fatalf("orders differ or are decided: %s %v / %s %v", classify(v1), v1.Evidence, classify(v2), v2.Evidence)
	}
}
