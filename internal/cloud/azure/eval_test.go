package azure

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/thapr0digy/portwarden/internal/cloud"
	"github.com/thapr0digy/portwarden/internal/cloud/reach"
)

// The fixtures are handwritten ARM responses in the shapes of the REST reference
// (learn.microsoft.com/rest/api/virtualnetwork network-security-groups/get,
// network-interfaces/get, public-ip-addresses/get, subnets/get; compute
// virtual-machines/get; read 2026-11-06), decoded with encoding/json like the client's.

const (
	sub    = "0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0"
	vmID   = "6f1d2c3b-4a59-4e8f-9d7c-1b2a3c4d5e6f"
	rgPath = "/subscriptions/" + sub + "/resourceGroups/web-rg/providers/"
	nicID  = rgPath + "Microsoft.Network/networkInterfaces/web-nic"
	pipID  = rgPath + "Microsoft.Network/publicIPAddresses/web-ip"
	subID  = rgPath + "Microsoft.Network/virtualNetworks/vnet1/subnets/web"
	snsgID = rgPath + "Microsoft.Network/networkSecurityGroups/subnet-nsg"
	nnsgID = rgPath + "Microsoft.Network/networkSecurityGroups/nic-nsg"
	asgWeb = rgPath + "Microsoft.Network/applicationSecurityGroups/web-asg"
	asgDB  = rgPath + "Microsoft.Network/applicationSecurityGroups/db-asg"
)

func decode[T any](t *testing.T, s string) T {
	t.Helper()
	var v T
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("fixture does not decode: %v\n%s", err, s)
	}
	return v
}

// r is a handwritten inbound security rule: extra is more JSON properties (sources,
// destinations) after the common ones.
func r(name string, prio int, access, proto, port, extra string) string {
	if !strings.Contains(extra, `"sourceAddressPrefix`) && !strings.Contains(extra, "sourceApplicationSecurityGroups") {
		extra += `,"sourceAddressPrefix":"*"`
	}
	if !strings.Contains(extra, `"destinationAddressPrefix`) && !strings.Contains(extra, "destinationApplicationSecurityGroups") {
		extra += `,"destinationAddressPrefix":"*"`
	}
	return fmt.Sprintf(`{"name":%q,"id":"%s/securityRules/%s","properties":{"protocol":%q,"sourcePortRange":"*","destinationPortRange":%q,"access":%q,"priority":%d,"direction":"Inbound"%s}}`,
		name, snsgID, name, proto, port, access, prio, extra)
}

// defaults are the default inbound and outbound rules every NSG GET returns.
const defaults = `[
 {"name":"AllowVnetInBound","properties":{"protocol":"*","sourcePortRange":"*","destinationPortRange":"*","sourceAddressPrefix":"VirtualNetwork","destinationAddressPrefix":"VirtualNetwork","access":"Allow","priority":65000,"direction":"Inbound"}},
 {"name":"AllowAzureLoadBalancerInBound","properties":{"protocol":"*","sourcePortRange":"*","destinationPortRange":"*","sourceAddressPrefix":"AzureLoadBalancer","destinationAddressPrefix":"*","access":"Allow","priority":65001,"direction":"Inbound"}},
 {"name":"DenyAllInBound","properties":{"protocol":"*","sourcePortRange":"*","destinationPortRange":"*","sourceAddressPrefix":"*","destinationAddressPrefix":"*","access":"Deny","priority":65500,"direction":"Inbound"}},
 {"name":"AllowInternetOutBound","properties":{"protocol":"*","sourcePortRange":"*","destinationPortRange":"*","sourceAddressPrefix":"*","destinationAddressPrefix":"Internet","access":"Allow","priority":65001,"direction":"Outbound"}}
]`

func nsgJSON(id, name string, rules []string) string {
	return fmt.Sprintf(`{"id":%q,"name":%q,"properties":{"securityRules":[%s],"defaultSecurityRules":%s}}`, id, name, strings.Join(rules, ","), defaults)
}

// world is one VM with one NIC and IP configuration (10.0.1.4, public 20.1.2.3 Standard).
type world struct {
	subnetRules, nicRules []string // nil: no NSG on that layer
	ipconfigExtra         string   // more ipConfiguration properties
	publicIP              string   // "" none; else the public IP's JSON
	private, version      string
	tags                  TagSet
	tagsErr               string
	errs                  map[string]string
	policy                reach.Policy
}

const standardIP = `{"id":"` + pipID + `","name":"web-ip","sku":{"name":"Standard"},"properties":{"ipAddress":"20.1.2.3","publicIPAddressVersion":"IPv4"}}`

func defaultWorld() world {
	return world{subnetRules: []string{}, nicRules: []string{}, publicIP: standardIP, private: "10.0.1.4", version: "IPv4"}
}

func (w world) data(t *testing.T) HostData {
	t.Helper()
	d := HostData{PublicIPs: map[string]PublicIP{}, Subnets: map[string]Subnet{}, NSGs: map[string]NSG{}, Errs: map[string]string{},
		Policy: w.policy, Tags: w.tags, TagsErr: w.tagsErr, Location: "westeurope"}
	d.VM = decode[VM](t, `{"id":"`+rgPath+`Microsoft.Compute/virtualMachines/web1","name":"web1","location":"westeurope","properties":{"vmId":"`+vmID+`","networkProfile":{"networkInterfaces":[{"id":"`+nicID+`"}]}}}`)
	nicNSG := ""
	if w.nicRules != nil {
		nicNSG = `"networkSecurityGroup":{"id":"` + nnsgID + `"},`
		d.NSGs[key(nnsgID)] = decode[NSG](t, nsgJSON(nnsgID, "nic-nsg", w.nicRules))
	}
	pub := ""
	if w.publicIP != "" {
		pub = `"publicIPAddress":{"id":"` + pipID + `"},`
		d.PublicIPs[key(pipID)] = decode[PublicIP](t, w.publicIP)
	}
	nic := decode[NIC](t, `{"id":"`+nicID+`","name":"web-nic","properties":{`+nicNSG+`"ipConfigurations":[{"id":"`+nicID+`/ipConfigurations/ipconfig1","name":"ipconfig1","properties":{`+
		pub+`"privateIPAddress":"`+w.private+`","privateIPAddressVersion":"`+w.version+`","subnet":{"id":"`+subID+`"}`+w.ipconfigExtra+`}}]}}`)
	d.NICs = []NICData{{ID: nicID, NIC: &nic}}
	subNSG := ""
	if w.subnetRules != nil {
		subNSG = `"networkSecurityGroup":{"id":"` + snsgID + `"}`
		d.NSGs[key(snsgID)] = decode[NSG](t, nsgJSON(snsgID, "subnet-nsg", w.subnetRules))
	}
	d.Subnets[key(subID)] = decode[Subnet](t, `{"id":"`+subID+`","name":"web","properties":{`+subNSG+`}}`)
	for k, v := range w.errs {
		d.Errs[key(k)] = v
		delete(d.NSGs, key(k))
		delete(d.Subnets, key(k))
		delete(d.PublicIPs, key(k))
	}
	return d
}

var ssh = cloud.Port{Key: "tcp/0.0.0.0:22", Proto: "tcp", Addr: "0.0.0.0", Port: 22, AgentLevel: cloud.LevelHostFirewallOpen}

type want int

const (
	wantOpen want = iota
	wantClosed
	wantUndetermined
)

func (w want) String() string { return [...]string{"open", "closed", "undetermined"}[w] }

func check(t *testing.T, d HostData, p cloud.Port, w want, evidence ...string) cloud.Verdict {
	t.Helper()
	v := Evaluate(d, []cloud.Port{p})[0]
	got := wantClosed
	switch {
	case v.Open:
		got = wantOpen
	case !v.Complete:
		got = wantUndetermined
	}
	if got != w || (v.Open && !v.Complete) {
		t.Fatalf("verdict %s (open %v complete %v), want %s; evidence:\n%s", got, v.Open, v.Complete, w, strings.Join(v.Evidence, "\n"))
	}
	if w == wantUndetermined && !strings.Contains(strings.Join(v.Evidence, "\n"), cloud.UndeterminedEvidence) {
		t.Fatalf("undetermined verdict without %s evidence: %v", cloud.UndeterminedEvidence, v.Evidence)
	}
	all := strings.Join(v.Evidence, "\n")
	for _, e := range evidence {
		if !strings.Contains(all, e) {
			t.Fatalf("evidence lacks %q:\n%s", e, all)
		}
	}
	return v
}

func allowSSH(name string, prio int, src string) string {
	return r(name, prio, "Allow", "Tcp", "22", `,"sourceAddressPrefix":"`+src+`"`)
}

func TestBothLayersAllowOpen(t *testing.T) {
	w := defaultWorld()
	w.subnetRules = []string{allowSSH("ssh", 300, "*")}
	w.nicRules = []string{allowSSH("ssh-nic", 310, "Internet")}
	check(t, w.data(t), ssh, wantOpen,
		"cloud: web-nic/ipconfig1 (20.1.2.3): subnet NSG subnet-nsg rule ssh (priority 300) allows tcp/22 from 0.0.0.0/0",
		"NIC NSG nic-nsg rule ssh-nic (priority 310) allows tcp/22 from 0.0.0.0/0",
		"cloud: web-nic/ipconfig1 (20.1.2.3) reachable from 0.0.0.0/0")
}

func TestBothLayersMustAllow(t *testing.T) {
	t.Run("subnet allows, NIC default deny", func(t *testing.T) {
		w := defaultWorld()
		w.subnetRules = []string{allowSSH("ssh", 300, "*")}
		check(t, w.data(t), ssh, wantClosed, "denied by NIC NSG nic-nsg rule DenyAllInBound (priority 65500)")
	})
	t.Run("NIC allows, subnet denies", func(t *testing.T) {
		w := defaultWorld()
		w.subnetRules = []string{r("no-ssh", 200, "Deny", "Tcp", "22", "")}
		w.nicRules = []string{allowSSH("ssh", 300, "*")}
		check(t, w.data(t), ssh, wantClosed, "subnet NSG subnet-nsg rule no-ssh (priority 200)")
	})
	t.Run("ranges intersect across layers", func(t *testing.T) {
		w := defaultWorld()
		w.subnetRules = []string{allowSSH("a", 300, "81.2.69.0/24")}
		w.nicRules = []string{allowSSH("b", 300, "81.2.69.160/28")}
		check(t, w.data(t), ssh, wantOpen, "reachable from 81.2.69.160/28")
	})
	t.Run("disjoint ranges", func(t *testing.T) {
		w := defaultWorld()
		w.subnetRules = []string{allowSSH("a", 300, "81.2.69.0/24")}
		w.nicRules = []string{allowSSH("b", 300, "81.2.70.0/24")}
		check(t, w.data(t), ssh, wantClosed)
	})
}

func TestPriorityOrder(t *testing.T) {
	w := defaultWorld()
	w.subnetRules = nil
	w.nicRules = []string{allowSSH("late-allow", 400, "*"), r("early-deny", 100, "Deny", "*", "*", "")}
	check(t, w.data(t), ssh, wantClosed, "early-deny (priority 100)")
	w.nicRules = []string{allowSSH("early-allow", 100, "*"), r("late-deny", 400, "Deny", "*", "*", "")}
	check(t, w.data(t), ssh, wantOpen, "early-allow")
	// A narrow deny before an allow-all leaves the rest open.
	w.nicRules = []string{r("deny-one", 100, "Deny", "Tcp", "22", `,"sourceAddressPrefix":"81.2.69.0/24"`), allowSSH("all", 200, "*")}
	v := check(t, w.data(t), ssh, wantOpen)
	if strings.Contains(strings.Join(v.Evidence, "\n"), "reachable from 0.0.0.0/0\n") {
		t.Fatalf("the denied range should be carved out: %v", v.Evidence)
	}
}

func TestDefaultRules(t *testing.T) {
	w := defaultWorld()
	check(t, w.data(t), ssh, wantClosed, "DenyAllInBound (priority 65500)")
}

func TestFallbackDenyWithoutDefaults(t *testing.T) {
	w := defaultWorld()
	w.subnetRules = nil
	d := w.data(t)
	n := d.NSGs[key(nnsgID)]
	n.Properties.DefaultSecurityRules = nil // A4: if they were left out, nothing opens by it
	d.NSGs[key(nnsgID)] = n
	check(t, d, ssh, wantClosed, "no rule matched (deny)")
}

func TestNoNSGLayer(t *testing.T) {
	t.Run("only subnet NSG", func(t *testing.T) {
		w := defaultWorld()
		w.nicRules = nil
		w.subnetRules = []string{allowSSH("ssh", 300, "*")}
		check(t, w.data(t), ssh, wantOpen, "no NSG on the NIC", "subnet NSG subnet-nsg rule ssh")
	})
	t.Run("only NIC NSG", func(t *testing.T) {
		w := defaultWorld()
		w.subnetRules = nil
		w.nicRules = []string{allowSSH("ssh", 300, "*")}
		check(t, w.data(t), ssh, wantOpen, "no NSG on the subnet")
		w.nicRules = []string{}
		check(t, w.data(t), ssh, wantClosed)
	})
}

// A2 (docs "Public IP addresses", SKU table): a Standard public IP is closed to inbound
// traffic unless an NSG allows it; a Basic one is open by default.
func TestAssumptionA2NoNSGAtAll(t *testing.T) {
	w := defaultWorld()
	w.subnetRules, w.nicRules = nil, nil
	check(t, w.data(t), ssh, wantClosed, "Standard public IP with no NSG on the subnet or NIC")
	w.publicIP = strings.Replace(standardIP, "Standard", "Basic", 1)
	check(t, w.data(t), ssh, wantOpen, "Basic public IP with no NSG", "reachable from 0.0.0.0/0")
	w.publicIP = strings.Replace(standardIP, `"sku":{"name":"Standard"},`, "", 1)
	check(t, w.data(t), ssh, wantUndetermined, "SKU")
}

// A1 (docs "Network security groups", "process traffic after Azure translates public IP
// addresses to private IP addresses"): a rule whose destination is the public IP does not
// match; one naming the private IP does.
func TestAssumptionA1DestinationIsPrivateIP(t *testing.T) {
	w := defaultWorld()
	w.subnetRules = nil
	w.nicRules = []string{allowSSH("to-public", 100, "*")}
	w.nicRules[0] = strings.Replace(w.nicRules[0], `"destinationAddressPrefix":"*"`, `"destinationAddressPrefix":"20.1.2.3"`, 1)
	check(t, w.data(t), ssh, wantClosed)
	w.nicRules[0] = strings.Replace(w.nicRules[0], `"20.1.2.3"`, `"10.0.1.4/32"`, 1)
	check(t, w.data(t), ssh, wantOpen)
}

func TestDestinationPrefix(t *testing.T) {
	cases := []struct {
		dest string
		want want
	}{
		{`"destinationAddressPrefix":"*"`, wantOpen},
		{`"destinationAddressPrefix":"VirtualNetwork"`, wantOpen},
		{`"destinationAddressPrefix":"10.0.1.0/24"`, wantOpen},
		{`"destinationAddressPrefixes":["10.9.0.0/16","10.0.1.4"]`, wantOpen},
		{`"destinationAddressPrefix":"10.0.2.0/24"`, wantClosed},
		{`"destinationAddressPrefix":"Internet"`, wantClosed},
		{`"destinationAddressPrefix":"AzureCloud"`, wantUndetermined},
		{`"destinationAddressPrefix":"10.0.1.0/99"`, wantUndetermined},
	}
	for _, c := range cases {
		t.Run(c.dest, func(t *testing.T) {
			w := defaultWorld()
			w.subnetRules = nil
			w.nicRules = []string{r("ssh", 100, "Allow", "Tcp", "22", ","+c.dest)}
			check(t, w.data(t), ssh, c.want)
		})
	}
}

func TestDestinationASG(t *testing.T) {
	w := defaultWorld()
	w.subnetRules = nil
	w.ipconfigExtra = `,"applicationSecurityGroups":[{"id":"` + strings.ToUpper(asgWeb) + `"}]`
	w.nicRules = []string{r("web", 100, "Allow", "Tcp", "22", `,"destinationApplicationSecurityGroups":[{"id":"`+asgWeb+`"}]`)}
	check(t, w.data(t), ssh, wantOpen, "rule web")
	w.nicRules = []string{r("db", 100, "Allow", "Tcp", "22", `,"destinationApplicationSecurityGroups":[{"id":"`+asgDB+`"}]`)}
	check(t, w.data(t), ssh, wantClosed)
	// A deny for the VM's group before an allow-all.
	w.nicRules = []string{r("deny-web", 100, "Deny", "*", "*", `,"destinationApplicationSecurityGroups":[{"id":"`+asgWeb+`"}]`), allowSSH("all", 200, "*")}
	check(t, w.data(t), ssh, wantClosed, "deny-web")
}

func TestSourceTags(t *testing.T) {
	tags := TagSet{"azurecloud": {"20.0.0.0/8", "2603:1000::/24"}, "azurecloud.westeurope": {"20.50.0.0/16"}, "broken": {"20.1.0.0/40"}}
	cases := []struct {
		name, src string
		tags      TagSet
		tagsErr   string
		want      want
		evidence  string
	}{
		{"star", "*", nil, "", wantOpen, "from 0.0.0.0/0"},
		{"Any", "Any", nil, "", wantOpen, "from 0.0.0.0/0"},
		{"Internet", "Internet", nil, "", wantOpen, "from 0.0.0.0/0"},
		{"VirtualNetwork", "VirtualNetwork", nil, "", wantClosed, ""},
		{"AzureLoadBalancer", "AzureLoadBalancer", nil, "", wantClosed, ""},
		{"listed tag", "AzureCloud", tags, "", wantOpen, "(service tag AzureCloud) allows tcp/22 from 20.0.0.0/8"},
		{"regional tag, any case", "azurecloud.WestEurope", tags, "", wantOpen, "from 20.50.0.0/16"},
		{"tag not listed", "AzureFrontDoor.Backend", tags, "", wantUndetermined, "names service tag AzureFrontDoor.Backend, not in the westeurope list"},
		{"list not read", "AzureCloud", nil, "403 Forbidden: AuthorizationFailed", wantUndetermined, "service tags not read: 403 Forbidden"},
		{"tag entry does not parse", "Broken", tags, "", wantUndetermined, "does not parse"},
		{"source does not parse", "10.0.0.0/33", nil, "", wantUndetermined, `source "10.0.0.0/33" does not parse`},
		{"private range", "10.0.0.0/8", nil, "", wantClosed, ""},
		{"office IP", "81.2.69.160", nil, "", wantOpen, "from 81.2.69.160/32"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := defaultWorld()
			w.subnetRules = nil
			w.tags, w.tagsErr = c.tags, c.tagsErr
			w.nicRules = []string{allowSSH("ssh", 100, c.src)}
			check(t, w.data(t), ssh, c.want, c.evidence)
		})
	}
	t.Run("unlisted tag shadowed by an earlier sure deny", func(t *testing.T) {
		w := defaultWorld()
		w.subnetRules = nil
		w.tags = tags
		w.nicRules = []string{r("deny", 100, "Deny", "Tcp", "22", ""), allowSSH("tag", 200, "Unknown.Tag")}
		check(t, w.data(t), ssh, wantClosed)
	})
	t.Run("unlisted tag behind a sure allow", func(t *testing.T) {
		w := defaultWorld()
		w.subnetRules = nil
		w.tags = tags
		w.nicRules = []string{allowSSH("all", 100, "*"), r("tag-deny", 200, "Deny", "Tcp", "22", `,"sourceAddressPrefix":"Unknown.Tag"`)}
		check(t, w.data(t), ssh, wantOpen)
	})
	t.Run("source application security groups are never internet", func(t *testing.T) {
		w := defaultWorld()
		w.subnetRules = nil
		w.nicRules = []string{r("from-asg", 100, "Allow", "Tcp", "22", `,"sourceApplicationSecurityGroups":[{"id":"`+asgWeb+`"}]`)}
		check(t, w.data(t), ssh, wantClosed)
	})
	t.Run("augmented sources", func(t *testing.T) {
		w := defaultWorld()
		w.subnetRules = nil
		w.nicRules = []string{r("multi", 100, "Allow", "Tcp", "22", `,"sourceAddressPrefixes":["10.0.0.0/8","81.2.69.160/28"]`)}
		check(t, w.data(t), ssh, wantOpen, "from 81.2.69.160/28")
	})
}

func TestReachRule(t *testing.T) {
	vpn := reach.NewPolicy([]netip.Prefix{netip.MustParsePrefix("81.2.69.160/28")})
	w := defaultWorld()
	w.subnetRules = nil
	w.policy = vpn
	w.nicRules = []string{allowSSH("vpn", 100, "81.2.69.160/28")}
	check(t, w.data(t), ssh, wantClosed)
	w.nicRules = []string{allowSSH("all", 100, "*")}
	check(t, w.data(t), ssh, wantOpen, "0.0.0.0/0 except vpn_cidrs 81.2.69.160/28")
}

func TestProtocolsAndPorts(t *testing.T) {
	udp := cloud.Port{Key: "udp/0.0.0.0:53", Proto: "udp", Addr: "0.0.0.0", Port: 53, AgentLevel: cloud.LevelHostFirewallOpen}
	cases := []struct {
		name string
		rule string
		port cloud.Port
		want want
	}{
		{"any protocol", r("x", 100, "Allow", "*", "22", ""), ssh, wantOpen},
		{"tcp lowercase", r("x", 100, "Allow", "tcp", "22", ""), ssh, wantOpen},
		{"udp rule, tcp port", r("x", 100, "Allow", "Udp", "22", ""), ssh, wantClosed},
		{"udp rule, udp port", r("x", 100, "Allow", "Udp", "53", ""), udp, wantOpen},
		{"icmp ignored", r("x", 100, "Allow", "Icmp", "*", ""), ssh, wantClosed},
		{"esp ignored", r("x", 100, "Allow", "Esp", "*", ""), ssh, wantClosed},
		{"unknown protocol", r("x", 100, "Allow", "Sctp", "22", ""), ssh, wantUndetermined},
		{"port range", r("x", 100, "Allow", "Tcp", "20-30", ""), ssh, wantOpen},
		{"port range miss", r("x", 100, "Allow", "Tcp", "23-30", ""), ssh, wantClosed},
		{"port list", strings.Replace(r("x", 100, "Allow", "Tcp", "", `,"destinationPortRanges":["80","443","22"]`), `"destinationPortRange":"",`, "", 1), ssh, wantOpen},
		{"port does not parse", r("x", 100, "Allow", "Tcp", "ssh", ""), ssh, wantUndetermined},
		{"source ports restricted", strings.Replace(r("x", 100, "Allow", "Tcp", "22", ""), `"sourcePortRange":"*"`, `"sourcePortRange":"1024-2048"`, 1), ssh, wantUndetermined},
		{"source ports cover clients", strings.Replace(r("x", 100, "Allow", "Tcp", "22", ""), `"sourcePortRange":"*"`, `"sourcePortRanges":["1024-40000","40001-65535"]`, 1), ssh, wantOpen},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := defaultWorld()
			w.subnetRules = nil
			w.nicRules = []string{c.rule}
			check(t, w.data(t), c.port, c.want)
		})
	}
}

func TestOutboundIgnored(t *testing.T) {
	w := defaultWorld()
	w.subnetRules = nil
	w.nicRules = []string{strings.Replace(allowSSH("out", 100, "*"), `"Inbound"`, `"Outbound"`, 1)}
	check(t, w.data(t), ssh, wantClosed)
}

func TestPriorityTie(t *testing.T) {
	w := defaultWorld()
	w.subnetRules = nil
	w.nicRules = []string{allowSSH("a", 100, "*"), r("b", 100, "Deny", "Tcp", "22", "")}
	check(t, w.data(t), ssh, wantUndetermined, "same priority")
}

func TestUnknownAccess(t *testing.T) {
	w := defaultWorld()
	w.subnetRules = nil
	w.nicRules = []string{r("odd", 100, "Inspect", "Tcp", "22", "")}
	check(t, w.data(t), ssh, wantUndetermined, `access "Inspect"`)
}

func TestUnknownDirection(t *testing.T) {
	w := defaultWorld()
	w.subnetRules = nil
	w.nicRules = []string{strings.Replace(allowSSH("odd", 100, "*"), `"Inbound"`, `"Both"`, 1)}
	check(t, w.data(t), ssh, wantUndetermined, `direction "Both"`)
}

func TestIPv6(t *testing.T) {
	w := defaultWorld()
	w.private, w.version = "fd00::4", "IPv6"
	w.publicIP = `{"id":"` + pipID + `","sku":{"name":"Standard"},"properties":{"ipAddress":"2603:1020:1:2::5","publicIPAddressVersion":"IPv6"}}`
	w.subnetRules = nil
	w.nicRules = []string{allowSSH("v4-only", 100, "0.0.0.0/0")}
	check(t, w.data(t), ssh, wantClosed)
	w.nicRules = []string{allowSSH("v6", 100, "::/0")}
	check(t, w.data(t), ssh, wantOpen, "(2603:1020:1:2::5)", "reachable from ::/0")
	w.nicRules = []string{allowSSH("star", 100, "*")}
	check(t, w.data(t), ssh, wantOpen, "reachable from ::/0")
	// An IPv4 public IP on an IPv6 configuration is not its address.
	w.publicIP = standardIP
	check(t, w.data(t), ssh, wantClosed, "no public IPv6 address")
}

// twoConfigs adds a second IP configuration (10.0.1.5) without a public IP.
func twoConfigs(t *testing.T, d HostData) HostData {
	nic := *d.NICs[0].NIC
	second := decode[IPConfig](t, `{"name":"ipconfig2","properties":{"privateIPAddress":"10.0.1.5","privateIPAddressVersion":"IPv4","subnet":{"id":"`+subID+`"}}}`)
	nic.Properties.IPConfigurations = append(nic.Properties.IPConfigurations, second)
	d.NICs[0].NIC = &nic
	return d
}

func TestBindAddress(t *testing.T) {
	w := defaultWorld()
	w.subnetRules = nil
	w.nicRules = []string{allowSSH("ssh", 100, "*")}
	d := twoConfigs(t, w.data(t))
	bound := ssh
	bound.Addr = "10.0.1.5"
	v := check(t, d, bound, wantClosed, "web-nic/ipconfig2")
	if strings.Contains(strings.Join(v.Evidence, "\n"), "ipconfig1") {
		t.Fatalf("a listener bound to ipconfig2's address is judged on ipconfig1: %v", v.Evidence)
	}
	bound.Addr = "10.0.1.4"
	check(t, d, bound, wantOpen, "web-nic/ipconfig1")
	check(t, d, ssh, wantOpen) // wildcard: every configuration
}

func TestMultiNIC(t *testing.T) {
	w := defaultWorld()
	w.subnetRules = nil
	w.nicRules = []string{allowSSH("ssh", 100, "*")}
	d := w.data(t)
	closedNIC := decode[NIC](t, `{"id":"`+rgPath+`Microsoft.Network/networkInterfaces/back-nic","name":"back-nic","properties":{"ipConfigurations":[{"name":"ip","properties":{"privateIPAddress":"10.0.2.4","subnet":{"id":"`+subID+`"}}}]}}`)
	d.NICs = append([]NICData{{ID: closedNIC.ID, NIC: &closedNIC}}, d.NICs...)
	d.VM.Properties.NetworkProfile.NetworkInterfaces = append(d.VM.Properties.NetworkProfile.NetworkInterfaces, Ref{ID: closedNIC.ID})
	check(t, d, ssh, wantOpen, "web-nic/ipconfig1")
}

func TestAgentLevelGate(t *testing.T) {
	w := defaultWorld()
	w.subnetRules = nil
	w.nicRules = []string{allowSSH("ssh", 100, "*")}
	bound := ssh
	bound.AgentLevel = cloud.LevelBound
	check(t, w.data(t), bound, wantUndetermined, "direct path not counted")
	w.nicRules = []string{}
	check(t, w.data(t), bound, wantClosed)
}

func TestLBBackendUndetermined(t *testing.T) {
	for _, member := range []string{"loadBalancerBackendAddressPools", "loadBalancerInboundNatRules", "applicationGatewayBackendAddressPools"} {
		t.Run(member, func(t *testing.T) {
			w := defaultWorld()
			w.publicIP = ""
			w.subnetRules = nil
			w.ipconfigExtra = `,"` + member + `":[{"id":"` + rgPath + `Microsoft.Network/loadBalancers/lb/x/y"}]`
			w.nicRules = []string{allowSSH("ssh", 100, "*")}
			check(t, w.data(t), ssh, wantUndetermined, "load balancer, NAT rule or application gateway backend, not read")
			// Firewalls closed: closed whatever is in front.
			w.nicRules = []string{}
			check(t, w.data(t), ssh, wantClosed)
		})
	}
}

func TestNoPublicNoBackendClosed(t *testing.T) {
	w := defaultWorld()
	w.publicIP = ""
	w.subnetRules = nil
	w.nicRules = []string{allowSSH("ssh", 100, "*")}
	check(t, w.data(t), ssh, wantClosed, "no public IPv4 address and in no load balancer", "VM has no public IPv4 or IPv6 address")
}

func TestDynamicIPUnallocated(t *testing.T) {
	w := defaultWorld()
	w.publicIP = `{"id":"` + pipID + `","sku":{"name":"Basic"},"properties":{"publicIPAllocationMethod":"Dynamic"}}`
	w.subnetRules = nil
	w.nicRules = []string{allowSSH("ssh", 100, "*")}
	check(t, w.data(t), ssh, wantClosed, "no public IPv4 address")
}

func TestLayerUnread(t *testing.T) {
	for _, c := range []struct{ name, id, evidence string }{
		{"subnet NSG", snsgID, "subnet NSG subnet-nsg not read: 429 Too Many Requests"},
		{"NIC NSG", nnsgID, "NIC NSG nic-nsg not read: 429 Too Many Requests"},
		{"subnet", subID, "subnet subnet not read: 429 Too Many Requests"},
		{"public IP", pipID, "public IP was not read: 429 Too Many Requests"},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := defaultWorld()
			w.subnetRules = []string{allowSSH("ssh", 100, "*")}
			w.nicRules = []string{allowSSH("ssh", 100, "*")}
			w.errs = map[string]string{c.id: "429 Too Many Requests"}
			check(t, w.data(t), ssh, wantUndetermined, c.evidence)
		})
	}
	t.Run("unread layer, the other one closed", func(t *testing.T) {
		w := defaultWorld()
		w.nicRules = []string{}
		w.errs = map[string]string{snsgID: "500"}
		check(t, w.data(t), ssh, wantClosed)
	})
	t.Run("NIC not read", func(t *testing.T) {
		w := defaultWorld()
		d := w.data(t)
		d.NICs = []NICData{{ID: nicID, Err: "403 Forbidden"}}
		check(t, d, ssh, wantUndetermined, "NIC web-nic: not read: 403 Forbidden")
	})
}

func TestNICCounts(t *testing.T) {
	w := defaultWorld()
	d := w.data(t)
	d.VM.Properties.NetworkProfile.NetworkInterfaces = nil
	check(t, d, ssh, wantUndetermined, "no network interfaces")
	d = w.data(t)
	for range maxNICs {
		d.VM.Properties.NetworkProfile.NetworkInterfaces = append(d.VM.Properties.NetworkProfile.NetworkInterfaces, Ref{ID: nicID})
	}
	check(t, d, ssh, wantUndetermined, "more than 16")
	d = w.data(t)
	d.TooManyConfigs = true
	check(t, d, ssh, wantUndetermined, "IP configurations")
}
