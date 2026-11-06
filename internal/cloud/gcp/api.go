package gcp

import "encoding/json"

// Response shapes of the two Compute Engine v1 calls, holding only the fields the judge
// reads (unknown fields are ignored). Field names follow the REST reference
// (docs.cloud.google.com/compute/docs/reference/rest/v1: instances/get,
// instances/getEffectiveFirewalls, firewalls, firewallPolicies/getRule; read 2026-11-05).

// Instance is instances.get.
type Instance struct {
	// ID is the instance number; the API sends it as a decimal string.
	ID              string           `json:"id"`
	Name            string           `json:"name"`
	Tags            Tags             `json:"tags"`
	ServiceAccounts []ServiceAccount `json:"serviceAccounts"`
	Interfaces      []Interface      `json:"networkInterfaces"`
}

// Tags are the instance's network tags.
type Tags struct {
	Items []string `json:"items"`
}

// ServiceAccount is one service account attached to the instance.
type ServiceAccount struct {
	Email string `json:"email"`
}

// Interface is one network interface (nic0 … nic7).
type Interface struct {
	Name              string         `json:"name"`
	Network           string         `json:"network"`
	NetworkIP         string         `json:"networkIP"`
	IPv6Address       string         `json:"ipv6Address"`
	AccessConfigs     []AccessConfig `json:"accessConfigs"`
	IPv6AccessConfigs []AccessConfig `json:"ipv6AccessConfigs"`
}

// AccessConfig is an external address: natIP for IPv4 (accessConfigs), externalIpv6 for
// IPv6 (ipv6AccessConfigs).
type AccessConfig struct {
	Type         string `json:"type"`
	NatIP        string `json:"natIP"`
	ExternalIPv6 string `json:"externalIpv6"`
}

// Effective is instances.getEffectiveFirewalls for one interface.
type Effective struct {
	Firewalls []Firewall `json:"firewalls"`
	Policies  []Policy   `json:"firewallPolicys"`
	// present: the response named firewalls or firewallPolicys (an answer with neither is
	// not taken as "no rules").
	present bool
}

// UnmarshalJSON records whether either list was in the response.
func (e *Effective) UnmarshalJSON(b []byte) error {
	var raw struct {
		Firewalls *[]Firewall `json:"firewalls"`
		Policies  *[]Policy   `json:"firewallPolicys"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	*e = Effective{present: raw.Firewalls != nil || raw.Policies != nil}
	if raw.Firewalls != nil {
		e.Firewalls = *raw.Firewalls
	}
	if raw.Policies != nil {
		e.Policies = *raw.Policies
	}
	return nil
}

// Firewall is a VPC firewall rule. Priority is a pointer because the API's default is
// 1000, not 0.
type Firewall struct {
	Name                  string   `json:"name"`
	Network               string   `json:"network"`
	Priority              *int     `json:"priority"`
	Direction             string   `json:"direction"`
	Disabled              bool     `json:"disabled"`
	SourceRanges          []string `json:"sourceRanges"`
	SourceTags            []string `json:"sourceTags"`
	SourceServiceAccounts []string `json:"sourceServiceAccounts"`
	TargetTags            []string `json:"targetTags"`
	TargetServiceAccounts []string `json:"targetServiceAccounts"`
	Allowed               []L4     `json:"allowed"`
	Denied                []L4     `json:"denied"`
}

// L4 is a protocol and its ports ("22", "8000-9000"; none: every port).
type L4 struct {
	Protocol string   `json:"IPProtocol"`
	Ports    []string `json:"ports"`
}

// Policy is a firewall policy in effect on the interface.
type Policy struct {
	Name      string `json:"name"`
	ShortName string `json:"shortName"`
	// Type is HIERARCHY, NETWORK, NETWORK_REGIONAL, SYSTEM_GLOBAL or SYSTEM_REGIONAL.
	Type string `json:"type"`
	// Priority is the association's priority (not set for HIERARCHY).
	Priority *int   `json:"priority"`
	Rules    []Rule `json:"rules"`
}

// Rule is a firewall policy rule.
type Rule struct {
	RuleName              string      `json:"ruleName"`
	Priority              int         `json:"priority"`
	Action                string      `json:"action"`
	Direction             string      `json:"direction"`
	Disabled              bool        `json:"disabled"`
	Match                 Match       `json:"match"`
	TargetResources       []string    `json:"targetResources"`
	TargetServiceAccounts []string    `json:"targetServiceAccounts"`
	TargetSecureTags      []SecureTag `json:"targetSecureTags"`
	TargetType            string      `json:"targetType"`
}

// Match is a policy rule's matcher.
type Match struct {
	SrcIPRanges            []string    `json:"srcIpRanges"`
	SrcFqdns               []string    `json:"srcFqdns"`
	SrcRegionCodes         []string    `json:"srcRegionCodes"`
	SrcThreatIntelligences []string    `json:"srcThreatIntelligences"`
	SrcAddressGroups       []string    `json:"srcAddressGroups"`
	SrcSecureTags          []SecureTag `json:"srcSecureTags"`
	SrcNetworks            []string    `json:"srcNetworks"`
	SrcNetworkType         string      `json:"srcNetworkType"`
	SrcNetworkContext      string      `json:"srcNetworkContext"`
	Layer4Configs          []PolicyL4  `json:"layer4Configs"`
}

// PolicyL4 is a policy rule's protocol and ports.
type PolicyL4 struct {
	Protocol string   `json:"ipProtocol"`
	Ports    []string `json:"ports"`
}

// SecureTag is a secure tag reference; State is EFFECTIVE or INEFFECTIVE.
type SecureTag struct {
	Name  string `json:"name"`
	State string `json:"state"`
}

// apiError is Google's error body.
type apiError struct {
	Error struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Status  string `json:"status"`
	} `json:"error"`
}
