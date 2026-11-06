package azure

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Resource ids followed from ARM responses are never pasted into a request: each is
// parsed against the shapes below (case-insensitive fixed segments, as ARM ids are), its
// subscription must be allow-listed, and the path is rebuilt from the parsed parts.

const (
	uuidPattern = `[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`
	// groupPattern is a resource-group name (as cloud.ParseAzureResource accepts it).
	groupPattern = `[-\p{L}\p{M}\p{N}_.()]{0,89}[-\p{L}\p{M}\p{N}_()]`
	// namePattern is a Microsoft.Network resource name: 1-80 of letters, digits, "_", "-"
	// and ".".
	namePattern = `[-\w.]{1,80}`
)

var (
	networkIDRe = regexp.MustCompile(`^/(?i:subscriptions)/(` + uuidPattern + `)/(?i:resourceGroups)/(` + groupPattern +
		`)/(?i:providers/Microsoft\.Network)/(?i:(networkInterfaces|publicIPAddresses|networkSecurityGroups))/(` + namePattern + `)$`)
	subnetIDRe = regexp.MustCompile(`^/(?i:subscriptions)/(` + uuidPattern + `)/(?i:resourceGroups)/(` + groupPattern +
		`)/(?i:providers/Microsoft\.Network/virtualNetworks)/(` + namePattern + `)/(?i:subnets)/(` + namePattern + `)$`)
	locationRe = regexp.MustCompile(`^[a-z0-9]{1,40}$`)
)

// Kinds of followed resources.
const (
	kindNIC      = "networkInterfaces"
	kindPublicIP = "publicIPAddresses"
	kindNSG      = "networkSecurityGroups"
	kindSubnet   = "subnets"
)

// armID is a parsed Microsoft.Network resource id.
type armID struct {
	subscription, group, kind, name string
	vnet                            string // subnets only
}

// parseID parses a followed id of the wanted kind.
func parseID(id, kind string) (armID, error) {
	if len(id) > 1024 {
		return armID{}, fmt.Errorf("resource id longer than 1024 bytes")
	}
	var a armID
	if kind == kindSubnet {
		m := subnetIDRe.FindStringSubmatch(id)
		if m == nil {
			return armID{}, fmt.Errorf("%q is not a subnet id", truncate(id, 200))
		}
		a = armID{subscription: strings.ToLower(m[1]), group: m[2], kind: kindSubnet, vnet: m[3], name: m[4]}
	} else {
		m := networkIDRe.FindStringSubmatch(id)
		if m == nil || !strings.EqualFold(m[3], kind) {
			return armID{}, fmt.Errorf("%q is not a %s id", truncate(id, 200), kind)
		}
		a = armID{subscription: strings.ToLower(m[1]), group: m[2], kind: kind, name: m[4]}
	}
	for _, n := range []string{a.group, a.name, a.vnet} {
		if n != "" && strings.Trim(n, ".") == "" {
			return armID{}, fmt.Errorf("%q names a path segment of dots", truncate(id, 200))
		}
	}
	return a, nil
}

// path rebuilds the request path from the parsed parts, each path-escaped.
func (a armID) path() string {
	p := "/subscriptions/" + url.PathEscape(a.subscription) + "/resourceGroups/" + url.PathEscape(a.group) + "/providers/Microsoft.Network/"
	if a.kind == kindSubnet {
		return p + "virtualNetworks/" + url.PathEscape(a.vnet) + "/subnets/" + url.PathEscape(a.name)
	}
	return p + a.kind + "/" + url.PathEscape(a.name)
}

// key is the map key for a resource id: ARM ids are case-insensitive.
func key(id string) string { return strings.ToLower(id) }
