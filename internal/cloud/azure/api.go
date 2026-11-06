package azure

// Response shapes of the ARM reads, holding only the fields the judge reads (unknown
// fields are ignored). Field names follow the REST reference (learn.microsoft.com/rest/api:
// compute virtual-machines/get; virtualnetwork network-interfaces/get,
// public-ip-addresses/get, subnets/get, network-security-groups/get, service-tags/list;
// read 2026-11-06).

// Ref is a reference to another resource by its ARM id.
type Ref struct {
	ID string `json:"id"`
}

// VM is virtualMachines/get.
type VM struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Location   string `json:"location"`
	Properties struct {
		VMID           string `json:"vmId"`
		NetworkProfile struct {
			NetworkInterfaces []Ref `json:"networkInterfaces"`
		} `json:"networkProfile"`
	} `json:"properties"`
}

// NIC is networkInterfaces/get.
type NIC struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Properties struct {
		NetworkSecurityGroup *Ref       `json:"networkSecurityGroup"`
		IPConfigurations     []IPConfig `json:"ipConfigurations"`
	} `json:"properties"`
}

// IPConfig is one of a NIC's IP configurations.
type IPConfig struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Properties struct {
		PrivateIPAddress                      string `json:"privateIPAddress"`
		PrivateIPAddressVersion               string `json:"privateIPAddressVersion"`
		PublicIPAddress                       *Ref   `json:"publicIPAddress"`
		Subnet                                *Ref   `json:"subnet"`
		ApplicationSecurityGroups             []Ref  `json:"applicationSecurityGroups"`
		LoadBalancerBackendAddressPools       []Ref  `json:"loadBalancerBackendAddressPools"`
		LoadBalancerInboundNatRules           []Ref  `json:"loadBalancerInboundNatRules"`
		ApplicationGatewayBackendAddressPools []Ref  `json:"applicationGatewayBackendAddressPools"`
	} `json:"properties"`
}

// inBackend: the configuration is behind a load balancer, an inbound NAT rule or an
// application gateway (none of which is read in this phase).
func (c IPConfig) inBackend() bool {
	p := c.Properties
	return len(p.LoadBalancerBackendAddressPools) > 0 || len(p.LoadBalancerInboundNatRules) > 0 ||
		len(p.ApplicationGatewayBackendAddressPools) > 0
}

// PublicIP is publicIPAddresses/get.
type PublicIP struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	SKU  struct {
		Name string `json:"name"`
	} `json:"sku"`
	Properties struct {
		IPAddress              string `json:"ipAddress"`
		PublicIPAddressVersion string `json:"publicIPAddressVersion"`
	} `json:"properties"`
}

// Subnet is subnets/get.
type Subnet struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Properties struct {
		NetworkSecurityGroup *Ref `json:"networkSecurityGroup"`
		RouteTable           *Ref `json:"routeTable"`
	} `json:"properties"`
}

// NSG is networkSecurityGroups/get.
type NSG struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Properties struct {
		SecurityRules        []SecurityRule `json:"securityRules"`
		DefaultSecurityRules []SecurityRule `json:"defaultSecurityRules"`
	} `json:"properties"`
}

// SecurityRule is one NSG rule (user or default).
type SecurityRule struct {
	Name       string `json:"name"`
	Properties struct {
		Protocol                             string   `json:"protocol"`
		SourcePortRange                      string   `json:"sourcePortRange"`
		SourcePortRanges                     []string `json:"sourcePortRanges"`
		DestinationPortRange                 string   `json:"destinationPortRange"`
		DestinationPortRanges                []string `json:"destinationPortRanges"`
		SourceAddressPrefix                  string   `json:"sourceAddressPrefix"`
		SourceAddressPrefixes                []string `json:"sourceAddressPrefixes"`
		SourceApplicationSecurityGroups      []Ref    `json:"sourceApplicationSecurityGroups"`
		DestinationAddressPrefix             string   `json:"destinationAddressPrefix"`
		DestinationAddressPrefixes           []string `json:"destinationAddressPrefixes"`
		DestinationApplicationSecurityGroups []Ref    `json:"destinationApplicationSecurityGroups"`
		Access                               string   `json:"access"`
		Priority                             int      `json:"priority"`
		Direction                            string   `json:"direction"`
	} `json:"properties"`
}

// serviceTagsPage is one page of locations/serviceTags.
type serviceTagsPage struct {
	Values []struct {
		Name       string `json:"name"`
		Properties struct {
			AddressPrefixes []string `json:"addressPrefixes"`
		} `json:"properties"`
	} `json:"values"`
	NextLink string `json:"nextLink"`
}

// armError is ARM's error body.
type armError struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}
