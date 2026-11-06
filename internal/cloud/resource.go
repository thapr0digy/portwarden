package cloud

import (
	"fmt"
	"regexp"
)

// MaxResourceLen caps a host-supplied cloud_resource.
const MaxResourceLen = 512

var (
	// projects/<project id>/zones/<zone>/instances/<instance number>. A project id is 6-30
	// lowercase letters, digits and hyphens (legacy domain-scoped ids carry "domain:").
	gcpResourceRe = regexp.MustCompile(`^projects/((?:[a-z0-9][a-z0-9.-]{0,62}:)?[a-z][a-z0-9-]{4,28}[a-z0-9])/zones/([a-z]+-[a-z]+[0-9]+-[a-z])/instances/([0-9]{1,20})$`)
	// /subscriptions/<uuid>/resourceGroups/<rg>/providers/Microsoft.Compute/virtualMachines/<name>.
	// Azure's fixed segments are case-insensitive; a group name is 1-90 of [-\w.()] not
	// ending in ".", a VM name 1-64 of [-\w.].
	azureResourceRe = regexp.MustCompile(`^/(?i:subscriptions)/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})/(?i:resourceGroups)/([-\w.()]{0,89}[-\w()])/(?i:providers/Microsoft\.Compute/virtualMachines)/([-\w.]{1,64})$`)
)

// ValidResource checks a host-supplied cloud_resource (M10) before it is stored: the
// shape of its cloud's full instance name, at most MaxResourceLen bytes, and for GCP the
// instance number equal to instanceID. "" is valid (older agents, AWS). The phase 2/3
// look-ups must still parse it into parts and build their API paths from those.
func ValidResource(cloudName, instanceID, r string) error {
	if r == "" {
		return nil
	}
	if len(r) > MaxResourceLen {
		return fmt.Errorf("cloud_resource longer than %d bytes", MaxResourceLen)
	}
	switch cloudName {
	case "gcp":
		_, _, inst, err := ParseGCPResource(r)
		if err != nil {
			return err
		}
		if inst != instanceID {
			return fmt.Errorf("cloud_resource names instance %s, the host block %q", inst, instanceID)
		}
	case "azure":
		if !azureResourceRe.MatchString(r) {
			return fmt.Errorf("cloud_resource is not /subscriptions/<uuid>/resourceGroups/<rg>/providers/Microsoft.Compute/virtualMachines/<name>")
		}
	default:
		return fmt.Errorf("cloud_resource is not expected on cloud %q", cloudName)
	}
	return nil
}

// ParseGCPResource splits a GCP cloud_resource (projects/<id>/zones/<zone>/instances/<n>)
// into its validated parts. Callers build API paths from these, never from r itself.
func ParseGCPResource(r string) (project, zone, instance string, err error) {
	if len(r) > MaxResourceLen {
		return "", "", "", fmt.Errorf("cloud_resource longer than %d bytes", MaxResourceLen)
	}
	m := gcpResourceRe.FindStringSubmatch(r)
	if m == nil {
		return "", "", "", fmt.Errorf("cloud_resource is not projects/<id>/zones/<zone>/instances/<number>")
	}
	return m[1], m[2], m[3], nil
}
