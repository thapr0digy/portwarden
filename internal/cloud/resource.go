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
	// Azure's fixed segments are case-insensitive; a group name is 1-90 characters of
	// Unicode letters, marks and digits, "_", "-", "." and "()", not ending in "." (Azure
	// allows Unicode there; format, space, control and symbol characters stay refused); a
	// VM name is 1-64 of ASCII [-\w.] (Azure allows no Unicode there).
	azureResourceRe = regexp.MustCompile(`^/(?i:subscriptions)/(` + uuidPattern + `)/(?i:resourceGroups)/([-\p{L}\p{M}\p{N}_.()]{0,89}[-\p{L}\p{M}\p{N}_()])/(?i:providers/Microsoft\.Compute/virtualMachines)/([-\w.]{1,64})$`)
	// An Azure instance id is the VM's vmId (IMDS compute.vmId), a UUID.
	azureVMIDRe = regexp.MustCompile(`^` + uuidPattern + `$`)
)

const uuidPattern = `[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`

// ValidResource checks a host-supplied cloud_resource (M10) before it is stored: the
// shape of its cloud's full instance name, at most MaxResourceLen bytes, for GCP the
// instance number equal to instanceID, and for Azure instanceID a UUID (the VM's vmId).
// "" is valid (older agents, AWS). The phase 2/3 look-ups must still parse it into parts
// and build their API paths from those (path-escaped). The Azure resource id carries the
// VM's name, not its vmId, so the instance cannot be matched here: the phase 3 look-up
// must read the VM by the parsed id and require its properties.vmId to equal instanceID
// (case-insensitive), else judge nothing (undetermined).
func ValidResource(cloudName, instanceID, r string) error {
	if r == "" {
		return nil
	}
	if len(r) > MaxResourceLen {
		return fmt.Errorf("cloud_resource longer than %d bytes", MaxResourceLen)
	}
	switch cloudName {
	case "gcp":
		m := gcpResourceRe.FindStringSubmatch(r)
		if m == nil {
			return fmt.Errorf("cloud_resource is not projects/<id>/zones/<zone>/instances/<number>")
		}
		if m[3] != instanceID {
			return fmt.Errorf("cloud_resource names instance %s, the host block %q", m[3], instanceID)
		}
	case "azure":
		if !azureResourceRe.MatchString(r) {
			return fmt.Errorf("cloud_resource is not /subscriptions/<uuid>/resourceGroups/<rg>/providers/Microsoft.Compute/virtualMachines/<name>")
		}
		if !azureVMIDRe.MatchString(instanceID) {
			return fmt.Errorf("the host block's Azure instance id is not a vmId (UUID)")
		}
	default:
		return fmt.Errorf("cloud_resource is not expected on cloud %q", cloudName)
	}
	return nil
}
