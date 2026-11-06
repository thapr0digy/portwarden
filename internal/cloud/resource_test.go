package cloud

import (
	"strings"
	"testing"
)

func TestValidResource(t *testing.T) {
	good := []struct{ cloud, id, r string }{
		{"aws", "i-0abc", ""},
		{"gcp", "1234567890123", "projects/my-project-1/zones/europe-west1-b/instances/1234567890123"},
		{"gcp", "42", "projects/example.com:legacy-proj/zones/us-central1-a/instances/42"},
		{"azure", "02aab8a4-74ef-476e-8182-f6d2ba4166a6", "/subscriptions/0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0/resourceGroups/rg-web_1(prod)/providers/Microsoft.Compute/virtualMachines/web-01"},
		{"azure", "02aab8a4-74ef-476e-8182-f6d2ba4166a6", "/subscriptions/0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0/resourcegroups/rg/providers/microsoft.compute/virtualmachines/web.01"},
	}
	for _, g := range good {
		if err := ValidResource(g.cloud, g.id, g.r); err != nil {
			t.Errorf("%q refused: %v", g.r, err)
		}
	}
	bad := []struct{ cloud, id, r string }{
		{"aws", "i-0abc", "arn:aws:ec2:eu-west-1:1:instance/i-0abc"},
		{"gcp", "1", "projects/my-project-1/zones/europe-west1-b/instances/2"},              // another instance
		{"gcp", "1", "projects/my-project-1/zones/europe-west1-b/instances/1/../../x"},      // path injection
		{"gcp", "1", "https://evil.example/projects/my-project-1/zones/z-a1-b/instances/1"}, // host injection
		{"gcp", "1", "projects/ab/zones/europe-west1-b/instances/1"},                        // project id too short
		{"azure", "x", "/subscriptions/not-a-uuid/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"},
		{"azure", "x", "/subscriptions/0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0/resourceGroups/rg./providers/Microsoft.Compute/virtualMachines/vm"},
		{"azure", "x", "/subscriptions/0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic"},
		{"azure", "x", "/subscriptions/0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm?api-version=1"},
		{"azure", "x", "/subscriptions/0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0/resourceGroups/" + strings.Repeat("r", 600) + "/providers/Microsoft.Compute/virtualMachines/vm"},
	}
	for _, b := range bad {
		if err := ValidResource(b.cloud, b.id, b.r); err == nil {
			t.Errorf("%q accepted", b.r)
		}
	}
}

const azureSub = "/subscriptions/0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0/resourceGroups/"
const azureVM = "/providers/Microsoft.Compute/virtualMachines/web-01"
const azureVMID = "02aab8a4-74ef-476e-8182-f6d2ba4166a6"

// Item 5: Azure allows Unicode letters and digits in resource-group names (1-90
// characters, not ending in "."); invisible, space and symbol characters stay refused.
func TestItem5AzureUnicodeResourceGroup(t *testing.T) {
	for _, rg := range []string{"rg-müller", "グループ", "组-1(prod)", "Ünïcödé_rg", strings.Repeat("é", 90)} {
		if err := ValidResource("azure", azureVMID, azureSub+rg+azureVM); err != nil {
			t.Errorf("%q refused: %v", rg, err)
		}
	}
	for _, rg := range []string{"rg‮", "rg​", "rg grp", "rg/x", "rg€", strings.Repeat("é", 91), "rg.", "müller.", "rg\xff"} {
		if err := ValidResource("azure", azureVMID, azureSub+rg+azureVM); err == nil {
			t.Errorf("%q accepted", rg)
		}
	}
	// The byte cap still applies: 90 four-byte letters and a 64-character VM name are a
	// well-formed id of more than MaxResourceLen bytes.
	long := azureSub + strings.Repeat("\U00020000", 90) + "/providers/Microsoft.Compute/virtualMachines/" + strings.Repeat("v", 64)
	if len(long) <= MaxResourceLen {
		t.Fatalf("fixture is %d bytes", len(long))
	}
	if err := ValidResource("azure", azureVMID, long); err == nil || !strings.Contains(err.Error(), "longer than") {
		t.Errorf("value over the byte cap: %v", err)
	}
	// VM names stay ASCII.
	if err := ValidResource("azure", azureVMID, azureSub+"rg/providers/Microsoft.Compute/virtualMachines/wéb"); err == nil {
		t.Error("Unicode VM name accepted")
	}
}

// Item 5: the Azure instance id (IMDS compute.vmId) must be a UUID when a resource is sent;
// the look-up (phase 3) must still match it against the VM it reads.
func TestItem5AzureInstanceIDMustBeUUID(t *testing.T) {
	r := azureSub + "rg" + azureVM
	if err := ValidResource("azure", azureVMID, r); err != nil {
		t.Fatalf("UUID vmId refused: %v", err)
	}
	if err := ValidResource("azure", strings.ToUpper(azureVMID), r); err != nil {
		t.Fatalf("upper-case UUID vmId refused: %v", err)
	}
	for _, id := range []string{"evil", "", "02aab8a4-74ef-476e-8182-f6d2ba4166a6/../x"} {
		if err := ValidResource("azure", id, r); err == nil {
			t.Errorf("instance id %q accepted", id)
		}
	}
}

func TestParseAzureResource(t *testing.T) {
	sub, group, vm, err := ParseAzureResource("/SUBSCRIPTIONS/0B1C2D3E-4F50-6172-8394-A5B6C7D8E9F0/resourcegroups/Web-RG/providers/microsoft.compute/virtualMachines/web1")
	if err != nil || sub != "0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0" || group != "Web-RG" || vm != "web1" {
		t.Fatalf("%q %q %q %v", sub, group, vm, err)
	}
	for _, bad := range []string{
		"",
		"/subscriptions/0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0/resourceGroups/rg/providers/Microsoft.Compute/virtualMachineScaleSets/ss/virtualMachines/3",
		"/subscriptions/0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/a/b",
		"/subscriptions/0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/a?x",
	} {
		if _, _, _, err := ParseAzureResource(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
