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
		{"azure", "vm-uuid", "/subscriptions/0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0/resourceGroups/rg-web_1(prod)/providers/Microsoft.Compute/virtualMachines/web-01"},
		{"azure", "vm-uuid", "/subscriptions/0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0/resourcegroups/rg/providers/microsoft.compute/virtualmachines/web.01"},
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
