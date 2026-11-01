// Package hostid reads the host identifier used in NATS subjects.
package hostid

import (
	"fmt"
	"os"
	"strings"
)

const length = 32

// DefaultPath is where systemd keeps the machine id.
const DefaultPath = "/etc/machine-id"

// Read returns the trimmed contents of path, which must be 32 lowercase hex characters.
func Read(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read host id: %w", err)
	}
	id := strings.TrimSpace(string(raw))
	if err := validate(id); err != nil {
		return "", fmt.Errorf("host id in %s: %w", path, err)
	}
	return id, nil
}

func validate(id string) error {
	if len(id) != length {
		return fmt.Errorf("want %d lowercase hex characters, got %d characters", length, len(id))
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return fmt.Errorf("want lowercase hex, found %q", c)
		}
	}
	return nil
}
