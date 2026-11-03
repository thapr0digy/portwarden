//go:build !linux

package main

import (
	"fmt"
	"os"

	"github.com/thapr0digy/portwarden/internal/version"
)

func main() {
	version.HandleFlag()
	fmt.Fprintln(os.Stderr, "portwarden-agent: linux only")
	os.Exit(1)
}
