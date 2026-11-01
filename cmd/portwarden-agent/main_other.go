//go:build !linux

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "portwarden-agent: linux only")
	os.Exit(1)
}
