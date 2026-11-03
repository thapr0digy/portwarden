//go:build !linux

package tamper

import (
	"fmt"
	"io/fs"
)

// signature identifies a file version by size, mode and mtime (the agent runs on Linux;
// this keeps the package testable elsewhere).
func signature(fi fs.FileInfo) string {
	return fmt.Sprintf("%d/%v/%d", fi.Size(), fi.Mode(), fi.ModTime().UnixNano())
}
