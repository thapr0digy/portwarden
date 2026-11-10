// Package version holds the build's version, stamped by `make dist` with
// -ldflags "-X github.com/thapr0digy/portwarden/internal/version.Version=<v>".
package version

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

// Version is "dev" in a plain `go build`.
var Version = "dev"

// String is "<version> (<go version> <os>/<arch>)".
func String() string {
	return fmt.Sprintf("%s (%s %s/%s)", Version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

// HandleFlag prints "<command> <String()>" and exits when the only argument is
// --version or -version; every Portwarden command calls it first.
func HandleFlag() {
	if printIfRequested(os.Args, os.Stdout) {
		os.Exit(0)
	}
}

func printIfRequested(args []string, w io.Writer) bool {
	if len(args) == 0 || !Requested(args[1:]) {
		return false
	}
	Fprint(w, filepath.Base(args[0]))
	return true
}

// Requested reports whether a command's arguments (without the program name) ask for
// its version: exactly one argument, --version or -version.
func Requested(args []string) bool {
	return len(args) == 1 && (args[0] == "--version" || args[0] == "-version")
}

// Fprint writes "<command> <String()>", the line --version prints.
func Fprint(w io.Writer, command string) {
	fmt.Fprintln(w, command, String())
}
