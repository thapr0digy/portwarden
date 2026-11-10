// Package cli is what the backend's subcommands (internal/cmd/...) share with the
// portwarden binary that dispatches to them (cmd/portwarden): an error that carries the
// process's exit status.
//
// A subcommand's Run reports its own failures (on stderr, or in its JSON log) exactly as
// its former main did, then returns Exit(code); the dispatcher only turns that into the
// exit status.
package cli

import (
	"errors"
	"flag"
	"fmt"
)

// ExitError ends the process with Code; the subcommand has already reported why.
type ExitError struct{ Code int }

func (e ExitError) Error() string { return fmt.Sprintf("exit status %d", e.Code) }

// Exit is the error a subcommand's Run returns to end with code: nil for 0.
func Exit(code int) error {
	if code == 0 {
		return nil
	}
	return ExitError{Code: code}
}

// Code is the exit status for Run's result: 0 for nil, an ExitError's code, and 1 for any
// other error (which the caller must report, since the subcommand did not).
func Code(err error) int {
	if err == nil {
		return 0
	}
	var e ExitError
	if errors.As(err, &e) {
		return e.Code
	}
	return 1
}

// FlagExit is the result of a failed flag.FlagSet.Parse (ContinueOnError, which already
// printed the error and the usage): the exit status flag.ExitOnError gives, 0 for -h and
// --help, 2 for anything else.
func FlagExit(err error) error {
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	return Exit(2)
}

// Reported reports whether err is an ExitError, whose cause was already reported.
func Reported(err error) bool {
	var e ExitError
	return errors.As(err, &e)
}
