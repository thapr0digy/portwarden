// portwarden is Portwarden's backend in one static binary: the inventory, alerter and
// verifier services and the natsauth and watch tools, each a subcommand
// (`portwarden alerter --config ...`). Installed under a command's former name
// (/usr/bin/portwarden-alerter, a symlink to /usr/bin/portwarden), it runs that command
// with the arguments as given, so existing units, scripts and habits keep working.
//
// The eBPF agent is not here: portwarden-agent needs CAP_BPF and CAP_PERFMON and stays
// its own binary, and this one does not link it (TestNoAgentDependencies).
//
// Each subcommand is the former main, unchanged: its flags, config, logs, signals and
// exit statuses, and the credentials it reads (only its own config's files).
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/thapr0digy/portwarden/internal/cmd/alerter"
	"github.com/thapr0digy/portwarden/internal/cmd/cli"
	"github.com/thapr0digy/portwarden/internal/cmd/inventory"
	"github.com/thapr0digy/portwarden/internal/cmd/natsauth"
	"github.com/thapr0digy/portwarden/internal/cmd/verifier"
	"github.com/thapr0digy/portwarden/internal/cmd/watch"
	"github.com/thapr0digy/portwarden/internal/version"
)

// program is this binary's own name; any other name must be a command's compatibility
// name (namePrefix + the command).
const (
	program    = "portwarden"
	namePrefix = "portwarden-"
)

// runFunc is a subcommand: it reports its own failures and returns cli.Exit.
type runFunc func(ctx context.Context, args []string, stdout, stderr io.Writer) error

type command struct {
	run     runFunc
	summary string
}

// commands are the subcommands; each is also installed as namePrefix+name.
var commands = map[string]command{
	"inventory": {inventory.Run, "service: the events in PostgreSQL, the read-only API, the cloud look-up; forget-host"},
	"alerter":   {alerter.Run, "service: pages on newly reachable listeners, host silence and tamper signals"},
	"verifier":  {verifier.Run, "service: the outside checker"},
	"natsauth":  {natsauth.Run, "tool: mint least-privilege NATS nkey users, render the server's authorization block"},
	"watch":     {watch.Run, "tool: print the ASM_EVENTS stream, read-only"},
}

func main() {
	os.Exit(dispatch(context.Background(), commands, os.Args, os.Stdout, os.Stderr))
}

// dispatch runs the command argv names and returns the process's exit status. argv[0]'s
// base name picks it: program takes the command from argv[1]; namePrefix+<command> (a
// compatibility symlink) runs that command on argv[1:]. Any other name, an unknown
// command or no command prints the usage and returns 2: a name never falls through to a
// default command.
func dispatch(ctx context.Context, cmds map[string]command, argv []string, stdout, stderr io.Writer) int {
	if len(argv) == 0 {
		fmt.Fprintln(stderr, program+": no program name")
		usage(stderr, cmds)
		return 2
	}
	name := filepath.Base(argv[0])
	if name != program {
		c, ok := cmds[strings.TrimPrefix(name, namePrefix)]
		if !ok || !strings.HasPrefix(name, namePrefix) {
			fmt.Fprintf(stderr, "%s: unknown command name %q\n", program, name)
			usage(stderr, cmds)
			return 2
		}
		return exitStatus(stderr, c.run(ctx, argv[1:], stdout, stderr))
	}
	args := argv[1:]
	if len(args) == 0 {
		usage(stderr, cmds)
		return 2
	}
	switch args[0] {
	case "help", "-h", "-help", "--help":
		return help(ctx, cmds, args[1:], stdout, stderr)
	case "version", "-version", "--version":
		if len(args) != 1 {
			usage(stderr, cmds)
			return 2
		}
		version.Fprint(stdout, program)
		return 0
	}
	c, ok := cmds[args[0]]
	if !ok {
		fmt.Fprintf(stderr, "%s: unknown command %q\n", program, args[0])
		usage(stderr, cmds)
		return 2
	}
	return exitStatus(stderr, c.run(ctx, args[1:], stdout, stderr))
}

// help prints the usage, or with one command name runs `<command> --help`.
func help(ctx context.Context, cmds map[string]command, args []string, stdout, stderr io.Writer) int {
	switch len(args) {
	case 0:
		usage(stdout, cmds)
		return 0
	case 1:
		if c, ok := cmds[args[0]]; ok {
			return exitStatus(stderr, c.run(ctx, []string{"--help"}, stdout, stderr))
		}
		fmt.Fprintf(stderr, "%s: unknown command %q\n", program, args[0])
	}
	usage(stderr, cmds)
	return 2
}

// exitStatus is the status for a subcommand's result. A cli.ExitError was reported by the
// subcommand; any other error was not, so it is reported here rather than lost.
func exitStatus(stderr io.Writer, err error) int {
	if err != nil && !cli.Reported(err) {
		fmt.Fprintln(stderr, program+":", err)
	}
	return cli.Code(err)
}

func usage(w io.Writer, cmds map[string]command) {
	names := make([]string, 0, len(cmds))
	for n := range cmds {
		names = append(names, n)
	}
	slices.Sort(names)
	fmt.Fprintf(w, "usage: %s <command> [flags]\n\n", program)
	fmt.Fprintln(w, "Portwarden's backend services and tools. Commands:")
	for _, n := range names {
		fmt.Fprintf(w, "  %-10s %s\n", n, cmds[n].summary)
	}
	fmt.Fprintf(w, "  %-10s %s\n", "version", "print the version")
	fmt.Fprintf(w, "  %-10s %s\n", "help", "this text; `help <command>` is `<command> --help`")
	fmt.Fprintf(w, "\nInstalled as %s<command> (a symlink to this binary), it runs that command.\n", namePrefix)
	fmt.Fprintln(w, "The eBPF agent is the separate portwarden-agent binary.")
}
