// Package natsauth is `portwarden natsauth` (also installed as portwarden-natsauth): it
// mints per-host and per-service NATS nkey users with Portwarden's least-privilege
// permissions and renders the nats-server authorization block.
//
//	portwarden natsauth mint --dir /etc/portwarden/nats-users --role host --host <machine-id>
//	portwarden natsauth mint --dir /etc/portwarden/nats-users --role inventory
//	portwarden natsauth render --dir /etc/portwarden/nats-users --out /etc/nats/portwarden-users.conf
//
// mint writes <name>.nk (the seed, mode 0600: copy it to the host or service and pass it
// as --nats-nkey) and <name>.json (public part). render writes the authorization block
// for every minted user; include it from the server config and reload nats-server.
package natsauth

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/thapr0digy/portwarden/internal/cmd/cli"
	"github.com/thapr0digy/portwarden/internal/natsauth"
	"github.com/thapr0digy/portwarden/internal/version"
)

// Name is the command's name in its usage and version line.
const Name = "portwarden-natsauth"

// Run is `portwarden natsauth` (and the portwarden-natsauth name): mint or render. It
// returns cli.Exit with the status the process ends with: 0, or 2 after printing the error.
func Run(_ context.Context, args []string, stdout, stderr io.Writer) error {
	if version.Requested(args) {
		version.Fprint(stdout, Name)
		return nil
	}
	if err := run(args, stdout, stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		fmt.Fprintln(stderr, Name+":", err)
		return cli.Exit(2)
	}
	return nil
}

const usage = "usage: portwarden-natsauth mint --dir D --role host|inventory|alerter|verifier|admin [--host ID]\n" +
	"       portwarden-natsauth render --dir D [--out FILE]"

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New(usage)
	}
	fs := flag.NewFlagSet(Name+" "+args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "", "directory of minted users (seeds and public parts)")
	switch args[0] {
	case "mint":
		role := fs.String("role", "", "host, inventory, alerter, verifier or admin")
		host := fs.String("host", "", "host id (/etc/machine-id), for --role host")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *dir == "" || *role == "" {
			return errors.New(usage)
		}
		if natsauth.Role(*role) != natsauth.RoleHost && *host != "" {
			return errors.New("--host applies to --role host only")
		}
		u, seed, err := natsauth.Mint(*dir, natsauth.Role(*role), *host)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "minted %s (%s): seed %s; run render and reload nats-server\n", u.Name, u.PublicKey, seed)
		return nil
	case "render":
		out := fs.String("out", "", "write the block here (default stdout)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *dir == "" {
			return errors.New(usage)
		}
		users, err := natsauth.Load(*dir)
		if err != nil {
			return err
		}
		block, err := natsauth.Render(users)
		if err != nil {
			return err
		}
		if *out == "" {
			_, err = io.WriteString(stdout, block)
			return err
		}
		tmp := *out + ".tmp"
		if err := os.WriteFile(tmp, []byte(block), 0o644); err != nil {
			return err
		}
		if err := os.Rename(tmp, *out); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "wrote %d users to %s\n", len(users), filepath.Clean(*out))
		return nil
	}
	return errors.New(usage)
}
