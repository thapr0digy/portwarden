// portwarden-natsauth mints per-host and per-service NATS nkey users with Portwarden's
// least-privilege permissions and renders the nats-server authorization block.
//
//	portwarden-natsauth mint --dir /etc/portwarden/nats-users --role host --host <machine-id>
//	portwarden-natsauth mint --dir /etc/portwarden/nats-users --role inventory
//	portwarden-natsauth render --dir /etc/portwarden/nats-users --out /etc/nats/portwarden-users.conf
//
// mint writes <name>.nk (the seed, mode 0600: copy it to the host or service and pass it
// as --nats-nkey) and <name>.json (public part). render writes the authorization block
// for every minted user; include it from the server config and reload nats-server.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/thapr0digy/portwarden/internal/natsauth"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, "portwarden-natsauth:", err)
		os.Exit(2)
	}
}

const usage = "usage: portwarden-natsauth mint --dir D --role host|inventory|alerter|verifier|admin [--host ID]\n" +
	"       portwarden-natsauth render --dir D [--out FILE]"

func run(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New(usage)
	}
	fs := flag.NewFlagSet("portwarden-natsauth "+args[0], flag.ContinueOnError)
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
