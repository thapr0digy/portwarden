# One `portwarden` binary for the backend (2026-11-10)

## What changed

The backend's five binaries (`portwarden-inventory`, `portwarden-alerter`,
`portwarden-verifier`, `portwarden-natsauth`, `portwarden-watch`) are now one static
binary, `portwarden`, with a subcommand each:

```
portwarden inventory [--config /etc/portwarden/inventory.json]
portwarden inventory forget-host [--force] <host-id>
portwarden alerter   [--config /etc/portwarden/alerter.json]
portwarden verifier  [--config /etc/portwarden/verifier.json]
portwarden natsauth  mint --dir D --role host|inventory|alerter|verifier|admin [--host ID]
portwarden natsauth  render --dir D [--out FILE]
portwarden watch     [--nats-url …] [--nats-nkey …] [--host …] [--since 10m]
portwarden version | portwarden help [<command>]
```

`portwarden-agent` is unchanged and stays its own binary.

## Why

The five were thin `main`s over `internal/` packages: two offline admin tools and three
services that share the bus, config and store code. Five static binaries carried five
copies of the Go runtime, NATS, protobuf and pgx (55.4 MB on amd64, 51.6 MB on arm64), and
five files to build, sign, list in SBOMs and keep in step. One binary is 19.5 MB on amd64
and 18.0 MB on arm64, and the backend .deb shrinks from 19.2 MB to 6.3 MB (arm64).

## Why the agent stays separate

The agent loads eBPF programs and runs with `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_PTRACE`
and `CAP_NET_ADMIN` under its own hardened unit, starts before the network, and checks
its own executable for tampering. The backend services run with no capabilities at all.
Putting the agent's code in the backend binary would ship eBPF loaders to machines that
never need them, and putting the backend in the agent would make the tamper-checked,
privileged executable change with every backend release. `cmd/portwarden`'s
`TestNoAgentDependencies` fails if the backend binary links `cilium/ebpf`, the agent's
`main` or any package only the agent uses (`go list -deps`).

## Compatibility

- **The former names still work.** The backend .deb installs `/usr/bin/portwarden` and
  `/usr/bin/portwarden-{inventory,alerter,verifier,natsauth,watch}` as root-owned relative
  symlinks to it. The binary picks the command from its own name (`argv[0]`, as busybox
  does) and passes the arguments as they are, so `portwarden-alerter --config F` is
  `portwarden alerter --config F`.
- **The units are unchanged.** They keep `ExecStart=/usr/bin/portwarden-<service>`, so the
  process name, the journal's identifier, `pkill -f` patterns, administrators' drop-ins and
  a downgrade to an older package all behave as before.
- **Each command is its former `main`.** Flags, config schema, logging (JSON on stderr for
  the services), signal handling (SIGTERM and SIGINT stop cleanly with status 0) and exit
  statuses are unchanged, as are subjects, streams, consumers and on-disk formats. One
  visible difference: `--help` prints `Usage of portwarden-alerter:` where it used to echo
  the path it was started as (`Usage of /usr/bin/portwarden-alerter:`).
- **Upgrades.** Upgrading from a package with five files replaces each with its symlink;
  `postinst` restarts running units onto the new binary as before
  (`dev/deb-check-backend.sh` checks this: a new PID whose executable is
  `/usr/bin/portwarden` and whose `argv[0]` is still `/usr/bin/portwarden-verifier`).
- **Packaging.** `make dist` builds `bin/linux_<arch>/portwarden` and `portwarden-agent`,
  SBOMs `sbom/portwarden_linux_<arch>.cdx.json` and `sbom/portwarden-agent_…`, and
  `SHA256SUMS` over them. `dev/dist-lint.sh` checks the backend .deb's layout.

## Security

- Only `portwarden` and the five `portwarden-<command>` names run anything. Any other name
  (`portwarden-agent`, `portwarden-help`, a renamed copy), an unknown command, or no
  command prints the usage and exits 2; a name never falls through to a default command.
- A command reads only its own flags and the files its config names. One binary holding
  every command gives a service no access to another's credentials: each unit still has its
  own `DynamicUser`, no capabilities, and only its own `LoadCredential` files, so the alerter
  process cannot read the inventory's seed or DSN whatever code its executable contains.
- `natsauth mint` still writes seeds mode 0600 and refuses to overwrite one (`O_EXCL`).

## Layout

- `cmd/portwarden`: the dispatcher (`dispatch`), its tests and the dependency check.
- `internal/cmd/{inventory,alerter,verifier,natsauth,watch}`: the former mains, each with
  `Run(ctx, args, stdout, stderr) error` and its former tests.
- `internal/cmd/cli`: `cli.Exit(code)`, the error a `Run` returns after reporting its own
  failure, which the dispatcher turns into the exit status.
