# Listener Watch

A Go agent with C eBPF programs that reports TCP listening sockets (host network namespace) to NATS JetStream.
M1 scope: TCP only, host netns only. Kernel floor 6.8 (Ubuntu 24.04+).

## Development

Kernel-touching work happens in a Lima VM named `lw` (Ubuntu 24.04), which mounts this repo writable at the same path.

| Command | What it does |
| --- | --- |
| `make vm` | Create and start the VM (`limactl start --name=lw dev/lima.yaml`); provisions the toolchain |
| `make generate` | In the VM: `buf generate` then `go generate ./...` (protobuf and bpf2go) |
| `make test` | `go test ./...` (macOS or Linux, no root) |
| `make itest` | In the VM: `sudo -E go test -tags integration ./...` (root, real kernel) |
| `make e2e` | In the VM: `dev/e2e.sh` |

`gen/asm/v1/events.pb.go` is committed, so `go build ./...` works on macOS without `buf`.
`bpf/vmlinux.h` is produced in the VM with `bpftool btf dump file /sys/kernel/btf/vmlinux format c`.

## Event schema

`proto/asm/v1/events.proto` (package `asm.v1`): `ListenerEvent`, `Snapshot`, `Heartbeat`.
A listener's identity is `netns/proto/addr:port`, e.g. `4026531840/tcp/0.0.0.0:8080` or `4026531840/tcp/[::]:8080`;
IPv4-mapped IPv6 addresses are unmapped first. See `internal/model`.
