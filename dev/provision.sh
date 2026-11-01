#!/bin/bash
# Installs the toolchain for kernel-touching work on Ubuntu 24.04. Idempotent; run as root.
set -euo pipefail

GO_VERSION=1.26.3
NATS_SERVER_VERSION=2.15.2
BUF_VERSION=1.50.0
ARCH=$(dpkg --print-architecture)   # amd64 | arm64

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y clang llvm libbpf-dev linux-tools-common "linux-tools-$(uname -r)" \
  curl ca-certificates unzip make protobuf-compiler

if ! /usr/local/go/bin/go version 2>/dev/null | grep -q "go${GO_VERSION} "; then
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz" | tar -C /usr/local -xz
fi
cat >/etc/profile.d/go.sh <<'PROFILE'
export PATH=$PATH:/usr/local/go/bin:/usr/local/bin
PROFILE
export PATH=$PATH:/usr/local/go/bin
export GOPATH=/root/go GOCACHE=/root/.cache/go-build HOME=${HOME:-/root}

if ! command -v nats-server >/dev/null || ! nats-server --version | grep -q "v${NATS_SERVER_VERSION}"; then
  tmp=$(mktemp -d)
  curl -fsSL "https://github.com/nats-io/nats-server/releases/download/v${NATS_SERVER_VERSION}/nats-server-v${NATS_SERVER_VERSION}-linux-${ARCH}.tar.gz" | tar -C "$tmp" -xz
  install -m 0755 "$tmp"/nats-server-*/nats-server /usr/local/bin/nats-server
  rm -rf "$tmp"
fi

# natscli (the `nats` command), buf and protoc-gen-go are installed with the pinned Go toolchain.
GOBIN=/usr/local/bin go install github.com/nats-io/natscli/nats@latest
GOBIN=/usr/local/bin go install "github.com/bufbuild/buf/cmd/buf@v${BUF_VERSION}"
GOBIN=/usr/local/bin go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
