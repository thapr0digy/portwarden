#!/usr/bin/env bash
# Builds lw-agent and installs it as an enabled systemd service. Run inside the VM as a
# user with sudo (make install-agent). Re-runnable: it restarts the service.
set -euo pipefail
cd "$(dirname "$0")/.."

bin=$(mktemp -d)
trap 'rm -rf "$bin"' EXIT
go build -o "$bin/lw-agent" ./cmd/lw-agent

id lw-agent >/dev/null 2>&1 ||
	sudo useradd --system --no-create-home --shell /usr/sbin/nologin lw-agent
sudo install -m 0755 "$bin/lw-agent" /usr/local/bin/lw-agent
sudo install -m 0644 deploy/lw-agent.service /etc/systemd/system/lw-agent.service
sudo systemctl daemon-reload
sudo systemctl enable lw-agent
sudo systemctl restart lw-agent
systemctl --no-pager status lw-agent || true
