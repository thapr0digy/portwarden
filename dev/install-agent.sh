#!/usr/bin/env bash
# Builds portwarden-agent and installs it as an enabled systemd service. Run inside the VM as a
# user with sudo (make install-agent). Re-runnable: it restarts the service.
set -euo pipefail
cd "$(dirname "$0")/.."

bin=$(mktemp -d)
trap 'rm -rf "$bin"' EXIT
go build -o "$bin/portwarden-agent" ./cmd/portwarden-agent

id portwarden-agent >/dev/null 2>&1 ||
	sudo useradd --system --no-create-home --shell /usr/sbin/nologin portwarden-agent
sudo install -m 0755 "$bin/portwarden-agent" /usr/local/bin/portwarden-agent
sudo install -m 0644 deploy/portwarden-agent.service /etc/systemd/system/portwarden-agent.service
sudo systemctl daemon-reload
sudo systemctl enable portwarden-agent
sudo systemctl restart portwarden-agent
systemctl --no-pager status portwarden-agent || true
# The spool lives in the unit's StateDirectory: owner portwarden-agent, mode 0700.
systemctl show portwarden-agent -p StateDirectory
sudo ls -ld /var/lib/portwarden
