#!/usr/bin/env bash
# Installs deploy/nats-server.conf and runs nats-server as a systemd service in the VM,
# so the agent has a broker across reboots. Dev only.
set -euo pipefail
cd "$(dirname "$0")/.."

sudo mkdir -p /etc/nats /var/lib/nats
sudo install -m 0644 deploy/nats-server.conf /etc/nats/nats-server.conf
sudo tee /etc/systemd/system/nats-server.service >/dev/null <<'UNIT'
[Unit]
Description=NATS server (Listener Watch dev)
After=network.target

[Service]
ExecStart=/usr/local/bin/nats-server -c /etc/nats/nats-server.conf
Restart=always

[Install]
WantedBy=multi-user.target
UNIT
sudo systemctl daemon-reload
sudo systemctl enable nats-server
sudo systemctl restart nats-server
systemctl --no-pager status nats-server | head -5
