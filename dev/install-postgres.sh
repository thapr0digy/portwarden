#!/usr/bin/env bash
# Installs PostgreSQL 16 from Ubuntu's archive in the VM for portwarden-inventory's
# integration tests and dev/e2e.sh. Dev only. Listens on localhost only (Ubuntu's
# default); TCP logins need a password (scram-sha-256, Ubuntu's default pg_hba). Roles and
# passwords are created at test time by dev/itest.sh and dev/e2e.sh, never stored here.
set -euo pipefail
if ! command -v psql >/dev/null || ! systemctl list-unit-files postgresql.service >/dev/null 2>&1; then
	sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q postgresql
fi
sudo systemctl enable --now postgresql
sudo -u postgres psql -qAtc 'select version()'
