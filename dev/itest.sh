#!/usr/bin/env bash
# Runs the integration tests inside the VM. Each package's test binary is compiled as
# the current user, so the Go build and module caches stay user-owned (a root `go test`
# leaves root-owned cache entries that break a later `make generate`); only the compiled
# binaries run as root. Extra arguments go to every binary, e.g. `-test.run TestSnapshot`.
set -euo pipefail
cd "$(dirname "$0")/.."

bin=$(mktemp -d)
# An installed portwarden-agent's probes would act on the tests' sockets (they assign MPTCP
# subflow cookies, for one), so the unit is stopped for the run and restarted on exit.
unit_was_active=false
pg_db=""
cleanup() {
	local status=$?
	rm -rf "$bin"
	if [ -n "$pg_db" ]; then
		sudo -u postgres psql -q -c "DROP DATABASE IF EXISTS $pg_db" -c "DROP ROLE IF EXISTS $pg_db" >/dev/null 2>&1 ||
			echo "itest: could not drop database/role $pg_db" >&2
	fi
	if $unit_was_active; then
		sudo systemctl start portwarden-agent || { echo "itest: could not restart portwarden-agent" >&2; status=1; }
	fi
	exit "$status"
}
trap cleanup EXIT
if systemctl is-active --quiet portwarden-agent; then
	unit_was_active=true
	sudo systemctl stop portwarden-agent
	echo "itest: stopped portwarden-agent for the run"
fi

# A throwaway PostgreSQL database and role with a generated password for the inventory
# store's tests (internal/inventory/pg), dropped on exit (dev/install-postgres.sh installs
# the server).
systemctl is-active --quiet postgresql || { echo "itest: postgresql is not running (dev/install-postgres.sh)" >&2; exit 1; }
pg_db="pw_itest_$$"
pg_pass=$(openssl rand -hex 24)
sudo -u postgres psql -q -v ON_ERROR_STOP=1 -c "CREATE ROLE $pg_db LOGIN PASSWORD '$pg_pass'" -c "CREATE DATABASE $pg_db OWNER $pg_db" >/dev/null
pg_dsn="postgres://$pg_db:$pg_pass@127.0.0.1:5432/$pg_db?sslmode=disable"

# Captured first so that set -e catches a load error (a broken integration-tagged file).
pkgs=$(go list -tags integration -f '{{.ImportPath}} {{.Dir}}' ./...)
if [ -z "$pkgs" ]; then
	echo "itest: go list found no packages" >&2
	exit 1
fi

status=0
while read -r pkg dir; do
	test_bin="$bin/${pkg//\//_}.test"
	go test -c -tags integration -o "$test_bin" "$pkg"
	[ -f "$test_bin" ] || continue # package has no tests
	# Run from the package directory, as `go test` does, so testdata/ resolves. Only the
	# user's PATH is passed through (tests may run tools such as nats-server from it);
	# sudo still resets HOME to /root and drops GOCACHE, so root never writes the user's
	# Go caches.
	if (cd "$dir" && sudo env PATH="$PATH" PORTWARDEN_TEST_PG="$pg_dsn" "$test_bin" "$@"); then
		echo "ok   $pkg"
	else
		echo "FAIL $pkg"
		status=1
	fi
done <<<"$pkgs"
exit "$status"
