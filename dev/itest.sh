#!/usr/bin/env bash
# Runs the integration tests inside the VM. Each package's test binary is compiled as
# the current user, so the Go build and module caches stay user-owned (a root `go test`
# leaves root-owned cache entries that break a later `make generate`); only the compiled
# binaries run as root. Extra arguments go to every binary, e.g. `-test.run TestSnapshot`.
set -euo pipefail
cd "$(dirname "$0")/.."

bin=$(mktemp -d)
trap 'rm -rf "$bin"' EXIT

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
	if (cd "$dir" && sudo env PATH="$PATH" "$test_bin" "$@"); then
		echo "ok   $pkg"
	else
		echo "FAIL $pkg"
		status=1
	fi
done <<<"$pkgs"
exit "$status"
