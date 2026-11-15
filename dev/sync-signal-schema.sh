#!/usr/bin/env bash
# Refreshes third_party/signal-schema, the pinned copy of Signal's event contract (the Go
# module github.com/slidehq/signal/schema), from a local Signal checkout. go.mod points the
# module at the copy with a replace directive, so every build (make test, make dist, CI)
# uses exactly these files and needs no access to the Signal repository, which has no
# remote yet. Once Signal publishes the module, the replace and the copy go away and go.mod
# requires a tagged schema/v1.x.y instead.
#
# Usage: dev/sync-signal-schema.sh [<signal checkout>]   (default: $SIGNAL_REPO, else
# ~/projects/appsec-signal). Copies the committed schema/ tree at the checkout's HEAD (never
# uncommitted edits) and records that commit in third_party/signal-schema/UPSTREAM. Then
# run `go mod tidy && make test`, and review the diff like any dependency bump.
set -euo pipefail
cd "$(dirname "$0")/.."

src=${1:-${SIGNAL_REPO:-$HOME/projects/appsec-signal}}
dst=third_party/signal-schema

if ! git -C "$src" rev-parse --verify -q HEAD:schema/go.mod >/dev/null; then
	echo "sync-signal-schema: $src has no committed schema/go.mod" >&2
	exit 1
fi
module=$(git -C "$src" show HEAD:schema/go.mod | awk '$1 == "module" { print $2; exit }')
if [ "$module" != github.com/slidehq/signal/schema ]; then
	echo "sync-signal-schema: $src schema/ is module $module, want github.com/slidehq/signal/schema" >&2
	exit 1
fi
commit=$(git -C "$src" rev-parse HEAD)

tmp=$(mktemp -d)
trap 'rm -rf "${tmp:?}"' EXIT
git -C "$src" archive --format=tar "HEAD:schema" | tar -x -C "$tmp"
printf 'appsec-signal %s schema/\nRefreshed with dev/sync-signal-schema.sh; do not edit these files here.\n' "$commit" >"$tmp/UPSTREAM"

rm -rf "${dst:?}"
mkdir -p "$(dirname "$dst")"
mv "$tmp" "$dst"
trap - EXIT
chmod -R u+rwX,go+rX "$dst"
echo "sync-signal-schema: $dst is appsec-signal ${commit:0:12} schema/"
