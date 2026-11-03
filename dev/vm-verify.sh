#!/usr/bin/env bash
# Runs the kernel test matrix (dev/matrix.sh) on the Lima VMs for the checkout this script
# sits in, from anywhere: a Flowryn worktree, a verify checkout, the main checkout.
#
#   dev/vm-verify.sh [--legs "2404 2604 amd64"]
#   dev/vm-verify.sh --list-files    # prints the files the copy would hold, and exits
#   dev/vm-verify.sh --copy-only     # makes the copy, prints its path, keeps it, and exits
#
# The VMs mount only ~/projects/portwarden (VMVERIFY_ROOT overrides it), so the checkout's
# files (git ls-files: tracked plus untracked-but-not-ignored, so uncommitted work is
# tested; plus any generated BPF objects; no .git, no build output) are copied to a fresh
# directory <root>/.vmverify/<short-sha>-XXXXXX, which the VMs see at the same path, with
# tar (symlinks kept as links; macOS's rsync fails on the testdata's dangling ones). The
# copy's own dev/matrix.sh then runs with the copy as its repo: it holds the host-wide
# VM lock (dev/vmlock.sh) for the run and waits until each VM runs no other tests. With
# the amd64 leg, `make dist` runs in the copy first so the .deb lifecycle check runs; git
# commands there read this checkout's history (GIT_DIR), not the main checkout's.
#
# On exit the copy's logs go to this checkout's .matrix/ and the copy is removed
# (VMVERIFY_KEEP=1 keeps it). Prints the matrix's per-leg summary; exits non-zero when
# any leg fails.
set -euo pipefail
cd "$(dirname "$0")/.."
src=$PWD
root=${VMVERIFY_ROOT:-$HOME/projects/portwarden}
legs="2404 2604 amd64"
list_only=false
copy_only=false

usage() { echo "usage: dev/vm-verify.sh [--legs \"2404 2604 amd64\"] | --list-files | --copy-only" >&2; }
while [ $# -gt 0 ]; do
	case $1 in
	--legs) [ $# -ge 2 ] || { usage; exit 2; }; legs=$2; shift 2 ;;
	--list-files) list_only=true; shift ;;
	--copy-only) copy_only=true; shift ;;
	-h | --help) usage; exit 0 ;;
	*) usage; exit 2 ;;
	esac
done
for leg in $legs; do
	case $leg in 2404 | 2604 | amd64) ;; *) echo "vm-verify: unknown leg $leg" >&2; exit 2 ;; esac
done
[ -n "${legs// /}" ] || { echo "vm-verify: no legs given" >&2; exit 2; }

# copy_list: NUL-separated paths, relative to the checkout, of the files to copy. Tracked
# files deleted in the worktree are skipped; generated BPF objects are added even if a
# future .gitignore hides them.
copy_list() {
	local f
	{
		git ls-files -z --cached --others --exclude-standard
		find bpf internal -type f \( -name '*_bpfel.o' -o -name '*_bpfel.go' -o -name '*_bpfeb.o' -o -name '*_bpfeb.go' \) -print0 2>/dev/null
	} | while IFS= read -r -d '' f; do
		if [ -f "$f" ] || [ -L "$f" ]; then printf '%s\0' "$f"; fi
	done
}

if $list_only; then
	copy_list | tr '\0' '\n' | sort -u
	exit 0
fi

tools="git"
$copy_only || tools="limactl git go make"
for tool in $tools; do
	command -v "$tool" >/dev/null || { echo "vm-verify: $tool not found" >&2; exit 1; }
done
[ -d "$root" ] || { echo "vm-verify: $root (the directory the VMs mount) does not exist" >&2; exit 1; }
root=$(cd "$root" && pwd -P)
base="$root/.vmverify"
case "$(pwd -P)/" in
"$base"/*) echo "vm-verify: run it from a checkout, not from a vm-verify copy" >&2; exit 2 ;;
esac

git_dir=$(git rev-parse --absolute-git-dir)
sha=$(git rev-parse --short=7 HEAD)
mkdir -p "$base"
# Ignored by itself too, for checkouts whose .gitignore predates .vmverify/.
[ -f "$base/.gitignore" ] || printf '*\n' >"$base/.gitignore"
copy=$(mktemp -d "$base/$sha-XXXXXX")

# save_logs: the copy's .matrix logs and summary (not the test binaries or rebuilt
# packages) into this checkout's .matrix/.
save_logs() {
	[ -d "${copy:?}/.matrix" ] || return 0
	mkdir -p "$src/.matrix"
	(cd "$copy/.matrix" && find . -type f \( -name '*.log' -o -name 'summary.txt' \) -print0) |
		tar -C "$copy/.matrix" --null -T - -cf - | tar -C "$src/.matrix" -xf -
}
cleanup() {
	local status=$?
	save_logs || { echo "vm-verify: could not copy the logs from $copy/.matrix" >&2; status=1; }
	if [ "${VMVERIFY_KEEP:-0}" = 1 ] || { $copy_only && [ "$status" = 0 ]; }; then
		$copy_only || echo "vm-verify: kept the copy at $copy" >&2
	else
		rm -rf "${copy:?}"
	fi
	exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "vm-verify: copying $src ($sha) to $copy"
copy_list | tar --null -T - -cf - | tar -C "$copy" -xpf -
[ -f "$copy/go.mod" ] && [ -x "$copy/dev/matrix.sh" ] || { echo "vm-verify: the copy is incomplete" >&2; exit 1; }
if $copy_only; then
	echo "$copy"
	exit 0
fi

export GIT_DIR=$git_dir
mkdir -p "$copy/.matrix"
case " $legs " in
*" amd64 "*)
	echo "vm-verify: make dist in the copy (log: .matrix/dist.log)"
	make -C "$copy" dist >"$copy/.matrix/dist.log" 2>&1 || { echo "vm-verify: make dist failed (see .matrix/dist.log)" >&2; exit 1; }
	;;
esac

echo "vm-verify: running dev/matrix.sh on legs: $legs"
rc=0
VMLOCK_COMMAND="dev/vm-verify.sh ($legs) from $src, copy $copy" MATRIX_LEGS=$legs "$copy/dev/matrix.sh" || rc=$?
exit "$rc"
