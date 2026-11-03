#!/usr/bin/env bash
# Tests for dev/vmlock.sh, dev/vm-verify.sh's file list and failure logs, and dev/dist.sh's
# offline tool build (make dev-test). Host only, no VM: every lock lives in a scratch
# directory. Each test is named after the assumption it checks; prints ok/FAIL per test and exits non-zero on any failure.
set -euo pipefail
cd "$(dirname "$0")/.."
repo=$PWD
scratch=$(mktemp -d "${TMPDIR:-/tmp}/vmlock-test.XXXXXX")
bg_pids=()
cleanup() {
	local p
	for p in "${bg_pids[@]}"; do kill "$p" 2>/dev/null || true; done
	rm -rf "${scratch:?}"
}
trap cleanup EXIT

failures=0
run_test() {
	local name=$1 out
	# Each test runs in a subshell; its background processes are killed when it ends.
	if out=$(
		rc=0
		"$name" || rc=$?
		for p in "${bg_pids[@]}"; do kill "$p" 2>/dev/null || true; done
		exit "$rc"
	) 2>&1; then
		echo "ok   $name"
	else
		echo "FAIL $name"
		printf '%s\n' "$out" | sed 's/^/     /'
		failures=$((failures + 1))
	fi
}

# lock_env <name>: a fresh lock path; fast polling and a short timeout.
lock_env() {
	export VMLOCK_DIR="$scratch/$1/lock" VMLOCK_POLL=1 VMLOCK_TIMEOUT=3
	unset VMLOCK_HELD
}
# holder_in_background <name> <seconds>: a separate process holding the lock for a while.
holder_in_background() {
	lock_env "$1"
	VMLOCK_COMMAND="holder-$1" bash -c '. dev/vmlock.sh; vmlock_acquire; sleep "$1"; vmlock_release' _ "$2" </dev/null >/dev/null 2>&1 &
	bg_pids+=($!)
	local i
	for i in $(seq 50); do [ -f "$VMLOCK_DIR/owner" ] && return 0; sleep 0.1; done
	echo "holder never took the lock"
	return 1
}

test_mkdir_lock_is_exclusive_and_waiter_names_the_holder() {
	holder_in_background excl 10
	local err
	if err=$(bash -c '. dev/vmlock.sh; vmlock_acquire' 2>&1); then
		echo "second acquire succeeded while held"
		return 1
	fi
	grep -q 'waiting for the VMs' <<<"$err" || { echo "no waiting note: $err"; return 1; }
	grep -q 'command=holder-excl' <<<"$err" || { echo "holder not named: $err"; return 1; }
	grep -q 'gave up after' <<<"$err" || { echo "no timeout message: $err"; return 1; }
}

test_waiter_gets_the_lock_after_release() {
	holder_in_background release 2
	export VMLOCK_TIMEOUT=15
	bash -c '. dev/vmlock.sh; vmlock_acquire; vmlock_release'
	[ ! -e "$VMLOCK_DIR" ] || { echo "lock left behind"; return 1; }
}

test_lock_of_a_dead_owner_is_taken_over() {
	lock_env stale
	sleep 0 </dev/null >/dev/null 2>&1 &
	local dead=$!
	wait "$dead"
	mkdir -p "$VMLOCK_DIR"
	printf 'token=old\npid=%s\nhost=%s\ncommand=crashed\n' "$dead" "$(hostname)" >"$VMLOCK_DIR/owner"
	local err
	err=$(bash -c '. dev/vmlock.sh; vmlock_acquire; echo "held=$(sed -n s/^command=//p "$VMLOCK_DIR/owner")"; vmlock_release' 2>&1)
	grep -q 'took over a stale lock' <<<"$err" || { echo "no takeover note: $err"; return 1; }
	grep -q '^held=.' <<<"$err" || { echo "did not hold: $err"; return 1; }
	[ ! -e "$VMLOCK_DIR" ] || { echo "lock left behind"; return 1; }
}

test_lock_of_a_live_owner_on_another_host_is_not_stale() {
	lock_env otherhost
	mkdir -p "$VMLOCK_DIR"
	printf 'token=x\npid=1\nhost=not-%s\n' "$(hostname)" >"$VMLOCK_DIR/owner"
	if bash -c '. dev/vmlock.sh; vmlock_acquire' >/dev/null 2>&1; then
		echo "took a lock owned by another host"
		return 1
	fi
	[ "$(sed -n 's/^token=//p' "$VMLOCK_DIR/owner")" = x ] || { echo "owner file changed"; return 1; }
}

test_ownerless_lock_older_than_a_minute_is_stale() {
	lock_env ownerless
	mkdir -p "$VMLOCK_DIR"
	touch -t "$(date -v-5M +%Y%m%d%H%M 2>/dev/null || date -d '-5 min' +%Y%m%d%H%M)" "$VMLOCK_DIR"
	bash -c '. dev/vmlock.sh; vmlock_acquire; vmlock_release' 2>/dev/null ||
		{ echo "ownerless old lock not taken over"; return 1; }
}

test_fresh_ownerless_lock_is_not_stale() {
	lock_env freshownerless
	mkdir -p "$VMLOCK_DIR"
	if bash -c '. dev/vmlock.sh; vmlock_acquire' >/dev/null 2>&1; then
		echo "took a lock whose owner may still be writing its owner file"
		return 1
	fi
}

test_child_under_a_held_lock_reenters_and_leaves_the_release_to_the_holder() {
	lock_env reenter
	export VMLOCK_TIMEOUT=1
	bash -c '
		. dev/vmlock.sh
		vmlock_acquire
		bash -c ". dev/vmlock.sh; vmlock_acquire; vmlock_release" || { echo "child could not re-enter"; exit 1; }
		[ -f "$VMLOCK_DIR/owner" ] || { echo "child released the holder lock"; exit 1; }
		vmlock_release
		[ ! -e "$VMLOCK_DIR" ] || { echo "holder did not release"; exit 1; }
	'
}

test_release_never_removes_another_owners_lock() {
	lock_env notmine
	mkdir -p "$VMLOCK_DIR"
	printf 'token=someone\npid=%s\nhost=%s\n' "$$" "$(hostname)" >"$VMLOCK_DIR/owner"
	bash -c '. dev/vmlock.sh; _vmlock_token=mine; vmlock_release'
	[ -f "$VMLOCK_DIR/owner" ] || { echo "removed another owner's lock"; return 1; }
}

test_run_mode_releases_the_lock_and_keeps_the_exit_status() {
	lock_env runmode
	local rc=0
	dev/vmlock.sh run -- bash -c '[ -f "$VMLOCK_DIR/owner" ] && exit 7' || rc=$?
	[ "$rc" = 7 ] || { echo "exit status $rc, want 7"; return 1; }
	[ ! -e "$VMLOCK_DIR" ] || { echo "lock left behind"; return 1; }
}

test_busy_pattern_does_not_match_the_shell_running_pgrep() {
	local pattern out self
	pattern=$(bash -c '. dev/vmlock.sh; printf %s "$VMLOCK_BUSY_PATTERN"')
	# Same shape as limactl shell: a shell whose command line carries the pattern. Other
	# test runs on this host may match; the shell itself must not.
	out=$(bash -c "echo self=\$\$; pgrep -f -- '$pattern' || true")
	self=$(sed -n 's/^self=//p' <<<"$out")
	[ -n "$self" ] || { echo "no pid printed"; return 1; }
	if grep -qx "$self" <<<"$out"; then
		echo "pattern matched its own shell ($self)"
		return 1
	fi
}

test_busy_pattern_matches_test_scripts_and_test_binaries() {
	local pattern d=$scratch/busy
	pattern=$(bash -c '. dev/vmlock.sh; printf %s "$VMLOCK_BUSY_PATTERN"')
	mkdir -p "$d"
	printf '#!/bin/sh\nsleep 30\n' >"$d/e2e.sh"
	chmod +x "$d/e2e.sh"
	"$d/e2e.sh" </dev/null >/dev/null 2>&1 &
	bg_pids+=($!)
	local p1=$!
	cp "$d/e2e.sh" "$d/probes.test" # a script: its command line is "<sh> .../probes.test 30"
	"$d/probes.test" 30 </dev/null >/dev/null 2>&1 &
	bg_pids+=($!)
	local p2=$!
	sleep 0.5
	local found
	found=$(pgrep -f -- "$pattern" || true)
	grep -qx "$p1" <<<"$found" || { echo "e2e.sh not matched: $found"; return 1; }
	grep -qx "$p2" <<<"$found" || { echo "probes.test not matched: $found"; return 1; }
}

# A scratch clone with this tree's scripts, for the copy-list tests.
clone_with_scripts() {
	local c=$scratch/clone-$1
	git clone -q --no-hardlinks "$repo" "$c"
	cp "$repo/dev/vm-verify.sh" "$repo/dev/vmlock.sh" "$c/dev/"
	cp "$repo/.gitignore" "$c/.gitignore"
	echo "$c"
}

test_copy_holds_tracked_and_new_files_but_not_ignored_deleted_or_git() {
	local c list
	c=$(clone_with_scripts list)
	echo new >"$c/new-untracked.txt"
	mkdir -p "$c/.matrix" "$c/dist"
	echo junk >"$c/.matrix/x.log"
	echo junk >"$c/dist/x.deb"
	git -C "$c" rm -q --cached Makefile >/dev/null # still on disk, now untracked
	rm "$c/buf.yaml"                               # tracked, deleted in the worktree
	list=$("$c/dev/vm-verify.sh" --list-files)
	grep -qx 'new-untracked.txt' <<<"$list" || { echo "untracked file missing"; return 1; }
	grep -qx 'go.mod' <<<"$list" || { echo "tracked file missing"; return 1; }
	grep -qx 'Makefile' <<<"$list" || { echo "untracked-on-disk Makefile missing"; return 1; }
	grep -qx 'buf.yaml' <<<"$list" && { echo "deleted file listed"; return 1; }
	grep -q '^\.matrix/\|^dist/\|^\.git/' <<<"$list" && { echo "ignored or .git files listed"; return 1; }
	return 0
}

test_copy_holds_the_generated_bpf_objects() {
	local list
	list=$(dev/vm-verify.sh --list-files)
	local f
	for f in $(cd "$repo" && find internal -name '*_bpfel.o'); do
		grep -qx "$f" <<<"$list" || { echo "missing $f"; return 1; }
	done
	grep -q '_bpfel\.o$' <<<"$list" || { echo "no BPF objects at all"; return 1; }
}

test_copy_reproduces_files_modes_and_dangling_symlinks_without_git() {
	local c root copy
	c=$(clone_with_scripts copy)
	root=$scratch/root
	mkdir -p "$root"
	echo new >"$c/new-untracked.txt"
	ln -s /nonexistent/target "$c/dangling-link"
	copy=$(cd "$c" && VMVERIFY_ROOT=$root dev/vm-verify.sh --copy-only 2>/dev/null | tail -1)
	case $copy in "$(cd "$root" && pwd -P)"/.vmverify/*-*) ;; *) echo "copy path: $copy"; return 1 ;; esac
	[ -f "$copy/go.mod" ] && [ -f "$copy/new-untracked.txt" ] || { echo "files missing"; return 1; }
	[ "$(readlink "$copy/dangling-link")" = /nonexistent/target ] || { echo "dangling symlink not kept"; return 1; }
	[ -x "$copy/dev/matrix.sh" ] || { echo "matrix.sh lost its exec bit"; return 1; }
	[ ! -e "$copy/.git" ] || { echo ".git copied"; return 1; }
	[ -f "$root/.vmverify/.gitignore" ] || { echo "scratch dir not self-ignored"; return 1; }
	local want got
	want=$(cd "$c" && dev/vm-verify.sh --list-files | wc -l | tr -d ' ')
	got=$(cd "$copy" && find . \( -type f -o -type l \) | wc -l | tr -d ' ')
	[ "$want" = "$got" ] || { echo "copy holds $got files, list has $want"; return 1; }
}

# failing_run <name> <legs> [setup command]: a scratch clone whose dev/matrix.sh is a stub
# that fails leg 2404's itest; limactl is a stub too. Runs vm-verify on it with a scratch
# root and prints "rc=<status>" after its output. The setup command runs in the clone.
failing_run() {
	local c root stubs rc=0
	c=$(clone_with_scripts "$1")
	root=$scratch/root-$1
	stubs=$scratch/stubs-$1
	mkdir -p "$root" "$stubs"
	printf '#!/bin/sh\nexit 0\n' >"$stubs/limactl"
	chmod +x "$stubs/limactl"
	cat >"$c/dev/matrix.sh" <<'STUB'
#!/usr/bin/env bash
cd "$(dirname "$0")/.."
mkdir -p .matrix/2404
echo "itest: stub failure marker" >.matrix/2404/itest.log
echo "e2e: fine" >.matrix/2404/e2e.log
printf 'leg | system | result | time\n2404 | stub | itest=FAIL e2e=ok | 1s\n' >.matrix/summary.txt
exit 1
STUB
	chmod +x "$c/dev/matrix.sh"
	[ -z "${3:-}" ] || (cd "$c" && eval "$3")
	(cd "$c" && PATH="$stubs:$PATH" VMVERIFY_ROOT=$root dev/vm-verify.sh --legs "$2" 2>&1) || rc=$?
	echo "rc=$rc"
}

test_failing_leg_leaves_its_logs_in_vmverify_logs_and_prints_their_tail() {
	local out root dir
	out=$(failing_run failleg 2404)
	root=$(cd "$scratch/root-failleg" && pwd -P)
	grep -q '^rc=1$' <<<"$out" || { echo "want rc=1: $out"; return 1; }
	dir=$(sed -n 's/^vm-verify: failed; logs kept in //p' <<<"$out")
	case $dir in "$root/.vmverify/logs/"*-*) ;; *) echo "no logs path printed: $out"; return 1 ;; esac
	[ -f "$dir/2404/itest.log" ] && [ -f "$dir/2404/e2e.log" ] && [ -f "$dir/summary.txt" ] ||
		{ echo "logs missing in $dir: $(ls -R "$dir")"; return 1; }
	grep -q 'last 40 lines of 2404/itest.log' <<<"$out" || { echo "itest.log tail not printed: $out"; return 1; }
	grep -q 'stub failure marker' <<<"$out" || { echo "itest.log content not printed: $out"; return 1; }
	grep -q 'last 40 lines of 2404/e2e.log' <<<"$out" && { echo "a passing log was printed: $out"; return 1; }
	[ -z "$(find "$root/.vmverify" -maxdepth 1 -name '*-*' -type d)" ] || { echo "copy not removed"; return 1; }
}

test_failed_make_dist_leaves_dist_log_in_vmverify_logs() {
	local out dir
	out=$(failing_run faildist amd64 'printf "dist:\n\t@echo dist stub failure marker; exit 1\n" >Makefile')
	grep -q '^rc=1$' <<<"$out" || { echo "want rc=1: $out"; return 1; }
	grep -q 'make dist failed' <<<"$out" || { echo "no dist failure note: $out"; return 1; }
	dir=$(sed -n 's/^vm-verify: failed; logs kept in //p' <<<"$out")
	[ -f "$dir/dist.log" ] || { echo "dist.log not kept: $out"; return 1; }
	grep -q 'dist stub failure marker' <<<"$out" || { echo "dist.log tail not printed: $out"; return 1; }
}

test_only_the_newest_20_failure_log_dirs_are_kept() {
	local logs i out dir
	logs=$scratch/root-prune/.vmverify/logs
	mkdir -p "$logs"
	for i in $(seq 25); do
		mkdir "$logs/old$i"
		touch -t "2001010100$(printf %02d "$i")" "$logs/old$i"
	done
	out=$(failing_run prune 2404)
	dir=$(sed -n 's/^vm-verify: failed; logs kept in //p' <<<"$out")
	[ -d "$dir" ] || { echo "new log dir gone: $out"; return 1; }
	[ "$(find "$logs" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')" = 20 ] || { echo "kept: $(ls "$logs")"; return 1; }
	[ ! -e "$logs/old6" ] && [ -d "$logs/old7" ] || { echo "pruned the wrong ones: $(ls "$logs")"; return 1; }
}

# The flaky make dist (2026-11-03): `go install pkg@version` asked proxy.golang.org about
# the tool even with the module cached, and failed when the proxy timed out.
test_dist_builds_its_cached_tools_without_network() {
	local tool
	for tool in $(grep -E '^(NFPM|CYCLONEDX)=' dev/dist.sh | cut -d= -f2-); do
		GOBIN=$scratch/prime go install "$tool" || { echo "could not fetch $tool to prime the cache"; return 1; }
	done
	HTTPS_PROXY=http://127.0.0.1:9 HTTP_PROXY=http://127.0.0.1:9 ARCHES=amd64 DIST_DIR=$scratch/dist-offline \
		dev/dist.sh >"$scratch/dist-offline.log" 2>&1 || { tail -20 "$scratch/dist-offline.log"; return 1; }
	ls "$scratch"/dist-offline/portwarden-agent_*_amd64.deb >/dev/null || { echo "no .deb"; return 1; }
	[ -n "$(ls "$scratch"/dist-offline/sbom/*.cdx.json 2>/dev/null)" ] || { echo "no SBOMs"; return 1; }
}

test_vm_verify_rejects_unknown_legs() {
	local rc=0
	dev/vm-verify.sh --legs "2404 riscv" >/dev/null 2>&1 || rc=$?
	[ "$rc" = 2 ] || { echo "exit $rc, want 2"; return 1; }
}

for t in $(declare -F | awk '{print $3}' | grep '^test_'); do
	run_test "$t"
done
[ "$failures" = 0 ] || { echo "vmlock-test: $failures failed"; exit 1; }
echo "vmlock-test: all passed"
