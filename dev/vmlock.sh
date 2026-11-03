#!/usr/bin/env bash
# Host-wide lock on the Lima test VMs, so two runs (dev/matrix.sh, dev/vm-verify.sh,
# make itest, make e2e) never use a VM at the same time.
#
# Sourced (dev/matrix.sh): vmlock_acquire, vmlock_release, vmlock_wait_idle <vm>.
# Run: dev/vmlock.sh run [--vm <name>] -- <command...> takes the lock, waits until the
# named VM runs no tests, runs the command and releases the lock on exit.
#
# The lock is a directory (mkdir is atomic; macOS has no flock) holding an owner file:
# token, pid, host, checkout, branch, start time, command. A waiter prints the owner and
# polls every VMLOCK_POLL seconds (default 10) up to VMLOCK_TIMEOUT (default 5400). A
# lock whose owner process is gone on this host is stale and taken over. A process
# started under a held lock (VMLOCK_HELD is the holder's token) re-enters it without
# waiting and leaves the release to the holder.
#
# Environment: VMLOCK_DIR (default <mount>/.vmverify/lock, where <mount> is MATRIX_MOUNT
# or ~/projects/portwarden, the directory the VMs mount).

VMLOCK_DIR=${VMLOCK_DIR:-${MATRIX_MOUNT:-$HOME/projects/portwarden}/.vmverify/lock}
VMLOCK_TIMEOUT=${VMLOCK_TIMEOUT:-5400}
VMLOCK_POLL=${VMLOCK_POLL:-10}
# Processes that mean a VM is running tests: the test scripts and compiled test binaries.
# The brackets keep the pattern from matching the shell that runs pgrep with it.
VMLOCK_BUSY_PATTERN='[e]2e\.sh|[i]test\.sh|[.]test( |$)'
_vmlock_token=""

_vmlock_field() { sed -n "s/^$1=//p" "$VMLOCK_DIR/owner" 2>/dev/null | head -1; }

vmlock_holder() {
	if [ -f "$VMLOCK_DIR/owner" ]; then
		tr '\n' ' ' <"$VMLOCK_DIR/owner"
		echo
	else
		echo "unknown (no owner file yet)"
	fi
}

# _vmlock_stale: the owner process is gone on this host, or no owner file appeared
# within a minute of the lock's creation (a holder killed between mkdir and the write).
_vmlock_stale() {
	local pid host
	if [ ! -f "$VMLOCK_DIR/owner" ]; then
		[ -n "$(find "$VMLOCK_DIR" -maxdepth 0 -mmin +1 2>/dev/null)" ]
		return
	fi
	pid=$(_vmlock_field pid)
	host=$(_vmlock_field host)
	[ "$host" = "$(hostname)" ] && [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null
}

# _vmlock_reclaim: moves a stale lock aside (rename is atomic), then removes it. When
# another waiter took the lock between our check and the rename, its lock is put back.
_vmlock_reclaim() {
	local judged aside
	judged=$(_vmlock_field token)
	aside="$VMLOCK_DIR.stale.$$.$RANDOM"
	mv "$VMLOCK_DIR" "$aside" 2>/dev/null || return 0
	if [ "$(sed -n 's/^token=//p' "$aside/owner" 2>/dev/null | head -1)" != "$judged" ]; then
		mv "$aside" "$VMLOCK_DIR" 2>/dev/null ||
			echo "vmlock: moved a live lock aside by mistake ($aside); its owner keeps running" >&2
		return 0
	fi
	echo "vmlock: took over a stale lock: $(tr '\n' ' ' <"$aside/owner" 2>/dev/null)" >&2
	rm -rf "${aside:?}"
}

vmlock_acquire() {
	if [ -n "${VMLOCK_HELD:-}" ] && [ "$(_vmlock_field token)" = "$VMLOCK_HELD" ]; then
		return 0
	fi
	mkdir -p "$(dirname "$VMLOCK_DIR")"
	local start=$SECONDS last_note=-1 token
	token="$$-$RANDOM-$(date +%s)"
	while ! mkdir "$VMLOCK_DIR" 2>/dev/null; do
		if _vmlock_stale; then
			_vmlock_reclaim
			continue
		fi
		local waited=$((SECONDS - start))
		if [ "$waited" -ge "$VMLOCK_TIMEOUT" ]; then
			echo "vmlock: gave up after ${waited}s; the VMs are held by: $(vmlock_holder)" >&2
			return 1
		fi
		if [ "$last_note" -lt 0 ] || [ $((waited - last_note)) -ge 300 ]; then
			echo "vmlock: waiting for the VMs (${waited}s of ${VMLOCK_TIMEOUT}s); held by: $(vmlock_holder)" >&2
			last_note=$waited
		fi
		sleep "$VMLOCK_POLL"
	done
	local branch
	branch=$(git -C "$PWD" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "-")
	{
		echo "token=$token"
		echo "pid=$$"
		echo "host=$(hostname)"
		echo "checkout=$PWD"
		echo "branch=$branch"
		echo "started=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
		echo "command=${VMLOCK_COMMAND:-$0}"
	} >"$VMLOCK_DIR/owner.tmp"
	mv "$VMLOCK_DIR/owner.tmp" "$VMLOCK_DIR/owner"
	_vmlock_token=$token
	export VMLOCK_HELD=$token
}

# vmlock_release: removes the lock only when this process took it.
vmlock_release() {
	[ -n "$_vmlock_token" ] || return 0
	if [ "$(_vmlock_field token)" = "$_vmlock_token" ]; then
		rm -rf "${VMLOCK_DIR:?}"
	fi
	_vmlock_token=""
}

# vmlock_wait_idle <vm>: waits until no test runs in the VM (a run started by hand inside
# it takes no lock), printing what runs. Fails after VMLOCK_TIMEOUT or when the VM
# cannot be asked.
vmlock_wait_idle() {
	local vm=$1 start=$SECONDS last_note=-1 procs rc
	while :; do
		rc=0
		procs=$(limactl shell "$vm" pgrep -af -- "$VMLOCK_BUSY_PATTERN" </dev/null 2>/dev/null) || rc=$?
		case $rc in
		1) return 0 ;;
		0) ;;
		*)
			echo "vmlock: cannot list processes in VM $vm (limactl/pgrep exit $rc)" >&2
			return 1
			;;
		esac
		local waited=$((SECONDS - start))
		if [ "$waited" -ge "$VMLOCK_TIMEOUT" ]; then
			echo "vmlock: VM $vm still busy after ${waited}s: $procs" >&2
			return 1
		fi
		if [ "$last_note" -lt 0 ] || [ $((waited - last_note)) -ge 300 ]; then
			echo "vmlock: VM $vm is running tests started outside the lock; waiting: $(echo "$procs" | tr '\n' ';')" >&2
			last_note=$waited
		fi
		sleep "$VMLOCK_POLL"
	done
}

_vmlock_run() {
	local vm=""
	while [ $# -gt 0 ]; do
		case $1 in
		--vm) vm=$2; shift 2 ;;
		--) shift; break ;;
		*) echo "vmlock: usage: dev/vmlock.sh run [--vm <name>] -- <command...>" >&2; return 2 ;;
		esac
	done
	[ $# -gt 0 ] || { echo "vmlock: no command given" >&2; return 2; }
	VMLOCK_COMMAND="$*"
	trap vmlock_release EXIT
	trap 'exit 130' INT
	trap 'exit 143' TERM
	vmlock_acquire || return 1
	if [ -n "$vm" ]; then
		vmlock_wait_idle "$vm" || return 1
	fi
	"$@"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
	set -euo pipefail
	case ${1:-} in
	run) shift; _vmlock_run "$@" ;;
	*) echo "usage: dev/vmlock.sh run [--vm <name>] -- <command...>" >&2; exit 2 ;;
	esac
fi
