#!/usr/bin/env bash
# Kernel test matrix (make matrix): runs the kernel-touching tests on each leg's Lima VM
# and prints one summary line per leg. Runs on the host (macOS or Linux) with limactl.
#
# Legs (MATRIX_LEGS, default "2404 2604 amd64"):
#   2404   Ubuntu 24.04 (kernel 6.8), VM "portwarden" (dev/lima.yaml): itest + e2e.
#   2604   Ubuntu 26.04 (kernel 7.0), VM "portwarden-2604" (dev/lima-2604.yaml): itest + e2e.
#   amd64  Ubuntu 24.04 on x86_64, VM "portwarden-amd64" (dev/lima-amd64.yaml; QEMU TCG on
#          an arm64 host, KVM on an x86_64 one): every package's unit tests and the
#          integration tests, cross-compiled for amd64 on the host and run as root in the
#          VM (they load and attach the real BPF objects), then dev/deb-check.sh runs the
#          amd64 .deb from dist/ (make dist) through install, upgrade, disable, purge.
# A missing VM is created and provisioned (dev/provision.sh from this checkout). VMs are
# left running for the next run: `limactl stop <vm>` or `limactl delete -f <vm>` removes
# them. Logs go to .matrix/<leg>/. MATRIX_MOUNT (CI) mounts that directory instead of
# ~/projects/portwarden; it must be this checkout or contain it.
#
# The repo under test is the checkout this script sits in: dev/vm-verify.sh runs the
# matrix.sh of a copy of any checkout, placed where the VMs can see it. A host-wide lock
# (dev/vmlock.sh) keeps other matrix runs, vm-verify and make itest/e2e out of the VMs
# meanwhile, and each leg first waits until its VM runs no tests started by hand.
set -euo pipefail
cd "$(dirname "$0")/.."
repo=$PWD
legs=${MATRIX_LEGS:-2404 2604 amd64}
out="$repo/.matrix"
mkdir -p "$out"
# shellcheck source=dev/vmlock.sh
. "$repo/dev/vmlock.sh"
trap vmlock_release EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
VMLOCK_COMMAND=${VMLOCK_COMMAND:-"dev/matrix.sh ($legs) in $repo"}
vmlock_acquire

vm_of() { case $1 in 2404) echo portwarden ;; 2604) echo portwarden-2604 ;; amd64) echo portwarden-amd64 ;; *) return 1 ;; esac; }
yaml_of() { case $1 in 2404) echo dev/lima.yaml ;; 2604) echo dev/lima-2604.yaml ;; amd64) echo dev/lima-amd64.yaml ;; esac; }

# vm_up <leg>: starts the leg's VM, creating and provisioning it first if needed.
vm_up() {
	local leg=$1 vm yaml
	vm=$(vm_of "$leg")
	yaml=$(yaml_of "$leg")
	if limactl list -q 2>/dev/null | grep -qx "$vm"; then
		limactl start --tty=false "$vm" >>"$out/$leg/vm.log" 2>&1
		return
	fi
	local set=()
	if [ -n "${MATRIX_MOUNT:-}" ]; then
		set=(--set ".mounts[0].location = \"$MATRIX_MOUNT\"")
	fi
	echo "matrix: creating VM $vm from $yaml (minutes; QEMU TCG takes longer)"
	limactl start --tty=false --name="$vm" "${set[@]}" "$yaml" >>"$out/$leg/vm.log" 2>&1
	if [ "$leg" = amd64 ]; then
		return # runs prebuilt test binaries: nothing to install
	fi
	limactl shell "$vm" sudo "$repo/dev/provision.sh" >>"$out/$leg/provision.log" 2>&1
}

vsh() { local vm=$1; shift; limactl shell "$vm" bash -lc "cd '$repo' && $*"; }

# run_full <leg>: dev/itest.sh and dev/e2e.sh in the VM.
run_full() {
	local leg=$1 vm itest=FAIL e2e=FAIL
	vm=$(vm_of "$leg")
	vsh "$vm" dev/itest.sh </dev/null >"$out/$leg/itest.log" 2>&1 && itest=ok
	vsh "$vm" dev/e2e.sh </dev/null >"$out/$leg/e2e.log" 2>&1 && e2e=ok
	echo "itest=$itest e2e=$e2e"
}

# run_cross <leg>: cross-compiled unit and integration tests, then the .deb.
run_cross() {
	local leg=$1 vm bin pkgs status=ok deb=SKIP
	vm=$(vm_of "$leg")
	bin="$out/$leg/bin"
	rm -rf "${bin:?}"
	mkdir -p "$bin"
	pkgs=$(go list -tags integration -f '{{if or .TestGoFiles .XTestGoFiles}}{{.ImportPath}} {{.Dir}}{{end}}' ./...)
	: >"$out/$leg/tests.log"
	while read -r pkg dir; do
		[ -n "$pkg" ] || continue
		local name=${pkg//\//_} tags=integration
		case $pkg in
		*/pgstate | */inventory/pg) continue ;; # need PostgreSQL (make itest covers them)
		esac
		CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -tags "$tags" -o "$bin/$name.test" "$pkg" >>"$out/$leg/tests.log" 2>&1 ||
			{ echo "BUILD FAIL $pkg" >>"$out/$leg/tests.log"; status=FAIL; continue; }
		[ -f "$bin/$name.test" ] || continue
		# </dev/null: limactl would otherwise read the package list off this loop's stdin.
		if limactl shell "$vm" bash -c "cd '$dir' && sudo '$bin/$name.test' -test.timeout 20m" </dev/null >>"$out/$leg/tests.log" 2>&1; then
			echo "ok   $pkg" >>"$out/$leg/tests.log"
		else
			echo "FAIL $pkg" >>"$out/$leg/tests.log"
			status=FAIL
		fi
	done <<<"$pkgs"
	# The .deb lifecycle (dev/deb-check.sh): install dist/'s amd64 agent package, upgrade it
	# to a second build with a higher version (checking the upgrade is not tamper), keep
	# an administrator's disable, purge.
	local debfile
	debfile=$(ls dist/portwarden-agent_*_amd64.deb 2>/dev/null | head -1 || true)
	if [ -n "$debfile" ]; then
		deb=FAIL
		local v2dir="$out/$leg/dist-upgrade" base
		base=${debfile#dist/portwarden-agent_}
		base=${base%-1_amd64.deb}
		rm -rf "${v2dir:?}"
		if ARCHES=amd64 SBOM=0 VERSION="$base+upgradetest" DIST_DIR="$v2dir" dev/dist.sh >"$out/$leg/dist-upgrade.log" 2>&1 &&
			limactl shell "$vm" bash -c "cd '$repo' && dev/deb-check.sh '$repo/$debfile' '$(ls "$v2dir"/portwarden-agent_*_amd64.deb)'" \
				</dev/null >"$out/$leg/deb.log" 2>&1; then
			deb=ok
		fi
	fi
	echo "tests=$status deb=$deb ($(grep -c '^ok ' "$out/$leg/tests.log") packages ok)"
}

rc=0
summary=()
for leg in $legs; do
	vm_of "$leg" >/dev/null || { echo "matrix: unknown leg $leg" >&2; exit 2; }
	mkdir -p "$out/$leg"
	start=$(date +%s)
	vm_up "$leg"
	vm=$(vm_of "$leg")
	if ! vmlock_wait_idle "$vm"; then
		rc=1
		line="$leg | - | FAIL (VM busy with tests started outside the lock) | $(($(date +%s) - start))s"
		echo "matrix: $line"
		summary+=("$line")
		continue
	fi
	info=$(limactl shell "$vm" bash -c '. /etc/os-release; echo "$PRETTY_NAME $(uname -r) $(uname -m)"' 2>/dev/null)
	echo "matrix: $leg: $info"
	if [ "$leg" = amd64 ]; then
		result=$(run_cross "$leg")
	else
		result=$(run_full "$leg")
	fi
	case $result in *FAIL*) rc=1 ;; esac
	line="$leg | $info | $result | $(($(date +%s) - start))s"
	echo "matrix: $line"
	summary+=("$line")
done
printf '%s\n' "leg | system | result | time" "${summary[@]}" | tee "$out/summary.txt"
exit "$rc"
