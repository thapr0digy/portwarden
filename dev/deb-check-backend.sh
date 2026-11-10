#!/usr/bin/env bash
# Package lifecycle check for the backend .deb, run as a sudo user on a disposable Ubuntu
# machine without portwarden-backend installed (dev/deb-check.sh runs it for a pair of
# portwarden-backend packages). Usage: dev/deb-check-backend.sh <old.deb> <new.deb> (new
# must be a higher version; old may be a release from before the single binary, when each
# command was its own file in /usr/bin).
#   1. install old: the three units are installed, none enabled or started;
#   2. the verifier runs from its real unit (its own nkey as a systemd credential, NATS
#      unreachable, so it waits for the stream and stays active);
#   3. upgrade to new: /usr/bin/portwarden is root-owned 0755, every former name a
#      root-owned symlink to it; the running verifier is restarted onto the new binary
#      (a new PID, /proc/<pid>/exe the new /usr/bin/portwarden, argv[0] still
#      /usr/bin/portwarden-verifier); the stopped units stay stopped;
#   4. an administrator's `systemctl disable --now` survives reinstalling;
#   5. remove stops the verifier and removes the binaries; purge removes the units.
# The files it writes under /etc/portwarden are removed at the end.
set -euo pipefail
old=$(realpath "$1")
new=$(realpath "$2")
unit=portwarden-verifier
commands=(inventory alerter verifier natsauth watch)
fail() { echo "deb-check-backend: FAIL: $*" >&2; sudo journalctl -u "$unit" -o cat --no-pager | tail -n 20 >&2; exit 1; }
log() { echo "deb-check-backend: $*"; }
main_pid() { systemctl show -p MainPID --value "$unit"; }
# wait_running <since epoch> <when>: the unit is active and its verifier logged the stream
# wait since then (so it is not crash-looping through Restart=always).
wait_running() {
	local j
	for _ in $(seq 30); do
		j=$(sudo journalctl -u "$unit" -o cat --no-pager --since "@$1")
		systemctl is-active --quiet "$unit" && grep -q '"msg":"waiting for the stream"' <<<"$j" && return 0
		sleep 1
	done
	fail "$unit is not running $2"
}
# The files this check writes; it refuses to run where any exists, and removes only them.
own_files=(/etc/portwarden/nats/verifier.nk /etc/portwarden/nats/verifier.json /etc/portwarden/verifier.json)
for f in "${own_files[@]}"; do
	if sudo test -e "$f"; then
		echo "deb-check-backend: $f exists; run this on a disposable machine" >&2
		exit 1
	fi
done
cleanup() { sudo rm -f "${own_files[@]}"; }
trap cleanup EXIT

if dpkg -s portwarden-backend >/dev/null 2>&1; then
	sudo DEBIAN_FRONTEND=noninteractive apt-get purge -y -q portwarden-backend >/dev/null
fi

log "install $(basename "$old")"
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$old" >/dev/null
for svc in inventory alerter verifier; do
	[ -f "/usr/lib/systemd/system/portwarden-$svc.service" ] || fail "portwarden-$svc.service not installed"
	! systemctl is-enabled --quiet "portwarden-$svc" || fail "portwarden-$svc enabled by the install"
	! systemctl is-active --quiet "portwarden-$svc" || fail "portwarden-$svc started by the install"
done
old_version=$(portwarden-verifier --version)
log "installed: $old_version"

log "run the verifier from its unit"
sudo mkdir -p /etc/portwarden/nats
sudo portwarden-natsauth mint --dir /etc/portwarden/nats --role verifier >/dev/null
[ "$(sudo stat -c %a /etc/portwarden/nats/verifier.nk)" = 600 ] || fail "minted seed is not 0600"
cat <<'JSON' | sudo tee /etc/portwarden/verifier.json >/dev/null
{"nats": {"url": "nats://127.0.0.1:1", "nkey_file": "/run/credentials/portwarden-verifier.service/nats.nk"},
 "allow_cidrs": ["127.0.0.0/8"]}
JSON
sudo chmod 0644 /etc/portwarden/verifier.json
t_start=$(date +%s)
sudo systemctl start "$unit"
wait_running "$t_start" "after start"
old_pid=$(main_pid)

log "upgrade to $(basename "$new")"
t0=$(date +%s)
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$new" >/dev/null
[ "$(stat -c '%U:%G %a %F' /usr/bin/portwarden)" = "root:root 755 regular file" ] ||
	fail "/usr/bin/portwarden: $(stat -c '%U:%G %a %F' /usr/bin/portwarden)"
for c in "${commands[@]}"; do
	f=/usr/bin/portwarden-$c
	[ -L "$f" ] && [ "$(readlink "$f")" = portwarden ] || fail "$f is not a symlink to portwarden: $(ls -l "$f")"
	[ "$(stat -c %U:%G "$f")" = root:root ] || fail "$f is owned by $(stat -c %U:%G "$f")"
	v=$("$f" --version) || fail "$f --version failed"
	case $v in "portwarden-$c "*) ;; *) fail "$f --version printed $v" ;; esac
	[ "${v#portwarden-"$c" }" != "${old_version#portwarden-verifier }" ] || fail "$f still reports the old version: $v"
done
new_version=$(portwarden-verifier --version)
[ "$new_version" != "$old_version" ] || fail "version did not change"
wait_running "$t0" "after the upgrade"
new_pid=$(main_pid)
[ "$new_pid" != "$old_pid" ] || fail "the running verifier was not restarted (PID $old_pid)"
exe=$(sudo readlink "/proc/$new_pid/exe")
[ "$exe" = /usr/bin/portwarden ] || fail "the restarted verifier runs $exe, not /usr/bin/portwarden"
argv0=$(sudo cat "/proc/$new_pid/cmdline" | tr '\0' '\n' | head -1)
[ "$argv0" = /usr/bin/portwarden-verifier ] || fail "the restarted verifier's argv[0] is $argv0"
for svc in inventory alerter; do
	! systemctl is-active --quiet "portwarden-$svc" || fail "the upgrade started portwarden-$svc"
done
log "running after upgrade: $new_version (PID $old_pid -> $new_pid, exe $exe, argv[0] $argv0)"

log "an administrator's disable survives reinstalling"
sudo systemctl enable --now "$unit" >/dev/null 2>&1
sudo systemctl disable --now "$unit" >/dev/null 2>&1
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q --reinstall "$new" >/dev/null
! systemctl is-enabled --quiet "$unit" || fail "reinstall re-enabled a disabled unit"
! systemctl is-active --quiet "$unit" || fail "reinstall started a disabled unit"

log "remove, then purge"
t_start=$(date +%s)
sudo systemctl start "$unit"
wait_running "$t_start" "before remove"
sudo DEBIAN_FRONTEND=noninteractive apt-get remove -y -q portwarden-backend >/dev/null
! systemctl is-active --quiet "$unit" || fail "active after remove"
for c in "" "${commands[@]/#/-}"; do
	[ ! -e "/usr/bin/portwarden$c" ] && [ ! -L "/usr/bin/portwarden$c" ] || fail "/usr/bin/portwarden$c left after remove"
done
[ -f /etc/portwarden/verifier.json ] || fail "remove deleted the operator's config"
sudo DEBIAN_FRONTEND=noninteractive apt-get purge -y -q portwarden-backend >/dev/null
for svc in inventory alerter verifier; do
	[ ! -e "/usr/lib/systemd/system/portwarden-$svc.service" ] || fail "portwarden-$svc.service left after purge"
done
log "ok"
