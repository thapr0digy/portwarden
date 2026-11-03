#!/usr/bin/env bash
# Package lifecycle check for the agent .deb, run as a sudo user on a disposable Ubuntu
# machine without portwarden-agent installed (dev/matrix.sh's x86_64 leg; the x86 test
# checklist). Usage: dev/deb-check.sh <old.deb> <new.deb> (new must be a higher version).
#   1. install old: the unit is enabled and active, logs "started" and watches its unit file;
#   2. upgrade to new in two halves: `dpkg --unpack` (prerm writes the upgrade marker,
#      the binary and unit are replaced, the old agent keeps running with 1 s tamper
#      passes) must give "upgraded" flags and no binary_replaced / unit_changed;
#      `dpkg --configure` restarts it onto the new version;
#   3. an administrator's `systemctl disable --now` survives reinstalling the package;
#   4. purge: inactive, unit gone, spool removed.
set -euo pipefail
old=$(realpath "$1")
new=$(realpath "$2")
fail() { echo "deb-check: FAIL: $*" >&2; sudo journalctl -u portwarden-agent -o cat --no-pager | tail -n 20 >&2; exit 1; }
log() { echo "deb-check: $*"; }
journal_since() { sudo journalctl -u portwarden-agent -o cat --no-pager --since "@$1"; }

if dpkg -s portwarden-agent >/dev/null 2>&1; then
	sudo DEBIAN_FRONTEND=noninteractive apt-get purge -y -q portwarden-agent >/dev/null
fi

log "install $(basename "$old")"
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$old" >/dev/null
systemctl is-enabled --quiet portwarden-agent || fail "not enabled after install"
for _ in $(seq 30); do systemctl is-active --quiet portwarden-agent && break; sleep 1; done
systemctl is-active --quiet portwarden-agent || fail "not active after install"
for _ in $(seq 30); do sudo journalctl -u portwarden-agent -o cat --no-pager | grep -q 'tamper: watching unit files' && break; sleep 1; done
sudo journalctl -u portwarden-agent -o cat --no-pager | grep -q '"msg":"started"' || fail "no started line"
sudo journalctl -u portwarden-agent -o cat --no-pager | grep -q 'tamper: watching unit files' || fail "unit check not on"
old_version=$(portwarden-agent --version)
log "running: $old_version"

log "upgrade, first half (dpkg --unpack) with 1 s tamper passes"
echo 'PORTWARDEN_AGENT_ARGS="--tamper-interval 1s"' | sudo tee /etc/default/portwarden-agent >/dev/null
sudo systemctl restart portwarden-agent
sleep 3
t0=$(date +%s)
sudo dpkg --unpack "$new" >/dev/null
[ -f /run/portwarden-agent/upgrading ] || fail "prerm wrote no upgrade marker"
sleep 4
journal_since "$t0" | grep -q '"kind":"upgraded"' || fail "the replaced binary was not reported as upgraded"
! journal_since "$t0" | grep -qE '"kind":"(binary_replaced|unit_changed|binary_missing)"' ||
	fail "the package upgrade raised a paging tamper flag: $(journal_since "$t0" | grep tamper | head -3)"
log "upgraded flags: $(journal_since "$t0" | grep -c '"kind":"upgraded"'), no binary_replaced or unit_changed"

log "upgrade, second half (dpkg --configure)"
sudo DEBIAN_FRONTEND=noninteractive dpkg --configure portwarden-agent >/dev/null
[ ! -e /run/portwarden-agent/upgrading ] || fail "postinst left the upgrade marker"
for _ in $(seq 30); do systemctl is-active --quiet portwarden-agent && break; sleep 1; done
new_version=$(portwarden-agent --version)
[ "$new_version" != "$old_version" ] || fail "version did not change"
pid_version=$(sudo cat "/proc/$(systemctl show -p MainPID --value portwarden-agent)/cmdline" | tr '\0' ' ')
log "running after upgrade: $new_version ($pid_version)"
# The conffile edit above is kept (config|noreplace).
grep -q -- '--tamper-interval 1s' /etc/default/portwarden-agent || fail "the conffile edit was overwritten"

log "an administrator's disable survives reinstalling"
sudo systemctl disable --now portwarden-agent
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q --reinstall "$new" >/dev/null
! systemctl is-enabled --quiet portwarden-agent || fail "reinstall re-enabled a disabled unit"
! systemctl is-active --quiet portwarden-agent || fail "reinstall started a disabled unit"

log "purge"
sudo DEBIAN_FRONTEND=noninteractive apt-get purge -y -q portwarden-agent >/dev/null
! systemctl is-active --quiet portwarden-agent || fail "active after purge"
[ ! -e /var/lib/portwarden ] || fail "/var/lib/portwarden left after purge"
[ ! -e /usr/lib/systemd/system/portwarden-agent.service ] || fail "unit left after purge"
log "ok"
