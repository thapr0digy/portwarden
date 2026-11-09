#!/usr/bin/env bash
# Records the proxies' own dumps that the config parser tests compare against. Run in the
# VM (it uses sudo): `limactl shell portwarden bash -lc 'cd $PWD && dev/proxy-fixtures.sh'`.
#
# - ubuntu-default cases copy the distro's config tree (/etc/nginx, /etc/apache2,
#   /etc/haproxy) into testdata/<case>/root and record its dump.
# - Hand-written cases live in testdata/<case>/root/etc/pw-<name>/. The absolute paths
#   in a dump must be real, so each case is dumped in a private mount namespace where
#   /etc is an overlay (upper layer on a tmpfs) holding /etc/pw-<name>; the real /etc is
#   never written and the overlay disappears with the namespace.
#
# Dumps: nginx -T (nginx-T.txt); apache2 -S and apache2 -t -D DUMP_INCLUDES with the
# distro's envvars (apache2-S.txt, apache2-includes.txt); haproxy -c (haproxy-c.txt).
set -euo pipefail
cd "$(dirname "$0")/.."
repo=$PWD

nginx_td=internal/proxy/nginx/testdata
apache_td=internal/proxy/apache/testdata
haproxy_td=internal/proxy/haproxy/testdata

copy_tree() { # <src dir> <case dir>
	local src=$1 case_dir=$2
	local dst=$case_dir/root$(dirname "$src")
	rm -rf "${case_dir:?}/root"
	mkdir -p "$dst"
	cp -a "$src" "$dst/" # world-readable distro files; cp -a keeps the symlinks
	# Absolute symlinks out of the tree (nginx's modules-enabled -> /usr/share/nginx/...):
	# copy their targets to the same path under root, so the links resolve there too.
	local link target
	while IFS= read -r link; do
		target=$(readlink "$link")
		case $target in /*) ;; *) continue ;; esac
		case $target in "$src"/*) continue ;; esac
		[ -e "$target" ] && cp -a --parents "$target" "$case_dir/root/"
	done < <(find "$dst" -type l)
}

# in_case <case dir> <script>: runs script (bash, as root) with /etc/pw-<name> from the
# case present in an overlay /etc; $PW is /etc/pw-<name>, $CASE the case dir.
in_case() {
	local case_dir=$repo/$1 script=$2
	local src
	src=$(ls -d "$case_dir"/root/etc/pw-*)
	sudo unshare --mount --propagation private env CASE="$case_dir" SRC="$src" REPO="$repo" bash -euo pipefail -c '
		mount -t tmpfs pw-fixtures /mnt
		mkdir /mnt/upper /mnt/work
		mount -t overlay overlay -o lowerdir=/etc,upperdir=/mnt/upper,workdir=/mnt/work /etc
		PW=/etc/$(basename "$SRC")
		cp -a "$SRC" "$PW"
		cd "$REPO"
		'"$script"
}

if command -v nginx >/dev/null; then
	copy_tree /etc/nginx "$nginx_td/ubuntu-default"
	sudo nginx -T 2>/dev/null >"$nginx_td/ubuntu-default/nginx-T.txt"
	for c in "$nginx_td"/*/; do
		ls -d "$c"root/etc/pw-* >/dev/null 2>&1 || continue
		in_case "$c" 'nginx -T -c "$PW/nginx.conf" 2>/dev/null >"$CASE/nginx-T.txt"'
	done
	echo "nginx fixtures recorded"
fi

if command -v apache2 >/dev/null; then
	apache_dump='set +u -a; . /etc/apache2/envvars; set +a
		/usr/sbin/apache2 -d "$ROOTDIR" -S 2>&1 | grep -v AH00558 >"$CASE/apache2-S.txt"
		/usr/sbin/apache2 -d "$ROOTDIR" -t -D DUMP_INCLUDES 2>&1 | grep -v AH00558 >"$CASE/apache2-includes.txt"'
	copy_tree /etc/apache2 "$apache_td/ubuntu-default"
	# Keep only what Apache reads: *-available files that nothing enables, and the
	# mime_magic data, are left out of the fixture.
	for f in "$apache_td"/ubuntu-default/root/etc/apache2/{mods,conf,sites}-available/*; do
		enabled=${f/-available\//-enabled/}
		[ -e "$enabled" ] || rm -- "$f"
	done
	rm -f -- "$apache_td/ubuntu-default/root/etc/apache2/magic"
	CASE=$apache_td/ubuntu-default ROOTDIR=/etc/apache2 bash -c "$apache_dump"
	for c in "$apache_td"/*/; do
		ls -d "$c"root/etc/pw-* >/dev/null 2>&1 || continue
		in_case "$c" 'ROOTDIR=$PW; '"$apache_dump"
	done
	echo "apache fixtures recorded"
fi

if command -v haproxy >/dev/null; then
	copy_tree /etc/haproxy "$haproxy_td/ubuntu-default"
	haproxy -c -f /etc/haproxy/haproxy.cfg >"$haproxy_td/ubuntu-default/haproxy-c.txt" 2>&1
	for c in "$haproxy_td"/*/; do
		ls -d "$c"root/etc/pw-* >/dev/null 2>&1 || continue
		in_case "$c" 'haproxy -c -f "$PW/haproxy.cfg" >"$CASE/haproxy-c.txt" 2>&1'
	done
	# The runtime case: start it, change it over the stats socket, record the servers
	# state the agent reads (internal/proxy/admin asks "show servers state").
	in_case "$haproxy_td/runtime/" '
		cli() { python3 -c "import socket,sys
s=socket.socket(socket.AF_UNIX); s.connect(\"/tmp/pw-runtime-admin.sock\")
s.sendall(sys.argv[1].encode()+b\"\n\"); out=b\"\"
while True:
    b=s.recv(65536)
    if not b: break
    out+=b
sys.stdout.write(out.decode())" "$1"; }
		haproxy -D -f "$PW/haproxy.cfg" -p /tmp/pw-runtime.pid
		trap "kill \$(cat /tmp/pw-runtime.pid); rm -f /tmp/pw-runtime-admin.sock /tmp/pw-runtime.pid" EXIT
		for _ in $(seq 50); do [ -S /tmp/pw-runtime-admin.sock ] && break; sleep 0.1; done
		cli "set server app/s2 addr 127.0.0.9 port 7009" >/dev/null
		cli "disable server app/s1" >/dev/null
		cli "add server app/extra 127.0.0.1:7300" >/dev/null
		cli "disable server app/gone" >/dev/null
		cli "del server app/gone" >/dev/null
		cli "show servers state" | sed -E "s/^([0-9]+ [^ ]+ [0-9]+ [^ ]+ [^ ]+ [0-9]+ [0-9]+ [0-9]+ [0-9]+) [0-9]+ /\1 0 /" >"$CASE/servers-state.txt"'
	echo "haproxy fixtures recorded"
fi

# Caddy: run each case's Caddyfile and record what the admin API says it runs (GET
# /config/). The admin address is the case's own (its global "admin" option).
if command -v caddy >/dev/null; then
	for c in internal/proxy/caddy/testdata/*/; do
		[ -f "$c/Caddyfile" ] || continue
		admin=$(sed -n 's/^[[:space:]]*admin[[:space:]]\+\([^[:space:]]*\).*/\1/p' "$c/Caddyfile" | head -1)
		sudo caddy run --config "$c/Caddyfile" --adapter caddyfile >/dev/null 2>&1 &
		for _ in $(seq 50); do curl -fsS "http://$admin/config/" >/dev/null 2>&1 && break; sleep 0.1; done
		curl -fsS "http://$admin/config/" | python3 -m json.tool --indent 1 >"$c/config.json"
		curl -fsS -X POST "http://$admin/stop" >/dev/null || sudo pkill -f "caddy run --config $c/Caddyfile"
		wait
	done
	echo "caddy fixtures recorded"
fi
