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
	apache_dump='set -a; . /etc/apache2/envvars; set +a
		/usr/sbin/apache2 -d "$ROOTDIR" -S 2>&1 | grep -v AH00558 >"$CASE/apache2-S.txt"
		/usr/sbin/apache2 -d "$ROOTDIR" -t -D DUMP_INCLUDES 2>&1 | grep -v AH00558 >"$CASE/apache2-includes.txt"'
	copy_tree /etc/apache2 "$apache_td/ubuntu-default"
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
	echo "haproxy fixtures recorded"
fi
