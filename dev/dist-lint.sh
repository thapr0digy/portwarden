#!/usr/bin/env bash
# Checks the packages make dist built (make dist-lint, inside the VM): each .deb's control
# data and file list (dpkg-deb), lintian with --fail-on error, the backend .deb's layout
# (/usr/bin/portwarden and a root-owned portwarden-<command> symlink to it per command),
# the two binaries' architecture and version stamp, and SHA256SUMS. Needs dpkg-deb and lintian (dev/provision.sh).
set -euo pipefail
cd "$(dirname "$0")/.."

[ -f dist/SHA256SUMS ] || { echo "dist-lint: no dist/ (run make dist first)" >&2; exit 1; }
status=0
(cd dist && sha256sum --quiet -c SHA256SUMS) || { echo "dist-lint: SHA256SUMS does not match" >&2; status=1; }
for deb in dist/*.deb; do
	echo "== $(basename "$deb")"
	dpkg-deb --field "$deb" Package Version Architecture Recommends Installed-Size
	dpkg-deb --contents "$deb" | awk '{print $1, $6}'
	if command -v lintian >/dev/null; then
		# A static Go binary and a proprietary licence are expected: report, do not fail.
		lintian --fail-on error --suppress-tags statically-linked-binary,embedded-library \
			--no-tag-display-limit "$deb" || status=1
	else
		echo "dist-lint: lintian not installed; skipped" >&2
	fi
done
# The backend .deb: one binary, and each former binary's name a root-owned relative
# symlink to it (the units' ExecStart and existing scripts use those names).
for deb in dist/portwarden-backend_*.deb; do
	contents=$(dpkg-deb --contents "$deb")
	grep -qE '^-rwxr-xr-x root/root .* \./usr/bin/portwarden$' <<<"$contents" ||
		{ echo "dist-lint: $deb: no root-owned 0755 /usr/bin/portwarden" >&2; status=1; }
	for c in inventory alerter verifier natsauth watch; do
		# (A symlink's mode is meaningless on Linux; nFPM stores it as l---------.)
		grep -qE "^l[-rwx]{9} root/root .* \./usr/bin/portwarden-$c -> portwarden\$" <<<"$contents" ||
			{ echo "dist-lint: $deb: /usr/bin/portwarden-$c is not a root-owned symlink to portwarden" >&2; status=1; }
	done
	n=$(grep -cE ' \./usr/bin/.' <<<"$contents" || true)
	[ "$n" = 6 ] || { echo "dist-lint: $deb: $n entries in /usr/bin, want portwarden and 5 symlinks" >&2; status=1; }
done
for f in dist/bin/linux_*/*; do
	arch=${f#dist/bin/linux_}
	arch=${arch%%/*}
	want=$([ "$arch" = amd64 ] && echo x86-64 || echo aarch64)
	file -b "$f" | grep -q "$want.*statically linked" || { echo "dist-lint: $f is not a static $want binary: $(file -b "$f")" >&2; status=1; }
done
host_arch=$(dpkg --print-architecture)
"dist/bin/linux_$host_arch/portwarden-agent" --version
"dist/bin/linux_$host_arch/portwarden" --version
exit "$status"
