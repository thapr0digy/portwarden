#!/usr/bin/env bash
# Builds the release artifacts (make dist): static binaries for linux/amd64 and
# linux/arm64, a .deb per architecture for portwarden-agent and portwarden-backend,
# a CycloneDX SBOM per binary, and SHA256SUMS. Runs on Linux or macOS with the pinned Go
# toolchain (go.mod); nFPM and cyclonedx-gomod run with `go run` at pinned versions.
#
# Reproducible: CGO off, -trimpath, -buildvcs=false, no build id, the version stamped
# with -X, and every file time in the packages set to the last commit's time
# (SOURCE_DATE_EPOCH). `dev/dist.sh --check` builds everything again in a temp directory
# and fails unless the binaries and packages are byte-identical to dist/.
#
# Environment: VERSION (default: from the latest v* tag, else 0.0.0~git<date>.<sha>),
# SOURCE_DATE_EPOCH and COMMIT (default: from git; set all three to build without git),
# DIST_DIR (default dist), ARCHES (default "amd64 arm64"), SBOM=0 skips the SBOMs.
# CYCLONEDX and NFPM below are tools, built for the host from the module cache when it
# holds them (see install_tool), so a build needs no network once they were fetched.
set -euo pipefail
cd "$(dirname "$0")/.."

NFPM=github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.46.3
CYCLONEDX=github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.12.0
COMMANDS=(agent inventory alerter verifier natsauth watch)
ARCHES=${ARCHES:-amd64 arm64}

check=false
if [ "${1:-}" = --check ]; then
	check=true
fi

# safe_dist_dir <absolute path>: fails, saying why, for /, $HOME or a top-level directory.
safe_dist_dir() {
	local d=${1%/}
	if [ -z "$d" ] || [ "$d" = "${HOME%/}" ] || [ "$(printf '%s' "$d" | tr -cd / | wc -c | tr -d ' ')" -lt 2 ]; then
		echo "dist: refusing DIST_DIR=${1} (/, \$HOME or a top-level directory)" >&2
		return 1
	fi
}

# install_tool <pkg@version> <dir>: builds a pinned tool into dir. First from the module
# cache alone (GOPROXY=file://...): `go install pkg@version` otherwise asks the proxy
# about the package's own path and the module's deprecation even when the module is
# cached, so a slow or unreachable proxy failed the build at random. Falls back to the
# configured GOPROXY when the cache lacks the tool.
install_tool() {
	local tool=$1 dir=$2 cache
	cache="file://$(go env GOMODCACHE)/cache/download"
	GOBIN="$dir" GOPROXY="$cache" go install "$tool" 2>/dev/null && return 0
	echo "dist: $tool is not in the module cache; fetching it" >&2
	GOBIN="$dir" go install "$tool"
}

sha256() {
	if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}

SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}
export SOURCE_DATE_EPOCH
if [ -z "${VERSION:-}" ]; then
	# Past a tag the commit time (to the second) leads the commit id, so successive
	# builds sort upward in dpkg (the id alone is not ordered): X+gitYYYYMMDDHHMMSS.<sha>
	# after tag vX, 0.0.0~gitYYYYMMDDHHMMSS.<sha> before any tag.
	stamp=$(date -u -r "$SOURCE_DATE_EPOCH" +%Y%m%d%H%M%S 2>/dev/null || date -u -d "@$SOURCE_DATE_EPOCH" +%Y%m%d%H%M%S)
	sha=$(git rev-parse --short=7 HEAD)
	if tag=$(git describe --tags --match 'v[0-9]*' --abbrev=0 2>/dev/null); then
		VERSION=${tag#v}
		[ "$(git rev-list -n1 "$tag")" = "$(git rev-parse HEAD)" ] || VERSION="$VERSION+git$stamp.$sha"
	else
		VERSION="0.0.0~git$stamp.$sha"
	fi
fi
mtime=$(date -u -r "$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)

if $check; then
	[ -f dist/SHA256SUMS ] || { echo "dist: no dist/SHA256SUMS to check against; run make dist first" >&2; exit 1; }
	tmp=$(mktemp -d)
	trap 'rm -rf "${tmp:?}"' EXIT
	DIST_DIR="$tmp/dist" VERSION="$VERSION" "$0" >/dev/null
	if diff dist/SHA256SUMS "$tmp/dist/SHA256SUMS"; then
		echo "dist: reproducible: a second build is byte-identical ($(wc -l <dist/SHA256SUMS | tr -d ' ') files)"
		exit 0
	fi
	echo "dist: NOT reproducible: the files above differ between two builds" >&2
	exit 1
fi

out=${DIST_DIR:-dist}
case "$out" in /*) ;; *) out="$PWD/$out" ;; esac
# bin/, sbom/ and work/ under it are cleared below: refuse anything that is not plainly
# a build directory (/, $HOME, a top-level directory such as /usr).
safe_dist_dir "$out" || exit 1
if [ -d "$out" ]; then
	rm -rf "${out:?}/bin" "${out:?}/sbom" "${out:?}/work"
	rm -f "${out:?}"/*.deb "${out:?}/SHA256SUMS"
fi
mkdir -p "$out/bin" "$out/work"
echo "dist: version $VERSION, SOURCE_DATE_EPOCH $SOURCE_DATE_EPOCH ($mtime), into $out"

ldflags="-s -w -buildid= -X github.com/thapr0digy/portwarden/internal/version.Version=$VERSION"
for arch in $ARCHES; do
	for c in "${COMMANDS[@]}"; do
		CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -buildvcs=false -ldflags "$ldflags" \
			-o "$out/bin/linux_$arch/portwarden-$c" "./cmd/portwarden-$c"
	done
done

# A minimal Debian changelog (lintian wants one); gzip -n leaves out name and time.
cat >"$out/work/changelog.Debian" <<CHANGELOG
portwarden ($VERSION-1) unstable; urgency=medium

  * Build of ${COMMIT:-$(git rev-parse HEAD)}.

 -- thapr0digy <thapr0digy@users.noreply.github.com>  $(LC_ALL=C date -u -r "$SOURCE_DATE_EPOCH" '+%a, %d %b %Y %H:%M:%S +0000' 2>/dev/null || LC_ALL=C date -u -d "@$SOURCE_DATE_EPOCH" '+%a, %d %b %Y %H:%M:%S +0000')
CHANGELOG
gzip -n -9 <"$out/work/changelog.Debian" >"$out/work/changelog.Debian.gz"

install_tool "$NFPM" "$out/work"

# The nFPM configs name ${PW_*} placeholders; nFPM does not expand them everywhere
# (contents, mtime), so they are substituted here into a rendered copy.
for arch in $ARCHES; do
	for pkg in agent backend; do
		sed -e "s#\${PW_ARCH}#$arch#g" -e "s#\${PW_VERSION}#$VERSION#g" -e "s#\${PW_MTIME}#$mtime#g" \
			-e "s#\${PW_BIN}#$out/bin/linux_$arch#g" -e "s#\${PW_WORK}#$out/work#g" \
			"deploy/packaging/nfpm-$pkg.yaml" >"$out/work/nfpm-$pkg-$arch.yaml"
		"$out/work/nfpm" pkg --packager deb --config "$out/work/nfpm-$pkg-$arch.yaml" --target "$out/" >/dev/null
	done
done

if [ "${SBOM:-1}" != 0 ]; then
	mkdir -p "$out/sbom"
	# cyclonedx-gomod reads each binary's embedded build info (bin mode: it needs no git
	# metadata, which it cannot read in a git worktree); no serial or time, so the SBOMs
	# are reproducible too.
	install_tool "$CYCLONEDX" "$out/work"
	for arch in $ARCHES; do
		for c in "${COMMANDS[@]}"; do
			# GOOS/GOARCH: it labels the purls with them (its own platform otherwise).
			GOOS=linux GOARCH=$arch "$out/work/cyclonedx-gomod" bin -json -noserial -notimestamp -version "$VERSION" \
				-output "$out/sbom/portwarden-${c}_linux_$arch.cdx.json" "$out/bin/linux_$arch/portwarden-$c" 2>/dev/null ||
				{ echo "dist: SBOM for portwarden-$c ($arch) failed" >&2; exit 1; }
		done
	done
fi

rm -rf "${out:?}/work"
(cd "$out" && sha256 bin/*/* ./*.deb $( [ -d sbom ] && echo sbom/*) | sed 's# \./# #' >SHA256SUMS)
echo "dist: done"
ls -l "$out"/*.deb
