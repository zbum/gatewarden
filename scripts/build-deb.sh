#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

GOARCH=${GOARCH:-amd64}
case "$GOARCH" in
amd64) DEB_ARCH=amd64 ;;
arm64) DEB_ARCH=arm64 ;;
*)
	echo "unsupported GOARCH=$GOARCH (use amd64 or arm64)" >&2
	exit 1
	;;
esac

revision=${DEB_REVISION:-1}
if [[ ! "$revision" =~ ^[0-9A-Za-z.+~]+$ ]]; then
	echo "invalid DEB_REVISION=$revision" >&2
	exit 1
fi
package_version=$("$root/scripts/package-version.sh")
if [[ ! "$package_version" =~ ^[0-9][0-9A-Za-z.+~]*$ ]]; then
	echo "invalid package version: $package_version" >&2
	exit 1
fi
DEB_VERSION="${package_version}-${revision}"

command -v docker >/dev/null 2>&1 || { echo "docker is required to build the deb" >&2; exit 1; }
make build-linux "GOARCH=$GOARCH"

image=${DEB_BUILD_IMAGE:-gatewarden-deb-build:22.04}
platform=${DEB_BUILD_PLATFORM:-linux/amd64}
"$root/scripts/ensure-build-image.sh" "$image" "$root/deploy/docker/deb-build.Dockerfile" "$platform"

docker run --rm -i \
	--platform "$platform" \
	-u "$(id -u):$(id -g)" \
	-e HOME=/tmp \
	-e "DEB_VERSION=$DEB_VERSION" \
	-e "DEB_ARCH=$DEB_ARCH" \
	-e "GOARCH=$GOARCH" \
	-v "$root:/work" \
	-w /work \
	"$image" \
	bash -s <<'EOS'
set -euo pipefail
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/DEBIAN" "$stage/usr/bin" "$stage/usr/lib/systemd/system"
install -m 0755 "dist/gatewarden-linux-$GOARCH" "$stage/usr/bin/gatewarden"
install -m 0644 deploy/systemd/gatewarden.service "$stage/usr/lib/systemd/system/gatewarden.service"
installed=$(du -sk "$stage/usr" | awk '{sum += $1} END {print sum}')
cat > "$stage/DEBIAN/control" <<EOF
Package: gatewarden
Version: $DEB_VERSION
Architecture: $DEB_ARCH
Maintainer: gatewarden <gatewarden@manty.co.kr>
Installed-Size: $installed
Depends: nftables
Section: net
Priority: optional
Homepage: https://nexus.manty.co.kr/repository/apt-hosted/
Description: Blocks repeated failed SSH login sources with nftables
 Gatewarden follows OpenSSH authentication failures and temporarily blocks
 repeat offenders in a dedicated nftables table.
 The package does not enable or start the service.
EOF
cat > "$stage/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
systemctl daemon-reload >/dev/null 2>&1 || true
EOF
cat > "$stage/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "remove" ]; then
	systemctl --no-reload disable --now gatewarden.service >/dev/null 2>&1 || true
fi
EOF
cat > "$stage/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
systemctl daemon-reload >/dev/null 2>&1 || true
if [ "$1" = "upgrade" ]; then
	systemctl try-restart gatewarden.service >/dev/null 2>&1 || true
fi
EOF
chmod 0755 "$stage/DEBIAN/postinst" "$stage/DEBIAN/prerm" "$stage/DEBIAN/postrm"
mkdir -p /work/dist/deb
dpkg-deb --root-owner-group --build "$stage" "/work/dist/deb/gatewarden_${DEB_VERSION}_${DEB_ARCH}.deb"
EOS

deb_path="dist/deb/gatewarden_${DEB_VERSION}_${DEB_ARCH}.deb"
[[ -f "$deb_path" ]] || { echo "dpkg-deb did not produce $deb_path" >&2; exit 1; }
cat > dist/deb/latest.env <<EOF
DEB_VERSION=$DEB_VERSION
DEB_ARCH=$DEB_ARCH
DEB_PATH=$deb_path
EOF
echo "built $deb_path"
