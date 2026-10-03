#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

GOARCH=${GOARCH:-amd64}
case "$GOARCH" in
amd64) RPM_ARCH=x86_64 ;;
arm64) RPM_ARCH=aarch64 ;;
*)
	echo "unsupported GOARCH=$GOARCH (use amd64 or arm64)" >&2
	exit 1
	;;
esac

RELEASE=${RPM_RELEASE:-1}
if [[ ! "$RELEASE" =~ ^[0-9A-Za-z._]+$ ]]; then
	echo "invalid RPM_RELEASE=$RELEASE" >&2
	exit 1
fi
VERSION=$("$root/scripts/package-version.sh")
if [[ ! "$VERSION" =~ ^[0-9A-Za-z._+~]+$ ]]; then
	echo "invalid RPM version: $VERSION" >&2
	exit 1
fi

command -v docker >/dev/null 2>&1 || { echo "docker is required to build the RPM" >&2; exit 1; }
make build-linux "GOARCH=$GOARCH"

image=${RPM_BUILD_IMAGE:-gatewarden-rpm-build:8}
platform=${RPM_BUILD_PLATFORM:-linux/amd64}
"$root/scripts/ensure-build-image.sh" "$image" "$root/deploy/docker/rpm-build.Dockerfile" "$platform"

docker run --rm -i \
	--platform "$platform" \
	-u "$(id -u):$(id -g)" \
	-e HOME=/tmp \
	-e "VERSION=$VERSION" \
	-e "RELEASE=$RELEASE" \
	-e "RPM_ARCH=$RPM_ARCH" \
	-e "GOARCH=$GOARCH" \
	-v "$root:/work" \
	-w /work \
	"$image" \
	bash -s <<'EOS'
set -euo pipefail
top=$(mktemp -d)
trap 'rm -rf "$top"' EXIT
mkdir -p "$top"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
cp "dist/gatewarden-linux-$GOARCH" "$top/SOURCES/gatewarden"
cp deploy/systemd/gatewarden.service "$top/SOURCES/gatewarden.service"
cp deploy/rpm/gatewarden.sysconfig "$top/SOURCES/gatewarden.sysconfig"
cp deploy/rpm/gatewarden.spec "$top/SPECS/gatewarden.spec"
rpmbuild -bb \
	--define "_topdir $top" \
	--define "gw_version $VERSION" \
	--define "gw_release $RELEASE" \
	--define "gw_arch $RPM_ARCH" \
	--target "$RPM_ARCH" \
	"$top/SPECS/gatewarden.spec"
mkdir -p /work/dist/rpm
find "$top/RPMS" -type f -name '*.rpm' -exec cp -f {} /work/dist/rpm/ \;
EOS

rpm_path="dist/rpm/gatewarden-${VERSION}-${RELEASE}.${RPM_ARCH}.rpm"
[[ -f "$rpm_path" ]] || { echo "rpmbuild did not produce $rpm_path" >&2; exit 1; }
cat > dist/rpm/latest.env <<EOF
VERSION=$VERSION
RELEASE=$RELEASE
RPM_ARCH=$RPM_ARCH
RPM_PATH=$rpm_path
EOF
echo "built $rpm_path"
