#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

: "${NEXUS_USER:?set NEXUS_USER}"
: "${NEXUS_PASS:?set NEXUS_PASS}"
NEXUS_URL=${NEXUS_URL:-https://nexus.manty.co.kr}
NEXUS_APT_REPO=${NEXUS_APT_REPO:-apt-hosted}
NEXUS_APT_DISTRIBUTION=${NEXUS_APT_DISTRIBUTION:-stable}
NEXUS_URL=${NEXUS_URL%/}

if [[ ${SKIP_PACKAGE_BUILD:-0} != 1 ]]; then
	"$root/scripts/build-deb.sh"
fi

# shellcheck disable=SC1091
source dist/deb/latest.env
deb_file="$root/$DEB_PATH"
[[ -f "$deb_file" ]] || { echo "missing $deb_file" >&2; exit 1; }

name=$(basename "$deb_file")
repo_url="$NEXUS_URL/repository/$NEXUS_APT_REPO"
upload_url="$NEXUS_URL/service/rest/v1/components?repository=$NEXUS_APT_REPO"
host=${NEXUS_URL#*://}
host=${host%%/*}
netrc=$(mktemp)
chmod 600 "$netrc"
trap 'rm -f "$netrc"' EXIT
cat > "$netrc" <<EOF
machine $host
login $NEXUS_USER
password $NEXUS_PASS
EOF

echo "uploading $name"
curl --fail --silent --show-error --netrc-file "$netrc" \
	-X POST -H 'accept: application/json' -F "apt.asset=@${deb_file}" "$upload_url"
echo

packages_base="$repo_url/dists/$NEXUS_APT_DISTRIBUTION/main/binary-$DEB_ARCH"
deadline=$((SECONDS + 90))
found=0
while ((SECONDS < deadline)); do
	plain=$(curl --fail --silent --show-error --netrc-file "$netrc" "$packages_base/Packages" 2>/dev/null || true)
	compressed=$(curl --fail --silent --show-error --netrc-file "$netrc" "$packages_base/Packages.gz" 2>/dev/null | gzip -dc 2>/dev/null || true)
	if printf '%s\n%s\n' "$plain" "$compressed" | grep -Fq "$name"; then
		found=1
		break
	fi
	sleep 3
done
[[ $found -eq 1 ]] || { echo "uploaded, but apt metadata does not list $name" >&2; exit 1; }
echo "apt metadata contains $name"
