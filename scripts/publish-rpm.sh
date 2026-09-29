#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

: "${NEXUS_USER:?set NEXUS_USER}"
: "${NEXUS_PASS:?set NEXUS_PASS}"
NEXUS_URL=${NEXUS_URL:-https://nexus.manty.co.kr}
NEXUS_YUM_REPO=${NEXUS_YUM_REPO:-yum-hosted}
NEXUS_URL=${NEXUS_URL%/}

if [[ ${SKIP_PACKAGE_BUILD:-0} != 1 ]]; then
	"$root/scripts/build-rpm.sh"
fi

# shellcheck disable=SC1091
source dist/rpm/latest.env
rpm_file="$root/$RPM_PATH"
[[ -f "$rpm_file" ]] || { echo "missing $rpm_file" >&2; exit 1; }

name=$(basename "$rpm_file")
repo_url="$NEXUS_URL/repository/$NEXUS_YUM_REPO/gatewarden/"
upload_url="${repo_url}${name}"
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
curl --fail --silent --show-error --netrc-file "$netrc" --upload-file "$rpm_file" "$upload_url"
echo

deadline=$((SECONDS + 90))
found=0
while ((SECONDS < deadline)); do
	if xml=$(curl --fail --silent --show-error --netrc-file "$netrc" "${repo_url}repodata/repomd.xml" 2>/dev/null); then
		href=$(printf '%s\n' "$xml" | sed -n 's/.*href="\([^"]*primary.xml.gz\)".*/\1/p' | head -n 1)
		if [[ -n "$href" ]] && curl --fail --silent --show-error --netrc-file "$netrc" \
			"$repo_url$href" | gzip -dc | grep -Fq "$name"; then
			found=1
			break
		fi
	fi
	sleep 3
done
[[ $found -eq 1 ]] || { echo "uploaded, but yum metadata does not list $name" >&2; exit 1; }
echo "yum metadata contains $name"
