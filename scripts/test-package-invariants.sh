#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

for script in scripts/*.sh; do
	bash -n "$script"
done

grep -Fq 'ExecStart=/usr/bin/gatewarden' deploy/systemd/gatewarden.service
grep -Fq 'Depends: nftables' scripts/build-deb.sh
grep -Fq 'Requires:       nftables' deploy/rpm/gatewarden.spec
if grep -REq 'systemctl[[:space:]]+enable|systemctl[[:space:]]+start' deploy scripts/build-deb.sh scripts/build-rpm.sh; then
	echo 'package lifecycle must not enable or start gatewarden' >&2
	exit 1
fi

test "$(scripts/package-version.sh)" = "$(tr -d '[:space:]' < VERSION)"
echo 'package invariants passed'
