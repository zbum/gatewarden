#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

for script in scripts/*.sh; do
	bash -n "$script"
done

grep -Fq 'EnvironmentFile=-/etc/gatewarden/gatewarden.env' deploy/systemd/gatewarden.service
grep -Fq 'ExecStart=/usr/bin/gatewarden' deploy/systemd/gatewarden.service
grep -Fq 'After=network-online.target ssh.service sshd.service' deploy/systemd/gatewarden.service
grep -Fq 'CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN' deploy/systemd/gatewarden.service
if grep -Eq 'eth0|-journal-unit|-interface' deploy/systemd/gatewarden.service; then
	echo 'unit must take the interface and journal unit from the environment file' >&2
	exit 1
fi
grep -Fq 'GATEWARDEN_JOURNAL_UNIT=ssh' deploy/debian/gatewarden.default
grep -Fq 'GATEWARDEN_JOURNAL_UNIT=sshd' deploy/rpm/gatewarden.sysconfig
if grep -Eq '^GATEWARDEN_INTERFACE=.+' deploy/debian/gatewarden.default deploy/rpm/gatewarden.sysconfig; then
	echo 'packages must not guess an interface name' >&2
	exit 1
fi
grep -Fq 'License:        GPL-2.0-or-later' deploy/rpm/gatewarden.spec
grep -Fq '%license /usr/share/licenses/gatewarden/LICENSE' deploy/rpm/gatewarden.spec
grep -Fq 'GNU GENERAL PUBLIC LICENSE' LICENSE
grep -Fq 'either version 2' LICENSE
grep -Fq 'any later version' LICENSE
grep -Fq '%config(noreplace) /etc/gatewarden/gatewarden.env' deploy/rpm/gatewarden.spec
grep -Fq '/etc/gatewarden/gatewarden.env' scripts/build-deb.sh
grep -Fq 'gatewarden.sysconfig' scripts/build-rpm.sh
if grep -REq '/etc/default/gatewarden|/etc/sysconfig/gatewarden' \
	deploy Makefile README.md INSTALL.md scripts/build-deb.sh scripts/build-rpm.sh; then
	echo 'configuration must live in /etc/gatewarden' >&2
	exit 1
fi
if grep -Eq 'nft' deploy/systemd/gatewarden.service scripts/build-deb.sh deploy/rpm/gatewarden.spec; then
	echo 'packages must enforce blocks with eBPF only' >&2
	exit 1
fi
if grep -REq --include='*.go' 'nft' .; then
	echo 'Go sources must enforce blocks with eBPF only' >&2
	exit 1
fi
if grep -REq 'systemctl[[:space:]]+enable|systemctl[[:space:]]+start' deploy scripts/build-deb.sh scripts/build-rpm.sh; then
	echo 'package lifecycle must not enable or start gatewarden' >&2
	exit 1
fi

test "$(scripts/package-version.sh)" = "$(tr -d '[:space:]' < VERSION)"
echo 'package invariants passed'
