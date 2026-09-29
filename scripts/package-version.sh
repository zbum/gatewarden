#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

if [[ -f VERSION ]]; then
	version=$(tr -d '[:space:]' < VERSION)
	if [[ ! "$version" =~ ^[0-9]+(\.[0-9A-Za-z]+)*$ ]]; then
		echo "invalid VERSION: $version" >&2
		exit 1
	fi
	printf '%s\n' "$version"
	exit 0
fi

hash=unknown
dirty=""
if git rev-parse --verify HEAD >/dev/null 2>&1; then
	hash=$(git rev-parse --short=12 HEAD)
	if [[ -n "$(git status --porcelain)" ]]; then
		dirty=".dirty"
	fi
fi
printf '0.0.0+%s.%s%s\n' "$(date -u +%Y%m%d%H%M%S)" "$hash" "$dirty"
