# Gatewarden

Gatewarden follows Linux OpenSSH authentication logs, counts failed logins per remote IP in a rolling window, and blocks repeat offenders with an eBPF/XDP IP map. A block expires after the ban duration. An address that keeps earning bans is blocked permanently.

> Runtime support is Linux-only because enforcement uses eBPF/XDP. Cross-platform build targets are provided, but Windows and macOS binaries cannot enforce firewall bans.

## Build and test

Go 1.26 or newer is required.

```sh
make test
make build-linux
make build-all
make deb
make rpm
```

Docker 기반 deb/RPM 빌드, apt/yum 설치, Jenkins 릴리스 게시 흐름은 [INSTALL.md](INSTALL.md)를 참고하십시오.

## Run

eBPF needs an Ethernet ingress interface, Linux XDP BPF-link support (upstream 5.9+), and `CAP_BPF` plus `CAP_NET_ADMIN`. Start with dry-run mode to validate settings without attaching the XDP program:

```sh
sudo ./dist/gatewarden-linux-amd64 -interface eth0 -dry-run -journal-unit ssh
sudo ./dist/gatewarden-linux-amd64 -interface eth0 -journal-unit sshd
sudo ./dist/gatewarden-linux-amd64 -interface eth0 -log-file /var/log/auth.log
```

Before enabling enforcement, add every administrator address or management network to `-allowlist`. The default protects loopback only and cannot infer the IP from which you administer the server. Test the exact service command with `-dry-run` while keeping a second SSH session open.

| Flag | Default | Meaning |
| --- | --- | --- |
| `-log-file` | empty | Follow this file with `tail -F`; when empty, use journald |
| `-journal-unit` | `ssh`, or `GATEWARDEN_JOURNAL_UNIT` | Unit passed to `journalctl -u`. Ubuntu uses `ssh`; Rocky and RHEL use `sshd` |
| `-window` | `5m` | Rolling interval used to count failures |
| `-threshold` | `5` | Failures inside the window before blocking |
| `-ban-duration` | `15m` | How long a temporary block lasts |
| `-permanent-after` | `3`, or `GATEWARDEN_PERMANENT_AFTER` | Temporary bans inside `-permanent-window` that promote the address to a permanent block. `0` disables permanent bans |
| `-permanent-window` | `24h`, or `GATEWARDEN_PERMANENT_WINDOW` | How far back a ban still counts toward a permanent block |
| `-allowlist` | `127.0.0.0/8,::1/128`, or `GATEWARDEN_ALLOWLIST` | Comma-separated IP addresses or CIDRs never blocked |
| `-interface` | `GATEWARDEN_INTERFACE` | Required Ethernet ingress interface for the XDP program |
| `-metrics-addr` | `127.0.0.1:9477`, or `GATEWARDEN_METRICS_ADDR` | HTTP listen address for `/metrics` and the read-only blocks list |
| `-state-file` | `/var/lib/gatewarden/state.json`, or `GATEWARDEN_STATE_FILE` | Permanent bans and recent ban times. Restored after restart |
| `-socket` | `/run/gatewarden/gatewarden.sock`, or `GATEWARDEN_SOCKET` | Unix socket for `blocks` and `unblock`, mode 0600 |
| `-dry-run` | `false` | Log changes without opening BPF objects |

The service recognizes common OpenSSH failed-password/public-key, invalid-user, PAM authentication-failure, and pre-authentication close records. Duplicate bans are suppressed and expired bans are removed.

## Current blocks and metrics

One ban is counted when an address reaches `-threshold` failures inside `-window`. The same address becomes permanent on the ban that reaches `-permanent-after` bans inside `-permanent-window`. Further failures from a permanently blocked address are ignored. Allowlisted addresses are never banned; an address that was banned before it was allowlisted stays blocked until `unblock`.

`sudo gatewarden blocks` prints the addresses blocked right now. Temporary rows show a UTC expiry. Permanent rows show `permanent` in the `EXPIRES` and `KIND` columns. `sudo gatewarden unblock <ip>` removes the live block, the permanent record, and the strike history, so the address must earn `-permanent-after` bans again. Both commands talk to the mode 0600 socket. The metrics TCP port is read-only.

```sh
sudo gatewarden blocks
sudo gatewarden unblock 203.0.113.10
```

Permanent bans and strike times are stored in `-state-file`. After a restart, permanent bans are inserted into the new XDP map. A restart ends a temporary block immediately, while its strike still counts. When the daemon is stopped, `blocks` and `unblock` read and edit that file directly. `unblock` of an address that is not blocked returns an error.

Prometheus scrapes `http://127.0.0.1:9477/metrics`. `gatewarden_blocked_current` counts temporary and permanent blocks. `gatewarden_permanent_current` and `gatewarden_permanent{ip="..."}` describe permanent blocks. `gatewarden_block_until_seconds{ip="..."}` is the Unix expiry of each temporary block. `gatewarden_failures_total`, `gatewarden_blocks_total`, and `gatewarden_unblocks_total` count events since the process started. `gatewarden_unblocks_total` counts expiry only.

[deploy/grafana/gatewarden.json](deploy/grafana/gatewarden.json) is a Grafana dashboard for these series. Import it and choose the Prometheus datasource. The job variable defaults to `gatewarden`. Counters on the dashboard reset when the process restarts.

## systemd

```sh
sudo make install
sudo systemctl daemon-reload
sudo systemctl enable --now gatewarden
journalctl -u gatewarden -f
```

The packaged unit reads `/etc/gatewarden/gatewarden.env` and passes no interface name of its own. Ubuntu packages default the journal unit to `ssh`. Rocky and RHEL packages default it to `sshd`. Set the interface to the host device, listed by `ip -br link`, before starting. The unit grants `CAP_BPF` and `CAP_NET_ADMIN`, allows unlimited locked memory, and uses a read-only filesystem view. `StateDirectory=gatewarden` and `RuntimeDirectory=gatewarden` provide `/var/lib/gatewarden` and `/run/gatewarden`. The unit restarts after unexpected failures. Packages deliberately do not enable or start Gatewarden. See [INSTALL.md](INSTALL.md).

## eBPF behavior and verification

XDP drops all ingress traffic from blocked IPv4/IPv6 sources on the selected
interface, including traffic for existing sessions and forwarded traffic. It does
not send TCP resets. Other interfaces and inner tunnel headers are not inspected.
Ethernet and up to two 802.1Q/802.1ad tags are supported; non-IP and incomplete
headers pass. Generic XDP is used; no existing XDP program is replaced. Startup
fails if attachment is unavailable.

The unpinned link and map are released when the process exits, including crashes.
Temporary bans end with the process. Permanent bans and the strike times used to
decide them are stored in `/var/lib/gatewarden/state.json` and inserted into the
new map after the next start. The map holds up to 65,536 IPs; insertion failures
are reported rather than silently evicting bans. `-dry-run` validates configuration
without checking kernel support or interface existence.

Run portable checks with `make check` and `make build-all`. On a disposable Linux
host/container with BPF and NET_ADMIN privileges, run:

```sh
GATEWARDEN_TEST_EBPF=1 go test -v -run TestKernel .
# Optional attachment test; use only a disposable Ethernet interface:
GATEWARDEN_TEST_EBPF=1 GATEWARDEN_TEST_INTERFACE=eth0 go test -v -run TestKernel .
```

Dependency rationale: [ADR 001](docs/adr/001-ebpf-firewall.md).

## License

Gatewarden is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 2 of the License, or (at your option) any later version. See [LICENSE](LICENSE). Change history is recorded in [CHANGELOG.md](CHANGELOG.md).
