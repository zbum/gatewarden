# Gatewarden

Gatewarden follows Linux OpenSSH authentication logs, counts failed logins per remote IP in a rolling window, and temporarily blocks repeat offenders with an eBPF/XDP IP map.

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
| `-ban-duration` | `15m` | How long an address remains blocked |
| `-allowlist` | `127.0.0.0/8,::1/128`, or `GATEWARDEN_ALLOWLIST` | Comma-separated IP addresses or CIDRs never blocked |
| `-interface` | `GATEWARDEN_INTERFACE` | Required Ethernet ingress interface for the XDP program |
| `-dry-run` | `false` | Log changes without opening BPF objects |

The service recognizes common OpenSSH failed-password/public-key, invalid-user, PAM authentication-failure, and pre-authentication close records. Duplicate bans are suppressed and expired bans are removed.

## systemd

```sh
sudo make install
sudo systemctl daemon-reload
sudo systemctl enable --now gatewarden
journalctl -u gatewarden -f
```

The packaged unit reads `GATEWARDEN_INTERFACE`, `GATEWARDEN_JOURNAL_UNIT`, and `GATEWARDEN_ALLOWLIST` from `/etc/gatewarden/gatewarden.env` and passes no interface name of its own. Ubuntu packages default the journal unit to `ssh`. Rocky and RHEL packages default it to `sshd`. Set the interface to the host device, listed by `ip -br link`, before starting. The unit grants `CAP_BPF` and `CAP_NET_ADMIN`, allows unlimited locked memory, uses a read-only filesystem view, and restarts after unexpected failures. Packages deliberately do not enable or start Gatewarden. See [INSTALL.md](INSTALL.md).

## eBPF behavior and verification

XDP drops all ingress traffic from blocked IPv4/IPv6 sources on the selected
interface, including traffic for existing sessions and forwarded traffic. It does
not send TCP resets. Other interfaces and inner tunnel headers are not inspected.
Ethernet and up to two 802.1Q/802.1ad tags are supported; non-IP and incomplete
headers pass. Generic XDP is used; no existing XDP program is replaced. Startup
fails if attachment is unavailable.

The unpinned link and map are released when the process exits, including crashes;
bans are not persistent. The map holds up to 65,536 IPs; insertion failures are
reported rather than silently evicting bans. `-dry-run` validates configuration
without checking kernel support or interface existence.

Run portable checks with `make check` and `make build-all`. On a disposable Linux
host/container with BPF and NET_ADMIN privileges, run:

```sh
GATEWARDEN_TEST_EBPF=1 go test -v -run TestKernel .
# Optional attachment test; use only a disposable Ethernet interface:
GATEWARDEN_TEST_EBPF=1 GATEWARDEN_TEST_INTERFACE=eth0 go test -v -run TestKernel .
```

Dependency rationale: [ADR 001](docs/adr/001-ebpf-firewall.md).

## Changelog

- 2026-10-03 (`feature/ebpf-connection-blocking`): block repeat SSH failures with
  eBPF/XDP only. Add explicit interface selection, IPv4/IPv6 block maps, VLAN
  parsing, portable lifecycle tests, and opt-in Linux kernel tests. Detection
  remains OpenSSH authentication-log parsing. Packages take the interface,
  journal unit, and allowlist from `/etc/gatewarden/gatewarden.env`. Ubuntu
  packages default the journal unit to `ssh`; Rocky and RHEL packages default
  it to `sshd`.
