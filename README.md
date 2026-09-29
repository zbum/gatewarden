# Gatewarden

Gatewarden follows Linux OpenSSH authentication logs, counts failed logins per remote IP in a rolling window, and temporarily blocks repeat offenders with a dedicated `nftables` table. It uses only the Go standard library.

> Runtime support is Linux-only because Gatewarden invokes `journalctl`/`tail` and `nft`. Cross-platform build targets are provided, but Windows and macOS binaries cannot enforce firewall bans.

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

Gatewarden needs root or `CAP_NET_ADMIN`. Start with dry-run mode to validate settings without changing the firewall:

```sh
sudo ./build/gatewarden-linux-amd64 -dry-run -journal-unit ssh
sudo ./build/gatewarden-linux-amd64 -journal-unit sshd
sudo ./build/gatewarden-linux-amd64 -log-file /var/log/auth.log
```

On startup Gatewarden creates its dedicated `inet gatewarden` table and refuses to start if that name already exists; it never deletes pre-existing firewall state. On graceful shutdown it removes its table. After a crash, inspect and remove a stale table with `sudo nft delete table inet gatewarden` before restarting.

Before enabling enforcement, add every administrator address or management network to `-allowlist`. The default protects loopback only and cannot infer the IP from which you administer the server. Test the exact service command with `-dry-run` while keeping a second SSH session open.

| Flag | Default | Meaning |
| --- | --- | --- |
| `-log-file` | empty | Follow this file with `tail -F`; when empty, use journald |
| `-journal-unit` | `ssh` | Unit passed to `journalctl -u` (`sshd` on some distributions) |
| `-window` | `5m` | Rolling interval used to count failures |
| `-threshold` | `5` | Failures inside the window before blocking |
| `-ban-duration` | `15m` | How long an address remains blocked |
| `-allowlist` | `127.0.0.0/8,::1/128` | Comma-separated IP addresses or CIDRs never blocked |
| `-nft-binary` | `nft` | nft executable name or path |
| `-nft-table` | `gatewarden` | Dedicated nftables inet table name |
| `-dry-run` | `false` | Log nft commands without executing them |

The service recognizes common OpenSSH failed-password/public-key, invalid-user, PAM authentication-failure, and pre-authentication close records. Duplicate bans are suppressed and expired bans are removed.

## systemd

```sh
sudo make install
sudo systemctl daemon-reload
sudo systemctl enable --now gatewarden
journalctl -u gatewarden -f
```

Adapt `ssh` to `sshd` if needed. The unit grants `CAP_NET_ADMIN`, uses a read-only filesystem view, and restarts after unexpected failures. Packages install `nftables` as a runtime dependency but deliberately do not enable or start Gatewarden.
