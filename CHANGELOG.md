# Changelog

## Unreleased

- Watch open SSH sessions with eBPF tracepoints on `accept` and `accept4`, the following fork, and process exit. The user name comes from the session process login uid. `sshd` processes that already exist are read once from `/proc` at startup. `gatewarden sessions` and `GET /sessions` show the user, source IP, client port, process id, and start time. `gatewarden_sessions_current` and `gatewarden_session_since_seconds{user,ip,port}` expose the same list. Authentication failures still come from the journal or `-log-file`, and lines written before startup are not counted.

## 0.2.1 — 2026-10-04

- Add a Grafana dashboard for the Prometheus series at `deploy/grafana/gatewarden.json`.
- Add Grafana alert rules at `deploy/grafana/alerting.yml`. A missing scrape, any permanent block, and more than 25 concurrent blocks notify the existing contact point `slack-manty-infra`.
- Document installation from the Nexus apt repository `apt-hosted` and the yum repository `yum-hosted/gatewarden/` at https://nexus.manty.co.kr.
- Show the Grafana dashboard on the README.

## 0.2.0 — 2026-10-04

- Publish `/metrics` and a read-only `/blocks` list on `127.0.0.1:9477`.
- Promote an address to a permanent block when it reaches `GATEWARDEN_PERMANENT_AFTER` bans (default 3) inside `GATEWARDEN_PERMANENT_WINDOW` (default 24h). `0` disables promotion.
- Store permanent bans and strike times in `/var/lib/gatewarden/state.json` and restore permanent bans when the process starts.
- Add `gatewarden blocks` and `gatewarden unblock` on `/run/gatewarden/gatewarden.sock` (mode 0600). When the daemon is stopped, both commands use the state file.

## 0.1.0 — 2026-10-03

- Block repeat SSH failures with eBPF/XDP only. The packaged unit reads `GATEWARDEN_INTERFACE`, `GATEWARDEN_JOURNAL_UNIT`, and `GATEWARDEN_ALLOWLIST` from `/etc/gatewarden/gatewarden.env`.
- Ubuntu packages default the journal unit to `ssh`. Rocky and RHEL packages default it to `sshd`. The interface name is left empty until the operator sets it.
- Add IPv4/IPv6 block maps, VLAN parsing, portable lifecycle tests, and opt-in Linux kernel tests. Failure detection remains OpenSSH authentication-log parsing.
- Depend on `github.com/cilium/ebpf`. Enforcement needs Linux with XDP BPF-link support (upstream 5.9+).
- License the project under GPL-2.0-or-later.
