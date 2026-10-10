# Install and operate

**English** · [한국어](INSTALL.ko.md)

Gatewarden packages target Ubuntu 22.04 or newer and Rocky Linux 8 / RHEL 8. Install them from the apt and yum repositories at [https://nexus.manty.co.kr](https://nexus.manty.co.kr). The first install leaves the service stopped. Add the administration address to the allowlist and check the command with `-dry-run` before starting, so the session you are using stays open. An upgrade restarts a service that is already running.

## Install from Nexus

### Ubuntu (apt)

Packages are at `https://nexus.manty.co.kr/repository/apt-hosted/`. The distribution is `stable` and the component is `main`. The metadata signing key is [`deploy/apt/public.gpg.key`](deploy/apt/public.gpg.key). Its fingerprint is `D9B2 41C5 43B7 6D68 4C7D 8B46 EC22 3AF2 F5C7 8607`.

When a `stable main` entry for that URL already exists, install with `sudo apt update` and then `sudo apt install gatewarden`.

```bash
sudo apt update
sudo apt install -y ca-certificates curl gnupg
curl --fail --silent --show-error --location \
  https://raw.githubusercontent.com/zbum/net-scouter/main/deploy/apt/public.gpg.key \
  --output /tmp/manty-apt.gpg.key
sudo install -d -m 0755 /etc/apt/keyrings
sudo gpg --batch --yes --dearmor \
  --output /etc/apt/keyrings/manty-apt.gpg /tmp/manty-apt.gpg.key
sudo chmod 0644 /etc/apt/keyrings/manty-apt.gpg
echo 'deb [signed-by=/etc/apt/keyrings/manty-apt.gpg] https://nexus.manty.co.kr/repository/apt-hosted/ stable main' \
  | sudo tee /etc/apt/sources.list.d/gatewarden.list
sudo apt update
sudo apt install gatewarden
```

From a clone of this repository, use `deploy/apt/public.gpg.key` as the key file.

```bash
sudo install -d -m 0755 /etc/apt/keyrings
sudo gpg --batch --yes --dearmor \
  --output /etc/apt/keyrings/manty-apt.gpg deploy/apt/public.gpg.key
sudo chmod 0644 /etc/apt/keyrings/manty-apt.gpg
```

Upgrade:

```bash
sudo apt update
sudo apt install --only-upgrade gatewarden
```

### Rocky Linux / RHEL (dnf)

Packages are at `https://nexus.manty.co.kr/repository/yum-hosted/gatewarden/`. The RPMs are unsigned.

```bash
sudo tee /etc/yum.repos.d/gatewarden.repo >/dev/null <<'EOF'
[gatewarden]
name=gatewarden
baseurl=https://nexus.manty.co.kr/repository/yum-hosted/gatewarden/
enabled=1
gpgcheck=0
EOF
sudo dnf install gatewarden
```

Upgrade:

```bash
sudo dnf upgrade gatewarden
```

## Check before starting

The package installs `/usr/bin/gatewarden`, `/usr/lib/systemd/system/gatewarden.service`, and `/etc/gatewarden/gatewarden.env`. Ubuntu, Rocky, and RHEL use that same configuration path. An upgrade keeps configuration the administrator has edited.

| Distribution | Default `GATEWARDEN_JOURNAL_UNIT` |
| --- | --- |
| Ubuntu | `ssh` |
| Rocky, RHEL | `sshd` |

`GATEWARDEN_INTERFACE` is empty. Set it to the ingress interface name before starting. `ip -br link` lists device names.

```bash
ip -br link
systemctl status ssh sshd --no-pager
sudoedit /etc/gatewarden/gatewarden.env
```

Ubuntu example:

```bash
GATEWARDEN_INTERFACE=ens18
GATEWARDEN_JOURNAL_UNIT=ssh
GATEWARDEN_ALLOWLIST=127.0.0.0/8,::1/128,192.0.2.10/32
```

Rocky and RHEL example:

```bash
GATEWARDEN_INTERFACE=ens18
GATEWARDEN_JOURNAL_UNIT=sshd
GATEWARDEN_ALLOWLIST=127.0.0.0/8,::1/128,192.0.2.10/32
```

Check the same values on the command line first. An explicit flag wins over the environment variable.

```bash
sudo /usr/bin/gatewarden -interface ens18 -dry-run -journal-unit sshd \
  -allowlist '127.0.0.0/8,::1/128,192.0.2.10/32'
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now gatewarden
sudo journalctl -u gatewarden -f
```

## Build packages

The release version is the root `VERSION` file. `GOARCH=amd64` maps to deb `amd64` and RPM `x86_64`. `GOARCH=arm64` maps to deb `arm64` and RPM `aarch64`. Docker runs `dpkg-deb` from Ubuntu 22.04 and `rpmbuild` from Rocky 8.

```bash
make package-images
make deb
make rpm
GOARCH=arm64 make deb
GOARCH=arm64 make rpm
make checksums
```

Publishing to Nexus needs a username and password. The scripts put the credentials in a mode 600 temporary netrc and delete that file when they exit.

```bash
NEXUS_USER=... NEXUS_PASS=... make publish-deb
NEXUS_USER=... NEXUS_PASS=... make publish-rpm
```

A Jenkins build of `release/<version>` publishes to the apt and yum repositories after the branch version matches `VERSION`. Other branches run tests and build packages.

## Current blocks and metrics

The running process serves the current block list and Prometheus metrics on `127.0.0.1:9477`. Change the address with `GATEWARDEN_METRICS_ADDR` in `/etc/gatewarden/gatewarden.env`. This TCP port is read-only.

```bash
sudo gatewarden blocks
curl -s 127.0.0.1:9477/metrics
```

`gatewarden_blocked_current` counts temporary and permanent blocks together. `gatewarden_permanent_current` and `gatewarden_permanent{ip="..."}` describe permanent blocks. `gatewarden_block_until_seconds{ip="..."}` is the expiry time of each temporary block.

Import `deploy/grafana/gatewarden.json` into Grafana and choose the Prometheus datasource. The job variable defaults to `gatewarden`. Cumulative counts on the dashboard start again at 0 when the gatewarden process restarts.

`deploy/grafana/alerting.yml` adds three alert rules. They notify the existing contact point `slack-manty-infra` when collection is down for 2 minutes, a permanent block appears, or more than 25 addresses stay temporarily blocked for 10 minutes. Permanent blocks are not part of that surge. The file leaves contact points and the default notification policy unchanged. On another Grafana, replace the Prometheus datasource UID inside the file. Put the file in `/etc/grafana/provisioning/alerting` and restart Grafana.

## Open SSH sessions

`sudo gatewarden sessions` lists SSH sessions that are open now: user, source address, client port, process id, and the UTC start time. The command uses the mode 0600 socket and works while the daemon is running. Sessions are not stored in the state file.

`GET /sessions` on the metrics address returns the same rows as JSON. `gatewarden_sessions_current` is the number of open sessions.

## Permanent blocks

An address that receives `GATEWARDEN_PERMANENT_AFTER` temporary bans (default 3) inside `GATEWARDEN_PERMANENT_WINDOW` (default 24h) stays blocked, starting with the ban that reaches that count. One ban is the event where the failure count reaches the threshold. Bans that fall outside the window drop out of the count. `GATEWARDEN_PERMANENT_AFTER=0` disables permanent blocks.

Permanent blocks and recent ban times are stored in `/var/lib/gatewarden/state.json` and inserted into the XDP map when the process starts again. A restart ends a temporary block that was in progress, and that ban still counts toward the next permanent decision. An allowlisted address is not newly blocked. Clear an address that is already blocked with `unblock`.

```bash
sudo gatewarden blocks
sudo gatewarden unblock 203.0.113.10
```

`blocks` and `unblock` talk to the running process through `/run/gatewarden/gatewarden.sock` (mode 0600). While the service is stopped, both commands read and edit the state file. An unblocked address starts its permanent count again from zero. Unblocking an address that is not blocked returns an error. In the list, a permanent block has `KIND` `permanent` and no expiry time.

Change the limits in the configuration file. The same flag names (`-permanent-after`, `-permanent-window`, `-state-file`, `-socket`) win when they are set.

```bash
GATEWARDEN_PERMANENT_AFTER=3
GATEWARDEN_PERMANENT_WINDOW=24h
GATEWARDEN_STATE_FILE=/var/lib/gatewarden/state.json
GATEWARDEN_SOCKET=/run/gatewarden/gatewarden.sock
```

## eBPF blocking

Detection reads OpenSSH authentication logs in userspace. Blocking and unblocking an address that crosses the threshold updates only the eBPF/XDP map. This needs Linux with XDP BPF-link support (upstream 5.9 or newer), an Ethernet interface, `CAP_BPF`, and `CAP_NET_ADMIN`. The tracepoint program that reads open SSH sessions also needs `CAP_PERFMON`. Verify this on the target kernel. A stock Rocky or RHEL 8 kernel can lack XDP BPF-link support. If attachment fails, the process does not start.

The unit does not include an interface name. An empty `GATEWARDEN_INTERFACE` is rejected at startup. eBPF drops every ingress packet from a blocked IP on the named interface, including existing connections and forwarded traffic, and it does not send a TCP RST. When the process exits, the kernel releases the link and the map. Temporary blocks end then. Permanent blocks are applied again from the state file at the next start.
