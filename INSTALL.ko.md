# 설치와 운영

[English](INSTALL.md) · **한국어**

Gatewarden 패키지는 Ubuntu 22.04 이상과 Rocky Linux 8 / RHEL 8 계열을 대상으로 합니다. 설치는 [https://nexus.manty.co.kr](https://nexus.manty.co.kr)의 apt, yum 저장소를 사용합니다. 처음 설치하면 서비스는 멈춰 있습니다. 원격 접속이 끊기지 않도록 관리 IP를 allowlist에 추가하고 `-dry-run`으로 먼저 검증한 뒤 직접 시작하십시오. 업그레이드하면 이미 실행 중인 서비스를 다시 시작합니다.

## Nexus 저장소에서 설치

### Ubuntu (apt)

패키지는 `https://nexus.manty.co.kr/repository/apt-hosted/`에 있습니다. Distribution은 `stable`, Component는 `main`입니다. 메타데이터 서명 키는 [`deploy/apt/public.gpg.key`](deploy/apt/public.gpg.key)입니다. 지문은 `D9B2 41C5 43B7 6D68 4C7D 8B46 EC22 3AF2 F5C7 8607`입니다.

이미 이 주소의 `stable main` 항목이 있으면 `sudo apt update` 다음 `sudo apt install gatewarden`으로 설치합니다.

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

이 저장소를 클론했다면 키 파일로 `deploy/apt/public.gpg.key`를 사용합니다.

```bash
sudo install -d -m 0755 /etc/apt/keyrings
sudo gpg --batch --yes --dearmor \
  --output /etc/apt/keyrings/manty-apt.gpg deploy/apt/public.gpg.key
sudo chmod 0644 /etc/apt/keyrings/manty-apt.gpg
```

업그레이드:

```bash
sudo apt update
sudo apt install --only-upgrade gatewarden
```

### Rocky Linux / RHEL (dnf)

패키지는 `https://nexus.manty.co.kr/repository/yum-hosted/gatewarden/`에 있습니다. RPM은 서명하지 않습니다.

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

업그레이드:

```bash
sudo dnf upgrade gatewarden
```

## 시작 전 검증

패키지는 `/usr/bin/gatewarden`, `/usr/lib/systemd/system/gatewarden.service`, `/etc/gatewarden/gatewarden.env`를 설치합니다. 설정 파일 위치는 Ubuntu와 Rocky, RHEL이 같습니다. 업그레이드 때 관리자가 고친 설정은 유지됩니다.

| 배포판 | `GATEWARDEN_JOURNAL_UNIT` 기본값 |
| --- | --- |
| Ubuntu | `ssh` |
| Rocky, RHEL | `sshd` |

`GATEWARDEN_INTERFACE`는 비어 있습니다. 수신 인터페이스 이름으로 채운 뒤 시작하십시오. `ip -br link`로 장치 이름을 확인합니다.

```bash
ip -br link
systemctl status ssh sshd --no-pager
sudoedit /etc/gatewarden/gatewarden.env
```

Ubuntu 예:

```bash
GATEWARDEN_INTERFACE=ens18
GATEWARDEN_JOURNAL_UNIT=ssh
GATEWARDEN_ALLOWLIST=127.0.0.0/8,::1/128,192.0.2.10/32
```

Rocky, RHEL 예:

```bash
GATEWARDEN_INTERFACE=ens18
GATEWARDEN_JOURNAL_UNIT=sshd
GATEWARDEN_ALLOWLIST=127.0.0.0/8,::1/128,192.0.2.10/32
```

같은 값을 명령행에서 먼저 확인합니다. 명시적 플래그는 환경 변수보다 우선합니다.

```bash
sudo /usr/bin/gatewarden -interface ens18 -dry-run -journal-unit sshd \
  -allowlist '127.0.0.0/8,::1/128,192.0.2.10/32'
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now gatewarden
sudo journalctl -u gatewarden -f
```

## 패키지 빌드

릴리스 버전은 루트 `VERSION`에 기록합니다. `GOARCH=amd64`는 deb `amd64` / RPM `x86_64`, `GOARCH=arm64`는 deb `arm64` / RPM `aarch64`로 매핑됩니다. Docker가 Ubuntu 22.04의 `dpkg-deb`와 Rocky 8의 `rpmbuild`를 실행합니다.

```bash
make package-images
make deb
make rpm
GOARCH=arm64 make deb
GOARCH=arm64 make rpm
make checksums
```

Nexus 게시에는 사용자명과 비밀번호가 필요합니다. 스크립트는 자격 증명을 mode 600 임시 netrc에 넣고 종료 시 삭제합니다.

```bash
NEXUS_USER=... NEXUS_PASS=... make publish-deb
NEXUS_USER=... NEXUS_PASS=... make publish-rpm
```

`release/<version>` Jenkins 빌드는 브랜치 버전과 `VERSION` 일치를 확인한 뒤에만 apt/yum 저장소에 게시합니다. 그 외 브랜치는 테스트와 패키지 빌드까지만 수행합니다.

## 현재 차단 목록과 지표

실행 중인 프로세스가 `127.0.0.1:9477`에서 현재 차단 목록과 Prometheus 지표를 제공합니다. 주소는 `/etc/gatewarden/gatewarden.env`의 `GATEWARDEN_METRICS_ADDR`로 바꿉니다. 이 TCP 포트는 읽기 전용입니다.

```bash
sudo gatewarden blocks
curl -s 127.0.0.1:9477/metrics
```

`gatewarden_blocked_current`는 임시 차단과 영구 차단을 합친 수입니다. `gatewarden_permanent_current`와 `gatewarden_permanent{ip="..."}`는 영구 차단입니다. `gatewarden_block_until_seconds{ip="..."}`는 임시 차단의 만료 시각입니다.

Grafana에서는 `deploy/grafana/gatewarden.json`을 가져옵니다. 가져올 때 Prometheus 데이터 소스를 고르면 됩니다. Job 변수 기본값은 `gatewarden`입니다. 화면의 누적 수는 gatewarden 프로세스가 다시 시작되면 0부터 셉니다.

`deploy/grafana/alerting.yml`은 알림 규칙 세 개를 넣습니다. 지표 수집이 2분 이상 끊기거나, 영구 차단이 생기거나, 임시 차단이 25개를 10분 이상 넘으면 이미 만들어 둔 contact point `slack-manty-infra`로 알립니다. 영구 차단은 급증 수에 넣지 않습니다. 이 파일은 contact point와 기본 notification policy를 바꾸지 않습니다. 다른 Grafana에 넣을 때는 파일 안의 Prometheus 데이터 소스 UID를 그 서버 값으로 바꿉니다. 파일을 `/etc/grafana/provisioning/alerting`에 두고 Grafana를 다시 시작합니다.

## 열린 SSH 세션

`sudo gatewarden sessions`는 지금 열려 있는 SSH 세션을 보여 줍니다. 사용자, 출발 주소, 클라이언트 포트, 프로세스 ID, UTC 시작 시각이 나옵니다. 이 명령은 모드 0600 소켓을 쓰며, 데몬이 실행 중일 때 동작합니다. 세션은 상태 파일에 저장되지 않습니다.

지표 주소의 `GET /sessions`는 같은 목록을 JSON으로 돌려줍니다. `gatewarden_sessions_current`는 열린 세션 수입니다.

## 영구 차단

같은 주소가 `GATEWARDEN_PERMANENT_WINDOW`(기본 24시간) 안에 임시 차단을 `GATEWARDEN_PERMANENT_AFTER`(기본 3)번 받으면, 그 횟수에 도달한 차단부터 만료 없이 유지됩니다. 한 번의 차단은 실패 횟수가 임계값에 도달한 사건입니다. 창 밖으로 벗어난 이전 차단은 횟수에서 빠집니다. `GATEWARDEN_PERMANENT_AFTER=0`이면 영구 차단을 쓰지 않습니다.

영구 차단과 최근 차단 시각은 `/var/lib/gatewarden/state.json`에 저장되고, 프로세스가 다시 시작되면 XDP 맵에 다시 넣습니다. 재시작하면 진행 중이던 임시 차단은 바로 풀리지만, 그 차단 횟수는 남아 다음 영구 차단 판정에 포함됩니다. 허용 목록에 있는 주소는 새로 차단되지 않습니다. 이미 차단된 주소는 `unblock`으로 해제합니다.

```bash
sudo gatewarden blocks
sudo gatewarden unblock 203.0.113.10
```

`blocks`와 `unblock`은 `/run/gatewarden/gatewarden.sock`(모드 0600)으로 실행 중인 프로세스에 연결합니다. 서비스가 멈춰 있으면 두 명령은 상태 파일을 직접 읽고 수정합니다. 해제된 주소는 영구 차단 횟수를 처음부터 다시 쌓습니다. 차단되어 있지 않은 주소를 해제하면 오류가 납니다. 목록에서 영구 차단은 `KIND`가 `permanent`이고 만료 시각이 없습니다.

기준은 설정 파일에서 바꿉니다. 같은 이름의 플래그(`-permanent-after`, `-permanent-window`, `-state-file`, `-socket`)를 주면 그 값이 우선합니다.

```bash
GATEWARDEN_PERMANENT_AFTER=3
GATEWARDEN_PERMANENT_WINDOW=24h
GATEWARDEN_STATE_FILE=/var/lib/gatewarden/state.json
GATEWARDEN_SOCKET=/run/gatewarden/gatewarden.sock
```

## eBPF 차단

탐지는 OpenSSH 인증 로그를 사용자 공간에서 읽습니다. 임계값을 넘긴 주소의 차단과 해제는 eBPF/XDP 맵만 갱신합니다. XDP BPF-link를 지원하는 Linux(업스트림 5.9 이상), Ethernet 인터페이스, `CAP_BPF`, `CAP_NET_ADMIN`이 필요합니다. 열린 SSH 세션을 읽는 tracepoint 프로그램은 `CAP_PERFMON`이 추가로 필요합니다. 대상 커널에서 먼저 검증하십시오. Rocky/RHEL 8 기본 커널은 XDP BPF-link를 지원하지 않을 수 있습니다. 붙이기에 실패하면 프로세스는 시작하지 않습니다.

unit은 인터페이스 이름을 포함하지 않습니다. `GATEWARDEN_INTERFACE`가 비어 있으면 시작이 거절됩니다. eBPF는 지정한 인터페이스로 들어오는 차단 IP의 모든 패킷(기존 연결 및 포워딩 포함)을 버리며 TCP RST를 보내지는 않습니다. 프로세스 종료 시 커널이 링크와 맵을 회수합니다. 임시 차단은 그때 끝나고, 영구 차단은 다음 시작 때 상태 파일에서 다시 적용됩니다.
