# Gatewarden

[English](README.md) · **한국어**

Gatewarden은 Linux OpenSSH 인증 로그를 따라가며, 원격 IP별 로그인 실패를 시간 창 안에서 세고, 반복 실패 주소를 eBPF/XDP IP 맵으로 차단합니다. 차단은 금지 시간이 지나면 풀립니다. 차단을 계속 받는 주소는 영구 차단됩니다.

<p align="center">
  <img src="docs/images/grafana-dashboard.png" width="880" alt="Gatewarden Grafana 대시보드: 현재 차단, 임시 차단, 영구 차단, 분당 SSH 실패, 차단 주소 표">
  <br>
  <em>지금 막힌 주소, 끝나지 않는 차단, 스캐너가 실패하는 속도. 보드는 <a href="deploy/grafana/gatewarden.json">deploy/grafana/gatewarden.json</a>입니다.</em>
</p>

> 실행은 Linux만 가능합니다. 차단에 eBPF/XDP를 쓰기 때문입니다. 다른 플랫폼용 빌드 타깃은 제공하지만, Windows와 macOS 바이너리는 방화벽 차단을 적용하지 못합니다.

## 빌드와 테스트

Go 1.26 이상이 필요합니다.

```sh
make test
make build-linux
make build-all
make deb
make rpm
```

게시된 패키지는 [https://nexus.manty.co.kr](https://nexus.manty.co.kr)에서 설치합니다. Ubuntu는 apt 저장소 `apt-hosted`(`stable` `main`)를 씁니다. Rocky와 RHEL은 yum 저장소 `yum-hosted/gatewarden/`을 씁니다. 처음 설치하면 서비스는 멈춰 있습니다. apt 서명 키를 포함한 절차는 [INSTALL.ko.md](INSTALL.ko.md)에 있습니다.

```sh
# Ubuntu
sudo apt update && sudo apt install gatewarden

# Rocky or RHEL
sudo dnf install gatewarden
```

`sudo make install`은 이 체크아웃에서 빌드한 바이너리를 설치합니다. Docker 패키지 빌드와 Jenkins 게시도 [INSTALL.ko.md](INSTALL.ko.md)에 있습니다.

## 실행

eBPF에는 Ethernet 수신 인터페이스, Linux XDP BPF-link(업스트림 5.9 이상), `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON`이 필요합니다. XDP 프로그램을 붙이지 않고 설정을 확인하려면 dry-run으로 시작합니다.

```sh
sudo ./dist/gatewarden-linux-amd64 -interface eth0 -dry-run -journal-unit ssh
sudo ./dist/gatewarden-linux-amd64 -interface eth0 -journal-unit sshd
sudo ./dist/gatewarden-linux-amd64 -interface eth0 -log-file /var/log/auth.log
```

차단을 켜기 전에 관리자 주소와 관리 네트워크를 `-allowlist`에 넣으십시오. 기본값은 루프백만 보호하며, 서버를 관리하는 IP를 스스로 알아내지 못합니다. 두 번째 SSH 세션을 연 채로, 서비스에 넣을 명령 그대로 `-dry-run`을 실행하십시오.

| 플래그 | 기본값 | 의미 |
| --- | --- | --- |
| `-log-file` | 비어 있음 | 이 파일을 `tail -F`로 따라갑니다. 비어 있으면 journald를 씁니다 |
| `-journal-unit` | `ssh`, 또는 `GATEWARDEN_JOURNAL_UNIT` | `journalctl -u`에 넘기는 유닛. Ubuntu는 `ssh`, Rocky와 RHEL은 `sshd` |
| `-window` | `5m` | 실패를 세는 시간 창 |
| `-threshold` | `5` | 창 안에서 차단까지 필요한 실패 횟수 |
| `-ban-duration` | `15m` | 임시 차단이 유지되는 시간 |
| `-permanent-after` | `3`, 또는 `GATEWARDEN_PERMANENT_AFTER` | `-permanent-window` 안의 임시 차단이 이 횟수에 도달하면 영구 차단. `0`이면 영구 차단을 끕니다 |
| `-permanent-window` | `24h`, 또는 `GATEWARDEN_PERMANENT_WINDOW` | 영구 차단 판정에 이전 차단을 포함하는 기간 |
| `-allowlist` | `127.0.0.0/8,::1/128`, 또는 `GATEWARDEN_ALLOWLIST` | 차단하지 않을 IP 또는 CIDR. 쉼표로 구분 |
| `-interface` | `GATEWARDEN_INTERFACE` | XDP 프로그램을 붙일 Ethernet 수신 인터페이스. 필수 |
| `-metrics-addr` | `127.0.0.1:9477`, 또는 `GATEWARDEN_METRICS_ADDR` | `/metrics`, `/blocks`, `/sessions`를 제공하는 HTTP 주소 |
| `-state-file` | `/var/lib/gatewarden/state.json`, 또는 `GATEWARDEN_STATE_FILE` | 영구 차단과 최근 차단 시각. 재시작 후 복원 |
| `-socket` | `/run/gatewarden/gatewarden.sock`, 또는 `GATEWARDEN_SOCKET` | `blocks`, `sessions`, `unblock`용 유닉스 소켓. 모드 0600 |
| `-dry-run` | `false` | BPF 오브젝트를 열지 않고 변경을 로그만 남깁니다 |

서비스는 OpenSSH의 비밀번호/공개키 실패, invalid user, PAM 인증 실패, 인증 전 연결 종료 기록을 알아봅니다. 로그인 성공과 이후 연결 종료도 알아봅니다. 중복 차단은 억제하고, 만료된 차단은 제거합니다.

## 현재 차단과 지표

한 번의 차단은 주소가 `-window` 안에서 `-threshold` 번의 실패에 도달한 사건입니다. 그 주소가 `-permanent-window` 안에서 `-permanent-after` 번의 차단에 도달하면, 그 차단부터 영구 차단입니다. 이미 영구 차단된 주소의 이후 실패는 무시합니다. 허용 목록의 주소는 새로 차단되지 않습니다. 허용 목록에 넣기 전에 차단된 주소는 `unblock`까지 차단이 유지됩니다.

`sudo gatewarden blocks`는 지금 차단된 주소를 출력합니다. 임시 차단은 UTC 만료 시각을 보여 줍니다. 영구 차단은 `EXPIRES`와 `KIND`에 `permanent`를 보여 줍니다. `sudo gatewarden unblock <ip>`는 현재 차단, 영구 기록, 차단 이력을 지웁니다. 그 주소는 `-permanent-after` 번의 차단을 다시 쌓아야 합니다. 두 명령은 모드 0600 소켓으로 통신합니다. 지표 TCP 포트는 읽기 전용입니다.

```sh
sudo gatewarden blocks
sudo gatewarden unblock 203.0.113.10
```

영구 차단과 차단 시각은 `-state-file`에 저장됩니다. 재시작 후 영구 차단은 새 XDP 맵에 다시 들어갑니다. 재시작하면 임시 차단은 바로 끝나고, 그 차단 횟수는 남습니다. 데몬이 멈춰 있으면 `blocks`와 `unblock`이 그 파일을 직접 읽고 고칩니다. 차단되어 있지 않은 주소를 `unblock`하면 오류가 납니다.

## 열린 SSH 세션

`sudo gatewarden sessions`는 지금 열려 있는 SSH 세션을 보여 줍니다. 사용자, 출발 주소, 클라이언트 포트, 프로세스 ID, 연결이 시작된 UTC 시각이 나옵니다. 예상하지 못한 세션을 찾을 때 씁니다.

```sh
sudo gatewarden sessions
```

이 명령은 모드 0600 소켓을 읽으며, 데몬이 실행 중일 때만 동작합니다. 세션은 상태 파일에 저장되지 않습니다. Linux에서 데몬은 `sshd`와 `sshd-session`의 `accept`, `accept4` tracepoint에 붙고, 소켓을 물려받은 자식 프로세스가 끝날 때까지 따라갑니다. 프로세스에 login uid가 생긴 뒤에 세션을 게시합니다. 사용자 이름은 그 uid에서 옵니다. 기록하는 값은 사용자, 출발 주소, 클라이언트 포트, 프로세스 ID, 시작 시각입니다. tracepoint는 데몬이 시작된 뒤에 accept된 연결을 보고합니다. 시작 시점에 이미 있는 프로세스는 `/proc`에서 한 번 읽습니다. `-dry-run`은 tracepoint를 붙이지 않습니다. 허용 목록 주소도 목록에 나옵니다. 허용 목록은 차단만 건너뜁니다.

인증 실패는 여전히 journal 유닛 또는 `-log-file`에서 옵니다. 따라가기는 그 스트림의 끝에서 시작하므로, 시작 전에 기록된 실패는 세지 않습니다.

지표 주소와 제어 소켓의 `GET /sessions`는 같은 행을 JSON으로 돌려줍니다. `gatewarden_sessions_current`는 열린 세션 수입니다. `gatewarden_session_since_seconds{user,ip,port}`는 각 세션의 Unix 시작 시각입니다.

Prometheus는 `http://127.0.0.1:9477/metrics`를 수집합니다. `gatewarden_blocked_current`는 임시 차단과 영구 차단을 합친 수입니다. `gatewarden_permanent_current`와 `gatewarden_permanent{ip="..."}`는 영구 차단입니다. `gatewarden_block_until_seconds{ip="..."}`는 임시 차단의 Unix 만료 시각입니다. `gatewarden_sessions_current`와 `gatewarden_session_since_seconds{user,ip,port}`는 지금 열린 SSH 세션입니다. `gatewarden_failures_total`, `gatewarden_blocks_total`, `gatewarden_unblocks_total`은 프로세스가 시작된 뒤의 사건 수입니다. `gatewarden_unblocks_total`은 만료만 셉니다.

[deploy/grafana/gatewarden.json](deploy/grafana/gatewarden.json)이 위 대시보드입니다. Prometheus 데이터 소스를 골라 가져옵니다. Job 변수 기본값은 `gatewarden`입니다. 대시보드에는 열린 세션 수 `gatewarden_sessions_current`와 그 세션 표가 있습니다. 보려면 파일을 다시 가져오십시오. 화면의 누적 수는 프로세스가 다시 시작되면 0부터 셉니다.

[deploy/grafana/alerting.yml](deploy/grafana/alerting.yml)은 알림 규칙 세 개를 넣습니다. `gatewarden` 수집이 끊기거나, 영구 차단이 있거나, 임시 차단이 한 번에 25개를 넘으면 이미 있는 contact point `slack-manty-infra`로 알립니다. 영구 차단은 급증 수에 넣지 않습니다. 이 파일은 contact point와 기본 notification policy를 바꾸지 않습니다. 다른 Grafana에 넣을 때는 Prometheus 데이터 소스 UID를 그 서버 값으로 바꿉니다.

## systemd

Nexus에서 패키지를 설치하고 `/etc/gatewarden/gatewarden.env`의 `GATEWARDEN_INTERFACE`를 설정한 뒤 서비스를 시작합니다.

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now gatewarden
journalctl -u gatewarden -f
```

패키지 unit은 `/etc/gatewarden/gatewarden.env`를 읽고, 인터페이스 이름을 직접 넘기지 않습니다. Ubuntu 패키지의 journal 유닛 기본값은 `ssh`입니다. Rocky와 RHEL 패키지는 `sshd`입니다. 시작 전에 `ip -br link`로 보이는 호스트 장치로 인터페이스를 설정하십시오. unit은 `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON`을 주고, 잠긴 메모리 제한을 풀며, 읽기 전용 파일시스템 뷰를 씁니다. `StateDirectory=gatewarden`과 `RuntimeDirectory=gatewarden`이 `/var/lib/gatewarden`과 `/run/gatewarden`을 제공합니다. 예기치 않은 종료 뒤에는 다시 시작합니다. 패키지는 Gatewarden을 enable하거나 start하지 않습니다. [INSTALL.ko.md](INSTALL.ko.md)를 보십시오.

## eBPF 동작과 검증

XDP는 선택한 인터페이스로 들어오는 차단된 IPv4/IPv6 출발지의 트래픽을 모두 버립니다. 기존 세션과 포워딩 트래픽도 포함합니다. TCP RST는 보내지 않습니다. 다른 인터페이스와 터널 안쪽 헤더는 보지 않습니다. Ethernet과 802.1Q/802.1ad 태그 두 개까지 지원합니다. IP가 아닌 패킷과 잘린 헤더는 통과합니다. generic XDP를 쓰며, 이미 붙은 XDP 프로그램을 바꾸지 않습니다. 붙이기에 실패하면 시작하지 않습니다.

고정하지 않은 링크와 맵은 프로세스가 끝나면, 비정상 종료를 포함해, 해제됩니다. 임시 차단은 프로세스와 함께 끝납니다. 영구 차단과 판정에 쓰는 차단 시각은 `/var/lib/gatewarden/state.json`에 남고, 다음 시작 때 새 맵에 들어갑니다. 맵은 IP를 65,536개까지 담습니다. 넣기에 실패하면 기존 차단을 조용히 지우지 않고 오류로 알립니다. `-dry-run`은 커널 지원과 인터페이스 존재를 확인하지 않고 설정만 검증합니다.

이식 가능한 검사는 `make check`와 `make build-all`로 실행합니다. BPF와 NET_ADMIN 권한이 있는 일회용 Linux 호스트나 컨테이너에서는 다음을 실행합니다.

```sh
GATEWARDEN_TEST_EBPF=1 go test -v -run TestKernel .
# 선택적 부착 시험. 일회용 Ethernet 인터페이스만 지정합니다.
GATEWARDEN_TEST_EBPF=1 GATEWARDEN_TEST_INTERFACE=eth0 go test -v -run TestKernel .
```

의존성 근거: [ADR 001](docs/adr/001-ebpf-firewall.md).

## 라이선스

Gatewarden은 자유 소프트웨어입니다. Free Software Foundation이 발표한 GNU General Public License 버전 2 또는 그 이후 버전의 조건에 따라 재배포하고 수정할 수 있습니다. [LICENSE](LICENSE)를 보십시오. 변경 이력은 [CHANGELOG.md](CHANGELOG.md)에 있습니다.
