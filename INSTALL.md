# 설치와 운영

Gatewarden 패키지는 Ubuntu 22.04 이상과 Rocky Linux 8 / RHEL 8 계열을 대상으로 합니다. 설치 과정은 서비스를 자동으로 enable/start하지 않습니다. 원격 접속이 끊기지 않도록 관리 IP를 allowlist에 추가하고 `-dry-run`으로 먼저 검증한 뒤 직접 시작하십시오.

## Ubuntu (apt)

Nexus `apt-hosted` 저장소의 Distribution은 기본적으로 `stable`입니다. 저장소 관리자가 제공한 공개 키를 등록합니다.

```bash
sudo install -d -m 0755 /etc/apt/keyrings
sudo gpg --dearmor -o /etc/apt/keyrings/manty-apt.gpg < public.gpg.key
echo 'deb [signed-by=/etc/apt/keyrings/manty-apt.gpg] https://nexus.manty.co.kr/repository/apt-hosted/ stable main' \
  | sudo tee /etc/apt/sources.list.d/gatewarden.list
sudo apt update
sudo apt install gatewarden
```

## Rocky Linux / RHEL (yum/dnf)

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

RPM은 기본적으로 서명하지 않습니다. 차단은 프로세스 안의 eBPF/XDP 맵으로 수행합니다.

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

## eBPF 차단

탐지는 OpenSSH 인증 로그를 사용자 공간에서 읽습니다. 임계값을 넘긴 주소의 차단과 해제는 eBPF/XDP 맵만 갱신합니다. XDP BPF-link를 지원하는 Linux(업스트림 5.9 이상), Ethernet 인터페이스, `CAP_BPF`, `CAP_NET_ADMIN`이 필요합니다. Rocky/RHEL 8 기본 커널은 이 조건을 만족하지 않을 수 있으므로 대상 커널에서 먼저 검증하십시오. 붙이기에 실패하면 프로세스는 시작하지 않습니다.

unit은 인터페이스 이름을 포함하지 않습니다. `GATEWARDEN_INTERFACE`가 비어 있으면 시작이 거절됩니다. eBPF는 지정한 인터페이스로 들어오는 차단 IP의 모든 패킷(기존 연결 및 포워딩 포함)을 버리며 TCP RST를 보내지는 않습니다. 프로세스 종료 시 커널이 링크와 맵을 회수합니다.
