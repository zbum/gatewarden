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

RPM은 기본적으로 서명하지 않습니다. deb와 RPM 모두 `nftables`를 런타임 의존성으로 설치합니다.

## 시작 전 검증

패키지는 `/usr/bin/gatewarden`와 `/usr/lib/systemd/system/gatewarden.service`를 설치합니다. 배포판에 따라 SSH unit 이름이 `ssh` 또는 `sshd`인지 확인하십시오.

```bash
systemctl status ssh sshd --no-pager
sudo /usr/bin/gatewarden -dry-run -journal-unit ssh \
  -allowlist '127.0.0.0/8,::1/128,192.0.2.10/32'
```

검증 후 `deploy/systemd/gatewarden.service`에 대응하는 설치 unit의 `ExecStart` 옵션을 환경에 맞게 override합니다.

```bash
sudo systemctl edit gatewarden
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
