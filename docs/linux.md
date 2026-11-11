# 리눅스 배포판별 설치

CheckHook의 설치 스크립트는 배포판을 자동으로 감지하고, 빠진 패키지가 있으면 그 배포판에 맞는
설치 명령을 알려 줍니다. 동작을 확인한 환경은 RHEL 10.2와 10.3이며, 나머지 배포판은 아직 실제
환경에서 시험하지 않았습니다.

| 계열 | 해당 배포판 | 패키지 관리자 | 보안 모듈 |
|---|---|---|---|
| rhel | RHEL, Rocky, Alma, Fedora, CentOS | dnf | SELinux |
| debian | Debian, Ubuntu, Linux Mint 등 | apt | AppArmor (Ubuntu) |
| arch | Arch, Manjaro, EndeavourOS | pacman | 없음 (기본값) |
| suse | openSUSE, SLES | zypper | AppArmor |

## 공통 패키지

| 용도 | RHEL 계열 | Debian·Ubuntu | Arch | openSUSE |
|---|---|---|---|---|
| 기본 | `nftables tcpdump python3-pyyaml` | `nftables tcpdump python3-yaml` | `nftables tcpdump python-yaml` | `nftables tcpdump python3-PyYAML` |
| XDP 집행 | `clang bpftool libbpf-devel` | `clang libbpf-dev` + bpftool | `clang bpf libbpf` | `clang bpftool libbpf-devel` |
| 학습 데이터 병합 | `wireshark-cli` | `wireshark-common` | `wireshark-cli` | `wireshark` |

- RHEL에서는 `libbpf-devel`이 CodeReady Builder 저장소에 있습니다.
- Ubuntu와 그 파생 배포판은 bpftool이 `linux-tools-common linux-tools-$(uname -r)`에
  들어 있습니다. Debian은 `bpftool` 패키지를 씁니다.

머신러닝 탐지기에는 `nfstream scikit-learn joblib`이 필요하며, 서비스가 root로 실행되므로
root 환경에 설치합니다. Debian 12, Ubuntu 23.04 이후처럼 시스템 Python을 pip로 바꾸지 못하게
막아 둔 배포판에서는 `--break-system-packages`를 붙여야 합니다.

```bash
sudo pip install nfstream scikit-learn joblib                           # RHEL, Arch 등
sudo pip install --break-system-packages nfstream scikit-learn joblib   # Debian, Ubuntu
```

## 시그니처 탐지기: Snort 3 또는 Suricata

CheckHook은 Snort 3의 `alert_json`과 Suricata의 `eve.json`을 모두 읽습니다. 줄마다 형식을
자동으로 구분합니다.

Snort 3는 대부분의 배포판이 패키지로 제공하지 않습니다. 소스에서 빌드했거나 Arch의 AUR로
설치했다면 `install-snort.sh`를 쓰고, 그렇지 않다면 배포판이 제공하는 Suricata를 쓰는 편이
간단합니다.

```bash
# Suricata 사용 (Debian, Ubuntu, openSUSE 등)
sudo apt-get install -y suricata          # 배포판에 맞는 명령으로 설치
sudo nano /etc/suricata/suricata.yaml     # af-packet 항목의 interface를 내 인터페이스로
sudo systemctl enable --now suricata
sudo bash packaging/use-suricata.sh       # CheckHook이 /var/log/suricata/eve.json을 읽도록 설정
```

`use-suricata.sh`는 설정 파일의 경보 파일 경로를 Suricata의 `eve.json`으로 바꾸고, CheckHook이
관리하던 Snort(`checkhook-ids`)가 있으면 멈춥니다. 차단 목록에는 한 가지 탐지기만 연결하는
것이 좋습니다. 기존 설정 파일은 `checkhook.yaml.bak`으로 남습니다.

Suricata 규칙은 `suricata-update`로 내려받을 수 있습니다. CheckHook의 기본 규칙
(`packaging/suricata/checkhook.rules`)을 함께 쓰려면 Suricata 설정의 `rule-files`에 추가합니다.

## 보안 모듈

- SELinux(RHEL 계열): tcpdump는 SELinux에서 `netutils_t` 영역으로 실행되어 일반
  `/var/lib` 파일에 쓰지 못합니다. `install-capture.sh`는 `/var/lib/checkhook` 디렉터리에만
  tcpdump가 원래 쓸 수 있는 라벨(`netutils_tmp_t`)을 붙입니다. 권한을 새로 늘리지는 않습니다.
- AppArmor(Ubuntu, openSUSE): tcpdump 프로필이 있으면 `install-capture.sh`가 프로필의
  로컬 설정 파일(`/etc/apparmor.d/local/usr.bin.tcpdump` 등)에 `/var/lib/checkhook` 쓰기
  규칙만 추가하고 프로필을 다시 읽어 들입니다.

## 캡처 사용자

tcpdump는 root로 시작해 인터페이스를 연 뒤 일반 사용자로 권한을 내립니다. 배포판에
`tcpdump` 사용자가 있으면 그 사용자를, 없으면 `checkhook-cap` 시스템 사용자를 만들어
사용합니다.

## 방화벽 관리 도구와의 관계

CheckHook은 별도의 nftables 테이블(`ip checkhook`)만 사용합니다. firewalld(RHEL, Fedora,
openSUSE)나 ufw(Ubuntu)의 규칙은 수정하지 않습니다. nftables에서는 한 테이블의 drop이
다른 테이블의 accept보다 우선하므로, 차단 목록의 IP는 다른 도구의 설정과 관계없이
차단됩니다. 설치 후 `sudo nft list tables`로 `ip checkhook` 테이블이 있는지 확인할 수 있습니다.
