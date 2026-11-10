# 출시 전 시험 (가상 머신 포함)

3.0.0을 내기 전에 아래 환경에서 설치와 기능을 확인합니다. 성능 측정(`benchmark/`)은 가상
머신에서 하면 숫자가 의미 없으므로, 여기서는 기능이 동작하는지만 봅니다.

| 환경 | 형태 | 시그니처 탐지기 | 집행 |
|---|---|---|---|
| RHEL 10.2 | 실제 컴퓨터 (확인 완료) | Snort 3 | XDP |
| Windows 11 | 실제 컴퓨터 | Suricata | Windows Defender 방화벽 |
| Windows 10 | VirtualBox | Suricata | Windows Defender 방화벽 |
| Debian | VirtualBox | Suricata | nftables, XDP(generic) |
| Arch | VirtualBox | Suricata 또는 Snort 3(AUR) | nftables, XDP(generic) |
| openSUSE | VirtualBox | Suricata | nftables, XDP(generic) |

## VirtualBox 설정

- **네트워크 어댑터 1: NAT.** 인터넷에 나가는 데 쓰고, 정상 트래픽 수집과 경보 시험도 이
  어댑터로 합니다. 인터페이스 이름은 보통 `enp0s3`이며, 설치 스크립트가 기본 경로를 보고
  자동으로 찾습니다.
- **공격 실습을 할 때만 어댑터 2: 내부 네트워크.** 칼리 같은 공격용 가상 머신과 같은 이름의
  내부 네트워크에 붙입니다. 이 네트워크는 집 네트워크와 분리되어 있습니다.
- **브리지 어댑터는 쓰지 않습니다.** 가상 머신이 집 네트워크에 그대로 올라가므로, 공격
  실습 트래픽이 집 네트워크로 나갈 수 있습니다.
- XDP는 `--mode generic`으로 시험합니다. 가상 랜카드의 native XDP 지원 여부는 확인하지
  않았습니다.
- 메모리는 4 GB 이상을 권합니다. LLM을 가상 머신 안에서 돌리려면 그보다 훨씬 많이 필요합니다.

## LLM(Ollama)

가상 머신마다 Ollama를 설치하지 않아도 시험은 됩니다. Ollama에 연결하지 못하면 자체 시험은
경고(`WARN`)만 내고, 검토 보고서에는 LLM 부분만 비고 "이 컴퓨터의 네트워크 장비와 겹치는
IP" 부분은 그대로 나옵니다.

LLM 부분까지 시험하려면 한 대(예: Windows 11 실제 컴퓨터)에서만 Ollama를 켜고 확인합니다.
다른 컴퓨터의 Ollama를 가상 머신에서 쓰려면 Ollama가 외부 연결을 받도록 바꿔야 하는데, 그러면
같은 네트워크의 다른 기기도 접속할 수 있게 되므로 시험이 끝나면 되돌립니다.

## 순서 (리눅스 가상 머신)

배포판별 패키지 이름은 `docs/linux.md`에 있습니다.

```bash
git clone https://github.com/VertigoJang/checkhook ~/checkhook && cd ~/checkhook
sudo bash packaging/install-capture.sh
sudo bash packaging/install-services.sh
# 시그니처 탐지기: 배포판의 Suricata를 설치하고 suricata.yaml의 interface를 맞춘 뒤
sudo suricata-update                      # 기본 규칙(ET Open) 받기
sudo systemctl enable --now suricata
sudo bash packaging/use-suricata.sh
# XDP까지 시험할 때
sudo bash packaging/install-xdp.sh --mode generic
sudo bash packaging/selftest.sh
```

## 순서 (윈도우)

`docs/windows.md`의 준비 단계(Python, Npcap, Suricata)를 마친 뒤 관리자 PowerShell에서
실행합니다.

```powershell
git clone https://github.com/VertigoJang/checkhook C:\checkhook; cd C:\checkhook
powershell -ExecutionPolicy Bypass -File packaging\windows\install.ps1
powershell -ExecutionPolicy Bypass -File packaging\windows\selftest.ps1
```

Windows 10은 2025년 10월 14일에 마이크로소프트의 일반 지원이 끝났습니다. 시험은 하지만,
문서에는 보안 업데이트를 받는 환경에서 쓰라고 적습니다.

## 자체 시험이 하는 일

`selftest.sh`와 `selftest.ps1`은 설정과 서비스를 읽기만 하고 바꾸지 않습니다. 예외는 차단
시험 하나입니다. 문서 예시용으로 예약된 주소 `203.0.113.250`(RFC 5737, 실제로 쓰는 곳이
없음)을 2분짜리 차단으로 넣었다가 바로 지웁니다.

| 항목 | 확인하는 것 |
|---|---|
| system | 배포판, 커널, Python 버전, 가상화 여부, 필수 패키지 |
| config | 설정 파일을 읽을 수 있는지, 설정된 인터페이스가 실제로 있는지 |
| services / tasks | `checkhookd`와 함께 설치한 서비스가 실행 중인지 |
| enforcement | 차단 목록에 넣고 지우는 과정이 실제로 되는지 |
| detection | 경보 형식을 읽을 수 있는지, 경보 파일이 쌓이는지 |
| capture | 학습용 수집 파일이 최근에 쓰였는지 |
| check | 이 컴퓨터의 DNS 서버와 게이트웨이를 읽을 수 있는지, Ollama에 연결되는지 |

`FAIL`이 0이면 통과입니다. `WARN`은 아직 경보가 없거나 Ollama가 없는 것처럼, 환경에 따라
생길 수 있는 상태입니다.

## 경보 시험

설치 직후에는 경보가 없어서 검토 단계를 확인할 수 없습니다. 널리 쓰이는 탐지 시험 주소에
접속하면 Suricata의 기본 규칙(ET Open)이 경보를 하나 냅니다.

```bash
curl -s http://testmynids.org/uid/index.html
sleep 5
sudo checkhook report
```

보고서에 경보 1건과 함께 차단 대상 IP가 나오면 탐지, 차단 목록, 검토가 이어져 동작하는
것입니다. `enforce: false` 상태이므로 실제로 차단되지는 않습니다.
