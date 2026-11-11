<p align="center"><img src="assets/checkhook-256.png" width="112" alt="CheckHook logo"></p>

<h1 align="center">CheckHook</h1>

<p align="center"><img src="assets/checkhook-banner.png" alt="CHECKHOOK"></p>

## 소개

CheckHook은 리눅스와 윈도우용 AI 방화벽입니다. 이름은 복싱 기술 체크훅(check hook)에서 따왔습니다.
체크훅은 달려드는 상대를 몸을 돌려 비켜 내면서 훅을 꽂는 반격 기술입니다. 이름에는 두 가지
뜻이 겹쳐 있습니다. Hook은 커널의 훅(XDP, nftables)에 붙어 차단 대상의 패킷을 버리는 단계를,
Check는 로컬 LLM이 차단 대상이 오탐인지 다시 확인하는 단계를 가리킵니다.

CheckHook은 탐지와 집행을 분리한 구조입니다.

- 탐지: Snort 3(또는 Suricata) 시그니처와 머신러닝 트래픽 흐름 분류기가 차단할 IP를 정합니다.
- 집행: nftables 또는 XDP가 커널에서 해당 IP의 패킷을 버립니다. 차단 목록의 각 항목은
  정해진 시간이 지나면 자동으로 해제됩니다.
- 검토: 차단했거나 차단할 IP를 이 컴퓨터의 DNS 서버, 게이트웨이, 자기 주소와 먼저 맞춰 보고,
  로컬 LLM(Ollama)이 나머지의 오탐 가능성을 판단합니다. 오탐이면 설정에 넣을 `skip:` 줄을
  보고서에 적어 줍니다. 검토 단계는 읽기만 하며, 차단 목록과 설정은 사람이 고칩니다.

탐지, 차단 만료, 검토는 데몬 `checkhookd` 하나가 맡습니다. 실행기 `checkhook`으로 상태를
보고 차단 목록을 관리합니다.

리눅스(RHEL·Rocky·Fedora, Debian·Ubuntu, Arch, openSUSE)와 윈도우 10·11을 지원합니다.
동작을 확인한 환경은 RHEL 10.2이며, 다른 배포판과 윈도우는 아직 실제 환경에서 시험하지
않았습니다.

## 개발 배경

2026년 "검은 10월(Black October)" 이후 AI를 이용한 크래킹이 크게 늘었습니다. 공격을
AI가 계획하고 실행하게 되면서, 사람이 직접 대응하는 방식으로는 공격 속도를 따라갈 수
없게 되었습니다.

이 문제에 이이제이의 논리를 적용했습니다. 『후한서』 등우·구순 열전에는 후한 조정이
변방 민족끼리 서로 싸우게 하자고 논의하는 대목이 있으며, 이 대목이 이이제이라는 말의
뿌리로 꼽힙니다. CheckHook은 이 논리를 네트워크에 옮겨, 크래킹 AI를 보안 AI로 막는 것을
목표로 합니다.

탐지 계층(시그니처, 머신러닝, 검토용 LLM)은 무엇을 차단할지 판단하고, 커널 계층(nftables,
XDP)은 그 판단을 빠르고 적은 비용으로 집행합니다. 두 계층을 분리해 각각 필요한 속도로
동작하도록 했습니다.

## 동작 흐름

1. 시그니처 탐지기(Snort 3 또는 Suricata)와 머신러닝 탐지기가 트래픽을 분석해 악성으로
   판단한 출발지 IP를 찾습니다.
2. 찾은 IP는 공유 차단 목록에 만료 시간과 함께 등록됩니다. 여러 탐지기가 같은 목록을
   사용합니다.
3. 집행 계층이 차단 목록에 있는 IP의 패킷을 버립니다. 리눅스에서는 nftables 또는 XDP,
   윈도우에서는 Windows Defender 방화벽이 이 역할을 맡습니다.
4. 한 시간마다 검토 보고서를 작성합니다. 차단 대상 중 이 컴퓨터의 DNS 서버나 게이트웨이가
   있으면 LLM 없이도 바로 오탐으로 표시하고, 나머지는 로컬 LLM이 판단합니다. `enforce: false`
   상태에서는 차단될 뻔한 IP를 같은 방식으로 검토합니다.

## 성능 측정

집행 계층을 고르기 위해 iptables 일반 규칙, iptables + ipset, nftables set, XDP + eBPF 맵의
네 가지를 비교했습니다. 차단 목록 크기 N을 10에서 100,000까지 바꾸며 차단되는 공격
트래픽과 통과하는 정상 트래픽을 각각 측정했고, 필터가 없는 상태를 기준선으로 함께
측정했습니다. 측정 환경은 Rocky Linux 10.2 가상머신 한 대이며, XDP는 generic 모드로
실행했습니다.

| 집행 계층 | N=10 | N=1k | N=10k | N=100k | CPU/Mpkt (N=10k, 차단) |
|---|---|---|---|---|---|
| XDP + eBPF 맵 | 887k | 909k | 911k | 899k | **0.40** |
| nftables set | 702k | 699k | 700k | 688k | 0.72 |
| iptables + ipset | 674k | 669k | 653k | 655k | 0.81 |
| iptables 일반 규칙 | 709k | 217k | **28.6k** | — | 34.5 |

표의 N 열은 차단 처리량(초당 패킷 수)입니다. iptables 일반 규칙은 N=10k까지만
측정했습니다.

- 해시 기반 계층(XDP, nftables set, ipset)은 N이 10에서 100,000으로 늘어도 처리량이 거의
  변하지 않았습니다. iptables 일반 규칙은 규칙을 순서대로 검사하므로(O(n)) N=10,000에서
  XDP보다 약 32배 느렸고, 패킷당 CPU 사용량은 약 86배였습니다.
- 공격 트래픽을 차단할 때는 XDP가 가장 효율적이었습니다. 커널이 패킷 구조체(skb)를 만들기
  전에 패킷을 버리기 때문에, 다른 해시 기반 계층의 절반 정도 CPU만 사용했습니다. 정상
  트래픽을 통과시킬 때는 해시 기반 계층 사이에 차이가 거의 없었습니다.

따라서 차단 목록이 크고 자주 바뀌는 환경에서는 해시 기반 계층을 사용해야 하며, 공격
트래픽이 많거나 CPU 여유가 적다면 XDP가 적합합니다. 상세 결과는 `docs/results.md`와
`docs/figures/`에 있습니다.

## 요구 사항

리눅스

- 공통: `nftables`, `python3`, PyYAML, `tcpdump`
- 시그니처 탐지: Snort 3 또는 Suricata
- 머신러닝 탐지: `nfstream`, `scikit-learn`, `joblib` (root 권한으로 설치)
- XDP 집행: `clang`, `bpftool`, libbpf 헤더
- 검토: Ollama와 언어 모델(기본값 `qwen2.5:7b`)

배포판별 패키지 이름과 보안 모듈(SELinux, AppArmor) 처리는 `docs/linux.md`에 정리했습니다.
설치 스크립트도 빠진 패키지가 있으면 배포판에 맞는 설치 명령을 알려 줍니다.

윈도우

- Python 3.9 이상, Npcap
- 시그니처 탐지: Suricata 윈도우 설치 파일
- 검토: Ollama 윈도우 버전

## 설치 및 실행

### 리눅스

```bash
git clone https://github.com/VertigoJang/checkhook && cd checkhook

sudo bash packaging/install-capture.sh  wlp0s20f3                # 학습용 정상 트래픽 수집
sudo bash packaging/install-services.sh --iface wlp0s20f3        # checkhookd, checkhook 명령
sudo bash packaging/install-snort.sh    --iface wlp0s20f3 --community   # Snort 3 센서
sudo bash packaging/install-xdp.sh      --iface wlp0s20f3        # 선택: XDP 집행

checkhook services      # 서비스 상태
checkhook logs          # 탐지 기록 확인
```

`wlp0s20f3` 자리에는 사용하는 네트워크 인터페이스 이름을 넣습니다. 인터페이스 이름은
`ip -o -4 route show default` 출력에서 `dev` 다음에 나옵니다.

`install-services.sh`는 데몬 `checkhookd`를 systemd 서비스로 등록하고, `checkhook`과
`checkhookd` 명령을 `/usr/local/bin`에 연결합니다. 패킷 수집, Snort 센서, XDP 로더는 각각
별도 서비스(`checkhook-capture`, `checkhook-ids`, `checkhook-xdp`)입니다.

Snort 3 대신 배포판의 Suricata를 쓰려면 Suricata를 설치해 실행한 뒤
`sudo bash packaging/use-suricata.sh`를 실행합니다. 자세한 내용은 `docs/linux.md`에 있습니다.

모든 설정은 `/etc/checkhook/checkhook.yaml` 파일 하나에서 관리합니다. 설정을 바꾼 뒤에는
`sudo systemctl restart checkhookd`로 데몬을 다시 시작합니다. 서비스별 상세 설명은
`docs/services.md`에 있습니다.

`checkhook`을 인자 없이 실행하면 배너와 명령 목록이 나옵니다. 주요 명령은 다음과 같습니다.

- `checkhook status`: 현재 차단 목록 확인
- `sudo checkhook block <IP>`, `sudo checkhook unblock <IP>`: 수동 차단과 해제
- `sudo checkhook xdp`: XDP 집행 상태와 버린 패킷 수 확인
- `sudo checkhook report`: LLM 검토 보고서 즉시 생성

`bash packaging/install-desktop.sh`를 실행하면 프로그램 메뉴에 CheckHook 아이콘이 생기며,
아이콘을 누르면 터미널에서 실행기가 열립니다.

### 윈도우

관리자 권한 PowerShell에서 실행합니다.

```powershell
git clone https://github.com/VertigoJang/checkhook C:\CheckHook
cd C:\CheckHook
powershell -ExecutionPolicy Bypass -File packaging\windows\install.ps1

.\checkhook.cmd services      # 상태 확인
.\checkhook.cmd logs          # 탐지 기록 확인
```

설치 스크립트는 `checkhookd` 예약 작업(부팅 시 SYSTEM 권한으로 시작)과, Suricata가
설치되어 있으면 `checkhook-suricata` 예약 작업을 등록하고 시작 메뉴에 바로 가기를 만듭니다.
설정 파일은 `C:\ProgramData\CheckHook\checkhook.yaml`입니다. 자세한 내용은
`docs/windows.md`에 있습니다.

## 머신러닝 모델 학습

머신러닝 탐지는 학습된 모델이 있어야 켜집니다. 학습용 정상 트래픽은 두 가지 형태로 모입니다.

- flow 기록: `checkhookd`가 끝난 연결(flow)마다 통계 특징을 `/var/lib/checkhook/flows/`에
  CSV로 남깁니다. 연결 하나에 수백 바이트라 몇 주 분량도 몇 GB 안에 들어갑니다. nfstream이
  설치되어 있으면 자동으로 켜집니다(`capture.enabled: auto`). 학습에는 이쪽을 씁니다.
- 패킷 헤더: `install-capture.sh`가 설치하는 수집 서비스가 패킷 헤더를 저장합니다. 트래픽이
  많으면 한 시간에 1 GB 가까이 쌓이므로 최근 몇 시간 분량만 남습니다(기본 최대 4 GB).
  나중에 특징을 바꿔 다시 뽑을 때 쓰는 원본입니다.

어느 쪽이든 패킷 내용은 저장하지 않습니다. 공격 트래픽은 외부와 분리된 실습망에서 따로
수집해야 합니다.

```bash
python3 -m ml.make_dataset --flows "/var/lib/checkhook/flows/*.csv" --label 0 --out ~/checkhook-data/benign.csv
python3 -m ml.make_dataset --pcap ~/checkhook-data/attack.pcap --attacker-ip <공격자 IP> --out ~/checkhook-data/attack.csv
checkhook train --data ~/checkhook-data/benign.csv --data ~/checkhook-data/attack.csv --out ~/checkhook-data/checkhook.joblib
checkhook eval  --model ~/checkhook-data/checkhook.joblib --data <학습에 쓰지 않은 정상 트래픽>.csv --target-fpr 0.01
```

`eval`은 학습에 쓰지 않은 정상 트래픽으로 오탐률을 측정하고, 목표 오탐률을 만족하는
임계값을 알려 줍니다. 모델 파일을 `/var/lib/checkhook/model.joblib`에 두고 설정 파일의
`ml.threshold`를 바꾼 뒤 `sudo systemctl restart checkhookd`로 데몬을 다시 시작하면
머신러닝 탐지가 켜집니다.

## 안전장치

- 처음 설치하면 `enforce: false` 상태로 시작합니다. 이 상태에서 탐지기는 차단 대상 IP를
  기록만 하고 실제로 차단하지 않습니다. 기록을 충분히 확인한 뒤 `enforce: true`로
  바꿉니다.
- 사설망, 루프백, 링크 로컬, 멀티캐스트 주소는 기본적으로 차단하지 않습니다. 게이트웨이처럼
  반드시 통신해야 하는 주소는 설정 파일의 `skip:`에 등록합니다.
- 모든 차단은 `block_timeout`(기본 1시간)이 지나면 자동으로 해제됩니다.
- 머신러닝 모델의 성능은 학습 데이터에 달려 있습니다. 모델을 사용하기 전에 `eval`로
  오탐률을 확인해야 합니다.
- 리눅스에서 CheckHook은 별도의 nftables 테이블(`ip checkhook`)만 사용하며 firewalld나 ufw
  규칙을 수정하지 않습니다. 윈도우에서는 `CheckHook` 그룹의 방화벽 규칙만 만들고 지웁니다.

## 디렉터리 구성

- `bin/`: 실행기 `checkhook`과 데몬 `checkhookd`
- `checkhook.cmd`: 윈도우 실행기
- `checkhook/`: 방화벽 서비스 (데몬, 차단 목록, IDS 연동, 머신러닝 탐지기, LLM 검토, XDP 집행,
  윈도우 방화벽 집행, 설정)
- `ml/`: 학습 데이터 생성, 모델 학습, 오탐률 평가
- `benchmark/`: 집행 계층 성능 측정 도구
- `packaging/`: systemd 서비스, 설치 스크립트, 설정 예시, Snort·Suricata 규칙, 데스크톱
  항목
- `packaging/windows/`: 윈도우 설치 스크립트, 실행기, 설정 예시
- `docs/`: 측정 결과, 그래프, 서비스 운영 문서, 리눅스 배포판별 설치, 윈도우 사용법
- `assets/`: 로고와 배너

## 라이선스

MIT 라이선스입니다. 단, XDP 프로그램(`checkhook/bpf/checkhook_xdp.c`)은 커널이 BPF 프로그램에
GPL 호환 라이선스 표기를 요구하기 때문에 MIT와 GPL-2.0 이중 라이선스로 배포합니다.
