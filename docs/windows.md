# 윈도우에서 사용하기

윈도우 10과 11을 대상으로 합니다. 이 문서의 설치 과정은 아직 실제 윈도우 환경에서 시험하지
않았습니다. 문제가 생기면 `C:\ProgramData\CheckHook\logs\checkhookd.log`를 확인합니다.

## 리눅스와 다른 점

윈도우에는 nftables와 XDP가 없고, Snort 3도 공식 윈도우 배포판이 없습니다. 그래서 다음과
같이 구성합니다.

| 역할 | 리눅스 | 윈도우 |
|---|---|---|
| 시그니처 탐지 | Snort 3 또는 Suricata | Suricata (`eve.json`) |
| 머신러닝 탐지 | nfstream | nfstream + Npcap |
| 집행 | nftables 또는 XDP | Windows Defender 방화벽 규칙 |
| 차단 만료 | 커널이 처리 | checkhookd가 1분마다 처리 |
| 학습 데이터 수집 | tcpdump (패킷 헤더) | checkhookd가 flow 통계를 CSV로 기록 |
| 실행 방식 | systemd 서비스 `checkhookd` | 예약 작업 `checkhookd` (부팅 시 SYSTEM 권한으로 시작) |

차단된 IP는 방화벽의 인바운드와 아웃바운드 규칙에 모두 등록되어 양방향 통신이 막힙니다.
방화벽 규칙은 `CheckHook` 그룹에 묶여 있어 다른 방화벽 규칙과 섞이지 않습니다. 윈도우
방화벽은 커널 단계에서 동작하지만 XDP처럼 드라이버 단계에서 패킷을 버리지는 않으므로,
성능 측정 결과의 XDP 수치는 윈도우에 해당하지 않습니다.

## 준비

1. Python 3.9 이상을 설치합니다. 예: `winget install Python.Python.3.12`. 설치 프로그램을 쓸
   경우 "Add python.exe to PATH"를 선택합니다.
2. Npcap을 설치합니다(https://npcap.com). 설치 화면의 "WinPcap API-compatible Mode"
   옵션을 켜 두면 Suricata와의 호환 문제를 줄일 수 있습니다.
3. 시그니처 탐지를 쓰려면 Suricata 윈도우 설치 파일(MSI)을 설치합니다
   (https://suricata.io/download). 설치하지 않아도 머신러닝 탐지와 차단은 동작합니다.
4. LLM 검토를 쓰려면 Ollama 윈도우 버전을 설치하고 모델을 받습니다.
   예: `ollama pull qwen2.5:7b`

## 설치

저장소를 내려받은 뒤 관리자 권한 PowerShell에서 실행합니다.

```powershell
git clone https://github.com/VertigoJang/checkhook C:\CheckHook
cd C:\CheckHook
powershell -ExecutionPolicy Bypass -File packaging\windows\install.ps1
```

설치 스크립트는 다음을 처리합니다.

- Python과 Npcap을 확인하고 Python 패키지(nfstream, scikit-learn, joblib, pyyaml,
  pandas)를 설치합니다. nfstream 설치가 실패하면 Python 3.12로 다시 시도합니다.
- `C:\ProgramData\CheckHook`에 설정 파일, 로그, flow 기록, Suricata 출력 폴더를 만듭니다. 이
  폴더는 관리자와 SYSTEM만 수정할 수 있습니다. 일반 사용자는 읽기만 가능합니다.
- Suricata가 설치되어 있으면 CheckHook 규칙을 추가하고 `suricata -T`로 설정을 검증한 뒤
  `checkhook-suricata` 예약 작업을 등록합니다.
- `checkhookd` 예약 작업을 등록합니다. checkhookd는 경보 연동, 머신러닝 탐지와 flow 기록,
  차단 만료, 한 시간 간격의 LLM 검토를 한 프로세스에서 실행합니다.
- 시작 메뉴에 CheckHook 바로 가기를 만듭니다.

기본 경로를 쓰는 어댑터가 아닌 다른 어댑터를 쓰려면 `-Adapter "Wi-Fi"`처럼 이름을 지정합니다.
Suricata를 쓰지 않으려면 `-NoSuricata`를 붙입니다.

## 사용

시작 메뉴의 CheckHook를 누르거나 저장소 폴더에서 `.\checkhook.cmd`를 실행합니다. 차단 목록을
바꾸는 명령은 관리자 권한 PowerShell에서 실행해야 합니다.

```powershell
.\checkhook.cmd services          # 예약 작업 상태, enforce, 방화벽 규칙 수
.\checkhook.cmd logs              # checkhookd 로그 실시간 보기
.\checkhook.cmd status            # 차단 목록
.\checkhook.cmd block 8.8.8.8 --timeout 1m
.\checkhook.cmd unblock 8.8.8.8
.\checkhook.cmd report            # LLM 검토 보고서
.\checkhook.cmd restart           # 설정 변경 후 checkhookd 재시작
```

설정 파일은 `C:\ProgramData\CheckHook\checkhook.yaml`입니다. 처음에는 `enforce: false`라서
탐지기는 차단 대상 IP를 기록만 합니다.

## 머신러닝 모델 학습

checkhookd는 `capture.enabled: true`일 때 flow 통계를 `C:\ProgramData\CheckHook\flows`에 CSV로
기록합니다. 패킷 내용은 저장하지 않습니다.

```powershell
.\checkhook.cmd dataset --flows "C:/ProgramData/CheckHook/flows/*.csv" --label 0 --out benign.csv
.\checkhook.cmd dataset --flows "attack-flows/*.csv" --attacker-ip <공격자 IP> --out attack.csv
.\checkhook.cmd train --data benign.csv --data attack.csv --out model.joblib
.\checkhook.cmd eval --model model.joblib --data <학습에 쓰지 않은 정상 트래픽>.csv --target-fpr 0.01
```

만든 모델을 `C:\ProgramData\CheckHook\model.joblib`에 복사하고 `.\checkhook.cmd restart`로
checkhookd를 다시 시작하면 머신러닝 탐지가 켜집니다. 공격 트래픽은 외부와 분리된 실습망에서
수집해야 합니다.

## 제거

```powershell
powershell -ExecutionPolicy Bypass -File packaging\windows\install.ps1 -Uninstall
```

예약 작업, `CheckHook` 방화벽 규칙, 시작 메뉴 바로 가기를 지웁니다. 설정과 수집한 데이터는
`C:\ProgramData\CheckHook`에 남습니다.

## 문제 해결

- checkhookd가 시작되지 않으면 `C:\ProgramData\CheckHook\logs\checkhookd.log`와 작업
  스케줄러의 `checkhookd` 기록을 확인합니다.
- Suricata 설정 검증이 실패하면 `C:\ProgramData\CheckHook\logs\suricata-test.log`를 확인합니다.
- Suricata가 `eve.json`을 만들지 않으면 캡처 장치 이름 문제일 수 있습니다. 작업 스케줄러에서
  `checkhook-suricata` 작업의 `-i` 인자를 어댑터의 IPv4 주소로 바꿔 시험해 봅니다.
