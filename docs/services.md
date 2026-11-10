# 리눅스 서비스 운영

CheckHook은 리눅스에서 systemd 서비스 몇 개로 동작합니다. 모든 서비스는 설정 파일
`/etc/checkhook/checkhook.yaml` 하나를 공유합니다.

| 서비스 | 하는 일 | 설치 스크립트 |
|---|---|---|
| `checkhookd` | 데몬. IDS 경보 연동, 머신러닝 탐지(모델이 있을 때), 차단 만료, 한 시간 간격의 LLM 검토 | `install-services.sh` |
| `checkhook-capture` | 머신러닝 학습용 정상 트래픽 수집 (패킷 헤더만, `/var/lib/checkhook/benign.pcap00..39`) | `install-capture.sh` |
| `checkhook-ids` | CheckHook이 관리하는 Snort 3 센서 (JSON 경보, 포트 스캔 탐지) | `install-snort.sh` |
| `checkhook-xdp` | XDP 프로그램 부착 (`backend: xdp`일 때만) | `install-xdp.sh` |

## 설치

```bash
sudo bash packaging/install-capture.sh  <인터페이스>
sudo bash packaging/install-services.sh --iface <인터페이스>
sudo bash packaging/install-snort.sh    --iface <인터페이스>      # --community: 커뮤니티 규칙 포함
checkhook services
```

`install-services.sh`는 설정 파일이 없을 때만 만들기 때문에, 다시 실행해도 기존 설정을
덮어쓰지 않습니다. 같은 스크립트가 `checkhook`과 `checkhookd` 명령을 `/usr/local/bin`에
연결합니다.

## 안전 모델

- 설정 파일은 `enforce: false`로 시작합니다. 이 상태에서 탐지기는 `[would-block] <IP>`를
  기록만 하고 아무것도 차단하지 않습니다. `checkhook logs`로 한동안 지켜본 뒤 차단을 켭니다.
- 사설망(RFC1918), 루프백, 링크 로컬, 멀티캐스트 주소는 `block_private: true`가 아니면
  차단하지 않습니다. 게이트웨이처럼 반드시 통신해야 하는 주소는 `skip:`에 등록합니다.
- 모든 차단은 `block_timeout`(기본 1시간)이 지나면 해제됩니다.
- LLM 검토는 읽기 전용입니다. 경보와 차단 목록을 읽고 오탐 의심 IP와 `skip:` 제안을 보고서에
  쓸 뿐, 차단 목록이나 설정을 직접 바꾸지 않습니다. 경보 내용으로 LLM을 속여 차단을 풀게
  만드는 공격을 막기 위해서입니다.

차단을 켜는 방법은 다음과 같습니다.

```bash
sudo sed -i 's/^enforce: false/enforce: true/' /etc/checkhook/checkhook.yaml
sudo systemctl restart checkhookd
```

## 시그니처 탐지기

`checkhookd`는 설정 파일의 `ids:` 항목에 적힌 경보 파일을 읽습니다. Snort 3의 `alert_json`과
Suricata의 `eve.json`을 모두 읽으며, 줄마다 형식을 자동으로 구분합니다.

`install-snort.sh`는 CheckHook이 Snort 3를 직접 실행하도록 설정합니다.

- `snort`와 기본 `snort.lua`를 찾습니다(`--base 경로`로 지정 가능). 기본 `snort.lua`는
  수정하지 않습니다.
- `/etc/checkhook/snort/checkhook.lua`를 만듭니다. 이 파일은 기본 설정을 불러온 뒤 JSON 경보,
  `port_scan` 검사기와 내장 규칙, CheckHook의 `local.rules`(`--community`를 주면 Snort 3
  커뮤니티 규칙까지)를 더합니다.
- `snort -T`로 검증한 뒤에만 서비스를 켭니다. 사용 중인 Snort가 `port_scan` 설정을 거부하면
  그 부분을 빼고 다시 검증합니다.
- 설정 파일의 경보 파일 경로를 `/var/log/checkhook/snort/alert_json.txt`로 바꿉니다. 기존
  설정은 `checkhook.yaml.bak`으로 남습니다.

규칙 파일은 `/etc/checkhook/snort/local.rules`입니다. 고친 뒤에는
`sudo systemctl restart checkhook-ids`를 실행합니다. 파일 끝에는 전체 경로를 시험하는 ICMP
규칙이 주석으로 들어 있습니다. 경보 파일은 100 MB마다 교체되며, 데몬은 새 파일을 자동으로
따라갑니다.

Snort를 직접 실행하려면 `install-snort.sh`를 건너뛰고 `ids.alert_file`에 Snort가 쓰는
`alert_json.txt` 경로를 적습니다. 배포판의 Suricata를 쓰려면 `docs/linux.md`를 참고합니다.

## 머신러닝 모델

`checkhookd`는 `ml.model` 파일이 있을 때만 머신러닝 탐지를 켭니다.

```bash
mergecap -w ~/checkhook-data/benign_train.pcap /var/lib/checkhook/benign.pcap*
# 학습 데이터 생성, 학습, 평가는 README의 "머신러닝 모델 학습" 참고
sudo cp ~/checkhook-data/checkhook.joblib /var/lib/checkhook/model.joblib
sudo sed -i 's/^  threshold: .*/  threshold: 0.95/' /etc/checkhook/checkhook.yaml   # checkhook eval이 알려 준 값
sudo systemctl restart checkhookd
```

## XDP 집행

기본 집행 방식은 nftables set입니다. `install-xdp.sh`를 실행하면 XDP로 바뀝니다. XDP는
커널이 패킷 구조체(skb)를 만들기 전에 차단 대상 패킷을 버립니다. 성능 측정에서 차단 시
패킷당 CPU 사용량은 다른 해시 기반 방식의 절반 정도였습니다(`docs/results.md`).

```bash
sudo dnf install -y clang bpftool libbpf-devel          # 배포판별 패키지는 docs/linux.md
sudo bash packaging/install-xdp.sh --iface <인터페이스>   # 드라이버가 지원하면 --mode native
sudo checkhook xdp                                      # 차단 IP 수, 버린 패킷 수
sudo bash packaging/install-xdp.sh --revert             # nftables로 되돌리기
```

동작 방식은 다음과 같습니다.

- `checkhook/bpf/checkhook_xdp.c`를 clang으로 컴파일하고 `bpftool prog load ... pinmaps`로
  읽어 들입니다. 맵은 `/sys/fs/bpf/checkhook`에 고정되고, 프로그램은 `bpftool net attach`로
  인터페이스에 붙습니다. 이 부착은 CheckHook 프로세스와 관계없이 커널에 남으며, 부팅 시
  `checkhook-xdp`가 다시 붙입니다.
- 탐지기는 고정된 해시 맵에 항목을 넣습니다(키: 출발지 IPv4, 값: `CLOCK_MONOTONIC` 기준
  만료 시각). XDP 프로그램이 만료 시각을 직접 확인하고 지난 항목을 지우므로 `block_timeout`이
  nftables와 똑같이 동작합니다.
- 무선 랜카드는 보통 native XDP를 지원하지 않습니다. `mode: generic`은 모든 랜카드에서
  동작합니다.
- IPv4만 다룹니다. 재부팅하면 차단 항목은 사라집니다(nftables도 같습니다).

`enforce:`는 집행 방식과 별개입니다. `enforce: false`이면 어느 쪽 차단 목록에도 아무것도
쓰지 않습니다.

## firewalld, ufw와의 관계

CheckHook은 firewalld나 ufw의 규칙을 건드리지 않습니다. 모든 규칙은 별도의 nftables 테이블
`ip checkhook`에 있으며, 이 테이블의 입력 체인은 우선순위 -150에 붙어 일반 필터 규칙(우선순위
0)보다 먼저 실행됩니다.

- nftables는 하나의 훅에 붙은 모든 체인을 평가합니다. 어느 체인이든 drop은 최종 결정이며,
  다른 테이블의 accept가 이를 뒤집지 못합니다. 따라서 차단된 IP는 firewalld 설정과 관계없이
  차단됩니다.
- CheckHook은 차단만 하고 허용 규칙은 만들지 않으므로 기존 방화벽 정책을 약하게 만들지
  않습니다.

직접 확인하는 방법입니다(테이블 이름은 firewalld 버전에 따라 다릅니다).

```bash
sudo nft list tables                    # ip checkhook과 firewalld의 테이블이 보여야 합니다
sudo firewall-cmd --reload
sudo nft list tables                    # 다시 불러온 뒤에도 ip checkhook이 남아 있어야 합니다
sudo nft list chain ip checkhook input  # priority -150 ... ip saddr @blocklist drop
```

firewalld를 다시 불러올 때 `checkhook` 테이블이 사라지는 환경이라면
`sudo systemctl restart checkhookd`로 다시 만들 수 있습니다. 이 경우 그때까지의 차단 항목은
사라집니다.

## 제거

```bash
sudo bash packaging/install-snort.sh    --uninstall   # /etc/checkhook/snort는 남김
sudo bash packaging/install-xdp.sh      --revert
sudo bash packaging/install-services.sh --uninstall   # /etc/checkhook는 남김
sudo bash packaging/install-capture.sh  --uninstall   # 수집한 파일은 남김
sudo checkhook teardown                               # nftables 테이블 삭제
```
