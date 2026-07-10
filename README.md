# 🛡️ Security Log Automation Platform

<!-- 기술 스택 배지 (shields.io 정적 배지 — GitHub 에서 자동 렌더링) -->
![n8n](https://img.shields.io/badge/n8n-workflow-EA4B71?logo=n8n&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)
![OpenAI](https://img.shields.io/badge/OpenAI-API-412991?logo=openai&logoColor=white)
![Discord](https://img.shields.io/badge/Discord-Webhook-5865F2?logo=discord&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)

n8n · Python · OpenAI · Discord 로 구성한 **보안 로그 자동 분석 & AI 대응 시스템 (SOAR)**.
가상 회사 서버 로그를 생성 → 자동 감지 → 위험도 분석 → AI 요약 → Discord 알림 → CSV/리포트 저장까지
실제 보안 운영(SOC) 사이클을 경량 도구로 재현한 포트폴리오 프로젝트입니다.

🔗 **Repository**: https://github.com/heejinny/security-log-platform

> ⚠️ 모든 IP 는 문서화 전용 예약 대역(RFC 5737: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`)을
> 사용한 **가상 데이터**이며, 실제 시스템을 대상으로 하지 않는 **교육·포트폴리오용** 프로젝트입니다.

---

## 1. 프로젝트 소개

기업의 보안 운영은 보통 **탐지(SIEM) → 분석 → 판단 → 자동 대응(SOAR) → 기록/리포트**의 사이클로 돌아갑니다.
이 프로젝트는 그 사이클을 다음과 같이 흉내 냅니다.

| 실무 구성요소 | 실무 예시 | 이 프로젝트 |
|---|---|---|
| 로그 소스 | 방화벽 / 웹서버 / EDR | `log_generator.py` (가상 로그) |
| 수집 / 감지 | Splunk, ELK, Wazuh | **n8n** (스케줄 트리거 + Execute Command) |
| 분석 엔진 | 상관분석 룰, ML | `analyzer.py` (룰 기반 스코어링) |
| 판단 보조 | 보안 애널리스트 | **OpenAI API** (한국어 요약) |
| 자동 대응 / 알림 | PagerDuty, Slack | **Discord Webhook** |
| 기록 / 리포트 | 케이스 DB, 대시보드 | CSV / JSON 파일 |

> 초기 버전은 **DB 없이 파일(CSV/JSON)** 로 시작하되, 저장소를 추상화(`storage.py`)해
> 나중에 MySQL / Elasticsearch 로 쉽게 교체할 수 있도록 설계했습니다.

---

## 2. 아키텍처

```
                          ┌──────────────────────────────┐
   log_generator.py       │        Docker (n8n+python)    │
   (가상 로그 생성)        │                               │
        │  logs/*.log      │   ┌──────────┐  스케줄 트리거  │
        └───────────────►  │   │   n8n    │──┐             │
                          │   └──────────┘  │ Execute Cmd  │
                          │                 ▼              │
                          │        run_pipeline.py         │
                          │   analyzer → ai_client         │
                          │        → notifier → storage    │
                          └───────┬───────┬────────┬───────┘
                                  │       │        │
                            Discord   output/    output/reports/
                            (알림)    events.csv  report_*.json/.csv
```

### 설계 원칙
1. **관심사 분리** — n8n = 오케스트레이션(언제/얼마나 자주), Python = 로직(어떻게 분석·판단).
2. **데이터 계약(JSON) 고정** — analyzer 가 표준 JSON 을 출력하고, 이후 모든 단계가 그것만 소비.
3. **Graceful Degradation** — OpenAI 키/Discord 웹훅이 없어도 파이프라인이 죽지 않고 대체 동작.
4. **stdout = JSON 전용** — 진단 로그는 stderr 로. n8n 이 stdout 을 그대로 JSON 파싱.

---

## 3. 실행 방법

### 사전 준비
- Docker / Docker Compose 설치
- (선택) OpenAI API Key, Discord Webhook URL

### 1) 환경변수 설정
```bash
cp .env.example .env
# .env 를 열어 OPENAI_API_KEY, DISCORD_WEBHOOK_URL 등을 채운다.
# (비워두면 규칙 기반 요약 + 콘솔 출력으로 자동 대체된다.)
```

### 2) 컨테이너 빌드 & 기동
```bash
docker compose up -d --build
# 브라우저에서 http://localhost:5678 접속 → 최초 1회 관리자 계정 생성
```

### 3) 가상 로그 생성
```bash
# 고정 공격 시나리오 1세트
python3 scripts/log_generator.py --once
# 또는 실시간 스트리밍 (Ctrl+C 로 중지)
python3 scripts/log_generator.py --stream --interval 2
```

### 4) 파이프라인 수동 실행 (n8n 없이도 검증 가능)
```bash
# 호스트에서
python3 scripts/run_pipeline.py
# 또는 컨테이너 안에서 (n8n Execute Command 와 동일)
docker compose exec n8n python3 /data/scripts/run_pipeline.py
```

### 5) n8n 워크플로우 임포트
n8n UI → 우상단 메뉴 → **Import from File** →
`n8n/workflows/alert-pipeline.json`, `n8n/workflows/daily-report.json` 선택 → 저장 → Active 토글.

- **Security Alert Pipeline**: 1분마다 `run_pipeline.py` 실행 (분석→AI→Discord→CSV)
- **Daily Security Report**: 매일 09:00 `report.py` 실행 (일일 리포트 생성)

---

## 4. 기능 설명

| 파일 | 역할 |
|---|---|
| `scripts/config.py` | 경로·IP풀·스코어링 규칙 등 **공통 설정(단일 진실 공급원)** |
| `scripts/log_generator.py` | 가상 보안 로그 생성 (`--once` / `--stream`) |
| `scripts/analyzer.py` | 로그 파싱 + 위험도 스코어링 + Brute Force 승격 → 표준 JSON |
| `scripts/ai_client.py` | OpenAI 한국어 요약 (실패 시 규칙 기반 대체) |
| `scripts/notifier.py` | Discord Webhook 전송 (미설정 시 콘솔 미리보기) |
| `scripts/storage.py` | CSV 저장 (`Storage` 추상화 → DB 확장 지점) |
| `scripts/report.py` | 일일 리포트 집계 → JSON + CSV |
| `scripts/run_pipeline.py` | 위 모듈을 묶는 **오케스트레이터** (n8n 이 호출) |

### 위험도 스코어링 규칙 (`config.py`)
| 이벤트 | 점수 |
|---|---|
| LOGIN FAILED | 10 |
| 동일 IP 5회 이상 → Brute Force | 60 |
| PORT SCAN | 40 |
| SQL INJECTION | 80 |
| XSS | 60 |
| MALWARE | 100 |

점수 → 등급: `0–29 LOW · 30–59 MEDIUM · 60–89 HIGH · 90–100 CRITICAL`

### 산출물
- `output/events.csv` — `timestamp,event,ip,score,severity,ai_summary`
- `output/reports/report_YYYY-MM-DD.json` / `.csv` — 일일 종합 리포트

---

## 5. 스크린샷 위치

`docs/screenshots/` 에 아래 이미지를 넣어 README 에서 참조하세요.

- `docs/screenshots/n8n-workflow.png` — n8n 워크플로우 캔버스
- `docs/screenshots/discord-alert.png` — Discord 보안 알림 카드
- `docs/screenshots/csv-output.png` — events.csv 결과
- `docs/screenshots/daily-report.png` — 일일 리포트

```markdown
![n8n workflow](docs/screenshots/n8n-workflow.png)
![discord alert](docs/screenshots/discord-alert.png)
```

---

## 6. 향후 개선 방향

- **저장소 확장**: `storage.py` 에 `MySQLStorage` / `ElasticStorage` 구현 추가
  (호출부 `get_storage("mysql")` 만 바꾸면 됨 — 인터페이스 이미 준비).
- **분석기 서비스화(2컨테이너)**: `analyzer`/`run_pipeline` 을 FastAPI 로 감싸 별도 컨테이너로 분리,
  n8n 은 Execute Command 대신 HTTP Request 노드로 호출 → 관심사 완전 분리·수평 확장.
- **실시간 탐지**: 파일 폴링 대신 `inotify` / n8n Webhook 트리거로 이벤트 즉시 처리.
- **대시보드**: Elasticsearch + Kibana(또는 Grafana) 연동으로 시각화.
- **탐지 고도화**: 룰 기반 → 이상탐지(ML), 위협 인텔리전스(IP 평판) 연동.
- **알림 라우팅**: 위험도별 채널 분기, PagerDuty/Slack/Email 다중 채널.

---

## 7. 기술 스택
Docker · Docker Compose · n8n · Python 3.12 · OpenAI API · Discord Webhook · CSV / JSON

---

## 8. 라이선스
[MIT License](LICENSE) © 2026 heejinny
