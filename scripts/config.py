# =============================================================
#  config.py  —  프로젝트 공통 설정 (단일 진실 공급원)
#
#  [왜 이 파일이 있는가]
#  경로, IP 목록, 이벤트 종류 같은 값이 여러 스크립트에서 쓰인다.
#  한 곳에 모아두면 나중에 바꿀 때 한 군데만 고치면 된다.
#  (log_generator.py, analyzer.py 등이 이 파일을 import 한다.)
# =============================================================

from pathlib import Path

# -------------------------------------------------------------
# 1) 경로 설정
# -------------------------------------------------------------
# 이 파일(config.py)은 <프로젝트>/scripts/config.py 에 있다.
# 따라서 부모의 부모가 프로젝트 루트다.
#   - 호스트에서 실행:   /Users/.../security-log-platform
#   - 컨테이너에서 실행:  /data   (scripts/logs/output이 그 아래 마운트됨)
# 파일 기준 상대경로라 두 환경에서 똑같이 동작한다.
BASE_DIR = Path(__file__).resolve().parent.parent

LOGS_DIR = BASE_DIR / "logs"
OUTPUT_DIR = BASE_DIR / "output"
REPORTS_DIR = OUTPUT_DIR / "reports"

# 생성기가 기록하고, 분석기가 읽는 메인 로그 파일
LOG_FILE = LOGS_DIR / "security.log"

# 분석 결과가 쌓이는 CSV (Step 8에서 사용)
EVENTS_CSV = OUTPUT_DIR / "events.csv"


# -------------------------------------------------------------
# 2) 가상 회사 네트워크 구성 (로그 생성용)
# -------------------------------------------------------------
# 사내(정상)로 취급할 IP 대역 예시. 여기서 오는 트래픽은 대체로 정상.
INTERNAL_IPS = [
    "192.168.0.5", "192.168.0.11", "192.168.0.23", "192.168.0.42",
]

# 외부(공격자로 자주 쓰는) IP. 문서화용 예약 대역(RFC 5737)을 사용해
# 실제 존재하는 IP를 건드리지 않는다.
EXTERNAL_IPS = [
    "203.0.113.2", "203.0.113.8", "203.0.113.20",
    "198.51.100.5", "198.51.100.77",
]

# 로그인 시도에 쓰이는 계정명
USERNAMES = ["admin", "root", "guest", "jenkins", "backup"]

# 멀웨어 탐지 대상 호스트명
HOSTS = ["PC-01", "PC-02", "SRV-DB-01", "SRV-WEB-01"]


# -------------------------------------------------------------
# 3) 이벤트 종류 (로그 원문에 찍히는 문자열)
#    분석기(Step 4)가 이 문자열을 보고 공격 유형을 판별한다.
# -------------------------------------------------------------
EVENT_LOGIN_SUCCESS = "LOGIN SUCCESS"
EVENT_LOGIN_FAILED = "LOGIN FAILED"
EVENT_PORT_SCAN = "PORT SCAN"
EVENT_SQL_INJECTION = "SQL INJECTION"
EVENT_XSS = "XSS ATTACK"
EVENT_MALWARE = "MALWARE DETECTED"


# -------------------------------------------------------------
# 4) 위험도 스코어링 규칙  (Step 4 분석기가 사용)
#    [왜 데이터로 분리하나] 점수 정책은 자주 바뀐다.
#    규칙을 코드가 아니라 '표(dict)'로 두면, 로직을 건드리지 않고
#    이 값만 고쳐서 튜닝할 수 있다. (나중에 JSON/DB로 빼기도 쉬움)
# -------------------------------------------------------------

# 단일 이벤트 기본 점수 (로그 원문 문자열 → 점수)
SCORE_RULES = {
    EVENT_LOGIN_SUCCESS: 0,    # 정상 로그인은 위험도 0
    EVENT_LOGIN_FAILED: 10,    # 로그인 실패 1건
    EVENT_PORT_SCAN: 40,
    EVENT_SQL_INJECTION: 80,
    EVENT_XSS: 60,
    EVENT_MALWARE: 100,
}

# Brute Force 판정: "같은 IP에서 로그인 실패가 이 횟수 이상"이면
# 개별 실패(10점)를 하나의 Brute Force 사건(아래 점수)으로 승격한다.
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_SCORE = 60

# 분석기가 출력에 쓰는 표준 공격 유형 이름 (데이터 계약)
TYPE_LOGIN_SUCCESS = "LOGIN_SUCCESS"
TYPE_LOGIN_FAILED = "LOGIN_FAILED"
TYPE_BRUTE_FORCE = "BRUTE_FORCE"
TYPE_PORT_SCAN = "PORT_SCAN"
TYPE_SQL_INJECTION = "SQL_INJECTION"
TYPE_XSS = "XSS"
TYPE_MALWARE = "MALWARE"

# 로그 원문 이벤트 → 표준 유형 이름 매핑
EVENT_TO_TYPE = {
    EVENT_LOGIN_SUCCESS: TYPE_LOGIN_SUCCESS,
    EVENT_LOGIN_FAILED: TYPE_LOGIN_FAILED,
    EVENT_PORT_SCAN: TYPE_PORT_SCAN,
    EVENT_SQL_INJECTION: TYPE_SQL_INJECTION,
    EVENT_XSS: TYPE_XSS,
    EVENT_MALWARE: TYPE_MALWARE,
}

# 점수 → 위험 등급(severity) 구간.
# 높은 점수부터 검사하며, 처음 만족하는 등급을 쓴다.
SEVERITY_BANDS = [
    (90, "CRITICAL"),
    (60, "HIGH"),
    (30, "MEDIUM"),
    (0,  "LOW"),
]

# 이 점수 이상인 이벤트만 Discord 알림을 보낸다. (.env로 조정 가능)
import os
ALERT_MIN_SCORE = int(os.getenv("ALERT_MIN_SCORE", "30"))


def score_to_severity(score: int) -> str:
    """점수를 LOW/MEDIUM/HIGH/CRITICAL 로 변환한다."""
    for threshold, label in SEVERITY_BANDS:
        if score >= threshold:
            return label
    return "LOW"
