#!/usr/bin/env python3
# =============================================================
#  log_generator.py  —  가상 회사 보안 로그 생성기
#
#  [이 스크립트가 하는 일]
#  실제 회사 서버에서 나올 법한 보안 로그를 흉내 내어 logs/security.log 에 기록한다.
#  정상 트래픽과 "의미 있는 공격 시퀀스"를 섞어서 만든다.
#  → 그래야 분석기(Step 4)가 Brute Force 같은 '패턴'을 탐지할 수 있다.
#
#  [사용법]
#    python3 log_generator.py --once            # 고정 공격 시나리오 1세트 생성 후 종료
#    python3 log_generator.py --stream          # 실시간처럼 계속 로그 추가 (Ctrl+C로 중지)
#    python3 log_generator.py --stream --interval 2   # 2초 간격으로 스트리밍
#
#  [설계 메모]
#  - 함수를 '이벤트 종류별'로 분리했다(generate_bruteforce 등). 역할이 명확해
#    유지보수/확장이 쉽다. (새 공격 추가 = 함수 하나 추가)
#  - 모든 함수는 '로그 문자열 리스트'를 돌려주기만 한다(부수효과 없음).
#    파일에 쓰는 일은 write_logs() 한 곳에서만 한다. → 테스트/재사용이 쉽다.
# =============================================================

import argparse
import random
import time
from datetime import datetime, timedelta

# 같은 폴더의 config.py 에서 공통 설정을 가져온다.
import config


# -------------------------------------------------------------
# 공통 유틸
# -------------------------------------------------------------
def _fmt(ts: datetime) -> str:
    """datetime → 로그용 문자열 'YYYY-MM-DD HH:MM:SS'."""
    return ts.strftime("%Y-%m-%d %H:%M:%S")


def _line(ts: datetime, event: str, **fields) -> str:
    """
    로그 한 줄을 표준 형식으로 조립한다.
    예) _line(ts, "LOGIN FAILED", user="admin", ip="203.0.113.2")
        → "2026-07-10 10:01:15 LOGIN FAILED user=admin ip=203.0.113.2"
    """
    tail = " ".join(f"{k}={v}" for k, v in fields.items())
    return f"{_fmt(ts)} {event} {tail}".rstrip()


# -------------------------------------------------------------
# 이벤트 종류별 생성 함수
#   각 함수는 (시작시각) → (로그줄 리스트) 를 돌려준다.
# -------------------------------------------------------------
def generate_normal(ts: datetime) -> list[str]:
    """정상 로그인 성공 1건 (사내 IP에서)."""
    return [_line(ts, config.EVENT_LOGIN_SUCCESS,
                  user=random.choice(config.USERNAMES),
                  ip=random.choice(config.INTERNAL_IPS))]


def generate_bruteforce(ts: datetime, attempts: int = 5) -> list[str]:
    """
    Brute Force 시나리오: 같은 외부 IP가 같은 계정으로
    짧은 시간에 로그인을 여러 번 실패한다.
    → 분석기가 '동일 IP 반복 실패'로 탐지하도록 만드는 핵심 패턴.
    """
    attacker_ip = random.choice(config.EXTERNAL_IPS)
    target_user = random.choice(config.USERNAMES)
    lines = []
    for i in range(attempts):
        # 각 시도를 몇 초 간격으로 벌린다.
        lines.append(_line(ts + timedelta(seconds=i * 3),
                           config.EVENT_LOGIN_FAILED,
                           user=target_user, ip=attacker_ip))
    return lines


def generate_port_scan(ts: datetime) -> list[str]:
    """포트 스캔 1건 (외부 IP가 서버 포트를 훑는 행위)."""
    return [_line(ts, config.EVENT_PORT_SCAN,
                  ip=random.choice(config.EXTERNAL_IPS))]


def generate_sql_injection(ts: datetime) -> list[str]:
    """SQL Injection 시도 1건."""
    return [_line(ts, config.EVENT_SQL_INJECTION,
                  ip=random.choice(config.EXTERNAL_IPS))]


def generate_xss(ts: datetime) -> list[str]:
    """XSS 공격 시도 1건."""
    return [_line(ts, config.EVENT_XSS,
                  ip=random.choice(config.EXTERNAL_IPS))]


def generate_malware(ts: datetime) -> list[str]:
    """멀웨어 탐지 1건 (특정 호스트에서)."""
    return [_line(ts, config.EVENT_MALWARE,
                  host=random.choice(config.HOSTS))]


# 스트리밍 모드에서 무작위로 하나씩 뽑아 쓸 '이벤트 생성기 풀'.
# (정상 트래픽에 가중치를 더 줘서 현실감 있게 — 공격은 가끔 발생)
_STREAM_POOL = (
    [generate_normal] * 5 +          # 정상이 가장 흔함
    [generate_bruteforce] * 2 +
    [generate_port_scan,
     generate_sql_injection,
     generate_xss,
     generate_malware]
)


# -------------------------------------------------------------
# 파일 쓰기 (부수효과는 여기 한 곳에만)
# -------------------------------------------------------------
def write_logs(lines: list[str]) -> None:
    """로그 줄들을 security.log 에 append 한다. 폴더가 없으면 만든다."""
    config.LOGS_DIR.mkdir(parents=True, exist_ok=True)
    with open(config.LOG_FILE, "a", encoding="utf-8") as f:
        for ln in lines:
            f.write(ln + "\n")


# -------------------------------------------------------------
# 모드 1) --once : 고정 시나리오 한 세트 생성
# -------------------------------------------------------------
def run_once() -> None:
    """
    프로젝트 예시와 비슷한 '하나의 사건 흐름'을 만든다.
    정상 로그인 → Brute Force → 포트스캔 → SQLi → XSS → 멀웨어 순서.
    시각은 현재 시각을 기준으로 순차적으로 벌려 놓는다.
    """
    now = datetime.now()
    scenario: list[str] = []

    scenario += generate_normal(now)
    scenario += generate_bruteforce(now + timedelta(seconds=15), attempts=5)
    scenario += generate_port_scan(now + timedelta(seconds=70))
    scenario += generate_sql_injection(now + timedelta(seconds=260))
    scenario += generate_xss(now + timedelta(seconds=350))
    scenario += generate_malware(now + timedelta(seconds=450))

    write_logs(scenario)
    print(f"[once] {len(scenario)} 줄 생성 → {config.LOG_FILE}")
    for ln in scenario:
        print("  " + ln)


# -------------------------------------------------------------
# 모드 2) --stream : 실시간처럼 계속 append
# -------------------------------------------------------------
def run_stream(interval: float) -> None:
    """
    interval 초마다 랜덤 이벤트를 하나씩 생성해 계속 추가한다.
    실제 서버 로그가 흘러가는 상황을 재현 → n8n 파일감시 트리거 데모에 적합.
    Ctrl+C 로 중지.
    """
    print(f"[stream] {interval}초 간격으로 로그 생성 시작. (Ctrl+C 로 중지)")
    print(f"[stream] 파일: {config.LOG_FILE}")
    try:
        while True:
            generator = random.choice(_STREAM_POOL)
            lines = generator(datetime.now())
            write_logs(lines)
            for ln in lines:
                print("  " + ln)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[stream] 중지됨.")


# -------------------------------------------------------------
# 진입점: 커맨드라인 인자 파싱
# -------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(description="가상 보안 로그 생성기")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--once", action="store_true",
                       help="고정 공격 시나리오 1세트 생성 후 종료")
    group.add_argument("--stream", action="store_true",
                       help="실시간처럼 계속 로그 생성")
    parser.add_argument("--interval", type=float, default=3.0,
                        help="stream 모드에서 생성 간격(초). 기본 3초")
    args = parser.parse_args()

    if args.once:
        run_once()
    else:
        run_stream(args.interval)


if __name__ == "__main__":
    main()
