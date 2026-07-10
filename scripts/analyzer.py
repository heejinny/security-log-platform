#!/usr/bin/env python3
# =============================================================
#  analyzer.py  —  로그 분석 + 위험도 스코어링  (프로젝트의 심장)
#
#  [하는 일]
#  1) logs/security.log 를 한 줄씩 읽어 구조화(파싱)한다.
#  2) 위험도 점수를 매긴다. (config.SCORE_RULES 기반)
#  3) "같은 IP 로그인 실패 N회 이상" → Brute Force 사건으로 승격한다.
#  4) Step 1에서 정한 '표준 JSON 계약' 형태의 이벤트 리스트를 돌려준다.
#     → 이 JSON을 이후 OpenAI/Discord/CSV/리포트가 그대로 소비한다.
#
#  [설계 원칙]
#  - '읽기(파싱)'와 '판단(스코어링)'을 함수로 분리 → 각각 테스트 가능.
#  - 점수/임계값은 config.py 의 데이터를 참조 → 정책 변경이 쉬움.
#  - 표준 출력은 항상 같은 스키마를 지킨다(데이터 계약). 앞뒤 단계가 안 깨진다.
#
#  [단독 실행]
#    python3 analyzer.py                # logs/security.log 분석 → JSON 출력
#    python3 analyzer.py --min-score 30 # 점수 30 이상만 출력
# =============================================================

# 타입 힌트를 '지연 평가'시켜, Python 3.9에서도 'dict | None' 같은
# 최신 문법을 문제없이 쓰게 한다. (호스트 3.9 / 컨테이너 3.12 모두 호환)
from __future__ import annotations

import argparse
import json
import re

import config

# 로그 한 줄을 파싱하는 정규식.
#   그룹1: 타임스탬프 (앞 19글자, 'YYYY-MM-DD HH:MM:SS')
#   그룹2: 나머지(이벤트 + key=value 들)
_LINE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(.*)$")

# 알려진 이벤트 문자열(두 단어)을 로그 뒷부분에서 찾아내기 위한 목록.
# 긴 것부터 매칭해야 "LOGIN"만 잘리는 실수를 피한다.
_KNOWN_EVENTS = sorted(config.SCORE_RULES.keys(), key=len, reverse=True)


# -------------------------------------------------------------
# 1) 파싱: 로그 문자열 → 구조화된 dict
# -------------------------------------------------------------
def parse_line(line: str) -> dict | None:
    """
    로그 한 줄을 dict 로 변환한다. 형식이 안 맞으면 None.
    반환 예:
      {"timestamp": "...", "event": "LOGIN FAILED",
       "fields": {"user": "admin", "ip": "203.0.113.2"}}
    """
    line = line.strip()
    if not line:
        return None

    m = _LINE_RE.match(line)
    if not m:
        return None
    timestamp, rest = m.group(1), m.group(2)

    # rest 앞부분에서 알려진 이벤트 문자열을 찾는다.
    event = None
    for ev in _KNOWN_EVENTS:
        if rest.startswith(ev):
            event = ev
            rest = rest[len(ev):].strip()
            break
    if event is None:
        return None  # 모르는 이벤트는 무시

    # 남은 부분의 key=value 들을 dict 로 파싱
    fields = {}
    for token in rest.split():
        if "=" in token:
            k, v = token.split("=", 1)
            fields[k] = v

    return {"timestamp": timestamp, "event": event, "fields": fields}


def parse_file(path=None) -> list[dict]:
    """로그 파일 전체를 파싱해 dict 리스트로 돌려준다."""
    path = path or config.LOG_FILE
    parsed = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                item = parse_line(line)
                if item:
                    parsed.append(item)
    except FileNotFoundError:
        return []
    return parsed


# -------------------------------------------------------------
# 2) 표준 이벤트(데이터 계약) 만들기
# -------------------------------------------------------------
def _make_event(timestamp, event_type, score, reason,
                ip=None, host=None, raw_logs=None) -> dict:
    """Step 1에서 정의한 표준 스키마대로 이벤트 dict 를 만든다."""
    return {
        "timestamp": timestamp,
        "event_type": event_type,
        "ip": ip,
        "host": host,
        "score": score,
        "severity": config.score_to_severity(score),
        "reason": reason,
        "raw_logs": raw_logs or [],
        "ai_summary": None,   # Step 6(OpenAI)에서 채워짐
    }


# -------------------------------------------------------------
# 3) 스코어링: 파싱된 로그 → 표준 이벤트 리스트
# -------------------------------------------------------------
def analyze(parsed: list[dict]) -> list[dict]:
    """
    파싱된 로그를 받아 위험도를 매긴 표준 이벤트 리스트를 만든다.
    핵심: 로그인 실패는 IP별로 모아, 임계값 이상이면 Brute Force로 승격.
    """
    events: list[dict] = []

    # (a) IP별 로그인 실패를 모은다. {ip: [로그dict, ...]}
    failed_by_ip: dict[str, list[dict]] = {}

    for item in parsed:
        ev = item["event"]
        f = item["fields"]
        ip = f.get("ip")
        host = f.get("host")
        raw = _rebuild_raw(item)

        if ev == config.EVENT_LOGIN_FAILED and ip:
            failed_by_ip.setdefault(ip, []).append(item)
            continue  # 실패 로그인은 아래에서 한꺼번에 처리

        if ev == config.EVENT_LOGIN_SUCCESS:
            # 정상 로그인: 통계용으로만 기록(점수 0)
            events.append(_make_event(
                item["timestamp"], config.TYPE_LOGIN_SUCCESS, 0,
                "정상 로그인 성공", ip=ip, raw_logs=[raw]))
            continue

        # 그 외 단일 공격 이벤트 (포트스캔/SQLi/XSS/멀웨어)
        score = config.SCORE_RULES.get(ev, 0)
        etype = config.EVENT_TO_TYPE.get(ev, "UNKNOWN")
        events.append(_make_event(
            item["timestamp"], etype, score,
            _default_reason(etype), ip=ip, host=host, raw_logs=[raw]))

    # (b) IP별 로그인 실패를 판정
    for ip, items in failed_by_ip.items():
        count = len(items)
        raws = [_rebuild_raw(x) for x in items]
        first_ts = items[0]["timestamp"]

        if count >= config.BRUTE_FORCE_THRESHOLD:
            # 임계값 이상 → Brute Force 사건으로 승격
            events.append(_make_event(
                first_ts, config.TYPE_BRUTE_FORCE, config.BRUTE_FORCE_SCORE,
                f"동일 IP({ip})에서 로그인 실패 {count}회 발생 → Brute Force 의심",
                ip=ip, raw_logs=raws))
        else:
            # 미만 → 개별 실패로 기록 (각 10점)
            for x in items:
                events.append(_make_event(
                    x["timestamp"], config.TYPE_LOGIN_FAILED,
                    config.SCORE_RULES[config.EVENT_LOGIN_FAILED],
                    f"로그인 실패 (IP {ip})", ip=ip,
                    raw_logs=[_rebuild_raw(x)]))

    # 시간순 정렬 후 반환
    events.sort(key=lambda e: e["timestamp"])
    return events


def _rebuild_raw(item: dict) -> str:
    """파싱된 dict 를 사람이 읽는 원본 형태 문자열로 되돌린다(근거 보존용)."""
    tail = " ".join(f"{k}={v}" for k, v in item["fields"].items())
    return f'{item["timestamp"]} {item["event"]} {tail}'.rstrip()


def _default_reason(event_type: str) -> str:
    """공격 유형별 기본 설명(사람이 읽는 한 줄)."""
    return {
        config.TYPE_PORT_SCAN: "외부 IP가 포트 스캔을 시도했습니다.",
        config.TYPE_SQL_INJECTION: "SQL Injection 공격 시도가 탐지되었습니다.",
        config.TYPE_XSS: "XSS(교차 사이트 스크립팅) 공격 시도가 탐지되었습니다.",
        config.TYPE_MALWARE: "호스트에서 악성코드가 탐지되었습니다.",
    }.get(event_type, "보안 이벤트가 탐지되었습니다.")


# -------------------------------------------------------------
# 진입점
# -------------------------------------------------------------
def run(path=None, min_score: int = 0) -> list[dict]:
    """파일을 읽어 분석하고, min_score 이상 이벤트만 돌려준다."""
    parsed = parse_file(path)
    events = analyze(parsed)
    if min_score > 0:
        events = [e for e in events if e["score"] >= min_score]
    return events


def main() -> None:
    parser = argparse.ArgumentParser(description="보안 로그 분석기")
    parser.add_argument("--min-score", type=int, default=0,
                        help="이 점수 이상 이벤트만 출력")
    parser.add_argument("--file", default=None, help="분석할 로그 파일 경로")
    args = parser.parse_args()

    events = run(path=args.file, min_score=args.min_score)
    # n8n Execute Command 가 받아 파싱할 수 있도록 JSON 으로 출력
    print(json.dumps(events, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
