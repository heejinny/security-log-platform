#!/usr/bin/env python3
# =============================================================
#  ai_client.py  —  OpenAI 로 보안 이벤트를 한국어로 요약
#
#  [하는 일]
#  분석기가 만든 이벤트(dict)를 받아, 사람이 읽기 쉬운 한국어 요약을 만든다.
#  요약에는 원인 / 예상 영향 / 권장 대응이 담긴다.
#
#  [핵심 설계: Graceful Degradation]
#  - OPENAI_API_KEY 가 있으면 → OpenAI 호출
#  - 키가 없거나 호출이 실패하면 → '규칙 기반 요약'으로 대체
#  즉, 외부 API가 죽어도 파이프라인 전체는 계속 동작한다.
#  (실무에서 외부 의존성은 항상 실패를 가정해야 한다.)
# =============================================================

from __future__ import annotations

import os
import sys

import config


def _log(msg: str) -> None:
    """진단 메시지는 stderr 로 (stdout 은 JSON 전용)."""
    print(msg, file=sys.stderr)


# -------------------------------------------------------------
# 프롬프트 조립 (OpenAI 에 보낼 지시문)
# -------------------------------------------------------------
def _build_prompt(event: dict) -> str:
    """이벤트 정보를 바탕으로 OpenAI 에 줄 질문을 만든다."""
    target = event.get("ip") or event.get("host") or "알 수 없음"
    return (
        "너는 기업 보안 관제(SOC) 애널리스트다. 아래 보안 이벤트를 "
        "비전문가도 이해할 수 있는 한국어로 3~4문장으로 요약하라. "
        "반드시 (1) 원인 (2) 예상 영향 (3) 권장 대응 을 포함하라.\n\n"
        f"- 공격 종류: {event.get('event_type')}\n"
        f"- 대상(IP/호스트): {target}\n"
        f"- 위험도: {event.get('severity')} ({event.get('score')}점)\n"
        f"- 탐지 근거: {event.get('reason')}\n"
    )


# -------------------------------------------------------------
# 1) OpenAI 실제 호출
# -------------------------------------------------------------
def _summarize_with_openai(event: dict) -> str | None:
    """
    OpenAI 로 요약을 생성한다.
    실패(키 없음/네트워크/쿼터)하면 None 을 돌려줘 상위에서 대체하게 한다.
    """
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    # 키가 없거나 템플릿 값 그대로면 호출하지 않는다.
    if not api_key or api_key.startswith("sk-여기에"):
        return None

    try:
        from openai import OpenAI
        client = OpenAI(api_key=api_key)
        model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        resp = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": _build_prompt(event)}],
            temperature=0.3,
            max_tokens=300,
        )
        return resp.choices[0].message.content.strip()
    except Exception as e:
        # 호출 실패는 치명적 오류가 아니다 → 로그만 남기고 대체로 넘어간다.
        _log(f"[ai_client] OpenAI 호출 실패, 규칙 기반으로 대체: {e}")
        return None


# -------------------------------------------------------------
# 2) 규칙 기반 대체 요약 (키 없거나 실패 시)
# -------------------------------------------------------------
_FALLBACK_TEMPLATES = {
    config.TYPE_BRUTE_FORCE: (
        "동일한 IP({target})에서 반복적인 로그인 실패가 발생하여 Brute Force "
        "공격으로 의심됩니다. 성공 시 계정 탈취로 이어질 수 있으므로, 해당 IP를 "
        "차단하고 대상 계정의 비밀번호 변경 및 다중 인증(MFA) 적용을 권장합니다."
    ),
    config.TYPE_PORT_SCAN: (
        "외부 IP({target})가 서버의 열린 포트를 탐색하는 포트 스캔이 감지되었습니다. "
        "이는 본격적인 공격의 사전 정찰 단계일 수 있습니다. 방화벽에서 해당 IP를 "
        "차단하고 불필요하게 열린 포트가 없는지 점검할 것을 권장합니다."
    ),
    config.TYPE_SQL_INJECTION: (
        "IP({target})에서 SQL Injection 공격 시도가 탐지되었습니다. 성공 시 "
        "데이터베이스 정보 유출·변조로 이어질 수 있습니다. 해당 IP 차단, 입력값 "
        "검증(파라미터 바인딩) 강화, WAF 규칙 점검을 권장합니다."
    ),
    config.TYPE_XSS: (
        "IP({target})에서 XSS(교차 사이트 스크립팅) 공격 시도가 탐지되었습니다. "
        "사용자 세션 탈취나 악성 스크립트 실행으로 이어질 수 있습니다. 출력값 "
        "이스케이프 처리와 CSP 적용, 해당 IP 차단을 권장합니다."
    ),
    config.TYPE_MALWARE: (
        "호스트({target})에서 악성코드가 탐지되었습니다. 내부 확산·데이터 유출 "
        "위험이 크므로, 해당 호스트를 네트워크에서 즉시 격리하고 백신 정밀 검사 및 "
        "감염 경로 조사를 권장합니다."
    ),
    config.TYPE_LOGIN_FAILED: (
        "IP({target})에서 로그인 실패가 발생했습니다. 단발성이면 위험은 낮으나, "
        "반복될 경우 Brute Force 가능성이 있으니 추이를 모니터링할 것을 권장합니다."
    ),
}


def _summarize_with_rules(event: dict) -> str:
    """OpenAI 없이도 동작하는 기본 요약."""
    target = event.get("ip") or event.get("host") or "알 수 없음"
    template = _FALLBACK_TEMPLATES.get(
        event.get("event_type"),
        "보안 이벤트가 탐지되었습니다. 상세 내용을 확인하고 필요한 대응을 검토하세요."
    )
    return template.format(target=target)


# -------------------------------------------------------------
# 공개 API
# -------------------------------------------------------------
def summarize(event: dict) -> str:
    """
    이벤트 하나를 한국어로 요약한다.
    OpenAI 우선 → 실패 시 규칙 기반. 항상 문자열을 돌려준다(절대 예외 안 냄).
    """
    return _summarize_with_openai(event) or _summarize_with_rules(event)


# -------------------------------------------------------------
# 리포트 종합 요약 (Step 9 report.py 에서 사용)
# -------------------------------------------------------------
def _report_prompt(stats: dict) -> str:
    return (
        "너는 기업 보안 관제(SOC) 애널리스트다. 아래 하루치 보안 통계를 바탕으로 "
        "경영진이 읽을 3~4문장짜리 한국어 종합 브리핑을 작성하라. "
        "가장 위험한 항목과 권장 조치를 강조하라.\n\n"
        f"- 총 이벤트: {stats.get('total_events')}건\n"
        f"- 공격 유형별: {stats.get('by_type')}\n"
        f"- 위험도별: {stats.get('by_severity')}\n"
        f"- 최다 공격 IP: {stats.get('top_ip')}\n"
        f"- 평균 위험도 점수: {stats.get('avg_score')}\n"
    )


def summarize_report(stats: dict) -> str:
    """하루치 통계(dict)를 받아 종합 요약 문장을 만든다. OpenAI 실패 시 규칙 기반."""
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if api_key and not api_key.startswith("sk-여기에"):
        try:
            from openai import OpenAI
            client = OpenAI(api_key=api_key)
            model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
            resp = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": _report_prompt(stats)}],
                temperature=0.3,
                max_tokens=300,
            )
            return resp.choices[0].message.content.strip()
        except Exception as e:
            _log(f"[ai_client] 리포트 요약 OpenAI 실패, 규칙 기반 대체: {e}")

    # 규칙 기반 대체
    top_ip = stats.get("top_ip") or "없음"
    crit = stats.get("by_severity", {}).get("CRITICAL", 0)
    high = stats.get("by_severity", {}).get("HIGH", 0)
    return (
        f"오늘 총 {stats.get('total_events')}건의 보안 이벤트가 탐지되었습니다. "
        f"이 중 CRITICAL {crit}건, HIGH {high}건으로 즉시 대응이 필요한 항목이 있습니다. "
        f"가장 많은 공격이 관측된 출처는 {top_ip}이며, 해당 IP 차단과 "
        f"고위험 이벤트의 개별 대응을 우선 검토할 것을 권장합니다."
    )


# 단독 실행: stdin 으로 이벤트 JSON 을 받아 요약을 붙여 다시 출력
if __name__ == "__main__":
    import json
    import sys
    events = json.load(sys.stdin)
    if isinstance(events, dict):
        events = [events]
    for e in events:
        e["ai_summary"] = summarize(e)
    print(json.dumps(events, ensure_ascii=False, indent=2))
