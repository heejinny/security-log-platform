#!/usr/bin/env python3
# =============================================================
#  notifier.py  —  Discord Webhook 으로 보안 알림 전송
#
#  [하는 일]
#  분석 + AI요약이 끝난 이벤트를 Discord 채널에 보기 좋은 카드(embed)로 보낸다.
#
#  [핵심 설계: Graceful Degradation]
#  - DISCORD_WEBHOOK_URL 이 있으면 → 실제 전송
#  - 없으면 → 콘솔에 '보낼 내용'을 출력 (개발/데모 시 편리)
#
#  [확장성]
#  send_alert() 라는 하나의 함수로 인터페이스를 고정했다.
#  나중에 Slack/Teams 로 바꾸려면 이 파일만 교체하면 된다.
# =============================================================

from __future__ import annotations

import os
import sys


def _log(msg: str) -> None:
    """진단 메시지는 stderr 로 보낸다.
    (stdout 은 최종 JSON 전용 → n8n 이 stdout 을 그대로 JSON 파싱한다.)"""
    print(msg, file=sys.stderr)
# 'requests' 는 실제 전송할 때만 필요하므로 함수 안에서 지연 import 한다.
# (웹훅 미설정 콘솔 모드는 외부 라이브러리 없이도 동작)

# 위험도별 Discord embed 색상(왼쪽 세로 막대). 10진수 정수.
_SEVERITY_COLOR = {
    "LOW": 0x2ECC71,       # 초록
    "MEDIUM": 0xF1C40F,    # 노랑
    "HIGH": 0xE67E22,      # 주황
    "CRITICAL": 0xE74C3C,  # 빨강
}


def _build_payload(event: dict) -> dict:
    """이벤트 → Discord Webhook JSON payload 로 변환."""
    target = event.get("ip") or event.get("host") or "알 수 없음"
    color = _SEVERITY_COLOR.get(event.get("severity"), 0x95A5A6)

    return {
        "embeds": [{
            "title": "🚨 Security Alert",
            "color": color,
            "fields": [
                {"name": "공격 종류", "value": str(event.get("event_type")), "inline": True},
                {"name": "IP / 호스트", "value": str(target), "inline": True},
                {"name": "위험도", "value": f"{event.get('severity')} ({event.get('score')}점)", "inline": True},
                {"name": "AI 분석", "value": event.get("ai_summary") or event.get("reason") or "-", "inline": False},
            ],
            "footer": {"text": f"탐지 시각: {event.get('timestamp')}"},
        }]
    }


def _webhook_url() -> str | None:
    """유효한 웹훅 URL 을 돌려준다. 없거나 템플릿 값이면 None."""
    url = os.getenv("DISCORD_WEBHOOK_URL", "").strip()
    if not url or "xxxx" in url:
        return None
    return url


def send_alert(event: dict) -> bool:
    """
    이벤트 하나를 Discord 로 보낸다.
    성공/전송생략 여부와 무관하게 예외를 밖으로 던지지 않는다(파이프라인 보호).
    반환: 실제 전송 성공하면 True, 그 외 False.
    """
    payload = _build_payload(event)
    url = _webhook_url()

    # 웹훅 미설정 → 콘솔 출력으로 대체
    if url is None:
        f = payload["embeds"][0]["fields"]
        _log("[notifier] (웹훅 미설정) Discord 로 보낼 내용 미리보기:")
        _log(f"    🚨 {f[0]['value']} | {f[1]['value']} | {f[2]['value']}")
        _log(f"    AI: {f[3]['value']}")
        return False

    try:
        import requests  # 실제 전송 시점에만 로드
        resp = requests.post(url, json=payload, timeout=10)
        if resp.status_code in (200, 204):
            return True
        _log(f"[notifier] Discord 응답 이상: HTTP {resp.status_code} {resp.text[:200]}")
        return False
    except Exception as e:
        _log(f"[notifier] Discord 전송 실패(무시하고 계속): {e}")
        return False


def send_many(events: list[dict]) -> int:
    """여러 이벤트를 순서대로 전송. 실제 전송 성공 건수를 돌려준다."""
    sent = 0
    for e in events:
        if send_alert(e):
            sent += 1
    return sent


# 단독 실행: stdin 으로 이벤트 JSON 리스트를 받아 전송
if __name__ == "__main__":
    import json
    import sys
    events = json.load(sys.stdin)
    if isinstance(events, dict):
        events = [events]
    ok = send_many(events)
    print(f"[notifier] 전송 성공 {ok} / 전체 {len(events)} 건")
