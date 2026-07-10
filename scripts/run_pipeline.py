#!/usr/bin/env python3
# =============================================================
#  run_pipeline.py  —  전체 대응 파이프라인 오케스트레이터
#
#  [하는 일] 아래 순서를 한 번에 실행한다.
#    1) analyzer  : 로그 분석 + 위험도 스코어링
#    2) ai_client : 위험 이벤트에 한국어 요약 부착
#    3) notifier  : Discord 알림 전송
#    4) storage   : CSV 저장
#  그리고 처리 결과 요약을 JSON 으로 출력한다(n8n 이 받아 파싱).
#
#  [왜 이 스크립트가 필요한가]
#  n8n 의 Execute Command 노드가 이 스크립트 하나만 부르면
#  '탐지→분석→AI→알림→기록'이 전부 실행된다.
#  파이썬이 '로직', n8n 이 '언제/얼마나 자주 실행할지'를 담당(관심사 분리).
#
#  [사용법]
#    python3 run_pipeline.py                # 알림 임계값 이상 이벤트 처리
#    python3 run_pipeline.py --min-score 60 # 임계값 조정
#    python3 run_pipeline.py --report       # 파이프라인 + 일일 리포트까지
# =============================================================

from __future__ import annotations

import argparse
import json

import ai_client
import analyzer
import config
import notifier
import report as report_mod
import storage


def run(min_score: int | None = None, make_report: bool = False) -> dict:
    """파이프라인 실행. 처리 결과 요약 dict 를 돌려준다."""
    threshold = config.ALERT_MIN_SCORE if min_score is None else min_score

    # 1) 분석 (임계값 이상만 '알림 대상'으로)
    alerts = analyzer.run(min_score=threshold)

    # 2) AI 요약 부착
    for e in alerts:
        e["ai_summary"] = ai_client.summarize(e)

    # 3) Discord 전송
    sent = notifier.send_many(alerts)

    # 4) CSV 저장
    saved = storage.get_storage("csv").save_events(alerts)

    result = {
        "threshold": threshold,
        "alerts_count": len(alerts),
        "discord_sent": sent,
        "csv_saved": saved,
        "alerts": alerts,
    }

    # 5) (선택) 일일 리포트도 생성
    if make_report:
        result["report"] = report_mod.generate()

    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="보안 대응 파이프라인")
    parser.add_argument("--min-score", type=int, default=None,
                        help="이 점수 이상 이벤트만 처리 (기본: config.ALERT_MIN_SCORE)")
    parser.add_argument("--report", action="store_true",
                        help="파이프라인 실행 후 일일 리포트도 생성")
    args = parser.parse_args()

    result = run(min_score=args.min_score, make_report=args.report)
    # n8n 이 받아 파싱할 수 있도록 마지막에 JSON 출력
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
