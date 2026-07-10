#!/usr/bin/env python3
# =============================================================
#  report.py  —  일일 보안 리포트 생성
#
#  [하는 일]
#  하루치 로그를 분석해 통계를 집계하고, 종합 요약을 붙여
#  JSON 과 CSV 두 형식으로 output/reports/ 에 저장한다.
#
#  [집계 항목] (요구사항)
#   - 총 이벤트 수
#   - 공격 종류별 개수
#   - 위험도별 개수
#   - 가장 많이 공격한 IP
#   - 평균 위험도
#   - AI 종합 요약
#
#  [설계]
#  - 통계 계산(build_stats)과 저장(save_json/save_csv)을 분리.
#  - 정상 로그인(LOGIN_SUCCESS, 0점)은 '공격' 통계에서 제외해 왜곡을 막는다.
# =============================================================

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from datetime import datetime

import ai_client
import analyzer
import config


# -------------------------------------------------------------
# 통계 집계
# -------------------------------------------------------------
def build_stats(events: list[dict]) -> dict:
    """분석된 이벤트 리스트 → 통계 dict."""
    # 정상 로그인은 위협 통계에서 제외
    threats = [e for e in events if e["event_type"] != config.TYPE_LOGIN_SUCCESS
               and e["score"] > 0]

    by_type = Counter(e["event_type"] for e in threats)
    by_severity = Counter(e["severity"] for e in threats)

    # 공격 IP 카운트 (ip 가 있는 것만)
    ip_counter = Counter(e["ip"] for e in threats if e.get("ip"))
    top_ip, top_ip_count = (ip_counter.most_common(1)[0]
                            if ip_counter else (None, 0))

    scores = [e["score"] for e in threats]
    avg_score = round(sum(scores) / len(scores), 1) if scores else 0.0

    return {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "date": datetime.now().strftime("%Y-%m-%d"),
        "total_events": len(threats),
        "by_type": dict(by_type),
        "by_severity": dict(by_severity),
        "top_ip": top_ip,
        "top_ip_count": top_ip_count,
        "avg_score": avg_score,
    }


# -------------------------------------------------------------
# 저장: JSON
# -------------------------------------------------------------
def save_json(report: dict) -> str:
    config.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    path = config.REPORTS_DIR / f"report_{report['date']}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    return str(path)


# -------------------------------------------------------------
# 저장: CSV (key,value 두 컬럼 + 유형별 상세)
# -------------------------------------------------------------
def save_csv(report: dict) -> str:
    config.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    path = config.REPORTS_DIR / f"report_{report['date']}.csv"
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["metric", "value"])
        w.writerow(["date", report["date"]])
        w.writerow(["total_events", report["total_events"]])
        w.writerow(["top_ip", report["top_ip"]])
        w.writerow(["top_ip_count", report["top_ip_count"]])
        w.writerow(["avg_score", report["avg_score"]])
        # 유형별 / 위험도별 상세
        for k, v in report["by_type"].items():
            w.writerow([f"type:{k}", v])
        for k, v in report["by_severity"].items():
            w.writerow([f"severity:{k}", v])
        w.writerow(["ai_summary", report["ai_summary"]])
    return str(path)


# -------------------------------------------------------------
# 진입점
# -------------------------------------------------------------
def generate(path=None) -> dict:
    """로그를 분석 → 통계 → AI 종합 요약 → JSON/CSV 저장. 리포트 dict 반환."""
    events = analyzer.run(path=path)          # 전체 이벤트(점수 무관)
    stats = build_stats(events)
    stats["ai_summary"] = ai_client.summarize_report(stats)

    json_path = save_json(stats)
    csv_path = save_csv(stats)
    stats["_files"] = {"json": json_path, "csv": csv_path}
    return stats


def main() -> None:
    parser = argparse.ArgumentParser(description="일일 보안 리포트 생성기")
    parser.add_argument("--file", default=None, help="분석할 로그 파일 경로")
    args = parser.parse_args()

    report = generate(path=args.file)
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
