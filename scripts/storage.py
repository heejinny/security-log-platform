#!/usr/bin/env python3
# =============================================================
#  storage.py  —  분석 결과 저장 (초기 버전: CSV)
#
#  [핵심 설계: 저장소 추상화]
#  Storage(추상 클래스) 라는 '인터페이스'를 먼저 정의하고,
#  그 구현으로 CSVStorage 를 만든다.
#  → 나중에 MySQLStorage, ElasticStorage 를 추가해도
#    이 함수를 쓰는 쪽(run_pipeline)은 코드를 바꿀 필요가 없다.
#  이것이 "DB 없이 시작하되, 나중에 쉽게 확장" 요구사항을 만족시키는 방법.
#
#  [CSV 형식] (요구사항)
#    timestamp,event,ip,score,severity,ai_summary
# =============================================================

from __future__ import annotations

import csv
from abc import ABC, abstractmethod

import config

# CSV 컬럼 순서 (한 곳에서 관리)
CSV_FIELDS = ["timestamp", "event", "ip", "score", "severity", "ai_summary"]


def _to_row(event: dict) -> dict:
    """표준 이벤트(dict) → CSV 한 행(dict). 필요한 컬럼만 추린다."""
    return {
        "timestamp": event.get("timestamp", ""),
        "event": event.get("event_type", ""),
        # ip 가 없으면(멀웨어 등) host 로 대체 저장
        "ip": event.get("ip") or event.get("host") or "",
        "score": event.get("score", 0),
        "severity": event.get("severity", ""),
        "ai_summary": event.get("ai_summary") or event.get("reason") or "",
    }


# -------------------------------------------------------------
# 인터페이스 (추상 클래스)
# -------------------------------------------------------------
class Storage(ABC):
    """모든 저장소가 지켜야 할 공통 규약."""

    @abstractmethod
    def save_events(self, events: list[dict]) -> int:
        """이벤트들을 저장하고 저장한 건수를 돌려준다."""
        raise NotImplementedError


# -------------------------------------------------------------
# 구현 1: CSV
# -------------------------------------------------------------
class CSVStorage(Storage):
    """이벤트를 CSV 파일에 append 한다. 파일이 없으면 헤더를 먼저 쓴다."""

    def __init__(self, path=None):
        self.path = path or config.EVENTS_CSV

    def save_events(self, events: list[dict]) -> int:
        if not events:
            return 0

        # output 폴더 보장
        config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

        # 파일이 아직 없으면 헤더를 써야 한다.
        write_header = not self.path.exists()

        with open(self.path, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
            if write_header:
                writer.writeheader()
            for e in events:
                writer.writerow(_to_row(e))
        return len(events)


# -------------------------------------------------------------
# 팩토리: 설정에 따라 적절한 저장소를 돌려준다.
#   지금은 CSV 만 있지만, 나중에 아래에 분기만 추가하면 된다.
#     if backend == "mysql": return MySQLStorage(...)
# -------------------------------------------------------------
def get_storage(backend: str = "csv") -> Storage:
    if backend == "csv":
        return CSVStorage()
    raise ValueError(f"지원하지 않는 저장소: {backend}")


# 단독 실행: stdin 으로 이벤트 JSON 을 받아 CSV 에 저장
if __name__ == "__main__":
    import json
    import sys
    events = json.load(sys.stdin)
    if isinstance(events, dict):
        events = [events]
    n = get_storage("csv").save_events(events)
    print(f"[storage] CSV 저장 {n} 건 → {config.EVENTS_CSV}")
