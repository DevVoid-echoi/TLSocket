from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path

from tlsocket.log_parser.models import LogRecord


def iter_record(log_file: str | Path) -> Iterable[LogRecord]:
    "Đọc từng dòng trong file log và trả về các bản ghi log hợp lệ"
    with open(log_file, encoding="utf-8") as f:
        for line in f:
            rec = parse_line(line)
            if rec is not None:
                yield rec

def parse_line(line: str) -> LogRecord | None:
    "Phân tích một dòng log và trả về bản ghi log nếu hợp lệ"
    line = line.strip()
    if not line:
        return None
    try:
        data = json.loads(line)
        timestamp = datetime.fromisoformat(data["ts"])
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        return LogRecord(
            timestamp=timestamp,
            level=data["level"],
            event_type=data["event"],
            username=data.get("username", "N/A"),
            ip=data.get("ip", "N/A"),
            extra_info=data.get("extra_info", ""),
        )
    except (ValueError, KeyError, TypeError):
        return None