from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class LogRecord: 
    "Định nghĩa cấu trúc dữ liệu cho một bản ghi log"
    date: str
    time: str 
    level: str
    event_type: str
    username: str
    ip: str
    extra_info: str
