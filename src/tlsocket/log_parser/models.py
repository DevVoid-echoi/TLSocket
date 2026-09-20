from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class LogRecord: 
    "Định nghĩa cấu trúc dữ liệu cho một bản ghi log"
    timestamp: datetime
    level: str
    event_type: str
    username: str
    ip: str
    extra_info: str
