from __future__ import annotations
from typing import Iterable, Optional
from collections import defaultdict, Counter
from dataclasses import dataclass
import json

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
