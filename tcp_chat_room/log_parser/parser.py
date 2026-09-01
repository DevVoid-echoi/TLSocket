from __future__ import annotations
from typing import Iterable, Optional
from models import LogRecord

def iter_record(log_file: str) -> Iterable[LogRecord]:
    "Đọc từng dòng trong file log và trả về các bản ghi log hợp lệ"
    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            rec = parse_line(line)
            if rec is not None:
                yield rec

def parse_line(line: str) -> Optional[LogRecord]:
    "Phân tích một dòng log và trả về bản ghi log nếu hợp lệ"
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    parts = line.split(maxsplit=3)
    if len(parts) < 4:
        return None
    date, time, level, rest = parts

    rest_parts = rest.split()
    event_type = rest_parts[0]

    username = "N/A"
    ip = "N/A"
    extra_info_list = []

    for kv in rest_parts[1:]:
        if "=" in kv:
            key, value = kv.split("=", 1)
            if key == "username":
                username = value
            elif key == "ip":
                ip = value
            else:
                extra_info_list.append(f"{key} = {value}")
        else:
            extra_info_list.append(kv)

    extra_info = " ".join(extra_info_list) if extra_info_list else "N/A"


    return LogRecord(date=date, time=time, level=level, event_type=event_type, username=username, ip=ip, extra_info=extra_info)