from __future__ import annotations
from typing import Iterable, Optional
from collections import defaultdict, Counter
import json
from models import LogRecord

"""
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BRUTE_FORCE_DETECTION_DIR = os.path.join(BASE_DIR, "security", "brute_force_detection")

from brute_force_detection import BruteForceDetector
"""

def analyze(records: Iterable[LogRecord]) -> dict:
    "Phân tích các bản ghi log và trả về thống kê"
    total = 0
    error_count = 0
    warning_count = 0
    failed_logins_count = 0
    successful_logins_count = 0
    banned_users_count = 0
    kicked_users_count = 0
    suspicious_ips = defaultdict(int)

    ip_count = Counter()

    for r in records:
        total += 1

        if r.ip and r.ip != "N/A":
            ip_count[r.ip] += 1
        
        all_ips_sorted = ip_count.most_common()

        level = r.level
        if level == "WARNING":
            warning_count += 1

        event = r.event_type
        if event == "CONNECTION_ERROR":
            error_count += 1
        if event == "LOGIN_FAILED":
            failed_logins_count += 1
        if event == "LOGIN_SUCCESS":
            successful_logins_count += 1
        if event == "KICK":
            kicked_users_count += 1
        if event == "BAN":
            banned_users_count += 1
        if event in["RATE_LIMIT_EXCEEDED", "[ALERT] BRUTE_FORCE_ATTEMPT"]:
            suspicious_ips[r.ip] += 1
        
        """
        latency_count[r.path] += 1
        latency_sum[r.path] += r.latency_ms
        """

    error_rate = error_count/total if total > 0 else 0

    """
    avg_latency_per_path = {
        path: (latency_sum[path]/latency_count[path])
        for path in latency_count
        if latency_count[path] > 0
    }

    avg_latency_sorted = sorted(avg_latency_per_path.items(), key=lambda x: x[1], reverse=True)
    """

    return{
        "total_requests": total,
        "all_ips": all_ips_sorted,
        "unique_ip_count": len(all_ips_sorted),
        "successful_logins": successful_logins_count,
        "failed_logins": failed_logins_count,
        "kicked_users": kicked_users_count,
        "banned_users": banned_users_count,
        "error_count": error_count,
        "error_rate": error_rate,
        "warning": warning_count,
        "top_5_IPs": ip_count.most_common(5),
        "suspicious_ips": dict(suspicious_ips)
    }