from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from tlsocket.log_parser.models import LogRecord

ATTACK_EVENTS = frozenset({
    "LOGIN_FAILED", "RATE_LIMIT_EXCEEDED", "CONNECTION_LIMIT_REACHED", "BRUTE_FORCE_ATTEMPT"
})


@dataclass(frozen=True)
class FailureBucket:
    start: datetime
    total: int
    failures: int

    @property
    def rate(self) -> float:
        return self.failures/self.total

def peak_attack_hours(records: Iterable[LogRecord], top_n: int = 3) -> list[tuple[str, int]]:
    counts: Counter[str] = Counter()
    for r in records:
        if r.event_type in ATTACK_EVENTS:
            hour = r.timestamp.astimezone(timezone.utc).strftime("%Y-%m-%d %H:00")
            counts[hour] += 1
    return counts.most_common(top_n)

def top_targeted_users(records: Iterable[LogRecord], top_n: int = 5) -> list[tuple[str, int]]:
    counts: Counter[str] = Counter(
        r.username for r in records
        if r.event_type == "LOGIN_FAILED"
        and r.username not in ("N/A", "Unknown")
        and "ALREADY_LOGGED_IN" not in r.extra_info
    )
    return counts.most_common(top_n)

def failure_rate_over_time(records: Iterable[LogRecord], bucket_minutes: int = 60) -> list[FailureBucket]:
    size = bucket_minutes * 60
    totals: Counter[int] = Counter()
    failures: Counter[int] = Counter()
    for r in records:
        epoch = int(r.timestamp.timestamp())
        bucket = epoch - epoch%size
        totals[bucket] += 1
        if r.level == "WARNING":
            failures[bucket] += 1
    return [
        FailureBucket(datetime.fromtimestamp(b, tz=timezone.utc), totals[b], failures[b]) for b in sorted(totals)
    ]

def analyze(records: Iterable[LogRecord]) -> dict[str, Any]:
    """Analyze log files and return statistics."""
    total = 0
    error_count = 0
    warning_count = 0
    failed_logins_count = 0
    successful_logins_count = 0
    banned_users_count = 0
    kicked_users_count = 0
    suspicious_ips: defaultdict[str, int] = defaultdict(int)
    brute_force_detector = False
    ddos_detector = False

    ip_count: Counter[str] = Counter()

    for r in records:
        total += 1

        if r.ip and r.ip != "N/A":
            ip_count[r.ip] += 1

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
        if event in["RATE_LIMIT_EXCEEDED", "BRUTE_FORCE_ATTEMPT"]:
            brute_force_detector = True
            if r.ip and r.ip != "N/A":
                suspicious_ips[r.ip] += 1
        if event in ["CONNECTION_LIMIT_REACHED"]:
            ddos_detector = True
            if r.ip and r.ip != "N/A":
                suspicious_ips[r.ip] += 1
        """
        latency_count[r.path] += 1
        latency_sum[r.path] += r.latency_ms
        """

    all_ips_sorted = ip_count.most_common()

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
        "suspicious_IPs": dict(suspicious_ips),
        "brute_force_alert": brute_force_detector,
        "ddos_alert": ddos_detector
    }