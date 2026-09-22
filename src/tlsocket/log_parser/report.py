from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

from tlsocket.log_parser.analyzer import (
    analyze,
    failure_rate_over_time,
    peak_attack_hours,
    top_targeted_users,
)
from tlsocket.log_parser.models import LogRecord


def build_report(records: Iterable[LogRecord]) -> dict[str, Any]:
    records = list(records)
    report = analyze(records)
    report["peak_attack_hours"] = peak_attack_hours(records)
    report["top_targeted_users"] = top_targeted_users(records)
    report["failure_rate_over_time"] = [
        {"start": b.start.isoformat(), "total": b.total, "failures": b.failures, "rate": b.rate} for b in failure_rate_over_time(records)
    ]
    return report

def to_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=4, ensure_ascii=False)

def to_table(report: dict[str, Any]) -> str:
    top_ips = [f"  {ip:<20} {count}" for ip, count in report['top_5_IPs']] or ["  (none)"]
    top_users = [f"  {user:<20} {count}" for user, count in report['top_targeted_users']] or ["  (none)"]
    peak_hours = [f"  {hour}  {count} events]" for hour, count in report['peak_attack_hours']] or ["  (none)"]

    lines = [
        f"Total requests:       {report['total_requests']}",
        f"Unique Ips:           {report['unique_ip_count']}",
        f"Successful logins:    {report['successful_logins']}",
        f"Failed logins:        {report['failed_logins']}",
        f"Kicked user:          {report['kicked_users']}",
        f"Banned user:          {report['banned_users']}",
        f"Errors:               {report['error_count']} ({report['error_rate']:.1%})",
        f"Warnings:             {report['warning']}",
        "",
        "Top 5 IPs:", *top_ips,
        "",
        "Top targeted users (failed logins):", *top_users,
        "",
        "Peak attack hours (UTC):", *peak_hours,
        "",
        f"Brute-force alert: {'YES' if report['brute_force_alert'] else 'NO'}",
        f"DDoS alert: {'YES' if report['ddos_alert'] else 'NO'}",
    ] 
    return "\n".join(lines)