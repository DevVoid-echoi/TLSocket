from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

from tlsocket.config import ALERT_LOG, SECURITY_LOG, SERVER_LOG
from tlsocket.log_parser.analyzer import ATTACK_EVENTS
from tlsocket.log_parser.filters import filter_since, parse_duration
from tlsocket.log_parser.models import LogRecord
from tlsocket.log_parser.parser import follow, iter_record
from tlsocket.log_parser.report import build_report, to_json, to_table

_ALIASES = {"security": SECURITY_LOG, "server": SERVER_LOG, "alerts": ALERT_LOG}


def _resolve_path(source: str) -> Path:
    return _ALIASES.get(source, Path(source))

def _print_live(record: LogRecord) -> None:
    ts = record.timestamp.strftime("%Y-%m-%d %H:%M:%S")
    line = f"{ts} {record.level:<7} {record.event_type:<24} user={record.username} ip={record.ip}"
    if record.event_type in ATTACK_EVENTS:
        print(f"\033[91m{line}\033[0m")
    else:
        print(line)

def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze a log file")
    parser.add_argument("source",
                        nargs="?",
                        default = "security",
                        help="Path to the security/server/alerts log file"
                        )
    parser.add_argument("--since", help="Print record since a period of time, e.g. 30s, 15m, 1h, 7d")
    parser.add_argument("--follow", action="store_true", help="Follow log in real-time")
    parser.add_argument("--format", choices=["table", "json"], default="table")
    parser.add_argument("-o", "--output", help="Path to the output file (optional)")

    args = parser.parse_args()

    path = _resolve_path(args.source)

    if args.follow:
        print(f"Following {path} (Ctrl+C/Cmd+C to stop)...")
        try:
            for record in follow(path):
                _print_live(record)
        except KeyboardInterrupt:
            print("\nStopped.")
        return 0

    records = iter_record(path)
    if args.since:
        cutoff = datetime.now(timezone.utc) - parse_duration(args.since)
        records = filter_since(records, cutoff)

    report = build_report(records)
    print(to_json(report) if args.format == "json" else to_table(report))

    if args.output:
        Path(args.output).write_text(to_json(report), encoding="utf-8")
        print(f"[+] Report saved in: {args.output}")

    return 0
    
if __name__ == "__main__":
    raise SystemExit(main())


   