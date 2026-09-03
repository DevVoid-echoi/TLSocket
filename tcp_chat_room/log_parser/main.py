from __future__ import annotations
import argparse 
from typing import Iterable, Optional
from collections import defaultdict, Counter
from dataclasses import dataclass
from datetime import datetime
import json
from parser import iter_record
from analyzer import analyze
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SEC_LOG_PATH = os.path.join(BASE_DIR, "logs", "security.log")
SER_LOG_PATH = os.path.join(BASE_DIR, "logs", "server.log")


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze a log file")
    parser.add_argument("-f", "--file",
                        choices=["security", "server"],
                        default = "security",
                        help="Path to the security/server/both log file"
                        )
    parser.add_argument("-o", "--output", help="Path to the output file (optional)")

    args = parser.parse_args()

    if args.file == "server":
        LOG_PATH = SER_LOG_PATH
    if args.file == "security":
        LOG_PATH = SEC_LOG_PATH

    results = analyze(iter_record(LOG_PATH))

    total_requests = results["total_requests"]
    all_ips = results["all_ips"]
    unique_ip_count = results["unique_ip_count"]
    successful_logins = results["successful_logins"]
    failed_logins = results["failed_logins"]
    kicked_users = results["kicked_users"]
    banned_users = results["banned_users"]
    error_count = results["error_count"]
    error_rate = results["error_rate"]
    warning = results["warning"]
    top_5_IPs = results["top_5_IPs"]
    suspicious_ips = results["suspicious_ips"]

    print("\n" + "=" * 50)
    if os.path.exists(LOG_PATH):
        with open(LOG_PATH, "r", encoding="utf-8") as f:
            print("--- LOG CONTENT ---")
            print(f.read())
    else:
        print("Log file does not exist!")
    print("=" * 50)
    print(f"Total request: {total_requests}")
    print("=" * 50)

    print(f"\nTotal Unique IPs: {unique_ip_count}")
    print("-" * 50)
    print(f"{'IP Address':<20} | {'Request Count':<15}")
    print("-" * 50)

    for ip, count in all_ips:
        print(f"{ip:<20} | {count:<15}")
    print("\n"+"=" * 50)

    print(f"Successful logins: {successful_logins}")
    print("=" * 50)

    print(f"Failed logins: {failed_logins}")
    print("=" * 50)

    print(f"Kicked users: {kicked_users}")
    print("=" * 50)

    print(f"Banned users: {banned_users}")
    print("=" * 50)

    print(f"Error count: {error_count}")
    print("=" * 50)

    print(f"Error rate: {error_rate:.2%}")
    print("=" * 50)

    print(f"Warning: {warning}")
    print("=" * 50)

    print("Top 5 IPs:")
    for ip, count in top_5_IPs:
        print(f"{ip}:{count}")
    print("=" * 50)

    print("Suspicious IPs:")
    for ip, count in suspicious_ips.items():
        print(f"{ip}: {count}")
    print("=" * 50)

    if warning > 0:
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print("\033[91m" + "=" * 50)
        print(f"[{now_str}] [ALERT] Security warnings/brute-force events detected ({warning} total)!")
        print("=" * 50 + "\033[0m")

    """
    print ("Average latency per path (sorted):")
    for path, avg_latency in avg_latency_sorted:
        print(f"{path}: {avg_latency:.2f} ms")
    """

    if args.output:
        report = {
            "total_requests": total_requests,
            "all_ips": all_ips,
            "unique_ip": unique_ip_count,
            "successful_logins": successful_logins,
            "failed_logins": failed_logins,
            "kicked_users": kicked_users,
            "banned_users": banned_users,
            "error_count": error_count,
            "error_rate": error_rate,
            "warning": warning,
            "top_5_IPs": top_5_IPs,
            "brute_force_alert": warning > 0,
            "suspicious_IPs": suspicious_ips 
        }

        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4, ensure_ascii=False)
            print(f"[+] Report saved successfully to: {args.output}")

    return 0

if __name__ == "__main__":
    raise SystemExit(main())


   