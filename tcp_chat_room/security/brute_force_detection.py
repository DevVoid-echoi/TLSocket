import os
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Iterable, List, Dict
from security.logger import log_alert
from config import MAX_LOGIN_ATTEMPTS, LOGIN_WINDOW, BLOCK_DURATION
import json

# Define the base directory for the project
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_PARSER_DIR = os.path.join(BASE_DIR, "log_parser")
DATA_DIR = os.path.join(BASE_DIR, "data")

from log_parser.models import LogRecord


class BruteForceDetector:
    def __init__(self, max_attempts: int=MAX_LOGIN_ATTEMPTS, window_seconds: int=LOGIN_WINDOW, block_duration: int=BLOCK_DURATION):
        # Initialize the maximum number of allowed failed attempts and the time window
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.block_duration = block_duration
        # Dictionary to keep track of failed attempts history for each IP address
        self.failed_attempts_history: Dict[str, List[datetime]] = defaultdict(list)
        self.violation_count: Dict[str, int] = defaultdict(int)  # Dictionary to keep track of violation counts for each IP
        self.blocked_ips: Dict[str,datetime] = {} # Dictionary to keep track of blocked IPs and their unblock time
        self.db_file = os.path.join(DATA_DIR, "brute_force_state.json")  # Path to the JSON file for saving state
        self.load_state()

    def save_state(self):
        data = {
            "violation_count": dict(self.violation_count),
            "blocked_ips": {
                ip: unblock_time.strftime("%Y-%m-%d %H:%M:%S") for ip, unblock_time in self.blocked_ips.items()
            }
        }
        with open(self.db_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)

    def load_state(self):
        if os.path.exists(self.db_file):
            try:
                with open (self.db_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                
                for ip, count in data.get("violation_count", {}).items():
                    self.violation_count[ip] = count

                for ip, unblock_time_str in data.get("blocked_ips", {}).items():
                    self.blocked_ips[ip] = datetime.strptime(unblock_time_str, "%Y-%m-%d %H:%M:%S")

            except Exception as e:
                print(f"[ERROR] Failed to load state from {self.db_file}: {e}")

    def _parse_timestamp(self, date_str: str, time_str: str) -> datetime:
        # Convert date and time strings into a datetime object
        return datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M:%S")

    def _get_ban_duration(self, ip:str) -> int:
        count = self.violation_count[ip]
        if count <= 1:
            mul = 1
        elif count == 2:
            mul = 5
        elif count == 3:
            mul = 30
        else:
            mul = 1440

        return self.block_duration * mul

    def is_ip_blocked(self, ip:str) -> bool:
        if ip not in self.blocked_ips:
            return False
        
        if datetime.now() > self.blocked_ips[ip]:
            del self.blocked_ips[ip]
            self.save_state()  # Save the state after unblocking the IP
            return False

        return True

    def get_remaining_ban_time(self, ip:str) -> int:
        if not self.is_ip_blocked(ip):
            return 0
        remaining = (self.blocked_ips[ip] - datetime.now()).total_seconds()
        return max(0, int(remaining))

    def process_record(self, record: LogRecord):
        # Process a log record to detect failed login attempts
        if record.event_type != "LOGIN_FAILED" or not record.ip or record.ip == "N/A":
            return  # Ignore non-login failed events or invalid IPs

        current_time = self._parse_timestamp(record.date, record.time)  # Get the current timestamp
        ip = record.ip  # Extract the IP address from the record
        timestamps = self.failed_attempts_history[ip]  # Get the list of timestamps for this IP

        timestamps.append(current_time)  # Add the current timestamp to the history

        # Define the threshold time for the window of failed attempts
        threshold_time = current_time - timedelta(seconds=self.window_seconds)
        # Filter out timestamps that are older than the threshold
        self.failed_attempts_history[ip] = [
            t for t in timestamps if t >= threshold_time
        ]

        valid_attempts = len(self.failed_attempts_history[ip])  # Count valid attempts
        if valid_attempts >= self.max_attempts:  # Check if the number of attempts exceeds the limit
            self.violation_count[ip] += 1  # Increment the violation count for this IP
            effective_duration = self._get_ban_duration(ip)  # Get the effective ban duration based on violation count
            unblock_time = current_time + timedelta(seconds=effective_duration)
            self.blocked_ips[ip] = unblock_time

            log_alert(ip=ip, failed_attempts=valid_attempts, window_seconds=self.window_seconds)  # Log an alert
            self.failed_attempts_history[ip].clear()  # Clear the history for this IP

            self.save_state()  # Save the state after blocking the IP

def detect_brute_force_stream(records: Iterable[LogRecord], max_attempts: int=5, window_seconds: int=60):
    # Create a BruteForceDetector instance and process a stream of log records
    detector = BruteForceDetector(max_attempts=max_attempts, window_seconds=window_seconds)
    for record in records:
        detector.process_record(record)  # Process each record to detect brute force attempts