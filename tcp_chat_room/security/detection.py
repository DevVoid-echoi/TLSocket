import os
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Iterable, List, Dict
from security.logger import log_alert
from log_parser.models import LogRecord

# Define the base directory for the project
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOG_PARSER_DIR = os.path.join(BASE_DIR, "log_parser")


class BruteForceDetector:
    def __init__(self, max_attempts: int=5, window_seconds: int=60):
        # Initialize the maximum number of allowed failed attempts and the time window
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        # Dictionary to keep track of failed attempts history for each IP address
        self.failed_attempts_history: Dict[str, List[datetime]] = defaultdict(list)

    def _parse_timestamp(self, date_str: str, time_str: str) -> datetime:
        # Convert date and time strings into a datetime object
        return datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M:%S")

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
            log_alert(ip=ip, failed_attempts=valid_attempts, window_seconds=self.window_seconds)  # Log an alert
            self.failed_attempts_history[ip].clear()  # Clear the history for this IP

def detect_brute_force_stream(records: Iterable[LogRecord], max_attempts: int=5, window_seconds: int=60):
    # Create a BruteForceDetector instance and process a stream of log records
    detector = BruteForceDetector(max_attempts=max_attempts, window_seconds=window_seconds)
    for record in records:
        detector.process_record(record)  # Process each record to detect brute force attempts