import logging
import os
from datetime import datetime

# Define the base directory and log directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(BASE_DIR, "logs")
DEFAULT_ALERT_LOG_PATH = os.path.join(LOG_DIR, "alerts.log")

def setup_alert_logger(log_file=DEFAULT_ALERT_LOG_PATH):
    # Create the log directory if it doesn't exist
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    # Create a logger for alert messages
    logger = logging.getLogger("AlertLogger")
    logger.setLevel(logging.WARNING)  # Set the logging level to WARNING

    # Check if the logger already has handlers
    if not logger.handlers:
        # Create a file handler for logging to a file
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        # Define the log message format
        formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
        file_handler.setFormatter(formatter)  # Set the formatter for the handler
        logger.addHandler(file_handler)  # Add the handler to the logger
    
    return logger  # Return the configured logger

# Initialize the alert logger
alert_logger = setup_alert_logger()

def log_alert(ip: str, failed_attempts: str, window_seconds: int):
    # Get the current timestamp as a formatted string
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Create the alert message
    alert_msg = (f"[ALERT] Possible brute-force attack | "
                 f"IP={ip} | FailedAttempts={failed_attempts} | Window={window_seconds}s")

    # Print the alert message to the console in red
    print(f"\033[91m{now_str} {alert_msg}\033[0m")

    # Create or get a logger for security-related messages
    sec_logger = logging.getLogger("SecurityLogger")
    sec_logger.warning(alert_msg)  # Log the alert message

    # Flush all handlers for the security logger
    for handlers in sec_logger.handlers:
        handlers.flush()
    
    # Log the alert message using the alert logger
    alert_logger.warning(alert_msg)