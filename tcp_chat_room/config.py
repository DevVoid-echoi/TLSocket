import os

HOST = "127.0.0.1"  # local_host
PORT = 9999

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BAN_FILE_PATH = os.path.join(SCRIPT_DIR, "data", "ban.txt")