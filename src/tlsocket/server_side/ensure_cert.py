import os
import socket
import subprocess
from pathlib import Path

from tlsocket.config import CERT_FILE


def _detect_lan_ip() -> str | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return str(s.getsockname()[0])
    except OSError:
        return None

def _cert_covers_ip(ip: str) -> bool:
    if not CERT_FILE.exists():
        return False
    try:
        out = subprocess.run(
            ["openssl", "x509", "-in", str(CERT_FILE), "-noout", "-ext", "subjectAltName"],
            check=True, capture_output=True, text=True,
        ).stdout
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False
    return f"IP Address:{ip}" in out

def ensure_lan_cert() -> None:
    if os.environ.get("TLSOCKET_AUTO_LAN_CERT"):
        ip = _detect_lan_ip()
        if not ip or _cert_covers_ip(ip):
            return
        print(f"[CERT] LAN IP {ip} not yet in the cert, re-signing server.crt...")
        script = Path(__file__).resolve().parents[3] / "scripts" / "gen_certs.sh"
        subprocess.run([str(script)], check=True, env={**os.environ, "TLSOCKET_LAN_IP": ip})
