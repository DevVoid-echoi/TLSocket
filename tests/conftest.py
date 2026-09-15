"""Fixture chung. File này được pytest import RẤT SỚM, trước mọi test module,
nên đây là chỗ đúng để redirect các đường dẫn runtime của tlsocket."""
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

# --- Redirect TRƯỚC khi bất kỳ 'import tlsocket' nào xảy ra ------------------
_TMP_ROOT = Path(tempfile.mkdtemp(prefix="tlsocket-tests-"))
_DATA = _TMP_ROOT / "data"
_LOGS = _TMP_ROOT / "logs"
_CERTS = _TMP_ROOT / "certs"
for d in (_DATA, _LOGS, _CERTS):
    d.mkdir(parents=True, exist_ok=True)

os.environ["TLSOCKET_DATA_DIR"] = str(_DATA)
os.environ["TLSOCKET_LOG_DIR"] = str(_LOGS)
os.environ["TLSOCKET_CERT_DIR"] = str(_CERTS)
os.environ["TLSOCKET_HOST"] = "127.0.0.1"
os.environ["TLSOCKET_PORT"] = "0" # Để OS chọn cổng trống

# Tạo cặp cert self-signed 1 lần cho cả phiên test. Chỉ integration test (GĐ 3)
# mới cần cert thật; bọc try/except để máy/CI thiếu `openssl` vẫn chạy được
# toàn bộ unit test thuần logic (validation, rbac, ...) - chỉ integration
# test mới fail (và fail rõ ràng, thay vì sập cả suite ngay lúc collection).
_CRT = _CERTS / "server.crt"
_KEY = _CERTS / "server.key"
if not _CRT.exists():
    try:
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-days", "1", "-keyout", str(_KEY), "-out", str(_CRT),
             "-subj", "/CN=localhost",
             "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
            check=True, capture_output=True,
        )

    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        print(f"[conftest] Không tạo được TLS cert cho test ({e}); "
              f"unit test thuần logic vẫn chạy bình thường, "
              f"integration test cần TLS sẽ fail.")


def pytest_sessionfinish(session, exitstatus):
    shutil.rmtree(_TMP_ROOT, ignore_errors=True)


@pytest.fixture
def data_dir() -> Path:
    return _DATA





