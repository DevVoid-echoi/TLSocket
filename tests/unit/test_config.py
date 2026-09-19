import os
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_default_runtime_dirs_are_anchored_to_project_root_not_cwd(tmp_path):
    """Chạy từ 1 thư mục bất kỳ (cwd != gốc project, giống nút Run của IDE
    đặt cwd = thư mục chứa file) không được sinh logs/data/certs lạc chỗ."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("TLSOCKET_")}
    code = "from tlsocket import config; print(config.LOG_DIR, config.DATA_DIR, config.CERT_DIR, sep='|')"
    result = subprocess.run(
        [sys.executable, "-c", code], cwd=tmp_path, env=env,
        capture_output=True, text=True, check=True,
    )
    log_dir, data_dir, cert_dir = (Path(p) for p in result.stdout.strip().split("|"))
    assert log_dir == PROJECT_ROOT / "logs"
    assert data_dir == PROJECT_ROOT / "data"
    assert cert_dir == PROJECT_ROOT / "certs"


def test_env_var_still_overrides_default(tmp_path):
    env = {**os.environ, "TLSOCKET_LOG_DIR": str(tmp_path / "custom_logs")}
    result = subprocess.run(
        [sys.executable, "-c", "from tlsocket import config; print(config.LOG_DIR)"],
        cwd=tmp_path, env=env, capture_output=True, text=True, check=True,
    )
    assert Path(result.stdout.strip()) == tmp_path / "custom_logs"
