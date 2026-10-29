"""redcheck/config.py — load env + target definitions."""
from __future__ import annotations

import os
from pathlib import Path

# ---------------------------------------------------------------------------
# Load .env if present (simple key=value, no dotenv dep required)
# ---------------------------------------------------------------------------
def _load_env(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k = k.strip()
        v = v.strip()
        if k and k not in os.environ:
            os.environ[k] = v

_load_env(Path(__file__).parent.parent / ".env")

# ---------------------------------------------------------------------------
# Target endpoints
# ---------------------------------------------------------------------------
BASE_SIMAD:  str = os.environ.get("BASE_SIMAD",  "http://127.0.0.1:8080").rstrip("/")
BASE_MODERN: str = os.environ.get("BASE_MODERN", "http://127.0.0.1:3000").rstrip("/")

DPRDEMOWEB_DIR: Path = Path(
    os.environ.get("DPRDEMOWEB_DIR", r"C:\Users\gemz\Documents\Github\dprdemoweb")
)

RATE_PER_SEC: float = float(os.environ.get("RATE_PER_SEC", "4"))

KMS_URL:       str = os.environ.get("KMS_URL", "")
KMS_APP_TOKEN: str = os.environ.get("KMS_APP_TOKEN", "")

ACCESS_MATRIX_PATH: Path = DPRDEMOWEB_DIR / "shared" / "access_matrix.json"
MODERN_LOG_PATH:    Path = DPRDEMOWEB_DIR / "web-modern" / "logs" / "app.log"

# ---------------------------------------------------------------------------
# Output directory
# ---------------------------------------------------------------------------
OUT_DIR: Path = Path(__file__).parent.parent / "out"
OUT_DIR.mkdir(exist_ok=True)
