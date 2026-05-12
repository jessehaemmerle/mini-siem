from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from app.db.session import SessionLocal
from app.detection.engine import run_detection_once


if __name__ == "__main__":
    db = SessionLocal()
    try:
        print(run_detection_once(db))
    finally:
        db.close()
