import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))
os.environ.setdefault("DATABASE_URL", "sqlite:///./test_siem.db")
os.environ.setdefault("JWT_SECRET", "test-secret")
os.environ.setdefault("API_KEY_HASH_SECRET", "test-api-secret")
