from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from app.services.opensearch_service import create_index_template


if __name__ == "__main__":
    create_index_template()
    print("OpenSearch index template ensured.")
