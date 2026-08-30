from __future__ import annotations

import json
import re
from pathlib import Path


TOKEN_PATTERNS = (
    re.compile(r"hf_[A-Za-z0-9]{20,}"),
    re.compile(r"gh[opusr]_[A-Za-z0-9]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
)


def test_tracked_kaggle_notebook_contains_no_embedded_access_token() -> None:
    notebook = Path("notebooks/meta-final.ipynb").read_text(encoding="utf-8")
    assert all(pattern.search(notebook) is None for pattern in TOKEN_PATTERNS)
    payload = json.loads(notebook)
    sources = "\n".join(str(cell.get("source", "")) for cell in payload["cells"])
    assert 'login(token=os.environ["HF_TOKEN"])' in sources
