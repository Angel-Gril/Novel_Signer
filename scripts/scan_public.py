"""Small conservative scan for accidental private trial material."""
from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
patterns = [
    re.compile(r"(?i)device[_-]?id\s*[:=]\s*['\"][0-9]{10,}"),
    re.compile(r"(?i)(x-)?(ss-req-ticket|rticket|token|authorization)\s*[:=]"),
    re.compile(r"(?i)BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY"),
]
allow_names = {"README.md", "REPORT.md", "API_CALLS.md", "SIGNATURE.md", "SEARCH.md", "architecture.md", "index.md"}
bad = []
for path in (ROOT / "platforms").rglob("*"):
    if not path.is_file() or path.name in allow_names or path.suffix == ".json":
        continue
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        continue
    for pattern in patterns:
        if pattern.search(text):
            bad.append(f"{path}: {pattern.pattern}")
if bad:
    print("public scan failed")
    print("\n".join(bad))
    raise SystemExit(1)
print("public scan passed")
