"""Compile the public Python fixtures without importing or running them."""
from __future__ import annotations

import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
files = sorted((ROOT / "platforms").rglob("*.py"))
for path in files:
    compile(path.read_text(encoding="utf-8"), str(path), "exec", dont_inherit=True)
print(f"compiled {len(files)} Python files")
