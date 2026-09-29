"""Compile the public Python fixtures without importing or running them."""
from __future__ import annotations

import pathlib
import ast

ROOT = pathlib.Path(__file__).resolve().parents[1]
files = sorted((ROOT / "platforms").rglob("*.py"))
for path in files:
    ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
print(f"compiled {len(files)} Python files")
