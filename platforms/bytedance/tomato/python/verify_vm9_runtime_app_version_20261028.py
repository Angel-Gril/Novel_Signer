"""Verify the redacted runtime-version boundary record."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("record", type=Path)
    args = parser.parse_args()
    data = json.loads(args.record.read_text(encoding="utf-8"))
    if data.get("schema") != "vm9-runtime-app-version-20261028-v1":
        raise AssertionError("unexpected schema")
    if data.get("package") != "com.dragon.read":
        raise AssertionError("unexpected package")
    if (data.get("installed_version_name"), data.get("installed_version_code")) != ("7.2.5.32", 72532):
        raise AssertionError("installed runtime version changed")
    if (data.get("pinned_research_version_name"), data.get("pinned_research_version_code")) != ("7.1.3.32", 71332):
        raise AssertionError("pinned research version changed")
    if data.get("raw_headers_or_tokens_retained"):
        raise AssertionError("record must remain redacted")
    print(json.dumps({
        "schema": data["schema"],
        "installed": f'{data["installed_version_name"]}/{data["installed_version_code"]}',
        "pinned": f'{data["pinned_research_version_name"]}/{data["pinned_research_version_code"]}',
        "runtime_probe_status": data["runtime_probe_status"],
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
