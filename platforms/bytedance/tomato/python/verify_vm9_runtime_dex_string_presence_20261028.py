"""Verify the redacted installed-APK DEX string-presence record."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("record", type=Path)
    parser.add_argument("--apk", type=Path)
    args = parser.parse_args()
    data = json.loads(args.record.read_text(encoding="utf-8"))
    if data.get("schema") != "vm9-runtime-dex-string-presence-20261028-v1":
        raise AssertionError("unexpected schema")
    if data.get("installed_version") != "7.2.5.32/72532":
        raise AssertionError("unexpected installed version")
    dso = data.get("metasec_dso", {})
    if dso.get("sha256") != dso.get("pinned_research_sha256") or not dso.get("sha256_matches_pinned"):
        raise AssertionError("installed metasec DSO does not match pinned research hash")
    if data.get("raw_method_bodies_retained"):
        raise AssertionError("raw method bodies must not be retained")
    names = set()
    for item in data.get("dex", []):
        names.update(item.get("strings", {}))
    required = {"frameSign", "onCallToAddSecurityFactor", "MSManagerUtils", "MSManager", "CronetUrlRequest"}
    if not required.issubset(names):
        raise AssertionError(("missing_strings", sorted(required - names)))
    if args.apk:
        digest = hashlib.sha256(args.apk.read_bytes()).hexdigest()
        if digest != data.get("apk_sha256"):
            raise AssertionError("APK digest mismatch")
        import zipfile
        with zipfile.ZipFile(args.apk) as apk:
            dso_bytes = apk.read("lib/arm64-v8a/libmetasec_ml.so")
        if hashlib.sha256(dso_bytes).hexdigest() != dso["sha256"]:
            raise AssertionError("APK DSO digest mismatch")
    print(json.dumps({
        "schema": data["schema"],
        "installed_version": data["installed_version"],
        "required_strings_present": True,
        "metasec_dso_sha256_matches_pinned": True,
        "raw_method_bodies_retained": data["raw_method_bodies_retained"],
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
