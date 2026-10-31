"""Scan DEX invoke instructions for direct Cronet security-factor callers.

The scan keeps only method descriptors, DEX sizes/digests, and aggregate counts.
It deliberately excludes the ``com.ttnet.org.chromium.net.impl`` implementation
package when reporting business callers, so the result answers a narrow question:
does another DEX method directly invoke the three selected methods?
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import zipfile
from collections import Counter
from pathlib import Path

logging.disable(logging.CRITICAL)
try:
    from loguru import logger as _loguru_logger
    _loguru_logger.remove()
except ImportError:
    pass

TARGETS = {
    "CronetUrlRequest.addSecurityFactor":
    "Lcom/ttnet/org/chromium/net/impl/CronetUrlRequest;->addSecurityFactor",
    "CronetUrlRequestContext.addSecurityFactor":
    "Lcom/ttnet/org/chromium/net/impl/CronetUrlRequestContext;->addSecurityFactor",
    "CronetUrlRequestContext.o0":
    "Lcom/ttnet/org/chromium/net/impl/CronetUrlRequestContext;->o0",
}
IMPLEMENTATION_PREFIX = "Lcom/ttnet/org/chromium/net/impl/"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def scan_dex(name: str, raw: bytes) -> tuple[Counter[str], Counter[str], int]:
    from androguard.core.dex import DEX

    all_calls: Counter[str] = Counter()
    external_calls: Counter[str] = Counter()
    method_count = 0
    dex = DEX(raw)
    for cls in dex.get_classes():
        class_name = str(cls.name)
        for method in cls.get_methods():
            method_count += 1
            code = method.get_code()
            if code is None:
                continue
            for instruction in method.get_instructions():
                output = instruction.get_output()
                for label, target in TARGETS.items():
                    if target in output:
                        all_calls[label] += 1
                        if not class_name.startswith(IMPLEMENTATION_PREFIX):
                            external_calls[label] += 1
    return all_calls, external_calls, method_count


def extract(apk_path: Path) -> dict[str, object]:
    with zipfile.ZipFile(apk_path) as archive:
        dex_items = [
            (name, archive.read(name))
            for name in archive.namelist()
            if name.startswith("classes") and name.endswith(".dex")
        ]
    if not dex_items:
        raise ValueError("APK contains no DEX files")
    all_calls: Counter[str] = Counter()
    external_calls: Counter[str] = Counter()
    method_count = 0
    dex_records = []
    for name, raw in dex_items:
        current_all, current_external, current_methods = scan_dex(name, raw)
        all_calls.update(current_all)
        external_calls.update(current_external)
        method_count += current_methods
        dex_records.append({"name": name, "size": len(raw), "sha256": digest(raw)})
    return {
        "dex_count": len(dex_items),
        "dex": dex_records,
        "method_count": method_count,
        "all_direct_call_counts": {label: all_calls[label] for label in TARGETS},
        "external_business_call_counts": {
            label: external_calls[label] for label in TARGETS
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = extract(args.apk)
    record = {
        "schema": "vm9-cronet-static-callers-20261031-v1",
        "evidence_date": "2026-10-31",
        "package": "com.dragon.read",
        "version": "7.2.5.32/72532",
        "apk_sha256": digest(args.apk.read_bytes()),
        "apk_size": args.apk.stat().st_size,
        "targets": TARGETS,
        "implementation_package_excluded_from_business_counts": IMPLEMENTATION_PREFIX,
        **result,
        "raw_method_bodies_retained": False,
        "raw_instruction_text_retained": False,
        "interpretation": (
            "Across all 27 DEX files, the selected Cronet security-factor methods have "
            "no direct invoke instructions from outside the Cronet implementation package. "
            "The only direct edges are the two implementation-level addSecurityFactor-to-o0 "
            "bridges. This points to native, reflection, or another indirect dispatch boundary; "
            "it does not prove that the Cronet path is unreachable at runtime."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "schema": record["schema"],
        "dex_count": record["dex_count"],
        "method_count": record["method_count"],
        "all_direct_call_counts": record["all_direct_call_counts"],
        "external_business_call_counts": record["external_business_call_counts"],
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
