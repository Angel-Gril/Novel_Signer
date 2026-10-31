"""Verify the redacted Cronet direct-caller scan."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

EXPECTED_SCHEMA = "vm9-cronet-static-callers-20261031-v1"
EXPECTED_APK = "95889d1a1ad0b11ed2451eedf0389516e1382640182026e82eb515e04fbc04fd"
EXPECTED_TARGETS = {
    "CronetUrlRequest.addSecurityFactor":
    "Lcom/ttnet/org/chromium/net/impl/CronetUrlRequest;->addSecurityFactor",
    "CronetUrlRequestContext.addSecurityFactor":
    "Lcom/ttnet/org/chromium/net/impl/CronetUrlRequestContext;->addSecurityFactor",
    "CronetUrlRequestContext.o0":
    "Lcom/ttnet/org/chromium/net/impl/CronetUrlRequestContext;->o0",
}


def verify(record: Path, apk: Path | None = None) -> dict[str, object]:
    data = json.loads(record.read_text(encoding="utf-8"))
    if data.get("schema") != EXPECTED_SCHEMA:
        raise AssertionError("unexpected schema")
    if data.get("package") != "com.dragon.read" or data.get("version") != "7.2.5.32/72532":
        raise AssertionError("unexpected target identity")
    if data.get("apk_sha256") != EXPECTED_APK:
        raise AssertionError("unexpected APK digest")
    if data.get("targets") != EXPECTED_TARGETS:
        raise AssertionError("target descriptors changed")
    if data.get("dex_count") != 27 or data.get("method_count", 0) <= 0:
        raise AssertionError("unexpected DEX summary")
    all_calls = data.get("all_direct_call_counts")
    external_calls = data.get("external_business_call_counts")
    if all_calls != {
        "CronetUrlRequest.addSecurityFactor": 0,
        "CronetUrlRequestContext.addSecurityFactor": 0,
        "CronetUrlRequestContext.o0": 2,
    }:
        raise AssertionError(("unexpected all-call counts", all_calls))
    if external_calls != {label: 0 for label in EXPECTED_TARGETS}:
        raise AssertionError(("unexpected external-call counts", external_calls))
    if data.get("raw_method_bodies_retained") is not False or data.get("raw_instruction_text_retained") is not False:
        raise AssertionError("raw code must not be retained")
    if apk is not None:
        if hashlib.sha256(apk.read_bytes()).hexdigest() != EXPECTED_APK:
            raise AssertionError("APK digest mismatch")
    return data


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--record", type=Path, required=True)
    parser.add_argument("--apk", type=Path)
    args = parser.parse_args()
    data = verify(args.record, args.apk)
    print(json.dumps({
        "schema": data["schema"],
        "dex_count": data["dex_count"],
        "external_business_call_counts": data["external_business_call_counts"],
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
