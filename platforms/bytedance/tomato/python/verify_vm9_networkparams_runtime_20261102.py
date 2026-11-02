"""Summarize and verify the redacted 2026-11-02 Android request capture."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import capture_vm9_networkparams_followup_20261031 as sanitizer


SCHEMA = "vm9-networkparams-runtime-20261102-v1"
APK_SHA256 = "95889d1a1ad0b11ed2451eedf0389516e1382640182026e82eb515e04fbc04fd"
BRIDGE_SHA256 = "02cb922b7fea29a566bd9ae4a190fad24c503076f2497af5706d117033de6a0e"
CAPTURE_SOURCE_SHA256 = "907c80aed0ad6c2a4377f02f8d12b2fea8154faced7a312c7845fb43a81768ea"
HOOKS = {
    "MSManager.frameSign",
    "ms.bd.c.r4.onCallToAddSecurityFactor",
    "CronetUrlRequest.addSecurityFactor",
    "CronetUrlRequestContext.addSecurityFactor",
    "CronetUrlRequestContext.o0",
    "ms.bd.c.s2.k",
    "ms.bd.c.s2.j.certificate",
}
HEADER_LENGTHS = {
    "X-Argus": 8,
    "X-Gorgon": 52,
    "X-Helios": 48,
    "X-Khronos": 10,
    "X-Ladon": 8,
    "X-Medusa": 1284,
}


def build_record(capture_path: Path) -> dict:
    capture = sanitizer.summarize(
        capture_path, "official_next_chapter", CAPTURE_SOURCE_SHA256,
    )
    if capture["event_counts"].get("securityFactor") != 18:
        raise AssertionError("expected 18 ordinary securityFactor callbacks")
    if set(capture["hooked_targets"]) != HOOKS:
        raise AssertionError("capture did not install the expected hook set")
    if len(capture["security_factor_calls"]) != 18:
        raise AssertionError("securityFactor event count does not match callbacks")
    if capture["cronet_event_count"] != 0 or capture["certificate_returns"]:
        raise AssertionError("capture no longer matches this bounded observation")
    for call in capture["security_factor_calls"]:
        actual = {row["key"]: row["value"]["length"]
                  for row in call["result"]["rows"]}
        if actual != HEADER_LENGTHS:
            raise AssertionError("incomplete or unexpected six-header result")

    return {
        "schema": SCHEMA,
        "evidence_date": "2026-11-02",
        "artifact": {
            "package": "com.dragon.read",
            "version_code": 72532,
            "installed_apk_sha256": APK_SHA256,
            "frida_version": "17.24.3",
            "bridge_sha256": BRIDGE_SHA256,
            "android_version": "9",
            "android_api_level": 28,
            "abi": "x86_64",
        },
        "trigger": "one next-chapter tap from ReaderActivity",
        "capture_count": 1,
        "captures": [capture],
        "security_factor_callback_observed": True,
        "six_header_call_count": 18,
        "observed_header_lengths": HEADER_LENGTHS,
        "cronet_runtime_branch_observed": False,
        "certificate_callback_observed": False,
        "same_request_certificate_correlation_verified": False,
        "whole_request_native_python_differential_verified": False,
        "fresh_standalone_signer_verified": False,
        "online_header_acceptance_verified": False,
        "raw_urls_or_header_values_retained": False,
        "target_app_modified": False,
        "interpretation": (
            "The official 7.2.5.32 APK remained installed during a normal reader UI action. "
            "The bounded capture observed 18 calls to the NetworkParams/r4 callback; every "
            "result had all six seven-god header names and the recorded lengths. The exercised "
            "window did not observe Cronet or certificate callbacks. This is Android runtime "
            "provider evidence, not a native/Python differential, standalone signer, or online "
            "acceptance result; zero events do not prove those other paths are unreachable."
        ),
    }


def verify(record: dict, capture_path: Path) -> dict:
    expected = build_record(capture_path)
    if record != expected:
        raise AssertionError("record differs from the redacted capture summary")
    encoded = json.dumps(record, ensure_ascii=False)
    for forbidden in ("http://", "https://", "Bearer ", "ibssh_", "frp-hat"):
        if forbidden.lower() in encoded.lower():
            raise AssertionError("evidence contains a forbidden raw value")
    return {
        "status": "verified_runtime_capture",
        "security_factor_calls": record["six_header_call_count"],
        "cronet_events": record["captures"][0]["cronet_event_count"],
        "certificate_returns": len(record["captures"][0]["certificate_returns"]),
        "whole_request_native_python_differential_verified": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output", type=Path)
    mode.add_argument("--record", type=Path)
    args = parser.parse_args()

    if args.output is not None:
        if args.output.exists():
            parser.error("--output already exists")
        record = build_record(args.capture)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(record, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    else:
        record = json.loads(args.record.read_text(encoding="utf-8"))
    print(json.dumps(verify(record, args.capture), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
