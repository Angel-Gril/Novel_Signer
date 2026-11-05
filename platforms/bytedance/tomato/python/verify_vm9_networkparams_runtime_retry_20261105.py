"""Build and verify the 2026-11-05 official APK Cronet/r4 runtime capture."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import capture_vm9_networkparams_followup_20261031 as sanitizer

SCHEMA = "vm9-networkparams-runtime-retry-20261105-v1"
APK_SHA256 = "95889d1a1ad0b11ed2451eedf0389516e1382640182026e82eb515e04fbc04fd"
PROBE_SHA256 = "74beb8771464bfd1f4506c69f79e37af34a2dc4331aea4bf05ae24ae30febe30"
BRIDGE_SHA256 = "749e107feb32c21227fa79a5feda5c4a13bf4d797d51d8c94156d8d4b3e97eb2"
PROBE = Path(__file__).with_name("capture_vm9_business_framesign_android_20261028.py")
BRIDGE = Path(r"C:\AI\6\frida-java-bridge_plain_runtime_compat.js")
HOOKS = {"MSManager.frameSign", "ms.bd.c.r4.onCallToAddSecurityFactor", "CronetUrlRequest.addSecurityFactor", "CronetUrlRequestContext.addSecurityFactor", "CronetUrlRequestContext.o0"}
HEADERS = {"X-Argus": 8, "X-Gorgon": 52, "X-Helios": 48, "X-Khronos": 10, "X-Ladon": 8, "X-Medusa": 1300}


def build_record(capture_path: Path) -> dict:
    if hashlib.sha256(PROBE.read_bytes()).hexdigest() != PROBE_SHA256:
        raise AssertionError("probe source hash changed")
    if hashlib.sha256(BRIDGE.read_bytes()).hexdigest() != BRIDGE_SHA256:
        raise AssertionError("bridge hash changed")
    capture = sanitizer.summarize(capture_path, "official_reader_root_frida_retry", PROBE_SHA256)
    if capture["event_counts"].get("securityFactor") != 2:
        raise AssertionError("expected two r4 callbacks")
    if set(capture["hooked_targets"]) != HOOKS:
        raise AssertionError("unexpected hook set")
    if len(capture["security_factor_calls"]) != 2:
        raise AssertionError("callback count mismatch")
    if capture["cronet_event_count"] != 0:
        raise AssertionError("Cronet entry unexpectedly observed")
    expected_url_lengths = [1155, 844]
    expected_input_counts = [14, 4]
    for index, call in enumerate(capture["security_factor_calls"]):
        if call["url"]["length"] != expected_url_lengths[index]:
            raise AssertionError("unexpected URL length")
        if call["input"]["count"] != expected_input_counts[index]:
            raise AssertionError("unexpected input count")
        actual = {row["key"]: row["value"]["length"] for row in call["result"]["rows"]}
        if actual != HEADERS:
            raise AssertionError("unexpected six-header result")
    return {
        "schema": SCHEMA,
        "evidence_date": "2026-11-05",
        "artifact": {
            "package": "com.dragon.read", "version_code": 72532,
            "installed_apk_sha256": APK_SHA256, "android_version": "9",
            "android_api_level": 28, "abi": "x86_64", "frida_version": "17.24.3",
            "frida_server_privilege": "root", "probe_source_sha256": PROBE_SHA256,
            "bridge_sha256": BRIDGE_SHA256,
        },
        "trigger": "already-open reader activity; bounded 60-second attach",
        "capture_count": 1, "captures": [capture],
        "security_factor_callback_observed": True, "six_header_call_count": 2,
        "observed_header_lengths": HEADERS, "cronet_runtime_branch_observed": False,
        "certificate_callback_observed": False, "same_request_certificate_correlation_verified": False,
        "callback_url_or_map_object_identity_joined": False, "provider_method_or_field_identity_joined": False,
        "ordinary_cronet_six_head_chain_verified": False, "whole_request_native_python_differential_verified": False,
        "fresh_standalone_signer_verified": False, "online_header_acceptance_verified": False,
        "raw_urls_or_header_values_retained": False, "target_app_modified": False,
        "interpretation": "On the official unmodified 7.2.5.32 APK, root Frida Java hooks captured two ordinary NetworkParams/r4 callbacks. Both returned all six seven-god header keys with the recorded lengths. CronetUrlRequest.addSecurityFactor, CronetUrlRequestContext.addSecurityFactor, and o0 were installed but did not enter during this reader window. This is a bounded path observation; it does not prove the Cronet branch is unreachable or establish online acceptance.",
    }


def verify(record: dict, capture_path: Path) -> dict:
    expected = build_record(capture_path)
    if record != expected:
        raise AssertionError("record differs from redacted capture summary")
    encoded = json.dumps(record, ensure_ascii=False)
    for forbidden in ("http://", "https://", "Bearer ", "ibssh_", "frp-hat"):
        if forbidden.lower() in encoded.lower():
            raise AssertionError("evidence contains forbidden raw value")
    return {"status": "verified_official_runtime_capture", "six_header_calls": record["six_header_call_count"], "cronet_events": record["captures"][0]["cronet_event_count"], "ordinary_cronet_six_head_chain_verified": False, "online_header_acceptance_verified": False}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output", type=Path)
    mode.add_argument("--record", type=Path)
    args = parser.parse_args()
    if args.output is not None:
        if args.output.exists(): parser.error("--output already exists")
        record = build_record(args.capture)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    else:
        record = json.loads(args.record.read_text(encoding="utf-8"))
    print(json.dumps(verify(record, args.capture), ensure_ascii=False))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
