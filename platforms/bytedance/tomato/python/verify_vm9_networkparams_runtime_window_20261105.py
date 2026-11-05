"""Verify a fresh redacted official NetworkParams/r4 runtime window.

The private JSONL capture is reduced to lengths, header names and SHA-256
digests.  This verifier deliberately accepts the one observed X-Neptune
response as a separate result class; it must not be counted as a six-header
response or used as evidence for Cronet.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any


SCHEMA = "vm9-networkparams-runtime-window-20261105-v1"
APK_SHA256 = "95889d1a1ad0b11ed2451eedf0389516e1382640182026e82eb515e04fbc04fd"
PROBE_SHA256 = "74beb8771464bfd1f4506c69f79e37af34a2dc4331aea4bf05ae24ae30febe30"
BRIDGE_SHA256 = "749e107feb32c21227fa79a5feda5c4a13bf4d797d51d8c94156d8d4b3e97eb2"
PROBE = Path(__file__).with_name("capture_vm9_business_framesign_android_20261028.py")
BRIDGE = Path(r"C:\AI\6\frida-java-bridge_plain_runtime_compat.js")
HOOKS = {
    "MSManager.frameSign",
    "ms.bd.c.r4.onCallToAddSecurityFactor",
    "CronetUrlRequest.addSecurityFactor",
    "CronetUrlRequestContext.addSecurityFactor",
    "CronetUrlRequestContext.o0",
}
HEADER_LENGTHS = {
    "X-Argus": {8},
    "X-Gorgon": {52},
    "X-Helios": {48},
    "X-Khronos": {10},
    "X-Ladon": {8},
    "X-Medusa": {1272, 1276},
}
ALT_HEADERS = {"X-Neptune": 26}
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def digest_row(value: dict[str, Any]) -> dict[str, Any]:
    require(set(value) == {"length", "sha256"}, "digest row fields")
    require(isinstance(value["length"], int) and value["length"] >= 0, "digest length")
    require(isinstance(value["sha256"], str) and DIGEST_RE.fullmatch(value["sha256"]), "digest")
    return {"length": value["length"], "sha256": value["sha256"]}


def load(path: Path) -> list[dict[str, Any]]:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    require(bool(rows), "empty capture")
    raw = json.dumps(rows, ensure_ascii=False)
    for forbidden in ("http://", "https://", "Bearer ", "ibssh_", "frp-hat"):
        require(forbidden.lower() not in raw.lower(), f"raw value: {forbidden}")
    require(all(isinstance(row, dict) for row in rows), "capture row")
    return rows


def context_summary(value: object) -> dict[str, int] | None:
    if value is None:
        return None
    require(isinstance(value, dict) and isinstance(value.get("thread_id"), int), "context")
    return {"thread_id": value["thread_id"]}


def factor_summary(row: dict[str, Any]) -> dict[str, Any]:
    require(isinstance(row.get("url"), dict), "url digest")
    require(isinstance(row.get("route"), dict), "route")
    route = row["route"]
    require(isinstance(route.get("path"), dict), "route path")
    inputs = []
    for header in row.get("input", {}).get("rows", []):
        require(isinstance(header, dict) and set(header) == {"key", "value"}, "input header")
        require(isinstance(header["key"], str), "input name")
        inputs.append({"key": header["key"], "value": digest_row(header["value"])})

    result = row.get("result")
    require(isinstance(result, dict), "result")
    result_rows = []
    for header in result.get("rows", []):
        require(isinstance(header, dict) and set(header) == {"key", "value"}, "result header")
        require(isinstance(header["key"], str), "result name")
        result_rows.append({"key": header["key"], "value": digest_row(header["value"])})
    result_rows.sort(key=lambda item: item["key"])
    names = {item["key"] for item in result_rows}
    if names == set(HEADER_LENGTHS):
        result_kind = "six_header"
        require(result.get("count") == 6 and len(result_rows) == 6, "six-header count")
        actual_lengths = {item["key"]: item["value"]["length"] for item in result_rows}
        require(all(actual_lengths[key] in lengths for key, lengths in HEADER_LENGTHS.items()),
                "six-header lengths")
    elif names == set(ALT_HEADERS):
        result_kind = "alternate"
        require(result.get("count") == 1 and len(result_rows) == 1, "alternate count")
        require(result_rows[0]["value"]["length"] == ALT_HEADERS["X-Neptune"], "alternate length")
    else:
        raise ValueError(f"unexpected result names: {sorted(names)}")
    return {
        "url": digest_row(row["url"]),
        "route": {
            "length": route["length"],
            "sha256": route["sha256"],
            "path": digest_row(route["path"]),
        },
        "input": {"count": len(inputs), "rows": inputs},
        "result_kind": result_kind,
        "result": {"count": result["count"], "rows": result_rows},
        "context": context_summary(row.get("context")),
    }


def summarize(capture: Path) -> dict[str, Any]:
    rows = load(capture)
    events = [row for row in rows if isinstance(row.get("event"), str)]
    factors = [factor_summary(row) for row in events if row.get("event") == "securityFactor"]
    cronet = [row for row in events if row.get("event") in {
        "cronetSecurityFactor", "cronetContextSecurityFactor", "cronetContextO0",
    }]
    hooked = sorted(row["target"] for row in events if row.get("event") == "hooked")
    require(set(hooked) == HOOKS, "hook set")
    require(len(factors) == 19, "r4 callback count")
    require(sum(item["result_kind"] == "six_header" for item in factors) == 18,
            "six-header callback count")
    require(sum(item["result_kind"] == "alternate" for item in factors) == 1,
            "alternate callback count")
    terminal = events[-1] if events and events[-1].get("event") == "session_detached" else None
    require(isinstance(terminal, dict) and terminal.get("reason") == "application-requested",
            "terminal detach")
    return {
        "label": "official_reader_root_frida_followup",
        "capture_sha256": hashlib.sha256(capture.read_bytes()).hexdigest(),
        "capture_bytes": capture.stat().st_size,
        "event_counts": dict(Counter(row.get("event") for row in events)),
        "hooked_targets": hooked,
        "security_factor_calls": factors,
        "cronet_event_count": len(cronet),
        "terminal_event": {"event": terminal["event"], "reason": terminal["reason"]},
        "raw_capture_retained_in_evidence": False,
    }


def build_record(capture: Path) -> dict[str, Any]:
    require(hashlib.sha256(PROBE.read_bytes()).hexdigest() == PROBE_SHA256, "probe hash")
    require(hashlib.sha256(BRIDGE.read_bytes()).hexdigest() == BRIDGE_SHA256, "bridge hash")
    summary = summarize(capture)
    return {
        "schema": SCHEMA,
        "evidence_date": "2026-11-05",
        "artifact": {
            "package": "com.dragon.read",
            "version_code": 72532,
            "installed_apk_sha256": APK_SHA256,
            "android_version": "9",
            "android_api_level": 28,
            "abi": "x86_64",
            "frida_version": "17.24.3",
            "frida_server_privilege": "root",
            "probe_source_sha256": PROBE_SHA256,
            "bridge_sha256": BRIDGE_SHA256,
        },
        "trigger": "already-open reader activity; bounded 30-second attach",
        "capture_count": 1,
        "captures": [summary],
        "security_factor_callback_observed": True,
        "security_factor_callback_count": 19,
        "six_header_call_count": 18,
        "alternate_result_count": 1,
        "observed_header_length_sets": {
            key: sorted(lengths) for key, lengths in HEADER_LENGTHS.items()
        },
        "observed_alternate_header_lengths": ALT_HEADERS,
        "cronet_runtime_branch_observed": False,
        "same_request_cronet_correlation_verified": False,
        "callback_url_or_map_object_identity_joined": False,
        "provider_method_or_field_identity_joined": False,
        "ordinary_cronet_six_head_chain_verified": False,
        "whole_request_native_python_differential_verified": False,
        "fresh_standalone_signer_verified": False,
        "online_header_acceptance_verified": False,
        "raw_urls_or_header_values_retained": False,
        "target_app_modified": False,
        "interpretation": (
            "A bounded attach to the official unmodified 7.2.5.32 APK observed 19 "
            "NetworkParams/r4 callbacks. Eighteen returned all six seven-god headers "
            "with the recorded lengths; one separate result contained X-Neptune only. "
            "All three Cronet entry hooks and o0 were installed but no Cronet event "
            "occurred in this reader window. This is an OkHttp/NetworkParams observation "
            "and does not establish Cronet execution, standalone signing, or online acceptance."
        ),
    }


def verify(record: dict[str, Any], capture: Path) -> dict[str, Any]:
    expected = build_record(capture)
    require(record == expected, "record differs from redacted capture summary")
    return {
        "schema": SCHEMA,
        "security_factor_callback_count": record["security_factor_callback_count"],
        "six_header_call_count": record["six_header_call_count"],
        "alternate_result_count": record["alternate_result_count"],
        "cronet_event_count": record["captures"][0]["cronet_event_count"],
        "ordinary_cronet_six_head_chain_verified": False,
        "online_header_acceptance_verified": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output", type=Path)
    mode.add_argument("--record", type=Path)
    args = parser.parse_args()
    if args.output is not None:
        require(not args.output.exists(), "--output already exists")
        record = build_record(args.capture)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    else:
        record = json.loads(args.record.read_text(encoding="utf-8"))
    print(json.dumps(verify(record, args.capture), ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
