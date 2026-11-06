"""Build and verify a fresh redacted official NetworkParams/r4 runtime window."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any


SCHEMA = "vm9-networkparams-runtime-fresh-20261107-v1"
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
    "resource_warning",
    "response_deserialized",
    "error_code_exception",
    "reader_exception",
}
MAIN_HOOKS = {
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
    "X-Medusa": {1288, 1292},
}
STACK_PREFIX = (
    ("ms.bd.c.r4", "onCallToAddSecurityFactor"),
    ("com.bytedance.frameworks.baselib.network.http.ok3.impl.OkHttp3SecurityFactorInterceptor", "intercept"),
    ("okhttp3.internal.http.RealInterceptorChain", "proceed"),
    ("okhttp3.internal.http.RealInterceptorChain", "proceed"),
    ("okhttp3.RealCall", "getResponseWithInterceptorChain"),
    ("okhttp3.RealCall", "execute"),
    ("com.bytedance.frameworks.baselib.network.http.ok3.impl.b", "p"),
    ("com.bytedance.frameworks.baselib.network.http.impl.a", "execute"),
)
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def digest_row(value: object) -> dict[str, Any]:
    require(isinstance(value, dict) and set(value) == {"length", "sha256"}, "digest row")
    require(isinstance(value["length"], int) and value["length"] >= 0, "digest length")
    require(isinstance(value["sha256"], str) and DIGEST_RE.fullmatch(value["sha256"]), "digest")
    return {"length": value["length"], "sha256": value["sha256"]}


def load(path: Path) -> list[dict[str, Any]]:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    require(bool(rows), "capture empty")
    raw = json.dumps(rows, ensure_ascii=False).lower()
    for forbidden in ("http://", "https://", "bearer ", "ibssh_", "frp-hat"):
        require(forbidden not in raw, f"raw value: {forbidden}")
    require(all(isinstance(row, dict) for row in rows), "capture row")
    return rows


def context_summary(value: object) -> dict[str, Any]:
    require(isinstance(value, dict) and isinstance(value.get("thread_id"), int), "context")
    stack = value.get("stack")
    require(isinstance(stack, list) and len(stack) >= len(STACK_PREFIX), "stack")
    methods = []
    for item in stack:
        require(isinstance(item, dict), "stack item")
        methods.append((item.get("class"), item.get("method")))
    duplicate_r4 = len(methods) > 1 and methods[0] == STACK_PREFIX[0] and methods[1] == STACK_PREFIX[0]
    normalized = (methods[:1] + methods[2:]) if duplicate_r4 else methods
    require(tuple(normalized[: len(STACK_PREFIX)]) == STACK_PREFIX, "OkHttp stack prefix")
    require(not any("Cronet" in str(item.get("class")) for item in stack), "Cronet stack frame")
    return {
        "thread_id": value["thread_id"],
        "stack_prefix": [
            {"class": class_name, "method": method_name}
            for class_name, method_name in STACK_PREFIX
        ],
        "stack_depth": len(stack),
        "duplicate_r4_frame": duplicate_r4,
    }


def factor_summary(row: dict[str, Any]) -> dict[str, Any]:
    url = digest_row(row.get("url"))
    route = row.get("route")
    require(isinstance(route, dict), "route")
    route_path = digest_row(route.get("path"))
    input_rows = []
    input_value = row.get("input")
    require(isinstance(input_value, dict), "input")
    for item in input_value.get("rows", []):
        require(isinstance(item, dict) and set(item) == {"key", "value"}, "input row")
        require(isinstance(item["key"], str), "input key")
        input_rows.append({"key": item["key"], "value": digest_row(item["value"])})
    result = row.get("result")
    require(isinstance(result, dict) and result.get("count") == 6, "result")
    result_rows = []
    for item in result.get("rows", []):
        require(isinstance(item, dict) and set(item) == {"key", "value"}, "result row")
        require(item["key"] in HEADER_LENGTHS, "result key")
        value = digest_row(item["value"])
        require(value["length"] in HEADER_LENGTHS[item["key"]], "result length")
        result_rows.append({"key": item["key"], "value": value})
    result_rows.sort(key=lambda item: item["key"])
    require({item["key"] for item in result_rows} == set(HEADER_LENGTHS), "six headers")
    return {
        "url": url,
        "route": {"length": route["length"], "sha256": route["sha256"], "path": route_path},
        "input": {"count": len(input_rows), "rows": input_rows},
        "result": {"count": 6, "rows": result_rows},
        "context": context_summary(row.get("context")),
    }


def summarize(capture: Path) -> dict[str, Any]:
    rows = load(capture)
    events = [row for row in rows if isinstance(row.get("event"), str)]
    hooked = sorted(row["target"] for row in events if row.get("event") == "hooked")
    require(set(hooked) == HOOKS, "hook set")
    require(set(MAIN_HOOKS).issubset(set(hooked)), "main hook set")
    factors = [factor_summary(row) for row in events if row.get("event") == "securityFactor"]
    require(len(factors) == 21, "r4 callback count")
    cronet = [row for row in events if row.get("event") in {
        "cronetSecurityFactor", "cronetContextSecurityFactor", "cronetContextO0",
    }]
    require(not cronet, "Cronet event")
    responses = [row for row in events if row.get("event") == "response_deserialized"]
    require(len(responses) == 17, "response count")
    response_codes = Counter((row.get("http_status"), row.get("business_code")) for row in responses)
    require(response_codes == Counter({(200, 0): 14, (200, -2002): 3}), "response codes")
    terminal = events[-1]
    require(terminal.get("event") == "session_detached" and
            terminal.get("reason") == "application-requested", "terminal detach")
    return {
        "capture_sha256": hashlib.sha256(capture.read_bytes()).hexdigest(),
        "capture_bytes": capture.stat().st_size,
        "capture_row_count": len(rows),
        "process_id": next(row["pid"] for row in events if row.get("event") == "probe_ready"),
        "event_counts": dict(Counter(row.get("event") for row in events)),
        "hooked_targets": hooked,
        "security_factor_calls": factors,
        "response_deserialized_count": len(responses),
        "response_http_business_code_counts": {
            f"{status}:{code}": count for (status, code), count in sorted(response_codes.items())
        },
        "cronet_event_count": len(cronet),
        "terminal_event": {"event": terminal["event"], "reason": terminal["reason"]},
        "raw_capture_retained_in_evidence": False,
    }


def build_record(capture: Path) -> dict[str, Any]:
    require(hashlib.sha256(PROBE.read_bytes()).hexdigest() == PROBE_SHA256, "probe hash")
    require(hashlib.sha256(BRIDGE.read_bytes()).hexdigest() == BRIDGE_SHA256, "bridge hash")
    observed = summarize(capture)
    return {
        "schema": SCHEMA,
        "evidence_date": "2026-11-07",
        "artifact": {
            "package": "com.dragon.read",
            "version_name": "7.2.5.32",
            "version_code": 72532,
            "installed_apk_sha256": APK_SHA256,
            "android_version": "9",
            "android_api_level": 28,
            "abi": "x86_64",
            "device_serial": "emulator-5554",
            "frida_version": "17.24.3",
            "frida_server_privilege": "root",
            "probe_source_sha256": PROBE_SHA256,
            "bridge_sha256": BRIDGE_SHA256,
        },
        "trigger": "already-running official home/recommendation activity; bounded 120-second attach",
        "capture_count": 1,
        "captures": [observed],
        "security_factor_callback_observed": True,
        "security_factor_callback_count": 21,
        "six_header_call_count": 21,
        "observed_header_length_sets": {
            key: sorted(lengths) for key, lengths in HEADER_LENGTHS.items()
        },
        "cronet_runtime_branch_observed": False,
        "r4_callback_cronet_identity_joined": False,
        "callback_url_or_map_object_identity_joined": False,
        "provider_method_or_field_identity_joined": False,
        "ordinary_cronet_six_header_chain_verified": False,
        "whole_request_native_python_differential_verified": False,
        "fresh_standalone_signer_verified": False,
        "online_header_acceptance_verified": False,
        "raw_urls_or_header_values_retained": False,
        "target_app_modified": False,
        "interpretation": (
            "A fresh bounded attach to the official unmodified 7.2.5.32 APK observed 21 "
            "NetworkParams/r4 security-factor callbacks. Every callback returned all six "
            "seven-god header keys; X-Medusa was observed at lengths 1288 and 1292. The "
            "bounded stacks consistently entered OkHttp3SecurityFactorInterceptor and "
            "okhttp3.RealCall, with no Cronet frames or Cronet entry events. Seventeen "
            "response-deserialization events were HTTP 200, with business codes 0 or -2002. "
            "This remains an OkHttp path observation and does not establish Cronet execution, "
            "standalone signing, whole-request differential, or online acceptance."
        ),
    }


def verify(record: dict[str, Any], capture: Path) -> dict[str, Any]:
    expected = build_record(capture)
    require(record == expected, "record differs from redacted capture summary")
    return {
        "schema": SCHEMA,
        "security_factor_callback_count": record["security_factor_callback_count"],
        "six_header_call_count": record["six_header_call_count"],
        "response_deserialized_count": record["captures"][0]["response_deserialized_count"],
        "cronet_event_count": record["captures"][0]["cronet_event_count"],
        "ordinary_cronet_six_header_chain_verified": False,
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
        require(not args.output.exists(), "evidence already exists")
        record = build_record(args.capture)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    else:
        record = json.loads(args.record.read_text(encoding="utf-8"))
    print(json.dumps(verify(record, args.capture), ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
