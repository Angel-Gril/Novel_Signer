"""Summarize and verify a redacted multi-request OkHttp/r4 capture."""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any


SCHEMA = "vm9-okhttp-r4-multirequest-window-20261106-v1"
HEADERS = ("X-Argus", "X-Gorgon", "X-Helios", "X-Khronos", "X-Ladon", "X-Medusa")
STACK_PREFIX = [
    ("ms.bd.c.r4", "onCallToAddSecurityFactor"),
    ("com.bytedance.frameworks.baselib.network.http.NetworkParams", "tryAddSecurityFactor"),
    ("com.bytedance.frameworks.baselib.network.http.ok3.impl.OkHttp3SecurityFactorInterceptor", "intercept"),
    ("okhttp3.internal.http.RealInterceptorChain", "proceed"),
    ("okhttp3.internal.http.RealInterceptorChain", "proceed"),
    ("okhttp3.RealCall", "getResponseWithInterceptorChain"),
    ("okhttp3.RealCall", "execute"),
    ("com.bytedance.frameworks.baselib.network.http.ok3.impl.b", "p"),
]
DEFAULT_CAPTURE = Path(
    r"C:\AI\6\_repo_stage\platforms\bytedance\tomato\evidence"
) / "_runtime_okhttp_r4_identity_20261105_run2.jsonl"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def load(path: Path) -> list[dict[str, Any]]:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()]
    require(rows, "capture is empty")
    raw = json.dumps(rows, ensure_ascii=False).lower()
    for forbidden in ("http://", "https://", "bearer ", "ibssh_", "frp-hat"):
        require(forbidden not in raw, f"raw value retained: {forbidden}")
    return rows


def summarize(path: Path) -> dict[str, Any]:
    rows = load(path)
    require(len(rows) == 264, "row count")
    require(rows[0] == {"event": "hooked", "target": "ms.bd.c.r4.onCallToAddSecurityFactor"},
            "hook readiness")
    require(rows[1].get("event") == "probe_ready" and rows[2].get("event") == "script_loaded",
            "probe readiness")
    require(rows[-1] == {"event": "session_detached", "reason": "application-requested"},
            "terminal event")
    enters = [row for row in rows if row.get("event") == "r4_enter"]
    leaves = [row for row in rows if row.get("event") == "r4_leave"]
    require(len(enters) == 130 and len(leaves) == 130, "callback count")
    require(all(row.get("ok") is True for row in leaves), "callback failure")
    result_sets = Counter(tuple(row.get("result_keys", [])) for row in leaves)
    require(result_sets[HEADERS] == 126 and result_sets[("X-Neptune",)] == 4,
            "result shape")
    input_counts = Counter()
    url_lengths = Counter()
    thread_ids: set[int] = set()
    for row in enters:
        require(row.get("url_id") == 0 and row.get("map_id") == 0,
                "identity fields are not stable evidence")
        keys = row.get("input_keys")
        require(isinstance(keys, list) and all(isinstance(value, str) for value in keys),
                "input key shape")
        input_counts[len(keys)] += 1
        require(isinstance(row.get("url_length"), int) and row["url_length"] >= 0,
                "url length")
        url_lengths[row["url_length"]] += 1
        require(isinstance(row.get("thread_id"), int), "thread id")
        thread_ids.add(row["thread_id"])
        stack = row.get("stack")
        require(isinstance(stack, list) and stack, "stack")
        classes = [str(item.get("class_name")) for item in stack]
        methods = [(item.get("class_name"), item.get("method_name")) for item in stack]
        require(methods[0] == STACK_PREFIX[0], "r4 stack head")
        require("com.bytedance.frameworks.baselib.network.http.ok3.impl.OkHttp3SecurityFactorInterceptor" in classes,
                "OkHttp interceptor missing")
        require("okhttp3.RealCall" in classes, "RealCall missing")
        require(not any("Cronet" in class_name for class_name in classes),
                "Cronet frame unexpectedly present")
    network_params_visible = sum(
        "com.bytedance.frameworks.baselib.network.http.NetworkParams" in
        [str(item.get("class_name")) for item in row.get("stack", [])]
        for row in enters)
    duplicate_r4 = sum(
        sum(str(item.get("class_name")) == "ms.bd.c.r4" for item in row.get("stack", [])) > 1
        for row in enters)
    return {
        "capture_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "capture_bytes": path.stat().st_size,
        "capture_row_count": len(rows),
        "process_id": rows[1]["pid"],
        "event_counts": {
            "hooked": 1,
            "probe_ready": 1,
            "script_loaded": 1,
            "r4_enter": len(enters),
            "r4_leave": len(leaves),
            "session_detached": 1,
        },
        "callback_count": len(enters),
        "six_header_callback_count": result_sets[HEADERS],
        "alternate_neptune_callback_count": result_sets[("X-Neptune",)],
        "input_key_count_distribution": {str(key): value for key, value in sorted(input_counts.items())},
        "url_length_min": min(url_lengths),
        "url_length_max": max(url_lengths),
        "url_length_distinct_count": len(url_lengths),
        "thread_count": len(thread_ids),
        "representative_stack_prefix": [
            {"class_name": class_name, "method_name": method_name}
            for class_name, method_name in STACK_PREFIX
        ],
        "okhttp_interceptor_visible_count": len(enters),
        "real_call_visible_count": len(enters),
        "network_params_visible_count": network_params_visible,
        "duplicate_r4_frame_count": duplicate_r4,
        "cronet_stack_frame_count": 0,
        "raw_business_values_retained": False,
    }


def build_record(capture: Path) -> dict[str, Any]:
    observed = summarize(capture)
    return {
        "schema": SCHEMA,
        "evidence_date": "2026-11-06",
        "source_scope": {
            "artifact": "official fq_7xz.apk redacted multi-request OkHttp/r4 callback window",
            "package_name": "com.dragon.read",
            "version_name": "7.2.5.32",
            "version_code": 72532,
            "device_serial": "emulator-5554",
            "frida_version": "17.24.3",
            "frida_server_privilege": "root",
            "raw_business_values_retained": False,
        },
        "source_artifacts": {
            "apk_sha256": "95889d1a1ad0b11ed2451eedf0389516e1382640182026e82eb515e04fbc04fd",
            "bridge_sha256": "749e107feb32c21227fa79a5feda5c4a13bf4d797d51d8c94156d8d4b3e97eb2",
            "probe_sha256": "68297ca89e1fd4d1cd111004f76d0499b3e93b0409a00eae82874e187490b8b5",
            "capture_sha256": observed["capture_sha256"],
            "capture_row_count": observed["capture_row_count"],
        },
        "observed": observed,
        "claims": {
            "okhttp_security_factor_stack_observed": True,
            "six_header_result_shape_observed": True,
            "alternate_neptune_result_observed": True,
            "java_object_identity_verified": False,
            "cronet_entry_runtime_observed": False,
            "r4_callback_cronet_identity_joined": False,
            "ordinary_cronet_six_header_chain_verified": False,
            "complete_standalone_signer_verified": False,
            "whole_request_native_python_differential_verified": False,
            "online_header_acceptance_verified": False,
        },
        "interpretation": (
            "Across 130 callbacks in this bounded window, 126 returned the six standard "
            "headers and four returned X-Neptune. Every captured stack used "
            "OkHttp3SecurityFactorInterceptor without a Cronet frame; NetworkParams remained "
            "visible in the bounded stack prefix for 31 callbacks. Identity fields "
            "were zero and are deliberately not used to join requests across layers."
        ),
    }


def verify_record(record_path: Path, capture_path: Path) -> dict[str, Any]:
    record = json.loads(record_path.read_text(encoding="utf-8"))
    require(record.get("schema") == SCHEMA, "schema")
    require(record.get("claims", {}).get("cronet_entry_runtime_observed") is False,
            "Cronet claim")
    require(record.get("claims", {}).get("complete_standalone_signer_verified") is False,
            "signer claim")
    observed = summarize(capture_path)
    require(record.get("observed") == observed, "observed summary")
    require(record["source_artifacts"]["capture_sha256"] == observed["capture_sha256"],
            "capture hash")
    return {
        "schema": SCHEMA,
        "callback_count": observed["callback_count"],
        "six_header_callback_count": observed["six_header_callback_count"],
        "alternate_neptune_callback_count": observed["alternate_neptune_callback_count"],
        "cronet_stack_frame_count": observed["cronet_stack_frame_count"],
        "cronet_entry_runtime_observed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    root = Path(__file__).resolve().parents[1]
    parser.add_argument("--capture", type=Path, default=DEFAULT_CAPTURE)
    parser.add_argument("--evidence", type=Path,
                        default=root / "evidence" / "vm9_okhttp_r4_multirequest_20261106.json")
    parser.add_argument("--output", action="store_true")
    args = parser.parse_args()
    if args.output:
        require(not args.evidence.exists(), "evidence already exists")
        args.evidence.write_text(json.dumps(build_record(args.capture), ensure_ascii=False, indent=2) + "\n",
                                    encoding="utf-8")
        result = {"status": "written", "evidence": str(args.evidence)}
    else:
        result = verify_record(args.evidence, args.capture)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
