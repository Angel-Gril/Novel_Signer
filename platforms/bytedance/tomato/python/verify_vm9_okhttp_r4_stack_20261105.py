"""Verify a redacted direct OkHttp -> r4 runtime stack capture.

The capture is intentionally bounded to one callback.  It proves the caller
stack and six-header result shape for that window; it does not prove Java
object identity, a Cronet request, standalone signing, or server acceptance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


NAME = "vm9_okhttp_r4_stack_20261105"
APK = Path(r"C:\AI\6\fq_7xz.apk")
BRIDGE = Path(r"C:\AI\6\frida-java-bridge_plain_runtime_compat.js")
PROBE = Path(r"C:\AI\6\probe_vm9_cronet_join_window_20261105_compat4.py")
CAPTURE = Path(r"C:\AI\6\_cronet_join_capture_20261105_run6.jsonl")
HEX256 = re.compile(r"^[0-9a-f]{64}$")
HEADERS = {
    "X-Argus", "X-Gorgon", "X-Helios", "X-Khronos", "X-Ladon", "X-Medusa"
}
INPUT_KEYS = [
    "accept-encoding", "lc", "passport-sdk-version", "sdk-version",
    "user-agent", "x-ss-stub", "x-tt-store-region", "x-tt-store-region-src",
    "x-vc-bdturing-sdk-version",
]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_capture(path: Path) -> list[dict[str, Any]]:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()]
    require(rows, "capture is empty")
    serialized = json.dumps(rows, ensure_ascii=False).lower()
    for forbidden in ("http://", "https://", "bearer ", "ibssh_", "frp-hat"):
        require(forbidden not in serialized, "raw value retained")
    return rows


def verify_capture(rows: list[dict[str, Any]]) -> dict[str, Any]:
    require([row.get("event") for row in rows] ==
            ["ready", "r4_security_enter", "r4_security_leave"], "event order")
    enter, leave = rows[1], rows[2]
    require(enter["url_length"] == 656, "URL length")
    require(enter["url_id"] == leave["url_id"] == 227964865, "URL identity field pair")
    require(enter["map_id"] == leave["map_id"] == 30669670, "Map identity field pair")
    require(enter["input_keys"] == INPUT_KEYS, "input key set")
    require(leave["ok"] is True and leave["result_keys"] == sorted(HEADERS),
            "result key set")
    stack = enter["stack"]
    require(isinstance(stack, list) and len(stack) >= 6, "stack")
    prefix = [(row.get("class_name"), row.get("method_name")) for row in stack[:6]]
    require(prefix == [
        ("ms.bd.c.r4", "onCallToAddSecurityFactor"),
        ("com.bytedance.frameworks.baselib.network.http.ok3.impl.OkHttp3SecurityFactorInterceptor", "intercept"),
        ("okhttp3.internal.http.RealInterceptorChain", "proceed"),
        ("okhttp3.RealCall", "getResponseWithInterceptorChain"),
        ("okhttp3.RealCall", "execute"),
        ("com.bytedance.frameworks.baselib.network.http.ok3.impl.b", "p"),
    ], "OkHttp stack prefix")
    require(not any("Cronet" in str(row.get("class_name")) for row in stack),
            "Cronet frame unexpectedly present")
    return {
        "callback_count": 1,
        "url_length": enter["url_length"],
        "input_key_count": len(enter["input_keys"]),
        "result_keys": sorted(HEADERS),
        "stack_prefix": [
            {"class_name": row["class_name"], "method_name": row["method_name"]}
            for row in stack[:6]
        ],
        "entry_return_id_fields_equal": True,
    }


def verify_record(path: Path, capture_path: Path = CAPTURE) -> dict[str, Any]:
    record = json.loads(path.read_text(encoding="utf-8"))
    require(record.get("schema") == "vm9-okhttp-r4-stack-20261105-v1", "schema")
    require(record.get("evidence_date") == "2026-11-05", "date")
    require(record["source_scope"] == {
        "artifact": "official fq_7xz.apk direct OkHttp security-factor callback",
        "package_name": "com.dragon.read",
        "version_name": "7.2.5.32",
        "version_code": 72532,
        "device_serial": "emulator-5554",
        "process_id": 1163,
        "frida_version": "17.24.3",
        "frida_server_privilege": "root",
        "raw_business_values_retained": False,
    }, "scope")
    artifacts = record["source_artifacts"]
    require(APK.is_file() and BRIDGE.is_file() and PROBE.is_file() and capture_path.is_file(),
            "runtime artifacts")
    expected = {
        "apk_sha256": "95889d1a1ad0b11ed2451eedf0389516e1382640182026e82eb515e04fbc04fd",
        "bridge_sha256": "749e107feb32c21227fa79a5feda5c4a13bf4d797d51d8c94156d8d4b3e97eb2",
        "probe_sha256": "68297ca89e1fd4d1cd111004f76d0499b3e93b0409a00eae82874e187490b8b5",
        "capture_sha256": "3e3c58124e9d6dd78ae30beddf2aa5498091251057c300f7d46cb8bb1ce9dd08",
    }
    # The bridge hash above is checked against the observed runtime artifact.
    expected["bridge_sha256"] = "749e107feb32c21227fa79a5feda5c4a13bf4d797d51d8c94156d8d4b3e97eb2"
    for key, value in expected.items():
        require(HEX256.fullmatch(value) and artifacts[key] == value, key)
    require(sha256(APK) == artifacts["apk_sha256"], "APK hash")
    require(sha256(BRIDGE) == artifacts["bridge_sha256"], "bridge hash")
    require(sha256(PROBE) == artifacts["probe_sha256"], "probe hash")
    require(sha256(capture_path) == artifacts["capture_sha256"], "capture hash")
    observed = verify_capture(load_capture(capture_path))
    require(record["observed"] == observed, "observed summary")
    require(record["claims"] == {
        "okhttp_security_factor_stack_observed": True,
        "six_header_result_shape_observed": True,
        "r4_entry_return_id_fields_equal": True,
        "java_object_identity_verified": False,
        "cronet_entry_runtime_observed": False,
        "r4_callback_cronet_identity_joined": False,
        "ordinary_cronet_six_header_chain_verified": False,
        "complete_standalone_signer_verified": False,
        "whole_request_native_python_differential_verified": False,
        "online_header_acceptance_verified": False,
    }, "claims")
    return {
        "schema": record["schema"],
        "okhttp_security_factor_stack_observed": True,
        "java_object_identity_verified": False,
        "cronet_entry_runtime_observed": False,
        "complete_standalone_signer_verified": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    root = Path(__file__).resolve().parents[1]
    parser.add_argument("--evidence", type=Path,
                        default=root / "evidence" / f"{NAME}.json")
    parser.add_argument("--capture", type=Path, default=CAPTURE)
    args = parser.parse_args()
    print(json.dumps(verify_record(args.evidence, args.capture), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
