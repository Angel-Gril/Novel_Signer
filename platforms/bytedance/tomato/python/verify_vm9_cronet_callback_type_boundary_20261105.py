"""Validate the static Cronet/r4 callback type boundary."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


NAME = "vm9_cronet_callback_type_boundary_20261105"
SOURCE_ROOT = Path(r"C:\AI\6\jadx_out16\sources")
HEX_256 = re.compile(r"^[0-9a-f]{64}$")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_hash(value: Any, label: str) -> None:
    require(isinstance(value, str) and HEX_256.fullmatch(value) is not None,
            f"{label} sha256")


def verify_record(evidence: Path, source_root: Path) -> dict[str, Any]:
    report = json.loads(evidence.read_text(encoding="utf-8"))
    require(report.get("schema") == "vm9-cronet-callback-type-boundary-20261105-v1", "schema")
    require(report.get("evidence_date") == "2026-11-05", "date")
    scope = report["source_scope"]
    require(scope["package_name"] == "com.dragon.read" and
            scope["version_name"] == "7.2.5.32" and
            scope["raw_method_bodies_retained"] is False, "source scope")
    for relative, expected in report["source_artifacts"].items():
        check_hash(expected, relative)
        path = source_root / relative
        require(path.is_file(), f"missing source: {relative}")
        require(digest(path) == expected, f"source hash: {relative}")
    static = report["static_observation"]
    require(static == {
        "cronet_request_add_security_factor_input": "String,String[]",
        "cronet_context_add_security_factor_input": "String,String[]",
        "cronet_context_o0_signature": "(String,Map<String,String>)Map<String,String>",
        "cronet_context_callback_field_type": "com.ttnet.org.chromium.net.w",
        "cronet_o0_delegates_to_callback_a": True,
        "cronet_input_map_value_type": "java.lang.String",
        "cronet_result_flattens_map_to_string_array": True,
        "r4_interface_type": "com.bytedance.frameworks.baselib.network.http.NetworkParams.b",
        "r4_input_value_read_as_type": "java.util.List",
        "r4_native_tag": "0x3000001",
        "direct_cronet_r4_java_type_identity_verified": False,
        "runtime_adapter_identity_resolved": False,
    }, "static boundary")
    claims = report["claims"]
    require(claims["cronet_static_owner_chain_verified"] is True and
            claims["r4_callback_observed"] is True and
            claims["cronet_entry_runtime_observed"] is False and
            claims["r4_callback_cronet_identity_joined"] is False,
            "runtime boundary")
    for key in (
        "callback_url_or_map_object_identity_joined",
        "ordinary_cronet_six_head_chain_verified",
        "provider_method_or_field_identity_joined",
        "android_captured_jni_buffer_consumption_byte_joined",
        "complete_standalone_signer_verified",
        "whole_request_native_python_differential_verified",
        "online_header_acceptance_verified",
    ):
        require(claims[key] is False, f"{key} overclaim")
    return {
        "schema": report["schema"],
        "cronet_static_owner_chain_verified": claims["cronet_static_owner_chain_verified"],
        "cronet_entry_runtime_observed": claims["cronet_entry_runtime_observed"],
        "r4_callback_cronet_identity_joined": claims["r4_callback_cronet_identity_joined"],
        "ordinary_cronet_six_head_chain_verified": claims["ordinary_cronet_six_head_chain_verified"],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    root = Path(__file__).resolve().parents[1]
    parser.add_argument("--evidence", type=Path,
                        default=root / "evidence" / f"{NAME}.json")
    parser.add_argument("--source-root", type=Path, default=SOURCE_ROOT)
    args = parser.parse_args()
    print(json.dumps(verify_record(args.evidence, args.source_root), sort_keys=True))


if __name__ == "__main__":
    main()
