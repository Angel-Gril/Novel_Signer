"""Validate the bounded decompiled-source Cronet callback injection scan."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


NAME = "vm9_cronet_callback_injection_scan_20261105"
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
    require(report.get("schema") == "vm9-cronet-callback-injection-scan-20261105-v1", "schema")
    require(report.get("evidence_date") == "2026-11-05", "date")
    scope = report["source_scope"]
    require(scope["package_name"] == "com.dragon.read" and
            scope["version_name"] == "7.2.5.32" and
            scope["raw_method_bodies_retained"] is False, "scope")
    artifacts = report["source_artifacts"]
    for relative, expected in artifacts.items():
        check_hash(expected, relative)
        path = source_root / relative
        require(path.is_file(), f"missing source: {relative}")
        require(digest(path) == expected, f"source hash: {relative}")
    scan = report["source_scan"]
    require(scan == {
        "public_builder_callback_method": "com.ttnet.org.chromium.net.c.a.f0(com.ttnet.org.chromium.net.w)",
        "builder_storage_method": "CronetEngineBuilderImpl.t(com.ttnet.org.chromium.net.w)",
        "context_field_assignment": "CronetUrlRequestContext.E = cronetEngineBuilderImpl.t",
        "callback_dispatch_method": "CronetUrlRequestContext.o0 -> w.a(String,Map)",
        "public_builder_callback_definition_count": 1,
        "builder_storage_definition_count": 1,
        "context_callback_field_count": 1,
        "concrete_w_subclass_text_matches": 0,
        "application_side_f0_callsite_matches": 0,
        "application_side_builder_callback_callsite_matches": 0,
        "scan_excludes_api_definitions": True,
    }, "scan ledger")
    claims = report["claims"]
    require(claims["public_cronet_callback_injection_api_verified"] is True and
            claims["decompiled_source_has_no_application_callback_callsite"] is True and
            claims["concrete_w_implementation_resolved"] is False and
            claims["runtime_adapter_identity_resolved"] is False and
            claims["cronet_entry_runtime_observed"] is False and
            claims["r4_callback_cronet_identity_joined"] is False,
            "adapter boundary")
    for key in (
        "ordinary_cronet_six_head_chain_verified",
        "callback_url_or_map_object_identity_joined",
        "provider_method_or_field_identity_joined",
        "android_captured_jni_buffer_consumption_byte_joined",
        "complete_standalone_signer_verified",
        "whole_request_native_python_differential_verified",
        "online_header_acceptance_verified",
    ):
        require(claims[key] is False, f"{key} overclaim")
    return {
        "schema": report["schema"],
        "public_cronet_callback_injection_api_verified": claims["public_cronet_callback_injection_api_verified"],
        "concrete_w_implementation_resolved": claims["concrete_w_implementation_resolved"],
        "runtime_adapter_identity_resolved": claims["runtime_adapter_identity_resolved"],
        "cronet_entry_runtime_observed": claims["cronet_entry_runtime_observed"],
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
