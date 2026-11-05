"""Validate the redacted runtime Cronet provider state observation."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


NAME = "vm9_cronet_provider_runtime_state_20261105"
APK = Path(r"C:\AI\6\fq_7xz.apk")
BRIDGE = Path(r"C:\AI\6\frida-java-bridge_plain.js")
PROBE = Path(r"C:\AI\6\probe_vm9_cronet_static_state_v2_20261105.py")
HEX256 = re.compile(r"^[0-9a-f]{64}$")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_record(path: Path) -> dict[str, Any]:
    record = json.loads(path.read_text(encoding="utf-8"))
    require(record.get("schema") == "vm9-cronet-provider-runtime-state-20261105-v1", "schema")
    require(record.get("evidence_date") == "2026-11-05", "date")
    scope = record["source_scope"]
    require(scope == {
        "artifact": "official fq_7xz.apk runtime Cronet provider state probe",
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
    require(APK.is_file() and BRIDGE.is_file() and PROBE.is_file(), "runtime artifacts")
    require(sha256(APK) == artifacts["apk_sha256"] == "95889d1a1ad0b11ed2451eedf0389516e1382640182026e82eb515e04fbc04fd", "APK hash")
    require(sha256(BRIDGE) == artifacts["bridge_sha256"] == "769b77aee5360f4cafb3d541810dda0aa6d97cad1eb3f3fa6285fa50c010b2cf", "bridge hash")
    require(sha256(PROBE) == artifacts["probe_script_sha256"] == "3f7c8365a8a9017c843a76094a232f4f934b859f13e9a60a1e774658de820830", "probe hash")
    for key in ("apk_sha256", "bridge_sha256", "probe_script_sha256"):
        require(HEX256.fullmatch(artifacts[key]) is not None, f"{key} format")

    observed = record["observed_state"]
    expected_provider = {"class_name": "com.dragon.read.base.http.b", "identity_hash": 85092747}
    for key in ("ttnet_provider", "ss_cronet_app_provider", "manager_provider", "manager_adapter"):
        require(observed[key] == expected_provider, key)
    require(observed["ss_cronet_client"] == {"class_name": "org.chromium.CronetClient", "identity_hash": 25262696}, "client")
    require(observed["cronet_engine"] == {"class_name": "com.ttnet.org.chromium.net.impl.CronetUrlRequestContext", "identity_hash": 131673874}, "engine")
    require(observed["networkparams_security_callback"] == {"class_name": "ms.bd.c.r4", "identity_hash": 199032449}, "r4")
    require(observed["provider_identity_hash_equal_across_ttnet_ss_manager"] is True, "provider identity")
    require(observed["boe_mode"] is False, "BOE")

    claims = record["claims"]
    for key in (
        "runtime_provider_storage_identity_resolved",
        "runtime_provider_manager_identity_resolved",
        "runtime_cronet_client_and_context_present",
        "runtime_networkparams_r4_callback_present",
    ):
        require(claims[key] is True, key)
    for key in (
        "runtime_initializer_calls_observed",
        "runtime_adapter_identity_resolved",
        "cronet_entry_runtime_observed",
        "r4_callback_cronet_identity_joined",
        "ordinary_cronet_six_head_chain_verified",
        "callback_url_or_map_object_identity_joined",
        "provider_method_or_field_identity_joined",
        "android_captured_jni_buffer_consumption_byte_joined",
        "complete_standalone_signer_verified",
        "whole_request_native_python_differential_verified",
        "online_header_acceptance_verified",
    ):
        require(claims[key] is False, f"{key} overclaim")
    serialized = json.dumps(record, ensure_ascii=False).lower()
    for forbidden in ("http://", "https://", "bearer ", "ibssh_", "frp-hat"):
        require(forbidden not in serialized, "forbidden raw value")
    return {
        "schema": record["schema"],
        "runtime_provider_storage_identity_resolved": claims["runtime_provider_storage_identity_resolved"],
        "runtime_provider_manager_identity_resolved": claims["runtime_provider_manager_identity_resolved"],
        "runtime_cronet_client_and_context_present": claims["runtime_cronet_client_and_context_present"],
        "runtime_networkparams_r4_callback_present": claims["runtime_networkparams_r4_callback_present"],
        "r4_callback_cronet_identity_joined": claims["r4_callback_cronet_identity_joined"],
        "ordinary_cronet_six_head_chain_verified": claims["ordinary_cronet_six_head_chain_verified"],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    root = Path(__file__).resolve().parents[1]
    parser.add_argument("--evidence", type=Path, default=root / "evidence" / f"{NAME}.json")
    args = parser.parse_args()
    print(json.dumps(verify_record(args.evidence), sort_keys=True))


if __name__ == "__main__":
    main()
