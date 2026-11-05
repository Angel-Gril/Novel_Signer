"""Validate the official runtime HTTP client selector state."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


NAME = "vm9_cronet_runtime_selector_state_20261105"
APK = Path(r"C:\AI\6\fq_7xz.apk")
BRIDGE = Path(r"C:\AI\6\frida-java-bridge_plain.js")
PROBE = Path(r"C:\AI\6\probe_vm9_http_client_state_20261105.py")
HEX256 = re.compile(r"^[0-9a-f]{64}$")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_record(path: Path) -> dict[str, Any]:
    record = json.loads(path.read_text(encoding="utf-8"))
    require(record.get("schema") == "vm9-cronet-runtime-selector-state-20261105-v1", "schema")
    require(record.get("evidence_date") == "2026-11-05", "date")
    require(record["source_scope"] == {
        "artifact": "official fq_7xz.apk runtime HTTP client selector state",
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
    require(APK.is_file() and BRIDGE.is_file() and PROBE.is_file(), "artifacts")
    require(sha256(APK) == artifacts["apk_sha256"] == "95889d1a1ad0b11ed2451eedf0389516e1382640182026e82eb515e04fbc04fd", "APK hash")
    require(sha256(BRIDGE) == artifacts["bridge_sha256"] == "769b77aee5360f4cafb3d541810dda0aa6d97cad1eb3f3fa6285fa50c010b2cf", "bridge hash")
    require(sha256(PROBE) == artifacts["probe_script_sha256"] == "ce94fa16dc9cf7e0adc364701ddd847465f212339570c0e1e0232c01ca5a1b61", "probe hash")
    for key in ("apk_sha256", "bridge_sha256", "probe_script_sha256"):
        require(HEX256.fullmatch(artifacts[key]) is not None, f"{key} format")
    require(record["observed_state"] == {
        "http_client_cronet_enable": False,
        "http_client_cronet_boot_succeed": True,
        "http_client_cronet_exception": False,
        "http_client_exception_message_present": False,
        "http_client_config_present": True,
        "okhttp_fallback_reason": 2,
        "ss_cronet_client_present": True,
        "cronet_engine_present": True,
    }, "observed state")
    claims = record["claims"]
    for key in (
        "runtime_selector_disabled_cronet_verified",
        "runtime_cronet_engine_present_verified",
        "runtime_cronet_boot_succeed_verified",
        "runtime_okhttp_fallback_reason_observed",
    ):
        require(claims[key] is True, key)
    for key in (
        "cronet_entry_runtime_observed",
        "r4_callback_cronet_identity_joined",
        "ordinary_cronet_six_head_chain_verified",
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
        "runtime_selector_disabled_cronet_verified": claims["runtime_selector_disabled_cronet_verified"],
        "runtime_cronet_engine_present_verified": claims["runtime_cronet_engine_present_verified"],
        "runtime_cronet_boot_succeed_verified": claims["runtime_cronet_boot_succeed_verified"],
        "runtime_okhttp_fallback_reason_observed": claims["runtime_okhttp_fallback_reason_observed"],
        "cronet_entry_runtime_observed": claims["cronet_entry_runtime_observed"],
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
