"""Validate the synthetic manager-to-r4 dispatch control."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


NAME = "vm9_cronet_synthetic_manager_r4_dispatch_20261105"
APK = Path(r"C:\AI\6\fq_7xz.apk")
BRIDGE = Path(r"C:\AI\6\frida-java-bridge_plain.js")
PROBE = Path(r"C:\AI\6\probe_vm9_cronet_synthetic_manager_r4_20261105.py")
HEX256 = re.compile(r"^[0-9a-f]{64}$")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_record(path: Path) -> dict[str, Any]:
    record = json.loads(path.read_text(encoding="utf-8"))
    require(record.get("schema") == "vm9-cronet-synthetic-manager-r4-dispatch-20261105-v1", "schema")
    require(record.get("evidence_date") == "2026-11-05", "date")
    require(record["source_scope"] == {
        "artifact": "official fq_7xz.apk synthetic manager-to-r4 dispatch control",
        "package_name": "com.dragon.read",
        "version_name": "7.2.5.32",
        "version_code": 72532,
        "device_serial": "emulator-5554",
        "process_id": 1163,
        "frida_version": "17.24.3",
        "frida_server_privilege": "root",
        "raw_business_values_retained": False,
        "synthetic_control": True,
    }, "scope")
    artifacts = record["source_artifacts"]
    require(APK.is_file() and BRIDGE.is_file() and PROBE.is_file(), "runtime artifacts")
    require(sha256(APK) == artifacts["apk_sha256"] == "95889d1a1ad0b11ed2451eedf0389516e1382640182026e82eb515e04fbc04fd", "APK hash")
    require(sha256(BRIDGE) == artifacts["bridge_sha256"] == "769b77aee5360f4cafb3d541810dda0aa6d97cad1eb3f3fa6285fa50c010b2cf", "bridge hash")
    require(sha256(PROBE) == artifacts["probe_script_sha256"] == "7a9f7d315db1066cadf3824684bed155a607ebce84a12c8ba9edc452c2dc3115", "probe hash")
    for key in ("apk_sha256", "bridge_sha256", "probe_script_sha256"):
        require(HEX256.fullmatch(artifacts[key]) is not None, f"{key} format")
    events = record["observed_events"]
    require(events["manager_before"] == {
        "provider_class": "com.dragon.read.base.http.b",
        "adapter_class": "com.dragon.read.base.http.b",
    }, "manager provider")
    require(events["synthetic_manager_call"] == {"url_length": 24, "input_key_count": 0}, "synthetic input")
    require(events["r4_enter"] == {"url_length": 24, "input_key_count": 0}, "r4 enter")
    require(events["r4_leave"] == {"ok": True, "result_key_count": 0}, "r4 leave")
    require(events["manager_after"] == {"ok": True, "result_key_count": 0}, "manager return")
    claims = record["claims"]
    require(claims["synthetic_manager_to_r4_dispatch_observed"] is True, "synthetic dispatch")
    require(claims["runtime_provider_manager_identity_resolved"] is True, "provider identity")
    for key in (
        "real_cronet_entry_observed",
        "real_request_r4_callback_joined",
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
        "synthetic_manager_to_r4_dispatch_observed": claims["synthetic_manager_to_r4_dispatch_observed"],
        "real_cronet_entry_observed": claims["real_cronet_entry_observed"],
        "real_request_r4_callback_joined": claims["real_request_r4_callback_joined"],
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
