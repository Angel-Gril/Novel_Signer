"""Validate the bounded direct Cronet entry hook window."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


NAME = "vm9_android_cronet_entry_window_20261105"
CAPTURE_DIR = Path(r"C:\AI\6\_probe_framesign_repeat_unidbg_20261103\android_jni_utf_provider_probe_20261104")
PROBE = Path(r"C:\AI\6\_probe_vm9_cronet_entries_20261105.py")
BRIDGE = Path(r"C:\AI\6\frida-java-bridge_plain.js")
HEX_256 = re.compile(r"^[0-9a-f]{64}$")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_hash(value: Any, label: str) -> None:
    require(isinstance(value, str) and HEX_256.fullmatch(value) is not None,
            f"{label} sha256")


def verify_capture(path: Path, expected_hash: str) -> None:
    require(path.is_file(), "capture file missing")
    require(digest(path) == expected_hash, "capture sha256")
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    require(len(rows) == 2, "capture row count")
    require(rows[0] == {
        "event": "hook_ready",
        "context_o0": True,
        "context_add": True,
        "request_add": True,
    }, "hook readiness")
    require(rows[1] == {"event": "ready", "pid": 21961}, "process readiness")


def verify_record(evidence: Path, capture_root: Path, probe: Path, bridge: Path) -> dict[str, Any]:
    report = json.loads(evidence.read_text(encoding="utf-8"))
    require(report.get("schema") == "vm9-android-cronet-entry-window-20261105-v1", "schema")
    require(report.get("evidence_date") == "2026-11-05", "date")
    env = report["environment"]
    require(env["package_name"] == "com.dragon.read" and env["version_name"] == "7.2.5.32",
            "package")
    require(env["device_serial"] == "emulator-5554" and env["process_id"] == 21961,
            "process")
    artifacts = report["artifacts"]
    for key in ("probe_sha256", "frida_java_bridge_sha256", "capture_sha256"):
        check_hash(artifacts[key], key)
    require(artifacts["capture_file"] == "cronet_entries2_20261105.jsonl" and
            artifacts["capture_row_count"] == 2 and artifacts["bounded_seconds"] == 45,
            "capture metadata")
    require(artifacts["raw_url_values_map_values_header_values_and_runtime_addresses_retained"] is False,
            "redaction")
    require(probe.is_file() and digest(probe) == artifacts["probe_sha256"], "probe hash")
    require(bridge.is_file() and digest(bridge) == artifacts["frida_java_bridge_sha256"], "bridge hash")
    verify_capture(capture_root / artifacts["capture_file"], artifacts["capture_sha256"])
    hooks = report["hooks"]
    require(hooks == {
        "cronet_context_o0": True,
        "cronet_context_add_security_factor": True,
        "cronet_request_add_security_factor": True,
    }, "hooks")
    observation = report["observation"]
    require(observation == {
        "cronet_context_o0_calls": 0,
        "cronet_context_add_security_factor_calls": 0,
        "cronet_request_add_security_factor_calls": 0,
        "r4_callback_calls_in_this_capture": 0,
        "url_values_captured": False,
        "map_values_captured": False,
    }, "observation")
    claims = report["claims"]
    require(claims["cronet_entry_hooks_installed"] is True and
            claims["cronet_entry_runtime_observed"] is False and
            claims["r4_callback_observed_in_same_capture"] is False,
            "entry boundary")
    for key in (
        "ordinary_cronet_six_head_chain_verified",
        "callback_url_or_map_object_identity_joined",
        "android_captured_jni_buffer_consumption_byte_joined",
        "provider_method_or_field_identity_joined",
        "complete_standalone_signer_verified",
        "whole_request_native_python_differential_verified",
        "online_header_acceptance_verified",
    ):
        require(claims[key] is False, f"{key} overclaim")
    return {
        "schema": report["schema"],
        "cronet_entry_hooks_installed": claims["cronet_entry_hooks_installed"],
        "cronet_entry_runtime_observed": claims["cronet_entry_runtime_observed"],
        "ordinary_cronet_six_head_chain_verified": claims["ordinary_cronet_six_head_chain_verified"],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    root = Path(__file__).resolve().parents[1]
    parser.add_argument("--evidence", type=Path,
                        default=root / "evidence" / f"{NAME}.json")
    parser.add_argument("--capture-root", type=Path, default=CAPTURE_DIR)
    parser.add_argument("--probe", type=Path, default=PROBE)
    parser.add_argument("--bridge", type=Path, default=BRIDGE)
    args = parser.parse_args()
    print(json.dumps(verify_record(args.evidence, args.capture_root, args.probe, args.bridge),
                     sort_keys=True))


if __name__ == "__main__":
    main()
