"""Validate the bounded Cronet callback/formatter window ledger."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any


NAME = "vm9_android_cronet_formatter_window_20261105"
HEX_256 = re.compile(r"^[0-9a-f]{64}$")
CAPTURE_DIR = Path(r"C:\AI\6\_probe_framesign_repeat_unidbg_20261103\android_jni_utf_provider_probe_20261104")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_hash(value: Any, label: str) -> None:
    require(isinstance(value, str) and HEX_256.fullmatch(value) is not None,
            f"{label} sha256")


def load_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        row = json.loads(line)
        require(isinstance(row, dict), f"{path.name}:{line_no} row shape")
        rows.append(row)
    return rows


def verify_capture(path: Path, expected_hash: str, expected_rows: int,
                   expected_callbacks: int, expected_lengths: list[int],
                   expected_vs: int) -> dict[str, int]:
    require(path.is_file(), f"missing capture: {path}")
    require(digest(path) == expected_hash, f"{path.name} capture sha256")
    rows = load_rows(path)
    require(len(rows) == expected_rows, f"{path.name} row count")
    allowed = {
        "jni_hooks", "libc", "security_hook_ready", "ready", "heartbeat",
        "security_enter", "security_leave", "vs",
    }
    require(set(row.get("event") for row in rows) <= allowed,
            f"{path.name} unexpected event")
    enters = [row for row in rows if row.get("event") == "security_enter"]
    leaves = [row for row in rows if row.get("event") == "security_leave"]
    require(len(enters) == expected_callbacks and len(leaves) == expected_callbacks,
            f"{path.name} callback count")
    require([row.get("url_length") for row in enters] == expected_lengths,
            f"{path.name} URL length ledger")
    for index, row in enumerate(enters):
        require(set(row) == {"event", "callback_seq", "url_length", "key_count", "keys"},
                f"{path.name} enter {index} shape")
        require(isinstance(row["url_length"], int) and row["url_length"] > 0,
                f"{path.name} enter {index} URL length")
        require(row["key_count"] == 0 and row["keys"] == [],
                f"{path.name} enter {index} input map")
    for index, row in enumerate(leaves):
        require(set(row) in ({"event", "callback_seq", "ok", "result_present"},
                              {"event", "callback_seq", "ok", "result_present", "result_keys"}),
                f"{path.name} leave {index} shape")
        require(row["ok"] is True and row["result_present"] is True,
                f"{path.name} leave {index} result object")
        if "result_keys" in row:
            require(row["result_keys"] == [], f"{path.name} leave {index} result map")
    vs_rows = [row for row in rows if row.get("event") == "vs"]
    require(vs_rows and all(row.get("hit_count") == 0 for row in vs_rows),
            f"{path.name} formatter match guard")
    heartbeats = [row for row in rows if row.get("event") == "heartbeat"]
    require(heartbeats, f"{path.name} heartbeat")
    require(max(row.get("vs", -1) for row in heartbeats) == expected_vs,
            f"{path.name} formatter call count")
    ready = [row for row in rows if row.get("event") == "ready"]
    require(len(ready) == 1 and ready[0].get("pid") == 21961,
            f"{path.name} process identity")
    return {"rows": len(rows), "callbacks": len(enters), "formatter_calls": expected_vs}


def verify_record(evidence: Path, capture_root: Path) -> dict[str, Any]:
    report = json.loads(evidence.read_text(encoding="utf-8"))
    require(report.get("schema") == "vm9-android-cronet-formatter-window-20261105-v1",
            "evidence schema")
    require(report.get("evidence_date") == "2026-11-05", "evidence date")
    env = report["environment"]
    require(env["package_name"] == "com.dragon.read" and env["version_name"] == "7.2.5.32",
            "runtime package")
    require(env["device_serial"] == "emulator-5554" and env["process_id"] == 21961,
            "runtime process")
    artifacts = report["artifacts"]
    for key in ("probe_sha256", "frida_java_bridge_sha256"):
        check_hash(artifacts[key], key)
    require(artifacts["raw_url_values_map_values_header_values_and_runtime_addresses_retained"] is False,
            "redaction guard")
    captures = artifacts["captures"]
    require(len(captures) == 2, "capture count")
    expected = [
        ("cronet_native_window_20261105.jsonl", 31, 60, 4, [684, 1154, 109, 1154], 502,
         "d004729a7621be0fa63e0389bc54ff6d46c8f9603aed1695c330f371a6f260bf"),
        ("cronet_native_window2_20261105.jsonl", 18, 25, 1, [1154], 36,
         "5bf4a0c6436dc42dfc01a1025e6da4746e56d194e60d6ca57101505a997fd237"),
    ]
    totals = []
    for item, (name, rows, seconds, callbacks, lengths, vs, sha) in zip(captures, expected):
        require(item["file"] == name and item["row_count"] == rows and
                item["bounded_seconds"] == seconds and item["process_id"] == 21961,
                f"{name} artifact metadata")
        require(item["sha256"] == sha, f"{name} evidence hash")
        totals.append(verify_capture(capture_root / name, sha, rows, callbacks, lengths, vs))
    obs = report["observation"]
    require(obs["hooked_callback"] == "ms.bd.c.r4.onCallToAddSecurityFactor(String,Map)" and
            obs["cronet_entry_hooks_installed"] is False and
            obs["cronet_entry_calls_observed"] is False,
            "callback identity")
    require(obs["formatter_hook"] == "libc.so!vsnprintf" and obs["capture_count"] == 2,
            "formatter identity")
    require(obs["callback_count"] == 5 and obs["callback_url_lengths"] == [684, 1154, 109, 1154, 1154],
            "callback ledger")
    require(obs["callback_input_map_key_counts"] == [0, 0, 0, 0, 0] and
            obs["callback_result_present_count"] == 5 and
            obs["callback_result_map_key_counts"] == [None, None, None, None, 0],
            "map ledger")
    require(obs["formatter_calls_by_capture"] == [502, 36] and
            obs["formatter_match_events"] == 0 and
            obs["jni_getter_pointer_or_fingerprint_matches"] == 0 and
            obs["callback_formatter_same_event_join_count"] == 0,
            "formatter ledger")
    claims = report["claims"]
    require(claims["r4_security_factor_callback_observed"] is True and
            claims["cronet_entry_runtime_observed"] is False and
            claims["callback_return_object_observed"] is True and
            claims["callback_result_map_keys_fully_enumerated"] is False,
            "positive callback claims")
    for key in (
        "six_header_result_observed_in_this_cronet_capture",
        "callback_url_or_map_object_identity_joined",
        "callback_to_formatter_dataflow_verified",
        "android_captured_jni_buffer_consumption_byte_joined",
        "provider_method_or_field_identity_joined",
        "ordinary_cronet_six_head_chain_verified",
        "complete_standalone_signer_verified",
        "whole_request_native_python_differential_verified",
        "online_header_acceptance_verified",
    ):
        require(claims[key] is False, f"{key} overclaim")
    return {
        "schema": report["schema"],
        "callback_count": obs["callback_count"],
        "formatter_calls": sum(obs["formatter_calls_by_capture"]),
        "formatter_match_events": obs["formatter_match_events"],
        "six_header_result_observed_in_this_cronet_capture": claims["six_header_result_observed_in_this_cronet_capture"],
        "ordinary_cronet_six_head_chain_verified": claims["ordinary_cronet_six_head_chain_verified"],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    root = Path(__file__).resolve().parents[1]
    parser.add_argument("--evidence", type=Path,
                        default=root / "evidence" / f"{NAME}.json")
    parser.add_argument("--capture-root", type=Path, default=CAPTURE_DIR)
    args = parser.parse_args()
    print(json.dumps(verify_record(args.evidence, args.capture_root), sort_keys=True))


if __name__ == "__main__":
    main()
