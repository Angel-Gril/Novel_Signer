"""Verify the redacted same-input Android-JVM/unidbg frameSign comparison."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


EXPECTED_KEYS = ("frametype", "lid", "signinfo", "signvalue", "signversion")
EXPECTED_INPUT = {
    "length": 49,
    "sha256": "652d1fd0299450b54779193974db5f8dad3eb09c4732ae3d96f0a13c03307b02",
}
HEX_256 = re.compile(r"[0-9a-f]{64}")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def validate_fields(rows: object, label: str) -> dict[str, dict]:
    require(isinstance(rows, list), f"{label}: fields must be a list")
    require(tuple(row.get("key") for row in rows if isinstance(row, dict)) == EXPECTED_KEYS,
            f"{label}: field keys")
    result = {}
    for row in rows:
        require(set(row) == {"key", "length", "sha256"}, f"{label}: raw field or extra data")
        require(isinstance(row["length"], int) and row["length"] > 0,
                f"{label}: field length")
        require(isinstance(row["sha256"], str) and HEX_256.fullmatch(row["sha256"]),
                f"{label}: field digest")
        result[row["key"]] = {"length": row["length"], "sha256": row["sha256"]}
    return result


def verify(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    require(data.get("schema") == "vm9-framesign-same-input-comparison-20261103-v1", "schema")
    require(data.get("frame_type") == 0, "frame type")
    require(tuple(data.get("result_keys", ())) == EXPECTED_KEYS, "declared keys")
    require(data.get("input") == {"profile": "homepage", **EXPECTED_INPUT}, "input digest")

    android = data["android_jvm"]
    require(android.get("actual_jni_provider_verified") is True, "Android provider")
    require(android.get("manager_class") == "com.bytedance.mobsec.metasec.ml.MSManager",
            "Android manager")
    require(android.get("result_cardinality") == 5, "Android result cardinality")
    require(android.get("metasec_maps_count", 0) > 0, "mapped native provider")
    require(android.get("raw_capture_retained") is False, "raw Android capture retained")
    android_fields = validate_fields(android.get("fields"), "Android")

    unidbg = data["unidbg"]
    require(unidbg.get("native_library_sha256") ==
            "712384bd0e310fded0ae9b6441c2a264dd356dfaf1ef42d2ebc3c790fdd9269c",
            "pinned native library")
    require(unidbg.get("frame_sign_handle") == "0x128a3000", "handle2 address")
    require(unidbg.get("handle_source_tag") == "0x4000002", "handle2 source tag")
    require(unidbg.get("frame_sign_tag") == "0x200000a", "frameSign tag")
    require(unidbg.get("synthetic_jni_provider_used") is True, "synthetic provider flag")
    require(unidbg.get("raw_capture_retained") is False, "raw unidbg capture retained")
    require("X-Neptune" in unidbg.get("preceding_sign_round_headers", []),
            "preceding setup round context")
    trials = unidbg.get("repeat_trials")
    require(isinstance(trials, list) and len(trials) == 2, "repeat trial count")
    unidbg_fields = []
    for index, trial in enumerate(trials):
        require(trial.get("result_length") == 10, f"unidbg trial {index}: result length")
        require(trial.get("handle_source") == "handle2", f"unidbg trial {index}: handle source")
        unidbg_fields.append(validate_fields(trial.get("fields"), f"unidbg trial {index}"))

    same_lengths = all(android_fields[key]["length"] == unidbg_fields[0][key]["length"]
                       for key in EXPECTED_KEYS)
    equal_hashes = {key: android_fields[key]["sha256"] == unidbg_fields[0][key]["sha256"]
                    for key in EXPECTED_KEYS}
    repeatable = unidbg_fields[0] == unidbg_fields[1]
    require(data["comparison"].get("same_input_digest") is True, "same input assertion")
    require(data["comparison"].get("same_frame_type") is True, "same frame type assertion")
    require(data["comparison"].get("field_keys_match") is True, "same field keys assertion")
    require(data["comparison"].get("field_lengths_match") is same_lengths and same_lengths,
            "same field lengths")
    require(data["comparison"].get("equal_field_hashes") == equal_hashes,
            "field hash comparison")
    require(data["comparison"].get("unidbg_repeatable_across_two_fresh_runs") is repeatable
            and repeatable, "unidbg repeatability")
    for key in ("clock_alignment_verified", "random_source_alignment_verified",
                "provider_state_alignment_verified", "fresh_standalone_signer_verified",
                "whole_request_native_python_differential_verified",
                "online_header_acceptance_verified"):
        require(data["comparison"].get(key) is False, f"overclaimed status: {key}")

    return {
        "same_input_verified": True,
        "field_keys_and_lengths_match": True,
        "frametype_lid_signversion_hashes_match": all(equal_hashes[key]
                                                      for key in ("frametype", "lid", "signversion")),
        "signinfo_signvalue_hashes_match": all(equal_hashes[key]
                                               for key in ("signinfo", "signvalue")),
        "unidbg_repeatable": repeatable,
        "standalone_signer_verified": False,
    }


def main() -> int:
    default = Path(__file__).resolve().parents[1] / "evidence" / \
        "vm9_framesign_same_input_comparison_20261103.json"
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, default=default)
    args = parser.parse_args()
    print(json.dumps(verify(args.evidence), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
