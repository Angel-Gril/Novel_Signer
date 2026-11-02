"""Verify redacted same-instance unidbg FrameSign repeat-call dynamics."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


EXPECTED_KEYS = ("frametype", "lid", "signinfo", "signvalue", "signversion")
EXPECTED_INPUT = {
    "profile": "homepage_default",
    "frame_type": 0,
    "length": 60,
    "sha256": "bcfb66faa824a3bc0ed7db2a43f11fb5fcf84a0335f0a955c8836363e71ca0f3",
}
EXPECTED_LENGTHS = {"frametype": 1, "lid": 10, "signinfo": 224, "signvalue": 64, "signversion": 3}
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
        require(set(row) == {"key", "length", "sha256"}, f"{label}: raw value or extra field")
        require(isinstance(row["length"], int) and row["length"] > 0,
                f"{label}: field length")
        require(isinstance(row["sha256"], str) and HEX_256.fullmatch(row["sha256"]),
                f"{label}: field digest")
        result[row["key"]] = {"length": row["length"], "sha256": row["sha256"]}
    return result


def verify(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    require(data.get("schema") == "vm9-framesign-unidbg-repeat-call-dynamics-20261103-v1",
            "schema")
    require(data.get("input") == EXPECTED_INPUT, "input identity")

    unidbg = data.get("unidbg", {})
    require(unidbg.get("version") == "0.9.9", "unidbg version")
    require(unidbg.get("backend") == "Unicorn2", "backend")
    require(unidbg.get("native_library_sha256") ==
            "712384bd0e310fded0ae9b6441c2a264dd356dfaf1ef42d2ebc3c790fdd9269c",
            "pinned native library")
    for key in ("original_harness_source_sha256", "redacted_probe_source_sha256",
                "compiled_entry_sha256"):
        require(isinstance(unidbg.get(key), str) and HEX_256.fullmatch(unidbg[key]),
                f"{key} format")
    require(unidbg.get("handle_source_tag") == "0x4000002", "handle source tag")
    require(unidbg.get("frame_sign_tag") == "0x200000a", "FrameSign tag")
    require(unidbg.get("same_emulator_instance") is True, "same emulator instance")
    require(unidbg.get("same_handle_reused") is True, "same handle")
    require(unidbg.get("preceding_business_sign_rounds") == 1, "setup call count")
    require(unidbg.get("synthetic_jni_provider_used") is True, "JNI provider type")
    require(unidbg.get("raw_capture_retained") is False, "raw capture retained")

    trials = unidbg.get("repeat_trials")
    require(isinstance(trials, list) and len(trials) == 2, "trial count")
    require([trial.get("ordinal") for trial in trials] == [1, 2], "trial order")
    require(all(trial.get("result_length") == 10 for trial in trials), "result cardinality")
    first, second = [validate_fields(trial.get("fields"), f"trial {index}")
                     for index, trial in enumerate(trials, 1)]
    require({key: first[key]["length"] for key in EXPECTED_KEYS} == EXPECTED_LENGTHS,
            "field lengths")
    require(all(first[key]["length"] == second[key]["length"] for key in EXPECTED_KEYS),
            "repeat field lengths")

    stable = ("frametype", "lid", "signversion")
    dynamic = ("signinfo", "signvalue")
    require(all(first[key]["sha256"] == second[key]["sha256"] for key in stable),
            "stable field digests")
    require(all(first[key]["sha256"] != second[key]["sha256"] for key in dynamic),
            "dynamic field digests")

    differences = unidbg.get("field_differences", {})
    expected_diffs = {
        "frametype": {"same_length": True, "changed_chars": 0, "first": -1, "last": -1,
                      "spans": 0, "common_prefix": 1, "common_suffix": 0},
        "lid": {"same_length": True, "changed_chars": 0, "first": -1, "last": -1,
                "spans": 0, "common_prefix": 10, "common_suffix": 0},
        "signinfo": {"same_length": True, "changed_chars": 210, "first": 0, "last": 223,
                     "spans": 15, "common_prefix": 0, "common_suffix": 0},
        "signvalue": {"same_length": True, "changed_chars": 62, "first": 0, "last": 63,
                       "spans": 3, "common_prefix": 0, "common_suffix": 0},
        "signversion": {"same_length": True, "changed_chars": 0, "first": -1, "last": -1,
                        "spans": 0, "common_prefix": 3, "common_suffix": 0},
    }
    require(differences == expected_diffs, "character difference summary")

    comparison = data.get("comparison", {})
    require(comparison.get("same_input_for_both_calls") is True, "same input assertion")
    require(comparison.get("same_vm_and_handle") is True, "same instance assertion")
    require(comparison.get("field_keys_and_lengths_stable") is True, "shape assertion")
    require(comparison.get("frametype_lid_signversion_hashes_stable") is True,
            "stable fields assertion")
    require(comparison.get("signinfo_hash_changes_between_calls") is True,
            "signinfo dynamic assertion")
    require(comparison.get("signvalue_hash_changes_between_calls") is True,
            "signvalue dynamic assertion")
    require(comparison.get("same_as_android_49_character_input") is False,
            "input cross-comparison assertion")
    for key in ("dynamic_source_identified", "fresh_standalone_signer_verified",
                "whole_request_native_python_differential_verified",
                "online_header_acceptance_verified"):
        require(comparison.get(key) is False, f"overclaimed status: {key}")

    return {
        "same_instance_repeat_verified": True,
        "stable_fields": list(stable),
        "per_call_dynamic_fields": list(dynamic),
        "signinfo_changed_chars": differences["signinfo"]["changed_chars"],
        "signvalue_changed_chars": differences["signvalue"]["changed_chars"],
        "dynamic_source_identified": False,
        "standalone_signer_verified": False,
    }


def main() -> int:
    default = Path(__file__).resolve().parents[1] / "evidence" / \
        "vm9_framesign_unidbg_repeat_call_dynamics_20261103.json"
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, default=default)
    args = parser.parse_args()
    print(json.dumps(verify(args.evidence), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
