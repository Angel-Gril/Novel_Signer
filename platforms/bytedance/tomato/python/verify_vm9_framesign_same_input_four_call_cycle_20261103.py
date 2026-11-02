"""Verify redacted same-input Android and unidbg FrameSign cycle evidence."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


EXPECTED_KEYS = ("frametype", "lid", "signinfo", "signvalue", "signversion")
EXPECTED_LENGTHS = {"frametype": 1, "lid": 10, "signinfo": 192,
                    "signvalue": 64, "signversion": 3}
EXPECTED_INPUT = {
    "profile": "homepage",
    "frame_type": 0,
    "length": 49,
    "sha256": "652d1fd0299450b54779193974db5f8dad3eb09c4732ae3d96f0a13c03307b02",
}
HEX_256 = re.compile(r"[0-9a-f]{64}")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def trials(rows: object, label: str) -> dict[int, dict[str, dict]]:
    require(isinstance(rows, list) and len(rows) == 4, f"{label}: repeat count")
    require(all(isinstance(row, dict) and set(row) == {"ordinal", "fields"} for row in rows),
            f"{label}: unexpected trial field")
    require([row.get("ordinal") for row in rows] == [1, 2, 3, 4], f"{label}: call ordinals")
    calls = {}
    for item in rows:
        fields = item.get("fields")
        require(isinstance(fields, list), f"{label} {item['ordinal']}: fields must be a list")
        require(tuple(field.get("key") for field in fields if isinstance(field, dict)) == EXPECTED_KEYS,
                f"{label} {item['ordinal']}: field keys")
        parsed = {}
        for field in fields:
            require(set(field) == {"key", "length", "sha256"},
                    f"{label} {item['ordinal']}: raw field or extra data")
            require(isinstance(field["length"], int) and field["length"] > 0,
                    f"{label} {item['ordinal']}: field length")
            require(isinstance(field["sha256"], str) and HEX_256.fullmatch(field["sha256"]),
                    f"{label} {item['ordinal']}: field digest")
            parsed[field["key"]] = {
                "length": field["length"],
                "sha256": field["sha256"],
            }
        require({key: value["length"] for key, value in parsed.items()} == EXPECTED_LENGTHS,
                f"{label} {item['ordinal']}: field lengths")
        calls[item["ordinal"]] = parsed
    return calls


def has_abab(calls: dict[int, dict[str, dict]], key: str) -> bool:
    return (
        calls[1][key]["sha256"] == calls[3][key]["sha256"] and
        calls[2][key]["sha256"] == calls[4][key]["sha256"] and
        calls[1][key]["sha256"] != calls[2][key]["sha256"]
    )


def verify(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(data, dict), "evidence must be an object")
    require(set(data) == {
        "schema", "evidence_date", "package", "app_version", "input", "android",
        "unidbg", "source_sha256", "raw_capture_retained", "comparison", "interpretation",
    }, "unexpected top-level field")
    require(data.get("schema") == "vm9-framesign-same-input-four-call-cycle-20261103-v1", "schema")
    require(data.get("package") == "com.dragon.read", "package")
    require(data.get("app_version") == "7.2.5.32/72532", "app version")
    require(data.get("input") == EXPECTED_INPUT, "input digest")
    require(data.get("raw_capture_retained") is False, "raw capture retained")

    android = data.get("android")
    require(isinstance(android, dict), "Android run must be an object")
    require(set(android) == {
        "evidence_file", "device_serial", "process_id", "apk_sha256", "method",
        "same_manager_instance_reused", "actual_jni_provider_verified", "metasec_maps_count",
        "repeat_trials",
    }, "unexpected Android run field")
    require(android.get("evidence_file") ==
            "evidence/vm9_framesign_android_four_call_cycle_20261103.json", "Android evidence link")
    require(android.get("device_serial") == "emulator-5554", "device serial")
    require(isinstance(android.get("process_id"), int) and android["process_id"] > 0,
            "Android process id")
    require(android.get("apk_sha256") ==
            "95889d1a1ad0b11ed2451eedf0389516e1382640182026e82eb515e04fbc04fd",
            "installed APK")
    require(android.get("method") == "MSManager.frameSign(String,int)", "Android method")
    require(android.get("same_manager_instance_reused") is True, "Android manager reuse")
    require(android.get("actual_jni_provider_verified") is True, "Android native provider")
    require(android.get("metasec_maps_count") == 3, "Android native mapping")
    android_calls = trials(android.get("repeat_trials"), "Android")

    unidbg = data.get("unidbg")
    require(isinstance(unidbg, dict), "unidbg run must be an object")
    require(set(unidbg) == {
        "version", "backend", "native_library_sha256", "original_harness_source_sha256",
        "redacted_probe_source_sha256", "compiled_entry_sha256", "handle_source_tag",
        "frame_sign_tag", "same_emulator_instance", "same_handle_reused",
        "preceding_business_sign_rounds", "fresh_isolated_rootfs", "synthetic_jni_provider_used",
        "repeat_trials",
    }, "unexpected unidbg field")
    require(unidbg.get("version") == "0.9.9", "unidbg version")
    require(unidbg.get("backend") == "Unicorn2", "unidbg backend")
    require(unidbg.get("native_library_sha256") ==
            "712384bd0e310fded0ae9b6441c2a264dd356dfaf1ef42d2ebc3c790fdd9269c",
            "native library")
    require(unidbg.get("handle_source_tag") == "0x4000002", "handle source")
    require(unidbg.get("frame_sign_tag") == "0x200000a", "FrameSign tag")
    require(unidbg.get("same_emulator_instance") is True, "same unidbg instance")
    require(unidbg.get("same_handle_reused") is True, "same unidbg handle")
    require(unidbg.get("preceding_business_sign_rounds") == 1, "setup round")
    require(unidbg.get("fresh_isolated_rootfs") is True, "isolated rootfs")
    require(unidbg.get("synthetic_jni_provider_used") is True, "synthetic JNI provider")
    unidbg_calls = trials(unidbg.get("repeat_trials"), "unidbg")

    sources = data.get("source_sha256")
    require(isinstance(sources, dict), "source hashes must be an object")
    require(set(sources) == {
        "android_probe", "frida_java_bridge", "unidbg_original_harness",
        "unidbg_redacted_probe", "unidbg_compiled_entry", "native_library",
    }, "source digest keys")
    require(all(isinstance(value, str) and HEX_256.fullmatch(value)
                for value in sources.values()), "source digest format")
    for key, expected in {
        "android_probe": "16df18e61df43f29c8f800b4cc635b8ce7b87a1490a19c1a42448da55712a5e6",
        "frida_java_bridge": "769b77aee5360f4cafb3d541810dda0aa6d97cad1eb3f3fa6285fa50c010b2cf",
        "unidbg_original_harness": "0ec14dfe7d812fd911ca099f27c1bd74580f4cd9ef23beb5c52997658a86f5c0",
        "unidbg_redacted_probe": "0084d79b904103f9cbe5ac72a8135510457552a093a4d5031104b9f027832ab7",
        "unidbg_compiled_entry": "f23b54d4f06b08a5986fd1fb3e48760c28c2e0671f5c69eaf433dcb7fda5d153",
        "native_library": "712384bd0e310fded0ae9b6441c2a264dd356dfaf1ef42d2ebc3c790fdd9269c",
    }.items():
        require(sources[key] == expected, f"source digest mismatch: {key}")

    stable_keys = ("frametype", "lid", "signversion")
    dynamic_keys = ("signinfo", "signvalue")
    stable_android = all(
        len({android_calls[n][key]["sha256"] for n in range(1, 5)}) == 1
        for key in stable_keys
    )
    stable_unidbg = all(
        len({unidbg_calls[n][key]["sha256"] for n in range(1, 5)}) == 1
        for key in stable_keys
    )
    stable_cross_runtime = all(
        android_calls[1][key]["sha256"] == unidbg_calls[1][key]["sha256"]
        for key in stable_keys
    )
    android_abab = all(has_abab(android_calls, key) for key in dynamic_keys)
    unidbg_abab = all(has_abab(unidbg_calls, key) for key in dynamic_keys)
    dynamic_mismatch = all(
        android_calls[n][key]["sha256"] != unidbg_calls[n][key]["sha256"]
        for n in range(1, 5) for key in dynamic_keys
    )
    require(stable_android and stable_unidbg and stable_cross_runtime,
            "stable field hashes do not align")
    require(android_abab and unidbg_abab, "dynamic A-B-A-B pattern")
    require(dynamic_mismatch, "dynamic hashes unexpectedly align")

    comparison = data.get("comparison")
    require(isinstance(comparison, dict), "comparison must be an object")
    require(set(comparison) == {
        "same_input_digest", "field_keys_and_lengths_match",
        "stable_field_hashes_match_across_runtimes", "android_dynamic_fields_follow_abab",
        "unidbg_dynamic_fields_follow_abab", "dynamic_hashes_match_across_runtimes",
        "dynamic_source_identified", "clock_random_provider_state_aligned",
        "fresh_standalone_signer_verified", "whole_request_native_python_differential_verified",
        "online_header_acceptance_verified",
    }, "unexpected comparison field")
    require(comparison.get("same_input_digest") is True, "same input assertion")
    require(comparison.get("field_keys_and_lengths_match") is True, "field shape assertion")
    require(comparison.get("stable_field_hashes_match_across_runtimes") is stable_cross_runtime
            and stable_cross_runtime, "stable digest assertion")
    require(comparison.get("android_dynamic_fields_follow_abab") is android_abab and android_abab,
            "Android cycle assertion")
    require(comparison.get("unidbg_dynamic_fields_follow_abab") is unidbg_abab and unidbg_abab,
            "unidbg cycle assertion")
    require(comparison.get("dynamic_hashes_match_across_runtimes") is False and dynamic_mismatch,
            "dynamic cross-runtime digest assertion")
    for key in ("dynamic_source_identified", "clock_random_provider_state_aligned",
                "fresh_standalone_signer_verified", "whole_request_native_python_differential_verified",
                "online_header_acceptance_verified"):
        require(comparison.get(key) is False, f"overclaimed status: {key}")

    return {
        "same_input_and_shape_verified": True,
        "stable_field_hashes_match": True,
        "both_runtime_cycles_verified": True,
        "dynamic_hashes_match": False,
        "dynamic_source_identified": False,
        "signer_equivalence_verified": False,
    }


def main() -> int:
    default = Path(__file__).resolve().parents[1] / "evidence" / \
        "vm9_framesign_same_input_four_call_cycle_20261103.json"
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, default=default)
    args = parser.parse_args()
    print(json.dumps(verify(args.evidence), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
