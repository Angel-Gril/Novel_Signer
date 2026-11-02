"""Verify redacted four-call Android FrameSign cycle evidence."""
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


def parse_fields(rows: object, label: str) -> dict[str, dict]:
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
    require({key: row["length"] for key, row in result.items()} == EXPECTED_LENGTHS,
            f"{label}: field lengths")
    return result


def verify(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(data, dict), "evidence must be an object")
    require(set(data) == {
        "schema", "evidence_date", "package", "app_version", "apk_sha256",
        "device_serial", "android", "abi", "frida_host_version", "process_id",
        "provider", "input", "result_keys", "call_order", "repeat_trials",
        "source_sha256", "raw_capture_retained", "comparison", "interpretation",
    }, "unexpected top-level field")
    require(data.get("schema") == "vm9-framesign-android-four-call-cycle-20261103-v1", "schema")
    require(data.get("package") == "com.dragon.read", "package")
    require(data.get("app_version") == "7.2.5.32/72532", "app version")
    require(data.get("apk_sha256") ==
            "95889d1a1ad0b11ed2451eedf0389516e1382640182026e82eb515e04fbc04fd",
            "installed APK")
    require(data.get("device_serial") == "emulator-5554", "device serial")
    require(data.get("android") == "9 / sdk 28", "Android version")
    require(data.get("abi") == "x86_64 with arm64 native translation", "device ABI")
    require(data.get("frida_host_version") == "17.24.3", "Frida host version")
    require(isinstance(data.get("process_id"), int) and data["process_id"] > 0, "process id")
    require(isinstance(data.get("input"), dict), "input must be an object")
    require(set(data["input"]) == set(EXPECTED_INPUT), "unexpected input field")
    require(data.get("input") == EXPECTED_INPUT, "input digest")
    require(data.get("result_keys") == list(EXPECTED_KEYS), "declared result keys")
    require(data.get("call_order") ==
            "Four consecutive reflection calls in one Java.perform callback using the same manager and input string.",
            "call order")
    require(data.get("raw_capture_retained") is False, "raw capture retained")

    provider = data.get("provider", {})
    require(isinstance(provider, dict), "provider must be an object")
    require(set(provider) == {
        "manager_class", "method", "overload_selection", "init_trigger",
        "same_manager_instance_reused", "actual_jni_provider_verified", "metasec_maps_count",
    }, "unexpected provider field")
    require(provider.get("manager_class") == "com.bytedance.mobsec.metasec.ml.MSManager",
            "manager class")
    require(provider.get("method") == "MSManager.frameSign(String,int)", "method")
    require(provider.get("overload_selection") ==
            "Reflection matched java.lang.String,int parameter types", "overload selection")
    require(provider.get("init_trigger") == "x1.m().k(Application)", "provider initialization")
    require(provider.get("same_manager_instance_reused") is True, "manager instance")
    require(provider.get("actual_jni_provider_verified") is True, "actual JNI provider")
    require(provider.get("metasec_maps_count") == 3, "native provider mapping")

    sources = data.get("source_sha256", {})
    require(isinstance(sources, dict), "source hashes must be an object")
    require(set(sources) == {"probe", "frida_java_bridge"}, "source digest keys")
    require(all(isinstance(value, str) and HEX_256.fullmatch(value)
                for value in sources.values()), "source digest format")

    trials = data.get("repeat_trials")
    require(isinstance(trials, list) and len(trials) == 4, "repeat count")
    require(all(isinstance(trial, dict) and set(trial) == {"ordinal", "fields"}
                for trial in trials), "unexpected trial field")
    require([trial.get("ordinal") for trial in trials] == [1, 2, 3, 4], "call ordinals")
    calls = {
        trial["ordinal"]: parse_fields(trial.get("fields"), f"trial {trial['ordinal']}")
        for trial in trials
    }
    stable_keys = ("frametype", "lid", "signversion")
    dynamic_keys = ("signinfo", "signvalue")
    stable = all(len({calls[n][key]["sha256"] for n in range(1, 5)}) == 1
                 for key in stable_keys)
    abab = all(
        calls[1][key]["sha256"] == calls[3][key]["sha256"] and
        calls[2][key]["sha256"] == calls[4][key]["sha256"] and
        calls[1][key]["sha256"] != calls[2][key]["sha256"]
        for key in dynamic_keys
    )
    comparison = data.get("comparison", {})
    require(isinstance(comparison, dict), "comparison must be an object")
    require(set(comparison) == {
        "same_input_for_all_calls", "same_manager_instance", "field_keys_and_lengths_match",
        "frametype_lid_signversion_hashes_stable", "signinfo_hash_follows_abab",
        "signvalue_hash_follows_abab", "dynamic_cause_identified",
        "clock_random_provider_state_cause_identified", "fresh_standalone_signer_verified",
        "whole_request_native_python_differential_verified", "online_header_acceptance_verified",
    }, "unexpected comparison field")
    require(comparison.get("same_input_for_all_calls") is True, "same input assertion")
    require(comparison.get("same_manager_instance") is True, "same manager assertion")
    require(comparison.get("field_keys_and_lengths_match") is True, "shape assertion")
    require(comparison.get("frametype_lid_signversion_hashes_stable") is stable and stable,
            "stable fields assertion")
    for key in dynamic_keys:
        require(comparison.get(f"{key}_hash_follows_abab") is True and abab,
                f"{key} ABAB assertion")
    for key in ("dynamic_cause_identified", "clock_random_provider_state_cause_identified",
                "fresh_standalone_signer_verified", "whole_request_native_python_differential_verified",
                "online_header_acceptance_verified"):
        require(comparison.get(key) is False, f"overclaimed status: {key}")

    return {
        "same_live_provider_and_input_verified": True,
        "four_calls_verified": True,
        "stable_fields": list(stable_keys),
        "dynamic_fields_follow_abab": list(dynamic_keys),
        "dynamic_cause_identified": False,
        "cross_runtime_equivalence_verified": False,
    }


def main() -> int:
    default = Path(__file__).resolve().parents[1] / "evidence" / \
        "vm9_framesign_android_four_call_cycle_20261103.json"
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, default=default)
    args = parser.parse_args()
    print(json.dumps(verify(args.evidence), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
