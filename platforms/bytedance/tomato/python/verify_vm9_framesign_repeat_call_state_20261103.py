"""Verify redacted repeat-call behavior from one live Android FrameSign provider."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


EXPECTED_KEYS = ("frametype", "lid", "signinfo", "signvalue", "signversion")
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


def fields(rows: object, label: str) -> dict[str, dict]:
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
    require(data.get("schema") == "vm9-framesign-repeat-call-state-20261103-v1", "schema")
    require(data.get("package") == "com.dragon.read", "package")
    require(data.get("app_version") == "7.2.5.32/72532", "app version")
    require(data.get("apk_sha256") ==
            "95889d1a1ad0b11ed2451eedf0389516e1382640182026e82eb515e04fbc04fd",
            "installed APK")
    require(data.get("device_serial") == "emulator-5554", "device serial")
    require(data.get("frida_host_version") == "17.24.3", "Frida host version")
    require(data.get("input") == EXPECTED_INPUT, "input digest")
    require(data.get("result_keys") == list(EXPECTED_KEYS), "declared result keys")
    require(data.get("raw_capture_retained") is False, "raw capture retained")

    provider = data.get("provider", {})
    require(provider.get("manager_class") == "com.bytedance.mobsec.metasec.ml.MSManager",
            "manager class")
    require(provider.get("method") == "MSManager.frameSign(String,int)", "method")
    require(provider.get("same_manager_instance_reused") is True, "manager instance")
    require(provider.get("actual_jni_provider_verified") is True, "actual JNI provider")
    require(provider.get("metasec_maps_count") == 3, "native provider mapping")
    require(isinstance(data.get("process_id"), int) and data["process_id"] > 0,
            "process id")
    sources = data.get("source_sha256", {})
    require(set(sources) == {"probe", "frida_java_bridge"}, "source digest keys")
    require(all(isinstance(value, str) and HEX_256.fullmatch(value)
                for value in sources.values()), "source digest format")

    trials = data.get("repeat_trials")
    require(isinstance(trials, list) and len(trials) == 2, "repeat count")
    require([trial.get("ordinal") for trial in trials] == [1, 2], "call order")
    first, second = [fields(trial.get("fields"), f"trial {index}")
                     for index, trial in enumerate(trials, 1)]
    require(all(first[key]["length"] == second[key]["length"] for key in EXPECTED_KEYS),
            "field lengths changed")
    require({key: first[key]["length"] for key in EXPECTED_KEYS} == {
        "frametype": 1, "lid": 10, "signinfo": 192, "signvalue": 64, "signversion": 3,
    }, "field length baseline")
    stable = all(first[key]["sha256"] == second[key]["sha256"]
                 for key in ("frametype", "lid", "signversion"))
    changing = all(first[key]["sha256"] != second[key]["sha256"]
                   for key in ("signinfo", "signvalue"))
    require(data["comparison"].get("same_input_digest") is True, "same input assertion")
    require(data["comparison"].get("same_provider_instance") is True, "same provider assertion")
    require(data["comparison"].get("field_keys_and_lengths_match") is True, "shape assertion")
    require(data["comparison"].get("frametype_lid_signversion_hashes_stable") is stable and stable,
            "stable fields assertion")
    require(data["comparison"].get("signinfo_hash_changes_between_calls") is True
            and first["signinfo"]["sha256"] != second["signinfo"]["sha256"],
            "signinfo dynamic assertion")
    require(data["comparison"].get("signvalue_hash_changes_between_calls") is True
            and first["signvalue"]["sha256"] != second["signvalue"]["sha256"],
            "signvalue dynamic assertion")
    require(data["comparison"].get("dynamic_field_lengths_stable") is True and changing,
            "dynamic field shape assertion")
    for key in ("clock_random_provider_state_cause_identified",
                "fresh_standalone_signer_verified",
                "whole_request_native_python_differential_verified",
                "online_header_acceptance_verified"):
        require(data["comparison"].get(key) is False, f"overclaimed status: {key}")

    return {
        "same_live_provider_and_input_verified": True,
        "stable_fields": ["frametype", "lid", "signversion"],
        "per_call_dynamic_fields": ["signinfo", "signvalue"],
        "dynamic_cause_identified": False,
        "standalone_signer_verified": False,
    }


def main() -> int:
    default = Path(__file__).resolve().parents[1] / "evidence" / \
        "vm9_framesign_repeat_call_state_20261103.json"
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, default=default)
    args = parser.parse_args()
    print(json.dumps(verify(args.evidence), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
