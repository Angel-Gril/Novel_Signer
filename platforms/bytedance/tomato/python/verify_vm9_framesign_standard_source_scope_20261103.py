"""Verify bounded source observations during live FrameSign JNI calls."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


KEYS = ("frametype", "lid", "signinfo", "signvalue", "signversion")
HEX_256 = re.compile(r"[0-9a-f]{64}")
EXPECTED_INPUT = {
    "profile": "homepage",
    "frame_type": 0,
    "length": 49,
    "sha256": "652d1fd0299450b54779193974db5f8dad3eb09c4732ae3d96f0a13c03307b02",
}
EXPECTED_LENGTHS = {"frametype": 1, "lid": 10, "signinfo": 192, "signvalue": 64, "signversion": 3}
RANDOM_COUNTERS = (
    "getrandom", "arc4random", "rand", "random", "secureRandom_nextBytes",
    "java_nanoTime", "java_currentTimeMillis",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def parse_fields(rows: object, label: str) -> dict[str, dict]:
    require(isinstance(rows, list), f"{label}: fields")
    require(tuple(row.get("key") for row in rows if isinstance(row, dict)) == KEYS,
            f"{label}: field order")
    result = {}
    for row in rows:
        require(set(row) == {"key", "length", "sha256"}, f"{label}: raw/extra data")
        require(isinstance(row["sha256"], str) and HEX_256.fullmatch(row["sha256"]),
                f"{label}: digest")
        require(isinstance(row["length"], int) and row["length"] > 0, f"{label}: length")
        result[row["key"]] = {"length": row["length"], "sha256": row["sha256"]}
    require({key: value["length"] for key, value in result.items()} == EXPECTED_LENGTHS,
            f"{label}: expected lengths")
    return result


def verify(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    require(data.get("schema") == "vm9-framesign-standard-source-scope-20261103-v1", "schema")
    require(data.get("package") == "com.dragon.read", "package")
    require(data.get("app_version") == "7.2.5.32/72532", "app version")
    require(data.get("apk_sha256") ==
            "95889d1a1ad0b11ed2451eedf0389516e1382640182026e82eb515e04fbc04fd",
            "APK hash")
    require(data.get("input") == EXPECTED_INPUT, "input")
    require(data.get("raw_capture_retained") is False, "raw capture retained")

    boundary = data.get("observation_boundary", {})
    require(boundary.get("java_entry") == "ms.bd.c.y2.a(int,int,long,String,Object)", "JNI entry")
    require(boundary.get("tag") == "0x200000a", "JNI tag")
    require(boundary.get("thread_filtered") is True, "thread filter")
    require(boundary.get("same_manager_instance_reused") is True, "provider instance")

    trials = data.get("repeat_trials")
    require(isinstance(trials, list) and len(trials) == 2, "trial count")
    require([trial.get("ordinal") for trial in trials] == [1, 2], "trial order")
    parsed = []
    for index, trial in enumerate(trials, 1):
        parsed.append(parse_fields(trial.get("fields"), f"trial {index}"))
        counts = trial.get("source_counts", {})
        require(set(counts) == {
            "clock_gettime", "gettimeofday", "getrandom", "arc4random", "rand",
            "random", "java_nanoTime", "java_currentTimeMillis", "secureRandom_nextBytes",
        }, f"trial {index}: counter set")
        require(counts.get("clock_gettime") == 1, f"trial {index}: clock count")
        require(all(counts.get(name) == 0 for name in RANDOM_COUNTERS),
                f"trial {index}: observed random/time API")
        require(counts.get("gettimeofday") == 0, f"trial {index}: gettimeofday")

    first, second = parsed
    require(all(first[key]["length"] == second[key]["length"] for key in KEYS), "length drift")
    require(all(first[key]["sha256"] == second[key]["sha256"]
                for key in ("frametype", "lid", "signversion")), "stable fields")
    require(all(first[key]["sha256"] != second[key]["sha256"]
                for key in ("signinfo", "signvalue")), "dynamic fields")

    clock = data.get("clock_observation", {})
    require(clock.get("immediate_return_module") == "libc.so", "clock caller module")
    require(clock.get("immediate_return_offset") == "0xb308c", "clock return offset")
    require(clock.get("caller_function") == "je_nstime_update", "clock caller function")
    require(clock.get("call_instruction_offset") == "0xb3087", "clock call offset")
    require(clock.get("plt_target_offset") == "0x1a7a0", "clock PLT offset")
    require(clock.get("plt_target_symbol") == "clock_gettime", "clock PLT symbol")
    require(clock.get("clock_id") == 6 and clock.get("clock_id_name") ==
            "CLOCK_MONOTONIC_COARSE", "clock id")
    require(clock.get("attributed_to_signer") is False, "signer clock overclaim")
    require(clock.get("native_backtrace_frames") == 0, "unwind status")

    artifacts = data.get("source_artifacts", {})
    require(artifacts.get("device_libc_sha256") ==
            "78d745c10b5765230482dd19c73cbe66e567a34877194f0a393e73e4eac468f7",
            "pinned libc")
    require(all(isinstance(value, str) and HEX_256.fullmatch(value)
                for value in artifacts.values()), "source hashes")
    for key in ("clock_call_attributed_to_signer", "standard_random_api_observed_on_signer_thread",
                "custom_random_source_excluded", "direct_syscall_source_excluded",
                "dynamic_cause_identified", "fresh_standalone_signer_verified",
                "whole_request_native_python_differential_verified",
                "online_header_acceptance_verified"):
        require(data["comparison"].get(key) is False, f"overclaimed status: {key}")
    return {
        "same_input_dynamic_fields_verified": True,
        "clock_call_attributed_to_signer": False,
        "standard_random_api_observed": False,
        "dynamic_cause_identified": False,
        "standalone_signer_verified": False,
    }


def main() -> int:
    default = Path(__file__).resolve().parents[1] / "evidence" / \
        "vm9_framesign_standard_source_scope_20261103.json"
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, default=default)
    args = parser.parse_args()
    print(json.dumps(verify(args.evidence), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
