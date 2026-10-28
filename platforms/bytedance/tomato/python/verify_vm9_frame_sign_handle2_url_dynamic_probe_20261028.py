"""Verify frameSign URL sensitivity with handle2 and frameType 0.

The inputs are three fresh isolated unidbg captures.  URL text and returned
values are reduced to lengths and SHA-256 digests before evidence is written.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

import verify_vm9_signer_objects as oracle


EXPECTED_HEADERS = (
    "X-Argus",
    "X-Gorgon",
    "X-Helios",
    "X-Khronos",
    "X-Ladon",
    "X-Medusa",
)
EXPECTED_KEYS = ("frametype", "lid", "signinfo", "signvalue", "signversion")
HANDLE2 = "0x128a3000"
PROFILES = ("homepage", "query_variant", "search_route")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def digest(value: str) -> dict:
    return {"length": len(value), "sha256": sha256_bytes(value.encode("utf-8"))}


def require(text: str, marker: str) -> None:
    if marker not in text:
        raise AssertionError(f"missing marker: {marker}")


def parse_result(trace: str, profile: str) -> dict:
    for marker in (
        "[HookMain] FRAME_SIGN_PROBE_HANDLE=0x128a3000 source=handle2",
        "[HookMain] MS.a tag=0x200000a handle=0x128a3000",
        "[HookMain] FRAME_SIGN_RESULT_LENGTH=10",
        "=== DONE ===",
    ):
        require(trace, marker)
    if "UC_ERR_WRITE_PROT" in trace or "write-protected memory" in trace:
        raise AssertionError(("URL profile write-protected failure", profile))
    if "FRAME_SIGN_RESULT_TYPE=null" in trace:
        raise AssertionError(("URL profile null result", profile))
    rows = re.findall(r"^\[HookMain\] FRAME_SIGN_RESULT\[(\d+)\]= (.*)$", trace, re.MULTILINE)
    indexed = {int(index): value.rstrip("\r") for index, value in rows}
    if sorted(indexed) != list(range(10)):
        raise AssertionError(("result indices", profile, sorted(indexed)))
    result = [indexed[index] for index in range(10)]
    if result[0:2] != ["frametype", "0"] or result[2] != "lid":
        raise AssertionError(("frameType/lid", profile, result[:4]))
    if result[4] != "signinfo" or result[6] != "signvalue" or result[8:10] != ["signversion", "1.0"]:
        raise AssertionError(("result keys", profile, result))
    if not re.fullmatch(r"[0-9a-f]+", result[5]) or not re.fullmatch(r"[0-9a-f]+", result[7]):
        raise AssertionError(("result encoding", profile))
    return {
        "frame_type": 0,
        "result_length": 10,
        "keys": list(EXPECTED_KEYS),
        "lid": digest(result[3]),
        "signinfo": digest(result[5]),
        "signvalue": digest(result[7]),
        "signversion": digest(result[9]),
    }


def parse_rounds(path: Path, profile: str) -> dict:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or "0" not in raw or not isinstance(raw["0"], dict):
        raise AssertionError(("rounds", profile))
    row = raw["0"]
    if not isinstance(row.get("url"), str) or not row["url"]:
        raise AssertionError(("missing URL", profile))
    if not all(isinstance(row.get(name), str) and row[name] for name in EXPECTED_HEADERS):
        raise AssertionError(("six headers", profile))
    if not isinstance(row.get("X-Khronos"), str) or not row["X-Khronos"].isdigit():
        raise AssertionError(("X-Khronos", profile))
    return {
        "input": digest(row["url"]),
        "header_names": list(EXPECTED_HEADERS),
        "header_observations": {name: digest(row[name]) for name in EXPECTED_HEADERS},
        "khronos_seconds": int(row["X-Khronos"]),
    }


def verify(*, library: Path, hook_source: Path, logs: dict[str, Path], rounds: dict[str, Path], output: Path) -> dict:
    library_hash = sha256(library)
    if library_hash != oracle.LIBRARY_SHA256:
        raise AssertionError(("pinned ELF hash", library_hash, oracle.LIBRARY_SHA256))
    observations = {}
    round_observations = {}
    source_hashes = {"library": library_hash, "hook_source": sha256(hook_source)}
    for profile in PROFILES:
        observations[profile] = parse_result(logs[profile].read_text(encoding="utf-8", errors="replace"), profile)
        round_observations[profile] = parse_rounds(rounds[profile], profile)
        source_hashes[f"run_log_{profile}"] = sha256(logs[profile])
        source_hashes[f"rounds_{profile}"] = sha256(rounds[profile])
    if observations["homepage"]["signinfo"]["sha256"] != "f40760e5df3b901d0b9c61c9436db707c98a0157839929ecb93f6858566439bc":
        raise AssertionError("homepage signinfo baseline changed")
    if observations["homepage"]["signvalue"]["sha256"] != "c7abb13bebcb7f63ead72e1e52267b305037d28953ae684ead6821926fb3fa0f":
        raise AssertionError("homepage signvalue baseline changed")
    signinfo_hashes = {row["signinfo"]["sha256"] for row in observations.values()}
    signvalue_hashes = {row["signvalue"]["sha256"] for row in observations.values()}
    input_hashes = {row["input"]["sha256"] for row in round_observations.values()}
    if len(input_hashes) != 3:
        raise AssertionError("controlled URL profiles are not distinct")
    if len(signinfo_hashes) < 2 or len(signvalue_hashes) != 3:
        raise AssertionError("URL sensitivity was not observed in both result fields")
    if len({row["khronos_seconds"] for row in round_observations.values()}) != 1:
        raise AssertionError("controlled timestamps differ")
    report = {
        "schema": "vm9-frame-sign-handle2-url-dynamic-probe-20261028-v1",
        "evidence_date": "2026-10-28",
        "sample_sha256": library_hash,
        "handle2_source_tag": "0x4000002",
        "frame_sign_tag": "0x200000a",
        "frame_sign_handle": HANDLE2,
        "frame_type": 0,
        "profiles": list(PROFILES),
        "all_frame_sign_results_verified": True,
        "result_length": 10,
        "result_keys": list(EXPECTED_KEYS),
        "distinct_input_profiles_verified": True,
        "signinfo_sensitive_to_url": True,
        "signvalue_sensitive_to_url": True,
        "observations": observations,
        "round_observations": round_observations,
        "synthetic_jni_provider_used": True,
        "actual_jni_provider_verified": False,
        "live_android_jvm_verified": False,
        "whole_request_native_python_differential_verified": False,
        "fresh_standalone_signer_verified": False,
        "online_header_acceptance_verified": False,
        "source_hashes": source_hashes,
        "interpretation": (
            "Three fresh isolated unidbg runs reuse handle2 and frameType 0 while varying "
            "only the redacted URL profile. Every run returns the same length-10 key/value "
            "shape; signinfo and signvalue both change across the distinct input profiles. "
            "Explicit Java/OS callbacks remain in the harness, so this is native input "
            "sensitivity evidence rather than live Android-JVM/provider, whole-request "
            "differential, standalone signer or online acceptance proof."
        ),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--hook-source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    for profile in PROFILES:
        parser.add_argument(f"--run-log-{profile}", dest=f"run_log_{profile}", type=Path, required=True)
        parser.add_argument(f"--rounds-{profile}", dest=f"rounds_{profile}", type=Path, required=True)
    args = parser.parse_args()
    logs = {profile: getattr(args, f"run_log_{profile}") for profile in PROFILES}
    rounds = {profile: getattr(args, f"rounds_{profile}") for profile in PROFILES}
    report = verify(library=args.library, hook_source=args.hook_source, logs=logs, rounds=rounds, output=args.output)
    print(json.dumps({
        "all_frame_sign_results_verified": report["all_frame_sign_results_verified"],
        "signinfo_sensitive_to_url": report["signinfo_sensitive_to_url"],
        "signvalue_sensitive_to_url": report["signvalue_sensitive_to_url"],
        "signinfo_sha256_by_profile": {key: value["signinfo"]["sha256"] for key, value in report["observations"].items()},
        "signvalue_sha256_by_profile": {key: value["signvalue"]["sha256"] for key, value in report["observations"].items()},
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
