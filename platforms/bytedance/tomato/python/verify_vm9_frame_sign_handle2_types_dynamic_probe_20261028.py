"""Verify frameSign type sensitivity with the Java-lifecycle handle2.

Each input is a fresh isolated unidbg capture with explicit Java/OS callbacks.
Only structural fields and SHA-256 digests are emitted; raw URLs, headers and
frame values are never copied into repository evidence.
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


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def digest(value: str) -> dict:
    return {"length": len(value), "sha256": sha256_bytes(value.encode("utf-8"))}


def require(text: str, marker: str) -> None:
    if marker not in text:
        raise AssertionError(f"missing marker: {marker}")


def parse_result(trace: str, frame_type: int) -> dict:
    for marker in (
        "[HookMain] FRAME_SIGN_PROBE_HANDLE=0x128a3000 source=handle2",
        "[HookMain] MS.a tag=0x200000a handle=0x128a3000",
        "[HookMain] FRAME_SIGN_RESULT_LENGTH=10",
        "=== DONE ===",
    ):
        require(trace, marker)
    if "UC_ERR_WRITE_PROT" in trace or "write-protected memory" in trace:
        raise AssertionError(("frame type write-protected failure", frame_type))
    if "FRAME_SIGN_RESULT_TYPE=null" in trace:
        raise AssertionError(("frame type null result", frame_type))
    rows = re.findall(r"^\[HookMain\] FRAME_SIGN_RESULT\[(\d+)\]= (.*)$", trace, re.MULTILINE)
    indexed = {int(index): value for index, value in rows}
    if sorted(indexed) != list(range(10)):
        raise AssertionError(("frame result indices", frame_type, sorted(indexed)))
    result = [indexed[index] for index in range(10)]
    if result[0] != "frametype" or result[1] != str(frame_type):
        raise AssertionError(("frametype", frame_type, result[:2]))
    if result[2] != "lid" or result[4] != "signinfo" or result[6] != "signvalue":
        raise AssertionError(("frame result keys", frame_type, result))
    if result[8:10] != ["signversion", "1.0"]:
        raise AssertionError(("frame result version", frame_type, result[8:]))
    if len(result[5]) != 224 or not re.fullmatch(r"[0-9a-f]+", result[5]):
        raise AssertionError(("signinfo", frame_type))
    if len(result[7]) != 64 or not re.fullmatch(r"[0-9a-f]+", result[7]):
        raise AssertionError(("signvalue", frame_type))
    return {
        "frame_type": frame_type,
        "result_length": 10,
        "keys": list(EXPECTED_KEYS),
        "lid": digest(result[3]),
        "signinfo": digest(result[5]),
        "signvalue": digest(result[7]),
        "signversion": digest(result[9]),
    }


def check_rounds(path: Path) -> dict:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or "0" not in raw or not isinstance(raw["0"], dict):
        raise AssertionError(("rounds", path))
    row = raw["0"]
    if not all(isinstance(row.get(name), str) and row[name] for name in EXPECTED_HEADERS):
        raise AssertionError(("six header setup", path))
    if not isinstance(row.get("X-Khronos"), str) or not row["X-Khronos"].isdigit():
        raise AssertionError(("X-Khronos", path))
    return {
        "header_names": list(EXPECTED_HEADERS),
        "header_observations": {name: digest(row[name]) for name in EXPECTED_HEADERS},
        "khronos_seconds": int(row["X-Khronos"]),
    }


def verify(*, library: Path, hook_source: Path, logs: dict[int, Path], rounds: dict[int, Path], output: Path) -> dict:
    library_hash = sha256(library)
    if library_hash != oracle.LIBRARY_SHA256:
        raise AssertionError(("pinned ELF hash", library_hash, oracle.LIBRARY_SHA256))
    observations = {}
    source_hashes = {"library": library_hash, "hook_source": sha256(hook_source)}
    for frame_type in range(4):
        trace = logs[frame_type].read_text(encoding="utf-8", errors="replace")
        observations[str(frame_type)] = parse_result(trace, frame_type)
        source_hashes[f"run_log_type{frame_type}"] = sha256(logs[frame_type])
        source_hashes[f"rounds_type{frame_type}"] = sha256(rounds[frame_type])
    round_observations = {str(frame_type): check_rounds(rounds[frame_type]) for frame_type in range(4)}
    signinfo_hashes = {row["signinfo"]["sha256"] for row in observations.values()}
    signvalue_hashes = {row["signvalue"]["sha256"] for row in observations.values()}
    if len(signinfo_hashes) != 1:
        raise AssertionError("signinfo changed across frame types")
    if len(signvalue_hashes) != 4:
        raise AssertionError("signvalue did not vary across frame types")
    khronos = {row["khronos_seconds"] for row in round_observations.values()}
    if len(khronos) != 1:
        raise AssertionError("round timestamps differ across the controlled type sweep")
    report = {
        "schema": "vm9-frame-sign-handle2-types-dynamic-probe-20261028-v1",
        "evidence_date": "2026-10-28",
        "sample_sha256": library_hash,
        "handle2_source_tag": "0x4000002",
        "frame_sign_tag": "0x200000a",
        "frame_sign_handle": HANDLE2,
        "frame_types": [0, 1, 2, 3],
        "all_frame_sign_results_verified": True,
        "result_length": 10,
        "result_keys": list(EXPECTED_KEYS),
        "signinfo_invariant_across_types": True,
        "signvalue_sensitive_to_frame_type": True,
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
            "Four fresh isolated unidbg runs use the Java-lifecycle handle2 from tag "
            "0x4000002 and call frameSign tag 0x200000A with frame types 0, 1, 2 and 3. "
            "Every run returns a length-10 String[] with the same five key names and "
            "the same signinfo digest, while each signvalue digest differs. This is "
            "native frame-type sensitivity evidence only; explicit Java/OS callbacks "
            "remain in the harness, so live Android-JVM/provider behavior, whole-request "
            "differential, standalone signing and online acceptance remain unverified."
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
    for frame_type in range(4):
        parser.add_argument(f"--run-log-type{frame_type}", dest=f"run_log_type{frame_type}", type=Path, required=True)
        parser.add_argument(f"--rounds-type{frame_type}", dest=f"rounds_type{frame_type}", type=Path, required=True)
    args = parser.parse_args()
    logs = {frame_type: getattr(args, f"run_log_type{frame_type}") for frame_type in range(4)}
    rounds = {frame_type: getattr(args, f"rounds_type{frame_type}") for frame_type in range(4)}
    report = verify(library=args.library, hook_source=args.hook_source, logs=logs, rounds=rounds, output=args.output)
    print(json.dumps({
        "all_frame_sign_results_verified": report["all_frame_sign_results_verified"],
        "signinfo_invariant_across_types": report["signinfo_invariant_across_types"],
        "signvalue_sensitive_to_frame_type": report["signvalue_sensitive_to_frame_type"],
        "signvalue_sha256_by_type": {key: value["signvalue"]["sha256"] for key, value in report["observations"].items()},
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
