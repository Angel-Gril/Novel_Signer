"""Validate one fresh unidbg native signer replay without publishing secrets.

The replay uses the pinned ELF and the existing HookMain harness.  HookMain
executes the real native VM and JNI registration path, but supplies explicit
unidbg Java/OS callbacks.  This verifier therefore records a useful fresh
native replay boundary while keeping the stronger live-JVM, whole-request
differential, online-acceptance and frameSign claims false.
"""
from __future__ import annotations

import argparse
import base64
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
REQUIRED_STDOUT_MARKERS = (
    "JNIEnv->RegisterNatives",
    "RegisterNative(ms/bd/c/m, a(IIJLjava/lang/String;Ljava/lang/Object;)Ljava/lang/Object;",
    "[HookMain] MS.a tag=0x3000001",
    "[HookMain] handle final =",
    "=== DONE ===",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _header_digest(value: str) -> dict:
    raw = value.encode("utf-8")
    return {"length": len(value), "sha256": hashlib.sha256(raw).hexdigest()}


def _redacted_url(url: str) -> dict:
    return {"length": len(url), "sha256": hashlib.sha256(url.encode()).hexdigest()}


def _validate_medusa(value: str) -> None:
    try:
        decoded = base64.b64decode(value, validate=True)
    except Exception as exc:  # pragma: no cover - assertion context only
        raise AssertionError("X-Medusa is not valid base64") from exc
    if len(decoded) < 16:
        raise AssertionError("X-Medusa payload is unexpectedly short")


def verify(
    *,
    library: Path,
    cpp_library: Path,
    apk: Path,
    signer_script: Path,
    hook_source: Path,
    hook_class: Path,
    rounds: Path,
    status: Path,
    stdout: Path,
    output: Path,
) -> dict:
    library_hash = sha256(library)
    if library_hash != oracle.LIBRARY_SHA256:
        raise AssertionError(("pinned ELF hash", library_hash, oracle.LIBRARY_SHA256))

    run_status = json.loads(status.read_text(encoding="utf-8"))
    if run_status.get("exit_code") != 0 or run_status.get("failure"):
        raise AssertionError(("run status", run_status))
    if run_status.get("signature_valid") is not True:
        raise AssertionError(("signature_valid", run_status))
    timestamp_ms = int(run_status["timestamp_ms"])
    if timestamp_ms <= 0:
        raise AssertionError("missing frozen timestamp")

    row = json.loads(rounds.read_text(encoding="utf-8"))
    if not isinstance(row, dict) or not row:
        raise AssertionError("rounds output is empty")
    if sorted(row) != ["X-Argus", "X-Gorgon", "X-Helios", "X-Khronos", "X-Ladon", "X-Medusa", "url"]:
        raise AssertionError(("header set", sorted(row)))
    if not isinstance(row["url"], str) or not row["url"]:
        raise AssertionError("missing input URL")
    expected_khronos = str(timestamp_ms // 1000)
    if row["X-Khronos"] != expected_khronos:
        raise AssertionError(("X-Khronos", row["X-Khronos"], expected_khronos))
    for name in EXPECTED_HEADERS:
        value = row.get(name)
        if not isinstance(value, str) or not value:
            raise AssertionError(("empty header", name))
    _validate_medusa(row["X-Medusa"])

    trace = stdout.read_text(encoding="utf-8", errors="replace")
    absent = [marker for marker in REQUIRED_STDOUT_MARKERS if marker not in trace]
    if absent:
        raise AssertionError(("stdout markers", absent))
    dynamic_frame_sign = bool(re.search(r"MS\.a tag=0x200000a", trace, re.IGNORECASE))
    if dynamic_frame_sign:
        raise AssertionError("this replay unexpectedly mixed frameSign; use a dedicated capture")

    source_files = {
        "library": library,
        "cpp_library": cpp_library,
        "apk": apk,
        "signer_script": signer_script,
        "hook_source": hook_source,
        "hook_class": hook_class,
        "rounds": rounds,
        "status": status,
    }
    source_hashes = {name: sha256(path) for name, path in source_files.items()}
    report = {
        "schema": "vm9-fresh-unidbg-signer-replay-20261028-v1",
        "evidence_date": "2026-10-28",
        "sample_sha256": library_hash,
        "harness": {
            "runtime": "unidbg Unicorn2",
            "entry": "+0x26e684 via JNI_OnLoad/RegisterNatives",
            "java_call_tag": "0x3000001",
            "frozen_timestamp_ms": timestamp_ms,
            "input": _redacted_url(row["url"]),
            "source_hashes": source_hashes,
        },
        "header_names": list(EXPECTED_HEADERS),
        "header_observations": {
            name: _header_digest(row[name]) for name in EXPECTED_HEADERS
        },
        "khronos_seconds": int(row["X-Khronos"]),
        "native_vm_replay_completed": True,
        "jni_registration_marker_verified": True,
        "six_header_shape_verified": True,
        "frame_sign_dynamic_capture_verified": False,
        "synthetic_jni_provider_used": True,
        "actual_jni_provider_verified": False,
        "live_android_jvm_verified": False,
        "whole_request_native_python_differential_verified": False,
        "fresh_standalone_signer_verified": False,
        "online_header_acceptance_verified": False,
        "interpretation": (
            "A fresh isolated unidbg run loaded the pinned native ELF, executed "
            "JNI_OnLoad/RegisterNatives and the real native signing tag 0x3000001, "
            "and returned all six expected header names with a frozen-time "
            "X-Khronos. Header values are reduced to length and SHA-256 here. "
            "The harness still supplies explicit Java/OS callbacks, so this is "
            "native replay evidence rather than live Android-JVM provider or "
            "whole-request differential proof. The frameSign tag was not invoked."
        ),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    for name in ("library", "cpp-library", "apk", "signer-script", "hook-source", "hook-class", "rounds", "status", "stdout", "output"):
        parser.add_argument(f"--{name}", dest=name.replace("-", "_"), type=Path, required=True)
    args = parser.parse_args()
    report = verify(**vars(args))
    print(json.dumps({
        "native_vm_replay_completed": report["native_vm_replay_completed"],
        "six_header_shape_verified": report["six_header_shape_verified"],
        "frame_sign_dynamic_capture_verified": report["frame_sign_dynamic_capture_verified"],
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
