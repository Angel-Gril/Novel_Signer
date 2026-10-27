"""Record the dedicated dynamic frameSign probe boundary.

The probe invokes the statically identified 0x200000A tag on the same native
JNI entry after a successful 0x3000001 setup.  The current harness returns
null for frameSign; this verifier treats the invocation marker as evidence of
dynamic routing and keeps result/provider claims explicitly false.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path

import verify_vm9_signer_objects as oracle


FRAME_MARKER = "[HookMain] MS.a tag=0x200000a"
SIGN_MARKER = "[HookMain] MS.a tag=0x3000001"
EXPECTED_HEADERS = (
    "X-Argus",
    "X-Gorgon",
    "X-Helios",
    "X-Khronos",
    "X-Ladon",
    "X-Medusa",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def digest(value: str) -> dict:
    return {"length": len(value), "sha256": hashlib.sha256(value.encode()).hexdigest()}


def verify(
    *,
    library: Path,
    hook_source: Path,
    frame_source: Path,
    frame_class: Path,
    frame_log: Path,
    sign_rounds: Path,
    output: Path,
) -> dict:
    library_hash = sha256(library)
    if library_hash != oracle.LIBRARY_SHA256:
        raise AssertionError(("pinned ELF hash", library_hash, oracle.LIBRARY_SHA256))
    trace = frame_log.read_text(encoding="utf-8", errors="replace")
    required = (
        "[HookMain] === FRAME SIGN PROBE ===",
        FRAME_MARKER,
        "FRAME_SIGN_RESULT_TYPE=null",
        "Write to write-protected memory (UC_ERR_WRITE_PROT)",
        "=== DONE ===",
    )
    absent = [marker for marker in required if marker not in trace]
    if absent:
        raise AssertionError(("frame probe markers", absent))
    if trace.count(FRAME_MARKER) != 1:
        raise AssertionError(("frame marker count", trace.count(FRAME_MARKER)))
    if SIGN_MARKER not in trace or "[HookMain] handle final =" not in trace:
        raise AssertionError("successful signing setup marker missing")

    raw_rounds = json.loads(sign_rounds.read_text(encoding="utf-8"))
    if not isinstance(raw_rounds, dict) or "0" not in raw_rounds:
        raise AssertionError("frame probe did not retain signing round")
    row = raw_rounds["0"]
    if not isinstance(row, dict):
        raise AssertionError("signing round is not an object")
    if any(not isinstance(row.get(name), str) or not row[name] for name in EXPECTED_HEADERS):
        raise AssertionError("six-header setup round is incomplete")
    try:
        base64.b64decode(row["X-Medusa"], validate=True)
    except Exception as exc:  # pragma: no cover - assertion context only
        raise AssertionError("X-Medusa is not base64") from exc
    timestamp = row.get("X-Khronos")
    if not isinstance(timestamp, str) or not timestamp.isdigit():
        raise AssertionError("missing X-Khronos")

    source_hashes = {
        "library": library_hash,
        "hook_source": sha256(hook_source),
        "frame_source": sha256(frame_source),
        "frame_class": sha256(frame_class),
        "frame_log": sha256(frame_log),
        "sign_rounds": sha256(sign_rounds),
    }
    report = {
        "schema": "vm9-frame-sign-dynamic-probe-20261028-v1",
        "evidence_date": "2026-10-28",
        "sample_sha256": library_hash,
        "jni_entry": "+0x26e684",
        "signing_setup_tag": "0x3000001",
        "frame_sign_tag": "0x200000a",
        "frame_sign_marker_count": 1,
        "frame_sign_dynamic_capture_verified": True,
        "frame_sign_result_verified": False,
        "frame_sign_result_kind": "null",
        "frame_sign_failure_kind": "unidbg_write_protected_memory",
        "frame_sign_failure_marker_verified": True,
        "signing_setup_six_header_shape_verified": True,
        "signing_setup_header_observations": {
            name: digest(row[name]) for name in EXPECTED_HEADERS
        },
        "signing_setup_input": digest(row["url"]),
        "signing_setup_khronos_seconds": int(timestamp),
        "source_hashes": source_hashes,
        "synthetic_jni_provider_used": True,
        "actual_jni_provider_verified": False,
        "live_android_jvm_verified": False,
        "whole_request_native_python_differential_verified": False,
        "fresh_standalone_signer_verified": False,
        "online_header_acceptance_verified": False,
        "interpretation": (
            "The dedicated unidbg probe reaches the same dynamically registered "
            "native entry with frameSign tag 0x200000A after a successful "
            "0x3000001 setup. The call reaches a unidbg write-protected-memory "
            "failure and the harness returns null, so the marker proves dynamic "
            "routing only; it does not prove a frameSign map, actual Android-JNI "
            "provider behavior, a live JVM, whole-request equivalence, standalone "
            "acceptance, or online header validation."
        ),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    for name in ("library", "hook-source", "frame-source", "frame-class", "frame-log", "sign-rounds", "output"):
        parser.add_argument(f"--{name}", dest=name.replace("-", "_"), type=Path, required=True)
    args = parser.parse_args()
    report = verify(**vars(args))
    print(json.dumps({
        "frame_sign_dynamic_capture_verified": report["frame_sign_dynamic_capture_verified"],
        "frame_sign_result_verified": report["frame_sign_result_verified"],
        "frame_sign_result_kind": report["frame_sign_result_kind"],
        "frame_sign_failure_kind": report["frame_sign_failure_kind"],
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
