"""Verify the read-only native writer provenance for the frameSign handle.

The input is a completed private HookMain capture.  This verifier only reads
the log and rounds JSON; it does not patch memory, synthesize a vtable, or
rerun the native target.
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
HANDLE = "0x1296a4a0"
OWNER_FIELD = "0x1296a4e8"
OWNER_VALUE = "0x12448a94"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(text: str, marker: str) -> None:
    if marker not in text:
        raise AssertionError(f"missing marker: {marker}")


def verify(*, library: Path, hook_source: Path, run_log: Path, rounds: Path, output: Path) -> dict:
    library_hash = sha256(library)
    if library_hash != oracle.LIBRARY_SHA256:
        raise AssertionError(("pinned ELF hash", library_hash, oracle.LIBRARY_SHA256))
    elf = library.read_bytes()
    if elf[0x25BF30 : 0x25BF34].hex() != "090d00f9":
        raise AssertionError("+0x25bf30 is not the expected inner-member store")
    if elf[0x15DC60 : 0x15DC64].hex() != "74fe04a9":
        raise AssertionError("+0x15dc60 is not the expected candidate +0x48 store")
    trace = run_log.read_text(encoding="utf-8", errors="replace")
    for marker in (
        "frameSign dynamic hooks installed",
        "handle final = 0x1296a4a0",
        "MS.a tag=0x200000a handle=0x1296a4a0",
        "FRAMESIGN_DYN pc=+0x15dbc4 tag=0x4000001",
        "FRAMESIGN_DYN pc=+0x15dc60 tag=0x4000001",
        "FRAMESIGN_DYN_WRITE seq=31 tag=0x4000001 object=0x1296a4a0 delta=0x48 address=0x1296a4e8 size=8 value=0x12448a94 pc=metasec+0x25bf14",
        "FRAME_SIGN_RESULT_TYPE=null",
        "Write to write-protected memory (UC_ERR_WRITE_PROT)",
        "=== DONE ===",
    ):
        require(trace, marker)

    writer = re.search(
        r"FRAMESIGN_DYN_WRITE seq=(?P<seq>\d+) tag=0x4000001 object=(?P<object>0x[0-9a-f]+) "
        r"delta=0x48 address=(?P<address>0x[0-9a-f]+) size=8 value=(?P<value>0x[0-9a-f]+) "
        r"pc=metasec\+0x25bf14",
        trace,
    )
    if not writer:
        raise AssertionError("handle +0x48 writer record missing")
    if (writer.group("object"), writer.group("address"), writer.group("value")) != (
        HANDLE,
        OWNER_FIELD,
        OWNER_VALUE,
    ):
        raise AssertionError("unexpected handle writer tuple")

    before = re.search(r"HANDLE_MEMORY_BEFORE_SIGN_0=([0-9a-f]+)", trace)
    after = re.search(r"HANDLE_MEMORY_AFTER_SIGN_0=([0-9a-f]+)", trace)
    if not before or not after:
        raise AssertionError("handle before/after snapshots missing")
    if before.group(1) != after.group(1):
        raise AssertionError("handle bytes changed across signing round")
    if bytes.fromhex(before.group(1)[0x48 * 2 : 0x50 * 2]).hex() != "948a441200000000":
        raise AssertionError("handle +0x48 snapshot does not point to 0x12448a94")

    raw_rounds = json.loads(rounds.read_text(encoding="utf-8"))
    if not isinstance(raw_rounds, dict) or not raw_rounds:
        raise AssertionError("rounds JSON is empty")
    observed = set()
    for row in raw_rounds.values():
        if isinstance(row, dict):
            observed.update(k for k in row if k.startswith("X-"))
    missing = [name for name in EXPECTED_HEADERS if name not in observed]
    if missing:
        raise AssertionError(f"six-header setup missing: {missing}")

    constructor = re.search(
        r"FRAMESIGN_DYN_WRITE seq=16 tag=0x4000001 object=(0x[0-9a-f]+) delta=0x48 "
        r"address=(0x[0-9a-f]+) size=8 value=(0x[0-9a-f]+) pc=metasec\+0x15dc60",
        trace,
    )
    if not constructor:
        raise AssertionError("candidate constructor +0x15dc60 writer missing")

    source_hashes = {
        "library": library_hash,
        "hook_source": sha256(hook_source),
        "run_log": sha256(run_log),
        "rounds": sha256(rounds),
    }
    report = {
        "schema": "vm9-frame-sign-owner-dynamic-probe-20261028-v1",
        "evidence_date": "2026-10-28",
        "sample_sha256": library_hash,
        "jni_entry": "+0x26e684",
        "signing_setup_tag": "0x3000001",
        "frame_sign_tag": "0x200000a",
        "handle": HANDLE,
        "handle_field_offset": "0x48",
        "handle_field_address": OWNER_FIELD,
        "handle_field_value": OWNER_VALUE,
        "handle_field_writer": {
            "pc": "+0x25bf14",
            "tag": "0x4000001",
            "sequence": int(writer.group("seq")),
            "value_is_executable_image_address": True,
            "static_member_store_pc": "+0x25bf30",
            "static_member_store_bytes": "090d00f9",
            "static_member_store_disassembly": "str x9, [x8, #0x18]",
        },
        "handle_field_snapshot_unchanged_across_sign": True,
        "candidate_constructor": {
            "entry": "+0x15dbc4",
            "field_store": "+0x15dc60",
            "observed_object": constructor.group(1),
            "observed_value": constructor.group(3),
            "is_signer_handle": False,
        },
        "frame_sign_dynamic_capture_verified": True,
        "frame_sign_result_verified": False,
        "frame_sign_result_kind": "null",
        "frame_sign_failure_kind": "unidbg_write_protected_memory",
        "orchestrator_entry_29ccd4_hit": "+0x29ccd4" in trace,
        "vm_branch_entry_29cf58_hit": "+0x29cf58" in trace,
        "signing_setup_six_header_shape_verified": True,
        "synthetic_jni_provider_used": True,
        "actual_jni_provider_verified": False,
        "live_android_jvm_verified": False,
        "whole_request_native_python_differential_verified": False,
        "fresh_standalone_signer_verified": False,
        "online_header_acceptance_verified": False,
        "source_hashes": source_hashes,
        "interpretation": (
            "The fresh unidbg capture observes the actual setup path writing the current "
            "signer handle's +0x48 field at +0x25bf14 during tag 0x4000001. The field "
            "contains 0x12448a94, an image-relative executable address, and remains "
            "unchanged across the six-header signing round. The nearby +0x15dbc4/+0x15dc60 "
            "constructor writes a different object, so it is not the current signer handle. "
            "frameSign still reaches the registered 0x200000A entry but fails in unidbg and "
            "returns null; no vtable or owner replacement was synthesized."
        ),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    for name in ("library", "hook-source", "run-log", "rounds", "output"):
        parser.add_argument(f"--{name}", dest=name.replace("-", "_"), type=Path, required=True)
    args = parser.parse_args()
    report = verify(**vars(args))
    print(json.dumps({
        "handle_field_writer_verified": True,
        "handle_field_value": report["handle_field_value"],
        "frame_sign_result_verified": report["frame_sign_result_verified"],
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
