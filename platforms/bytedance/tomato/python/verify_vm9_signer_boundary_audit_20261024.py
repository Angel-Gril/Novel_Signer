"""Audit the current public outer/request boundary before standalone signing.

This is a read-only, source/evidence-backed audit.  It deliberately does not
run the private ELF, replay a native snapshot, or treat a Python composition
as a signer.  The result is useful to callers and reviewers because it names
the exact missing ownership boundaries instead of inferring them from a
successful callback count.
"""
from __future__ import annotations

import argparse
import hashlib
import inspect
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
PYTHON = ROOT / "python"
EVIDENCE = ROOT / "evidence" / "vm9_java_request_handoff_fresh_20261024.json"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _require_signature(module_name: str, function_name: str, required: tuple[str, ...]):
    module = __import__(module_name)
    function = getattr(module, function_name, None)
    if not callable(function):
        raise AssertionError(f"missing production entry {module_name}.{function_name}")
    parameters = inspect.signature(function).parameters
    absent = [name for name in required if name not in parameters]
    if absent:
        raise AssertionError(f"{module_name}.{function_name} lacks {absent}")
    return function


def audit(evidence_path: Path = EVIDENCE) -> dict:
    if not evidence_path.is_file():
        raise AssertionError(f"missing handoff evidence: {evidence_path}")
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    cases = evidence.get("cases")
    if not isinstance(cases, list) or not cases:
        raise AssertionError("handoff evidence has no cases")

    # These are the real callable owners currently exposed by production
    # Python.  Signature inspection catches accidental removal of a boundary
    # even when an old evidence file still parses.
    facade = _require_signature(
        "vm9_request_vm", "invoke_java_request_facade_service",
        ("image_base", "facade_address", "url_reference",
         "header_array_reference", "invoke_jni", "allocate", "calloc", "free"),
    )
    child = _require_signature(
        "vm9_request_vm", "invoke_java_request_service",
        ("receiver_address", "url_reference_address",
         "header_reference_address", "output_reference_address",
         "diagnostic_scope", "allocate", "free"),
    )
    request = _require_signature(
        "vm9_request_vm", "invoke_request_vm_callback",
        ("url_reference_address", "header_reference_address",
         "output_reference_address", "diagnostic_scope", "allocate", "free"),
    )
    outer = _require_signature(
        "vm9_outer_constructor", "construct_default_outer",
        ("outer_root_address", "root_output_address", "publication_callback",
         "publication_required"),
    )
    constructors = _require_signature(
        "vm9_elf_bootstrap", "run_elf_constructors",
        ("entry_return_address", "get_auxval", "varuint_scratch_address",
         "expression_scratch_address", "custom_scratch_address"),
    )

    required_false = {
        "request_objects_are_synthetic": True,
        "actual_jvm_used": False,
        "actual_os_threads_created": False,
        "whole_handoff_native_differential_verified": False,
        "request_diagnostic_transaction_committed": False,
        "request_pages_published_to_outer_session": False,
    }
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            raise AssertionError(f"case {index} is not an object")
        for key, expected in required_false.items():
            if case.get(key) is not expected:
                raise AssertionError(
                    f"case {index} changed boundary {key}: {case.get(key)!r}"
                )
        if not case.get("normal_java_facade_entry_used"):
            raise AssertionError(f"case {index} did not use normal facade")
        if not case.get("child_dispatcher_entry_used"):
            raise AssertionError(f"case {index} did not use child dispatcher")
        if not case.get("owning_request_vm_entry_used"):
            raise AssertionError(f"case {index} did not use owning request VM")

    source_files = {
        "request_vm": PYTHON / "vm9_request_vm.py",
        "facade": PYTHON / "vm9_jni_request.py",
        "outer_constructor": PYTHON / "vm9_outer_constructor.py",
        "elf_bootstrap": PYTHON / "vm9_elf_bootstrap.py",
        "handoff_evidence": evidence_path,
    }
    hashes = {}
    for name, path in source_files.items():
        if not path.is_file():
            raise AssertionError(f"missing audit input: {path}")
        hashes[name] = sha256(path)

    rows = [
        {
            "boundary": "outer_constructor",
            "owner": "vm9_outer_constructor.construct_default_outer",
            "status": "sample_verified_native_boundary_only",
            "evidence": "vm9_outer_signer_native_20261024 is private/native-only; no Python whole-state proof",
            "blocks_standalone": True,
        },
        {
            "boundary": "java_facade_to_child",
            "owner": "vm9_request_vm.invoke_java_request_facade_service",
            "status": "python_composition_verified",
            "evidence": evidence_path.name,
            "blocks_standalone": True,
        },
        {
            "boundary": "owning_request_output",
            "owner": "vm9_request_vm.invoke_request_vm_callback",
            "status": "synthetic_provider_output_only",
            "evidence": evidence_path.name,
            "blocks_standalone": True,
        },
        {
            "boundary": "published_signer_state",
            "owner": "outer allocator/session publication",
            "status": "not_published",
            "evidence": "request_pages_published_to_outer_session=false",
            "blocks_standalone": True,
        },
        {
            "boundary": "live_jvm_and_os",
            "owner": "Android JVM, JNI and OS thread providers",
            "status": "synthetic_or_unverified",
            "evidence": "actual_jvm_used=false; actual_os_threads_created=false",
            "blocks_standalone": True,
        },
        {
            "boundary": "online_header_acceptance",
            "owner": "current reading endpoints",
            "status": "unverified",
            "evidence": "current_online_header_matrix_verified=false",
            "blocks_standalone": True,
        },
    ]
    missing = [row["boundary"] for row in rows if row["blocks_standalone"]]
    return {
        "schema": "vm9-signer-boundary-audit-v1",
        "evidence_date": "2026-10-24",
        "source_hashes": hashes,
        "handoff_case_count": len(cases),
        "production_entries": {
            "facade": facade.__name__,
            "child": child.__name__,
            "request": request.__name__,
            "outer": outer.__name__,
            "constructors": constructors.__name__,
        },
        "composition_path": ["+0x17b8f8", "+0x27dd04", "+0x2830c4"],
        "rows": rows,
        "standalone_signer_verified": False,
        "missing_boundaries": missing,
        "decision": "continue_boundary_recovery",
        "limitations": [
            "This audit reads current source and committed evidence only.",
            "It does not claim a live JVM, real OS threads, whole-native request differential, or online acceptance.",
            "A successful Python callback return is not a published signer state until the outer session and provider effects have an explicit commit owner.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, default=EVIDENCE)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(PYTHON))
    report = audit(args.evidence)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({
        "decision": report["decision"],
        "standalone_signer_verified": report["standalone_signer_verified"],
        "missing_boundaries": report["missing_boundaries"],
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
