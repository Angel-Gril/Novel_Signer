"""Compare the native outer-child facade boundary with an independent model.

The native side keeps the real outer child and request VM on one Unicorn CPU.
The Python side creates its own facade fixture; it never reads native object
bytes. The comparison is intentionally semantic: JNI slot/control-flow shape,
returned array cardinality, and the cleanup phase ledger. Native request-VM
allocation details remain a separate observation because the Python request
provider is not the native VM.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

import verify_vm9_java_request_facade_fresh_20261020 as facade
import verify_vm9_native_outer_facade_actual_child_20261027 as native
import verify_vm9_signer_objects as oracle
import vm9_jni_request as model


BASES = native.BASES
MODEL_EVENT_NAMES = frozenset(("JNI", "NewObjectArray", "SetObjectArrayElement"))


def _event_shape(event):
    """Drop handles and pointers while retaining JNI operation identity."""
    if event[0] == "JNI":
        return ("JNI", int(event[1]))
    if event[0] == "NewObjectArray":
        return ("NewObjectArray", int(event[2]))
    if event[0] == "SetObjectArrayElement":
        return ("SetObjectArrayElement", int(event[3]))
    raise AssertionError(("unexpected facade event", event[0]))


def _project_events(events):
    return [_event_shape(event) for event in events
            if event[0] in MODEL_EVENT_NAMES]


def _model_case(library: Path, image: int) -> dict:
    """Run the independent Python facade fixture and retain only semantics."""
    pages, arguments = facade.fixture(library, image, "normal")
    service = facade.Services(image, "normal")
    result = model.invoke_java_request_facade(
        pages,
        **arguments,
        allocate=service.malloc,
        calloc=service.calloc,
        free=service.free,
        invoke_jni=service.model_jni,
        invoke_request=service.model_request,
        diagnostic_observer=service.diagnostic,
    )
    return {
        "result": result,
        "event_shape": _project_events(service.events),
        "element_count": len(service.elements),
        "element_lengths": [len(value) for value in service.elements],
        "allocation_calls": len(service.effects.calls),
        "free_calls": len(service.free_bytes),
        "active_blocks": len(service.effects.blocks),
    }


def _native_phase_lifecycle(case: dict) -> dict:
    """Join the facade phase to the pre-facade allocation set by address."""
    start = case["facade_allocation_start"]
    pre_facade = case["continuation_allocations"][:start]
    events = case["facade_allocator_events"]
    active = {int(row[1]): int(row[0]) for row in pre_facade}
    phase_allocations = set()
    unknown_frees = 0
    for event in events:
        if event[0] == "alloc":
            pointer = int(event[2])
            active[pointer] = int(event[1])
            phase_allocations.add(pointer)
        elif event[0] == "free":
            pointer = int(event[1])
            if pointer not in active:
                unknown_frees += 1
            else:
                del active[pointer]
        else:
            raise AssertionError(("unexpected allocator event", event[0]))
    active_phase = phase_allocations.intersection(active)
    return {
        "allocation_event_count": sum(event[0] == "alloc" for event in events),
        "free_event_count": sum(event[0] == "free" for event in events),
        "allocation_size_histogram": dict(sorted(Counter(
            int(event[1]) for event in events if event[0] == "alloc").items())),
        "last_event_kind": events[-1][0] if events else None,
        "phase_allocation_pointer_count": len(phase_allocations),
        "phase_freed_pointer_count": len(phase_allocations - active_phase),
        "phase_active_pointer_count": len(active_phase),
        "preexisting_pointer_frees": unknown_frees,
    }


def _run_case(library: Path, libc: Path, image: int) -> dict:
    actual = native.run(library, libc, image)
    expected = _model_case(library, image)
    actual_shape = _project_events(actual["facade_service_events"])
    if actual_shape != expected["event_shape"]:
        raise AssertionError((hex(image), "JNI semantic sequence", actual_shape,
                              expected["event_shape"]))
    if not actual["actual_facade_return_verified"]:
        raise AssertionError((hex(image), "native facade return"))
    if actual["facade_return_registers"]["x0"] != hex(expected["result"]):
        raise AssertionError((hex(image), "result handle", actual["facade_return_registers"],
                              hex(expected["result"])))
    actual_lengths = [len(bytes.fromhex(value))
                      for value in actual["facade_service_elements"]]
    if len(actual_lengths) != expected["element_count"]:
        raise AssertionError((hex(image), "output element count", actual_lengths,
                              expected["element_count"]))
    lifecycle = _native_phase_lifecycle(actual)
    if lifecycle["allocation_event_count"] <= lifecycle["free_event_count"]:
        raise AssertionError((hex(image), "facade phase lifecycle", lifecycle))
    if lifecycle["last_event_kind"] != "free":
        raise AssertionError((hex(image), "facade cleanup terminal event", lifecycle))
    if actual["error"] is not None or actual["unmapped_events"]:
        raise AssertionError((hex(image), "native continuation error",
                              actual["error"], actual["unmapped_events"][:4]))
    return {
        "image_base": hex(image),
        "native_facade_return": actual["facade_return_registers"]["x0"],
        "python_facade_return": hex(expected["result"]),
        "native_jni_event_shape": [list(row) for row in actual_shape],
        "python_jni_event_shape": [list(row) for row in expected["event_shape"]],
        "native_output_element_count": len(actual_lengths),
        "native_output_element_lengths": actual_lengths,
        "python_output_element_count": expected["element_count"],
        "python_output_element_lengths": expected["element_lengths"],
        "native_facade_phase_lifecycle": lifecycle,
        "python_facade_cleanup_observation": {
            "allocation_calls": expected["allocation_calls"],
            "free_calls": expected["free_calls"],
            "active_blocks_after_return": expected["active_blocks"],
        },
        "native_actual_outer_child_used": actual["real_outer_child_receiver_used"],
        "native_request_vm_entry_used": actual["real_request_vm_entry_used"],
        "native_facade_return_verified": actual["actual_facade_return_verified"],
        "native_unmapped_event_count": len(actual["unmapped_events"]),
        "semantic_jni_sequence_equal": True,
        "output_cardinality_equal": len(actual_lengths) == expected["element_count"],
        "native_python_allocator_sequence_equal": False,
        "whole_request_native_python_differential_verified": False,
        "fresh_standalone_signer_verified": False,
        "online_header_acceptance_verified": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--libc", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    digest = hashlib.sha256(args.library.read_bytes()).hexdigest()
    assert digest == oracle.LIBRARY_SHA256, digest
    rows = [_run_case(args.library, args.libc, image) for image in BASES]
    report = {
        "schema": "vm9-native-facade-cleanup-semantics-20261028-v1",
        "evidence_date": "2026-10-28",
        "sample_sha256": digest,
        "matching_libc_sha256": hashlib.sha256(args.libc.read_bytes()).hexdigest(),
        "cases": rows,
        "native_controls": len(rows),
        "semantic_jni_sequence_equal_each": all(
            row["semantic_jni_sequence_equal"] for row in rows),
        "output_cardinality_equal_each": all(
            row["output_cardinality_equal"] for row in rows),
        "native_python_allocator_sequence_equal": False,
        "native_input_snapshot_used": False,
        "synthetic_jni_provider_used": True,
        "whole_request_native_python_differential_verified": False,
        "fresh_standalone_signer_verified": False,
        "online_header_acceptance_verified": False,
        "interpretation": (
            "The actual cold outer child reaches the normal facade and native "
            "request VM on the same CPU at both image bases. Its JNI operation "
            "shape and returned-array cardinality match an independently "
            "constructed Python facade fixture after pointer/handle values are "
            "removed. The native phase ledger also reaches a free terminal "
            "event. The real request VM allocates a different internal graph "
            "from the Python provider, so allocator byte/sequence equality and "
            "whole-request native/Python equality remain explicitly unverified; "
            "no header value is interpreted as a seven-gods signer result."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n",
                           encoding="utf-8", newline="\n")
    print("native facade cleanup semantics", len(rows), "cases", flush=True)


if __name__ == "__main__":
    main()
