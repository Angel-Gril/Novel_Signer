"""Differentially verify the two outer callback-reference member assignments.

The native ``service_refs`` handler constructor is already covered by
``verify_vm9_signer_objects``.  This probe continues from that exact object
layout, executes the measured ``+0x58``/``+0x60`` virtual bodies, and compares
their reference-wrapper writes with the explicit Python publication helper.
It does not interpret either reference as a Java value or signer result.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import verify_vm9_signer_objects as oracle
import vm9_objects as objects


BASES = (0x122C0000, 0x775C205000)
GUEST = oracle.GUEST
LIBRARY_SHA256 = oracle.LIBRARY_SHA256
PROFILES = (
    "fresh", "repeat", "same_payload_distinct_counters", "self_alias",
    "source_40_alias_member_30", "source_30_alias_member_40", "swap_members",
    "retained_replacement", "shared_counter", "increment_wrap",
    "null_payload", "null_counter", "equal_pointee_unmapped_counter",
)


def _seed_reference(pages, source, count, payload=GUEST + 0x9300):
    oracle._write_span(
        pages, source,
        payload.to_bytes(8, "little") + count.to_bytes(8, "little"),
    )
    oracle._write_span(pages, count, (7).to_bytes(4, "little"))


def _seed_case(pages):
    # Keep all source wrappers within the native verifier's 0xa000 copy
    # window.  The distinct service/callback pairs make each increment visible.
    refs = {
        "service_a": (GUEST + 0x8400, GUEST + 0x8000),
        "service_b": (GUEST + 0x8420, GUEST + 0x8010),
        "reference_30": (GUEST + 0x9000, GUEST + 0x8800),
        "reference_40": (GUEST + 0x9020, GUEST + 0x8810),
    }
    for source, count in refs.values():
        _seed_reference(pages, source, count)
    return refs


def _constructor_native(library, libc, base, pages, target, refs):
    _, memory, allocations, _ = oracle.native(
        library, base, 0x263FB8, [target], pages, libc=libc,
        service_references=(refs["service_a"][0], refs["service_b"][0]),
    )
    return memory, allocations


def _pages_with_memory(memory, refs):
    pages = oracle.fresh_pages()
    for source, count in refs.values():
        _seed_reference(pages, source, count)
    oracle._write_span(pages, GUEST, memory)
    return pages


def _assignment_inputs(pages, target, refs, profile):
    source_30, source_40 = refs["reference_30"][0], refs["reference_40"][0]
    if profile in ("repeat", "same_payload_distinct_counters", "self_alias",
                   "equal_pointee_unmapped_counter",
                   "source_40_alias_member_30", "source_30_alias_member_40",
                   "swap_members", "retained_replacement", "shared_counter"):
        for offset in (0x30, 0x40):
            source = refs[f"reference_{offset:x}"][0]
            oracle._write_span(pages, target + offset,
                               oracle._read_span(pages, source, 16))
    if profile == "same_payload_distinct_counters":
        for offset in (0x30, 0x40):
            _seed_reference(pages, target + offset, GUEST + 0x8840 + offset)
    if profile in ("source_40_alias_member_30", "source_30_alias_member_40",
                   "swap_members", "retained_replacement", "shared_counter"):
        for offset in (0x30, 0x40):
            counter = GUEST + 0x8840 + (0 if profile == "shared_counter" else offset)
            _seed_reference(pages, target + offset, counter, GUEST + 0x9400 + offset)
    if profile == "self_alias":
        source_30, source_40 = target + 0x30, target + 0x40
    elif profile == "source_40_alias_member_30":
        source_40 = target + 0x30
    elif profile == "source_30_alias_member_40":
        source_30 = target + 0x40
    elif profile == "swap_members":
        source_30, source_40 = target + 0x40, target + 0x30
    elif profile == "increment_wrap":
        for name in ("reference_30", "reference_40"):
            oracle._write_span(pages, refs[name][1], bytes.fromhex("ffffffff"))
    elif profile == "null_payload":
        for source in (source_30, source_40):
            oracle._write_span(pages, source, bytes(8))
    elif profile == "null_counter":
        for source in (source_30, source_40):
            oracle._write_span(pages, source + 8, bytes(8))
    elif profile == "equal_pointee_unmapped_counter":
        for source in (source_30, source_40, target + 0x30, target + 0x40):
            oracle._write_span(pages, source + 8,
                               (GUEST + 0x20000).to_bytes(8, "little"))
    return source_30, source_40


def _run(library: Path, libc: Path, base: int, profile="fresh") -> dict:
    target = GUEST + 0x1000
    native_input = oracle.fresh_pages()
    refs = _seed_case(native_input)
    native_constructor, native_allocations = _constructor_native(
        library, libc, base, native_input, target, refs,
    )

    model = oracle.fresh_pages()
    model_refs = _seed_case(model)
    allocator = oracle.Allocator()
    objects.construct_signer_handler(
        model, object_address=target, image_base=base,
        allocate=allocator.model, kind="service_refs",
        service_reference_address=model_refs["service_a"][0],
        flag_reference_address=model_refs["service_b"][0],
    )
    constructor_match = oracle.flatten(model)[:0xA000] == native_constructor
    if not constructor_match or allocator.calls != native_allocations:
        raise AssertionError({
            "base": hex(base),
            "constructor_match": constructor_match,
            "model_allocations": allocator.calls,
            "native_allocations": native_allocations,
        })

    native_pages = _pages_with_memory(native_constructor, refs)
    source_30, source_40 = _assignment_inputs(native_pages, target, refs, profile)
    model_30, model_40 = _assignment_inputs(model, target, model_refs, profile)
    # Native outer order is +0x58 (destination +0x40), then +0x60
    # (destination +0x30).  Each direct entry returns through its own helper;
    # feed the first result into the second fresh CPU to preserve both count
    # increments and the exact native writes.
    _, after_40, _, _ = oracle.native(
        library, base, 0x28508C,
        [target, source_40], native_pages, libc=libc,
    )
    _, after_both, _, _ = oracle.native(
        library, base, 0x285094,
        [target, source_30],
        _pages_with_memory(after_40, refs), libc=libc,
    )

    objects.bind_signer_handler_reference_members(
        model, object_address=target,
        reference_30=model_30, reference_40=model_40,
    )
    publication_match = oracle.flatten(model)[:0xA000] == after_both
    if not publication_match:
        raise AssertionError({"base": hex(base), "profile": profile,
                              "publication_match": False})

    return {
        "image_base": hex(base),
        "profile": profile,
        "handler_vtable_offset": "0x35dc50",
        "constructor_offset": "0x263fb8",
        "native_virtual_copy_order": ["0x28508c", "0x285094"],
        "native_destination_member_order": ["+0x40", "+0x30"],
        "constructor_allocation_sequence": native_allocations,
        "constructor_memory_match": constructor_match,
        "publication_memory_match": publication_match,
        "reference_30_count_after": int.from_bytes(
            oracle._read_span(model, model_refs["reference_30"][1], 4), "little"),
        "reference_40_count_after": int.from_bytes(
            oracle._read_span(model, model_refs["reference_40"][1], 4), "little"),
        "object_reference_members_verified": True,
    }


def _rollback_cases() -> list[dict]:
    rejected = []
    for label, changes in (
        ("null_object", {"object_address": 0}),
        ("null_reference_30", {"reference_30": 0}),
        ("null_reference_40", {"reference_40": 0}),
    ):
        current = oracle.fresh_pages()
        refs = _seed_case(current)
        before = oracle.flatten(current)
        try:
            objects.bind_signer_handler_reference_members(
                current,
                object_address=changes.get("object_address", GUEST + 0x1000),
                reference_30=changes.get("reference_30", refs["reference_30"][0]),
                reference_40=changes.get("reference_40", refs["reference_40"][0]),
            )
        except objects.RefillUnsupported as exc:
            rejected.append({"label": label, "exception": type(exc).__name__,
                             "rollback": oracle.flatten(current) == before})
        else:
            raise AssertionError(label)
    # The first (+0x40) assignment succeeds before the second requires an
    # unsupported destructor or reads an unmapped source. Neither may publish.
    for count in (0, 1, 0x80000000, 0xFFFFFFFF):
        current = oracle.fresh_pages()
        refs = _seed_case(current)
        target = GUEST + 0x1000
        oracle._write_span(current, target, bytes(0x80))
        old_counter = GUEST + 0x8880
        _seed_reference(current, target + 0x30, old_counter, GUEST + 0x9440)
        oracle._write_span(current, old_counter, count.to_bytes(4, "little"))
        before = oracle.flatten(current)
        try:
            objects.bind_signer_handler_reference_members(
                current, object_address=target,
                reference_30=refs["reference_30"][0],
                reference_40=refs["reference_40"][0],
            )
        except objects.RefillUnsupported as exc:
            assert "final-owner destruction" in str(exc)
            rejected.append({"label": f"late_destructor_{count:#x}",
                             "exception": type(exc).__name__,
                             "rollback": oracle.flatten(current) == before})
        else:
            raise AssertionError(("last-owner assignment was accepted", count))
    current = oracle.fresh_pages()
    refs = _seed_case(current)
    target = GUEST + 0x1000
    oracle._write_span(current, target, bytes(0x80))
    before = oracle.flatten(current)
    try:
        objects.bind_signer_handler_reference_members(
            current, object_address=target, reference_30=GUEST + 0x20000,
            reference_40=refs["reference_40"][0],
        )
    except ValueError as exc:
        rejected.append({"label": "late_unmapped_source",
                         "exception": type(exc).__name__,
                         "rollback": oracle.flatten(current) == before})
    else:
        raise AssertionError("unmapped assignment was accepted")
    assert len(rejected) == 8 and all(row["rollback"] for row in rejected)
    return rejected


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--libc", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    digest = hashlib.sha256(args.library.read_bytes()).hexdigest()
    if digest != LIBRARY_SHA256:
        raise AssertionError(digest)
    cases = [_run(args.library, args.libc, base, profile)
             for base in BASES for profile in PROFILES]
    report = {
        "schema": "vm9-request-context-reference-members-20261102-v2",
        "sample_sha256": digest,
        "matching_libc_sha256": hashlib.sha256(args.libc.read_bytes()).hexdigest(),
        "cases": cases,
        "native_controls": len(cases) * 3,
        "rollback_guards": _rollback_cases(),
        "object_reference_members_verified": all(
            case["object_reference_members_verified"] for case in cases
        ),
        "signer_result_interpretation": False,
        "whole_request_native_differential_verified": False,
        "fresh_standalone_signer_verified": False,
        "online_header_acceptance_verified": False,
        "native_output_used_as_model_input": False,
        "diagnostic_scope_and_physical_stack_effects_verified": False,
        "final_owner_destruction_supported": False,
        "comparison_note": (
            "The service_refs handler's explicit +0x30/+0x40 callback-reference "
            "assignments match +0x28508c then +0x285094 on both image bases, "
            "including equal-pointee skips, retained releases, source/member "
            "aliases and uint32 increments. Last-owner destruction refuses "
            "without publishing either member. Diagnostic scopes and physical "
            "stack writes remain excluded; no Java or signer semantics are inferred."
        ),
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("request-context reference members", len(cases), "native cases PASS", flush=True)


if __name__ == "__main__":
    main()
