"""Differentially verify the two outer callback-reference member copies.

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


def _run(library: Path, libc: Path, base: int) -> dict:
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

    # Native outer order is +0x58 (destination +0x40), then +0x60
    # (destination +0x30).  Each direct entry returns through its own helper;
    # feed the first result into the second fresh CPU to preserve both count
    # increments and the exact native writes.
    _, after_40, _, _ = oracle.native(
        library, base, 0x28508C,
        [target, refs["reference_40"][0]],
        _pages_with_memory(native_constructor, refs), libc=libc,
    )
    _, after_both, _, _ = oracle.native(
        library, base, 0x285094,
        [target, refs["reference_30"][0]],
        _pages_with_memory(after_40, refs), libc=libc,
    )

    objects.bind_signer_handler_reference_members(
        model, object_address=target,
        reference_30=model_refs["reference_30"][0],
        reference_40=model_refs["reference_40"][0],
    )
    publication_match = oracle.flatten(model)[:0xA000] == after_both
    if not publication_match:
        raise AssertionError({"base": hex(base), "publication_match": False})

    return {
        "image_base": hex(base),
        "handler_vtable_offset": "0x35dc50",
        "constructor_offset": "0x263fb8",
        "native_virtual_copy_order": ["0x28508c", "0x285094"],
        "native_destination_member_order": ["+0x40", "+0x30"],
        "constructor_allocation_sequence": native_allocations,
        "constructor_memory_match": constructor_match,
        "publication_memory_match": publication_match,
        "reference_30_count_after": 8,
        "reference_40_count_after": 8,
        "object_reference_members_verified": True,
    }


def _rollback_cases() -> list[dict]:
    pages = oracle.fresh_pages()
    refs = _seed_case(pages)
    before = oracle.flatten(pages)
    rejected = []
    for label, changes in (
        ("null_object", {"object_address": 0}),
        ("null_reference_30", {"reference_30": 0}),
        ("null_reference_40", {"reference_40": 0}),
    ):
        current = oracle.fresh_pages()
        _seed_case(current)
        try:
            objects.bind_signer_handler_reference_members(
                current,
                object_address=changes.get("object_address", GUEST + 0x1000),
                reference_30=changes.get("reference_30", refs["reference_30"][0]),
                reference_40=changes.get("reference_40", refs["reference_40"][0]),
            )
        except Exception as exc:
            rejected.append({"label": label, "exception": type(exc).__name__,
                             "rollback": oracle.flatten(current) == before})
        else:
            raise AssertionError(label)
    assert len(rejected) == 3 and all(row["rollback"] for row in rejected)
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
    cases = [_run(args.library, args.libc, base) for base in BASES]
    report = {
        "schema": "vm9-request-context-reference-members-20261028-v1",
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
        "comparison_note": (
            "The service_refs handler's explicit +0x30/+0x40 callback-reference "
            "copies match the measured +0x285094/+0x28508c native bodies on both "
            "image bases. The helper preserves native reference-count updates and "
            "does not infer Java or signer semantics."
        ),
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("request-context reference members", len(cases), "native cases PASS", flush=True)


if __name__ == "__main__":
    main()
