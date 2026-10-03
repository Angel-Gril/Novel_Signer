"""Differential singleton/service construction from fresh ELF and guest inputs.

The matching private ELF and bionic libc execute only as verification oracles.
No JVM, captured pages, copied service output or request material is used.
Guard helpers execute normally; gettid and successful uncontended mutex calls
are explicit host boundaries. Wait/recursive guard branches are unsupported.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import vm9_objects as objects
from vm9_allocator import RefillUnsupported, _read_span, _write_span
from verify_vm9_signer_objects import (
    Allocator, GUEST, LIBRARY_SHA256, fresh_pages, image_pages, native,
)


KINDS = {
    "service": (0x15F094, objects.SERVICE_A_GUARD_OFFSET, objects.SERVICE_A_SLOT_OFFSET),
    "flag": (0x264158, objects.SERVICE_B_GUARD_OFFSET, objects.SERVICE_B_SLOT_OFFSET),
    "configuration": (0x15F608, objects.CONFIG_GUARD_OFFSET, objects.CONFIG_SLOT_OFFSET),
}
THREAD_ID = 137
STRING_SLOT = GUEST + 0x3500
INTEGER = GUEST + 0x3510
WIDE = GUEST + 0x3520
SOURCE = GUEST + 0x2FF8


def fixture(library, base, variant="elf_defaults"):
    pages = fresh_pages()
    pages.update(image_pages(library, base))
    for _, guard, slot in KINDS.values():
        _write_span(pages, base + guard, b"\0\0\x5a\xa5\x10\x32\x54\x76")
        _write_span(pages, base + slot, bytes(8))
    if variant == "elf_defaults":
        return pages
    payload, integer, wide = {
        "null": (None, -1, 0),
        "empty": (b"", 0, 1),
        "utf8": ("fresh-中文-input".encode(), 17, 0x0102030405060708),
        "negative": (b"x" * 39, -1234567, 0xFFFFFFFFFFFFFFFF),
        "int_min": (b"cross-page", -(1 << 31), 0x8000000000000000),
        "int_max": (b"z", (1 << 31) - 1, 0x7FFFFFFFFFFFFFFF),
    }[variant]
    for offset, pointer in ((0x374FC0, STRING_SLOT), (0x375020, INTEGER), (0x375030, WIDE)):
        _write_span(pages, base + offset, pointer.to_bytes(8, "little"))
    _write_span(pages, STRING_SLOT, (SOURCE if payload is not None else 0).to_bytes(8, "little"))
    if payload is not None:
        _write_span(pages, SOURCE, payload + b"\0")
    _write_span(pages, INTEGER, integer.to_bytes(4, "little", signed=True))
    _write_span(pages, WIDE, wide.to_bytes(8, "little"))
    _write_span(pages, base + 0x3E0B58, (0x123456789ABCDEF0).to_bytes(8, "little"))
    return pages


def getter(pages, base, kind, allocate, thread_id=None):
    if kind == "configuration":
        return objects.construct_configuration_reference(pages, image_base=base,
            allocate=allocate, thread_id=thread_id)
    return objects.construct_service_reference(pages, image_base=base, kind=kind,
        allocate=allocate, thread_id=thread_id)


def observe_image(pages):
    return {(page << 12, 4096): None for page in pages
            if not GUEST <= page << 12 < GUEST + 0x10000}


def assert_match(pages, expected, calls, allocation, observed, label):
    actual = _read_span(pages, GUEST, 0xA000)
    if actual != expected:
        first = next(i for i, (a, b) in enumerate(zip(actual, expected)) if a != b)
        raise AssertionError(f"{label}: first guest mismatch at +{first:#x}")
    assert allocation.calls == calls, (label, "allocation sequence")
    for (address, width), data in observed.items():
        assert _read_span(pages, address, width) == data, (label, "image memory", hex(address))


def alternating_effect(base):
    """Allocator effects expose native's pointer rereads and numeric latch points."""
    count = 0

    def apply(write):
        nonlocal count
        count += 1
        write(STRING_SLOT, (SOURCE if count & 1 else 0).to_bytes(8, "little"))
        write(INTEGER, (-1000 - count).to_bytes(4, "little", signed=True))
        write(WIDE, (0x12340000 + count).to_bytes(8, "little"))
        write(base + 0x3E0B58, count.to_bytes(8, "little"))
    return apply


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--libc", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == LIBRARY_SHA256
    cases, negatives = [], []
    for base in (0x122C0000, 0x775C205000):
        for variant in ("elf_defaults", "null", "empty", "utf8", "negative", "int_min", "int_max"):
            for cross_page in (False, True):
                pages = fixture(args.library, base, variant)
                target = GUEST + (0x1FF0 if cross_page else 0x1000)
                observed = observe_image(pages)
                _, expected, calls, _ = native(args.library, base, 0x281700,
                    [target], pages, libc=args.libc, real_singletons=True,
                    observed_memory=observed)
                allocation = Allocator()
                objects.construct_service_payload(pages, object_address=target,
                    image_base=base, allocate=allocation.model)
                assert_match(pages, expected, calls, allocation, observed, variant)
                cases.append({"case": "service_payload", "image_base": hex(base),
                    "input_variant": variant, "cross_page": cross_page,
                    "memory_match": True, "allocation_sequence_match": True,
                    "image_memory_match": True, "allocations": len(calls)})

        for kind, (entry, guard, slot) in KINDS.items():
            for state in ("cold", "warm", "nonzero_byte0", "byte1_complete", "other_byte1"):
                pages = fixture(args.library, base, "utf8")
                if state in ("warm", "nonzero_byte0"):
                    _write_span(pages, base + guard, bytes((1 if state == "warm" else 2,)))
                    _write_span(pages, base + slot, (GUEST + 0x3F00).to_bytes(8, "little"))
                elif state == "byte1_complete":
                    _write_span(pages, base + guard + 1, b"\x01")
                    _write_span(pages, base + slot, (GUEST + 0x3F00).to_bytes(8, "little"))
                elif state == "other_byte1":
                    _write_span(pages, base + guard + 1, b"\x84")
                observed = observe_image(pages)
                result, expected, calls, ledger = native(args.library, base, entry,
                    [], pages, libc=args.libc, real_singletons=True,
                    thread_id=THREAD_ID, observed_memory=observed)
                allocation = Allocator()
                cold = state in ("cold", "other_byte1")
                model = getter(pages, base, kind, allocation.model,
                               THREAD_ID if cold else None)
                assert model.wrapper_address == result
                assert_match(pages, expected, calls, allocation, observed, kind + state)
                cases.append({"case": kind + "_getter", "image_base": hex(base),
                    "guard_state": state, "memory_match": True,
                    "allocation_sequence_match": True, "image_memory_match": True,
                    "host_boundary_calls": ledger})

        for warm in ((), ("service",), ("service", "flag")):
            for cross_page in (False, True):
                pages = fixture(args.library, base, "negative")
                for index, kind in enumerate(warm):
                    _, guard, slot = KINDS[kind]
                    wrapper, count = GUEST + 0x3600 + index * 0x20, GUEST + 0x3700 + index * 0x10
                    _write_span(pages, base + guard, b"\x01")
                    _write_span(pages, base + slot, wrapper.to_bytes(8, "little"))
                    _write_span(pages, wrapper, (GUEST + 0x3800).to_bytes(8, "little")
                                + count.to_bytes(8, "little"))
                    _write_span(pages, count, (7).to_bytes(4, "little"))
                target = GUEST + (0x1FE8 if cross_page else 0x1000)
                observed = observe_image(pages)
                _, expected, calls, _ = native(args.library, base, 0x263FB8, [target],
                    pages, libc=args.libc, real_singletons=True, thread_id=THREAD_ID,
                    observed_memory=observed)
                allocation = Allocator()
                objects.construct_signer_handler(pages, object_address=target,
                    image_base=base, kind="service_refs", allocate=allocation.model,
                    initialize_services=True, thread_id=THREAD_ID)
                assert_match(pages, expected, calls, allocation, observed, "handler")
                cases.append({"case": "handler_with_real_getters", "image_base": hex(base),
                    "prepublished": list(warm), "cross_page": cross_page,
                    "memory_match": True, "allocation_sequence_match": True,
                    "image_memory_match": True, "allocations": len(calls)})

        pages = fixture(args.library, base, "utf8")
        observed = observe_image(pages)
        host_effect = alternating_effect(base)
        _, expected, calls, _ = native(args.library, base, 0x281700, [GUEST + 0x1FF0],
            pages, libc=args.libc, real_singletons=True, observed_memory=observed,
            allocation_effect=lambda cpu, size, pointer: host_effect(cpu.mem_write))
        allocation, model_effect = Allocator(), alternating_effect(base)

        def allocate(staged, size):
            result = allocation.model(staged, size)
            model_effect(lambda address, data: _write_span(staged, address, data))
            return result

        objects.construct_service_payload(pages, object_address=GUEST + 0x1FF0,
            image_base=base, allocate=allocate)
        assert_match(pages, expected, calls, allocation, observed, "allocator_source_mutation")
        cases.append({"case": "allocator_source_mutation", "image_base": hex(base),
            "string_pointer_rereads_verified": True, "numeric_latch_points_verified": True,
            "memory_match": True, "allocation_sequence_match": True, "image_memory_match": True})

    base = 0x122C0000

    def rejected(label, mutate, action):
        pages = fixture(args.library, base, "utf8")
        mutate(pages)
        before = {page: bytes(data) for page, data in pages.items()}
        try:
            action(pages)
        except (RefillUnsupported, ValueError):
            assert {page: bytes(data) for page, data in pages.items()} == before, label
        else:
            raise AssertionError(label + " was accepted")
        negatives.append({"case": label, "rejected": True, "pages_unchanged": True})

    rejected("cold_missing_thread_id", lambda pages: None,
             lambda pages: getter(pages, base, "service", Allocator().model))
    for byte1 in (2, 6):
        rejected("guard_initializing_" + str(byte1),
            lambda pages, value=byte1: _write_span(pages, base + KINDS["service"][1] + 1, bytes((value,))),
            lambda pages: getter(pages, base, "service", Allocator().model, THREAD_ID))
    for fail_index in (1, 2, 3, 4, 6, 10, 24, 26, 27):
        def failure(pages, index=fail_index):
            allocation = Allocator()

            def allocate(staged, size):
                if len(allocation.calls) + 1 == index:
                    raise RefillUnsupported("bounded test allocation failure")
                return allocation.model(staged, size)

            getter(pages, base, "service", allocate, THREAD_ID)
        rejected("allocation_failure_" + str(fail_index), lambda pages: None, failure)
    rejected("missing_string_input_page",
        lambda pages: pages.pop((base + 0x6FE64) >> 12),
        lambda pages: getter(pages, base, "service", Allocator().model, THREAD_ID))
    rejected("null_controller_allocation", lambda pages: None,
        lambda pages: objects.construct_service_payload(pages, object_address=GUEST + 0x1000,
            image_base=base, allocate=lambda staged, size: 0))
    rejected("conflicting_handler_dependencies", lambda pages: None,
        lambda pages: objects.construct_signer_handler(pages, object_address=GUEST + 0x1000,
            image_base=base, kind="service_refs", allocate=Allocator().model,
            initialize_services=True, service_reference_address=GUEST + 0x3600))

    result = {
        "evidence_id": "vm9_service_singletons_native_20261004",
        "library_sha256": LIBRARY_SHA256,
        "libc_sha256": hashlib.sha256(args.libc.read_bytes()).hexdigest(),
        "fresh_memory": True, "captured_pages_used": False, "jvm_required": False,
        "native_execution_used_for_verification_only": True,
        "service_payload_constructor_complete_for_measured_branch": True,
        "native_guard_helpers_executed": True, "all_image_pages_compared": True,
        "host_boundaries": ["malloc", "strlen", "memcpy", "memset", "successful_guard_mutex",
                            "explicit_gettid", "diagnostic_scope_excluded"],
        "pthread_mutex_init": "real_matching_libc_instructions",
        "unsupported": ["guard_wait_recursion", "operator_new_retry_throw",
                        "diagnostic_global_effects", "complete_root_global_startup"],
        "complete_python_medusa": False, "cases": cases, "negative_cases": negatives,
    }
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"cases": len(cases), "negative_cases": len(negatives),
        "service_payload_constructor_complete_for_measured_branch": True,
        "complete_python_medusa": False}))


if __name__ == "__main__":
    main()
