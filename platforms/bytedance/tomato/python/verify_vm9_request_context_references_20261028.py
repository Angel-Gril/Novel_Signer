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


def _cleanup_case(library, libc, base, profile, count):
    from unicorn import arm64_const as arm

    target = GUEST + 0x1000
    original = oracle.fresh_pages()
    refs = _seed_case(original)
    oracle._write_span(original, target, bytes(0x80))
    sizes = {}
    for offset in (0x40, 0x30):
        counter, payload = GUEST + 0x8900 + offset, GUEST + 0x9500 + offset
        if profile == "null_old_object":
            payload = 0
        elif profile == "null_old_counter":
            counter = 0
        if payload:
            oracle._write_span(original, payload,
                               (base + objects.CONFIG_VTABLE_OFFSET).to_bytes(8, "little"))
            sizes[payload] = 8
        oracle._write_span(original, target + offset,
                           payload.to_bytes(8, "little") + counter.to_bytes(8, "little"))
        if counter:
            oracle._write_span(original, counter, count.to_bytes(4, "little"))
            sizes[counter] = 4
    model = {k: bytearray(v) for k, v in original.items()}
    model.update(oracle.image_pages(library, base))
    expected, actual = [], []

    def release(read, write, pointer, events):
        width = sizes[pointer]
        events.append((pointer, read(pointer, width)))
        write(pointer, b"\xdd" * width)
        # Model an allocator callback changing the still-live source wrapper.
        if profile == "free_mutates_source" and pointer == GUEST + 0x8940:
            write(refs["reference_40"][0], (GUEST + 0x9600).to_bytes(8, "little"))
        if profile == "free_nulls_old_object" and pointer == GUEST + 0x8940:
            write(target + 0x40, bytes(8))

    def native_free(cpu):
        release(lambda a, n: bytes(cpu.mem_read(a, n)), cpu.mem_write,
                cpu.reg_read(arm.UC_ARM64_REG_X0), expected)
        return 0

    def model_free(pages, pointer):
        release(lambda a, n: oracle._read_span(pages, a, n),
                lambda a, raw: oracle._write_span(pages, a, raw), pointer, actual)

    _, after_40, _, _ = oracle.native(
        library, base, 0x28508C, [target, refs["reference_40"][0]],
        original, libc=libc, host_imports={0x347FA0: native_free})
    _, after_both, _, _ = oracle.native(
        library, base, 0x285094, [target, refs["reference_30"][0]],
        _pages_with_memory(after_40, refs), libc=libc,
        host_imports={0x347FA0: native_free})
    objects.bind_signer_handler_reference_members(
        model, object_address=target, reference_30=refs["reference_30"][0],
        reference_40=refs["reference_40"][0], image_base=base, free=model_free)
    assert oracle.flatten(model)[:0xA000] == after_both, (hex(base), profile, "memory")
    assert actual == expected, (hex(base), profile, "release order/pre-free bytes")
    return dict(image_base=hex(base), profile=profile, original_count=count,
                full_object_window_match=True, release_order_and_pre_free_bytes_match=True,
                freed_blocks=len(actual), native_output_used_as_model_input=False)


def _cleanup_guards(library, base):
    rows = []
    for label in ("missing_free", "missing_image", "unknown_destructor",
                  "counter_free_failure", "object_free_failure",
                  "second_member_failure"):
        p = oracle.fresh_pages()
        p.update(oracle.image_pages(library, base))
        refs = _seed_case(p)
        target = GUEST + 0x1000
        oracle._write_span(p, target, bytes(0x80))
        for offset in (0x40, 0x30):
            counter, payload = GUEST + 0x8900 + offset, GUEST + 0x9500 + offset
            _seed_reference(p, target + offset, counter, payload)
            oracle._write_span(p, counter, (1).to_bytes(4, "little"))
            table = 0x35D5F0 if label == "unknown_destructor" else objects.CONFIG_VTABLE_OFFSET
            oracle._write_span(p, payload, (base + table).to_bytes(8, "little"))
        effects = []
        def free(tx, pointer):
            effects.append(pointer)
            oracle._write_span(tx, pointer, b"\xdd" * 4)
            failed_pointer = {"counter_free_failure": GUEST + 0x8940,
                              "object_free_failure": GUEST + 0x9540,
                              "second_member_failure": GUEST + 0x9530}.get(label)
            if pointer == failed_pointer:
                raise objects.RefillUnsupported("injected handler cleanup failure")
        before = {k: bytes(v) for k, v in p.items()}
        try:
            objects.bind_signer_handler_reference_members(
                p, object_address=target, reference_30=refs["reference_30"][0],
                reference_40=refs["reference_40"][0],
                image_base=None if label == "missing_image" else base,
                free=None if label == "missing_free" else free)
        except (objects.RefillUnsupported, ValueError):
            pass
        else:
            raise AssertionError(("cleanup guard accepted", label))
        assert before == {k: bytes(v) for k, v in p.items()}, label
        rows.append(dict(image_base=hex(base), profile=label, all_pages_unchanged=True,
                         provider_effects_observed=len(effects),
                         provider_effects_rolled_back=False))
    return rows


def _seed_empty_child(pages, *, image_base, count, null_container=False,
                      address_base=0x1000):
    child = GUEST + address_base
    container = child + 0x1000
    controller = child + 0x2000
    sentinel = child + 0x3000
    counter = child + 0x4000
    oracle._write_span(pages, child,
                       (image_base + 0x35D5F0).to_bytes(8, "little")
                       + bytes(8))
    pointer = 0 if null_container else container
    oracle._write_span(pages, child + 0x10,
                       pointer.to_bytes(8, "little") + counter.to_bytes(8, "little"))
    oracle._write_span(pages, counter, count.to_bytes(4, "little"))
    oracle._write_span(pages, child + 0x20, bytes(8))
    if not null_container:
        oracle._write_span(pages, container,
            (image_base + 0x35B828).to_bytes(8, "little")
            + (image_base + 0x182D6C).to_bytes(8, "little")
            + (image_base + 0x182D6C).to_bytes(8, "little")
            + (image_base + 0x188A94).to_bytes(8, "little")
            + controller.to_bytes(8, "little"))
        oracle._write_span(pages, controller,
            sentinel.to_bytes(8, "little") + bytes(8)
            + (image_base + 0x182D6C).to_bytes(8, "little")
            + (image_base + 0x24B560).to_bytes(8, "little"))
        oracle._write_span(pages, sentinel,
            bytes(8) + sentinel.to_bytes(8, "little")
            + sentinel.to_bytes(8, "little") + bytes(8))
    return child, container, controller, sentinel, counter


def _child_cleanup_case(library, libc, base, profile, count):
    from unicorn import arm64_const as arm

    native_pages = oracle.fresh_pages()
    child, container, controller, sentinel, counter = _seed_empty_child(
        native_pages, image_base=base, count=count,
        null_container=profile == "null_container")
    model = {k: bytearray(v) for k, v in native_pages.items()}
    model.update(oracle.image_pages(library, base))
    expected, actual = [], []
    sizes = {counter: 4, child: 0x28, container: 0x28,
             controller: 0x28, sentinel: 0x28}

    def native_free(cpu):
        pointer = cpu.reg_read(arm.UC_ARM64_REG_X0)
        expected.append((pointer, bytes(cpu.mem_read(pointer, sizes.get(pointer, 4)))))
        return 0

    def model_free(pages, pointer):
        actual.append((pointer, bytes(oracle._read_span(pages, pointer, sizes.get(pointer, 4)))))

    _, memory, _, _ = oracle.native(
        library, base, 0x27E864, [child], native_pages, libc=libc,
        host_imports={0x347FA0: native_free}, instruction_limit=100000,
        extra_registers={arm.UC_ARM64_REG_TPIDR_EL0: GUEST + 0xD000})
    objects.destroy_signer_child(model, child_address=child,
                                 image_base=base, free=model_free)
    assert oracle.flatten(model)[:0xA000] == memory, (hex(base), profile, "memory")
    assert actual == expected, (hex(base), profile, "free order/pre-free bytes")
    return dict(image_base=hex(base), profile=profile, original_count=count,
                full_guest_window_match=True, free_order_and_pre_free_bytes_match=True,
                freed_blocks=len(actual), native_snapshot_input=False)


def _child_cleanup_guards(library, base):
    rows = []
    for label in ("nonempty_tree", "wrong_child_vtable", "unknown_container_vtable",
                  "missing_free", "missing_sentinel"):
        pages = oracle.fresh_pages()
        child, container, controller, sentinel, counter = _seed_empty_child(
            pages, image_base=base, count=1)
        if label == "nonempty_tree":
            oracle._write_span(pages, controller + 8, (1).to_bytes(8, "little"))
        elif label == "wrong_child_vtable":
            oracle._write_span(pages, child, (base + 0x35F7E0).to_bytes(8, "little"))
        elif label == "unknown_container_vtable":
            oracle._write_span(pages, container, (base + 0x35B7C0).to_bytes(8, "little"))
        elif label == "missing_sentinel":
            oracle._write_span(pages, controller, bytes(8))
        before = {k: bytes(v) for k, v in pages.items()}
        try:
            objects.destroy_signer_child(
                pages, child_address=child, image_base=base,
                free=None if label == "missing_free" else (lambda *_: None))
        except (objects.RefillUnsupported, ValueError):
            pass
        else:
            raise AssertionError(("child cleanup guard accepted", label))
        assert before == {k: bytes(v) for k, v in pages.items()}, label
        rows.append(dict(image_base=hex(base), profile=label,
                         all_pages_unchanged=True))
    return rows


def _child_assignment_case(library, libc, base):
    from unicorn import arm64_const as arm

    native_pages = oracle.fresh_pages()
    refs = _seed_case(native_pages)
    target = GUEST + 0x1000
    child, container, controller, sentinel, child_counter = _seed_empty_child(
        native_pages, image_base=base, count=1, address_base=0x5000)
    old_counter = GUEST + 0x4800
    oracle._write_span(native_pages, target, bytes(0x80))
    oracle._write_span(native_pages, target + 0x40,
                       child.to_bytes(8, "little") + old_counter.to_bytes(8, "little"))
    oracle._write_span(native_pages, old_counter, (1).to_bytes(4, "little"))
    model = {k: bytearray(v) for k, v in native_pages.items()}
    model.update(oracle.image_pages(library, base))
    expected, actual = [], []
    sizes = {old_counter: 4, child_counter: 4, child: 0x28,
             container: 0x28, controller: 0x28, sentinel: 0x28}
    def native_free(cpu):
        pointer = cpu.reg_read(arm.UC_ARM64_REG_X0)
        expected.append((pointer, bytes(cpu.mem_read(pointer, sizes.get(pointer, 4)))))
        return 0
    def model_free(pages, pointer):
        actual.append((pointer, bytes(oracle._read_span(pages, pointer, sizes.get(pointer, 4)))))
    _, memory, _, _ = oracle.native(
        library, base, 0x28508C, [target, refs["reference_40"][0]],
        native_pages, libc=libc, host_imports={0x347FA0: native_free},
        instruction_limit=100000,
        extra_registers={arm.UC_ARM64_REG_TPIDR_EL0: GUEST + 0xD000})
    objects.bind_signer_handler_reference_members(
        model, object_address=target, reference_30=refs["reference_30"][0],
        reference_40=refs["reference_40"][0], image_base=base, free=model_free)
    assert oracle.flatten(model)[:0xA000] == memory
    assert actual == expected
    return dict(image_base=hex(base), old_child_address=hex(child),
                full_guest_window_match=True, child_cleanup_order_match=True,
                freed_blocks=len(actual), native_snapshot_input=False)


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
    cleanup_cases = [_cleanup_case(args.library, args.libc, base, profile, count)
                     for base in BASES for profile, count in (
                         ("last_owner", 1), ("zero_count", 0),
                         ("signed_min", 0x80000000), ("negative_count", 0xFFFFFFFF),
                         ("null_old_object", 1), ("null_old_counter", 1),
                         ("free_mutates_source", 1), ("free_nulls_old_object", 1))]
    child_cleanup_cases = [_child_cleanup_case(
        args.library, args.libc, base, profile, count)
        for base in BASES for profile, count in (
            ("empty_container", 1), ("null_container", 1),
            ("retained_container", 2), ("signed_min", 0x80000000),
            ("negative_count", 0xFFFFFFFF))]
    child_assignment_cases = [_child_assignment_case(
        args.library, args.libc, base) for base in BASES]
    report = {
        "schema": "vm9-request-context-reference-members-20261102-v4",
        "sample_sha256": digest,
        "matching_libc_sha256": hashlib.sha256(args.libc.read_bytes()).hexdigest(),
        "cases": cases,
        "cleanup_cases": cleanup_cases,
        "child_cleanup_cases": child_cleanup_cases,
        "child_assignment_cases": child_assignment_cases,
        "native_controls": len(cases) * 3 + len(cleanup_cases) * 2 + len(child_cleanup_cases) * 2 + len(child_assignment_cases) * 2,
        "rollback_guards": _rollback_cases(),
        "cleanup_guards": [row for base in BASES
                           for row in _cleanup_guards(args.library, base)],
        "child_cleanup_guards": [row for base in BASES
                                 for row in _child_cleanup_guards(args.library, base)],
        "object_reference_members_verified": all(
            case["object_reference_members_verified"] for case in cases
        ),
        "signer_result_interpretation": False,
        "whole_request_native_differential_verified": False,
        "fresh_standalone_signer_verified": False,
        "online_header_acceptance_verified": False,
        "native_output_used_as_model_input": False,
        "diagnostic_scope_and_physical_stack_effects_verified": False,
        "configuration_and_null_final_owner_cleanup_supported": True,
        "arbitrary_final_owner_destruction_supported": False,
        "empty_signer_child_cleanup_supported": True,
        "child_cleanup_connected_to_reference_assignment": True,
        "nonempty_signer_child_cleanup_supported": False,
        "external_free_effects_rolled_back": False,
        "comparison_note": (
            "The service_refs handler's explicit +0x30/+0x40 callback-reference "
            "assignments match +0x28508c then +0x285094 on both image bases, "
            "including equal-pointee skips, retained releases, source/member "
            "aliases and uint32 increments. Explicit image/free services support "
            "configuration and NULL last-owner cleanup with native free order and "
            "pre-free bytes. Unknown deleting targets refuse; external free-provider "
            "effects are outside page rollback. Diagnostic scopes and physical "
            "stack writes remain excluded; no Java or signer semantics are inferred."
        ),
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("request-context reference members", len(cases), "assignment cases;",
          len(cleanup_cases), "reference cleanup;", len(child_cleanup_cases),
          "child cleanup cases PASS", flush=True)


if __name__ == "__main__":
    main()
