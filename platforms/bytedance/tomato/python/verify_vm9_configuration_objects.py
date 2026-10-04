"""Fresh-native differences for the 88-byte configuration object prefix.

Compare every guest object/allocation byte and loaded image page. Private
decoded constants stay in memory. The later parser initializer is excluded.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from unicorn.arm64_const import UC_ARM64_REG_X8

import vm9_objects as objects
from vm9_allocator import RefillUnsupported, _read_span, _write_span
from verify_vm9_signer_objects import Allocator, GUEST, LIBRARY_SHA256, fresh_pages, image_pages, native


def string_input(pages, address, data, *, length=None, pointer=GUEST + 0x2800):
    if length is None:
        length = len(data)
    # Capacity/vtable are deliberately unrelated: the clone reads only length
    # and, after allocation, payload. Embedded NUL is part of declared bytes.
    _write_span(pages, address, bytes(8) + (777).to_bytes(4, "little")
                + length.to_bytes(4, "little") + pointer.to_bytes(8, "little"))
    if data:
        _write_span(pages, pointer, data)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--libc", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == LIBRARY_SHA256
    cases, negatives = [], []

    def compare(label, base, pages, entry, arguments, operation, *, stop=None, registers=None,
                effect=None, check_result=False, mutexes=False):
        observed = {(page << 12, 4096): None for page in pages
                    if not GUEST <= page << 12 < GUEST + 0x10000}
        result, expected, allocations, ledger = native(args.library, base, entry, arguments,
            pages, libc=args.libc, observed_memory=observed, stop_offset=stop,
            extra_registers=registers, allocation_effect=effect, real_mutexes=mutexes)
        allocator = Allocator()
        actual_result = operation(allocator)
        actual = _read_span(pages, GUEST, 0xA000)
        if actual != expected:
            first = next(i for i, (a, b) in enumerate(zip(actual, expected)) if a != b)
            raise AssertionError(f"{label}: mismatch at guest+{first:#x}: {actual[first]:#x} != {expected[first]:#x}")
        assert allocator.calls == allocations, label + " allocation sequence"
        for (address, width), data in observed.items():
            assert _read_span(pages, address, width) == data, label + " image page"
        if check_result:
            assert actual_result == result, label + " return value"
        if mutexes:
            assert [item[0] for item in ledger] == ["pthread_mutex_lock", "pthread_mutex_unlock"]
        cases.append({"case": label, "image_base": hex(base), "memory_match": True,
                      "all_image_pages_match": True, "allocation_sequence_match": True,
                      "allocations": len(allocations), "normal_mutex_pair_verified": mutexes})
        return actual_result

    for base in (0x122C0000, 0x775C205000):
        for target_offset in (0x1000, 0x1FF8):
            target, source = GUEST + target_offset, GUEST + 0x3000
            for label, data, length in (("empty", b"", 0), ("embedded_zero", b"a\0b", 3),
                                        ("utf8", "配置".encode(), 6),
                                        ("long", b"x" * 240, 240),
                                        ("negative_min", b"", 0x80000000),
                                        ("negative_minus_one", b"", 0xFFFFFFFF)):
                pages = fresh_pages()
                string_input(pages, source, data, length=length, pointer=0 if length >= 0x80000000 else GUEST + 0x2800)
                compare("clone_" + label, base, pages, 0x2483E0, [target, source],
                    lambda a: objects.clone_string_object(pages, object_address=target,
                        source_object_address=source, image_base=base, allocate=a.model), check_result=True)

            pages = fresh_pages()
            string_input(pages, source, b"abcd")
            _write_span(pages, GUEST + 0x2900, b"WXYZ")
            def mutate_native(cpu, size, pointer):
                cpu.mem_write(source + 12, (1).to_bytes(4, "little"))
                cpu.mem_write(source + 16, (GUEST + 0x2900).to_bytes(8, "little"))
            def mutated_model(a):
                def allocate(staged, size):
                    pointer = a.model(staged, size)
                    _write_span(staged, source + 12, (1).to_bytes(4, "little"))
                    _write_span(staged, source + 16, (GUEST + 0x2900).to_bytes(8, "little"))
                    return pointer
                return objects.clone_string_object(pages, object_address=target,
                    source_object_address=source, image_base=base, allocate=allocate)
            compare("clone_length_saved_pointer_read_after_allocation", base, pages, 0x2483E0,
                    [target, source], mutated_model, effect=mutate_native, check_result=True)

            for length in (0, 0xFFFFFFFF):
                pages = fresh_pages()
                string_input(pages, target, b"", length=length)
                compare("clone_self_alias_" + hex(length), base, pages, 0x2483E0, [target, target],
                    lambda a: objects.clone_string_object(pages, object_address=target,
                        source_object_address=target, image_base=base, allocate=a.model), check_result=True)

            pages = fresh_pages()
            compare("container_reference_48", base, pages, 0x25C8FC, [],
                lambda a: objects.construct_configuration_container_reference(pages,
                    object_address=target, image_base=base, allocate=a.model),
                registers={UC_ARM64_REG_X8: target})

            for flag in (0, 1, 7):
                for payloads in ((b"", b""), (b"a\0b", b"input"), (b"x" * 240, b"four")):
                    pages = fresh_pages()
                    pages.update(image_pages(args.library, base))
                    first, second = GUEST + 0x3000, GUEST + 0x3020
                    string_input(pages, first, payloads[0], pointer=GUEST + 0x2800)
                    string_input(pages, second, payloads[1], pointer=GUEST + 0x2C00)
                    _write_span(pages, base + 0x3DEB68, flag.to_bytes(4, "little"))
                    layout = compare(f"object88_prefix_flag_{flag}_lengths_{len(payloads[0])}_{len(payloads[1])}",
                        base, pages, 0x26194C, [target, first, second, 0],
                        lambda a: objects.construct_configuration_object_layout(pages,
                            object_address=target, first_string_address=first, second_string_address=second,
                            image_base=base, allocate=a.model), stop=0x261A1C)
                    assert len(layout.reference_count_addresses) == 3
                    assert cases[-1]["allocations"] == 9
                    cases[-1]["initializer_executed"] = False

            for shared in (0, 0x2000):
                for acquire, counts in ((True, (0, 1, 7, 0x7FFFFFFE)), (False, (1, 2, 7, 0x7FFFFFFE))):
                    for count in counts:
                        pages = fresh_pages()
                        _write_span(pages, target, shared.to_bytes(2, "little"))
                        _write_span(pages, target + 0x88, count.to_bytes(4, "little"))
                        model = objects.acquire_uncontended_shared_reader if acquire else objects.release_uncontended_shared_reader
                        updated = compare(f"reader_{'acquire' if acquire else 'release'}_{shared:x}_{count:x}",
                            base, pages, 0x32A444 if acquire else 0x32A4FC, [target],
                            lambda a: model(pages, mutex_address=target), mutexes=True)
                        assert updated == count + (1 if acquire else -1)

    def reject(label, pages, operation):
        before = {page: bytes(data) for page, data in pages.items()}
        try:
            operation()
        except (RefillUnsupported, ValueError):
            assert before == {page: bytes(data) for page, data in pages.items()}, label + " rollback"
        else:
            raise AssertionError(label + " did not reject")
        negatives.append({"case": label, "rejected": True, "pages_unchanged": True})

    base = 0x122C0000
    for acquire, counts in ((True, (0x7FFFFFFF, 0x80000000, 0xFFFFFFFF)),
                            (False, (0, 0x7FFFFFFF, 0x80000000, 0x80000001, 0xFFFFFFFF))):
        for count in counts:
            pages = fresh_pages()
            target = GUEST + 0x1000
            _write_span(pages, target, bytes(2))
            _write_span(pages, target + 0x88, count.to_bytes(4, "little"))
            model = objects.acquire_uncontended_shared_reader if acquire else objects.release_uncontended_shared_reader
            reject(f"reader_{acquire}_{count:x}", pages, lambda: model(pages, mutex_address=target))
    for target in (GUEST + 0x1000, GUEST + 0xFF80):
        pages = fresh_pages()
        _write_span(pages, target, (1 if target == GUEST + 0x1000 else 0).to_bytes(2, "little"))
        reject("reader_mutex_or_missing_count_" + hex(target - GUEST), pages,
               lambda: objects.acquire_uncontended_shared_reader(pages, mutex_address=target))

    for label, length, pointer, bound, allocator in (
            ("bound", 4, GUEST + 0x2800, 3, Allocator().model),
            ("missing_payload", 4, GUEST + 0x10000, 100, Allocator().model),
            ("missing_allocated_page", 4, GUEST + 0x2800, 100, lambda p, s: GUEST + 0x10000),
            ("invalid_bound", 4, GUEST + 0x2800, -1, Allocator().model)):
        pages = fresh_pages()
        string_input(pages, GUEST + 0x3000, b"", length=length, pointer=pointer)
        reject("clone_" + label, pages, lambda: objects.clone_string_object(pages,
            object_address=GUEST + 0x1000, source_object_address=GUEST + 0x3000,
            image_base=base, allocate=allocator, max_payload_bytes=bound))

    # malloc failure is a supported clone result, unlike operator-new failure.
    pages = fresh_pages()
    string_input(pages, GUEST + 0x3000, b"abcd")
    assert objects.clone_string_object(pages, object_address=GUEST + 0x1000,
        source_object_address=GUEST + 0x3000, image_base=base, allocate=lambda p, s: 0) == 0
    assert _read_span(pages, GUEST + 0x1008, 16) == (5).to_bytes(4, "little") + (4).to_bytes(4, "little") + bytes(8)

    for failure_index in range(9):
        pages = fresh_pages()
        pages.update(image_pages(args.library, base))
        string_input(pages, GUEST + 0x3000, b"abcd")
        allocator = Allocator()
        def fail(staged, size):
            # Clone malloc failures (indices 1/4) succeed; all other new/count
            # allocations fail closed. Force an unmapped pointer for the clones.
            if len(allocator.calls) == failure_index:
                return GUEST + 0x10000 if failure_index in (1, 4) else 0
            return allocator.model(staged, size)
        reject(f"object88_allocation_{failure_index}", pages,
            lambda: objects.construct_configuration_object_layout(pages,
                object_address=GUEST + 0x1000, first_string_address=GUEST + 0x3000,
                second_string_address=GUEST + 0x3000, image_base=base, allocate=fail))

    report = {"fresh_memory": True, "captured_pages_used": False, "jvm_used": False,
              "library_sha256": LIBRARY_SHA256, "libc_sha256": hashlib.sha256(args.libc.read_bytes()).hexdigest(),
              "differential_cases": len(cases), "negative_cases": len(negatives),
              "cases": cases, "negatives": negatives, "clone_malloc_null_python_check": True,
              "scope": "declared_length_clone_48_byte_container_88_byte_prefix_and_serialized_readers",
              "complete_88_byte_initializer": False, "complete_python_medusa": False}
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"differential_cases": len(cases), "negative_cases": len(negatives)}))


if __name__ == "__main__":
    main()
