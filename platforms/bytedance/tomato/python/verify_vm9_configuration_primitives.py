"""Fresh-memory native differences for masked bytes and normal mutexes.

Private ELF strings are compared in memory and never written to the report.
This proves components, not complete root configuration or Medusa startup.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from unicorn.arm64_const import UC_ARM64_REG_X5

import vm9_objects as objects
from vm9_allocator import RefillUnsupported, _read_span, _write_span
from verify_vm9_signer_objects import Allocator, GUEST, LIBRARY_SHA256, fresh_pages, image_pages, native


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--libc", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == LIBRARY_SHA256
    cases, negatives = [], []

    for base in (0x122C0000, 0x775C205000):
        def compare_decode(pages, source, destination, mask, label, bound=4096):
            observed = {(page << 12, 4096): None for page in pages
                        if not GUEST <= page << 12 < GUEST + 0x10000}
            _, expected, calls, _ = native(args.library, base, 0x167E54,
                [source, destination, mask], pages, observed_memory=observed)
            count = objects.decode_masked_bytes(pages, source_address=source,
                destination_address=destination, mask_address=mask, max_bytes=bound)
            assert _read_span(pages, GUEST, 0xA000) == expected, label
            assert calls == [], label
            for (address, width), data in observed.items():
                assert _read_span(pages, address, width) == data, label
            cases.append({"case": label, "image_base": hex(base),
                          "memory_match": True, "written_bytes": count})

        for length in (0, 1, 4, 31, 255):
            for target in (GUEST + 0x1000, GUEST + 0x1FF8):
                pages = fresh_pages()
                source, mask = GUEST + 0x2800, GUEST + 0x3000
                _write_span(pages, source, bytes((i * 37 + 11) & 255 for i in range(length)))
                _write_span(pages, mask, bytes((i % 255) + 1 for i in range(length)) + b"\0")
                compare_decode(pages, source, target, mask,
                               f"synthetic_length_{length}_{target - GUEST:x}", length)

        for kind, delta in (("source", -1), ("source", 0), ("source", 1),
                            ("mask", -1), ("mask", 0), ("mask", 1)):
            pages = fresh_pages()
            source, mask = GUEST + 0x2000, GUEST + 0x3000
            _write_span(pages, source, bytes(8) + b"\1" + bytes(40))
            _write_span(pages, mask, b"\1\3\5\0" + bytes(40))
            target = (source if kind == "source" else mask) + delta
            compare_decode(pages, source, target, mask, f"alias_{kind}_{delta}", 32)

        pages = fresh_pages()
        _write_span(pages, GUEST + 0x1000, b"\0")
        compare_decode(pages, 0, 0, GUEST + 0x1000, "zero_mask_unmapped_source_and_output", 0)

        for source, mask in ((0xA62C8, 0xA6534), (0xA62D0, 0xA6440), (0xA5A60, 0xA5A80)):
            pages = fresh_pages()
            pages.update(image_pages(args.library, base))
            compare_decode(pages, base + source, GUEST + 0x1FF8,
                           base + mask, f"elf_constants_{source:x}")

        for shared in (0, 0x2000):
            for target_offset in (0x1000, 0x1FFE):
                pages = fresh_pages()
                target = GUEST + target_offset
                _write_span(pages, target, shared.to_bytes(2, "little"))
                for lock, entry in ((True, 0x347F00), (False, 0x347F10)):
                    result, expected, calls, ledger = native(args.library, base, entry,
                        [target], pages, libc=args.libc, real_mutexes=True)
                    model = objects.lock_uncontended_mutex if lock else objects.unlock_uncontended_mutex
                    assert model(pages, mutex_address=target) == result == 0
                    assert _read_span(pages, GUEST, 0xA000) == expected
                    assert not calls
                    assert ledger == [["pthread_mutex_lock" if lock else "pthread_mutex_unlock", target]]
                    cases.append({"case": "normal_mutex_lock" if lock else "normal_mutex_unlock",
                                  "image_base": hex(base), "shared_bit": bool(shared),
                                  "at_page_end": target_offset == 0x1FFE, "memory_match": True})

        for target_offset in (0x1000, 0x1FF8):
            for variant, flag in (("independent", 5), ("null_counts", 0),
                                  ("count_overflow", 0xFFFF_FFFF), ("shared_reference", 7)):
                pages = fresh_pages()
                pages.update(image_pages(args.library, base))
                sources = [GUEST + 0xA100 + index * 0x20 for index in range(3)]
                for index, source in enumerate(sources):
                    counter = 0 if variant == "null_counts" else GUEST + 0x3800 + index * 0x10
                    _write_span(pages, source, (GUEST + 0xA800 + index * 0x20).to_bytes(8, "little")
                                + counter.to_bytes(8, "little"))
                    if counter:
                        count = 0xFFFF_FFFF if variant == "count_overflow" else index + 7
                        _write_span(pages, counter, count.to_bytes(4, "little"))
                if variant == "shared_reference":
                    sources = [sources[0]] * 3
                target = GUEST + target_offset
                observed = {(page << 12, 4096): None for page in pages
                            if not GUEST <= page << 12 < GUEST + 0x10000}
                _, expected, calls, _ = native(args.library, base, 0x257084,
                    [target, *sources, 0], pages, libc=args.libc,
                    extra_registers={UC_ARM64_REG_X5: flag}, stop_offset=0x257240,
                    observed_memory=observed)
                allocator = Allocator()
                layout = objects.construct_root_configuration_layout(pages,
                    object_address=target, initial_reference_address=sources[0],
                    first_reference_address=sources[1], second_reference_address=sources[2],
                    flag=flag, image_base=base, allocate=allocator.model)
                actual = _read_span(pages, GUEST, 0xA000)
                if actual != expected:
                    first = next(i for i, (a, b) in enumerate(zip(actual, expected)) if a != b)
                    raise AssertionError(f"{variant}: prefix guest mismatch at +{first:#x}: {actual[first]:#x} != {expected[first]:#x}")
                assert allocator.calls == calls and len(calls) == 30
                for (address, width), data in observed.items():
                    assert _read_span(pages, address, width) == data
                assert len(layout.container_addresses) == 2 and len(layout.string_addresses) == 6
                cases.append({"case": "root_configuration_prefix_" + variant,
                              "image_base": hex(base), "cross_page": target_offset == 0x1FF8,
                              "memory_match": True, "allocation_sequence_match": True,
                              "allocations": len(calls), "initializer_executed": False})

    def reject(label, pages, operation):
        original = {page: bytes(data) for page, data in pages.items()}
        try:
            operation()
        except (RefillUnsupported, ValueError):
            assert original == {page: bytes(data) for page, data in pages.items()}
        else:
            raise AssertionError(label + " did not reject")
        negatives.append({"case": label, "rejected": True, "pages_unchanged": True})

    for bad in (-1, 0x100001):
        pages = fresh_pages()
        reject(f"decoder_invalid_bound_{bad}", pages, lambda: objects.decode_masked_bytes(
            pages, source_address=GUEST, destination_address=GUEST + 0x1000,
            mask_address=GUEST + 0x2000, max_bytes=bad))
    pages = fresh_pages()
    reject("decoder_bound_after_partial_write", pages, lambda: objects.decode_masked_bytes(
        pages, source_address=GUEST, destination_address=GUEST + 0x1000,
        mask_address=GUEST + 0x2000, max_bytes=2))
    for missing in ("source", "destination", "mask"):
        pages = fresh_pages()
        addresses = {"source": GUEST, "destination": GUEST + 0x1000, "mask": GUEST + 0x2000}
        addresses[missing] = GUEST + 0x10000
        reject("decoder_missing_" + missing, pages, lambda: objects.decode_masked_bytes(
            pages, source_address=addresses["source"], destination_address=addresses["destination"],
            mask_address=addresses["mask"]))
    for lock, states in ((True, (1, 2, 3, 0x4000, 0x8000, 0xFFFF)),
                         (False, (0, 2, 3, 0x4001, 0x8001, 0xFFFF))):
        for state in states:
            pages = fresh_pages()
            _write_span(pages, GUEST + 0x1000, state.to_bytes(2, "little"))
            model = objects.lock_uncontended_mutex if lock else objects.unlock_uncontended_mutex
            reject(f"mutex_{'lock' if lock else 'unlock'}_state_{state:x}", pages,
                   lambda: model(pages, mutex_address=GUEST + 0x1000))
    for target in (GUEST + 1, GUEST + 0x10000):
        pages = fresh_pages()
        reject(f"mutex_invalid_address_{target - GUEST:x}", pages,
               lambda: objects.lock_uncontended_mutex(pages, mutex_address=target))

    for failure_index in (0, 15, 29):
        pages = fresh_pages()
        base = 0x122C0000
        pages.update(image_pages(args.library, base))
        _write_span(pages, GUEST + 0x3000, bytes(16))
        allocator = Allocator()
        def fail(staged, size):
            return 0 if len(allocator.calls) == failure_index else allocator.model(staged, size)
        reject(f"configuration_prefix_allocation_{failure_index}", pages,
            lambda: objects.construct_root_configuration_layout(pages,
                object_address=GUEST + 0x1000, initial_reference_address=GUEST + 0x3000,
                first_reference_address=GUEST + 0x3000, second_reference_address=GUEST + 0x3000,
                flag=5, image_base=base, allocate=fail))
    for flag in (-1, 0x100000000):
        pages = fresh_pages()
        reject(f"configuration_invalid_flag_{flag}", pages,
            lambda: objects.construct_root_configuration_layout(pages,
                object_address=GUEST, initial_reference_address=GUEST + 0x3000,
                first_reference_address=GUEST + 0x3000, second_reference_address=GUEST + 0x3000,
                flag=flag, image_base=base, allocate=Allocator().model))

    report = {"fresh_memory": True, "captured_pages_used": False, "jvm_used": False,
              "library_sha256": LIBRARY_SHA256,
              "libc_sha256": hashlib.sha256(args.libc.read_bytes()).hexdigest(),
              "differential_cases": len(cases), "negative_cases": len(negatives),
              "cases": cases, "negatives": negatives,
              "scope": "masked_bytes_uncontended_mutex_and_root_configuration_prefix",
              "complete_root_constructor": False, "complete_python_medusa": False}
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"differential_cases": len(cases), "negative_cases": len(negatives)}))


if __name__ == "__main__":
    main()
