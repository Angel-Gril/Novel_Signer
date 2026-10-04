"""Native differences for configuration base64, sized strings and references.

Fresh synthetic inputs and private ELF lookup tables; decoded text is never
exported. Free is an explicit nonreusing allocator boundary in this verifier.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X8

import vm9_objects as objects
from vm9_allocator import RefillUnsupported, _read_span, _write_span
from verify_vm9_signer_objects import Allocator, GUEST, LIBRARY_SHA256, fresh_pages, image_pages, native
from verify_vm9_configuration_objects import string_input


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == LIBRARY_SHA256
    cases, negatives = [], []

    def compare(label, base, pages, entry, arguments, operation, *, registers=None,
                check_status=False, native_free=None):
        observed = {(page << 12, 4096): None for page in pages
                    if not GUEST <= page << 12 < GUEST + 0x10000}
        result, expected, allocations, _ = native(args.library, base, entry, arguments, pages,
            observed_memory=observed, extra_registers=registers,
            host_imports={0x347FA0: native_free} if native_free else None)
        allocator = Allocator()
        actual_result = operation(allocator)
        actual = _read_span(pages, GUEST, 0xA000)
        if actual != expected:
            first = next(i for i, (a, b) in enumerate(zip(actual, expected)) if a != b)
            raise AssertionError(f"{label}: mismatch at guest+{first:#x}: {actual[first]:#x} != {expected[first]:#x}")
        assert allocator.calls == allocations, label + " allocation sequence"
        for (address, width), data in observed.items():
            assert _read_span(pages, address, width) == data, label + " image pages"
        if check_status:
            assert actual_result & 0xFFFFFFFF == result, label + " w0 status"
        cases.append({"case": label, "image_base": hex(base), "memory_match": True,
                      "all_image_pages_match": True, "allocation_sequence_match": True,
                      "allocations": len(allocations)})

    profiles = (("empty", b""), ("spaces", b"   "), ("linebreaks", b"\r\n\n"),
                ("one", b"TQ=="), ("two", b"TWE="), ("three", b"TWFu"),
                ("two_groups", b"TWFuTQ=="), ("one_partial", b"T"),
                ("two_partial", b"TQ"), ("three_partial", b"TWE"),
                ("padding_only", b"=="), ("leading_space", b" TQ=="),
                ("trailing_space", b"TQ==   "), ("space_before_newline", b"TQ== \r\n"),
                ("newline_inside_group", b"T\nQ=="), ("bare_cr", b"TQ==\r"),
                ("tab", b"TQ==\t"), ("internal_space", b"T Q=="),
                ("too_much_padding", b"TQ==="), ("digit_after_padding", b"TQ==A"),
                ("invalid_ascii", b"TQ$="), ("high_bit", b"TQ\x80="),
                ("binary", base64.b64encode(bytes(range(64)))))
    for base in (0x122C0000, 0x775C205000):
        for label, data in profiles:
            for mode in ("buffer", "query", "small"):
                pages = fresh_pages()
                pages.update(image_pages(args.library, base))
                source, slot = GUEST + 0x2800, GUEST + 0x3000
                _write_span(pages, source, data)
                output = 0 if mode == "query" else GUEST + 0x1FFE
                capacity = 0 if mode == "small" else 128
                compare("base64_" + label + "_" + mode, base, pages, 0x245814,
                    [output, capacity, slot, source, len(data)],
                    lambda a: objects.decode_configuration_base64(pages,
                        destination_address=output, destination_size=capacity, length_address=slot,
                        source_address=source, source_size=len(data), image_base=base), check_status=True)
        for delta in (-2, 0, 1):
            pages = fresh_pages()
            pages.update(image_pages(args.library, base))
            source, slot = GUEST + 0x1FFE, GUEST + 0x3000
            data = b"TWFuTQ=="
            _write_span(pages, source, data)
            compare("base64_alias_" + str(delta), base, pages, 0x245814,
                [source + delta, 128, slot, source, len(data)],
                lambda a: objects.decode_configuration_base64(pages,
                    destination_address=source + delta, destination_size=128, length_address=slot,
                    source_address=source, source_size=len(data), image_base=base), check_status=True)
        for length, data in ((0, b""), (3, b"a\0b"), (240, b"x" * 240),
                             (0x80000000, b""), (0xFFFFFFFF, b"")):
            pages = fresh_pages()
            source, target = GUEST + 0x2800, GUEST + 0x1FF8
            _write_span(pages, source, data)
            compare("sized_string_" + hex(length), base, pages, 0x2481FC, [target, source, length],
                lambda a: objects.construct_sized_string_object(pages, object_address=target,
                    source_address=source, length=length, image_base=base, allocate=a.model))
        for label, data in profiles:
            pages = fresh_pages()
            pages.update(image_pages(args.library, base))
            source, target = GUEST + 0x3000, GUEST + 0x1FF8
            string_input(pages, source, data)
            native_frees, model_frees = [], []
            def free_native(cpu):
                native_frees.append(cpu.reg_read(UC_ARM64_REG_X0))
                return 0
            def free_model(staged, pointer):
                model_frees.append(pointer)
            compare("decoded_reference_" + label, base, pages, 0x258E7C, [source],
                lambda a: objects.construct_decoded_configuration_reference(pages,
                    object_address=target, source_object_address=source, image_base=base,
                    allocate=a.model, free=free_model),
                registers={UC_ARM64_REG_X8: target}, native_free=free_native)
            assert native_frees == model_frees and len(model_frees) == 1
            cases[-1]["free_sequence_match"] = True

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
    for missing in ("table", "source", "destination", "length"):
        pages = fresh_pages()
        if missing != "table":
            pages.update(image_pages(args.library, base))
        source, output, slot = GUEST + 0x2800, GUEST + 0x1FFF, GUEST + 0x3000
        _write_span(pages, source, b"TWFu")
        if missing == "source": source = GUEST + 0x10000
        if missing == "destination": output = GUEST + 0xFFFF  # fails after the first byte
        if missing == "length": slot = GUEST + 0x10000  # fails after decoded bytes
        reject("base64_missing_" + missing, pages, lambda: objects.decode_configuration_base64(
            pages, destination_address=output, destination_size=8, length_address=slot,
            source_address=source, source_size=4, image_base=base))
    for length in (-1, 0x100001):
        pages = fresh_pages()
        reject("base64_bound_" + str(length), pages, lambda: objects.decode_configuration_base64(
            pages, destination_address=GUEST, destination_size=8, length_address=GUEST + 0x3000,
            source_address=GUEST + 0x2800, source_size=length, image_base=base))
    for stage in (0, 1, 2, 3):
        pages = fresh_pages()
        pages.update(image_pages(args.library, base))
        string_input(pages, GUEST + 0x3000, b"TWFu")
        allocator = Allocator()
        def fail(staged, size):
            return GUEST + 0x10000 if len(allocator.calls) == stage else allocator.model(staged, size)
        reject("decoded_reference_allocation_" + str(stage), pages,
            lambda: objects.construct_decoded_configuration_reference(pages,
                object_address=GUEST + 0x1000, source_object_address=GUEST + 0x3000,
                image_base=base, allocate=fail, free=lambda p, s: None))
    pages = fresh_pages()
    pages.update(image_pages(args.library, base))
    string_input(pages, GUEST + 0x3000, b"TWFu")
    def failing_free(staged, pointer):
        _write_span(staged, pointer, b"x")
        raise RefillUnsupported("unsupported free")
    reject("decoded_reference_free", pages, lambda: objects.construct_decoded_configuration_reference(
        pages, object_address=GUEST + 0x1000, source_object_address=GUEST + 0x3000,
        image_base=base, allocate=Allocator().model, free=failing_free))

    report = {"fresh_memory": True, "captured_pages_used": False, "jvm_used": False,
              "library_sha256": LIBRARY_SHA256, "differential_cases": len(cases),
              "negative_cases": len(negatives), "cases": cases, "negatives": negatives,
              "free_boundary": "explicit_nonreusing_allocator", "complete_88_byte_initializer": False,
              "complete_python_medusa": False}
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"differential_cases": len(cases), "negative_cases": len(negatives)}))


if __name__ == "__main__":
    main()
