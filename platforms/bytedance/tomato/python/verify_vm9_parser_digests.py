"""Fresh native differences for parser digests and single-byte string append.

Only synthetic inputs are used. Export counts, offsets and comparisons;
digest bytes, ELF alphabets and guest snapshots remain private.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X8

import vm9_objects as objects
from vm9_allocator import _PageTransaction, _read_span, _write_span, RefillUnsupported
from verify_vm9_configuration_objects import string_input
from verify_vm9_signer_objects import GUEST, LIBRARY_SHA256, fresh_pages, image_pages, native
from verify_vm9_strings import Effects, fields


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == LIBRARY_SHA256
    cases, negatives = [], []

    def compare(label, base, pages, entry, arguments, operation, *, registers=None,
                blocks=(), failures=(), inplace=False, mutate=None, check_result=False):
        # Leave physical room for in-place realloc; an allocator cannot grow
        # a payload over another live allocation (such as the reference count).
        spacing = 128 if inplace else 16
        expected = Effects(blocks=blocks, failures=failures, inplace=inplace, mutate=mutate, minimum_spacing=spacing)
        actual = Effects(blocks=blocks, failures=failures, inplace=inplace, mutate=mutate, minimum_spacing=spacing)
        observed = {(page << 12, 4096): None for page in pages
                    if not GUEST <= page << 12 < GUEST + 0x10000}
        result, memory, _, _ = native(args.library, base, entry, arguments, pages,
            extra_registers=registers, observed_memory=observed, instruction_limit=100000,
            malloc_handler=lambda cpu, size: expected.native(cpu, "malloc", size),
            host_imports={
                0x347FA0: lambda cpu: expected.native(cpu, "free", pointer=cpu.reg_read(UC_ARM64_REG_X0)),
                0x348320: lambda cpu: expected.native(cpu, "realloc", cpu.reg_read(UC_ARM64_REG_X1), cpu.reg_read(UC_ARM64_REG_X0)),
            })
        try:
            modeled_result = operation(actual)
        except Exception as exc:
            raise AssertionError(label + ": " + str(exc)) from exc
        got = _read_span(pages, GUEST, 0xA000)
        if got != memory:
            first = next(i for i, (a, b) in enumerate(zip(got, memory)) if a != b)
            raise AssertionError(f"{label}: guest+{first:#x} {got[first]:#x} != {memory[first]:#x}")
        assert expected.calls == actual.calls, (label, "effect order", expected.calls, actual.calls)
        assert expected.blocks == actual.blocks, (label, "allocator state")
        assert all(_read_span(pages, a, n) == data for (a, n), data in observed.items()), label + " image pages"
        if check_result:
            assert modeled_result & 0xFFFFFFFF == result & 0xFFFFFFFF, (label, modeled_result, result)
        cases.append({"case": label, "image_base": hex(base), "guest_bytes_match": True,
            "all_main_image_pages_match": True, "allocator_state_match": True, "effect_order_match": True,
            "native_result_checked": check_result,
            "effects": [{"kind": c[0], "size": c[1]} if c[0] != "free" else {"kind": "free"}
                        for c in actual.calls]})

    for base in (0x122C0000, 0x775C205000):
        for capacity, length, failures, inplace in (
            (8, 0, (), False), (8, 6, (), False), (8, 7, (), False),
            (8, 8, (), True), (8, 6, (0,), False), (8, 7, (0, 1), False),
            (8, 7, (0, 1, 2), False), (8, 0x80000000, (), False),
        ):
            pages = fresh_pages()
            destination, pointer = GUEST + 0x1FF8, GUEST + 0x2800
            fields(pages, destination, capacity, length, pointer)
            _write_span(pages, pointer, b"abcdefgh\0" + bytes(32))
            def append(e):
                staged = _PageTransaction(pages)
                status = objects._append_string_byte(staged, destination, 0xE9,
                    e.malloc, e.realloc, e.free, 0x100000)
                staged.commit()
                return status
            compare(f"byte_{capacity}_{length:x}_{failures}_{inplace}", base, pages,
                0x246DD4, [destination, 0xE9], append, blocks=[(pointer, 48)],
                failures=failures, inplace=inplace, check_result=True)

        for entry, algorithm in ((0x25874C, "md5"), (0x258780, "sha1")):
            profiles = [("empty", b""), ("short", b"abc"), ("binary", bytes(range(64))),
                        ("multi_block", b"x" * 129), ("embedded_zero", b"a\0b\0c")]
            scenarios = [(label, data, flag, (), False, None, False)
                         for label, data in profiles for flag in (0, 1, 2, 3)]
            scenarios += [("raw_payload_null", b"abc", 0, (1,), False, None, False),
                          ("hex_empty_payload_null", b"abc", 1, (1,), False, None, False),
                          ("hex_malloc_null_realloc_moves", b"abc", 1, (3,), False, None, False),
                          ("hex_malloc_null_realloc_inplace", b"abc", 1, (3,), True, None, False),
                          ("hex_rounded_retry_exact", b"abc", 1, (3, 4), False, None, False),
                          ("hex_initial_growth_fails", b"abc", 1, (3, 4, 5), False, None, False),
                          ("null_source_empty", b"", 0, (), False, None, True)]
            if algorithm == "md5":
                scenarios += [("null_source_nonzero_length", b"abc", 1, (), False, None, True)]

            for label, data, flag, failures, inplace, _, null_pointer in scenarios:
                pages = fresh_pages()
                pages.update(image_pages(args.library, base))
                source, target = GUEST + 0x1FF8, GUEST + 0x1000
                string_input(pages, source, data, pointer=GUEST + 0x2FF8)
                if null_pointer:
                    _write_span(pages, source + 16, bytes(8))
                compare(f"{algorithm}_{label}_{flag}", base, pages, entry, [source, flag],
                    lambda e: objects.construct_digest_reference(pages, object_address=target,
                        source_object_address=source, algorithm=algorithm, flag=flag, image_base=base,
                        allocate=e.malloc, reallocate=e.realloc, free=e.free),
                    registers={UC_ARM64_REG_X8: target}, failures=failures, inplace=inplace)

            for change in ("alphabet", "got", "input_after_hash", "reference_before_publish"):
                pages = fresh_pages()
                pages.update(image_pages(args.library, base))
                source, target = GUEST + 0x1FF8, GUEST + 0x1000
                string_input(pages, source, b"abc", pointer=GUEST + 0x2FF8)
                alphabet = int.from_bytes(_read_span(pages, base + 0x37A068, 8), "little")
                _write_span(pages, GUEST + 0x3200, b"0123456789ABCDEF")
                def mutate(kind, index, read, write):
                    if kind == "malloc" and index == 3:
                        if change == "alphabet":
                            write(alphabet, b"0123456789ABCDEF")
                        elif change == "got":
                            write(base + 0x37A068, (GUEST + 0x3200).to_bytes(8, "little"))
                        elif change == "input_after_hash":
                            write(GUEST + 0x2FF8, b"xyz")
                        else:
                            assert read(target, 16) == bytes(16), "hex reference published before conversion"
                compare(f"{algorithm}_{change}", base, pages, entry, [source, 1],
                    lambda e: objects.construct_digest_reference(pages, object_address=target,
                        source_object_address=source, algorithm=algorithm, flag=1, image_base=base,
                        allocate=e.malloc, reallocate=e.realloc, free=e.free),
                    registers={UC_ARM64_REG_X8: target}, mutate=mutate)

    def reject(label, pages, **options):
        before = {p: bytes(b) for p, b in pages.items()}
        e = Effects(blocks={})
        try:
            objects.construct_digest_reference(pages, object_address=GUEST + 0x1000,
                source_object_address=GUEST + 0x1FF8, image_base=0x122C0000,
                allocate=e.malloc, reallocate=e.realloc, free=e.free, **options)
        except (RefillUnsupported, ValueError):
            assert before == {p: bytes(b) for p, b in pages.items()}
            negatives.append({"case": label, "rejected": True, "page_rollback": True})
        else:
            raise AssertionError(label + " accepted")

    for label, opts, drop in (
        ("unknown_algorithm", {"algorithm": "sha256", "flag": 0}, None),
        ("negative_flag", {"algorithm": "md5", "flag": -1}, None),
        ("source_bound", {"algorithm": "md5", "flag": 0, "max_source_bytes": 2}, None),
        ("missing_payload", {"algorithm": "md5", "flag": 0}, (GUEST + 0x3000) >> 12),
        ("missing_alphabet", {"algorithm": "md5", "flag": 1}, "alphabet"),
    ):
        pages = fresh_pages()
        pages.update(image_pages(args.library, 0x122C0000))
        string_input(pages, GUEST + 0x1FF8, b"abc", pointer=GUEST + 0x3800)
        if drop == "alphabet":
            drop = int.from_bytes(_read_span(pages, 0x122C0000 + 0x37A068, 8), "little") >> 12
        if drop is not None:
            del pages[drop]
        reject(label, pages, **opts)

    report = {"fresh_memory": True, "synthetic_inputs_only": True, "captured_pages_used": False,
        "jvm_used": False, "library_sha256": LIBRARY_SHA256,
        "differential_cases": len(cases), "negative_cases": len(negatives), "cases": cases,
        "negatives": negatives, "allocator_boundary": "explicit_malloc_realloc_free_effects",
        "complete_88_byte_initializer": False, "complete_python_medusa": False}
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"differential_cases": len(cases), "negative_cases": len(negatives)}))


if __name__ == "__main__":
    main()
