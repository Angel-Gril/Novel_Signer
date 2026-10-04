"""Fresh native checks for 136/320-byte prefixes and their actual dependencies.

The registry map/TLS guard path is excluded. No native state or decoded
constant is copied into Python model outputs. Export only offsets/counts.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X8

import vm9_objects as objects
from vm9_allocator import RefillUnsupported, _read_span, _write_span
from verify_vm9_signer_objects import GUEST, LIBRARY_SHA256, fresh_pages, image_pages, native
from verify_vm9_strings import Effects


FLAG_DESTINATIONS = [(0x3D16B4, 0x3D1690), (0x3D16E4, 0x3D16C0),
                     (0x3D1714, 0x3D16F0), (0x3D1744, 0x3D1720), (0x3D1774, 0x3D1750)]


def fixture(library, base, profile="cold"):
    pages = fresh_pages()
    pages.update(image_pages(library, base))
    for index, (flag, destination) in enumerate(FLAG_DESTINATIONS):
        if profile == "warm" or profile == "mixed" and index & 1:
            _write_span(pages, base + flag, (2 + index).to_bytes(4, "little"))
            _write_span(pages, base + destination, b"synthetic\0")
    if profile == "warm":
        _write_span(pages, base + 0x3DE6B0, (17).to_bytes(4, "little"))
        _write_span(pages, base + 0x3DE690, b"synthetic\0")
    return pages


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--libc", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == LIBRARY_SHA256
    cases, negatives = [], []

    def compare(label, base, pages, entry, arguments, operation, *, stop=None,
                registers=None, mutate=None, clock=None, check_result=False):
        expected, actual = Effects(blocks={}, mutate=mutate), Effects(blocks={}, mutate=mutate)
        observed = {(page << 12, 4096): None for page in pages
                    if not GUEST <= page << 12 < GUEST + 0x10000}
        native_clock_calls, python_clock_calls = [], []
        imports = {}
        if clock is not None:
            seconds, nanoseconds = clock
            def native_clock(cpu):
                assert cpu.reg_read(UC_ARM64_REG_X0) == 0
                native_clock_calls.append(len(expected.calls))
                pointer = cpu.reg_read(UC_ARM64_REG_X1)
                cpu.mem_write(pointer, seconds.to_bytes(8, "little", signed=True)
                    + nanoseconds.to_bytes(8, "little", signed=True))
                return 0
            imports[0x348450] = native_clock
        result, memory, _, _ = native(args.library, base, entry, arguments, pages,
            libc=args.libc, real_mutexes=True, observed_memory=observed,
            extra_registers=registers, stop_offset=stop, host_imports=imports,
            instruction_limit=100000,
            malloc_handler=lambda cpu, size: expected.native(cpu, "malloc", size))
        def read_clock(staged, clock_id):
            assert clock_id == 0
            python_clock_calls.append(len(actual.calls))
            return 0, *clock
        modeled = operation(actual, read_clock)
        got = _read_span(pages, GUEST, 0xA000)
        if got != memory:
            offset = next(i for i, (a, b) in enumerate(zip(got, memory)) if a != b)
            raise AssertionError(f"{label}: guest+{offset:#x}")
        assert expected.calls == actual.calls, (label, "allocation sequence")
        assert expected.blocks == actual.blocks, (label, "allocator state")
        assert native_clock_calls == python_clock_calls, (label, "clock call order")
        assert all(_read_span(pages, a, n) == data for (a, n), data in observed.items()), label + " image pages"
        if check_result:
            assert modeled == result, (label, "native result")
        cases.append({"case": label, "image_base": hex(base), "guest_bytes_match": True,
            "all_main_image_pages_match": True, "allocation_sequence_match": True,
            "allocator_state_match": True, "clock_call_order_match": True,
            "allocation_sizes": [c[1] for c in actual.calls], "clock_calls": len(python_clock_calls),
            "native_result_checked": check_result})

    for base in (0x122C0000, 0x775C205000):
        for value in (0, 1, GUEST + 0x3500, 0xFFFFFFFFFFFFFFFF):
            for relocated in (False, True):
                pages = fixture(args.library, base)
                slot = GUEST + 0x2FFC if relocated else base + 0x3D1900
                if relocated:
                    _write_span(pages, base + 0x379968, (slot + 0xE6FDE0).to_bytes(8, "little"))
                _write_span(pages, slot, value.to_bytes(8, "little"))
                compare(f"table_{value:x}_{relocated}", base, pages, 0x173470, [],
                    lambda e, c: objects.read_singleton136_table_value(pages, image_base=base), check_result=True)

        for target in (GUEST + 0x1000, GUEST + 0x1FFC):
            for flag in (0, 2, 0xFFFFFFFE):
                pages = fixture(args.library, base)
                compare(f"normal_mutex_{target-GUEST:x}_{flag:x}", base, pages, 0x15DEA8, [target, flag],
                    lambda e, c: objects.construct_normal_mutex_object(pages, object_address=target, image_base=base))
            pages = fixture(args.library, base)
            compare(f"helper56_{target-GUEST:x}", base, pages, 0x1666E8, [target],
                lambda e, c: objects.construct_singleton_helper56(pages, object_address=target,
                    image_base=base, allocate=e.malloc))
            for profile in ("cold", "warm", "mixed"):
                pages = fixture(args.library, base, profile)
                _write_span(pages, base + 0x3D1900, (0x123456789ABCDEF0).to_bytes(8, "little"))
                compare(f"layout136_{profile}_{target-GUEST:x}", base, pages, 0x166370, [target], stop=0x166544,
                    operation=lambda e, c: objects.construct_singleton_layout136(pages,
                        object_address=target, image_base=base, allocate=e.malloc))
                pages = fixture(args.library, base, profile)
                compare(f"registry320_{profile}_{target-GUEST:x}", base, pages, 0x2566EC, [target], stop=0x256808,
                    operation=lambda e, c: objects.construct_registry_layout320(pages,
                        object_address=target, image_base=base, allocate=e.malloc))

        for event in ("table_after_latch", "fields_after_first_malloc"):
            pages = fixture(args.library, base)
            target = GUEST + 0x1000
            _write_span(pages, base + 0x3D1900, (7).to_bytes(8, "little"))
            def mutate(kind, index, read, write):
                if index == 0:
                    if event == "table_after_latch":
                        write(base + 0x3D1900, (11).to_bytes(8, "little"))
                    else:
                        write(target + 8, (99).to_bytes(4, "little"))
                        write(target + 0x58, bytes([0xDD]) * 8)
            compare("layout136_" + event, base, pages, 0x166370, [target], stop=0x166544, mutate=mutate,
                operation=lambda e, c: objects.construct_singleton_layout136(pages,
                    object_address=target, image_base=base, allocate=e.malloc))

        for seconds, ns in ((0, 0), (1, 999), (1, 1000), (1, 999999999),
                            (1791023800, 123456789), (-1, 0), (-1, 999999999),
                            (-(1 << 63), 0), ((1 << 63) - 1, 999999999)):
            pages = fixture(args.library, base)
            target = GUEST + 0x1FFC
            compare(f"clock_{seconds}_{ns}", base, pages, 0x256898, [],
                registers={UC_ARM64_REG_X8: target}, clock=(seconds, ns),
                operation=lambda e, c: objects.construct_registry_clock_reference(pages,
                    object_address=target, allocate=e.malloc, read_clock=c))

    def reject(label, operation, *, missing=None, failures=()):
        pages = fixture(args.library, 0x122C0000)
        if missing is not None:
            del pages[missing]
        before = {p: bytes(b) for p, b in pages.items()}
        effects = Effects(blocks={}, failures=failures)
        try:
            operation(pages, effects)
        except (RefillUnsupported, ValueError):
            assert before == {p: bytes(b) for p, b in pages.items()}
            negatives.append({"case": label, "rejected": True, "page_rollback": True})
        else:
            raise AssertionError(label + " accepted")

    for index in range(4):
        reject(f"layout136_malloc_null_{index}", lambda p, e: objects.construct_singleton_layout136(p,
            object_address=GUEST + 0x1000, image_base=0x122C0000, allocate=e.malloc), failures=(index,))
    for label, offset in (("missing_mask", 0x70000), ("missing_decoded_flags", 0x3D1000), ("missing_table_got", 0x379000)):
        reject(label, lambda p, e: objects.construct_singleton_layout136(p,
            object_address=GUEST + 0x1000, image_base=0x122C0000, allocate=e.malloc),
            missing=(0x122C0000 + offset) >> 12)
    for index in (0, 1, 5):
        reject(f"registry320_malloc_null_{index}", lambda p, e: objects.construct_registry_layout320(p,
            object_address=GUEST + 0x1000, image_base=0x122C0000, allocate=e.malloc), failures=(index,))
    for label, clock in (("clock_failure", (1, 0, 0)), ("clock_invalid_ns", (0, 1, 1000000000)),
                         ("clock_invalid_sec", (0, 1 << 63, 0))):
        reject(label, lambda p, e: objects.construct_registry_clock_reference(p,
            object_address=GUEST + 0x1000, allocate=e.malloc, read_clock=lambda p, i: clock))

    report = {"library_sha256": LIBRARY_SHA256, "fresh_memory": True,
        "captured_pages_used": False, "jvm_used": False, "differential_cases": len(cases),
        "negative_cases": len(negatives), "cases": cases, "negatives": negatives,
        "normal_mutex_attributes": "null", "allocator_boundary": "explicit_malloc_effects",
        "clock_boundary": "explicit_clock_gettime_status_and_timespec",
        "complete_singleton136_initializer": False, "complete_registry320_initializer": False,
        "complete_88_byte_initializer": False, "complete_python_medusa": False}
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"differential_cases": len(cases), "negative_cases": len(negatives)}))


if __name__ == "__main__":
    main()
