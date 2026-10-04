"""Fresh native emulated-TLS differences with explicit OS pthread effects.

Native executes +0x343980 for cold key initialization. Serialized once,
key allocation, get/set-specific and malloc/realloc are explicit boundaries;
this does not claim a full pthread implementation or complete startup.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_PC

import vm9_objects as objects
from vm9_allocator import RefillUnsupported, _read_span, _write_span
from verify_vm9_signer_objects import GUEST, LIBRARY_SHA256, fresh_pages, image_pages, native
from verify_vm9_strings import Effects

CONTROL, OS_SLOT, ARRAY, TEMPLATE = GUEST + 0x1FF8, GUEST + 0x3500, GUEST + 0x2800, GUEST + 0x2FF8
KEY = 0x80000021


def fixture(library, base, *, index, size, alignment, template=True, capacity=None, cached=False, once=2):
    pages = fresh_pages()
    pages.update(image_pages(library, base))
    _write_span(pages, CONTROL, size.to_bytes(8, "little") + alignment.to_bytes(8, "little")
        + index.to_bytes(8, "little") + (TEMPLATE if template else 0).to_bytes(8, "little"))
    _write_span(pages, TEMPLATE, bytes(range(128)))
    _write_span(pages, base + 0x3E31F0, bytes([int(once == 2)]))
    _write_span(pages, base + 0x3E31F4, KEY.to_bytes(4, "little"))
    _write_span(pages, base + 0x3E31F8, once.to_bytes(4, "little"))
    _write_span(pages, base + 0x3E3200, (0).to_bytes(8, "little"))
    _write_span(pages, OS_SLOT, (ARRAY if capacity is not None else 0).to_bytes(8, "little"))
    blocks = {}
    if capacity is not None:
        _write_span(pages, ARRAY, (1).to_bytes(8, "little") + capacity.to_bytes(8, "little") + bytes(capacity * 8))
        blocks[ARRAY] = 16 + capacity * 8
        if cached:
            _write_span(pages, ARRAY + 16 + (index - 1) * 8, (GUEST + 0x3200).to_bytes(8, "little"))
    return pages, blocks


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--libc", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == LIBRARY_SHA256
    cases, negatives = [], []

    def compare(label, base, *, index=1, size=32, alignment=8, template=True,
                capacity=None, cached=False, once=2, inplace=False, effect=None, set_status=0):
        pages, blocks = fixture(args.library, base, index=index, size=size, alignment=alignment,
            template=template, capacity=capacity, cached=cached, once=once)
        def mutation(kind, count, read, write):
            if kind == "malloc" and count == (0 if capacity is not None else 1) and effect:
                if effect == "template_after_malloc":
                    write(CONTROL + 24, (GUEST + 0x3200).to_bytes(8, "little"))
                    write(GUEST + 0x3200, b"Z" * size)
                elif effect == "size_alignment_latched":
                    write(CONTROL, (99).to_bytes(8, "little") + (3).to_bytes(8, "little"))
        expected = Effects(blocks=blocks, inplace=inplace, mutate=mutation, minimum_spacing=512)
        actual = Effects(blocks=blocks, inplace=inplace, mutate=mutation, minimum_spacing=512)
        native_events, python_events = [], []
        pending_once = False
        def read(cpu, a, n): return bytes(cpu.mem_read(a, n))
        def get(cpu):
            assert cpu.reg_read(UC_ARM64_REG_X0) == KEY
            native_events.append(["get", len(expected.calls)])
            return int.from_bytes(read(cpu, OS_SLOT, 8), "little")
        def set_value(cpu):
            assert cpu.reg_read(UC_ARM64_REG_X0) == KEY
            native_events.append(["set", len(expected.calls)])
            if set_status == 0:
                cpu.mem_write(OS_SLOT, cpu.reg_read(UC_ARM64_REG_X1).to_bytes(8, "little"))
            return set_status
        def create(cpu):
            assert cpu.reg_read(UC_ARM64_REG_X0) == base + 0x3E31F4
            assert cpu.reg_read(UC_ARM64_REG_X1) == base + 0x3439BC
            native_events.append(["create", len(expected.calls)])
            cpu.mem_write(base + 0x3E31F4, KEY.to_bytes(4, "little"))
            return 0
        def once_call(cpu):
            nonlocal pending_once
            assert cpu.reg_read(UC_ARM64_REG_X0) == base + 0x3E31F8
            assert cpu.reg_read(UC_ARM64_REG_X1) == base + 0x343980
            state = int.from_bytes(read(cpu, base + 0x3E31F8, 4), "little")
            if state == 0:
                cpu.mem_write(base + 0x3E31F8, (1).to_bytes(4, "little"))
                pending_once = True
                cpu.reg_write(UC_ARM64_REG_PC, base + 0x343980)
                return None  # Actual native key-initializer callback executes.
            assert state == 2
            return 0
        def observe(cpu, address):
            nonlocal pending_once
            if pending_once and address == base + 0x343818:
                cpu.mem_write(base + 0x3E31F8, (2).to_bytes(4, "little"))
                pending_once = False
        observed = {(page << 12, 4096): None for page in pages
                    if not GUEST <= page << 12 < GUEST + 0x10000}
        result, memory, _, _ = native(args.library, base, 0x34377C, [CONTROL], pages,
            libc=args.libc, real_mutexes=True, instruction_observer=observe, instruction_limit=100000,
            observed_memory=observed, malloc_handler=lambda cpu, n: expected.native(cpu, "malloc", n),
            host_imports={0x3485D0: get, 0x348580: set_value, 0x348620: create, 0x3486B0: once_call,
                0x348320: lambda cpu: expected.native(cpu, "realloc", cpu.reg_read(UC_ARM64_REG_X1), cpu.reg_read(UC_ARM64_REG_X0))})
        def model_get(staged, key):
            assert key == KEY
            python_events.append(["get", len(actual.calls)])
            return int.from_bytes(_read_span(staged, OS_SLOT, 8), "little")
        def model_set(staged, key, value):
            assert key == KEY
            python_events.append(["set", len(actual.calls)])
            if set_status == 0:
                _write_span(staged, OS_SLOT, value.to_bytes(8, "little"))
            return set_status
        def model_create(staged, key_address, destructor):
            assert key_address == base + 0x3E31F4 and destructor == base + 0x3439BC
            python_events.append(["create", len(actual.calls)])
            _write_span(staged, key_address, KEY.to_bytes(4, "little"))
            return 0
        modeled = objects.get_emulated_tls_address(pages, control_address=CONTROL, image_base=base,
            allocate=actual.malloc, reallocate=actual.realloc, get_specific=model_get,
            set_specific=model_set, create_key=model_create, once_wake=lambda *args: 0)
        assert modeled == result, (label, "return pointer")
        got = _read_span(pages, GUEST, 0xA000)
        if got != memory:
            offset = next(i for i, (a, b) in enumerate(zip(got, memory)) if a != b)
            raise AssertionError(f"{label}: guest+{offset:#x}")
        assert actual.calls == expected.calls and actual.blocks == expected.blocks, (label, "allocator")
        assert native_events == python_events, (label, "pthread event order")
        assert all(_read_span(pages, a, n) == data for (a, n), data in observed.items()), label + " image pages"
        cases.append({"case": label, "image_base": hex(base), "guest_bytes_match": True,
            "all_main_image_pages_match": True, "return_pointer_match": True,
            "allocator_effects_match": True, "pthread_event_order_match": True,
            "allocation_sizes": [c[1] for c in actual.calls], "pthread_events": [e[0] for e in python_events],
            "cold_native_key_initializer_executed": once == 0})

    for base in (0x122C0000, 0x775C205000):
        for index, once in ((0, 0), (0, 2), (1, 2), (14, 2), (15, 2), (31, 2)):
            for template in (False, True):
                compare(f"new_array_{index}_{once}_{template}", base, index=index, once=once, template=template)
        for size, alignment in ((0, 0), (1, 1), (7, 2), (16, 8), (31, 16), (65, 64), (96, 128)):
            compare(f"alignment_{size}_{alignment}", base, size=size, alignment=alignment)
        for inplace in (False, True):
            for index, capacity in ((3, 2), (15, 14), (31, 30)):
                compare(f"grow_{index}_{capacity}_{inplace}", base, index=index, capacity=capacity, inplace=inplace)
        for cached in (False, True):
            compare(f"existing_slot_{cached}", base, index=2, capacity=14, cached=cached)
        for effect in ("template_after_malloc", "size_alignment_latched"):
            compare(effect, base, capacity=14, effect=effect)
        compare("ignored_setspecific_failure", base, set_status=22)

    def reject(label, *, index=1, alignment=8, once=2, size=32, capacity=None, failures=(),
               create_status=0, missing=None, missing_wake=False, wake_status=0):
        base = 0x122C0000
        pages, blocks = fixture(args.library, base, index=index, size=size, alignment=alignment, capacity=capacity, once=once)
        if missing is not None:
            del pages[missing]
        before = {p: bytes(b) for p, b in pages.items()}
        effects = Effects(blocks=blocks, failures=failures)
        def get(staged, key): return int.from_bytes(_read_span(staged, OS_SLOT, 8), "little")
        def set_value(staged, key, value):
            _write_span(staged, OS_SLOT, value.to_bytes(8, "little"))
            return 0
        try:
            objects.get_emulated_tls_address(pages, control_address=CONTROL, image_base=base,
                allocate=effects.malloc, reallocate=effects.realloc, get_specific=get, set_specific=set_value,
                create_key=lambda p, k, d: create_status,
                once_wake=None if missing_wake else lambda *args: wake_status)
        except (RefillUnsupported, ValueError):
            assert before == {p: bytes(b) for p, b in pages.items()}
            negatives.append({"case": label, "rejected": True, "page_rollback": True})
        else:
            raise AssertionError(label + " accepted")
    reject("once_in_progress", index=0, once=1)
    reject("key_create_failure", index=0, once=0, create_status=11)
    reject("missing_once_wake_boundary", index=0, once=0, missing_wake=True)
    reject("once_wake_errno_path", index=0, once=0, wake_status=-1)
    reject("index_bound", index=4097)
    reject("invalid_alignment", alignment=12)
    reject("payload_bound", size=0x100000)
    reject("array_malloc_null", failures=(0,))
    reject("variable_malloc_null", failures=(1,))
    reject("array_realloc_null", index=3, capacity=2, failures=(0,))
    reject("missing_control_page", missing=(GUEST + 0x2000) >> 12)
    reject("missing_global_page", missing=(0x122C0000 + 0x3E3000) >> 12)
    report = {"library_sha256": LIBRARY_SHA256, "libc_sha256": hashlib.sha256(args.libc.read_bytes()).hexdigest(),
        "fresh_memory": True, "captured_pages_used": False, "jvm_used": False,
        "differential_cases": len(cases), "negative_cases": len(negatives), "cases": cases, "negatives": negatives,
        "pthread_boundary": "serialized_once_and_explicit_key_get_set_wake_results",
        "bionic_key_allocation_implemented": False, "thread_destructors_executed": False,
        "complete_registry320_initializer": False, "complete_singleton136_initializer": False,
        "complete_88_byte_initializer": False, "complete_python_medusa": False}
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"differential_cases": len(cases), "negative_cases": len(negatives)}))


if __name__ == "__main__":
    main()
