"""Fresh native local thread-destructor and scoped TLS-tree initialization.

TLS address resolution is an explicit component boundary here; the same-run
root verifier separately composes it with the recovered emulated TLS model.
No process/thread destructor is executed and no host key is created.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_PC, UC_ARM64_REG_TPIDR_EL0

import vm9_objects as objects
from vm9_allocator import RefillUnsupported, _read_span, _write_span, pthread_key_create, pthread_setspecific
from verify_vm9_signer_objects import GUEST, LIBRARY_SHA256, fresh_pages, image_pages, native
from verify_vm9_root_configuration import LIBC_BASE, LIBC_PTHREAD_GENERATION_OFFSET, TLS
from verify_vm9_strings import Effects


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--libc", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == LIBRARY_SHA256
    with args.libc.open("rb") as stream:
        elf = ELFFile(stream)
        exports = {s.name: LIBC_BASE + s["st_value"] for sec in elf.iter_sections()
                   if sec["sh_type"] == "SHT_DYNSYM" for s in sec.iter_symbols()}
    generation_table = LIBC_BASE + LIBC_PTHREAD_GENERATION_OFFSET
    cases, negatives = [], []

    def fixture(base, guard_ready, thread_flag, tree_flag):
        pages = fresh_pages()
        pages.update(image_pages(args.library, base))
        pages.update(image_pages(args.libc, LIBC_BASE))
        _write_span(pages, TLS + 8, (TLS + 0x200).to_bytes(8, "little"))
        _write_span(pages, TLS + 0x200, bytes(0x900))
        _write_span(pages, base + 0x3E2FA8, bytes([guard_ready, guard_ready]) + bytes(6))
        _write_span(pages, base + 0x3E2FB0, (0x80000000).to_bytes(4, "little"))
        _write_span(pages, generation_table, (1 if guard_ready else 0).to_bytes(8, "little"))
        _write_span(pages, GUEST + 0x3100, bytes([thread_flag]))
        _write_span(pages, GUEST + 0x3110, (GUEST + 0x3400).to_bytes(8, "little"))
        _write_span(pages, GUEST + 0x3200, bytes([tree_flag]))
        return pages

    def compare(base, entry, guard_ready, thread_flag, tree_flag, failure=None):
        pages = fixture(base, guard_ready, thread_flag, tree_flag)
        expected = Effects(blocks={}, failures=(0,) if failure == "malloc" else ())
        actual = Effects(blocks={}, failures=(0,) if failure == "malloc" else ())
        native_events, model_events = [], []
        addresses = {0x3D13A0: GUEST + 0x3100, 0x3D13C0: GUEST + 0x3110,
                     0x382470: GUEST + 0x3200, 0x382450: GUEST + 0x3300}
        def native_tls(cpu):
            offset = cpu.reg_read(UC_ARM64_REG_X0) - base
            native_events.append(["tls", hex(offset)])
            return addresses[offset]
        def model_tls(staged, control):
            model_events.append(["tls", hex(control - base)])
            return addresses[control - base]
        def native_atexit(cpu):
            native_events.append(["atexit", *[hex(cpu.reg_read(r) - base)
                for r in (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2)]])
            return 0
        def model_atexit(staged, destructor, obj, dso):
            model_events.append(["atexit", *[hex(v - base) for v in (destructor, obj, dso)]])
            return 0
        def key_create(cpu):
            native_events.append(["create_key"])
            cpu.reg_write(UC_ARM64_REG_PC, exports["pthread_key_create"])
        def create_key(staged, pointer, destructor):
            model_events.append(["create_key"])
            return pthread_key_create(staged, key_address=pointer, destructor=destructor,
                                      generation_table=generation_table)
        def set_native(cpu):
            native_events.append(["set_specific"])
            if failure == "setspecific":
                return 22
            cpu.reg_write(UC_ARM64_REG_PC, exports["pthread_setspecific"])
        def set_specific(staged, key, value):
            model_events.append(["set_specific"])
            if failure == "setspecific":
                return 22
            return pthread_setspecific(staged, key=key, value=value, thread_pointer=TLS,
                                       generation_table=generation_table)
        def register(staged, destructor, obj, dso):
            return objects.register_emulated_thread_destructor(staged, destructor_address=destructor,
                object_address=obj, image_base=base, allocate=actual.malloc, get_tls=model_tls,
                create_key=create_key, set_specific=set_specific, register_atexit=model_atexit, thread_id=137)
        observed = {(p << 12, 4096): None for p in pages if base <= p << 12 < base + 0x400000}
        observed[TLS, 0xB00] = None
        observed[generation_table, 141 * 16] = None
        result, memory, _, _ = native(args.library, base, entry,
            [base + 0x268CF0, GUEST + 0x3300, base + 0x34C700] if entry == 0x34265C else [],
            pages, libc=args.libc, real_singletons=True, real_mutexes=True, thread_id=137,
            extra_registers={UC_ARM64_REG_TPIDR_EL0: TLS}, observed_memory=observed,
            host_imports={0x34377C: native_tls, 0x348620: key_create, 0x348580: set_native, 0x347EA0: native_atexit},
            malloc_handler=lambda cpu, size: expected.native(cpu, "malloc", size), instruction_limit=100000)
        if entry == 0x34265C:
            modeled = register(pages, base + 0x268CF0, GUEST + 0x3300, base + 0x34C700)
            assert modeled == result
        else:
            objects.initialize_scoped_tls_registry(pages, image_base=base, get_tls=model_tls,
                                                  register_destructor=register)
        assert _read_span(pages, GUEST, 0xA000) == memory
        assert all(_read_span(pages, a, n) == data for (a, n), data in observed.items())
        assert expected.calls == actual.calls
        assert native_events == model_events
        cases.append({"entry_offset": hex(entry), "image_base": hex(base), "guard_ready": bool(guard_ready),
            "thread_flag": thread_flag, "tree_flag": tree_flag, "failure": failure,
            "guest_objects_match": True, "all_image_pages_match": True, "tls_state_match": True,
            "pthread_generation_table_match": True, "allocation_sequence_match": True,
            "registration_event_order_match": True, "allocation_calls": len(actual.calls)})

    for base in (0x122C0000, 0x775C205000):
        for ready in (0, 1):
            for flag in (0, 1, 2, 3):
                compare(base, 0x34265C, ready, flag, 0)
            for tree_flag in (0, 1, 2):
                compare(base, 0x269880, ready, 0, tree_flag)
        for failure in ("malloc", "setspecific"):
            compare(base, 0x34265C, 0, 0, 0, failure)

    base = 0x122C0000
    for label in ("imported_registration", "in_progress_guard", "key_create_failure", "missing_gettid", "missing_tls_page"):
        pages = fixture(base, 0, 0, 0)
        if label == "imported_registration":
            _write_span(pages, base + 0x3751A0, (1).to_bytes(8, "little"))
        if label == "in_progress_guard":
            _write_span(pages, base + 0x3E2FA9, bytes([2]))
        before = {p: bytes(b) for p, b in pages.items()}
        def get_tls(staged, control):
            return 0x80000000 if label == "missing_tls_page" else GUEST + 0x3100
        try:
            objects.register_emulated_thread_destructor(pages, destructor_address=base + 0x268CF0,
                object_address=GUEST + 0x3300, image_base=base, allocate=Effects(blocks={}).malloc,
                get_tls=get_tls, create_key=lambda *a: 11 if label == "key_create_failure" else 0,
                set_specific=lambda *a: 0, register_atexit=lambda *a: 0,
                thread_id=None if label == "missing_gettid" else 137)
        except (RefillUnsupported, ValueError):
            assert before == {p: bytes(b) for p, b in pages.items()}
            negatives.append({"case": label, "rejected": True, "page_rollback": True})
        else:
            raise AssertionError(label + " accepted")
    report = {"library_sha256": LIBRARY_SHA256, "libc_sha256": hashlib.sha256(args.libc.read_bytes()).hexdigest(),
        "differential_cases": len(cases), "negative_cases": len(negatives), "cases": cases, "negatives": negatives,
        "fresh_memory": True, "captured_pages_used": False, "tls_resolution_is_component_boundary": True,
        "destructors_executed": False, "host_keys_created": False, "jvm_used": False,
        "complete_scoped_lock": False, "complete_python_medusa": False}
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"differential_cases": len(cases), "negative_cases": len(negatives)}))


if __name__ == "__main__":
    main()
