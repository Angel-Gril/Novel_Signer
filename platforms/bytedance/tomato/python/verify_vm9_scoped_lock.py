"""Fresh native differences for the zero/one-entry scoped TLS writer branch.

TLS addresses are explicit component inputs. Compare stack-origin padding
copied into the node, poisoned frees, wake calls and matching bionic mutexes.
Multiple live keys, shared-reader ownership and waiting are unsupported.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_PC, UC_ARM64_REG_TPIDR_EL0

import vm9_objects as objects
from vm9_allocator import RefillUnsupported, _read_span, _write_span
from verify_vm9_signer_objects import GUEST, LIBRARY_SHA256, fresh_pages, image_pages, native
from verify_vm9_root_configuration import LIBC_BASE, TLS
from verify_vm9_strings import Effects

TREE, MUTEX, NODE = GUEST + 0x3300, GUEST + 0x2800, GUEST + 0x3800
SCRATCH = GUEST + 0xEEB8  # Native entry SP-0x50+8: the constructor's copied pair.


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
    cases, negatives = [], []

    def fixture(base, target, profile, condition):
        pages = fresh_pages()
        pages.update(image_pages(args.library, base))
        _write_span(pages, TLS + 8, (TLS + 0x200).to_bytes(8, "little"))
        _write_span(pages, TLS + 0x200, bytes(0x900))
        _write_span(pages, GUEST + 0x3200, bytes([1]))
        _write_span(pages, TREE, (TREE + 8).to_bytes(8, "little") + bytes(16))
        objects.construct_mutex_state(pages, object_address=MUTEX, image_base=base)
        _write_span(pages, MUTEX + 0x30, condition.to_bytes(4, "little"))
        _write_span(pages, target, (base + 0x35D2A0).to_bytes(8, "little")
            + MUTEX.to_bytes(8, "little") + bytes(4))
        blocks = {}
        if profile in ("idle", "owned", "nested"):
            _write_span(pages, TREE, NODE.to_bytes(8, "little") * 2 + (1).to_bytes(8, "little"))
            _write_span(pages, NODE, bytes(16) + (TREE + 8).to_bytes(8, "little"))
            _write_span(pages, NODE + 24, bytes([1]))
            _write_span(pages, NODE + 32, MUTEX.to_bytes(8, "little"))
            _write_span(pages, NODE + 40, bytes([int(profile != "idle")]))
            blocks[NODE] = 48
        if profile in ("owned", "nested"):
            _write_span(pages, MUTEX + 0x90, (0x80000000).to_bytes(4, "little"))
        if profile == "nested":
            _write_span(pages, target + 16, ((-0x91D) & 0xFFFFFFFF).to_bytes(4, "little"))
        return pages, blocks

    def compare(base, target, entry, profile, condition=0, mutation=False):
        pages, blocks = fixture(base, target, profile, condition)
        def mutate(kind, index, read, write):
            if kind == "malloc" and mutation:
                write(SCRATCH + 9, b"padding")
        expected, actual = Effects(blocks=blocks, mutate=mutate), Effects(blocks=blocks, mutate=mutate)
        native_events, model_events = [], []
        def native_tls(cpu):
            offset = cpu.reg_read(UC_ARM64_REG_X0) - base
            native_events.append(["tls", hex(offset)])
            return {0x382470: GUEST + 0x3200, 0x382450: TREE}[offset]
        def get_tls(staged, control):
            model_events.append(["tls", hex(control - base)])
            return {0x382470: GUEST + 0x3200, 0x382450: TREE}[control - base]
        def initialize(staged):
            objects.initialize_scoped_tls_registry(staged, image_base=base, get_tls=get_tls,
                register_destructor=lambda *a: (_ for _ in ()).throw(AssertionError("warm tree registered twice")))
        def broadcast_native(cpu):
            cpu.reg_write(UC_ARM64_REG_PC, exports["pthread_cond_broadcast"])
        def syscall(cpu, number):
            assert number == 98
            event = ["wake", cpu.reg_read(UC_ARM64_REG_X0), cpu.reg_read(UC_ARM64_REG_X1), cpu.reg_read(UC_ARM64_REG_X2)]
            assert event[2] in (1, 129) and event[3] == 0x7FFFFFFF
            native_events.append(event)
            return 0
        def wake(staged, pointer, operation, count):
            model_events.append(["wake", pointer, operation, count])
            return 0
        observed = {(p << 12, 4096): None for p in pages if base <= p << 12 < base + 0x400000}
        observed[TLS, 0xB00] = None
        _, memory, _, _ = native(args.library, base, entry, [target, MUTEX], pages,
            libc=args.libc, real_mutexes=True, observed_memory=observed,
            extra_registers={UC_ARM64_REG_TPIDR_EL0: TLS}, instruction_limit=100000,
            host_imports={0x34377C: native_tls, 0x3485A0: broadcast_native,
                0x347FA0: lambda cpu: expected.native(cpu, "free", pointer=cpu.reg_read(UC_ARM64_REG_X0))},
            syscall_handler=syscall, malloc_handler=lambda cpu, size: expected.native(cpu, "malloc", size))
        if entry == 0x268EB0:
            status = objects.construct_single_scoped_lock(pages, object_address=target, mutex_address=MUTEX,
                scratch_address=SCRATCH, image_base=base, allocate=actual.malloc,
                get_tls=get_tls, initialize_registry=initialize)
            assert status == (0xFFFFF6E3 if profile in ("owned", "nested") else 0)
        else:
            objects.destroy_single_scoped_lock(pages, object_address=target, image_base=base,
                free=actual.free, get_tls=get_tls, initialize_registry=initialize,
                broadcast=lambda staged, pointer: objects.broadcast_condition_no_waiters(
                    staged, condition_address=pointer, wake=wake))
        got = _read_span(pages, GUEST, 0xA000)
        if got != memory:
            first = next(i for i, (a,b) in enumerate(zip(got, memory)) if a != b)
            raise AssertionError(f"{hex(entry)} {profile}: guest+{first:#x}")
        assert all(_read_span(pages, a, n) == data for (a,n), data in observed.items())
        assert actual.calls == expected.calls and actual.blocks == expected.blocks
        assert model_events == native_events, (model_events, native_events)
        cases.append({"entry_offset": hex(entry), "image_base": hex(base), "cross_page": target & 4095 > 4076,
            "profile": profile, "condition_state": hex(condition), "padding_mutated_at_malloc": mutation,
            "guest_objects_match": True, "all_main_image_pages_match": True, "tls_state_match": True,
            "effect_order_match": True, "allocator_state_match": True, "tls_wake_event_order_match": True})

    for base in (0x122C0000, 0x775C205000):
        for target in (GUEST + 0x1000, GUEST + 0x1FF8):
            for profile in ("empty", "idle", "owned"):
                compare(base, target, 0x268EB0, profile)
            for condition in (0, 1, 2, 3, 0xFFFFFFFC, 0xFFFFFFFF):
                compare(base, target, 0x268FBC, "owned", condition)
            compare(base, target, 0x268FBC, "nested")
        compare(base, GUEST + 0x1000, 0x268EB0, "empty", mutation=True)

    base, target = 0x122C0000, GUEST + 0x1000
    for label in ("multiple_live_keys", "another_mutex_key", "active_readers", "contended_mutex", "null_allocation", "missing_scratch", "wake_error"):
        pages, blocks = fixture(base, target, "owned" if label == "wake_error" else "empty", 0)
        if label == "multiple_live_keys":
            _write_span(pages, TREE + 16, (2).to_bytes(8, "little"))
        if label == "another_mutex_key":
            pages, blocks = fixture(base, target, "idle", 0)
            _write_span(pages, NODE + 32, (MUTEX + 8).to_bytes(8, "little"))
        if label == "active_readers":
            _write_span(pages, MUTEX + 0x90, (1).to_bytes(4, "little"))
        if label == "contended_mutex":
            _write_span(pages, MUTEX + 8, (2).to_bytes(2, "little"))
        before = {p: bytes(b) for p,b in pages.items()}
        effects = Effects(blocks=blocks, failures=(0,) if label == "null_allocation" else ())
        def get_tls(staged, control):
            return {0x382470: GUEST + 0x3200, 0x382450: TREE}[control - base]
        def initialize(staged):
            objects.initialize_scoped_tls_registry(staged, image_base=base, get_tls=get_tls, register_destructor=lambda *a: 0)
        try:
            if label == "wake_error":
                objects.destroy_single_scoped_lock(pages, object_address=target, image_base=base,
                    free=effects.free, get_tls=get_tls, initialize_registry=initialize,
                    broadcast=lambda staged, pointer: objects.broadcast_condition_no_waiters(
                        staged, condition_address=pointer, wake=lambda *a: -1))
            else:
                objects.construct_single_scoped_lock(pages, object_address=target, mutex_address=MUTEX,
                    scratch_address=0x80000000 if label == "missing_scratch" else SCRATCH,
                    image_base=base, allocate=effects.malloc, get_tls=get_tls, initialize_registry=initialize)
        except (RefillUnsupported, ValueError):
            assert before == {p: bytes(b) for p,b in pages.items()}
            negatives.append({"case": label, "rejected": True, "page_rollback": True})
        else:
            raise AssertionError(label + " accepted")
    report = {"library_sha256": LIBRARY_SHA256, "libc_sha256": hashlib.sha256(args.libc.read_bytes()).hexdigest(),
        "differential_cases": len(cases), "negative_cases": len(negatives), "cases": cases, "negatives": negatives,
        "fresh_memory": True, "captured_pages_used": False, "tls_resolution_is_component_boundary": True,
        "single_live_mutex_only": True, "full_scoped_lock_tree": False, "native_stack_padding_is_input": True,
        "no_host_waiters": True, "jvm_used": False, "complete_python_medusa": False}
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"differential_cases": len(cases), "negative_cases": len(negatives)}))


if __name__ == "__main__":
    main()
