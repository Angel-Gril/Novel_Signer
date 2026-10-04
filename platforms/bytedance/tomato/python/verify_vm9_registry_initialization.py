"""Fresh checks for +0x2568c8 and the complete registry320 constructor body.

The matching bionic mutex/condition code runs normally. TLS resolution is an
explicit warm component boundary, not a complete native/Python cold startup.
Compare all object/image bytes and allocator/TLS/wake/clock order. No decoded
configuration key or payload is exported.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_SP, UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X30, UC_ARM64_REG_TPIDR_EL0

import vm9_objects as objects
import vm9_registry as registry
from vm9_allocator import RefillUnsupported, _read_span, _write_span
from verify_vm9_signer_objects import GUEST, LIBRARY_SHA256, REGS, STOP, native
from verify_vm9_root_configuration import LIBC_BASE, TLS
from verify_vm9_registry import BASES, DISPATCH, fixture, check_memory
from verify_vm9_strings import Effects

OBJECT, FLAG, TREE = GUEST + 0x1000, GUEST + 0x3500, GUEST + 0x3600
ENTRY_SP = GUEST + 0xEF00


def warm_tls(pages):
    _write_span(pages, TLS + 8, (TLS + 0x200).to_bytes(8, "little"))
    _write_span(pages, TLS + 0x200, bytes(0x900))
    _write_span(pages, FLAG, bytes([1]))
    _write_span(pages, TREE, (TREE + 8).to_bytes(8, "little") + bytes(16))


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

    def compare(base, label, *, keys=None, values=None, profile="cold", clock=(1791023800, 123456789), mutation=None,
                top_kind="construct"):
        pages, blocks, addresses = fixture(args.library, base, keys or [])
        warm_tls(pages)
        prefix = Effects(blocks=blocks)
        if keys is not None:
            objects.construct_registry_layout320(pages, object_address=OBJECT, image_base=base, allocate=prefix.malloc)
            operations = [("set", 0x2568C8, [OBJECT, obj, value])
                          for (obj, _, _), value in zip(addresses, values)]
        else:
            if profile == "warm":
                _write_span(pages, base + 0x3DE6B0, (3).to_bytes(4, "little"))
                _write_span(pages, base + 0x3DE690, b"synthetic\0")
            entries = {"construct": 0x2566EC, "registry_getter": 0x15E694,
                       "singleton": 0x166370, "singleton_getter": 0x161068}
            operations = [(top_kind, entries[top_kind], [] if "getter" in top_kind else [OBJECT])]
            if "getter" in top_kind:
                operations *= 3  # Cold first resolution, then two warm getter returns.
        native_events, model_events = [], []
        native_freed_bytes, model_freed_bytes = [], []
        expected, actual = Effects(blocks=prefix.blocks, mutate=mutation), Effects(blocks=prefix.blocks, mutate=mutation)
        expected.next = actual.next = prefix.next
        def native_free(cpu):
            pointer = cpu.reg_read(UC_ARM64_REG_X0)
            if pointer:
                native_freed_bytes.append((pointer, bytes(cpu.mem_read(pointer, expected.blocks[pointer]))))
            return expected.native(cpu, "free", pointer=pointer)
        def model_free(staged, pointer):
            if pointer:
                model_freed_bytes.append((pointer, _read_span(staged, pointer, actual.blocks[pointer])))
            return actual.free(staged, pointer)
        def native_tls(cpu):
            control = cpu.reg_read(UC_ARM64_REG_X0)
            native_events.append(["tls", control - base, len(expected.calls)])
            return {base + 0x382470: FLAG, base + 0x382450: TREE}[control]
        def get_tls(staged, control):
            model_events.append(["tls", control - base, len(actual.calls)])
            return {base + 0x382470: FLAG, base + 0x382450: TREE}[control]
        def initialize(staged):
            objects.initialize_scoped_tls_registry(staged, image_base=base, get_tls=get_tls,
                register_destructor=lambda *a: (_ for _ in ()).throw(AssertionError("warm tree registered twice")))
        def native_broadcast(cpu):
            cpu.reg_write(UC_ARM64_REG_PC, exports["pthread_cond_broadcast"])
        def syscall(cpu, number):
            assert number == 98
            event = ["wake", cpu.reg_read(UC_ARM64_REG_X0), cpu.reg_read(UC_ARM64_REG_X1),
                     cpu.reg_read(UC_ARM64_REG_X2), len(expected.calls)]
            assert event[2] in (1, 129) and event[3] == 0x7FFFFFFF
            native_events.append(event)
            return 0
        def wake(staged, pointer, operation, count):
            model_events.append(["wake", pointer, operation, count, len(actual.calls)])
            return 0
        def broadcast(staged, pointer):
            return objects.broadcast_condition_no_waiters(staged, condition_address=pointer, wake=wake)
        def native_clock(cpu):
            assert cpu.reg_read(UC_ARM64_REG_X0) == 0
            native_events.append(["clock", 0, len(expected.calls)])
            cpu.mem_write(cpu.reg_read(UC_ARM64_REG_X1), clock[0].to_bytes(8, "little", signed=True)
                + clock[1].to_bytes(8, "little", signed=True))
            return 0
        def read_clock(staged, clock_id):
            model_events.append(["clock", clock_id, len(actual.calls)])
            return 0, *clock
        completed = []
        def observer(cpu, address):
            if address != DISPATCH: return
            assert cpu.reg_read(UC_ARM64_REG_SP) == ENTRY_SP
            completed.append((cpu.reg_read(UC_ARM64_REG_X0), bytes(cpu.mem_read(GUEST, 0xA000)),
                list(expected.calls), dict(expected.blocks), list(native_events)))
            if len(completed) == len(operations):
                cpu.reg_write(UC_ARM64_REG_PC, STOP)
                return
            _, entry, arguments = operations[len(completed)]
            for reg, value in zip(REGS, arguments): cpu.reg_write(reg, value)
            cpu.reg_write(UC_ARM64_REG_X30, DISPATCH)
            cpu.reg_write(UC_ARM64_REG_PC, base + entry)
        observed = {(p << 12, 4096): None for p in pages if base <= p << 12 < base + 0x400000}
        observed[TLS, 0xB00] = None
        native(args.library, base, operations[0][1], operations[0][2], pages,
            libc=args.libc, real_mutexes=True, real_singletons=True, thread_id=137,
            instruction_limit=300000, observed_memory=observed,
            instruction_observer=observer, extra_registers={UC_ARM64_REG_X30: DISPATCH, UC_ARM64_REG_TPIDR_EL0: TLS},
            host_imports={0x34377C: native_tls, 0x3485A0: native_broadcast, 0x348450: native_clock,
                0x347FA0: native_free},
            syscall_handler=syscall, malloc_handler=lambda cpu, size: expected.native(cpu, "malloc", size))
        for index, ((kind, _, arguments), (result, memory, calls, live, events)) in enumerate(zip(operations, completed)):
            common = dict(image_base=base, entry_stack_address=ENTRY_SP, allocate=actual.malloc,
                          free=model_free, get_tls=get_tls, initialize_registry=initialize, broadcast=broadcast)
            if kind == "construct":
                registry.construct_registry320(pages, object_address=OBJECT, read_clock=read_clock, **common)
            elif kind == "singleton":
                registry.construct_singleton136(pages, object_address=OBJECT, read_clock=read_clock,
                                                 thread_id=137, **common)
            elif kind in ("registry_getter", "singleton_getter"):
                operation = registry.get_registry320_reference if kind == "registry_getter" else registry.get_singleton136_reference
                reference = operation(pages, read_clock=read_clock, thread_id=137, **common)
                assert reference.wrapper_address == result, (label, index, "getter return")
            else:
                got = registry.set_configuration_u32(pages, registry_address=OBJECT,
                                                     key_address=arguments[1], value=arguments[2], **common)
                assert got == result & 0xFFFFFFFF, (label, index, got, result)
            check_memory(f"{label}_{index}", pages, memory)
            assert actual.calls == calls, (label, index, "allocation/free order", actual.calls, calls)
            assert actual.blocks == live, (label, index, "allocator state")
            assert model_events == events, (label, index, "TLS/clock/wake order", model_events, events)
        assert len(completed) == len(operations)
        assert model_freed_bytes == native_freed_bytes, label + " pre-free payloads"
        assert all(_read_span(pages, a, n) == data for (a, n), data in observed.items()), label + " image/TLS"
        cases.append({"case": label, "image_base": hex(base), "operation_count": len(operations),
            "all_intermediate_guest_bytes_match": True, "all_main_image_pages_match": True,
            "tls_state_match": True, "allocator_state_match": True, "effect_order_match": True,
            "tls_clock_wake_event_order_match": True, "setter_returns_match": keys is not None,
            "all_pre_free_payloads_match": True,
            "allocation_sizes": [c[1] for c in actual.calls if c[0] != "free"],
            "free_count": sum(c[0] == "free" for c in actual.calls), "native_stack_padding_is_input": True})

    for base in BASES:
        for label, keys, values in [
            ("set_first", [b"first"], [1]),
            ("set_replace", [b"a", b"a", b"a"], [0, 0xFFFFFFFF, 7]),
            ("set_rotations", [bytes([c]) for c in b"cabfed"], [1, 2, 3, 4, 5, 6]),
            ("set_nul_equivalent", [b"a\0x", b"a\0longer", b"b", b"a\0z"], [0x80000000, 42, 3, 1]),
            ("set_empty_binary", [b"", b"\xff", b"\x80", b"", b"\xff"], [11, 22, 33, 44, 55])]:
            compare(base, label, keys=keys, values=values)
        def padding(kind, index, read, write):
            if kind == "malloc" and index == 0:
                write(ENTRY_SP - 0xA8 + 9, b"padding")
        compare(base, "setter_padding_at_malloc", keys=[b"a"], values=[3], mutation=padding)
        def clone_source(kind, index, read, write):
            if kind == "malloc" and index == 2:
                write(GUEST + 0x3000, b"z\0")
        compare(base, "setter_clone_source_after_malloc", keys=[b"a"], values=[3], mutation=clone_source)
        for profile in ("cold", "warm"):
            for clock in ((0, 0), (1791023800, 123456789), (-1, 999999999)):
                compare(base, f"constructor_{profile}_{clock[0]}", profile=profile, clock=clock)
            for top_kind in ("registry_getter", "singleton", "singleton_getter"):
                compare(base, top_kind + "_" + profile, profile=profile, top_kind=top_kind)

    base = BASES[0]
    for label in ("multiple_live_tls_keys", "active_readers", "missing_stack", "null_key", "null_value", "null_pair", "null_node", "wake_error", "clock_error",
                  "singleton_clock_error", "registry_getter_missing_thread_id", "singleton_getter_missing_thread_id", "registry_recursive_guard", "singleton_recursive_guard"):
        pages, blocks, addresses = fixture(args.library, base, [b"a"])
        warm_tls(pages)
        effects = Effects(blocks=blocks)
        if label not in ("clock_error", "singleton_clock_error") and "getter" not in label and "guard" not in label:
            objects.construct_registry_layout320(pages, object_address=OBJECT, image_base=base, allocate=effects.malloc)
        if label in ("registry_recursive_guard", "singleton_recursive_guard"):
            _write_span(pages, base + (0x3D1558 if label.startswith("registry") else 0x3D1680) + 1, bytes([2]))
        if label == "multiple_live_tls_keys": _write_span(pages, TREE + 16, (2).to_bytes(8, "little"))
        if label == "active_readers": _write_span(pages, OBJECT + 0x110, (1).to_bytes(4, "little"))
        if label.startswith("null_"):
            effects.failures.add(effects.allocation_index + {"null_key": 1, "null_value": 3, "null_pair": 4, "null_node": 5}[label])
        before = {p: bytes(b) for p, b in pages.items()}
        def get_tls(staged, control): return {base + 0x382470: FLAG, base + 0x382450: TREE}[control]
        def initialize(staged):
            objects.initialize_scoped_tls_registry(staged, image_base=base, get_tls=get_tls, register_destructor=lambda *a: 0)
        def broadcast(staged, pointer):
            return objects.broadcast_condition_no_waiters(staged, condition_address=pointer,
                wake=lambda *a: -1 if label == "wake_error" else 0)
        try:
            common = dict(image_base=base, entry_stack_address=0x80000000 if label == "missing_stack" else ENTRY_SP,
                allocate=effects.malloc, free=effects.free, get_tls=get_tls, initialize_registry=initialize, broadcast=broadcast)
            if label == "clock_error":
                registry.construct_registry320(pages, object_address=OBJECT, read_clock=lambda *a: (1, 0, 0), **common)
            elif label == "singleton_clock_error":
                registry.construct_singleton136(pages, object_address=OBJECT, thread_id=137,
                                                read_clock=lambda *a: (1, 0, 0), **common)
            elif "getter" in label or "guard" in label:
                operation = registry.get_registry320_reference if label.startswith("registry") else registry.get_singleton136_reference
                operation(pages, read_clock=lambda *a: (0, 1, 0), **common)
            else:
                registry.set_configuration_u32(pages, registry_address=OBJECT, key_address=addresses[0][0], value=1, **common)
        except (RefillUnsupported, ValueError):
            assert before == {p: bytes(b) for p, b in pages.items()}
            negatives.append({"case": label, "rejected": True, "page_rollback": True})
        else: raise AssertionError(label + " accepted")
    report = {"library_sha256": LIBRARY_SHA256, "libc_sha256": hashlib.sha256(args.libc.read_bytes()).hexdigest(),
        "differential_cases": len(cases), "negative_cases": len(negatives), "cases": cases, "negatives": negatives,
        "fresh_memory": True, "captured_pages_used": False, "native_output_used_as_input": False,
        "tls_resolution_is_component_boundary": True, "warm_tls_registry_only": True,
        "registry320_constructor_body": True, "registry320_lazy_publication": True,
        "singleton136_constructor_body": True, "singleton136_lazy_publication": True,
        "guard_boundary": "existing_serialized_successful_single_thread_guard",
        "complete_cold_registry320_initialization": False, "complete_cold_singleton136_initialization": False,
        "complete_python_medusa": False, "jvm_used": False}
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"differential_cases": len(cases), "negative_cases": len(negatives)}))


if __name__ == "__main__":
    main()
