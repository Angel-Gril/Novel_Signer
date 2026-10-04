"""Differential checks using ELF code and newly allocated guest memory.

No JVM or captured pages are used. Allocation, diagnostic scope entry/exit,
thread attachment and JNI calls are explicit oracle boundaries. This verifies
constructor components and publication semantics, not full Medusa startup.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_INTR
from unicorn.arm64_const import (
    UC_ARM64_REG_PC, UC_ARM64_REG_SP, UC_ARM64_REG_X0, UC_ARM64_REG_X1,
    UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X30,
    UC_ARM64_REG_TPIDR_EL0, UC_ARM64_REG_X19, UC_ARM64_REG_X28,
    UC_ARM64_REG_X8,
)

import vm9_callbacks as callbacks
import vm9_objects as objects
from vm9_allocator import RefillUnsupported, _read_span, _write_span

LIBRARY_SHA256 = "712384bd0e310fded0ae9b6441c2a264dd356dfaf1ef42d2ebc3c790fdd9269c"
GUEST = 0x70000000
GUEST_SIZE = 0x10000
STOP = GUEST + 0xF000
REGS = (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
        UC_ARM64_REG_X3, UC_ARM64_REG_X4)


class Allocator:
    def __init__(self):
        self.next = GUEST + 0x4000
        self.calls = []

    def take(self, size):
        pointer = self.next
        self.next += (size + 15) & ~15
        assert self.next < GUEST + 0x9000
        self.calls.append([size, pointer])
        return pointer

    def model(self, pages, size):
        pointer = self.take(size)
        _read_span(pages, pointer, size)
        return pointer


def fresh_pages():
    return {address >> 12: bytearray(b"\xa5" * 4096)
            for address in range(GUEST, GUEST + GUEST_SIZE, 4096)}


def flatten(pages):
    return _read_span(pages, GUEST, GUEST_SIZE)


def image_pages(library, base):
    """Fresh ELF load/relative relocation inputs, never captured process pages."""
    pages = {}
    with library.open("rb") as stream:
        elf = ELFFile(stream)
        for segment in elf.iter_segments():
            if segment["p_type"] != "PT_LOAD":
                continue
            start = base + segment["p_vaddr"]
            end = (start + segment["p_memsz"] + 4095) & ~4095
            for address in range(start & ~4095, end, 4096):
                pages.setdefault(address >> 12, bytearray(4096))
            _write_span(pages, start, segment.data())
        for section in elf.iter_sections():
            if section["sh_type"] == "SHT_RELA":
                for relocation in section.iter_relocations():
                    if relocation["r_info_type"] == 1027:
                        _write_span(pages, base + relocation["r_offset"],
                                    (base + relocation["r_addend"]).to_bytes(8, "little"))
    return pages


def native(library, base, function, arguments, pages, *, references=(), env=0,
           ref_types=None, libc=None, service_references=(),
           extra_registers=None, stop_offset=None, real_singletons=False,
           thread_id=None, observed_memory=None, allocation_effect=None,
           real_mutexes=False, host_imports=None, instruction_limit=10000,
           instruction_observer=None, syscall_handler=None, malloc_handler=None):
    cpu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    with library.open("rb") as stream:
        elf = ELFFile(stream)
        for segment in elf.iter_segments():
            if segment["p_type"] != "PT_LOAD":
                continue
            start = base + segment["p_vaddr"]
            aligned = start & ~4095
            size = ((start + segment["p_memsz"] + 4095) & ~4095) - aligned
            cpu.mem_map(aligned, size)
            cpu.mem_write(start, segment.data())
        for section in elf.iter_sections():
            if section["sh_type"] == "SHT_RELA":
                for relocation in section.iter_relocations():
                    if relocation["r_info_type"] == 1027:
                        cpu.mem_write(base + relocation["r_offset"],
                                      (base + relocation["r_addend"]).to_bytes(8, "little"))
    libc_base = 0x51000000
    mutex_entries = {}
    if libc:
        with libc.open("rb") as stream:
            elf = ELFFile(stream)
            for segment in elf.iter_segments():
                if segment["p_type"] != "PT_LOAD":
                    continue
                start = libc_base + segment["p_vaddr"]
                aligned = start & ~4095
                size = ((start + segment["p_memsz"] + 4095) & ~4095) - aligned
                cpu.mem_map(aligned, size)
                cpu.mem_write(start, segment.data())
            for section in elf.iter_sections():
                if section["sh_type"] in ("SHT_SYMTAB", "SHT_DYNSYM"):
                    for symbol in section.iter_symbols():
                        if symbol.name in ("pthread_mutex_init", "pthread_mutex_lock", "pthread_mutex_unlock"):
                            mutex_entries[symbol.name] = libc_base + symbol["st_value"]
                elif section["sh_type"] == "SHT_RELA":
                    symbols = elf.get_section(section["sh_link"])
                    for relocation in section.iter_relocations():
                        kind = relocation["r_info_type"]
                        if kind == 1027:
                            target = libc_base + relocation["r_addend"]
                        elif kind in (257, 1025, 1026):
                            symbol = symbols.get_symbol(relocation["r_info_sym"])
                            if symbol["st_shndx"] == "SHN_UNDEF":
                                continue
                            target = libc_base + symbol["st_value"] + relocation["r_addend"]
                        else:
                            continue
                        cpu.mem_write(libc_base + relocation["r_offset"],
                                      target.to_bytes(8, "little"))
        assert "pthread_mutex_init" in mutex_entries
    cpu.mem_map(GUEST, GUEST_SIZE)
    cpu.mem_write(GUEST, flatten(pages))
    for page, data in pages.items():
        if not GUEST <= page << 12 < GUEST + GUEST_SIZE:
            cpu.mem_write(page << 12, bytes(data))
    cpu.reg_write(UC_ARM64_REG_SP, GUEST + 0xEF00)
    cpu.reg_write(UC_ARM64_REG_X30, STOP)
    cpu.reg_write(UC_ARM64_REG_TPIDR_EL0, GUEST + 0xD000)
    for reg, value in zip(REGS, arguments):
        cpu.reg_write(reg, value)
    for reg, value in (extra_registers or {}).items():
        cpu.reg_write(reg, value)
    allocation = Allocator()
    ledger = []
    refs = iter(references)
    ref_types = ref_types or {}
    host_get_type = GUEST + 0xF100
    host_deletes = {GUEST + 0xF110: "local", GUEST + 0xF120: "global",
                    GUEST + 0xF130: "weak_global"}

    def hook(cpu, address, size, user):
        if instruction_observer:
            instruction_observer(cpu, address)
        offset = address - base
        if offset == 0x347FD0:  # malloc PLT; operator new executes normally
            requested = cpu.reg_read(UC_ARM64_REG_X0)
            result = malloc_handler(cpu, requested) if malloc_handler else allocation.take(requested)
            if allocation_effect:
                allocation_effect(cpu, requested, result)
        elif offset == 0x347F20:  # memset PLT
            target, fill, width = [cpu.reg_read(reg) for reg in REGS[:3]]
            cpu.mem_write(target, bytes([fill & 255]) * width)
            result = target
        elif offset == 0x347EE0:
            assert "pthread_mutex_init" in mutex_entries and cpu.reg_read(UC_ARM64_REG_X1) == 0
            cpu.reg_write(UC_ARM64_REG_PC, mutex_entries["pthread_mutex_init"])
            return
        elif offset == 0x347F40:  # strlen PLT
            source = cpu.reg_read(UC_ARM64_REG_X0)
            result = 0
            while result < 0x100000 and cpu.mem_read(source + result, 1) != b"\0":
                result += 1
            assert result < 0x100000, "unterminated oracle string"
        elif offset in (0x347F60, 0x348410):  # memcpy / memmove PLT
            target, source, width = [cpu.reg_read(reg) for reg in REGS[:3]]
            cpu.mem_write(target, bytes(cpu.mem_read(source, width)))
            result = target
        elif offset in (0x347F00, 0x347F10) and (real_singletons or real_mutexes):
            lock = offset == 0x347F00
            if real_mutexes:
                target = cpu.reg_read(UC_ARM64_REG_X0)
                state = int.from_bytes(cpu.mem_read(target, 2), "little")
                if state & ~0x2000 != (0 if lock else 1):
                    raise RefillUnsupported("oracle supports only uncontended normal bionic mutexes")
                name = "pthread_mutex_lock" if lock else "pthread_mutex_unlock"
                assert name in mutex_entries
                ledger.append([name, target])
                cpu.reg_write(UC_ARM64_REG_PC, mutex_entries[name])
                return
            assert cpu.reg_read(UC_ARM64_REG_X0) == base + 0x3E2F40
            ledger.append(["guard_lock" if lock else "guard_unlock"])
            result = 0  # Explicit successful single-thread mutex boundary.
        elif offset == 0x348310 and real_singletons:
            assert cpu.reg_read(UC_ARM64_REG_X0) == 0xB2
            assert isinstance(thread_id, int) and 0 <= thread_id <= 0xFFFF_FFFF
            ledger.append(["gettid", thread_id])
            result = thread_id
        elif offset in (0x3485A0, 0x3485B0, 0x32D64C) and real_singletons and offset not in (host_imports or {}):
            raise RefillUnsupported("condition broadcast/wait or runtime abort is outside the oracle")
        elif offset in (0x15F094, 0x264158) and not real_singletons:
            result = service_references[0 if offset == 0x15F094 else 1]
        elif offset in (0x26C858, 0x26C9D0):
            # Logging scope effects are outside the object-memory contract.
            result = 0
        elif offset == 0x26EDC4:
            cpu.mem_write(cpu.reg_read(UC_ARM64_REG_X0), env.to_bytes(8, "little"))
            result = 0
        elif offset == 0x26E70C:
            args = [cpu.reg_read(reg) for reg in REGS]
            ledger.append(["invoke", *args])
            result = next(refs)
        elif address == host_get_type:
            reference = cpu.reg_read(UC_ARM64_REG_X1)
            ledger.append(["get_type", cpu.reg_read(UC_ARM64_REG_X0), reference])
            result = ref_types.get(reference, 0)
        elif address in host_deletes:
            ledger.append(["delete", host_deletes[address],
                           cpu.reg_read(UC_ARM64_REG_X0), cpu.reg_read(UC_ARM64_REG_X1)])
            result = 0
        elif offset in (host_imports or {}):
            result = host_imports[offset](cpu)
            if result is None:
                assert cpu.reg_read(UC_ARM64_REG_PC) != address, "oracle import did not redirect"
                return
        else:
            return
        cpu.reg_write(UC_ARM64_REG_X0, result)
        cpu.reg_write(UC_ARM64_REG_PC, cpu.reg_read(UC_ARM64_REG_X30))

    cpu.hook_add(UC_HOOK_CODE, hook)
    if syscall_handler:
        def interrupt(cpu, number, user):
            if number != 2:
                raise RefillUnsupported("unsupported native interrupt")
            result = syscall_handler(cpu, cpu.reg_read(UC_ARM64_REG_X8))
            cpu.reg_write(UC_ARM64_REG_X0, result & 0xFFFF_FFFF_FFFF_FFFF)
        cpu.hook_add(UC_HOOK_INTR, interrupt)
    end = base + stop_offset if stop_offset is not None else STOP
    cpu.emu_start(base + function, end, count=instruction_limit)
    assert cpu.reg_read(UC_ARM64_REG_PC) == end, "native did not return"
    # Ignore the native stack and synthetic thread pointer area. All object
    # and allocator payload pages are compared, including untouched padding.
    memory = bytes(cpu.mem_read(GUEST, 0xA000))
    if observed_memory is not None:
        for address, width in observed_memory:
            observed_memory[address, width] = bytes(cpu.mem_read(address, width))
    return cpu.reg_read(UC_ARM64_REG_X0), memory, allocation.calls, ledger


def jni_pages(env):
    pages = fresh_pages()
    table = GUEST + 0xB000
    if env:
        _write_span(pages, env, table.to_bytes(8, "little"))
    for offset, target in ((0x740, GUEST + 0xF100), (0xB8, GUEST + 0xF110),
                           (0xB0, GUEST + 0xF120), (0x718, GUEST + 0xF130)):
        _write_span(pages, table + offset, target.to_bytes(8, "little"))
    return pages


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--libc", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == LIBRARY_SHA256
    cases = []
    for base in (0x122C0000, 0x775C205000):
        for label, offset in (("reference_wrapper", 0x165968),
                              ("child_reference", 0x27D188),
                              ("container_reference", 0x1A4494),
                              ("base_reference_a", 0x15DE2C),
                              ("base_reference_b", 0x16620C),
                              ("mutex_state", 0x17D7E0),
                              ("callback_container", 0x25CAD4),
                              ("signer_child", 0x27D0C4)):
            for object_offset in (0x1000, 0x1FF0):
                pages = fresh_pages()
                target = GUEST + object_offset
                source = GUEST + 0xA100
                descriptor = (base + 0x27EC20, 0, base + 0x17CD3C)
                _write_span(pages, source, b"".join(v.to_bytes(8, "little") for v in descriptor))
                native_args = [target, source] if label != "signer_child" else [target]
                _, expected, allocation_calls, _ = native(args.library, base, offset, native_args, pages)
                allocation = Allocator()
                if "reference" in label:
                    objects.construct_reference_wrapper(pages, object_address=target,
                        referenced_address=source, allocate=allocation.model)
                elif label == "mutex_state":
                    objects.construct_mutex_state(pages, object_address=target, image_base=base)
                elif label == "callback_container":
                    objects.construct_callback_container(pages, object_address=target,
                        descriptor_address=source, image_base=base, allocate=allocation.model)
                else:
                    objects.construct_signer_child(pages, object_address=target,
                        image_base=base, allocate=allocation.model)
                assert flatten(pages)[:0xA000] == expected, (label, hex(base), hex(target))
                assert allocation.calls == allocation_calls, label
                cases.append({"case": label, "image_base": hex(base),
                              "cross_page": object_offset == 0x1FF0,
                              "memory_match": True, "allocation_sequence_match": True})

        for label, offset in (("copy_service_reference", 0x264404),
                              ("copy_flag_reference", 0x2641D8),
                              ("copy_shared_reference", 0x15F690)):
            for counter in (None, 0, 1, 0xFFFF_FFFF):
                pages = fresh_pages()
                source, target = GUEST + 0x1010, GUEST + 0x1FF8
                count_pointer = GUEST + 0x8000 if counter is not None else 0
                _write_span(pages, source, (GUEST + 0xA180).to_bytes(8, "little")
                            + count_pointer.to_bytes(8, "little"))
                if count_pointer:
                    _write_span(pages, count_pointer, counter.to_bytes(4, "little"))
                _, expected, _, _ = native(args.library, base, offset, [target, source], pages)
                objects.copy_reference_wrapper(pages, object_address=target, source_address=source)
                assert flatten(pages)[:0xA000] == expected, label
                cases.append({"case": label, "image_base": hex(base),
                              "count_before": counter, "memory_match": True})
            pages = fresh_pages()
            target = GUEST + 0x1FF8
            _write_span(pages, target, (GUEST + 0xA180).to_bytes(8, "little")
                        + (GUEST + 0x8000).to_bytes(8, "little"))
            _write_span(pages, GUEST + 0x8000, (7).to_bytes(4, "little"))
            _, expected, _, _ = native(args.library, base, offset, [target, target], pages)
            objects.copy_reference_wrapper(pages, object_address=target, source_address=target)
            assert flatten(pages)[:0xA000] == expected
            cases.append({"case": label + "_self_alias", "image_base": hex(base),
                          "memory_match": True})

        for cross_page in (False, True):
            pages = fresh_pages()
            root = GUEST + (0x1FE0 if cross_page else 0x1000)
            config_a, config_b = GUEST + 0xA100, GUEST + 0xA108
            child_a, child_b = GUEST + 0xA200, GUEST + 0xA208
            result = objects.construct_signer_root(pages, object_address=root,
                configuration_a=config_a, configuration_b=config_b,
                child_a=child_a, child_b=child_b)
            assert result.object_address == root
            assert int.from_bytes(_read_span(pages, root + 8, 8), "little") == config_a
            assert int.from_bytes(_read_span(pages, root + 0x20, 8), "little") == child_b
            cases.append({"case": "root_dependency_assembly", "image_base": hex(base),
                          "cross_page": cross_page, "memory_match": True})

        for kind, offset in (("embedded_state", 0x288E98), ("service_refs", 0x263FB8)):
            for object_offset in (0x1000, 0x1FE8):
                pages = fresh_pages()
                source_a, source_b = GUEST + 0xA100, GUEST + 0xA110
                for source, counter in ((source_a, GUEST + 0x8000), (source_b, GUEST + 0x8010)):
                    _write_span(pages, source, (GUEST + 0xA180).to_bytes(8, "little")
                                + counter.to_bytes(8, "little"))
                    _write_span(pages, counter, (7).to_bytes(4, "little"))
                target = GUEST + object_offset
                _, expected, calls, _ = native(args.library, base, offset, [target], pages,
                    libc=args.libc, service_references=(source_a, source_b))
                allocation = Allocator()
                objects.construct_signer_handler(pages, object_address=target, image_base=base,
                    allocate=allocation.model, kind=kind, service_reference_address=source_a,
                    flag_reference_address=source_b)
                assert flatten(pages)[:0xA000] == expected, (kind, hex(base))
                assert allocation.calls == calls
                cases.append({"case": "handler_" + kind, "image_base": hex(base),
                              "cross_page": object_offset == 0x1FE8,
                              "memory_match": True, "allocation_sequence_match": True,
                              "service_singleton_construction_verified": False})

        for kind, start, end, field, vtable in (
            ("embedded_state", 0x27CCC8, 0x27CCE4, 0x20, 0x35F7E0),
            ("service_refs", 0x27CD7C, 0x27CD98, 0x18, 0x35DC50),
        ):
            pages = fresh_pages()
            root, child, handler, pair = (GUEST + 0x1000, GUEST + 0x1100,
                                          GUEST + 0x1200, GUEST + 0x1FF8)
            _write_span(pages, root + field, child.to_bytes(8, "little"))
            _write_span(pages, child + 0x20, pair.to_bytes(8, "little"))
            _write_span(pages, handler, (base + vtable).to_bytes(8, "little"))
            _, expected, _, _ = native(args.library, base, start, [], pages,
                extra_registers={UC_ARM64_REG_X19: handler, UC_ARM64_REG_X28: root}, stop_offset=end)
            objects.bind_signer_child_callback(pages, child_address=child,
                handler_address=handler, image_base=base, kind=kind)
            assert flatten(pages)[:0xA000] == expected
            cases.append({"case": "bind_" + kind, "image_base": hex(base),
                          "cross_page": True, "memory_match": True})

        for first, second, env, types in (
            (GUEST + 0xA200, GUEST + 0xA208, GUEST + 0xA000, (1, 2)),
            (GUEST + 0xA200, GUEST + 0xA208, GUEST + 0xA000, (3, 0)),
            (0, GUEST + 0xA208, GUEST + 0xA000, (0, 1)),
            (GUEST + 0xA200, 0, GUEST + 0xA000, (2, 0)),
            (0, 0, GUEST + 0xA000, (0, 0)),
            (GUEST + 0xA200, GUEST + 0xA208, 0, (1, 2)),
            (GUEST + 0xA200, GUEST + 0xA208, GUEST + 0xA000, (4, 0xFFFF_FFFF)),
        ):
            pages = jni_pages(env)
            ref_types = {first: types[0], second: types[1]}
            result, _, _, ledger = native(args.library, base, 0x28C268,
                [GUEST + 0x1000], pages, references=(first, second), env=env, ref_types=ref_types)
            actual_ledger = []
            refs = iter((first, second))

            def invoke(*values):
                actual_ledger.append(["invoke", *values])
                return next(refs)

            def get_type(environment, reference):
                actual_ledger.append(["get_type", environment, reference])
                return ref_types.get(reference, 0)

            def delete(kind, environment, reference):
                actual_ledger.append(["delete", kind, environment, reference])

            actual = callbacks.publish_signer_handle(root_address=GUEST + 0x1000,
                environment=env, invoke=invoke, get_reference_type=get_type, delete_reference=delete)
            assert int(actual) == result and actual_ledger == ledger
            cases.append({"case": "publisher", "image_base": hex(base),
                "first_nonnull": bool(first), "second_nonnull": bool(second),
                "environment_nonnull": bool(env), "reference_types": list(types),
                "return_match": True, "callback_and_cleanup_order_match": True})

    negatives = []
    for label, failure in (("null_allocation", 0), ("unmapped_allocation", 0x60000000)):
        pages = fresh_pages()
        before = flatten(pages)
        try:
            objects.construct_signer_child(pages, object_address=GUEST + 0x1000,
                image_base=0x122C0000, allocate=lambda staged, size: failure)
        except (RefillUnsupported, ValueError):
            assert flatten(pages) == before
        else:
            raise AssertionError(label)
        negatives.append({"case": label, "rejected": True, "pages_unchanged": True})
    for fail_index in range(2, 7):
        pages = fresh_pages()
        before = flatten(pages)
        allocation = Allocator()

        def fail_later(staged, size):
            if len(allocation.calls) + 1 == fail_index:
                return 0
            return allocation.model(staged, size)

        try:
            objects.construct_signer_child(pages, object_address=GUEST + 0x1FF0,
                image_base=0x122C0000, allocate=fail_later)
        except RefillUnsupported:
            assert flatten(pages) == before
        else:
            raise AssertionError(("late_allocation", fail_index))
        negatives.append({"case": "allocation_failure_" + str(fail_index),
                          "rejected": True, "pages_unchanged": True})
    for label, actual_vtable, pair in (
        ("wrong_handler_type", 0, GUEST + 0x2000),
        ("null_callback_pair", 0x122C0000 + 0x35F7E0, 0),
        ("unmapped_callback_pair", 0x122C0000 + 0x35F7E0, 0x60000000),
    ):
        pages = fresh_pages()
        _write_span(pages, GUEST + 0x1000, actual_vtable.to_bytes(8, "little"))
        _write_span(pages, GUEST + 0x1120, pair.to_bytes(8, "little"))
        before = flatten(pages)
        try:
            objects.bind_signer_child_callback(pages, child_address=GUEST + 0x1100,
                handler_address=GUEST + 0x1000, image_base=0x122C0000, kind="embedded_state")
        except (ValueError, RefillUnsupported):
            assert flatten(pages) == before
        else:
            raise AssertionError(label)
        negatives.append({"case": label, "rejected": True, "pages_unchanged": True})
    for label, kwargs in (("null_configuration", {"configuration_a": 0}),
                          ("null_child", {"child_b": 0}),
                          ("unmapped_root", {"object_address": GUEST + 0x60000000})):
        pages = fresh_pages()
        before = flatten(pages)
        values = {"object_address": GUEST + 0x1000, "configuration_a": GUEST + 0xA100,
                  "configuration_b": GUEST + 0xA108, "child_a": GUEST + 0xA200,
                  "child_b": GUEST + 0xA208}
        values.update(kwargs)
        try:
            objects.construct_signer_root(pages, **values)
        except (ValueError, RefillUnsupported):
            assert flatten(pages) == before
        else:
            raise AssertionError(label)
        negatives.append({"case": label, "rejected": True, "pages_unchanged": True})
    result = {"evidence_id": "vm9_signer_objects_python_20261003",
        "native_library_sha256": LIBRARY_SHA256,
        "libc_sha256": hashlib.sha256(args.libc.read_bytes()).hexdigest(),
        "fresh_memory": True, "captured_pages_required": False, "jvm_required": False,
        "native_execution_used_for_verification_only": True, "cases": cases,
        "negative_cases": negatives,
        "oracle_boundaries": ["malloc", "memset", "diagnostic scope entry/exit",
                              "service and flag singleton getters (explicit fresh references)",
                              "thread attachment", "Java callback and JNI reference methods"],
        "root_dependency_assembly": True, "complete_root_constructor": False,
        "complete_python_medusa": False}
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"differential_cases": len(cases), "negative_cases": len(negatives),
                      "complete_root_constructor": False}))


if __name__ == "__main__":
    main()
