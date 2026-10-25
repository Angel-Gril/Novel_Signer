"""Trace the native bootstrap owner of the request VM dispatch table.

This is a read-only owner probe.  It maps the unresolved runtime-table page
with a canary only so native reads/writes can be observed without inventing
handler addresses.  The canary is never treated as a dispatch table and the
probe cannot produce a signer result.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as arm

import verify_vm9_request_dispatch_fresh_20261020 as dispatch
import verify_vm9_signer_objects as oracle

BASES = (0x122C0000, 0x775C205000)
# Keep the literal list readable while rejecting an accidental non-hex edit.
TABLE_OFFSETS = tuple(int(value.replace(" ", ""), 16) for value in
                      ("13bb8f0", "13bbaf0", "13bbcf0", "13bbe18", "13bb7f0"))
SLOT_OFFSETS = (0x3798D8, 0x3798E0, 0x3798E8, 0x3798F0, 0x3798F8)
TABLE_PAGE_OFFSET = 0x13BB000
TABLE_PAGE_COUNT = 2
CANARY = bytes([0xA5]) * 4096
LIBRARY_SHA256 = oracle.LIBRARY_SHA256


def _imports(library: Path):
    with library.open("rb") as stream:
        elf = ELFFile(stream)
        dynamic = elf.get_section_by_name(".dynsym")
        relocs = elf.get_section_by_name(".rela.plt")
        return {0x347E70 + 0x20 + index * 0x10:
                dynamic.get_symbol(relocation["r_info_sym"]).name
                for index, relocation in enumerate(relocs.iter_relocations())}


def _runtime_pages(image: int):
    return {((image + TABLE_PAGE_OFFSET + page * 0x1000) >> 12): bytearray(CANARY)
            for page in range(TABLE_PAGE_COUNT)}


def run(library: Path, libc: Path, image: int):
    pages, kw = dispatch.fixture(library, image, "callback_success")
    pair = dispatch.G + 0x2400
    dispatch._write_span(pages, pair, (image + 0x2830C4).to_bytes(8, "little"))
    dispatch._write_span(pages, dispatch.G + 0x2500, bytes(0x200))
    pages.update(_runtime_pages(image))
    imports = _imports(library)
    initial_slot_values = {
        hex(image + offset): bytes(dispatch._read_span(pages, image + offset, 8)).hex()
        for offset in SLOT_OFFSETS
    }
    events = []
    counters = {"instructions": 0}
    original_native = oracle.native

    def _regs(cpu):
        return [cpu.reg_read(getattr(arm, f"UC_ARM64_REG_X{i}")) for i in range(6)]

    def _vm_regs(cpu):
        return {f"x{i}": hex(cpu.reg_read(getattr(arm, f"UC_ARM64_REG_X{i}")))
                for i in (8, 9, 10, 11, 12, 13, 14, 19, 20, 23, 28)}

    def _record(kind, **fields):
        if len(events) < 4096:
            events.append(dict(kind=kind, **fields))

    def traced_native(*native_args, **kwargs):
        base = native_args[1]
        old_instruction = kwargs.get("instruction_observer")
        old_write = kwargs.get("memory_write_observer")
        old_read = kwargs.get("memory_read_observer")
        old_unmapped = kwargs.get("unmapped_observer")
        old_malloc = kwargs.get("malloc_handler")
        table_start = base + TABLE_PAGE_OFFSET
        table_end = table_start + TABLE_PAGE_COUNT * 0x1000

        def instruction(cpu, address):
            counters["instructions"] += 1
            if old_instruction:
                old_instruction(cpu, address)
            offset = address - base
            if offset in imports:
                _record("import_call", pc=hex(offset), name=imports[offset],
                        registers=[hex(value) for value in _regs(cpu)])
            if offset in (0x27DD04, 0x2830C4, 0x168324, 0x16848C,
                          0x168490, 0x1684BC, 0x170308, 0x17033C):
                _record("dispatch_instruction", pc=hex(offset),
                        registers=[hex(value) for value in _regs(cpu)],
                        vm_registers=_vm_regs(cpu))
            if offset == 0x16848C:
                slot = base + 0x3798D8
                _record("relocation_slot_read", pc=hex(offset), address=hex(slot),
                        value=bytes(cpu.mem_read(slot, 8)).hex())
            elif offset == 0x168490:
                _record("relocation_slot_loaded", pc=hex(offset),
                        value=hex(cpu.reg_read(arm.UC_ARM64_REG_X10)))
            elif offset == 0x170308:
                _record("dispatch_target_before_read", pc=hex(offset),
                        value=hex(cpu.reg_read(arm.UC_ARM64_REG_X10)))
            elif offset == 0x1684BC:
                x10 = cpu.reg_read(arm.UC_ARM64_REG_X10)
                x9 = cpu.reg_read(arm.UC_ARM64_REG_X9)
                address = x10 + ((x9 & 0x3F) << 3)
                _record("runtime_handler_target_before_read", pc=hex(offset),
                        address=hex(address))
                try:
                    _record("runtime_handler_value", pc=hex(offset), address=hex(address),
                            value=bytes(cpu.mem_read(address, 8)).hex())
                except Exception:
                    pass
            elif offset == 0x17033C:
                address = cpu.reg_read(arm.UC_ARM64_REG_X8)
                _record("runtime_handler_target_before_read", pc=hex(offset),
                        address=hex(address))
                try:
                    _record("runtime_handler_value", pc=hex(offset), address=hex(address),
                            value=bytes(cpu.mem_read(address, 8)).hex())
                except Exception:
                    pass

        def write(cpu, address, size):
            if old_write:
                old_write(cpu, address, size)
            if (base + SLOT_OFFSETS[0] <= address < base + SLOT_OFFSETS[-1] + 8
                    or table_start <= address < table_end):
                _record("memory_write", pc=hex(cpu.reg_read(arm.UC_ARM64_REG_PC) - base),
                        address=hex(address), size=size,
                        value=bytes(cpu.mem_read(address, size)).hex())

        def read(cpu, address, size):
            if old_read:
                old_read(cpu, address, size)
            if table_start <= address < table_end:
                _record("runtime_table_read", pc=hex(cpu.reg_read(arm.UC_ARM64_REG_PC) - base),
                        address=hex(address), size=size,
                        value=bytes(cpu.mem_read(address, size)).hex())

        def unmapped(cpu, access, address, size, value):
            if old_unmapped:
                old_unmapped(cpu, access, address, size, value)
            _record("unmapped", pc=hex(cpu.reg_read(arm.UC_ARM64_REG_PC) - base),
                    access=access, address=hex(address), size=size, value=hex(value))

        def malloc(cpu, size):
            _record("malloc", pc=hex(cpu.reg_read(arm.UC_ARM64_REG_PC) - base), size=size)
            return old_malloc(cpu, size) if old_malloc else None

        kwargs["map_extra_input_pages"] = True
        kwargs["instruction_observer"] = instruction
        kwargs["memory_write_observer"] = write
        kwargs["memory_read_observer"] = read
        kwargs["unmapped_observer"] = unmapped
        if old_malloc:
            kwargs["malloc_handler"] = malloc
        return original_native(*native_args, **kwargs)

    service = dispatch.Services(image, "callback_success")
    def malloc(cpu, size):
        return service.allocation("malloc", size,
            lambda address, width: bytes(cpu.mem_read(address, width)),
            lambda address, data: cpu.mem_write(address, data))
    # The wrapper above is deliberately used only for this direct native call.
    oracle.native = traced_native
    outcome = "returned"
    error = None
    try:
        oracle.native(library, image, 0x27DD04,
            [kw[name] for name in ("receiver_address", "url_reference_address",
                                    "header_reference_address", "mode")], pages,
            libc=libc, real_diagnostics=True, real_singletons=True,
            real_mutexes=True, real_recursive_mutexes=True, thread_id=137,
            extra_registers={arm.UC_ARM64_REG_X8: dispatch.OUT,
                             arm.UC_ARM64_REG_SP: dispatch.SP,
                             arm.UC_ARM64_REG_TPIDR_EL0: dispatch.TP},
            host_imports=service.imports(image), malloc_handler=malloc,
            instruction_limit=1_000_000,
            map_extra_input_pages=True)
    except Exception as exc:  # The first unresolved read is expected to stop this probe.
        outcome = "stopped"
        error = f"{type(exc).__name__}: {exc}"
    finally:
        oracle.native = original_native

    writes = [event for event in events if event["kind"] == "memory_write"]
    reads = [event for event in events if event["kind"] == "runtime_table_read"]
    external_reads = [event for event in reads
                      if int(event["address"], 16) >= image + TABLE_PAGE_OFFSET
                      and int(event["address"], 16) < image + TABLE_PAGE_OFFSET + TABLE_PAGE_COUNT * 0x1000]
    slot_reads = [event for event in events if event["kind"] == "relocation_slot_read"]
    slot_loaded = [event for event in events if event["kind"] == "relocation_slot_loaded"]
    targets = [event for event in events if event["kind"] == "dispatch_target_before_read"]
    handler_values = [event for event in events if event["kind"] == "runtime_handler_value"]
    imports_seen = [event for event in events if event["kind"] == "import_call"]
    return {
        "image_base": hex(image),
        "outcome": outcome,
        "error": error,
        "native_instructions_observed": counters["instructions"],
        "runtime_table_pointer_slots": [hex(image + offset) for offset in SLOT_OFFSETS],
        "relocation_slot_initial_values": initial_slot_values,
        "runtime_table_addresses": [hex(image + offset) for offset in TABLE_OFFSETS],
        "runtime_table_page_canary_mapped": True,
        "runtime_table_canary_value": "a5" * 8,
        "slot_or_table_writes": writes,
        "runtime_table_reads": reads,
        "external_runtime_table_reads": external_reads,
        "import_calls": imports_seen,
        "pthread_create_calls": [e for e in imports_seen if e["name"] == "pthread_create"],
        "mmap_calls": [e for e in imports_seen if e["name"] == "mmap"],
        "calloc_calls": [e for e in imports_seen if e["name"] == "calloc"],
        "malloc_calls": [e for e in events if e["kind"] == "malloc"],
        "first_runtime_table_read": reads[0] if reads else None,
        "first_external_runtime_table_read": external_reads[0] if external_reads else None,
        "first_relocation_slot_read": slot_reads[0] if slot_reads else None,
        "relocation_slot_loaded": slot_loaded[0] if slot_loaded else None,
        "dispatch_target_before_failed_read": targets[0] if targets else None,
        "first_effective_handler_value": handler_values[0] if handler_values else None,
        "slot_write_observed": bool(writes),
        "synthetic_dispatch_table_used": False,
        "whole_request_native_differential_verified": False,
        "fresh_signer_output_verified": False,
        "events": events,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--libc", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    digest = hashlib.sha256(args.library.read_bytes()).hexdigest()
    if digest != LIBRARY_SHA256:
        raise SystemExit(f"unexpected native sample {digest}")
    rows = [run(args.library, args.libc, image) for image in BASES]
    report = {
        "schema": "vm9-request-runtime-table-owner-fresh-20261025-v1",
        "evidence_date": "2026-10-25",
        "sample_sha256": LIBRARY_SHA256,
        "matching_libc_sha256": hashlib.sha256(args.libc.read_bytes()).hexdigest(),
        "cases": rows,
        "canary_mapping_is_observation_only": True,
        "runtime_table_content_reconstructed": False,
        "synthetic_dispatch_table_used": False,
        "limitations": [
            "The unresolved runtime page is filled with a canary solely to observe native reads and writes.",
            "A canary read is a stop condition, not evidence of a valid handler or completed request.",
            "No signer output, whole-request native differential, live JVM or online acceptance is claimed.",
        ],
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("runtime table owner probe", len(rows), "cases", flush=True)


if __name__ == "__main__":
    main()
