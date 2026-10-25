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
VM_OPERAND_WATCH_RANGES = ((0x7000DF00, 0x7000DF80),
                           (0x7000EE00, 0x7000EE80))

# These are the VM instructions whose stores are on the last failing paths.
# The native code is a threaded interpreter: the handler entry decodes a
# virtual instruction, performs the operation, and then branches through the
# next handler.  Keep the operation names descriptive rather than pretending
# that the obfuscated VM has source-level names.
VM_HANDLER_OPS = {
    0x1692FC: "add64",
    0x16DB74: "add_signed32_immediate",
    0x16E254: "materialize_signed_immediate",
    0x16E41C: "materialize_bitwise_value",
    0x16F974: "load_indexed_signed_offset",
    0x17030C: "load_signed_word_indexed",
}
VM_OPERAND_STORE_PCS = (0x15F5A8, 0x15F5BC, 0x15F5C4, 0x162884,
                        0x162898, 0x1628A0, 0x171268)


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
    operand_writes = []
    counters = {"instructions": 0}
    workspace = {"base": None, "cursor": None, "code": None}
    original_native = oracle.native

    def _regs(cpu):
        return [cpu.reg_read(getattr(arm, f"UC_ARM64_REG_X{i}")) for i in range(6)]

    def _vm_regs(cpu):
        return {f"x{i}": hex(cpu.reg_read(getattr(arm, f"UC_ARM64_REG_X{i}")))
                for i in (8, 9, 10, 11, 12, 13, 14, 19, 20, 23, 28)}

    def _record(kind, **fields):
        if len(events) < 4096:
            events.append(dict(kind=kind, **fields))

    def _read_word(cpu, address, width=8):
        try:
            return bytes(cpu.mem_read(address, width)).hex()
        except Exception:
            return None

    def _read_u32(cpu, address):
        raw = _read_word(cpu, address, 4)
        return int.from_bytes(bytes.fromhex(raw), "little") if raw is not None else None

    def _slot_value(cpu, index):
        if index is None or not 0 <= int(index) < 32:
            return None
        backing = cpu.reg_read(arm.UC_ARM64_REG_X28)
        raw = _read_word(cpu, backing + int(index) * 8, 8)
        return hex(int.from_bytes(bytes.fromhex(raw), "little")) if raw is not None else None

    def _handler_semantics(cpu, offset):
        """Record decoded operands at a handler store before it executes.

        The cursor form is used by the handlers that load the current VM word
        from ``[x19]``.  ``+0x1692fc`` is the one branch that receives the word
        in x21 directly, so both candidates are retained for auditability.
        Register values are captured before the store; the separate
        ``vm_register_write`` event records the post-store bytes.
        """
        operation = VM_HANDLER_OPS[offset]
        x = {index: cpu.reg_read(getattr(arm, f"UC_ARM64_REG_X{index}"))
             for index in (8, 9, 10, 11, 12, 13, 14, 15, 19, 21, 28)}
        cursor = x[19]
        cursor_pointer = _read_u32(cpu, cursor)
        cursor_pointer_address = None
        if cursor_pointer is not None:
            pointer_raw = _read_word(cpu, cursor, 8)
            cursor_pointer_address = int.from_bytes(bytes.fromhex(pointer_raw), "little")
        opcode_at_cursor = (_read_u32(cpu, cursor_pointer_address)
                            if cursor_pointer_address is not None else None)
        opcode_x21 = x[21] & 0xFFFFFFFF
        if offset == 0x1692FC:
            source_indices = [(opcode_x21 >> 12) & 0x1F,
                              (opcode_x21 >> 22) & 0x1F]
            destination_index = (opcode_x21 >> 17) & 0x1F
            result = x[10]
            source_values = [_slot_value(cpu, index) for index in source_indices]
            decoded = {
                "source_indices": source_indices,
                "destination_index": destination_index,
                "source_values": source_values,
                "destination_before": _slot_value(cpu, destination_index),
                "result": hex(result),
            }
        elif offset == 0x16DB74:
            source_index = x[11] & 0x1F
            destination_index = x[15] & 0x1F
            decoded = {
                "source_indices": [source_index],
                "destination_index": destination_index,
                "source_values": [_slot_value(cpu, source_index)],
                "destination_before": _slot_value(cpu, destination_index),
                "result": hex(x[10]),
                "immediate_delta": hex((x[10] - x[11]) & 0xFFFFFFFFFFFFFFFF),
            }
        elif offset == 0x16E254:
            destination_index = x[13] & 0x1F
            decoded = {
                "source_indices": [],
                "destination_index": destination_index,
                "source_values": [],
                "destination_before": _slot_value(cpu, destination_index),
                "result": hex(x[15]),
            }
        elif offset == 0x16E41C:
            destination_index = x[10] & 0x1F
            decoded = {
                "source_indices": [],
                "destination_index": destination_index,
                "source_values": [],
                "destination_before": _slot_value(cpu, destination_index),
                "result": hex(x[14]),
            }
        elif offset == 0x16F974:
            source_index = x[10] & 0x1F
            destination_index = x[14] & 0x1F
            operand_address = (x[12] + x[13]) & ((1 << 64) - 1)
            decoded = {
                "source_indices": [source_index],
                "destination_index": destination_index,
                "source_values": [_slot_value(cpu, source_index)],
                "destination_before": _slot_value(cpu, destination_index),
                "result": hex(x[9]),
                "signed_offset": hex(x[13] & 0xFFFFFFFFFFFFFFFF),
                "operand_address": hex(operand_address),
                "operand_value": _read_word(cpu, operand_address, 8),
            }
        else:  # +0x17030c
            source_index = x[13] & 0x1F
            destination_index = x[14] & 0x1F
            signed_offset = x[11] if x[11] < (1 << 63) else x[11] - (1 << 64)
            operand_address = (x[10] + signed_offset) & ((1 << 64) - 1)
            decoded = {
                "source_indices": [source_index],
                "destination_index": destination_index,
                "source_values": [_slot_value(cpu, source_index)],
                "destination_before": _slot_value(cpu, destination_index),
                "result": hex(x[9]),
                "signed_offset": hex(x[11] & 0xFFFFFFFFFFFFFFFF),
                "operand_address": hex(operand_address),
                "operand_value": _read_word(cpu, operand_address, 4),
            }
        _record("vm_handler_semantics", pc=hex(offset), operation=operation,
                opcode_from_x21=hex(opcode_x21),
                opcode_at_cursor=(hex(opcode_at_cursor)
                                  if opcode_at_cursor is not None else None),
                cursor_address=hex(cursor),
                cursor_pointer=(hex(cursor_pointer_address)
                                if cursor_pointer_address is not None else None),
                registers={f"x{index}": hex(value) for index, value in x.items()},
                written_value=decoded["result"],
                decoded=decoded)

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
            if offset in VM_HANDLER_OPS:
                _handler_semantics(cpu, offset)
            if offset in VM_OPERAND_STORE_PCS:
                registers = {f"x{index}": hex(cpu.reg_read(getattr(arm, f"UC_ARM64_REG_X{index}")))
                             for index in (8, 9, 10, 15, 16, 17, 19, 20, 21, 28)}
                if offset == 0x171268:
                    address = (int(registers["x17"], 16) +
                               int(registers["x16"], 16)) & ((1 << 64) - 1)
                    written_value = registers["x15"]
                elif offset == 0x15F5A8:
                    address = int(registers["x20"], 16)
                    written_value = "0x0"
                elif offset == 0x15F5BC:
                    address = int(registers["x20"], 16)
                    written_value = registers["x8"]
                elif offset == 0x15F5C4:
                    address = int(registers["x20"], 16) + 8
                    written_value = registers["x8"]
                elif offset == 0x162884:
                    address = int(registers["x20"], 16)
                    written_value = "0x0"
                elif offset == 0x162898:
                    address = int(registers["x20"], 16)
                    written_value = registers["x8"]
                else:  # +0x1628a0
                    address = int(registers["x20"], 16) + 8
                    written_value = registers["x8"]
                if any(start <= address < end for start, end in VM_OPERAND_WATCH_RANGES):
                    _record("vm_operand_store_semantics", pc=hex(offset),
                            address=hex(address), written_value=written_value,
                            previous_value=_read_word(cpu, address, 8),
                            registers=registers)
            if offset == 0x16848C:
                # +168324 derives the physical VM frame from the caller's
                # stack input.  x28 is the 32-slot backing array and x19 is
                # its instruction cursor at this point in the real frame.
                x28 = cpu.reg_read(arm.UC_ARM64_REG_X28)
                x19 = cpu.reg_read(arm.UC_ARM64_REG_X19)
                workspace["base"] = x28
                workspace["cursor"] = x19
                workspace["code"] = x28 - 0x130
                _record("vm_workspace_owner", pc=hex(offset),
                        register_backing_address=hex(x28),
                        cursor_address=hex(x19), code_address=hex(x28 - 0x130),
                        register_words=[hex(int.from_bytes(bytes(cpu.mem_read(x28 + i * 8, 8)), "little"))
                                        for i in range(32)],
                        cursor_word=hex(int.from_bytes(bytes(cpu.mem_read(x19, 8)), "little")),
                        code_word=hex(int.from_bytes(bytes(cpu.mem_read(x28 - 0x130, 8)), "little")),
                        operand_watch_initial={hex(start): _read_word(cpu, start, end - start)
                                               for start, end in VM_OPERAND_WATCH_RANGES})
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
            if offset in (0x1702EC, 0x1702F4, 0x1702FC, 0x170304, 0x170308):
                x28 = cpu.reg_read(arm.UC_ARM64_REG_X28)
                x13 = cpu.reg_read(arm.UC_ARM64_REG_X13)
                x10 = cpu.reg_read(arm.UC_ARM64_REG_X10)
                x11 = cpu.reg_read(arm.UC_ARM64_REG_X11)
                x1 = cpu.reg_read(arm.UC_ARM64_REG_X1)
                x12 = cpu.reg_read(arm.UC_ARM64_REG_X12)
                x23 = cpu.reg_read(arm.UC_ARM64_REG_X23)
                target = None
                if offset == 0x1702F4:
                    target = x28 + (x13 << 3)
                elif offset == 0x170308:
                    signed = x11 if x11 < (1 << 63) else x11 - (1 << 64)
                    target = (x10 + signed) & ((1 << 64) - 1)
                _record("vm_workspace_state", pc=hex(offset),
                        x28=hex(x28), x13=hex(x13), x10=hex(x10), x11=hex(x11),
                        x1=hex(x1), x12=hex(x12), x23=hex(x23),
                        target=hex(target) if target is not None else None,
                        target_bytes=_read_word(cpu, target, 8) if target is not None else None,
                        x28_bytes=_read_word(cpu, x28, 0x40),
                        x1_bytes=_read_word(cpu, x1, 0x40),
                        x12_bytes=_read_word(cpu, x12, 0x20),
                        x23_bytes=_read_word(cpu, x23, 0x20))

        def write(cpu, address, size):
            if old_write:
                old_write(cpu, address, size)
            if any(start <= address < end for start, end in VM_OPERAND_WATCH_RANGES):
                operand_writes.append({
                    "kind": "vm_operand_write",
                    "pc": hex(cpu.reg_read(arm.UC_ARM64_REG_PC) - base),
                    "address": hex(address),
                    "size": size,
                    "previous_value": bytes(cpu.mem_read(address, size)).hex(),
                })
            if (base + SLOT_OFFSETS[0] <= address < base + SLOT_OFFSETS[-1] + 8
                    or table_start <= address < table_end
                    or 0x7000EC00 <= address < 0x7000ED40
                    or 0x7000D500 <= address < 0x7000D700):
                before = bytes(cpu.mem_read(address, size)).hex()
                _record("memory_write", pc=hex(cpu.reg_read(arm.UC_ARM64_REG_PC) - base),
                        address=hex(address), size=size,
                        previous_value=before)
            backing = workspace["base"]
            if backing is not None and backing - 8 <= address < backing + 32 * 8:
                first = address - backing
                _record("vm_register_write", pc=hex(cpu.reg_read(arm.UC_ARM64_REG_PC) - base),
                        address=hex(address), slot=first // 8 if first >= 0 else -1,
                        size=size, previous_value=bytes(cpu.mem_read(address, size)).hex())

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
    register_writes = [event for event in events if event["kind"] == "vm_register_write"]
    handler_semantics = [event for event in events
                         if event["kind"] == "vm_handler_semantics"]
    slot_1_zero_results = [event for event in handler_semantics
                           if event["decoded"].get("destination_index") == 1
                           and event.get("written_value") == "0x0"]
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
        "dispatch_target_before_failed_read": targets[-1] if targets else None,
        "first_effective_handler_value": handler_values[0] if handler_values else None,
        "vm_workspace_owner": next((event for event in events
                                     if event["kind"] == "vm_workspace_owner"), None),
        "vm_operand_writes": operand_writes,
        "vm_operand_store_semantics": [event for event in events
                                        if event["kind"] == "vm_operand_store_semantics"],
        "vm_operand_pointer_writer": next((event for event in events
                                            if event["kind"] == "vm_operand_store_semantics"
                                            and event["address"] == "0x7000df38"
                                            and event["written_value"] == "0x7000ee38"), None),
        "vm_handler_semantics": handler_semantics,
        "last_vm_handler_semantics": next((event for event in reversed(events)
                                            if event["kind"] == "vm_handler_semantics"), None),
        "vm_register_writes": register_writes,
        "vm_register_slot_1_zero_results": slot_1_zero_results,
        "vm_register_slot_1_last_zero_result": (slot_1_zero_results[-1]
                                                 if slot_1_zero_results else None),
        "vm_register_slot_1_written_before_failure": any(
            event.get("slot") == 1 for event in events
            if event["kind"] == "vm_register_write"),
        "vm_register_slot_1_value_before_failure": next((event["x28_bytes"][16:32]
                                                          for event in reversed(events)
                                                          if event["kind"] == "vm_workspace_state"
                                                          and event["pc"] == "0x1702f4"), None),
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
        "schema": "vm9-request-runtime-table-owner-fresh-20261025-v5",
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
            "Memory write observer values are pre-store snapshots; handler written_value and post-store workspace snapshots carry the actual result.",
            "Handler semantics identify the VM operation that produced the failing register value; they do not reconstruct the missing VM program or dispatch table.",
            "No signer output, whole-request native differential, live JVM or online acceptance is claimed.",
        ],
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("runtime table owner probe", len(rows), "cases", flush=True)


if __name__ == "__main__":
    main()
