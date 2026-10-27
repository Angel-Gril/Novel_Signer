"""Continue the real native outer child into the Java facade on one CPU.

The outer getter owns the receiver and its callback pair.  At the cold return
the verifier keeps that Unicorn CPU, overlays only fresh guest URL/header/JNI
fixture bytes, and enters the normal facade with ``root+0x18`` as receiver.
This is a bounded ABI/continuation probe; it does not claim a signer result.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from unicorn import arm64_const as arm

import verify_vm9_java_request_facade_fresh_20261020 as facade
import verify_vm9_jni_header_input_fresh_20261020 as headers
import verify_vm9_outer_signer_native as outer
import verify_vm9_signer_objects as oracle


BASES = (0x122C0000, 0x775C205000)
G = headers.G
FACADE_ENTRY = 0x17B8F8
CHILD_ENTRY = 0x27DD04
OWNING_VM = 0x2830C4
JNI_FIND_CLASS = G + 0xF800
JNI_METHOD_LOOKUP = G + 0xF810
JNI_EXCEPTION_CHECK = G + 0xF830
JNI_VARIADIC_CALL = G + 0xF850
JNI_METHOD_LOOKUP_108 = G + 0xF870
JNI_ARRAY_ACCESS = G + 0xF890
JNI_ARRAY_LENGTH = G + 0xF8B0
JNI_ARRAY_ELEMENT = G + 0xF8D0
JNI_STRING_ACCESS = G + 0xF8F0
JNI_STRING_RELEASE = G + 0xF910
JNI_HANDLE_CALL = G + 0xF930

VM_HANDLER_OPS = {
    0x1692FC: "add64",
    0x16DB74: "add_signed32_immediate",
    0x16E254: "materialize_signed_immediate",
    0x16E41C: "materialize_bitwise_value",
    0x16F974: "load_indexed_signed_offset",
    0x17030C: "load_signed_word_indexed",
}
VM_SOURCE_STORE = 0x16E118

FORMATTER_WINDOWS = {
    0xFB548: {
        "window_start": 0xFB480,
        "window_end": 0xFB590,
        "immediate_offset": 0xFB520,
        "signed_value": -7,
        "format_call_offset": 0xFB548,
    },
    0xFEFBC: {
        "window_start": 0xFEF00,
        "window_end": 0xFF000,
        "immediate_offset": 0xFEF94,
        "signed_value": -11,
        "format_call_offset": 0xFEFBC,
    },
}
FORMATTER_TRACE_OFFSETS = frozenset((
    0xFB520, 0xFB548,
    0xFEF94, 0xFEFBC,
    0xFB5DC, 0xFEE00,
    0xF83F8, 0xF8400, 0xF8404, 0xF8554, 0xF858C,
))


def _u(cpu, address, width=8):
    return int.from_bytes(bytes(cpu.mem_read(address, width)), "little")


def _json_safe(value):
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {key: _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return value


def _decode_formatter_bytecode(library: Path) -> dict:
    """Decode the two formatter-producing OP59 words from the pinned ELF."""
    raw = library.read_bytes()
    candidates = []
    for offset, call_offset in ((0xFB520, 0xFB548), (0xFEF94, 0xFEFBC)):
        word = int.from_bytes(raw[offset:offset + 4], "little")
        if (word & 0x3F) != 59:
            raise AssertionError(f"formatter source {offset:#x} is not OP59")
        source = ((word >> 17) & 0x0F) | ((word >> 27) & 0x10)
        destination = ((word >> 7) & 0x0F) | ((word >> 12) & 0x10)
        immediate = (
            ((word >> 21) & 0x1F)
            | (((word >> 11) & 1) << 5)
            | (((word >> 12) & 1) << 6)
            | (((word >> 13) & 1) << 7)
            | (((word >> 14) & 1) << 8)
            | (((word >> 15) & 1) << 9)
            | (((word >> 26) & 1) << 10)
            | (((word >> 27) & 1) << 11)
            | (((word >> 28) & 1) << 12)
            | (((word >> 29) & 1) << 13)
            | (((word >> 30) & 1) << 14)
            | (((word >> 6) & 1) << 15)
        )
        signed = immediate - 0x10000 if immediate & 0x8000 else immediate
        candidates.append({
            "bytecode_offset": hex(offset),
            "instruction_word": hex(word),
            "operation": "OP59",
            "source_register": f"R{source}",
            "destination_register": f"R{destination}",
            "signed_immediate": signed,
            "format_call_offset": hex(call_offset),
        })
    return {
        "encoding": "OP59: R[d] = sext32(R[s]) + sext16(imm16)",
        "source_register": "R0",
        "destination_register": "R2",
        "candidates": candidates,
        "interpretation": (
            "Both candidates consume virtual slot R0 and differ only in the "
            "embedded signed immediate; the formatter receives the resulting "
            "R2 value."
        ),
    }


def _overlay_guest(cpu, pages):
    """Copy fixture bytes into the already mapped guest without its canary."""
    for page, data in pages.items():
        address = page << 12
        if not G <= address < G + 0x10000:
            continue
        raw = bytes(data)
        cursor = 0
        while cursor < len(raw):
            if raw[cursor] == 0xA5:
                cursor += 1
                continue
            end = cursor + 1
            while end < len(raw) and raw[end] != 0xA5:
                end += 1
            cpu.mem_write(address + cursor, raw[cursor:end])
            cursor = end


def run(library: Path, libc: Path, image: int) -> dict:
    state = {
        "outer_root": None,
        "outer_child": None,
        "outer_vtable": None,
        "outer_vtable_target": None,
        "outer_pair": None,
        "outer_pair_target": None,
        "facade_entry": None,
        "child_entry": None,
        "owning_vm_entry": None,
        "facade_return": None,
        "facade_started": False,
        "last_pc_offset": None,
        "native_instructions": 0,
        "facade_instructions": 0,
        "memcpy_import_count": 0,
        "unresolved_branch": None,
        "descriptor_write_events": [],
        "descriptor_read_events": [],
        "argument_object_write_events": [],
        "argument_object_read_events": [],
        "syscall_mmap_events": [],
        "argument_store_events": [],
        "vm_source_slot_events": [],
        "vm_handler_trace": [],
        "vm_workspace_write_events": [],
        "vm_backing_write_events": [],
        "vm_workspace_snapshots": [],
        "descriptor_snapshot": None,
        "continuation_allocations": [],
        "continuation_allocator_events": [],
        "main_import_relocations": [],
        "main_import_write_events": [],
        "continuation_jni_calls": [],
        "helper_object_events": [],
        "helper_object_write_events": [],
        "helper_stack_write_events": [],
        "facade_return_registers": None,
        "facade_dispatch_events": [],
        "facade_stack_snapshots": [],
        "facade_native_object_snapshots": [],
        "facade_format_events": [],
        "facade_native_format_summary": [],
        "facade_tree_insert_events": [],
        "vm_bytecode_window_events": [],
        "last_vm_bytecode_window_pc": None,
        "facade_stack_write_events": [],
        "request_vm_entry_events": [],
        "unmapped": [],
    }
    markers = []
    service = facade.Services(image, "normal")
    fixture_pages, arguments = facade.fixture(library, image, "normal")

    # Keep only the Java/JNI guest import addresses.  The outer oracle already
    # binds its libc PLT (including malloc/calloc/free) to matching libc.
    continuation_imports = {
        offset: handler for offset, handler in service.imports(image).items()
        if abs(offset) > 0x10000000
    }

    def install_handle(cpu, pointer):
        cpu.mem_write(pointer, JNI_HANDLE_CALL.to_bytes(8, "little"))
        cpu.mem_write(pointer + 8, (0).to_bytes(8, "little"))
        cpu.mem_write(pointer + 0x10, (0).to_bytes(8, "little"))
        cpu.mem_write(pointer + 0x18, (0).to_bytes(8, "little"))
        cpu.mem_write(pointer + 0x20, (0).to_bytes(8, "little"))

    def find_class(cpu):
        install_handle(cpu, G + 0x9800)
        state["continuation_jni_calls"].append({
            "slot_offset": "0x30",
            "operation": "FindClass",
            "env": hex(cpu.reg_read(arm.UC_ARM64_REG_X0)),
            "name": hex(cpu.reg_read(arm.UC_ARM64_REG_X1)),
            "result": hex(G + 0x9800),
        })
        return G + 0x9800

    def method_lookup(cpu):
        install_handle(cpu, G + 0x9810)
        state["continuation_jni_calls"].append({
            "slot_offset": "0x388",
            "operation": "JNI_method_lookup_or_call",
            "env": hex(cpu.reg_read(arm.UC_ARM64_REG_X0)),
            "receiver": hex(cpu.reg_read(arm.UC_ARM64_REG_X1)),
            "arg2": hex(cpu.reg_read(arm.UC_ARM64_REG_X2)),
            "arg3": hex(cpu.reg_read(arm.UC_ARM64_REG_X3)),
            "result": hex(G + 0x9810),
        })
        return G + 0x9810

    def exception_check(cpu):
        state["continuation_jni_calls"].append({
            "slot_offset": "0x720",
            "operation": "ExceptionCheck",
            "env": hex(cpu.reg_read(arm.UC_ARM64_REG_X0)),
            "result": "0x0",
        })
        return 0

    def variadic_call(cpu):
        install_handle(cpu, G + 0x9820)
        state["continuation_jni_calls"].append({
            "slot_offset": "0x398",
            "operation": "JNI_variadic_call",
            "env": hex(cpu.reg_read(arm.UC_ARM64_REG_X0)),
            "arg1": hex(cpu.reg_read(arm.UC_ARM64_REG_X1)),
            "arg2": hex(cpu.reg_read(arm.UC_ARM64_REG_X2)),
            "arg3": hex(cpu.reg_read(arm.UC_ARM64_REG_X3)),
            "result": hex(G + 0x9820),
        })
        return G + 0x9820

    def method_lookup_108(cpu):
        install_handle(cpu, G + 0x9830)
        state["continuation_jni_calls"].append({
            "slot_offset": "0x108",
            "operation": "JNI_method_lookup_108",
            "env": hex(cpu.reg_read(arm.UC_ARM64_REG_X0)),
            "receiver": hex(cpu.reg_read(arm.UC_ARM64_REG_X1)),
            "arg2": hex(cpu.reg_read(arm.UC_ARM64_REG_X2)),
            "arg3": hex(cpu.reg_read(arm.UC_ARM64_REG_X3)),
            "result": hex(G + 0x9830),
        })
        return G + 0x9830

    def array_access(cpu):
        install_handle(cpu, G + 0x9840)
        state["continuation_jni_calls"].append({
            "slot_offset": "0x118",
            "operation": "JNI_array_or_string_access",
            "env": hex(cpu.reg_read(arm.UC_ARM64_REG_X0)),
            "arg1": hex(cpu.reg_read(arm.UC_ARM64_REG_X1)),
            "arg2": hex(cpu.reg_read(arm.UC_ARM64_REG_X2)),
            "arg3": hex(cpu.reg_read(arm.UC_ARM64_REG_X3)),
            "result": hex(G + 0x9840),
        })
        return G + 0x9840

    def array_length(cpu):
        state["continuation_jni_calls"].append({
            "slot_offset": "0x558",
            "operation": "GetArrayLength",
            "env": hex(cpu.reg_read(arm.UC_ARM64_REG_X0)),
            "array": hex(cpu.reg_read(arm.UC_ARM64_REG_X1)),
            "result": "0x3",
        })
        return 3

    def array_element(cpu):
        index = cpu.reg_read(arm.UC_ARM64_REG_X2)
        install_handle(cpu, G + 0x9850 + (index & 0xF) * 0x10)
        state["continuation_jni_calls"].append({
            "slot_offset": "0x568",
            "operation": "GetObjectArrayElement",
            "env": hex(cpu.reg_read(arm.UC_ARM64_REG_X0)),
            "array": hex(cpu.reg_read(arm.UC_ARM64_REG_X1)),
            "index": index,
            "result": hex(G + 0x9850 + (index & 0xF) * 0x10),
        })
        return G + 0x9850 + (index & 0xF) * 0x10

    def string_access(cpu):
        install_handle(cpu, G + 0x9860)
        state["continuation_jni_calls"].append({
            "slot_offset": "0x548",
            "operation": "JNI_string_access",
            "env": hex(cpu.reg_read(arm.UC_ARM64_REG_X0)),
            "string": hex(cpu.reg_read(arm.UC_ARM64_REG_X1)),
            "arg2": hex(cpu.reg_read(arm.UC_ARM64_REG_X2)),
            "result": hex(G + 0x9860),
        })
        return G + 0x9860

    def string_release(cpu):
        state["continuation_jni_calls"].append({
            "slot_offset": "0x550",
            "operation": "JNI_string_release",
            "env": hex(cpu.reg_read(arm.UC_ARM64_REG_X0)),
            "string": hex(cpu.reg_read(arm.UC_ARM64_REG_X1)),
            "chars": hex(cpu.reg_read(arm.UC_ARM64_REG_X2)),
            "result": "0x0",
        })
        return 0

    def handle_call(cpu):
        state["continuation_jni_calls"].append({
            "slot_offset": "object-vtable",
            "operation": "JNI_handle_method",
            "receiver": hex(cpu.reg_read(arm.UC_ARM64_REG_X0)),
            "arg1": hex(cpu.reg_read(arm.UC_ARM64_REG_X1)),
            "arg2": hex(cpu.reg_read(arm.UC_ARM64_REG_X2)),
            "result": "0x0",
        })
        return 0

    continuation_imports[JNI_FIND_CLASS - image] = find_class
    continuation_imports[JNI_METHOD_LOOKUP - image] = method_lookup
    continuation_imports[JNI_EXCEPTION_CHECK - image] = exception_check
    continuation_imports[JNI_VARIADIC_CALL - image] = variadic_call
    continuation_imports[JNI_METHOD_LOOKUP_108 - image] = method_lookup_108
    continuation_imports[JNI_ARRAY_ACCESS - image] = array_access
    continuation_imports[JNI_ARRAY_LENGTH - image] = array_length
    continuation_imports[JNI_ARRAY_ELEMENT - image] = array_element
    continuation_imports[JNI_STRING_ACCESS - image] = string_access
    continuation_imports[JNI_STRING_RELEASE - image] = string_release
    continuation_imports[JNI_HANDLE_CALL - image] = handle_call

    def execution_observer(cpu, pc):
        pending = state.pop("pending_vm_writes", [])
        for event in pending:
            try:
                value_after_write = bytes(cpu.mem_read(
                    int(event["address"], 16), event["size"])).hex()
                event["value_after_write"] = value_after_write
                workspace_index = event.get("workspace_event_index")
                if workspace_index is not None:
                    state["vm_workspace_write_events"][workspace_index][
                        "value_after_write"] = value_after_write
            except Exception:
                event["value_after_write"] = None
            if len(state["vm_backing_write_events"]) < 1024:
                state["vm_backing_write_events"].append(event)
        offset = pc - image
        state["last_pc_offset"] = hex(offset)
        state["native_instructions"] += 1
        if state["facade_started"]:
            state["facade_instructions"] += 1
            # The native VM keeps its current bytecode PC through x19.  Keep
            # a bounded, narrow trace around the two formatter candidates so
            # the source-slot claim is independently reproducible.  x19 is a
            # normal native register outside the VM, so invalid/unmapped
            # values are deliberately ignored.
            if len(state["vm_bytecode_window_events"]) < 512:
                try:
                    cursor = cpu.reg_read(arm.UC_ARM64_REG_X19)
                    bytecode_pc = _u(cpu, cursor)
                    bytecode_offset = bytecode_pc - image
                    if (bytecode_offset in FORMATTER_TRACE_OFFSETS
                            and bytecode_pc != state["last_vm_bytecode_window_pc"]):
                        state["last_vm_bytecode_window_pc"] = bytecode_pc
                        slots = [
                            hex(_u(cpu, cpu.reg_read(arm.UC_ARM64_REG_X28) + index * 8))
                            for index in range(32)
                        ]
                        state["vm_bytecode_window_events"].append({
                            "native_pc_offset": hex(offset),
                            "bytecode_offset": hex(bytecode_offset),
                            "bytecode_word": hex(_u(cpu, bytecode_pc, 4)),
                            "cursor": hex(cursor),
                            "backing": hex(cpu.reg_read(arm.UC_ARM64_REG_X28)),
                            "slots_0_31": slots,
                        })
                except Exception:
                    pass
        if state["facade_started"] and offset in VM_HANDLER_OPS:
            x = {index: cpu.reg_read(getattr(arm, f"UC_ARM64_REG_X{index}"))
                 for index in (8, 9, 10, 11, 12, 13, 14, 15, 19, 21, 28)}
            backing = x[28]

            def slot_value(index):
                if not 0 <= index < 32:
                    return None
                try:
                    return int.from_bytes(bytes(cpu.mem_read(backing + index * 8, 8)), "little")
                except Exception:
                    return None

            def read_word(address, width=8):
                try:
                    return bytes(cpu.mem_read(address, width)).hex()
                except Exception:
                    return None

            opcode = x[21] & 0xFFFFFFFF
            if offset == 0x1692FC:
                source_indices = [(opcode >> 12) & 0x1F, (opcode >> 22) & 0x1F]
                destination = (opcode >> 17) & 0x1F
                decoded = {
                    "source_indices": source_indices,
                    "destination_index": destination,
                    "source_values": [slot_value(index) for index in source_indices],
                    "destination_before": slot_value(destination),
                    "result": hex(x[10]),
                }
            elif offset == 0x16DB74:
                source = x[11] & 0x1F
                destination = x[15] & 0x1F
                decoded = {
                    "source_indices": [source],
                    "destination_index": destination,
                    "source_values": [slot_value(source)],
                    "destination_before": slot_value(destination),
                    "result": hex(x[10]),
                    "immediate_delta": hex((x[10] - x[11]) & ((1 << 64) - 1)),
                }
            elif offset == 0x16E254:
                destination = x[13] & 0x1F
                decoded = {
                    "source_indices": [], "destination_index": destination,
                    "source_values": [], "destination_before": slot_value(destination),
                    "result": hex(x[15]),
                }
            elif offset == 0x16E41C:
                destination = x[10] & 0x1F
                decoded = {
                    "source_indices": [], "destination_index": destination,
                    "source_values": [], "destination_before": slot_value(destination),
                    "result": hex(x[14]),
                }
            elif offset == 0x16F974:
                source = x[10] & 0x1F
                destination = x[14] & 0x1F
                operand_address = (x[12] + x[13]) & ((1 << 64) - 1)
                decoded = {
                    "source_indices": [source], "destination_index": destination,
                    "source_values": [slot_value(source)],
                    "destination_before": slot_value(destination),
                    "result": hex(x[9]),
                    "signed_offset": hex(x[13] & ((1 << 64) - 1)),
                    "operand_address": hex(operand_address),
                    "operand_value": read_word(operand_address),
                }
            else:
                source = x[13] & 0x1F
                destination = x[14] & 0x1F
                signed_offset = x[11] if x[11] < (1 << 63) else x[11] - (1 << 64)
                operand_address = (x[10] + signed_offset) & ((1 << 64) - 1)
                decoded = {
                    "source_indices": [source], "destination_index": destination,
                    "source_values": [slot_value(source)],
                    "destination_before": slot_value(destination),
                    "result": hex(x[9]),
                    "signed_offset": hex(x[11] & ((1 << 64) - 1)),
                    "operand_address": hex(operand_address),
                    "operand_value": read_word(operand_address, 4),
                }
            if len(state["vm_handler_trace"]) < 1024:
                state["vm_handler_trace"].append({
                    "pc_offset": hex(offset),
                    "operation": VM_HANDLER_OPS[offset],
                    "registers": {f"x{index}": hex(value) for index, value in x.items()},
                    "decoded": decoded,
                })
        elif state["facade_started"] and offset == VM_SOURCE_STORE:
            x28 = cpu.reg_read(arm.UC_ARM64_REG_X28)
            x12 = cpu.reg_read(arm.UC_ARM64_REG_X12)
            destination = x28 + x12 * 8
            previous = None
            try:
                previous = bytes(cpu.mem_read(destination, 8)).hex()
            except Exception:
                pass
            if len(state["vm_handler_trace"]) < 1024:
                state["vm_handler_trace"].append({
                    "pc_offset": hex(offset), "operation": "store_indexed",
                    "registers": {
                        f"x{index}": hex(cpu.reg_read(getattr(arm, f"UC_ARM64_REG_X{index}")))
                        for index in (9, 12, 28)
                    },
                    "decoded": {
                        "destination_address": hex(destination),
                        "destination_slot": x12,
                        "value": hex(cpu.reg_read(arm.UC_ARM64_REG_X9)),
                        "previous_value": previous,
                    },
                })
        if offset == 0x347F60:
            state["memcpy_import_count"] += 1
            return
        if offset in (FACADE_ENTRY, CHILD_ENTRY, OWNING_VM, 0x168324,
                      0x16848C, 0x2830EC, 0x283100, 0x28310C,
                      0x171268, 0x2858BC, 0x2859CC, 0x2859D0,
                      0x2859D4, 0x2859D8, 0x2859DC, 0x16AA4C,
                      0x285B80, 0x285B84, 0x285B88, 0x285B8C,
                      0x17BA24, 0x17BA38, 0x17BA40, 0x17BA44, 0x17BA60,
                      0x17BA68, 0x17BA6C, 0x17BA70, 0x17BA74, 0x17BA7C, 0x17BA84,
                      0x17BA8C, 0x17BAA0, 0x17BAC0,
                      0x248908, 0x25BF3C,
                      0x28B700, 0x28B704, 0x28B70C, 0x28B710,
                      0x28B718, 0x28B71C, 0x28B724, 0x28B72C,
                      0x28B734, 0x28B73C, 0x347F00, 0x347F10):
            row = {
                "pc_offset": hex(offset),
                "x0": hex(cpu.reg_read(arm.UC_ARM64_REG_X0)),
                "x1": hex(cpu.reg_read(arm.UC_ARM64_REG_X1)),
                "x2": hex(cpu.reg_read(arm.UC_ARM64_REG_X2)),
                "x3": hex(cpu.reg_read(arm.UC_ARM64_REG_X3)),
                "x8": hex(cpu.reg_read(arm.UC_ARM64_REG_X8)),
                "sp": hex(cpu.reg_read(arm.UC_ARM64_REG_SP)),
                "x30": hex(cpu.reg_read(arm.UC_ARM64_REG_X30)),
            }
            if offset in (0x285B80, 0x285B84, 0x285B88, 0x285B8C):
                pointer = cpu.reg_read(arm.UC_ARM64_REG_X0)
                try:
                    raw = bytes(cpu.mem_read(pointer, 0x30))
                    row["object_address"] = hex(pointer)
                    row["object_bytes_0x30"] = raw.hex()
                    row["object_words"] = [
                        hex(int.from_bytes(raw[index:index + 8], "little"))
                        for index in range(0, len(raw), 8)
                    ]
                except Exception as exc:
                    row["object_address"] = hex(pointer)
                    row["object_error"] = f"{type(exc).__name__}: {exc}"
                state["helper_object_events"].append(dict(row))
            if offset in (0x17BA24, 0x17BA38, 0x17BA40):
                row.update(
                    x9=hex(cpu.reg_read(arm.UC_ARM64_REG_X9)),
                    x21=hex(cpu.reg_read(arm.UC_ARM64_REG_X21)),
                )
                state["facade_dispatch_events"].append(dict(row))
            if offset in (0x17BA44, 0x17BA60, 0x17BA68, 0x17BA6C, 0x17BA70,
                          0x17BA74, 0x17BA7C, 0x17BA84, 0x17BA8C):
                sp = cpu.reg_read(arm.UC_ARM64_REG_SP)
                row["stack_words"] = []
                for displacement in range(0, 0x50, 8):
                    try:
                        row["stack_words"].append({
                            "offset": hex(displacement),
                            "value": hex(_u(cpu, sp + displacement)),
                        })
                    except Exception:
                        row["stack_words"].append({
                            "offset": hex(displacement), "value": None,
                        })
                state["facade_stack_snapshots"].append(dict(row))
                if offset in (0x17BA68, 0x17BA6C):
                    reference = _u(cpu, sp + 8)
                    tree_row = {"pc_offset": hex(offset),
                                "reference_address": hex(reference)}
                    try:
                        tree_row["reference_words"] = [
                            hex(_u(cpu, reference + index * 8))
                            for index in range(4)
                        ]
                        container = _u(cpu, reference)
                        tree_row["container_words"] = [
                            hex(_u(cpu, container + index * 8))
                            for index in range(8)
                        ] if container else []
                        tree_row["stack_reference_objects"] = {}
                        for displacement in (8, 0x18, 0x28, 0x38):
                            pointer = _u(cpu, sp + displacement)
                            words = []
                            if pointer:
                                for index in range(16):
                                    try:
                                        words.append(hex(_u(cpu, pointer + index * 8)))
                                    except Exception:
                                        words.append(None)
                            tree_row["stack_reference_objects"][hex(displacement)] = {
                                "address": hex(pointer), "words": words,
                            }
                        graph = {}
                        for displacement in (0x20, 0x28, 0x30, 0x38,
                                              0x48, 0x50, 0x58, 0x60):
                            pointer = _u(cpu, reference + displacement)
                            if pointer:
                                words = []
                                for index in range(12):
                                    try:
                                        words.append(hex(_u(cpu, pointer + index * 8)))
                                    except Exception:
                                        words.append(None)
                                graph[hex(displacement)] = {
                                    "address": hex(pointer), "words": words,
                                }
                        tree_row["native_object_graph"] = graph
                        controller = _u(cpu, reference + 0x20)
                        sentinel = _u(cpu, controller) if controller else 0
                        root = _u(cpu, sentinel + 8) if sentinel else 0
                        tree_row["native_tree_summary"] = {
                            "container_address": hex(reference),
                            "controller_address": hex(controller),
                            "sentinel_address": hex(sentinel),
                            "node_count": _u(cpu, controller + 8, 4) if controller else 0,
                            "root_address": hex(root),
                            "controller_words": [hex(_u(cpu, controller + index * 8))
                                                  for index in range(8)] if controller else [],
                            "sentinel_words": [hex(_u(cpu, sentinel + index * 8))
                                                for index in range(10)] if sentinel else [],
                            "root_words": [hex(_u(cpu, root + index * 8))
                                           for index in range(10)] if root else [],
                        }
                        pair = _u(cpu, root + 0x20) if root else 0
                        tree_row["native_tree_summary"]["pair_address"] = hex(pair)
                        tree_row["native_tree_summary"]["pair_words"] = (
                            [hex(_u(cpu, pair + index * 8)) for index in range(8)]
                            if pair else []
                        )
                        tree_row["native_tree_summary"]["pair_object_words"] = {}
                        for label, pointer in (("key", _u(cpu, pair) if pair else 0),
                                                ("value", _u(cpu, pair + 8) if pair else 0)):
                            words = []
                            if pointer:
                                for index in range(8):
                                    try:
                                        words.append(hex(_u(cpu, pointer + index * 8)))
                                    except Exception:
                                        words.append(None)
                            tree_row["native_tree_summary"]["pair_object_words"][label] = {
                                "address": hex(pointer), "words": words,
                            }
                            if pointer:
                                header = _u(cpu, pointer + 8)
                                capacity = header & 0xFFFFFFFF
                                length = (header >> 32) & 0xFFFFFFFF
                                payload = _u(cpu, pointer + 16)
                                tree_row["native_tree_summary"]["pair_object_words"][label].update(
                                    capacity=capacity, length=length,
                                    payload_address=hex(payload),
                                    payload_hex=bytes(cpu.mem_read(payload, length)).hex()
                                    if payload and length <= 4096 else None,
                                )
                        # The normal facade keeps native configuration objects
                        # on its own continuation frame.  They are not the
                        # output-reference wrapper used by the observation-only
                        # request runner, so record their vtables/links without
                        # applying that runner's stricter reference contract.
                        tree_row["native_object_snapshot"] = True
                    except Exception as exc:
                        tree_row["error"] = f"{type(exc).__name__}: {exc}"
                    state["facade_native_object_snapshots"].append(tree_row)
            if offset == 0x248908:
                row["format_object"] = row["x0"]
                row["format_argument"] = row["x2"]
                row["format_string_address"] = row["x3"]
                try:
                    fmt = bytearray()
                    pointer = cpu.reg_read(arm.UC_ARM64_REG_X1)
                    for index in range(256):
                        byte = bytes(cpu.mem_read(pointer + index, 1))
                        if byte == b"\0":
                            break
                        fmt.extend(byte)
                    row["format_hex"] = bytes(fmt).hex()
                except Exception:
                    row["format_hex"] = None
                try:
                    pointer = cpu.reg_read(arm.UC_ARM64_REG_X3)
                    string = bytearray()
                    for index in range(256):
                        byte = bytes(cpu.mem_read(pointer + index, 1))
                        if byte == b"\0":
                            break
                        string.extend(byte)
                    row["format_string_hex"] = bytes(string).hex()
                except Exception:
                    row["format_string_hex"] = None
                state["facade_format_events"].append(dict(row))
                try:
                    signed = cpu.reg_read(arm.UC_ARM64_REG_X2) & 0xFFFFFFFF
                    signed = signed - (1 << 32) if signed & 0x80000000 else signed
                    fmt_raw = bytes.fromhex(row["format_hex"] or "")
                    string_raw = bytes.fromhex(row["format_string_hex"] or "")
                    fmt_raw = fmt_raw.split(b"\0", 1)[0]
                    string_raw = string_raw.split(b"\0", 1)[0]
                    if fmt_raw == b"%d|%s":
                        state["facade_native_format_summary"].append({
                            "object_address": row["x0"],
                            "signed_int32": signed,
                            "format": fmt_raw.decode("ascii"),
                            "string_hex": string_raw.hex(),
                            "string": string_raw.decode("utf-8", "backslashreplace"),
                            "caller_offset": hex(cpu.reg_read(arm.UC_ARM64_REG_X30) - image),
                            "vm_backing": hex(cpu.reg_read(arm.UC_ARM64_REG_X28)),
                            "vm_pc_slot": hex(cpu.reg_read(arm.UC_ARM64_REG_X19)),
                            "vm_bytecode_pc": hex(_u(
                                cpu, cpu.reg_read(arm.UC_ARM64_REG_X19))),
                            "vm_bytecode_offset": hex(_u(
                                cpu, cpu.reg_read(arm.UC_ARM64_REG_X19)) - image),
                            "vm_register_slots_0_15": [
                                hex(_u(cpu, cpu.reg_read(arm.UC_ARM64_REG_X28) + index * 8))
                                for index in range(16)
                            ],
                        })
                except Exception:
                    pass
            if offset == 0x25BF3C:
                state["facade_tree_insert_events"].append(dict(row))
            if offset in (0x2830C4, 0x2830EC, 0x283100, 0x28310C):
                row.update(
                    x8=hex(cpu.reg_read(arm.UC_ARM64_REG_X8)),
                    x19=hex(cpu.reg_read(arm.UC_ARM64_REG_X19)),
                    x28=hex(cpu.reg_read(arm.UC_ARM64_REG_X28)),
                )
                state["request_vm_entry_events"].append(dict(row))
            if offset == 0x171268:
                x15 = cpu.reg_read(arm.UC_ARM64_REG_X15)
                x16 = cpu.reg_read(arm.UC_ARM64_REG_X16)
                x17 = cpu.reg_read(arm.UC_ARM64_REG_X17)
                x13 = cpu.reg_read(arm.UC_ARM64_REG_X13)
                x14 = cpu.reg_read(arm.UC_ARM64_REG_X14)
                x28 = cpu.reg_read(arm.UC_ARM64_REG_X28)
                row.update(x15=hex(x15), x16=hex(x16), x17=hex(x17),
                           x13=hex(x13), x14=hex(x14), x28=hex(x28),
                           store_address=hex(x17 + x16), store_value=hex(x15))
                source_slot = x14 & 0x1F
                try:
                    source_value = int.from_bytes(bytes(cpu.mem_read(
                        x28 + source_slot * 8, 8)), "little")
                except Exception:
                    source_value = None
                row.update(source_slot=source_slot,
                           base_slot=x13 & 0x1F,
                           source_value=(hex(source_value)
                                         if source_value is not None else None),
                           source_address=hex(x28 + source_slot * 8))
                state["vm_source_slot_events"].append(dict(row))
                if 0x7000e700 <= x17 + x16 < 0x7000e780:
                    state["argument_store_events"].append(row.copy())
            elif offset == 0x16848C:
                x28 = cpu.reg_read(arm.UC_ARM64_REG_X28)
                try:
                    words = [int.from_bytes(bytes(cpu.mem_read(x28 + i * 8, 8)), "little")
                             for i in range(32)]
                except Exception:
                    words = None
                state["vm_workspace_snapshots"].append({
                    "pc_offset": hex(offset), "backing": hex(x28),
                    "words": [hex(value) for value in words] if words is not None else None,
                    "cursor": hex(cpu.reg_read(arm.UC_ARM64_REG_X19)),
                })
            elif offset in (0x2830EC, 0x283100, 0x28310C):
                row["frame_registers"] = {
                    name: hex(cpu.reg_read(getattr(arm, name)))
                    for name in ("UC_ARM64_REG_X0", "UC_ARM64_REG_X1",
                                 "UC_ARM64_REG_X2", "UC_ARM64_REG_X3",
                                 "UC_ARM64_REG_X8", "UC_ARM64_REG_SP")
                }
            if offset in (0x347F00, 0x347F10):
                row["mutex_target"] = row["x0"]
            if offset != 0x171268 or (
                    0x7000e700 <= cpu.reg_read(arm.UC_ARM64_REG_X17)
                    + cpu.reg_read(arm.UC_ARM64_REG_X16) < 0x7000e780):
                markers.append(row)
            if offset == FACADE_ENTRY:
                state["facade_entry"] = row
                state["facade_started"] = True
            elif offset == CHILD_ENTRY and state["child_entry"] is None:
                state["child_entry"] = row
            elif offset == OWNING_VM and state["owning_vm_entry"] is None:
                state["owning_vm_entry"] = row
            elif offset == 0x17BAA0:
                state["facade_return"] = "epilogue_17baa0"
            elif offset == 0x17BAC0:
                state["facade_return"] = "epilogue_17bac0"
                state["facade_return_registers"] = dict(row)
            elif offset == 0x2859DC:
                dispatch_object = cpu.reg_read(arm.UC_ARM64_REG_X0)
                try:
                    raw = bytes(cpu.mem_read(dispatch_object, 0x100))
                    words = [int.from_bytes(raw[index:index + 8], "little")
                             for index in range(0, len(raw), 8)]
                    state["descriptor_snapshot"] = {
                        "address": hex(dispatch_object),
                        "bytes_0x100": raw.hex(),
                        "u64_words": [hex(value) for value in words],
                    }
                except Exception as exc:
                    state["descriptor_snapshot"] = {
                        "address": hex(dispatch_object),
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                state["unresolved_branch"] = {
                    "pc_offset": hex(offset),
                    "branch_register": "x3",
                    "branch_target": row["x3"],
                    "dispatch_object": row["x0"],
                    "selector": row["x2"],
                }

    def descriptor_write_observer(cpu, address, size):
        # Keep this ledger inside the actual facade/request continuation.  The
        # same memory window is used by the outer bootstrap and by matching
        # libc, so address filtering alone records mostly pre-facade noise.
        # Code-hook offsets are relative to the selected main-image base;
        # negative offsets identify the second case's libc/outer mappings.
        pc_offset = cpu.reg_read(arm.UC_ARM64_REG_PC) - image
        in_main_image = 0 <= pc_offset < 0x400000
        in_facade_window = state["facade_started"] and state["facade_return"] is None
        # The final facade frame is anchored at SP=0x7000ee50 and its
        # temporaries/result references occupy this upper stack range.  Lower
        # addresses belong to nested request helpers; retaining them adds
        # allocator-frame churn without helping identify +0x17bac0's value.
        if (len(state["facade_stack_write_events"]) < 128
                and in_main_image and in_facade_window
                and 0x7000EE50 <= address < 0x7000EF00
                and address + size <= 0x7000EF00):
            try:
                value = bytes(cpu.mem_read(address, size)).hex()
            except Exception:
                value = None
            state["facade_stack_write_events"].append({
                "address": hex(address), "size": size,
                "value_after_write": value,
                "pc_offset": hex(pc_offset),
                "x0": hex(cpu.reg_read(arm.UC_ARM64_REG_X0)),
                "x1": hex(cpu.reg_read(arm.UC_ARM64_REG_X1)),
                "x2": hex(cpu.reg_read(arm.UC_ARM64_REG_X2)),
                "x3": hex(cpu.reg_read(arm.UC_ARM64_REG_X3)),
            })
        helper_address = image + 0x2484B8
        if (len(state["helper_object_write_events"]) < 128
                and address <= helper_address < address + size):
            try:
                value = bytes(cpu.mem_read(helper_address, 0x30)).hex()
            except Exception:
                value = None
            state["helper_object_write_events"].append({
                "address": hex(helper_address),
                "value_after_write": value,
                "pc_offset": hex(cpu.reg_read(arm.UC_ARM64_REG_PC) - image),
                "write_address": hex(address),
                "write_size": size,
            })
        helper_stack = 0x7000E560
        helper_stack_end = helper_stack + 0x20
        if (len(state["helper_stack_write_events"]) < 256
                and address < helper_stack_end and address + size > helper_stack):
            try:
                value = bytes(cpu.mem_read(helper_stack, 0x20)).hex()
            except Exception:
                value = None
            state["helper_stack_write_events"].append({
                "pc_offset": hex(cpu.reg_read(arm.UC_ARM64_REG_PC) - image),
                "write_address": hex(address),
                "write_size": size,
                "value_after_write": value,
                "x15": hex(cpu.reg_read(arm.UC_ARM64_REG_X15)),
                "x16": hex(cpu.reg_read(arm.UC_ARM64_REG_X16)),
                "x17": hex(cpu.reg_read(arm.UC_ARM64_REG_X17)),
                "x13": hex(cpu.reg_read(arm.UC_ARM64_REG_X13)),
                "x14": hex(cpu.reg_read(arm.UC_ARM64_REG_X14)),
                "x28": hex(cpu.reg_read(arm.UC_ARM64_REG_X28)),
            })
        got_address = image + 0x382C80
        if (len(state["main_import_write_events"]) < 128
                and address <= got_address < address + size):
            try:
                value = bytes(cpu.mem_read(got_address, 8)).hex()
            except Exception:
                value = None
            state["main_import_write_events"].append({
                "address": hex(got_address),
                "value_after_write": value,
                "pc_offset": hex(cpu.reg_read(arm.UC_ARM64_REG_PC) - image),
                "write_address": hex(address),
                "write_size": size,
            })
        # The stop object is a heap allocation in the 0x1370xxxx range.  Keep
        # the bounded write ledger for that page and retain the native PC;
        # this is provenance evidence, not an injected callback target.
        if 0x13708000 <= address < 0x13708100 and len(state["descriptor_write_events"]) < 512:
            try:
                value = bytes(cpu.mem_read(address, size)).hex()
            except Exception:
                value = None
            state["descriptor_write_events"].append({
                "address": hex(address),
                "size": size,
                "value_after_write": value,
                "pc_offset": hex(cpu.reg_read(arm.UC_ARM64_REG_PC) - image),
            })
        if 0x7000e700 <= address < 0x7000e780 and len(state["argument_object_write_events"]) < 512:
            try:
                value = bytes(cpu.mem_read(address, size)).hex()
            except Exception:
                value = None
            state["argument_object_write_events"].append({
                "address": hex(address), "size": size,
                "value_after_write": value,
                "pc_offset": hex(cpu.reg_read(arm.UC_ARM64_REG_PC) - image),
            })
        # The VM may temporarily repurpose X28 while writing its physical
        # backing array, so use the bounded final workspace neighborhood as
        # the observation window instead of trusting X28 at the write hook.
        if 0x7000eb00 <= address and address + size <= 0x7000ed00:
            x28 = cpu.reg_read(arm.UC_ARM64_REG_X28)
            slot = ((address - x28) // 8
                    if (x28 & 7) == 0 and x28 <= address
                    and address + size <= x28 + 32 * 8 else None)
            try:
                value_at_hook = bytes(cpu.mem_read(address, size)).hex()
            except Exception:
                value_at_hook = None
            workspace_index = None
            if len(state["vm_workspace_write_events"]) < 4096:
                workspace_index = len(state["vm_workspace_write_events"])
                state["vm_workspace_write_events"].append({
                    "address": hex(address), "size": size,
                    "value_at_hook": value_at_hook,
                    "value_after_write": None,
                    "pc": hex(cpu.reg_read(arm.UC_ARM64_REG_PC)),
                    "pc_offset": hex(cpu.reg_read(arm.UC_ARM64_REG_PC) - image),
                    "x8": hex(cpu.reg_read(arm.UC_ARM64_REG_X8)),
                    "x9": hex(cpu.reg_read(arm.UC_ARM64_REG_X9)),
                    "x10": hex(cpu.reg_read(arm.UC_ARM64_REG_X10)),
                    "x11": hex(cpu.reg_read(arm.UC_ARM64_REG_X11)),
                    "x12": hex(cpu.reg_read(arm.UC_ARM64_REG_X12)),
                    "x13": hex(cpu.reg_read(arm.UC_ARM64_REG_X13)),
                    "x14": hex(cpu.reg_read(arm.UC_ARM64_REG_X14)),
                    "x28_at_write": hex(x28),
                })
            if len(state.get("pending_vm_writes", ())) < 512:
                try:
                    previous = bytes(cpu.mem_read(address, size)).hex()
                except Exception:
                    previous = None
                state.setdefault("pending_vm_writes", []).append({
                    "address": hex(address), "size": size, "slot": slot,
                    "previous_value": previous,
                    "workspace_event_index": workspace_index,
                    "pc_offset": hex(cpu.reg_read(arm.UC_ARM64_REG_PC) - image),
                    "x28_at_write": hex(x28),
                })

    def descriptor_read_observer(cpu, address, size):
        if 0x13708000 <= address < 0x13708100 and len(state["descriptor_read_events"]) < 512:
            try:
                value = bytes(cpu.mem_read(address, size)).hex()
            except Exception:
                value = None
            state["descriptor_read_events"].append({
                "address": hex(address),
                "size": size,
                "value_at_read": value,
                "pc_offset": hex(cpu.reg_read(arm.UC_ARM64_REG_PC) - image),
            })
        if 0x7000e700 <= address < 0x7000e780 and len(state["argument_object_read_events"]) < 512:
            try:
                value = bytes(cpu.mem_read(address, size)).hex()
            except Exception:
                value = None
            state["argument_object_read_events"].append({
                "address": hex(address), "size": size,
                "value_at_read": value,
                "pc_offset": hex(cpu.reg_read(arm.UC_ARM64_REG_PC) - image),
            })

    def terminal_continuation(cpu, *, root, **_unused):
        child = _u(cpu, root + 0x18)
        vtable = _u(cpu, child)
        target = _u(cpu, vtable + 0x20)
        pair = _u(cpu, child + 0x20)
        pair_target = _u(cpu, pair)
        state.update(outer_root=root, outer_child=child, outer_vtable=vtable,
                     outer_vtable_target=target, outer_pair=pair,
                     outer_pair_target=pair_target)
        # The outer cold return is the join point.  Keep the allocator ledger
        # available even if the following facade later stops at an unresolved
        # descriptor branch.
        state["continuation_allocations"] = list(_unused.get("allocation_sequence", ()))
        state["continuation_allocator_events"] = list(_unused.get("allocator_events", ()))
        if vtable != image + 0x35D5F0 or target != image + CHILD_ENTRY:
            raise AssertionError(("outer child vtable/target", hex(vtable), hex(target)))
        if pair_target != image + OWNING_VM:
            raise AssertionError(("outer child pair target", hex(pair_target)))

        # The outer native run is complete.  Its G+0x1000/G+0x2000 fixture
        # words can now be replaced by the independently generated facade
        # objects; the receiver itself remains the native heap child above.
        _overlay_guest(cpu, fixture_pages)
        # These are the facade's explicit branch selectors.  The outer getter
        # leaves them cold, while the standalone facade fixture initializes
        # them before entering +0x17b8f8.
        cpu.mem_write(image + 0x3D1570, ((1 << 64) - 1).to_bytes(8, "little"))
        cpu.mem_write(image + 0x3D1578, (0).to_bytes(8, "little"))
        cpu.mem_write(image + 0x3DF110, (facade.CLASS).to_bytes(8, "little"))
        cpu.mem_write(G + 0xB000 + 0x30, JNI_FIND_CLASS.to_bytes(8, "little"))
        cpu.mem_write(G + 0xB000 + 0x388, JNI_METHOD_LOOKUP.to_bytes(8, "little"))
        cpu.mem_write(G + 0xB000 + 0x720, JNI_EXCEPTION_CHECK.to_bytes(8, "little"))
        cpu.mem_write(G + 0xB000 + 0x398, JNI_VARIADIC_CALL.to_bytes(8, "little"))
        cpu.mem_write(G + 0xB000 + 0x108, JNI_METHOD_LOOKUP_108.to_bytes(8, "little"))
        cpu.mem_write(G + 0xB000 + 0x118, JNI_ARRAY_ACCESS.to_bytes(8, "little"))
        cpu.mem_write(G + 0xB000 + 0x558, JNI_ARRAY_LENGTH.to_bytes(8, "little"))
        cpu.mem_write(G + 0xB000 + 0x568, JNI_ARRAY_ELEMENT.to_bytes(8, "little"))
        cpu.mem_write(G + 0xB000 + 0x548, JNI_STRING_ACCESS.to_bytes(8, "little"))
        cpu.mem_write(G + 0xB000 + 0x550, JNI_STRING_RELEASE.to_bytes(8, "little"))
        cpu.mem_write(facade.FACADE + 0x18, child.to_bytes(8, "little"))
        cpu.reg_write(arm.UC_ARM64_REG_X0, arguments["environment_pointer"])
        cpu.reg_write(arm.UC_ARM64_REG_X1, arguments["facade_address"])
        cpu.reg_write(arm.UC_ARM64_REG_X2, arguments["url_reference"])
        cpu.reg_write(arm.UC_ARM64_REG_X3, arguments["header_array_reference"])
        cpu.reg_write(arm.UC_ARM64_REG_X8, 0)
        cpu.reg_write(arm.UC_ARM64_REG_SP, arguments["entry_stack_address"])
        cpu.reg_write(arm.UC_ARM64_REG_TPIDR_EL0, arguments["thread_pointer"])
        cpu.reg_write(arm.UC_ARM64_REG_X30, oracle.STOP)
        cpu.reg_write(arm.UC_ARM64_REG_PC, image + FACADE_ENTRY)
        return True

    def unmapped(_cpu, access, address, size, value):
        state["unmapped"].append({
            "access": access, "address": hex(address), "size": size,
            "value": hex(value),
        })

    def syscall_observer(cpu, number, result):
        if len(state["syscall_mmap_events"]) < 512:
            state["syscall_mmap_events"].append({
                "number": number,
                "result": hex(result) if isinstance(result, int) else result,
                "x0": hex(cpu.reg_read(arm.UC_ARM64_REG_X0)),
                "x1": hex(cpu.reg_read(arm.UC_ARM64_REG_X1)),
                "x2": hex(cpu.reg_read(arm.UC_ARM64_REG_X2)),
                "x3": hex(cpu.reg_read(arm.UC_ARM64_REG_X3)),
                "x8": hex(cpu.reg_read(arm.UC_ARM64_REG_X8)),
                "pc_offset": hex(cpu.reg_read(arm.UC_ARM64_REG_PC) - image),
                "x30": hex(cpu.reg_read(arm.UC_ARM64_REG_X30)),
                "sp": hex(cpu.reg_read(arm.UC_ARM64_REG_SP)),
            })

    def main_import_observer(name, kind, address, target):
        state["main_import_relocations"].append({
            "symbol": name,
            "relocation_type": kind,
            "address": hex(address),
            "address_offset": hex(address - image),
            "target": hex(target),
            "target_libc_offset": hex(target - 0x51000000),
        })

    error = None
    result = None
    try:
        result = outer.case(
            library, libc, image, None,
            execution_observer=execution_observer,
            terminal_continuation=terminal_continuation,
            continuation_host_imports=continuation_imports,
            continuation_references=(G + 0x9000, G + 0x9010, G + 0x9020,
                                     G + 0x9030, G + 0x9040, G + 0x9050),
            continuation_reference_types={
                G + 0x9000: 2, G + 0x9010: 2, G + 0x9020: 2,
                G + 0x9030: 2, G + 0x9040: 2, G + 0x9050: 2,
            },
            continuation_memory_write_observer=descriptor_write_observer,
            continuation_memory_read_observer=descriptor_read_observer,
            continuation_syscall_observer=syscall_observer,
            continuation_main_import_names=("memset", "__cxa_atexit"),
            continuation_main_import_observer=main_import_observer,
            unmapped_observer=unmapped,
        )
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"

    child_entry = state["child_entry"]
    cxa_relocations = [
        event for event in state["main_import_relocations"]
        if event["symbol"] == "__cxa_atexit"
    ]
    cxa_target = next(
        (event["target"] for event in cxa_relocations
         if event["address_offset"] == "0x382cd8"),
        None,
    )
    facade_return_value = (
        state["facade_return_registers"]["x0"]
        if state["facade_return_registers"] is not None else None
    )
    facade_result_source = next(
        (row for row in state["facade_stack_snapshots"]
         if row["pc_offset"] == "0x17ba6c"),
        None,
    )
    facade_result_source_verified = (
        facade_result_source is not None
        and facade_result_source["x0"] == facade_return_value
    )
    actual_facade_return_verified = (
        state["facade_return"] == "epilogue_17bac0"
        and facade_return_value == hex(G + 0x1E10)
    )
    return {
        "image_base": hex(image),
        "outer_function_offset": "0x1658e4",
        "facade_entry_offset": hex(FACADE_ENTRY),
        "child_entry_offset": hex(CHILD_ENTRY),
        "owning_vm_entry_offset": hex(OWNING_VM),
        "outcome": (
            "same_cpu_real_outer_child_facade_returned"
            if state["facade_return"] is not None and error is None
            else "same_cpu_real_outer_child_facade_stopped"
        ),
        "error": error,
        "outer_graph": {
            key: hex(value) if isinstance(value, int) else value
            for key, value in state.items()
            if key.startswith("outer_")
        },
        "facade_entry": state["facade_entry"],
        "child_entry": child_entry,
        "owning_vm_entry": state["owning_vm_entry"],
        "facade_return": state["facade_return"],
        "facade_return_registers": state["facade_return_registers"],
        "facade_result_source": facade_result_source,
        "facade_result_source_verified": facade_result_source_verified,
        "facade_dispatch_events": state["facade_dispatch_events"],
        "facade_stack_snapshots": state["facade_stack_snapshots"],
        "facade_native_object_snapshots": state["facade_native_object_snapshots"],
        "facade_format_events": state["facade_format_events"],
        "facade_native_format_summary": state["facade_native_format_summary"],
        "facade_tree_insert_events": state["facade_tree_insert_events"],
        "vm_bytecode_window_events": state["vm_bytecode_window_events"],
        "facade_stack_write_events": state["facade_stack_write_events"],
        "request_vm_entry_events": state["request_vm_entry_events"],
        "actual_facade_return_verified": actual_facade_return_verified,
        "real_request_vm_entry_used": bool(state["request_vm_entry_events"]),
        "real_cxa_atexit_relocation_used": cxa_target is not None,
        "real_cxa_atexit_target": cxa_target,
        "facade_jni_event_count": len(getattr(service, "events", ())),
        "facade_service_events": _json_safe(list(getattr(service, "events", ()))),
        "facade_service_requests": _json_safe(list(getattr(service, "requests", ()))),
        "facade_service_elements": _json_safe(list(getattr(service, "elements", ()))),
        "last_pc_offset": state["last_pc_offset"],
        "native_instructions_observed": state["native_instructions"],
        "facade_instructions_observed": state["facade_instructions"],
        "real_memcpy_import_count": state["memcpy_import_count"],
        "unresolved_branch": state["unresolved_branch"],
        "descriptor_snapshot": state["descriptor_snapshot"],
        "descriptor_write_events": state["descriptor_write_events"],
        "descriptor_read_events": state["descriptor_read_events"],
        "argument_object_write_events": state["argument_object_write_events"],
        "argument_object_read_events": state["argument_object_read_events"],
        "argument_store_events": state["argument_store_events"],
        "vm_source_slot_events": [
            event for event in state["vm_source_slot_events"]
            if 0x7000e700 <= int(event["store_address"], 16) < 0x7000e780
        ],
        "vm_source_slot_writer_events": [
            {
                "pc": event["pc"],
                "pc_offset": event["pc_offset"],
                "instruction": "str x9, [x28, x12, lsl #3]",
                "destination": event["address"],
                "x28": event["x28_at_write"],
                "x12": event["x12"],
                "x9": event["x9"],
                "x8": event["x8"],
            }
            for event in state["vm_workspace_write_events"]
            if state["vm_source_slot_events"] and
            int(event["address"], 16) == int(
                state["vm_source_slot_events"][-1]["source_address"], 16)
            and event["pc_offset"] == "0x16e118"
            and event["x12"] == "0x1"
            and event["x9"] == "0x0"
        ],
        "vm_handler_trace_tail": state["vm_handler_trace"][-96:],
        "vm_final_zero_source": next(
            (
                event for event in reversed(state["vm_handler_trace"])
                if event["operation"] == "load_indexed_signed_offset"
                and event["decoded"].get("destination_index") == 1
                and event["decoded"].get("result") == "0x0"
            ),
            None,
        ),
        "vm_final_zero_source_global_offset": (
            hex(
                int(
                    next(
                        (
                            event for event in reversed(state["vm_handler_trace"])
                            if event["operation"] == "load_indexed_signed_offset"
                            and event["decoded"].get("destination_index") == 1
                            and event["decoded"].get("result") == "0x0"
                        ),
                        {"decoded": {"operand_address": None}},
                    )["decoded"]["operand_address"],
                    16,
                ) - image
            )
            if next(
                (
                    event for event in reversed(state["vm_handler_trace"])
                    if event["operation"] == "load_indexed_signed_offset"
                    and event["decoded"].get("destination_index") == 1
                    and event["decoded"].get("result") == "0x0"
                ),
                {"decoded": {"operand_address": None}},
            )["decoded"].get("operand_address")
            else None
        ),
        "vm_workspace_snapshots": (
            [state["vm_workspace_snapshots"][-1]]
            if state["vm_workspace_snapshots"] else []
        ),
        "syscall_mmap_events": state["syscall_mmap_events"],
        "continuation_allocations": state["continuation_allocations"],
        "continuation_allocator_events": state["continuation_allocator_events"],
        "main_import_relocations": state["main_import_relocations"],
        "main_import_write_events": state["main_import_write_events"],
        "continuation_jni_calls": state["continuation_jni_calls"],
        "helper_object_events": state["helper_object_events"],
        "helper_object_write_events": state["helper_object_write_events"],
        "helper_stack_write_events": state["helper_stack_write_events"],
        "markers": markers,
        "unmapped_events": state["unmapped"],
        "native_outer_result": result,
        "same_cpu_native_bootstrap_to_outer": False,
        "same_cpu_native_outer_to_facade": True,
        "real_outer_child_receiver_used": True,
        "synthetic_receiver_tree_used": False,
        "synthetic_dispatch_table_used": False,
        "synthetic_jni_provider_used": True,
        "normal_facade_entry_used": True,
        "whole_request_native_differential_verified": False,
        "fresh_standalone_signer_verified": False,
        "online_header_acceptance_verified": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--libc", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    digest = hashlib.sha256(args.library.read_bytes()).hexdigest()
    assert digest == oracle.LIBRARY_SHA256, digest
    rows = [run(args.library, args.libc, image) for image in BASES]
    report = {
        "schema": "vm9-native-outer-facade-actual-child-20261027-v5",
        "evidence_date": "2026-10-27",
        "sample_sha256": digest,
        "matching_libc_sha256": hashlib.sha256(args.libc.read_bytes()).hexdigest(),
        "cases": rows,
        "same_cpu_native_outer_to_facade": True,
        "real_outer_child_receiver_used": True,
        "actual_facade_return_verified": all(
            case["actual_facade_return_verified"] for case in rows
        ),
        "facade_result_source_verified": all(
            case["facade_result_source_verified"] for case in rows
        ),
        "real_request_vm_entry_used": all(
            case["real_request_vm_entry_used"] for case in rows
        ),
        "real_cxa_atexit_relocation_used": all(
            case["real_cxa_atexit_relocation_used"] for case in rows
        ),
        "synthetic_receiver_tree_used": False,
        "synthetic_jni_provider_used": True,
        "normal_facade_entry_used": True,
        "whole_request_native_differential_verified": False,
        "fresh_standalone_signer_verified": False,
        "online_header_acceptance_verified": False,
        "formatter_bytecode_static": _decode_formatter_bytecode(args.library),
        "formatter_path_observed_offsets_each": [
            sorted({
                event["bytecode_offset"]
                for event in case["vm_bytecode_window_events"]
            })
            for case in rows
        ],
        "interpretation": (
            "The outer getter's actual first child is retained on the same Unicorn "
            "CPU and used as the normal facade receiver.  The child vtable and "
            "callback pair provenance are checked before entering +0x17b8f8; "
            "URL/header/JNI services remain explicit fixture providers.  At the "
            "descriptor stop, +0x171268 writes x15=0x13708000 into the argument "
            "+0x08 and clears +0x00; the object is in a fresh zero-filled mmap "
            "and the final source slot is written by the VM handler at image+0x16e118: "
            "the observed store has x28=0x7000eba8, x12=1 and x9=0 on both image "
            "bases.  The preceding VM load now resolves the image-relative +0x382c80 "
            "R_AARCH64_ABS64 memset GOT slot through the matching libc relocation "
            "and records that target; without this explicit dynamic-linker step the "
            "slot remains zero.  The real request VM entry +0x2830c4 then completes "
            "and the facade returns the native Java result handle at +0x17bac0. "
            "JNI/Java services remain synthetic providers, so this verifies the "
            "native continuation and return boundary only.  At +0x17ba6c the "
            "native request call returns G+0x1e10 in x0, which is copied into "
            "x19 and reaches the +0x17bac0 epilogue unchanged; this links the "
            "observed facade result to the native call return rather than a "
            "Python-side snapshot.  It does not claim a "
            "live JVM, whole-request differential, standalone signer, or online "
            "acceptance."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
    print("native outer -> actual child -> facade", len(rows), "cases", flush=True)


if __name__ == "__main__":
    main()
