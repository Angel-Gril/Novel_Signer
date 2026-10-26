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


def _u(cpu, address, width=8):
    return int.from_bytes(bytes(cpu.mem_read(address, width)), "little")


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
        "vm_workspace_write_events": [],
        "vm_backing_write_events": [],
        "vm_workspace_snapshots": [],
        "descriptor_snapshot": None,
        "continuation_allocations": [],
        "continuation_allocator_events": [],
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
        if offset == 0x347F60:
            state["memcpy_import_count"] += 1
            return
        if offset in (FACADE_ENTRY, CHILD_ENTRY, OWNING_VM, 0x168324,
                      0x16848C, 0x2830EC, 0x283100, 0x28310C,
                      0x171268, 0x2858BC, 0x2859CC, 0x2859D0,
                      0x2859D4, 0x2859D8, 0x2859DC, 0x347F00, 0x347F10):
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
            unmapped_observer=unmapped,
        )
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"

    child_entry = state["child_entry"]
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
        "vm_workspace_snapshots": (
            [state["vm_workspace_snapshots"][-1]]
            if state["vm_workspace_snapshots"] else []
        ),
        "syscall_mmap_events": state["syscall_mmap_events"],
        "continuation_allocations": state["continuation_allocations"],
        "continuation_allocator_events": state["continuation_allocator_events"],
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
        "schema": "vm9-native-outer-facade-actual-child-20261027-v3",
        "evidence_date": "2026-10-27",
        "sample_sha256": digest,
        "matching_libc_sha256": hashlib.sha256(args.libc.read_bytes()).hexdigest(),
        "cases": rows,
        "same_cpu_native_outer_to_facade": True,
        "real_outer_child_receiver_used": True,
        "synthetic_receiver_tree_used": False,
        "synthetic_jni_provider_used": True,
        "normal_facade_entry_used": True,
        "whole_request_native_differential_verified": False,
        "fresh_standalone_signer_verified": False,
        "online_header_acceptance_verified": False,
        "interpretation": (
            "The outer getter's actual first child is retained on the same Unicorn "
            "CPU and used as the normal facade receiver.  The child vtable and "
            "callback pair provenance are checked before entering +0x17b8f8; "
            "URL/header/JNI services remain explicit fixture providers.  At the "
            "descriptor stop, +0x171268 writes x15=0x13708000 into the argument "
            "+0x08 and clears +0x00; the object is in a fresh zero-filled mmap "
            "and the final source slot is written by the VM handler at image+0x16e118: "
            "the observed store has x28=0x7000eba8, x12=1 and x9=0 on both image "
            "bases.  This is handler provenance, not a missing-input or injected "
            "callback target.  A return or STOP therefore records continuation only, "
            "never signer output."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
    print("native outer -> actual child -> facade", len(rows), "cases", flush=True)


if __name__ == "__main__":
    main()
