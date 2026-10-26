"""Trace callback-object fields on the same-CPU bootstrap/request continuation.

This probe composes the already accepted URL-bearing request continuation and
adds observation only.  It does not write a callback target or a dispatch
table.  Code hooks capture the five-instruction ``+0x2858a8`` object bridge,
while a write hook retains native writes in the guest callback scratch region.
The report is intended to identify which fields are native-produced before the
first real ``memcpy`` import and which remain zero at the branch boundary.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn import arm64_const as arm

import verify_vm9_bootstrap_request_memcpy_continuation_20261026 as continuation
import verify_vm9_signer_objects as oracle


WRAPPER_OFFSETS = (0x2858A8, 0x2858AC, 0x2858B0, 0x2858B4, 0x2858B8)
# The continuation's callback object and its memcpy source/destination are
# allocated in this guest scratch window.  Restricting the write ledger to the
# window keeps the evidence reviewable while retaining every object-field
# write; the broader request write stream is already retained by the parent
# continuation evidence.
GUEST_TRACE_LO = 0x7000E900
GUEST_TRACE_HI = 0x7000EA20
MAX_WRITES = 20000


def _read(cpu, address: int, size: int) -> str | None:
    try:
        return bytes(cpu.mem_read(address, size)).hex()
    except Exception:
        return None


def _regs(cpu) -> dict[str, str]:
    return {
        f"x{index}": hex(cpu.reg_read(getattr(arm, f"UC_ARM64_REG_X{index}")))
        for index in (0, 1, 2, 3, 8, 19, 30)
    }


def run(library: Path, libc: Path, image: int) -> dict:
    traces: list[dict] = []
    writes: list[dict] = []
    vm_store_events: list[dict] = []
    vm_backings: set[int] = set()
    vm_register_writes: list[dict] = []
    holder: dict[str, object] = {}
    original_native = continuation.bootstrap.native

    def wrapped_native(*args, **kwargs):
        cpu, service, vm, jni, scopes = original_native(*args, **kwargs)
        image_base = int(args[2])
        holder["cpu"] = cpu

        def code_hook(c, address, _size, _user):
            offset = address - image_base
            # The VM register file is live before the target-field store.  The
            # previous version learned x28 only at +0x171268, so all slot
            # producers that ran earlier were silently missed.  Capture the
            # backing on every known VM handler entry instead; this remains an
            # observation-only ledger and does not alter execution.
            if offset in continuation.VM_HANDLERS:
                backing = c.reg_read(arm.UC_ARM64_REG_X28)
                if GUEST_TRACE_LO - 0x1000 <= backing < GUEST_TRACE_HI + 0x1000:
                    vm_backings.add(backing)
            if offset == 0x171268:
                x13 = c.reg_read(arm.UC_ARM64_REG_X13)
                x14 = c.reg_read(arm.UC_ARM64_REG_X14)
                x15 = c.reg_read(arm.UC_ARM64_REG_X15)
                x16 = c.reg_read(arm.UC_ARM64_REG_X16)
                x17 = c.reg_read(arm.UC_ARM64_REG_X17)
                x28 = c.reg_read(arm.UC_ARM64_REG_X28)
                vm_backings.add(x28)
                destination = (x17 + x16) & ((1 << 64) - 1)
                if GUEST_TRACE_LO <= destination < GUEST_TRACE_HI:
                    source_slot = x14 & 0x1F
                    base_slot = x13 & 0x1F
                    source_address = x28 + source_slot * 8
                    base_address = x28 + base_slot * 8
                    vm_store_events.append({
                        "pc_offset": "+0x171268",
                        "destination_address": hex(destination),
                        "written_value": hex(x15),
                        "source_slot": source_slot,
                        "source_value": _read(c, source_address, 8),
                        "source_address": hex(source_address),
                        "base_slot": base_slot,
                        "base_value": _read(c, base_address, 8),
                        "registers": {
                            "x13": hex(x13), "x14": hex(x14), "x15": hex(x15),
                            "x16": hex(x16), "x17": hex(x17), "x28": hex(x28),
                        },
                    })
            if offset not in WRAPPER_OFFSETS:
                return
            object_address = c.reg_read(arm.UC_ARM64_REG_X0)
            row = {
                "pc_offset": hex(offset),
                "registers": _regs(c),
                "object_address": hex(object_address),
                "object_bytes_before": _read(c, object_address, 0x30),
            }
            row["object_fields_before"] = {
                "field_0": _read(c, object_address, 8),
                "field_8": _read(c, object_address + 8, 8),
                "field_16": _read(c, object_address + 16, 8),
                "field_24": _read(c, object_address + 24, 8),
                "field_32": _read(c, object_address + 32, 8),
            }
            traces.append(row)

        def write_hook(c, _access, address, size, value, _user):
            if len(writes) >= MAX_WRITES:
                return
            if GUEST_TRACE_LO <= address < GUEST_TRACE_HI:
                writes.append({
                    "pc_offset": hex(c.reg_read(arm.UC_ARM64_REG_PC) - image_base),
                    "address": hex(address),
                    "size": size,
                    "value": hex(value),
                    "previous_bytes": _read(c, address, size),
                })
            # A libc import can write into the same guest stack range while
            # servicing the request.  Keep this ledger limited to stores
            # issued by the relocated native image, so a host/import write is
            # never presented as a VM-slot producer.
            pc = c.reg_read(arm.UC_ARM64_REG_PC)
            if not image_base <= pc < image_base + 0x400000:
                return
            for backing in vm_backings:
                if backing <= address < backing + 32 * 8:
                    delta = address - backing
                    vm_register_writes.append({
                        "pc_offset": hex(c.reg_read(arm.UC_ARM64_REG_PC) - image_base),
                        "address": hex(address),
                        "backing": hex(backing),
                        "slot": delta // 8 if delta >= 0 else -1,
                        "size": size,
                        "value": hex(value),
                        "previous_bytes": _read(c, address, size),
                    })

        cpu.hook_add(UC_HOOK_CODE, code_hook)
        cpu.hook_add(UC_HOOK_MEM_WRITE, write_hook)
        return cpu, service, vm, jni, scopes

    continuation.bootstrap.native = wrapped_native
    try:
        result = continuation.run(library, libc, image)
    finally:
        continuation.bootstrap.native = original_native

    cpu = holder.get("cpu")
    post_objects = {}
    if cpu is not None:
        for address in sorted({int(row["object_address"], 16) for row in traces}):
            post_objects[hex(address)] = {
                "bytes_after": _read(cpu, address, 0x30),
                "field_0": _read(cpu, address, 8),
                "field_8": _read(cpu, address + 8, 8),
                "field_16": _read(cpu, address + 16, 8),
                "field_24": _read(cpu, address + 24, 8),
                "field_32": _read(cpu, address + 32, 8),
            }
    field0_values = [
        row["object_fields_before"]["field_0"]
        for row in traces
        if row["pc_offset"] == "0x2858b4"
    ]
    object_addresses = sorted({int(row["object_address"], 16) for row in traces})
    object_field0_writes = [
        event for event in writes
        if event["pc_offset"] == "0x171268"
        and any(int(event["address"], 16) == address for address in object_addresses)
    ]
    expected_target = image + 0x347F60
    target_writes = [
        event for event in object_field0_writes
        if int(event["address"], 16) in object_addresses
        and int(event["value"], 16) == expected_target
    ]
    object_addresses_hex = {hex(address) for address in object_addresses}
    target_slot_keys = {
        (int(event["registers"]["x28"], 16), event["source_slot"])
        for event in vm_store_events
        if event["destination_address"] in object_addresses_hex
    }
    target_source_history = [
        event for event in vm_register_writes
        if (int(event["backing"], 16), event["slot"]) in target_slot_keys
    ]
    target_store_events = [
        event for event in vm_store_events
        if event["destination_address"] in object_addresses_hex
    ]
    source_value_matches = [
        int.from_bytes(bytes.fromhex(event["source_value"]), "little")
        == int(event["written_value"], 16)
        for event in target_store_events
    ]
    source_history_values = [
        int(event["value"], 16) for event in target_source_history
    ]
    target_value = int(target_store_events[-1]["written_value"], 16) if target_store_events else None
    target_history_indices = [
        index for index, value in enumerate(source_history_values)
        if target_value is not None and value == target_value
    ]
    return {
        "image_base": result["image_base"],
        "continuation_result": result,
        "callback_wrapper_trace": traces,
        "callback_wrapper_trace_count": len(traces),
        "native_guest_writes": writes,
        "native_guest_write_count": len(writes),
        "vm_store_events": vm_store_events,
        "vm_register_writes": vm_register_writes,
        "callback_object_field0_source_slot3_writes": [
            event for event in vm_register_writes if event["slot"] == 3
        ],
        "callback_object_field0_source_history": target_source_history,
        "callback_object_field0_source_history_values": [hex(value) for value in source_history_values],
        "callback_object_field0_source_history_final": (
            hex(source_history_values[-1]) if source_history_values else None
        ),
        "callback_object_field0_source_value_matches_store": bool(source_value_matches) and all(source_value_matches),
        "callback_object_field0_source_history_contains_target": (
            target_value is not None and target_value in source_history_values
        ),
        "callback_object_field0_source_history_target_indices": target_history_indices,
        "callback_object_field0_source_history_target_value": (
            hex(target_value) if target_value is not None else None
        ),
        "callback_object_field0_vm_store_events": target_store_events,
        "post_object_snapshots": post_objects,
        "branch_field_0_values_at_2858b4": field0_values,
        "branch_field_0_nonzero_at_2858b4": any(
            value not in (None, "0000000000000000") for value in field0_values
        ),
        "callback_target_writer_invocation_observed": any(
            row["pc_offset"] == "0x2858b4"
            and row["object_fields_before"]["field_0"] not in (None, "0000000000000000")
            for row in traces
        ),
        "callback_object_field0_writer_pc": "+0x171268",
        "callback_object_field0_writer_events": object_field0_writes,
        "callback_object_field0_writer_target": hex(expected_target),
        "callback_object_field0_writer_target_match": bool(target_writes),
        "callback_object_field0_writer_provenance_closed": bool(target_writes),
        "callback_object_field0_source_provenance_closed": (
            bool(target_store_events)
            and bool(source_history_values)
            and bool(source_value_matches)
            and all(source_value_matches)
            and target_value in source_history_values
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--libc", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    digest = hashlib.sha256(args.library.read_bytes()).hexdigest()
    if digest != oracle.LIBRARY_SHA256:
        raise SystemExit(f"unexpected native sample {digest}")
    rows = [run(args.library, args.libc, image) for image in continuation.BASES]
    report = {
        "schema": "vm9-bootstrap-request-callback-object-trace-fresh-20261026-v2",
        "evidence_date": "2026-10-26",
        "sample_sha256": digest,
        "matching_libc_sha256": hashlib.sha256(args.libc.read_bytes()).hexdigest(),
        "cases": rows,
        "observation_only": True,
        "runtime_table_owner_recovered": False,
        "runtime_table_content_reconstructed": False,
        "synthetic_dispatch_table_used": False,
        "synthetic_callback_vtable_used": False,
        "whole_request_native_success": False,
        "fresh_standalone_signer_verified": False,
        "online_header_acceptance_verified": False,
        "interpretation": (
            "The trace is attached to the same native bootstrap/request continuation "
            "that services the real memcpy PLT. It records callback-object field "
            "values before each bridge instruction and native guest writes, but it "
            "does not fill any missing callback target or runtime dispatch page."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("callback object trace", len(rows), "cases", flush=True)


if __name__ == "__main__":
    main()
