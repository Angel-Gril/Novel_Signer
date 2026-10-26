"""Observe the native Java-facade ABI at an injected child target.

The normal facade VM is executed from fresh ELF pages with explicit JNI and
matching-libc services. Only the synthetic receiver's virtual method slot is
changed to native ``+0x27dd04``; the probe stops on that child entry before any
child instruction executes. This is an ABI/state-branch observation, not a
normal facade result, whole-request differential, or signing success.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from unicorn import arm64_const as arm

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import verify_vm9_java_request_facade_fresh_20261020 as facade
import verify_vm9_jni_header_input_fresh_20261020 as headers
import verify_vm9_signer_objects as oracle

BASES = facade.BASES
CHILD = 0x27DD04
FACADE_ENTRY = 0x17B8F8


def _u(cpu, address, width=8):
    return int.from_bytes(bytes(cpu.mem_read(address, width)), "little")


def run(library: Path, libc: Path, image: int) -> dict:
    pages, arguments = facade.fixture(library, image, "normal")
    # Artificial virtual-target injection. Use the native receiver vtable slot
    # and add only the bounded child receiver/mutex/tree fields required by
    # +27dd04; no native snapshot or callback vtable is imported.
    target_slot = image + 0x35D5F0 + 0x20
    headers.binary.w(pages, facade.RECEIVER, image + 0x35D5F0)
    headers.binary.w(pages, target_slot, image + CHILD)
    mutex = headers.G + 0x2600
    container = headers.G + 0x2700
    control = headers.G + 0x2800
    sentinel = headers.G + 0x2900
    pair = headers.G + 0x2A00
    headers._write_span(pages, mutex, bytes(0x98))
    def write_word(address, value, width=8):
        headers.binary.w(pages, address, value, width)
    for address, value in (
        (facade.RECEIVER + 8, mutex), (facade.RECEIVER + 0x10, container),
        (facade.RECEIVER + 0x20, pair), (container, image + 0x35B828),
        (container + 0x20, control), (control, sentinel), (control + 8, 0),
        (sentinel, 1), (sentinel + 8, 0), (sentinel + 0x10, sentinel),
        (sentinel + 0x18, sentinel), (pair, 0), (pair + 8, headers.G + 0x2B00)):
        write_word(address, value)
    service = facade.Services(image, "normal")
    holder = {"entry": None, "last_pc_offset": None, "unmapped": []}
    instruction_count = 0
    observed_offsets = []

    def observe(cpu, address):
        nonlocal instruction_count
        instruction_count += 1
        offset = address - image
        holder["last_pc_offset"] = hex(offset)
        if offset not in observed_offsets and offset in (FACADE_ENTRY, CHILD):
            observed_offsets.append(offset)
        if offset != CHILD or holder["entry"] is not None:
            return
        entry = {"x" + str(index): hex(cpu.reg_read(getattr(arm, "UC_ARM64_REG_X" + str(index))))
                 for index in (0, 1, 2, 3, 8)}
        entry.update({"sp": hex(cpu.reg_read(arm.UC_ARM64_REG_SP)),
                      "x30": hex(cpu.reg_read(arm.UC_ARM64_REG_X30)),
                      "stack_delta_from_facade_fixture": facade.SP - cpu.reg_read(arm.UC_ARM64_REG_SP),
                      "url_reference_words": [hex(_u(cpu, cpu.reg_read(arm.UC_ARM64_REG_X1) + i))
                                              for i in (0, 8)],
                      "header_reference_words": [hex(_u(cpu, cpu.reg_read(arm.UC_ARM64_REG_X2) + i))
                                                 for i in (0, 8)],
                      "output_reference_words": [hex(_u(cpu, cpu.reg_read(arm.UC_ARM64_REG_X8) + i))
                                                 for i in (0, 8)]})
        holder["entry"] = entry
        # Continue through child; entry is retained only for ABI observation.

    def malloc(cpu, size):
        return service.allocation("malloc", size,
            lambda address, width: bytes(cpu.mem_read(address, width)),
            lambda address, data: cpu.mem_write(address, data))

    def unmapped(cpu, access, address, size, value):
        holder["unmapped"].append({"pc_offset": hex(cpu.reg_read(arm.UC_ARM64_REG_PC) - image),
                                   "access": access, "address": hex(address),
                                   "size": size, "value": hex(value)})

    error = None
    returned = None
    try:
        returned, _memory, _allocations, _ledger = oracle.native(
            library, image, FACADE_ENTRY,
            [arguments[name] for name in ("environment_pointer", "facade_address",
                                           "url_reference", "header_array_reference")],
            pages, libc=libc, real_diagnostics=True, real_singletons=True,
            real_mutexes=True, real_recursive_mutexes=True, thread_id=137,
            extra_registers={arm.UC_ARM64_REG_SP: facade.SP,
                             arm.UC_ARM64_REG_TPIDR_EL0: headers.TP},
            host_imports=service.imports(image), malloc_handler=malloc,
            instruction_observer=observe, unmapped_observer=unmapped,
            instruction_limit=120000)
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"

    cpu = None
    return {"image_base": hex(image), "facade_entry_offset": hex(FACADE_ENTRY),
            "injected_virtual_target_offset": hex(CHILD),
            "target_slot_address": hex(target_slot),
            "outcome": "child_entry_observed_and_continued" if holder["entry"] else "stopped_before_child_entry",
            "error": error, "returned_x0": hex(returned) if returned is not None else None,
            "native_instructions_observed": instruction_count,
            "last_pc_offset": holder["last_pc_offset"],
            "unmapped_events": holder["unmapped"],
            "observed_offsets": [hex(offset) for offset in observed_offsets],
            "child_entry": holder["entry"],
            "synthetic_virtual_target_injected": True,
            "child_instruction_executed": bool(holder["entry"]),
            "native_snapshot_input": False,
            "normal_facade_child_handoff_verified": False,
            "whole_request_native_differential_verified": False,
            "fresh_standalone_signer_verified": False,
            "online_header_acceptance_verified": False}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--libc", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    digest = hashlib.sha256(args.library.read_bytes()).hexdigest()
    assert digest == oracle.LIBRARY_SHA256, digest
    rows = [run(args.library, args.libc, image) for image in BASES]
    assert all(row["child_entry"] is not None for row in rows), rows
    assert all(row["child_entry"]["x3"] == "0x138" for row in rows)
    assert all(row["child_entry"]["stack_delta_from_facade_fixture"] == 176 for row in rows)
    report = {
        "schema": "vm9-java-facade-injected-child-continuation-20261026-v1",
        "evidence_date": "2026-10-26", "sample_sha256": digest,
        "matching_libc_sha256": hashlib.sha256(args.libc.read_bytes()).hexdigest(),
        "cases": rows, "fresh_native_cases": len(rows),
        "observation_only": True, "synthetic_virtual_target_injected": True,
        "child_instruction_executed": True, "native_snapshot_input": False,
        "normal_facade_child_handoff_verified": False,
        "whole_request_native_differential_verified": False,
        "fresh_standalone_signer_verified": False,
        "online_header_acceptance_verified": False,
        "interpretation": "Fresh native +0x17b8f8 reaches the injected image+0x27dd04 slot on both bases and then executes the child until the first unresolved native/VM boundary. The receiver/virtual target is a synthetic fixture mutation; this does not establish the normal facade target, child VM completion, or signing.",
        "limitations": [
            "The virtual target slot is deliberately changed from the fixture guest service to image+0x27dd04.",
            "JNI, allocator, diagnostics and URL/header objects remain explicit fixture providers.",
            "The child run is bounded and any stop/error is recorded as an unresolved boundary.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
    print("facade injected child continuation", len(rows), "fresh cases", flush=True)


if __name__ == "__main__":
    main()
