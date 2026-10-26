"""Record the normal facade's receiver/vtable/target load provenance.

The facade fixture still supplies JNI and a synthetic request service.  This
probe leaves its receiver vtable untouched and records the native loads that
lead to the service call.  It is provenance evidence for the existing fixture
path, not proof of the real request VM or a signer result.
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
from vm9_allocator import _read_span

BASES = facade.BASES
FACADE_ENTRY = 0x17B8F8


def _word(cpu, address):
    return int.from_bytes(bytes(cpu.mem_read(address, 8)), "little")


def run(library: Path, libc: Path, image: int) -> dict:
    pages, arguments = facade.fixture(library, image, "normal")
    service = facade.Services(image, "normal")
    # These are the fixture's native object locations.  No target/vtable word
    # is changed by this verifier.
    receiver_field = facade.FACADE + 0x18
    receiver = facade.RECEIVER
    vtable = facade.VTABLE
    target_slot = vtable + 0x20
    expected_target = facade.REQUEST
    watched = {
        receiver_field: "facade.receiver_field",
        receiver: "receiver.vtable",
        target_slot: "receiver.vtable.target_slot",
    }
    events = []
    instructions = []
    unmapped = []
    call = {"args": None, "pc_offset": None}

    def instruction(cpu, address):
        offset = address - image
        if offset in (FACADE_ENTRY, 0x17BAC0, 0x17B8F8) or address == facade.REQUEST:
            instructions.append({
                "pc": hex(address), "pc_offset": hex(offset),
                "x0": hex(cpu.reg_read(arm.UC_ARM64_REG_X0)),
                "x1": hex(cpu.reg_read(arm.UC_ARM64_REG_X1)),
                "x2": hex(cpu.reg_read(arm.UC_ARM64_REG_X2)),
                "x8": hex(cpu.reg_read(arm.UC_ARM64_REG_X8)),
            })

    def read(cpu, address, size):
        if address not in watched:
            return
        events.append({
            "kind": "read", "field": watched[address], "address": hex(address),
            "size": size, "pc": hex(cpu.reg_read(arm.UC_ARM64_REG_PC)),
            "pc_offset": hex(cpu.reg_read(arm.UC_ARM64_REG_PC) - image),
            "value": hex(_word(cpu, address)) if size == 8 else bytes(cpu.mem_read(address, size)).hex(),
        })

    def write(cpu, address, size):
        if address not in watched:
            return
        events.append({
            "kind": "write", "field": watched[address], "address": hex(address),
            "size": size, "pc": hex(cpu.reg_read(arm.UC_ARM64_REG_PC)),
            "pc_offset": hex(cpu.reg_read(arm.UC_ARM64_REG_PC) - image),
            "value": hex(_word(cpu, address)) if size == 8 else bytes(cpu.mem_read(address, size)).hex(),
        })

    def unmapped_observer(cpu, access, address, size, value):
        unmapped.append({"pc_offset": hex(cpu.reg_read(arm.UC_ARM64_REG_PC) - image),
                         "access": access, "address": hex(address), "size": size,
                         "value": hex(value)})

    def request(args, read_mem, write_mem):
        call["args"] = [hex(value) for value in args]
        call["pc_offset"] = hex(int(call.get("pc", image)) - image) if call.get("pc") else None
        return service.request(args, read_mem, write_mem)

    # Keep the native service adapter, while retaining the request argument
    # record from the callback itself.
    imports = service.imports(image)
    original_request = imports[facade.REQUEST - image]

    def request_import(cpu):
        args = tuple(cpu.reg_read(getattr(arm, "UC_ARM64_REG_X" + str(i))) for i in range(4)) + (
            cpu.reg_read(arm.UC_ARM64_REG_X8),)
        call["args"] = [hex(value) for value in args]
        call["pc"] = cpu.reg_read(arm.UC_ARM64_REG_PC)
        call["pc_offset"] = hex(call["pc"] - image)
        return original_request(cpu)

    imports[facade.REQUEST - image] = request_import

    def malloc(cpu, size):
        return service.allocation("malloc", size,
            lambda address, width: bytes(cpu.mem_read(address, width)),
            lambda address, data: cpu.mem_write(address, data))

    returned = None
    error = None
    try:
        returned, _memory, _allocations, _ledger = oracle.native(
            library, image, FACADE_ENTRY,
            [arguments[name] for name in ("environment_pointer", "facade_address",
                                           "url_reference", "header_array_reference")],
            pages, libc=libc, real_diagnostics=True, real_singletons=True,
            real_mutexes=True, real_recursive_mutexes=True, thread_id=137,
            extra_registers={arm.UC_ARM64_REG_SP: facade.SP,
                             arm.UC_ARM64_REG_TPIDR_EL0: headers.TP},
            host_imports=imports, malloc_handler=malloc,
            instruction_observer=instruction, memory_read_observer=read,
            memory_write_observer=write, unmapped_observer=unmapped_observer,
            instruction_limit=500000)
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"

    if error is not None:
        raise RuntimeError(f"native facade provenance failed at {image:#x}: {error}")
    chain = [event["field"] for event in events if event["kind"] == "read"]
    expected_chain = ["facade.receiver_field", "receiver.vtable",
                      "receiver.vtable.target_slot"]
    cursor = 0
    for field in chain:
        if cursor < len(expected_chain) and field == expected_chain[cursor]:
            cursor += 1
    assert cursor == len(expected_chain), (image, chain)
    assert all(event["value"] == hex(value) for event, value in zip(
        [event for event in events if event["kind"] == "read"],
        (receiver, vtable, expected_target))), events
    assert not [event for event in events if event["kind"] == "write"], events
    assert call["args"] is not None and call["args"][0] == hex(receiver)
    assert call["args"][3] == hex(0x138) and int(call["args"][1], 16) != 0
    assert int(call["args"][2], 16) != 0 and int(call["args"][4], 16) != 0

    values = {name: hex(int.from_bytes(_read_span(pages, address, 8), "little"))
              for address, name in watched.items()}
    return {
        "image_base": hex(image), "facade_entry_offset": hex(FACADE_ENTRY),
        "receiver_field_address": hex(receiver_field), "receiver_address": hex(receiver),
        "vtable_address": hex(vtable), "target_slot_address": hex(target_slot),
        "expected_request_target": hex(expected_target), "initial_watched_values": values,
        "load_store_events": events, "instruction_markers": instructions,
        "native_chain_writes": [],
        "fixture_chain_initializer": "verify_vm9_java_request_facade_fresh_20261020.fixture",
        "request_call": call, "service_requests": service.requests,
        "returned_x0": hex(returned) if returned is not None else None,
        "error": error, "unmapped_events": unmapped,
        "synthetic_virtual_request_service": True,
        "synthetic_virtual_target_injected": False,
        "normal_facade_child_handoff_verified": False,
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
        "schema": "vm9-java-facade-target-provenance-20261026-v1",
        "evidence_date": "2026-10-26", "sample_sha256": digest,
        "matching_libc_sha256": hashlib.sha256(args.libc.read_bytes()).hexdigest(),
        "cases": rows, "fresh_native_cases": len(rows),
        "synthetic_virtual_request_service": True,
        "synthetic_virtual_target_injected": False,
        "normal_facade_child_handoff_verified": False,
        "whole_request_native_differential_verified": False,
        "fresh_standalone_signer_verified": False,
        "online_header_acceptance_verified": False,
        "interpretation": "The untouched facade fixture's native path loads facade+0x18, then receiver+0 and vtable+0x20 before invoking the explicit request service. No native instruction writes those chain fields during the call; their values originate in the explicit facade.fixture provider. This closes only fixture-path load provenance; it does not establish a real Java receiver, child dispatcher, request VM, or signer output.",
        "limitations": [
            "JNI, receiver object, vtable and request target are explicit fixture providers.",
            "The request service is synthetic and the actual request VM is not executed.",
            "No online header acceptance or standalone signer result is claimed.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
    print("facade target provenance", len(rows), "fresh cases", flush=True)


if __name__ == "__main__":
    main()
