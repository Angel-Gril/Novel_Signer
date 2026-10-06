"""Fresh differential for the direct +0x2584b8 -> br x1 handoff.

The current root VM callback sequence enters +0x2584b8 directly with a
16-byte descriptor: field 0 is the active target and field 1 is a fresh
shared-reader object. This verifier executes that direct wrapper natively on
fresh pages and compares the target's mutex/count effects with Python.

The longer +0x2584ac pre-dispatch/reload path and packed callback-object
composition remain separate unsupported boundaries.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from elftools.elf.elffile import ELFFile

import vm9_callbacks as callbacks
import vm9_objects as objects
from vm9_allocator import _read_span, _write_span
from verify_vm9_signer_objects import GUEST, LIBRARY_SHA256, fresh_pages, native

WRAPPER = 0x2584B8
TARGETS = {"acquire": 0x32A444, "release": 0x32A4FC}
COUNTS = {"acquire": (0, 1, 7, 0x7FFFFFFE),
          "release": (1, 2, 7, 0x7FFFFFFE)}
BASES = (0x122C0000, 0x775C205000)


def disassembly(library: Path):
    with library.open("rb") as stream:
        elf = ELFFile(stream)
        section = next(section for section in elf.iter_sections()
                       if section["sh_addr"] <= WRAPPER < section["sh_addr"] + section["sh_size"])
        stream.seek(section["sh_offset"] + WRAPPER - section["sh_addr"])
        code = stream.read(12)
    rows = list(Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN).disasm(code, WRAPPER))
    rendered = [f"{row.mnemonic} {row.op_str}".strip() for row in rows]
    expected = ["ldp x1, x8, [x0]", "mov x0, x8", "br x1"]
    assert rendered == expected, (rendered, expected)
    return rendered


def one_case(library: Path, libc: Path, base: int, kind: str, count: int):
    pages = fresh_pages()
    descriptor = GUEST + 0x1000
    object_address = GUEST + 0x2000
    _write_span(pages, descriptor, (base + TARGETS[kind]).to_bytes(8, "little")
                + object_address.to_bytes(8, "little"))
    _write_span(pages, object_address, (0x2000).to_bytes(2, "little"))
    _write_span(pages, object_address + 0x88, count.to_bytes(4, "little"))
    observed = {(descriptor, 16): None, (object_address, 0x90): None}
    native_result, expected_memory, allocations, ledger = native(
        library, base, WRAPPER, [descriptor], pages, libc=libc,
        real_mutexes=True, observed_memory=observed,
    )
    model_pages = {index: bytearray(data) for index, data in pages.items()}
    model = (objects.acquire_uncontended_shared_reader if kind == "acquire"
             else objects.release_uncontended_shared_reader)
    direct = callbacks.dispatch_direct_descriptor_branch(
        model_pages,
        descriptor_address=descriptor,
        branch_dispatch=lambda target, object_value: (
            model(model_pages, mutex_address=object_value)
            if target == base + TARGETS[kind] else (_ for _ in ()).throw(
                AssertionError(f"unexpected branch target {target:#x}"))),
    )
    assert direct.branch_target == base + TARGETS[kind]
    assert direct.object_address == object_address
    model_count = direct.branch_result
    actual_memory = _read_span(model_pages, GUEST, 0xA000)
    if actual_memory != expected_memory:
        first = next(i for i, (left, right) in enumerate(zip(actual_memory, expected_memory)) if left != right)
        raise AssertionError(f"{kind} {count:#x}: memory mismatch at guest+{first:#x}")
    if native_result != 0:
        raise AssertionError(f"{kind} {count:#x}: branch target returned {native_result:#x}, expected mutex status 0")
    if model_count != count + (1 if kind == "acquire" else -1):
        raise AssertionError(f"{kind} {count:#x}: model count mismatch")
    assert [item[0] for item in ledger] == ["pthread_mutex_lock", "pthread_mutex_unlock"]
    assert allocations == []
    assert _read_span(model_pages, descriptor, 16) == _read_span(pages, descriptor, 16)
    return {
        "image_base": hex(base),
        "kind": kind,
        "wrapper_offset": hex(WRAPPER),
        "target_offset": hex(TARGETS[kind]),
        "descriptor": hex(descriptor),
        "object_address": hex(object_address),
        "initial_count": hex(count),
        "final_count": hex(model_count),
        "native_return": hex(native_result),
        "memory_match": True,
        "descriptor_unchanged": True,
        "direct_br_x1_executed": True,
        "python_direct_descriptor_dispatch": True,
        "normal_mutex_pair": ledger,
        "allocations": 0,
        "fresh_memory": True,
        "native_input_snapshot_used": False,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--library", type=Path, required=True)
    ap.add_argument("--libc", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == LIBRARY_SHA256
    cases = [one_case(args.library, args.libc, base, kind, count)
             for base in BASES for kind in ("acquire", "release") for count in COUNTS[kind]]
    report = {
        "evidence_id": "vm9_descriptor_branch_handoff_fresh_20261006",
        "schema": "vm9-descriptor-branch-handoff-fresh-v1",
        "status": "direct_wrapper_branch_handoff_verified",
        "native_library_sha256": hashlib.sha256(args.library.read_bytes()).hexdigest(),
        "libc_sha256": hashlib.sha256(args.libc.read_bytes()).hexdigest(),
        "wrapper_offset": hex(WRAPPER),
        "wrapper_disassembly": disassembly(args.library),
        "active_target_offsets": {label: hex(offset) for label, offset in TARGETS.items()},
        "controls": len(cases),
        "cases": cases,
        "all_memory_matches": all(case["memory_match"] for case in cases),
        "all_direct_br_handoffs": all(case["direct_br_x1_executed"] for case in cases),
        "all_python_direct_dispatches": all(case["python_direct_descriptor_dispatch"] for case in cases),
        "all_descriptor_unchanged": all(case["descriptor_unchanged"] for case in cases),
        "pre_dispatch_trampoline_executed": False,
        "packed_callback_x8_parameterized": False,
        "full_callback_chain_recovered": False,
        "fresh_medusa_output_verified": False,
        "complete_python_medusa": False,
        "limitations": [
            "This proves the direct +0x2584b8 descriptor handoff used by the bounded root VM callback sequence.",
            "The longer +0x2584ac pre-dispatch path, packed x8 composition and current native object graph remain unresolved.",
            "No online signer, Rust download chain or product capability is implied.",
        ],
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("descriptor direct branch handoff fresh differential PASS", len(cases))


if __name__ == "__main__":
    main()
