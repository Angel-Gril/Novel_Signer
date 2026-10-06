"""Verify the input-driven +0x2584ac descriptor trampoline boundary.

This is a local semantic component test. It does not claim that the packed
callback object or the current VM9 callback target is parameterized.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from elftools.elf.elffile import ELFFile

import vm9_allocator as allocator
import vm9_callbacks as callbacks


def digest_pages(pages) -> str:
    digest = hashlib.sha256()
    for index in sorted(pages):
        digest.update(index.to_bytes(8, "little"))
        digest.update(bytes(pages[index]))
    return digest.hexdigest()


def put(pages, address, value):
    page = pages[address >> 12]
    offset = address & 0xFFF
    page[offset:offset + len(value)] = value


def native_trampoline_disassembly(library: Path):
    """Read only the six public instruction fields at +0x2584ac."""
    raw_hash = hashlib.sha256(library.read_bytes()).hexdigest()
    with library.open("rb") as stream:
        elf = ELFFile(stream)
        section = next(
            section for section in elf.iter_sections()
            if section["sh_addr"] <= 0x2584AC < section["sh_addr"] + section["sh_size"]
        )
        file_offset = section["sh_offset"] + (0x2584AC - section["sh_addr"])
        stream.seek(file_offset)
        code = stream.read(24)
    disassembler = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    rows = list(disassembler.disasm(code, 0x2584AC))
    rendered = [f"{row.mnemonic} {row.op_str}".strip() for row in rows]
    expected = [
        "str x30, [sp, #-0x10]!",
        "ldr x8, [x0]",
        "blr x8",
        "ldp x1, x8, [x0]",
        "mov x0, x8",
        "br x1",
    ]
    if rendered[:len(expected)] != expected:
        raise AssertionError({"expected": expected, "actual": rendered})
    return raw_hash, rendered[:len(expected)]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--library", type=Path, default=Path(r"C:\AI\6\libmetasec_ml_71332.so"))
    args = ap.parse_args()
    native_hash, native_disassembly = native_trampoline_disassembly(args.library)

    pages = {index: bytearray(0x1000) for index in range(4)}
    descriptor = 0x1000
    target_a, target_b = 0x125EA444, 0x125EA4FC
    object_a = 0x3000 + 0x88
    put(pages, descriptor, target_a.to_bytes(8, "little") + object_a.to_bytes(8, "little"))
    events = []

    def pre_dispatch(local_pages, target, address):
        assert target == target_a and address == descriptor
        events.append(["pre_dispatch", target, address])
        allocator._write_span(local_pages, descriptor, target_b.to_bytes(8, "little"))

    def branch_dispatch(target, object_address):
        events.append(["branch_dispatch", target, object_address])
        return 0x5A

    result = callbacks.dispatch_descriptor_trampoline(
        pages, descriptor_address=descriptor,
        pre_dispatch=pre_dispatch, branch_dispatch=branch_dispatch,
    )
    assert result.initial_target == target_a
    assert result.initial_object == object_a
    assert result.final_target == target_b
    assert result.final_object == object_a
    assert result.branch_result == 0x5A
    assert events == [["pre_dispatch", target_a, descriptor],
                      ["branch_dispatch", target_b, object_a]]

    negative = []
    for label, kwargs in (
        ("missing_pre_dispatch", {"pre_dispatch": None, "branch_dispatch": branch_dispatch}),
        ("missing_branch_dispatch", {"pre_dispatch": pre_dispatch, "branch_dispatch": None}),
    ):
        before = digest_pages(pages)
        try:
            callbacks.dispatch_descriptor_trampoline(
                pages, descriptor_address=descriptor, **kwargs,
            )
        except allocator.RefillUnsupported:
            pass
        else:
            raise AssertionError(label)
        assert digest_pages(pages) == before
        negative.append({"case": label, "rejected": True, "unchanged": True})

    null_pages = {index: bytearray(page) for index, page in pages.items()}
    put(null_pages, descriptor, (0).to_bytes(8, "little") + object_a.to_bytes(8, "little"))
    before = digest_pages(null_pages)
    try:
        callbacks.dispatch_descriptor_trampoline(
            null_pages, descriptor_address=descriptor,
            pre_dispatch=pre_dispatch, branch_dispatch=branch_dispatch,
        )
    except allocator.RefillUnsupported:
        pass
    else:
        raise AssertionError("null_initial_fields")
    assert digest_pages(null_pages) == before
    negative.append({"case": "null_initial_fields", "rejected": True, "unchanged": True})

    report = {
        "evidence_id": "vm9_descriptor_trampoline_semantics_20261006",
        "schema": "vm9-descriptor-trampoline-semantics-v1",
        "status": "bounded_semantics_parameterized",
        "instruction_boundary": {
            "entry": "+0x2584ac",
            "pre_dispatch": "ldr x8,[x0]; blr x8",
            "reload_and_handoff": "ldp x1,x8,[x0]; mov x0,x8; br x1",
            "native_static_disassembly_match": True,
            "native_sample_sha256": native_hash,
            "native_disassembly": native_disassembly,
        },
        "initial_target": hex(result.initial_target),
        "final_target": hex(result.final_target),
        "object_address": hex(result.final_object),
        "branch_result": hex(result.branch_result),
        "events": events,
        "negative_cases": negative,
        "native_input_snapshot_used": False,
        "packed_callback_x8_parameterized": False,
        "active_current_vm_callback_recovered": False,
        "fresh_medusa_output_verified": False,
        "limitations": [
            "The pre-dispatch and branch callbacks are explicit caller inputs; no native pointer is executed.",
            "The packed callback-object composition and current VM9 object graph remain unresolved.",
            "This local semantic test does not establish a fresh online signer or Rust download chain.",
        ],
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("descriptor trampoline semantics PASS")


if __name__ == "__main__":
    main()
