"""Verify the VM STORE64 decoder behind native ``+0x171268``.

The optional trace is a private native/VM capture used only as an oracle.  The
public result records hashes, offsets and decoded field relations; it does not
turn a captured register file into a signer input.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from elftools.elf.elffile import ELFFile

import vm9_descriptor_writer as writer
from vm9_allocator import RefillUnsupported


WRITER_OFFSET = 0x171268
DESCRIPTOR_SAMPLE = 0xE4FFE290


def disassemble(library: Path, start: int, end: int):
    with library.open("rb") as stream:
        elf = ELFFile(stream)
        section = next(
            section for section in elf.iter_sections()
            if section["sh_addr"] <= start < section["sh_addr"] + section["sh_size"]
        )
        stream.seek(section["sh_offset"] + start - section["sh_addr"])
        code = stream.read(end - start)
    return list(Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN).disasm(code, start))


def page_digest(pages) -> str:
    digest = hashlib.sha256()
    for page in sorted(pages):
        digest.update(page.to_bytes(8, "little"))
        digest.update(bytes(pages[page]))
    return digest.hexdigest()


def trace_hits(trace_path: Path, descriptor: int, call_filter: str | None):
    payload = json.loads(trace_path.read_text(encoding="utf-8"))
    hits = []
    for call, events in payload.items():
        if call_filter is not None and call != call_filter:
            continue
        for event in events:
            if len(event) < 35:
                continue
            word = int(event[1]) & writer.MASK32
            if (word & 0x3F) != writer.STORE64_OPCODE:
                continue
            registers = [int(value) & writer.MASK64 for value in event[3:35]]
            fields = writer.decode_store64(word)
            destination = (registers[fields.base_slot] + fields.immediate) & writer.MASK64
            if destination not in (descriptor, descriptor + 8):
                continue
            hits.append({
                "call": call,
                "instruction_index": int(event[0]),
                "word": hex(word),
                "base_slot": fields.base_slot,
                "value_slot": fields.value_slot,
                "immediate": fields.immediate,
                "base_value": hex(registers[fields.base_slot]),
                "value": hex(registers[fields.value_slot]),
                "destination": hex(destination),
                "field_offset": destination - descriptor,
            })
    return hits


def run_model(hit, descriptor):
    pages = {descriptor >> 12: bytearray(0x1000)}
    registers = [0] * 32
    registers[hit["base_slot"]] = int(hit["base_value"], 16)
    registers[hit["value_slot"]] = int(hit["value"], 16)
    word = int(hit["word"], 16)
    result = writer.execute_descriptor_store(
        pages,
        word=word,
        virtual_registers=registers,
        descriptor_address=descriptor,
        field_offset=hit["field_offset"],
    )
    stored = int.from_bytes(
        pages[descriptor >> 12][(descriptor & 0xFFF) + hit["field_offset"]:
            (descriptor & 0xFFF) + hit["field_offset"] + 8],
        "little",
    )
    assert result.destination == descriptor + hit["field_offset"]
    assert stored == result.value == int(hit["value"], 16)
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, default=Path(r"C:\AI\6\libmetasec_ml_71332.so"))
    parser.add_argument("--trace", type=Path, default=Path(r"C:\AI\6\_vmtrace_a.json"))
    parser.add_argument("--descriptor-address", type=lambda value: int(value, 0), default=DESCRIPTOR_SAMPLE)
    parser.add_argument("--call", default="991c0#1", help="captured VM call to inspect")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    rows = disassemble(args.library, WRITER_OFFSET - 0x30, WRITER_OFFSET + 0x10)
    by_address = {row.address: row for row in rows}
    expected = {
        WRITER_OFFSET - 0x30: "ldr x17, [x28, x13, lsl #3]",
        WRITER_OFFSET - 0x28: "ldr x15, [x28, x14, lsl #3]",
        WRITER_OFFSET - 0x20: "sxth x16, w11",
        WRITER_OFFSET: "str x15, [x17, x16]",
    }
    native_rows = {}
    for address, text in expected.items():
        row = by_address[address]
        rendered = f"{row.mnemonic} {row.op_str}".strip()
        assert rendered == text, (hex(address), rendered, text)
        native_rows[hex(address)] = rendered

    hits = trace_hits(args.trace, args.descriptor_address, args.call)
    assert hits, "the supplied trace has no descriptor STORE64 hit"
    modeled = [run_model(hit, args.descriptor_address) for hit in hits]

    # Negative controls prove the public boundary does not guess a callback.
    negatives = []
    pages = {args.descriptor_address >> 12: bytearray(0x1000)}
    before = page_digest(pages)
    try:
        writer.decode_store64(0)
    except RefillUnsupported:
        negatives.append({"case": "non_store64_word", "rejected": True})
    else:
        raise AssertionError("non_store64_word")
    try:
        writer.execute_descriptor_store(
            pages,
            word=int(hits[0]["word"], 16),
            virtual_registers=[0] * 32,
            descriptor_address=args.descriptor_address,
            field_offset=0,
        )
    except (RefillUnsupported, ValueError):
        negatives.append({"case": "uninitialized_register_target", "rejected": True})
    else:
        raise AssertionError("uninitialized_register_target")
    assert page_digest(pages) == before

    report = {
        "evidence_id": "vm9_descriptor_writer_store64_20261006",
        "schema": "vm9-descriptor-writer-store64-v1",
        "status": "instruction_boundary_parameterized",
        "native_library_sha256": hashlib.sha256(args.library.read_bytes()).hexdigest(),
        "trace_sha256": hashlib.sha256(args.trace.read_bytes()).hexdigest(),
        "writer": {
            "so_offset": hex(WRITER_OFFSET),
            "native_instructions": native_rows,
            "semantics": "STORE64: guest[virtual_register[base_slot] + signed_immediate] = virtual_register[value_slot]",
        },
        "descriptor_sample": {
            "address": hex(args.descriptor_address),
            "call": args.call,
            "hit_count": len(hits),
            "hits": hits,
            "modeled_results": [
                {
                    "destination": hex(result.destination),
                    "value": hex(result.value),
                    "previous": hex(result.previous),
                }
                for result in modeled
            ],
        },
        "negative_controls": negatives,
        "input_boundary": {
            "vm_word": True,
            "virtual_registers": True,
            "descriptor_field_target": True,
            "owner_frame_live_state": False,
            "packed_callback_x8": False,
            "fresh_input_generation": False,
            "fresh_medusa_output": False,
        },
        "limitations": [
            "The trace is a captured VM/native oracle, not a fresh startup.",
            "This recovers the STORE64 field permutation and memory effect only.",
            "The caller that produces the VM word/register file and the owner-frame continuations remain unresolved.",
            "No online server validation, Rust signer, or download product is implied.",
        ],
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("descriptor writer STORE64 PASS")


if __name__ == "__main__":
    main()
