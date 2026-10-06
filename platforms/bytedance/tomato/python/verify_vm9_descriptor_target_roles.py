"""Audit the active descriptor branch target entries.

The active +0x991c0 writer emits image-relative +0x32a444 and +0x32a4fc.
This verifier checks those addresses as function entries and records the prior
+0x31e444/+0x31e4fc offset mismatch explicitly. It does not execute the final
``br x1`` transfer or claim a complete callback object.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from elftools.elf.elffile import ELFFile


CONTEXT_START = 0x32A424
TARGET_A = 0x32A444
TARGET_B = 0x32A4FC
CONTEXT_END = 0x32A568
OLD_TARGET_A = 0x31E444
OLD_TARGET_B = 0x31E4FC


def disassemble(library: Path, start: int, end: int):
    with library.open("rb") as stream:
        elf = ELFFile(stream)
        section = next(
            section for section in elf.iter_sections()
            if section["sh_addr"] <= start < section["sh_addr"] + section["sh_size"]
        )
        offset = section["sh_offset"] + (start - section["sh_addr"])
        stream.seek(offset)
        code = stream.read(end - start)
    rows = list(Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN).disasm(code, start))
    return [
        {"address": hex(row.address), "mnemonic": row.mnemonic, "op_str": row.op_str}
        for row in rows
    ]


def rendered(rows):
    return [f"{row['mnemonic']} {row['op_str']}".strip() for row in rows]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--library", type=Path, default=Path(r"C:\AI\6\libmetasec_ml_71332.so"))
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    sample_hash = hashlib.sha256(args.library.read_bytes()).hexdigest()
    rows = disassemble(args.library, CONTEXT_START, CONTEXT_END)
    by_address = {int(row["address"], 16): row for row in rows}
    rendered_at = lambda address: f"{by_address[address]['mnemonic']} {by_address[address]['op_str']}".strip()
    assert rendered_at(TARGET_A) == "paciasp"
    assert rendered_at(TARGET_A + 4) == "sub sp, sp, #0x50"
    assert rendered_at(TARGET_A + 8) == "stp x29, x30, [sp, #0x20]"
    assert rendered_at(TARGET_B) == "paciasp"
    assert rendered_at(TARGET_B + 4) == "stp x29, x30, [sp, #-0x20]!"
    assert rendered_at(TARGET_B + 8) == "str x19, [sp, #0x10]"
    assert rendered_at(TARGET_B + 0xC) == "mov x29, sp"
    report = {
        "evidence_id": "vm9_descriptor_target_roles_20261006",
        "schema": "vm9-descriptor-target-roles-v2",
        "status": "corrected_active_target_entry_audit",
        "native_sample_sha256": sample_hash,
        "context": {"start": hex(CONTEXT_START), "end": hex(CONTEXT_END)},
        "active_writer_relocation": {
            "image_relative_targets": [hex(TARGET_A), hex(TARGET_B)],
            "runtime_examples_at_0x122c0000": ["0x125ea444", "0x125ea4fc"],
            "formula": "image_base + target_offset",
        },
        "targets": {
            hex(TARGET_A): {
                "role": "shared_reader_acquire_function_entry",
                "entry_instructions": [rendered_at(TARGET_A + offset) for offset in (0, 4, 8)],
                "standalone_callback_entry": True,
                "python_component": "vm9_objects.acquire_uncontended_shared_reader",
            },
            hex(TARGET_B): {
                "role": "shared_reader_release_function_entry",
                "entry_instructions": [rendered_at(TARGET_B + offset) for offset in (0, 4, 8, 0xC)],
                "standalone_callback_entry": True,
                "python_component": "vm9_objects.release_uncontended_shared_reader",
            },
        },
        "correction": {
            "previously_audited_offsets": [hex(OLD_TARGET_A), hex(OLD_TARGET_B)],
            "previous_interpretation": "interior continuation locations",
            "corrected_interpretation": "not selected by the active descriptor writer; active values resolve to +0x32a444/+0x32a4fc",
        },
        "native_input_snapshot_used": False,
        "active_final_br_target_executed": False,
        "callback_object_parameterized": False,
        "fresh_medusa_output_verified": False,
        "limitations": [
            "Static entry audit only; the final br x1 transfer and return handoff are not executed here.",
            "The descriptor writer and packed callback x8 composition remain separate input boundaries.",
            "The Python shared-reader components do not prove the complete current Medusa signer.",
        ],
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("descriptor target roles correction PASS")


if __name__ == "__main__":
    main()
