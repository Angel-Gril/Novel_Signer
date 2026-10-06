"""Audit the static roles of the two observed descriptor branch targets.

The targets are reported as continuation locations only. This verifier does
not execute them and does not claim a callback-object implementation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from elftools.elf.elffile import ELFFile


CONTEXT_START = 0x31E1D4
TARGET_A = 0x31E444
TARGET_B = 0x31E4FC
CONTEXT_END = 0x31E540


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
    assert rendered(rows[:1]) == ["sub sp, sp, #0x1c0"]
    assert rendered([by_address[TARGET_A]]) == ["ldur x0, [x29, #-0x40]"]
    assert rendered([by_address[TARGET_B]]) == ["mov x29, sp"]
    a_tail = rendered([by_address[address] for address in (0x31E47C, 0x31E480, 0x31E490, 0x31E498)])
    assert "ldp x20, x19, [sp, #0x1b0]" in a_tail
    assert "ret" in a_tail
    b_prefix = rendered([by_address[address] for address in (0x31E4F4, 0x31E4F8, TARGET_B)])
    assert b_prefix[:2] == ["stp x29, x30, [sp, #-0x20]!", "str x19, [sp, #0x10]"]
    report = {
        "evidence_id": "vm9_descriptor_target_roles_20261006",
        "schema": "vm9-descriptor-target-roles-v1",
        "status": "static_continuation_role_audit",
        "native_sample_sha256": sample_hash,
        "context": {"start": hex(CONTEXT_START), "end": hex(CONTEXT_END)},
        "targets": {
            hex(TARGET_A): {
                "role": "interior_continuation_with_owner_frame_epilogue",
                "first_instruction": rendered([by_address[TARGET_A]])[0],
                "epilogue_evidence": a_tail,
                "standalone_callback_entry": False,
            },
            hex(TARGET_B): {
                "role": "interior_continuation_after_prologue_prefix",
                "first_instruction": rendered([by_address[TARGET_B]])[0],
                "preceding_instructions": b_prefix,
                "standalone_callback_entry": False,
            },
        },
        "native_input_snapshot_used": False,
        "callback_object_parameterized": False,
        "fresh_medusa_output_verified": False,
        "limitations": [
            "The audit is static and does not execute either target or recover its live frame inputs.",
            "The descriptor writer, packed x8 composition and active continuation state remain unresolved.",
            "No online signer, Rust download chain or product capability is implied.",
        ],
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("descriptor target roles PASS")


if __name__ == "__main__":
    main()
