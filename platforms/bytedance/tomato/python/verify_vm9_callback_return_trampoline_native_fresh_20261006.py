"""Fresh native differential for the +0x25863c -> +0x25865c return trampoline.

The current root controls observe this trampoline as a separate callback-family
path from the direct +0x2584b8 reader wrapper.  This verifier executes the
original ELF bytes through the stack save/restore, object zeroing, selector
calculation and final indirect branch, then stops at that branch target.  It
does not claim the target body or a current Medusa result.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_HOOK_CODE, UC_MODE_ARM
from unicorn.arm64_const import (
    UC_ARM64_REG_PC,
    UC_ARM64_REG_SP,
    UC_ARM64_REG_X8,
    UC_ARM64_REG_X9,
    UC_ARM64_REG_X10,
    UC_ARM64_REG_X19,
    UC_ARM64_REG_X20,
    UC_ARM64_REG_X30,
)

IMAGE = 0x12000000
PAGE = 0x1000
ENTRY_OFFSET = 0x25863C
CONT_OFFSET = 0x25865C
BRANCH_OFFSET = 0x2586A0
CODE_PAGE = IMAGE + 0x258000
CODE_BYTES = 0x1000
STACK = 0x50000000
OBJECT = 0x51000000
RETURN_SENTINEL = 0x70000000


def read_code(library: Path) -> tuple[str, bytes, list[str], list[str]]:
    raw_hash = hashlib.sha256(library.read_bytes()).hexdigest()
    with library.open("rb") as stream:
        elf = ELFFile(stream)
        section = next(
            section for section in elf.iter_sections()
            if section["sh_addr"] <= 0x258000 < section["sh_addr"] + section["sh_size"]
        )
        file_offset = section["sh_offset"] + (0x258000 - section["sh_addr"])
        stream.seek(file_offset)
        code = stream.read(CODE_BYTES)
    disassembler = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    entry = [
        f"{row.mnemonic} {row.op_str}".strip()
        for row in disassembler.disasm(code[ENTRY_OFFSET - 0x258000:CONT_OFFSET - 0x258000 + 0x20], ENTRY_OFFSET)
    ]
    continuation = [
        f"{row.mnemonic} {row.op_str}".strip()
        for row in disassembler.disasm(code[CONT_OFFSET - 0x258000:BRANCH_OFFSET - 0x258000 + 0x20], CONT_OFFSET)
    ]
    expected_entry = [
        "add x10, x10, #0x6dc",
        "ldr x8, [sp, #8]",
        "sub sp, sp, #0x10",
        "stp x9, x30, [sp]",
        "adr x9, #0x25865c",
        "mov x30, x9",
        "ret",
    ]
    if entry[:len(expected_entry)] != expected_entry:
        raise AssertionError({"entry": entry, "expected": expected_entry})
    expected_prefix = [
        "ldp x9, x30, [sp]",
        "add sp, sp, #0x10",
        "mov w8, #2",
        "stp xzr, xzr, [x19]",
        "tst w20, #1",
        "str x8, [sp, #0x18]",
        "ldr x8, [sp, #0x18]",
        "str x9, [sp, #0x20]",
        "ldr x9, [sp, #0x20]",
        "madd w8, w8, w8, w8",
        "mul x9, x9, x10",
        "adrp x10, #0x258000",
        "and x8, x8, #1",
        "add x10, x10, #0x6a0",
        "add x8, x8, x10",
        "csel x8, x8, x9, ne",
        "br x8",
    ]
    if continuation[:len(expected_prefix)] != expected_prefix:
        raise AssertionError({"continuation": continuation, "expected": expected_prefix})
    return raw_hash, code, entry[:len(expected_entry)], continuation[:len(expected_prefix)]


def run_case(index: int, code: bytes, *, selector: int, saved_x9: int) -> dict:
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.mem_map(CODE_PAGE, CODE_BYTES)
    uc.mem_map(STACK, PAGE)
    uc.mem_map(OBJECT, PAGE)
    initial_x10 = IMAGE + 0x258000 + 0x1D0 + index * 8
    multiplied_x9 = (saved_x9 * (initial_x10 + 0x6DC)) & ((1 << 64) - 1)
    branch_target = (IMAGE + BRANCH_OFFSET) if (selector & 1) else multiplied_x9
    branch_page = branch_target & ~(PAGE - 1)
    if branch_page != CODE_PAGE:
        uc.mem_map(branch_page, PAGE)
    uc.mem_write(CODE_PAGE, code)
    initial_x30 = RETURN_SENTINEL + index * 0x100
    initial_sp = STACK + 0x800
    uc.mem_write(initial_sp + 8, (0xE14 + index).to_bytes(8, "little"))
    uc.mem_write(OBJECT, b"\xA5" * 16)
    seen: dict[str, int] = {}

    def on_code(emu: Uc, address: int, _size: int, _user) -> None:
        if address == branch_target:
            seen.update({
                "pc": address,
                "sp": emu.reg_read(UC_ARM64_REG_SP),
                "x8": emu.reg_read(UC_ARM64_REG_X8),
                "x9": emu.reg_read(UC_ARM64_REG_X9),
                "x10": emu.reg_read(UC_ARM64_REG_X10),
                "x19": emu.reg_read(UC_ARM64_REG_X19),
                "x20": emu.reg_read(UC_ARM64_REG_X20),
                "x30": emu.reg_read(UC_ARM64_REG_X30),
            })
            emu.emu_stop()

    uc.hook_add(UC_HOOK_CODE, on_code)
    uc.reg_write(UC_ARM64_REG_SP, initial_sp)
    uc.reg_write(UC_ARM64_REG_X8, 0)
    uc.reg_write(UC_ARM64_REG_X9, saved_x9)
    uc.reg_write(UC_ARM64_REG_X10, initial_x10)
    uc.reg_write(UC_ARM64_REG_X19, OBJECT)
    uc.reg_write(UC_ARM64_REG_X20, selector)
    uc.reg_write(UC_ARM64_REG_X30, initial_x30)
    try:
        uc.emu_start(IMAGE + ENTRY_OFFSET, 0, count=100)
    except Exception as exc:
        raise AssertionError({"index": index, "selector": selector, "saved_x9": saved_x9, "branch_target": hex(branch_target), "pc": hex(uc.reg_read(UC_ARM64_REG_PC)), "x8": hex(uc.reg_read(UC_ARM64_REG_X8)), "error": str(exc)}) from exc
    object_bytes = bytes(uc.mem_read(OBJECT, 16))
    stack_x8 = int.from_bytes(uc.mem_read(initial_sp + 0x18, 8), "little")
    stack_x9 = int.from_bytes(uc.mem_read(initial_sp + 0x20, 8), "little")
    checks = {
        "branch_boundary_reached": seen.get("pc") == branch_target,
        "branch_target_matches_selector": seen.get("x8") == branch_target,
        "x9_multiplied_input": seen.get("x9") == multiplied_x9,
        "sp_restored": seen.get("sp") == initial_sp,
        "x30_restored": seen.get("x30") == initial_x30,
        "object_zeroed": object_bytes == bytes(16),
        "stack_x8_seed": stack_x8 == 2,
        "stack_x9_saved": stack_x9 == saved_x9,
        "selector_register_preserved": seen.get("x20") == selector,
    }
    if not all(checks.values()):
        raise AssertionError({"index": index, "selector": selector, "saved_x9": saved_x9,
                              "branch_target": hex(branch_target), "seen": seen,
                              "object": object_bytes.hex(), "stack_x8": hex(stack_x8),
                              "stack_x9": hex(stack_x9), "checks": checks})
    return {
        "index": index,
        "selector": selector,
        "saved_x9": hex(saved_x9),
        "branch_target": hex(branch_target),
        "branch_state": {key: hex(value) for key, value in seen.items()},
        "object_after": object_bytes.hex(),
        "stack_x8": hex(stack_x8),
        "stack_x9": hex(stack_x9),
        "checks": checks,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--library", type=Path, default=Path(r"C:\AI\6\libmetasec_ml_71332.so"))
    args = ap.parse_args()
    native_hash, code, entry_disassembly, continuation_disassembly = read_code(args.library)
    controls = []
    for index, (selector, saved_x9) in enumerate(((0, 1), (1, 1), (2, 1), (3, 1), (1, 2), (1, 3), (0, 2), (2, 3))):
        controls.append(run_case(index, code, selector=selector, saved_x9=saved_x9))
    report = {
        "evidence_id": "vm9_callback_return_trampoline_native_fresh_20261006",
        "schema": "vm9-callback-return-trampoline-native-fresh-v1",
        "status": "native_return_trampoline_fresh_differential_pass",
        "native_library_sha256": native_hash,
        "entry_offset": hex(ENTRY_OFFSET),
        "continuation_offset": hex(CONT_OFFSET),
        "branch_offset": hex(BRANCH_OFFSET),
        "entry_disassembly": entry_disassembly,
        "continuation_disassembly": continuation_disassembly,
        "controls": len(controls),
        "cases": controls,
        "all_native_controls_pass": True,
        "stack_save_restore_verified": True,
        "object_zero_initialization_verified": True,
        "selector_branch_verified": True,
        "current_vm_callback_object_graph_recovered": False,
        "packed_callback_x8_parameterized": False,
        "fresh_medusa_output_verified": False,
        "complete_python_medusa": False,
        "no_jvm_rust_signer_complete": False,
        "limitations": [
            "The final branch target is a stop boundary; its body and continuation are not executed.",
            "The controls use synthetic fresh registers, stack and object memory; they do not parameterize the current VM9 owner frame.",
            "The trampoline is a separate callback-family path and does not prove the +0x2584ac descriptor graph or packed callback x8 composition.",
        ],
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("callback return trampoline native fresh differential PASS")


if __name__ == "__main__":
    main()
