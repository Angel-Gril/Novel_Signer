"""Fresh native differential for the packed-callback consumer at +0x2887f0.

The object layout is supplied as fresh input.  The verifier executes the exact
ELF consumer bytes and stops at the caller return boundary.  It proves how the
consumer passes packed x8, x0 and x1 to its indirect target; it intentionally
does not invent the upstream packed-x8 composition rule.
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
    UC_ARM64_REG_X0,
    UC_ARM64_REG_X1,
    UC_ARM64_REG_X8,
    UC_ARM64_REG_X9,
    UC_ARM64_REG_X10,
    UC_ARM64_REG_X30,
)

OFFSET = 0x2887F0
SIZE = 28
PAGE = 0x1000
CODE = 0x100000
CALLBACK = 0x200000
RETURN = 0x300000
OBJECT_BASE = 0x500000
STACK = 0x600000


def read_code(library: Path) -> tuple[str, bytes, list[str]]:
    raw_hash = hashlib.sha256(library.read_bytes()).hexdigest()
    with library.open("rb") as stream:
        elf = ELFFile(stream)
        section = next(
            section for section in elf.iter_sections()
            if section["sh_addr"] <= OFFSET < section["sh_addr"] + section["sh_size"]
        )
        stream.seek(section["sh_offset"] + OFFSET - section["sh_addr"])
        code = stream.read(SIZE)
    rendered = [
        f"{row.mnemonic} {row.op_str}".strip()
        for row in Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN).disasm(code, OFFSET)
    ]
    expected = [
        "str x30, [sp, #-0x10]!",
        "ldp x9, x1, [x0, #0x10]",
        "ldp x10, x8, [x0]",
        "mov x0, x9",
        "blr x10",
        "ldr x30, [sp], #0x10",
        "ret",
    ]
    if rendered != expected:
        raise AssertionError({"expected": expected, "actual": rendered})
    return raw_hash, code, rendered


def run_case(index: int, code: bytes, *, packed_x8: int, arg0: int, arg1: int, return_value: int) -> dict:
    object_address = OBJECT_BASE + index * 0x40
    initial_x30 = RETURN + 0x100 + index * 0x10
    initial_sp = STACK + 0x800
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    for address in (CODE, CALLBACK, RETURN, STACK, OBJECT_BASE):
        uc.mem_map(address, PAGE)
    uc.mem_write(CODE, code)
    uc.mem_write(CALLBACK, b"\xc0\x03\x5f\xd6")
    object_bytes = (
        CALLBACK.to_bytes(8, "little") + packed_x8.to_bytes(8, "little")
        + arg0.to_bytes(8, "little") + arg1.to_bytes(8, "little")
    )
    uc.mem_write(object_address, object_bytes)
    seen: dict[str, int] = {}

    def on_code(emu: Uc, address: int, _size: int, _user) -> None:
        if address == CALLBACK:
            seen.update({
                "callback_pc": address,
                "callback_x0": emu.reg_read(UC_ARM64_REG_X0),
                "callback_x1": emu.reg_read(UC_ARM64_REG_X1),
                "callback_x8": emu.reg_read(UC_ARM64_REG_X8),
                "callback_x9": emu.reg_read(UC_ARM64_REG_X9),
                "callback_x10": emu.reg_read(UC_ARM64_REG_X10),
                "callback_x30": emu.reg_read(UC_ARM64_REG_X30),
                "callback_sp": emu.reg_read(UC_ARM64_REG_SP),
            })
            emu.reg_write(UC_ARM64_REG_X0, return_value)
            emu.reg_write(UC_ARM64_REG_PC, emu.reg_read(UC_ARM64_REG_X30))
            return
        if address == initial_x30:
            seen.update({
                "return_pc": address,
                "return_x0": emu.reg_read(UC_ARM64_REG_X0),
                "return_sp": emu.reg_read(UC_ARM64_REG_SP),
                "return_x30": emu.reg_read(UC_ARM64_REG_X30),
            })
            emu.emu_stop()

    uc.hook_add(UC_HOOK_CODE, on_code)
    uc.reg_write(UC_ARM64_REG_X0, object_address)
    uc.reg_write(UC_ARM64_REG_X30, initial_x30)
    uc.reg_write(UC_ARM64_REG_SP, initial_sp)
    uc.emu_start(CODE, 0, count=100)
    saved_x30 = int.from_bytes(uc.mem_read(initial_sp - 0x10, 8), "little")
    checks = {
        "callback_x0_is_arg0": seen.get("callback_x0") == arg0,
        "callback_x1_is_arg1": seen.get("callback_x1") == arg1,
        "callback_x8_is_packed_input": seen.get("callback_x8") == packed_x8,
        "callback_x10_is_target": seen.get("callback_x10") == CALLBACK,
        "callback_x30_is_return_pc": seen.get("callback_x30") == CODE + 0x14,
        "saved_original_x30": saved_x30 == initial_x30,
        "return_x0_preserved": seen.get("return_x0") == return_value,
        "return_sp_restored": seen.get("return_sp") == initial_sp,
        "return_x30_restored": seen.get("return_x30") == initial_x30,
    }
    if not all(checks.values()):
        raise AssertionError({"index": index, "seen": seen, "saved_x30": hex(saved_x30), "checks": checks})
    return {
        "index": index,
        "object_address": hex(object_address),
        "packed_x8": hex(packed_x8),
        "arg0": hex(arg0),
        "arg1": hex(arg1),
        "return_value": hex(return_value),
        "callback": {key: hex(value) for key, value in seen.items() if key.startswith("callback_")},
        "return_boundary": {key: hex(value) for key, value in seen.items() if key.startswith("return_")},
        "saved_original_x30": hex(saved_x30),
        "checks": checks,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--library", type=Path, default=Path(r"C:\AI\6\libmetasec_ml_71332.so"))
    args = ap.parse_args()
    native_hash, code, disassembly = read_code(args.library)
    controls = []
    for index in range(12):
        controls.append(run_case(
            index, code,
            packed_x8=(0x440132F700000000 | (0x75952FA9 + index)) & ((1 << 64) - 1),
            arg0=0x710000 + index * 0x20,
            arg1=0x720000 + index * 0x30,
            return_value=0x80 + index,
        ))
    report = {
        "evidence_id": "vm9_packed_callback_consumer_native_fresh_20261006",
        "schema": "vm9-packed-callback-consumer-native-fresh-v1",
        "status": "native_packed_callback_consumer_fresh_differential_pass",
        "native_library_sha256": native_hash,
        "consumer_offset": hex(OFFSET),
        "consumer_size": SIZE,
        "consumer_disassembly": disassembly,
        "controls": len(controls),
        "cases": controls,
        "all_native_controls_pass": True,
        "packed_x8_consumer_abi_verified": True,
        "packed_x8_composition_parameterized": False,
        "current_vm_callback_object_graph_recovered": False,
        "fresh_medusa_output_verified": False,
        "complete_python_medusa": False,
        "no_jvm_rust_signer_complete": False,
        "limitations": [
            "The packed x8 word is a fresh explicit object input; no upstream composition rule is inferred.",
            "The callback body is a synthetic hook and the consumer stops at the caller return boundary.",
            "This does not establish the current VM9 object graph, fresh Medusa output or online acceptance.",
        ],
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("packed callback consumer native fresh differential PASS")


if __name__ == "__main__":
    main()
