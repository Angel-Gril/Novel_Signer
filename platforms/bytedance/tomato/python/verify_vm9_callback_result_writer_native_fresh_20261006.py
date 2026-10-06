"""Fresh native differential for the +0x28863c callback result writer."""
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
    UC_ARM64_REG_X8,
    UC_ARM64_REG_X19,
    UC_ARM64_REG_X30,
)

OFFSET = 0x28863C
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
        section = next(section for section in elf.iter_sections()
                       if section["sh_addr"] <= OFFSET < section["sh_addr"] + section["sh_size"])
        stream.seek(section["sh_offset"] + OFFSET - section["sh_addr"])
        code = stream.read(SIZE)
    rendered = [f"{row.mnemonic} {row.op_str}".strip()
                for row in Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN).disasm(code, OFFSET)]
    expected = [
        "stp x30, x19, [sp, #-0x10]!",
        "ldr x8, [x0]",
        "mov x19, x0",
        "blr x8",
        "str w0, [x19, #8]",
        "ldp x30, x19, [sp], #0x10",
        "ret",
    ]
    if rendered != expected:
        raise AssertionError({"expected": expected, "actual": rendered})
    return raw_hash, code, rendered


def run_case(index: int, code: bytes, *, initial_result_word: int, callback_result: int) -> dict:
    object_address = OBJECT_BASE + index * 0x40
    initial_x30 = RETURN + 0x100 + index * 0x10
    initial_x19 = 0x710000 + index * 0x20
    initial_sp = STACK + 0x800
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    for address in (CODE, CALLBACK, RETURN, STACK, OBJECT_BASE):
        uc.mem_map(address, PAGE)
    uc.mem_write(CODE, code)
    uc.mem_write(CALLBACK, b"\xc0\x03\x5f\xd6")
    object_bytes = CALLBACK.to_bytes(8, "little") + initial_result_word.to_bytes(8, "little")
    uc.mem_write(object_address, object_bytes)
    seen: dict[str, int] = {}

    def on_code(emu: Uc, address: int, _size: int, _user) -> None:
        if address == CALLBACK:
            seen.update({
                "callback_pc": address,
                "callback_x0": emu.reg_read(UC_ARM64_REG_X0),
                "callback_x8": emu.reg_read(UC_ARM64_REG_X8),
                "callback_x19": emu.reg_read(UC_ARM64_REG_X19),
                "callback_x30": emu.reg_read(UC_ARM64_REG_X30),
                "callback_sp": emu.reg_read(UC_ARM64_REG_SP),
            })
            emu.reg_write(UC_ARM64_REG_X0, callback_result)
            emu.reg_write(UC_ARM64_REG_PC, emu.reg_read(UC_ARM64_REG_X30))
            return
        if address == initial_x30:
            seen.update({
                "return_pc": address,
                "return_x0": emu.reg_read(UC_ARM64_REG_X0),
                "return_x19": emu.reg_read(UC_ARM64_REG_X19),
                "return_sp": emu.reg_read(UC_ARM64_REG_SP),
                "return_x30": emu.reg_read(UC_ARM64_REG_X30),
            })
            emu.emu_stop()

    uc.hook_add(UC_HOOK_CODE, on_code)
    uc.reg_write(UC_ARM64_REG_X0, object_address)
    uc.reg_write(UC_ARM64_REG_X8, 0)
    uc.reg_write(UC_ARM64_REG_X19, initial_x19)
    uc.reg_write(UC_ARM64_REG_X30, initial_x30)
    uc.reg_write(UC_ARM64_REG_SP, initial_sp)
    uc.emu_start(CODE, 0, count=100)
    saved_x30 = int.from_bytes(uc.mem_read(initial_sp - 0x10, 8), "little")
    saved_x19 = int.from_bytes(uc.mem_read(initial_sp - 0x8, 8), "little")
    result_word = int.from_bytes(uc.mem_read(object_address + 8, 4), "little")
    checks = {
        "callback_x0_is_object": seen.get("callback_x0") == object_address,
        "callback_x19_is_object": seen.get("callback_x19") == object_address,
        "callback_x30_is_return_pc": seen.get("callback_x30") == CODE + 0x10,
        "saved_original_x30": saved_x30 == initial_x30,
        "saved_original_x19": saved_x19 == initial_x19,
        "result_low_word_written": result_word == (callback_result & 0xFFFFFFFF),
        "return_x0_preserved": seen.get("return_x0") == callback_result,
        "return_x19_restored": seen.get("return_x19") == initial_x19,
        "return_sp_restored": seen.get("return_sp") == initial_sp,
        "return_x30_restored": seen.get("return_x30") == initial_x30,
    }
    if not all(checks.values()):
        raise AssertionError({"index": index, "seen": seen, "saved_x30": hex(saved_x30),
                              "saved_x19": hex(saved_x19), "result_word": hex(result_word),
                              "checks": checks})
    return {
        "index": index,
        "object_address": hex(object_address),
        "initial_result_word": hex(initial_result_word),
        "callback_result": hex(callback_result),
        "callback": {key: hex(value) for key, value in seen.items() if key.startswith("callback_")},
        "return_boundary": {key: hex(value) for key, value in seen.items() if key.startswith("return_")},
        "saved_original_x30": hex(saved_x30),
        "saved_original_x19": hex(saved_x19),
        "result_word_after": hex(result_word),
        "checks": checks,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--library", type=Path, default=Path(r"C:\AI\6\libmetasec_ml_71332.so"))
    args = ap.parse_args()
    native_hash, code, disassembly = read_code(args.library)
    controls = [run_case(index, code, initial_result_word=0xA5A5A5A500000000 | index,
                         callback_result=0x100000000 + index * 0x1111 + index)
                for index in range(12)]
    report = {
        "evidence_id": "vm9_callback_result_writer_native_fresh_20261006",
        "schema": "vm9-callback-result-writer-native-fresh-v1",
        "status": "native_callback_result_writer_fresh_differential_pass",
        "native_library_sha256": native_hash,
        "writer_offset": hex(OFFSET),
        "writer_size": SIZE,
        "writer_disassembly": disassembly,
        "controls": len(controls),
        "cases": controls,
        "all_native_controls_pass": True,
        "callback_object_result_writeback_verified": True,
        "packed_x8_composition_parameterized": False,
        "current_vm_callback_object_graph_recovered": False,
        "fresh_medusa_output_verified": False,
        "complete_python_medusa": False,
        "no_jvm_rust_signer_complete": False,
        "limitations": [
            "The callback body is a synthetic hook; only the native result-writeback wrapper is executed.",
            "The object target and result word are fresh inputs; no upstream writer or packed-x8 composition is inferred.",
            "No current VM9 owner-frame, fresh Medusa output or online acceptance is established.",
        ],
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("callback result writer native fresh differential PASS")


if __name__ == "__main__":
    main()
