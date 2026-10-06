"""Execute the recovered +0x2584ac wrapper on fresh synthetic descriptors.

This is a native instruction differential, not a current VM9 signer.  The
private ELF bytes are executed by Unicorn with synthetic callback/branch
boundaries.  The callback hook mutates the descriptor before the wrapper's
reload, so the test covers the real ``blr``/reload/``br`` control flow and the
saved ``x30`` stack effect without executing an unknown native callback body.
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
    UC_ARM64_REG_X30,
)

WRAPPER_OFFSET = 0x2584AC
WRAPPER_SIZE = 24
PAGE = 0x1000
CODE = 0x100000
CALLBACK = 0x200000
BRANCH_BASE = 0x300000
DESCRIPTOR_BASE = 0x500000
STACK_BASE = 0x600000
RETURN_SENTINEL = 0x7FFF0000


def read_wrapper(library: Path) -> tuple[str, bytes, list[str]]:
    raw_hash = hashlib.sha256(library.read_bytes()).hexdigest()
    with library.open("rb") as stream:
        elf = ELFFile(stream)
        section = next(
            section for section in elf.iter_sections()
            if section["sh_addr"] <= WRAPPER_OFFSET < section["sh_addr"] + section["sh_size"]
        )
        file_offset = section["sh_offset"] + (WRAPPER_OFFSET - section["sh_addr"])
        stream.seek(file_offset)
        code = stream.read(WRAPPER_SIZE)
    rows = list(Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN).disasm(code, WRAPPER_OFFSET))
    rendered = [f"{row.mnemonic} {row.op_str}".strip() for row in rows]
    expected = [
        "str x30, [sp, #-0x10]!",
        "ldr x8, [x0]",
        "blr x8",
        "ldp x1, x8, [x0]",
        "mov x0, x8",
        "br x1",
    ]
    if rendered != expected:
        raise AssertionError({"expected": expected, "actual": rendered})
    return raw_hash, code, rendered


def run_case(index: int, code_bytes: bytes, *, initial_object: int,
             final_object: int, final_target: int) -> dict:
    descriptor = DESCRIPTOR_BASE + index * 0x40
    stack_top = STACK_BASE + 0x800
    initial_x30 = RETURN_SENTINEL + index * 0x100
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    for address in (CODE, CALLBACK, BRANCH_BASE + index * PAGE, DESCRIPTOR_BASE, STACK_BASE):
        uc.mem_map(address, PAGE)
    uc.mem_write(CODE, code_bytes)
    uc.mem_write(CALLBACK, b"\xc0\x03\x5f\xd6")  # ret; hook supplies the body.
    uc.mem_write(descriptor, CALLBACK.to_bytes(8, "little") + initial_object.to_bytes(8, "little"))
    callback_seen: dict[str, int] = {}
    branch_seen: dict[str, int] = {}
    branch_address = BRANCH_BASE + index * PAGE

    def on_code(emu: Uc, address: int, size: int, _user) -> None:
        if address == CALLBACK:
            callback_seen.update({
                "x0": emu.reg_read(UC_ARM64_REG_X0),
                "x30": emu.reg_read(UC_ARM64_REG_X30),
                "sp": emu.reg_read(UC_ARM64_REG_SP),
            })
            # This represents the observed pre-dispatch side effect.  It is
            # deliberately input-driven and performed before ldp reloads x1/x8.
            emu.mem_write(descriptor, final_target.to_bytes(8, "little") + final_object.to_bytes(8, "little"))
            emu.reg_write(UC_ARM64_REG_PC, emu.reg_read(UC_ARM64_REG_X30))
            return
        if address == branch_address:
            branch_seen.update({
                "x0": emu.reg_read(UC_ARM64_REG_X0),
                "x1": emu.reg_read(UC_ARM64_REG_X1),
                "x30": emu.reg_read(UC_ARM64_REG_X30),
                "sp": emu.reg_read(UC_ARM64_REG_SP),
            })
            emu.emu_stop()

    uc.hook_add(UC_HOOK_CODE, on_code)
    uc.reg_write(UC_ARM64_REG_X0, descriptor)
    uc.reg_write(UC_ARM64_REG_X30, initial_x30)
    uc.reg_write(UC_ARM64_REG_SP, stack_top)
    uc.emu_start(CODE, CODE + WRAPPER_SIZE, count=100)
    final_descriptor = int.from_bytes(uc.mem_read(descriptor, 8), "little")
    saved_x30 = int.from_bytes(uc.mem_read(branch_seen.get("sp", STACK_BASE), 8), "little") if branch_seen else None
    expected_callback_return = CODE + 0x0C
    checks = {
        "callback_x0_descriptor": callback_seen.get("x0") == descriptor,
        "callback_x30_is_reload_pc": callback_seen.get("x30") == expected_callback_return,
        "descriptor_rewritten": final_descriptor == final_target,
        "descriptor_object_rewritten": int.from_bytes(uc.mem_read(descriptor + 8, 8), "little") == final_object,
        "branch_x0_final_object": branch_seen.get("x0") == final_object,
        "branch_x1_final_target": branch_seen.get("x1") == final_target,
        "branch_x30_is_reload_pc": branch_seen.get("x30") == expected_callback_return,
        "saved_original_x30": saved_x30 == initial_x30,
        "branch_boundary_reached": bool(branch_seen),
    }
    if not all(checks.values()):
        raise AssertionError({"index": index, "checks": checks, "callback": callback_seen, "branch": branch_seen,
                              "saved_x30": saved_x30, "descriptor": hex(final_descriptor)})
    return {
        "index": index,
        "descriptor": hex(descriptor),
        "initial_target": hex(CALLBACK),
        "initial_object": hex(initial_object),
        "final_target": hex(final_target),
        "final_object": hex(final_object),
        "callback_entry": {key: hex(value) for key, value in callback_seen.items()},
        "branch_entry": {key: hex(value) for key, value in branch_seen.items()},
        "saved_original_x30": hex(saved_x30),
        "checks": checks,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--library", type=Path, default=Path(r"C:\AI\6\libmetasec_ml_71332.so"))
    args = ap.parse_args()
    native_hash, code, disassembly = read_wrapper(args.library)
    cases = []
    for index in range(12):
        cases.append(run_case(
            index, code,
            initial_object=0x700000 + index * 0x120,
            final_object=0x710000 + index * 0x180,
            final_target=BRANCH_BASE + index * PAGE,
        ))
    report = {
        "evidence_id": "vm9_descriptor_trampoline_native_fresh_20261006",
        "schema": "vm9-descriptor-trampoline-native-fresh-v1",
        "status": "native_wrapper_fresh_differential_pass",
        "native_library_sha256": native_hash,
        "wrapper_offset": hex(WRAPPER_OFFSET),
        "wrapper_size": WRAPPER_SIZE,
        "wrapper_disassembly": disassembly,
        "controls": len(cases),
        "cases": cases,
        "all_native_controls_pass": True,
        "callback_body_executed": False,
        "callback_side_effect_modeled_at_hook": True,
        "saved_x30_stack_effect_verified": True,
        "final_br_x1_boundary_verified": True,
        "packed_callback_x8_parameterized": False,
        "current_vm_callback_object_graph_recovered": False,
        "fresh_medusa_output_verified": False,
        "complete_python_medusa": False,
        "no_jvm_rust_signer_complete": False,
        "limitations": [
            "Unicorn stops at the final branch target; it does not execute an unknown native callback body or continuation.",
            "The pre-dispatch mutation is a synthetic fresh input to the wrapper, not a captured current VM9 object graph.",
            "This proves the wrapper instruction contract and stack save, not a fresh online Medusa result or header matrix.",
        ],
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("descriptor trampoline native fresh differential PASS")


if __name__ == "__main__":
    main()
