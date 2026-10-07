"""Locate the first post-loop target after request handler +0x171138."""
from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path
from unicorn.arm64_const import (
    UC_ARM64_REG_PC, UC_ARM64_REG_SP, UC_ARM64_REG_X0, UC_ARM64_REG_X1,
    UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X8, UC_ARM64_REG_X9,
    UC_ARM64_REG_X19, UC_ARM64_REG_X20, UC_ARM64_REG_X22, UC_ARM64_REG_X23,
    UC_ARM64_REG_X28, UC_ARM64_REG_X29,
)
import verify_vm9_signer_objects as oracle

HANDLER = 0x171138
HANDLER_END = 0x1712C8
DISPATCH = 0x16D7D0

class Stop(Exception):
    def __init__(self, snapshot): self.snapshot = snapshot

def snapshot(cpu, *, count=None):
    regs = (("pc", UC_ARM64_REG_PC), ("sp", UC_ARM64_REG_SP),
            ("x0", UC_ARM64_REG_X0), ("x1", UC_ARM64_REG_X1),
            ("x4", UC_ARM64_REG_X4), ("x5", UC_ARM64_REG_X5),
            ("x8", UC_ARM64_REG_X8), ("x9", UC_ARM64_REG_X9),
            ("x19", UC_ARM64_REG_X19), ("x20", UC_ARM64_REG_X20),
            ("x22", UC_ARM64_REG_X22), ("x23", UC_ARM64_REG_X23),
            ("x28", UC_ARM64_REG_X28), ("x29", UC_ARM64_REG_X29))
    out = {"regs": {name: cpu.reg_read(reg) for name, reg in regs}}
    if count is not None: out["handler_instruction_count"] = count
    return out

def case(library, image, object_offset, preserved_x8):
    pages = oracle.image_pages(library, image); pages.update(oracle.fresh_pages())
    object_address = oracle.GUEST + object_offset
    state = {"dispatch": False, "handler": False, "count": 0}
    def observe(cpu, address):
        off = address - image
        if off == DISPATCH:
            state["dispatch"] = True
        if state["dispatch"] and off == HANDLER and not state["handler"]:
            state["handler"] = True
            state["count"] = 1
            state["entry"] = snapshot(cpu, count=1)
            return
        if state["handler"]:
            state["count"] += 1
            if not (HANDLER <= off < HANDLER_END):
                state["exit"] = snapshot(cpu, count=state["count"])
                raise Stop(state["exit"])
    try:
        oracle.native(library, image, 0x256ED4, [object_address], pages,
            extra_registers={
                UC_ARM64_REG_X8: preserved_x8,
                UC_ARM64_REG_X29: oracle.GUEST + 0xDE00,
                UC_ARM64_REG_X28: 0x123456789ABCDEF0,
                UC_ARM64_REG_X19: oracle.GUEST + 0x2200,
            }, instruction_observer=observe, instruction_limit=1000000)
    except Stop as stop:
        assert stop.snapshot["regs"]["pc"] != image + HANDLER
    else:
        raise AssertionError("+0x171138 did not leave its loop")
    return {
        "image_base": hex(image), "object_offset": hex(object_offset),
        "preserved_x8": hex(preserved_x8),
        "handler_entry": hex(state["entry"]["regs"]["pc"] - image),
        "first_post_handler": hex(state["exit"]["regs"]["pc"] - image),
        "handler_instruction_count": state["exit"]["handler_instruction_count"],
        "native_input_snapshot_used": False,
    }

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--library", type=Path, required=True); ap.add_argument("--output", type=Path, required=True); a = ap.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest() == oracle.LIBRARY_SHA256
    rows=[]
    for image in (0x122C0000, 0x775C205000):
        for off, x8 in ((0x1800, 0x7004EDD8), (0x1FF8, 0x64000000), (0x2800, image + 0x257050)):
            rows.append(case(a.library, image, off, x8)); print('nested handler', hex(image), hex(off), 'PASS', flush=True)
    report = {
        "schema": "vm9-request-nested-handler-exit-fresh-observation-v1",
        "evidence_date": "2026-10-07", "sample_sha256": oracle.LIBRARY_SHA256,
        "controls": len(rows), "cases": rows,
        "handler_entry_located": True, "handler_exit_located": True,
        "handler_python_implementation_verified": False,
        "complete_python_medusa": False, "fresh_input_signer_output_verified": False,
        "current_online_header_matrix_verified": False,
        "limitations": [
            "This is a native boundary observation for +0x171138's normal loop.",
            "The handler loop and +0x16855c body are not implemented in Python.",
            "No URL/header/JNI conversion, JVM, server request or signature output is used.",
        ],
    }
    a.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('nested handler', len(rows), 'fresh observations PASS')
if __name__ == '__main__': main()
