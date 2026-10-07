"""Fresh differential for one request nested-VM dispatcher transition."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from unicorn.arm64_const import (
    UC_ARM64_REG_PC, UC_ARM64_REG_SP, UC_ARM64_REG_X0, UC_ARM64_REG_X1,
    UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X8,
    UC_ARM64_REG_X19, UC_ARM64_REG_X20, UC_ARM64_REG_X22, UC_ARM64_REG_X23,
    UC_ARM64_REG_X24, UC_ARM64_REG_X28, UC_ARM64_REG_X29, UC_ARM64_REG_X30,
)

import verify_vm9_signer_objects as oracle
from vm9_allocator import RefillUnsupported, _read_span
from vm9_request_caller import prepare_request_vm_caller
from vm9_request_dispatcher import (
    DISPATCH_OFFSET, prepare_request_dispatch_frame,
    initialize_request_dispatch_scratch, dispatch_request_word,
)

LIBRARY_SHA256 = oracle.LIBRARY_SHA256


class DispatchStop(Exception):
    def __init__(self, phase, snapshot):
        self.phase = phase
        self.snapshot = snapshot


def _regs(cpu):
    items = (
        ("pc", UC_ARM64_REG_PC), ("sp", UC_ARM64_REG_SP),
        ("x0", UC_ARM64_REG_X0), ("x1", UC_ARM64_REG_X1),
        ("x2", UC_ARM64_REG_X2), ("x3", UC_ARM64_REG_X3),
        ("x4", UC_ARM64_REG_X4), ("x8", UC_ARM64_REG_X8),
        ("x19", UC_ARM64_REG_X19), ("x20", UC_ARM64_REG_X20),
        ("x22", UC_ARM64_REG_X22), ("x23", UC_ARM64_REG_X23),
        ("x24", UC_ARM64_REG_X24), ("x28", UC_ARM64_REG_X28),
        ("x29", UC_ARM64_REG_X29), ("x30", UC_ARM64_REG_X30),
    )
    return {name: cpu.reg_read(reg) for name, reg in items}


def _snapshot(cpu, regs):
    ranges = {
        "x19": (regs["x19"], 0x10),
        "x22": (regs["x22"], 4),
        "x23": (regs["x23"], 4),
        "x28": (regs["x28"], 0x100),
        "x29_minus_8": (regs["x29"] - 8, 8),
        "x30": (regs["x30"], 2),
    }
    return {
        "regs": regs,
        "memory": {
            key: {"address": address,
                  "bytes": bytes(cpu.mem_read(address, width))}
            for key, (address, width) in ranges.items()
        },
    }


def native_case(library, image, object_offset, preserved_x8):
    pages = oracle.image_pages(library, image)
    pages.update(oracle.fresh_pages())
    entry = oracle.GUEST + 0xEF00
    object_address = oracle.GUEST + object_offset
    initial = {key: bytearray(data) for key, data in pages.items()}
    state = {"entered": False}
    allowed = range(DISPATCH_OFFSET, DISPATCH_OFFSET + 0x2D0)

    def observe(cpu, address):
        offset = address - image
        if offset == DISPATCH_OFFSET and not state["entered"]:
            state["entered"] = True
            state["entry"] = _snapshot(cpu, _regs(cpu))
            return
        if state["entered"] and offset not in allowed:
            state["target"] = _snapshot(cpu, _regs(cpu))
            raise DispatchStop("target", state["target"])

    try:
        oracle.native(
            library, image, 0x256ED4, [object_address], initial,
            extra_registers={
                UC_ARM64_REG_X8: preserved_x8,
                UC_ARM64_REG_X29: oracle.GUEST + 0xDE00,
                UC_ARM64_REG_X28: 0x123456789ABCDEF0,
                UC_ARM64_REG_X19: oracle.GUEST + 0x2200,
            }, instruction_observer=observe, instruction_limit=100000)
    except DispatchStop as stop:
        assert stop.phase == "target"
    else:
        raise AssertionError("dispatcher did not reach a next handler")
    return state


def model_case(library, image, object_offset, preserved_x8):
    pages = oracle.image_pages(library, image)
    pages.update(oracle.fresh_pages())
    entry = oracle.GUEST + 0xEF00
    frame = prepare_request_dispatch_frame(entry_stack_address=entry,
                                           image_base=image)
    prepare_request_vm_caller(
        pages, entry_stack_address=entry, return_address=oracle.STOP,
        thread_pointer=oracle.GUEST + 0xD000, image_base=image,
        object_address=oracle.GUEST + object_offset,
        preserved_x8=preserved_x8,
        saved_frame_pointer=oracle.GUEST + 0xDE00,
        saved_x28=0x123456789ABCDEF0, saved_x19=oracle.GUEST + 0x2200)
    initialize_request_dispatch_scratch(pages, frame)
    result = dispatch_request_word(pages, frame)
    return frame, pages, result


def _range_bytes(pages, address, width):
    return _read_span(pages, address, width)


def case(library, image, object_offset, preserved_x8):
    native = native_case(library, image, object_offset, preserved_x8)
    frame, pages, result = model_case(library, image, object_offset, preserved_x8)
    entry = native["entry"]["regs"]
    expected = {
        "sp": frame.sp, "x0": frame.x0, "x1": frame.x1, "x2": frame.x2,
        "x3": frame.x3, "x4": frame.x4, "x8": frame.x8, "x19": frame.x19,
        "x20": frame.x20, "x22": frame.x22, "x23": frame.x23,
        "x24": frame.x24, "x28": frame.x28, "x29": frame.x29,
        "x30": frame.x30,
    }
    assert all(entry[key] == value for key, value in expected.items()), (entry, expected)
    target = native["target"]["regs"]
    assert target["pc"] == result["next_handler"], (hex(target["pc"]), result)
    model_ranges = {
        "x19": (frame.x19, 0x10), "x22": (frame.x22, 4),
        "x23": (frame.x23, 4), "x28": (frame.x28, 0x100),
        "x29_minus_8": (frame.x29 - 8, 8), "x30": (frame.x30, 2),
    }
    for name, (address, width) in model_ranges.items():
        expected_bytes = native["target"]["memory"][name]["bytes"]
        assert _range_bytes(pages, address, width) == expected_bytes, name
    return {
        "image_base": hex(image), "object_offset": hex(object_offset),
        "preserved_x8": hex(preserved_x8),
        "word": hex(result["word"]), "next_word": hex(result["next_word"]),
        "slot_index": result["slot_index"], "slot2_index": result["slot2_index"],
        "encoded_displacement": hex(result["encoded_displacement"]),
        "signed_displacement": result["signed_displacement"],
        "table_index": result["table_index"],
        "next_handler": hex(result["next_handler"]),
        "next_handler_offset": hex(result["next_handler_offset"]),
        "entry_registers_match": True, "writes_match": True,
        "native_input_snapshot_used": False,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == LIBRARY_SHA256
    rows = []
    for image in (0x122C0000, 0x775C205000):
        for object_offset, preserved_x8 in (
            (0x1800, 0x7004EDD8), (0x1FF8, 0x64000000),
            (0x2800, image + 0x257050),
        ):
            row = case(args.library, image, object_offset, preserved_x8)
            rows.append(row)
            print("request dispatcher", row["image_base"], row["object_offset"], "PASS", flush=True)
    report = {
        "schema": "vm9-request-dispatcher-fresh-differential-v1",
        "evidence_date": "2026-10-07", "sample_sha256": LIBRARY_SHA256,
        "controls": len(rows), "cases": rows,
        "dispatcher_transition_verified": True,
        "nested_vm_next_handler_verified": True,
        "complete_python_medusa": False,
        "fresh_input_signer_output_verified": False,
        "current_online_header_matrix_verified": False,
        "limitations": [
            "Only +0x16d7d0's normal decode path is modeled; its repair path is not.",
            "The next +0x171138 handler is located but not implemented.",
            "No URL/header/JNI conversion, JVM, server request or signature output is used.",
        ],
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("request dispatcher", len(rows), "fresh differential controls PASS")


if __name__ == "__main__":
    main()
