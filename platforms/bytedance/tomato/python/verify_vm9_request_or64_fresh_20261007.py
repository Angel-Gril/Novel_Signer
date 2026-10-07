"""Fresh native/Python differential for +0x16a5a8, including aliases."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from unicorn import arm64_const as arm

import verify_vm9_signer_objects as oracle
from vm9_allocator import RefillUnsupported, _read_span, _write_span
from vm9_request_or64 import (
    HANDLER_OFFSET, HANDLER_END, prepare_or64_state, apply_or64,
)

MASK64 = (1 << 64) - 1
REGISTER_NAMES = ("x4", "x5", "x8", "x9", "x10", "x11", "x12", "x13",
                  "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x28", "x29")


class Stop(Exception):
    pass


def control_pages(library, image, control):
    pages = oracle.image_pages(library, image)
    pages.update(oracle.fresh_pages())
    stream, wordptr, backing = (oracle.GUEST + n for n in (0xE000, 0xE800, 0xD000))
    x22, x23, x24, x25, x29 = (oracle.GUEST + n for n in
                               (0xE100, 0xE200, 0xE300, 0xE400, 0xE500))
    word = control["word"]
    if control.get("scratch_alias"):
        x22 = backing + ((word >> 27) & 31) * 8
    _write_span(pages, stream, wordptr.to_bytes(8, "little"))
    # Deliberately different stream word proves that x21 is the opcode input.
    stream_word = control.get("stream_word", word)
    _write_span(pages, wordptr, stream_word.to_bytes(4, "little") +
                control["next_word"].to_bytes(4, "little"))
    values = [(0x1111222233334444 ^ i * 0x0101010101010101) & MASK64
              for i in range(32)]
    if control.get("zero_slots"):
        values = [0] * 32
    for i, value in enumerate(values):
        _write_span(pages, backing + i * 8, value.to_bytes(8, "little"))
    key = control.get("return_key", 0x33DC5)
    _write_span(pages, x29 - 8, key.to_bytes(8, "little"))
    if control.get("synthetic_table"):
        table = oracle.GUEST + 0xC800
        mask = (control["x5"] | 0x01010104) ^ control["x4"]
        table_pointer = (table - mask) & MASK64
        _write_span(pages, image + 0x3798D8, table_pointer.to_bytes(8, "little"))
        for i in range(64):
            target = image + 0x160000 + i * 4
            _write_span(pages, table + i * 8,
                        ((target + key) & MASK64).to_bytes(8, "little"))
    inputs = dict(image_base=image, stream_slot_address=stream, backing_address=backing,
                  x20=image + 0x379000, x22=x22, x23=x23, x24=x24, x25=x25,
                  x29=x29, x4=control["x4"], x5=control["x5"], word_register=word)
    return pages, prepare_or64_state(**inputs)


def native_case(library, image, pages, state):
    observed = {"entered": False, "writes": []}
    registers = {"x4": state.x4, "x5": state.x5, "x19": state.stream_slot_address,
                 "x20": state.x20, "x21": state.word_register, "x22": state.x22,
                 "x23": state.x23, "x24": state.x24, "x25": state.x25,
                 "x28": state.backing_address, "x29": state.x29}

    def observe(cpu, address):
        off = address - image
        if off == HANDLER_OFFSET and not observed["entered"]:
            observed["entered"] = True
            return
        if observed["entered"] and not HANDLER_OFFSET <= off < HANDLER_END:
            observed["target"] = address
            observed["regs"] = {name: cpu.reg_read(getattr(arm, "UC_ARM64_REG_" + name.upper()))
                                for name in REGISTER_NAMES}
            # Stop raises before oracle.native's normal-return memory export.
            # Read the live emulator now, after every handler store completed.
            observed["guest"] = bytes(cpu.mem_read(oracle.GUEST, oracle.GUEST_SIZE))
            raise Stop

    def write(cpu, address, width):
        observed["writes"].append((address, width))

    try:
        oracle.native(library, image, HANDLER_OFFSET, [], pages,
            extra_registers={getattr(arm, "UC_ARM64_REG_" + name.upper()): value
                             for name, value in registers.items()},
            instruction_observer=observe, memory_write_observer=write,
            instruction_limit=10000)
    except Stop:
        pass
    else:
        raise AssertionError("OR handler did not reach its indirect branch target")
    return observed, registers


def case(library, image, control):
    native_pages, state = control_pages(library, image, control)
    native, initial_registers = native_case(library, image, native_pages, state)
    model_pages, model_state = control_pages(library, image, control)
    result = apply_or64(model_pages, model_state)
    assert native["target"] == result["next_handler"], control["name"]
    assert oracle.flatten(model_pages) == native["guest"], control["name"]
    assert native["writes"] == result["writes"], (control["name"], native["writes"], result["writes"])
    expected = {**initial_registers, **result["register_updates"]}
    for name in REGISTER_NAMES:
        assert native["regs"][name] == expected[name], (control["name"], name)
    return {
        "image_base": hex(image), "case": control["name"],
        "dispatch_table_kind": "explicit_synthetic" if control.get("synthetic_table") else "relocated_ELF",
        "word": hex(result["word"]), "stream_word": hex(control.get("stream_word", result["word"])),
        "next_word": hex(result["next_word"]), "src_a": result["src_a"],
        "src_b": result["src_b"], "dst": result["dst"],
        "result": hex(result["result"]), "next_handler_offset": hex(result["next_handler_offset"]),
        "guest_bytes_compared": oracle.GUEST_SIZE, "native_write_count": len(native["writes"]),
        "registers_match": True, "full_guest_memory_match": True,
        "ordered_writes_match": True, "native_input_snapshot_used": False,
    }


def negative_cases(library, image, sample):
    pages, state = control_pages(library, image, sample)
    initial = {k: bytes(v) for k, v in pages.items()}
    bad = prepare_or64_state(**{**vars(state), "word_register": 0})
    try:
        apply_or64(pages, bad)
    except RefillUnsupported:
        pass
    else:
        raise AssertionError("wrong opcode accepted")
    assert all(bytes(pages[k]) == v for k, v in initial.items())
    try:
        prepare_or64_state(**{**vars(state), "word_register": 1 << 32})
    except RefillUnsupported:
        pass
    else:
        raise AssertionError("non-word x21 accepted")
    missing_table = prepare_or64_state(**{**vars(state), "x20": 0})
    try:
        apply_or64(pages, missing_table)
    except ValueError as error:
        assert "missing checkpoint page" in str(error)
    else:
        raise AssertionError("unmapped dispatch pointer accepted")
    assert all(bytes(pages[k]) == v for k, v in initial.items())
    return ["wrong_opcode_refused_without_writes", "non_word_x21_refused",
            "missing_dispatch_table_refused_without_partial_writes"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == oracle.LIBRARY_SHA256
    base = 17 | (44 << 6)
    sample = dict(name="ELF_sample", word=base | (16 << 12) | (7 << 22),
                  next_word=0x58F30FF4, x4=0xFF5F9EBBF5FE033C, x5=0xA061440A061440)
    controls = [sample]
    for name, a, b, dst, scratch in (
        ("x21_independent", 29, 1, 3, False),
        ("destination_alias_left", 2, 31, 2, False),
        ("destination_alias_right", 0, 31, 31, False),
        ("same_source_zero", 31, 31, 0, False),
        ("scratch_alias_right", 7, 3, 16, True),
    ):
        controls.append(dict(name=name, word=base | (dst << 12) | (19 << 17) | (a << 22) | (b << 27),
            next_word=0xFB68201A, x4=0x64000000, x5=0x123456789ABCDEF0,
            stream_word=0xCAFEBABE, synthetic_table=True, return_key=0x1122334455667788,
            scratch_alias=scratch, zero_slots=name == "same_source_zero"))
    rows = []
    for image in (0x122C0000, 0x775C205000):
        for control in controls:
            rows.append(case(args.library, image, control))
            print("or64", hex(image), control["name"], "PASS", flush=True)
    negatives = negative_cases(args.library, 0x122C0000, sample)
    report = {
        "schema": "vm9-request-or64-fresh-differential-v1", "evidence_date": "2026-10-07",
        "sample_sha256": oracle.LIBRARY_SHA256, "controls": len(rows), "cases": rows,
        "negative_cases": negatives, "handler_offset": "0x16a5a8", "branch_offset": "0x16a610",
        "operation": "VM op17/sub44 OR64", "handler_python_implementation_verified": True,
        "complete_python_medusa": False, "fresh_input_signer_output_verified": False,
        "current_online_header_matrix_verified": False, "no_jvm_rust_signer_complete": False,
        "limitations": [
            "This proves one OR64 handler and its indirect next-handler selection, not the next handler body.",
            "Ten controls use an explicitly generated dispatch table; two use the relocated ELF table.",
            "No URL/header/JNI conversion, JVM, server request or signature output is used.",
        ],
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("or64", len(rows), "fresh differentials and", len(negatives), "negative controls PASS")


if __name__ == "__main__":
    main()
