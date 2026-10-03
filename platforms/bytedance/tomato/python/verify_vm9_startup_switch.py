"""Verify the A/B global and gate against real bytecode and native controls.

No captured memory pages, URL, device state, JVM or native execution is used.
The optional private library is mandatory for the generic VM differential.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

import vm9_callbacks as callbacks
from vm9_allocator import RefillUnsupported


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--library", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    library = args.library.resolve()
    digest = hashlib.sha256(library.read_bytes()).hexdigest()
    if digest != "712384bd0e310fded0ae9b6441c2a264dd356dfaf1ef42d2ebc3c790fdd9269c":
        raise ValueError("native library does not match the measured build")
    os.environ["TOMATO_LIBMETASEC"] = str(library)
    import vm_full

    expected_words = [0x00401028, 0x04401035, 0x0843002D]
    for index, expected in enumerate(expected_words):
        assert int.from_bytes(vm_full.SO[0x70B9C + 4*index:0x70BA0 + 4*index], "little") == expected

    # Published native controls supply the expected branch outcomes. The
    # additional signed boundaries are compared with the existing VM's actual
    # three instructions, rather than a second copy of the bit-mask model.
    controls = [(0, True), (2, True), (34, False), (1791023800000, True),
                (1791023801000, False), (1791023999535, False),
                (-1, False), (-(1 << 63), True), ((1 << 63)-1, False)]
    results = []
    mem = vm_full.Mem()
    for image_base in (0x122C0000, 0x775C205000):
        address = image_base + 0x3D1578
        for value, expected_taken in controls:
            pages = {address >> 12: bytearray(b"\xa5" * 0x1000)}
            before = bytes(pages[address >> 12])
            assert callbacks.initialize_ab_switch(pages, image_base=image_base, ab_switch=value) == address
            outcome = callbacks.evaluate_ab_switch_gate(pages, image_base=image_base)
            assert outcome.branch_taken == expected_taken
            position = address & 0xFFF
            page = bytes(pages[address >> 12])
            assert page[:position] == before[:position] and page[position+8:] == before[position+8:]

            pointer = 0x70001000
            mem.wr(pointer, value.to_bytes(8, "little", signed=True))
            vm = vm_full.VM(mem, 0x706C0, 0, 0, 0, 0, 0, maxsteps=3)
            vm.pc = vm_full.B + 0x70B9C
            vm.R[0], vm.R[1] = 0, pointer
            try:
                vm.run()
            except RuntimeError as error:
                if not str(error).startswith("step limit @") or len(vm.ops) != 3:
                    raise
            else:
                raise AssertionError("generic VM did not stop at the three-instruction bound")
            assert vm.pc - vm_full.B == outcome.next_bytecode_offset
            results.append({"image_base": hex(image_base), "ab_switch": value,
                "branch_taken": outcome.branch_taken,
                "next_bytecode_offset": hex(outcome.next_bytecode_offset),
                "outside_global_unchanged": True, "generic_vm_matches": True})

    negative = []
    for value in (-(1 << 63)-1, 1 << 63):
        pages = {(0x122C0000+0x3D1578) >> 12: bytearray(0x1000)}
        before = {key: bytes(page) for key, page in pages.items()}
        try:
            callbacks.initialize_ab_switch(pages, image_base=0x122C0000, ab_switch=value)
        except RefillUnsupported:
            assert before == {key: bytes(page) for key, page in pages.items()}
        else:
            raise AssertionError("out-of-range Java long accepted")
        negative.append({"case": "long_underflow" if value < 0 else "long_overflow", "unchanged": True})
    try:
        callbacks.initialize_ab_switch({}, image_base=0x122C0000)
    except ValueError:
        negative.append({"case": "unmapped_global", "unchanged": True})
    else:
        raise AssertionError("unmapped global accepted")

    result = {"evidence_id": "vm9_startup_switch_python_20261003",
        "native_library_sha256": digest, "differential_cases": results,
        "negative_cases": negative, "fresh_pages": True,
        "captured_memory_required": False, "native_execution_required": False,
        "jvm_required": False, "complete_signer_initialization": False,
        "independent_current_medusa": False}
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"differential_cases": len(results), "negative_cases": len(negative),
        "complete_signer_initialization": False}))


if __name__ == "__main__":
    main()
