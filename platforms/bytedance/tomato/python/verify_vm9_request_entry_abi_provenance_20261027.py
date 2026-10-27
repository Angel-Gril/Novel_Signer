"""Verify the two request-entry ABIs that precede the formatter split.

The normal Java facade enters ``+0x2830c4`` from the native caller at
``+0x27e6a8``.  Its ``x3`` is the native header-vector pointer loaded from
``*(receiver + 0x20) + 0x08`` and the JNI wrapper packs it into the VM argument
array.  The independent output-reference continuation also enters
``+0x2830c4`` but supplies ``x3=0x101``.  This verifier keeps that distinction
explicit and does not interpret either value as a signer status.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
from elftools.elf.elffile import ELFFile


ACTUAL_EVIDENCE = Path(__file__).parents[1] / "evidence" / (
    "vm9_native_outer_facade_actual_child_20261027.json"
)
REFERENCE_EVIDENCE = Path(__file__).parents[1] / "evidence" / (
    "vm9_request_output_reference_20261027_rerun.json"
)
BASES = (0x122C0000, 0x775C205000)


STATIC_EXPECTED = {
    0x27E660: ("ldr", "x8, [sp, #0x38]"),
    0x27E664: ("add", "x0, sp, #0x78"),
    0x27E668: ("ldr", "x1, [sp, #8]"),
    0x27E694: ("ldr", "w2, [sp, #0x1c]"),
    0x27E69C: ("ldr", "x8, [x8, #0x20]"),
    0x27E6A0: ("ldr", "x3, [x8, #8]"),
    0x27E470: ("ldr", "x3, [x8, #8]"),
    0x27E6A8: ("blr", "x9"),
    0x2830EC: ("stp", "x8, x0, [sp, #8]"),
    0x283100: ("str", "w2, [sp, #0x20]"),
    0x28310C: ("str", "x1, [sp, #0x18]"),
    0x283114: ("stp", "x3, x9, [sp, #0x28]"),
    0x283130: ("bl", "#0x168324"),
    0x168324: ("stp", "x29, x30, [sp, #-0x60]!"),
    0x168464: ("stp", "x3, x0, [x16, #-0xe8]"),
}


def _static_evidence(library: Path) -> dict:
    with library.open("rb") as stream:
        elf = ELFFile(stream)
        text = elf.get_section_by_name(".text")
        data, start = text.data(), text["sh_addr"]
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    rows = []
    for offset, expected in STATIC_EXPECTED.items():
        instruction = next(md.disasm(data[offset - start:offset - start + 4], offset))
        actual = (instruction.mnemonic, instruction.op_str)
        if actual != expected:
            raise AssertionError((hex(offset), expected, actual))
        rows.append({
            "offset": hex(offset),
            "bytes": instruction.bytes.hex(),
            "mnemonic": instruction.mnemonic,
            "operands": instruction.op_str,
        })
    return {
        "source": "pinned ELF .text",
        "instructions": rows,
        "facade_x3_source": "*(receiver+0x20)+0x08",
        "wrapper_pack_offset": "0x20",
        "vm_direct_x3_role": "constant code/data pointer; user x3 is read from packed argument array",
    }


def _actual_case(case: dict, image: int) -> dict:
    events = case["request_abi_facade_events"]
    source = next(row for row in events if row["pc_offset"] == "0x27e6a4")
    wrapper = next(row for row in events if row["pc_offset"] == "0x283130")
    vm = next(
        row for row in events
        if row["pc_offset"] == "0x168324"
        and row.get("vm_argument_base") == wrapper["vm_argument_base"]
    )
    vector_words = source["native_header_vector_words"]
    wrapper_words = wrapper["vm_argument_words"]
    vm_words = vm["vm_argument_words"]
    if source["request_target"] != hex(image + 0x2830C4):
        raise AssertionError(("facade request target", source["request_target"]))
    if source["x2"] != "0x138":
        raise AssertionError(("facade mode", source["x2"]))
    if vector_words[1] != source["x3"]:
        raise AssertionError(("header vector field", vector_words, source["x3"]))
    if wrapper_words[3] != source["x2"] or wrapper_words[4] != source["x3"]:
        raise AssertionError(("wrapper pack", wrapper_words, source["x2"], source["x3"]))
    if wrapper["packed_x3_argument_value"] != source["x3"]:
        raise AssertionError(("wrapper x3", wrapper["packed_x3_argument_value"], source["x3"]))
    if vm_words[4] != source["x3"] or not vm["direct_vm_x3_is_packed_constant"]:
        raise AssertionError(("VM x3 indirection", vm_words, vm["direct_vm_x3_value"]))
    return {
        "image_base": hex(image),
        "facade_caller_offset": "0x27e6a8",
        "facade_request_target": source["request_target"],
        "facade_mode_x2": source["x2"],
        "facade_native_header_vector_object": source["native_header_vector_object"],
        "facade_native_header_vector_words": vector_words,
        "facade_x3_header_pointer": source["x3"],
        "wrapper_argument_base": wrapper["vm_argument_base"],
        "wrapper_argument_words": wrapper_words,
        "wrapper_packed_x3": wrapper["packed_x3_argument_value"],
        "vm_argument_words": vm_words,
        "vm_direct_x3": vm["direct_vm_x3_value"],
        "vm_direct_x3_is_packed_constant": vm["direct_vm_x3_is_packed_constant"],
        "source_and_pack_match": True,
    }


def _reference_case(case: dict, image: int) -> dict:
    entry = case["request_entry"]
    if entry["x2"] != "0x138" or entry["x3"] != "0x101":
        raise AssertionError(("output-reference entry", entry))
    transition = next(
        row for row in case["x3_transition_trace"]
        if row["pc_offset"] == "0x27e474"
    )
    if transition["x3"] != "0x101":
        raise AssertionError(("output-reference x3 producer", transition))
    if transition.get("source_value") != "0x101":
        raise AssertionError(("output-reference x3 source", transition))
    return {
        "image_base": hex(image),
        "entry_offset": "0x2830c4",
        "x0": entry["x0"],
        "x1": entry["x1"],
        "x2": entry["x2"],
        "x3": entry["x3"],
        "x8": entry["x8"],
        "x3_producer_offset": "0x27e470",
        "x3_producer_source_address": transition.get("source_address"),
        "x3_producer_source_value": transition.get("source_value"),
        "x3_transition_trace": case["x3_transition_trace"],
        "semantic_note": "independent output-reference continuation supplies x3=0x101 at the same VM wrapper entry",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--actual-evidence", type=Path, default=ACTUAL_EVIDENCE)
    parser.add_argument("--reference-evidence", type=Path, default=REFERENCE_EVIDENCE)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    actual = json.loads(args.actual_evidence.read_text(encoding="utf-8"))
    reference = json.loads(args.reference_evidence.read_text(encoding="utf-8"))
    digest = hashlib.sha256(args.library.read_bytes()).hexdigest()
    actual_cases = {
        int(case["image_base"], 16): case for case in actual["cases"]
    }
    reference_cases = {
        int(case["image_base"], 16): case for case in reference["cases"]
    }
    rows = []
    for image in BASES:
        rows.append({
            "actual_facade": _actual_case(actual_cases[image], image),
            "independent_output_reference": _reference_case(reference_cases[image], image),
        })
    report = {
        "schema": "vm9-request-entry-abi-provenance-20261027-v1",
        "evidence_date": "2026-10-27",
        "sample_sha256": digest,
        "static": _static_evidence(args.library),
        "cases": rows,
        "same_wrapper_entry_observed": True,
        "facade_x3_is_native_header_pointer": True,
        "output_reference_x3_is_0x101": True,
        "output_reference_x3_producer_offset": "0x27e470",
        "output_reference_x3_producer_observed_pc": "0x27e474",
        "output_reference_x3_source": "[0x70002400+0x08] = 0x101",
        "x3_roles_are_equivalent": False,
        "whole_request_native_differential_verified": False,
        "fresh_standalone_signer_verified": False,
        "online_header_acceptance_verified": False,
        "interpretation": (
            "The normal facade's +0x27e6a8 caller loads x3 from the native header "
            "vector object at receiver+0x20, then +0x2830c4 saves that value at "
            "argument-array offset +0x20 before entering +0x168324.  The VM's "
            "direct x3 register is a separate image-relative constant, while its "
            "user argument remains in the packed array.  The independent "
            "output-reference continuation first loads x3 from [0x70002400+0x08] "
            "at +0x27e470 (observed on the following PC +0x27e474), yielding 0x101 "
            "before reaching the same +0x2830c4 wrapper.  Its x3 is therefore a "
            "different input role.  This explains why "
            "the -5 guard path cannot be selected by treating 0x101 as the facade "
            "header-vector pointer; it does not close signer semantics."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
    print("request entry ABI provenance", len(rows), "cases", flush=True)


if __name__ == "__main__":
    main()
