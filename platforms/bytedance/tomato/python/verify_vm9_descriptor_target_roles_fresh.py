"""Fresh differential proof for the corrected descriptor target entries.

The active +0x991c0 writer emits image-relative +0x32a444 and +0x32a4fc.
This verifier invokes those two native functions directly on fresh guest pages
and compares their memory effects and return object pointer with the bounded
Python shared-reader model.  It does not execute the descriptor trampoline or
claim that either function is the complete current Medusa callback chain.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from elftools.elf.elffile import ELFFile

import vm9_objects as objects
from vm9_allocator import _read_span, _write_span
from verify_vm9_signer_objects import GUEST, LIBRARY_SHA256, fresh_pages, native

TARGETS = {
    "acquire": 0x32A444,
    "release": 0x32A4FC,
}
OLD_TARGETS = {"acquire": 0x31E444, "release": 0x31E4FC}
BASES = (0x122C0000, 0x775C205000)
COUNTS = {"acquire": (0, 1, 7, 0x7FFFFFFE),
          "release": (1, 2, 7, 0x7FFFFFFE)}


def relocation_occurrences(library: Path):
    with library.open("rb") as stream:
        elf = ELFFile(stream)
        relsec = elf.get_section_by_name(".rela.dyn")
        rows = sorted(
            ({"relocation_offset": relocation["r_offset"],
              "addend": relocation["r_addend"],
              "type": relocation["r_info_type"]}
             for relocation in relsec.iter_relocations()),
            key=lambda row: row["relocation_offset"],
        )
    active = [row for row in rows if row["addend"] in TARGETS.values()]
    superseded = [row for row in rows if row["addend"] in OLD_TARGETS.values()]
    assert len(active) == 10
    assert not superseded
    by_offset = {row["relocation_offset"]: row for row in rows}
    regions = []
    for row in active:
        if row["addend"] != TARGETS["acquire"]:
            continue
        pair = [by_offset.get(row["relocation_offset"] + 8),
                by_offset.get(row["relocation_offset"] + 16)]
        assert pair[0] and pair[0]["addend"] == 0x32A40C
        assert pair[1] and pair[1]["addend"] == TARGETS["release"]
        context = []
        for delta in (-16, -8, 0, 8, 16, 24):
            item = by_offset.get(row["relocation_offset"] + delta)
            if item is not None:
                context.append({"relocation_offset": hex(item["relocation_offset"]),
                                "addend": hex(item["addend"]),
                                "type": item["type"]})
        regions.append({"active_pair_offset": hex(row["relocation_offset"]),
                        "context": context})
    assert len(regions) == 5
    return {
        "active": [{"relocation_offset": hex(row["relocation_offset"]),
                     "addend": hex(row["addend"]), "type": row["type"]}
                    for row in active],
        "superseded": [],
        "active_pair_regions": regions,
    }


def disassemble_entries(library: Path):
    with library.open("rb") as stream:
        elf = ELFFile(stream)
        section = next(section for section in elf.iter_sections()
                       if section["sh_addr"] <= TARGETS["acquire"] < section["sh_addr"] + section["sh_size"])
        rows = {}
        for label, start, width in (
            ("acquire", TARGETS["acquire"], 12),
            ("release", TARGETS["release"], 16),
        ):
            stream.seek(section["sh_offset"] + start - section["sh_addr"])
            code = stream.read(width)
            rows[label] = [
                {"address": hex(row.address), "mnemonic": row.mnemonic, "op_str": row.op_str}
                for row in Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN).disasm(code, start)
            ]
    assert [row["mnemonic"] for row in rows["acquire"][:3]] == ["paciasp", "sub", "stp"]
    assert [row["mnemonic"] for row in rows["release"][:4]] == ["paciasp", "stp", "str", "mov"]
    return rows


def one_case(library: Path, libc: Path, base: int, kind: str, count: int):
    pages = fresh_pages()
    target = GUEST + 0x1000
    shared = 0x2000
    _write_span(pages, target, shared.to_bytes(2, "little"))
    _write_span(pages, target + 0x88, count.to_bytes(4, "little"))
    observed = {}
    native_result, expected_memory, allocations, ledger = native(
        library, base, TARGETS[kind], [target], pages, libc=libc,
        observed_memory=observed, real_mutexes=True,
    )
    model_pages = {index: bytearray(data) for index, data in pages.items()}
    model = (objects.acquire_uncontended_shared_reader if kind == "acquire"
             else objects.release_uncontended_shared_reader)
    model_count = model(model_pages, mutex_address=target)
    actual_memory = _read_span(model_pages, GUEST, 0xA000)
    if actual_memory != expected_memory:
        first = next(i for i, (left, right) in enumerate(zip(actual_memory, expected_memory)) if left != right)
        raise AssertionError(f"{kind} {count:#x}: memory mismatch at guest+{first:#x}")
    if native_result != 0:
        raise AssertionError(f"{kind} {count:#x}: native return {native_result:#x} != normal mutex status 0")
    if model_count != count + (1 if kind == "acquire" else -1):
        raise AssertionError(f"{kind} {count:#x}: model count mismatch")
    actual_count = int.from_bytes(_read_span(model_pages, target + 0x88, 4), "little")
    assert actual_count == model_count
    assert [item[0] for item in ledger] == ["pthread_mutex_lock", "pthread_mutex_unlock"]
    assert allocations == []
    return {
        "image_base": hex(base),
        "kind": kind,
        "native_offset": hex(TARGETS[kind]),
        "old_offset_not_executed": hex(OLD_TARGETS[kind]),
        "initial_count": hex(count),
        "final_count": hex(actual_count),
        "native_return": hex(native_result),
        "object_address": hex(target),
        "memory_match": True,
        "return_status_zero": True,
        "normal_mutex_pair": ledger,
        "allocations": 0,
        "fresh_memory": True,
        "native_input_snapshot_used": False,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--library", type=Path, required=True)
    ap.add_argument("--libc", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == LIBRARY_SHA256
    cases = [one_case(args.library, args.libc, base, kind, count)
             for base in BASES for kind in ("acquire", "release") for count in COUNTS[kind]]
    report = {
        "evidence_id": "vm9_descriptor_target_roles_fresh_20261006",
        "schema": "vm9-descriptor-target-roles-fresh-v1",
        "status": "corrected_targets_direct_fresh_differential",
        "native_library_sha256": hashlib.sha256(args.library.read_bytes()).hexdigest(),
        "libc_sha256": hashlib.sha256(args.libc.read_bytes()).hexdigest(),
        "active_image_relative_targets": {label: hex(offset) for label, offset in TARGETS.items()},
        "superseded_image_relative_targets": {label: hex(offset) for label, offset in OLD_TARGETS.items()},
        "native_entry_disassembly": disassemble_entries(args.library),
        "relative_relocation_occurrences": relocation_occurrences(args.library),
        "controls": len(cases),
        "cases": cases,
        "all_memory_matches": all(case["memory_match"] for case in cases),
        "all_return_statuses_zero": all(case["return_status_zero"] for case in cases),
        "active_relocation_count": 10,
        "superseded_relocation_count": 0,
        "all_mutex_pairs_match": all(case["normal_mutex_pair"] == [
            ["pthread_mutex_lock", GUEST + 0x1000],
            ["pthread_mutex_unlock", GUEST + 0x1000],
        ] for case in cases),
        "descriptor_trampoline_executed": False,
        "callback_object_parameterized": False,
        "fresh_medusa_output_verified": False,
        "complete_python_medusa": False,
        "limitations": [
            "The direct calls prove the corrected shared-reader entries only.",
            "The +0x2584ac trampoline, packed callback object and continuation chain remain unexecuted.",
            "No online signer, Rust download chain or product capability is implied.",
        ],
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("descriptor target roles fresh differential PASS", len(cases))


if __name__ == "__main__":
    main()

