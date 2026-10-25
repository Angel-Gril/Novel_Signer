"""Statically inventory the unresolved outer runtime-table owner boundary.

The current request VM reads five relative-relocation slots whose addends point
outside the main ELF PT_LOAD pages.  This probe does not execute or reconstruct
that table.  It records every direct PLT callsite for loader-like imports and
searches the whole main text for stores that can target the five slots.  The
result is evidence for choosing the next runtime/loader boundary, not a table
or signer implementation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
from elftools.elf.elffile import ELFFile

import verify_vm9_signer_objects as oracle


BASES = (0x122C0000, 0x775C205000)
SLOT_OFFSETS = (0x3798D8, 0x3798E0, 0x3798E8, 0x3798F0, 0x3798F8)
TABLE_ADDENDS = (0x13BB8F0, 0x13BBAF0, 0x13BBCF0, 0x13BBE18, 0x13BB7F0)
TABLE_PAGE_OFFSET = 0x13BB000
LOADER_IMPORTS = {
    "pthread_create", "pthread_join", "pthread_key_create", "pthread_setspecific",
    "pthread_getspecific", "dlopen", "dlsym", "dlclose", "dl_iterate_phdr",
    "mmap", "mprotect", "munmap", "calloc", "syscall",
}
KNOWN_LOADER_CALLERS = (0x184AD4, 0x18A314)


def _signed(value: int, bits: int) -> int:
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def _adrp_target(word: int, address: int) -> tuple[int, int] | None:
    if word & 0x9F000000 != 0x90000000:
        return None
    rd = word & 0x1F
    immlo = (word >> 29) & 3
    immhi = (word >> 5) & 0x7FFFF
    immediate = _signed((immhi << 2) | immlo, 21) << 12
    return rd, (address & ~0xFFF) + immediate


def _add_target(word: int, registers: dict[int, int]) -> tuple[int, int] | None:
    # ADD (immediate), 64-bit, with a tracked base register.
    if word & 0xFF000000 not in (0x91000000, 0x91400000):
        return None
    rd = word & 0x1F
    rn = (word >> 5) & 0x1F
    immediate = ((word >> 10) & 0xFFF) << (12 if (word >> 22) & 1 else 0)
    if rn not in registers:
        return None
    return rd, registers[rn] + immediate


def _store_target(word: int, registers: dict[int, int]) -> tuple[int, int, int] | None:
    # STR (unsigned immediate), 64/32/16/8-bit.  Width is retained only for
    # auditability; all five target slots are eight-byte objects.
    if word & 0x3B000000 not in (0x39000000, 0x3D000000):
        return None
    rn = (word >> 5) & 0x1F
    if rn not in registers:
        return None
    rt = word & 0x1F
    scale = (word >> 30) & 3
    immediate = ((word >> 10) & 0xFFF) << scale
    return rt, registers[rn] + immediate, 1 << scale


def _local_slot_store(words: list[int], index: int, address: int) -> tuple[int, int] | None:
    """Return (slot, width) only for a short ADRP/(ADD)/STR sequence."""
    rn = (words[index] >> 5) & 0x1F
    store = _store_target(words[index], {rn: 0})
    if store is None:
        return None
    _, _, width = store
    if index >= 1:
        direct = _adrp_target(words[index - 1], address - 4)
        if direct is not None and direct[0] == rn:
            target = direct[1] + (((words[index] >> 10) & 0xFFF) << ((words[index] >> 30) & 3))
            if target in SLOT_OFFSETS:
                return target, width
    if index >= 2:
        add_address = address - 4
        add_word = words[index - 1]
        add_source = (add_word >> 5) & 0x1F
        add_register = add_word & 0x1F
        adrp = _adrp_target(words[index - 2], address - 8)
        add = _add_target(add_word, {add_source: adrp[1]} if adrp is not None else {})
        if (adrp is not None and adrp[0] == add_source and add is not None
                and add[0] == rn):
            target = add[1] + (((words[index] >> 10) & 0xFFF) << ((words[index] >> 30) & 3))
            if target in SLOT_OFFSETS:
                return target, width
    return None


def _plt_imports(elf: ELFFile) -> dict[int, str]:
    dynamic = elf.get_section_by_name(".dynsym")
    relocs = elf.get_section_by_name(".rela.plt")
    # This sample uses the fixed 0x347e70 PLT veneer range.  Derive the first
    # veneer from the conventional AArch64 PLT layout rather than trusting a
    # captured process address.
    plt = elf.get_section_by_name(".plt")
    first = plt["sh_addr"] + 0x20 if plt is not None else 0x347E90
    return {
        first + index * 0x10: dynamic.get_symbol(relocation["r_info_sym"]).name
        for index, relocation in enumerate(relocs.iter_relocations())
    }


def _bl_target(word: int, address: int) -> int | None:
    if word & 0xFC000000 != 0x94000000:
        return None
    return address + (_signed(word & 0x03FFFFFF, 26) << 2)


def scan(library: Path) -> dict:
    with library.open("rb") as stream:
        elf = ELFFile(stream)
        text = elf.get_section_by_name(".text")
        data = text.data()
        text_base = text["sh_addr"]
        imports = _plt_imports(elf)

        # Relocation proof: all five slots are R_AARCH64_RELATIVE with addends
        # outside the main PT_LOAD image.
        dynsym = elf.get_section_by_name(".dynsym")
        relative = {}
        for relocation in elf.get_section_by_name(".rela.dyn").iter_relocations():
            if relocation["r_offset"] in SLOT_OFFSETS:
                relative[hex(relocation["r_offset"])] = {
                    "type": relocation["r_info_type"],
                    "addend": hex(relocation["r_addend"]),
                    "symbol_index": relocation["r_info_sym"],
                    "symbol": dynsym.get_symbol(relocation["r_info_sym"]).name,
                }

        import_calls = []
        slot_writes = []
        words = struct.iter_unpack("<I", data[: len(data) - len(data) % 4])
        word_list = [word for (word,) in words]
        for index, word in enumerate(word_list):
            address = text_base + index * 4
            target = _bl_target(word, address)
            if target in imports and imports[target] in LOADER_IMPORTS:
                import_calls.append({
                    "pc": hex(address), "target": hex(target), "import": imports[target],
                })
            # Prove a slot store only when the base register is formed by an
            # adjacent ADRP/(optional ADD) sequence.  Keeping this window
            # local avoids treating a stale register value from an obfuscated
            # data island as a write to the global relocation slot.
            local_store = _local_slot_store(word_list, index, address)
            if local_store is not None:
                slot, width = local_store
                slot_writes.append({"pc": hex(address), "slot": hex(slot), "width": width})

        # Keep only deterministic, human-reviewable import inventory.  The
        # static text contains obfuscated data islands, so a direct BL hit is
        # recorded as a candidate callsite and not as proof that bootstrap runs
        # it.  The same caveat is why slot_writes is a conservative result.
        loader_calls = [row for row in import_calls if row["pc"] in {
            "0x184504", "0x184b04", "0x184cac", "0x184cc4", "0x184d18",
            "0x184d7c", "0x184d88", "0x184cd0", "0x18a6d8", "0x18a990", "0x18d390",
            "0x1dba34", "0x2029f4", "0x204790",
        }]
        init_array = elf.get_section_by_name(".init_array")
        init_relocations = [
            {"slot": hex(relocation["r_offset"]), "type": relocation["r_info_type"],
             "addend": hex(relocation["r_addend"])}
            for relocation in elf.get_section_by_name(".rela.dyn").iter_relocations()
            if init_array["sh_addr"] <= relocation["r_offset"] < init_array["sh_addr"] + init_array["sh_size"]
        ]
        return {
            "schema": "vm9-outer-runtime-owner-static-scan-fresh-20261025-v1",
            "evidence_date": "2026-10-25",
            "sample_sha256": hashlib.sha256(library.read_bytes()).hexdigest(),
            "text": {"address": hex(text_base), "size": len(data)},
            "init_array": {
                "address": hex(init_array["sh_addr"]),
                "size": init_array["sh_size"],
                "relative_relocations": init_relocations,
            },
            "relative_slots": relative,
            "slot_offsets": [hex(value) for value in SLOT_OFFSETS],
            "table_addends": [hex(value) for value in TABLE_ADDENDS],
            "external_table_page_offset": hex(TABLE_PAGE_OFFSET),
            "loader_import_callsites": loader_calls,
            "all_loader_import_callsite_count": len(import_calls),
            "all_loader_import_callsites": import_calls,
            "slot_store_candidates": slot_writes,
            "slot_store_candidate_count": len(slot_writes),
            "known_outer_loader_candidate": {
                "entry_offset": hex(KNOWN_LOADER_CALLERS[0]),
                "caller_offset": hex(KNOWN_LOADER_CALLERS[1]),
                "observed_static_sequence": [
                    "+0x18a314 -> +0x184ad4",
                    "+0x184ad4 -> dlopen(path, RTLD_NOW)",
                    "+0x184cac -> munmap",
                    "+0x184cd0 -> mmap",
                    "+0x184d18 -> munmap",
                ],
                "table_slot_store_observed": False,
                "executed_in_same_cpu_bootstrap_request_spike": False,
                "interpretation": "loader-like outer candidate only; no runtime-table ownership proven",
            },
            "runtime_table_owner_recovered": False,
            "runtime_table_content_reconstructed": False,
            "whole_request_native_success": False,
            "fresh_signer_output_verified": False,
            "limitations": [
                "The text has obfuscated code/data islands; BL and store hits are static candidates.",
                "The static scan does not execute the outer loader or inspect a live Android linker.",
                "No dispatch handler addresses or table bytes are inferred from relocation addends.",
            ],
        }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = scan(args.library)
    if report["sample_sha256"] != oracle.LIBRARY_SHA256:
        raise SystemExit("unexpected native sample")
    assert set(report["relative_slots"]) == {hex(value) for value in SLOT_OFFSETS}
    assert report["slot_store_candidate_count"] == 0
    assert any(row["pc"] == "0x184b04" and row["import"] == "dlopen"
               for row in report["all_loader_import_callsites"])
    assert any(row["pc"] == "0x184cd0" and row["import"] == "mmap"
               for row in report["all_loader_import_callsites"])
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
    print("outer runtime owner static scan", report["all_loader_import_callsite_count"], "loader callsites", flush=True)


if __name__ == "__main__":
    main()
