"""Record the native constructor and vtable provenance for the outer loader method.

This is a read-only ELF check.  It connects the loader-like method at
``+0x189eac`` to the relocated vtable slot at ``0x34db18`` and to the real
constructor path at ``+0x18ceb0``.  It also verifies the inner allocator and
the constructor's initialized field set.  It does not invent a path string,
execute the loader, or claim that the external runtime table has been found.
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


V_TABLE = 0x34DB08
V_SLOT = 0x34DB18
METHOD = 0x189EAC
PATH_WRITER_SLOT = 0x34DB48
PATH_WRITER = 0x188AC0
FIELD_CONSUMER_SLOT = 0x34DB50
FIELD_CONSUMER = 0x189CBC
CONSTRUCTOR = 0x18CEB0
ALLOC_CALLER = 0x18B9F0
ALLOCATOR = 0x32A1F0
LOADER_CALLSITE = 0x18A314
LOADER_HELPER = 0x184AD4
INNER_CONSTRUCTOR = 0x2481AC


def _decode(data: bytes, text_base: int, address: int) -> dict:
    offset = address - text_base
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    rows = list(md.disasm(data[offset : offset + 4], address, count=1))
    if len(rows) != 1:
        raise AssertionError(f"cannot decode {address:#x}")
    row = rows[0]
    return {"address": hex(address), "mnemonic": row.mnemonic, "operands": row.op_str}


def _bl_target(word: int, address: int) -> int | None:
    if word & 0xFC000000 != 0x94000000:
        return None
    immediate = word & 0x03FFFFFF
    if immediate & (1 << 25):
        immediate -= 1 << 26
    return address + (immediate << 2)


def _direct_callers(data: bytes, text_base: int, target: int) -> list[str]:
    callers: list[str] = []
    for offset in range(0, len(data) - 3, 4):
        address = text_base + offset
        word = struct.unpack_from("<I", data, offset)[0]
        if _bl_target(word, address) == target:
            callers.append(hex(address))
    return callers


def verify(library: Path) -> dict:
    with library.open("rb") as stream:
        elf = ELFFile(stream)
        text = elf.get_section_by_name(".text")
        data = text.data()
        text_base = text["sh_addr"]
        relocs = elf.get_section_by_name(".rela.dyn")
        vtable_relocation = None
        neighboring_relocations: list[dict] = []
        for relocation in relocs.iter_relocations():
            if relocation["r_offset"] == V_SLOT:
                vtable_relocation = {
                    "offset": hex(relocation["r_offset"]),
                    "type": relocation["r_info_type"],
                    "addend": hex(relocation["r_addend"]),
                    "symbol_index": relocation["r_info_sym"],
                }
            if V_TABLE <= relocation["r_offset"] < V_TABLE + 0x50:
                neighboring_relocations.append({
                    "offset": hex(relocation["r_offset"]),
                    "type": relocation["r_info_type"],
                    "addend": hex(relocation["r_addend"]),
                })

        if vtable_relocation is None:
            raise AssertionError("missing relocated vtable method slot")
        if vtable_relocation["type"] != 1027 or vtable_relocation["addend"] != hex(METHOD):
            raise AssertionError(f"unexpected vtable slot: {vtable_relocation}")
        path_writer_relocation = next(
            (row for row in neighboring_relocations if row["offset"] == hex(PATH_WRITER_SLOT)),
            None,
        )
        if path_writer_relocation is None or path_writer_relocation["type"] != 1027:
            raise AssertionError("missing relocated path-writer slot")
        if path_writer_relocation["addend"] != hex(PATH_WRITER):
            raise AssertionError(f"unexpected path-writer slot: {path_writer_relocation}")
        field_consumer_relocation = next(
            (row for row in neighboring_relocations if row["offset"] == hex(FIELD_CONSUMER_SLOT)),
            None,
        )
        if field_consumer_relocation is None or field_consumer_relocation["type"] != 1027:
            raise AssertionError("missing relocated field-consumer slot")
        if field_consumer_relocation["addend"] != hex(FIELD_CONSUMER):
            raise AssertionError(f"unexpected field-consumer slot: {field_consumer_relocation}")

        instructions = {
            hex(address): _decode(data, text_base, address)
            for address in (
                0x18B9F0,
                0x18B9FC,
                0x18BA00,
                0x18BA04,
                0x18CEB0,
                0x18CF10,
                0x18CF14,
                0x18CF20,
                0x18CF24,
                0x18CF28,
                0x18CF2C,
                0x18CF30,
                0x18CF34,
                0x18CF38,
                0x18CF48,
                0x18CF50,
                0x18CF54,
                0x18A30C,
                0x18A310,
                0x18A314,
                0x188AC0,
                0x189040,
                0x189054,
                0x189164,
                0x189168,
                0x18916C,
                0x189170,
                0x189174,
                0x189178,
                0x189184,
                0x189CBC,
                0x189CC4,
                0x189CC8,
                0x189CCC,
                0x189CD0,
                0x184AF4,
                0x184AFC,
                0x184B04,
                0x2481AC,
                0x2481CC,
                0x2481D0,
                0x2481D4,
                0x2481DC,
            )
        }

        expected = {
            ("0x18b9f0", "mov", "w0, #0xb8"),
            ("0x18b9fc", "mov", "x21, x0"),
            ("0x18ba00", "bl", "#0x18ceb0"),
            ("0x18ba04", "ldr", "x0, [x25, #0x30]"),
            ("0x18cf10", "adrp", "x8, #0x34d000"),
            ("0x18cf14", "add", "x0, x19, #0x10"),
            ("0x18cf20", "str", "x8, [x19]"),
            ("0x18cf24", "bl", "#0x18d4d8"),
            ("0x18cf28", "adrp", "x8, #0x34d000"),
            ("0x18cf2c", "add", "x0, x19, #0x30"),
            ("0x18cf30", "add", "x8, x8, #0xb08"),
            ("0x18cf34", "str", "x8, [x19]"),
            ("0x18cf38", "bl", "#0x2481ac"),
            ("0x18cf48", "stp", "xzr, xzr, [x19, #0x48]"),
            ("0x18cf50", "add", "x21, x19, #0x68"),
            ("0x18cf54", "str", "x1, [x19, #0x60]"),
            ("0x18a30c", "ldr", "x8, [x23, #0x20]"),
            ("0x18a310", "ldr", "x0, [x8, #0x40]"),
            ("0x18a314", "bl", "#0x184ad4"),
            ("0x188ac0", "stp", "x29, x30, [sp, #-0x60]!"),
            ("0x189040", "ldur", "x8, [x29, #-0xe0]"),
            ("0x189054", "stur", "x8, [x29, #-0x20]"),
            ("0x189164", "ldur", "x8, [x29, #-0x20]"),
            ("0x189168", "ldr", "x8, [x8, #0x30]"),
            ("0x18916c", "ldur", "x9, [x29, #-0x28]"),
            ("0x189170", "ldr", "x9, [x9]"),
            ("0x189174", "ldur", "x10, [x29, #-0x20]"),
            ("0x189178", "add", "x8, x8, x9"),
            ("0x189184", "str", "x8, [x10, #0x40]"),
            ("0x189cbc", "stp", "x29, x30, [sp, #-0x10]!"),
            ("0x189cc4", "add", "x8, x0, #0x10"),
            ("0x189cc8", "ldr", "x9, [x0, #0x40]"),
            ("0x189ccc", "mov", "x0, x8"),
            ("0x189cd0", "blr", "x9"),
            ("0x184af4", "mov", "w1, #2"),
            ("0x184afc", "mov", "x20, x0"),
            ("0x184b04", "bl", "#0x348060"),
            ("0x2481cc", "str", "x9, [x0]"),
            ("0x2481d0", "str", "d0, [x0, #8]"),
            ("0x2481d4", "mov", "w0, #8"),
            ("0x2481dc", "str", "x0, [x19, #0x10]"),
        }
        actual = {
            (address, row["mnemonic"], row["operands"])
            for address, row in instructions.items()
        }
        if not expected <= actual:
            raise AssertionError(f"constructor facts changed: {sorted(expected - actual)}")

        constructor_callers = _direct_callers(data, text_base, CONSTRUCTOR)
        if constructor_callers != [hex(ALLOC_CALLER + 0x10)]:
            raise AssertionError(f"unexpected direct constructor callers: {constructor_callers}")

        return {
            "schema": "vm9-loader-vtable-constructor-fresh-20261026-v3",
            "evidence_date": "2026-10-26",
            "sample_sha256": hashlib.sha256(library.read_bytes()).hexdigest(),
            "vtable": {
                "base": hex(V_TABLE),
                "method_slot": hex(V_SLOT),
                "method_addend": hex(METHOD),
                "path_writer_slot": hex(PATH_WRITER_SLOT),
                "path_writer_addend": hex(PATH_WRITER),
                "field_consumer_slot": hex(FIELD_CONSUMER_SLOT),
                "field_consumer_addend": hex(FIELD_CONSUMER),
                "slot_relocation": vtable_relocation,
                "neighboring_relocations": sorted(neighboring_relocations, key=lambda row: int(row["offset"], 16)),
            },
            "constructor_path": {
                "allocation_callsite": hex(ALLOC_CALLER),
                "allocation_size": hex(0xB8),
                "allocator": hex(ALLOCATOR),
                "constructor": hex(CONSTRUCTOR),
                "direct_constructor_callers": constructor_callers,
                "constructor_vtable_sequence": [
                    "temporary base vtable 0x34db68 -> +0x18d4d8",
                    "final object vtable 0x34db08 -> +0x2481ac inner member constructor",
                ],
                "initialized_fields_observed": ["+0x0 vtable", "+0x8", "+0x10", "+0x48", "+0x58", "+0x60", "+0x68"],
                "path_field_offset": hex(0x40),
                "path_field_written_by_constructor": False,
                "path_field_written_by_same_vtable_method": True,
                "path_field_has_alternate_consumer": True,
                "alternate_consumer_dataflow": (
                    "+0x189cbc reads [object+0x40] as a callable and invokes it "
                    "with object+0x10"
                ),
                "path_writer_dataflow": (
                    "initial x0 -> [x29-0xe0] -> [x29-0x20] -> x10; "
                    "x8 = *(initial x0 + 0x30) + *([x29-0x28]); "
                    "str x8,[x10 + 0x40]"
                ),
            },
            "loader_method": {
                "entry": hex(METHOD),
                "callsite": hex(LOADER_CALLSITE),
                "helper": hex(LOADER_HELPER),
                "path_dataflow": "initial x0 -> [x29-0xd8] -> [x23+0x20] -> x0=[x0+0x40]",
                "path_field_offset": hex(0x40),
                "runtime_path_observed": False,
            },
            "interpretation": (
                "The relocated 0x34db18 slot is a real vtable entry for +0x189eac. "
                "The native code also contains a real 0xb8-byte allocation and "
                "+0x18ceb0 constructor that installs the same final vtable and "
                "initializes an inner +0x30 member. The constructor does not write "
                "the +0x40 path field later read by +0x18a310. The same vtable "
                "also exposes +0x188ac0 at slot +0x40, and that "
                "method writes the +0x40 field after deriving a value from the "
                "initial object's +0x30 member and a secondary input. This closes "
                "the native writer provenance, but +0x189cbc also consumes +0x40 "
                "as a callable. The field's state/role is therefore not uniquely "
                "identified as a path string; invocation and runtime path remain open."
            ),
            "conclusions": {
                "vtable_method_provenance_closed": True,
                "constructor_provenance_closed": True,
                "path_field_constructor_provenance_closed": False,
                "path_field_vtable_writer_provenance_closed": True,
                "path_field_writer_invocation_verified": False,
                "path_field_role_uniquely_identified": False,
                "runtime_table_owner_recovered": False,
                "runtime_table_content_reconstructed": False,
                "whole_request_native_success": False,
                "fresh_standalone_signer_verified": False,
                "online_header_acceptance_verified": False,
            },
            "limitations": [
                "This is static ELF evidence; it does not execute the constructor or Java loader.",
                "The method is reached through a relocated vtable slot, so no direct BL caller is expected.",
                "No path string, external runtime dispatch page, handler, callback vtable, or signer output is inferred.",
            ],
            "instructions": list(instructions.values()),
        }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = verify(args.library)
    if report["sample_sha256"] != oracle.LIBRARY_SHA256:
        raise SystemExit("unexpected native sample")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    print(
        "loader vtable constructor provenance",
        report["conclusions"]["vtable_method_provenance_closed"],
        report["conclusions"]["path_field_constructor_provenance_closed"],
        flush=True,
    )


if __name__ == "__main__":
    main()
