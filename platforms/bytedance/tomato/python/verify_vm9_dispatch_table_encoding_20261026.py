"""Resolve encoded VM dispatch pointers against fresh ELF/native evidence.

The five relocation addends are biased pointers, not external allocations.
This observer reuses the bootstrap/request driver, records the real table
loads and indirect branches, and repeats with its external canary pages absent.
It never changes a relocation, table entry, callback or native instruction.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
from elftools.elf.elffile import ELFFile
from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn import arm64_const as arm

import verify_vm9_bootstrap_request_memcpy_continuation_20261026 as continuation
import verify_vm9_signer_objects as oracle
from vm9_allocator import _write_span


MASK = (1 << 64) - 1
HANDLER_BIAS = 0x33DC5
SLOTS = (0x3798D8, 0x3798E0, 0x3798E8, 0x3798F0, 0x3798F8)
TABLES = (0x34CF68, 0x34D168, 0x34D368, 0x34D490, 0x34CE68)
# Contiguous relocated handler entries in the pinned ELF. The two subopcode
# tables contain 37 entries; their six-bit selectors do not imply 64 valid rows.
COUNTS = (64, 64, 37, 37, 32)


def decode_constants(image: int) -> tuple[int, int]:
    """Unsigned AArch64 arithmetic at +1683f4..+1684a4, from pinned opcodes."""
    anchor = image + 0x168324
    mixed = (((0x00A060400A021040 | (~anchor & MASK))
              & 0x00A061440A061440)
             + (anchor & 0x0000010400040400)) & MASK
    correction = ((mixed | 0x01010104) ^ 0xFF5F9EBBF5FE033C) & MASK
    return mixed, correction


def static_evidence(library: Path) -> dict:
    with library.open("rb") as stream:
        elf = ELFFile(stream)
        relocations = {row["r_offset"]: row
                       for row in elf.get_section_by_name(".rela.dyn").iter_relocations()}
        text = elf.get_section_by_name(".text")
        data, text_base = text.data(), text["sh_addr"]
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        facts = []
        expected = {
            0x168344: ("adrp", "x6, #0x168000"),
            0x16834C: ("add", "x6, x6, #0x324"),
            0x168358: ("mov", "w8, #0x3dc5"),
            0x168360: ("movk", "w8, #3, lsl #16"),
            0x168378: ("stur", "x8, [x29, #-8]"),
            0x1683F4: ("mov", "x12, #0x1040"),
            0x1683F8: ("mov", "x11, #0x400"),
            0x168400: ("movk", "x12, #0xa02, lsl #16"),
            0x168404: ("movk", "x12, #0x6040, lsl #32"),
            0x168408: ("movk", "x11, #4, lsl #16"),
            0x16840C: ("movk", "x12, #0xa0, lsl #48"),
            0x16843C: ("mov", "x13, #0x1440"),
            0x168440: ("movk", "x13, #0xa06, lsl #16"),
            0x16844C: ("movk", "x13, #0x6144, lsl #32"),
            0x168450: ("movk", "x11, #0x104, lsl #32"),
            0x168454: ("orn", "x12, x12, x6"),
            0x168458: ("movk", "x13, #0xa0, lsl #48"),
            0x168468: ("and", "x11, x6, x11"),
            0x16846C: ("and", "x12, x12, x13"),
            0x168470: ("mov", "x4, #0x33c"),
            0x16847C: ("add", "x5, x12, x11"),
            0x168480: ("mov", "w11, #0x104"),
            0x168484: ("movk", "x4, #0xf5fe, lsl #16"),
            0x16848C: ("ldr", "x10, [x20, #0x8d8]"),
            0x168490: ("movk", "w11, #0x101, lsl #16"),
            0x168494: ("movk", "x4, #0x9ebb, lsl #32"),
            0x168498: ("orr", "x11, x5, x11"),
            0x16849C: ("movk", "x4, #0xff5f, lsl #48"),
            0x1684A4: ("eor", "x11, x11, x4"),
            0x1684AC: ("add", "x10, x10, x11"),
            0x1684BC: ("ldr", "x9, [x10, x9, lsl #3]"),
            0x1684D4: ("sub", "x9, x9, x10"),
            0x1684F0: ("br", "x9"),
        }
        for address, pair in expected.items():
            ins = next(md.disasm(data[address - text_base:address - text_base + 4], address))
            assert (ins.mnemonic, ins.op_str) == pair, hex(address)
            facts.append({"pc_offset": hex(address), "mnemonic": ins.mnemonic,
                          "operands": ins.op_str})
        rows = []
        for slot, table, count in zip(SLOTS, TABLES, COUNTS):
            relocation = relocations[slot]
            assert relocation["r_info_type"] == 1027
            entries = []
            for index in range(count):
                address = table + index * 8
                entry = relocations[address]
                assert entry["r_info_type"] == 1027
                target = entry["r_addend"] - HANDLER_BIAS
                assert 0x168324 <= target < 0x17319C and target % 4 == 0
                entries.append({"index": index, "relocation_offset": hex(address),
                                "addend": hex(entry["r_addend"]),
                                "decoded_handler_offset": hex(target)})
            section = next(s for s in elf.iter_sections()
                           if s["sh_addr"] <= table < s["sh_addr"] + s["sh_size"])
            load = next(s for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"
                        and s["p_vaddr"] <= table
                        and table + count * 8 <= s["p_vaddr"] + s["p_filesz"])
            assert section.name == ".data.rel.ro"
            file_offset = load["p_offset"] + table - load["p_vaddr"]
            stream.seek(file_offset)
            raw = stream.read(count * 8)
            assert len(raw) == count * 8
            for image in continuation.BASES:
                _, correction = decode_constants(image)
                assert (image + relocation["r_addend"] + correction) & MASK == image + table
            rows.append({"slot_offset": hex(slot),
                         "encoded_pointer_addend": hex(relocation["r_addend"]),
                         "decoded_table_offset": hex(table), "section": section.name,
                         "file_offset": hex(file_offset), "entry_count": count,
                         "file_bytes_sha256": hashlib.sha256(raw).hexdigest(),
                         "entries": entries})
        return {"instruction_facts": facts, "tables": rows,
                "handler_bias": hex(HANDLER_BIAS),
                "decoded_entry_count": sum(COUNTS)}


def run(library: Path, libc: Path, image: int, canary: bool) -> dict:
    original_native = continuation.bootstrap.native
    original_count = continuation.TABLE_PAGE_COUNT
    expected_pages = oracle.image_pages(library, image)
    events, corrections, slot_reads, writes = [], [], [], []
    holder = {}
    pending = None
    branch_target = None

    def wrapped_native(*args, **kwargs):
        nonlocal pending, branch_target
        cpu, *rest = original_native(*args, **kwargs)
        holder["cpu"] = cpu

        def code(c, address, _size, _user):
            nonlocal pending, branch_target
            if branch_target is not None:
                assert address == branch_target, (hex(address), hex(branch_target))
                pending["branch_destination_observed"] = True
                pending = branch_target = None
            if address == image + 0x1684AC:
                mixed, correction = decode_constants(image)
                observed = c.reg_read(arm.UC_ARM64_REG_X11)
                assert c.reg_read(arm.UC_ARM64_REG_X5) == mixed
                assert observed == correction
                encoded = c.reg_read(arm.UC_ARM64_REG_X10)
                assert (encoded + correction) & MASK == image + TABLES[0]
                corrections.append({"mixed_x5": hex(mixed), "correction_x11": hex(observed),
                                    "encoded_x10": hex(encoded),
                                    "decoded_table_address": hex((encoded + correction) & MASK)})
            if pending is None:
                return
            word = int.from_bytes(c.mem_read(address, 4), "little")
            if word & 0xFFFFFC1F == 0xD61F0000:  # BR Xn
                index = (word >> 5) & 31
                target = c.reg_read(getattr(arm, f"UC_ARM64_REG_X{index}"))
                assert target == int(pending["decoded_handler_address"], 16)
                pending["branch_pc_offset"] = hex(address - image)
                pending["branch_register"] = f"x{index}"
                branch_target = target

        def read(c, _access, address, size, _value, _user):
            nonlocal pending
            if image + SLOTS[0] <= address < image + SLOTS[-1] + 8:
                slot_reads.append(hex(address - image))
            for table, count in zip(TABLES, COUNTS):
                if not image + table <= address < image + table + count * 8:
                    continue
                assert pending is None, "new table read before previous branch"
                assert size == 8 and (address - image - table) % 8 == 0
                raw = bytes(c.mem_read(address, size))
                offset = address & 4095
                assert raw == bytes(expected_pages[address >> 12][offset:offset + size])
                frame = c.reg_read(arm.UC_ARM64_REG_X29)
                bias = int.from_bytes(c.mem_read(frame - 8, 8), "little")
                assert bias == HANDLER_BIAS
                target = (int.from_bytes(raw, "little") - bias) & MASK
                assert image + 0x168324 <= target < image + 0x17319C and target % 4 == 0
                pending = {"load_pc_offset": hex(c.reg_read(arm.UC_ARM64_REG_PC) - image),
                           "table_offset": hex(table), "index": (address - image - table) // 8,
                           "loaded_word": hex(int.from_bytes(raw, "little")),
                           "live_frame_bias": hex(bias), "matches_fresh_ELF_relocations": True,
                           "decoded_handler_address": hex(target),
                           "decoded_handler_offset": hex(target - image),
                           "branch_destination_observed": False}
                events.append(pending)
                return

        def write(c, _access, address, size, _value, _user):
            if any(address < image + slot + 8 and image + slot < address + size for slot in SLOTS):
                writes.append({"pc_offset": hex(c.reg_read(arm.UC_ARM64_REG_PC) - image),
                               "address": hex(address), "size": size})
            if any(address < image + table + count * 8 and image + table < address + size
                   for table, count in zip(TABLES, COUNTS)):
                raise AssertionError("native dispatch-table modification")

        cpu.hook_add(UC_HOOK_CODE, code, begin=image + 0x168324, end=image + 0x17319C)
        cpu.hook_add(UC_HOOK_MEM_READ, read)
        cpu.hook_add(UC_HOOK_MEM_WRITE, write)
        # Bootstrap already executed some dispatch blocks. Invalidate Unicorn's
        # translations so the newly added read observer also covers those
        # blocks on continuation. This alters no guest code or memory.
        cpu.ctl_flush_tb()
        return (cpu, *rest)

    continuation.bootstrap.native = wrapped_native
    # This disables only the parent probe's observation canary mapping. No
    # execution state is filled or substituted; all five tables stay ELF input.
    continuation.TABLE_PAGE_COUNT = original_count if canary else 0
    try:
        result = continuation.run(library, libc, image)
    finally:
        continuation.bootstrap.native = original_native
        continuation.TABLE_PAGE_COUNT = original_count
    assert result["request_reached_oracle_stop"] and result["unmapped_event_count"] == 0
    assert pending is None and branch_target is None
    assert events and all(row["branch_destination_observed"] for row in events)
    assert writes == [] and corrections
    cpu = holder["cpu"]
    ext_start = image + continuation.TABLE_PAGE_OFFSET
    ext_end = ext_start + original_count * 4096
    regions = list(cpu.mem_regions())
    mapped = any(start < ext_end and ext_start <= end for start, end, _ in regions)
    assert mapped == canary
    digest = hashlib.sha256()
    page_count = 0
    for start, end, _ in sorted(regions):
        for page in range(start, end + 1, 4096):
            if ext_start <= page < ext_end:
                continue
            digest.update(page.to_bytes(8, "little"))
            digest.update(bytes(cpu.mem_read(page, 4096)))
            page_count += 1
    return {"image_base": hex(image), "external_canary_pages_mapped": canary,
            "continuation": result, "corrections": corrections,
            "relocation_slot_read_counts": dict(sorted(Counter(slot_reads).items())),
            "relocation_slot_writes": writes, "dispatch_load_count": len(events),
            "table_load_counts": dict(sorted(Counter(row["table_offset"] for row in events).items())),
            "all_loads_match_fresh_ELF_relocations": True,
            "all_decoded_branches_observed": True,
            "physical_page_count_excluding_canary": page_count,
            "physical_pages_sha256_excluding_canary": digest.hexdigest(),
            "dispatch_events": events}


def selector_controls(library: Path, image: int, static: dict) -> dict:
    """Execute each table's native selector, stopping before the chosen handler.

    These are fresh component inputs, separate from the complete continuation.
    The tables and their biased handler words are loaded only from the ELF.
    """
    stream, cursor, frame = oracle.GUEST + 0xA100, oracle.GUEST + 0xA200, oracle.GUEST + 0xA300
    pages = oracle.fresh_pages()
    _write_span(pages, cursor, stream.to_bytes(8, "little"))
    _write_span(pages, stream, bytes(4))
    _write_span(pages, frame - 8, HANDLER_BIAS.to_bytes(8, "little"))
    mixed, _ = decode_constants(image)
    registers = {arm.UC_ARM64_REG_X19: cursor, arm.UC_ARM64_REG_X29: frame,
                 arm.UC_ARM64_REG_X20: image + 0x379000,
                 arm.UC_ARM64_REG_X5: mixed, arm.UC_ARM64_REG_X4: 0xFF5F9EBBF5FE033C,
                 arm.UC_ARM64_REG_X10: stream - 4}
    holder = {}

    def observe(cpu, _address):
        holder["cpu"] = cpu

    first = static["tables"][0]["entries"][0]
    oracle.native(library, image, 0x16B9CC, [], pages, extra_registers=registers,
                  stop_offset=int(first["decoded_handler_offset"], 16),
                  instruction_observer=observe, instruction_limit=64)
    cpu = holder["cpu"]
    selectors = (0x16B9CC, 0x16855C, 0x16BA04, 0x16C368, 0x16CF78)
    rows = []
    for table_index, (selector, table) in enumerate(zip(selectors, static["tables"])):
        for entry in table["entries"]:
            index = entry["index"]
            word = index if table_index == 0 else index << (22 if table_index == 4 else 6)
            cpu.mem_write(stream, word.to_bytes(4, "little"))
            cpu.mem_write(cursor, stream.to_bytes(8, "little"))
            for register, value in registers.items():
                cpu.reg_write(register, value)
            expected = image + int(entry["decoded_handler_offset"], 16)
            cpu.emu_start(image + selector, expected, count=64)
            assert cpu.reg_read(arm.UC_ARM64_REG_PC) == expected
            assert cpu.reg_read(arm.UC_ARM64_REG_X8) == expected
            rows.append({"table_offset": table["decoded_table_offset"], "index": index,
                         "selector_pc_offset": hex(selector), "input_word": hex(word),
                         "native_handler_offset": hex(expected - image),
                         "matches_ELF_decoded_target": True})
    assert len(rows) == 234
    return {"image_base": hex(image), "fresh_component_input": True,
            "native_handler_body_executed": False, "native_selector_controls": len(rows),
            "controls": rows}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--libc", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == oracle.LIBRARY_SHA256
    static = static_evidence(args.library)
    selectors = [selector_controls(args.library, image, static) for image in continuation.BASES]
    cases, controls = [], []
    for image in continuation.BASES:
        mapped = run(args.library, args.libc, image, True)
        absent = run(args.library, args.libc, image, False)
        assert mapped["dispatch_events"] == absent["dispatch_events"]
        assert mapped["physical_pages_sha256_excluding_canary"] == absent["physical_pages_sha256_excluding_canary"]
        assert mapped["continuation"] == absent["continuation"]
        controls.append({"image_base": hex(image), "dispatch_events_equal": True,
                         "continuation_results_equal": True,
                         "all_noncanary_physical_pages_equal": True})
        cases.extend((mapped, absent))
        print("encoded dispatch tables", hex(image), mapped["dispatch_load_count"],
              "loads; no-canary control equal", flush=True)
    report = {"schema": "vm9-dispatch-table-encoding-fresh-20261026-v1",
              "sample_sha256": oracle.LIBRARY_SHA256, "evidence_date": "2026-10-26",
              "matching_libc_sha256": hashlib.sha256(args.libc.read_bytes()).hexdigest(),
              "static": static, "cases": cases, "canary_absence_controls": controls,
              "selector_boundary_controls": selectors,
              "native_selector_control_count": sum(row["native_selector_controls"] for row in selectors),
              "continuation_read_observer_translation_cache_flushed": True,
              "observation_only": True, "native_snapshot_input": False,
              "dispatch_table_bytes_source": "pinned ELF PT_LOAD and R_AARCH64_RELATIVE relocations",
              "encoded_dispatch_pointer_provenance_closed": True,
              "external_dispatch_mapping_required_for_this_continuation": False,
              "synthetic_dispatch_table_used": False, "synthetic_callback_vtable_used": False,
              "whole_request_native_differential_verified": False,
              "fresh_standalone_signer_verified": False, "online_header_acceptance_verified": False,
              "interpretation": "The five out-of-image relocation addends are encoded pointers. "
                  "Native arithmetic corrects them to file-backed .data.rel.ro tables; each loaded "
                  "relocated word is decoded by subtracting the live frame bias before BR. "
                  "No separate runtime writer or external mapping is needed for these five tables "
                  "in this continuation. This supersedes the earlier missing-external-owner hypothesis.",
              "limitations": ["Synthetic request/JNI/OS/import providers remain those of the parent probe.",
                              "The continuation visits tables 0 and 1; all-five selector controls stop before handler bodies.",
                              "The native return remains a continuation, not whole-request differential or signing."]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
