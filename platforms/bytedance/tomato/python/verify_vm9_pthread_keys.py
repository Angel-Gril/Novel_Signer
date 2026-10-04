"""Matching bionic pthread_key_create: fresh generation table and key output."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from elftools.elf.elffile import ELFFile

import vm9_allocator as model
from verify_vm9_signer_objects import GUEST, LIBRARY_SHA256, fresh_pages, image_pages, native
from verify_vm9_root_configuration import LIBC_BASE, LIBC_PTHREAD_GENERATION_OFFSET


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--libc", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == LIBRARY_SHA256
    with args.libc.open("rb") as stream:
        elf = ELFFile(stream)
        symbol = next(s for sec in elf.iter_sections() if sec["sh_type"] == "SHT_DYNSYM"
                      for s in sec.iter_symbols() if s.name == "pthread_key_create")
        entry = LIBC_BASE + symbol["st_value"]
    table = LIBC_BASE + LIBC_PTHREAD_GENERATION_OFFSET
    cases, negatives = [], []
    for base in (0x122C0000, 0x775C205000):
        for used in (0, 1, 2, 140, 141):
            for generation in (0, 2, 0xFFFFFFFFFFFFFFFE):
                pages = fresh_pages()
                pages.update(image_pages(args.libc, LIBC_BASE))
                target = GUEST + 0x1FFE
                for index in range(141):
                    value = 1 if index < used else generation
                    model._write_span(pages, table + index * 16,
                        value.to_bytes(8, "little") + (0x12340000 + index).to_bytes(8, "little"))
                observed = {(table, 141 * 16): None}
                destructor = 0x0123456789ABCDEF
                result, memory, allocations, _ = native(args.library, base, entry - base,
                    [target, destructor], pages, libc=args.libc, observed_memory=observed)
                actual = model.pthread_key_create(pages, key_address=target,
                    destructor=destructor, generation_table=table)
                assert actual == result == (11 if used == 141 else 0)
                assert model._read_span(pages, GUEST, 0xA000) == memory
                assert model._read_span(pages, table, 141 * 16) == observed[table, 141 * 16]
                assert not allocations
                cases.append({"image_base": hex(base), "used_entries": used,
                    "initial_free_generation": hex(generation), "result": actual,
                    "guest_bytes_match": True, "generation_table_match": True,
                    "whole_generation_table_bytes": 141 * 16, "allocations": 0})
        for alias in (0, 8, 16):
            pages = fresh_pages()
            pages.update(image_pages(args.libc, LIBC_BASE))
            model._write_span(pages, table, bytes(141 * 16))
            target = table + alias
            observed = {(table, 141 * 16): None}
            result, memory, _, _ = native(args.library, base, entry - base,
                [target, 0x1111222233334444], pages, libc=args.libc, observed_memory=observed)
            actual = model.pthread_key_create(pages, key_address=target,
                destructor=0x1111222233334444, generation_table=table)
            assert actual == result == 0
            assert model._read_span(pages, GUEST, 0xA000) == memory
            assert model._read_span(pages, table, 141 * 16) == observed[table, 141 * 16]
            cases.append({"image_base": hex(base), "output_alias_offset": alias,
                "guest_bytes_match": True, "generation_table_match": True, "result": actual})

    for label, key, destructor, gen, missing in (
        ("unaligned_table", GUEST + 0x1000, 0, table + 1, None),
        ("negative_destructor", GUEST + 0x1000, -1, table, None),
        ("missing_table_page", GUEST + 0x1000, 0, table, table >> 12),
        ("missing_output_page", GUEST + 0x1000, 0, table, (GUEST + 0x1000) >> 12),
    ):
        pages = fresh_pages()
        pages.update(image_pages(args.libc, LIBC_BASE))
        model._write_span(pages, table, bytes(141 * 16))
        if missing is not None:
            del pages[missing]
        before = {p: bytes(b) for p, b in pages.items()}
        try:
            model.pthread_key_create(pages, key_address=key, destructor=destructor, generation_table=gen)
        except (model.RefillUnsupported, ValueError):
            assert before == {p: bytes(b) for p, b in pages.items()}
            negatives.append({"case": label, "rejected": True, "page_rollback": True})
        else:
            raise AssertionError(label + " accepted")
    report = {"library_sha256": LIBRARY_SHA256, "libc_sha256": hashlib.sha256(args.libc.read_bytes()).hexdigest(),
        "fresh_memory": True, "captured_pages_used": False, "jvm_used": False,
        "differential_cases": len(cases), "negative_cases": len(negatives), "cases": cases, "negatives": negatives,
        "generation_table_offset": hex(LIBC_PTHREAD_GENERATION_OFFSET), "key_entries": 141,
        "serialized_state_only": True, "host_keys_created": False, "destructors_executed": False,
        "complete_python_pthread_boot": False, "complete_python_medusa": False}
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"differential_cases": len(cases), "negative_cases": len(negatives)}))


if __name__ == "__main__":
    main()
