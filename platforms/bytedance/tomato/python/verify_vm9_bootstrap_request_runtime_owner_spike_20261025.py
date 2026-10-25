"""Same-CPU JNI/bootstrap -> request runtime-table creator spike.

This is a read-only feasibility probe.  It executes the existing complete
init_array/JNI bootstrap driver, keeps the returned Unicorn CPU, overlays only
fresh request fixture inputs, and continues through the real ``+0x27dd04`` /
``+0x2830c4`` request path.  The unresolved external runtime pages contain a
canary solely for observing reads and writes; the canary is never used as a
dispatch table and this probe cannot produce signer output.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

from elftools.elf.elffile import ELFFile
from unicorn import UC_HOOK_CODE
from unicorn import arm64_const as arm

import verify_vm9_elf_constructor_sequence_20261011 as sequence
import verify_vm9_jni_complete_bootstrap_20261011 as bootstrap
import verify_vm9_request_dispatch_fresh_20261020 as dispatch
import verify_vm9_signer_objects as oracle


BASES = (0x122C0000, 0x775C205000)
TABLE_PAGE_OFFSET = 0x13BB000
TABLE_PAGE_COUNT = 2
CANARY = bytes([0xA5]) * 4096
LIBRARY_SHA256 = oracle.LIBRARY_SHA256
CREATOR_IMPORTS = ("mmap", "mprotect", "munmap", "calloc", "pthread_create")


def _imports(library: Path):
    with library.open("rb") as stream:
        elf = ELFFile(stream)
        dynamic = elf.get_section_by_name(".dynsym")
        relocs = elf.get_section_by_name(".rela.plt")
        return {
            0x347E70 + 0x20 + index * 0x10:
            dynamic.get_symbol(relocation["r_info_sym"]).name
            for index, relocation in enumerate(relocs.iter_relocations())
        }


def _overlay_request_fixture(cpu, pages):
    """Copy only explicit non-padding guest inputs into the bootstrap CPU."""
    for page, data in pages.items():
        address = page << 12
        if not 0x70000000 <= address < 0x70010000:
            continue
        raw = bytes(data)
        cursor = 0
        while cursor < len(raw):
            if raw[cursor] == 0xA5:
                cursor += 1
                continue
            end = cursor + 1
            while end < len(raw) and raw[end] != 0xA5:
                end += 1
            cpu.mem_write(address + cursor, raw[cursor:end])
            cursor = end


def run(library: Path, libc: Path, image: int):
    args = argparse.Namespace(library=library, libc=libc)
    profile = {} if image == BASES[0] else {
        "allocation_delta": 0xC00,
        "thread_id": 1,
        "padding": 0xFF,
        "stack_padding": 0x39,
    }
    bootstrap_stack = sequence.v.SP if image == BASES[0] else sequence.v.SP - 0xC80
    pages = bootstrap.fresh(args, image, profile, Python=True)
    table_start = image + TABLE_PAGE_OFFSET
    table_end = table_start + TABLE_PAGE_COUNT * 0x1000
    imports = _imports(library)
    events = []
    import_counts = Counter()
    original_native = oracle.native

    def record(kind, **fields):
        if len(events) < 2048:
            events.append(dict(kind=kind, **fields))

    def wrapped(*native_args, **kwargs):
        old_instruction = kwargs.get("instruction_observer")
        old_write = kwargs.get("memory_write_observer")
        old_read = kwargs.get("memory_read_observer")
        old_unmapped = kwargs.get("unmapped_observer")
        base = native_args[1]

        def instruction(cpu, address):
            offset = address - base
            if offset in imports:
                name = imports[offset]
                import_counts[name] += 1
            if offset in (0x27DD04, 0x2830C4, 0x168324,
                          0x16848C, 0x1684BC, 0x170308):
                record("instruction", pc=hex(offset))
            if old_instruction:
                old_instruction(cpu, address)

        def write(cpu, address, size):
            if table_start <= address < table_end:
                record("runtime_table_write", pc=hex(cpu.reg_read(arm.UC_ARM64_REG_PC) - base),
                       address=hex(address), size=size,
                       value=bytes(cpu.mem_read(address, size)).hex())
            if old_write:
                old_write(cpu, address, size)

        def read(cpu, address, size):
            if table_start <= address < table_end:
                record("runtime_table_read", pc=hex(cpu.reg_read(arm.UC_ARM64_REG_PC) - base),
                       address=hex(address), size=size,
                       value=bytes(cpu.mem_read(address, size)).hex())
            if old_read:
                old_read(cpu, address, size)

        def unmapped(cpu, access, address, size, value):
            record("unmapped", pc=hex(cpu.reg_read(arm.UC_ARM64_REG_PC) - base),
                   address=hex(address), size=size, value=hex(value))
            if old_unmapped:
                old_unmapped(cpu, access, address, size, value)

        kwargs["instruction_observer"] = instruction
        kwargs["memory_write_observer"] = write
        kwargs["memory_read_observer"] = read
        kwargs["unmapped_observer"] = unmapped
        return original_native(*native_args, **kwargs)

    oracle.native = wrapped
    try:
        cpu, service, _vm, _jni, _scopes = bootstrap.native(
            args, pages, image, profile, bootstrap_stack, 0)

        request_pages, request = dispatch.fixture(library, image, "callback_success")
        _overlay_request_fixture(cpu, request_pages)

        for page in range(TABLE_PAGE_COUNT):
            address = table_start + page * 0x1000
            cpu.mem_map(address, 0x1000)
            cpu.mem_write(address, CANARY)

        # The owner probe's real callback pair forces the request into the
        # native owning VM instead of a synthetic callback target.
        cpu.mem_write(dispatch.G + 0x2400,
                      (image + 0x2830C4).to_bytes(8, "little"))
        cpu.mem_write(dispatch.G + 0x2500, (0).to_bytes(8, "little"))

        cpu.reg_write(arm.UC_ARM64_REG_X0, request["receiver_address"])
        cpu.reg_write(arm.UC_ARM64_REG_X1, request["url_reference_address"])
        cpu.reg_write(arm.UC_ARM64_REG_X2, request["header_reference_address"])
        cpu.reg_write(arm.UC_ARM64_REG_X3, request["mode"])
        cpu.reg_write(arm.UC_ARM64_REG_X8, request["output_reference_address"])
        cpu.reg_write(arm.UC_ARM64_REG_SP, request["entry_stack_address"])
        cpu.reg_write(arm.UC_ARM64_REG_TPIDR_EL0, request["thread_pointer"])
        cpu.reg_write(arm.UC_ARM64_REG_X30, oracle.STOP)
        cpu.mem_write(request["thread_pointer"] + 0x28, CANARY[:8])

        def request_code(cpu, address, _size, _user):
            offset = address - image
            if offset in (0x27DD04, 0x2830C4, 0x168324,
                          0x16848C, 0x1684BC, 0x170308):
                record("request_instruction", pc=hex(offset))

        cpu.hook_add(UC_HOOK_CODE, request_code,
                     begin=image + 0x27DD04, end=image + 0x283500)

        outcome = "returned"
        error = None
        try:
            cpu.emu_start(image + 0x27DD04, oracle.STOP, count=2_000_000)
        except Exception as exc:  # first unresolved read is the expected stop
            outcome = "stopped"
            error = f"{type(exc).__name__}: {exc}"

        return {
            "image_base": hex(image),
            "bootstrap_stack": hex(bootstrap_stack),
            "bootstrap_native_completed": True,
            "bootstrap_JNI_return_asserted": True,
            "same_cpu_request_continuation": True,
            "outcome": outcome,
            "error": error,
            "runtime_table_addresses": [
                hex(image + 0x13BB8F0), hex(image + 0x13BBAF0),
                hex(image + 0x13BBCF0), hex(image + 0x13BBE18),
                hex(image + 0x13BB7F0),
            ],
            "runtime_table_canary_mapped": True,
            "runtime_table_reads": [e for e in events if e["kind"] == "runtime_table_read"],
            "runtime_table_writes": [e for e in events if e["kind"] == "runtime_table_write"],
            "unmapped_events": [e for e in events if e["kind"] == "unmapped"],
            "request_instructions": [e for e in events if e["kind"] == "request_instruction"],
            "import_counts": dict(sorted(import_counts.items())),
            "creator_import_counts": {
                name: import_counts.get(name, 0) for name in CREATOR_IMPORTS
            },
            "bootstrap_service_event_count": len(service.events),
            "synthetic_dispatch_table_used": False,
            "runtime_table_content_reconstructed": False,
            "whole_request_native_success": False,
            "fresh_signer_output_verified": False,
            "events": events,
        }
    finally:
        oracle.native = original_native


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--libc", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if hashlib.sha256(args.library.read_bytes()).hexdigest() != LIBRARY_SHA256:
        raise SystemExit("unexpected native sample")
    rows = [run(args.library, args.libc, image) for image in BASES]
    for row in rows:
        assert row["runtime_table_reads"] == []
        assert row["runtime_table_writes"] == []
        assert any(event["pc"] == "0x2830c4" for event in row["request_instructions"])
        assert row["creator_import_counts"]["mmap"] == 0
        assert row["creator_import_counts"]["mprotect"] == 0
        assert row["creator_import_counts"]["munmap"] == 0
        assert row["creator_import_counts"]["calloc"] == 0
    evidence = {
        "schema": "vm9-bootstrap-request-runtime-owner-spike-fresh-20261025-v1",
        "evidence_date": "2026-10-25",
        "sample_sha256": LIBRARY_SHA256,
        "matching_libc_sha256": hashlib.sha256(args.libc.read_bytes()).hexdigest(),
        "cases": rows,
        "same_unicorn_cpu_bootstrap_to_request_verified": True,
        "external_runtime_table_creator_found": False,
        "runtime_table_content_reconstructed": False,
        "synthetic_dispatch_table_used": False,
        "whole_request_native_success": False,
        "fresh_signer_output_verified": False,
        "limitations": [
            "The two external runtime pages are canary mapped only for observation.",
            "Both bases reach the real +0x2830c4 owning request VM on the same CPU.",
            "The first unresolved read is guest address 0xc before any external runtime-table read.",
            "No mmap/mprotect/munmap/calloc call or runtime-table write occurs in this composition.",
            "This does not identify the outer/runtime loader that owns the external table.",
            "No signer output, live JVM, physical ABI, or online acceptance is claimed.",
        ],
    }
    args.output.write_text(json.dumps(evidence, indent=2) + "\n",
                           encoding="utf-8", newline="\n")
    print("bootstrap -> request runtime owner spike", len(rows), "cases", flush=True)


if __name__ == "__main__":
    main()
