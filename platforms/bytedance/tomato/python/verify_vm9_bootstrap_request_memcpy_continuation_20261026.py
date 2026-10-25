"""Continue the request VM through the first real callback import.

The ordinary request fixture starts from a fresh image and therefore leaves the
catalog's lazy string caches cold.  This probe keeps the real bootstrap CPU,
overlays only the explicit request objects (including the native two-word URL
reference), and enters ``+0x27dd04``.  External runtime pages are canary mapped
only for observation.  The callback target is the ELF ``memcpy`` PLT, so this
probe supplies only its ordinary byte-copy ABI and returns through x30.  No
callback vtable, runtime dispatch page, or signer output is synthesized.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

from elftools.elf.elffile import ELFFile
from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_UNMAPPED, UC_HOOK_MEM_WRITE
from unicorn import arm64_const as arm

import verify_vm9_elf_constructor_sequence_20261011 as sequence
import verify_vm9_jni_complete_bootstrap_20261011 as bootstrap
import verify_vm9_jni_cold_once_fresh_20261008 as cold
import verify_vm9_request_dispatch_fresh_20261020 as dispatch
import verify_vm9_signer_objects as oracle
from vm9_allocator import _write_span


BASES = (0x122C0000, 0x775C205000)
TABLE_PAGE_OFFSET = 0x13BB000
TABLE_PAGE_COUNT = 2
CANARY = bytes([0xA5]) * 4096
URL = (
    b"https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/detail/v1/"
    b"?aid=1967&book_id=7373660003258862617"
)
URL_POINTER = dispatch.G + 0x1D00
REFCOUNT = dispatch.G + 0x1D80
VM_HANDLERS = (0x1692FC, 0x16DB74, 0x16E254, 0x16E41C,
               0x16F974, 0x17030C, 0x171268)
CALLBACK_TRAMPOLINE = (0x2858A8, 0x2858AC, 0x2858B0, 0x2858B4, 0x2858B8)
IMPORT_NAMES = {
    0x347F20: "memset", 0x347F40: "strlen", 0x347F60: "memcpy",
    0x347F70: "vsnprintf", 0x347FA0: "free", 0x347FD0: "malloc",
    0x347FE0: "memcmp", 0x348000: "pthread_create", 0x348320: "realloc",
    0x348410: "memmove", 0x348450: "clock_gettime", 0x3484B0: "strtol",
    0x348590: "pthread_cond_signal", 0x3485A0: "pthread_cond_broadcast",
    0x3482F0: "memchr",
    0x347FB0: "__strlen_chk",
}


def _request_fixture(library: Path, image: int):
    pages, request = dispatch.fixture(library, image, "callback_success")
    _write_span(pages, URL_POINTER, URL + b"\0")
    _write_span(pages, REFCOUNT, (1).to_bytes(4, "little"))
    _write_span(pages, dispatch.URL, URL_POINTER.to_bytes(8, "little"))
    _write_span(pages, dispatch.URL + 8, REFCOUNT.to_bytes(8, "little"))
    return pages, request


def _overlay_request_fixture(cpu, pages):
    """Overlay only guest request inputs; preserve bootstrapped image globals."""
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


def _restore_bootstrapped_jni_pages(cpu):
    """Keep request overlays from replacing the already-used JavaVM/JNI table."""
    def word(address, value):
        cpu.mem_write(address, value.to_bytes(8, "little"))

    word(cold.acquisition.VM, cold.acquisition.TABLE)
    word(cold.ENV, dispatch.G + 0x6000)
    word(cold.INNER_ENV, dispatch.G + 0x6000)
    for index, slot in enumerate(cold.initialization.SLOTS):
        word(dispatch.G + 0x6000 + slot, dispatch.G + 0xF210 + index * 0x10)
    for index, slot in enumerate(cold.EXTRA):
        word(dispatch.G + 0x6000 + slot, dispatch.G + 0xF400 + index * 0x10)
    for slot, fn in ((0x20, cold.acquisition.ATTACH),
                     (0x28, cold.acquisition.DETACH),
                     (0x30, cold.acquisition.GET)):
        word(cold.acquisition.TABLE + slot, fn)


def _runtime_pages(image: int):
    return {((image + TABLE_PAGE_OFFSET + index * 0x1000) >> 12): CANARY
            for index in range(TABLE_PAGE_COUNT)}


def run(library: Path, libc: Path, image: int) -> dict:
    profile = {} if image == BASES[0] else {
        "allocation_delta": 0xC00,
        "thread_id": 1,
        "padding": 0xFF,
        "stack_padding": 0x39,
    }
    bootstrap_stack = sequence.v.SP if image == BASES[0] else sequence.v.SP - 0xC80
    args = argparse.Namespace(library=library, libc=libc)
    pages = bootstrap.fresh(args, image, profile, Python=True)
    cpu, service, _vm, _jni, _scopes = bootstrap.native(
        args, pages, image, profile, bootstrap_stack, 0)
    with libc.open("rb") as stream:
        libc_elf = ELFFile(stream)
        libc_exports = {
            symbol.name: sequence.LIBC_BASE + symbol["st_value"]
            for symbol in libc_elf.get_section_by_name(".dynsym").iter_symbols()
            if symbol["st_shndx"] != "SHN_UNDEF" and symbol["st_value"]
        }

    request_pages, request = _request_fixture(library, image)
    _overlay_request_fixture(cpu, request_pages)
    _restore_bootstrapped_jni_pages(cpu)
    flag_range = image + 0x3E2C80
    flags_before = bytes(cpu.mem_read(flag_range, 0x40)).hex()

    table_start = image + TABLE_PAGE_OFFSET
    table_end = table_start + TABLE_PAGE_COUNT * 0x1000
    for page in range(TABLE_PAGE_COUNT):
        address = table_start + page * 0x1000
        cpu.mem_map(address, 0x1000)
        cpu.mem_write(address, CANARY)

    # The pair is the actual request VM owner boundary used by the previous
    # owner probe.  Its callback field remains native data produced by the VM.
    cpu.mem_write(dispatch.G + 0x2400,
                  (image + 0x2830C4).to_bytes(8, "little"))
    cpu.mem_write(dispatch.G + 0x2500, bytes(0x200))
    cpu.reg_write(arm.UC_ARM64_REG_X0, request["receiver_address"])
    cpu.reg_write(arm.UC_ARM64_REG_X1, request["url_reference_address"])
    cpu.reg_write(arm.UC_ARM64_REG_X2, request["header_reference_address"])
    cpu.reg_write(arm.UC_ARM64_REG_X3, request["mode"])
    cpu.reg_write(arm.UC_ARM64_REG_X8, request["output_reference_address"])
    cpu.reg_write(arm.UC_ARM64_REG_SP, request["entry_stack_address"])
    cpu.reg_write(arm.UC_ARM64_REG_TPIDR_EL0, request["thread_pointer"])
    cpu.reg_write(arm.UC_ARM64_REG_X30, oracle.STOP)
    cpu.mem_write(request["thread_pointer"] + 0x28, CANARY[:8])

    events = []
    handler_counts = Counter()
    callback_trace = []
    import_trace = []
    tail_trace = []
    runtime_reads = []
    runtime_writes = []
    flag_reads = []
    flag_writes = []
    unmapped = []
    instruction_count = 0

    def code_hook(c, address, _size, _user):
        nonlocal instruction_count
        instruction_count += 1
        if len(tail_trace) >= 256:
            tail_trace.pop(0)
        tail_trace.append({
            "pc_offset": hex(address - image),
            "x0": hex(c.reg_read(arm.UC_ARM64_REG_X0)),
            "x1": hex(c.reg_read(arm.UC_ARM64_REG_X1)),
            "x2": hex(c.reg_read(arm.UC_ARM64_REG_X2)),
            "x3": hex(c.reg_read(arm.UC_ARM64_REG_X3)),
            "x30": hex(c.reg_read(arm.UC_ARM64_REG_X30)),
        })
        offset = address - image
        if offset in VM_HANDLERS:
            handler_counts[hex(offset)] += 1
        if offset in CALLBACK_TRAMPOLINE:
            row = {
                "pc_offset": hex(offset),
                "x0": hex(c.reg_read(arm.UC_ARM64_REG_X0)),
                "x1": hex(c.reg_read(arm.UC_ARM64_REG_X1)),
                "x2": hex(c.reg_read(arm.UC_ARM64_REG_X2)),
                "x3": hex(c.reg_read(arm.UC_ARM64_REG_X3)),
                "x8": hex(c.reg_read(arm.UC_ARM64_REG_X8)),
                "x30": hex(c.reg_read(arm.UC_ARM64_REG_X30)),
            }
            object_address = c.reg_read(arm.UC_ARM64_REG_X0)
            try:
                row["object_bytes"] = bytes(c.mem_read(object_address, 0x30)).hex()
            except Exception:
                row["object_bytes"] = None
            callback_trace.append(row)

    def import_hook(c, address, _size, _user):
        if address == cold.acquisition.GET:
            row = {
                "pc_offset": hex(address - image),
                "name": "JavaVM.GetEnv",
                "x0": hex(c.reg_read(arm.UC_ARM64_REG_X0)),
                "x1": hex(c.reg_read(arm.UC_ARM64_REG_X1)),
                "x2": hex(c.reg_read(arm.UC_ARM64_REG_X2)),
                "x30": hex(c.reg_read(arm.UC_ARM64_REG_X30)),
            }
            assert c.reg_read(arm.UC_ARM64_REG_X0) == cold.acquisition.VM
            assert c.reg_read(arm.UC_ARM64_REG_X2) == 0x10006
            output = c.reg_read(arm.UC_ARM64_REG_X1)
            c.mem_write(output, cold.ENV.to_bytes(8, "little"))
            c.reg_write(arm.UC_ARM64_REG_X0, 0)
            c.reg_write(arm.UC_ARM64_REG_PC, c.reg_read(arm.UC_ARM64_REG_X30))
            row["environment"] = hex(cold.ENV)
            row["status"] = 0
            row["returned_pc"] = hex(c.reg_read(arm.UC_ARM64_REG_PC))
            import_trace.append(row)
            return
        offset = address - image
        name = IMPORT_NAMES.get(offset)
        if name is None:
            return
        row = {
            "pc_offset": hex(offset),
            "name": name,
            "x0": hex(c.reg_read(arm.UC_ARM64_REG_X0)),
            "x1": hex(c.reg_read(arm.UC_ARM64_REG_X1)),
            "x2": hex(c.reg_read(arm.UC_ARM64_REG_X2)),
            "x3": hex(c.reg_read(arm.UC_ARM64_REG_X3)),
            "x30": hex(c.reg_read(arm.UC_ARM64_REG_X30)),
        }
        import_trace.append(row)
        if name != "memcpy":
            if name in ("vsnprintf", "memchr", "__strlen_chk"):
                target = libc_exports.get(name)
                if target is None:
                    raise RuntimeError("matching libc lacks vsnprintf")
                c.reg_write(arm.UC_ARM64_REG_PC, target)
                row["redirected_to"] = hex(target)
            return
        target = c.reg_read(arm.UC_ARM64_REG_X0)
        source = c.reg_read(arm.UC_ARM64_REG_X1)
        width = c.reg_read(arm.UC_ARM64_REG_X2)
        c.mem_write(target, bytes(c.mem_read(source, width)))
        c.reg_write(arm.UC_ARM64_REG_X0, target)
        c.reg_write(arm.UC_ARM64_REG_PC, c.reg_read(arm.UC_ARM64_REG_X30))
        row.update({
            "copy_destination": hex(target),
            "copy_source": hex(source),
            "copy_size": width,
            "returned_pc": hex(c.reg_read(arm.UC_ARM64_REG_PC)),
        })

    def read_hook(c, _access, address, size, _value, _user):
        pc = c.reg_read(arm.UC_ARM64_REG_PC) - image
        if table_start <= address < table_end:
            runtime_reads.append({
                "pc": hex(pc), "address": hex(address), "size": size,
                "value": bytes(c.mem_read(address, size)).hex(),
            })
        if flag_range <= address < flag_range + 0x40:
            flag_reads.append({
                "pc": hex(pc), "address": hex(address), "size": size,
                "value": bytes(c.mem_read(address, size)).hex(),
            })

    def write_hook(c, _access, address, size, value, _user):
        pc = c.reg_read(arm.UC_ARM64_REG_PC) - image
        if table_start <= address < table_end:
            runtime_writes.append({
                "pc": hex(pc), "address": hex(address), "size": size,
                "value": hex(value),
            })
        if flag_range <= address < flag_range + 0x40:
            flag_writes.append({
                "pc": hex(pc), "address": hex(address), "size": size,
                "value": hex(value),
            })

    def unmapped_hook(c, access, address, size, value, _user):
        unmapped.append({
            "pc": hex(c.reg_read(arm.UC_ARM64_REG_PC) - image),
            "access": access,
            "address": hex(address),
            "size": size,
            "value": hex(value),
        })

    cpu.hook_add(UC_HOOK_CODE, code_hook,
                 begin=image + 0x15DB00, end=image + 0x347E64)
    cpu.hook_add(UC_HOOK_CODE, import_hook,
                 begin=image + 0x347E90, end=image + 0x3486F0)
    cpu.hook_add(UC_HOOK_CODE, import_hook,
                 begin=cold.acquisition.GET, end=cold.acquisition.GET)
    cpu.hook_add(UC_HOOK_MEM_READ, read_hook)
    cpu.hook_add(UC_HOOK_MEM_WRITE, write_hook)
    cpu.hook_add(UC_HOOK_MEM_UNMAPPED, unmapped_hook)

    outcome = "returned"
    error = None
    try:
        cpu.emu_start(image + 0x27DD04, oracle.STOP, count=2_000_000)
    except Exception as exc:
        outcome = "stopped"
        error = f"{type(exc).__name__}: {exc}"

    pc = cpu.reg_read(arm.UC_ARM64_REG_PC)
    output_address = request["output_reference_address"]
    output_words = bytes(cpu.mem_read(output_address, 16))
    return {
        "image_base": hex(image),
        "bootstrap_stack": hex(bootstrap_stack),
        "bootstrap_native_completed": True,
        "bootstrap_JNI_return_asserted": True,
        "same_cpu_request_continuation": True,
        "outcome": outcome,
        "error": error,
        "stop_pc": hex(pc),
        "stop_pc_offset": hex(pc - image),
        "request_reached_oracle_stop": pc == oracle.STOP,
        "returned_x0": hex(cpu.reg_read(arm.UC_ARM64_REG_X0)),
        "returned_x8": hex(cpu.reg_read(arm.UC_ARM64_REG_X8)),
        "output_reference_address": hex(output_address),
        "output_reference_words": output_words.hex(),
        "output_reference_nonzero": any(output_words),
        "native_instructions_observed": instruction_count,
        "vm_handler_event_count": sum(handler_counts.values()),
        "vm_handler_counts": dict(handler_counts),
        "clock_gettime_calls": sum(event[0] == "clock_gettime" for event in service.events),
        "flags_before_request": flags_before,
        "flags_after_request": bytes(cpu.mem_read(flag_range, 0x40)).hex(),
        "flag_reads": flag_reads,
        "flag_writes": flag_writes,
        "runtime_table_reads": runtime_reads,
        "runtime_table_writes": runtime_writes,
        "callback_object_trace": callback_trace,
        "import_trace": import_trace,
        "tail_trace": tail_trace,
        "unmapped_events": unmapped,
        "url_reference_words": "char* plus refcount pointer",
        "url_byte_length": len(URL),
        "synthetic_dispatch_table_used": False,
        "synthetic_callback_vtable_used": False,
        "runtime_table_content_reconstructed": False,
        "whole_request_native_success": False,
        "fresh_standalone_signer_verified": False,
        "online_header_acceptance_verified": False,
        "real_memcpy_import_service_used": any(
            event["name"] == "memcpy" for event in import_trace
        ),
        "real_javavm_getenv_provider_used": any(
            event["name"] == "JavaVM.GetEnv" for event in import_trace
        ),
        "bootstrap_native_import_hooks_preserved": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--libc", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if hashlib.sha256(args.library.read_bytes()).hexdigest() != oracle.LIBRARY_SHA256:
        raise SystemExit("unexpected native sample")
    rows = [run(args.library, args.libc, image) for image in BASES]
    evidence = {
        "schema": "vm9-bootstrap-request-memcpy-continuation-fresh-20261026-v1",
        "evidence_date": "2026-10-26",
        "sample_sha256": hashlib.sha256(args.library.read_bytes()).hexdigest(),
        "matching_libc_sha256": hashlib.sha256(args.libc.read_bytes()).hexdigest(),
        "url_fixture": {
            "format": "NUL-terminated URL bytes plus native two-word reference",
            "byte_length": len(URL),
            "sha256": hashlib.sha256(URL).hexdigest(),
            "pointer_word_address": hex(URL_POINTER),
            "refcount_word_address": hex(REFCOUNT),
        },
        "cases": rows,
        "same_unicorn_cpu_bootstrap_to_request_verified": True,
        "catalog_lazy_cache_preserved": all(
            row["flags_before_request"] != "00" * 0x40 for row in rows
        ),
        "runtime_table_owner_recovered": False,
        "runtime_table_content_reconstructed": False,
        "synthetic_dispatch_table_used": False,
        "synthetic_callback_vtable_used": False,
        "whole_request_native_success": False,
        "fresh_standalone_signer_verified": False,
        "online_header_acceptance_verified": False,
        "real_memcpy_import_service_used": all(
            row["real_memcpy_import_service_used"] for row in rows
        ),
        "real_javavm_getenv_provider_used": all(
            row["real_javavm_getenv_provider_used"] for row in rows
        ),
        "request_reached_oracle_stop_all": all(
            row["request_reached_oracle_stop"] for row in rows
        ),
        "bootstrap_native_import_hooks_preserved": True,
        "comparison_note": (
            "The same CPU that completed the real JNI/bootstrap sequence keeps the "
            "lazy builtin cache bytes before request entry. The actual two-word URL "
            "reference then advances the request beyond the empty-URL boundary; the "
            "the real callback reaches the ELF memcpy PLT and the probe supplies only "
            "its byte-copy ABI before returning through x30. No callback vtable, "
            "runtime dispatch page, or signer output is synthesized."
        ),
    }
    args.output.write_text(json.dumps(evidence, indent=2) + "\n",
                           encoding="utf-8", newline="\n")
    print("bootstrap -> request URL continuation", len(rows), "cases", flush=True)


if __name__ == "__main__":
    main()
