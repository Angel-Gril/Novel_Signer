"""Differential mapping/sbrk bodies from fresh ELF and explicit kernel cases."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
    UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_TPIDR_EL0)
import vm9_allocator as allocator
import vm9_libc_mapping as mapping
import verify_vm9_root_configuration as root
from verify_vm9_thread_key_cleanup import fresh, WORKER_TLS
from verify_vm9_pthread_exit import inputs
from verify_vm9_signer_objects import native, GUEST, LIBRARY_SHA256

LIBC_SHA256 = "d2376df6d2ac3e0213f85e3614c4c7ad1d28c84c44926058d5c1b95c855563db"
REGS = (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
        UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5)
FLAG = GUEST + 0x3480


def os_case(library, libc, base, label):
    plain = label.startswith("plain")
    length = 0x4000
    alignment = 0x10000
    start = 0x13600000 if label in ("plain", "plain_name_failure", "aligned_fast") else 0x13601000
    second = {"aligned_prefix": 0x13611000, "aligned_suffix": 0x13620000}.get(label, 0x13629000)
    addresses = [start, second]
    if label.endswith("null"):
        addresses[0] = 0
    if label.endswith("first_failure") or label == "plain_mmap_failure":
        addresses[0] = -12
    if label == "aligned_second_failure":
        addresses[1] = -12
    p = fresh(library, libc, base)
    seed = fresh(library, libc, base)
    for pages in (p, seed):
        allocator._write_span(pages, FLAG, bytes([0xA5]) * 8)
    actual_os = allocator.GuestOS(p)
    expected_os = allocator.GuestOS(seed)
    actual_events = []
    expected_events = []
    native_bytes = {}
    cursor = [0]

    def reply(operation, fields, events, index):
        events.append([operation, *fields])
        if operation == "mmap":
            assert fields[:1] == [0] and fields[2:] == [3, 0x22, 0xFFFFFFFF, 0]
            result = addresses[index[0]]
            index[0] += 1
            return result
        if operation == "prctl":
            assert fields[0:2] == [0x53564D41, 0] and fields[4] == b"libc_malloc"
            return -22 if label.endswith("name_failure") else 0
        assert operation == "munmap"
        return 0

    def syscall(cpu, number):
        fields = [cpu.reg_read(r) for r in REGS]
        if number == 222:
            result = reply("mmap", fields, expected_events, cursor)
            if result > 0:
                region = expected_os.map_anonymous(fields[1], address=result, fd=fields[4], anonymous_name=b"")
                cpu.mem_map(region.base, region.length)
            return result
        if number == 167:
            name = bytes(cpu.mem_read(fields[4], 12)).split(b"\0", 1)[0]
            result = reply("prctl", fields[:4] + [name], expected_events, cursor)
            if result >= 0:
                expected_os.name_exact(fields[2], fields[3], name)
            return result
        assert number == 215, number
        result = reply("munmap", fields[:2], expected_events, cursor)
        expected_os.unmap_range(*fields[:2])
        cpu.mem_unmap(*fields[:2])
        return result

    def observe(cpu, pc):
        if pc - root.LIBC_BASE in ((0x7F5D4,) if plain else (0x7F65C, 0x7F6E4)):
            native_bytes.clear()
            for region in expected_os.mappings:
                for page in range(region.base >> 12, region.end >> 12):
                    native_bytes[page] = bytes(cpu.mem_read(page << 12, 4096))

    observed = {(WORKER_TLS, 0xB00): None}
    offset = 0x7F56C if plain else 0x7F600
    arguments = [length] if plain else [length, alignment, FLAG]
    returned, memory, _, _ = native(library, base, root.LIBC_BASE + offset - base,
        arguments, inputs(seed), libc=libc, real_mutexes=True, syscall_handler=syscall,
        instruction_observer=observe, observed_memory=observed,
        extra_registers={UC_ARM64_REG_TPIDR_EL0: WORKER_TLS}, instruction_limit=20000)
    counter = [0]
    def os_call(tx, operation, *fields):
        return reply(operation, list(fields), actual_events, counter)
    if plain:
        result = mapping.map_allocator(actual_os, length=length, thread_pointer=WORKER_TLS, os_call=os_call)
    else:
        result = mapping.map_aligned_allocator(actual_os, length=length, alignment=alignment,
            flag_address=FLAG, thread_pointer=WORKER_TLS, os_call=os_call)
    assert result == returned, (label, result, returned)
    assert allocator._read_span(p, GUEST, 0xA000) == memory, (label, "guest bytes")
    assert all(allocator._read_span(p, a, n) == v for (a, n), v in observed.items()), (label, "TLS")
    assert actual_events == expected_events, (label, "ordered OS calls")
    assert actual_os.mappings == expected_os.mappings, (label, "owned mappings")
    assert actual_os.next_address == expected_os.next_address
    assert len(native_bytes) == sum(item.length // 4096 for item in expected_os.mappings)
    assert all(bytes(p[k]) == v for k, v in native_bytes.items()), (label, "retained pages")
    return dict(case=label, image_base=hex(base), ordered_os_calls=len(actual_events),
        return_guest_tls_and_retained_pages_match=True, mapping_metadata_match=True,
        untouched_flag_padding_match=True, native_input_snapshot_used=False)


def sbrk_case(library, libc, base, label):
    settings = {
        "cold_query": (0, 0, [0x13600000]),
        "warm_query": (0x13600000, 0, []),
        "cold_grow": (0, 4096, [0x13600000, 0x13601000]),
        "warm_grow": (0x13600000, 4096, [0x13601000]),
        "warm_shrink": (0x13602000, -4096, [0x13601000]),
        "grow_refused": (0x13600000, 4096, [0x13600000]),
        "shrink_kernel_retains_old": (0x13602000, -4096, [0x13602000]),
        "overflow": (mapping.MASK - 1, 3, []),
        "underflow": (3, -4, []),
        "signed_min_underflow": (3, -(1 << 63), []),
    }
    cache, increment, outcomes = settings[label]
    p = fresh(library, libc, base)
    seed = fresh(library, libc, base)
    address = root.LIBC_BASE + 0xDE840
    for pages in (p, seed):
        allocator._write_span(pages, address, cache.to_bytes(8, "little"))
    native_calls = []
    model_calls = []
    nresults = iter(outcomes)
    mresults = iter(outcomes)
    entry = root.LIBC_BASE + 0x1E6C8
    def observe(cpu, pc):
        if pc == entry:
            cpu.mem_write(address, cache.to_bytes(8, "little"))
    def syscall(cpu, number):
        assert number == 214
        native_calls.append(cpu.reg_read(UC_ARM64_REG_X0))
        return next(nresults)
    observed = {(address, 8): None, (WORKER_TLS, 0xB00): None}
    result, memory, _, _ = native(library, base, entry - base, [increment & mapping.MASK],
        inputs(seed), libc=libc, real_mutexes=True, instruction_observer=observe,
        syscall_handler=syscall, observed_memory=observed,
        extra_registers={UC_ARM64_REG_TPIDR_EL0: WORKER_TLS}, instruction_limit=20000)
    def brk(staged, target):
        model_calls.append(target)
        return next(mresults)
    actual = mapping.sbrk(p, increment=increment & mapping.MASK, libc_base=root.LIBC_BASE,
        thread_pointer=WORKER_TLS, brk=brk)
    assert actual == result and native_calls == model_calls, label
    assert allocator._read_span(p, GUEST, 0xA000) == memory, label
    assert all(allocator._read_span(p, a, n) == v for (a, n), v in observed.items()), label
    return dict(case=label, image_base=hex(base), returned_value_cache_errno_and_calls_match=True,
        native_input_snapshot_used=False)


def owner_checks():
    cases = []
    for label in ("prefix", "suffix", "middle", "whole"):
        pages = {}
        os = allocator.GuestOS(pages)
        region = os.map_anonymous(0x6000, anonymous_name=b"control")
        for k, page in pages.items():
            page[:] = bytes([k & 255]) * 4096
        before = {k: bytes(v) for k, v in pages.items()}
        offset, size = {"prefix": (0, 0x2000), "suffix": (0x4000, 0x2000),
                        "middle": (0x2000, 0x2000), "whole": (0, 0x6000)}[label]
        os.protect_exact(region.base, region.length, 1)
        os.unmap_range(region.base + offset, size)
        removed = set(range((region.base + offset) >> 12, (region.base + offset + size) >> 12))
        assert set(pages) == set(before) - removed
        assert all(bytes(v) == before[k] for k, v in pages.items())
        assert all(m.prot == 1 and m.anonymous_name == b"control" for m in os.mappings)
        assert sum(m.length for m in os.mappings) == region.length - size
        cases.append(dict(case=label, surviving_bytes_names_protection_preserved=True))
    for label in ("exact_still_rejects_partial", "unaligned", "zero_length", "unknown", "cross_mapping",
                  "missing_page", "bad_name", "partial_name", "bad_protection", "partial_protection", "rollback"):
        pages = {}
        os = allocator.GuestOS(pages)
        region = os.map_anonymous(0x4000)
        os.map_anonymous(0x4000)
        if label == "missing_page":
            del pages[(region.base >> 12) + 2]
        before = {k: bytes(v) for k, v in pages.items()}
        records = list(os.mappings)
        cursor = os.next_address
        try:
            if label == "exact_still_rejects_partial":
                os.unmap_exact(region.base, 4096)
            elif label == "bad_name":
                os.name_exact(region.base, region.length, b"x\0y")
            elif label == "partial_name":
                os.name_exact(region.base, 4096, b"control")
            elif label == "bad_protection":
                os.protect_exact(region.base, region.length, 7)
            elif label == "partial_protection":
                os.protect_exact(region.base, 4096, 1)
            elif label == "rollback":
                tx = os.begin()
                tx.name_exact(region.base, region.length, b"staged")
                tx.protect_exact(region.base, region.length, 1)
                tx.unmap_range(region.base, 4096)
                tx.unmap_range(region.base, 4096)
            else:
                address, size = {"unaligned": (region.base + 1, 4096), "zero_length": (region.base, 0),
                    "unknown": (region.base - 4096, 4096), "cross_mapping": (region.base, 0x5000),
                    "missing_page": (region.base, 4096)}[label]
                os.unmap_range(address, size)
        except allocator.RefillUnsupported:
            pass
        else:
            raise AssertionError((label, "expected rejection"))
        assert before == {k: bytes(v) for k, v in pages.items()} and records == os.mappings
        assert cursor == os.next_address
        cases.append(dict(case=label, rejected=True, pages_mappings_cursor_unchanged=True))
    for label in ("munmap_failure", "invalid_kernel", "invalid_alignment", "unmapped_flag", "late_name_provider_failure"):
        pages = {GUEST >> 12: bytearray(4096)}
        os = allocator.GuestOS(pages)
        before = {k: bytes(v) for k, v in pages.items()}
        calls = []
        def os_call(tx, op, *fields):
            calls.append(op)
            if label == "invalid_kernel": return None
            if op == "mmap": return 0x13601000
            if label == "late_name_provider_failure": raise allocator.RefillUnsupported("unavailable OS naming")
            if op == "prctl": return 0
            return -22
        try:
            mapping.map_aligned_allocator(os, length=0x4000,
                alignment=3 if label == "invalid_alignment" else 0x10000,
                flag_address=GUEST + (0x1000 if label == "unmapped_flag" else 16),
                thread_pointer=GUEST, os_call=os_call)
        except (allocator.RefillUnsupported, ValueError):
            pass
        else:
            raise AssertionError((label, "expected explicit rejection"))
        assert before == {k: bytes(v) for k, v in pages.items()} and not os.mappings
        assert os.next_address == 0x13600000
        cases.append(dict(case=label, rejected=True, pages_mappings_cursor_unchanged=True,
                          external_provider_effects_rolled_back=False, external_calls=len(calls)))
    return cases


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--library", type=Path, required=True)
    ap.add_argument("--libc", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest() == LIBC_SHA256
    controls = []
    breaks = []
    for base in (0x122C0000, 0x775C205000):
        for label in ("plain", "plain_mmap_failure", "plain_null", "plain_name_failure",
                      "aligned_fast", "aligned_prefix", "aligned_suffix", "aligned_both",
                      "aligned_first_failure", "aligned_second_failure", "aligned_name_failure"):
            controls.append(os_case(args.library, args.libc, base, label))
            print("mapping", hex(base), label, "PASS", flush=True)
        for label in ("cold_query", "warm_query", "cold_grow", "warm_grow", "warm_shrink", "grow_refused",
                      "shrink_kernel_retains_old", "overflow", "underflow", "signed_min_underflow"):
            breaks.append(sbrk_case(args.library, args.libc, base, label))
            print("sbrk", hex(base), label, "PASS", flush=True)
    owner = owner_checks()
    report = dict(schema="vm9-libc-mapping-v1", sample_sha256=LIBRARY_SHA256, libc_sha256=LIBC_SHA256,
        mapping_cases=controls, sbrk_cases=breaks, owner_cases=owner,
        native_input_snapshot_used=False, python_malloc_cold_boot_complete=False, standalone_medusa_complete=False)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(dict(mapping=len(controls), sbrk=len(breaks), owner=len(owner))))


if __name__ == "__main__":
    main()
