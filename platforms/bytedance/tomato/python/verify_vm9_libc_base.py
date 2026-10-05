"""Real native +0x7d998 and same-fresh preinit with Python-owned base maps."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
    UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X30, UC_ARM64_REG_PC,
    UC_ARM64_REG_TPIDR_EL0)
import vm9_allocator as allocator
import vm9_libc_boot as boot
import vm9_libc_base as base_model
from verify_vm9_thread_key_cleanup import fresh, WORKER_TLS, TABLE
from verify_vm9_pthread_exit import inputs
from verify_vm9_signer_objects import native, GUEST, STOP, LIBRARY_SHA256
from verify_vm9_libc_mapping import LIBC_SHA256
from verify_vm9_libc_cold_malloc import cstring
from verify_vm9_libc_arena_boot import put, get, LIBC

REGS = (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5)
CONTINUE = GUEST + 0xF6E0


def prepare(library, libc, image, composed):
    p = fresh(library, libc, image)
    if not composed:
        boot.preinit_prefix(p, libc_base=LIBC, thread_pointer=WORKER_TLS, brk=lambda *args: 0x13600000)
    return p


def case(library, libc, image, label, composed=False, complete=False, cold=False):
    requests = {"cold_small": [7], "cold_large": [8193], "hot_split": [7, 180, 64, 4096],
        "recycle_node": [257920, 4096, 64], "recycle_map_failure": [257920, 4096, 64],
        "multi_node_tree": [200000, 200000, 200000, 200000, 8192, 32768, 16384],
        "misaligned": [7, 180], "map_failure": [7], "second_map_failure": [7], "name_failure": [7, 180]}.get(label, [7])
    p = prepare(library, libc, image, composed)
    seed = prepare(library, libc, image, composed)
    if label == "exhausted_keys":
        for pages in (p, seed):
            for i in range(141): put(pages, TABLE + i * 16, 1)
    initial_address = 0x13601000 if label in ("misaligned", "second_map_failure") else 0x13600000
    os = allocator.GuestOS(p, next_address=initial_address)
    nos = allocator.GuestOS(seed, next_address=initial_address)
    observed = {(LIBC + 0xE67B8, 0x370): None, (LIBC + 0xE9110, 0xE60): None,
        (LIBC + 0xDB650, 0xF0): None, (LIBC + 0xDE840, 8): None,
        (WORKER_TLS, 0xB00): None, (TABLE, 141 * 16): None}
    expected_calls = []
    actual_calls = []
    results = []
    ncalls = [0]
    mcalls = [0]
    stage = [0]
    native_base_entries = [0]
    entry = LIBC + (0x8E350 if cold else 0x8E250 if composed else 0x7D998)
    def fail_mmap(count):
        return label == "map_failure" and count == 1 or label in ("second_map_failure", "recycle_map_failure") and count == 2
    def nsyscall(cpu, number):
        fields = [cpu.reg_read(reg) for reg in REGS]
        if number == 214:
            assert fields[0] == 0
            expected_calls.append(["brk", 0])
            return 0x13600000
        if number == 222:
            ncalls[0] += 1
            expected_calls.append(["mmap", *fields])
            assert fields[0] == 0 and fields[2:] == [3, 0x22, 0xFFFFFFFF, 0]
            if fail_mmap(ncalls[0]): return -12
            record = nos.map_anonymous(fields[1], address=nos.next_address, fd=fields[4], anonymous_name=b"")
            cpu.mem_map(record.base, record.length)
            observed.update({(k << 12, 4096): None for k in range(record.base >> 12, record.end >> 12)})
            return record.base
        if number == 167:
            assert fields[:2] == [0x53564D41, 0]
            name = cstring(cpu, fields[4])
            expected_calls.append(["prctl", *fields[:4], name])
            assert name == b"libc_malloc"
            if label == "name_failure": return -22
            nos.name_exact(fields[2], fields[3], name)
            return 0
        assert number == 215, number
        expected_calls.append(["munmap", *fields[:2]])
        tx = nos.begin()
        tx.unmap_range(*fields[:2])
        cpu.mem_unmap(*fields[:2])
        tx.commit()
        for k in range(fields[0] >> 12, (fields[0] + fields[1]) >> 12): observed.pop((k << 12, 4096), None)
        return 0
    def os_call(tx, operation, *fields):
        actual_calls.append([operation, *fields])
        if operation == "mmap":
            mcalls[0] += 1
            return -12 if fail_mmap(mcalls[0]) else tx.next_address
        if operation == "prctl": return -22 if label == "name_failure" else 0
        assert operation == "munmap"
        return 0
    def brk(staged, target):
        actual_calls.append(["brk", target])
        return 0x13600000
    def observe(cpu, pc):
        if pc == LIBC + 0x7D998: native_base_entries[0] += 1
        if pc == entry and stage[0] == 0:
            spans = [(TABLE, 141 * 16)] if composed else list(observed)
            for a, n in spans:
                if LIBC <= a < LIBC + 0x400000: cpu.mem_write(a, allocator._read_span(seed, a, n))
    def continuation(cpu):
        result = cpu.reg_read(UC_ARM64_REG_X0)
        results.append(result)
        if result: cpu.mem_write(result, bytes([0x5A]) * min(requests[stage[0]], 64))
        stage[0] += 1
        if stage[0] == len(requests):
            cpu.reg_write(UC_ARM64_REG_PC, STOP)
        else:
            cpu.reg_write(UC_ARM64_REG_X0, requests[stage[0]])
            cpu.reg_write(UC_ARM64_REG_X30, CONTINUE)
            cpu.reg_write(UC_ARM64_REG_PC, entry)
        return None
    if composed:
        imports = {}
        extra = {UC_ARM64_REG_TPIDR_EL0: WORKER_TLS}
        stop = (None if label in ("map_failure", "exhausted_keys") else LIBC + 0x8E41C - image) if cold else None if label == "map_failure" or complete else LIBC + 0x8E31C - image
        arguments = []
    else:
        imports = {CONTINUE - image: continuation}
        extra = {UC_ARM64_REG_TPIDR_EL0: WORKER_TLS, UC_ARM64_REG_X30: CONTINUE}
        stop = None
        arguments = [requests[0]]
    returned, memory, allocations, ledger = native(library, image, entry - image, arguments, inputs(seed),
        libc=libc, real_mutexes=True, instruction_observer=observe, syscall_handler=nsyscall,
        host_imports=imports, extra_registers=extra, observed_memory=observed,
        instruction_limit=200000, stop_offset=stop)
    assert not allocations and not ledger
    if composed:
        execute = base_model.cold_init_until_cpu_query if cold else base_model.preinit_complete_with_base_allocator if complete else base_model.preinit_with_base_allocator
        actual = execute(os, libc_base=LIBC,
            thread_pointer=WORKER_TLS, brk=brk, os_call=os_call)
        assert actual == (1 if label in ("map_failure", "exhausted_keys") else 0x8E41C if cold else 0 if complete else 0x8E31C), (label, actual)
        assert returned == (1 if label in ("map_failure", "exhausted_keys") else 0)
    else:
        actual = []
        for size in requests:
            pointer = base_model.base_allocate(os, request_size=size, libc_base=LIBC,
                thread_pointer=WORKER_TLS, os_call=os_call)
            actual.append(pointer)
            if pointer: allocator._write_span(p, pointer, bytes([0x5A]) * min(size, 64))
        assert actual == results, (label, "returned pointers", actual, results)
    assert actual_calls == expected_calls, (label, "ordered OS calls")
    assert os.mappings == nos.mappings and os.next_address == nos.next_address, (label, "OS records")
    assert allocator._read_span(p, GUEST, 0xA000) == memory, (label, "guest bytes")
    for (a, n), value in observed.items():
        data = allocator._read_span(p, a, n)
        if data != value:
            delta = [(hex(a + i - LIBC), x, y) for i, (x, y) in enumerate(zip(data, value)) if x != y]
            raise AssertionError((label, "globals/TLS/mapped pages", delta[:10]))
    expected_base_entries = (3 if complete or cold else 2) if composed and label != "map_failure" else len(requests)
    assert native_base_entries[0] == expected_base_entries, (label, "actual native base entries")
    return dict(case=label, image_base=hex(image), same_fresh_preinit_composed=composed, complete_default_preinit_returned=complete, same_fresh_cold_init_prefix=cold,
        actual_base_allocator_used=True, malloc_hook_calls=0, synthetic_allocation_returns=False,
        return_guest_globals_tls_mapping_bytes_and_metadata_match=True, ordered_os_calls=len(actual_calls),
        successful_owned_mappings=len(os.mappings), base_calls=native_base_entries[0],
        native_input_snapshot_used=False, explicit_virtual_os=True)


def rejection_cases(library, libc):
    results = []
    for label in ("invalid_size", "contended_mutex", "bad_chunk_mask", "corrupt_sentinel", "late_naming_provider_failure", "foreign_staging_chain", "composed_rollback", "cold_prefix_rollback", "cold_prefix_nonfresh", "cold_prefix_owned"):
        composed = label in ("composed_rollback", "cold_prefix_rollback", "cold_prefix_nonfresh", "cold_prefix_owned")
        p = prepare(library, libc, 0x122C0000, composed)
        os = allocator.GuestOS(p)
        if label == "cold_prefix_nonfresh": put(p, LIBC + 0xDB6A0, 2, 4)
        if label == "cold_prefix_owned": put(p, LIBC + 0xE69B8, GUEST)
        if label == "contended_mutex": put(p, LIBC + 0xE6860, 2, 2)
        if label == "bad_chunk_mask": put(p, LIBC + 0xE9EC0, 1)
        if label == "corrupt_sentinel": put(p, LIBC + 0xE67E8 + 0x50, 0)
        before = {k: bytes(v) for k, v in p.items()}
        records = list(os.mappings)
        cursor = os.next_address
        calls = []
        def service(tx, op, *fields):
            calls.append(op)
            if op == "mmap": return tx.next_address
            raise allocator.RefillUnsupported("explicit unavailable naming provider")
        try:
            if label.startswith("cold_prefix_"):
                base_model.cold_init_until_cpu_query(os, libc_base=LIBC, thread_pointer=WORKER_TLS,
                    brk=lambda *args: 0x13600000, os_call=service)
            elif composed:
                base_model.preinit_with_base_allocator(os, libc_base=LIBC, thread_pointer=WORKER_TLS,
                    brk=lambda *args: 0x13600000, os_call=service)
            elif label == "foreign_staging_chain":
                base_model._allocate_staged(os.begin(), allocator._PageTransaction(p), request_size=7,
                    libc_base=LIBC, thread_pointer=WORKER_TLS, os_call=service)
            else:
                base_model.base_allocate(os, request_size=0 if label == "invalid_size" else 7,
                    libc_base=LIBC, thread_pointer=WORKER_TLS, os_call=service)
        except (allocator.RefillUnsupported, ValueError): pass
        else: raise AssertionError((label, "expected rejection"))
        assert before == {k: bytes(v) for k, v in p.items()} and records == os.mappings and cursor == os.next_address
        results.append(dict(case=label, rejected=True, pages_mappings_cursor_unchanged=True,
            external_calls=len(calls), external_provider_effects_rolled_back=False))
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--library", type=Path, required=True)
    ap.add_argument("--libc", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest() == LIBC_SHA256
    cases = []
    for image in (0x122C0000, 0x775C205000):
        for label in ("cold_small", "cold_large", "hot_split", "recycle_node", "recycle_map_failure", "multi_node_tree", "misaligned", "map_failure", "second_map_failure", "name_failure"):
            cases.append(case(args.library, args.libc, image, label))
            print("base allocator", hex(image), label, "PASS", flush=True)
        for label in ("default", "misaligned", "name_failure", "map_failure"):
            cases.append(case(args.library, args.libc, image, label, composed=True))
            print("real base preinit", hex(image), label, "PASS", flush=True)
        for label in ("default", "misaligned", "name_failure", "map_failure"):
            cases.append(case(args.library, args.libc, image, label, composed=True, complete=True))
            print("complete real base preinit", hex(image), label, "PASS", flush=True)
        for label in ("default", "misaligned", "name_failure", "map_failure", "exhausted_keys"):
            cases.append(case(args.library, args.libc, image, label, composed=True, cold=True))
            print("fresh real cold init prefix", hex(image), label, "PASS", flush=True)
    rejected = rejection_cases(args.library, args.libc)
    report = dict(schema="vm9-libc-real-base-preinit-v1", sample_sha256=LIBRARY_SHA256,
        libc_sha256=LIBC_SHA256, cases=cases, rejection_cases=rejected,
        actual_base_allocator_integrated=True, preinit_composed_stop_offset="0x8e31c",
        initial_arena_constructed_in_default_controls=True, default_empty_preinit_complete=True,
        cold_init_prefix_stop_offset="0x8e41c", cpu_query_and_reentrant_malloc_restored=False,
        python_preinit_complete=False, python_malloc_cold_boot_complete=False,
        standalone_medusa_complete=False, native_input_snapshot_used=False)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(dict(base_and_composed=len(cases), rejected=len(rejected))))


if __name__ == "__main__": main()
