"""Native controls for same-fresh cold prefix, tcache creation and arena bind.

The continuation at +0x8e41c is explicit: CPU query, full cold-init return are not executed or claimed.
Public small/refill controls run as explicit continuations of that fresh prefix. Only inactive keys and ELF
options seed native; no Python-generated boot pages seed the oracle.
"""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X30, UC_ARM64_REG_PC, UC_ARM64_REG_TPIDR_EL0
import vm9_allocator as allocator
import vm9_libc_base as base_model
import vm9_libc_tcache as model
from verify_vm9_thread_key_cleanup import fresh, WORKER_TLS, TABLE
from verify_vm9_pthread_exit import inputs
from verify_vm9_signer_objects import native, GUEST, STOP, LIBRARY_SHA256
from verify_vm9_libc_mapping import LIBC_SHA256, REGS
from verify_vm9_libc_cold_malloc import cstring
from verify_vm9_libc_arena_boot import put, get, LIBC

CONTINUE = GUEST + 0xF720
ENTRIES = {0x8E250, 0x8E350, 0x99938, 0x8DDA0, 0x98C54, 0x98490,
    0x98428, 0x8F00C, 0x7970C, 0x97ECC, 0x7A668, 0x79FA4, 0x787DC, 0x765B0, 0x7E14C}


def case(library, libc, image, label):
    p, seed = fresh(library, libc, image), fresh(library, libc, image)
    bits = 16 if label in ("chunk16", "public_partial") else 20 if label == "chunk20" else 18
    for pages in (p, seed):
        put(pages, LIBC + 0xDB668, bits)
        if label in ("disabled", "public_disabled"): put(pages, LIBC + 0xDB6B0, 0, 1)
        if label in ("map_failure_no_dss", "public_null", "public_partial"): put(pages, LIBC + 0xDB690, 0, 4)
    start = 0x13601000 if label == "misaligned" else 0x13600000
    os, nos = allocator.GuestOS(p, next_address=start), allocator.GuestOS(seed, next_address=start)
    observed = {(LIBC + 0xE67B8, 0x370): None, (LIBC + 0xE9110, 0xE60): None,
        (LIBC + 0xDB650, 0xF0): None, (LIBC + 0xDE840, 8): None,
        (WORKER_TLS, 0xB00): None, (TABLE, 141 * 16): None}
    n_calls, m_calls, results = [], [], []
    counts = Counter()
    n_maps, m_maps = [0], [0]
    pending = []
    wrapper = LIBC + 0xDB6B8
    tsd = wrapper + 8
    public = label.startswith("public_")
    requests = {"public_default": [128], "public_sizes": [0, 1, 31, 127, 4095, 7169, 14335],
        "public_bitmap": [8] * 65, "public_exhausted": [4096] * 12,
        "public_regions": [14336] * 40, "public_disabled": [128, 48, 7168],
        "public_zero": [128] * 3, "public_null": [128], "public_partial": [14336], "public_ready": [128],
        "public_state_zero": [128], "public_state_two": [128, 128]}.get(label, [])
    iterations = len(requests) if public else 3 if label in ("three_caches", "three_binds") else 1
    binding = label in ("bind", "three_binds", "bind_noncurrent")
    direct = label == "direct_create"
    def fail_mmap(count):
        return (label == "map_failure_no_dss" and count == 2
            or label == "public_null" and count >= 2
            or label == "public_partial" and count >= 4)
    def syscall(cpu, number):
        fields = [cpu.reg_read(reg) for reg in REGS]
        if number == 214:
            assert fields[0] == 0
            n_calls.append(["brk", 0]); return 0x13600000
        if number == 222:
            n_calls.append(["mmap", *fields]); n_maps[0] += 1
            if fail_mmap(n_maps[0]): return -12
            assert fields[0] == 0 and fields[2:] == [3, 0x22, 0xFFFFFFFF, 0]
            rec = nos.map_anonymous(fields[1], prot=fields[2], flags=fields[3], fd=fields[4], anonymous_name=b"")
            cpu.mem_map(rec.base, rec.length)
            observed.update({(k << 12, 4096): None for k in range(rec.base >> 12, rec.end >> 12)})
            return rec.base
        if number == 167:
            name = cstring(cpu, fields[4]); assert name == b"libc_malloc"
            n_calls.append(["prctl", *fields[:4], name])
            if label == "name_failure": return -22
            nos.name_exact(fields[2], fields[3], name); return 0
        assert number == 215, number
        n_calls.append(["munmap", *fields[:2]])
        tx = nos.begin(); tx.unmap_range(*fields[:2]); cpu.mem_unmap(*fields[:2]); tx.commit()
        for k in range(fields[0] >> 12, (fields[0] + fields[1]) >> 12): observed.pop((k << 12, 4096), None)
        return 0
    def os_call(tx, operation, *fields):
        m_calls.append([operation, *fields])
        if operation == "mmap":
            m_maps[0] += 1
            return -12 if fail_mmap(m_maps[0]) else tx.next_address
        if operation == "prctl": return -22 if label == "name_failure" else 0
        assert operation == "munmap"; return 0
    def brk(pages, target): m_calls.append(["brk", target]); return 0x13600000
    def observe(cpu, pc):
        offset = pc - LIBC
        if offset in ENTRIES: counts[offset] += 1
        if offset == 0x8E250:
            for a, n in ((TABLE, 141 * 16), (LIBC + 0xDB668, 8),
                    (LIBC + 0xDB690, 4), (LIBC + 0xDB6B0, 1)):
                cpu.mem_write(a, allocator._read_span(seed, a, n))
    def dispatch(cpu):
        if not pending:
            cpu.reg_write(UC_ARM64_REG_PC, STOP); return None
        offset, args = pending.pop(0)
        for reg, value in zip(REGS, args): cpu.reg_write(reg, value)
        cpu.reg_write(UC_ARM64_REG_X30, CONTINUE)
        cpu.reg_write(UC_ARM64_REG_PC, LIBC + offset)
        return None
    def cold_continuation(cpu):
        if label == "public_ready": cpu.mem_write(LIBC + 0xDB6A0, bytes(4))
        if label == "public_zero": cpu.mem_write(LIBC + 0xE69C9, bytes([1]))
        if label in ("state_zero", "public_state_zero"): cpu.mem_write(tsd, (0).to_bytes(4, "little"))
        if label in ("state_two", "public_state_two"): cpu.mem_write(tsd, (2).to_bytes(4, "little"))
        if label == "bind_noncurrent": cpu.mem_write(tsd, (3).to_bytes(4, "little"))
        arena = int.from_bytes(cpu.mem_read(LIBC + 0xE6968, 8), "little")
        entry = 0x8F00C if public else 0x8DDA0 if binding else 0x98490 if direct else 0x98C54
        pending.extend((entry, [size]) for size in requests) if public else pending.extend(
            (entry, [tsd, arena] if direct else [tsd]) for _ in range(iterations))
        return dispatch(cpu)
    def poison_remaining(read, write):
        cache = int.from_bytes(read(wrapper + 0x10, 8), "little")
        target = cache + 8 * 32  # controlled 128-byte class
        count = int.from_bytes(read(target + 0x30, 4), "little")
        vector = int.from_bytes(read(target + 0x38, 8), "little")
        for i in range(count):
            pointer = int.from_bytes(read(vector + i * 8, 8), "little")
            write(pointer, bytes([0xA5]) * 128)
    def continuation(cpu):
        results.append(cpu.reg_read(UC_ARM64_REG_X0))
        if label == "public_zero" and len(results) > 1:
            assert bytes(cpu.mem_read(results[-1], 128)) == bytes(128)
        if label == "public_zero" and len(results) == 1:
            poison_remaining(cpu.mem_read, cpu.mem_write)
        return dispatch(cpu)
    returned, memory, allocations, ledger = native(library, image, LIBC + 0x8E350 - image,
        [], inputs(seed), libc=libc, real_mutexes=True, instruction_observer=observe,
        syscall_handler=syscall, host_imports={LIBC + 0x8E41C - image: cold_continuation,
            CONTINUE - image: continuation}, extra_registers={UC_ARM64_REG_TPIDR_EL0: WORKER_TLS},
        observed_memory=observed, instruction_limit=300000)
    assert not allocations and not ledger and len(results) == iterations and returned == results[-1]
    stop = base_model.cold_init_until_cpu_query(os, libc_base=LIBC,
        thread_pointer=WORKER_TLS, brk=brk, os_call=os_call)
    assert stop == 0x8E41C
    if label in ("state_zero", "state_two", "bind_noncurrent", "public_state_zero", "public_state_two"):
        put(p, tsd, {"state_zero": 0, "state_two": 2, "bind_noncurrent": 3, "public_state_zero": 0, "public_state_two": 2}[label], 4)
    if label == "public_ready": put(p, LIBC + 0xDB6A0, 0, 4)
    if label == "public_zero": put(p, LIBC + 0xE69C9, 1, 1)
    arena = get(p, LIBC + 0xE6968)
    actual = []
    for i in range(iterations):
        if public:
            result = model.allocate_public_small(os, request_size=requests[i], libc_base=LIBC,
                thread_pointer=WORKER_TLS, os_call=os_call)
        elif binding:
            result = model.bind_thread_arena(os, tsd_address=tsd, libc_base=LIBC)
        else:
            fn = model.create_thread_cache if direct else model.get_thread_cache
            extra = {"arena_address": arena} if direct else {}
            result = fn(os, tsd_address=tsd, libc_base=LIBC, thread_pointer=WORKER_TLS,
                os_call=os_call, **extra)
        actual.append(result)
        if label == "public_zero" and i > 0:
            assert allocator._read_span(p, result, 128) == bytes(128)
        if label == "public_zero" and i == 0:
            poison_remaining(lambda a,n: allocator._read_span(p,a,n),
                lambda a,b: allocator._write_span(p,a,b))
    if label == "public_null":
        assert actual == [0] and get(p, WORKER_TLS + 0x10, 4) == 12
    if label == "public_partial":
        cache = get(p, wrapper + 0x10)
        assert actual[0] and m_maps[0] >= 4 and get(p, cache + 35 * 32 + 0x30, 4) == 1
    assert actual == results, (label, "results", actual, results)
    assert n_calls == m_calls, (label, "ordered OS calls")
    assert os.mappings == nos.mappings and os.next_address == nos.next_address, (label, "OS metadata")
    assert allocator._read_span(p, GUEST, 0xA000) == memory
    for (address, width), value in observed.items():
        data = allocator._read_span(p, address, width)
        if data != value:
            diffs = [(hex(address + i - LIBC), x, y) for i, (x,y) in enumerate(zip(data,value)) if x != y]
            raise AssertionError((label, "global/TLS/owned mapping mismatch", diffs[:16]))
    assert counts[0x8E250] == 1 and get(p, LIBC + 0xDB6A0, 4) == (0 if label == "public_ready" else 1)
    return dict(case=label, image_base=hex(image), same_fresh_cold_prefix_composed=True,
        return_guest_globals_tls_all_mapping_bytes_and_metadata_match=True,
        ordered_os_calls=len(m_calls), retained_owned_mappings=len(os.mappings),
        actual_entry_counts={hex(k): v for k,v in sorted(counts.items())},
        ready_flag_fixture_applied=label == "public_ready",
        allocation_provider_used=False, native_input_snapshot_used=False, explicit_virtual_os=True,
        python_malloc_cold_boot_complete=False)


def rejection_cases(library, libc):
    labels = ("multi_arena", "arena_mutex_busy", "missing_arena", "bad_arena_table",
        "bad_class_count", "bad_capacity_total", "large_cache_storage", "junk_storage",
        "cache_publish_mutex_busy", "missing_tsd", "disabled_nonempty", "late_provider_failure",
        "public_negative", "public_large", "public_cold", "public_other_owner", "public_profiling",
        "public_gc", "public_corrupt_count", "public_cached_junk", "refill_nonempty",
        "refill_large_class", "refill_excessive_batch", "refill_bad_slab_class")
    results = []
    for label in labels:
        p = fresh(library, libc, 0x122C0000)
        os = allocator.GuestOS(p)
        unavailable = [False]
        calls = []
        def service(tx, operation, *fields):
            calls.append(operation)
            if unavailable[0] and operation == "prctl":
                raise allocator.RefillUnsupported("explicit naming provider unavailable")
            return tx.next_address if operation == "mmap" else 0
        stop = base_model.cold_init_until_cpu_query(os, libc_base=LIBC,
            thread_pointer=WORKER_TLS, brk=lambda *args: 0x13600000, os_call=service)
        assert stop == 0x8E41C
        wrapper, tsd = LIBC + 0xDB6B8, LIBC + 0xDB6C0
        arena = get(p, LIBC + 0xE6968)
        cached = label in ("public_gc", "public_corrupt_count", "public_cached_junk",
            "refill_nonempty", "refill_large_class", "refill_excessive_batch", "refill_bad_slab_class")
        cache = 0
        if cached:
            assert model.allocate_public_small(os, request_size=128, libc_base=LIBC,
                thread_pointer=WORKER_TLS, os_call=service)
            cache = get(p, wrapper + 0x10)
        if label == "multi_arena": put(p, LIBC + 0xE6970, 2, 4)
        if label == "arena_mutex_busy": put(p, LIBC + 0xE6980, 2, 2)
        if label == "missing_arena": put(p, LIBC + 0xE6968, 0)
        if label == "bad_arena_table": put(p, LIBC + 0xE69D0, GUEST)
        if label == "bad_class_count": put(p, LIBC + 0xE9F48, 46)
        if label == "bad_capacity_total": put(p, LIBC + 0xE6A9C, 0, 4)
        if label == "large_cache_storage":
            count = get(p, LIBC + 0xE9F48)
            table = get(p, LIBC + 0xE9F50)
            for i in range(count): put(p, table + i * 4, 100, 4)
            put(p, LIBC + 0xE6A9C, count * 100, 4)
        if label == "junk_storage": put(p, LIBC + 0xE69A8, 1, 1)
        if label == "cache_publish_mutex_busy": put(p, arena + 8, 2, 2)
        if label == "missing_tsd":
            key = get(p, LIBC + 0xE9F68, 4)
            assert allocator.pthread_setspecific(p, key=key, value=0, thread_pointer=WORKER_TLS,
                generation_table=LIBC + 0xE0200) == 0
        if label == "disabled_nonempty":
            put(p, wrapper + 0x48, 0, 4); put(p, wrapper + 0x10, GUEST)
        if label == "late_provider_failure": unavailable[0] = True
        if label == "public_cold": put(p, LIBC + 0xDB6A0, 3, 4)
        if label == "public_other_owner": put(p, LIBC + 0xE69B8, 0)
        if label == "public_profiling": put(p, LIBC + 0xE69C0, 1)
        if label == "public_gc": put(p, cache + 0x18, 227, 4)
        if label == "public_corrupt_count": put(p, cache + 8 * 32 + 0x30, 0xFFFFFFFF, 4)
        if label == "public_cached_junk": put(p, LIBC + 0xE69A8, 1, 1)
        if label in ("refill_excessive_batch", "refill_bad_slab_class"):
            put(p, cache + 8 * 32 + 0x30, 0, 4)
        if label == "refill_excessive_batch": put(p, get(p, LIBC + 0xE9F50) + 8 * 4, 512, 4)
        if label == "refill_bad_slab_class":
            slab = get(p, arena + 0x508 + 8 * 0xE0 + 0x28)
            put(p, slab, 99, 4)
        before = {k: bytes(v) for k,v in p.items()}
        records, cursor, initial_calls = list(os.mappings), os.next_address, len(calls)
        try:
            if label.startswith("public_"):
                size = -1 if label == "public_negative" else 0x3801 if label == "public_large" else 128
                model.allocate_public_small(os, request_size=size, libc_base=LIBC,
                    thread_pointer=WORKER_TLS, os_call=service)
            elif label.startswith("refill_"):
                model.refill_small_cache_bin(os, arena_address=arena, cache_address=cache,
                    class_id=36 if label == "refill_large_class" else 8, libc_base=LIBC,
                    thread_pointer=WORKER_TLS, os_call=service)
            else:
                model.get_thread_cache(os, tsd_address=tsd, libc_base=LIBC,
                    thread_pointer=WORKER_TLS, os_call=service)
        except (allocator.RefillUnsupported, ValueError):
            pass
        else:
            raise AssertionError((label, "expected explicit rejection"))
        assert before == {k: bytes(v) for k,v in p.items()}
        assert records == os.mappings and cursor == os.next_address
        results.append(dict(case=label, rejected=True, guest_pages_records_and_cursor_unchanged=True,
            external_os_calls=len(calls)-initial_calls, external_provider_effects_rolled_back=False))
    return results


CASE_LABELS = ("default", "three_caches", "disabled", "state_zero", "state_two",
    "bind", "three_binds", "bind_noncurrent", "direct_create", "chunk16", "chunk20",
    "misaligned", "name_failure", "map_failure_no_dss", "public_default",
    "public_sizes", "public_bitmap", "public_exhausted", "public_regions",
    "public_disabled", "public_zero", "public_null", "public_partial",
    "public_ready", "public_state_zero", "public_state_two")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--library", type=Path, required=True)
    ap.add_argument("--libc", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--case", action="append", choices=CASE_LABELS)
    args = ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest() == LIBC_SHA256
    cases = []
    labels = args.case or CASE_LABELS
    for image in (0x122C0000, 0x775C205000):
        for label in labels:
            cases.append(case(args.library, args.libc, image, label))
            print("fresh libc tcache", hex(image), label, "PASS", flush=True)
    rejected = rejection_cases(args.library, args.libc)
    print("tcache rejection/rollback", len(rejected), "PASS", flush=True)
    report = dict(schema="vm9-libc-fresh-tcache-v1", sample_sha256=LIBRARY_SHA256,
        libc_sha256=LIBC_SHA256, cases=cases, rejection_cases=rejected, native_input_snapshot_used=False,
        full_case_set_verified=set(labels) == set(CASE_LABELS),
        single_arena_binding_restored=any(c["actual_entry_counts"].get("0x8dda0") for c in cases),
        default_tcache_creation_restored=any(c["actual_entry_counts"].get("0x98490") for c in cases),
        bounded_public_small_and_clean_refill_restored=any(
            c["actual_entry_counts"].get("0x8f00c") and c["actual_entry_counts"].get("0x7970c") for c in cases),
        public_malloc_tcache_complete=False, python_malloc_cold_boot_complete=False,
        standalone_medusa_complete=False, current_online_header_matrix_verified=False)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
