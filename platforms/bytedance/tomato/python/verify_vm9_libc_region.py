"""Same-fresh preinit, chunk registration and clean direct/internal small allocation.

No allocator returns or native initialization pages seed the Python model.
OS inputs and the direct sequence continuation are explicit controls. This
verifier does not execute CPU sysconf, full public malloc or request signing.
"""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X30,
    UC_ARM64_REG_PC, UC_ARM64_REG_TPIDR_EL0)
from elftools.elf.elffile import ELFFile
import vm9_allocator as allocator
from verify_vm9_thread_key_cleanup import fresh, WORKER_TLS, TABLE
from verify_vm9_pthread_exit import inputs
from verify_vm9_signer_objects import native, GUEST, STOP, LIBRARY_SHA256
from verify_vm9_libc_mapping import LIBC_SHA256, REGS
from verify_vm9_libc_cold_malloc import cstring
from verify_vm9_libc_arena_boot import put, get, LIBC

CONTINUE = GUEST + 0xF710
ENTRIES = {0x765B0, 0x7ED7C, 0x7EA48, 0x7EDC4, 0x7F600, 0x7E14C, 0x94E78, 0x7D998, 0x8E250, 0x79FA4, 0x787DC, 0x7779C, 0x772B0, 0x7DD70, 0x8DF44}


def case(library, libc, image, label, rtree=False, small=False, internal=False, cold_internal=False):
    p, seed = fresh(library, libc, image), fresh(library, libc, image)
    bits = 16 if label == "chunk16" else 20 if label == "chunk20" else 18
    for pages in (p, seed):
        put(pages, LIBC + 0xDB668, bits)
        if label == "map_failure_no_dss": put(pages, LIBC + 0xDB690, 0, 4)
    start = 0x13601000 if label == "misaligned" else 0x13600000
    os, nos = allocator.GuestOS(p, next_address=start), allocator.GuestOS(seed, next_address=start)
    observed = {(LIBC + 0xE67B8, 0x370): None, (LIBC + 0xE9110, 0xE60): None,
        (LIBC + 0xDB650, 0xF0): None, (LIBC + 0xDE840, 8): None,
        (WORKER_TLS, 0xB00): None, (TABLE, 141 * 16): None}
    n_calls, m_calls, results = [], [], []
    entry_counts = Counter()
    n_maps, m_maps = [0], [0]
    work = []
    requests = {"small8": [8], "small32": [32] * 3, "small48": [48], "unaligned_sizes": [1, 31, 127, 4095, 7169, 14335],
        "small128": [128] * 3, "small7168": [7168], "small14336": [14336],
        "bitmap_boundary": [8] * 65, "exhausted_slabs": [4096] * 3,
        "multiple_regions": [14336] * 40, "zero128": [128],
        "internal_accounting": [128, 128, 48], "internal_fresh": [128], "internal_preinit_map_failure": [128]}.get(label, [])
    zero = label == "zero128"
    keys = {"zero_key": [0], "low_key": [0x13640000], "high_key": [1 << 63],
        "overwrite": [0x13640000, 0x13640000], "neighbor_keys": [0x13640000, 0x13680000],
        "cross_root": [0x13640000, 1 << 48], "rtree_base_map_failure": [1 << 63]}.get(label, [])
    def failed(count): return (label in ("map_failure_no_dss", "rtree_base_map_failure") and count == 2) or (label == "internal_preinit_map_failure" and count == 1)
    def syscall(cpu, number):
        fields = [cpu.reg_read(reg) for reg in REGS]
        if number == 214:
            assert fields[0] == 0, "DSS break mutation is not supplied"
            n_calls.append(["brk", 0]); return 0x13600000
        if number == 222:
            n_calls.append(["mmap", *fields]); n_maps[0] += 1
            if failed(n_maps[0]): return -12
            record = nos.map_anonymous(fields[1], prot=fields[2], flags=fields[3], fd=fields[4], anonymous_name=b"")
            cpu.mem_map(record.base, record.length)
            observed.update({(k << 12, 4096): None for k in range(record.base >> 12, record.end >> 12)})
            return record.base
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
            m_maps[0] += 1; return -12 if failed(m_maps[0]) else tx.next_address
        if operation == "prctl": return -22 if label == "name_failure" else 0
        assert operation == "munmap"; return 0
    def brk(pages, target): m_calls.append(["brk", target]); return 0x13600000
    with libc.open("rb") as stream:
        symbols = ELFFile(stream).get_section_by_name(".dynsym")
        mutexes = {s.name: s["st_value"] for s in symbols.iter_symbols() if s.name in ("pthread_mutex_lock", "pthread_mutex_unlock")}
    def observe(cpu, pc):
        off = pc - LIBC
        if off in ENTRIES: entry_counts[off] += 1
        if off == 0x8E250:
            for a, n in ((TABLE, 141 * 16), (LIBC + 0xDB668, 8), (LIBC + 0xDB690, 4)):
                cpu.mem_write(a, allocator._read_span(seed, a, n))
    def continuation(cpu):
        results.append(cpu.reg_read(UC_ARM64_REG_X0))
        if len(results) == 1:
            if not cold_internal: assert results[0] == 0
            arena = int.from_bytes(cpu.mem_read(LIBC + 0xE6968, 8), "little")
            if cold_internal:
                work.extend((0x8DF44, [size, int(zero), 1]) for size in requests[1:])
            elif small:
                entry = 0x8DF44 if internal else 0x79FA4
                work.extend((entry, [size, int(zero), 1] if internal else [arena, size, int(zero)]) for size in requests)
            elif rtree:
                work.extend((0x7E14C, [key, GUEST + 0x6000 + i * 16]) for i, key in enumerate(keys))
            else:
                work.append((mutexes["pthread_mutex_lock"], [arena + 8]))
                work.extend((0x765B0, [arena]) for _ in range(2 if label == "two_regions" else 1))
                work.append((mutexes["pthread_mutex_unlock"], [arena + 8]))
        if small and (cold_internal or len(results) > 1):
            size = requests[len(results) - (1 if cold_internal else 2)]
            if results[-1]: cpu.mem_write(results[-1], bytes([0x5A]) * min(size, 64))
        if not work:
            cpu.reg_write(UC_ARM64_REG_PC, STOP); return None
        entry, args = work.pop(0)
        for reg, value in zip(REGS, args): cpu.reg_write(reg, value)
        cpu.reg_write(UC_ARM64_REG_X30, CONTINUE)
        cpu.reg_write(UC_ARM64_REG_PC, LIBC + entry)
        return None
    first_entry = 0x8DF44 if cold_internal else 0x8E250
    first_arguments = [requests[0], int(zero), 1] if cold_internal else []
    returned, memory, allocations, ledger = native(library, image, LIBC + first_entry - image, first_arguments,
        inputs(seed), libc=libc, real_mutexes=True, instruction_observer=observe,
        syscall_handler=syscall, host_imports={CONTINUE - image: continuation},
        extra_registers={UC_ARM64_REG_TPIDR_EL0: WORKER_TLS, UC_ARM64_REG_X30: CONTINUE},
        observed_memory=observed, instruction_limit=300000)
    assert not allocations and not ledger and returned == results[-1]
    import vm9_libc_region as model
    if cold_internal:
        actual = [model.allocate_internal_small(os, request_size=size, zero=zero, account=True,
            libc_base=LIBC, thread_pointer=WORKER_TLS, brk=brk, os_call=os_call) for size in requests]
        assert actual == results, (label, "cold internal entry", actual, results)
        for pointer, size in zip(actual, requests):
            if pointer: allocator._write_span(p, pointer, bytes([0x5A]) * min(size, 64))
    elif small:
        actual = model.preinit_with_small_allocations(os, requests=requests, zero=zero,
            account=internal, libc_base=LIBC, thread_pointer=WORKER_TLS, brk=brk, os_call=os_call)
        assert [0, *actual] == results, (label, "returned objects", actual, results)
        for pointer, size in zip(actual, requests):
            if pointer: allocator._write_span(p, pointer, bytes([0x5A]) * min(size, 64))
    elif rtree:
        references = [(key, GUEST + 0x6000 + i * 16) for i, key in enumerate(keys)]
        actual = model.preinit_with_chunk_references(os, references=references,
            libc_base=LIBC, thread_pointer=WORKER_TLS, brk=brk, os_call=os_call)
        assert [0, *actual] == results
    else:
        actual = model.preinit_with_initial_regions(os, region_count=2 if label == "two_regions" else 1,
            libc_base=LIBC, thread_pointer=WORKER_TLS, brk=brk, os_call=os_call)
        assert [0, 0, *actual, 0] == results, (label, "returned regions", actual, results)
    assert n_calls == m_calls, (label, "ordered OS calls", [(row[0], *row[2:3]) for row in n_calls], [(row[0], *row[2:3]) for row in m_calls])
    assert os.mappings == nos.mappings and os.next_address == nos.next_address, (label, "mapping metadata/cursor")
    assert allocator._read_span(p, GUEST, 0xA000) == memory
    for (address, width), value in observed.items():
        data = allocator._read_span(p, address, width)
        if data != value:
            differences = [(hex(address + i - LIBC), x, y) for i, (x, y) in enumerate(zip(data, value)) if x != y]
            raise AssertionError((label, "guest/global/TLS/owned mapping bytes", differences[:12]))
    assert entry_counts[0x8E250] == 1
    if rtree: assert entry_counts[0x7D998] >= 4
    if not rtree and not small and label != "map_failure_no_dss":
        assert entry_counts[0x765B0] == len(actual) and entry_counts[0x7E14C] == len(actual)
    return dict(case=label, image_base=hex(image), same_fresh_preinit_composed=True,
        rtree_reference_control=rtree, direct_small_allocation_control=small, internal_accounting_control=internal, actual_internal_fresh_entry=cold_internal, actual_base_allocator_used=True,
        return_guest_globals_tls_all_mapping_bytes_and_metadata_match=True,
        ordered_os_calls=len(m_calls), surviving_owned_mappings=len(os.mappings),
        actual_entry_counts={hex(k): v for k,v in sorted(entry_counts.items())},
        malloc_hook_calls=0, allocation_provider_used=False, native_input_snapshot_used=False,
        explicit_virtual_os=True, python_malloc_cold_boot_complete=False)



def rejection_cases(library, libc):
    import vm9_libc_region as model
    import vm9_libc_base as base
    import vm9_objects as objects
    results = []
    labels = ("spare_chunk", "unknown_callback", "primary_dss", "nonempty_cache",
        "contended_arena", "contended_cache", "secondary_dss_map_failure",
        "late_naming_failure", "pending_rtree", "registration_cleanup_failure",
        "rtree_unknown_callback", "rtree_invalid_key", "rtree_bad_geometry",
        "composed_late_naming_failure")
    for label in labels:
        pages = fresh(library, libc, 0x122C0000)
        os = allocator.GuestOS(pages)
        setup_calls, calls = [], []
        def setup_service(tx, op, *fields):
            setup_calls.append(op)
            return tx.next_address if op == "mmap" else 0
        if label != "composed_late_naming_failure":
            assert base.preinit_complete_with_base_allocator(os, libc_base=LIBC,
                thread_pointer=WORKER_TLS, brk=lambda *a: 0x13600000, os_call=setup_service) == 0
            arena = get(pages, LIBC + 0xE6968)
            objects.lock_uncontended_mutex(pages, mutex_address=arena + 8)
            if label == "spare_chunk": put(pages, arena + 0xC8, GUEST + 0x5000)
            if label == "unknown_callback": put(pages, arena + 0x4F0, 0)
            if label == "primary_dss": put(pages, arena + 0xC0, 1, 4)
            if label == "nonempty_cache":
                tree = allocator._AllocatorTree(pages, arena + 0x1F8, lambda node: node, link_offset=0x48)
                tree.insert(GUEST + 0x5000)
            if label == "contended_arena": put(pages, arena + 8, 0x10, 4)
            if label == "contended_cache": put(pages, arena + 0x498, 0x10, 4)
            if label == "pending_rtree": put(pages, LIBC + 0xE9F18, 1)
            if label == "registration_cleanup_failure":
                # Consume existing base space using an exact size class,
                # forcing the low-key radix node to need a new base mapping.
                while get(pages, get(pages, LIBC + 0xE67E8) + 0x10) >= 0x20000:
                    assert base.base_allocate(os, request_size=0x20000, libc_base=LIBC,
                        thread_pointer=WORKER_TLS, os_call=setup_service)
            if label == "rtree_unknown_callback": put(pages, LIBC + 0xE9ED0, 0)
            if label == "rtree_bad_geometry": put(pages, LIBC + 0xE9EE0, 0, 4)
        before = {k: bytes(v) for k,v in pages.items()}, list(os.mappings), os.next_address
        map_count, name_count = [0], [0]
        def service(tx, op, *fields):
            calls.append(op)
            if op == "mmap":
                map_count[0] += 1
                if label == "secondary_dss_map_failure" or label == "registration_cleanup_failure" and map_count[0] == 2:
                    return -12
                return tx.next_address
            if op == "prctl":
                name_count[0] += 1
                if label == "late_naming_failure" or label == "composed_late_naming_failure" and name_count[0] == 2:
                    raise allocator.RefillUnsupported("explicit OS naming provider failure")
                return 0
            assert op == "munmap"; return 0
        try:
            if label == "composed_late_naming_failure":
                model.preinit_with_initial_regions(os, region_count=1, libc_base=LIBC,
                    thread_pointer=WORKER_TLS, brk=lambda *a: 0x13600000, os_call=service)
            elif label.startswith("rtree_"):
                model.store_chunk_reference(os, key=-1 if label == "rtree_invalid_key" else 0x13640000,
                    value=GUEST + 0x6000, libc_base=LIBC, thread_pointer=WORKER_TLS, os_call=service)
            else:
                model.allocate_fresh_arena_region(os, arena_address=arena, libc_base=LIBC,
                    thread_pointer=WORKER_TLS, os_call=service)
        except (allocator.RefillUnsupported, ValueError): pass
        else: raise AssertionError((label, "must reject"))
        assert before == ({k: bytes(v) for k,v in pages.items()}, list(os.mappings), os.next_address), (label, "OS/page rollback")
        results.append(dict(case=label, rejected=True, guest_pages_records_and_cursor_unchanged=True,
            external_os_calls=len(calls), external_provider_effects_rolled_back=False))
    return results



def small_rejection_cases(library, libc):
    import vm9_libc_region as model
    import vm9_libc_base as base
    import vm9_objects as objects
    labels=("small_zero_request","small_large_request","small_junk_fill","small_contended_bin",
        "small_dirty_extent","small_bad_slab_class","small_bad_bitmap",
        "small_secondary_dss_map_failure","small_late_naming_failure",
        "internal_unknown_state","internal_missing_arena","internal_late_failure")
    results=[]
    for label in labels:
        pages=fresh(library,libc,0x122C0000)
        os=allocator.GuestOS(pages)
        def setup_service(tx,op,*fields):return tx.next_address if op=="mmap" else 0
        if label!="internal_late_failure":
            assert base.preinit_complete_with_base_allocator(os,libc_base=LIBC,
                thread_pointer=WORKER_TLS,brk=lambda *a:0x13600000,os_call=setup_service)==0
            arena=get(pages,LIBC+0xE6968)
            control=arena+0x508+2*0xE0
            if label=="small_junk_fill":put(pages,get(pages,LIBC+0xD8ED8),1,1)
            if label=="small_contended_bin":put(pages,control,0x10,4)
            if label=="small_dirty_extent":
                objects.lock_uncontended_mutex(pages,mutex_address=arena+8)
                region=model.allocate_fresh_arena_region(os,arena_address=arena,libc_base=LIBC,
                    thread_pointer=WORKER_TLS,os_call=setup_service)
                objects.unlock_uncontended_mutex(pages,mutex_address=arena+8)
                put(pages,region+0x68,get(pages,region+0x68)|8)
            if label in ("small_bad_slab_class","small_bad_bitmap"):
                assert model.allocate_arena_small(os,arena_address=arena,request_size=32,
                    libc_base=LIBC,thread_pointer=WORKER_TLS,os_call=setup_service)
                slab=get(pages,control+0x28)
                put(pages,slab,3,4) if label=="small_bad_slab_class" else put(pages,slab+8,0)
            if label=="internal_unknown_state":put(pages,LIBC+0xDB6A0,4,4)
            if label=="internal_missing_arena":put(pages,LIBC+0xE6968,0)
        before=({k:bytes(v) for k,v in pages.items()},list(os.mappings),os.next_address)
        calls=[];names=[0]
        def service(tx,op,*fields):
            calls.append(op)
            if op=="mmap":return -12 if label=="small_secondary_dss_map_failure" else tx.next_address
            if op=="prctl":
                names[0]+=1
                if label=="small_late_naming_failure" or label=="internal_late_failure" and names[0]==2:
                    raise allocator.RefillUnsupported("explicit small allocation OS provider failure")
                return 0
            assert op=="munmap";return 0
        try:
            if label.startswith("internal_"):
                model.allocate_internal_small(os,request_size=128,libc_base=LIBC,
                    thread_pointer=WORKER_TLS,brk=lambda *a:0x13600000,os_call=service)
            else:
                size=0 if label=="small_zero_request" else 0x4000 if label=="small_large_request" else 32
                model.allocate_arena_small(os,arena_address=arena,request_size=size,
                    libc_base=LIBC,thread_pointer=WORKER_TLS,os_call=service)
        except (allocator.RefillUnsupported,ValueError):pass
        else:raise AssertionError((label,"must reject"))
        assert before==({k:bytes(v) for k,v in pages.items()},list(os.mappings),os.next_address),(label,"rollback")
        results.append(dict(case=label,rejected=True,guest_pages_records_and_cursor_unchanged=True,
            external_os_calls=len(calls),external_provider_effects_rolled_back=False))
    return results


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--library",type=Path,required=True)
    ap.add_argument("--libc",type=Path,required=True)
    ap.add_argument("--output",type=Path,required=True)
    args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==LIBC_SHA256
    controls=[]
    for image in (0x122C0000,0x775C205000):
        for label in ("default","two_regions","chunk16","chunk20","misaligned","name_failure","map_failure_no_dss"):
            controls.append(case(args.library,args.libc,image,label))
            print("fresh arena region",hex(image),label,"PASS",flush=True)
        for label in ("zero_key","low_key","high_key","overwrite","neighbor_keys","cross_root","rtree_base_map_failure"):
            controls.append(case(args.library,args.libc,image,label,rtree=True))
            print("real rtree base allocation",hex(image),label,"PASS",flush=True)
    for image in (0x122C0000,0x775C205000):
        for label in ("small8","small32","small48","small128","small7168","small14336",
                "bitmap_boundary","exhausted_slabs","multiple_regions","zero128","internal_accounting","unaligned_sizes"):
            controls.append(case(args.library,args.libc,image,label,small=True,internal=label=="internal_accounting"))
            print("fresh direct small allocation",hex(image),label,"PASS",flush=True)
    for image in (0x122C0000,0x775C205000):
        for label in ("internal_fresh", "internal_preinit_map_failure"):
            controls.append(case(args.library,args.libc,image,label,small=True,internal=True,cold_internal=True))
            print("fresh internal small entry",hex(image),label,"PASS",flush=True)
    rejected=rejection_cases(args.library,args.libc)+small_rejection_cases(args.library,args.libc)
    report=dict(schema="vm9-libc-fresh-arena-region-v1",sample_sha256=LIBRARY_SHA256,
        libc_sha256=LIBC_SHA256,cases=controls,rejection_cases=rejected,python_malloc_cold_boot_complete=False,
        standalone_medusa_complete=False,current_online_header_matrix_verified=False,
        native_input_snapshot_used=False,default_fresh_arena_zero_region_restored=True,
        direct_clean_small_allocation_restored=True,positive_internal_small_entry_restored=True,
        public_malloc_tcache_complete=False,cpu_query_and_reentrant_public_malloc_restored=False)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(dict(native_controls=len(controls),rejected=len(rejected))))


if __name__=="__main__":main()
