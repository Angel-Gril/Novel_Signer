"""Same-fresh public allocation, cached small free and reuse native controls."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import vm9_allocator as allocator
import vm9_libc_base as base_model
import vm9_libc_tcache as model
from verify_vm9_thread_key_cleanup import fresh, WORKER_TLS
from verify_vm9_libc_arena_boot import LIBC, get, put
from verify_vm9_libc_tcache import case, LIBRARY_SHA256, LIBC_SHA256

ACTIONS = {
    "free_null": [("free", None)],
    "free128": [("allocate", 128), ("free", 0)],
    "free4096": [("allocate", 4096), ("free", 0)],
    "free_sizes": [("allocate", s) for s in (1,31,127,4095,7169,14335)] + [("free", i) for i in range(6)],
    "free_reuse": [("allocate", 128), ("free", 0), ("allocate", 128)],
    "free_zero": [("allocate", 128), ("free", 0), ("allocate", 128)],
    "free_multiple": [("allocate", 128)] * 4 + [("free", i) for i in (3,2,1,0)] + [("allocate", 128)] * 4,
    "free_state_two": [("allocate", 128), ("free", 0)],
}


def rejection_cases(library, libc):
    results = []
    for label in ("bad_pointer", "huge_pointer", "wrong_page_tag", "profiling", "direct_release",
        "free_junk", "full_bin", "corrupt_count", "duplicate", "gc", "missing_tsd", "interior_pointer", "never_issued_slot"):
        p = fresh(library, libc, 0x122C0000)
        os = allocator.GuestOS(p)
        assert base_model.cold_init_until_cpu_query(os, libc_base=LIBC, thread_pointer=WORKER_TLS,
            brk=lambda *args: 0x13600000, os_call=lambda tx,op,*args: tx.next_address if op=="mmap" else 0) == 0x8E41C
        pointer = model.allocate_public_small(os, request_size=128, libc_base=LIBC,
            thread_pointer=WORKER_TLS, os_call=lambda tx,op,*args: tx.next_address if op=="mmap" else 0)
        wrapper = LIBC + 0xDB6B8
        cache = get(p, wrapper + 0x10)
        target = cache + 8 * 32
        if label == "interior_pointer": pointer += 1
        if label == "never_issued_slot":
            arena = get(p, LIBC + 0xE6968)
            slab = get(p, arena + 0x508 + 8 * 0xE0 + 0x28)
            put(p, slab + 8, get(p, slab + 8) | 1)
        if label == "bad_pointer": pointer = -1
        if label == "huge_pointer": pointer &= ~get(p, LIBC + 0xE9EC0)
        if label == "wrong_page_tag":
            chunk = pointer & ~get(p, LIBC + 0xE9EC0)
            page = (pointer - chunk) >> 12
            put(p, chunk + 0x68 + (page-get(p, LIBC + 0xE9EB0))*8, 0)
        if label == "profiling": put(p, LIBC + 0xE69C0, 1)
        if label == "direct_release": put(p, wrapper + 0x10, 0)
        if label == "free_junk": put(p, LIBC + 0xE69CA, 1, 1)
        if label == "full_bin": put(p, target + 0x30, get(p, get(p, LIBC + 0xE9F50)+8*4, 4), 4)
        if label == "corrupt_count": put(p, target + 0x30, 0xFFFFFFFF, 4)
        if label == "duplicate": model.release_cached_small(os, pointer=pointer, libc_base=LIBC, thread_pointer=WORKER_TLS)
        if label == "gc": put(p, cache + 0x18, 227, 4)
        if label == "missing_tsd":
            key = get(p, LIBC + 0xE9F68, 4)
            assert allocator.pthread_setspecific(p, key=key, value=0, thread_pointer=WORKER_TLS,
                generation_table=LIBC + 0xE0200) == 0
        before = {k: bytes(v) for k,v in p.items()}
        records, cursor = list(os.mappings), os.next_address
        try:
            model.release_cached_small(os, pointer=pointer, libc_base=LIBC, thread_pointer=WORKER_TLS)
        except (allocator.RefillUnsupported, ValueError): pass
        else: raise AssertionError((label, "expected rejection"))
        assert before == {k: bytes(v) for k,v in p.items()}
        assert records == os.mappings and cursor == os.next_address
        results.append(dict(case=label, rejected=True, guest_pages_records_and_cursor_unchanged=True))
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--library", type=Path, required=True)
    ap.add_argument("--libc", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--case", action="append", choices=ACTIONS)
    args = ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest() == LIBC_SHA256
    cases = []
    for image in (0x122C0000, 0x775C205000):
        for label in args.case or ACTIONS:
            row = case(args.library, args.libc, image, label, free_actions=ACTIONS[label])
            row["defined_alloc_returns_guest_globals_tls_all_mapping_bytes_and_metadata_match"] = row.pop(
                "return_guest_globals_tls_all_mapping_bytes_and_metadata_match")
            cases.append(row)
            print("cached small free", hex(image), label, "PASS", flush=True)
    rejected = rejection_cases(args.library, args.libc)
    print("cached free rejection/rollback", len(rejected), "PASS", flush=True)
    report = dict(schema="vm9-libc-cached-small-free-v1", sample_sha256=LIBRARY_SHA256,
        libc_sha256=LIBC_SHA256, cases=cases, rejection_cases=rejected,
        native_input_snapshot_used=False, c_free_void_abi=True,
        bounded_cached_small_free_restored=any(c["case"] != "free_null" for c in cases),
        full_bin_flush_restored=False,
        direct_arena_release_restored=False, cpu_stdio_and_file_os_restored=False,
        python_malloc_cold_boot_complete=False, standalone_medusa_complete=False,
        current_online_header_matrix_verified=False)
    args.output.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")


if __name__ == "__main__":
    main()
