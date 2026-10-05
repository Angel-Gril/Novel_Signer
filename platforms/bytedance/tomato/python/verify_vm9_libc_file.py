"""Fresh prefix/native controls for private recursive mutex and readonly FILE."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import vm9_allocator as allocator
import vm9_libc_stdio as stdio
import vm9_libc_file as model
import vm9_libc_base as base_model
from verify_vm9_libc_stdio import stdio_fresh, case, LOCK_CASE_LABELS, FILE_CASE_LABELS
from verify_vm9_libc_arena_boot import LIBC, put, get
from verify_vm9_thread_key_cleanup import WORKER_TLS
from verify_vm9_signer_objects import GUEST, LIBRARY_SHA256
from verify_vm9_libc_mapping import LIBC_SHA256


def rejection_cases(library, libc):
    labels = ("write_mode", "append_mode", "update_mode", "nul_mode", "oversized_mode", "nul_path",
        "oversized_path", "buffered_close", "auxiliary_close", "ungetc_close", "foreign_close_callback",
        "busy_recursive_mutex", "shared_recursive_mutex", "normal_recursive_mutex", "waiter_recursive_mutex",
        "missing_tid", "invalid_fd_result", "invalid_close_result", "late_open_provider_failure",
        "buffer_already_present", "buffer_foreign_callback", "buffer_character_stat", "buffer_bad_stat",
        "buffer_large_block", "buffer_negative_block", "buffer_bad_provider", "buffer_late_allocator_rejection")
    rows = []
    for label in labels:
        p = stdio_fresh(library, libc, 0x122C0000)
        os = allocator.GuestOS(p)
        def call(tx, operation, *args):
            if operation == "mmap": return tx.next_address
            if operation == "openat": return 53
            return 0
        assert base_model.cold_init_until_cpu_query(os, libc_base=LIBC, thread_pointer=WORKER_TLS,
            brk=lambda *args: 0x13600000, os_call=call) == 0x8E41C
        mode, path, external = b"r", b"/proc/stat", []
        close = label.endswith("close") or label in ("foreign_close_callback", "invalid_close_result")
        lock = "recursive_mutex" in label or label == "missing_tid"
        buffer = label.startswith("buffer_") and label != "buffered_close"
        file = 0
        if close or buffer:
            file = model.open_readonly_stdio_file(os, path=path, mode=mode, libc_base=LIBC, thread_pointer=WORKER_TLS, os_call=call)
            if label == "buffered_close": put(p, file + 0x18, GUEST + 0x3000)
            if label == "auxiliary_close": put(p, file + 0x78, GUEST + 0x3000)
            if label == "ungetc_close": put(p, get(p, file + 0x58), GUEST + 0x3000)
            if label == "foreign_close_callback": put(p, file + 0x38, GUEST + 0xF210)
        if buffer:
            if label == "buffer_already_present": put(p, file + 0x18, GUEST + 0x3000)
            if label == "buffer_foreign_callback": put(p, file + 0x48, GUEST + 0xF210)
            if label == "buffer_late_allocator_rejection": put(p, LIBC + 0xE69C0, 1)
            def call(tx, operation, *args):
                external.append(operation)
                assert operation == "fstat"
                if label == "buffer_bad_provider": return 0
                if label == "buffer_bad_stat": return (0, bytes(127))
                data = bytearray(128)
                data[16:20] = (0x2000 if label == "buffer_character_stat" else 0x8124).to_bytes(4, "little")
                size = 16384 if label == "buffer_large_block" else 0xFFFFFFFF if label == "buffer_negative_block" else 4096
                data[56:60] = size.to_bytes(4, "little")
                return (0, bytes(data))
        if lock:
            address = GUEST + 0x1000
            state, owner = {"busy_recursive_mutex": (0x4001,138), "shared_recursive_mutex": (0x6000,0),
                "normal_recursive_mutex": (0,0), "waiter_recursive_mutex": (0x4002,137)}.get(label,(0x4000,0))
            allocator._write_span(p,address,state.to_bytes(2,"little")+bytes(2)+owner.to_bytes(4,"little")+bytes(32))
            if label == "missing_tid": put(p,get(p,WORKER_TLS+8)+0x10,0,4)
        mode = {"write_mode": b"w", "append_mode": b"a", "update_mode": b"r+", "nul_mode": b"r\0", "oversized_mode": b"r"*65}.get(label,mode)
        path = {"nul_path": b"a\0", "oversized_path": b"a"*256}.get(label,path)
        if label in ("invalid_fd_result", "invalid_close_result", "late_open_provider_failure"):
            def call(tx, operation, *args):
                external.append(operation)
                if operation == "mmap": return tx.next_address
                if operation == "openat":
                    if label == "late_open_provider_failure": raise allocator.RefillUnsupported("explicit late open provider failure")
                    return 1 << 32
                if operation == "close": return 1
                return 0
        before = {k:bytes(v) for k,v in p.items()}
        records,cursor = list(os.mappings),os.next_address
        try:
            if lock: stdio.lock_recursive_mutex(p,mutex_address=address,thread_pointer=WORKER_TLS)
            elif buffer: model.create_readonly_stdio_buffer(os,file_address=file,libc_base=LIBC,thread_pointer=WORKER_TLS,os_call=call)
            elif close: model.close_unbuffered_stdio_file(os,file_address=file,libc_base=LIBC,thread_pointer=WORKER_TLS,os_call=call)
            else: model.open_readonly_stdio_file(os,path=path,mode=mode,libc_base=LIBC,thread_pointer=WORKER_TLS,os_call=call)
        except (allocator.RefillUnsupported,ValueError): pass
        else: raise AssertionError((label,"expected rejection"))
        assert before=={k:bytes(v) for k,v in p.items()} and records==os.mappings and cursor==os.next_address
        if label=="late_open_provider_failure": assert external==["mmap","mprotect","openat"]
        if label=="buffer_late_allocator_rejection": assert external==["fstat"]
        rows.append(dict(case=label,rejected=True,guest_pages_records_and_cursor_unchanged=True,
            external_provider_effects_not_rolled_back=bool(external)))
    return rows


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--library",type=Path,required=True); ap.add_argument("--libc",type=Path,required=True)
    ap.add_argument("--output",type=Path,required=True)
    ap.add_argument("--case",action="append",choices=LOCK_CASE_LABELS+FILE_CASE_LABELS)
    args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==LIBC_SHA256
    rows=[]
    for image in (0x122C0000,0x775C205000):
        for label in args.case or LOCK_CASE_LABELS+FILE_CASE_LABELS:
            rows.append(case(args.library,args.libc,image,label))
            print("fresh libc readonly FILE",hex(image),label,"PASS",flush=True)
    rejected=rejection_cases(args.library,args.libc)
    print("readonly FILE rejection/rollback",len(rejected),"PASS",flush=True)
    report=dict(schema="vm9-libc-fresh-readonly-file-v1",sample_sha256=LIBRARY_SHA256,libc_sha256=LIBC_SHA256,
        cases=rows,rejection_cases=rejected,full_case_set_verified=set(args.case or LOCK_CASE_LABELS+FILE_CASE_LABELS)==set(LOCK_CASE_LABELS+FILE_CASE_LABELS),
        native_input_snapshot_used=False,private_uncontended_recursive_lock_unlock_restored=set(LOCK_CASE_LABELS).issubset({c["case"] for c in rows}),
        readonly_open_and_unbuffered_close_restored={"open", "open_close"}.issubset({c["case"] for c in rows}),regular_file_buffer_constructor_restored=any(c["case"].startswith("buffer_") for c in rows),
        file_read_refill_and_cpu_parsing_restored=False,buffered_close_release_restored=False,
        dynamic_file_growth_restored=False,python_malloc_cold_boot_complete=False,
        standalone_medusa_complete=False,current_online_header_matrix_verified=False)
    args.output.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")


if __name__=="__main__": main()
