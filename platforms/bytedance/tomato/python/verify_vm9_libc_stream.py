"""Fresh matching-libc readonly line reading and allocated buffer release."""
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path
from verify_vm9_libc_stdio import case,STREAM_CASE_LABELS,stdio_fresh
import vm9_allocator as allocator
import vm9_libc_base as base_model
import vm9_libc_file as model
from verify_vm9_libc_arena_boot import LIBC,put,get
from verify_vm9_signer_objects import GUEST
from verify_vm9_thread_key_cleanup import WORKER_TLS
from verify_vm9_signer_objects import LIBRARY_SHA256
from verify_vm9_libc_mapping import LIBC_SHA256


def rejection_cases(library,libc):
    labels=("read_count_mismatch","read_bad_data","read_oversized","read_bad_tuple","read_eintr_budget",
        "read_foreign_callback","read_zero_size","fgets_bad_size","fgets_large_size","fgets_bad_output",
        "fgets_busy_mutex","refill_ungetc","refill_nonread","refill_flush","close_busy_mutex",
        "close_full_bin","close_profiling","late_close_provider_failure","late_read_provider_failure")
    rows=[]
    for label in labels:
        p=stdio_fresh(library,libc,0x122C0000);os=allocator.GuestOS(p)
        external=[]
        def call(tx,op,*args):
            external.append(op)
            if op=="mmap":return tx.next_address
            if op=="openat":return 53
            if op=="fstat":
                data=bytearray(128);data[16:20]=(0x8124).to_bytes(4,"little");data[56:60]=(4096).to_bytes(4,"little")
                return (0,bytes(data))
            if op=="read":return (2,b"a\n")
            return 0
        assert base_model.cold_init_until_cpu_query(os,libc_base=LIBC,thread_pointer=WORKER_TLS,
            brk=lambda *args:0x13600000,os_call=call)==0x8E41C
        file=model.open_readonly_stdio_file(os,path=b"/proc/stat",libc_base=LIBC,thread_pointer=WORKER_TLS,os_call=call)
        model.create_readonly_stdio_buffer(os,file_address=file,libc_base=LIBC,thread_pointer=WORKER_TLS,os_call=call)
        close=label.startswith("close_") or label=="late_close_provider_failure"
        if close:model.fgets_stdio_line(os,file_address=file,output_address=GUEST+0x5000,size=256,libc_base=LIBC,thread_pointer=WORKER_TLS,os_call=call)
        size,out=256,GUEST+0x5000
        if label=="fgets_bad_size":size="bad"
        if label=="fgets_large_size":size=65537
        if label=="fgets_bad_output":out=0xDEAD0000
        if label in ("fgets_busy_mutex","close_busy_mutex"):
            mutex=get(p,file+0x58)+0x38;put(p,mutex,0x4001,2);put(p,mutex+4,138,4)
        if label=="read_foreign_callback":put(p,file+0x40,GUEST+0xF210)
        if label=="read_zero_size":put(p,file+0x20,0)
        if label=="refill_ungetc":put(p,get(p,file+0x58),GUEST+0x1000)
        if label=="refill_nonread":put(p,file+0x10,8,4)
        if label=="refill_flush":put(p,file+0x10,6,4)
        if label=="close_profiling":put(p,LIBC+0xE69C0,1)
        if label=="close_full_bin":put(p,get(p,LIBC+0xDB6B8+0x10)+28*32+0x30,0xFFFFFFFF,4)
        original_call=call
        def failing_call(tx,op,*args):
            if op=="read":
                external.append(op)
                if label=="late_read_provider_failure":raise allocator.RefillUnsupported("explicit late read failure")
                if label=="read_count_mismatch":return (2,b"a")
                if label=="read_bad_data":return (1,None)
                if label=="read_oversized":return (args[1]+1,b"x"*(args[1]+1))
                if label=="read_bad_tuple":return 0
                if label=="read_eintr_budget":return (-4,None)
                return (2,b"a\n")
            if op=="close" and label=="late_close_provider_failure":
                external.append(op);raise allocator.RefillUnsupported("explicit late close failure")
            return original_call(tx,op,*args)
        external.clear()
        before={k:bytes(v) for k,v in p.items()};records,cursor=list(os.mappings),os.next_address
        try:
            if close:model.close_readonly_stdio_file(os,file_address=file,libc_base=LIBC,thread_pointer=WORKER_TLS,os_call=failing_call)
            else:model.fgets_stdio_line(os,file_address=file,output_address=out,size=size,libc_base=LIBC,thread_pointer=WORKER_TLS,os_call=failing_call)
        except (allocator.RefillUnsupported,ValueError):pass
        else:raise AssertionError((label,"expected rejection"))
        assert before=={k:bytes(v) for k,v in p.items()} and records==os.mappings and cursor==os.next_address
        if label in ("close_full_bin","close_profiling","late_close_provider_failure"):assert external==["close"],(label,external)
        if label=="read_eintr_budget":assert external==["read"]*16
        rows.append(dict(case=label,rejected=True,guest_pages_records_and_cursor_unchanged=True,external_provider_effects_not_rolled_back=bool(external)))
    return rows


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--library",type=Path,required=True);ap.add_argument("--libc",type=Path,required=True)
    ap.add_argument("--output",type=Path,required=True)
    ap.add_argument("--case",action="append",choices=STREAM_CASE_LABELS)
    args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==LIBC_SHA256
    rows=[]
    for image in (0x122C0000,0x775C205000):
        for label in args.case or STREAM_CASE_LABELS:
            rows.append(case(args.library,args.libc,image,label))
            print("fresh libc readonly stream",hex(image),label,"PASS",flush=True)
    rejected=rejection_cases(args.library,args.libc)
    print("readonly stream rejection/rollback",len(rejected),"PASS",flush=True)
    report=dict(schema="vm9-libc-fresh-readonly-stream-v1",sample_sha256=LIBRARY_SHA256,libc_sha256=LIBC_SHA256,
        cases=rows,rejection_cases=rejected,full_case_set_verified=set(args.case or STREAM_CASE_LABELS)==set(STREAM_CASE_LABELS),
        native_input_snapshot_used=False,readonly_fgets_refill_read_restored=True,
        allocated_buffer_close_release_restored=True,python_malloc_cold_boot_complete=False,
        standalone_medusa_complete=False,current_online_header_matrix_verified=False)
    args.output.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")


if __name__=="__main__":main()
