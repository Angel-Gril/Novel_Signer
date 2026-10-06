"""Same-fresh native controls for bounded empty-cache large allocation."""
from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path
import vm9_allocator as allocator
import vm9_libc_cold as model
from vm9_libc_boot import _u, _w, _indirect
from verify_vm9_libc_stdio import case, cpu_fresh, LARGE_MALLOC_CASE_LABELS, LIBC, GUEST, WORKER_TLS
from vm9_libc_tcache import _current_tsd
from verify_vm9_signer_objects import LIBRARY_SHA256
from verify_vm9_libc_mapping import LIBC_SHA256


def rejection_cases(library, libc):
    rows=[]
    for label in ("large_small_request", "large_negative_request", "large_over_limit", "large_nonempty_cache",
                  "large_gc_event", "large_junk_option", "large_zero_option", "large_profiling"):
        p=cpu_fresh(library,libc,0x122C0000)
        os=allocator.GuestOS(p)
        cursor=[0]
        contents=b"cpu 0 0\ncpu0 0\ncpu1 0\n"
        def service(tx, op, *args):
            if op=="mmap":return tx.next_address
            if op=="openat":return 53
            if op=="fstat":
                data=bytearray(128);data[16:20]=(0x8124).to_bytes(4,"little");data[56:60]=(4096).to_bytes(4,"little")
                return (0,bytes(data))
            if op=="read":
                data=contents[cursor[0]:cursor[0]+args[1]];cursor[0]+=len(data)
                return (len(data),data)
            return 0
        assert model.initialize_default_malloc(os,scratch_address=GUEST+0xED98,libc_base=LIBC,
            thread_pointer=WORKER_TLS,brk=lambda *args:0x13600000,os_call=service)==0
        # Rejections modify only explicit synthetic branch input after natural boot.
        wrapper=_current_tsd(p,LIBC,WORKER_TLS)
        cache=_u(p,wrapper+0x10)
        size={"large_small_request":32,"large_negative_request":-1,"large_over_limit":65537}.get(label,16384)
        if label=="large_nonempty_cache":_w(p,cache+36*32+0x30,1,4)
        if label=="large_gc_event":_w(p,cache+0x18,227,4)
        if label=="large_junk_option":_w(p,_indirect(p,LIBC,0xD8ED8),1,1)
        if label=="large_zero_option":_w(p,_indirect(p,LIBC,0xD8EF0),1,1)
        if label=="large_profiling":_w(p,LIBC+0xE69C0,1)
        before={key:bytes(value) for key,value in p.items()}
        records,start=list(os.mappings),os.next_address
        try:
            model.allocate_default_large(os,request_size=size,scratch_address=GUEST+0xED98,
                libc_base=LIBC,thread_pointer=WORKER_TLS,brk=lambda *args:0x13600000,os_call=service)
        except allocator.RefillUnsupported:pass
        else:raise AssertionError((label,"must reject"))
        assert before=={key:bytes(value) for key,value in p.items()} and records==os.mappings and start==os.next_address
        rows.append(dict(case=label,rejected=True,guest_pages_records_and_cursor_unchanged=True,
            natural_default_cold_return_preceded_rejection=True))
    return rows


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--library",type=Path,required=True);ap.add_argument("--libc",type=Path,required=True)
    ap.add_argument("--output",type=Path,required=True)
    ap.add_argument("--case",action="append",choices=LARGE_MALLOC_CASE_LABELS)
    args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==LIBC_SHA256
    rows=[]
    for image in (0x122C0000,0x775C205000):
        for label in args.case or LARGE_MALLOC_CASE_LABELS:
            rows.append(case(args.library,args.libc,image,label))
            print("fresh public large",hex(image),label,"PASS",flush=True)
    rejected=rejection_cases(args.library,args.libc)
    print("large rejection/rollback",len(rejected),"PASS",flush=True)
    report=dict(schema="vm9-libc-fresh-public-large-v1",sample_sha256=LIBRARY_SHA256,libc_sha256=LIBC_SHA256,
        cases=rows,rejection_cases=rejected,full_case_set_verified=set(args.case or LARGE_MALLOC_CASE_LABELS)==set(LARGE_MALLOC_CASE_LABELS),
        native_input_snapshot_used=False,allocation_provider_used=False,explicit_virtual_os=True,
        bounded_empty_cache_large_verified=True,default_initialization_task_allocator_composed=False,
        python_malloc_all_branches_complete=False,standalone_medusa_complete=False,current_online_header_matrix_verified=False)
    args.output.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")


if __name__=="__main__":main()
