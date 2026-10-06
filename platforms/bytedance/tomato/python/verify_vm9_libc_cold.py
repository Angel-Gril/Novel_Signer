"""Fresh default malloc initializer, natural return, no frontier continuation."""
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path
from verify_vm9_libc_stdio import case,COLD_CASE_LABELS,FRESH_MALLOC_CASE_LABELS,cpu_fresh
import vm9_allocator as allocator
import vm9_libc_cold as model
from verify_vm9_libc_arena_boot import LIBC,put
from verify_vm9_thread_key_cleanup import WORKER_TLS
from verify_vm9_signer_objects import GUEST
from verify_vm9_signer_objects import LIBRARY_SHA256
from verify_vm9_libc_mapping import LIBC_SHA256


def rejection_cases(library,libc):
    labels=("cold_nonfresh","cold_owner_present","cold_atfork_busy","cold_stage_body_changed",
        "cold_guard_unresolved","cold_guard_mutated","cold_late_mmap_provider","cold_late_read_provider")
    rows=[]
    for label in labels:
        p=cpu_fresh(library,libc,0x122C0000);os=allocator.GuestOS(p)
        if label=="cold_nonfresh":put(p,LIBC+0xDB6A0,0,4)
        if label=="cold_owner_present":put(p,LIBC+0xE69B8,GUEST+0x1000)
        if label=="cold_atfork_busy":put(p,LIBC+0xDB380,0x4001,2);put(p,LIBC+0xDB384,138,4)
        if label=="cold_stage_body_changed":put(p,LIBC+0x933AC,0)
        if label=="cold_guard_unresolved":put(p,LIBC+0xD8DC8,0)
        external=[];maps=[0];cursor=[0]
        contents=b"cpu 0 0\ncpu0 0\ncpu1 0\n"
        def call(tx,op,*args):
            external.append(op)
            if op=="mmap":
                maps[0]+=1
                if label=="cold_late_mmap_provider" and maps[0]==2:raise allocator.RefillUnsupported("explicit late cold mmap failure")
                return tx.next_address
            if op=="openat":return 53
            if op=="fstat":
                data=bytearray(128);data[16:20]=(0x8124).to_bytes(4,"little");data[56:60]=(4096).to_bytes(4,"little")
                return (0,bytes(data))
            if op=="read":
                if label=="cold_late_read_provider":raise allocator.RefillUnsupported("explicit late cold read failure")
                if label=="cold_guard_mutated":put(tx.pages,LIBC+0xDE888,1)
                data=contents[cursor[0]:cursor[0]+args[1]];cursor[0]+=len(data)
                return (len(data),data)
            return 0
        before={k:bytes(v) for k,v in p.items()};records,start=list(os.mappings),os.next_address
        try:
            model.initialize_default_malloc(os,scratch_address=GUEST+0xED98,libc_base=LIBC,thread_pointer=WORKER_TLS,
                brk=lambda *args:external.append("brk") or 0x13600000,os_call=call)
        except (allocator.RefillUnsupported,ValueError):pass
        else:raise AssertionError((label,"expected rejection"))
        assert before=={k:bytes(v) for k,v in p.items()} and records==os.mappings and start==os.next_address
        if label=="cold_guard_mutated":assert cursor[0]==len(contents) and "close" in external
        rows.append(dict(case=label,rejected=True,guest_pages_records_and_cursor_unchanged=True,
            external_provider_effects_not_rolled_back=bool(external),ordered_external_calls=len(external)))
    return rows


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--library",type=Path,required=True);ap.add_argument("--libc",type=Path,required=True)
    ap.add_argument("--output",type=Path,required=True);ap.add_argument("--case",action="append",choices=COLD_CASE_LABELS+FRESH_MALLOC_CASE_LABELS)
    args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==LIBC_SHA256
    rows=[]
    for image in (0x122C0000,0x775C205000):
        for label in args.case or COLD_CASE_LABELS+FRESH_MALLOC_CASE_LABELS:
            rows.append(case(args.library,args.libc,image,label))
            print("fresh libc natural cold return",hex(image),label,"PASS",flush=True)
    rejected=rejection_cases(args.library,args.libc)
    print("natural cold return rejection/rollback",len(rejected),"PASS",flush=True)
    verified_labels={row["case"] for row in rows}
    report=dict(schema="vm9-libc-fresh-default-cold-return-v1",sample_sha256=LIBRARY_SHA256,libc_sha256=LIBC_SHA256,
        cases=rows,rejection_cases=rejected,full_case_set_verified=set(args.case or COLD_CASE_LABELS+FRESH_MALLOC_CASE_LABELS)==set(COLD_CASE_LABELS+FRESH_MALLOC_CASE_LABELS),
        native_input_snapshot_used=False,explicit_virtual_os=True,natural_default_cold_return_verified=all(row["natural_default_cold_return"] and row["natural_ready_flag_zero"] for row in rows),
        full_default_cold_matrix_verified=set(COLD_CASE_LABELS)<=verified_labels,
        full_fresh_public_small_matrix_verified=set(FRESH_MALLOC_CASE_LABELS)<=verified_labels,
        cold_frontier_continuation_used=False,ready_flag_fixture_applied=False,
        fresh_public_small_malloc_verified=any(c["fresh_public_small_malloc_control"] for c in rows),
        python_malloc_all_branches_complete=False,standalone_medusa_complete=False,current_online_header_matrix_verified=False)
    args.output.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")


if __name__=="__main__":main()
