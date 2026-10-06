"""Same fresh startup/worker/actual allocator through joinable guest pthread_exit.

Native code and Python start independently. All caller and key-return states,
actual purge calls and final guest state compare; no snapshot seeds Python.
"""
from __future__ import annotations
from pathlib import Path
import argparse,json,hashlib,os
import vm9_allocator as a,vm9_libc_exit as model
import verify_vm9_worker_allocator as h,verify_vm9_libc_stdio as io,verify_vm9_signer_objects as oracle
from verify_vm9_startup_worker_allocator import case
from verify_vm9_startup_worker_exit_allocator import fresh_worker


def rejection_cases(library,libc,vm_module):
    image=0x122c0000;source=fresh_worker(library,libc,image,vm_module);rows=[]
    saved={k:bytes(v) for k,v in source.os.pages.items()}
    for label in ('busy_libc_emutls_mutex','unknown_cleanup_handler','late_first_purge_failure',
            'late_second_purge_failure','late_unknown_key_destructor','late_terminal_exit_failure'):
        p={k:bytearray(v) for k,v in saved.items()};env=h.Environment(p,2)
        env.os.mappings=list(source.os.mappings);env.os.next_address=source.os.next_address
        tls=h.WORKERS[0];thread=io.get(p,tls+8);events=[];wakes=[]
        if label=='busy_libc_emutls_mutex':a._write_span(p,io.LIBC+0xE6AF0,(1).to_bytes(4,'little'))
        elif label=='unknown_cleanup_handler':
            node=io.GUEST+0x8000
            a._write_span(p,node,bytes(8)+(io.LIBC+0x9BD40).to_bytes(8,'little')+bytes(8))
            a._write_span(p,thread+0x58,node.to_bytes(8,'little'))
        elif label=='late_unknown_key_destructor':
            index=140;entry=io.TABLE+index*16;slot=thread+0xe8+index*16
            a._write_span(p,entry,(1).to_bytes(8,'little')+(io.LIBC+0x99588).to_bytes(8,'little'))
            a._write_span(p,slot,(1).to_bytes(8,'little')+(io.GUEST+0x8000).to_bytes(8,'little'))
        before={k:bytes(v) for k,v in p.items()};records=list(env.os.mappings);cursor=env.os.next_address
        def wake(staged,*fields):wakes.append(fields);return 0
        def service(staged,operation,*fields):
            if operation=='madvise':
                events.append((operation,*fields))
                if label=='late_first_purge_failure' or label=='late_second_purge_failure' and len(events)==2:return -12
                return 0
            if operation=='exit':
                events.append((operation,*fields))
                if label=='late_terminal_exit_failure':raise a.RefillUnsupported('late explicit terminal service failure')
                return 0
            return env.service(staged,operation,*fields)
        try:model.run_worker_pthread_exit(env.os,image_base=image,libc_base=io.LIBC,
            thread_pointer=tls,return_value=9,scratch_address=h.SCRATCH,os_call=service,once_wake=wake)
        except (a.RefillUnsupported,ValueError):pass
        else:raise AssertionError((label,'expected rejection'))
        assert before=={k:bytes(v) for k,v in p.items()} and records==env.os.mappings and cursor==env.os.next_address
        assert wakes
        if label=='late_first_purge_failure':assert len(events)==1
        elif label in ('late_second_purge_failure','late_unknown_key_destructor'):assert len(events)==2
        elif label=='late_terminal_exit_failure':assert [x[0] for x in events]==['madvise','madvise','exit']
        else:assert not events
        rows.append(dict(case=label,rejected=True,all_guest_pages_owned_mappings_and_cursor_unchanged=True,
            completed_madvise_provider_calls_before_rejection=sum(e[0]=='madvise' for e in events),
            terminal_provider_called_before_rejection=any(e[0]=='exit' for e in events),external_provider_effects_not_rolled_back=True))
        print('actual allocator pthread exit rejection',label,'PASS',flush=True)
    return rows


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--libc',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==h.LIBC_SHA256
    os.environ['TOMATO_LIBMETASEC']=str(args.library.resolve())
    import vm_full
    initial=vm_full.B
    rows=[case(args.library,args.libc,image,vm_full,pthread_exit=True) for image in (0x122c0000,0x775c205000)]
    rejected=rejection_cases(args.library,args.libc,vm_full)
    assert vm_full.B==initial
    report=dict(schema='vm9-same-startup-worker-actual-allocator-pthread-exit-v1',sample_sha256=oracle.LIBRARY_SHA256,
        libc_sha256=h.LIBC_SHA256,cases=rows,rejection_cases=rejected,full_joinable_guest_pthread_exit_composed=True,
        actual_libc_emutls_getter_and_array_destructor_composed=True,actual_small_empty_extent_release_and_purge_composed=True,
        actual_detached_worker_and_region_reclaim_composed=False,allocator_all_branches_restored=False,
        actual_os_thread_creation_and_termination_verified=False,explicit_successful_advisory_madvise=True,
        native_input_snapshot_used=False,complete_python_medusa=False,current_online_header_matrix_verified=False)
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print('same startup worker actual allocator pthread exit',len(rows),'native /',len(rejected),'rollback PASS',flush=True)


if __name__=='__main__':main()
