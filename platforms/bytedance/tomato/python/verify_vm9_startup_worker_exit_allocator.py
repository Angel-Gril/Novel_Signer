"""Fresh main startup -> worker -> actual allocator/support key cleanup.

Matching ELF code is an expected-result oracle. Python starts independently
from ELF and explicit descriptors/virtual OS. No native pages seed Python.
"""
from __future__ import annotations
import argparse,hashlib,json,os
from pathlib import Path
import vm9_allocator as a,vm9_libc_exit as model
import verify_vm9_worker_allocator as h,verify_vm9_libc_stdio as io
import verify_vm9_root_configuration as root,verify_vm9_signer_objects as oracle
import vm9_startup_allocator as startup
from verify_vm9_startup_worker_allocator import case
from verify_vm9_default_task_prefix import fresh as task_fresh


def fresh_worker(library,libc,image,vm_module):
    p=h.fresh(library,libc,image);stack=io.GUEST+0x60000
    for address in range(stack,stack+0x10000,4096):p[address>>12]=bytearray(4096)
    for key,value in task_fresh(library,libc,image,0).items():
        if image<=key<<12<image+0x400000:p[key]=bytearray(value)
    env=h.Environment(p,2);threads=[]
    def create(staged,out,attr,entry,arg):
        handle=io.GUEST+0xc800+len(threads)*0x100
        a._write_span(staged,out,handle.to_bytes(8,'little'));threads.append([handle,entry,arg]);return 0
    startup.initialize_main_startup(env.os,entry_stack_address=h.TOP,return_address=oracle.STOP,
        thread_pointer=root.TLS,image_base=image,vm_module=vm_module,scratch_address=h.SCRATCH,
        libc_base=io.LIBC,brk=env.brk,os_call=env.service,create_thread=create,
        register_destructor=lambda *args:0,thread_id=137,
        signal_condition=lambda staged,address:__import__('vm9_startup').signal_condition_no_waiters(
            staged,condition_address=address,wake=lambda *args:0))
    queue=io.get(p,threads[1][2]+0x18)
    def wait(staged,address,op,expected,timeout):
        a._write_span(staged,queue+0x88,b'\0');return -4
    startup.run_default_queue_worker(env.os,argument_address=threads[1][2],image_base=image,
        entry_stack_address=stack+0xf000,thread_pointer=h.WORKERS[0],thread_id=271,
        vm_module=vm_module,scratch_address=h.SCRATCH,libc_base=io.LIBC,brk=env.brk,
        os_call=env.service,broadcast=lambda *args:0,clock=lambda *args:(1000,1234),futex=wait)
    return env


def rejection_cases(library,libc,vm_module):
    image=0x122c0000;source=fresh_worker(library,libc,image,vm_module);rows=[]
    saved={k:bytes(v) for k,v in source.os.pages.items()}
    for label in ('busy_cache_ring_mutex','cache_count_overflow','nonempty_large_cache',
            'late_unknown_key_destructor','late_corrupt_support_vector'):
        p={k:bytearray(v) for k,v in saved.items()};env=h.Environment(p,2)
        env.os.mappings=list(source.os.mappings);env.os.next_address=source.os.next_address
        tls=h.WORKERS[0];key=io.get(p,io.LIBC+0xE9F68,4)
        wrapper=a.pthread_getspecific(p,key=key,thread_pointer=tls,generation_table=io.TABLE)
        cache=io.get(p,wrapper+0x10);arena=io.get(p,wrapper+0x30)
        if label=='busy_cache_ring_mutex':a._write_span(p,arena+8,(1).to_bytes(4,'little'))
        elif label=='cache_count_overflow':a._write_span(p,cache+0x30,(0xffffffff).to_bytes(4,'little'))
        elif label=='nonempty_large_cache':a._write_span(p,cache+36*32+0x30,(1).to_bytes(4,'little'))
        elif label=='late_unknown_key_destructor':
            index=140;entry=io.TABLE+index*16;slot=io.get(p,tls+8)+0xe8+index*16
            a._write_span(p,entry,(1).to_bytes(8,'little')+(io.LIBC+0x99588).to_bytes(8,'little'))
            a._write_span(p,slot,(1).to_bytes(8,'little')+(io.GUEST+0x8000).to_bytes(8,'little'))
        else:
            support_key=io.get(p,image+0x3E2F30,4)
            support_wrapper=a.pthread_getspecific(p,key=support_key,thread_pointer=tls,generation_table=io.TABLE)
            support=io.get(p,support_wrapper)
            a._write_span(p,support+8,(io.get(p,support)+1).to_bytes(8,'little'))
        before={k:bytes(v) for k,v in p.items()};records=list(env.os.mappings);cursor=env.os.next_address
        frees=[];original=model._internal_free
        def counted(staged,pointer,base):
            original(staged,pointer,base);frees.append(pointer)
        model._internal_free=counted
        try:
            try:model.cleanup_worker_thread_keys(env.os,image_base=image,thread_pointer=tls,
                libc_base=io.LIBC,scratch_address=h.SCRATCH,os_call=env.service)
            except (a.RefillUnsupported,ValueError):pass
            else:raise AssertionError((label,'expected rejection'))
        finally:model._internal_free=original
        assert before=={k:bytes(v) for k,v in p.items()}
        assert records==env.os.mappings and cursor==env.os.next_address
        if label.startswith('late_'):assert len(frees)>=3,(label,'did not reach late cleanup')
        if label=='nonempty_large_cache':assert len(frees)==0
        rows.append(dict(case=label,rejected=True,all_guest_pages_owned_mappings_and_cursor_unchanged=True,
            completed_actual_internal_frees_before_rejection=len(frees),external_provider_effects_not_rolled_back=True))
        print('actual worker TLS exit rejection',label,'PASS',flush=True)
    return rows


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--libc',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==h.LIBC_SHA256
    os.environ['TOMATO_LIBMETASEC']=str(args.library.resolve())
    import vm_full
    initial=vm_full.B
    rows=[case(args.library,args.libc,image,vm_full,tls_exit=True) for image in (0x122c0000,0x775c205000)]
    rejected=rejection_cases(args.library,args.libc,vm_full)
    assert vm_full.B==initial
    report=dict(schema='vm9-same-startup-worker-actual-allocator-tls-exit-v1',
        sample_sha256=oracle.LIBRARY_SHA256,libc_sha256=h.LIBC_SHA256,cases=rows,rejection_cases=rejected,
        actual_allocator_and_support_key_exit_composed=True,full_pthread_exit_verified=False,
        empty_slab_extent_release_restored=False,nonempty_large_cache_cleanup_restored=False,
        allocator_all_branches_restored=False,native_input_snapshot_used=False,
        explicit_virtual_os=True,complete_python_medusa=False,current_online_header_matrix_verified=False)
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print('same startup worker actual allocator TLS exit',len(rows),'native /',len(rejected),'rollback PASS',flush=True)


if __name__=='__main__':main()
