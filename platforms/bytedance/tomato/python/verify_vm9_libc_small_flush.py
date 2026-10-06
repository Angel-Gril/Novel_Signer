"""Fresh matching-libc C free through half-cache small-bin flush.

Native output is compared only; Python starts independently from ELF/TLS/OS.
The shared +0x97f40 owner is also used by allocator TSD destruction.
"""
from __future__ import annotations
from pathlib import Path
import argparse,collections,hashlib,json
import vm9_allocator as a,vm9_libc_exit as model
from vm9_libc_boot import _u,_w
import verify_vm9_worker_allocator as h,verify_vm9_libc_stdio as io
import verify_vm9_signer_objects as oracle
from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X30,UC_ARM64_REG_SP,UC_ARM64_REG_PC,UC_ARM64_REG_TPIDR_EL0

LABELS=('class32','class128','class256','reuse','three_flushes','foreign_only','foreign_mixed')


def operations(label):
    first,second=h.WORKERS[:2];size={'class128':128,'class256':256}.get(label,32)
    ops=[('malloc',h.MAIN_TLS,48)]
    if label.startswith('foreign'):
        ops += [('malloc',first,32)]*12+[('malloc',second,32)]*12
        indices=list(range(1,9)) if label=='foreign_only' else [i for pair in zip(range(1,5),range(13,17)) for i in pair]
        return ops+[('free',second,i) for i in indices]+[('free',second,17)]
    count=20 if label=='three_flushes' else 12
    ops += [('malloc',first,size)]*count+[('free',first,i) for i in range(1,count+1)]
    if label=='reuse':ops += [('malloc',first,size)]*6
    return ops


def free(environment,tls,pointer):
    return model.release_small_with_flush(environment.os,pointer=pointer,libc_base=io.LIBC,
        thread_pointer=tls,scratch_address=h.SCRATCH,os_call=environment.service)


def case(library,libc,image,label):
    p=h.fresh(library,libc,image);seed={k:bytearray(v) for k,v in p.items()}
    me=h.Environment(p,2);ne=h.Environment(seed,2);ops=operations(label)
    observed=io.observed_spans();observed.update({(tls,0xB00):None for tls in h.WORKERS})
    observed.update({(io.LIBC+0xD8DC8,8):None,(io.LIBC+0xDE888,8):None,
        (io.LIBC+0xDB380,40):None,(io.LIBC+0xE01C0,16):None})
    expected=[];native_allocations=[];counts=collections.Counter();mapped=[False];booted=[False]
    def observe(cpu,pc):
        if pc-io.LIBC in (0x97F40,0x7B024):counts[pc-io.LIBC]+=1
        if pc==image+0x347FD0 and not mapped[0]:
            mapped[0]=True
            for start,length in ((h.STACK,h.STACK_BYTES),*((tls,0x2000) for tls in h.WORKERS)):
                cpu.mem_map(start,length)
                for address in range(start,start+length,4096):cpu.mem_write(address,bytes(seed[address>>12]))
        if pc==io.LIBC+0x8E250 and not booted[0]:
            booted[0]=True;cpu.mem_write(io.TABLE,a._read_span(seed,io.TABLE,141*16))
    def continuation(cpu):
        index=len(expected);operation,tls,value=ops[index]
        if operation=='malloc':native_allocations.append(cpu.reg_read(UC_ARM64_REG_X0))
        expected.append({span:bytes(cpu.mem_read(*span)) for span in observed})
        if len(expected)==len(ops):cpu.reg_write(UC_ARM64_REG_PC,io.STOP);return
        operation,tls,value=ops[len(expected)]
        cpu.reg_write(UC_ARM64_REG_X0,value if operation=='malloc' else native_allocations[value])
        cpu.reg_write(UC_ARM64_REG_SP,h.TOP);cpu.reg_write(UC_ARM64_REG_TPIDR_EL0,tls)
        cpu.reg_write(UC_ARM64_REG_X30,io.CONTINUE)
        cpu.reg_write(UC_ARM64_REG_PC,image+0x347FD0 if operation=='malloc' else io.LIBC+0x1BAC0)
    initial={k:v for k,v in io.inputs(seed).items()
        if not h.STACK<=k<<12<h.STACK+h.STACK_BYTES and not h.WORKERS[0]<=k<<12<h.WORKERS[-1]+0x2000}
    _,memory,substitutions,_=oracle.native(library,image,0x347FD0,[48],initial,libc=libc,
        real_malloc=True,real_mutexes=True,instruction_observer=observe,
        syscall_handler=lambda cpu,number:ne.syscall(cpu,number,observed),
        host_imports={io.CONTINUE-image:continuation},observed_memory=observed,
        extra_registers={UC_ARM64_REG_SP:h.TOP,UC_ARM64_REG_TPIDR_EL0:h.MAIN_TLS,UC_ARM64_REG_X30:io.CONTINUE},instruction_limit=4000000)
    assert not substitutions and len(expected)==len(ops) and counts[0x97F40]>0
    actual=[]
    for index,(operation,tls,value) in enumerate(ops):
        if operation=='malloc':
            actual.append(h.allocate(me,tls,value));assert actual[-1]==native_allocations[len(actual)-1]
        else:free(me,tls,actual[value])
        differences=[hex(address) for (address,width),data in expected[index].items() if a._read_span(p,address,width)!=data]
        assert not differences,(label,index,operation,differences)
    assert a._read_span(p,io.GUEST,0xA000)==memory
    assert me.calls==ne.calls and me.os.mappings==ne.os.mappings and me.os.next_address==ne.os.next_address
    return dict(case=label,image_base=hex(image),actual_malloc_returns=len(actual),actual_free_calls=sum(op[0]=='free' for op in ops),
        native_small_bin_flush_calls=counts[0x97F40],native_small_slab_returns=counts[0x7B024],
        all_observed_globals_tls_and_retained_mapping_bytes_match_at_every_return=True,
        final_guest_bytes_os_order_mappings_protection_and_cursor_match=True,
        actual_allocator_from_fresh_elf=True,native_input_snapshot_used=False,substituted_allocations=0,
        c_free_void_abi=True,foreign_arena_cache_control=label.startswith('foreign'))


def rejection_cases(library,libc):
    image=0x122C0000;source=h.fresh(library,libc,image);environment=h.Environment(source,2)
    h.allocate(environment,h.MAIN_TLS,48);tls=h.WORKERS[0]
    pointers=[h.allocate(environment,tls,32) for _ in range(12)]
    for pointer in pointers[:8]:free(environment,tls,pointer)
    tsd=model._current_tsd(source,io.LIBC,tls);cache=_u(source,tsd+0x10)
    arena,class_id,_=model._small_slot(source,pointers[8],io.LIBC)
    target=cache+class_id*32;vector=_u(source,target+0x38)
    assert _u(source,target+0x30,4)==8
    rows=[]
    for label in ('busy_bin_mutex','corrupt_count','wrong_cached_class','full_cache_duplicate','late_duplicate_cached_slot','late_gc_event','late_slot_provider_failure'):
        p={k:bytearray(v) for k,v in source.items()};env=h.Environment(p,2)
        env.os.mappings=list(environment.os.mappings);env.os.next_address=environment.os.next_address
        if label=='busy_bin_mutex':_w(p,arena+0x508+class_id*0xE0,1,4)
        elif label=='corrupt_count':_w(p,target+0x30,9,4)
        elif label=='wrong_cached_class':
            # This live allocation has another class; no invalid raw address is fabricated.
            other=h.allocate(env,tls,128);_w(p,vector,other)
        elif label=='late_duplicate_cached_slot':_w(p,vector+24,_u(p,vector))
        elif label=='late_gc_event':_w(p,cache+0x18,227,4)
        victim=pointers[0] if label=='full_cache_duplicate' else pointers[8]
        before={k:bytes(v) for k,v in p.items()};records=list(env.os.mappings);cursor=env.os.next_address
        original=a._return_slab_slot;returned=[]
        def trace(*args,**kwargs):
            result=original(*args,**kwargs);returned.append(1)
            if label=='late_slot_provider_failure' and len(returned)==3:raise a.RefillUnsupported('late explicit slot provider failure')
            return result
        a._return_slab_slot=trace
        try:
            try:free(env,tls,victim)
            except (a.RefillUnsupported,ValueError):pass
            else:raise AssertionError((label,'expected rejection'))
        finally:a._return_slab_slot=original
        assert before=={k:bytes(v) for k,v in p.items()} and records==env.os.mappings and cursor==env.os.next_address
        if label.startswith('late_'):assert len(returned)>=3
        rows.append(dict(case=label,rejected=True,guest_pages_owned_mappings_and_cursor_unchanged=True,
            completed_actual_slab_returns_before_rejection=len(returned)))
    return rows


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--libc',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--case',action='append',choices=LABELS);args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==h.LIBC_SHA256
    rows=[]
    for image in (0x122C0000,0x775C205000):
        for label in args.case or LABELS:
            rows.append(case(args.library,args.libc,image,label));print('fresh small flush',hex(image),label,'PASS',flush=True)
    rejected=rejection_cases(args.library,args.libc)
    report=dict(schema='vm9-libc-fresh-small-cache-flush-v1',sample_sha256=oracle.LIBRARY_SHA256,
        libc_sha256=h.LIBC_SHA256,cases=rows,rejection_cases=rejected,
        shared_exit_and_public_small_flush_owner=True,native_input_snapshot_used=False,
        tcache_gc_restored=False,complete_root_actual_allocator_verified=False,
        complete_python_medusa=False,current_online_header_matrix_verified=False)
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print('small flush',len(rows),'native /',len(rejected),'rollback PASS',flush=True)


if __name__=='__main__':main()
