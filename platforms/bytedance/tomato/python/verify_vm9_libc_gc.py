"""Fresh actual-allocator differential controls for small-cursor tcache GC."""
from __future__ import annotations
from pathlib import Path
import argparse,collections,hashlib,json
import vm9_allocator as a,vm9_libc_exit as model,vm9_libc_tcache as cache_owner
import vm9_libc_release as release
from vm9_libc_boot import _u,_w
import verify_vm9_worker_allocator as h,verify_vm9_libc_stdio as io,verify_vm9_signer_objects as oracle
from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X30,UC_ARM64_REG_SP,UC_ARM64_REG_PC,UC_ARM64_REG_TPIDR_EL0

PROFILES={'negative_floor':(-1,1,8),'negative_adapt':(-1,3,8),'zero':(0,1,8),
    'positive_one':(1,1,8),'positive_two':(2,1,8),'positive_all':(3,1,8),
    'positive_fill_limit':(2,3,8),'positive_variable_shift':(2,31,8),
    'cursor35':(0,1,35),'cursor_wrap':(0,1,35),
    'malloc_trigger':(2,1,8),'free_trigger':(-1,1,8),
    'root_free_trigger':(-1,1,0),'large_trigger':(-1,1,8)}


def control(read,write,label):
    thread=read(h.MAIN_TLS+8,8);key=read(io.LIBC+0xE9F68,4)&0x7FFFFFFF
    wrapper=read(thread+0xE8+key*16+8,8);cache=read(wrapper+0x10,8)
    assert wrapper and cache
    low,fill,index=PROFILES[label]
    write(cache+0x18,227 if label.endswith('trigger') else 228,4)
    write(cache+0x1C,index,4);write(cache+index*32+0x28,low&0xFFFFFFFF,4)
    write(cache+index*32+0x2C,fill,4)
    if label=='cursor_wrap':write(io.LIBC+0xE9F48,36,8)
    return wrapper,cache


def collect(p,tsd,cache,environment):
    def extent(staged,arena,slab,dirty,force_clean,constants):
        return release.release_empty_small_extent(staged,arena,slab,dirty,force_clean,constants,
            libc_base=io.LIBC,os_call=environment.service)
    return model._collect_small_cache(p,tsd,cache,libc_base=io.LIBC,release_extent=extent)


def case(library,libc,image,label):
    p=h.fresh(library,libc,image);seed={k:bytearray(v) for k,v in p.items()}
    me=h.Environment(p,2);ne=h.Environment(seed,2);expected=[];results=[];mapped=[False];booted=[False];counts=collections.Counter()
    observed=io.observed_spans();observed.update({(tls,0xB00):None for tls in h.WORKERS})
    observed.update({(io.LIBC+0xDB380,40):None,(io.LIBC+0xD8DC8,8):None,(io.LIBC+0xDE888,8):None,(io.LIBC+0xE01C0,16):None})
    def observe(cpu,pc):
        if pc-io.LIBC in (0x9833C,0x97F40,0x7B024):counts[pc-io.LIBC]+=1
        if pc==image+0x347FD0 and not mapped[0]:
            mapped[0]=True
            for start,length in ((h.STACK,h.STACK_BYTES),*((tls,0x2000) for tls in h.WORKERS)):
                cpu.mem_map(start,length)
                for address in range(start,start+length,4096):cpu.mem_write(address,bytes(seed[address>>12]))
        if pc==io.LIBC+0x8E250 and not booted[0]:
            booted[0]=True;cpu.mem_write(io.TABLE,a._read_span(seed,io.TABLE,141*16))
    def continuation(cpu):
        results.append(cpu.reg_read(UC_ARM64_REG_X0));expected.append({span:bytes(cpu.mem_read(*span)) for span in observed})
        if len(results)==2:cpu.reg_write(UC_ARM64_REG_PC,io.STOP);return
        read=lambda address,width:int.from_bytes(cpu.mem_read(address,width),'little')
        write=lambda address,value,width:cpu.mem_write(address,value.to_bytes(width,'little'))
        wrapper,cache=control(read,write,label)
        if label in ('malloc_trigger','large_trigger'):
            cpu.reg_write(UC_ARM64_REG_X0,16384 if label=='large_trigger' else 128)
            cpu.reg_write(UC_ARM64_REG_PC,image+0x347FD0)
        elif label in ('free_trigger','root_free_trigger'):
            cpu.reg_write(UC_ARM64_REG_X0,results[0]);cpu.reg_write(UC_ARM64_REG_PC,io.LIBC+0x1BAC0)
        else:
            cpu.reg_write(UC_ARM64_REG_X0,wrapper+8);cpu.reg_write(UC_ARM64_REG_X1,cache)
            cpu.reg_write(UC_ARM64_REG_PC,io.LIBC+0x9833C)
        cpu.reg_write(UC_ARM64_REG_X30,io.CONTINUE)
    initial={k:v for k,v in io.inputs(seed).items()
        if not h.STACK<=k<<12<h.STACK+h.STACK_BYTES and not h.WORKERS[0]<=k<<12<h.WORKERS[-1]+0x2000}
    _,memory,substitutions,_=oracle.native(library,image,0x347FD0,[128],initial,libc=libc,
        real_malloc=True,real_mutexes=True,instruction_observer=observe,observed_memory=observed,
        syscall_handler=lambda cpu,number:ne.syscall(cpu,number,observed),host_imports={io.CONTINUE-image:continuation},
        extra_registers={UC_ARM64_REG_SP:h.TOP,UC_ARM64_REG_TPIDR_EL0:h.MAIN_TLS,UC_ARM64_REG_X30:io.CONTINUE},instruction_limit=3000000)
    assert not substitutions and len(expected)==2 and counts[0x9833C]==1
    pointer=h.allocate(me,h.MAIN_TLS,128);assert pointer==results[0]
    for (address,width),data in expected[0].items():assert a._read_span(p,address,width)==data,('boot',hex(address))
    wrapper,cache=control(lambda address,width:int.from_bytes(a._read_span(p,address,width),'little'),lambda address,value,width:_w(p,address,value,width),label)
    tx=me.os.begin()
    callback=lambda staged,tsd,value:collect(staged,tsd,value,me)
    if label in ('malloc_trigger','large_trigger'):
        operation=cache_owner._public_large if label=='large_trigger' else cache_owner._public_small
        value=operation(tx,request_size=16384 if label=='large_trigger' else 128,libc_base=io.LIBC,
            thread_pointer=h.MAIN_TLS,os_call=me.service,scratch_address=h.SCRATCH,collect_cache=callback)
        assert value==results[1]
    elif label in ('free_trigger','root_free_trigger'):
        model._free_in_exit(tx,tx.pages,pointer,libc_base=io.LIBC,thread_pointer=h.MAIN_TLS,
            scratch_address=h.SCRATCH,os_call=me.service,collect_cache=callback)
    else:collect(tx.pages,wrapper+8,cache,me)
    tx.commit()
    differences=[hex(address) for (address,width),data in expected[1].items() if a._read_span(p,address,width)!=data]
    assert not differences,(label,differences)
    assert a._read_span(p,io.GUEST,0xA000)==memory
    assert me.calls==ne.calls and me.os.mappings==ne.os.mappings and me.os.next_address==ne.os.next_address
    return dict(case=label,image_base=hex(image),native_gc_calls=counts[0x9833C],native_small_flush_calls=counts[0x97F40],
        native_slab_returns=counts[0x7B024],all_observed_tls_globals_and_retained_mapping_bytes_match_at_each_return=True,
        guest_bytes_os_order_mapping_records_protection_and_cursor_match=True,
        final_gc_cursor=_u(p,cache+0x1C,4),final_event_counter=_u(p,cache+0x18,4),
        actual_allocator_from_fresh_elf=True,native_input_snapshot_used=False,substituted_allocations=0)


def rejection_cases(library,libc):
    source=h.fresh(library,libc,0x122C0000);environment=h.Environment(source,2)
    h.allocate(environment,h.MAIN_TLS,128)
    wrapper,cache=control(lambda address,width:int.from_bytes(a._read_span(source,address,width),'little'),
        lambda address,value,width:_w(source,address,value,width),'positive_all')
    target=cache+8*32;vector=_u(source,target+0x38)
    rows=[]
    for label in ('large_cursor','out_of_range_cursor','corrupt_count','low_exceeds_count','invalid_fill','busy_bin_mutex','late_duplicate_slot','late_slot_failure'):
        p={k:bytearray(v) for k,v in source.items()};env=h.Environment(p,2)
        env.os.mappings=list(environment.os.mappings);env.os.next_address=environment.os.next_address
        if label=='large_cursor':_w(p,cache+0x1C,36,4)
        elif label=='out_of_range_cursor':_w(p,cache+0x1C,45,4)
        elif label=='corrupt_count':_w(p,target+0x30,9,4)
        elif label=='low_exceeds_count':_w(p,target+0x28,4,4)
        elif label=='invalid_fill':_w(p,target+0x2C,32,4)
        elif label=='busy_bin_mutex':
            arena,_,_=model._small_slot(p,_u(p,vector),io.LIBC);_w(p,arena+0x508+8*0xE0,1,4)
        elif label=='late_duplicate_slot':_w(p,vector+16,_u(p,vector))
        before={k:bytes(v) for k,v in p.items()};records=list(env.os.mappings);cursor=env.os.next_address;returned=[]
        original=a._return_slab_slot
        def trace(*args,**kwargs):
            value=original(*args,**kwargs);returned.append(1)
            if label=='late_slot_failure':raise a.RefillUnsupported('late GC slot provider failure')
            return value
        a._return_slab_slot=trace
        try:
            tx=env.os.begin()
            try:collect(tx.pages,wrapper+8,cache,env);tx.commit()
            except (a.RefillUnsupported,ValueError):pass
            else:raise AssertionError((label,'expected rejection'))
        finally:a._return_slab_slot=original
        assert before=={k:bytes(v) for k,v in p.items()} and records==env.os.mappings and cursor==env.os.next_address
        if label.startswith('late_'):assert returned
        rows.append(dict(case=label,rejected=True,guest_pages_owned_mappings_and_cursor_unchanged=True,
            actual_slab_returns_before_rejection=len(returned)))
    return rows


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--libc',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--case',action='append',choices=PROFILES);args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==h.LIBC_SHA256
    rows=[]
    for image in (0x122C0000,0x775C205000):
        for label in args.case or PROFILES:
            rows.append(case(args.library,args.libc,image,label));print('small GC',hex(image),label,'PASS',flush=True)
    rejected=rejection_cases(args.library,args.libc)
    report=dict(schema='vm9-libc-small-gc-v1',sample_sha256=oracle.LIBRARY_SHA256,libc_sha256=h.LIBC_SHA256,
        cases=rows,rejection_cases=rejected,small_gc_owner_restored=True,large_cursor_gc_restored=False,
        native_input_snapshot_used=False,complete_python_medusa=False,current_online_header_matrix_verified=False)
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print('small GC',len(rows),'native /',len(rejected),'rollback PASS',flush=True)


if __name__=='__main__':main()
