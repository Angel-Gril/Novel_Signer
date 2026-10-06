"""Native differential controls for fresh matching-libc emulated TLS.

Both runtimes start from ELF plus explicit descriptors/virtual OS. Native
outputs are expected bytes only and never initialize the Python runtime.
"""
from __future__ import annotations
from pathlib import Path
import argparse,json,hashlib,collections
import vm9_allocator as a,vm9_libc_emutls as model
import verify_vm9_worker_allocator as h,verify_vm9_libc_stdio as io
import verify_vm9_signer_objects as oracle
from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X30,UC_ARM64_REG_SP,UC_ARM64_REG_PC,UC_ARM64_REG_TPIDR_EL0

LABELS=('cold','repeat','aligned64','template','two_descriptors','two_threads','preassigned_index','destroy','destroy_two','destroy_aligned')
CONTROL=io.GUEST+0x8000
TEMPLATE=io.GUEST+0x8100


def prepare(p,label):
    size,align=(23,64) if label in ('aligned64','destroy_aligned') else (8,8)
    template=TEMPLATE if label=='template' else 0
    for address in (CONTROL,CONTROL+32):
        a._write_span(p,address,size.to_bytes(8,'little')+align.to_bytes(8,'little')+bytes(8)+template.to_bytes(8,'little'))
    a._write_span(p,TEMPLATE,b'example!')


def operations(label):
    worker=h.WORKERS[0]
    return [(worker,CONTROL),*(([(worker,CONTROL)] if label=='repeat' else
        [(worker,CONTROL+32)] if label in ('two_descriptors','preassigned_index','destroy_two') else
        [(h.WORKERS[1],CONTROL)] if label=='two_threads' else []))]


def case(library,libc,image,label):
    p=h.fresh(library,libc,image);prepare(p,label);seed={k:bytearray(v) for k,v in p.items()}
    me=h.Environment(p,2);ne=h.Environment(seed,2)
    observed=io.observed_spans();observed.update({(tls,0xB00):None for tls in h.WORKERS})
    observed.update({(CONTROL,64):None,(TEMPLATE,8):None})
    observed.update({(io.LIBC+0xDB380,0x48):None,(io.LIBC+0xD8DC8,8):None,(io.LIBC+0xDE888,8):None,(io.LIBC+0xE01C0,16):None})
    controls=[];results=[];destructors=[];events=[];model_events=[];mapped=[False];booted=[False];counts=collections.Counter();ops=operations(label)
    def observe(cpu,pc):
        if pc==image+0x347fd0 and not mapped[0]:
            mapped[0]=True
            for start,length in ((h.STACK,h.STACK_BYTES),*((tls,0x2000) for tls in h.WORKERS)):
                cpu.mem_map(start,length)
                for address in range(start,start+length,4096):cpu.mem_write(address,bytes(seed[address>>12]))
        if pc==io.LIBC+0x8e250 and not booted[0]:
            booted[0]=True;cpu.mem_write(io.TABLE,a._read_span(seed,io.TABLE,141*16))
        if pc-io.LIBC in (0x9be24,0x9bd10,0x9bd90,0x1baa0,0x1bb08,0x9bd3c):counts[pc-io.LIBC]+=1
    def syscall(cpu,number):
        if number==98:
            fields=[cpu.reg_read(reg) for reg in (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2)]
            assert fields[1:]==[129,0x7fffffff]
            events.append(fields);return 0
        return ne.syscall(cpu,number,observed)
    def continuation(cpu):
        results.append(cpu.reg_read(UC_ARM64_REG_X0))
        controls.append({span:bytes(cpu.mem_read(*span)) for span in observed})
        index=len(results)-1
        if index==len(ops):
            if label.startswith('destroy'):
                tls=ops[-1][0];key=int.from_bytes(cpu.mem_read(io.LIBC+0xE6AE8,4),'little')
                thread=int.from_bytes(cpu.mem_read(tls+8,8),'little')
                array=int.from_bytes(cpu.mem_read(thread+0xe8+(key&0x7fffffff)*16+8,8),'little')
                cpu.reg_write(UC_ARM64_REG_X0,array);cpu.reg_write(UC_ARM64_REG_PC,io.LIBC+0x9bd3c)
                return
            cpu.reg_write(UC_ARM64_REG_PC,io.STOP);return
        if index>len(ops):cpu.reg_write(UC_ARM64_REG_PC,io.STOP);return
        if label=='preassigned_index' and index==1:cpu.mem_write(CONTROL+32+16,(32).to_bytes(8,'little'))
        tls,descriptor=ops[index]
        cpu.reg_write(UC_ARM64_REG_TPIDR_EL0,tls);cpu.reg_write(UC_ARM64_REG_SP,h.TOP)
        cpu.reg_write(UC_ARM64_REG_X0,descriptor);cpu.reg_write(UC_ARM64_REG_X30,io.CONTINUE)
        cpu.reg_write(UC_ARM64_REG_PC,io.LIBC+0x9be24)
    inputs={k:v for k,v in io.inputs(seed).items() if not h.STACK<=k<<12<h.STACK+h.STACK_BYTES and not h.WORKERS[0]<=k<<12<h.WORKERS[-1]+0x2000}
    _,memory,allocations,_=oracle.native(library,image,0x347fd0,[48],inputs,libc=libc,real_malloc=True,real_mutexes=True,
        instruction_observer=observe,syscall_handler=syscall,host_imports={io.CONTINUE-image:continuation},observed_memory=observed,
        extra_registers={UC_ARM64_REG_SP:h.TOP,UC_ARM64_REG_X30:io.CONTINUE,UC_ARM64_REG_TPIDR_EL0:h.MAIN_TLS},instruction_limit=3000000)
    assert not allocations and len(results)==len(ops)+1+int(label.startswith('destroy'))
    actual=h.allocate(me,h.MAIN_TLS,48);assert actual==results[0]
    for (address,width),expected in controls[0].items():assert a._read_span(p,address,width)==expected,('main',hex(address))
    def wake(staged,*fields):model_events.append(list(fields));return 0
    for index,(tls,descriptor) in enumerate(ops):
        if label=='preassigned_index' and index==1:a._write_span(p,CONTROL+32+16,(32).to_bytes(8,'little'))
        actual=model.get_thread_variable(me.os,control_address=descriptor,libc_base=io.LIBC,
            thread_pointer=tls,scratch_address=h.SCRATCH,os_call=me.service,once_wake=wake)
        assert actual==results[index+1],('getter pointer',label,index,hex(actual),hex(results[index+1]),dict(counts))
        for (address,width),expected in controls[index+1].items():
            assert a._read_span(p,address,width)==expected,('getter bytes',label,index,hex(address))
    if label.startswith('destroy'):
        import vm9_libc_tcache as tcache
        tls=ops[-1][0]
        array=a.pthread_getspecific(p,key=io.get(p,io.LIBC+0xE6AE8,4),thread_pointer=tls,generation_table=io.TABLE)
        def free(staged,pointer):
            tcache._release_cached_small_pages(staged,pointer=pointer,libc_base=io.LIBC,thread_pointer=tls)
            destructors.append(pointer)
        model.destroy_array(p,array_address=array,free=free)
        for (address,width),expected in controls[-1].items():
            assert a._read_span(p,address,width)==expected,('libc array destructor bytes',label,hex(address))
        assert len(destructors)==len(ops)+1
    assert me.calls==ne.calls and me.os.mappings==ne.os.mappings and me.os.next_address==ne.os.next_address
    assert events==model_events and a._read_span(p,io.GUEST,0xA000)==memory
    if label=='repeat':assert results[1]==results[2]
    if label=='two_threads':assert results[1]!=results[2]
    if label=='aligned64':assert results[1]%64==0 and a._read_span(p,results[1],23)==bytes(23)
    if label=='template':assert a._read_span(p,results[1],8)==b'example!'
    return dict(case=label,image_base=hex(image),getter_returns=len(ops),native_entry_counts={hex(k):v for k,v in counts.items()},
        fresh_main_then_independent_worker_tls=True,all_observed_globals_tls_control_payload_and_owned_mapping_bytes_match_at_every_return=True,
        actual_allocator_used=True,actual_free_calls_compared=len(destructors),os_order_mappings_protection_cursor_and_once_wake_match=True,
        substituted_allocations=0,native_input_snapshot_used=False,explicit_virtual_os=True)


def rejection_cases(library,libc):
    image=0x122c0000;source=h.fresh(library,libc,image);prepare(source,'cold')
    env=h.Environment(source,2);h.allocate(env,h.MAIN_TLS,48)
    rows=[]
    for label in ('busy_once','busy_index_mutex','exhausted_keys','index_overflow',
            'late_bad_alignment','late_once_wake_failure','array_growth'):
        p={k:bytearray(v) for k,v in source.items()};e=h.Environment(p,2)
        e.os.mappings=list(env.os.mappings);e.os.next_address=env.os.next_address
        descriptor=CONTROL;events=[]
        if label=='array_growth':
            model.get_thread_variable(e.os,control_address=CONTROL,libc_base=io.LIBC,
                thread_pointer=h.WORKERS[0],scratch_address=h.SCRATCH,os_call=e.service,once_wake=lambda *args:0)
            descriptor=CONTROL+32;a._write_span(p,descriptor+16,(34).to_bytes(8,'little'))
        elif label=='busy_once':a._write_span(p,io.LIBC+0xE6AEC,(1).to_bytes(4,'little'))
        elif label=='busy_index_mutex':a._write_span(p,io.LIBC+0xE6AF0,(1).to_bytes(4,'little'))
        elif label=='exhausted_keys':
            for i in range(141):a._write_span(p,io.TABLE+i*16,(1).to_bytes(8,'little'))
        elif label=='index_overflow':a._write_span(p,io.LIBC+0xE6B18,(model.MAX_SLOTS).to_bytes(8,'little'))
        elif label=='late_bad_alignment':a._write_span(p,descriptor+8,(3).to_bytes(8,'little'))
        before={k:bytes(v) for k,v in p.items()};records=list(e.os.mappings);cursor=e.os.next_address
        def wake(staged,*fields):events.append(fields);return -4 if label=='late_once_wake_failure' else 0
        try:model.get_thread_variable(e.os,control_address=descriptor,libc_base=io.LIBC,
            thread_pointer=h.WORKERS[0],scratch_address=h.SCRATCH,os_call=e.service,once_wake=wake)
        except (a.RefillUnsupported,ValueError):pass
        else:raise AssertionError((label,'expected rejection'))
        assert before=={k:bytes(v) for k,v in p.items()} and records==e.os.mappings and cursor==e.os.next_address
        if label in ('busy_index_mutex','index_overflow','late_bad_alignment','late_once_wake_failure'):assert events
        rows.append(dict(case=label,rejected=True,all_guest_pages_owned_mappings_and_cursor_unchanged=True,
            external_once_wake_effects_not_rolled_back=bool(events)))
    # The actual free provider updates its own staging chain before a late
    # failure; the array destructor must still roll back every guest byte.
    model.get_thread_variable(env.os,control_address=CONTROL,libc_base=io.LIBC,
        thread_pointer=h.WORKERS[0],scratch_address=h.SCRATCH,os_call=env.service,once_wake=lambda *args:0)
    array=a.pthread_getspecific(source,key=io.get(source,io.LIBC+0xE6AE8,4),thread_pointer=h.WORKERS[0],generation_table=io.TABLE)
    import vm9_libc_tcache as tcache
    for label in ('array_capacity_overflow','late_array_free_failure'):
        p={k:bytearray(v) for k,v in source.items()};events=[]
        if label=='array_capacity_overflow':a._write_span(p,array,(model.MAX_SLOTS+1).to_bytes(8,'little'))
        before={k:bytes(v) for k,v in p.items()}
        def free(staged,pointer):
            tcache._release_cached_small_pages(staged,pointer=pointer,libc_base=io.LIBC,thread_pointer=h.WORKERS[0])
            events.append(pointer)
            if len(events)==2:raise a.RefillUnsupported('late explicit free failure')
        try:model.destroy_array(p,array_address=array,free=free)
        except a.RefillUnsupported:pass
        else:raise AssertionError((label,'expected rejection'))
        assert before=={k:bytes(v) for k,v in p.items()}
        if label.startswith('late_'):assert len(events)==2
        rows.append(dict(case=label,rejected=True,all_guest_pages_unchanged=True,
            actual_staged_free_calls_before_rejection=len(events)))
    return rows


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--libc',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--case',action='append',choices=LABELS);args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==h.LIBC_SHA256
    rows=[]
    for image in (0x122c0000,0x775c205000):
        for label in args.case or LABELS:
            rows.append(case(args.library,args.libc,image,label));print('matching libc emutls',hex(image),label,'PASS',flush=True)
    rejected=rejection_cases(args.library,args.libc)
    args.output.write_text(json.dumps(dict(schema='vm9-libc-fresh-emutls-getter-v1',sample_sha256=oracle.LIBRARY_SHA256,
        libc_sha256=h.LIBC_SHA256,cases=rows,rejection_cases=rejected,
        emutls_array_destructor_with_actual_free_verified=any(c['actual_free_calls_compared'] for c in rows),
        complete_pthread_exit_verified=False,complete_python_medusa=False,native_input_snapshot_used=False),indent=2)+'\n',encoding='utf-8')

    print('libc emutls',len(rows),'native /',len(rejected),'rollback PASS',flush=True)


if __name__=='__main__':main()
