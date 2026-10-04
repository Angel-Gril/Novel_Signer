"""Same fresh startup, independent worker TLS, idle dispatch and cleanup.

The native scheduler selects a startup-generated idle worker; Python generates
its own descriptors from ELF inputs. The default nonempty queue is untouched.
OS thread-exit destructors and real allocator boot remain separate boundaries.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn.arm64_const import UC_ARM64_REG_PC,UC_ARM64_REG_SP,UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X30,UC_ARM64_REG_TPIDR_EL0
import os
import vm9_startup as startup
import vm9_objects as objects
import vm9_allocator as allocator
import verify_vm9_startup_init as fixture
import verify_vm9_root_configuration as root
from verify_vm9_signer_objects import native,GUEST,STOP,LIBRARY_SHA256

WORKER_TLS=GUEST+0xD000


def put(p,a,v,n=8):allocator._write_span(p,a,(v&((1<<(8*n))-1)).to_bytes(n,'little'))
def get(p,a,n=8):return int.from_bytes(allocator._read_span(p,a,n),'little')


def inputs(library,libc,base,thread_id):
    p=fixture.fresh_inputs(library,libc,base)
    put(p,WORKER_TLS+8,WORKER_TLS+0x200)
    allocator._write_span(p,WORKER_TLS+0x200,bytes(0x900))
    put(p,WORKER_TLS+0x210,thread_id,4)
    put(p,WORKER_TLS+0x10,37,4)
    return p


def probe(library,libc,exports,*,base,kind,thread_id):
    model=inputs(library,libc,base,thread_id)
    seed=inputs(library,libc,base,thread_id)
    oracle={p:v for p,v in seed.items() if not root.LIBC_BASE<=p<<12<root.LIBC_BASE+0x400000}
    table=root.LIBC_BASE+root.LIBC_PTHREAD_GENERATION_OFFSET
    observed={(root.TLS,0xB00):None,(WORKER_TLS,0xB00):None,(table,141*16):None}
    observed.update({(p<<12,4096):None for p in model if base<=p<<12<base+0x400000})
    events=[];actual_events=[];threads=[];model_threads=[];allocations=[];model_allocations=[]
    switched=[False];worker_arg=[None];worker_context=[None];worker_waits=[0];model_waits=[0]
    selected=0 if kind=='executor' else 2
    def read(cpu,a,n=8):return int.from_bytes(cpu.mem_read(a,n),'little')
    def write(cpu,a,v,n=8):cpu.mem_write(a,(v&((1<<(8*n))-1)).to_bytes(n,'little'))
    def create(cpu):
        values=[cpu.reg_read(r) for r in (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3)]
        assert values[1]==0
        handle=GUEST+0xC800+len(threads)*0x100;write(cpu,values[0],handle)
        threads.append([handle,*values[2:]]);events.append(['thread_create',*values,handle]);return 0
    def register(cpu):
        events.append(['register',*[cpu.reg_read(r) for r in (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2)]]);return 0
    def allocation(cpu,size,pointer):allocations.append([size,pointer]);events.append(['allocate',size,pointer])
    def free(cpu):events.append(['free',cpu.reg_read(UC_ARM64_REG_X0)]);return 0
    def redirect(name,record=True):
        def effect(cpu):
            if record:events.append([name])
            cpu.reg_write(UC_ARM64_REG_PC,exports[name])
        return effect
    def clock(cpu):
        clock_id=cpu.reg_read(UC_ARM64_REG_X0);value=(1000,1234)
        events.append(['clock',clock_id,*value])
        cpu.mem_write(cpu.reg_read(UC_ARM64_REG_X1),b''.join(v.to_bytes(8,'little') for v in value));return 0
    def syscall(cpu,number):
        if number==113:return clock(cpu)
        assert number==98,number
        address=cpu.reg_read(UC_ARM64_REG_X0);op=cpu.reg_read(UC_ARM64_REG_X1);expected=cpu.reg_read(UC_ARM64_REG_X2)
        if op&0x7f==1:events.append(['wake',address,op,expected]);return 0
        assert switched[0]
        pointer=cpu.reg_read(UC_ARM64_REG_X3)
        timeout=None if not pointer else [read(cpu,pointer+i*8) for i in range(2)]
        events.append(['wait',address,op,expected,timeout,-4]);worker_waits[0]+=1
        if kind=='executor':
            ctx=worker_context[0];assert address==ctx+0xb0 and read(cpu,ctx+0x88,2)==0
            write(cpu,ctx+0x80,0,1);write(cpu,ctx+0x84,1,4)
        else:
            q=worker_context[0];assert address==q+0x58 and read(cpu,q+0x30,2)==0
            write(cpu,q+0x88,0,1)
        return -4
    def observe(cpu,address):
        if address!=base+0x280478 or switched[0]:return
        switched[0]=True;_,entry,arg=threads[selected];worker_arg[0]=arg
        owner=read(cpu,arg+8);worker_context[0]=read(cpu,owner+8) if kind=='executor' else read(cpu,arg+0x18)
        cpu.reg_write(UC_ARM64_REG_PC,entry);cpu.reg_write(UC_ARM64_REG_X0,arg)
        cpu.reg_write(UC_ARM64_REG_X30,STOP);cpu.reg_write(UC_ARM64_REG_SP,GUEST+0xEF00)
        cpu.reg_write(UC_ARM64_REG_TPIDR_EL0,WORKER_TLS)
    result,memory,_,_=native(library,base,0x28040c,[],oracle,libc=libc,real_singletons=True,
        real_mutexes=True,thread_id=thread_id,extra_registers={UC_ARM64_REG_TPIDR_EL0:root.TLS},
        host_imports={0x348000:create,0x347ea0:register,0x347fa0:free,0x348450:clock,
            0x348590:redirect('pthread_cond_signal',False),0x348620:redirect('pthread_key_create'),
            0x348580:redirect('pthread_setspecific'),0x3485d0:redirect('pthread_getspecific'),
            0x3486b0:redirect('pthread_once',False),0x3485b0:redirect('pthread_cond_wait',False),
            0x3485c0:redirect('pthread_cond_timedwait',False)},instruction_observer=observe,
        syscall_handler=syscall,allocation_effect=allocation,observed_memory=observed,instruction_limit=1000000)
    assert switched[0] and result==0 and worker_waits[0]==1
    position=GUEST+0x4000
    def allocate(p,size):
        nonlocal position
        pointer=position;position+=(size+15)&~15
        if position>=GUEST+0x9000:raise allocator.RefillUnsupported('bounded startup arena exhausted')
        allocator._read_span(p,pointer,size);model_allocations.append([size,pointer]);actual_events.append(['allocate',size,pointer]);return pointer
    def create_thread(p,out,attr,entry,arg):
        handle=GUEST+0xC800+len(model_threads)*0x100;put(p,out,handle)
        model_threads.append([handle,entry,arg]);actual_events.append(['thread_create',out,attr,entry,arg,handle]);return 0
    def model_register(p,*args):actual_events.append(['register',*args]);return 0
    def wake(p,*args):actual_events.append(['wake',*args]);return 0
    def key(p,address,destructor):
        actual_events.append(['pthread_key_create'])
        return allocator.pthread_key_create(p,key_address=address,destructor=destructor,generation_table=table)
    def specific(p,key,value):
        actual_events.append(['pthread_setspecific'])
        return allocator.pthread_setspecific(p,key=key,value=value,thread_pointer=WORKER_TLS,generation_table=table)
    def get_specific(p,key):
        actual_events.append(['pthread_getspecific'])
        return allocator.pthread_getspecific(p,key=key,thread_pointer=WORKER_TLS,generation_table=table)
    def get_tls(p,descriptor):
        return objects.get_emulated_tls_address(p,control_address=descriptor,image_base=base,allocate=allocate,
            reallocate=lambda *a:(_ for _ in ()).throw(allocator.RefillUnsupported('unexpected TLS growth')),
            get_specific=get_specific,set_specific=specific,create_key=key,once_wake=wake)
    def model_clock(p,clock_id):actual_events.append(['clock',clock_id,1000,1234]);return (1000,1234)
    def model_free(p,pointer):actual_events.append(['free',pointer])
    startup.initialize_startup_caller(model,entry_stack_address=GUEST+0xEF00,return_address=STOP,
        thread_pointer=root.TLS,image_base=base,vm_module=vm_full,allocate=allocate,create_thread=create_thread,
        register_destructor=model_register,thread_id=thread_id,
        signal_condition=lambda p,address:startup.signal_condition_no_waiters(p,condition_address=address,wake=wake))
    _,entry,arg=model_threads[selected]
    assert arg==worker_arg[0]
    wrapper=get(model,arg);owner=get(model,arg+8)
    ctx=get(model,owner+8) if kind=='executor' else get(model,arg+0x18)
    def futex(p,address,op,expected,timeout):
        actual_events.append(['wait',address,op,expected,None if timeout is None else list(timeout),-4]);model_waits[0]+=1
        if kind=='executor':
            assert address==ctx+0xb0 and get(p,ctx+0x88,2)==0
            put(p,ctx+0x80,0,1);put(p,ctx+0x84,1,4)
        else:
            assert address==ctx+0x58 and get(p,ctx+0x30,2)==0
            put(p,ctx+0x88,0,1)
        return -4
    def invoke(*a):raise allocator.RefillUnsupported('default initialization task body remains unrecovered')
    actual=startup.run_startup_worker(model,argument_address=arg,worker_kind=kind,image_base=base,
        thread_pointer=WORKER_TLS,thread_id=thread_id,create_key=key,set_specific=specific,get_tls=get_tls,
        clock=model_clock,futex=futex,free=model_free,invoke=invoke,task_address=GUEST+0xBC00)
    assert actual==result==0 and model_waits[0]==1
    assert allocator._read_span(model,GUEST,0xA000)==memory,('guest',kind,
        [hex(GUEST+i) for i,(a,b) in enumerate(zip(allocator._read_span(model,GUEST,0xA000),memory)) if a!=b][:25])
    for (address,width),expected in observed.items():
        assert allocator._read_span(model,address,width)==expected,('worker state',kind,hex(address))
    assert model_allocations==allocations,'allocation sequence'
    assert model_threads==threads,'thread descriptors'
    normalize=lambda values:[v[:1]+v[2:] if v[0]=='thread_create' else v for v in values]
    assert normalize(actual_events)==normalize(events),('ordered startup/worker effects',kind,actual_events,events)
    support_key=get(model,base+0x3e2f30,4)
    retained=allocator.pthread_getspecific(model,key=support_key,thread_pointer=WORKER_TLS,generation_table=table)
    assert retained==wrapper,'support ownership must remain in TLS until OS thread exit'
    frees=[e[1] for e in actual_events if e[0]=='free']
    assert frees==[arg] and wrapper not in frees
    return dict(image_base=hex(base),thread_id=thread_id,worker_kind=kind,worker_index=selected,
        startup_generated_worker_arguments=True,worker_tls_independent=True,worker_wait_calls=1,
        complete_idle_worker_normal_return=True,argument_cleanup_match=True,argument_free_calls=len(frees),
        support_retained_in_tls=True,all_main_image_pages_match=True,both_threads_tls_match=True,
        generation_table_match=True,guest_objects_match=True,allocation_sequence_match=True,
        allocation_count=len(allocations),worker_allocation_sizes=[s for s,_ in allocations[16:]],
        thread_handles_arguments_and_order_match=True,ordered_semantic_effects_match=True,
        native_input_snapshot_used=False,default_initialization_task_executed=False,
        os_thread_exit_destructor_executed=False,complete_worker_runtime=False,
        complete_allocator_boot=False,complete_python_medusa=False)



def negative_cases(library,libc):
    import verify_vm9_startup_workers as worker_fixture
    base=0x122c0000;cases=[]
    for label in ('unknown_worker','getter_failure','unknown_poll_vtable','executor_cancellation',
                  'queue_wait_bound','task_body_unrecovered'):
        p=worker_fixture.inputs(library,libc,base,False)
        kind='queue' if label.startswith('queue') or label=='task_body_unrecovered' else 'executor'
        arg=GUEST+0x3100;ctx=GUEST+0x3618;q=GUEST+0x3800;items=GUEST+0x3900
        put(p,ctx+8,get(p,base+0x3750b8)+0x48)
        if label=='unknown_poll_vtable':put(p,ctx+8,0)
        if label=='executor_cancellation':put(p,ctx+0x6a,1,1)
        allocator._write_span(p,q,bytes(144))
        for i,v in enumerate((items,items,items+48)):put(p,q+0x18+i*8,v)
        put(p,q+0x88,1,1)
        if label=='task_body_unrecovered':
            put(p,items,base+0x35d630);put(p,items+0x20,items);put(p,q+0x20,items+48)
        before={k:bytes(v) for k,v in p.items()};events=[]
        def key(p,address,destructor):events.append('key_create');put(p,address,0x80000002,4);return 0
        def specific(*args):events.append('set_specific');return 0
        def getter(p,address):
            events.append('get_tls')
            if label=='getter_failure':raise allocator.RefillUnsupported('unavailable TLS getter')
            return GUEST+0x4200
        def invoke(*args):events.append('invoke');raise allocator.RefillUnsupported('unrecovered task body')
        try:
            startup.run_startup_worker(p,argument_address=arg,
                worker_kind='invalid' if label=='unknown_worker' else kind,image_base=base,
                thread_pointer=root.TLS,thread_id=137,create_key=key,set_specific=specific,get_tls=getter,
                clock=lambda *a:(1000,0),futex=lambda *a:0,free=lambda *a:events.append('free'),invoke=invoke,
                task_address=GUEST+0xbc00,max_iterations=2)
        except allocator.RefillUnsupported:pass
        else:raise AssertionError(('worker did not reject',label))
        assert {k:bytes(v) for k,v in p.items()}==before,('worker rollback',label)
        if label=='unknown_worker':assert not events
        cases.append(dict(case=label,rejected=True,guest_pages_unchanged=True,
            environment_effect_count=len(events),external_effects_rolled_back=False))
    return cases


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--libc',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args();assert hashlib.sha256(args.library.read_bytes()).hexdigest()==LIBRARY_SHA256
    os.environ['TOMATO_LIBMETASEC']=str(args.library.resolve())
    global vm_full
    import vm_full
    with args.libc.open('rb') as f:
        e=ELFFile(f);exports={s.name:root.LIBC_BASE+s['st_value'] for sec in e.iter_sections()
            if sec['sh_type']=='SHT_DYNSYM' for s in sec.iter_symbols() if s['st_shndx']!='SHN_UNDEF'}
    cases=[probe(args.library,args.libc,exports,base=base,kind=kind,thread_id=tid)
        for base in (0x122c0000,0x775c205000) for kind in ('executor','queue') for tid in (137,271)]
    negatives=negative_cases(args.library,args.libc)
    report=dict(library_sha256=LIBRARY_SHA256,native_runs=len(cases),cases=cases,negative_cases=negatives,
        same_fresh_startup_and_worker_control=True,native_input_snapshot_used=False,
        native_code_used_by_python_model=False,bounded_allocator_used=True,virtual_os_used=True,
        host_threads_created=False,host_wait_executed=False,default_initialization_task_executed=False,
        os_thread_exit_destructor_executed=False,complete_worker_runtime=False,
        complete_allocator_boot=False,complete_python_medusa=False)
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(native_runs=len(cases),negative_checks=len(negatives),same_fresh_startup_idle_worker_match=True)))


if __name__=='__main__':main()
