"""Fresh native queue callable ownership, erase, waiting and bounded dispatch.

The task invocation is an explicit environment callback in both models. These
controls verify scheduling and cleanup, not the default initialization VM body.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn.arm64_const import UC_ARM64_REG_PC,UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_TPIDR_EL0
import vm9_startup as startup
from vm9_allocator import _read_span,_write_span,RefillUnsupported
from verify_vm9_signer_objects import native,fresh_pages,image_pages,GUEST,LIBRARY_SHA256
from verify_vm9_root_configuration import LIBC_BASE,TLS

DEST=GUEST+0x1000;SOURCE=GUEST+0x1100;HEAP=GUEST+0x2000
VECTOR=GUEST+0x1200;ITEMS=GUEST+0x1400;QUEUE=GUEST+0x1800;OBJECT=GUEST+0x1900
TASK=GUEST+0xBC00;MARKER=GUEST+0x3200


def put(p,a,v,n=8):_write_span(p,a,(v&((1<<(8*n))-1)).to_bytes(n,'little'))
def get(p,a,n=8):return int.from_bytes(_read_span(p,a,n),'little')


def callable_input(p,address,kind,base,index=0):
    pointer=0 if kind=='empty' else HEAP+index*64 if kind.startswith('heap') else address
    put(p,address+0x20,pointer)
    if pointer:
        put(p,pointer,base+(0x372600 if 'queue' in kind else 0x35d630))
        if 'queue' in kind:put(p,pointer+8,QUEUE)


def compare(p,memory,events,actual_events,allocations):
    assert _read_span(p,GUEST,0xA000)==memory,'guest state including callable padding'
    assert events==actual_events,('ordered callable effects',events,actual_events)
    assert not allocations


def lifecycle(library,*,base,operation,source_kind,dest_kind='empty',self_assign=False):
    def inputs():
        p=image_pages(library,base);p.update(fresh_pages())
        callable_input(p,DEST,dest_kind,base,index=1)
        callable_input(p,SOURCE,source_kind,base,index=2)
        return p
    p=inputs();oracle=inputs();events=[];actual_events=[]
    source=DEST if self_assign else SOURCE
    entry={'destroy':0x167310,'reset':0x2918b0,'assign':0x291848,'move':0x3259c4}[operation]
    def free(cpu):events.append(['free',cpu.reg_read(UC_ARM64_REG_X0)]);return 0
    result,memory,allocations,_=native(library,base,entry,[DEST,source],oracle,host_imports={0x347fa0:free})
    def model_free(p,pointer):actual_events.append(['free',pointer])
    if operation in ('destroy','reset'):
        startup.destroy_callable(p,object_address=DEST,image_base=base,free=model_free,reset=operation=='reset')
    elif operation=='assign':
        startup.assign_callable(p,destination_address=DEST,source_address=source,image_base=base,free=model_free)
    else:startup.move_callable(p,destination_address=DEST,source_address=source,image_base=base)
    compare(p,memory,events,actual_events,allocations)
    if operation in ('assign','reset'):assert result==DEST
    return dict(image_base=hex(base),operation=operation,source_kind=source_kind,destination_kind=dest_kind,
        self_assignment=self_assign,free_calls=len(events),guest_bytes_match=True,padding_preserved=True,
        ordered_semantic_effects_match=True,native_input_snapshot_used=False)


def erase(library,*,base,kinds,index):
    def inputs():
        p=image_pages(library,base);p.update(fresh_pages())
        for i,kind in enumerate(kinds):callable_input(p,ITEMS+i*48,kind,base,index=i)
        for i,v in enumerate((ITEMS,ITEMS+len(kinds)*48,ITEMS+8*48)):put(p,VECTOR+i*8,v)
        return p
    p=inputs();oracle=inputs();events=[];actual_events=[];element=ITEMS+index*48
    def free(cpu):events.append(['free',cpu.reg_read(UC_ARM64_REG_X0)]);return 0
    result,memory,allocations,_=native(library,base,0x326670,[VECTOR,element],oracle,host_imports={0x347fa0:free})
    actual=startup.erase_queue_callable(p,vector_address=VECTOR,element_address=element,image_base=base,
        free=lambda p,a:actual_events.append(['free',a]))
    compare(p,memory,events,actual_events,allocations);assert result==actual==element
    return dict(image_base=hex(base),operation='erase',kinds=kinds,erased_index=index,
        free_calls=len(events),guest_bytes_match=True,padding_preserved=True,
        ordered_semantic_effects_match=True,native_input_snapshot_used=False)


def queue(library,libc,exports,*,base,kinds,wait_action):
    def inputs():
        p=image_pages(library,base);p.update(fresh_pages())
        _write_span(p,QUEUE,bytes(144))
        for i,kind in enumerate(kinds):callable_input(p,ITEMS+i*48,kind,base,index=i)
        for i,v in enumerate((ITEMS,ITEMS+len(kinds)*48,ITEMS+8*48)):put(p,QUEUE+0x18+i*8,v)
        put(p,QUEUE+0x88,int(wait_action!='stopped'),1)
        put(p,OBJECT,base+0x372600);put(p,OBJECT+8,QUEUE);put(p,MARKER,0)
        put(p,TLS+0x10,37,4)
        return p
    p=inputs();oracle=inputs();events=[];actual_events=[];observed={(TLS,0xB00):None}
    injected=[False];model_injected=[False]
    def task(cpu):
        assert int.from_bytes(cpu.mem_read(QUEUE+0x30,2),'little')==0,'task called with mutex held'
        pointer=cpu.reg_read(UC_ARM64_REG_X0)
        # Inline functions live in the loop's stack; normalize this address.
        identity='inline' if GUEST+0xE000<=pointer<GUEST+0xF000 else hex(pointer)
        events.append(['invoke',identity])
        count=int.from_bytes(cpu.mem_read(MARKER,8),'little');cpu.mem_write(MARKER,(count+1).to_bytes(8,'little'))
        return 0
    def redirect(cpu):cpu.reg_write(UC_ARM64_REG_PC,exports['pthread_cond_wait'])
    def free(cpu):events.append(['free',cpu.reg_read(UC_ARM64_REG_X0)]);return 0
    def syscall(cpu,number):
        assert number==98,number
        assert int.from_bytes(cpu.mem_read(QUEUE+0x30,2),'little')==0,'wait with held mutex'
        assert cpu.reg_read(UC_ARM64_REG_X0)==QUEUE+0x58
        assert cpu.reg_read(UC_ARM64_REG_X1)==128 and cpu.reg_read(UC_ARM64_REG_X2)==0
        assert cpu.reg_read(UC_ARM64_REG_X3)==0
        events.append(['wait'])
        if wait_action=='inject' and not injected[0]:
            injected[0]=True
            cpu.mem_write(ITEMS,(base+0x35d630).to_bytes(8,'little'))
            cpu.mem_write(ITEMS+0x20,ITEMS.to_bytes(8,'little'))
            cpu.mem_write(QUEUE+0x20,(ITEMS+48).to_bytes(8,'little'))
        else:cpu.mem_write(QUEUE+0x88,b'\0')
        return -4
    _,memory,allocations,_=native(library,base,0x326578,[OBJECT],oracle,libc=libc,real_mutexes=True,
        extra_registers={UC_ARM64_REG_TPIDR_EL0:TLS},host_imports={0x280554:task,0x347fa0:free,0x3485b0:redirect},
        syscall_handler=syscall,observed_memory=observed,instruction_limit=100000)
    def model_task(p,function,pointer):
        assert function==base+0x280554
        assert get(p,QUEUE+0x30,2)==0,'model task with held mutex'
        actual_events.append(['invoke','inline' if pointer==TASK else hex(pointer)])
        put(p,MARKER,get(p,MARKER)+1);return 0
    def model_futex(p,address,operation,expected,timeout):
        assert (address,operation,expected,timeout)==(QUEUE+0x58,128,0,None)
        assert get(p,QUEUE+0x30,2)==0,'model wait with held mutex'
        actual_events.append(['wait'])
        if wait_action=='inject' and not model_injected[0]:
            model_injected[0]=True;callable_input(p,ITEMS,'inline',base);put(p,QUEUE+0x20,ITEMS+48)
        else:put(p,QUEUE+0x88,0,1)
        return -4
    count=startup.run_queue_callable(p,object_address=OBJECT,task_address=TASK,image_base=base,
        thread_pointer=TLS,clock=lambda *a:(_ for _ in ()).throw(AssertionError('untimed wait read clock')),
        futex=model_futex,free=lambda p,a:actual_events.append(['free',a]),invoke=model_task)
    # Each model owns a different unpublished local scratch outside the
    # compared guest objects; neither scratch is copied from native output.
    compare(p,memory,events,actual_events,allocations)
    assert _read_span(p,TLS,0xB00)==observed[TLS,0xB00],'TLS errno'
    assert count==get(p,MARKER)
    return dict(image_base=hex(base),operation='queue_loop',kinds=kinds,wait_action=wait_action,
        tasks_run=count,wait_calls=sum(e[0]=='wait' for e in events),free_calls=sum(e[0]=='free' for e in events),
        guest_bytes_match=True,tls_errno_match=True,ordered_semantic_effects_match=True,
        native_input_snapshot_used=False,task_body_is_explicit_environment_callback=True,physical_task_scratch_compared=False)


def negatives(library,base):
    results=[]
    for label in ('unknown_destructor','bad_vector','erase_bound','queue_wait_bound','queue_unrecovered_task'):
        p=image_pages(library,base);p.update(fresh_pages());_write_span(p,QUEUE,bytes(144))
        callable_input(p,DEST,'inline',base)
        if label=='unknown_destructor':put(p,DEST,base+0x1000)
        for i,v in enumerate((ITEMS,ITEMS+48,ITEMS+48)):put(p,VECTOR+i*8,v)
        if label=='bad_vector':put(p,VECTOR+8,ITEMS+47)
        if label=='erase_bound':put(p,VECTOR+8,ITEMS+96);put(p,VECTOR+16,ITEMS+96)
        put(p,OBJECT,base+0x372600);put(p,OBJECT+8,QUEUE)
        for i,v in enumerate((ITEMS,ITEMS,ITEMS+48)):put(p,QUEUE+0x18+i*8,v)
        put(p,QUEUE+0x88,1,1)
        if label=='queue_unrecovered_task':
            callable_input(p,ITEMS,'inline',base);put(p,QUEUE+0x20,ITEMS+48)
        before={k:bytes(v) for k,v in p.items()}
        def reject_task(*args):raise RefillUnsupported('task body is unrecovered')
        try:
            if label=='unknown_destructor':startup.destroy_callable(p,object_address=DEST,image_base=base,free=lambda *a:None)
            elif label in ('bad_vector','erase_bound'):
                startup.erase_queue_callable(p,vector_address=VECTOR,element_address=ITEMS,image_base=base,free=lambda *a:None,max_items=1)
            else:
                startup.run_queue_callable(p,object_address=OBJECT,task_address=TASK,image_base=base,
                    thread_pointer=TLS,clock=lambda *a:None,futex=lambda *a:0,free=lambda *a:None,invoke=reject_task,max_iterations=2)
        except RefillUnsupported:pass
        else:raise AssertionError(('did not reject',label))
        assert {k:bytes(v) for k,v in p.items()}==before,('rollback',label)
        results.append(dict(case=label,rejected=True,guest_pages_unchanged=True))
    return results


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--libc',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args();assert hashlib.sha256(args.library.read_bytes()).hexdigest()==LIBRARY_SHA256
    with args.libc.open('rb') as f:
        e=ELFFile(f);exports={s.name:LIBC_BASE+s['st_value'] for sec in e.iter_sections()
            if sec['sh_type']=='SHT_DYNSYM' for s in sec.iter_symbols() if s['st_shndx']!='SHN_UNDEF'}
    cases=[]
    kinds=('empty','inline','inline_queue','heap','heap_queue')
    for base in (0x122c0000,0x775c205000):
        for kind in kinds:
            for op in ('destroy','reset'):cases.append(lifecycle(args.library,base=base,operation=op,source_kind='empty',dest_kind=kind))
            for dest in ('empty','inline','heap'):
                cases.append(lifecycle(args.library,base=base,operation='assign',source_kind=kind,dest_kind=dest))
            cases.append(lifecycle(args.library,base=base,operation='move',source_kind=kind))
            cases.append(lifecycle(args.library,base=base,operation='assign',source_kind='empty',dest_kind=kind,self_assign=True))
        for kinds_ in (('inline',),('heap',),('inline','heap','empty','inline_queue','heap_queue')):
            for i in range(len(kinds_)):cases.append(erase(args.library,base=base,kinds=kinds_,index=i))
        for kinds_,action in (((),'stopped'),((),'stop'),((),'inject'),(('inline','heap','inline'),'stopped'),(('heap','inline'),'stop')):
            cases.append(queue(args.library,args.libc,exports,base=base,kinds=kinds_,wait_action=action))
    rejected=negatives(args.library,0x122c0000)
    report=dict(library_sha256=LIBRARY_SHA256,native_runs=len(cases),cases=cases,negative_cases=rejected,
        fresh_synthetic_inputs=True,native_input_snapshot_used=False,native_code_used_by_python_model=False,
        task_body_is_explicit_environment_callback=True,host_threads_created=False,host_wait_executed=False,
        complete_worker_runtime=False,complete_allocator_boot=False,complete_python_medusa=False)
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(native_runs=len(cases),negative_checks=len(rejected),queue_callable_match=True)))


if __name__=='__main__':main()
