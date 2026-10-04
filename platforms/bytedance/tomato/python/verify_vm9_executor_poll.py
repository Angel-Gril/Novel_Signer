"""Fresh matching-native executor deque, poll, signal waits and serial loop.

Task bodies and finite clock/futex outcomes are explicit environment services.
No input snapshot, host worker thread or full allocator boot is required here.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn.arm64_const import UC_ARM64_REG_PC,UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X8,UC_ARM64_REG_TPIDR_EL0
import vm9_startup as startup
from vm9_allocator import _read_span,_write_span,RefillUnsupported
from verify_vm9_signer_objects import native,fresh_pages,image_pages,GUEST,LIBRARY_SHA256
from verify_vm9_root_configuration import LIBC_BASE,TLS

CTX=GUEST+0x1000;OUT=GUEST+0x1300;MAP=GUEST+0x1800;TASKS=GUEST+0x2000
HEAP=GUEST+0x2600;MARKER=GUEST+0x3000;SEGMENTS=(GUEST+0x4000,GUEST+0x5000,GUEST+0x6000)
CTRL=CTX+0x84


def put(p,a,v,n=8):_write_span(p,a,(v&((1<<(8*n))-1)).to_bytes(n,'little'))
def get(p,a,n=8):return int.from_bytes(_read_span(p,a,n),'little')


def inputs(library,base,deadlines,head=0,heap=False,counter=0):
    p=image_pages(library,base);p.update(fresh_pages())
    _write_span(p,CTX,bytes(0xe8))
    table=get(p,base+0x3750b8);put(p,CTX,table+0x10);put(p,CTX+8,table+0x48)
    put(p,CTX+0x78,get(p,base+0x3750c0)+0x10);put(p,CTX+0xe0,CTX+0x78)
    put(p,CTX+0x80,1,1);put(p,CTRL,counter,4);put(p,MARKER,0)
    for i,v in enumerate((MAP,MAP,MAP+24,3,head,len(deadlines))):put(p,CTX+0x38+i*8,v)
    for i,s in enumerate(SEGMENTS):put(p,MAP+i*8,s);_write_span(p,s,bytes(4096))
    for i,deadline in enumerate(deadlines):
        task=TASKS+i*64;pointer=HEAP+i*64 if heap else task
        put(p,task+0x20,pointer);put(p,pointer,base+0x35d630)
        put(p,task+0x30,deadline);put(p,task+0x38,-1)
        index=head+i;put(p,SEGMENTS[index//512]+index%512*8,task)
    put(p,CTX+0x70,1000);put(p,TLS+0x10,37,4)
    return p


class Services:
    def __init__(self,p,*,action='timeout',delay=20):
        self.pages=p;self.events=[];self.action=action;self.delay=delay;self.monotonic_reads=0;self.advanced=0;self.waits=0
    def clock_value(self,clock_id):
        if clock_id==0:value=(1000,900000123)
        else:
            value=divmod(1000000000+self.monotonic_reads*100000+self.advanced,1000000000)
            self.monotonic_reads+=1
        self.events.append(['clock',clock_id,*value]);return value
    def clock(self,p,clock_id):return self.clock_value(clock_id)
    def futex_effect(self,read,write,address,operation,expected,timeout):
        assert address==CTRL+0x2c and operation==128
        assert read(CTRL+4,2)==0,'mutex held during futex'
        result=-110 if self.action=='timeout' else -4
        self.events.append(['futex',address,operation,expected,list(timeout),result]);self.waits+=1
        if self.action=='timeout':self.advanced+=max(1,self.delay)*1000000
        elif self.action=='signal':write(CTRL,2,4)
        elif self.action=='stop':write(CTX+0x80,0,1);write(CTRL,1,4)
        elif self.action=='spurious_then_signal' and self.waits>=2:write(CTRL,1,4)
        return result
    def free(self,p,pointer):self.events.append(['free',pointer])
    def invoke(self,p,function,pointer):
        assert function==self.base+0x280554
        assert get(p,CTX+0x10,2)==0,'task invoked with executor mutex held'
        self.events.append(['invoke',pointer]);put(p,MARKER,get(p,MARKER)+1);return 0


def probe(library,libc,exports,*,base,operation,deadlines=(),head=0,heap=False,delay=20,counter=0,action='timeout',stopped=False):
    p=inputs(library,base,deadlines,head,heap,counter);oracle=inputs(library,base,deadlines,head,heap,counter)
    if stopped:
        for seed in (p,oracle):put(seed,CTX+0x68,1,1)
    a=Services(p,action=action,delay=delay);n=Services(oracle,action=action,delay=delay);a.base=base
    def cpu_read(cpu,address,width=8):return int.from_bytes(cpu.mem_read(address,width),'little')
    def cpu_write(cpu,address,value,width=8):cpu.mem_write(address,(value&((1<<(width*8))-1)).to_bytes(width,'little'))
    def clock(cpu):
        value=n.clock_value(cpu.reg_read(UC_ARM64_REG_X0))
        cpu.mem_write(cpu.reg_read(UC_ARM64_REG_X1),b''.join((v&((1<<64)-1)).to_bytes(8,'little') for v in value));return 0
    def syscall(cpu,number):
        if number==113:return clock(cpu)
        assert number==98,number
        pointer=cpu.reg_read(UC_ARM64_REG_X3)
        timeout=tuple(cpu_read(cpu,pointer+i*8) for i in range(2))
        return n.futex_effect(lambda x,w:cpu_read(cpu,x,w),lambda x,v,w:cpu_write(cpu,x,v,w),
            cpu.reg_read(UC_ARM64_REG_X0),cpu.reg_read(UC_ARM64_REG_X1),cpu.reg_read(UC_ARM64_REG_X2),timeout)
    def redirect(cpu):cpu.reg_write(UC_ARM64_REG_PC,exports['pthread_cond_timedwait'])
    def free(cpu):n.events.append(['free',cpu.reg_read(UC_ARM64_REG_X0)]);return 0
    def invoke(cpu):
        assert cpu_read(cpu,CTX+0x10,2)==0,'native task with held mutex'
        n.events.append(['invoke',cpu.reg_read(UC_ARM64_REG_X0)]);cpu_write(cpu,MARKER,cpu_read(cpu,MARKER)+1);return 0
    entry={'pop':0x32722c,'ready':0x326ec8,'delay':0x326f48,'poll':0x326dfc,'wait':0x328a84,'loop':0x326b84}[operation]
    observed={(TLS,0xB00):None}
    args=[CTRL,delay&0xffffffff] if operation=='wait' else [CTX]
    result,memory,allocations,_=native(library,base,entry,args,oracle,libc=libc,real_mutexes=True,
        extra_registers={UC_ARM64_REG_TPIDR_EL0:TLS,UC_ARM64_REG_X8:OUT},observed_memory=observed,
        host_imports={0x348450:clock,0x3485c0:redirect,0x347fa0:free,0x280554:invoke},
        syscall_handler=syscall,instruction_limit=500000)
    if operation=='pop':put(p,OUT,startup.pop_executor_task(p,context_address=CTX,free=a.free));actual=None
    elif operation=='ready':put(p,OUT,startup.take_ready_executor_task(p,context_address=CTX,free=a.free) or 0);actual=None
    elif operation=='delay':actual=startup.next_executor_delay(p,context_address=CTX)
    elif operation=='poll':actual=startup.poll_executor(p,context_address=CTX,image_base=base,clock=a.clock,free=a.free,invoke=a.invoke)
    elif operation=='wait':actual=startup.wait_signal_controller(p,controller_address=CTRL,delay_ms=delay,
        thread_pointer=TLS,clock=a.clock,futex=lambda p,*args:a.futex_effect(lambda x,w:get(p,x,w),lambda x,v,w:put(p,x,v,w),*args))
    else:actual=startup.run_executor_context(p,context_address=CTX,image_base=base,thread_pointer=TLS,
        clock=a.clock,futex=lambda p,*args:a.futex_effect(lambda x,w:get(p,x,w),lambda x,v,w:put(p,x,v,w),*args),free=a.free,invoke=a.invoke)
    assert _read_span(p,GUEST,0xA000)==memory,('guest',operation,head,
        [hex(GUEST+i) for i,(x,y) in enumerate(zip(_read_span(p,GUEST,0xA000),memory)) if x!=y][:20])
    assert _read_span(p,TLS,0xB00)==observed[TLS,0xB00],('TLS errno',operation)
    assert a.events==n.events,('ordered effects',operation,a.events,n.events)
    assert not allocations
    if operation in ('poll','delay','wait'):assert actual==startup._s32(result),('return',operation,actual,result)
    return dict(image_base=hex(base),operation=operation,task_count=len(deadlines),head_index=head,
        heap_callable=heap,stopped=stopped,signal_counter=counter,delay_ms=delay,wait_action=action,
        tasks_invoked=sum(e[0]=='invoke' for e in a.events),free_calls=sum(e[0]=='free' for e in a.events),
        clock_calls=sum(e[0]=='clock' for e in a.events),futex_calls=a.waits,
        guest_bytes_match=True,tls_errno_match=True,ordered_semantic_effects_match=True,
        return_matches=operation in ('poll','delay','wait'),native_input_snapshot_used=False,
        task_body_is_explicit_environment_callback=True)


def negatives(library,base):
    cases=[]
    for label in ('repeat_task','bad_map','bad_task','poll_bound','signal_wait_bound','callback_repeat'):
        p=inputs(library,base,(0,0) if label=='poll_bound' else (0,));events=[]
        if label=='repeat_task':put(p,TASKS+0x38,1)
        if label=='bad_map':put(p,CTX+0x48,MAP-8)
        if label=='bad_task':put(p,SEGMENTS[0],0)
        before={k:bytes(v) for k,v in p.items()}
        clock=lambda *a:(1,0)
        def invoke(p,fn,pointer):
            events.append('invoke')
            if label=='callback_repeat':put(p,TASKS+0x38,10)
        try:
            if label=='signal_wait_bound':
                startup.wait_signal_controller(p,controller_address=CTRL,delay_ms=20,thread_pointer=TLS,
                    clock=clock,futex=lambda *a:-4,max_waits=2)
            else:startup.poll_executor(p,context_address=CTX,image_base=base,clock=clock,
                free=lambda *a:events.append('free'),invoke=invoke,max_tasks=1)
        except RefillUnsupported:pass
        else:raise AssertionError(('did not reject',label))
        assert {k:bytes(v) for k,v in p.items()}==before,('rollback',label)
        if label in ('repeat_task','bad_map','bad_task'):assert not events
        cases.append(dict(case=label,rejected=True,guest_pages_unchanged=True,
            environment_effect_count=len(events),external_effects_rolled_back=False))
    return cases


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--libc',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args();assert hashlib.sha256(args.library.read_bytes()).hexdigest()==LIBRARY_SHA256
    with args.libc.open('rb') as f:
        e=ELFFile(f);exports={s.name:LIBC_BASE+s['st_value'] for sec in e.iter_sections()
            if sec['sh_type']=='SHT_DYNSYM' for s in sec.iter_symbols() if s['st_shndx']!='SHN_UNDEF'}
    cases=[]
    for base in (0x122c0000,0x775c205000):
        for head in (0,511,512,1023):
            for op in ('pop','ready'):cases.append(probe(args.library,args.libc,exports,base=base,operation=op,deadlines=(900,1200),head=head))
        for deadlines in ((),(900,),(1200,),(1000+(1<<31)+5,)):
            for op in ('ready','delay','poll'):cases.append(probe(args.library,args.libc,exports,base=base,operation=op,deadlines=deadlines))
        cases.append(probe(args.library,args.libc,exports,base=base,operation='poll',deadlines=(900,900,1200),heap=True))
        cases.append(probe(args.library,args.libc,exports,base=base,operation='poll',deadlines=(900,),stopped=True))
        for delay,counter,action in ((0,0,'timeout'),(-2,0,'timeout'),(20,2,'signal'),(20,0,'timeout'),
            (20,0,'signal'),(20,-1,'signal'),(20,0,'spurious_then_signal')):
            cases.append(probe(args.library,args.libc,exports,base=base,operation='wait',delay=delay,counter=counter,action=action))
        for deadlines in ((),(900,)):
            cases.append(probe(args.library,args.libc,exports,base=base,operation='loop',deadlines=deadlines,action='stop'))
    rejected=negatives(args.library,0x122c0000)
    report=dict(library_sha256=LIBRARY_SHA256,native_runs=len(cases),cases=cases,negative_cases=rejected,
        fresh_synthetic_inputs=True,native_input_snapshot_used=False,native_code_used_by_python_model=False,
        task_body_is_explicit_environment_callback=True,repeat_insertion_supported=False,
        host_threads_created=False,host_wait_executed=False,complete_worker_runtime=False,
        complete_allocator_boot=False,complete_python_medusa=False)
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(native_runs=len(cases),negative_checks=len(rejected),executor_poll_and_wait_match=True)))


if __name__=='__main__':main()
