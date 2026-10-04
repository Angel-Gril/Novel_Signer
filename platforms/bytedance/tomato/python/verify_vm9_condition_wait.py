"""Matching-libc condition wait: fresh guest mutex, clock and futex effects.

The guest syscall provider supplies a finite wake/error result and optional
condition generation changes. No host thread, blocking wait or native input
checkpoint is used by the Python model.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn.arm64_const import (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,
    UC_ARM64_REG_X3,UC_ARM64_REG_PC,UC_ARM64_REG_TPIDR_EL0)
import vm9_startup as startup
from vm9_allocator import _read_span,_write_span,RefillUnsupported
from verify_vm9_signer_objects import native,fresh_pages,GUEST,LIBRARY_SHA256
from verify_vm9_root_configuration import LIBC_BASE,TLS

COND=GUEST+0x1800;MUTEX=GUEST+0x1900;TIMESPEC=GUEST+0x1a00
LOCK=GUEST+0x1b00
CLOCKS={0:(1000,900000000),1:(5,200000000)}


def fixture(condition,mutex,deadline):
    pages=fresh_pages()
    _write_span(pages,COND,condition.to_bytes(4,'little'))
    _write_span(pages,MUTEX,mutex.to_bytes(2,'little'))
    _write_span(pages,TLS+0x10,(37).to_bytes(4,'little'))
    if deadline is not None:
        _write_span(pages,TIMESPEC,b''.join((n&((1<<64)-1)).to_bytes(8,'little') for n in deadline))
    return pages


def probe(library,libc,exports,*,base,condition,mutex,deadline,syscall_result=0,change_generation=False,owned=False):
    pages=fixture(condition,mutex,None if owned else deadline)
    oracle=fixture(condition,mutex,None if owned else deadline)
    if owned:
        for p in (pages,oracle):
            _write_span(p,LOCK,MUTEX.to_bytes(8,'little')+b'\1')
    events=[];actual_events=[];observed={(TLS,0xB00):None}
    def syscall(cpu,number):
        if number==113:
            clock_id=cpu.reg_read(UC_ARM64_REG_X0);value=CLOCKS[clock_id]
            cpu.mem_write(cpu.reg_read(UC_ARM64_REG_X1),b''.join(n.to_bytes(8,'little') for n in value))
            events.append(['clock',clock_id,*value]);return 0
        assert number==98,number
        address=cpu.reg_read(UC_ARM64_REG_X0);operation=cpu.reg_read(UC_ARM64_REG_X1)
        expected=cpu.reg_read(UC_ARM64_REG_X2);pointer=cpu.reg_read(UC_ARM64_REG_X3)
        timeout=None if not pointer else [int.from_bytes(cpu.mem_read(pointer+i*8,8),'little',signed=True) for i in range(2)]
        assert int.from_bytes(cpu.mem_read(MUTEX,2),'little')==mutex&0x2000,'futex sees locked mutex'
        events.append(['futex',address,operation,expected,timeout,syscall_result])
        if change_generation:cpu.mem_write(COND,((condition+4)&0xffffffff).to_bytes(4,'little'))
        return syscall_result
    function=exports['pthread_cond_wait' if deadline is None else 'pthread_cond_timedwait']
    arguments=[COND,MUTEX,0 if deadline is None else TIMESPEC]
    imports={}
    if owned:
        arguments=[COND,LOCK,0 if deadline is None else deadline&((1<<64)-1)]
        function=base+(0x329574 if deadline is None else 0x3295c4)
        def redirect(cpu):cpu.reg_write(UC_ARM64_REG_PC,exports['pthread_cond_wait' if deadline is None else 'pthread_cond_timedwait'])
        imports={0x3485b0:redirect,0x3485c0:redirect}
    result,memory,allocations,_=native(library,base,function-base,arguments,oracle,
        libc=libc,extra_registers={UC_ARM64_REG_TPIDR_EL0:TLS},observed_memory=observed,
        syscall_handler=syscall,host_imports=imports)
    def clock(p,clock_id):
        value=CLOCKS[clock_id];actual_events.append(['clock',clock_id,*value]);return value
    def futex(p,address,operation,expected,timeout):
        assert int.from_bytes(_read_span(p,MUTEX,2),'little')==mutex&0x2000,'model futex sees locked mutex'
        actual_events.append(['futex',address,operation,expected,None if timeout is None else list(timeout),syscall_result])
        if change_generation:_write_span(p,COND,((condition+4)&0xffffffff).to_bytes(4,'little'))
        return syscall_result
    if owned:
        actual=startup.wait_owned_condition(pages,condition_address=COND,lock_address=LOCK,
            thread_pointer=TLS,deadline_ns=deadline,clock=clock,futex=futex)
    else:
        actual=startup.wait_condition(pages,condition_address=COND,mutex_address=MUTEX,
            thread_pointer=TLS,absolute_timeout=deadline,clock=clock,futex=futex)
    assert actual==result,('wait return',actual,result)
    assert _read_span(pages,GUEST,0xA000)==memory,'guest state'
    assert _read_span(pages,TLS,0xB00)==observed[TLS,0xB00],'TLS/errno state'
    assert actual_events==events,('ordered wait effects',actual_events,events)
    assert not allocations
    return dict(image_base=hex(base),condition_word=hex(condition),mutex_shared=bool(mutex&0x2000),
        timed=deadline is not None,owned_wrapper=owned,syscall_result=syscall_result,result=actual,
        generation_changed=change_generation,clock_calls=sum(e[0]=='clock' for e in events),
        futex_calls=sum(e[0]=='futex' for e in events),
        mutex_unlocked_during_futex=any(e[0]=='futex' for e in events),
        expired_deadline_retains_lock=not any(e[0]=='futex' for e in events) and actual==110,
        mutex_reacquired_on_return=any(e[0]=='futex' for e in events),
        mutex_locked_on_return=True,guest_bytes_match=True,tls_errno_match=True,
        ordered_semantic_effects_match=True,native_input_snapshot_used=False)


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--libc',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args();assert hashlib.sha256(args.library.read_bytes()).hexdigest()==LIBRARY_SHA256
    with args.libc.open('rb') as stream:
        elf=ELFFile(stream)
        exports={s.name:LIBC_BASE+s['st_value'] for sec in elf.iter_sections() if sec['sh_type']=='SHT_DYNSYM' for s in sec.iter_symbols() if s['st_shndx']!='SHN_UNDEF'}
    cases=[]
    for base in (0x122c0000,0x775c205000):
        for condition in (0,3,4,0xfffffffc):
            for mutex in (1,0x2001):
                for result in (0,-110,-4):
                    cases.append(probe(args.library,args.libc,exports,base=base,condition=condition,
                        mutex=mutex,deadline=None if result==-4 else (1002,100000000),
                        syscall_result=result,change_generation=result==0))
        for condition in (0,2):
            for deadline in ((0,0),(-1,999999999),(1000,900000000),(6,100000000)):
                cases.append(probe(args.library,args.libc,exports,base=base,condition=condition,mutex=1,
                    deadline=deadline,syscall_result=-110))
        for condition in (0,3):
            for deadline in (None,-1000000001,-1,0,1002100000000,0x59682F000000E941,(1<<63)-1):
                cases.append(probe(args.library,args.libc,exports,base=base,condition=condition,mutex=1,
                    deadline=deadline,syscall_result=-110 if deadline is not None else -4,owned=True))
    negatives=[]
    for label in ('unowned','bad_deadline','bad_mutex','bad_futex','bad_clock'):
        pages=fixture(0,1,None);_write_span(pages,LOCK,MUTEX.to_bytes(8,'little')+b'\1')
        if label=='unowned':_write_span(pages,LOCK+8,b'\0')
        if label=='bad_mutex':_write_span(pages,MUTEX,(2).to_bytes(2,'little'))
        before={k:bytes(v) for k,v in pages.items()}
        try:
            startup.wait_owned_condition(pages,condition_address=COND,lock_address=LOCK,
                thread_pointer=TLS,deadline_ns=(1<<63) if label=='bad_deadline' else 1002100000000,
                clock=lambda p,c:(1000,1000000000) if label=='bad_clock' else CLOCKS[c],
                futex=lambda *a:'invalid' if label=='bad_futex' else 0)
        except RefillUnsupported:pass
        else:raise AssertionError(('did not reject',label))
        assert {k:bytes(v) for k,v in pages.items()}==before,('rollback',label)
        negatives.append(dict(case=label,rejected=True,guest_pages_unchanged=True))
    report=dict(library_sha256=LIBRARY_SHA256,libc_sha256=hashlib.sha256(args.libc.read_bytes()).hexdigest(),
        native_runs=len(cases),cases=cases,negative_cases=negatives,fresh_synthetic_inputs=True,native_input_snapshot_used=False,
        native_code_used_by_python_model=False,host_threads_created=False,host_wait_executed=False,
        complete_worker_runtime=False,complete_allocator_boot=False,complete_python_medusa=False)
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(native_runs=len(cases),condition_wait_match=True,negative_checks=len(negatives))))


if __name__=='__main__':main()
