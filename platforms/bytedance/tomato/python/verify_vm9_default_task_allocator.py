"""Same-fresh real allocator -> six default VM bodies, with separate stack/TLS."""
from __future__ import annotations
import argparse,collections,hashlib,json,os,time
from pathlib import Path
import vm9_allocator as a
import vm9_startup as startup
import vm9_startup_allocator as startup_model
import verify_vm9_libc_stdio as h
import verify_vm9_signer_objects as oracle
from verify_vm9_default_task_prefix import fresh as task_fresh,DEFAULT_CALLERS
from verify_vm9_libc_mapping import LIBC_SHA256
from unicorn.arm64_const import UC_ARM64_REG_SP,UC_ARM64_REG_X0,UC_ARM64_REG_TPIDR_EL0
TASK_STACK=h.GUEST+0x40000
TASK_STACK_BYTES=0x10000
TASK_TOP=TASK_STACK+TASK_STACK_BYTES-0x1000


def case(library,libc,image,vm_module):
    p=h.cpu_fresh(library,libc,image)
    task_seed=task_fresh(library,libc,image,0x3C)
    for page,data in task_seed.items():
        if image<=page<<12<image+0x400000:p[page]=bytearray(data)
    for page in range(TASK_STACK>>12,(TASK_STACK+TASK_STACK_BYTES)>>12):p[page]=bytearray([0x3C])*4096
    seed={key:bytearray(value) for key,value in p.items()}
    nos=a.GuestOS(seed);mos=a.GuestOS(p)
    observed=h.observed_spans();observed.update({(page<<12,4096):None for page in p if image<=page<<12<image+0x400000})
    observed.update({(h.LIBC+0xD8DC8,8):None,(h.LIBC+0xDE888,8):None,(h.LIBC+0xDB380,40):None,(h.LIBC+0xE01C0,16):None})
    n_calls=[];m_calls=[];returns=[];current=[0];counts=collections.Counter();n_cursor=[0];m_cursor=[0];malloc_calls=[0]
    nested_offsets={offset:index for index in range(6) for offset in (0x280970+index*0x1E4+0x64,0x2809F8+index*0x1E4+0x58)}
    native_nested=collections.Counter()
    initial_vm_base=vm_module.B
    contents=b'cpu 0 0\ncpu0 0\ncpu1 0\n'
    def stat():
        data=bytearray(128);data[16:20]=(0x8124).to_bytes(4,'little');data[56:60]=(4096).to_bytes(4,'little');return bytes(data)
    def syscall(cpu,number):
        fields=[cpu.reg_read(reg) for reg in h.REGS]
        if number==214:n_calls.append(['brk',0]);return 0x13600000
        if number==222:
            n_calls.append(['mmap',*fields]);record=nos.map_anonymous(fields[1],prot=fields[2],flags=fields[3],fd=fields[4],anonymous_name=b'')
            cpu.mem_map(record.base,record.length)
            observed.update({(page<<12,4096):None for page in range(record.base>>12,record.end>>12)})
            return record.base
        if number==167:
            name=h.cstring(cpu,fields[4]);n_calls.append(['prctl',*fields[:4],name]);nos.name_exact(fields[2],fields[3],name);return 0
        if number==56:
            path=h.cstring(cpu,fields[1]);n_calls.append(['openat',fields[0],path,fields[2],fields[3]]);return 53
        if number==80:n_calls.append(['fstat',fields[0]]);cpu.mem_write(fields[1],stat());return 0
        if number==63:
            data=contents[n_cursor[0]:n_cursor[0]+fields[2]];n_cursor[0]+=len(data)
            n_calls.append(['read',fields[0],fields[2]]);cpu.mem_write(fields[1],data);return len(data)
        if number==57:n_calls.append(['close',fields[0]]);return 0
        if number==226:
            n_calls.append(['mprotect',*fields[:3]]);nos.protect_exact(*fields[:3]);cpu.mem_protect(*fields[:3]);return 0
        if number==215:
            n_calls.append(['munmap',*fields[:2]]);nos.unmap_range(*fields[:2]);cpu.mem_unmap(*fields[:2])
            for page in range(fields[0]>>12,(fields[0]+fields[1])>>12):observed.pop((page<<12,4096),None)
            return 0
        raise AssertionError(('uncovered syscall',number))
    def service(tx,op,*fields):
        m_calls.append([op,*fields])
        if op=='mmap':return tx.next_address
        if op=='read':
            data=contents[m_cursor[0]:m_cursor[0]+fields[1]];m_cursor[0]+=len(data);return (len(data),data)
        if op=='fstat':return (0,stat())
        if op=='openat':return 53
        assert op in ('close','prctl','mprotect','munmap'),op
        return 0
    def observe(cpu,pc):
        off=pc-image;lo=pc-h.LIBC
        if off==0x280554:
            cpu.mem_map(TASK_STACK,TASK_STACK_BYTES);cpu.mem_write(TASK_STACK,bytes([0x3C])*TASK_STACK_BYTES)
        if lo in (0x8E250,0x8E41C,0x8E51C,0x99C78,0x7A3C8):counts[lo]+=1
        if lo==0x8E250:cpu.mem_write(h.TABLE,a._read_span(seed,h.TABLE,141*16))
        if off==0x347FD0:malloc_calls[0]+=1
        if off in nested_offsets:native_nested[off]+=1
        if off in DEFAULT_CALLERS:current[0]=cpu.reg_read(UC_ARM64_REG_SP)
        if off in tuple(caller+0x5C for caller in DEFAULT_CALLERS):
            index=DEFAULT_CALLERS.index(off-0x5C)
            returns.append(dict(index=index,registers=[int.from_bytes(cpu.mem_read(current[0]-0x148+i*8,8),'little') for i in range(32)],
                virtual_stack=bytes(cpu.mem_read(current[0]-0x1B0,0x50)),
                pages={page:bytes(cpu.mem_read(page<<12,4096)) for page in p if image<=page<<12<image+0x400000},
                mappings={page:bytes(cpu.mem_read(page<<12,4096)) for record in nos.mappings for page in range(record.base>>12,record.end>>12)}))
            print('actual native task caller',hex(image),index+1,'returned',flush=True)
    n_broadcasts=[];m_broadcasts=[]
    def broadcast(cpu):
        n_broadcasts.append([cpu.reg_read(UC_ARM64_REG_X0),[int.from_bytes(cpu.mem_read(image+0x3E09E8+i*0x48,8),'little') for i in range(6)],int.from_bytes(cpu.mem_read(image+0x3E2EB8,2),'little')])
        return 0
    ranges=[(image+0x280554,image+0x281414),(image+0x347E00,image+0x348600)]
    ranges += [(h.LIBC+offset,h.LIBC+offset+4) for offset in (0x8E250,0x8E41C,0x8E51C,0x99C78,0x7A3C8)]
    start=time.monotonic()
    result,memory,allocations,ledger=oracle.native(library,image,0x280554,[],{key:data for key,data in h.inputs(seed).items() if not TASK_STACK<=key<<12<TASK_STACK+TASK_STACK_BYTES},libc=libc,real_mutexes=True,
        host_imports={0x3485A0:broadcast},syscall_handler=syscall,instruction_observer=observe,observed_memory=observed,
        extra_registers={UC_ARM64_REG_TPIDR_EL0:h.WORKER_TLS,UC_ARM64_REG_SP:TASK_TOP},instruction_limit=900000000,code_hook_ranges=tuple(ranges),real_malloc=True)
    print('native composition boundaries',json.dumps(dict(default_returns=len(returns),main_malloc_calls=malloc_calls[0],generic_allocator_calls=len(allocations),other_helper_calls=len(ledger))),flush=True)
    expected_mutex_ledger=[['pthread_mutex_lock',image+0x3E2EB8],['pthread_mutex_unlock',image+0x3E2EB8]]*12
    assert len(returns)==6 and malloc_calls[0]==6 and not allocations
    assert ledger==expected_mutex_ledger,('actual once mutex calls',ledger)
    assert sum(native_nested.values())==48
    for index in range(6):
        assert native_nested[0x280970+index*0x1E4+0x64]==1 and native_nested[0x2809F8+index*0x1E4+0x58]==7
    assert all(counts[offset]==1 for offset in (0x8E250,0x8E41C,0x8E51C,0x99C78)) and counts[0x7A3C8]==6
    compared=[];nested=[]
    original=startup.run_default_initialization_caller
    def compare(*args,**kwargs):
        actual,phases=original(*args,**kwargs);index=kwargs['table_index'];expected=returns[index];staged=args[0]
        assert list(actual.registers)==expected['registers'],('caller registers',index)
        assert a._read_span(staged,kwargs['entry_stack_address']-0x1B0,0x50)==expected['virtual_stack'],('virtual stack',index)
        assert all(bytes(staged[page])==data for page,data in expected['pages'].items()),('caller image',index)
        assert all(bytes(staged[page])==data for page,data in expected['mappings'].items()),('caller allocator mappings',index)
        nested.extend(phases);compared.append(index);print('Python actual allocator task caller',hex(image),index+1,'match',flush=True)
        return actual,phases
    startup.run_default_initialization_caller=compare
    try:
        def model_broadcast(staged,address):
            m_broadcasts.append([address,[h.get(staged,image+0x3E09E8+i*0x48) for i in range(6)],h.get(staged,image+0x3E2EB8,2)])
            return 0
        result=startup_model.initialize_default_task(mos,vm_module=vm_module,entry_stack_address=TASK_TOP,
            return_address=h.STOP,thread_pointer=h.WORKER_TLS,image_base=image,scratch_address=h.GUEST+0xF800,
            libc_base=h.LIBC,brk=lambda *args:m_calls.append(['brk',0]) or 0x13600000,os_call=service,broadcast=model_broadcast)
    finally:startup.run_default_initialization_caller=original
    assert a._read_span(p,h.GUEST,0xA000)==memory
    mismatches=[]
    for (address,width),data in observed.items():
        actual=a._read_span(p,address,width)
        if actual!=data:
            mismatches.append(dict(address=hex(address),width=width,differences=[(hex(address+i),left,right) for i,(left,right) in enumerate(zip(actual,data)) if left!=right][:24]))
    if mismatches:
        print('final observed differences',json.dumps(mismatches),flush=True)
    assert not mismatches,'final observed state mismatch'
    assert n_calls==m_calls and nos.mappings==mos.mappings and nos.next_address==mos.next_address
    assert n_broadcasts==m_broadcasts and len(m_broadcasts)==6
    assert all(caller.complete for caller in result.caller_results) and [len(phases) for phases in result.nested_results]==[8]*6
    assert h.get(p,h.LIBC+0xDB6A0,4)==0 and vm_module.B==initial_vm_base
    row=dict(image_base=hex(image),native_default_returns=6,python_default_returns_compared=len(compared),python_nested_vm_returns=len(nested),native_nested_vm_returns=sum(native_nested.values()),
        native_nested_return_counts={hex(key):value for key,value in sorted(native_nested.items())},
        actual_main_malloc_plt_calls=malloc_calls[0],actual_libc_entry_counts={hex(key):value for key,value in sorted(counts.items())},
        all_retained_mapping_bytes_and_main_image_slots_tls_os_order_match=True,
        ordered_once_broadcasts_verified=True,actual_native_malloc=True,substituted_native_allocations=0,
        natural_default_cold_return=True,independent_stack_region_bytes=TASK_STACK_BYTES,
        native_input_snapshot_used=False,explicit_virtual_os=True)
    print(json.dumps(row),flush=True)
    return row


def rejection_cases(library,libc,vm_module):
    rows=[]
    for label in ('busy_third_once','third_broadcast_fails','unmapped_stack','tagged_return'):
        image=0x122C0000;p=h.cpu_fresh(library,libc,image)
        for page,data in task_fresh(library,libc,image,0x3C).items():
            if image<=page<<12<image+0x400000:p[page]=bytearray(data)
        for page in range(TASK_STACK>>12,(TASK_STACK+TASK_STACK_BYTES)>>12):p[page]=bytearray([0x3C])*4096
        if label=='busy_third_once':h.put(p,image+0x3E09E8+2*0x48,1)
        guest_os=a.GuestOS(p);cursor=[0];calls=[];broadcasts=[]
        contents=b'cpu 0 0\ncpu0 0\ncpu1 0\n'
        def service(tx,op,*fields):
            calls.append(op)
            if op=='mmap':return tx.next_address
            if op=='openat':return 53
            if op=='fstat':
                data=bytearray(128);data[16:20]=(0x8124).to_bytes(4,'little');data[56:60]=(4096).to_bytes(4,'little')
                return (0,bytes(data))
            if op=='read':
                data=contents[cursor[0]:cursor[0]+fields[1]];cursor[0]+=len(data);return (len(data),data)
            assert op in ('close','prctl','mprotect','munmap'),op
            return 0
        def broadcast(staged,address):
            broadcasts.append(address)
            return 1 if label=='third_broadcast_fails' and len(broadcasts)==3 else 0
        before={key:bytes(value) for key,value in p.items()};records=list(guest_os.mappings);next_address=guest_os.next_address
        old=vm_module.B
        try:
            startup_model.initialize_default_task(guest_os,vm_module=vm_module,image_base=image,
                entry_stack_address=h.GUEST+0x900000 if label=='unmapped_stack' else TASK_TOP,
                return_address=1<<63 if label=='tagged_return' else h.STOP,thread_pointer=h.WORKER_TLS,
                scratch_address=h.GUEST+0xF800,libc_base=h.LIBC,brk=lambda *args:calls.append('brk') or 0x13600000,
                os_call=service,broadcast=broadcast)
        except (a.RefillUnsupported,ValueError):pass
        else:raise AssertionError((label,'must reject'))
        assert before=={key:bytes(value) for key,value in p.items()} and records==guest_os.mappings and next_address==guest_os.next_address
        assert vm_module.B==old
        assert len(broadcasts)=={'busy_third_once':2,'third_broadcast_fails':3,'unmapped_stack':0,'tagged_return':0}[label]
        rows.append(dict(case=label,rejected=True,guest_pages_mappings_protection_and_cursor_unchanged=True,
            vm_base_restored=True,broadcasts_before_rejection=len(broadcasts),external_provider_effects_not_rolled_back=bool(calls)))
    return rows


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--library',type=Path,required=True);ap.add_argument('--libc',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==LIBC_SHA256
    os.environ['TOMATO_LIBMETASEC']=str(args.library.resolve())
    import vm_full
    rows=[case(args.library,args.libc,image,vm_full) for image in (0x122C0000,0x775C205000)]
    rejected=rejection_cases(args.library,args.libc,vm_full)
    print('real allocator task rejection/rollback',len(rejected),'PASS',flush=True)
    report=dict(schema='vm9-default-task-actual-allocator-v1',sample_sha256=oracle.LIBRARY_SHA256,libc_sha256=LIBC_SHA256,
        cases=rows,rejection_cases=rejected,serial_default_task_actual_allocator_composed=True,
        native_input_snapshot_used=False,explicit_virtual_os=True,independent_stack_and_tls_regions=True,
        same_startup_worker_actual_allocator_composed=False,complete_python_medusa=False,current_online_header_matrix_verified=False)
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')


if __name__=='__main__':main()
