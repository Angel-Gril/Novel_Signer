"""Same fresh main startup -> default worker with actual malloc and argument free.

OS services and serial thread selection are explicit. No native snapshot seeds
Python. Normal return retains TLS support/TSD; OS exit is a separate frontier.
"""
from __future__ import annotations
from pathlib import Path
import argparse,hashlib,json,os,collections
import verify_vm9_worker_allocator as h,verify_vm9_libc_stdio as io
import vm9_allocator as a
import vm9_startup as startup,verify_vm9_root_configuration as root,verify_vm9_signer_objects as oracle
import vm9_startup_allocator as startup_model
from verify_vm9_default_task_prefix import fresh as task_fresh,DEFAULT_CALLERS
from elftools.elf.elffile import ELFFile
from unicorn.arm64_const import (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X29,UC_ARM64_REG_X30,
    UC_ARM64_REG_PC,UC_ARM64_REG_SP,UC_ARM64_REG_TPIDR_EL0)


def case(LIBRARY,LIBC,IMAGE,vm_module):
    p=h.fresh(LIBRARY,LIBC,IMAGE)
    WSTACK=io.GUEST+0x60000;WTOP=WSTACK+0xF000;WTLS=h.WORKERS[0]
    for address in range(WSTACK,WSTACK+0x10000,4096):p[address>>12]=bytearray(4096)
    native_nested=collections.Counter();model_nested=[];native_side=[];model_side=[]
    switched=[False];worker_argument=[None];worker_queue=[None];main_expected={};task_returns=[];caller_top=[0]
    for key,value in task_fresh(LIBRARY,LIBC,IMAGE,0).items():
     if IMAGE<=key<<12<IMAGE+0x400000:p[key]=bytearray(value)
    seed={k:bytearray(v) for k,v in p.items()};ne=h.Environment(seed,2);me=h.Environment(p,2)
    observed=io.observed_spans();observed[root.TLS,0xb00]=None;observed[WTLS,0xb00]=None
    observed.update({(key<<12,4096):None for key in p if IMAGE<=key<<12<IMAGE+0x400000})
    observed.update({(io.LIBC+0xD8DC8,8):None,(io.LIBC+0xDE888,8):None,(io.LIBC+0xDB380,40):None,(io.LIBC+0xE01C0,16):None})
    exports={}
    with LIBC.open('rb') as fp:
     elf=ELFFile(fp)
     exports={s.name:io.LIBC+s['st_value'] for sec in elf.iter_sections() if sec['sh_type']=='SHT_DYNSYM' for s in sec.iter_symbols() if s['st_shndx']!='SHN_UNDEF'}
    threads=[];model_threads=[];counts=collections.Counter();resources=[False];boot=[False];caller=[];records=[];model_records=[]
    def write(cpu,address,value):cpu.mem_write(address,value.to_bytes(8,'little'))
    def create(cpu):
     out,attr,entry,arg=[cpu.reg_read(reg) for reg in (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3)]
     handle=io.GUEST+0xC800+len(threads)*0x100;write(cpu,out,handle);threads.append([handle,entry,arg]);return 0
    def register(cpu):records.append([cpu.reg_read(reg) for reg in (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2)]);return 0
    def redirect(name):
     def effect(cpu):cpu.reg_write(UC_ARM64_REG_PC,exports[name])
     return effect
    def syscall(cpu,num):
     if num==113:
      native_side.append(['clock',cpu.reg_read(UC_ARM64_REG_X0),1000,1234]);cpu.mem_write(cpu.reg_read(UC_ARM64_REG_X1),(1000).to_bytes(8,'little')+(1234).to_bytes(8,'little'));return 0
     if num==98:
      if cpu.reg_read(UC_ARM64_REG_X1)&0x7f==1:
       native_side.append(['wake',cpu.reg_read(UC_ARM64_REG_X0),cpu.reg_read(UC_ARM64_REG_X1),cpu.reg_read(UC_ARM64_REG_X2)]);return 0
      assert switched[0]
      queue=worker_queue[0];assert cpu.reg_read(UC_ARM64_REG_X0)==queue+0x58
      native_side.append(['wait',cpu.reg_read(UC_ARM64_REG_X0),cpu.reg_read(UC_ARM64_REG_X1),cpu.reg_read(UC_ARM64_REG_X2),None]);cpu.mem_write(queue+0x88,b'\0');return -4
     return ne.syscall(cpu,num,observed)
    def observe(cpu,pc):
     if pc-IMAGE in {offset for i in range(6) for offset in (0x280970+i*0x1E4+0x64,0x2809F8+i*0x1E4+0x58)}:native_nested[pc-IMAGE]+=1
     if pc==IMAGE+0x28040c and not resources[0]:
      resources[0]=True;cpu.mem_map(h.STACK,h.STACK_BYTES)
      for start,length in ((WSTACK,0x10000), *((address,0x2000) for address in h.WORKERS)):
       cpu.mem_map(start,length)
       for address in range(start,start+length,4096):cpu.mem_write(address,bytes(seed[address>>12]))
      for address in range(h.STACK,h.STACK+h.STACK_BYTES,4096):cpu.mem_write(address,bytes(seed[address>>12]))
     if pc==io.LIBC+0x8e250 and not boot[0]:boot[0]=True;cpu.mem_write(io.TABLE,a._read_span(seed,io.TABLE,141*16))
     if pc==IMAGE+0x347fd0:counts['malloc_plt']+=1
     if pc==IMAGE+0x347fa0:counts['free_plt']+=1
     if pc==IMAGE+0x280468:
      stack=h.TOP-0x400;caller.extend([int.from_bytes(cpu.mem_read(stack+0x2b8+i*8,8),'little') for i in range(32)])
     if pc==IMAGE+0x280478 and not switched[0]:
      main_expected.update({span:bytes(cpu.mem_read(*span)) for span in observed})
      switched[0]=True;handle,entry,arg=threads[1];worker_argument[0]=arg
      worker_queue[0]=int.from_bytes(cpu.mem_read(arg+0x18,8),'little')
      cpu.reg_write(UC_ARM64_REG_PC,entry);cpu.reg_write(UC_ARM64_REG_SP,WTOP)
      cpu.reg_write(UC_ARM64_REG_X0,arg);cpu.reg_write(UC_ARM64_REG_X30,oracle.STOP)
      cpu.reg_write(UC_ARM64_REG_TPIDR_EL0,WTLS);cpu.reg_write(UC_ARM64_REG_X29,0)
      for index in range(19,29):cpu.reg_write(UC_ARM64_REG_X0+index,0)
     if pc-IMAGE in DEFAULT_CALLERS:caller_top[0]=cpu.reg_read(UC_ARM64_REG_SP)
     if pc-IMAGE in tuple(caller+0x5c for caller in DEFAULT_CALLERS):
      top=caller_top[0];index=DEFAULT_CALLERS.index(pc-IMAGE-0x5c)
      task_returns.append(dict(index=index,registers=[int.from_bytes(cpu.mem_read(top-0x148+i*8,8),'little') for i in range(32)],
       virtual_stack=bytes(cpu.mem_read(top-0x1b0,0x50)),spans={span:bytes(cpu.mem_read(*span)) for span in observed}))
      print('NATIVE_WORKER_CALLER_RETURN',index+1,flush=True)
    inputs={k:v for k,v in io.inputs(seed).items() if not h.STACK<=k<<12<h.STACK+h.STACK_BYTES and not h.WORKERS[0]<=k<<12<h.WORKERS[-1]+0x2000 and not WSTACK<=k<<12<WSTACK+0x10000}
    result,memory,allocations,_=oracle.native(LIBRARY,IMAGE,0x28040c,[],inputs,libc=LIBC,real_malloc=True,real_mutexes=True,real_singletons=True,thread_id=lambda cpu:271 if cpu.reg_read(UC_ARM64_REG_TPIDR_EL0)==WTLS else 137,
     host_imports={0x348000:create,0x347ea0:register,0x347fa0:redirect('free'),0x348590:redirect('pthread_cond_signal'),0x348620:redirect('pthread_key_create'),0x348580:redirect('pthread_setspecific'),
      0x3485D0:redirect('pthread_getspecific'),0x3486B0:redirect('pthread_once'),0x3485B0:redirect('pthread_cond_wait'),
      0x3485C0:redirect('pthread_cond_timedwait'),0x3485A0:lambda cpu:0,
      0x348310:lambda cpu:271 if cpu.reg_read(UC_ARM64_REG_TPIDR_EL0)==WTLS else 137},
     syscall_handler=syscall,instruction_observer=observe,observed_memory=observed,extra_registers={UC_ARM64_REG_SP:h.TOP,UC_ARM64_REG_TPIDR_EL0:root.TLS},instruction_limit=900000000,
     code_hook_ranges=((IMAGE+0x28040c,IMAGE+0x281414),(IMAGE+0x326000,IMAGE+0x327000),
     (IMAGE+0x347E00,IMAGE+0x348700),(io.LIBC+0x8e250,io.LIBC+0x8e254)))
    print('NATIVE_STARTUP_PASS',result,'threads',len(threads),'counts',dict(counts),'substitutions',len(allocations),flush=True)
    def model_create(staged,out,attr,entry,arg):
     handle=io.GUEST+0xc800+len(model_threads)*0x100;a._write_span(staged,out,handle.to_bytes(8,'little'));model_threads.append([handle,entry,arg]);return 0
    def model_register(staged,*args):model_records.append(list(args));return 0
    def wake(staged,*fields):model_side.append(['wake',*fields]);return 0
    actual=startup_model.initialize_main_startup(me.os,entry_stack_address=h.TOP,return_address=oracle.STOP,
     thread_pointer=root.TLS,image_base=IMAGE,vm_module=vm_module,scratch_address=h.SCRATCH,libc_base=io.LIBC,brk=me.brk,os_call=me.service,
     create_thread=model_create,register_destructor=model_register,thread_id=137,
     signal_condition=lambda staged,address:startup.signal_condition_no_waiters(staged,condition_address=address,wake=wake))
    assert list(actual.registers)==caller
    assert threads==model_threads and records==model_records
    for (address,width),data in main_expected.items():assert a._read_span(p,address,width)==data,('main before worker',hex(address))
    def clock(staged,clock_id):model_side.append(['clock',clock_id,1000,1234]);return (1000,1234)
    def futex(staged,address,op,expected,timeout):
     model_side.append(['wait',address,op,expected,timeout]);a._write_span(staged,worker_queue[0]+0x88,b'\0');return -4
    original=startup.run_default_initialization_caller
    def compare(staged,**kwargs):
     actual,nested=original(staged,**kwargs);model_nested.extend(nested);expected=task_returns[kwargs['table_index']]
     assert list(actual.registers)==expected['registers'],('worker VM slots',kwargs['table_index'])
     assert a._read_span(staged,kwargs['entry_stack_address']-0x1b0,0x50)==expected['virtual_stack']
     differences=[]
     for (address,width),data in expected['spans'].items():
      current=a._read_span(staged,address,width)
      if current!=data:differences.append((hex(address),[(hex(address+i-IMAGE) if IMAGE<=address<IMAGE+0x400000 else hex(address+i),x,y) for i,(x,y) in enumerate(zip(current,data)) if x!=y][:24]))
     print('WORKER_SPAN_DIFFS',kwargs['table_index'],differences,flush=True)
     assert not differences,('worker caller spans',kwargs['table_index'])
     print('PYTHON_WORKER_CALLER_MATCH',kwargs['table_index']+1,flush=True)
     return actual,nested
    startup.run_default_initialization_caller=compare
    try:
     worker=startup_model.run_default_queue_worker(me.os,argument_address=model_threads[1][2],image_base=IMAGE,entry_stack_address=WTOP,
      thread_pointer=WTLS,thread_id=271,vm_module=vm_module,scratch_address=h.SCRATCH,libc_base=io.LIBC,brk=me.brk,os_call=me.service,
      broadcast=lambda *args:0,clock=clock,futex=futex)
    finally:startup.run_default_initialization_caller=original
    mismatch=[]
    for (address,width),data in observed.items():
     current=a._read_span(p,address,width)
     if current!=data:mismatch.append((hex(address),[(i,x,y) for i,(x,y) in enumerate(zip(current,data)) if x!=y][:12]))
    print('FINAL_WORKER','six caller controls',len(task_returns),'mismatch',mismatch,'os_match',me.calls==ne.calls,flush=True)
    assert not mismatch and me.calls==ne.calls
    assert len(task_returns)==6 and len(model_nested)==48 and sum(native_nested.values())==48
    assert counts['malloc_plt']==22 and counts['free_plt']==1 and not allocations
    assert worker.return_code==result==0 and len(worker.tasks)==1
    assert native_side==model_side and ne.os.mappings==me.os.mappings and ne.os.next_address==me.os.next_address
    assert a._read_span(p,io.GUEST,0xA000)==memory
    support_key=io.get(p,IMAGE+0x3E2F30,4)
    assert a.pthread_getspecific(p,key=support_key,thread_pointer=WTLS,generation_table=io.TABLE)
    row=dict(image_base=hex(IMAGE),main_thread_id=137,worker_thread_id=271,
     actual_native_malloc_plt_calls=22,actual_native_argument_free_calls=1,substituted_allocations=0,
     native_default_caller_returns=6,python_default_caller_returns_compared=6,
     native_nested_vm_returns=sum(native_nested.values()),python_nested_vm_returns=len(model_nested),
     all32_slots_virtual_stack_image_tls_globals_and_owned_mapping_bytes_match_at_each_caller=True,
     final_guest_image_both_tls_globals_and_all_owned_mapping_bytes_match=True,
     os_clock_wait_wake_order_mapping_records_protection_and_cursor_match=True,
     startup_generated_worker_descriptor_used=True,worker_support_retained_in_tls=True,
     normal_argument_cleanup_verified=True,actual_native_malloc=True,native_input_snapshot_used=False,
     explicit_virtual_os=True,physical_stack_compared=False,actual_os_thread_creation_and_exit_verified=False)
    print(json.dumps(row),flush=True)
    return row


def rejection_cases(library,libc,vm_module):
    rows=[]
    image=0x122C0000
    for label in ('unmapped_worker_stack','busy_third_once','third_broadcast_failure','late_argument_ownership'):
        pages=h.fresh(library,libc,image);worker_stack=io.GUEST+0x60000;worker_top=worker_stack+0xF000
        for address in range(worker_stack,worker_stack+0x10000,4096):pages[address>>12]=bytearray(4096)
        for key,value in task_fresh(library,libc,image,0).items():
            if image<=key<<12<image+0x400000:pages[key]=bytearray(value)
        env=h.Environment(pages,2);threads=[];broadcasts=[];waits=[]
        def create(staged,out,attr,entry,arg):
            handle=io.GUEST+0xC800+len(threads)*0x100;io.put(staged,out,handle);threads.append([handle,entry,arg]);return 0
        startup_model.initialize_main_startup(env.os,vm_module=vm_module,image_base=image,
            entry_stack_address=h.TOP,return_address=oracle.STOP,thread_pointer=root.TLS,
            scratch_address=h.SCRATCH,libc_base=io.LIBC,brk=env.brk,os_call=env.service,
            create_thread=create,register_destructor=lambda *args:0,thread_id=137,
            signal_condition=lambda staged,address:startup.signal_condition_no_waiters(staged,condition_address=address,wake=lambda *args:0))
        arg=threads[1][2];queue=io.get(pages,arg+0x18)
        if label=='unmapped_worker_stack':worker_top=0x7F100000
        if label=='busy_third_once':io.put(pages,image+0x3E09E8+2*0x48,1)
        before={key:bytes(value) for key,value in pages.items()};records=list(env.os.mappings);cursor=env.os.next_address;calls=len(env.calls)
        def broadcast(staged,address):
            broadcasts.append(address)
            if label=='third_broadcast_failure' and len(broadcasts)==3:
                raise a.RefillUnsupported('explicit third broadcast provider failure')
            return 0
        def futex(staged,*args):
            waits.append(args);a._write_span(staged,queue+0x88,b'\0')
            if label=='late_argument_ownership':io.put(staged,arg,io.GUEST+0x1000)
            return -4
        try:
            startup_model.run_default_queue_worker(env.os,vm_module=vm_module,image_base=image,argument_address=arg,
                entry_stack_address=worker_top,thread_pointer=h.WORKERS[0],thread_id=271,
                scratch_address=h.SCRATCH,libc_base=io.LIBC,brk=env.brk,os_call=env.service,
                broadcast=broadcast,clock=lambda *args:(1000,1234),futex=futex)
        except (a.RefillUnsupported,ValueError):pass
        else:raise AssertionError(('unsupported worker accepted',label))
        assert before=={key:bytes(value) for key,value in pages.items()}
        assert records==env.os.mappings and cursor==env.os.next_address
        rows.append(dict(case=label,rejected=True,all_guest_pages_mapping_protection_cursor_unchanged=True,
            broadcasts_before_rejection=len(broadcasts),waits_before_rejection=len(waits),
            external_provider_effects_not_rolled_back=bool(broadcasts or waits or len(env.calls)>calls)))
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
    rows=[case(args.library,args.libc,image,vm_full) for image in (0x122C0000,0x775C205000)]
    rejected=rejection_cases(args.library,args.libc,vm_full)
    assert vm_full.B==initial
    report=dict(schema='vm9-same-startup-worker-actual-allocator-v1',sample_sha256=oracle.LIBRARY_SHA256,
        libc_sha256=h.LIBC_SHA256,cases=rows,rejection_cases=rejected,
        same_startup_worker_actual_allocator_composed=True,worker_allocator_tls_exit_destructors_composed=False,
        complete_python_medusa=False,current_online_header_matrix_verified=False)
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print('same startup worker allocator',len(rows),'native /',len(rejected),'rollback PASS',flush=True)


if __name__=='__main__':main()
