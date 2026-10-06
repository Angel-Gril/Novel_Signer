"""Fresh main startup with actual allocator and explicit descriptor creation.

Native output is an oracle only. Workers, real OS threads and fresh signature
are separate boundaries. Physical libc stack bytes are not compared.
"""
from __future__ import annotations
from pathlib import Path
import argparse,hashlib,json,os,collections
import verify_vm9_worker_allocator as h,verify_vm9_libc_stdio as io
import vm9_allocator as a
import vm9_startup as startup,verify_vm9_root_configuration as root,verify_vm9_signer_objects as oracle
import vm9_startup_allocator as startup_model
from verify_vm9_default_task_prefix import fresh as task_fresh
from elftools.elf.elffile import ELFFile
from unicorn.arm64_const import (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,
    UC_ARM64_REG_PC,UC_ARM64_REG_SP,UC_ARM64_REG_TPIDR_EL0)


def case(LIBRARY,LIBC,IMAGE,vm_module):
    p=h.fresh(LIBRARY,LIBC,IMAGE)
    for key,value in task_fresh(LIBRARY,LIBC,IMAGE,0).items():
     if IMAGE<=key<<12<IMAGE+0x400000:p[key]=bytearray(value)
    seed={k:bytearray(v) for k,v in p.items()};ne=h.Environment(seed,2);me=h.Environment(p,2)
    observed=io.observed_spans();observed[root.TLS,0xb00]=None
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
     if num==98:
      assert cpu.reg_read(UC_ARM64_REG_X1)&0x7f==1;return 0
     return ne.syscall(cpu,num,observed)
    def observe(cpu,pc):
     if pc==IMAGE+0x28040c and not resources[0]:
      resources[0]=True;cpu.mem_map(h.STACK,h.STACK_BYTES)
      for address in range(h.STACK,h.STACK+h.STACK_BYTES,4096):cpu.mem_write(address,bytes(seed[address>>12]))
     if pc==io.LIBC+0x8e250 and not boot[0]:boot[0]=True;cpu.mem_write(io.TABLE,a._read_span(seed,io.TABLE,141*16))
     if pc==IMAGE+0x347fd0:counts['malloc_plt']+=1
     if pc==IMAGE+0x347fa0:counts['free_plt']+=1
     if pc==IMAGE+0x280468:
      stack=h.TOP-0x400;caller.extend([int.from_bytes(cpu.mem_read(stack+0x2b8+i*8,8),'little') for i in range(32)])
    inputs={k:v for k,v in io.inputs(seed).items() if not h.STACK<=k<<12<h.STACK+h.STACK_BYTES and not h.WORKERS[0]<=k<<12<h.WORKERS[-1]+0x2000}
    result,memory,allocations,_=oracle.native(LIBRARY,IMAGE,0x28040c,[],inputs,libc=LIBC,real_malloc=True,real_mutexes=True,real_singletons=True,thread_id=137,
     host_imports={0x348000:create,0x347ea0:register,0x347fa0:redirect('free'),0x348590:redirect('pthread_cond_signal')},
     syscall_handler=syscall,instruction_observer=observe,observed_memory=observed,extra_registers={UC_ARM64_REG_SP:h.TOP,UC_ARM64_REG_TPIDR_EL0:root.TLS},instruction_limit=2000000)
    assert len(threads)==3 and counts['malloc_plt']==16 and not counts['free_plt'] and not allocations
    def model_create(staged,out,attr,entry,arg):
     handle=io.GUEST+0xc800+len(model_threads)*0x100;a._write_span(staged,out,handle.to_bytes(8,'little'));model_threads.append([handle,entry,arg]);return 0
    def model_register(staged,*args):model_records.append(list(args));return 0
    actual=startup_model.initialize_main_startup(me.os,entry_stack_address=h.TOP,return_address=oracle.STOP,
     thread_pointer=root.TLS,image_base=IMAGE,vm_module=vm_module,scratch_address=h.SCRATCH,libc_base=io.LIBC,brk=me.brk,os_call=me.service,
     create_thread=model_create,register_destructor=model_register,thread_id=137,
     signal_condition=lambda staged,address:startup.signal_condition_no_waiters(staged,condition_address=address,wake=lambda *args:0))
    assert list(actual.registers)==caller,'startup VM slots'
    for (address,width),data in observed.items():
     assert a._read_span(p,address,width)==data,('startup observed bytes',hex(address))
    assert a._read_span(p,io.GUEST,0xA000)==memory
    assert me.calls==ne.calls and threads==model_threads and records==model_records
    assert me.os.mappings==ne.os.mappings and me.os.next_address==ne.os.next_address
    assert io.get(p,io.LIBC+0xDB6A0,4)==0
    row=dict(image_base=hex(IMAGE),actual_malloc_plt_calls=16,substituted_allocations=0,
     thread_descriptors=3,destructor_registrations=len(records),all32_vm_slots_and_main_image_match=True,
     guest_main_tls_libc_globals_and_all_owned_mapping_bytes_match=True,
     ordered_os_descriptors_registrations_mapping_protection_and_cursor_match=True,
     main_startup_actual_allocator_composed=True,native_input_snapshot_used=False,
     explicit_virtual_os=True,physical_stack_compared=False,actual_os_threads_created=False)
    print(json.dumps(row),flush=True)
    return row


def rejection_cases(library,libc,vm_module):
    rows=[]
    for label in ('tagged_return','busy_startup_guard','third_thread_creation_failure'):
        image=0x122C0000;pages=h.fresh(library,libc,image)
        for key,value in task_fresh(library,libc,image,0).items():
            if image<=key<<12<image+0x400000:pages[key]=bytearray(value)
        environment=h.Environment(pages,2);created=[]
        if label=='busy_startup_guard':io.put(pages,image+0x3E2D80,2,4)
        before={key:bytes(value) for key,value in pages.items()}
        mappings=list(environment.os.mappings);cursor=environment.os.next_address
        def create(staged,out,attr,entry,arg):
            created.append([entry,arg])
            if label=='third_thread_creation_failure' and len(created)==3:return 11
            io.put(staged,out,io.GUEST+0xC800+(len(created)-1)*0x100)
            return 0
        try:
            startup_model.initialize_main_startup(environment.os,vm_module=vm_module,image_base=image,
                entry_stack_address=h.TOP,return_address=(1<<60)|oracle.STOP if label=='tagged_return' else oracle.STOP,
                thread_pointer=root.TLS,scratch_address=h.SCRATCH,libc_base=io.LIBC,brk=environment.brk,
                os_call=environment.service,create_thread=create,register_destructor=lambda *args:0,thread_id=137,
                signal_condition=lambda staged,address:startup.signal_condition_no_waiters(staged,condition_address=address,wake=lambda *args:0))
        except (a.RefillUnsupported,ValueError):pass
        else:raise AssertionError(('unsupported startup accepted',label))
        assert {key:bytes(value) for key,value in pages.items()}==before
        assert environment.os.mappings==mappings and environment.os.next_address==cursor
        rows.append(dict(case=label,rejected=True,all_guest_pages_mapping_records_protection_and_cursor_unchanged=True,
            thread_create_requests_before_rejection=len(created),external_provider_effects_not_rolled_back=bool(created or environment.calls)))
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
    report=dict(schema='vm9-main-startup-actual-allocator-v1',sample_sha256=oracle.LIBRARY_SHA256,
        libc_sha256=h.LIBC_SHA256,cases=rows,rejection_cases=rejected,
        main_startup_actual_allocator_composed=True,same_startup_worker_actual_allocator_composed=False,
        complete_python_medusa=False,current_online_header_matrix_verified=False)
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print('main startup allocator',len(rows),'native /',len(rejected),'rollback PASS',flush=True)


if __name__=='__main__':main()
