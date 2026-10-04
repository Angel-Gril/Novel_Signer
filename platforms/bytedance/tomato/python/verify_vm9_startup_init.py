"""Fresh-input differences for the bounded main-thread startup caller.

Successful thread creation is an explicit deferred guest-scheduler boundary;
workers are queued and not executed by this main-thread comparison.
No native input snapshots or decoded data are exported or used by Python.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn.arm64_const import (UC_ARM64_REG_PC,UC_ARM64_REG_SP,UC_ARM64_REG_X0,
    UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_TPIDR_EL0)
import vm9_startup as startup
import verify_vm9_root_configuration as fixture
from verify_vm9_signer_objects import native,GUEST,STOP,LIBRARY_SHA256,image_pages
from vm9_allocator import _read_span,_write_span,RefillUnsupported


def fresh_inputs(library,libc,base):
    pages,_,_=fixture.fresh_inputs(library,base=base,property_value=None)
    pages.update(image_pages(libc,fixture.LIBC_BASE))
    with library.open('rb') as stream:
        elf=ELFFile(stream)
        for section in elf.iter_sections():
            if section['sh_type']!='SHT_RELA':continue
            symbols=elf.get_section(section['sh_link'])
            for rel in section.iter_relocations():
                if rel['r_info_type'] in (257,1025,1026) and symbols.get_symbol(rel['r_info_sym']).name=='memcpy':
                    _write_span(pages,base+rel['r_offset'],(base+0x347F60+rel['r_addend']).to_bytes(8,'little'))
    return pages


def probe(library,libc,*,base,vm_module,thread_id=137):
    model_pages=fresh_inputs(library,libc,base)
    native_pages={p:v for p,v in fresh_inputs(library,libc,base).items()
        if not fixture.LIBC_BASE<=p<<12<fixture.LIBC_BASE+0x400000}
    native_allocations=[];native_frees=[];native_register=[];native_threads=[];native_wakes=[];native_effects=[]
    expected={}
    with libc.open('rb') as stream:
        elf=ELFFile(stream)
        exports={s.name:fixture.LIBC_BASE+s['st_value'] for section in elf.iter_sections()
            if section['sh_type']=='SHT_DYNSYM' for s in section.iter_symbols() if s['st_shndx']!='SHN_UNDEF'}
    def allocate_effect(cpu,size,pointer):
        native_allocations.append([size,pointer]);native_effects.append(['allocate',size,pointer])
    def free(cpu):
        pointer=cpu.reg_read(UC_ARM64_REG_X0);native_frees.append(pointer);native_effects.append(['free',pointer]);return 0
    def register(cpu):
        values=[cpu.reg_read(r) for r in (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2)]
        native_register.append(values);native_effects.append(['register',*values]);return 0
    def create(cpu):
        values=[cpu.reg_read(r) for r in (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3)]
        assert values[1]==0 and values[2]-base in (0x326A2C,0x3260A4)
        handle=GUEST+0xC800+len(native_threads)*0x100
        cpu.mem_write(values[0],handle.to_bytes(8,'little'))
        native_threads.append([handle,values[2],values[3]])
        native_effects.append(['thread_create',*values,handle]);return 0
    def signal(cpu):cpu.reg_write(UC_ARM64_REG_PC,exports['pthread_cond_signal'])
    def syscall(cpu,number):
        if number==98 and cpu.reg_read(UC_ARM64_REG_X1)&0x7F==1:
            values=[cpu.reg_read(r) for r in (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2)]
            native_wakes.append(values);native_effects.append(['wake',*values]);return 0
        raise RefillUnsupported('unknown startup syscall')
    def observe(cpu,address):
        if address==base+0x280468:
            stack=GUEST+0xEF00-0x400
            expected.update(guest=bytes(cpu.mem_read(GUEST,0xA000)),
                image={p:bytes(cpu.mem_read(p<<12,4096)) for p in model_pages if base<=p<<12<base+0x400000},
                tls=bytes(cpu.mem_read(fixture.TLS,0xB00)),
                generations=bytes(cpu.mem_read(fixture.LIBC_BASE+fixture.LIBC_PTHREAD_GENERATION_OFFSET,141*16)),
                registers=[int.from_bytes(cpu.mem_read(stack+0x2B8+i*8,8),'little') for i in range(32)])
    native(library,base,0x28040C,[],native_pages,libc=libc,real_singletons=True,
        real_mutexes=True,thread_id=thread_id,extra_registers={UC_ARM64_REG_TPIDR_EL0:fixture.TLS},
        host_imports={0x347FA0:free,0x347EA0:register,0x348000:create,0x348590:signal},
        instruction_limit=500000,instruction_observer=observe,syscall_handler=syscall,allocation_effect=allocate_effect)
    assert expected
    model_allocations=[];model_threads=[];model_register=[];model_wakes=[];model_effects=[]
    allocation_next=GUEST+0x4000
    def allocate(p,size):
        nonlocal allocation_next
        pointer=allocation_next;allocation_next+=(size+15)&~15
        if allocation_next>=GUEST+0x9000:raise RefillUnsupported('startup arena exhausted')
        _read_span(p,pointer,size);model_allocations.append([size,pointer]);model_effects.append(['allocate',size,pointer]);return pointer
    def create_thread(p,out,attr,start,arg):
        assert attr==0
        handle=GUEST+0xC800+len(model_threads)*0x100
        _write_span(p,out,handle.to_bytes(8,'little'));model_threads.append([handle,start,arg])
        model_effects.append(['thread_create',out,attr,start,arg,handle]);return 0
    def atexit(p,*args):model_register.append(list(args));model_effects.append(['register',*args]);return 0
    def wake(p,*args):model_wakes.append(list(args));model_effects.append(['wake',*args]);return 0
    def signal_condition(p,address):return startup.signal_condition_no_waiters(p,condition_address=address,wake=wake)
    previous=vm_module.B
    result=startup.initialize_startup_caller(model_pages,entry_stack_address=GUEST+0xEF00,
        return_address=STOP,thread_pointer=fixture.TLS,image_base=base,vm_module=vm_module,
        allocate=allocate,create_thread=create_thread,register_destructor=atexit,
        thread_id=thread_id,signal_condition=signal_condition)
    assert vm_module.B==previous
    assert list(result.registers)==expected['registers'],('slots',[i for i,(a,b) in enumerate(zip(result.registers,expected['registers'])) if a!=b])
    actual=_read_span(model_pages,GUEST,0xA000)
    assert actual==expected['guest'],('guest',[hex(i) for i,(a,b) in enumerate(zip(actual,expected['guest'])) if a!=b][:25])
    assert all(_read_span(model_pages,p<<12,4096)==v for p,v in expected['image'].items()),'image'
    assert _read_span(model_pages,fixture.TLS,0xB00)==expected['tls'],'TLS'
    assert _read_span(model_pages,fixture.LIBC_BASE+fixture.LIBC_PTHREAD_GENERATION_OFFSET,141*16)==expected['generations'],'generation table'
    assert model_allocations==native_allocations,'allocation sequence'
    assert not native_frees,'unexpected free'
    assert model_threads==native_threads,'thread descriptors'
    assert model_register==native_register,'registration sequence'
    assert model_wakes==native_wakes,'wake sequence'
    # Native thread output points to nested physical scratch, while Python
    # owns different temporary scratch. Compare semantic requests, including
    # entry and arg, after removing only the unpublished output address.
    def normalized(values):return [v[:1]+v[2:] if v[0]=='thread_create' else v for v in values]
    assert normalized(model_effects)==normalized(native_effects),'ordered semantic effects'
    return dict(image_base=hex(base),thread_id=thread_id,steps=result.steps,
        stop_bytecode_offset=hex(result.stop_offset),all_32_terminal_slots_match=True,
        guest_objects_match=True,all_main_image_pages_match=True,tls_match=True,generation_table_match=True,
        allocation_sequence_match=True,allocations=len(model_allocations),explicit_frees=len(native_frees),
        thread_creation_count=len(model_threads),thread_entry_offsets=[hex(v[1]-base) for v in model_threads],
        thread_handles_arguments_and_order_match=True,destructor_registrations=len(model_register),
        wake_sequence_match=True,wake_count=len(model_wakes),ordered_semantic_effects_match=True,
        native_input_snapshot_used=False,caller_prelude_python_generated=True,
        worker_execution_deferred=True,physical_thread_output_scratch_compared=False,
        modeled_callbacks=result.modeled_callbacks)


def negative_cases(library,libc,vm_module):
    base=0x122C0000;cases=[]
    for label in ('instruction_bound','unaligned_stack','unmapped_stack',
            'pac_return','unmapped_tls','unmapped_bytecode','invalid_thread_id',
            'recursive_guard','allocator_null','thread_error','missing_thread_handle',
            'condition_error','nonempty_queue'):
        pages=fresh_inputs(library,libc,base)
        if label=='unmapped_bytecode':del pages[(base+0xA7050)>>12]
        if label=='recursive_guard':_write_span(pages,base+0x3E2D80,b'\0\2')
        if label=='nonempty_queue':
            _write_span(pages,base+0x3E2D80,b'\1\1')
            _write_span(pages,base+0x3E2D78,(GUEST+0x6000).to_bytes(8,'little'))
            _write_span(pages,GUEST+0x6000,(GUEST+0x6040).to_bytes(8,'little')+bytes(24))
            _write_span(pages,GUEST+0x6040,bytes(144))
            for offset,value in ((0x18,0x6200),(0x20,0x6230),(0x28,0x6230)):
                _write_span(pages,GUEST+0x6040+offset,(GUEST+value).to_bytes(8,'little'))
        before={k:bytes(v) for k,v in pages.items()};effects=[];position=GUEST+0x4000
        def allocate(p,size):
            nonlocal position
            effects.append('allocate')
            if label=='allocator_null':return 0
            result=position;position+=(size+15)&~15;return result
        def create(p,out,attr,start,arg):
            effects.append('thread_create')
            if label=='thread_error':return 11
            _write_span(p,out,(0 if label=='missing_thread_handle' else GUEST+0xC800).to_bytes(8,'little'))
            return 0
        def register(p,*args):effects.append('register');return 0
        def signal(p,address):effects.append('signal');return 5 if label=='condition_error' else 0
        previous=vm_module.B
        try:
            startup.initialize_startup_caller(pages,
                entry_stack_address=GUEST+(0x200000 if label=='unmapped_stack' else 0xEF01 if label=='unaligned_stack' else 0xEF00),
                return_address=1<<63 if label=='pac_return' else STOP,
                thread_pointer=GUEST+0x200000 if label=='unmapped_tls' else fixture.TLS,
                image_base=base,vm_module=vm_module,allocate=allocate,create_thread=create,
                register_destructor=register,thread_id=-1 if label=='invalid_thread_id' else 137,
                signal_condition=signal,max_steps=0 if label=='instruction_bound' else 100000)
        except (RefillUnsupported,ValueError):
            assert {k:bytes(v) for k,v in pages.items()}==before,label+' page rollback'
            assert vm_module.B==previous,label+' VM base restoration'
            if label not in ('allocator_null','thread_error','missing_thread_handle','condition_error'):
                assert not effects,label+' unexpected environment call'
            cases.append(dict(case=label,rejected=True,guest_page_rollback=True,
                vm_base_restored=True,environment_effect_count=len(effects),external_effects_rolled_back=False))
        else:raise AssertionError(label+' accepted')
    return cases


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--libc',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();assert hashlib.sha256(args.library.read_bytes()).hexdigest()==LIBRARY_SHA256
    os.environ['TOMATO_LIBMETASEC']=str(args.library.resolve());import vm_full
    cases=[probe(args.library,args.libc,base=base,thread_id=tid,vm_module=vm_full)
        for base in (0x122C0000,0x775C205000) for tid in (137,271)]
    negatives=negative_cases(args.library,args.libc,vm_full)
    report=dict(library_sha256=LIBRARY_SHA256,libc_sha256=hashlib.sha256(args.libc.read_bytes()).hexdigest(),
        native_runs=len(cases),cases=cases,negative_count=len(negatives),negative_cases=negatives,fresh_elf_inputs=True,native_input_snapshot_used=False,
        native_code_used_by_python_model=False,worker_execution_deferred=True,
        complete_thread_runtime=False,complete_outer_signer_constructor=False,
        complete_allocator_boot=False,complete_python_medusa=False,jvm_used=False)
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(native_runs=len(cases),negative_count=len(negatives),startup_main_thread_python_implemented=True,complete_python_medusa=False)))


if __name__=='__main__':main()
