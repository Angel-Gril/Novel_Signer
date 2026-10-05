"""Fresh ELF/stack input differences for first default and arena VM callers."""
from __future__ import annotations
import argparse,hashlib,json,os
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn.arm64_const import (UC_ARM64_REG_PC,UC_ARM64_REG_SP,UC_ARM64_REG_X0,
    UC_ARM64_REG_X19,UC_ARM64_REG_X28,UC_ARM64_REG_X29,UC_ARM64_REG_X30,UC_ARM64_REG_TPIDR_EL0)
import vm9_startup as startup
import verify_vm9_startup_init as fixture
import verify_vm9_root_configuration as root
from verify_vm9_signer_objects import native,GUEST,STOP,LIBRARY_SHA256
from vm9_allocator import _read_span,_write_span,RefillUnsupported


def fresh(library,libc,base,fill=0xA5):
    pages=fixture.fresh_inputs(library,libc,base)
    _write_span(pages,GUEST+0xE000,bytes([fill])*0x1000)
    with library.open('rb') as stream:
        elf=ELFFile(stream)
        for section in elf.iter_sections():
            if section['sh_type']!='SHT_RELA':continue
            symbols=elf.get_section(section['sh_link'])
            for rel in section.iter_relocations():
                if rel['r_info_type'] not in (257,1025,1026):continue
                name=symbols.get_symbol(rel['r_info_sym']).name
                target={'memcpy':0x347F60,'memset':0x347F20,'strlen':0x347F40}.get(name)
                if target is not None:
                    _write_span(pages,base+rel['r_offset'],(base+target+rel['r_addend']).to_bytes(8,'little'))
    return pages


DEFAULT_CALLERS=(0x280590,0x280610,0x280690,0x280710,0x280790,0x280810)


def prelude(library,libc,vm_module,base,caller,fill):
    arguments=(0,) if caller in DEFAULT_CALLERS else (GUEST+0x4000,37) if caller in (0x280970,0x280B54) else (GUEST+0x4800,GUEST+0x4000)
    pages=fresh(library,libc,base,fill);model=fresh(library,libc,base,fill)
    size=0x350 if caller in DEFAULT_CALLERS else {0x280970:0x520,0x2809F8:0x300,0x280B54:0x520,0x280BDC:0x300}[caller]
    start=GUEST+0xEF00-0x20-size-0x180;width=GUEST+0xEF00-start
    observed={(start,width):None}
    native(library,base,caller,arguments,pages,libc=libc,stop_offset=0x1684F0,
        instruction_limit=10000,observed_memory=observed)
    frame=startup.prepare_initialization_caller(model,caller_offset=caller,arguments=arguments,
        entry_stack_address=GUEST+0xEF00,return_address=STOP,thread_pointer=GUEST+0xD000,image_base=base)
    actual=_read_span(model,start,width);expected=observed[start,width]
    assert actual==expected,('caller prelude',hex(caller),[(hex(start+i),a,b) for i,(a,b) in enumerate(zip(actual,expected)) if a!=b][:16])
    return dict(image_base=hex(base),caller_offset=hex(caller),stack_prefill=fill,
        caller_and_generic_prelude_match=True,all_34_initial_backing_words_match=True,
        physical_prelude_span_match=True,native_input_snapshot_used=False)


def boundary(library,libc,vm_module,base,caller,fill,*,bytecode_stop=None):
    arguments=(0,) if caller in DEFAULT_CALLERS else (GUEST+0x4000,0) if caller in (0x280970,0x280B54) else (GUEST+0x4800,GUEST+0x4000)
    native_pages=fresh(library,libc,base,fill);model=fresh(library,libc,base,fill)
    expected={};backing=GUEST+0xEF00-0x148
    virtual_top=GUEST+0xEF00-0x160
    frame_width=0x50 if caller in DEFAULT_CALLERS else {0x280970:0x220,0x2809F8:0x50,0x280B54:0x220,0x280BDC:0x50}[caller]
    virtual_start=virtual_top-frame_width
    class Boundary(Exception):pass
    def observe(cpu,address):
        continuation={0x280970:0x2809D4,0x2809F8:0x280A50,0x280B54:0x280BB8,0x280BDC:0x280C34}.get(caller)
        if (caller in DEFAULT_CALLERS and address==base+0x281598+(caller-0x280590)//0x80*0x14) or (bytecode_stop is None and continuation is not None and address==base+continuation) or (
            bytecode_stop is not None and base+0x168324<=address<base+0x174000 and
            cpu.reg_read(UC_ARM64_REG_X28)==backing and
            int.from_bytes(cpu.mem_read(cpu.reg_read(UC_ARM64_REG_X19),8),'little')==base+bytecode_stop):
            if caller in DEFAULT_CALLERS:
                packed=cpu.reg_read(UC_ARM64_REG_X0)
                expected['words']=[int.from_bytes(cpu.mem_read(packed+i*8,8),'little') for i in range(4)]
            expected['registers']=[int.from_bytes(cpu.mem_read(backing+i*8,8),'little') for i in range(32)]
            expected['guest']=bytes(cpu.mem_read(GUEST,0xA000))
            # VM local stack is above the packed-input frame and below backing.
            expected['vm_frame']=bytes(cpu.mem_read(virtual_start,frame_width))
            expected['image']={page:bytes(cpu.mem_read(page<<12,4096)) for page in model if base<=page<<12<base+0x400000}
            raise Boundary()
    try:native(library,base,caller,arguments,native_pages,libc=libc,instruction_limit=12000000,instruction_observer=observe)
    except Boundary:pass
    assert expected,'native boundary not reached'
    previous=vm_module.B
    result=startup.run_initialization_vm(model,caller_offset=caller,arguments=arguments,
        entry_stack_address=GUEST+0xEF00,return_address=STOP,thread_pointer=GUEST+0xD000,
        image_base=base,vm_module=vm_module,stop_offset=bytecode_stop)
    assert vm_module.B==previous
    assert list(result.registers)==expected['registers'],('slots',[(i,hex(a),hex(b)) for i,(a,b) in enumerate(zip(result.registers,expected['registers'])) if a!=b])
    assert _read_span(model,GUEST,0xA000)==expected['guest'],'guest'
    assert _read_span(model,virtual_start,frame_width)==expected['vm_frame'],('vm frame',[(hex(virtual_start+i),a,b) for i,(a,b) in enumerate(zip(_read_span(model,virtual_start,frame_width),expected['vm_frame'])) if a!=b][:16])
    assert all(_read_span(model,page<<12,4096)==data for page,data in expected['image'].items()),'image'
    if caller in DEFAULT_CALLERS:assert list(result.callbacks[-1]['words'])==expected['words']
    return dict(image_base=hex(base),caller_offset=hex(caller),stack_prefill=fill,
        steps=result.steps,stop_bytecode_offset=hex(result.stop_offset),
        all_32_boundary_registers_match=True,vm_local_frame_match=True,
        all_main_image_pages_match=True,guest_heap_match=True,
        modeled_callback_count=sum(event['executed'] for event in result.callbacks),
        callback_word_package_match=caller in DEFAULT_CALLERS,
        native_input_snapshot_used=False,nested_caller_vm_returned=result.complete,complete_default_task_vm=False)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--libc',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();assert hashlib.sha256(args.library.read_bytes()).hexdigest()==LIBRARY_SHA256
    os.environ['TOMATO_LIBMETASEC']=str(args.library.resolve());import vm_full
    cases=[]
    for base in (0x122C0000,0x775C205000):
        for fill in (0xA5,0x3C):
            for caller in (0x280590,0x280970,0x2809F8):cases.append(prelude(args.library,args.libc,vm_full,base,caller,fill))
            cases.append(boundary(args.library,args.libc,vm_full,base,0x280590,fill))
        for caller in (0x280970,0x2809F8):cases.append(boundary(args.library,args.libc,vm_full,base,caller,0x3C))
    negatives=[];base=0x122C0000
    for label in ('unaligned_stack','unmapped_stack','missing_bytecode','tagged_return','step_budget'):
        pages=fresh(args.library,args.libc,base)
        if label=='missing_bytecode':del pages[(base+0xEDCF0)>>12]
        before={key:bytes(value) for key,value in pages.items()};old=vm_full.B
        try:
            startup.run_initialization_vm(pages,caller_offset=0x280590,arguments=(0,),
                entry_stack_address=GUEST+0xEF08 if label=='unaligned_stack' else GUEST+0x200000 if label=='unmapped_stack' else GUEST+0xEF00,
                return_address=1<<63 if label=='tagged_return' else STOP,
                thread_pointer=GUEST+0xD000,image_base=base,vm_module=vm_full,
                max_steps=1 if label=='step_budget' else 100000)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError(label+' accepted')
        assert {key:bytes(value) for key,value in pages.items()}==before
        assert vm_full.B==old
        negatives.append(dict(case=label,rejected=True,guest_pages_unchanged=True,vm_base_restored=True))
    report=dict(library_sha256=LIBRARY_SHA256,native_runs=len(cases),cases=cases,negative_cases=negatives,
        fresh_elf_and_entry_stack_inputs=True,native_input_snapshot_used=False,
        complete_default_task_vm=False,complete_allocator_boot=False,complete_python_medusa=False)
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(native_runs=len(cases),entry_preludes_and_first_callback_match=True)))
if __name__=='__main__':main()

