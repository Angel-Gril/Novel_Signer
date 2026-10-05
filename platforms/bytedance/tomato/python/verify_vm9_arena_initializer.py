"""Native return differences for one table initializer including eight nested VMs."""
from __future__ import annotations
import argparse,hashlib,json,os,time
from pathlib import Path
from unicorn.arm64_const import UC_ARM64_REG_SP
import vm9_startup as startup
from verify_vm9_default_task_prefix import fresh
from verify_vm9_signer_objects import native,GUEST,STOP,LIBRARY_SHA256
from vm9_allocator import _read_span


def probe(library,libc,vm_module,base,region):
    oracle=fresh(library,libc,base,0x3C);model=fresh(library,libc,base,0x3C)
    observations=[];native_allocations=[];entered=[];current_entry_stack=0
    def observe(cpu,address):
        nonlocal current_entry_stack
        off=address-base
        if off in (0x280970,0x2809F8):
            current_entry_stack=cpu.reg_read(UC_ARM64_REG_SP);entered.append(off)
        if off in (0x2809D4,0x280A50):
            backing=current_entry_stack-0x148
            observations.append(dict(registers=[int.from_bytes(cpu.mem_read(backing+i*8,8),'little') for i in range(32)],
                heap=bytes(cpu.mem_read(GUEST,0xA000))))
            print(json.dumps(dict(image_base=hex(base),native_nested_returns=len(observations))),flush=True)
    image={(page<<12,4096):None for page in model if base<=page<<12<base+0x400000}
    def allocation(cpu,size,pointer):native_allocations.append([size,pointer])
    _,heap,_,_=native(library,base,0x280890,[0],oracle,libc=libc,instruction_observer=observe,
        instruction_limit=150000000,malloc_handler=lambda *_:region,
        allocation_effect=allocation,observed_memory=image)
    assert native_allocations==[[0x4000,region]] and entered==[0x280970]+[0x2809F8]*7
    assert len(observations)==8
    original=startup.run_initialization_vm;model_phases=[]
    def observed_model(pages,**kwargs):
        result=original(pages,**kwargs)
        expected=observations[len(model_phases)]
        assert list(result.registers)==expected['registers'],('terminal slots',len(model_phases),[(i,hex(a),hex(b)) for i,(a,b) in enumerate(zip(result.registers,expected['registers'])) if a!=b])
        assert _read_span(pages,GUEST,0xA000)==expected['heap'],('phase heap',len(model_phases))
        model_phases.append(result)
        return result
    startup.run_initialization_vm=observed_model
    effects=[]
    def allocate(pages,size):effects.append([size,region]);_read_span(pages,region,size);return region
    try:
        result=startup.initialize_arena_boot(model,image_base=base,allocate=allocate,vm_module=vm_module,
            entry_stack_address=GUEST+0xEF00,return_address=STOP,thread_pointer=GUEST+0xD000)
    finally:startup.run_initialization_vm=original
    assert _read_span(model,GUEST,0xA000)==heap
    assert all(_read_span(model,address,width)==data for (address,width),data in image.items()),'main image'
    assert effects==native_allocations
    assert result.region_address==region and all(r.complete for r in result.caller_results)
    return dict(image_base=hex(base),allocator_region_offset=hex(region-GUEST),
        initialized_region_bytes=0x4000,nested_caller_entries=8,nested_caller_returns=8,
        python_phase_steps=[r.steps for r in result.caller_results],
        all_32_terminal_slots_match_at_every_nested_return=True,
        complete_guest_heap_match_at_every_nested_return=True,all_main_image_pages_match=True,
        allocation_sequence_match=True,first_table_initializer_completed=True,
        full_default_six_caller_task_completed=False,native_input_snapshot_used=False,
        complete_real_allocator_boot=False,complete_python_medusa=False)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--libc',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();assert hashlib.sha256(args.library.read_bytes()).hexdigest()==LIBRARY_SHA256
    os.environ['TOMATO_LIBMETASEC']=str(args.library.resolve());import vm_full
    cases=[probe(args.library,args.libc,vm_full,base,GUEST+0x4300) for base in (0x122C0000,0x775C205000)]
    report=dict(library_sha256=LIBRARY_SHA256,native_runs=len(cases),nested_vm_return_comparisons=8*len(cases),cases=cases,
        synthetic_elf_tls_allocator_inputs=True,native_input_snapshot_used=False,
        complete_real_allocator_boot=False,complete_python_medusa=False)
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(native_runs=len(cases),nested_return_comparisons=8*len(cases),first_initializer_match=True)))
if __name__=='__main__':main()
