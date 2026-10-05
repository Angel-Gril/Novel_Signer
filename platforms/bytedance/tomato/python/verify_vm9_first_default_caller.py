"""Fresh native return differences for the first of six default task callers."""
from __future__ import annotations
import argparse,hashlib,json,os
from pathlib import Path
from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_SP
import vm9_startup as startup
from verify_vm9_default_task_prefix import fresh
from verify_vm9_signer_objects import native,GUEST,STOP,LIBRARY_SHA256
from vm9_allocator import _read_span,_write_span


def probe(library,libc,vm_module,base,hot,table_index=0):
    oracle=fresh(library,libc,base,0x3C);model=fresh(library,libc,base,0x3C)
    control=base+0x3E09E8+table_index*0x48;mutex=base+0x3E2EB8;region=GUEST+0x4300
    if hot:
        for pages in (oracle,model):_write_span(pages,control,((1<<64)-1).to_bytes(8,'little'))
    expected={};actual_effects=[];phases=[]
    def observe(cpu,address):
        if address in (base+0x2809D4+table_index*0x1E4,base+0x280A50+table_index*0x1E4):
            phases.append(address-base)
            print(json.dumps(dict(image_base=hex(base),case='cold' if not hot else 'hot',table_index=table_index,nested_returns=len(phases))),flush=True)
        if address==base+0x2805EC+table_index*0x80:
            expected['registers']=[int.from_bytes(cpu.mem_read(GUEST+0xEF00-0x148+i*8,8),'little') for i in range(32)]
            expected['virtual_frame']=bytes(cpu.mem_read(GUEST+0xEF00-0x1B0,0x50))
    def allocation(cpu,size,pointer):actual_effects.append(['allocate',size,pointer])
    def broadcast(cpu):
        actual_effects.append(['broadcast',cpu.reg_read(UC_ARM64_REG_X0),
            int.from_bytes(cpu.mem_read(control,8),'little'),int.from_bytes(cpu.mem_read(mutex,2),'little')]);return 0
    observed={(page<<12,4096):None for page in model if base<=page<<12<base+0x400000}
    _,heap,_,_=native(library,base,0x280590+table_index*0x80,[0],oracle,libc=libc,real_mutexes=True,
        malloc_handler=lambda *_:region,allocation_effect=allocation,
        host_imports={0x3485A0:broadcast},instruction_limit=160000000,
        instruction_observer=observe,observed_memory=observed)
    effects=[]
    def allocate(pages,size):effects.append(['allocate',size,region]);return region
    def notify(pages,address):
        effects.append(['broadcast',address,int.from_bytes(_read_span(pages,control,8),'little'),
            int.from_bytes(_read_span(pages,mutex,2),'little')]);return 0
    result,nested=startup.run_default_initialization_caller(model,table_index=table_index,allocate=allocate,broadcast=notify,
        vm_module=vm_module,entry_stack_address=GUEST+0xEF00,return_address=STOP,
        thread_pointer=GUEST+0xD000,image_base=base)
    assert expected and result.complete
    assert list(result.registers)==expected['registers'],('slots',[(i,hex(a),hex(b)) for i,(a,b) in enumerate(zip(result.registers,expected['registers'])) if a!=b])
    assert _read_span(model,GUEST+0xEF00-0x1B0,0x50)==expected['virtual_frame']
    assert _read_span(model,GUEST,0xA000)==heap,'guest'
    assert all(_read_span(model,address,width)==data for (address,width),data in observed.items()),'image'
    assert effects==actual_effects
    assert len(nested)==len(phases)==(0 if hot else 8)
    return dict(image_base=hex(base),case='hot_once' if hot else 'cold_once',
        table_index=table_index,default_caller_returned=True,caller_vm_steps=result.steps,nested_returns=len(phases),
        all_32_terminal_slots_match=True,virtual_frame_match=True,guest_heap_match=True,
        all_main_image_pages_match=True,ordered_allocation_broadcast_states_match=True,
        once_complete_value_match=True,condition_broadcast_is_explicit_provider=True,
        native_input_snapshot_used=False,all_six_default_callers_complete=False,
        complete_worker_runtime=False,complete_real_allocator_boot=False,complete_python_medusa=False)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--libc',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--table-index',type=int,choices=(0,1),default=0)
    args=parser.parse_args();assert hashlib.sha256(args.library.read_bytes()).hexdigest()==LIBRARY_SHA256
    os.environ['TOMATO_LIBMETASEC']=str(args.library.resolve());import vm_full
    cases=[probe(args.library,args.libc,vm_full,base,hot,args.table_index) for base in (0x122C0000,0x775C205000) for hot in (False,True)]
    report=dict(library_sha256=LIBRARY_SHA256,native_runs=len(cases),cases=cases,
        fresh_elf_stack_tls_allocator_inputs=True,native_input_snapshot_used=False,
        all_six_default_callers_complete=False,complete_real_allocator_boot=False,complete_python_medusa=False)
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(native_runs=len(cases),default_caller_return_match=True,table_index=args.table_index)))
if __name__=='__main__':main()
