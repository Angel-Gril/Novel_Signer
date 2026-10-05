"""Fresh six-caller task control with independent mapped allocation regions.

Native returned pages/slots are expected outputs only. The matching ELF/libc,
synthetic stack/TLS, arena-region mapping, allocator and broadcast providers
are independent explicit inputs; this does not implement real allocator boot.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
from unicorn.arm64_const import UC_ARM64_REG_SP,UC_ARM64_REG_X0
import vm9_startup as startup
from verify_vm9_default_task_prefix import fresh,DEFAULT_CALLERS
from verify_vm9_signer_objects import native,GUEST,STOP,LIBRARY_SHA256
from vm9_allocator import _read_span,_write_span,RefillUnsupported

ARENAS=GUEST+0x10000
ARENA_BYTES=6*0x4000


def task_model_pages(library,libc,base):
    pages=fresh(library,libc,base,0x3C)
    for address in range(ARENAS,ARENAS+ARENA_BYTES,0x1000):
        pages[address>>12]=bytearray([0x3C])*0x1000
    return pages


def task_negative_checks(library,libc,vm_module):
    base=0x122C0000;checks=[]
    for label in ('busy_third_once','third_allocation_fails','third_broadcast_fails',
            'unmapped_stack','tagged_return'):
        pages=task_model_pages(library,libc,base)
        if label=='busy_third_once':
            _write_span(pages,base+0x3E09E8+2*0x48,(1).to_bytes(8,'little'))
        before={key:bytes(value) for key,value in pages.items()}
        allocations=[];broadcasts=[];old=vm_module.B
        def allocate(staged,size):
            index=len(allocations);allocations.append(size)
            return 0 if label=='third_allocation_fails' and index==2 else ARENAS+index*0x4000
        def broadcast(staged,address):
            broadcasts.append(address)
            return 1 if label=='third_broadcast_fails' and len(broadcasts)==3 else 0
        try:
            startup.run_default_initialization_task(pages,allocate=allocate,broadcast=broadcast,
                vm_module=vm_module,
                entry_stack_address=GUEST+0x200000 if label=='unmapped_stack' else GUEST+0xEF00,
                return_address=1<<63 if label=='tagged_return' else STOP,
                thread_pointer=GUEST+0xD000,image_base=base)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError(label+' accepted')
        assert {key:bytes(value) for key,value in pages.items()}==before,label
        assert vm_module.B==old,label
        assert len(allocations)==({'busy_third_once':2,'third_allocation_fails':3,
            'third_broadcast_fails':3,'unmapped_stack':0,'tagged_return':0}[label])
        checks.append(dict(case=label,rejected=True,guest_pages_unchanged=True,
            vm_base_restored=True,allocator_provider_calls=len(allocations),
            broadcast_provider_calls=len(broadcasts),external_provider_effects_rolled_back=False))
    return checks


def probe(library,libc,vm_module,base,hot):
    oracle=fresh(library,libc,base,0x3C)
    model=task_model_pages(library,libc,base)
    if hot:
        for pages in (oracle,model):
            for index in range(6):
                _write_span(pages,base+0x3E09E8+index*0x48,((1<<64)-1).to_bytes(8,'little'))
    returns=[];native_effects=[];current_stack=0
    def observe(cpu,address):
        nonlocal current_stack
        off=address-base
        if off==0x280554:
            cpu.mem_map(ARENAS,ARENA_BYTES)
            cpu.mem_write(ARENAS,bytes([0x3C])*ARENA_BYTES)
        if off in DEFAULT_CALLERS:current_stack=cpu.reg_read(UC_ARM64_REG_SP)
        if off in tuple(caller+0x5C for caller in DEFAULT_CALLERS):
            index=DEFAULT_CALLERS.index(off-0x5C)
            returns.append(dict(index=index,
                registers=[int.from_bytes(cpu.mem_read(current_stack-0x148+i*8,8),'little') for i in range(32)],
                virtual_stack=bytes(cpu.mem_read(current_stack-0x1B0,0x50)),
                guest=bytes(cpu.mem_read(GUEST,0xA000)),
                arenas=bytes(cpu.mem_read(ARENAS,ARENA_BYTES))))
            print(json.dumps(dict(image_base=hex(base),case='hot' if hot else 'cold',native_default_returns=len(returns))),flush=True)
    allocations=[]
    def allocate_native(cpu,size):
        assert size==0x4000 and len(allocations)<6
        pointer=ARENAS+len(allocations)*0x4000
        allocations.append(pointer);native_effects.append(['allocate',size,pointer]);return pointer
    def broadcast_native(cpu):
        states=[int.from_bytes(cpu.mem_read(base+0x3E09E8+i*0x48,8),'little') for i in range(6)]
        native_effects.append(['broadcast',cpu.reg_read(UC_ARM64_REG_X0),states,
            int.from_bytes(cpu.mem_read(base+0x3E2EB8,2),'little')]);return 0
    observed={(page<<12,4096):None for page in model if base<=page<<12<base+0x400000}
    observed[ARENAS,ARENA_BYTES]=None
    native(library,base,0x280554,[],oracle,libc=libc,real_mutexes=True,
        malloc_handler=allocate_native,host_imports={0x3485A0:broadcast_native},
        instruction_observer=observe,observed_memory=observed,instruction_limit=900000000,
        code_hook_ranges=((base+0x280554,base+0x281414),(base+0x347E00,base+0x348600)))
    assert len(returns)==6
    assert allocations==([] if hot else [ARENAS+i*0x4000 for i in range(6)])
    effects=[];model_allocations=[];compared=[]
    def allocate(pages,size):
        assert size==0x4000 and len(model_allocations)<6
        pointer=ARENAS+len(model_allocations)*0x4000
        model_allocations.append(pointer);effects.append(['allocate',size,pointer]);return pointer
    def broadcast(pages,address):
        effects.append(['broadcast',address,
            [int.from_bytes(_read_span(pages,base+0x3E09E8+i*0x48,8),'little') for i in range(6)],
            int.from_bytes(_read_span(pages,base+0x3E2EB8,2),'little')]);return 0
    original=startup.run_default_initialization_caller
    def compare_caller(pages,**kwargs):
        result,nested=original(pages,**kwargs)
        expected=returns[len(compared)];index=kwargs['table_index']
        assert index==expected['index']
        assert list(result.registers)==expected['registers'],('slots',index,
            [(i,hex(a),hex(b)) for i,(a,b) in enumerate(zip(result.registers,expected['registers'])) if a!=b])
        assert _read_span(pages,kwargs['entry_stack_address']-0x1B0,0x50)==expected['virtual_stack'],('virtual stack',index)
        assert _read_span(pages,GUEST,0xA000)==expected['guest'],('guest',index)
        actual=_read_span(pages,ARENAS,ARENA_BYTES)
        assert actual==expected['arenas'],('arenas',index)
        compared.append(index);return result,nested
    startup.run_default_initialization_caller=compare_caller
    old=vm_module.B
    try:
        result=startup.run_default_initialization_task(model,allocate=allocate,broadcast=broadcast,
            vm_module=vm_module,entry_stack_address=GUEST+0xEF00,return_address=STOP,
            thread_pointer=GUEST+0xD000,image_base=base)
    finally:startup.run_default_initialization_caller=original
    assert vm_module.B==old
    assert effects==native_effects
    assert all(_read_span(model,address,width)==data for (address,width),data in observed.items()),'final image/arenas'
    assert all(caller.complete for caller in result.caller_results)
    assert [len(phases) for phases in result.nested_results]==([0]*6 if hot else [8]*6)
    return dict(image_base=hex(base),case='hot_all_once' if hot else 'cold_all_once',
        default_caller_returns=6,nested_vm_returns=0 if hot else 48,
        caller_steps=[caller.steps for caller in result.caller_results],
        all_32_slots_and_virtual_stack_match_at_each_default_return=True,
        complete_guest_and_all_six_regions_match_at_each_default_return=True,
        all_main_image_pages_match=True,allocation_broadcast_order_and_states_match=True,
        sixth_tailcall_stack_and_return_verified=True,native_input_snapshot_used=False,
        all_six_default_callers_complete=True,serial_default_task_body_complete=True,
        native_code_hook_ranges_limited_to_wrappers_and_plt=True,
        allocator_regions_explicitly_mapped=True,condition_broadcast_is_explicit_provider=True,
        complete_worker_runtime=False,os_thread_exit_destructor_executed=False,
        complete_real_allocator_boot=False,complete_python_medusa=False)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--libc',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--image-base',type=lambda value:int(value,0))
    args=parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==LIBRARY_SHA256
    os.environ['TOMATO_LIBMETASEC']=str(args.library.resolve())
    import vm_full
    bases=(args.image_base,) if args.image_base is not None else (0x122C0000,0x775C205000)
    cases=[probe(args.library,args.libc,vm_full,base,hot) for base in bases for hot in (False,True)]
    negatives=task_negative_checks(args.library,args.libc,vm_full)
    report=dict(library_sha256=LIBRARY_SHA256,native_runs=len(cases),cases=cases,
        negative_checks=len(negatives),negative_cases=negatives,
        fresh_elf_stack_tls_allocator_inputs=True,native_input_snapshot_used=False,
        serial_default_task_body_complete=True,all_six_default_callers_complete=True,
        complete_worker_runtime=False,complete_real_allocator_boot=False,complete_python_medusa=False)
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(native_runs=len(cases),serial_six_caller_task_match=True)))


if __name__=='__main__':main()
