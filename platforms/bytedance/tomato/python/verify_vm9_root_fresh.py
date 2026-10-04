"""Python root factory against native controls from independent fresh ELF inputs.

Python receives fresh ELF/TLS/reference pages before any native constructor,
not an entry snapshot. Native terminal pages are comparison outputs only.
Only counts, offsets, input lengths and comparison booleans are exported.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_PC

import vm9_configuration_init as configuration
import vm9_objects as objects
import vm9_registry as registry
import vm9_root as root
import verify_vm9_root_configuration as oracle
from verify_vm9_signer_objects import GUEST, LIBRARY_SHA256, image_pages
from vm9_allocator import (_read_span, _write_span, RefillUnsupported,
    pthread_key_create, pthread_getspecific, pthread_setspecific)


def probe(library, libc, *, base, property_value, vm_module):
    pages,inputs,_=oracle.fresh_inputs(library,base=base,property_value=property_value)
    pages.update(image_pages(libc,oracle.LIBC_BASE))
    # Python input exists before starting native. These controls only produce
    # expected outputs, never a root/caller/VM input snapshot.
    allocations=[];frees=[];registrations=[];wakes=[];effects=[];expected={}
    generation=oracle.LIBC_BASE+oracle.LIBC_PTHREAD_GENERATION_OFFSET
    def observe(cpu,address):
        if address==base+0x348450:effects.append(["clock",cpu.reg_read(UC_ARM64_REG_X0)])
        if address==base+0x257368:
            backing=GUEST+0xEF00-0xA0-0x80-0x5A0+0x458
            expected["registers"]=[int.from_bytes(cpu.mem_read(backing+i*8,8),"little") for i in range(32)]
        if address==base+0x257660:
            expected.update(guest=bytes(cpu.mem_read(GUEST,0xA000)),
                image={p:bytes(cpu.mem_read(p<<12,4096)) for p in pages if base<=p<<12<base+0x400000},
                tls=bytes(cpu.mem_read(oracle.TLS,0xB00)),
                generation=bytes(cpu.mem_read(generation,141*16)))
    def native_allocate(cpu,size,pointer):allocations.append([size,pointer]);effects.append(["allocate",size,pointer])
    def native_free(cpu,pointer):frees.append(pointer);effects.append(["free",pointer])
    def native_register(cpu,*args):registrations.append(list(args));effects.append(["register",*args])
    def native_wake(cpu,*args):wakes.append(list(args));effects.append(["wake",*args])
    control=oracle.probe(library,libc,base=base,property_value=property_value,
        instruction_observer=observe,allocation_effect=native_allocate,free_effect=native_free,
        registration_effect=native_register,wake_effect=native_wake)
    assert control["returned"] and set(expected)=={"registers","guest","image","tls","generation"}
    model_allocations=[];model_frees=[];model_registrations=[];model_wakes=[];model_effects=[]
    next_pointer=GUEST+0x4000
    def allocate(p,size):
        nonlocal next_pointer
        result=next_pointer;next_pointer+=(size+15)&~15
        if next_pointer>=GUEST+0x9000:raise RefillUnsupported("root fixture arena exhausted")
        _read_span(p,result,size);model_allocations.append([size,result]);model_effects.append(["allocate",size,result])
        return result
    def free(p,pointer):model_frees.append(pointer);model_effects.append(["free",pointer])
    def reallocate(*args):raise RefillUnsupported("observed root path has no realloc")
    def wake(p,pointer,operation,count):
        model_wakes.append([pointer,operation,count]);model_effects.append(["wake",pointer,operation,count]);return 0
    def atexit(p,destructor,obj,dso):
        model_registrations.append([destructor,obj,dso]);model_effects.append(["register",destructor,obj,dso]);return 0
    def create_key(p,key_address,destructor):
        return pthread_key_create(p,key_address=key_address,destructor=destructor,generation_table=generation)
    def get_specific(p,key):return pthread_getspecific(p,key=key,thread_pointer=oracle.TLS,generation_table=generation)
    def set_specific(p,key,value):return pthread_setspecific(p,key=key,value=value,thread_pointer=oracle.TLS,generation_table=generation)
    def get_tls(p,control_address):
        return objects.get_emulated_tls_address(p,control_address=control_address,image_base=base,
            allocate=allocate,reallocate=reallocate,get_specific=get_specific,set_specific=set_specific,
            create_key=create_key,once_wake=wake)
    def thread_destructor(p,destructor,obj,dso):
        assert dso==base+0x34C700
        return objects.register_emulated_thread_destructor(p,destructor_address=destructor,
            object_address=obj,image_base=base,allocate=allocate,get_tls=get_tls,
            create_key=create_key,set_specific=set_specific,register_atexit=atexit,thread_id=137)
    def initialize_registry(p):
        objects.initialize_scoped_tls_registry(p,image_base=base,get_tls=get_tls,register_destructor=thread_destructor)
    def broadcast(p,pointer):return objects.broadcast_condition_no_waiters(p,condition_address=pointer,wake=wake)
    def clock(p,clock_id):model_effects.append(["clock",clock_id]);return 0,1791023800,500000000
    def singleton(p,sp):
        return registry.get_singleton136_reference(p,entry_stack_address=sp,image_base=base,
            allocate=allocate,free=free,read_clock=clock,get_tls=get_tls,
            initialize_registry=initialize_registry,broadcast=broadcast,thread_id=137).wrapper_address
    def read_property(p,name):return property_value
    def syscall(p,number,args):
        if number in (48,56,79):return -2
        if number in (57,63):return -9
        if number==198:return -97
        raise RefillUnsupported("unknown root virtual syscall")
    def mkdir(p,path,mode):_write_span(p,oracle.TLS+0x100,(17).to_bytes(4,"little"));return 0xFFFFFFFF
    def prepare_format(p):
        configuration.prepare_bionic_format_locale(p,once_address=oracle.LIBC_BASE+0xDE938,
            key_address=oracle.LIBC_BASE+0xDE930,generation_table=generation,thread_pointer=oracle.TLS,wake=wake)
    previous_base=vm_module.B
    result=root.construct_root_reference(pages,output_reference_address=GUEST+0x1800,
        first_reference_address=GUEST+0x1000,second_reference_address=GUEST+0x1010,
        initializer_reference_address=GUEST+0x1020,flag=5,entry_stack_address=GUEST+0xEF00,
        thread_pointer=oracle.TLS,image_base=base,vm_module=vm_module,allocate=allocate,reallocate=reallocate,
        free=free,get_singleton=singleton,get_tls=get_tls,initialize_registry=initialize_registry,
        broadcast=broadcast,read_property=read_property,syscall=syscall,errno_address=oracle.TLS+0x100,
        mkdir=mkdir,register_destructor=atexit,thread_id=137,prepare_format=prepare_format)
    assert vm_module.B==previous_base,"VM base restoration"
    assert list(result.vm_result.registers)==expected["registers"],("all32",[i for i,(a,b) in enumerate(zip(result.vm_result.registers,expected["registers"])) if a!=b])
    actual_guest=_read_span(pages,GUEST,0xA000)
    assert actual_guest==expected["guest"],("root guest",[hex(i) for i,(a,b) in enumerate(zip(actual_guest,expected["guest"])) if a!=b][:24])
    assert all(_read_span(pages,p<<12,4096)==v for p,v in expected["image"].items()),"root globals"
    assert _read_span(pages,oracle.TLS,0xB00)==expected["tls"],"root TLS"
    assert _read_span(pages,generation,141*16)==expected["generation"],"root generations"
    assert model_allocations==allocations,"root allocations"
    assert model_frees==frees,"root frees"
    assert model_registrations==registrations,"root destructor registrations"
    assert model_wakes==wakes,"root wakes"
    assert model_effects==effects,"root ordered effects"
    assert int.from_bytes(_read_span(pages,GUEST+0x1800,8),"little")==result.object_address
    assert int.from_bytes(_read_span(pages,result.reference_count_address,4),"little")==1
    return dict(image_base=hex(base),native_control_returned=True,
        steps=result.vm_result.steps,stop_bytecode_offset=hex(result.vm_result.stop_offset),
        input_string_lengths=[len(inputs[0]),len(inputs[0]),len(inputs[1])],
        guest_objects_match=True,all_image_pages_match=True,tls_match=True,pthread_generations_match=True,
        all_32_vm_slots_match=True,allocation_sequence_match=True,free_sequence_match=True,
        registration_sequence_match=True,wake_sequence_match=True,ordered_effects_match=True,
        allocations=len(allocations),explicit_frees=len(frees),registrations=len(registrations),
        wakes=len(wakes),vm_base_restored=True,native_input_snapshot_used=False,
        caller_prelude_python_generated=True,root_reference_count_is_one=True)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--library",type=Path,required=True)
    parser.add_argument("--libc",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==LIBRARY_SHA256
    os.environ["TOMATO_LIBMETASEC"]=str(args.library.resolve())
    import vm_full
    cases=[]
    for base in (0x122C0000,0x775C205000):
        for label,value in (("absent",None),("sdk_30",b"30"),("sdk_negative",b"-1"),("sdk_signed_suffix",b"  +31suffix")):
            result=probe(args.library,args.libc,base=base,property_value=value,vm_module=vm_full)
            result["property_profile"]=label;cases.append(result)
    negatives=[]
    for label in ("unaligned_stack","pac_return","instruction_bound","unmapped_stack","unmapped_tls","missing_bytecode","invalid_word","missing_object","missing_source"):
        pages,_,_=oracle.fresh_inputs(args.library,base=0x122C0000,property_value=None)
        pages.update(image_pages(args.libc,oracle.LIBC_BASE))
        if label=="missing_bytecode":pages.pop((0x122C0000+0x991C0)>>12)
        before={p:bytes(v) for p,v in pages.items()};previous=vm_full.B
        def unexpected(*args):raise AssertionError("root caller preflight invoked environment")
        try:
            root.construct_root_caller(pages,object_address=-1 if label=="invalid_word" else GUEST+(0x100000 if label=="missing_object" else 0x1000),
                source_reference_address=GUEST+(0x100000 if label=="missing_source" else 0x1100),
                entry_stack_address=GUEST+(0x100000 if label=="unmapped_stack" else 0xE001 if label=="unaligned_stack" else 0xE000),
                return_address=1<<63 if label=="pac_return" else 0x122C0000+0x257250,
                thread_pointer=GUEST+(0x100000 if label=="unmapped_tls" else 0xA000),
                image_base=0x122C0000,vm_module=vm_full,max_steps=0 if label=="instruction_bound" else 100000,
                allocate=unexpected,reallocate=unexpected,free=unexpected,get_singleton=unexpected,get_tls=unexpected,
                initialize_registry=unexpected,broadcast=unexpected,read_property=unexpected,
                syscall=unexpected,errno_address=GUEST+0xA100,mkdir=unexpected,register_destructor=unexpected)
        except (RefillUnsupported,ValueError):
            assert before=={p:bytes(v) for p,v in pages.items()},label+" page rollback"
            assert vm_full.B==previous,label+" VM base restoration"
            negatives.append(dict(case=label,rejected=True,page_rollback=True,vm_base_restored=True))
        else:raise AssertionError(label+" root caller accepted")
    factory_negatives=[]
    for fail_index in (0,40):
        pages,_,_=oracle.fresh_inputs(args.library,base=0x122C0000,property_value=None)
        pages.update(image_pages(args.libc,oracle.LIBC_BASE))
        before={p:bytes(v) for p,v in pages.items()};previous=vm_full.B;calls=[]
        def allocation_failure(p,size):
            if len(calls)==fail_index:raise RefillUnsupported("injected factory allocation failure")
            pointer=GUEST+0x4000+sum((v+15)&~15 for v in calls)
            calls.append(size);return pointer
        def unused(*args):raise AssertionError("factory rollback reached environment before injected allocation")
        try:
            root.construct_root_reference(pages,output_reference_address=GUEST+0x1800,
                first_reference_address=GUEST+0x1000,second_reference_address=GUEST+0x1010,
                initializer_reference_address=GUEST+0x1020,flag=5,entry_stack_address=GUEST+0xEF00,
                thread_pointer=oracle.TLS,image_base=0x122C0000,vm_module=vm_full,
                allocate=allocation_failure,reallocate=unused,free=unused,get_singleton=unused,
                get_tls=unused,initialize_registry=unused,broadcast=unused,read_property=unused,
                syscall=unused,errno_address=GUEST+0xA100,mkdir=unused,register_destructor=unused)
        except RefillUnsupported as exc:
            assert str(exc)=="injected factory allocation failure",str(exc)
            assert len(calls)==fail_index
            assert before=={p:bytes(v) for p,v in pages.items()},"factory page rollback"
            assert vm_full.B==previous,"factory VM base restoration"
            factory_negatives.append(dict(case="allocation_failure_"+str(fail_index),
                rejected=True,page_rollback=True,vm_base_restored=True,
                allocation_calls_before_failure=len(calls),external_effects_rolled_back=False))
        else:raise AssertionError("factory accepted injected allocation failure")
    report=dict(library_sha256=LIBRARY_SHA256,libc_sha256=hashlib.sha256(args.libc.read_bytes()).hexdigest(),
        native_runs=len(cases),cases=cases,root_caller_negative_count=len(negatives),
        root_caller_negative_cases=negatives,root_factory_negative_count=len(factory_negatives),
        root_factory_negative_cases=factory_negatives,fresh_elf_inputs=True,native_input_snapshot_used=False,
        external_captured_pages_used=False,native_code_used_by_python_model=False,jvm_used=False,
        bounded_root_factory_python_implemented=True,complete_python_medusa=False,
        complete_process_initialization=False,real_arena_os_region_initialization=False,
        diagnostic_scope_excluded=True,virtual_environment_profile="missing_files_unavailable_logger_no_waiters",
        allocator_boundary="bounded_nonreusing_malloc_free",
        fresh_input_signer_output_verified=False,online_header_matrix_verified=False)
    args.output.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(dict(native_runs=len(cases),root_caller_negative_count=len(negatives),root_factory_negative_count=len(factory_negatives),bounded_root_factory_python_implemented=True,
        native_input_snapshot_used=False,complete_python_medusa=False)))


if __name__=="__main__":main()
