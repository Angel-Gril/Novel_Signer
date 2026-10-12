"""Fresh actual nested shared-reader consumers and composition to scope entry.

Existing reader owners are reused. New original-wrapper and nested controls
cover packed aliases and retained scratch without repeating old helper groups.
"""
from pathlib import Path
import argparse,hashlib,inspect,json,os
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
import verify_vm9_request_token_random_fresh_20261013 as dependency
import vm9_request_token_vm as model
from vm9_allocator import RefillUnsupported,_read_span,_write_span

BASES=dependency.BASES;SP=dependency.SP;TP=dependency.TP
OBJ=oracle.GUEST+0x3800;PACKED=dependency.PACKED;w=dependency.dependency.w


def wrapper_fixture(library,base,label):
    p=oracle.image_pages(library,base);p.update(oracle.fresh_pages())
    _write_span(p,OBJ,bytes(0xA0));target=0x32A444;count=0;packed=PACKED
    if label=='acquire_seven':count=7
    elif label=='acquire_max_minus_one':count=0x7FFFFFFE
    elif label=='release_one':target=0x32A4FC;count=1
    elif label=='release_seven':target=0x32A4FC;count=7
    elif label=='release_max_minus_one':target=0x32A4FC;count=0x7FFFFFFE
    elif label=='shared_mutex':w(p,OBJ,0x2000,2)
    elif label=='packed_count_alias':packed=OBJ+0x80
    w(p,OBJ+0x88,count,4)
    _write_span(p,packed,(base+target).to_bytes(8,'little')+OBJ.to_bytes(8,'little')+b'\xA5'*16)
    return p,target,packed


def original_wrapper(library,libc,base,p,packed,target):
    watch={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
    if target==0x32A444:
        watch[SP-0x48,0x18]=None
    result,memory,allocations,ledger=oracle.native(library,base,0x288B24,[packed],p,
        libc=libc,real_mutexes=True,extra_registers={arm.UC_ARM64_REG_TPIDR_EL0:TP},
        observed_memory=watch,instruction_limit=10000)
    assert not allocations and [r[0] for r in ledger]==['pthread_mutex_lock','pthread_mutex_unlock']
    return result,memory,watch


def original_prefix(library,libc,p,inputs,values,kind):
    base=inputs['image_base'];clock=dependency.dependency.Clock(values);imports={};cpus=[]
    def redirect(entry):
        def call(c):c.reg_write(arm.UC_ARM64_REG_PC,entry)
        return call
    dependency.dependency.imports_owner.bind_native_imports(library,libc,redirect,imports)
    def observe(c,a):
        if not cpus:cpus.append(c)
    backing=SP-0x680+0x650-0x118
    watch={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000 or 0x51000000<=page<<12<0x51100000}
    watch[backing,0x100]=None
    returned,memory,allocations,ledger=oracle.native(library,base,0x285EA8 if kind=='callback' else 0x287500,
        [PACKED if kind=='callback' else inputs['object_address']],p,libc=libc,real_mutexes=True,
        real_singletons=True,thread_id=137,host_imports=imports,syscall_handler=clock.native,
        instruction_observer=observe,stop_offset=0x288B30,observed_memory=watch,instruction_limit=100000,
        extra_registers={arm.UC_ARM64_REG_SP:SP,arm.UC_ARM64_REG_X30:inputs['return_address'],
            arm.UC_ARM64_REG_X29:inputs['saved_frame_pointer'],arm.UC_ARM64_REG_X28:inputs['saved_x28'],
            arm.UC_ARM64_REG_X19:inputs['saved_x19'],arm.UC_ARM64_REG_TPIDR_EL0:TP})
    assert not allocations
    descriptor=bytes(cpus[0].mem_read(returned,32))
    assert int.from_bytes(descriptor[:8],'little')==base+0x26C858
    return memory,watch,clock,returned,descriptor


def red(library,libc,vm_module):
    assert not hasattr(model,'apply_token_shared_reader_callback')
    assert 'continue_shared_readers' not in inspect.signature(model.execute_request_token_vm_prefix).parameters
    rows=[]
    for base in BASES:
        p,target,packed=wrapper_fixture(library,base,'acquire_seven')
        result,memory,watch=original_wrapper(library,libc,base,p,packed,target)
        assert result==0 and int.from_bytes(memory[0x3888:0x388C],'little')==8
        rows.append(dict(image_base=hex(base),original_shared_reader_consumer_returned=True,
            prior_nested_reader_consumer_missing=True,native_snapshot_input=False))
    return rows


def compare_wrapper(library,libc,base,label):
    p,target,packed=wrapper_fixture(library,base,label)
    returned,memory,watch=original_wrapper(library,libc,base,p,packed,target)
    result=model.apply_token_shared_reader_callback(p,argument_block_address=packed,
        image_base=base,entry_stack_address=SP,thread_pointer=TP)
    assert result==returned==0 and _read_span(p,oracle.GUEST,0xA000)==memory
    assert all(_read_span(p,a,n)==raw for (a,n),raw in watch.items())
    print('PASS nested reader consumer',hex(base),label,flush=True)
    return dict(image_base=hex(base),case=label,original_wrapper_returned=True,
        zero_native_return_guest_ELF_packed_and_acquire_scratch_equal=True,
        actual_uncontended_libc_mutexes=True,native_snapshot_input=False)


def compare_prefix(library,libc,base,label,kind,vm_module):
    p,inputs,values=dependency.fresh(library,libc,base,label,kind)
    # BC+118884 loads service+8, then the StringObject's declared W length.
    import vm9_objects as objects
    string=oracle.GUEST+0x3500;source=oracle.GUEST+0x6200
    _write_span(p,source,b'ABCD\0')
    objects.construct_string_object(p,object_address=string,source_address=source,
        allocate=lambda p,n:oracle.GUEST+0x6100,vtable_address=base+0x34F5F8,
        empty_descriptor_address=base+0x6E168)
    w(p,oracle.GUEST+0x3008,string)
    memory,watch,expected,arg,descriptor=original_prefix(library,libc,p,inputs,values,kind)
    before={k:bytes(v) for k,v in p.items()};clock=dependency.dependency.Clock(values)
    services=dict(libc_base=0x51000000,syscall=clock.model,errno_address=TP+0x10,thread_id=137,
        continue_shared_readers=True)
    if kind=='nested':result=model.execute_request_token_vm_prefix(p,vm_module=vm_module,
        random_services=services,continue_shared_readers=True,**inputs)
    else:
        diag={};callback=dependency.source_callback(vm_module,inputs,services,diag)
        from types import SimpleNamespace
        vm=SimpleNamespace(m=SimpleNamespace(pages=p,u64=lambda a:int.from_bytes(_read_span(p,a,8),'little')))
        try:callback(vm,base+0x285EA8,PACKED)
        except RefillUnsupported as exc:assert 'nested request VM boundary' in str(exc)
        else:raise AssertionError('partial nested return was accepted')
        result=diag['request_nested_vm_boundary_state']
    assert result.callbacks[-1][:2]==(0x288B30,0x26C858) and result.callbacks[-1][2]==arg
    assert _read_span(result.staged,arg,32)==descriptor and clock.calls==expected.calls
    native_words=tuple(int.from_bytes(watch[result.frame.register_backing_address,0x100][i*8:i*8+8],'little') for i in range(32))
    assert result.registers==native_words
    assert _read_span(result.staged,oracle.GUEST,0xA000)==memory
    assert all(_read_span(result.staged,a,n)==raw for (a,n),raw in watch.items() if a!=result.frame.register_backing_address)
    assert before=={k:bytes(v) for k,v in p.items()}
    print('PASS nested reader prefix',hex(base),kind,label,result.steps,flush=True)
    return dict(image_base=hex(base),kind=kind,case=label,original_scope_boundary_reached=True,
        steps=result.steps,stop_bytecode_offset=hex(result.pc-base),next_wrapper='0x288b30',next_target='0x26c858',
        all_32_virtual_registers_descriptor_guest_ELF_libc_and_time_equal=True,
        supplied_pages_unchanged=True,source_callback_executed=kind=='callback',native_snapshot_input=False)


def guards(library):
    rows=[]
    for label in ('writer','saturated','zero_release','signal_release','contended','unsupported_target','canary_count_alias'):
        base=BASES[0];p,target,packed=wrapper_fixture(library,base,'acquire_seven')
        kw=dict(argument_block_address=packed,image_base=base,entry_stack_address=SP,thread_pointer=TP)
        if label=='writer':w(p,OBJ+0x88,0x80000000,4)
        elif label=='saturated':w(p,OBJ+0x88,0x7FFFFFFF,4)
        elif label in ('zero_release','signal_release'):
            w(p,packed,base+0x32A4FC);w(p,OBJ+0x88,0 if label=='zero_release' else 0x7FFFFFFF,4)
        elif label=='contended':w(p,OBJ,1,2)
        elif label=='unsupported_target':w(p,packed,base+0x32A570)
        elif label=='canary_count_alias':kw['thread_pointer']=OBJ+0x60
        before={k:bytes(v) for k,v in p.items()}
        try:model.apply_token_shared_reader_callback(p,**kw)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in p.items()}
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True))
    return rows


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--library',type=Path,required=True);p.add_argument('--libc',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--group',choices=('red','consumer','prefix','callback','guards','all'),default='all')
    args=p.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==dependency.dependency.dependency.LIBC_SHA256
    os.environ['TOMATO_LIBMETASEC']=str(args.library.resolve())
    import vm_full
    assert Path(vm_full.__file__).resolve().parent==Path(__file__).resolve().parent
    e=dict(schema='vm9-request-token-readers-fresh-v1',evidence_date='2026-10-13',consumer_cases=[],prefix_cases=[],callback_cases=[],negative_cases=[],
        sample_sha256=oracle.LIBRARY_SHA256,libc_sha256=dependency.dependency.dependency.LIBC_SHA256,
        native_snapshot_input=False,private_names_or_payloads_published=False,whole_physical_stack_bytes_compared=False,
        whole_request_native_differential_verified=False,actual_URL_header_JNI_conversion_verified=False,
        live_Android_JVM_verified=False,complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False,
        complete_nested_caller_return_verified=False)
    if args.group=='red':e['red_cases']=red(args.library,args.libc,vm_full)
    if args.group in ('consumer','all'):e['consumer_cases']=[compare_wrapper(args.library,args.libc,b,n) for b in BASES for n in
        ('acquire_zero','acquire_seven','acquire_max_minus_one','release_one','release_seven','release_max_minus_one','shared_mutex','packed_count_alias')]
    for kind,group,key in (('nested','prefix','prefix_cases'),('callback','callback','callback_cases')):
        if args.group in (group,'all'):e[key]=[compare_prefix(args.library,args.libc,b,n,kind,vm_full) for b in BASES for n in ('default','warm','seconds_wide')]
    if args.group in ('guards','all'):e['negative_cases']=guards(args.library)
    e.update(native_Python_controls=sum(len(e[k]) for k in ('consumer_cases','prefix_cases','callback_cases')),rollback_guards=len(e['negative_cases']))
    args.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS nested readers',args.group,e['native_Python_controls'],e['rollback_guards'])


if __name__=='__main__':main()
