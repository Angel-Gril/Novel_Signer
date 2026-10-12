"""Fresh nested random continuation and the actual outer callback source.

Runs original +287500/+285ea8 instructions to the shared-reader boundary.
The independent Python path uses matching-libc state and explicit wall time.
"""
from pathlib import Path
import argparse,ast,hashlib,inspect,json,os
from types import SimpleNamespace
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
import verify_vm9_request_random_getter_fresh_20261013 as dependency
import verify_vm9_request_prefix_fresh_20261007 as prefix
import vm9_request_token_vm as model
from vm9_allocator import RefillUnsupported,_read_span,_write_span

BASES=dependency.BASES;SP=dependency.SP;TP=dependency.TP;PACKED=dependency.PACKED


def fresh(library,libc,base,label,kind):
    p,values=dependency.fresh(library,libc,base,label)
    inputs=dict(entry_stack_address=SP,return_address=oracle.STOP,
        thread_pointer=TP,image_base=base,object_address=oracle.GUEST+0x1800,
        saved_frame_pointer=oracle.GUEST+0xDE00,saved_x28=0x123456789ABCDEF0,
        saved_x19=oracle.GUEST+0x2200)
    # Bytecode +118820 loads the owning service at input+0x10, then +0x100.
    # These are synthetic ABI pointers and independently zeroed receiver bytes.
    _write_span(p,inputs['object_address'],bytes(64))
    dependency.w(p,inputs['object_address']+0x10,oracle.GUEST+0x3000)
    _write_span(p,oracle.GUEST+0x3000,bytes(0x108))
    dependency.w(p,oracle.GUEST+0x3100,oracle.GUEST+0x3800)
    _write_span(p,oracle.GUEST+0x3800,bytes(0xA0))
    if kind=='callback':
        inputs.update(return_address=base+0x16AA4C,saved_frame_pointer=SP+0x120,
            saved_x28=oracle.GUEST+0x2200,saved_x19=oracle.GUEST+0x21F8)
        _write_span(p,PACKED,(base+0x287500).to_bytes(8,'little')+inputs['object_address'].to_bytes(8,'little')+b'\xA5'*16)
    return p,inputs,values


def original(library,libc,p,inputs,values,kind):
    base=inputs['image_base'];clock=dependency.Clock(values);imports={};cpus=[]
    def redirect(entry):
        def call(c):c.reg_write(arm.UC_ARM64_REG_PC,entry)
        return call
    dependency.imports_owner.bind_native_imports(library,libc,redirect,imports)
    def observe(c,a):
        if not cpus:cpus.append(c)
    frame_local=SP-0x680;backing=frame_local+0x650-0x118
    watch={(page<<12,4096):None for page in p if
        base<=page<<12<base+0x400000 or dependency.LIBC_BASE<=page<<12<dependency.LIBC_BASE+0x100000}
    watch[backing,0x100]=None
    result,memory,allocations,services=oracle.native(library,base,0x285EA8 if kind=='callback' else 0x287500,
        [PACKED if kind=='callback' else inputs['object_address']],p,
        libc=libc,real_mutexes=True,real_singletons=True,thread_id=137,
        host_imports=imports,syscall_handler=clock.native,instruction_observer=observe,
        stop_offset=0x288B24,observed_memory=watch,instruction_limit=100000,
        extra_registers={arm.UC_ARM64_REG_SP:SP,arm.UC_ARM64_REG_X30:inputs['return_address'],
            arm.UC_ARM64_REG_X29:inputs['saved_frame_pointer'],arm.UC_ARM64_REG_X28:inputs['saved_x28'],
            arm.UC_ARM64_REG_X19:inputs['saved_x19'],arm.UC_ARM64_REG_TPIDR_EL0:TP})
    assert not allocations and all(row[0] in ('gettid','pthread_mutex_lock','pthread_mutex_unlock') for row in services)
    descriptor=bytes(cpus[0].mem_read(result,32))
    target=int.from_bytes(descriptor[:8],'little')-base
    assert target==0x32A444,hex(target)
    return memory,watch,clock,result,descriptor


def red(library,libc,vm_module):
    rows=[]
    assert 'random_services' not in inspect.signature(model.execute_request_token_vm_prefix).parameters
    for base in BASES:
        p,inputs,values=fresh(library,libc,base,'default','nested')
        memory,watch,clock,arg,descriptor=original(library,libc,p,inputs,values,'nested')
        result=model.execute_request_token_vm_prefix(p,vm_module=vm_module,**inputs)
        assert result.callbacks[-1][:2]==(0x288B08,0x26CC8C) and result.steps==179
        rows.append(dict(image_base=hex(base),original_random_and_next_callback_reached=True,
            baseline_nested_prefix_stops_before_random=True,prior_random_services_parameter_missing=True,
            native_snapshot_input=False))
    return rows


def source_callback(vm_module,inputs,services,diag):
    tree=ast.parse(inspect.getsource(prefix.execute_prefix))
    callback=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=='callback')
    ns=dict(vars(prefix),vm_module=vm_module,inputs=inputs,random_services=services,
        image=inputs['image_base'],ledger=[],decoded=[],diagnostic_scope=diag,
        allocate=None,reallocate=None,free=None,
        frame=SimpleNamespace(native_stack_address=SP+0x180,register_backing_address=oracle.GUEST+0x2200))
    exec(compile(ast.Module(body=[callback],type_ignores=[]),str(Path(prefix.__file__).resolve()),'exec'),ns)
    return ns['callback']


def compare(library,libc,base,label,kind,vm_module):
    p,inputs,values=fresh(library,libc,base,label,kind)
    memory,watch,expected,arg,descriptor=original(library,libc,p,inputs,values,kind)
    before={k:bytes(v) for k,v in p.items()};clock=dependency.Clock(values)
    services=dict(libc_base=dependency.LIBC_BASE,syscall=clock.model,errno_address=TP+0x10,thread_id=137)
    if kind=='nested':result=model.execute_request_token_vm_prefix(p,vm_module=vm_module,random_services=services,**inputs)
    else:
        diag={};callback=source_callback(vm_module,inputs,services,diag)
        vm=SimpleNamespace(m=SimpleNamespace(pages=p,u64=lambda a:int.from_bytes(_read_span(p,a,8),'little')))
        try:callback(vm,base+0x285EA8,PACKED)
        except RefillUnsupported as exc:assert 'nested request VM boundary' in str(exc)
        else:raise AssertionError('outer callback falsely completed')
        result=diag['request_nested_vm_boundary_state']
    assert result.callbacks[-1][:2]==(0x288B24,0x32A444)
    assert result.callbacks[-1][2]==arg and _read_span(result.staged,arg,32)==descriptor
    assert clock.calls==expected.calls
    native_words=tuple(int.from_bytes(watch[result.frame.register_backing_address,0x100][i*8:i*8+8],'little') for i in range(32))
    assert result.registers==native_words,[i for i in range(32) if result.registers[i]!=native_words[i]]
    assert _read_span(result.staged,oracle.GUEST,0xA000)==memory
    assert all(_read_span(result.staged,a,n)==raw for (a,n),raw in watch.items() if a!=result.frame.register_backing_address)
    assert before=={k:bytes(v) for k,v in p.items()}
    print('PASS nested random',hex(base),kind,label,result.steps,flush=True)
    return dict(image_base=hex(base),kind=kind,case=label,original_next_callback_reached=True,
        steps=result.steps,stop_bytecode_offset=hex(result.pc-base),next_wrapper='0x288b24',next_target='0x32a444',
        all_32_virtual_registers_and_descriptor_equal=True,guest_ELF_libc_random_state_equal=True,
        walltime_calls_equal=True,supplied_pages_unchanged=True,source_callback_executed=kind=='callback',
        complete_nested_caller_return_verified=False,native_snapshot_input=False)


def guards(library,libc,vm_module):
    rows=[]
    for label in ('missing_syscall','bad_libc_base','contended_random_guard','invalid_budget','early_budget'):
        p,inputs,values=fresh(library,libc,BASES[0],'default','nested');clock=dependency.Clock(values)
        services=dict(libc_base=dependency.LIBC_BASE,syscall=clock.model,errno_address=TP+0x10,thread_id=137)
        extra={}
        if label=='missing_syscall':services['syscall']=None
        elif label=='bad_libc_base':services['libc_base']=-1
        elif label=='contended_random_guard':dependency.w(p,BASES[0]+0x3DEDB0,0x200)
        elif label=='invalid_budget':extra['maxsteps']=0
        elif label=='early_budget':extra['maxsteps']=1
        before={k:bytes(v) for k,v in p.items()};old_base=vm_module.B
        try:model.execute_request_token_vm_prefix(p,vm_module=vm_module,random_services=services,**extra,**inputs)
        except (RefillUnsupported,ValueError,RuntimeError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in p.items()} and vm_module.B==old_base
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,interpreter_image_base_restored=True))
    return rows


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--library',type=Path,required=True);p.add_argument('--libc',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--group',choices=('red','native','callback','guards','all'),default='all')
    args=p.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==dependency.dependency.LIBC_SHA256
    os.environ['TOMATO_LIBMETASEC']=str(args.library.resolve())
    import vm_full
    assert Path(vm_full.__file__).resolve().parent==Path(__file__).resolve().parent
    e=dict(schema='vm9-request-token-random-fresh-v1',evidence_date='2026-10-13',cases=[],negative_cases=[],
        sample_sha256=oracle.LIBRARY_SHA256,libc_sha256=dependency.dependency.LIBC_SHA256,
        native_snapshot_input=False,private_names_or_payloads_published=False,
        whole_physical_stack_bytes_compared=False,whole_request_native_differential_verified=False,
        actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False,
        complete_nested_caller_return_verified=False)
    if args.group=='red':e['red_cases']=red(args.library,args.libc,vm_full)
    for kind,group in (('nested','native'),('callback','callback')):
        if args.group in (group,'all'):
            e['cases'].extend(compare(args.library,args.libc,b,n,kind,vm_full) for b in BASES for n in ('default','warm','seconds_wide'))
    if args.group in ('guards','all'):e['negative_cases']=guards(args.library,args.libc,vm_full)
    e.update(native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']))
    args.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS nested random',args.group,e['native_Python_controls'],e['rollback_guards'])


if __name__=='__main__':main()
