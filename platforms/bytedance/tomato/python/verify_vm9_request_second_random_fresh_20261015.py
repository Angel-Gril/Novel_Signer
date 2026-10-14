"""New second random callback against original wrapper and matching libc."""
from pathlib import Path
import argparse,ast,hashlib,inspect,json
import verify_vm9_request_random_getter_fresh_20261013 as fixture_owner
import verify_vm9_signer_objects as oracle
import vm9_request_random as model
import vm9_request_287474_vm as second
from vm9_allocator import RefillUnsupported,_read_span,_write_span
BASES=fixture_owner.BASES;SP=fixture_owner.SP;TP=fixture_owner.TP;LIBC_BASE=fixture_owner.LIBC_BASE
PROFILES=('default','warm','type_zero','seconds_wide','failure_errno','guard_byte_two',
    'completed_second_byte','packed_cross_page')


def fixture(library,libc,image,label):
    p,values=fixture_owner.fresh(library,libc,image,label)
    block=oracle.GUEST+0x2FFC if label=='packed_cross_page' else fixture_owner.PACKED
    _write_span(p,block,(image+0x26CC8C).to_bytes(8,'little')+b'\xA5'*24)
    return p,values,block


def identity(library):
    p=oracle.image_pages(library,BASES[0]);image=BASES[0]
    raw=bytes.fromhex('fe4fbfa9080040f9f30300aa00013fd6600a00b9fe4fc1a8c0035fd6')
    assert _read_span(p,image+0x28863C,28)==_read_span(p,image+0x288B08,28)==raw
    return dict(byte_count=28,identical_to_existing_token_random_wrapper=True,result_offset=8,result_width=4)


def original(library,libc,image,p,values,block):
    clock=fixture_owner.Clock(values);imports={};seen=set();steps=[0]
    def redirect(entry):
        def call(c):c.reg_write(fixture_owner.arm.UC_ARM64_REG_PC,entry)
        return call
    fixture_owner.imports_owner.bind_native_imports(library,libc,redirect,imports)
    def observe(c,a):
        steps[0]+=1
        if a-image in (0x28863C,0x26CC8C):seen.add(a-image)
    observed={(page<<12,4096):None for page in p if
        image<=page<<12<image+0x400000 or LIBC_BASE<=page<<12<LIBC_BASE+0x100000}
    observed.update({(TP+0x10,0x20):None,(SP-0x38,8):None,(SP-0x40,8):None})
    result,memory,allocations,services=oracle.native(library,image,0x28863C,[block],p,
        libc=libc,real_mutexes=True,real_singletons=True,thread_id=137,
        syscall_handler=clock.native,host_imports=imports,observed_memory=observed,
        instruction_observer=observe,extra_registers={fixture_owner.arm.UC_ARM64_REG_TPIDR_EL0:TP},instruction_limit=100000)
    assert not allocations and seen=={0x28863C,0x26CC8C}
    return result,memory,observed,clock,steps[0]


def invoke(p,image,block,clock,changes=None):
    kw=dict(argument_block_address=block,image_base=image,libc_base=LIBC_BASE,
        entry_stack_address=SP,thread_pointer=TP,syscall=clock.model,errno_address=TP+0x10,thread_id=137)
    kw.update(changes or {})
    return model.store_request_random_callback(p,**kw)


def red(library,libc):
    assert not any(isinstance(n,ast.Constant) and n.value==0x28863C for n in ast.walk(ast.parse(inspect.getsource(second.execute_request_287474_vm_prefix))))
    rows=[]
    for image in BASES:
        p,values,block=fixture(library,libc,image,'default');result,memory,observed,clock,steps=original(library,libc,image,p,values,block)
        assert len(clock.calls)==1 and int.from_bytes(memory[block-oracle.GUEST+8:block-oracle.GUEST+12],'little')==result
        rows.append(dict(image_base=hex(image),original_second_random_wrapper_returned=True,
            actual_libc_random_and_explicit_time_executed=True,previous_second_random_wiring_missing=True,native_snapshot_input=False))
    return rows


def compare(library,libc,image,label):
    p,values,block=fixture(library,libc,image,label)
    returned,memory,observed,expected,steps=original(library,libc,image,p,values,block)
    actual=fixture_owner.Clock(values);result=invoke(p,image,block,actual)
    assert returned==result and actual.calls==expected.calls,(label,'return/effects')
    assert _read_span(p,oracle.GUEST,0xA000)==memory,label
    assert all(_read_span(p,a,n)==raw for (a,n),raw in observed.items()),label
    print('PASS second random',hex(image),label,steps,flush=True)
    return dict(image_base=hex(image),case=label,native_instructions=steps,
        actual_wrapper='0x28863c',actual_getter='0x26cc8c',original_wrapper_and_random_returned=True,
        declared_guest_ELF_libc_TLS_and_scratch_equal=True,clock_syscalls_and_return_equal=True,
        actual_matching_libc_random_guard_mutexes=True,packed_W_result_and_padding_equal=True,
        clock_calls=len(actual.calls),native_snapshot_input=False)


def guards(library,libc):
    rows=[]
    for label in ('bad_target','missing_packed','missing_result_page','contended_guard','contended_random_mutex',
            'unmapped_state','missing_time_provider','invalid_syscall_result','time_provider_canary_mutation',
            'unaligned_stack','missing_thread_id'):
        image=BASES[0];p,values,block=fixture(library,libc,image,'default');clock=fixture_owner.Clock(values);changes={}
        w=fixture_owner.w
        if label=='bad_target':w(p,block,image+1)
        elif label=='missing_packed':del p[block>>12]
        elif label=='missing_result_page':
            block=oracle.GUEST+0x9FF8;w(p,block,image+0x26CC8C);del p[(block+8)>>12]
        elif label=='contended_guard':w(p,image+0x3DEDB0,0x200)
        elif label=='contended_random_mutex':w(p,LIBC_BASE+0xDFB30,1,2)
        elif label=='unmapped_state':w(p,LIBC_BASE+0xDA210,0x66000000)
        elif label=='missing_time_provider':changes['syscall']=None
        elif label=='invalid_syscall_result':changes['syscall']=lambda *a:1<<64
        elif label=='time_provider_canary_mutation':
            def mutate(p,n,args):w(p,TP+0x28,0);return clock.model(p,n,args)
            changes['syscall']=mutate
        elif label=='unaligned_stack':changes['entry_stack_address']=SP-1
        elif label=='missing_thread_id':changes['thread_id']=None
        before={k:bytes(v) for k,v in p.items()}
        try:invoke(p,image,block,clock,changes)
        except (RefillUnsupported,ValueError,TypeError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_provider_effects_rolled_back=False))
    return rows


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--libc',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--group',choices=('red','random','guards','all'),default='all');args=parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==fixture_owner.dependency.LIBC_SHA256
    e=dict(schema='vm9-request-second-random-fresh-v1',evidence_date='2026-10-15',sample_sha256=oracle.LIBRARY_SHA256,
        wrapper_identity=identity(args.library),cases=[],negative_cases=[],accepted_native_controls_not_repeated=True,
        native_snapshot_input=False,private_names_or_payloads_published=False,whole_physical_stack_bytes_compared=False,
        whole_request_native_differential_verified=False,complete_second_vm_verified=False,
        actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,complete_python_medusa=False,
        fresh_signer_output_verified=False,live_server_matrix_verified=False,allocator_provider_mapping_rollback_verified=False)
    if args.group=='red':e['red_cases']=red(args.library,args.libc)
    if args.group in ('random','all'):e['cases']=[compare(args.library,args.libc,b,n) for b in BASES for n in PROFILES]
    if args.group in ('guards','all'):e['negative_cases']=guards(args.library,args.libc)
    e.update(native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']))
    args.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS second random',args.group,e['native_Python_controls'],e['rollback_guards'])
if __name__=='__main__':main()
