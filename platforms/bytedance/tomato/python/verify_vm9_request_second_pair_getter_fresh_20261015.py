"""Fresh +28868c/+2633a4 tail-called scoped reference copy comparisons."""
from pathlib import Path
import argparse,ast,hashlib,inspect,json
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
import verify_vm9_reference_scopes_fresh_20261011 as fixture_owner
import vm9_request_287474_vm as second
from vm9_allocator import RefillUnsupported,_read_span,_write_span
G=oracle.GUEST;SP=fixture_owner.SP;TP=fixture_owner.TP
RECEIVER=G+0x6000;PACKED=G+0x1700
BASES=(0x122C0000,0x775C205000)
PROFILES=('cold','warm','count_zero','count_max','NULL_counter','NULL_pointer',
    'cross_page_output','cross_page_source','same_pair','output_before_source',
    'output_after_source','packed_output_alias','packed_receiver_alias','output_counter_alias')


def fixture(library,image,label):
    p,blocks,output,pointer=fixture_owner.fixture(library,image,'copy',
        count=None if label=='NULL_counter' else 0 if label=='count_zero' else 0xFFFFFFFF if label=='count_max' else 2,
        warm=label!='cold',null_object=label=='NULL_pointer')
    receiver=G+0x5FE4 if label=='cross_page_source' else RECEIVER
    source=receiver+0x18
    _write_span(p,source,_read_span(p,fixture_owner.SOURCE,16))
    output={'cross_page_output':G+0x8FFC,'same_pair':source,'output_before_source':source-8,
        'output_after_source':source+8,'packed_output_alias':PACKED,
        'packed_receiver_alias':PACKED+16,'output_counter_alias':fixture_owner.COUNT}.get(label,output)
    _write_span(p,PACKED,b''.join(v.to_bytes(8,'little') for v in (image+0x2633A4,output,receiver)))
    return p,blocks,dict(argument_block_address=PACKED,image_base=image,entry_stack_address=SP,
        thread_pointer=TP,thread_id=137)


def original(library,libc,image,p,blocks):
    expected=fixture_owner.Services(blocks);seen=set();steps=[0]
    watch={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000}
    watch[SP-0x60,24]=None
    def observe(cpu,address):
        steps[0]+=1;offset=address-image
        if offset in (0x28868C,0x2633A4,0x15F580,0x26C858,0x26C9D0):seen.add(offset)
        if offset in (0x347F00,0x347F10):
            expected.diagnostic('pthread_mutex_lock' if offset==0x347F00 else 'pthread_mutex_unlock',cpu.reg_read(arm.UC_ARM64_REG_X0))
        elif offset==0x348310:expected.diagnostic('gettid',137)
    _,memory,_,_=oracle.native(library,image,0x28868C,[PACKED],p,
        libc=libc,real_diagnostics=True,real_singletons=True,real_mutexes=True,real_recursive_mutexes=True,
        malloc_handler=expected.native_malloc,thread_id=137,observed_memory=watch,
        instruction_observer=observe,instruction_limit=100000,
        extra_registers={arm.UC_ARM64_REG_SP:SP,arm.UC_ARM64_REG_TPIDR_EL0:TP})
    assert seen=={0x28868C,0x2633A4,0x15F580,0x26C858,0x26C9D0}
    return memory,watch,expected,steps[0]


def red(library,libc):
    assert not hasattr(second,'apply_request_287474_pair_getter_callback')
    assert not any(isinstance(n,ast.Constant) and n.value==0x28868C for n in ast.walk(ast.parse(inspect.getsource(second.execute_request_287474_vm_prefix))))
    rows=[]
    for image in BASES:
        p,blocks,kw=fixture(library,image,'warm')
        memory,watch,effects,steps=original(library,libc,image,p,blocks)
        assert memory[fixture_owner.OUT-G:fixture_owner.OUT-G+16]==_read_span(p,RECEIVER+0x18,16)
        assert int.from_bytes(memory[fixture_owner.COUNT-G:fixture_owner.COUNT-G+4],'little')==3
        assert memory[PACKED-G:PACKED-G+24]==_read_span(p,PACKED,24)
        rows.append(dict(image_base=hex(image),previous_second_wiring_missing=True,
            original_wrapper_tail_getter_and_scoped_copy_returned=True,hidden_output_pair_and_increment_observed=True,
            packed_arguments_unchanged=True,actual_diagnostic_recursive_mutexes=True,native_snapshot_input=False))
    return rows


def compare(library,libc,image,label):
    p,blocks,kw=fixture(library,image,label)
    memory,watch,expected,steps=original(library,libc,image,p,blocks)
    actual=fixture_owner.Services(blocks)
    output=second.apply_request_287474_pair_getter_callback(p,**kw,allocate=actual.malloc,
        diagnostic_observer=actual.diagnostic)
    assert output==int.from_bytes(_read_span(p,PACKED+8,8),'little') or label=='packed_output_alias'
    assert _read_span(p,G,0xA000)==memory,(label,'guest')
    for (a,n),raw in watch.items():assert _read_span(p,a,n)==raw,(label,hex(a),_read_span(p,a,n).hex(),raw.hex())
    assert actual.events==expected.events and actual.effects.calls==expected.effects.calls,(label,'ordered effects')
    assert actual.effects.blocks==expected.effects.blocks
    print('PASS second pair getter',hex(image),label,steps,flush=True)
    return dict(image_base=hex(image),case=label,actual_wrapper='0x28868c',actual_getter='0x2633a4',
        native_instructions=steps,original_wrapper_tail_getter_and_scoped_copy_returned=True,
        all_declared_guest_image_and_scope_bytes_equal=True,hidden_output_pair_and_ordered_aliases_equal=True,
        ordered_diagnostic_allocator_and_recursive_mutex_effects_equal=True,no_packed_result_store=True,
        native_snapshot_input=False)


def guards(library):
    rows=[]
    for label in ('wrong_target','missing_packed','unaligned_stack','missing_scope','missing_output',
            'missing_source','NULL_receiver','diagnostic_guard_wait','missing_allocator','missing_thread_id'):
        p,blocks,kw=fixture(library,BASES[0],'cold');service=fixture_owner.Services(blocks)
        kw.update(allocate=service.malloc,diagnostic_observer=service.diagnostic)
        if label=='wrong_target':fixture_owner.w(p,PACKED,BASES[0]+1)
        elif label=='missing_packed':del p[PACKED>>12]
        elif label=='unaligned_stack':kw['entry_stack_address']+=1
        elif label=='missing_scope':kw['entry_stack_address']=0x66001000
        elif label=='missing_output':fixture_owner.w(p,PACKED+8,0x66000000)
        elif label=='missing_source':fixture_owner.w(p,PACKED+16,0x66000000)
        elif label=='NULL_receiver':fixture_owner.w(p,PACKED+16,0)
        elif label=='diagnostic_guard_wait':fixture_owner.w(p,BASES[0]+fixture_owner.diagnostics.GUARD+1,2,1)
        elif label=='missing_allocator':kw['allocate']=None
        elif label=='missing_thread_id':kw['thread_id']=None
        before={k:bytes(v) for k,v in p.items()}
        try:second.apply_request_287474_pair_getter_callback(p,**kw)
        except (RefillUnsupported,ValueError,TypeError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_provider_effects_rolled_back=False))
    return rows


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--libc',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--group',choices=('red','getters','guards','all'),default='all');args=parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==fixture_owner.LIBC_SHA256
    e=dict(schema='vm9-request-second-pair-getter-fresh-v1',evidence_date='2026-10-15',
        sample_sha256=oracle.LIBRARY_SHA256,cases=[],negative_cases=[],accepted_native_controls_not_repeated=True,
        native_snapshot_input=False,private_names_or_payloads_published=False,
        whole_physical_stack_bytes_compared=False,complete_physical_ABI_verified=False,
        whole_request_native_differential_verified=False,complete_second_vm_verified=False,
        actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False,
        allocator_provider_mapping_rollback_verified=False)
    if args.group=='red':e['red_cases']=red(args.library,args.libc)
    if args.group in ('getters','all'):e['cases']=[compare(args.library,args.libc,b,n) for b in BASES for n in PROFILES]
    if args.group in ('guards','all'):e['negative_cases']=guards(args.library)
    e.update(native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']))
    args.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS second pair getter',args.group,e['native_Python_controls'],e['rollback_guards'])
if __name__=='__main__':main()
