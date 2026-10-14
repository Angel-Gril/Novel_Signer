"""Fresh +288658/+257804 hidden-output reference getter comparisons."""
from pathlib import Path
import argparse,ast,hashlib,inspect,json
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
import verify_vm9_reference_scopes_fresh_20261011 as fixture_owner
import vm9_registry as registry
import vm9_request_287474_vm as second
from vm9_allocator import RefillUnsupported,_read_span,_write_span
G=oracle.GUEST;SP=fixture_owner.SP;TP=fixture_owner.TP
REGISTRY=G+0x6000;MUTEX=G+0x7000;PACKED=G+0x1700
BASES=(0x122C0000,0x775C205000)
PROFILES=('cold','warm','count_zero','count_max','NULL_counter','NULL_pointer',
    'readers7','shared_mutex','cross_page_output','cross_page_source',
    'same_pair','output_before_source','output_after_source','packed_output_alias',
    'output_counter_alias','output_mutex_pointer_alias')


def fixture(library,image,label):
    p,blocks,output,pointer=fixture_owner.fixture(library,image,'copy',
        count=None if label=='NULL_counter' else 0 if label=='count_zero' else 0xFFFFFFFF if label=='count_max' else 2,
        warm=label!='cold',null_object=label=='NULL_pointer')
    receiver=G+0x5F20 if label=='cross_page_source' else REGISTRY
    source=receiver+0xD8
    _write_span(p,source,_read_span(p,fixture_owner.SOURCE,16))
    _write_span(p,receiver+0x100,MUTEX.to_bytes(8,'little'))
    _write_span(p,MUTEX,bytes(0x98))
    readers=7 if label=='readers7' else 0
    fixture_owner.w(p,MUTEX+0x90,readers,4)
    fixture_owner.w(p,MUTEX+8,0x2000 if label=='shared_mutex' else 0,2)
    output={'cross_page_output':G+0x8FFC,'same_pair':source,'output_before_source':source-8,
        'output_after_source':source+8,'packed_output_alias':PACKED,
        'output_counter_alias':fixture_owner.COUNT,'output_mutex_pointer_alias':receiver+0x100}.get(label,output)
    _write_span(p,PACKED,b''.join(v.to_bytes(8,'little') for v in (image+0x257804,output,receiver)))
    return p,blocks,dict(argument_block_address=PACKED,image_base=image,entry_stack_address=SP,
        thread_pointer=TP,thread_id=137),readers


def original(library,libc,image,p,blocks):
    expected=fixture_owner.Services(blocks);seen=set();steps=[0];shared=[];diagnostic=[]
    watch={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000}
    watch[SP-0x60,24]=None
    def observe(cpu,address):
        steps[0]+=1;offset=address-image
        if offset==0x257850:
            # The following shared-reader release reuses the dead copy frame.
            # Compare live diagnostic fields here; +12 padding and physical
            # saved-register slots are outside this semantic contract.
            diagnostic.append(bytes(cpu.mem_read(SP-0xB0,12))+bytes(cpu.mem_read(SP-0xA0,8)))
        if offset in (0x288658,0x257804,0x1654E0,0x1654B4,0x15F580,0x26C858,0x26C9D0):seen.add(offset)
        if offset in (0x347F00,0x347F10):
            event=['pthread_mutex_lock' if offset==0x347F00 else 'pthread_mutex_unlock',cpu.reg_read(arm.UC_ARM64_REG_X0)]
            if event[1]==MUTEX+8:shared.append(event)
            else:expected.diagnostic(*event)
        elif offset==0x348310:expected.diagnostic('gettid',137)
    result,memory,allocations,ledger=oracle.native(library,image,0x288658,[PACKED],p,
        libc=libc,real_diagnostics=True,real_singletons=True,real_mutexes=True,real_recursive_mutexes=True,
        malloc_handler=expected.native_malloc,thread_id=137,observed_memory=watch,
        instruction_observer=observe,instruction_limit=100000,
        extra_registers={arm.UC_ARM64_REG_SP:SP,arm.UC_ARM64_REG_TPIDR_EL0:TP})
    assert seen=={0x288658,0x257804,0x1654E0,0x1654B4,0x15F580,0x26C858,0x26C9D0}
    assert shared==[[kind,MUTEX+8] for kind in ('pthread_mutex_lock','pthread_mutex_unlock')*2]
    assert len(diagnostic)==1
    return memory,watch,expected,steps[0],diagnostic[0]


def red(library,libc):
    assert not hasattr(registry,'read_configuration_string_reference')
    assert not any(isinstance(n,ast.Constant) and n.value==0x288658 for n in ast.walk(ast.parse(inspect.getsource(second.execute_request_287474_vm_prefix))))
    rows=[]
    for image in BASES:
        p,blocks,kw,readers=fixture(library,image,'warm')
        memory,watch,effects,steps,diagnostic=original(library,libc,image,p,blocks)
        assert memory[fixture_owner.OUT-G:fixture_owner.OUT-G+16]==_read_span(p,REGISTRY+0xD8,16)
        assert int.from_bytes(memory[fixture_owner.COUNT-G:fixture_owner.COUNT-G+4],'little')==3
        rows.append(dict(image_base=hex(image),previous_owner_and_second_wiring_missing=True,
            original_wrapper_getter_and_diagnostic_copy_returned=True,hidden_output_pair_and_increment_observed=True,
            actual_shared_reader_and_recursive_mutexes=True,native_snapshot_input=False))
    return rows


def compare(library,libc,image,label):
    p,blocks,kw,readers=fixture(library,image,label)
    memory,watch,expected,steps,diagnostic=original(library,libc,image,p,blocks)
    actual=fixture_owner.Services(blocks)
    second.apply_request_287474_reference_getter_callback(p,**kw,allocate=actual.malloc,
        diagnostic_observer=actual.diagnostic)
    assert _read_span(p,G,0xA000)==memory,(label,'guest')
    for (a,n),raw in watch.items():assert _read_span(p,a,n)==raw,(label,hex(a),_read_span(p,a,n).hex(),raw.hex())
    assert _read_span(p,SP-0xB0,12)+_read_span(p,SP-0xA0,8)==diagnostic,(label,'live diagnostic scope')
    assert actual.events==expected.events and actual.effects.calls==expected.effects.calls,(label,'ordered effects')
    assert actual.effects.blocks==expected.effects.blocks
    assert int.from_bytes(_read_span(p,MUTEX+0x90,4),'little')==readers
    assert _read_span(p,MUTEX+0x94,1)==b'\x01'
    print('PASS second reference getter',hex(image),label,steps,flush=True)
    return dict(image_base=hex(image),case=label,actual_wrapper='0x288658',actual_getter='0x257804',
        native_instructions=steps,original_wrapper_getter_and_diagnostic_copy_returned=True,
        all_declared_guest_image_and_live_scope_bytes_equal=True,hidden_output_pair_and_ordered_aliases_equal=True,
        diagnostic_fields_compared_before_dead_frame_reuse=True,dead_copy_frame_and_physical_padding_compared=False,
        ordered_diagnostic_allocator_and_recursive_mutex_effects_equal=True,
        four_actual_shared_mutex_transitions=True,reader_count_restored_and_flag_retained=True,
        native_snapshot_input=False)


def guards(library):
    rows=[]
    for label in ('wrong_target','missing_packed','unaligned_stack','missing_scope','missing_output',
            'missing_source','NULL_receiver','shared_mutex_contention','writer_count','saturated_readers',
            'diagnostic_guard_wait','missing_allocator','missing_thread_id'):
        p,blocks,kw,readers=fixture(library,BASES[0],'cold');service=fixture_owner.Services(blocks)
        kw.update(allocate=service.malloc,diagnostic_observer=service.diagnostic)
        if label=='wrong_target':fixture_owner.w(p,PACKED,BASES[0]+1)
        elif label=='missing_packed':del p[PACKED>>12]
        elif label=='unaligned_stack':kw['entry_stack_address']+=1
        elif label=='missing_scope':kw['entry_stack_address']=0x66001000
        elif label=='missing_output':fixture_owner.w(p,PACKED+8,0x66000000)
        elif label=='missing_source':fixture_owner.w(p,PACKED+16,0x66000000)
        elif label=='NULL_receiver':fixture_owner.w(p,PACKED+16,0)
        elif label=='shared_mutex_contention':fixture_owner.w(p,MUTEX+8,2,2)
        elif label in ('writer_count','saturated_readers'):fixture_owner.w(p,MUTEX+0x90,0x80000000 if label=='writer_count' else 0x7FFFFFFF,4)
        elif label=='diagnostic_guard_wait':fixture_owner.w(p,BASES[0]+fixture_owner.diagnostics.GUARD+1,2,1)
        elif label=='missing_allocator':kw['allocate']=None
        elif label=='missing_thread_id':kw['thread_id']=None
        before={k:bytes(v) for k,v in p.items()}
        try:second.apply_request_287474_reference_getter_callback(p,**kw)
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
    e=dict(schema='vm9-request-second-reference-getter-fresh-v1',evidence_date='2026-10-15',
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
    print('PASS second reference getter',args.group,e['native_Python_controls'],e['rollback_guards'])
if __name__=='__main__':main()
