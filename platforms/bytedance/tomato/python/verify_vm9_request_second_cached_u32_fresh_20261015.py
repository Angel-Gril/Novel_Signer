"""New +288670/+257880 cached W getter against original ELF instructions."""
from pathlib import Path
import argparse,ast,hashlib,inspect,json
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
from verify_vm9_jni_environment_fresh_20261007 import LIBC_SHA256
import vm9_registry as registry
import vm9_request_287474_vm as second
from vm9_allocator import RefillUnsupported,_read_span,_write_span
G=oracle.GUEST;SP=G+0xEF00;TP=G+0x3000
REGISTRY=G+0x6000;MUTEX=G+0x7000;PACKED=G+0x1700
BASES=(0x122C0000,0x775C205000)
PROFILES=('normal','zero','u32_max','high_bit','readers7','near_reader_limit','shared_mutex',
    'cross_page_field','cross_page_packed','packed_value_alias','packed_receiver_value_alias',
    'reader_count_value_alias','reader_flag_value_alias')
def u(p,a,n=8):return int.from_bytes(_read_span(p,a,n),'little')
def w(p,a,v,n=8):_write_span(p,a,v.to_bytes(n,'little'))


def fixture(library,image,label):
    p=oracle.image_pages(library,image);p.update(oracle.fresh_pages())
    receiver=G+0x5F16 if label=='cross_page_field' else REGISTRY
    mutex=receiver+0x58 if label=='reader_count_value_alias' else receiver+0x54 if label=='reader_flag_value_alias' else MUTEX
    _write_span(p,mutex,bytes(0x98));w(p,receiver+0x100,mutex)
    value={'zero':0,'u32_max':0xFFFFFFFF,'high_bit':0x80000000}.get(label,0x1234ABCD)
    w(p,receiver+0xE8,value,4)
    readers=7 if label in ('readers7','reader_count_value_alias') else 0x7FFFFFFD if label=='near_reader_limit' else 0
    w(p,mutex+0x90,readers,4);w(p,mutex+0x94,0,1)
    w(p,mutex+8,0x2000 if label=='shared_mutex' else 0,2)
    block=G+0x8FF4 if label=='cross_page_packed' else receiver+0xD8 if label=='packed_value_alias' else receiver+0xE0 if label=='packed_receiver_value_alias' else PACKED
    _write_span(p,block,(image+0x257880).to_bytes(8,'little')+receiver.to_bytes(8,'little')+b'\xA5'*8)
    expected=u(p,receiver+0xE8,4)
    if label=='reader_count_value_alias':expected+=1
    elif label=='reader_flag_value_alias':expected=(expected&0xFFFFFF00)|1
    return p,dict(argument_block_address=block,image_base=image,entry_stack_address=SP),mutex,readers,expected


def original(library,libc,image,p,block,mutex):
    seen=set();steps=[0]
    watch={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000}
    watch[SP-0x50,24]=None
    def observe(cpu,address):
        steps[0]+=1
        if address-image in (0x288670,0x257880,0x1654E0,0x1654B4,0x32A444,0x32A4FC):seen.add(address-image)
    result,memory,allocations,ledger=oracle.native(library,image,0x288670,[block],p,
        libc=libc,real_mutexes=True,
        observed_memory=watch,instruction_observer=observe,instruction_limit=50000,
        extra_registers={arm.UC_ARM64_REG_SP:SP,arm.UC_ARM64_REG_TPIDR_EL0:TP})
    assert seen=={0x288670,0x257880,0x1654E0,0x1654B4,0x32A444,0x32A4FC}
    assert not allocations and ledger==[[kind,mutex+8] for kind in ('pthread_mutex_lock','pthread_mutex_unlock')*2],ledger
    return result,memory,watch,steps[0]


def red(library,libc):
    assert not hasattr(registry,'read_configuration_cached_u32')
    assert not any(isinstance(n,ast.Constant) and n.value==0x288670 for n in ast.walk(ast.parse(inspect.getsource(second.execute_request_287474_vm_prefix))))
    rows=[]
    for image in BASES:
        p,kw,mutex,readers,value=fixture(library,image,'reader_count_value_alias')
        result,memory,watch,steps=original(library,libc,image,p,kw['argument_block_address'],mutex)
        assert result==value==8 and int.from_bytes(memory[mutex+0x90-G:mutex+0x94-G],'little')==7
        assert int.from_bytes(memory[PACKED-G+16:PACKED-G+20],'little')==8
        rows.append(dict(image_base=hex(image),previous_owner_and_second_wiring_missing=True,
            original_wrapper_and_cached_getter_returned=True,cached_acquired_count_survives_release=True,
            W_result_stored_at_packed16=True,four_actual_mutex_transitions=True,native_snapshot_input=False))
    return rows


def compare(library,libc,image,label):
    p,kw,mutex,readers,value=fixture(library,image,label)
    result,memory,watch,steps=original(library,libc,image,p,kw['argument_block_address'],mutex)
    actual=second.apply_request_287474_cached_u32_callback(p,**kw)
    assert actual==result==value,(label,'cached value',actual,result,value)
    assert _read_span(p,G,0xA000)==memory,(label,'guest')
    for (a,n),raw in watch.items():assert _read_span(p,a,n)==raw,(label,hex(a))
    assert u(p,mutex+0x90,4)==readers and u(p,mutex+0x94,1)==1
    print('PASS second cached u32',hex(image),label,steps,flush=True)
    return dict(image_base=hex(image),case=label,actual_wrapper='0x288670',actual_getter='0x257880',
        native_instructions=steps,original_wrapper_and_cached_getter_returned=True,
        all_declared_guest_image_and_scope_bytes_equal=True,W_return_packed_result_and_padding_equal=True,
        value_cached_before_reader_release=True,four_actual_mutex_transitions=True,
        reader_count_restored_and_flag_retained=True,no_allocator_or_JNI_services=True,native_snapshot_input=False)


def guards(library):
    rows=[]
    for label in ('wrong_target','missing_packed','missing_result_page','unaligned_stack','missing_scope',
            'missing_receiver','NULL_receiver','missing_value','missing_mutex','mutex_contention',
            'writer_count','saturated_readers','signal_reader_limit'):
        image=BASES[0];p,kw,mutex,readers,value=fixture(library,image,'normal');block=kw['argument_block_address']
        if label=='wrong_target':w(p,block,image+1)
        elif label=='missing_packed':del p[block>>12]
        elif label=='missing_result_page':
            block=G+0x9FF0;kw['argument_block_address']=block
            w(p,block,image+0x257880);w(p,block+8,REGISTRY);del p[(block+16)>>12]
        elif label=='unaligned_stack':kw['entry_stack_address']+=1
        elif label=='missing_scope':kw['entry_stack_address']=0x66001000
        elif label=='missing_receiver':w(p,block+8,0x66000000)
        elif label=='NULL_receiver':w(p,block+8,0)
        elif label=='missing_value':
            receiver=G+0x8F10;w(p,block+8,receiver);w(p,receiver+0x100,mutex);del p[(receiver+0xE8)>>12]
        elif label=='missing_mutex':w(p,REGISTRY+0x100,0x66000000)
        elif label=='mutex_contention':w(p,mutex+8,2,2)
        elif label in ('writer_count','saturated_readers','signal_reader_limit'):
            w(p,mutex+0x90,{'writer_count':0x80000000,'saturated_readers':0x7FFFFFFF,'signal_reader_limit':0x7FFFFFFE}[label],4)
        before={k:bytes(v) for k,v in p.items()}
        try:second.apply_request_287474_cached_u32_callback(p,**kw)
        except (RefillUnsupported,ValueError,TypeError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True))
    return rows


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--libc',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--group',choices=('red','getters','guards','all'),default='all');args=parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==LIBC_SHA256
    e=dict(schema='vm9-request-second-cached-u32-fresh-v1',evidence_date='2026-10-15',sample_sha256=oracle.LIBRARY_SHA256,
        cases=[],negative_cases=[],accepted_native_controls_not_repeated=True,native_snapshot_input=False,
        private_names_or_payloads_published=False,whole_physical_stack_bytes_compared=False,
        complete_physical_ABI_verified=False,whole_request_native_differential_verified=False,
        complete_second_vm_verified=False,actual_URL_header_JNI_conversion_verified=False,
        live_Android_JVM_verified=False,complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False,allocator_provider_mapping_rollback_verified=False)
    if args.group=='red':e['red_cases']=red(args.library,args.libc)
    if args.group in ('getters','all'):e['cases']=[compare(args.library,args.libc,b,n) for b in BASES for n in PROFILES]
    if args.group in ('guards','all'):e['negative_cases']=guards(args.library)
    e.update(native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']))
    args.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS second cached u32',args.group,e['native_Python_controls'],e['rollback_guards'])
if __name__=='__main__':main()
