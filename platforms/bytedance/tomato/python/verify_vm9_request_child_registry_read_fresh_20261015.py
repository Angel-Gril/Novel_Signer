"""Actual +28156c/+256a18 shared-reader u32 lookup from fresh tree inputs."""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import vm9_registry as registry
import vm9_request_28048c_vm as child
import verify_vm9_registry as tree_fixture
import verify_vm9_signer_objects as oracle
from verify_vm9_jni_environment_fresh_20261007 import LIBC_SHA256
from verify_vm9_strings import Effects
from vm9_allocator import RefillUnsupported,_read_span,_write_span

G=oracle.GUEST;REGISTRY=G+0x8000;PACKED=G+0x1700;SP=G+0xEF00
PROFILES=('empty','found_zero','found_max','found_high_bit','absent_left','absent_right',
    'NUL_equivalent','NULL_query','NULL_value','readers7','shared_mutex','flag255',
    'cross_page_query','cross_page_value','cross_page_packed','packed_value_alias',
    'guard_padding_value_alias','guard_status_value_alias','flag_value_alias','reader_count_value_alias')

def fixture(library,image,label):
    query=b'a\0tail' if label=='NUL_equivalent' else b'0' if label=='absent_left' else b'z' if label=='absent_right' else b'b'
    keys=[] if label=='empty' else [b'a',b'b',b'c']
    p,blocks,addresses=tree_fixture.fixture(library,image,keys+[query]);effects=Effects(blocks=blocks)
    registry.construct_configuration_tree(p,container_address=REGISTRY+8,
        descriptor_address=tree_fixture.DESCRIPTOR,image_base=image,allocate=effects.malloc)
    _write_span(p,REGISTRY+0x80,bytes(0x98));block=G+0x6FF0 if label=='cross_page_packed' else PACKED
    guard=SP-16-0x50
    value_pointer=addresses[1][2] if keys else 0
    if label=='cross_page_value':value_pointer=G+0x5FFE
    elif label=='packed_value_alias':value_pointer=block+24
    elif label=='guard_padding_value_alias':value_pointer=guard+20
    elif label=='guard_status_value_alias':value_pointer=guard+16
    elif label=='flag_value_alias':value_pointer=REGISTRY+0x114
    elif label=='reader_count_value_alias':value_pointer=REGISTRY+0x110
    value=0 if label=='found_zero' else 0xFFFFFFFF if label=='found_max' else 0x80000000 if label=='found_high_bit' else 0x1234ABCD
    if value_pointer:_write_span(p,value_pointer,value.to_bytes(4,'little'))
    for i,(key,payload,pointer) in enumerate(addresses[:-1]):
        if i==1:pointer=0 if label=='NULL_value' else value_pointer
        registry.insert_configuration_pair(p,container_address=REGISTRY+8,key_address=key,value_address=pointer,
            image_base=image,allocate=effects.malloc,free=effects.free)
    key=0 if label=='NULL_query' else addresses[-1][0]
    if label=='cross_page_query':
        key=G+0x6FF8;_write_span(p,key,_read_span(p,addresses[-1][0],24))
    readers=7 if label in ('readers7','reader_count_value_alias') else 0
    _write_span(p,REGISTRY+0x110,readers.to_bytes(4,'little'))
    _write_span(p,REGISTRY+0x114,bytes([255 if label=='flag255' else 0]))
    _write_span(p,REGISTRY+0x88,(0x2000 if label=='shared_mutex' else 0).to_bytes(2,'little'))
    _write_span(p,block,b''.join(v.to_bytes(8,'little') for v in (image+0x256A18,REGISTRY,key,0xA5A5A5A5A5A5A5A5)))
    return p,dict(argument_block_address=block,image_base=image,entry_stack_address=SP),readers

def compare(library,libc,image,label):
    pages,inputs,readers=fixture(library,image,label);initial={k:bytearray(v) for k,v in pages.items()}
    value=child.apply_request_28048c_registry_read_callback(pages,**inputs)
    observed={(page<<12,4096):None for page in initial if image<=page<<12<image+0x400000}
    guard=SP-16-0x50;observed[guard,24]=None;seen=set();steps=[0]
    def observe(cpu,address):
        steps[0]+=1
        if address-image in (0x28156C,0x256A18,0x1654E0,0x1654B4,0x32A444,0x32A4FC):seen.add(address-image)
    result,memory,allocations,ledger=oracle.native(library,image,0x28156C,[inputs['argument_block_address']],initial,
        libc=libc,real_singletons=True,real_mutexes=True,thread_id=137,observed_memory=observed,
        instruction_observer=observe,instruction_limit=50000,extra_registers={arm.UC_ARM64_REG_SP:SP})
    assert result==value and _read_span(pages,G,0xA000)==memory,label
    assert all(_read_span(pages,a,n)==b for (a,n),b in observed.items()),label
    assert not allocations and ledger==[[operation,REGISTRY+0x88] for operation in ('pthread_mutex_lock','pthread_mutex_unlock')*2],label
    assert seen=={0x28156C,0x256A18,0x1654E0,0x1654B4,0x32A444,0x32A4FC},label
    assert int.from_bytes(_read_span(pages,REGISTRY+0x110,4),'little')==readers
    assert _read_span(pages,REGISTRY+0x114,1)==b'\1'
    assert _read_span(pages,inputs['argument_block_address']+28,4)==b'\xA5'*4
    print('PASS child configuration read',hex(image),label,flush=True)
    return dict(image_base=hex(image),case=label,actual_wrapper='0x28156c',actual_getter='0x256a18',
        native_instructions=steps[0],original_wrapper_getter_and_shared_readers_returned=True,
        all_declared_guest_image_and_scope_bytes_equal=True,W_result_and_padding_equal=True,
        four_actual_mutex_transitions_equal=True,reader_count_restored_and_flag_retained=True,
        no_allocation_or_JNI_services=True,native_snapshot_input=False)

def guards(library):
    rows=[]
    for label in ('wrong_target','missing_packed','unaligned_stack','missing_scope',
            'mutex_contention','writer_count','saturated_readers','unknown_comparator',
            'node_bound','missing_query','missing_value','source_bound'):
        pages,inputs,_=fixture(library,tree_fixture.BASES[0],'found_max')
        block=inputs['argument_block_address'];image=inputs['image_base']
        if label=='wrong_target':_write_span(pages,block,(image+1).to_bytes(8,'little'))
        elif label=='missing_packed':del pages[block>>12]
        elif label=='unaligned_stack':inputs['entry_stack_address']+=1
        elif label=='missing_scope':del pages[(SP-0x100)>>12]
        elif label=='mutex_contention':_write_span(pages,REGISTRY+0x88,b'\2\0')
        elif label in ('writer_count','saturated_readers'):_write_span(pages,REGISTRY+0x110,(0x80000000 if label=='writer_count' else 0x7FFFFFFF).to_bytes(4,'little'))
        elif label=='unknown_comparator':_write_span(pages,REGISTRY+8+24,bytes(8))
        elif label=='node_bound':inputs['max_nodes']=1
        elif label=='missing_query':_write_span(pages,block+16,(G+0x10000).to_bytes(8,'little'))
        elif label=='missing_value':del pages[(G+0x2800)>>12]
        elif label=='source_bound':inputs['max_bytes']=0
        before={k:bytes(v) for k,v in pages.items()}
        try:child.apply_request_28048c_registry_read_callback(pages,**inputs)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in pages.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True))
    return rows

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--libc',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--group',choices=('reads','guards','all'),default='all');args=parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==LIBC_SHA256
    report=dict(schema='vm9-request-child-registry-read-fresh-v1',evidence_date='2026-10-15',
        sample_sha256=oracle.LIBRARY_SHA256,cases=[],negative_cases=[],accepted_native_controls_not_repeated=True,
        native_snapshot_input=False,private_names_or_payloads_published=False,
        whole_request_native_differential_verified=False,complete_helper_vm_verified=False,
        complete_child_vm_verified=False,complete_second_vm_verified=False,
        actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False,whole_physical_stack_bytes_compared=False,
        allocator_provider_mapping_rollback_verified=False)
    if args.group in ('reads','all'):report['cases']=[compare(args.library,args.libc,image,label) for image in tree_fixture.BASES for label in PROFILES]
    if args.group in ('guards','all'):report['negative_cases']=guards(args.library)
    report.update(native_Python_controls=len(report['cases']),rollback_guards=len(report['negative_cases']))
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS child registry read',report['native_Python_controls'],report['rollback_guards'])
if __name__=='__main__':main()
