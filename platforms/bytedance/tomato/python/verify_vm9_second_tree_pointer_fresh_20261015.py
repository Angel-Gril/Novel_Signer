"""Fresh +2887b0/+256b84 shared-reader tree lookup and full X64 writeback."""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import vm9_registry as registry
import vm9_request_287474_vm as model
import verify_vm9_registry as trees
import verify_vm9_signer_objects as oracle
from verify_vm9_strings import Effects
from vm9_allocator import RefillUnsupported,_read_span,_write_span
G=oracle.GUEST;SP=G+0xEF00;TP=G+0xD000;REGISTRY=G+0x8000;BLOCK=G+0x1700
BASES=(0x122C0000,0x775C205000)
PROFILES=('empty','found_zero','found_high','absent_left','absent_right','NUL_equivalent',
    'NULL_query','NULL_value','readers7','shared_mutex','flag255','cross_page_query',
    'cross_page_value','cross_page_result','packed_value_alias','reader_count_value_alias',
    'flag_value_alias','guard_status_value_alias','guard_pointer_value_alias','result_reader_alias')


def put(p,address,value,width=8):_write_span(p,address,value.to_bytes(width,'little'))


def fixture(library,image,label):
    query=b'a\0tail' if label=='NUL_equivalent' else b'0' if label=='absent_left' else b'z' if label=='absent_right' else b'b'
    keys=[] if label=='empty' else [b'a',b'b',b'c']
    p,blocks,addresses=trees.fixture(library,image,keys+[query]);effects=Effects(blocks=blocks)
    registry.construct_configuration_tree(p,container_address=REGISTRY+0x58,
        descriptor_address=trees.DESCRIPTOR,image_base=image,allocate=effects.malloc)
    _write_span(p,REGISTRY+0x80,bytes(0x98))
    block=G+0x6FE4 if label=='cross_page_result' else REGISTRY+0xF8 if label=='result_reader_alias' else BLOCK
    guard=SP-0x60;pointer=G+0x6000;value=0 if label=='found_zero' else 0xFEDCBA9876543210
    if label=='cross_page_value':pointer=G+0x5FFC
    elif label=='packed_value_alias':pointer=block+24
    elif label=='reader_count_value_alias':pointer=REGISTRY+0x110
    elif label=='flag_value_alias':pointer=REGISTRY+0x114
    elif label=='guard_status_value_alias':pointer=guard+16
    elif label=='guard_pointer_value_alias':pointer=guard+8
    put(p,pointer,value)
    for i,(key,payload,old_pointer) in enumerate(addresses[:-1]):
        target=0 if label=='NULL_value' and i==1 else pointer if i==1 else old_pointer
        registry.insert_configuration_pair(p,container_address=REGISTRY+0x58,key_address=key,
            value_address=target,image_base=image,allocate=effects.malloc,free=effects.free)
    key=0 if label=='NULL_query' else addresses[-1][0]
    if label=='cross_page_query':key=G+0x6FF8;_write_span(p,key,_read_span(p,addresses[-1][0],24))
    readers=7 if label in ('readers7','reader_count_value_alias') else 0
    put(p,REGISTRY+0x110,readers,4);put(p,REGISTRY+0x114,255 if label=='flag255' else 0,1)
    put(p,REGISTRY+0x88,0x2000 if label=='shared_mutex' else 0,2)
    initial_result=0 if label=='result_reader_alias' else 0xA6A6A6A6A6A6A6A6
    _write_span(p,block,b''.join(v.to_bytes(8,'little') for v in (image+0x256B84,REGISTRY,key,initial_result)))
    return p,dict(argument_block_address=block,image_base=image,entry_stack_address=SP),readers


def original(library,libc,image,p,kw):
    seen=set();steps=[0]
    expected={0x2887B0,0x256B84,0x25C168,0x1654E0,0x1654B4,0x32A444,0x32A4FC}
    def observe(cpu,address):
        steps[0]+=1
        if address-image in expected:seen.add(address-image)
    watch={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000}
    watch.update({(G,SP-G-0x1000):None,(SP,G+0x10000-SP):None,(SP-0x60,24):None})
    result,_,allocations,ledger=oracle.native(library,image,0x2887B0,[kw['argument_block_address']],p,
        libc=libc,real_singletons=True,real_mutexes=True,observed_memory=watch,
        instruction_limit=50000,instruction_observer=observe,
        extra_registers={arm.UC_ARM64_REG_SP:SP,arm.UC_ARM64_REG_TPIDR_EL0:TP})
    assert seen==expected and not allocations
    assert ledger==[[operation,REGISTRY+0x88] for operation in ('pthread_mutex_lock','pthread_mutex_unlock')*2]
    return result,watch,steps[0]


def red(library,libc):
    assert not hasattr(model,'apply_request_287474_tree_pointer_callback')
    rows=[]
    for image in BASES:
        p,kw,_=fixture(library,image,'reader_count_value_alias')
        result,watch,steps=original(library,libc,image,p,kw)
        assert result==0xFEDCBA0100000008
        rows.append(dict(image_base=hex(image),previous_tree_pointer_callback_missing=True,
            original_wrapper_getter_lookup_and_shared_readers_returned=True,
            X64_value_read_while_shared_reader_held_observed=True,native_instructions=steps,native_snapshot_input=False))
    return rows


def compare(library,libc,image,label):
    p,kw,readers=fixture(library,image,label);block=kw['argument_block_address']
    following=_read_span(p,block+32,8)
    result,watch,steps=original(library,libc,image,p,kw)
    value=model.apply_request_287474_tree_pointer_callback(p,**kw)
    assert value==result and all(_read_span(p,a,n)==b for (a,n),b in watch.items()),label
    assert _read_span(p,block+32,8)==following,label
    if label!='result_reader_alias':
        assert int.from_bytes(_read_span(p,REGISTRY+0x110,4),'little')==readers
        assert _read_span(p,REGISTRY+0x114,1)==b'\1'
    print('PASS second tree pointer',hex(image),label,steps,flush=True)
    return dict(image_base=hex(image),case=label,native_instructions=steps,
        original_wrapper_getter_lookup_and_shared_readers_returned=True,
        declared_guest_image_and_scope_bytes_equal=True,X64_packed_result_and_following_bytes_equal=True,
        four_actual_libc_mutex_transitions_equal=True,shared_reader_load_then_release_then_store_equal=True,
        scope_padding_preserved=True,no_allocator_or_JNI_or_syscall_services=True,
        native_snapshot_input=False,physical_spills_and_PAC_compared=False)


def guards(library):
    rows=[]
    for label in ('wrong_target','missing_packed','unaligned_stack','missing_scope','missing_receiver',
            'mutex_contention','writer_count','saturated_readers','unknown_comparator','node_bound',
            'missing_query','missing_value_after_acquisition','missing_result_after_release','source_bound',
            'packed_spill_alias','receiver_spill_alias','key_spill_alias','value_spill_alias'):
        p,kw,_=fixture(library,BASES[0],'cross_page_value' if label=='missing_value_after_acquisition' else 'found_high')
        block=kw['argument_block_address'];image=kw['image_base']
        if label=='wrong_target':put(p,block,image+1)
        elif label=='missing_packed':kw['argument_block_address']=0x66000000
        elif label=='unaligned_stack':kw['entry_stack_address']+=1
        elif label=='missing_scope':del p[(SP-0x60)>>12]
        elif label=='missing_receiver':put(p,block+8,0x66000000)
        elif label=='mutex_contention':put(p,REGISTRY+0x88,2,2)
        elif label in ('writer_count','saturated_readers'):put(p,REGISTRY+0x110,0x80000000 if label=='writer_count' else 0x7FFFFFFF,4)
        elif label=='unknown_comparator':put(p,REGISTRY+0x70,0)
        elif label=='node_bound':kw['max_nodes']=1
        elif label=='missing_query':put(p,block+16,G+0x10000)
        elif label=='missing_value_after_acquisition':del p[(G+0x6000)>>12]
        elif label=='missing_result_after_release':
            new=G+0x9FE8;_write_span(p,new,_read_span(p,block,24));del p[(G+0xA000)>>12];kw['argument_block_address']=new
        elif label=='source_bound':kw['max_bytes']=0
        elif label=='packed_spill_alias':
            new=SP-0x100;_write_span(p,new,_read_span(p,block,32));kw['argument_block_address']=new
        elif label=='receiver_spill_alias':put(p,block+8,SP-0x200)
        elif label=='key_spill_alias':put(p,block+16,SP-0x100)
        elif label=='value_spill_alias':
            key=int.from_bytes(_read_span(p,block+16,8),'little')
            tree=registry._ConfigurationTree(p,REGISTRY+0x58,image,4096,0x100000)
            node=tree.find(key);pair=tree.u64(node+32);put(p,pair+8,SP-0x100)
        before={k:bytes(v) for k,v in p.items()}
        try:model.apply_request_287474_tree_pointer_callback(p,**kw)
        except (RefillUnsupported,ValueError,TypeError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True))
    return rows


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--libc',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--mode',choices=('red','native','guards'),default='native');a=parser.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(a.libc.read_bytes()).hexdigest()=='d2376df6d2ac3e0213f85e3614c4c7ad1d28c84c44926058d5c1b95c855563db'
    e=dict(cases=[],negative_cases=[],red_cases=[],complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False,complete_second_vm_verified=False,complete_physical_ABI_verified=False,
        actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,allocator_provider_mapping_rollback_verified=False)
    if a.mode=='red':e['red_cases']=red(a.library,a.libc)
    elif a.mode=='guards':e['negative_cases']=guards(a.library)
    else:e['cases']=[compare(a.library,a.libc,b,n) for b in BASES for n in PROFILES]
    e.update(native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']))
    a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
if __name__=='__main__':main()
