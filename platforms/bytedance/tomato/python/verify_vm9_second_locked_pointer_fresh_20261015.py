"""Fresh +288794/+282b84 normal-mutex getter, scope and X64 writeback."""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
import vm9_request_287474_vm as model
from vm9_allocator import RefillUnsupported,_read_span,_write_span
G=oracle.GUEST;SP=G+0xEF00;TP=G+0xD000;BLOCK=G+0x1200
BASES=(0x122C0000,0x775C205000)
PROFILES=('normal','shared_mutex','zero','high_pointer','cross_page_result','cross_page_field',
    'field_alias_mutex','retained_mutex_owner','result_receiver_alias')


def put(p,address,value,width=8):_write_span(p,address,value.to_bytes(width,'little'))


def fixture(library,image,label):
    p=oracle.image_pages(library,image);p.update(oracle.fresh_pages())
    receiver=G+0x3000;owner=G+0x5000;block=BLOCK;value=0x66554433
    if label=='zero':value=0
    elif label=='high_pointer':value=0xFEDCBA9876543210
    elif label=='cross_page_result':block=G+0x6FEC
    elif label=='cross_page_field':receiver=G+0x3FBC
    elif label=='field_alias_mutex':owner=receiver+0x38;value=0x8877665500000000
    elif label=='retained_mutex_owner':owner=G+0x2000;receiver=owner-0x90
    elif label=='result_receiver_alias':block=receiver+0x30
    _write_span(p,block,(image+0x282B84).to_bytes(8,'little')+receiver.to_bytes(8,'little')+b'\xa6'*16)
    put(p,receiver+0x40,value);put(p,receiver+0x98,owner)
    if label!='retained_mutex_owner':put(p,owner+8,0x2000 if label=='shared_mutex' else 0,2)
    return p,dict(argument_block_address=block,image_base=image,entry_stack_address=SP),receiver,owner


def original(library,libc,image,p,kw,owner):
    steps=[0];seen=set()
    def observe(cpu,address):
        steps[0]+=1
        if address-image in (0x288794,0x282B84,0x15F778):seen.add(address-image)
    watch={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000}
    watch.update({(G,SP-G-0x1000):None,(SP,G+0x10000-SP):None,(SP-0x50,24):None})
    result,_,allocations,ledger=oracle.native(library,image,0x288794,[kw['argument_block_address']],p,
        libc=libc,real_mutexes=True,instruction_limit=10000,instruction_observer=observe,observed_memory=watch,
        extra_registers={arm.UC_ARM64_REG_SP:SP,arm.UC_ARM64_REG_TPIDR_EL0:TP})
    assert seen=={0x288794,0x282B84,0x15F778} and not allocations
    assert ledger==[['pthread_mutex_lock',owner+8],['pthread_mutex_unlock',owner+8]],ledger
    return result,watch,steps[0],ledger


def red(library,libc):
    assert not hasattr(model,'apply_request_287474_locked_pointer_callback')
    rows=[]
    for image in BASES:
        p,kw,receiver,owner=fixture(library,image,'field_alias_mutex')
        result,watch,steps,ledger=original(library,libc,image,p,kw,owner)
        assert result==0x8877665500000001
        rows.append(dict(image_base=hex(image),previous_locked_pointer_callback_missing=True,
            original_wrapper_getter_destructor_and_libc_mutexes_returned=True,
            field_read_while_mutex_held_observed=True,native_instructions=steps,native_snapshot_input=False))
    return rows


def compare(library,libc,image,label):
    p,kw,receiver,owner=fixture(library,image,label)
    result,watch,steps,ledger=original(library,libc,image,p,kw,owner)
    actual=model.apply_request_287474_locked_pointer_callback(p,**kw)
    assert actual==result and all(_read_span(p,a,n)==b for (a,n),b in watch.items()),label
    assert _read_span(p,kw['argument_block_address']+24,8)==b'\xa6'*8,label
    print('PASS second locked pointer',hex(image),label,steps,flush=True)
    return dict(image_base=hex(image),case=label,native_instructions=steps,
        original_wrapper_getter_destructor_returned=True,matching_libc_mutex_lock_unlock_equal=True,
        declared_guest_image_and_scope_bytes_equal=True,X64_packed_result_and_following_bytes_equal=True,
        retained_mutex_owner_and_load_before_unlock_equal=True,scope_padding_preserved=True,
        no_allocator_or_JNI_or_syscall_services=True,native_snapshot_input=False,physical_spills_and_PAC_compared=False)


def guards(library):
    rows=[]
    for label in ('wrong_target','missing_packed','unmapped_receiver','unmapped_mutex','contended_mutex','recursive_mutex',
            'unaligned_stack','missing_scope_page','missing_value_after_lock','missing_result_after_scope',
            'packed_spill_alias','receiver_spill_alias','mutex_spill_alias'):
        p,kw,receiver,owner=fixture(library,BASES[0],'normal');image=kw['image_base']
        if label=='wrong_target':put(p,BLOCK,image+1)
        elif label=='missing_packed':kw['argument_block_address']=0x66000000
        elif label=='unmapped_receiver':put(p,BLOCK+8,0x66000000)
        elif label=='unmapped_mutex':put(p,receiver+0x98,0x66000000)
        elif label=='contended_mutex':put(p,owner+8,1,2)
        elif label=='recursive_mutex':put(p,owner+8,0x4000,2)
        elif label=='unaligned_stack':kw['entry_stack_address']+=1
        elif label=='missing_scope_page':kw['entry_stack_address']=G+0x10000;del p[(G+0xF000)>>12]
        elif label=='missing_value_after_lock':
            receiver=G+0x2F80;put(p,BLOCK+8,receiver);put(p,receiver+0x98,owner);del p[(G+0x2000)>>12]
        elif label=='missing_result_after_scope':
            block=G+0x9FF0;_write_span(p,block,(image+0x282B84).to_bytes(8,'little')+receiver.to_bytes(8,'little'))
            del p[(G+0xA000)>>12];kw['argument_block_address']=block
        elif label=='packed_spill_alias':
            kw['argument_block_address']=SP-0x70;put(p,SP-0x70,image+0x282B84);put(p,SP-0x68,receiver)
        elif label=='receiver_spill_alias':put(p,BLOCK+8,SP-0x100)
        elif label=='mutex_spill_alias':put(p,receiver+0x98,SP-0x90)
        before={k:bytes(v) for k,v in p.items()}
        try:model.apply_request_287474_locked_pointer_callback(p,**kw)
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
