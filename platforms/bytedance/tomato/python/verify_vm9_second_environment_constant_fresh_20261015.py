"""Fresh original +2886fc/+256330 wrapper controls for the second VM."""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
from verify_vm9_jni_environment_fresh_20261007 import LIBC_SHA256
import vm9_request_287474_vm as model
from vm9_allocator import RefillUnsupported,_read_span,_write_span

G=oracle.GUEST;SP=G+0xEF00;BLOCK=G+0x1200
BASES=(0x122C0000,0x775C205000)
PROFILES=('cold','warm','warm_even','warm_high','warm_without_decoder_page',
    'ignored_unmapped_receiver','ignored_NULL_receiver','cross_page_result',
    'result_alias_destination','result_alias_flag')

def write(p,a,v,n=8):_write_span(p,a,(v&((1<<(8*n))-1)).to_bytes(n,'little'))

def fixture(library,image,label):
    p=oracle.image_pages(library,image);p.update(oracle.fresh_pages())
    block=G+0x1FEC if label=='cross_page_result' else BLOCK
    if label=='result_alias_destination':block=image+0x3DE4D4-16
    elif label=='result_alias_flag':block=image+0x3DE4D8-16
    receiver=0 if label=='ignored_NULL_receiver' else 0xFFFFFFFFFFFFFFF0
    _write_span(p,block,(image+0x256330).to_bytes(8,'little')+receiver.to_bytes(8,'little')+b'\xb5'*8)
    flag=0 if not label.startswith('warm') else {'warm_even':2,'warm_high':0x80000000}.get(label,1)
    write(p,image+0x3DE4D8,flag,4)
    if flag:_write_span(p,image+0x3DE4D4,b'w\0qz')
    if label=='warm_without_decoder_page':p.pop((image+0x98000)>>12)
    return p,dict(argument_block_address=block,entry_stack_address=SP,image_base=image)

def original(library,image,p,kw):
    steps=[0];seen=set();missing_decoder=(image+0x98000)>>12 not in p
    watch={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000}
    def observe(cpu,address):
        if not steps[0] and missing_decoder:cpu.mem_unmap(image+0x98000,4096)
        steps[0]+=1;off=address-image
        if off in (0x2886FC,0x256330,0x167E54):seen.add(off)
    result,memory,allocations,ledger=oracle.native(library,image,0x2886FC,[kw['argument_block_address']],p,
        instruction_limit=10000,instruction_observer=observe,observed_memory=watch,
        extra_registers={arm.UC_ARM64_REG_SP:SP})
    assert {0x2886FC,0x256330}<=seen and not allocations and not ledger
    assert result==image+0x3DE4D4
    return result,memory,watch,steps[0],0x167E54 in seen

def red(library):
    assert not hasattr(model,'apply_request_287474_environment_constant_callback')
    rows=[]
    for image in BASES:
        p,kw=fixture(library,image,'cold');result,memory,watch,steps,decoded=original(library,image,p,kw)
        assert int.from_bytes(memory[BLOCK-G+16:BLOCK-G+24],'little')==result and decoded
        rows.append(dict(image_base=hex(image),previous_wrapper_missing=True,original_wrapper_and_getter_returned=True,
            full_X64_packed_result_observed=True,original_decoder_executed=True,native_instructions=steps,native_snapshot_input=False))
    return rows

def compare(library,image,label):
    p,kw=fixture(library,image,label);result,memory,watch,steps,decoded=original(library,image,p,kw)
    actual=model.apply_request_287474_environment_constant_callback(p,**kw)
    assert actual==result and _read_span(p,G,0xA000)==memory,label
    for (a,n),raw in watch.items():assert _read_span(p,a,n)==raw,(label,hex(a))
    assert int.from_bytes(_read_span(p,kw['argument_block_address']+16,8),'little')==result
    assert decoded==(not label.startswith('warm'))
    print('PASS second environment constant',hex(image),label,steps,flush=True)
    return dict(image_base=hex(image),case=label,native_instructions=steps,original_wrapper_and_getter_returned=True,
        all_declared_guest_and_image_fields_equal=True,full_X64_packed_result_and_alias_effects_equal=True,
        receiver_not_dereferenced=True,decoder_executed=decoded,no_allocator_or_JNI_or_mutex_effects=True,
        native_snapshot_input=False,physical_padding_and_register_spills_compared=False)

def guards(library):
    rows=[]
    for label in ('wrong_target','unmapped_block','partial_packed_input','unaligned_stack','missing_flag',
            'missing_cold_decoder_page','missing_output_page','packed_spill_alias'):
        image=BASES[0];p,kw=fixture(library,image,'cold')
        if label=='wrong_target':write(p,BLOCK,image+0x2562DC)
        elif label=='unmapped_block':kw['argument_block_address']=0x66000000
        elif label=='partial_packed_input':
            a=G+0x9FF8;write(p,a,image+0x256330);p.pop((G+0xA000)>>12);kw['argument_block_address']=a
        elif label=='unaligned_stack':kw['entry_stack_address']+=1
        elif label=='missing_flag':p.pop((image+0x3DE000)>>12)
        elif label=='missing_cold_decoder_page':p.pop((image+0x98000)>>12)
        elif label=='missing_output_page':
            a=G+0x9FF0;_write_span(p,a,_read_span(p,BLOCK,16));p.pop((G+0xA000)>>12);kw['argument_block_address']=a
        elif label=='packed_spill_alias':
            a=SP-0x20;_write_span(p,a,_read_span(p,BLOCK,24));kw['argument_block_address']=a
        before={k:bytes(v) for k,v in p.items()}
        try:model.apply_request_287474_environment_constant_callback(p,**kw)
        except (RefillUnsupported,ValueError,TypeError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True))
    return rows

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library',type=Path,required=True);parser.add_argument('--libc',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--mode',choices=('red','native','guards'),default='native')
    a=parser.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(a.libc.read_bytes()).hexdigest()==LIBC_SHA256
    e=dict(cases=[],negative_cases=[],red_cases=[],complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False,complete_second_vm_verified=False,complete_physical_ABI_verified=False,
        actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,allocator_provider_mapping_rollback_verified=False)
    if a.mode=='red':e['red_cases']=red(a.library)
    elif a.mode=='guards':e['negative_cases']=guards(a.library)
    else:e['cases']=[compare(a.library,image,label) for image in BASES for label in PROFILES]
    e.update(native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']))
    a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
if __name__=='__main__':main()
