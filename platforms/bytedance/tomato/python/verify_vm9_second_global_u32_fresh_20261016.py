"""Fresh +28863c/+1c3018 global unsigned-word getter and packed W0 store."""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
import vm9_request_287474_vm as model
from vm9_allocator import _read_span,_write_span,RefillUnsupported
BASES=(0x122C0000,0x775C205000);G=oracle.GUEST;SP=G+0xEF00
PROFILES=('zero','one','highbit','allones','mixed','cross_packed','cross_output','result_alias_global')
GUARDS=('wrong_target','unmapped_packed','partial_target','missing_global','partial_global',
    'missing_result','partial_result','unaligned_stack','invalid_stack','packed_stack_alias')
def fresh(library,image,label):
    p=oracle.image_pages(library,image);p.update(oracle.fresh_pages())
    block={'cross_packed':G+0x1FFC,'cross_output':G+0x1FF6,
        'result_alias_global':image+0x37A794-8}.get(label,G+0x1200)
    value={'zero':0,'one':1,'highbit':0x80000000,'allones':0xFFFFFFFF}.get(label,0x8A31C65D)
    _write_span(p,block,(image+0x1C3018).to_bytes(8,'little')+b'\xB5'*8+b'\x63'*8)
    _write_span(p,image+0x37A794,value.to_bytes(4,'little'))
    return p,dict(argument_block_address=block,entry_stack_address=SP,image_base=image),value
def original(library,image,p,kw):
    seen=set();steps=[0];watch={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000}
    def observe(cpu,address):
        steps[0]+=1
        if address-image in (0x28863C,0x1C3018):seen.add(address-image)
    result,memory,allocations,ledger=oracle.native(library,image,0x28863C,[kw['argument_block_address']],p,
        extra_registers={arm.UC_ARM64_REG_SP:SP},observed_memory=watch,instruction_observer=observe)
    assert seen=={0x28863C,0x1C3018} and not allocations and not ledger
    return result,memory,watch,steps[0]
def red(library):
    assert not hasattr(model,'apply_request_287474_global_u32_callback');rows=[]
    for image in BASES:
        p,kw,value=fresh(library,image,'highbit');result,memory,watch,steps=original(library,image,p,kw)
        at=kw['argument_block_address']-G
        assert result==value and memory[at+8:at+12]==value.to_bytes(4,'little') and memory[at+12:at+16]==b'\xB5'*4
        rows.append(dict(image_base=hex(image),previous_global_u32_dispatch_missing=True,
            original_wrapper_getter_and_four_byte_store_returned=True,padding_preserved=True,
            unsigned_W0_observed=True,steps=steps,native_snapshot_input=False))
    return rows
def compare(library,image,label):
    p,kw,value=fresh(library,image,label);before=_read_span(p,kw['argument_block_address'],24)
    result,memory,watch,steps=original(library,image,p,kw)
    actual=model.apply_request_287474_global_u32_callback(p,**kw)
    assert actual==result==value and _read_span(p,G,0xA000)==memory
    for (a,n),b in watch.items():assert _read_span(p,a,n)==b,(label,hex(a))
    after=_read_span(p,kw['argument_block_address'],24)
    assert after[:8]==before[:8] and after[8:12]==value.to_bytes(4,'little') and after[12:]==before[12:]
    print('PASS second global u32',hex(image),label,flush=True)
    return dict(image_base=hex(image),case=label,steps=steps,original_wrapper_getter_and_four_byte_store_returned=True,
        guest_image_and_packed_bytes_equal=True,unsigned_W0_and_exact_four_byte_store_equal=True,
        packed_padding_preserved=True,no_allocator_or_diagnostic_or_JNI_effects=True,native_snapshot_input=False,
        physical_spills_and_PAC_compared=False)
def guards(library):
    rows=[]
    for label in GUARDS:
        image=BASES[0];p,kw,_=fresh(library,image,'mixed');block=kw['argument_block_address']
        if label=='wrong_target':_write_span(p,block,(image+0x1C3024).to_bytes(8,'little'))
        elif label=='unmapped_packed':kw['argument_block_address']=0x66000000
        elif label=='partial_target':
            a=0x66000FFC;p[a>>12]=bytearray(4096);_write_span(p,a,(image+0x1C3018).to_bytes(8,'little')[:4]);kw['argument_block_address']=a
        elif label=='missing_global':p.pop((image+0x37A794)>>12)
        elif label=='partial_global':p[(image+0x37A794)>>12]=p[(image+0x37A794)>>12][:0x796]
        elif label in ('missing_result','partial_result'):
            a=G+0x9FF8 if label=='missing_result' else G+0x9FF6
            _write_span(p,a,(image+0x1C3018).to_bytes(8,'little'));p.pop((G+0xA000)>>12);kw['argument_block_address']=a
        elif label=='unaligned_stack':kw['entry_stack_address']+=1
        elif label=='invalid_stack':kw['entry_stack_address']=0
        elif label=='packed_stack_alias':
            a=SP-0x20;_write_span(p,a,_read_span(p,block,24));kw['argument_block_address']=a
        before={k:bytes(v) for k,v in p.items()}
        try:model.apply_request_287474_global_u32_callback(p,**kw)
        except (RefillUnsupported,ValueError,TypeError):pass
        else:raise AssertionError('global u32 guard accepted '+label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True))
    return rows
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True);ap.add_argument('--mode',choices=('red','native','guards'),default='native');a=ap.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    e=dict(cases=[],negative_cases=[],red_cases=[],native_snapshot_input=False,complete_second_vm_verified=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False,
        actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,complete_physical_ABI_verified=False)
    if a.mode=='red':e['red_cases']=red(a.library)
    elif a.mode=='guards':e['negative_cases']=guards(a.library)
    else:e['cases']=[compare(a.library,image,label) for image in BASES for label in PROFILES]
    e.update(native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']))
    a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
if __name__=='__main__':main()
