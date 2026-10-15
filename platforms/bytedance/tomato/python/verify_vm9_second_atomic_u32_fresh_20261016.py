"""Original +28887c/+256f58 serial acquire-load of receiver+138."""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
import vm9_request_287474_vm as model
from vm9_allocator import _read_span,_write_span,RefillUnsupported
G=oracle.GUEST;SP=G+0xEF00;BASES=(0x122C0000,0x775C205000)
PROFILES=('zero','one','highbit','allones','mixed','cross_packed','cross_output',
    'result_alias_field','field_at_page_end')
GUARDS=('wrong_target','unmapped_packed','partial_target','missing_receiver_word','missing_field',
    'partial_field','missing_result','partial_result','unaligned_stack','invalid_stack',
    'unaligned_field','wrapped_field','packed_stack_alias','field_stack_alias')


def fresh(library,image,label):
    p=oracle.image_pages(library,image);p.update(oracle.fresh_pages())
    block={'cross_packed':G+0x1FFC,'cross_output':G+0x1FEE}.get(label,G+0x1200)
    receiver={'result_alias_field':block+16-0x138,'field_at_page_end':G+0x6FFC-0x138}.get(label,G+0x6000)
    value={'zero':0,'one':1,'highbit':0x80000000,'allones':0xFFFFFFFF}.get(label,0x8A31C65D)
    _write_span(p,receiver+0xE8,(value^0xFFFFFFFF).to_bytes(4,'little'))
    _write_span(p,block,(image+0x256F58).to_bytes(8,'little')+receiver.to_bytes(8,'little')+b'\xB5'*8)
    _write_span(p,receiver+0x138,value.to_bytes(4,'little'))
    return p,dict(argument_block_address=block,entry_stack_address=SP,image_base=image),value


def original(library,image,p,kw):
    seen=set();steps=[0]
    watch={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000 or G<=page<<12<G+0xA000}
    def observe(cpu,address):
        steps[0]+=1
        if address-image in (0x28887C,0x256F58):seen.add(address-image)
    result,_,allocations,ledger=oracle.native(library,image,0x28887C,[kw['argument_block_address']],p,
        extra_registers={arm.UC_ARM64_REG_SP:SP},observed_memory=watch,instruction_observer=observe)
    assert seen=={0x28887C,0x256F58} and not allocations and not ledger
    return result,watch,steps[0]


def red(library):
    rows=[]
    for image in BASES:
        p,kw,value=fresh(library,image,'highbit');result,watch,steps=original(library,image,p,kw)
        before={k:bytes(v) for k,v in p.items()}
        try:model.apply_request_287474_cached_u32_callback(p,**kw)
        except RefillUnsupported as exc:assert str(exc)=='unexpected second configuration cached value target'
        else:raise AssertionError('atomic getter accepted before change')
        assert result==value and before=={k:bytes(v) for k,v in p.items()}
        rows.append(dict(image_base=hex(image),original_atomic_getter_returned=True,
            prior_model_rejected=True,unsigned_W0_observed=True,steps=steps,native_snapshot_input=False))
    return rows


def compare(library,image,label):
    p,kw,value=fresh(library,image,label);block=kw['argument_block_address'];before=_read_span(p,block,24)
    if label=='cross_output':assert (block+16)>>12!=(block+19)>>12
    result,watch,steps=original(library,image,p,kw)
    actual=model.apply_request_287474_cached_u32_callback(p,**kw)
    assert actual==result==value,label
    assert all(b==_read_span(p,a,n) for (a,n),b in watch.items()),label
    after=_read_span(p,block,24)
    assert before[:16]==after[:16] and after[16:20]==value.to_bytes(4,'little') and before[20:]==after[20:]
    print('PASS serial atomic u32',hex(image),label,flush=True)
    return dict(image_base=hex(image),case=label,steps=steps,original_atomic_getter_returned=True,
        complete_declared_guest_and_image_bytes_equal=True,unsigned_W0_and_exact_four_byte_store_equal=True,
        packed_receiver_and_padding_preserved=True,old_locked_field_distinguished=True,
        no_allocator_mutex_JNI_or_syscall_effects=True,native_snapshot_input=False,
        concurrent_acquire_release_semantics_verified=False,physical_spills_and_PAC_compared=False)


def guards(library):
    rows=[]
    for label in GUARDS:
        image=BASES[0];p,kw,_=fresh(library,image,'mixed');block=kw['argument_block_address'];receiver=G+0x6000
        def receiver_word(value):_write_span(p,block+8,value.to_bytes(8,'little'))
        if label=='wrong_target':_write_span(p,block,(image+0x256F64).to_bytes(8,'little'))
        elif label=='unmapped_packed':kw['argument_block_address']=0x66000000
        elif label=='partial_target':
            a=0x66000FFC;p[a>>12]=bytearray(4096);_write_span(p,a,(image+0x256F58).to_bytes(8,'little')[:4]);kw['argument_block_address']=a
        elif label=='missing_receiver_word':
            a=0x66000FF8;p[a>>12]=bytearray(4096);_write_span(p,a,(image+0x256F58).to_bytes(8,'little'));kw['argument_block_address']=a
        elif label=='missing_field':del p[receiver>>12]
        elif label=='partial_field':p[receiver>>12]=p[receiver>>12][:0x13A]
        elif label in ('missing_result','partial_result'):
            a=G+0x9FF0 if label=='missing_result' else G+0x9FEE
            _write_span(p,a,(image+0x256F58).to_bytes(8,'little')+receiver.to_bytes(8,'little'))
            p.pop((G+0xA000)>>12);kw['argument_block_address']=a
        elif label=='unaligned_stack':kw['entry_stack_address']+=1
        elif label=='invalid_stack':kw['entry_stack_address']=0
        elif label=='unaligned_field':receiver_word(receiver+1)
        elif label=='wrapped_field':receiver_word((1<<64)-0x130)
        elif label=='packed_stack_alias':
            a=SP-0x20;_write_span(p,a,_read_span(p,block,24));kw['argument_block_address']=a
        elif label=='field_stack_alias':receiver_word(SP-0x140)
        before={k:bytes(v) for k,v in p.items()}
        try:model.apply_request_287474_cached_u32_callback(p,**kw)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True))
    return rows


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True);ap.add_argument('--mode',choices=('red','native','guards'),default='native');a=ap.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    e=dict(cases=[],negative_cases=[],red_cases=[],native_snapshot_input=False,complete_second_vm_verified=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False,
        actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,complete_physical_ABI_verified=False,
        concurrent_acquire_release_semantics_verified=False)
    if a.mode=='red':e['red_cases']=red(a.library)
    elif a.mode=='guards':e['negative_cases']=guards(a.library)
    else:e['cases']=[compare(a.library,image,label) for image in BASES for label in PROFILES]
    e.update(native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']))
    a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
if __name__=='__main__':main()
