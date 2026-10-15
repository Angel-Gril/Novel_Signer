"""Fresh original +28876c/+204f58 cached TPIDR_EL0 callback comparisons."""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
import vm9_request_287474_vm as model
from vm9_allocator import RefillUnsupported,_read_span,_write_span
G=oracle.GUEST;SP=G+0xEF00;BLOCK=G+0x1200
BASES=(0x122C0000,0x775C205000)
PROFILES={'cold':(0,G+0xD000),'zero_thread_pointer':(0,0),
    'cached':(0x76543210,G+0xD000),'cached_high':(0xFEDCBA9876543210,0),
    'cached_unmapped_thread':(0x66554433,0x66000000),
    'cross_page_result':(0,0x8877665544332211),'result_alias_cache':(0,G+0xD000)}


def fixture(library,image,label):
    cached,tp=PROFILES[label];p=oracle.image_pages(library,image);p.update(oracle.fresh_pages())
    block=G+0x6FF8 if label=='cross_page_result' else image+0x3DA088 if label=='result_alias_cache' else BLOCK
    _write_span(p,block,(image+0x204F58).to_bytes(8,'little')+b'\xa6'*16)
    _write_span(p,image+0x3DA090,cached.to_bytes(8,'little'))
    return p,dict(argument_block_address=block,entry_stack_address=SP,thread_pointer=tp,image_base=image)


def original(library,image,p,kw):
    steps=[0];seen=set()
    def observe(cpu,address):
        steps[0]+=1
        if address-image in (0x28876C,0x204F58,0x20513C):seen.add(address-image)
    watch={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000}
    watch.update({(G,SP-G-0x40):None,(SP,G+0x10000-SP):None})
    result,memory,allocations,ledger=oracle.native(library,image,0x28876C,[kw['argument_block_address']],p,
        instruction_limit=1000,instruction_observer=observe,observed_memory=watch,
        extra_registers={arm.UC_ARM64_REG_SP:SP,arm.UC_ARM64_REG_TPIDR_EL0:kw['thread_pointer']})
    assert seen=={0x28876C,0x204F58,0x20513C} and not allocations and not ledger
    return result,watch,steps[0]


def red(library):
    assert not hasattr(model,'apply_request_287474_thread_pointer_callback')
    rows=[]
    for image in BASES:
        p,kw=fixture(library,image,'cold');result,watch,steps=original(library,image,p,kw)
        assert result==kw['thread_pointer']
        page=(image+0x3DA090)&~4095;offset=(image+0x3DA090)&4095
        assert watch[page,4096][offset:offset+8]==result.to_bytes(8,'little')
        rows.append(dict(image_base=hex(image),previous_thread_pointer_callback_missing=True,
            original_wrapper_obfuscated_getter_returned=True,cold_TPIDR_read_and_cache_write_observed=True,
            native_instructions=steps,native_snapshot_input=False))
    return rows


def compare(library,image,label):
    p,kw=fixture(library,image,label);result,watch,steps=original(library,image,p,kw)
    actual=model.apply_request_287474_thread_pointer_callback(p,**kw)
    assert actual==result and all(_read_span(p,a,n)==b for (a,n),b in watch.items()),label
    assert _read_span(p,kw['argument_block_address']+16,8)==b'\xa6'*8,label
    cached,tp=PROFILES[label];assert actual==(cached or tp),label
    assert int.from_bytes(_read_span(p,image+0x3DA090,8),'little')==(cached or tp),label
    print('PASS second thread pointer',hex(image),label,steps,flush=True)
    return dict(image_base=hex(image),case=label,native_instructions=steps,
        original_wrapper_obfuscated_getter_returned=True,declared_guest_and_image_ranges_equal=True,
        X64_result_cache_and_following_bytes_equal=True,cold_and_cached_thread_pointer_semantics_equal=True,
        no_allocator_or_JNI_or_mutex_or_syscall_services=True,native_snapshot_input=False,physical_spills_and_PAC_compared=False)


def guards(library):
    rows=[]
    for label in ('wrong_target','missing_packed','missing_cache_page','unaligned_stack','invalid_thread_pointer',
            'final_store_failure_after_cache_write','packed_spill_alias'):
        p,kw=fixture(library,BASES[0],'cold');image=kw['image_base']
        if label=='wrong_target':_write_span(p,BLOCK,(image+0x204F54).to_bytes(8,'little'))
        elif label=='missing_packed':kw['argument_block_address']=0x66000000
        elif label=='missing_cache_page':del p[(image+0x3DA090)>>12]
        elif label=='unaligned_stack':kw['entry_stack_address']+=1
        elif label=='invalid_thread_pointer':kw['thread_pointer']=1<<64
        elif label=='final_store_failure_after_cache_write':
            block=G+0x9FF8;_write_span(p,block,(image+0x204F58).to_bytes(8,'little'))
            del p[(G+0xA000)>>12];kw['argument_block_address']=block
        elif label=='packed_spill_alias':
            kw['argument_block_address']=SP-0x30;_write_span(p,SP-0x30,(image+0x204F58).to_bytes(8,'little'))
        before={k:bytes(v) for k,v in p.items()}
        try:model.apply_request_287474_thread_pointer_callback(p,**kw)
        except (RefillUnsupported,ValueError,TypeError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True))
    return rows


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--mode',choices=('red','native','guards'),default='native')
    a=parser.parse_args();assert hashlib.sha256(a.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    e=dict(cases=[],negative_cases=[],red_cases=[],complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False,complete_second_vm_verified=False,complete_physical_ABI_verified=False,
        actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,allocator_provider_mapping_rollback_verified=False)
    if a.mode=='red':e['red_cases']=red(a.library)
    elif a.mode=='guards':e['negative_cases']=guards(a.library)
    else:e['cases']=[compare(a.library,b,n) for b in BASES for n in PROFILES]
    e.update(native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']))
    a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
if __name__=='__main__':main()
