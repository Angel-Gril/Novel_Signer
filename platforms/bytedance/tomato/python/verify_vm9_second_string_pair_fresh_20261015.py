"""Fresh +2887f0 hidden-X8 pair wrapper versus the existing clone/append owner.

Its complete28-byte stream equals +288ba0. Fresh controls execute +2887f0;
previous token groups are not replayed. Component allocator effects are explicit.
"""
from pathlib import Path
import argparse,hashlib,json
import vm9_request_token_vm as token
import vm9_request_287474_vm as second
import verify_vm9_request_token_strings_fresh_20261013 as dependency
from verify_vm9_strings import Effects
from vm9_allocator import RefillUnsupported,_read_span,_write_span
G=dependency.G;SP=G+0xEF00;PACKED=dependency.PACKED
BASES=dependency.BASES;PROFILES=dependency.PAIR_CASES


def fixture(library,libc,image,label):
    p,_,blocks,failures=dependency.fixture(library,libc,image,'pair',label)
    return p,blocks,failures


def equivalent_wrappers(library):
    p=dependency.oracle.image_pages(library,BASES[0])
    assert _read_span(p,BASES[0]+0x2887F0,28)==_read_span(p,BASES[0]+0x288BA0,28)


def red(library,libc):
    assert not hasattr(second,'RequestVm287474StringPairPrefix');equivalent_wrappers(library);rows=[]
    for image in BASES:
        p,blocks,failures=fixture(library,libc,image,'binary');effects=Effects(blocks=blocks,failures=failures)
        try:token.apply_token_string_transform_callback(p,wrapper_offset=0x2887F0,
            argument_block_address=PACKED,image_base=image,entry_stack_address=SP,
            allocate=effects.malloc,reallocate=effects.realloc,free=effects.free)
        except RefillUnsupported:pass
        else:raise AssertionError('previous owner unexpectedly accepts second pair wrapper')
        effects=Effects(blocks=blocks,failures=failures)
        returned,memory,watch,wake=dependency.original(library,libc,image,p,0x2887F0,effects,{})
        length=int.from_bytes(memory[dependency.DEST-G+12:dependency.DEST-G+16],'little')
        pointer=int.from_bytes(memory[dependency.DEST-G+16:dependency.DEST-G+24],'little')
        assert memory[pointer-G:pointer-G+length]==b'a\0bXYZ\xff' and not wake
        rows.append(dict(image_base=hex(image),previous_second_pair_wrapper_rejected=True,
            original_hidden_X8_clone_and_append_returned=True,complete_wrapper_stream_equal_to_accepted_token_wrapper=True,
            binary_concatenation_observed=True,native_snapshot_input=False))
    return rows


def compare(library,libc,image,label):
    p,blocks,failures=fixture(library,libc,image,label);expected=Effects(blocks=blocks,failures=failures)
    returned,memory,watch,wake=dependency.original(library,libc,image,p,0x2887F0,expected,{})
    actual=Effects(blocks=blocks,failures=failures)
    result=token.apply_token_string_transform_callback(p,wrapper_offset=0x2887F0,
        argument_block_address=PACKED,image_base=image,entry_stack_address=SP,
        allocate=actual.malloc,reallocate=actual.realloc,free=actual.free)
    assert _read_span(p,G,0xA000)==memory and all(_read_span(p,a,n)==b for (a,n),b in watch.items()),label
    assert actual.calls==expected.calls and actual.blocks==expected.blocks and not wake,label
    assert result&0xFFFFFFFF==returned&0xFFFFFFFF,label
    print('PASS second string pair',hex(image),label,flush=True)
    return dict(image_base=hex(image),case=label,original_hidden_X8_clone_and_append_returned=True,
        complete_wrapper_stream_equal_to_accepted_token_wrapper=True,all_guest_image_and_packed_padding_equal=True,
        ordered_allocator_free_reallocation_effects_equal=True,uint32_append_status_equal=True,
        component_allocator_provider_explicit=True,native_snapshot_input=False,physical_spills_and_PAC_compared=False)


def guards(library,libc):
    rows=[]
    for label in ('wrong_target','missing_first','missing_output','first_payload_spill_alias','second_payload_spill_alias',
            'output_spill_alias','provider_redirects_payload_to_spill','payload_bound'):
        image=BASES[0];p,blocks,failures=fixture(library,libc,image,'binary');effects=Effects(blocks=blocks)
        kw=dict(wrapper_offset=0x2887F0,argument_block_address=PACKED,image_base=image,entry_stack_address=SP,
            allocate=effects.malloc,reallocate=effects.realloc,free=effects.free)
        if label=='wrong_target':dependency.word(p,PACKED,1)
        elif label=='missing_first':dependency.word(p,PACKED+16,G+0x10000)
        elif label=='missing_output':dependency.word(p,PACKED+8,G+0x10000)
        elif label in ('first_payload_spill_alias','second_payload_spill_alias'):
            obj=dependency.FIRST if label.startswith('first') else dependency.SECOND
            dependency.word(p,obj+16,SP-0x100)
        elif label=='output_spill_alias':dependency.word(p,PACKED+8,SP-0x100)
        elif label=='provider_redirects_payload_to_spill':
            def allocate(tx,n):
                result=effects.malloc(tx,n);dependency.word(tx,dependency.SECOND+16,SP-0x100);return result
            kw['allocate']=allocate
        elif label=='payload_bound':kw['max_bytes']=2
        before={k:bytes(v) for k,v in p.items()}
        try:token.apply_token_string_transform_callback(p,**kw)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_provider_effects_rolled_back=False))
    return rows


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--libc',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--mode',choices=('red','native','guards'),default='native');ap.add_argument('--case',action='append',choices=PROFILES);a=ap.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==dependency.oracle.LIBRARY_SHA256
    assert hashlib.sha256(a.libc.read_bytes()).hexdigest()==dependency.LIBC_SHA256
    equivalent_wrappers(a.library)
    e=dict(cases=[],negative_cases=[],red_cases=[],native_snapshot_input=False,complete_second_vm_verified=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False,
        actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,
        complete_physical_ABI_verified=False,allocator_provider_mapping_rollback_verified=False)
    if a.mode=='red':e['red_cases']=red(a.library,a.libc)
    elif a.mode=='native':
        for b in BASES:
            for label in a.case or PROFILES:
                e['cases'].append(compare(a.library,a.libc,b,label))
                a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
    else:e['negative_cases']=guards(a.library,a.libc)
    e.update(native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']))
    a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
if __name__=='__main__':main()
