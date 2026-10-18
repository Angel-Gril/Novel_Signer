"""Synthetic messages through the original Protobuf-C pack trampoline."""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
import verify_vm9_second_protobuf_size_fresh_20261018 as sizes
import vm9_request_287474_vm as model
from vm9_allocator import RefillUnsupported,_read_span,_write_span

G=sizes.G;SP=sizes.SP;BASES=sizes.BASES;BLOCK=sizes.BLOCK;MESSAGE=sizes.MESSAGE
OUTPUT=G+0x9000
PROFILES=tuple('bytes' if n=='bytes_unmapped_payload' else n for n in sizes.PROFILES)+('nested_prefix_growth','cross_page_output')


def fixture(library,image,label):
    source='bytes_unmapped_payload' if label=='bytes' else 'nested_populated' if label=='nested_prefix_growth' else 'varint_128' if label=='cross_page_output' else label
    p,kw=sizes.fixture(library,image,source)
    if label=='bytes':
        sizes.w(p,MESSAGE+24+15*16+8,G+0x7800);_write_span(p,G+0x7800,bytes(range(128)))
    elif label=='nested_prefix_growth':
        sizes.schema(p,sizes.CHILD_DESC,G+0x6000,[(1,15,24,0)])
        sizes.w(p,sizes.CHILD+24,129);sizes.w(p,sizes.CHILD+32,G+0x7800)
        _write_span(p,G+0x7800,b'\xA7'*129)
    output=G+0x8FFF if label=='cross_page_output' else OUTPUT
    block=G+0x6FE4 if label=='cross_page_result' else BLOCK
    _write_span(p,block,(image+0x2A337C).to_bytes(8,'little')+MESSAGE.to_bytes(8,'little')+
        output.to_bytes(8,'little')+b'\xA6'*16)
    _write_span(p,output,b'\xC5'*512)
    kw['argument_block_address']=block
    return p,kw


def original(library,image,p,kw):
    steps=[0];minimum=[SP];seen=set()
    def observe(cpu,a):
        steps[0]+=1;minimum[0]=min(minimum[0],cpu.reg_read(arm.UC_ARM64_REG_SP));seen.add(a-image)
    watch={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000}
    result,memory,allocations,ledger=oracle.native(library,image,0x2889F4,[kw['argument_block_address']],p,
        observed_memory=watch,instruction_observer=observe,instruction_limit=50000,
        extra_registers={arm.UC_ARM64_REG_SP:SP})
    assert {0x2889F4,0x2A337C,0x253D08}<=seen and not allocations and not ledger
    assert minimum[0]>=SP-0x1000
    return result,memory,watch,steps[0],SP-minimum[0],0x348410 in seen


def compare(library,image,label):
    p,kw=fixture(library,image,label)
    result,memory,watch,steps,stack,moved=original(library,image,p,kw)
    callback=getattr(model,'apply_request_287474_protobuf_pack_callback',None)
    assert callable(callback),'original Protobuf-C pack wrapper returned, but the second pack callback is missing'
    assert callback(p,**kw)==result
    assert _read_span(p,G,0xA000)==memory,label
    assert all(_read_span(p,a,n)==raw for (a,n),raw in watch.items()),label
    if label=='nested_prefix_growth':assert moved
    print('PASS second protobuf pack',hex(image),label,steps,flush=True)
    return dict(image_base=hex(image),case=label,native_instructions=steps,native_stack_bytes=stack,
        original_wrapper_and_pack_helpers_returned=True,return_and_exact_eight_byte_store_equal=True,
        all_encoded_payload_and_declared_guest_image_bytes_equal=True,nested_prefix_memmove_observed=moved,
        explicit_strlen_memcpy_memmove_services=True,native_input_snapshot_used=False,
        physical_spills_and_register_ABI_compared=False)


GUARDS=('wrong_target','NULL_packed','wrapped_packed','missing_packed','unaligned_stack','NULL_message',
    'missing_message','bad_magic','unknown_fields','repeated','oneof','field_limit','depth_limit','node_limit',
    'byte_bound','cycle','NULL_output','wrapped_output','missing_output','output_message_alias',
    'output_descriptor_alias','output_table_alias','output_string_alias','output_bytes_alias','output_packed_alias',
    'packed_spill_alias','output_spill_alias','message_spill_alias','payload_spill_alias','missing_bytes_payload',
    'partial_payload_store','partial_result_after_payload')


def guards(library):
    rows=[]
    for label in GUARDS:
        profile='nested_populated' if label in ('cycle','depth_limit','node_limit') else 'bytes' if label in ('output_bytes_alias','missing_bytes_payload','payload_spill_alias') else 'string'
        p,kw=fixture(library,BASES[0],profile);w=sizes.w
        if label=='wrong_target':w(p,BLOCK,BASES[0]+0x2A3378)
        elif label=='NULL_packed':kw['argument_block_address']=0
        elif label=='wrapped_packed':kw['argument_block_address']=(1<<64)-24
        elif label=='missing_packed':kw['argument_block_address']=0x66000000
        elif label=='unaligned_stack':kw['entry_stack_address']+=1
        elif label=='NULL_message':w(p,BLOCK+8,0)
        elif label=='missing_message':w(p,BLOCK+8,0x66000000)
        elif label=='bad_magic':w(p,sizes.DESC,0,4)
        elif label=='unknown_fields':w(p,MESSAGE+8,1,4)
        elif label=='repeated':w(p,sizes.TABLE+12,2,4)
        elif label=='oneof':w(p,sizes.TABLE+48,4,4)
        elif label=='field_limit':kw['max_fields']=1
        elif label=='depth_limit':kw['max_depth']=0
        elif label=='node_limit':kw['max_nodes']=1
        elif label=='byte_bound':kw['max_bytes']=64
        elif label=='cycle':w(p,MESSAGE+24+16*16,MESSAGE);w(p,sizes.TABLE+16*72+32,sizes.DESC)
        elif label=='NULL_output':w(p,BLOCK+16,0)
        elif label=='wrapped_output':w(p,BLOCK+16,(1<<64)-4)
        elif label=='missing_output':w(p,BLOCK+16,0x66000000)
        elif label.startswith('output_') and label.endswith('_alias') and label!='output_spill_alias':
            target={'output_message_alias':MESSAGE,'output_descriptor_alias':sizes.DESC,'output_table_alias':sizes.TABLE,
                'output_string_alias':G+0x7FF8,'output_bytes_alias':G+0x7800,'output_packed_alias':BLOCK}[label]
            w(p,BLOCK+16,target)
        elif label=='packed_spill_alias':kw['argument_block_address']=SP-0x100;_write_span(p,SP-0x100,_read_span(p,BLOCK,40))
        elif label=='output_spill_alias':w(p,BLOCK+16,SP-0x100)
        elif label=='message_spill_alias':w(p,BLOCK+8,SP-0x100)
        elif label=='payload_spill_alias':w(p,MESSAGE+24+15*16+8,SP-0x100)
        elif label=='missing_bytes_payload':w(p,MESSAGE+24+15*16+8,0x66000000)
        elif label=='partial_payload_store':w(p,BLOCK+16,G+0x9FFE);p.pop((G+0xA000)>>12)
        elif label=='partial_result_after_payload':
            kw['argument_block_address']=G+0x9FE4;_write_span(p,G+0x9FE4,_read_span(p,BLOCK,28));p.pop((G+0xA000)>>12)
        before={k:bytes(v) for k,v in p.items()}
        try:model.apply_request_287474_protobuf_pack_callback(p,**kw)
        except (RefillUnsupported,ValueError,TypeError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_model_pages_unchanged=True))
        print('PASS second protobuf pack refusal',label,flush=True)
    return rows


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True);ap.add_argument('--mode',choices=('red','native','guards'),default='native')
    a=ap.parse_args();assert hashlib.sha256(a.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    e=dict(cases=[],negative_cases=[])
    if a.mode=='guards':e['negative_cases']=guards(a.library)
    else:
        for image in BASES[:1] if a.mode=='red' else BASES:
            for label in ('nested_prefix_growth',) if a.mode=='red' else PROFILES:
                e['cases'].append(compare(a.library,image,label));a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
    a.output.write_text(json.dumps(dict(e,native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']),
        native_input_snapshot_used=False,complete_python_medusa=False),indent=2)+'\n',encoding='utf-8',newline='\n')


if __name__=='__main__':main()
