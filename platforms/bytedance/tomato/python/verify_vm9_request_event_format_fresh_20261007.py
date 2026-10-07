"""Native controls for the request's five borrowed argument format path.

Stop the original event caller before +0x28ff44 emission. Compare complete
payload after temporary cleanup and explicitly observed initialized objects.
Builder-only controls exclude unspecified token stack padding, as documented.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from unicorn import arm64_const as arm
import vm9_request_format_objects as fmt
import vm9_request_leaf_prefixes as leaves
from vm9_allocator import RefillUnsupported, _read_span, _write_span
from verify_vm9_signer_objects import GUEST, LIBRARY_SHA256, image_pages, fresh_pages, native
from verify_vm9_strings import Effects
from verify_vm9_request_mode_format_fresh_20261007 import imports, services, snapshot
from verify_vm9_worker_allocator import LIBC_SHA256

BASES=(0x122C0000,0x775C205000)
STACK=GUEST+0xEF00
OBJECT,FORMAT,BUFFER,OUTPUT=(GUEST+n for n in (0x1800,0x2000,0x3000,0x3400))
ARGUMENTS=tuple(GUEST+0x2800+16*i for i in range(5))
DEFAULT_FORMAT=b'{"x1":{0},"x2":{1},"x3":{2},"x4":{3}}'


def fresh(library,image):return {**image_pages(library,image),**fresh_pages()}
def put_values(p,values):
    for index,(address,value) in enumerate(zip(ARGUMENTS,values)):
        _write_span(p,address,value.to_bytes(4 if index==4 else 8,'little'))


def builder_case(library,libc,image,entries,data):
    p=fresh(library,image);_write_span(p,FORMAT,data+b'\0');put_values(p,(1,2,3,4,0xFFFFFFFF))
    observed={(image+0x3E1000,4096):None}
    expected,actual=Effects(blocks={}),Effects(blocks={})
    _,memory,_,ledger=native(library,image,0x28E86C,[FORMAT,*ARGUMENTS],p,libc=libc,
        extra_registers={arm.UC_ARM64_REG_X8:OBJECT,arm.UC_ARM64_REG_X5:ARGUMENTS[4]},host_imports=services(entries,expected),
        malloc_handler=lambda cpu,size:expected.native(cpu,'malloc',size),
        observed_memory=observed,instruction_limit=400000)
    assert not ledger
    model={k:bytearray(v) for k,v in p.items()}
    fmt.build_event_format_object(model,image_base=image,object_address=OBJECT,
        format_address=FORMAT,argument_addresses=ARGUMENTS,allocate=actual.malloc,free=actual.free)
    assert expected.calls==actual.calls and expected.blocks==actual.blocks
    actual_payload=bytearray(_read_span(model,GUEST,0xA000));native_payload=bytearray(memory)
    assert _read_span(model,OBJECT,144)==memory[OBJECT-GUEST:OBJECT-GUEST+144]
    begin,end=(int.from_bytes(memory[OBJECT-GUEST+n:OBJECT-GUEST+n+8],'little') for n in (40,48))
    excluded=[];differences=0
    for token in range(begin,end,64):
        tag=int.from_bytes(memory[token-GUEST:token-GUEST+4],'little')
        for address,width in (((token+4,4),(token+44,4)) if tag==2 else ((token+4,4),(token+45,3))):
            start=address-GUEST;differences+=sum(a!=b for a,b in zip(actual_payload[start:start+width],native_payload[start:start+width]))
            actual_payload[start:start+width]=native_payload[start:start+width]=bytes(width)
            excluded.append({'payload_offset':start,'length':width,'reason':'unspecified_token_stack_padding'})
    assert actual_payload==native_payload
    for key,value in observed.items():assert _read_span(model,*key)==value
    return dict(image_base=hex(image),format_input_hex=data.hex(),token_count=(end-begin)//64,
        full_144_byte_formatter_match=True,initialized_token_fields_and_remaining_payload_match=True,
        full_unmasked_builder_payload_equivalence_claimed=False,excluded_spans=excluded,
        observed_padding_differing_bytes=differences,ordered_allocator_effects_match=True,
        allocation_sizes=[c[1] for c in actual.calls if c[0]=='malloc'],
        original_native_five_argument_constructor_executed=True,native_input_snapshot_used=False)


def prefix_case(library,libc,image,entries,values,divisor=1):
    p=fresh(library,image);_write_span(p,image+0x3839E8,divisor.to_bytes(8,'little'))
    local=STACK-0x1B0;event=GUEST+0x1000
    observed={(image+0x3E1000,4096):None,(image+0x3D2000,4096):None,(local,0x178):None}
    expected,actual=Effects(blocks={}),Effects(blocks={})
    _,memory,_,ledger=native(library,image,0x28DDD0,[event,*values],p,libc=libc,
        extra_registers={arm.UC_ARM64_REG_X5:values[4]},host_imports=services(entries,expected),
        malloc_handler=lambda cpu,size:expected.native(cpu,'malloc',size),
        observed_memory=observed,instruction_limit=1000000,stop_offset=0x28FF44)
    assert not ledger
    captures=[];model={k:bytearray(v) for k,v in p.items()};before=snapshot(model)
    def observer(p,**fields):
        if fields['phase']=='before_event_emission':captures.append(({k:bytearray(v) for k,v in p.items()},fields))
    try:
        leaves.execute_event_formatter_prefix(model,image_base=image,entry_stack_address=STACK,
            event_object_address=event,argument_words=values[:4],mode=values[4],
            allocate=actual.malloc,free=actual.free,observer=observer)
    except RefillUnsupported as exc:
        assert str(exc)=='request event emission +0x28ff44 is not recovered',str(exc)
    else:raise AssertionError('unrecovered event emission was accepted')
    assert snapshot(model)==before,'parent request transaction unexpectedly committed'
    assert len(captures)==1
    staged,fields=captures[0]
    assert expected.calls==actual.calls and expected.blocks==actual.blocks
    assert _read_span(staged,GUEST,0xA000)==memory,'whole payload mismatch'
    for key,value in observed.items():assert _read_span(staged,*key)==value,(key,_read_span(staged,*key).hex(),value.hex())
    tag=_read_span(staged,local,1)[0]
    length=int.from_bytes(_read_span(staged,local+8,8),'little') if tag&1 else tag>>1
    pointer=int.from_bytes(_read_span(staged,local+16,8),'little') if tag&1 else local+1
    text=_read_span(staged,pointer,length)
    desired=DEFAULT_FORMAT
    for index,value in enumerate(values[:4]):desired=desired.replace(('{'+str(index)+'}').encode(),str(value).encode())
    assert text==desired
    assert fields['unresolved_leaf_target_offset']=='0x28ff44'
    assert len(actual.blocks)==1 and tag&1,'only final event JSON owns a heap block'
    return dict(image_base=hex(image),arguments_uint64=list(values[:4]),mode_uint32=values[4],
        sampling_divisor=divisor,output_utf8=text.decode('ascii'),output_is_heap_cpp_string=True,
        full_cpp_objects_conversion_buffer_formatter_tail_payload_and_global_pages_match=True,
        payload_mask_used=False,ordered_allocator_and_cleanup_effects_match=True,
        allocation_sizes=[c[1] for c in actual.calls if c[0]=='malloc'],
        live_owned_output_block_count=len(actual.blocks),temporary_allocations_all_freed=True,
        actual_native_event_prefix_executed_until_emission=True,event_emission_body_executed=False,
        parent_request_transaction_committed=False,native_input_snapshot_used=False)


def late_case(library,libc,image,entries,data,old,new):
    p=fresh(library,image);_write_span(p,FORMAT,data+b'\0');put_values(p,old);builder=Effects(blocks={})
    fmt.build_event_format_object(p,image_base=image,object_address=OBJECT,format_address=FORMAT,
        argument_addresses=ARGUMENTS,allocate=builder.malloc,free=builder.free)
    put_values(p,new);observed={(BUFFER,144):None,(image+0x3E1000,4096):None,(image+0x3D2000,4096):None}
    effect=Effects(blocks=builder.blocks)
    _,memory,_,ledger=native(library,image,0x1B40D4,[OBJECT],p,libc=libc,
        extra_registers={arm.UC_ARM64_REG_X8:BUFFER},host_imports=services(entries,effect),
        malloc_handler=lambda cpu,size:effect.native(cpu,'malloc',size),observed_memory=observed,instruction_limit=500000)
    assert not ledger and not effect.calls
    model={k:bytearray(v) for k,v in p.items()}
    length=fmt.render_event_format_to_buffer(model,image_base=image,format_object_address=OBJECT,buffer_object_address=BUFFER)
    assert _read_span(model,GUEST,0xA000)==memory
    for key,value in observed.items():assert _read_span(model,*key)==value,(key,[(hex(key[0]-image+i),_read_span(model,*key)[i:i+8].hex(),value[i:i+8].hex()) for i in range(0,key[1],8) if _read_span(model,*key)[i:i+8]!=value[i:i+8]])
    expected=data
    for index,value in enumerate(new):
        signed=value-(1<<32) if index==4 and value&(1<<31) else value
        expected=expected.replace(('{'+str(index)+'}').encode(),str(signed).encode())
    assert _read_span(model,BUFFER+16,length)==expected
    return dict(image_base=hex(image),format_input_hex=data.hex(),initial_values=list(old),updated_values=list(new),
        output_utf8=expected.decode('ascii'),original_native_renderer_reads_live_uint64_and_int32=True,
        full_buffer_payload_and_two_global_pages_match=True,fixture_from_separately_verified_builder=True,
        native_input_snapshot_used=False)


def negatives(library):
    image=BASES[0];results=[]
    for name,data in (('out_of_range_index',b'{5}'),('unsupported_spec',b'{0:03d}'),
            ('unsupported_escape',b'{{0}}'),('multi_digit_index',b'{00}'),('too_many_tokens',b'x{0}'*33)):
        p=fresh(library,image);_write_span(p,FORMAT,data+b'\0');before=snapshot(p);e=Effects(blocks={})
        try:fmt.build_event_format_object(p,image_base=image,object_address=OBJECT,format_address=FORMAT,
            argument_addresses=ARGUMENTS,allocate=e.malloc,free=e.free)
        except RefillUnsupported:pass
        else:raise AssertionError(name+' accepted')
        assert snapshot(p)==before and not e.calls;results.append(name+'_refused_without_page_or_allocator_changes')
    p=fresh(library,image);before=snapshot(p);e=Effects(blocks={})
    try:fmt.build_event_format_object(p,image_base=image,object_address=OBJECT,format_address=FORMAT,
        argument_addresses=ARGUMENTS[:4],allocate=e.malloc,free=e.free)
    except RefillUnsupported:pass
    else:raise AssertionError('wrong argument count accepted')
    assert snapshot(p)==before and not e.calls;results.append('wrong_argument_count_refused_without_changes')
    for failure in range(8):
        p=fresh(library,image);_write_span(p,FORMAT,DEFAULT_FORMAT+b'\0');put_values(p,(0,0,0,0,0));before=snapshot(p)
        e=Effects(blocks={},failures=(failure,))
        try:fmt.execute_event_arguments(p,image_base=image,format_object_address=OBJECT,
            conversion_object_address=BUFFER,output_object_address=OUTPUT,format_address=FORMAT,
            argument_addresses=ARGUMENTS,allocate=e.malloc,free=e.free)
        except RefillUnsupported:pass
        else:raise AssertionError('allocation failure accepted')
        assert snapshot(p)==before;results.append('allocation_'+str(failure)+'_failure_refused_without_page_commit')
    for name,mutate,limit in (
            ('unknown_vtable',lambda p:_write_span(p,OBJECT+64,bytes(8)),128),
            ('invalid_index',lambda p:_write_span(p,int.from_bytes(_read_span(p,OBJECT+40,8),'little')+24,(5).to_bytes(8,'little')),128),
            ('changed_uint64_selector',lambda p:(_write_span(p,image+0x3D20C0,b'?\0'),_write_span(p,image+0x3D20C4,(7).to_bytes(4,'little'))),128),
            ('changed_hex_selector',lambda p:(_write_span(p,image+0x3D20E0,b'?\0'),_write_span(p,image+0x3D20E4,(7).to_bytes(4,'little'))),128),
            ('inline_growth',lambda p:None,0)):
        p=fresh(library,image);_write_span(p,FORMAT,b'{0}\0');put_values(p,(1,2,3,4,0));e=Effects(blocks={})
        fmt.build_event_format_object(p,image_base=image,object_address=OBJECT,format_address=FORMAT,
            argument_addresses=ARGUMENTS,allocate=e.malloc,free=e.free)
        mutate(p);before=snapshot(p)
        try:fmt.render_event_format_to_buffer(p,image_base=image,format_object_address=OBJECT,
            buffer_object_address=BUFFER,max_output_bytes=limit)
        except RefillUnsupported:pass
        else:raise AssertionError(name+' accepted')
        assert snapshot(p)==before;results.append(name+'_refused_without_page_commit')
    return results


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--library',type=Path,required=True);ap.add_argument('--libc',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);ap.add_argument('--prefix-only',action='store_true')
    args=ap.parse_args();assert hashlib.sha256(args.library.read_bytes()).hexdigest()==LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==LIBC_SHA256
    entries=imports(args.library,args.libc);builders,prefixes,late=[],[],[]
    valuesets=((0,0,0,0,0),(1,2,3,0,0xFFFFFFFF),((1<<64)-1,1<<63,0,7,1<<31))
    for image in BASES:
        for values in valuesets:
            prefixes.append(prefix_case(args.library,args.libc,image,entries,values));print('event prefix',hex(image),values,'PASS',flush=True)
        if args.prefix_only:continue
        for data in (b'',b'plain',b'{4}',b'{3}{2}{1}{0}',DEFAULT_FORMAT,b'x{0}y{4}z{0}'):
            builders.append(builder_case(args.library,args.libc,image,entries,data));print('event builder',hex(image),data,'PASS',flush=True)
        for data,new in ((b'{0}/{1}/{2}/{3}/{4}',((1<<64)-1,1<<63,7,8,0xFFFFFFFF)),
                (b'{4}:{4}',(0,1,2,3,1<<31))):
            late.append(late_case(args.library,args.libc,image,entries,data,(0,0,0,0,0),new));print('live event parameters',hex(image),data,'PASS',flush=True)
    if args.prefix_only:return
    negative=negatives(args.library)
    report=dict(schema='vm9-request-event-format-fresh-differential-v1',evidence_date='2026-10-07',
        sample_sha256=LIBRARY_SHA256,libc_sha256=LIBC_SHA256,builder_controls=len(builders),
        event_prefix_controls=len(prefixes),live_parameter_controls=len(late),negative_controls=len(negative),
        builder_cases=builders,event_prefix_cases=prefixes,live_parameter_cases=late,negative_checks=negative,
        five_parameter_formatter_bytes=144,bounded_event_arguments_format_verified=True,
        default_fifth_cell_constructed_but_not_referenced=True,full_generic_format_grammar_recovered=False,
        native_input_snapshot_used=False,matching_libc_allocator_used=False,matching_libc_string_imports_executed=True,
        oracle_memcpy_memset_byte_services_used=True,whole_native_stack_tls_os_equivalence_claimed=False,
        complete_request_event_callback_verified=False,complete_python_medusa=False,
        fresh_signer_output_verified=False,live_server_matrix_verified=False,
        unresolved_targets=['0x28ff44','0x26edc4'])
    args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print('event-format controls',len(builders)+len(prefixes)+len(late),'negative',len(negative),'PASS',flush=True)

if __name__=='__main__':main()
