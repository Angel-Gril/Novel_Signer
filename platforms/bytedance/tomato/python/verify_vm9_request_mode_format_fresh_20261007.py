"""Original-body mode format construction, rendering and cleanup controls.

Builder comparisons exclude only unspecified token padding. Complete mode
controls compare full payload, output/inline objects and ordered Effects after
all temporary allocations are freed. Matching libc executes string imports.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as arm
import vm9_objects as objects
import vm9_request_format_objects as fmt
from vm9_allocator import RefillUnsupported, _read_span, _write_span
from verify_vm9_signer_objects import GUEST, LIBRARY_SHA256, image_pages, fresh_pages, native
from verify_vm9_strings import Effects
from verify_vm9_worker_allocator import LIBC_SHA256

BASES = (0x122C0000,0x775C205000)
STACK = GUEST+0xEF00
OBJECT,FORMAT,ARGUMENT = (GUEST+n for n in (0x1800,0x2000,0x2800))


def imports(library,libc):
    exports={}
    with libc.open('rb') as stream:
        for section in ELFFile(stream).iter_sections():
            if section['sh_type']=='SHT_DYNSYM':
                exports.update({s.name:0x51000000+s['st_value'] for s in section.iter_symbols() if s['st_shndx']!='SHN_UNDEF'})
    result={}
    with library.open('rb') as stream:
        elf=ELFFile(stream);plt=elf.get_section_by_name('.plt');rel=elf.get_section_by_name('.rela.plt');symbols=elf.get_section(rel['sh_link'])
        for index,r in enumerate(rel.iter_relocations()):
            name=symbols.get_symbol(r['r_info_sym']).name
            if name in ('strlen','__strlen_chk','memchr','memcmp','strcmp','strncmp'):
                result[plt['sh_addr']+32+index*16]=exports[name]
    return result


def services(entries,effects):
    def redirect(address):
        def run(cpu):cpu.reg_write(arm.UC_ARM64_REG_PC,address);return None
        return run
    result={off:redirect(address) for off,address in entries.items()}
    result[0x347FA0]=lambda cpu:effects.native(cpu,'free',pointer=cpu.reg_read(arm.UC_ARM64_REG_X0))
    return result


def fresh(library,image):return {**image_pages(library,image),**fresh_pages()}

def snapshot(p):return {k:bytes(v) for k,v in p.items()}


def builder_case(library,libc,image,entries,data):
    p=fresh(library,image);_write_span(p,FORMAT,data+b'\0');_write_span(p,ARGUMENT,bytes(4))
    observed={(image+0x3E1000,4096):None}
    expected,actual=Effects(blocks={}),Effects(blocks={})
    _,memory,_,ledger=native(library,image,0x28F0F4,[FORMAT,ARGUMENT],p,libc=libc,
        extra_registers={arm.UC_ARM64_REG_X8:OBJECT},host_imports=services(entries,expected),
        malloc_handler=lambda cpu,size:expected.native(cpu,'malloc',size),
        observed_memory=observed,instruction_limit=300000)
    assert not ledger
    model={k:bytearray(v) for k,v in p.items()}
    fmt.build_mode_format_object(model,image_base=image,object_address=OBJECT,
        format_address=FORMAT,argument_address=ARGUMENT,allocate=actual.malloc,free=actual.free)
    assert expected.calls==actual.calls and expected.blocks==actual.blocks
    native_payload=bytearray(memory);model_payload=bytearray(_read_span(model,GUEST,0xA000))
    assert model_payload[OBJECT-GUEST:OBJECT-GUEST+80]==native_payload[OBJECT-GUEST:OBJECT-GUEST+80]
    begin,end=(int.from_bytes(memory[OBJECT-GUEST+n:OBJECT-GUEST+n+8],'little') for n in (40,48))
    excluded=[];differing=0
    for token in range(begin,end,64):
        tag=int.from_bytes(memory[token-GUEST:token-GUEST+4],'little')
        spans=((token+4,4),(token+44,4)) if tag==2 else ((token+4,4),(token+45,3))
        for address,width in spans:
            start=address-GUEST
            differing+=sum(a!=b for a,b in zip(model_payload[start:start+width],native_payload[start:start+width]))
            excluded.append([hex(address-GUEST),width])
            native_payload[start:start+width]=bytes(width);model_payload[start:start+width]=bytes(width)
    assert model_payload==native_payload
    global_model=_read_span(model,image+0x3E1000,4096)
    assert global_model==observed[image+0x3E1000,4096], [(hex(0x3E1000+i),a,b) for i,(a,b) in enumerate(zip(global_model,observed[image+0x3E1000,4096])) if a!=b]
    return dict(image_base=hex(image),format_input_hex=data.hex(),token_count=(end-begin)//64,
        full_format_object_match=True,initialized_token_fields_and_unused_capacity_match=True,
        payload_matches_after_unspecified_token_padding_exclusion=True,
        excluded_unspecified_padding_windows=excluded,unspecified_padding_differing_bytes=differing,
        full_unmasked_builder_payload_equivalence_claimed=False,
        ordered_allocation_copy_and_free_effects_match=True,actual_native_builder_body_executed=True,
        matching_libc_string_imports_executed=True,native_input_snapshot_used=False)


def warm_mode(p,image,data):
    for src,name,mask,flag in (
            (0x11F1CC,0x3E1AD0,0x11F1D8,0x3E1ADC),
            (0x11F5C0,0x3E1E10,0x11F5D4,0x3E1E14),
            (0x11F5C4,0x3E1E18,0x11F5CC,0x3E1E20),
            (0x11F1BC,0x3E1AB0,0x11F1F0,0x3E1AB4),
            (0x11F1C0,0x3E1AB8,0x11F1EC,0x3E1ABC),
            (0x11F1C4,0x3E1AC0,0x11F1E8,0x3E1AC4),
            (0x11F1C8,0x3E1AC8,0x11F1E4,0x3E1ACC)):
        objects.decode_masked_bytes(p,source_address=image+src,destination_address=image+name,mask_address=image+mask)
        _write_span(p,image+flag,(7).to_bytes(4,'little'))
    assert len(data)<=10
    _write_span(p,image+0x3E1AD0,data+b'\0')


def mode_case(library,libc,image,entries,mode,data=None):
    p=fresh(library,image)
    if data is not None:warm_mode(p,image,data)
    observed={(image+0x3E1000,4096):None,(STACK-0xB0,80):None,
        (STACK-0x140,144):None,(STACK-0x60,4):None}
    expected,actual=Effects(blocks={}),Effects(blocks={})
    _,memory,_,ledger=native(library,image,0x28E788,[mode],p,libc=libc,
        extra_registers={arm.UC_ARM64_REG_X8:OBJECT},host_imports=services(entries,expected),
        malloc_handler=lambda cpu,size:expected.native(cpu,'malloc',size),
        observed_memory=observed,instruction_limit=400000)
    assert not ledger
    model={k:bytearray(v) for k,v in p.items()}
    result=fmt.execute_event_mode(model,image_base=image,entry_stack_address=STACK,
        output_object_address=OBJECT,mode=mode,allocate=actual.malloc,free=actual.free)
    assert expected.calls==actual.calls and expected.blocks==actual.blocks
    assert not actual.blocks
    assert _read_span(model,GUEST,0xA000)==memory
    for key,value in observed.items():assert _read_span(model,*key)==value,(key,_read_span(model,*key).hex(),value.hex())
    tag=memory[OBJECT-GUEST]
    assert not tag&1
    output=memory[OBJECT-GUEST+1:OBJECT-GUEST+1+(tag>>1)]
    signed=mode-(1<<32) if mode&(1<<31) else mode
    expected_text=(data or b'{"x0":{0}}').replace(b'{0}',str(signed).encode('ascii')) if data!=b'' else b''
    assert output==expected_text and result.rendered_length==len(output)
    return dict(image_base=hex(image),mode_uint32=mode,mode_signed_int32=signed,
        warm_input=data is not None,format_input_hex=data.hex() if data is not None else None,
        output_utf8=output.decode('ascii'),full_cpp_object_and_payload_match=True,
        full_inline_buffer_and_format_object_match=True,observed_global_page_match=True,
        ordered_allocator_and_cleanup_effects_match=True,temporary_allocations_all_freed=True,
        actual_native_mode_constructor_renderer_converter_and_cleanup_executed=True,
        explicit_component_allocator_used=True,matching_libc_string_imports_executed=True,
        native_input_snapshot_used=False,mode_return_x0_abi_compared=False)



def late_parameter_case(library,libc,image,entries,old,new):
    # Fixture comes from the independently native-verified builder owner.
    # Both renderers then see the same explicit post-construction mutation.
    p=fresh(library,image);_write_span(p,FORMAT,b'{0}\0');_write_span(p,ARGUMENT,old.to_bytes(4,'little'))
    builder=Effects(blocks={})
    fmt.build_mode_format_object(p,image_base=image,object_address=OBJECT,
        format_address=FORMAT,argument_address=ARGUMENT,allocate=builder.malloc,free=builder.free)
    _write_span(p,ARGUMENT,new.to_bytes(4,'little'))
    buffer=GUEST+0x3000;observed={(buffer,144):None,(image+0x3E1000,4096):None}
    effect=Effects(blocks=builder.blocks)
    _,memory,_,ledger=native(library,image,0x1B40D4,[OBJECT],p,libc=libc,
        extra_registers={arm.UC_ARM64_REG_X8:buffer},host_imports=services(entries,effect),
        malloc_handler=lambda cpu,size:effect.native(cpu,'malloc',size),observed_memory=observed,
        instruction_limit=300000)
    assert not ledger and not effect.calls
    model={k:bytearray(v) for k,v in p.items()}
    length=fmt.render_mode_format_to_buffer(model,image_base=image,
        format_object_address=OBJECT,buffer_object_address=buffer)
    assert _read_span(model,GUEST,0xA000)==memory
    for key,value in observed.items():assert _read_span(model,*key)==value
    signed=new-(1<<32) if new&(1<<31) else new
    assert _read_span(model,buffer+16,length)==str(signed).encode('ascii')
    return dict(image_base=hex(image),initial_mode=old,updated_mode=new,
        original_native_converter_uses_updated_parameter=True,
        borrowed_pointer_retained_without_scalar_snapshot=True,
        full_buffer_payload_and_global_page_match=True,native_input_snapshot_used=False,
        fixture_from_separately_native_verified_builder=True)


def negatives(library):
    image=BASES[0];results=[]
    for name,data in (('unsupported_index',b'{1}'),('unsupported_spec',b'{0:03d}'),
            ('unsupported_escape',b'{{0}}'),('too_many_tokens',b'x{0}'*33)):
        p=fresh(library,image);_write_span(p,FORMAT,data+b'\0');before=snapshot(p);e=Effects(blocks={})
        try:fmt.build_mode_format_object(p,image_base=image,object_address=OBJECT,
            format_address=FORMAT,argument_address=ARGUMENT,allocate=e.malloc,free=e.free)
        except RefillUnsupported:pass
        else:raise AssertionError(name+' accepted')
        assert snapshot(p)==before and not e.calls;results.append(name+'_refused_without_page_or_allocator_changes')
    for failure in range(5):
        p=fresh(library,image);before=snapshot(p);e=Effects(blocks={},failures=(failure,))
        try:fmt.execute_event_mode(p,image_base=image,entry_stack_address=STACK,
            output_object_address=OBJECT,mode=0,allocate=e.malloc,free=e.free)
        except RefillUnsupported as exc:assert 'operator-new failure' in str(exc)
        else:raise AssertionError('allocation failure accepted')
        assert snapshot(p)==before;results.append('allocation_'+str(failure)+'_failure_refused_without_page_commit')
    p=fresh(library,image);warm_mode(p,image,b'{0}');_write_span(p,image+0x3E1E10,b'[]\0');before=snapshot(p);e=Effects(blocks={})
    try:fmt.execute_event_mode(p,image_base=image,entry_stack_address=STACK,
        output_object_address=OBJECT,mode=0,allocate=e.malloc,free=e.free)
    except RefillUnsupported as exc:assert 'character sets' in str(exc)
    else:raise AssertionError('changed parser charset accepted')
    assert snapshot(p)==before;results.append('changed_parser_charset_refused_without_page_commit')
    for name,offset,data,flag in (('changed_radix',0x3E1D60,b'??\0',0x3E1D64),
            ('changed_renderer_selector',0x3E1AB0,b'?\0',0x3E1AB4)):
        p=fresh(library,image);warm_mode(p,image,b'{0}')
        _write_span(p,image+offset,data);_write_span(p,image+flag,(7).to_bytes(4,'little'))
        before=snapshot(p);e=Effects(blocks={})
        try:fmt.execute_event_mode(p,image_base=image,entry_stack_address=STACK,
            output_object_address=OBJECT,mode=0,allocate=e.malloc,free=e.free)
        except RefillUnsupported:pass
        else:raise AssertionError(name+' accepted')
        assert snapshot(p)==before;results.append(name+'_refused_without_page_commit')
    for name,mutation,limit in (('unknown_vtable',lambda p:_write_span(p,OBJECT+64,bytes(8)),128),
            ('inline_growth',lambda p:None,0)):
        p=fresh(library,image);_write_span(p,FORMAT,b'{0}\0');_write_span(p,ARGUMENT,bytes(4));e=Effects(blocks={})
        fmt.build_mode_format_object(p,image_base=image,object_address=OBJECT,
            format_address=FORMAT,argument_address=ARGUMENT,allocate=e.malloc,free=e.free)
        mutation(p);before=snapshot(p)
        try:fmt.render_mode_format_to_buffer(p,image_base=image,format_object_address=OBJECT,
            buffer_object_address=GUEST+0x3000,max_output_bytes=limit)
        except RefillUnsupported:pass
        else:raise AssertionError(name+' accepted')
        assert snapshot(p)==before;results.append(name+'_refused_without_page_commit')
    return results


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--library',type=Path,required=True);ap.add_argument('--libc',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args();assert hashlib.sha256(args.library.read_bytes()).hexdigest()==LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==LIBC_SHA256
    entries=imports(args.library,args.libc);builders,modes,late=[],[],[]
    for image in BASES:
        for data in (b'',b'plain',b'{0}',b'{"x0":{0}}',b'{0}{0}',b'x{0}y{0}z'):
            builders.append(builder_case(args.library,args.libc,image,entries,data));print('mode builder',hex(image),data,'PASS',flush=True)
        for mode in (0,1,7,2147483647,2147483648,4294967295):
            modes.append(mode_case(args.library,args.libc,image,entries,mode));print('mode body',hex(image),mode,'PASS',flush=True)
        for data in (b'{"x0":{0}}',b'{0}',b'v={0}',b'{0}{0}',b''):
            modes.append(mode_case(args.library,args.libc,image,entries,4294967295,data));print('warm mode body',hex(image),data,'PASS',flush=True)
        for old,new in ((0,4294967295),(4294967295,7)):
            late.append(late_parameter_case(args.library,args.libc,image,entries,old,new));print('late mode parameter',hex(image),old,new,'PASS',flush=True)
    negative=negatives(args.library)
    report=dict(schema='vm9-request-mode-format-fresh-differential-v1',evidence_date='2026-10-07',
        sample_sha256=LIBRARY_SHA256,libc_sha256=LIBC_SHA256,builder_controls=len(builders),
        mode_body_controls=len(modes),late_parameter_update_controls=len(late),negative_controls=len(negative),builder_cases=builders,
        mode_body_cases=modes,late_parameter_update_cases=late,negative_checks=negative,native_input_snapshot_used=False,
        signed_int32_live_parameter_reference_verified=True,bounded_mode_body_verified=True,
        matching_libc_allocator_used=False,full_generic_format_grammar_recovered=False,
        complete_request_event_callback_verified=False,complete_python_medusa=False,
        fresh_input_signer_output_verified=False,current_online_header_matrix_verified=False,
        limitations=['Builder comparison excludes unspecified token padding at +4..7 and literal +44..47 / argument +45..47; all initialized fields are compared.',
            'Complete bounded mode body compares full final payload/objects after temporary cleanup; full native stack/TLS/OS and X0 return ABI are not compared.',
            'Malloc/free are explicit Effects; matching libc executes string imports, not allocator.',
            'Oracle memcpy/memset imports are explicit byte-copy/fill services; the full native stack and generic memory runtime are not compared.',
            'Mode controls use inline C++ outputs; an end-to-end mode output heap branch is not claimed.',
            'Only plain literals and {0}, signed int32 and inline <=128 conversion are recovered; escapes/specs, other argument types and buffer growth refuse.',
            'Event five-argument formatting/emission, real JNI and whole request/fresh signing remain open.'])
    args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print('request mode format PASS',len(builders),len(modes),len(late),len(negative),flush=True)

if __name__=='__main__':main()
