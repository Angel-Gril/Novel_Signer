"""Fresh synthetic native differences for descriptor-driven configuration unpack.

Export only offsets/counts/comparison flags. Never export wire bytes, schema
names, generated defaults or native outputs for later model input.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from unicorn.arm64_const import UC_ARM64_REG_X0

import vm9_protobuf as model
from vm9_allocator import RefillUnsupported, _read_span, _write_span
from verify_vm9_signer_objects import GUEST, LIBRARY_SHA256, fresh_pages, image_pages, native
from verify_vm9_strings import Effects


def varint(value):
    value &= (1 << 64) - 1
    result = bytearray()
    while value > 127:
        result.append((value & 127) | 128); value >>= 7
    result.append(value)
    return bytes(result)


def scalar(tag, value):
    return varint(tag << 3) + varint(value)


def string(tag, value):
    return varint((tag << 3) | 2) + varint(len(value)) + value


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--library', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == LIBRARY_SHA256
    cases, negatives = [], []
    bases = (0x122C0000, 0x775C205000)
    payloads = [('empty', b''), ('zero_tag', b'\0'), ('group', b'\x0b'),
        ('truncated_tag', b'\x88'), ('long_tag', b'\x88'*6),
        ('zero_low_tag', b'\x80\x01\x01'), ('truncated_varint', b'\x08\x80'),
        ('oversized_varint', b'\x08'+b'\x80'*10),
        ('truncated_fixed32', b'\x15\x01'), ('truncated_fixed64', b'\x19\x01'),
        ('truncated_length', b'\x12\x80'), ('length_over_intmax', b'\x12'+varint(1<<31)),
        ('short_length', b'\x12\x05a'), ('wrong_wire', b'\x0d1234'),
        ('unknown_varint', scalar(99, 777)), ('unknown_fixed64', varint((99<<3)|1)+b'abcdefgh'),
        ('unknown_fixed32', varint((99<<3)|5)+b'abcd'), ('unknown_string', string(99,b'abc')),
        ('known_wrong_wire', scalar(2,4)), ('duplicate_string', string(2,b'first')+string(2,b'last')),
        ('root_all', scalar(1,21)+string(2,b'alpha')+string(3,b'beta')+scalar(4,7)+string(5,b'gamma')+scalar(6,999)+scalar(9,6)),
        ('nested_empty',string(7,b'')+string(8,b'')),
        ('nested_fields',string(7,string(1,b'name')+string(2,b'a')+string(2,b'b')+scalar(3,8))+string(8,string(1,b'key')+string(2,b'value'))),
        ('nested_malformed',string(7,b'\0')), ('nested_wrong_wire',scalar(7,1)),
        ('repeated_messages',string(7,string(1,b'A'))+string(7,string(1,b'B'))+string(8,string(2,b'C'))),
        ('duplicate_and_unknown',string(2,b'one')+scalar(99,1)+string(2,b'two')+string(99,b''))]
    for value in (0,1,2,127,128,255,0xFFFFFFFF,1<<32,0xFFFFFFFFFFFFFFFF):
        payloads.append((f'scalar_{value}',scalar(1,value)+scalar(6,value)+scalar(4,value)+scalar(9,value)))
    for length in (0,1,7,16,127,128,255):
        payloads.append((f'string_{length}',string(2,b'Z'*length)))
    for count in (1,2,8,16):
        payloads.append((f'repeated_{count}',b''.join(string(7,string(2,b'R')) for _ in range(count))))
    for count in (1,2,8,16):
        payloads.append((f'unknown_{count}',b''.join(scalar(90+i,i) for i in range(count))))

    def compare(base,label,payload,failures=(),descriptor=0x350D68,free_after=False):
        pages=fresh_pages();pages.update(image_pages(args.library,base))
        data=GUEST+0x2000
        _write_span(pages,data,payload)
        expected, actual = Effects(blocks={},failures=failures),Effects(blocks={},failures=failures)
        observed={(page<<12,4096):None for page in pages if not GUEST<=page<<12<GUEST+0x10000}
        before_native_free=[]; before_model_free=[]
        def nfree(cpu):
            pointer=cpu.reg_read(UC_ARM64_REG_X0)
            if pointer:before_native_free.append((pointer,bytes(cpu.mem_read(pointer,expected.blocks[pointer]))))
            return expected.native(cpu,'free',pointer=pointer)
        def pfree(p,ptr):
            if ptr:before_model_free.append((ptr,_read_span(p,ptr,actual.blocks[ptr])))
            return actual.free(p,ptr)
        try:
            returned,memory,_,_=native(args.library,base,0x254330,[base+descriptor,0,len(payload),data],pages,
                malloc_handler=lambda cpu,size:expected.native(cpu,'malloc',size),
                host_imports={0x347FA0:nfree},observed_memory=observed,instruction_limit=200000)
        except Exception as exc:
            raise AssertionError(label + ' native oracle failed') from exc
        got=model.unpack_configuration_message(pages,data_address=data,length=len(payload),image_base=base,
            descriptor_address=base+descriptor,allocate=actual.malloc,free=pfree)
        assert got==returned,label+' return'
        current=_read_span(pages,GUEST,0xA000)
        if current!=memory:
            first=next(i for i,(a,b) in enumerate(zip(current,memory)) if a!=b)
            raise AssertionError(f'{label} guest+{first:#x}: {current[first]:#x} != {memory[first]:#x}')
        assert actual.calls==expected.calls,(label,actual.calls,expected.calls)
        assert before_model_free==before_native_free,label+' pre-free bytes'
        assert all(_read_span(pages,a,n)==value for (a,n),value in observed.items()),label+' image'
        cases.append({'case':label,'image_base':hex(base),'descriptor_offset':hex(descriptor),
            'guest_bytes_match':True,'image_bytes_match':True,'returned_pointer_match':True,
            'allocation_and_free_order_match':True,'pre_free_bytes_match':True,'returned_null':not bool(got)})
        if free_after and got:
            # Reload native result only for an independent cleanup oracle run;
            # the Python cleanup starts from its own Python unpack output.
            native_pages=fresh_pages();native_pages.update(image_pages(args.library,base))
            _write_span(native_pages,GUEST,memory)
            expected.calls=[];actual.calls=[];before_native_free.clear();before_model_free.clear()
            result,freed_memory,_,_=native(args.library,base,0x2550CC,[returned,0],native_pages,
                host_imports={0x347FA0:nfree},instruction_limit=200000)
            model.free_configuration_message(pages,message_address=got,image_base=base,free=pfree)
            assert _read_span(pages,GUEST,0xA000)==freed_memory,label+' cleanup bytes'
            assert actual.calls==expected.calls,label+' cleanup order'
            assert before_model_free==before_native_free,label+' cleanup pre-free bytes'
            assert not actual.blocks and not expected.blocks,label+' cleanup allocation leak'
            cases.append({'case':label+'_free','image_base':hex(base),'guest_bytes_match':True,
                'allocation_and_free_order_match':True,'pre_free_bytes_match':True,'no_live_allocations':True})
    for base in bases:
        for label,payload in payloads:compare(base,label,payload,free_after=True)
        failure_payload=dict(payloads)['nested_fields']+string(99,b'unknown')
        for index in range(13):compare(base,f'allocation_failure_{index}',failure_payload,failures=(index,))
        for descriptor,payload in ((0x350C80,string(1,b'key')+string(2,b'a')+string(2,b'b')+scalar(3,5)),(0x350BD0,string(1,b'key')+string(2,b'value'))):
            compare(base,'direct_'+hex(descriptor),payload,descriptor=descriptor,free_after=True)
    for label in ('unmapped_data','unknown_schema','input_bound','member_bound','slab_bound','custom_allocator'):
        pages=fresh_pages();pages.update(image_pages(args.library,bases[0]));data=GUEST+0x2000
        payload=b''.join(scalar(99,1) for _ in range(17 if label=='slab_bound' else 2));_write_span(pages,data,payload)
        before={k:bytes(v) for k,v in pages.items()};effects=Effects(blocks={})
        try:
            model.unpack_configuration_message(pages,data_address=GUEST+0x100000 if label=='unmapped_data' else data,
                length=len(payload),image_base=bases[0],allocate=effects.malloc,free=effects.free,
                descriptor_address=bases[0]+0x350000 if label=='unknown_schema' else 0,
                max_bytes=1 if label=='input_bound' else 0x100000,max_members=1 if label=='member_bound' else 32,
                allocator_address=GUEST if label=='custom_allocator' else 0)
        except (RefillUnsupported,ValueError):
            assert {k:bytes(v) for k,v in pages.items()}==before,label+' rollback'
            negatives.append({'case':label,'rejected':True,'page_rollback':True})
        else:raise AssertionError(label+' accepted')
    report={'library_sha256':LIBRARY_SHA256,'native_differences':len(cases),'cases':cases,
        'negative_count':len(negatives),'negative_cases':negatives,'fresh_synthetic_inputs':True,
        'native_outputs_used_as_model_input':False,'cleanup_model_uses_own_unpack_output':True,
        'jvm_used':False,'complete_protobuf_c':False,'complete_python_medusa':False,
        'rollback_scope':'guest_pages_only; allocation/free ledger is an explicit external effect'}
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'native_differences':len(cases),'negative_count':len(negatives)}))


if __name__=='__main__':main()
