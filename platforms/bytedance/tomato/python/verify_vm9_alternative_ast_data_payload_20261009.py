"""Fresh actual B data payload callback and section 11 length ABI controls.

Original vtables/functions execute; private payloads and snapshots stay local.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import random

import verify_vm9_alternative_ast_data_20261009 as data_controls
import verify_vm9_alternative_segments_20261008 as segments
import verify_vm9_alternative_import_limits_20261008 as harness
import verify_vm9_alternative_sections_20261008 as sections
import verify_vm9_signer_objects as oracle
import vm9_alternative_startup as alternative
from verify_vm9_alternative_blob_xor_20261008 import constructor_codec_byte
from vm9_allocator import RefillUnsupported, _read_span, _write_span

FUNCTIONS = {0x140:0x31E1D4,0x158:0x31E53C,0x160:0x31E5B4}
CB, AST, INPUT, HEAP = data_controls.CB,data_controls.AST,data_controls.INPUT,data_controls.HEAP
put,vector = data_controls.put,data_controls.vector
SEED = 0x31E53C


def prepare(library, base, spec):
    pages,sizes = data_controls.prepare(library,base,spec)
    _write_span(pages,INPUT+spec.get('input_offset',0),spec.get('payload',b''))
    if 'payload_vector' in spec:
        size,capacity = spec['payload_vector']
        record = int.from_bytes(_read_span(pages,AST+0xF8,8),'little')-176
        pointer = max([data_controls.OLD]+[p+((max(n,1)+15)&~15) for p,n in sizes.items()])
        assert pointer+max(capacity,1) < INPUT
        sizes[pointer] = capacity
        vector(pages,record,pointer,size,capacity)
        _write_span(pages,pointer,b'\xd6'*capacity)
    return pages,sizes


def abi_case(args, base):
    spec = dict(label='data_length_ABI',blob=b'A'*8+sections.section(11,b'\1'+segments.data(1,payload=b'z'*128)))
    return harness.compare(args,base,spec,segment_sections=True,model_options=segments.options())


def payload_case(args, base):
    spec = dict(label='data_payload_create_write',payload=b'\0\xffz',
        callbacks=[(0x140,(0,0,1)),(0x158,(99,INPUT,3))],destroy_data=True)
    return data_controls.compare(args,base,spec,functions=FUNCTIONS,prepare_case=prepare)


def actual_payloads(library):
    # Independent Python XOR and envelope/LEB fixture decoding; no model parser
    # or native input/output snapshots supply the data segments.
    base = 0x122C0000
    pages = data_controls.ast_controls.fresh_image(library,base)
    key = constructor_codec_byte(library)
    blob = bytes(value^key for value in _read_span(pages,base+0x387D20,0x37FD0))
    def leb(data,cursor,width=5):
        value = 0
        for index in range(width):
            byte = data[cursor]; cursor += 1; value |= (byte&127)<<(index*7)
            if byte < 128: return value,cursor
        raise AssertionError('actual fixture LEB did not terminate')
    cursor,body = 8,None
    while cursor < len(blob):
        number = blob[cursor]; length,cursor = leb(blob,cursor+1)
        end = cursor+length; assert end <= len(blob)
        if number == 11:
            assert body is None; body = blob[cursor:end]
        cursor = end
    assert cursor == len(blob) and body is not None
    count,cursor = leb(body,0); result = []
    for index in range(count):
        flags,cursor = leb(body,cursor); assert flags <= 7
        memory_index = 0
        if flags&2: memory_index,cursor = leb(body,cursor)
        if not flags&1:
            while True:
                opcode = body[cursor]; cursor += 1
                if opcode == 0x0B: break
                if opcode in (0x41,0x42): _,cursor = leb(body,cursor,5 if opcode==0x41 else 10)
                elif opcode in (0x43,0x44): cursor += 4 if opcode==0x43 else 8
                else: assert opcode == 0,'unexpected actual fixture expression'
        length,cursor = leb(body,cursor); end = cursor+length
        assert end <= len(body)
        result.append((index,memory_index,flags,body[cursor:end])); cursor = end
    assert cursor == len(body) and [len(row[3]) for row in result] == [3632,352,0]
    return result,body


def ast_fixtures(library):
    cases = [dict(label='payload_create_write',payload=b'\0\xffz',
        callbacks=[(0x140,(0,0,1)),(0x158,(99,INPUT,3))],destroy_data=True)]
    for size,capacity in ((0,0),(0,8),(3,8),(8,8),(9,13)):
        for length in sorted({0,1,max(1,size-1),size,capacity,capacity+1,2*capacity+1}):
            payload = bytes((i*73+19)&255 for i in range(length))
            cases.append(dict(label=f'payload_resize_{size}_{capacity}_{length}',
                data_vector=(2,3),payload_vector=(size,capacity),payload=payload,
                callbacks=[(0x158,(0xFFFFFFFFFFFFFFFF,INPUT,length))],destroy_data=True))
    for pointer in (0,0x90000000,0xFFFFFFFFFFFFFFFF):
        cases.append(dict(label=f'payload_zero_unused_pointer_{pointer}',
            callbacks=[(0x158,(0xFFFFFFFFFFFFFFFF,pointer,0))]))
    for length in (3,128,257,4095):
        cases.append(dict(label=f'payload_unaligned_input_{length}',data_vector=(1,1),
            input_offset=1,payload=bytes((i*37)&255 for i in range(length)),
            callbacks=[(0x158,(4,INPUT+1,length))]))
    for mode in ('empty','rich','mixed'):
        cases.append(dict(label='payload_rich_'+mode,data_vector=(2,2),owned_mode=mode,
            payload=b'y'*14,callbacks=[(0x158,(7,INPUT,14)),(0x160,(3,))],destroy_data=True))
    cases.append(dict(label='payload_repeated_resize',data_vector=(2,2),payload_vector=(3,8),
        payload=bytes(range(65)),callbacks=[(0x158,(n,INPUT,n)) for n in (5,8,9,1,0,17,65,0)],
        destroy_data=True))
    cases.append(dict(label='payload_create_reserve_write_create_write',payload=bytes(range(33)),
        callbacks=[(0x160,(2,)),(0x140,(0,7,3)),(0x158,(0,INPUT,33)),
                   (0x160,(3,)),(0x140,(1,9,1)),(0x158,(1,INPUT,5))],destroy_data=True))
    cases.append(dict(label='payload_retained_during_callback_cleanup',data_vector=(2,2),
        owned_mode='rich',payload=bytes(range(33)),callbacks=[(0x158,(9,INPUT,33))],
        cleanup=True,cleanup_count=1,tree_depth=1,type_vector=(1,2),rich=True))
    rng = random.Random(SEED)
    for index in range(8):
        capacity = rng.randrange(1,33); size = rng.randrange(capacity+1); length = rng.randrange(65)
        cases.append(dict(label=f'generated_payload_{index}',data_vector=(2,3),
            payload_vector=(size,capacity),payload=bytes(rng.getrandbits(8) for _ in range(length)),
            callbacks=[(0x158,(rng.getrandbits(64),INPUT,length))],destroy_data=True))
    actual,_ = actual_payloads(library)
    for index,memory_index,flags,payload in actual:
        cases.append(dict(label=f'actual_ELF_payload_{index}',actual=True,payload=payload,
            callbacks=[(0x140,(index,memory_index,flags)),(0x158,(index,INPUT,len(payload)))],
            destroy_data=True))
    return cases


def abi_fixtures(library):
    cases = []
    for length in (0,1,127,128,257):
        payload = bytes((i*73)&255 for i in range(length))
        for flags in (0,1,3):
            cases.append(dict(label=f'length_ABI_{flags}_{length}',blob=b'A'*8+
                sections.section(11,b'\1'+segments.data(flags,payload=payload))))
    cases.append(dict(label='length_ABI_callback_failure',blob=b'A'*8+
        sections.section(11,b'\2'+segments.data(1,payload=b'abc')*2),failure_slot=0x158,failure_call=1))
    _,body = actual_payloads(library)
    cases.append(dict(label='actual_ELF_length_ABI',blob=b'A'*8+sections.section(11,body),
        actual_ELF_data_section_input=True))
    return cases


def compare_payload(args,base,spec):
    row = data_controls.compare(args,base,spec,functions=FUNCTIONS,prepare_case=prepare)
    pages,_,_ = data_controls.model_case(args,base,spec,prepare_case=prepare)
    # Check the final active record independently. Zero length preserves its
    # prior size; the destructor later resets end but retains payload bytes.
    size = spec.get('payload_vector',(0,0))[0]
    if spec.get('owned_mode') in ('rich','mixed'): size = 9
    expected = b'\xd6'*size if 'payload_vector' in spec else b'\xd1'*size
    for slot,argv in spec.get('callbacks',[]):
        if slot == 0x140: size,expected = 0,b''
        elif slot == 0x158 and argv[2]: size,expected = argv[2],spec['payload'][:argv[2]]
    end = int.from_bytes(_read_span(pages,AST+0xF8,8),'little')
    begin = int.from_bytes(_read_span(pages,AST+0xF0,8),'little')
    if end > begin:
        record = end-176
        pointer,stop,cap = (int.from_bytes(_read_span(pages,record+offset,8),'little') for offset in (0,8,16))
        assert stop-pointer == (0 if spec.get('destroy_data') else size)
        assert cap-pointer >= size and _read_span(pages,pointer,size) == expected
    row.update(synthetic_fixture=not spec.get('actual',False),
        actual_ELF_data_payload_input=spec.get('actual',False),independent_payload_expectation_match=True)
    return row


def negatives(args):
    base = 0x122C0000; cases = []; records = []
    def u(p,a): return int.from_bytes(_read_span(p,a,8),'little')
    def record(p): return u(p,AST+0xF8)-176
    def add(label,changes=None,setup=None,spec=None):
        cases.append((label,changes or {},setup,spec or dict(label='guard',data_vector=(2,2),
            payload_vector=(3,8),payload=bytes(range(33)))))
    add('payload_slot_binding',setup=lambda p:put(p,base+0x372370+0x158,base+0x31E5B4))
    add('payload_no_active_record',spec=dict(label='guard',payload=b'x'))
    add('payload_attached_callback',setup=lambda p:put(p,CB+8,INPUT))
    add('payload_unknown_type',setup=lambda p:put(p,record(p)+0x20,base+0x372518))
    add('payload_source_null',dict(arguments=(0,0,33)))
    add('payload_source_unmapped',dict(arguments=(0,0x90000000,33)))
    add('payload_source_overflow',dict(arguments=(0,(1<<64)-16,33)))
    add('payload_source_cross_missing_page',dict(arguments=(0,oracle.GUEST+0xFFF0,33)))
    for name,target in (('callback',CB),('output',AST),('record',None),('existing_payload','payload')):
        def setup(p,target=target):
            pointer = record(p) if target is None else u(p,record(p)) if target=='payload' else target
            put(p,CB+0x78,pointer)
        add('payload_source_alias_'+name,setup=setup,changes=dict(source_from_callback=True))
    add('payload_length_u64_not_u32',dict(arguments=(0,INPUT,0x100000001)))
    add('payload_input_byte_budget',dict(arguments=(0,INPUT,353),max_vector_bytes=352))
    add('payload_growth_byte_budget',dict(arguments=(0,INPUT,201),max_vector_bytes=399),
        spec=dict(label='guard',data_vector=(1,1),payload_vector=(3,200),payload=b'x'*201))
    add('payload_missing_allocator',dict(allocate=None))
    add('payload_bad_argument_count',dict(arguments=(0,INPUT)))
    add('payload_bad_argument_length',dict(arguments=(0,INPUT,-1)))
    add('payload_partial_header',setup=lambda p:put(p,record(p)+8,u(p,record(p))+9))
    add('payload_node_budget',dict(max_nodes=1))
    for target in ('unmapped','unaligned','record','existing_payload','source','source_tail','retained','image','cross_missing_page'):
        def setup(p,target=target):
            if target == 'cross_missing_page': p.pop((oracle.GUEST+0xB000)>>12,None)
        add('payload_allocation_'+target,setup=setup,changes=dict(allocation_target=target))
    for label,changes,setup,spec in cases:
        pages,_ = prepare(args.library,base,spec)
        if setup: setup(pages)
        changes = dict(changes)
        if changes.pop('source_from_callback',False): changes['arguments'] = (0,u(pages,CB+0x78),33)
        target = changes.pop('allocation_target',None)
        planned = []
        def allocate(size):
            pointer = {'unmapped':0x90000000,'unaligned':HEAP+1,'record':record(pages),
                'existing_payload':u(pages,record(pages)),'source':INPUT,'source_tail':INPUT+24,
                'retained':INPUT+0x200,'image':base+0x375090,
                'cross_missing_page':oracle.GUEST+0xAFF8}.get(target,HEAP)
            planned.append((pointer,size)); return pointer
        params = dict(callback_address=CB,image_base=base,slot_offset=0x158,
            arguments=(0,INPUT,33),allocate=allocate,reserved_regions=((INPUT+0x200,INPUT+0x300),))
        params.update(changes)
        before = {key:bytes(value) for key,value in pages.items()}
        try: alternative.run_reader_ast_callback(pages,**params)
        except (RefillUnsupported,ValueError): pass
        else: raise AssertionError('payload guard accepted: '+label)
        assert before == {key:bytes(value) for key,value in pages.items()},label
        if target: assert len(planned)==1,label
        records.append(dict(label=label,rejected=True,all_pages_unchanged=True,
            native_invalid_memory_path_compared=False,allocation_plans_before_rejection=len(planned)))
    # A late guard after a completed create/write must retain that checkpoint.
    pages,_ = prepare(args.library,base,dict(label='late_guard',payload=b'abcdefghi'))
    offset = 0
    def allocate(size):
        nonlocal offset
        pointer = HEAP+offset; offset += (size+15)&~15; return pointer
    for slot,argv in ((0x140,(0,0,1)),(0x158,(0,INPUT,9))):
        alternative.run_reader_ast_callback(pages,callback_address=CB,image_base=base,
            slot_offset=slot,arguments=argv,allocate=allocate)
    before = {key:bytes(value) for key,value in pages.items()}
    try:
        alternative.run_reader_ast_callback(pages,callback_address=CB,image_base=base,
            slot_offset=0x158,arguments=(0,INPUT,33),allocate=lambda n:INPUT)
    except RefillUnsupported: pass
    else: raise AssertionError('late payload alias accepted')
    assert before == {key:bytes(value) for key,value in pages.items()}
    records.append(dict(label='payload_late_guard_after_create_write',rejected=True,all_pages_unchanged=True,
        native_invalid_memory_path_compared=False,completed_callbacks_before_rejection=2))
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library',required=True,type=Path)
    parser.add_argument('--libc',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest() == 'd2376df6d2ac3e0213f85e3614c4c7ad1d28c84c44926058d5c1b95c855563db'
    records,abi_records = [],[]; specs = ast_fixtures(args.library); abis = abi_fixtures(args.library)
    rejected = negatives(args)
    for base in (0x122C0000,0x775C205000):
        for index,spec in enumerate(specs,1):
            records.append(compare_payload(args,base,spec))
            if index%24 == 0: print('B data payload:',hex(base),index,'/',len(specs),'passed',flush=True)
        for spec in abis:
            row = harness.compare(args,base,spec,segment_sections=True,model_options=segments.options())
            row['slot_158_index_pointer_length_and_cursor_match'] = True; abi_records.append(row)
    evidence = dict(schema='vm9-alternative-ast-data-payload-fresh-v1',evidence_date='2026-10-09',
        evidence_timezone='Asia/Shanghai',sample_sha256=oracle.LIBRARY_SHA256,generated_fixture_seed=SEED,
        native_Python_AST_data_payload_controls=len(records),native_Python_parser_length_ABI_controls=len(abi_records),
        rollback_negative_controls=len(rejected),pre_change_behavior_RED_controls=2,
        recovered_callback_slot_hex='0x158',actual_native_vtable_offset_hex='0x372370',
        payload_callback_offset_hex='0x31e53c',byte_vector_append_offset_hex='0x2db2b4',
        parser_offset_hex='0x323fb4',parser_slot_158_call_offset_hex='0x32415c',
        slot_158_arguments=['index','payload_pointer','payload_length_u64'],
        actual_ELF_payload_controls=sum(r['actual_ELF_data_payload_input'] for r in records),
        actual_ELF_length_ABI_controls=sum(r['actual_ELF_data_section_input'] for r in abi_records),
        native_input_snapshot_used=False,private_payloads_published=False,parser_length_ABI_repaired=True,
        data_payload_callback_implemented=True,attached_parser_implemented=False,
        parser_AST_composition_implemented=False,complete_AST_callbacks_implemented=False,
        complete_python_reader_implemented=False,independent_Python_factory_implemented=False,
        complete_python_bootstrap_controls=0,complete_python_medusa=False,
        fresh_signer_output_verified=False,live_server_matrix_verified=False,
        cases=records,parser_ABI_cases=abi_records,negative_cases=rejected)
    args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    print('B data payload:',len(records),'AST +',len(abi_records),'parser ABI +',len(rejected),'rollback checks passed',flush=True)


if __name__ == '__main__': main()
