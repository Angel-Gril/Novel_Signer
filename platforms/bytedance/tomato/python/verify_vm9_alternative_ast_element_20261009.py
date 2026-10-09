"""Fresh B F0 and element reserve/create/expression/ownership controls.

Synthetic fixtures are independent of native snapshots. Original vtable
entries and both element/nested destructors execute with natural returns.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import random

import verify_vm9_alternative_ast_data_20261009 as controls
import verify_vm9_alternative_ast_data_expression_20261009 as expression
import verify_vm9_signer_objects as oracle
import vm9_alternative_startup as alternative
from vm9_allocator import RefillUnsupported, _read_span, _write_span

CB, AST, INPUT, HEAP = controls.CB, controls.AST, controls.INPUT, controls.HEAP
put, vector = controls.put, controls.vector
FUNCTIONS = {0xF0:0x31DB94,0x100:0x31DBCC,0x108:0x31DBF0,
             0x110:0x31DE48,0x118:0x31DE98,0x168:0x31E5D8,
             0x140:0x31E1D4,0x148:0x31E4A4,0x150:0x31E4F4}
SEED = 0x31DBF0


def prepare(library, base, spec):
    pages,sizes = expression.prepare(library,base,spec)
    pointer = max([controls.OLD]+[p+((max(n,1)+15)&~15) for p,n in sizes.items()])
    def block(size, marker=0xA7):
        nonlocal pointer
        result = pointer; pointer += (max(size,1)+15)&~15
        assert pointer < INPUT
        sizes[result] = size; _write_span(pages,result,bytes([marker])*max(size,1))
        return result
    def owned(header, stride, count, capacity, marker):
        result = block(capacity*stride,marker)
        vector(pages,header,result,count,capacity,stride)
        return result
    def children(header, count, mode):
        result = owned(header,56,count,count+1,0xD5)
        for index in range(count):
            child = result+index*56; vector(pages,child+0x10)
            if mode != 'mixed' or index%2:
                owned(child+0x10,8,0 if mode == 'empty' else index+1,index+2,0xE1+index)
    def nested(address, mode, index):
        _write_span(pages,address,bytes([0xB1+index])*144)
        put(pages,address,base+0x3724F0)
        for offset in (0x10,0x28,0x50,0x78): vector(pages,address+offset)
        if mode == 'null': return
        for offset,stride,count,capacity in ((0x10,8,1,2),(0x28,8,2,3),(0x50,16,1,2)):
            owned(address+offset,stride,0 if mode == 'empty' else count,capacity,0xC1+index)
        children(address+0x78,spec.get('child_count',2),mode)
    count,capacity = spec.get('element_vector',(0,0))
    if capacity or spec.get('element_nonnull_empty'):
        begin = block(capacity*184)
        vector(pages,AST+0xD8,begin,count,capacity,184)
        for index in range(count):
            address = begin+index*184
            _write_span(pages,address,bytes([0x91+index])*184)
            put(pages,address+0x28,base+0x3724F0)
            for offset in (0,0x38,0x50,0x78,0xA0): vector(pages,address+offset)
            for offset in (0x18,0x20,0x68,0x90): put(pages,address+offset,0xABC00000+index+offset)
            for offset in (0x30,0x70,0x98): put(pages,address+offset,0xDE000000+index+offset,4)
            mode = spec.get('owned_mode','null')
            if mode == 'null': continue
            for offset,stride,size,cap in ((0x38,8,1,2),(0x50,8,2,3),(0x78,16,2,3)):
                owned(address+offset,stride,0 if mode == 'empty' else size,cap,0xD1+index)
            children(address+0xA0,spec.get('child_count',2),mode)
            n = spec.get('nested_count',2)
            nested_begin = owned(address,144,n,spec.get('nested_capacity',n+1),0xD6)
            for j in range(n): nested(nested_begin+j*144,'null' if mode=='mixed' and j%2 else mode,j)
    if 'element_constant' in spec: put(pages,base+0x6E210,spec['element_constant'])
    return pages,sizes


def minimal_specs():
    return [dict(label='F0_zero_word',raw_vector=(3,9),callbacks=[(0xF0,())]),
        dict(label='element_reserve',callbacks=[(0x100,(3,))]),
        dict(label='element_create',callbacks=[(0x108,(99,7,3))]),
        dict(label='element_expression_begin',element_vector=(1,1),raw_vector=(11,17),callbacks=[(0x110,(99,))]),
        dict(label='element_expression_end',frames=(1,1),raw_vector=(12,16),
            tree=[(0,None,None,1,[0,4,8])],callbacks=[(0x118,(99,))]),
        dict(label='element_nested_destructor',element_vector=(1,1),owned_mode='rich',destroy_element=True)]


def fixtures():
    cases = minimal_specs()
    for size,cap in ((0,0),(0,1),(1,3),(3,3),(7,9),(12,16)):
        cases.append(dict(label=f'zero_words_{size}_{cap}',raw_vector=(size,cap),
            callbacks=[(0xF0,()),(0x168,(0xFFFFFFFF12345678,)),(0xF0,())],cleanup=True))
    for size,cap in ((0,0),(0,3),(1,1),(2,3)):
        for count in (0x100000000 if cap==0 else 0,cap,cap+2,0x100000001):
            cases.append(dict(label=f'reserve_{size}_{cap}_{count}',element_vector=(size,cap),
                owned_mode='rich',callbacks=[(0x100,(count,))],destroy_element=True))
    for size,cap in ((1,1),(2,2),(2,4)):
        for mode in ('null','empty','rich','mixed'):
            cases.append(dict(label=f'create_{size}_{cap}_{mode}',element_vector=(size,cap),
                owned_mode=mode,callbacks=[(0x108,(99,7,3))],destroy_element=True))
    for flags in (*range(8),0x100000003,0xFFFFFFFF00000002,0xFFFFFFFFFFFFFFFF):
        for table in (0,0xFFFFFFFF,0x100000001):
            cases.append(dict(label=f'flags_{flags}_table_{table}',callbacks=[(0x108,(0xFFFFFFFFFFFFFFFF,table,flags))],
                element_constant=0x8877665544332211,destroy_element=True))
    cases += [dict(label='reserve_nonnull_zero_capacity',element_nonnull_empty=True,callbacks=[(0x100,(3,))]),
        dict(label='create_nonnull_zero_capacity',element_nonnull_empty=True,callbacks=[(0x108,(0,0,0))],destroy_element=True),
        dict(label='nested_empty_block',element_vector=(1,1),owned_mode='rich',nested_count=0,child_count=0,
            callbacks=[(0x100,(3,))],destroy_element=True),
        dict(label='reserve_create_sequence',element_vector=(2,2),owned_mode='mixed',
            callbacks=[(0x100,(4,)),(0x108,(0,3,0)),(0x108,(1,5,3)),(0x108,(2,7,1)),
                (0x100,(7,)),(0x108,(3,9,2))],destroy_element=True),
        dict(label='create_begin_zero_word_end_destroy_cleanup',raw_vector=(3,9),
            callbacks=[(0x108,(0,7,3)),(0x110,(99,)),(0xF0,()),(0x168,(0x12345678,)),(0x118,(88,))],
            destroy_element=True,cleanup=True),
        dict(label='shared_data_element_frames',element_vector=(1,1),data_vector=(1,1),
            callbacks=[(0x110,(0,)),(0xF0,()),(0x118,(0,)),(0x148,(0,)),(0x168,(17,)),(0x150,(0,)),
                (0x110,(0,)),(0xF0,()),(0x118,(0,))],destroy_data=True,destroy_element=True,cleanup=True)]
    # The same valid mathematical trees exercise the shared expression owner
    # through 118, including successor replacement and all erase rotations.
    for original in expression.fixtures():
        if original['label'].startswith(('erase_shape','descending','fixups','end_')) or original['label'] in (
                'begin_overridden_image_constant','begin_0_0_0','begin_1_2_3','begin_3_3_3','begin_11_2_3'):
            spec = dict(original); spec['label'] = 'element_'+spec['label']
            if 'data_vector' in spec: spec['element_vector'] = spec.pop('data_vector')
            spec['callbacks'] = [({0x148:0x110,0x150:0x118}.get(slot,slot),argv) for slot,argv in spec['callbacks']]
            cases.append(spec)
    rng = random.Random(SEED)
    for index in range(6):
        cap = rng.randrange(1,4); size = rng.randrange(cap+1)
        cases.append(dict(label=f'generated_{index}',element_vector=(size,cap),
            owned_mode=rng.choice(('empty','rich','mixed')),nested_count=rng.randrange(3),child_count=rng.randrange(3),
            callbacks=[(0x108,(rng.getrandbits(64),rng.getrandbits(64),rng.getrandbits(64))),
                (0x100,(cap+3,))],destroy_element=True))
    return cases


def compare(args, base, spec):
    row = controls.compare(args,base,spec,functions=FUNCTIONS,prepare_case=prepare)
    pages,_,_ = controls.model_case(args,base,spec,prepare_case=prepare)
    def u(address,size=8): return int.from_bytes(_read_span(pages,address,size),'little')
    count = spec.get('element_vector',(0,0))[0]
    creates = [argv for slot,argv in spec.get('callbacks',[]) if slot == 0x108]
    begin,end,cap = (u(AST+offset) for offset in (0xD8,0xE0,0xE8))
    assert (end-begin)//184 == count+len(creates) and begin <= end <= cap
    initial,_ = prepare(args.library,base,spec)
    for index,(_,table,flags) in enumerate(creates,count):
        address = begin+index*184
        assert u(address+0x18) == int.from_bytes(_read_span(initial,base+0x6E210,8),'little')
        assert u(address+0x20) == (0,1,0,2)[flags&3] | ((table&0xFFFFFFFF)<<32)
        assert u(address+0x28) == base+0x3724F0
        assert u(address+0x30,4) == u(address+0x68) == u(address+0x70,4) == u(address+0x98,4) == 0
        for offset in (0,0x38,0x78,0xA0): assert _read_span(pages,address+offset,24) == bytes(24)
        result = u(address+0x50)
        assert result and u(result) == 0xFFFFFFFFFFFFFFFF
        assert u(address+0x58) == result+(0 if spec.get('destroy_element') else 8)
        assert u(address+0x60) == result+8
    length = spec.get('raw_vector',(0,0))[0]; expected = bytearray(b'\x35'*length)
    frames = spec.get('frames',(0,0))[0]; starts = {}; keys = {n[0]:n[4] for n in spec.get('tree',[])}
    for slot,argv in spec.get('callbacks',[]):
        if slot in (0x110,0x148):
            starts[slot] = len(expected); frames = 1
        elif slot in (0xF0,0x168): expected.extend((0 if slot==0xF0 else argv[0]&0xFFFFFFFF).to_bytes(4,'little'))
        elif slot in (0x118,0x150):
            for position in keys.pop(frames-1,[]):
                old = len(expected)
                if position+4 > old: expected.extend(bytes(position+4-old))
                expected[position:position+4] = old.to_bytes(4,'little')
            frames -= 1
    raw = u(AST+0x108)
    assert u(AST+0x110)-raw == len(expected) and _read_span(pages,raw,len(expected)) == expected
    frame = u(CB+0x30)
    assert u(CB+0x38)-frame == (0 if spec.get('cleanup') and frame else frames*16)
    if starts:
        assert _read_span(pages,frame,8) == _read_span(initial,base+0x6E188,8)
        assert _read_span(pages,frame+8,8) == bytes([255])*8
        for slot,start in starts.items():
            record_end,offset = (u(AST+0xE0),0x90) if slot == 0x110 else (u(AST+0xF8),0x88)
            stride = 184 if slot == 0x110 else 176
            assert u(record_end-stride+offset,4) == start
    for index in range(count,count+len(creates)):
        if 0x110 not in starts: assert u(begin+index*184+0x90) == 0xFFFFFFFF
    if not spec.get('cleanup'): assert u(CB+0x58) == len(keys)
    row['independent_element_frame_and_raw_expectation_match'] = True
    return row


def negatives(args):
    base = 0x122C0000; rows=[]; cases=[]
    standard = dict(label='guard',element_vector=(2,2),owned_mode='rich')
    def u(p,a): return int.from_bytes(_read_span(p,a,8),'little')
    def record(p): return u(p,AST+0xD8)
    def nested(p): return u(p,record(p))
    def add(label,changes=None,setup=None,spec=None): cases.append((label,changes or {},setup,spec or standard))
    for slot in (0xF0,0x100,0x108,0x110,0x118):
        add(f'slot_{slot:x}_binding',dict(slot_offset=slot,arguments=() if slot==0xF0 else (3,) if slot!=0x108 else (0,1,3)),
            setup=lambda p,s=slot:put(p,base+0x372370+s,0))
    add('type_GOT',setup=lambda p:put(p,base+0x375090,0))
    add('element_constant_missing',setup=lambda p:p.pop((base+0x6E210)>>12))
    add('attached',setup=lambda p:put(p,CB+8,INPUT))
    add('partial_element',setup=lambda p:put(p,AST+0xE0,record(p)+1))
    add('partial_nested',setup=lambda p:put(p,record(p)+8,nested(p)+1))
    add('partial_child',setup=lambda p:put(p,record(p)+0xA8,u(p,record(p)+0xA0)+1))
    add('unknown_element_type',setup=lambda p:put(p,record(p)+0x28,base+0x372518))
    add('unknown_nested_type',setup=lambda p:put(p,nested(p),base+0x372518))
    add('shared_nested_type_vector',setup=lambda p:vector(p,nested(p)+0x10,u(p,record(p)+0x50),1,3,8))
    add('nested_self_alias',setup=lambda p:vector(p,record(p),record(p),1,1,144))
    add('node_budget',dict(max_nodes=6))
    add('growth_budget',dict(max_nodes=3),spec=dict(label='guard',element_vector=(2,2)))
    add('byte_budget',dict(max_vector_bytes=735),spec=dict(label='guard',element_vector=(2,2)))
    add('missing_allocator',dict(allocate=None))
    for slot,spec in ((0xF0,dict(label='guard')),(0x100,dict(label='guard')),
                      (0x110,dict(label='guard',element_vector=(1,1)))):
        add(f'{slot:x}_missing_allocator',dict(slot_offset=slot,arguments=() if slot==0xF0 else (3,),allocate=None),spec=spec)
    add('bad_create_arity',dict(arguments=(0,1)))
    add('bad_create_u64',dict(arguments=(0,1,1<<64)))
    add('bad_zero_arity',dict(slot_offset=0xF0,arguments=(0,)))
    add('begin_no_element',dict(slot_offset=0x110,arguments=(0,)),spec=dict(label='guard'))
    add('end_no_frame',dict(slot_offset=0x118,arguments=(0,)),spec=dict(label='guard'))
    add('reserve_count_budget',dict(slot_offset=0x100,arguments=(4097,)),spec=dict(label='guard'))
    add('zero_word_byte_budget',dict(slot_offset=0xF0,arguments=(),max_vector_bytes=3),spec=dict(label='guard'))
    add('unmapped_empty_owned',setup=lambda p:vector(p,AST+0xD8,0x90000000),spec=dict(label='guard'))
    add('destructor_shared_nested',dict(destructor=True),setup=lambda p:vector(p,nested(p)+0x10,u(p,record(p)+0x50),1,3,8))
    for label,changes,setup,spec in cases:
        pages,_ = prepare(args.library,base,spec)
        if setup: setup(pages)
        before={k:bytes(v) for k,v in pages.items()}; offset=0
        def allocate(size):
            nonlocal offset
            pointer=HEAP+offset; offset+=(size+15)&~15; return pointer
        params=dict(callback_address=CB,image_base=base,slot_offset=0x108,arguments=(0,7,3),allocate=allocate)
        if changes.get('destructor'):
            run=lambda:alternative.destroy_reader_ast_element_record(pages,record_address=record(pages),image_base=base)
        else:
            params.update(changes); run=lambda:alternative.run_reader_ast_callback(pages,**params)
        try: run()
        except (RefillUnsupported,ValueError): pass
        else: raise AssertionError('element guard accepted: '+label)
        assert before == {k:bytes(v) for k,v in pages.items()},label
        rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_invalid_memory_path_compared=False))
    for mode,spec,total in (('growth',standard,5),('spare',dict(label='guard',element_vector=(1,3),owned_mode='rich'),4)):
        for fail_at in range(1,total+1):
            for target in ('unmapped','unaligned','partial','callback','output','record','nested','child','retained','image','duplicate'):
                if target == 'duplicate' and fail_at == 1: continue
                pages,_=prepare(args.library,base,spec)
                partial=oracle.GUEST+0xAFF8
                if target == 'partial':
                    if fail_at==4 and mode=='growth': pages.pop((oracle.GUEST+0xB000)>>12,None)
                    else: pages[partial>>12]=pages[partial>>12][:4092]
                before={k:bytes(v) for k,v in pages.items()}; planned=[]; offset=0
                def allocate(size):
                    nonlocal offset
                    pointer=HEAP+offset; offset+=(size+15)&~15
                    if len(planned)+1 == fail_at:
                        pointer={'unmapped':0x90000000,'unaligned':HEAP+1,'partial':partial,'callback':CB,
                            'output':AST,'record':record(pages),'nested':nested(pages),
                            'child':u(pages,record(pages)+0xA0),'retained':INPUT,
                            'image':base+0x6E210,'duplicate':planned[0] if planned else 0}[target]
                    planned.append(pointer); return pointer
                try:
                    alternative.run_reader_ast_callback(pages,callback_address=CB,image_base=base,
                        slot_offset=0x108,arguments=(0,7,3),allocate=allocate,reserved_regions=((INPUT,INPUT+2048),))
                except (RefillUnsupported,ValueError): pass
                else: raise AssertionError(('allocation guard accepted',mode,fail_at,target))
                assert len(planned)==fail_at and before=={k:bytes(v) for k,v in pages.items()},(mode,fail_at,target)
                rows.append(dict(label=f'{mode}_allocation_{fail_at}_{target}',rejected=True,all_pages_unchanged=True,
                    allocation_plans_before_rejection=len(planned),native_invalid_memory_path_compared=False))
    # Begin writes its active pointer/length before requesting a frame; end
    # can already have patched/reallocated raw storage when a later plan fails.
    for slot,spec,total in ((0xF0,dict(label='guard',raw_vector=(3,3)),1),
            (0x100,standard,1),(0x110,dict(label='guard',element_vector=(1,1),raw_vector=(3,9)),1),
            (0x118,dict(label='guard',frames=(1,1),tree=[(0,None,None,1,[0,32])]),2)):
        for fail_at in range(1,total+1):
            for target in ('unmapped','unaligned','partial','callback','output','image','duplicate'):
                if target=='duplicate' and fail_at==1: continue
                pages,_=prepare(args.library,base,spec); partial=oracle.GUEST+0xAFF8
                if target=='partial': pages[partial>>12]=pages[partial>>12][:4092]
                before={k:bytes(v) for k,v in pages.items()}; planned=[]; offset=0
                def allocate(size):
                    nonlocal offset
                    pointer=HEAP+offset; offset+=(size+15)&~15
                    if len(planned)+1==fail_at:
                        pointer={'unmapped':0x90000000,'unaligned':HEAP+1,'partial':partial,
                            'callback':CB,'output':AST,'image':base+0x6E210,
                            'duplicate':planned[0] if planned else 0}[target]
                    planned.append(pointer); return pointer
                try:
                    alternative.run_reader_ast_callback(pages,callback_address=CB,image_base=base,
                        slot_offset=slot,arguments=() if slot==0xF0 else (3,),allocate=allocate)
                except (RefillUnsupported,ValueError): pass
                else: raise AssertionError(('slot allocation guard accepted',slot,fail_at,target))
                assert len(planned)==fail_at and before=={k:bytes(v) for k,v in pages.items()},(slot,fail_at,target)
                rows.append(dict(label=f'{slot:x}_allocation_{fail_at}_{target}',rejected=True,all_pages_unchanged=True,
                    allocation_plans_before_rejection=len(planned),native_invalid_memory_path_compared=False))
    return rows


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    rows=[]; rejected=negatives(args); specs=fixtures()
    for base in (0x122C0000,0x775C205000):
        for index,spec in enumerate(specs,1):
            rows.append(compare(args,base,spec))
            if index%16==0 or index==len(specs): print('B element:',hex(base),index,'/',len(specs),'passed',flush=True)
    evidence=dict(schema='vm9-alternative-ast-element-fresh-v1',evidence_date='2026-10-09',
        evidence_timezone='Asia/Shanghai',sample_sha256=oracle.LIBRARY_SHA256,generated_fixture_seed=SEED,
        native_Python_AST_element_controls=len(rows),rollback_negative_controls=len(rejected),
        pre_change_behavior_RED_controls=6,recovered_callback_slots_hex=['0xf0','0x100','0x108','0x110','0x118'],
        actual_native_vtable_offset_hex='0x372370',zero_word_offset_hex='0x31db94',
        reserve_offset_hex='0x31dbcc',create_offset_hex='0x31dbf0',expression_begin_offset_hex='0x31de48',
        expression_end_offset_hex='0x31de98',move_offset_hex='0x3205e8',append_offset_hex='0x320724',
        record_copy_offset_hex='0x32085c',element_destructor_offset_hex='0x2cc2b8',nested_destructor_offset_hex='0x2cc470',
        element_record_stride=184,nested_record_stride=144,child_record_stride=56,frame_stride=16,tree_payload_stride=4,
        all_fixtures_synthetic=True,native_input_snapshot_used=False,private_payloads_published=False,
        stack_temporary_destructor_executed=True,stack_temporary_frees_compared=True,stack_temporary_destroy_event_compared=False,
        element_callbacks_implemented=True,parser_AST_composition_implemented=False,attached_parser_implemented=False,
        complete_AST_callbacks_implemented=False,complete_python_reader_implemented=False,
        independent_Python_factory_implemented=False,complete_python_bootstrap_controls=0,complete_python_medusa=False,
        fresh_signer_output_verified=False,live_server_matrix_verified=False,cases=rows,negative_cases=rejected)
    args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    print('B element:',len(rows),'native/Python +',len(rejected),'rollback checks passed',flush=True)


if __name__=='__main__': main()
