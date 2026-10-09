"""Fresh B data expression frames, u32 fixups and actual tree erasure controls."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

import verify_vm9_alternative_ast_data_20261009 as controls
import verify_vm9_signer_objects as oracle
import vm9_alternative_startup as alternative
from vm9_allocator import RefillUnsupported, _read_span, _write_span

CB, AST, INPUT, HEAP = controls.CB, controls.AST, controls.INPUT, controls.HEAP
put, vector = controls.put, controls.vector
FUNCTIONS = {0x140:0x31E1D4, 0x148:0x31E4A4, 0x150:0x31E4F4, 0x168:0x31E5D8}


def prepare(library, base, spec):
    pages, sizes = controls.prepare(library, base, {k:v for k,v in spec.items() if k != 'cleanup'})
    pointer = max([controls.OLD]+[p+((max(n,1)+15)&~15) for p,n in sizes.items()])
    def block(size):
        nonlocal pointer
        result = pointer; pointer += (max(size,1)+15)&~15
        assert pointer < INPUT
        sizes[result] = size
        _write_span(pages,result,b'\xa6'*max(size,1))
        return result
    count, capacity = spec.get('frames',(0,0))
    if capacity:
        begin = block(capacity*16); vector(pages,CB+0x30,begin,count,capacity,16)
    raw, capacity = spec.get('raw_vector',(0,0))
    if capacity:
        _write_span(pages,int.from_bytes(_read_span(pages,AST+0x108,8),'little'),b'\x35'*capacity)
    if 'frame_constant' in spec: put(pages,base+0x6E188,spec['frame_constant'])
    # Each tuple is (key, left index, right index, black, patch byte offsets).
    # Trees are built directly from mathematical fixtures, never native output.
    nodes = spec.get('tree',[])
    addresses = [block(64) for _ in nodes]
    sentinel = CB+0x50
    parents = {spec.get('tree_root',0):sentinel} if nodes else {}
    for index,(_,left,right,_,_) in enumerate(nodes):
        for child in (left,right):
            if child is not None: parents[child] = addresses[index]
    for index,(key,left,right,black,patches) in enumerate(nodes):
        node = addresses[index]
        put(pages,node,addresses[left] if left is not None else 0)
        put(pages,node+8,addresses[right] if right is not None else 0)
        put(pages,node+0x10,parents[index]); put(pages,node+0x18,black,1)
        put(pages,node+0x20,key,4)
        if patches or spec.get('nonnull_tree_payload'):
            capacity = len(patches)+spec.get('tree_spare',2)
            payload = block(capacity*4); vector(pages,node+0x28,payload,len(patches),capacity,4)
            _write_span(pages,payload,b''.join(v.to_bytes(4,'little') for v in patches))
        else: vector(pages,node+0x28)
    if nodes:
        root = spec.get('tree_root',0); first = root
        while nodes[first][1] is not None: first = nodes[first][1]
        put(pages,CB+0x48,addresses[first]); put(pages,CB+0x50,addresses[root]); put(pages,CB+0x58,len(nodes))
    return pages,sizes


def minimal_specs():
    return [dict(label='data_expression_begin',data_vector=(1,1),raw_vector=(11,17),
                callbacks=[(0x148,(0xFFFFFFFFFFFFFFFF,))]),
            dict(label='data_expression_end_u32_tree_payload',frames=(1,1),raw_vector=(12,16),
                tree=[(0,None,None,1,[0,4,8])],callbacks=[(0x150,(77,))]),
            dict(label='cleanup_u32_tree_payload',tree=[(0,None,None,1,[0,4,8])],cleanup=True)]


def compare(args,base,spec):
    row = controls.compare(args,base,spec,functions=FUNCTIONS,prepare_case=prepare)
    pages,_,_ = controls.model_case(args,base,spec,prepare_case=prepare)
    # Separate byte/length expectations do not consume native output or model helpers.
    raw_size,raw_capacity = spec.get('raw_vector',(0,0))
    expected = bytearray(b'\x35'*raw_size)
    frame_count = spec.get('frames',(0,0))[0]
    active_record = bool(spec.get('data_vector',(0,0))[0])
    expected_start = None
    keys = {node[0]:node[4] for node in spec.get('tree',[])}
    for slot,argv in spec.get('callbacks',[]):
        if slot == 0x140: active_record = True
        elif slot == 0x148:
            expected_start = len(expected); frame_count = 1
        elif slot == 0x168: expected.extend((argv[0]&0xFFFFFFFF).to_bytes(4,'little'))
        elif slot == 0x150:
            for position in keys.pop(frame_count-1,[]):
                old_length = len(expected)
                if position+4 > old_length: expected.extend(bytes(position+4-old_length))
                expected[position:position+4] = old_length.to_bytes(4,'little')
            frame_count -= 1
    raw_pointer = int.from_bytes(_read_span(pages,AST+0x108,8),'little')
    raw_end = int.from_bytes(_read_span(pages,AST+0x110,8),'little')
    assert raw_end-raw_pointer == len(expected)
    assert _read_span(pages,raw_pointer,len(expected)) == expected
    begin = int.from_bytes(_read_span(pages,CB+0x30,8),'little')
    end = int.from_bytes(_read_span(pages,CB+0x38,8),'little')
    assert end-begin == (0 if spec.get('cleanup') and begin else frame_count*16)
    if expected_start is not None:
        record_end = int.from_bytes(_read_span(pages,AST+0xF8,8),'little')
        assert int.from_bytes(_read_span(pages,record_end-176+0x88,4),'little') == expected_start
    if any(slot==0x148 for slot,_ in spec.get('callbacks',[])):
        assert _read_span(pages,begin,8) == _read_span(pages,base+0x6E188,8)
        assert _read_span(pages,begin+8,8) == bytes([255])*8
    if not spec.get('cleanup'):
        assert int.from_bytes(_read_span(pages,CB+0x58,8),'little') == len(keys)
    row.update(synthetic_fixture=True,native_input_snapshot_used=False,
        independent_frame_and_raw_fixup_expectation_match=True)
    return row


def fixtures():
    cases = minimal_specs()
    for length in (0,1,3,4,11,32):
        for frames in ((0,0),(2,3),(3,3)):
            cases.append(dict(label=f'begin_{length}_{frames[0]}_{frames[1]}',data_vector=(2,3),
                raw_vector=(length,length+5),frames=frames,callbacks=[(0x148,(0xFFFFFFFFFFFFFFFF,))]))
    cases.append(dict(label='begin_overridden_image_constant',data_vector=(1,1),frame_constant=0x8877665544332211,
        callbacks=[(0x148,(9,)),(0x150,(4,))],cleanup=True))
    cases.append(dict(label='create_begin_words_end_destroy_cleanup',raw_vector=(3,9),
        callbacks=[(0x140,(0,7,3)),(0x148,(1,)),(0x168,(0xFFEEDDCC,)),(0x168,(0x12345678,)),(0x150,(22,))],
        destroy_data=True,cleanup=True))
    for patches,size,capacity in (([0,4,8],12,16),([1,6],7,9),([3,10,20],7,9),
                                 ([0,0,32,0],0,0),([],0,0),([128],3,9)):
        cases.append(dict(label=f'fixups_{size}_{capacity}_'+('_'.join(map(str,patches)) or 'empty'),
            frames=(1,2),raw_vector=(size,capacity),tree=[(0,None,None,1,patches)],
            nonnull_tree_payload=True,tree_spare=0 if not patches else 2,
            callbacks=[(0x150,(0xFFFFFFFFFFFFFFFF,))],cleanup=True))
    cases.append(dict(label='end_no_matching_key',frames=(1,2),raw_vector=(3,9),
        tree=[(1,None,None,1,[0])],callbacks=[(0x150,(0,))],cleanup=True))
    cases.append(dict(label='end_empty_tree',frames=(3,4),callbacks=[(0x150,(0,)),(0x150,(1,)),(0x150,(2,))],cleanup=True))
    def perfect(height,red_leaves=False):
        rows=[]
        def build(low,high,depth):
            if low == high: return None
            key = (low+high)//2; index = len(rows); rows.append(None)
            left,right = build(low,key,depth+1),build(key+1,high,depth+1)
            rows[index]=(key,left,right,int(not red_leaves or depth != height-1),[0,4,8])
            return index
        build(0,(1<<height)-1,0); return rows
    layouts = [perfect(2),perfect(3),perfect(3,True),perfect(4),
        [(1,1,2,1,[0]),(0,None,None,1,[0]),(3,3,None,1,[0]),(2,None,None,0,[0])],
        [(1,1,2,1,[0]),(0,None,None,1,[0]),(3,3,4,0,[0]),(2,None,None,1,[0]),(4,None,None,1,[0])],
        [(3,1,4,1,[0]),(1,2,3,0,[0]),(0,None,None,1,[0]),(2,None,None,1,[0]),(4,None,None,1,[0])],
        [(1,1,None,1,[0]),(0,None,None,0,[0])],[(0,None,1,1,[0]),(1,None,None,0,[0])]]
    for index,tree in enumerate(layouts):
        keys = sorted(row[0] for row in tree)
        if len(keys) == 15: keys = [0,1,3,7,11,13,14]
        for key in keys:
            cases.append(dict(label=f'erase_shape_{index}_key_{key}',frames=(key+1,key+2),
                raw_vector=(12,16),tree=tree,callbacks=[(0x150,(77,))],cleanup=True))
    cases.append(dict(label='descending_erase_all_keys',frames=(7,8),raw_vector=(12,16),tree=perfect(3),
        callbacks=[(0x150,(key,)) for key in range(6,-1,-1)],cleanup=True))
    return cases


def negatives(args):
    standard = dict(label='guard',data_vector=(1,1),frames=(1,1),raw_vector=(7,9),
        tree=[(0,None,None,1,[1,32])])
    cases=[]
    def add(label,changes=None,setup=None,spec=None): cases.append((label,changes or {},setup,spec or standard))
    add('begin_no_active_record',dict(slot_offset=0x148),spec=dict(label='guard'))
    add('end_no_frame',spec=dict(label='guard'))
    add('wrong_slot_binding',setup=lambda p:put(p,0x122C0000+0x372370+0x150,0))
    add('begin_wrong_slot_binding',dict(slot_offset=0x148),setup=lambda p:put(p,0x122C0000+0x372370+0x148,0))
    add('attached_callback',setup=lambda p:put(p,CB+8,INPUT))
    add('bad_argument_count',dict(arguments=()))
    add('bad_argument_value',dict(arguments=(-1,)))
    add('partial_frame_size',setup=lambda p:put(p,CB+0x38,int.from_bytes(_read_span(p,CB+0x30,8),'little')+1))
    add('partial_frame_capacity',setup=lambda p:put(p,CB+0x40,int.from_bytes(_read_span(p,CB+0x40,8),'little')+1))
    add('frame_node_budget',dict(max_nodes=1),spec=dict(label='guard',frames=(2,3)))
    add('tree_count',setup=lambda p:put(p,CB+0x58,2))
    add('tree_begin',setup=lambda p:put(p,CB+0x48,CB+0x50))
    def root(p):return int.from_bytes(_read_span(p,CB+0x50,8),'little')
    add('tree_root_parent',setup=lambda p:put(p,root(p)+0x10,CB))
    add('tree_root_red',setup=lambda p:put(p,root(p)+0x18,0,1))
    add('tree_unknown_color',setup=lambda p:put(p,root(p)+0x18,2,1))
    add('tree_cycle',setup=lambda p:put(p,root(p),root(p)))
    add('tree_shared_node',setup=lambda p:put(p,root(p)+8,root(p)))
    add('partial_u32_payload',setup=lambda p:put(p,root(p)+0x30,int.from_bytes(_read_span(p,root(p)+0x28,8),'little')+1))
    add('tree_payload_alias_raw',setup=lambda p:vector(p,root(p)+0x28,int.from_bytes(_read_span(p,AST+0x108,8),'little'),1,2,4))
    add('fixup_offset_budget',dict(max_vector_bytes=32))
    add('fixup_offset_u32_wrap',spec=dict(label='guard',frames=(1,1),tree=[(0,None,None,1,[0xFFFFFFFF])]))
    add('missing_allocator',dict(allocate=None))
    add('late_duplicate_raw_allocation',dict(allocate=lambda n:HEAP),
        spec=dict(label='guard',frames=(1,1),tree=[(0,None,None,1,[0,32])]))
    for label,pointer in (('callback',CB),('output',AST),('frame',None),('tree',None),('payload',None),
                          ('image',0x122C0000+0x6E188),('unaligned',HEAP+1),('unmapped',0x90000000)):
        def service(size,label=label,pointer=pointer):
            return pointer if pointer is not None else current[label]
        add('allocation_'+label,dict(allocate=service))
    for label,slot in (('begin_missing_allocator',0x148),('begin_allocation_alias',0x148)):
        add(label,dict(slot_offset=slot,allocate=None if 'missing' in label else lambda n:CB),
            spec=dict(label='guard',data_vector=(1,1)))
    tree=[(1,1,2,1,[]),(0,None,None,1,[]),(2,None,None,1,[])]
    add('tree_bad_child_parent',setup=lambda p:put(p,int.from_bytes(_read_span(p,root(p),8),'little')+0x10,CB),
        spec=dict(label='guard',frames=(2,2),tree=tree))
    add('tree_black_height',setup=lambda p:put(p,int.from_bytes(_read_span(p,root(p),8),'little')+0x18,0,1),
        spec=dict(label='guard',frames=(2,2),tree=tree))
    add('tree_duplicate_key',setup=lambda p:put(p,int.from_bytes(_read_span(p,root(p),8),'little')+0x20,1,4),
        spec=dict(label='guard',frames=(2,2),tree=tree))
    rows=[]
    for label,changes,setup,spec in cases:
        pages,_ = prepare(args.library,0x122C0000,spec)
        if setup: setup(pages)
        current = dict(frame=int.from_bytes(_read_span(pages,CB+0x30,8),'little'),tree=root(pages))
        current['payload'] = int.from_bytes(_read_span(pages,current['tree']+0x28,8),'little') if current['tree'] else 0
        before={k:bytes(v) for k,v in pages.items()}
        params=dict(callback_address=CB,image_base=0x122C0000,slot_offset=0x150,arguments=(0,),allocate=lambda n:HEAP)
        params.update(changes)
        try: alternative.run_reader_ast_callback(pages,**params)
        except (RefillUnsupported,ValueError): pass
        else: raise AssertionError('guard accepted: '+label)
        assert before == {k:bytes(v) for k,v in pages.items()},label
        rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_invalid_memory_path_compared=False))
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == oracle.LIBRARY_SHA256
    rows=[]; specs=fixtures(); rejected=negatives(args)
    for base in (0x122C0000,0x775C205000):
        for index,spec in enumerate(specs,1):
            rows.append(compare(args,base,spec))
            if index%16 == 0 or index==len(specs): print('B data expression:',hex(base),index,'/',len(specs),'passed',flush=True)
    evidence=dict(schema='vm9-alternative-ast-data-expression-fresh-v1',evidence_date='2026-10-09',
        evidence_timezone='Asia/Shanghai',sample_sha256=oracle.LIBRARY_SHA256,
        native_Python_AST_data_expression_controls=len(rows),rollback_negative_controls=len(rejected),
        pre_change_behavior_RED_controls=3,recovered_callback_slots_hex=['0x148','0x150'],
        actual_native_vtable_offset_hex='0x372370',expression_begin_offset_hex='0x31e4a4',
        expression_end_offset_hex='0x31e4f4',frame_append_offset_hex='0x31fee4',frame_stride=16,
        fixup_offset_hex='0x32000c',tree_erase_offset_hex='0x2695c0',tree_payload_stride=4,
        raw_patch_offset_hex='0x32151c',raw_length_offset_hex='0x321570',all_fixtures_synthetic=True,
        native_input_snapshot_used=False,private_payloads_published=False,data_expression_callbacks_implemented=True,
        parser_AST_composition_implemented=False,attached_parser_implemented=False,complete_AST_callbacks_implemented=False,
        complete_python_reader_implemented=False,independent_Python_factory_implemented=False,complete_python_bootstrap_controls=0,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False,
        cases=rows,negative_cases=rejected)
    args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    print('B data expression:',len(rows),'controls +',len(rejected),'rollback checks passed',flush=True)


if __name__ == '__main__': main()
