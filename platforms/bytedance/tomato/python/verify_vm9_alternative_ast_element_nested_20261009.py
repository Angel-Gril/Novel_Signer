"""Fresh B element result type, nested reserve and expression begin/end controls.

Original vtable slots execute on synthetic input, including actual nested
movement/destruction; independent expectations never consume native snapshots.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import random

import verify_vm9_alternative_ast_data_20261009 as controls
import verify_vm9_alternative_ast_data_expression_20261009 as expression
import verify_vm9_alternative_ast_element_20261009 as element
import verify_vm9_signer_objects as oracle
import vm9_alternative_startup as alternative
from vm9_allocator import RefillUnsupported, _read_span

CB,AST,INPUT,HEAP=element.CB,element.AST,element.INPUT,element.HEAP
put,vector,prepare=element.put,element.vector,element.prepare
FUNCTIONS={**element.FUNCTIONS,0x120:0x31DEE0,0x128:0x31DEF4,0x130:0x31DF1C,0x138:0x31E18C}
SEED=0x31DF1C


def minimal_specs():
    return [dict(label='element_result_type',element_vector=(1,1),callbacks=[(0x120,(99,0xFFFFFFFFFFFFFFF0))]),
        dict(label='nested_reserve',element_vector=(1,1),owned_mode='rich',callbacks=[(0x128,(99,5))]),
        dict(label='nested_create_begin',element_vector=(1,1),raw_vector=(3,9),callbacks=[(0x130,(99,))]),
        dict(label='nested_expression_end',frames=(1,1),raw_vector=(12,16),tree=[(0,None,None,1,[0,4,8])],
            callbacks=[(0x138,(99,))])]


def fixtures():
    cases=minimal_specs()
    for value in (0,1,0xFFFFFFFF,0x100000001,0x8000000012345678,0xFFFFFFFFFFFFFFF0,0xFFFFFFFFFFFFFFEF,0xFFFFFFFFFFFFFFEB):
        cases.append(dict(label=f'type_{value}',element_vector=(2,3),owned_mode='mixed',
            callbacks=[(0x120,(0xFFFFFFFFFFFFFFFF,value))],destroy_element=True))
    for size,capacity in ((0,0),(1,1),(2,3)):
        for count in (0,capacity+2,0x100000001):
            for mode in ('rich','empty'):
                cases.append(dict(label=f'reserve_{size}_{capacity}_{count}_{mode}',element_vector=(1,1),
                    owned_mode=mode,nested_count=size,nested_capacity=capacity,
                    callbacks=[(0x128,(0xFFFFFFFFFFFFFFFF,count))],destroy_element=True))
    for size,capacity in ((0,0),(1,1),(2,3)):
        for mode in ('null','empty','rich','mixed'):
            if mode=='null' and (size,capacity)!=(0,0): continue
            cases.append(dict(label=f'create_{size}_{capacity}_{mode}',element_vector=(1,1),owned_mode=mode,
                nested_count=size,nested_capacity=capacity,callbacks=[(0x120,(99,0x8000000012345678)),
                    (0x130,(0xFFFFFFFFFFFFFFFF,)),(0xF0,()),(0x138,(88,))],destroy_element=True,cleanup=True))
    for length in (0,1,3,11):
        for frames in ((0,0),(2,3),(3,3)):
            cases.append(dict(label=f'begin_{length}_{frames[0]}_{frames[1]}',element_vector=(1,1),
                raw_vector=(length,length+5),frames=frames,callbacks=[(0x130,(99,))],destroy_element=True))
    cases += [dict(label='reserve_create_reserve_sequence',element_vector=(2,2),owned_mode='rich',nested_count=1,nested_capacity=1,
        callbacks=[(0x128,(0,4)),(0x120,(99,0xFFFFFFFFFFFFFFF0)),(0x130,(0,)),(0x138,(0,)),
            (0x120,(0,0x8000000012345678)),(0x130,(1,)),(0xF0,()),(0x138,(1,)),
            (0x128,(0,7)),(0x130,(2,)),(0x138,(2,))],destroy_element=True,cleanup=True),
        dict(label='create_element_type_nested_begin_word_end',callbacks=[(0x108,(0,7,3)),
            (0x120,(0,0xFFFFFFFFFFFFFFEB)),(0x128,(0,3)),(0x130,(0,)),(0x168,(17,)),(0x138,(0,))],
            destroy_element=True,cleanup=True),
        dict(label='nested_overridden_frame_constant',element_vector=(1,1),frame_constant=0x8877665544332211,
            callbacks=[(0x130,(0,)),(0x138,(0,))],destroy_element=True,cleanup=True),
        dict(label='nested_begin_then_element_begin',element_vector=(1,1),callbacks=[(0x130,(0,)),(0xF0,()),
            (0x138,(0,)),(0x110,(0,)),(0xF0,()),(0x118,(0,))],destroy_element=True,cleanup=True),
        dict(label='nested_create_word_fixup_erase_move',element_vector=(1,1),owned_mode='rich',
            nested_count=2,nested_capacity=2,raw_vector=(3,9),tree=[(0,None,None,1,[1,24])],
            callbacks=[(0x120,(0,0xFFFFFFFFFFFFFFEF)),(0x130,(0,)),(0xF0,()),(0x138,(0,)),
                (0x128,(0,7))],destroy_element=True,cleanup=True),
        dict(label='repeated_nested_create_growth',element_vector=(1,1),
            callbacks=[item for i in range(5) for item in ((0x120,(i,0x8000000012340000+i)),
                (0x130,(i,)),(0x168,(i+7,)),(0x138,(i,)))],destroy_element=True,cleanup=True)]
    for original in expression.fixtures():
        if original['label'].startswith(('erase_shape','descending','fixups','end_')):
            spec=dict(original); spec['label']='nested_'+spec['label']
            spec['callbacks']=[(0x138,argv) for _,argv in spec['callbacks']]
            cases.append(spec)
    rng=random.Random(SEED)
    for i in range(6):
        capacity=rng.randrange(1,4); size=rng.randrange(capacity+1)
        cases.append(dict(label=f'generated_nested_{i}',element_vector=(1,1),owned_mode=rng.choice(('rich','empty','mixed')),
            nested_count=size,nested_capacity=capacity,child_count=rng.randrange(3),frames=(2,3),
            callbacks=[(0x120,(rng.getrandbits(64),rng.getrandbits(64))),
                (0x130,(rng.getrandbits(64),)),(0x138,(rng.getrandbits(64),))],destroy_element=True))
    return cases


def compare(args,base,spec):
    row=controls.compare(args,base,spec,functions=FUNCTIONS,prepare_case=prepare)
    pages,_,_=controls.model_case(args,base,spec,prepare_case=prepare)
    def u(address,size=8): return int.from_bytes(_read_span(pages,address,size),'little')
    initial,_=prepare(args.library,base,spec)
    raw=bytearray(b'\x35'*spec.get('raw_vector',(0,0))[0])
    frames=spec.get('frames',(0,0))[0]; keys={n[0]:n[4] for n in spec.get('tree',[])}
    element_end=u(AST+0xE0); record=element_end-184
    type_value=int.from_bytes(_read_span(initial,record+0x18,8),'little') if spec.get('element_vector',(0,0))[0] else None
    created=[]
    for slot,argv in spec.get('callbacks',[]):
        if slot==0x108: type_value=int.from_bytes(_read_span(initial,base+0x6E210,8),'little')
        elif slot==0x120: type_value=argv[1]
        elif slot==0x130: created.append((type_value,len(raw))); frames=1
        elif slot in (0x110,0x148): frames=1
        elif slot in (0xF0,0x168): raw.extend((0 if slot==0xF0 else argv[0]&0xFFFFFFFF).to_bytes(4,'little'))
        elif slot in (0x138,0x118,0x150):
            for position in keys.pop(frames-1,[]):
                length=len(raw)
                if position+4>length: raw.extend(bytes(position+4-length))
                raw[position:position+4]=length.to_bytes(4,'little')
            frames-=1
    if type_value is not None: assert u(record+0x18)==type_value
    if spec.get('element_vector',(0,0))[0] or any(slot==0x108 for slot,_ in spec.get('callbacks',[])):
        begin,end,cap=(u(record+offset) for offset in (0,8,16))
        old_count=0 if spec.get('owned_mode','null')=='null' else spec.get('nested_count',2)
        expected_count=0 if spec.get('destroy_element') and begin else old_count+len(created)
        assert (end-begin)//144==expected_count and begin<=end<=cap
        for index,(value,start) in enumerate(created,old_count):
            node=begin+index*144
            assert u(node)==base+0x3724F0 and u(node+8,4)==0
            for offset in (0x10,0x50,0x78): assert _read_span(pages,node+offset,24)==bytes(24)
            result=u(node+0x28)
            assert result and u(result)==value and u(node+0x30)==result+(0 if spec.get('destroy_element') else 8)
            assert u(node+0x38)==result+8
            assert u(node+0x40)==u(node+0x48,4)==u(node+0x70,4)==0
            assert u(node+0x68)==start
        if any(slot==0x128 for slot,_ in spec.get('callbacks',[])) and not created:
            requested=max(argv[1]&0xFFFFFFFF for slot,argv in spec['callbacks'] if slot==0x128)
            initial_cap=0 if spec.get('owned_mode','null')=='null' else spec.get('nested_capacity',old_count+1)
            assert (cap-begin)//144==max(requested,initial_cap)
    pointer=u(AST+0x108)
    assert u(AST+0x110)-pointer==len(raw) and _read_span(pages,pointer,len(raw))==raw
    frame=u(CB+0x30)
    assert u(CB+0x38)-frame==(0 if spec.get('cleanup') and frame else frames*16)
    if created:
        assert _read_span(pages,frame,8)==_read_span(initial,base+0x6E188,8)
        assert _read_span(pages,frame+8,8)==bytes([255])*8
    if not spec.get('cleanup'): assert u(CB+0x58)==len(keys)
    row['independent_nested_type_frame_and_raw_expectation_match']=True
    return row


def negatives(args):
    base=0x122C0000; rows=[]; cases=[]
    standard=dict(label='guard',element_vector=(1,1),owned_mode='rich',nested_count=2,nested_capacity=2)
    def u(p,a): return int.from_bytes(_read_span(p,a,8),'little')
    def record(p): return u(p,AST+0xD8)
    def nested(p): return u(p,record(p))
    def add(label,changes=None,setup=None,spec=None): cases.append((label,changes or {},setup,spec or standard))
    for slot,argv in ((0x120,(0,1)),(0x128,(0,4)),(0x130,(0,)),(0x138,(0,))):
        add(f'slot_{slot:x}_binding',dict(slot_offset=slot,arguments=argv),setup=lambda p,s=slot:put(p,base+0x372370+s,0))
        if slot!=0x138: add(f'{slot:x}_no_active_element',dict(slot_offset=slot,arguments=argv),spec=dict(label='guard'))
    add('GOT',setup=lambda p:put(p,base+0x375090,0))
    add('partial_nested',setup=lambda p:put(p,record(p)+8,nested(p)+1))
    add('nested_alias_type',setup=lambda p:vector(p,nested(p)+0x10,u(p,record(p)+0x50),1,3,8))
    add('unknown_nested_type',setup=lambda p:put(p,nested(p),base+0x372518))
    add('attached',setup=lambda p:put(p,CB+8,INPUT))
    add('create_arity',dict(arguments=(0,1)))
    add('type_value_overflow',dict(slot_offset=0x120,arguments=(0,1<<64)))
    add('reserve_negative',dict(slot_offset=0x128,arguments=(0,-1)))
    add('reserve_node_budget',dict(slot_offset=0x128,arguments=(0,4097)))
    add('create_total_node_budget',dict(max_nodes=3),spec=dict(label='guard',element_vector=(1,1),owned_mode='rich',
        nested_count=2,nested_capacity=2,child_count=0))
    add('create_growth_capacity_budget',dict(max_nodes=5),spec=dict(label='guard',element_vector=(1,1),owned_mode='rich',
        nested_count=3,nested_capacity=3,child_count=0))
    add('create_byte_budget',dict(max_vector_bytes=575),spec=dict(label='guard',element_vector=(1,1),owned_mode='rich',
        nested_count=2,nested_capacity=2,child_count=0))
    add('begin_frame_partial',setup=lambda p:vector(p,CB+0x30,HEAP,1,17))
    add('begin_frame_capacity_budget',dict(max_nodes=3),spec=dict(label='guard',element_vector=(1,1),frames=(2,4)))
    add('begin_image_constant_missing',setup=lambda p:p.pop((base+0x6E188)>>12))
    add('end_no_frame',dict(slot_offset=0x138,arguments=(0,)),spec=dict(label='guard'))
    add('end_late_offset',dict(slot_offset=0x138,arguments=(0,),max_vector_bytes=32),
        spec=dict(label='guard',frames=(1,1),tree=[(0,None,None,1,[0,64])]))
    add('missing_allocator',dict(allocate=None))
    add('reserve_missing_allocator',dict(slot_offset=0x128,arguments=(0,4),allocate=None))
    add('begin_GOT_missing',setup=lambda p:p.pop((base+0x375090)>>12))
    for label,changes,setup,spec in cases:
        pages,_=prepare(args.library,base,spec)
        if setup: setup(pages)
        before={k:bytes(v) for k,v in pages.items()}; offset=0
        def allocate(size):
            nonlocal offset
            result=HEAP+offset; offset+=(size+15)&~15; return result
        params=dict(callback_address=CB,image_base=base,slot_offset=0x130,arguments=(0,),allocate=allocate)
        params.update(changes)
        try: alternative.run_reader_ast_callback(pages,**params)
        except (RefillUnsupported,ValueError): pass
        else: raise AssertionError('nested guard accepted: '+label)
        assert before=={k:bytes(v) for k,v in pages.items()},label
        rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_invalid_memory_path_compared=False))
    for mode,spec,slot,argv,total in (
        ('create_growth',standard,0x130,(0,),4),
        ('create_spare',dict(label='guard',element_vector=(1,1),owned_mode='rich',nested_count=1,nested_capacity=3),0x130,(0,),3),
        ('reserve',standard,0x128,(0,4),1),
        ('end',dict(label='guard',frames=(1,1),tree=[(0,None,None,1,[0,32])]),0x138,(0,),2)):
        for fail_at in range(1,total+1):
            for target in ('unmapped','unaligned','partial','callback','output','element','nested','child','retained','image','duplicate'):
                if target=='duplicate' and fail_at==1: continue
                pages,_=prepare(args.library,base,spec); partial=oracle.GUEST+0xAFF8
                if target=='partial':
                    if mode=='create_growth' and fail_at==3 or mode=='reserve': pages.pop((oracle.GUEST+0xB000)>>12,None)
                    else: pages[partial>>12]=pages[partial>>12][:4092]
                before={k:bytes(v) for k,v in pages.items()}; planned=[]; offset=0
                def allocate(size):
                    nonlocal offset
                    pointer=HEAP+offset; offset+=(size+15)&~15
                    if len(planned)+1==fail_at:
                        element_ptr=record(pages) if spec.get('element_vector') else 0
                        pointer={'unmapped':0x90000000,'unaligned':HEAP+1,'partial':partial,'callback':CB,'output':AST,
                            'element':element_ptr,'nested':nested(pages) if element_ptr else u(pages,CB+0x50),
                            'child':u(pages,element_ptr+0xA0) if element_ptr else u(pages,CB+0x30),
                            'retained':INPUT,'image':base+0x6E188,'duplicate':planned[0] if planned else 0}[target]
                    planned.append(pointer); return pointer
                try: alternative.run_reader_ast_callback(pages,callback_address=CB,image_base=base,
                    slot_offset=slot,arguments=argv,allocate=allocate,reserved_regions=((INPUT,INPUT+2048),))
                except (RefillUnsupported,ValueError): pass
                else: raise AssertionError(('nested allocation guard accepted',mode,fail_at,target))
                assert len(planned)==fail_at and before=={k:bytes(v) for k,v in pages.items()},(mode,fail_at,target)
                rows.append(dict(label=f'{mode}_allocation_{fail_at}_{target}',rejected=True,all_pages_unchanged=True,
                    allocation_plans_before_rejection=len(planned),native_invalid_memory_path_compared=False))
    return rows


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library',required=True,type=Path); parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    rows=[]; specs=fixtures(); rejected=negatives(args)
    assert len({s['label'] for s in specs})==len(specs)
    for base in (0x122C0000,0x775C205000):
        for index,spec in enumerate(specs,1):
            rows.append(compare(args,base,spec))
            if index%16==0 or index==len(specs): print('B nested:',hex(base),index,'/',len(specs),'passed',flush=True)
    evidence=dict(schema='vm9-alternative-ast-element-nested-fresh-v1',evidence_date='2026-10-09',
        evidence_timezone='Asia/Shanghai',sample_sha256=oracle.LIBRARY_SHA256,generated_fixture_seed=SEED,
        native_Python_AST_element_nested_controls=len(rows),rollback_negative_controls=len(rejected),
        pre_change_behavior_RED_controls=4,recovered_callback_slots_hex=['0x120','0x128','0x130','0x138'],
        actual_native_vtable_offset_hex='0x372370',result_type_offset_hex='0x31dee0',
        nested_reserve_offset_hex='0x31def4',nested_begin_offset_hex='0x31df1c',nested_end_offset_hex='0x31e18c',
        nested_reserve_helper_offset_hex='0x320a78',nested_append_growth_offset_hex='0x31f690',
        nested_destructor_offset_hex='0x2cc470',nested_record_stride=144,frame_stride=16,tree_payload_stride=4,
        result_type_width=8,native_parser_calls_nested_begin_end=False,nested_begin_end_bounded_argument_count=1,
        all_fixtures_synthetic=True,native_input_snapshot_used=False,private_payloads_published=False,
        element_nested_callbacks_implemented=True,parser_AST_composition_implemented=False,attached_parser_implemented=False,
        complete_AST_callbacks_implemented=False,complete_python_reader_implemented=False,independent_Python_factory_implemented=False,
        complete_python_bootstrap_controls=0,complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False,cases=rows,negative_cases=rejected)
    args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    print('B nested:',len(rows),'native/Python +',len(rejected),'rollback checks passed',flush=True)


if __name__=='__main__': main()
