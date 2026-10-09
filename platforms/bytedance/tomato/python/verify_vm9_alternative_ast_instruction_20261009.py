"""Fresh B instruction predicate/end and typed raw-constant callback controls.

Original vtable functions execute naturally. Fixtures and status expectations
are synthetic input; independent byte assertions never read native snapshots.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import random

import verify_vm9_alternative_ast_data_20261009 as controls
import verify_vm9_alternative_ast_data_expression_20261009 as expression
import verify_vm9_alternative_ast_element_nested_20261009 as nested
import verify_vm9_signer_objects as oracle
import vm9_alternative_startup as alternative
from vm9_allocator import RefillUnsupported, _read_span

CB,AST,INPUT,HEAP=nested.CB,nested.AST,nested.INPUT,nested.HEAP
put,vector=nested.put,nested.vector
FUNCTIONS={**nested.FUNCTIONS,0xC0:0x31DA9C,0xC8:0x31DAB4,0xD0:0x31DB04,
    0xD8:0x31DB28,0xE0:0x31DB4C,0xE8:0x31DB70}
TYPES={0xD0:(4,4),0xD8:(5,8),0xE0:(2,4),0xE8:(3,8)}
SEED=0x32140C


def prepare(library,base,spec):
    pages,sizes=nested.prepare(library,base,spec)
    if 'active_pointer' in spec: put(pages,CB+0x28,spec['active_pointer'])
    return pages,sizes


def minimal_specs():
    return [dict(label='predicate_missing_active',frames=(2,3),callbacks=[(0xC0,(0xFFFFFFFF,))],callback_statuses=[1]),
        dict(label='predicate_active',active_pointer=1,frames=(2,3),callbacks=[(0xC0,(0xFFFFFFFF,))]),
        dict(label='instruction_end_keeps_last_frame',frames=(1,2),raw_vector=(12,16),
            tree=[(0,None,None,1,[0,4,8])],callbacks=[(0xC8,())]),
        dict(label='instruction_end_erases_inner_frame',frames=(2,3),raw_vector=(12,16),
            tree=[(1,None,None,1,[0,4,8])],callbacks=[(0xC8,())]),
        *[dict(label=f'typed_{slot:x}',raw_vector=(3,3),callbacks=[(slot,(0xFFEEDDCC12345678,))]) for slot in TYPES]]


def fixtures():
    cases=minimal_specs()
    for active in (0,1,AST,0xFFFFFFFFFFFFFFFF):
        for count,cap in ((0,0),(0,2),(1,2),(3,3)):
            cases.append(dict(label=f'predicate_{active}_{count}_{cap}',active_pointer=active,frames=(count,cap),
                callbacks=[(0xC0,(0x100000001,))],callback_statuses=[int(not active or not count)]))
    for slot in TYPES:
        for size,cap in ((0,0),(0,4),(1,5),(3,3),(7,9),(12,24)):
            for bits in (0,0xFFFFFFFF12345678,0x8000000000000000,0x7FF800007FC00001,0xFFFFFFFFFFFFFFFF):
                cases.append(dict(label=f'constant_{slot:x}_{size}_{cap}_{bits}',raw_vector=(size,cap),callbacks=[(slot,(bits,))]))
    cases += [dict(label='all_constants_in_one_buffer',raw_vector=(3,9),
            callbacks=[(0xD0,(0x7FC00001,)),(0xD8,(0x7FF8000000000001,)),(0xE0,(0xFFFFFFFF80000000,)),
                (0xE8,(0xFFFFFFFFFFFFFFEF,)),(0xF0,()),(0x168,(17,))],cleanup=True),
        dict(label='data_begin_constants_end_then_expression_end',data_vector=(1,1),raw_vector=(3,9),
            tree=[(0,None,None,1,[1,24])],callbacks=[(0x148,(0,)),(0xC0,(2,)),(0xE0,(0xFFFFFFFF,)),
                (0xD8,(0x8000000000000000,)),(0xC8,()),(0x150,(0,))],destroy_data=True,cleanup=True),
        dict(label='nested_begin_constants_end_then_nested_end',element_vector=(1,1),
            callbacks=[(0x120,(0,0xFFFFFFFFFFFFFFF0)),(0x130,(0,)),(0xC0,(4,)),(0xD0,(0x7FC00001,)),
                (0xE8,(0xFFFFFFFFFFFFFFEF,)),(0xC8,()),(0x138,(0,))],destroy_element=True,cleanup=True),
        dict(label='inner_then_outer_instruction_end',active_pointer=1,frames=(3,4),raw_vector=(7,9),
            tree=[(2,1,None,1,[1,24]),(1,None,None,0,[0])],
            callbacks=[(0xE0,(17,)),(0xC8,()),(0xD8,(0x1122334455667788,)),(0xC8,()),(0xC8,())],cleanup=True)]
    for original in expression.fixtures():
        if original['label'].startswith('erase_shape'):
            spec=dict(original); spec['label']='instruction_'+spec['label']
            spec['callbacks']=[(0xC8,())]; cases.append(spec)
        elif original['label']=='descending_erase_all_keys':
            spec=dict(original); spec['label']='instruction_descending_erase_to_outer'
            spec['callbacks']=[(0xC8,())]*7; cases.append(spec)
    rng=random.Random(SEED)
    for i in range(8):
        size=rng.randrange(16); cap=size+rng.randrange(8)
        cases.append(dict(label=f'generated_constants_{i}',raw_vector=(size,cap),
            callbacks=[(rng.choice(tuple(TYPES)),(rng.getrandbits(64),)) for _ in range(6)]))
    return cases


def compare(args,base,spec):
    row=controls.compare(args,base,spec,functions=FUNCTIONS,prepare_case=prepare)
    pages,_,statuses=controls.model_case(args,base,spec,prepare_case=prepare)
    initial,_=prepare(args.library,base,spec)
    def u(address,size=8): return int.from_bytes(_read_span(pages,address,size),'little')
    raw=bytearray(b'\x35'*spec.get('raw_vector',(0,0))[0]); frames=spec.get('frames',(0,0))[0]
    keys={n[0]:n[4] for n in spec.get('tree',[])}; active=spec.get('active_pointer',0); expected_statuses=[]
    for slot,argv in spec.get('callbacks',[]):
        status=0
        if slot in (0x110,0x130,0x148): frames=1; active=1
        elif slot==0xC0: status=int(not active or not frames)
        elif slot in TYPES:
            tag,width=TYPES[slot]
            raw.extend(tag.to_bytes(4,'little')); raw.extend((argv[0]&((1<<(width*8))-1)).to_bytes(width,'little'))
        elif slot in (0xF0,0x168): raw.extend((0 if slot==0xF0 else argv[0]&0xFFFFFFFF).to_bytes(4,'little'))
        elif slot in (0xC8,0x118,0x138,0x150):
            if slot!=0xC8 or frames!=1:
                for position in keys.pop(frames-1,[]):
                    length=len(raw)
                    if position+4>length: raw.extend(bytes(position+4-length))
                    raw[position:position+4]=length.to_bytes(4,'little')
                frames-=1
        expected_statuses.append(status)
    assert statuses==expected_statuses
    pointer=u(AST+0x108)
    assert u(AST+0x110)-pointer==len(raw) and _read_span(pages,pointer,len(raw))==raw
    frame=u(CB+0x30)
    assert u(CB+0x38)-frame==(0 if spec.get('cleanup') and frame else frames*16)
    if not spec.get('cleanup'): assert u(CB+0x58)==len(keys)
    if all(slot==0xC0 or slot==0xC8 and spec.get('frames',(0,0))[0]==1 for slot,_ in spec['callbacks']) and not spec.get('cleanup'):
        assert {k:bytes(v) for k,v in pages.items()}=={k:bytes(v) for k,v in initial.items()}
    row.update(independent_status_frame_and_typed_raw_expectation_match=True,
        callback_statuses=statuses,native_zero_and_one_statuses_compared=True)
    return row


def negatives(args):
    base=0x122C0000; rows=[]; cases=[]
    def u(p,a): return int.from_bytes(_read_span(p,a,8),'little')
    standard=dict(label='guard',frames=(2,3),active_pointer=1,raw_vector=(7,9),tree=[(1,None,None,1,[1,32])])
    def add(label,changes=None,setup=None,spec=None): cases.append((label,changes or {},setup,spec or standard))
    for slot in (0xC0,0xC8,*TYPES):
        add(f'slot_{slot:x}_binding',dict(slot_offset=slot,arguments=() if slot==0xC8 else (1,)),
            setup=lambda p,s=slot:put(p,base+0x372370+s,0))
    add('attached_callback',setup=lambda p:put(p,CB+8,INPUT))
    add('constant_arity',dict(arguments=()))
    add('constant_overflow',dict(arguments=(1<<64,)))
    add('end_arity',dict(slot_offset=0xC8,arguments=(0,)))
    add('end_empty_frame',dict(slot_offset=0xC8,arguments=()),spec=dict(label='guard'))
    add('predicate_partial_frame',dict(slot_offset=0xC0,arguments=(1,)),setup=lambda p:put(p,CB+0x38,u(p,CB+0x30)+1))
    add('end_partial_frame',dict(slot_offset=0xC8,arguments=()),setup=lambda p:put(p,CB+0x40,u(p,CB+0x40)+1))
    for slot in (0xC0,0xC8):
        add(f'{slot:x}_frame_budget',dict(slot_offset=slot,arguments=() if slot==0xC8 else (1,),max_nodes=1),
            spec=dict(label='guard',frames=(2,3)))
    for slot in TYPES:
        width=TYPES[slot][1]
        add(f'{slot:x}_late_byte_budget',dict(slot_offset=slot,max_vector_bytes=width+3),spec=dict(label='guard'))
        add(f'{slot:x}_missing_allocator',dict(slot_offset=slot,allocate=None),spec=dict(label='guard'))
    add('late_growth_capacity_budget',dict(max_vector_bytes=31),spec=dict(label='guard',raw_vector=(7,9)))
    add('end_late_offset',dict(slot_offset=0xC8,arguments=(),max_vector_bytes=32),
        spec=dict(label='guard',frames=(2,3),tree=[(1,None,None,1,[0,64])]))
    add('end_bad_tree_count',dict(slot_offset=0xC8,arguments=()),setup=lambda p:put(p,CB+0x58,2))
    add('end_bad_tree_root_color',dict(slot_offset=0xC8,arguments=()),setup=lambda p:put(p,u(p,CB+0x50)+0x18,0,1))
    for label,changes,setup,spec in cases:
        pages,_=prepare(args.library,base,spec)
        if setup: setup(pages)
        before={k:bytes(v) for k,v in pages.items()}; offset=0
        def allocate(size):
            nonlocal offset
            pointer=HEAP+offset; offset+=(size+15)&~15; return pointer
        params=dict(callback_address=CB,image_base=base,slot_offset=0xD8,arguments=(0x1122334455667788,),allocate=allocate)
        params.update(changes)
        try: alternative.run_reader_ast_callback(pages,**params)
        except (RefillUnsupported,ValueError): pass
        else: raise AssertionError('instruction guard accepted: '+label)
        assert before=={k:bytes(v) for k,v in pages.items()},label
        rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_invalid_memory_path_compared=False))
    for slot in (*TYPES,0xC8):
        spec=dict(label='guard',frames=(2,3),tree=[(1,None,None,1,[0,32])]) if slot==0xC8 else dict(label='guard',frames=(1,2))
        for fail_at in (1,2):
            for target in ('unmapped','unaligned','partial','callback','output','frame','tree','retained','image','duplicate'):
                if target=='duplicate' and fail_at==1: continue
                pages,_=prepare(args.library,base,spec); partial=oracle.GUEST+0xAFF8
                if target=='partial': pages[partial>>12]=pages[partial>>12][:4092]
                before={k:bytes(v) for k,v in pages.items()}; planned=[]; offset=0
                def allocate(size):
                    nonlocal offset
                    pointer=HEAP+offset; offset+=(size+15)&~15
                    if len(planned)+1==fail_at:
                        pointer={'unmapped':0x90000000,'unaligned':HEAP+1,'partial':partial,'callback':CB,
                            'output':AST,'frame':u(pages,CB+0x30),'tree':u(pages,CB+0x50) if slot==0xC8 else u(pages,CB+0x30),
                            'retained':INPUT,'image':base+0x6E188,'duplicate':planned[0] if planned else 0}[target]
                    planned.append(pointer); return pointer
                try: alternative.run_reader_ast_callback(pages,callback_address=CB,image_base=base,
                    slot_offset=slot,arguments=() if slot==0xC8 else (0x8877665544332211,),allocate=allocate,
                    reserved_regions=((INPUT,INPUT+2048),))
                except (RefillUnsupported,ValueError): pass
                else: raise AssertionError(('instruction allocation guard accepted',slot,fail_at,target))
                assert len(planned)==fail_at and before=={k:bytes(v) for k,v in pages.items()},(slot,fail_at,target)
                rows.append(dict(label=f'{slot:x}_allocation_{fail_at}_{target}',rejected=True,all_pages_unchanged=True,
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
            if index%24==0 or index==len(specs): print('B instruction:',hex(base),index,'/',len(specs),'passed',flush=True)
    evidence=dict(schema='vm9-alternative-ast-instruction-fresh-v1',evidence_date='2026-10-09',
        evidence_timezone='Asia/Shanghai',sample_sha256=oracle.LIBRARY_SHA256,generated_fixture_seed=SEED,
        native_Python_AST_instruction_controls=len(rows),rollback_negative_controls=len(rejected),
        pre_change_behavior_RED_controls=8,recovered_callback_slots_hex=['0xc0','0xc8','0xd0','0xd8','0xe0','0xe8'],
        actual_native_vtable_offset_hex='0x372370',predicate_offset_hex='0x31da9c',instruction_end_offset_hex='0x31dab4',
        f32_offset_hex='0x31db04',f64_offset_hex='0x31db28',i32_offset_hex='0x31db4c',i64_offset_hex='0x31db70',
        typed_u32_helper_offset_hex='0x32140c',typed_u64_helper_offset_hex='0x321490',
        f32_tag=4,f64_tag=5,i32_tag=2,i64_tag=3,tag_width=4,frame_stride=16,tree_payload_stride=4,
        status_one_controls=sum(1 in r['callback_statuses'] for r in rows),
        all_fixtures_synthetic=True,native_input_snapshot_used=False,private_payloads_published=False,
        instruction_callbacks_implemented=True,parser_AST_composition_implemented=False,attached_parser_implemented=False,
        complete_AST_callbacks_implemented=False,complete_python_reader_implemented=False,independent_Python_factory_implemented=False,
        complete_python_bootstrap_controls=0,complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False,cases=rows,negative_cases=rejected)
    args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    print('B instruction:',len(rows),'native/Python +',len(rejected),'rollback checks passed',flush=True)


if __name__=='__main__': main()
