"""Fresh B local-group and function-end callbacks on owned 144-byte layouts.

Fixtures use existing data/element/nested ownership, never a native snapshot.
The code-begin callback and function output container remain unsupported.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import random

import verify_vm9_alternative_ast_instruction_20261009 as instruction
import verify_vm9_alternative_ast_data_20261009 as controls
import verify_vm9_signer_objects as oracle
import vm9_alternative_startup as alternative
from vm9_allocator import RefillUnsupported, _read_span, _write_span

CB, AST, INPUT, HEAP = instruction.CB, instruction.AST, instruction.INPUT, instruction.HEAP
put, vector = instruction.put, instruction.vector
FUNCTIONS = {**instruction.FUNCTIONS, 0xB0:0x31D974, 0xB8:0x31D984, 0xF8:0x31DBB4}
SEED = 0x31D984


def active_record(pages, spec):
    u = lambda address: int.from_bytes(_read_span(pages,address,8),'little')
    kind = spec.get('active_kind','data')
    if kind == 'data': return u(AST+0xF0)+0x20
    element = u(AST+0xD8)
    if kind == 'element': return element+0x28
    return u(element)+spec.get('active_index',0)*144


def prepare(library, base, spec):
    initial = dict(spec)
    kind = spec.get('active_kind','data')
    initial.setdefault('owned_mode','rich')
    initial['data_vector' if kind == 'data' else 'element_vector'] = (1,1)
    if kind == 'nested': initial.update(nested_count=2,nested_capacity=3)
    pages, sizes = instruction.prepare(library,base,initial)
    target = active_record(pages,spec)
    header = target+0x50
    old = int.from_bytes(_read_span(pages,header,8),'little')
    if old: sizes.pop(old)
    pointer = max([controls.OLD]+[p+((max(n,1)+15)&~15) for p,n in sizes.items()])
    count, cap = spec.get('locals',(0,0))
    if cap or spec.get('nonnull_empty'):
        assert pointer+max(cap*16,1) < INPUT
        sizes[pointer] = cap*16
        _write_span(pages,pointer,b'\xa3'*max(cap*16,1))
        vector(pages,header,pointer,count,cap,16)
    else: vector(pages,header)
    put(pages,CB+0x28,target)
    put(pages,CB+0x78,spec.get('declared_groups',19),4)
    put(pages,CB+0x7C,spec.get('cumulative',0),4)
    return pages,sizes


def minimal_specs():
    return [dict(label='local_group_spare',locals=(1,3),cumulative=7,
                 callbacks=[(0xB8,(99,2,0xFFFFFFFFFFFFFFEF))]),
            dict(label='local_group_growth',active_kind='nested',locals=(1,1),cumulative=0xFFFFFFFF,
                 callbacks=[(0xB8,(0xFFFFFFFFFFFFFFFF,0x100000002,0x8000000012345678))]),
            dict(label='function_end',active_kind='element',frames=(2,3),
                 callbacks=[(0xF8,(0xFFFFFFFFFFFFFFFF,0xFFFFFFFF12345678))])]


def fixtures():
    cases = minimal_specs()
    for kind in ('data','element','nested'):
        for size, cap in ((0,0),(0,3),(1,1),(2,3)):
            for count in (0,1,0xFFFFFFFF,0x100000002):
                for bits in (0xFFFFFFFFFFFFFFFF,0x8000000012345678):
                    cases.append(dict(label=f'local_{kind}_{size}_{cap}_{count}_{bits}',active_kind=kind,
                        locals=(size,cap),cumulative=0xFFFFFFFE,callbacks=[(0xB8,(0xFFFFFFFFFFFFFFFF,count,bits))],
                        **({'destroy_data':True} if kind=='data' else {'destroy_element':True})))
        for length in (0,1,0xFFFFFFFF,0x100000001,0xFFFFFFFF12345678):
            cases.append(dict(label=f'end_{kind}_{length}',active_kind=kind,locals=(1,2),frames=(2,3),
                tree=[(1,None,None,1,[0,4])],raw_vector=(9,13),callbacks=[(0xF8,(99,length))]))
        cases.append(dict(label=f'groups_reset_append_end_cleanup_{kind}',active_kind=kind,locals=(1,1),
            callbacks=[(0xB0,(0x100000003,)),(0xB8,(9,0,0xFFFFFFFFFFFFFFF0)),
                (0xB8,(8,0xFFFFFFFF,0xFFFFFFFFFFFFFFEF)),(0xB8,(7,2,0xFFFFFFFFFFFFFFFB)),
                (0xF8,(6,0xFFFFFFFF11223344))],cleanup=True,
            **({'destroy_data':True} if kind=='data' else {'destroy_element':True})))
    cases += [dict(label='second_nested_active',active_kind='nested',active_index=1,locals=(2,2),
                  callbacks=[(0xB8,(0,7,0xFFFFFFFFFFFFFFEB)),(0xF8,(1,99))],destroy_element=True),
              dict(label='nonnull_zero_capacity',nonnull_empty=True,callbacks=[(0xB8,(0,0,1))],destroy_data=True),
              dict(label='local_constants_then_end_predicate',locals=(1,1),frames=(1,2),raw_vector=(3,9),
                  callbacks=[(0xB8,(0,3,0xFFFFFFFFFFFFFFFF)),(0xC0,(9,)),(0xE0,(17,)),
                      (0xD8,(0x7FF8000000000001,)),(0xF8,(0,13)),(0xC0,(9,))],
                  callback_statuses=[0,0,0,0,0,1],destroy_data=True,cleanup=True)]
    rng=random.Random(SEED)
    for i in range(6):
        cap=rng.randrange(1,4); size=rng.randrange(cap+1)
        cases.append(dict(label=f'generated_local_groups_{i}',active_kind=rng.choice(('data','element','nested')),
            locals=(size,cap),cumulative=rng.getrandbits(32),
            callbacks=[(0xB8,(rng.getrandbits(64),rng.getrandbits(64),rng.getrandbits(64))) for _ in range(5)]
                +[(0xF8,(rng.getrandbits(64),rng.getrandbits(64)))]))
    return cases


def compare(args, base, spec):
    row=controls.compare(args,base,spec,functions=FUNCTIONS,prepare_case=prepare)
    # Inspect callback results before optional destruction using an independent
    # Python execution. Expected bytes come only from synthetic inputs.
    callbacks={k:v for k,v in spec.items() if k not in ('destroy_data','destroy_element','cleanup')}
    pages,_,statuses=controls.model_case(args,base,callbacks,prepare_case=prepare)
    initial,_=prepare(args.library,base,callbacks)
    target=active_record(initial,callbacks)
    u=lambda address,size=8:int.from_bytes(_read_span(pages,address,size),'little')
    raw=bytearray(b'\xa3'*(spec.get('locals',(0,0))[0]*16))
    cumulative=spec.get('cumulative',0); declared=spec.get('declared_groups',19)
    active=target; length=int.from_bytes(_read_span(initial,target+0x70,4),'little')
    expected=[]
    for slot,argv in spec['callbacks']:
        status=0
        if slot==0xB0: declared=argv[0]&0xFFFFFFFF; cumulative=0
        elif slot==0xB8:
            count=argv[1]&0xFFFFFFFF; cumulative=(cumulative+count)&0xFFFFFFFF
            raw.extend(argv[2].to_bytes(8,'little')+count.to_bytes(4,'little')+cumulative.to_bytes(4,'little'))
        elif slot==0xF8: active=0; length=argv[1]&0xFFFFFFFF
        elif slot==0xC0: status=int(not active or not spec.get('frames',(0,0))[0])
        expected.append(status)
    begin=u(target+0x50)
    assert u(target+0x58)-begin==len(raw) and _read_span(pages,begin,len(raw))==raw
    assert u(CB+0x78,4)==declared and u(CB+0x7C,4)==cumulative
    assert u(CB+0x28)==active and u(target+0x70,4)==length and statuses==expected
    assert _read_span(pages,CB+0x30,0x48)==_read_span(initial,CB+0x30,0x48)
    if all(slot==0xF8 for slot,_ in spec['callbacks']):
        put(initial,CB+0x28,0); put(initial,target+0x70,length,4)
        assert {k:bytes(v) for k,v in pages.items()}=={k:bytes(v) for k,v in initial.items()}
    row.update(independent_local_cumulative_end_and_frame_expectation_match=True,
               callback_statuses=statuses,active_layout=spec.get('active_kind','data'))
    return row


def negatives(args):
    base=0x122C0000; rows=[]; cases=[]
    standard=dict(label='guard',locals=(1,1),frames=(2,3))
    def add(label,changes=None,setup=None,spec=None): cases.append((label,changes or {},setup,spec or standard))
    def u(p,a): return int.from_bytes(_read_span(p,a,8),'little')
    for slot,argv in ((0xB8,(0,1,1)),(0xF8,(0,1))):
        add(f'{slot:x}_binding',dict(slot_offset=slot,arguments=argv),
            lambda p,s=slot:put(p,base+0x372370+s,0))
        for label,pointer in (('null',0),('unmapped',0x90000000),('callback',CB),('output',AST),('unaligned',None)):
            add(f'{slot:x}_active_{label}',dict(slot_offset=slot,arguments=argv),
                lambda p,v=pointer:put(p,CB+0x28,v if v is not None else active_record(p,standard)+1))
        add(f'{slot:x}_active_nested_spare',dict(slot_offset=slot,arguments=argv),
            lambda p:put(p,CB+0x28,u(p,u(p,AST+0xD8)+8)),spec=dict(label='guard',active_kind='nested'))
    add('attached',setup=lambda p:put(p,CB+8,INPUT))
    add('local_arity',dict(arguments=(0,1)))
    add('local_register_overflow',dict(arguments=(0,1,1<<64)))
    add('end_arity',dict(slot_offset=0xF8,arguments=(0,)))
    add('local_partial',setup=lambda p:put(p,active_record(p,standard)+0x58,u(p,active_record(p,standard)+0x50)+1))
    add('local_capacity_budget',dict(max_nodes=2),spec=dict(label='guard',locals=(1,3),owned_mode='null'))
    add('local_doubled_capacity_budget',dict(max_nodes=3),spec=dict(label='guard',locals=(2,2),owned_mode='null'))
    add('local_growth_budget',dict(max_vector_bytes=31),spec=dict(label='guard',locals=(1,1),owned_mode='null'))
    add('missing_allocator',dict(allocate=None))
    add('inactive_after_end',dict(sequence=True))
    add('late_end_write',dict(slot_offset=0xF8,arguments=(0,1),late_failure=True))
    for size,cap in ((1,1),(1,3)):
        add(f'late_local_publication_{size}_{cap}',dict(late_local_publish=True),spec=dict(label='guard',locals=(size,cap)))
    for label,changes,setup,spec in cases:
        pages,_=prepare(args.library,base,spec)
        if setup: setup(pages)
        before={k:bytes(v) for k,v in pages.items()}
        params=dict(callback_address=CB,image_base=base,slot_offset=0xB8,arguments=(0,1,1),allocate=lambda n:HEAP)
        sequence=changes.pop('sequence',False); late=changes.pop('late_failure',False)
        late_local=changes.pop('late_local_publish',False)
        params.update(changes)
        if sequence:
            alternative.run_reader_ast_callback(pages,callback_address=CB,image_base=base,slot_offset=0xF8,arguments=(0,1))
            before={k:bytes(v) for k,v in pages.items()}
        original=alternative._write_span
        if late or late_local:
            target=active_record(pages,spec)+(0x70 if late else 0x50 if spec['locals'][0]==spec['locals'][1] else 0x58)
            def fail(p,address,data):
                if address==target: raise RefillUnsupported('injected late local/end write')
                original(p,address,data)
            alternative._write_span=fail
        try:
            try: alternative.run_reader_ast_callback(pages,**params)
            except (RefillUnsupported,ValueError): pass
            else: raise AssertionError('local guard accepted: '+label)
        finally: alternative._write_span=original
        assert before=={k:bytes(v) for k,v in pages.items()},label
        rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_invalid_memory_path_compared=False))
    for target in ('unmapped','unaligned','partial','callback','output','record','frame','retained','image','old'):
        pages,_=prepare(args.library,base,standard); partial=oracle.GUEST+0xAFF8
        if target=='partial': pages[partial>>12]=pages[partial>>12][:4092]
        before={k:bytes(v) for k,v in pages.items()}; planned=[]
        def allocate(size):
            pointer={'unmapped':0x90000000,'unaligned':HEAP+1,'partial':partial,'callback':CB,'output':AST,
                'record':active_record(pages,standard),'frame':u(pages,CB+0x30),'retained':INPUT,
                'image':base+0x6E188,'old':u(pages,active_record(pages,standard)+0x50)}[target]
            planned.append((size,pointer)); return pointer
        try: alternative.run_reader_ast_callback(pages,callback_address=CB,image_base=base,slot_offset=0xB8,
            arguments=(0,1,1),allocate=allocate,reserved_regions=((INPUT,INPUT+2048),))
        except (RefillUnsupported,ValueError): pass
        else: raise AssertionError('local allocation guard accepted: '+target)
        assert len(planned)==1 and before=={k:bytes(v) for k,v in pages.items()},target
        rows.append(dict(label='allocation_'+target,rejected=True,all_pages_unchanged=True,
                         allocation_plans_before_rejection=1,native_invalid_memory_path_compared=False))
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
            if index%24==0 or index==len(specs): print('B locals:',hex(base),index,'/',len(specs),'passed',flush=True)
    evidence=dict(schema='vm9-alternative-ast-local-fresh-v1',evidence_date='2026-10-09',
        evidence_timezone='Asia/Shanghai',sample_sha256=oracle.LIBRARY_SHA256,generated_fixture_seed=SEED,
        native_Python_AST_local_controls=len(rows),rollback_negative_controls=len(rejected),
        pre_change_behavior_RED_controls=3,recovered_callback_slots_hex=['0xb8','0xf8'],
        actual_native_vtable_offset_hex='0x372370',local_group_offset_hex='0x31d984',function_end_offset_hex='0x31dbb4',
        active_layout_stride=144,local_record_stride=16,type_width=8,count_and_cumulative_width=4,
        active_layouts=['data_inline','element_inline','element_nested'],
        all_fixtures_synthetic=True,native_input_snapshot_used=False,private_payloads_published=False,
        local_group_and_end_callbacks_implemented=True,code_begin_callback_implemented=False,
        function_output_container_implemented=False,parser_AST_composition_implemented=False,attached_parser_implemented=False,
        complete_AST_callbacks_implemented=False,complete_python_reader_implemented=False,independent_Python_factory_implemented=False,
        complete_python_bootstrap_controls=0,complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False,cases=rows,negative_cases=rejected)
    args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    print('B locals:',len(rows),'native/Python +',len(rejected),'rollback checks passed',flush=True)


if __name__=='__main__': main()
