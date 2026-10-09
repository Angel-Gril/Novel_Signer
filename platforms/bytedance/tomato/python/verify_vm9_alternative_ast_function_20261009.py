"""Fresh B function creation, independent type cache and 144-byte ownership.

Actual +50 and +2cc470 execute on synthetic inputs, never native snapshots.
Code begin and attached parser composition remain outside this checkpoint.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import random

import verify_vm9_alternative_ast_data_20261009 as controls
import verify_vm9_alternative_ast_local_20261009 as local
import verify_vm9_signer_objects as oracle
import vm9_alternative_startup as alternative
from vm9_allocator import RefillUnsupported, _read_span, _write_span

CB, AST, INPUT, HEAP = local.CB, local.AST, local.INPUT, local.HEAP
put, vector = local.put, local.vector
FUNCTIONS = {**local.FUNCTIONS, 0x50:0x31C7B8}
SEED = 0x31C7B8
DEFAULT_TYPES = [(0xABCDEF01, [0xFFFFFFFFFFFFFFF0], [0x8000000012345678, 7]),
                 (0x98765432, [1, 2, 3], []), (0, [], [])]


def prepare(library, base, spec):
    pages, sizes = local.instruction.prepare(library,base,{k:v for k,v in spec.items() if k != 'cleanup'})
    pointer = max([controls.OLD]+[p+((max(n,1)+15)&~15) for p,n in sizes.items()])
    def block(size, marker=0xA7):
        nonlocal pointer
        out=pointer; pointer+=(max(size,1)+15)&~15
        assert pointer < INPUT
        sizes[out]=size; _write_span(pages,out,bytes([marker])*max(size,1))
        return out
    def owned(header,stride,values,capacity,marker):
        out=block(capacity*stride,marker)
        vector(pages,header,out,len(values),capacity,stride)
        if values: _write_span(pages,out,b''.join(v.to_bytes(stride,'little') for v in values))
        return out
    def type_node(address,definition):
        scalar,params,results=definition
        put(pages,address,base+0x3724F0); put(pages,address+8,scalar,4)
        for offset,values,marker in ((0x10,params,0xD1),(0x28,results,0xD2)):
            vector(pages,address+offset)
            if values or spec.get('type_empty_storage'):
                owned(address+offset,8,values,len(values)+2,marker)
    definitions=spec.get('definitions',DEFAULT_TYPES)
    begin=block((len(definitions)+1)*64)
    vector(pages,AST,begin,len(definitions),len(definitions)+1,64)
    for index,definition in enumerate(definitions): type_node(begin+index*64,definition)
    size,capacity=spec.get('function_vector',(0,0))
    if capacity or spec.get('function_nonnull_empty'):
        begin=block(capacity*144); vector(pages,AST+0x30,begin,size,capacity,144)
        for index in range(size):
            address=begin+index*144
            _write_span(pages,address,bytes([0xB1+index])*144)
            type_node(address,definitions[index%len(definitions)])
            for offset in (0x50,0x78): vector(pages,address+offset)
            if spec.get('function_mode','rich')=='null':
                # Keep the copied type vectors; null only controls locals/children.
                continue
            empty=spec.get('function_mode')=='empty'
            owned(address+0x50,16,[] if empty else [0x1122334455667788],2,0xD3)
            count=spec.get('child_count',2)
            children=block((count+1)*56,0xD4)
            vector(pages,address+0x78,children,count,count+1,56)
            for child_index in range(count):
                child=children+child_index*56; vector(pages,child+0x10)
                if spec.get('function_mode')!='mixed' or child_index%2:
                    owned(child+0x10,8,[] if empty else list(range(child_index+1)),child_index+2,0xE1)
    size,capacity=spec.get('cache_vector',(0,0))
    if capacity or spec.get('cache_nonnull_empty'):
        begin=block(capacity*64); vector(pages,CB+0x80,begin,size,capacity,64)
        for index in range(size): type_node(begin+index*64,definitions[index%len(definitions)])
    if spec.get('active_function') is not None:
        begin=int.from_bytes(_read_span(pages,AST+0x30,8),'little')
        put(pages,CB+0x28,begin+spec['active_function']*144)
    return pages,sizes


def minimal_specs():
    return [dict(label='function_spare_cache_spare',function_vector=(1,3),cache_vector=(1,3),callbacks=[(0x50,(17,0))]),
            dict(label='function_growth_cache_growth',function_vector=(1,1),cache_vector=(1,1),callbacks=[(0x50,(0xFFFFFFFF12345678,0x100000000))]),
            dict(label='function_rich_destructor',function_vector=(2,3),destroy_function=True)]


def fixtures():
    cases=minimal_specs()
    states=((0,0),(0,3),(1,1),(2,3))
    for fs,fc in states:
        for cs,cc in states:
            for type_index in range(3):
                cases.append(dict(label=f'function_{fs}_{fc}_cache_{cs}_{cc}_type_{type_index}',
                    function_vector=(fs,fc),cache_vector=(cs,cc),
                    callbacks=[(0x50,(0xFFFFFFFF12345678,0xFFFFFFFF00000000+type_index))],
                    destroy_function=True,cleanup=True))
    for mode in ('null','empty','rich','mixed'):
        for count in (0,1,3):
            cases.append(dict(label=f'function_destructor_{mode}_{count}',function_vector=(2,3),
                function_mode=mode,child_count=count,destroy_function=True))
    for fn,cn in ((True,False),(False,True),(True,True)):
        cases.append(dict(label=f'nonnull_zero_capacity_{fn}_{cn}',function_nonnull_empty=fn,
            cache_nonnull_empty=cn,type_empty_storage=True,callbacks=[(0x50,(0,2))],destroy_function=True,cleanup=True))
    for params,results in (([],[]),([0xFFFFFFFFFFFFFFFF],[]),([],[0x8000000000000000]),
                           ([1,2,0xFFFFFFFFFFFFFFEF],[3,4,0x7FF8000000000001])):
        for full in (False,True):
            cases.append(dict(label=f'type_vectors_{len(params)}_{len(results)}_full_{full}',
                definitions=[(0xFFFFFFFF,params,results)],type_empty_storage=True,
                function_vector=(1,1) if full else (0,3),cache_vector=(1,1) if full else (0,3),
                callbacks=[(0x50,(0xFFFFFFFFFFFFFFFF,0))],destroy_function=True,cleanup=True))
    for state in states:
        cases.append(dict(label=f'repeated_function_growth_{state[0]}_{state[1]}',function_vector=state,cache_vector=state,
            callbacks=[(0x50,(0x100000000+i,i%3)) for i in range(8)],destroy_function=True,cleanup=True))
    for cap in (1,3):
        for count in (0,1,0xFFFFFFFF,0x100000002):
            cases.append(dict(label=f'function_owned_local_end_{cap}_{count}',function_vector=(1,cap),active_function=0,
                callbacks=[(0xB0,(0x100000003,)),(0xB8,(99,count,0xFFFFFFFFFFFFFFEF)),
                    (0xF8,(88,0xFFFFFFFF12345678))],destroy_function=True,cleanup=True))
    cases += [dict(label='function_with_other_owned_outputs',function_vector=(1,1),cache_vector=(1,1),
        data_vector=(1,1),element_vector=(1,1),owned_mode='rich',callbacks=[(0x50,(99,1))],
        destroy_function=True,destroy_data=True,destroy_element=True,cleanup=True),
        dict(label='function_spare_retains_active_and_frames',function_vector=(1,3),active_function=0,frames=(2,3),
            raw_vector=(3,9),callbacks=[(0x50,(0,0))],destroy_function=True,cleanup=True)]
    rng=random.Random(SEED)
    for index in range(6):
        fc=rng.randrange(1,4); fs=rng.randrange(fc+1); cc=rng.randrange(1,4); cs=rng.randrange(cc+1)
        cases.append(dict(label=f'generated_functions_{index}',function_vector=(fs,fc),cache_vector=(cs,cc),
            function_mode=rng.choice(('empty','rich','mixed')),child_count=rng.randrange(3),
            callbacks=[(0x50,(rng.getrandbits(64),(rng.getrandbits(32)<<32)|rng.randrange(3))) for _ in range(4)],
            destroy_function=True,cleanup=True))
    return cases


def compare(args,base,spec):
    row=controls.compare(args,base,spec,functions=FUNCTIONS,prepare_case=prepare)
    before,_=prepare(args.library,base,spec)
    callback_spec={k:v for k,v in spec.items() if k not in ('destroy_function','destroy_data','destroy_element','cleanup')}
    pages,effects,statuses=controls.model_case(args,base,callback_spec,prepare_case=prepare)
    u=lambda p,a,n=8:int.from_bytes(_read_span(p,a,n),'little')
    definitions=spec.get('definitions',DEFAULT_TYPES)
    created=[argv for slot,argv in spec.get('callbacks',[]) if slot==0x50]
    fs,fc=spec.get('function_vector',(0,0)); cs,cc=spec.get('cache_vector',(0,0))
    expected_allocations=[]
    for _,raw_type in created:
        _,params,results=definitions[raw_type&0xFFFFFFFF]
        lengths=[len(values)*8 for values in (params,results) if values]
        expected_allocations.extend(lengths)
        if fs==fc:
            fc=max(fs+1,fc*2); expected_allocations.append(fc*144)
        if cs==cc:
            cc=max(cs+1,cc*2); expected_allocations.append(cc*64)
        expected_allocations.extend(lengths); fs+=1; cs+=1
    if all(slot==0x50 for slot,_ in spec.get('callbacks',[])):
        assert [e[2] for e in effects if e[0]=='allocate']==expected_allocations
    fb,cb=u(pages,AST+0x30),u(pages,CB+0x80)
    assert u(pages,AST+0x38)-fb==fs*144 and u(pages,AST+0x40)-fb==fc*144
    assert u(pages,CB+0x88)-cb==cs*64 and u(pages,CB+0x90)-cb==cc*64
    source_begin=u(before,AST)
    assert _read_span(pages,source_begin,(len(definitions)+1)*64)==_read_span(before,source_begin,(len(definitions)+1)*64)
    payload_pointers=[]
    for index,(function_index,raw_type) in enumerate(created):
        type_index=raw_type&0xFFFFFFFF; scalar,params,results=definitions[type_index]
        record=fb+(spec.get('function_vector',(0,0))[0]+index)*144
        cache=cb+(spec.get('cache_vector',(0,0))[0]+index)*64
        for node in (record,cache):
            assert u(pages,node)==base+0x3724F0 and u(pages,node+8,4)==scalar
            for offset,values in ((0x10,params),(0x28,results)):
                begin,end,cap=(u(pages,node+offset+n) for n in (0,8,16))
                expected=b''.join(v.to_bytes(8,'little') for v in values)
                assert end-begin==cap-begin==len(expected) and _read_span(pages,begin,len(expected))==expected
                if begin:
                    assert begin != u(pages,source_begin+type_index*64+offset)
                    payload_pointers.append(begin)
                else: assert (begin,end,cap)==(0,0,0)
        assert u(pages,record+0x40,4)==type_index and u(pages,record+0x44,4)==function_index&0xFFFFFFFF
        assert u(pages,record+0x48,4)==u(pages,record+0x70,4)==0
        assert u(pages,record+0x68)==0xFFFFFFFF
        assert _read_span(pages,record+0x50,24)==_read_span(pages,record+0x78,24)==bytes(24)
        for offset in (0x0C,0x4C,0x74):
            expected=_read_span(before,record+offset,4) if record<INPUT else b'\xa5'*4
            assert _read_span(pages,record+offset,4)==expected
        expected=_read_span(before,cache+0x0C,4) if cache<INPUT else b'\xa5'*4
        assert _read_span(pages,cache+0x0C,4)==expected
    assert len(payload_pointers)==len(set(payload_pointers))
    for index,(_,params,results) in enumerate(definitions):
        for offset,values in ((0x10,params),(0x28,results)):
            pointer=u(before,source_begin+index*64+offset)
            assert _read_span(pages,pointer,len(values)*8)==b''.join(v.to_bytes(8,'little') for v in values)
    if spec.get('active_function') is not None:
        target=u(before,CB+0x28); cumulative=0; expected_count=0
        for slot,argv in spec.get('callbacks',[]):
            if slot==0xB0: cumulative=0
            elif slot==0xB8: cumulative=(cumulative+(argv[1]&0xFFFFFFFF))&0xFFFFFFFF; expected_count+=1
        assert u(pages,CB+0x7C,4)==cumulative
        initial_count=(u(before,target+0x58)-u(before,target+0x50))//16
        assert (u(pages,target+0x58)-u(pages,target+0x50))//16==initial_count+expected_count
        if any(slot==0xF8 for slot,_ in spec.get('callbacks',[])):
            assert u(pages,CB+0x28)==0 and u(pages,target+0x70,4)==0x12345678
        else:
            assert u(pages,CB+0x28)==target
            assert _read_span(pages,CB+0x30,0x48)==_read_span(before,CB+0x30,0x48)
    final,_,_=controls.model_case(args,base,spec,prepare_case=prepare)
    if spec.get('destroy_function'):
        for record in range(u(final,AST+0x30),u(final,AST+0x38),144):
            for offset in (0x10,0x28,0x50,0x78): assert u(final,record+offset)==u(final,record+offset+8)
    if spec.get('cleanup'): assert u(final,CB+0x80)==u(final,CB+0x88)
    row.update(independent_type_bytes_scalar_indices_padding_ownership_and_allocation_expectations_match=True,
        independent_function_local_end_and_destruction_expectations_match=True,
        actual_native_function_destructor_executed=bool(spec.get('destroy_function') or
            (spec.get('function_vector',(0,0))[0] and created and spec.get('function_vector',(0,0))[0]==spec.get('function_vector',(0,0))[1])),
        created_functions=len(created),callback_statuses=statuses)
    return row


def negatives(args):
    base=0x122C0000; rows=[]; cases=[]
    standard=dict(label='guard',function_vector=(1,1),cache_vector=(1,1))
    u=lambda p,a:int.from_bytes(_read_span(p,a,8),'little')
    record=lambda p:u(p,AST+0x30)
    source=lambda p:u(p,AST)
    child=lambda p:u(p,record(p)+0x78)
    def add(label,changes=None,setup=None,operation='callback',spec=None):
        cases.append((label,changes or {},setup,operation,spec or standard))
    add('function_slot_binding',setup=lambda p:put(p,base+0x372370+0x50,0))
    add('function_move_binding',setup=lambda p:put(p,base+0x375090,0))
    add('function_type_destructor_binding',setup=lambda p:put(p,base+0x3724F0,0))
    add('attached_parser',setup=lambda p:put(p,CB+8,INPUT))
    for argv in ((0,),(0,0,0),(0,1<<64),(-1,0)):
        add('arity_or_register_'+str(argv),dict(arguments=argv))
    for index in (3,4,0xFFFFFFFF): add(f'nonlogical_source_{index}',dict(arguments=(0,index)))
    for header in (AST+0x30,CB+0x80):
        for field,value in ((8,1),(16,1),(8,-144)):
            add(f'partial_or_reversed_{header:x}_{field}_{value}',setup=lambda p,h=header,f=field,v=value:put(p,h+f,u(p,h)+v))
        add(f'null_begin_{header:x}',setup=lambda p,h=header:put(p,h,0))
        add(f'alias_callback_{header:x}',setup=lambda p,h=header:vector(p,h,CB,0,1,144 if h==AST+0x30 else 64))
    add('function_capacity_budget',dict(max_nodes=2),spec=dict(label='guard',function_vector=(0,3),definitions=[(0,[],[])]))
    add('function_doubled_capacity_budget',dict(max_nodes=3),spec=dict(label='guard',function_vector=(2,2),definitions=[(0,[],[])]))
    add('function_append_total_node_budget',dict(max_nodes=5))
    add('function_byte_budget',dict(max_vector_bytes=287))
    add('cache_growth_budget',dict(max_vector_bytes=255),spec=dict(label='guard',function_vector=(0,1),cache_vector=(2,2)))
    add('missing_allocator',dict(allocate=None))
    add('function_wrong_vtable',setup=lambda p:put(p,record(p),base+0x372518))
    add('function_partial_locals',setup=lambda p:put(p,record(p)+0x58,u(p,record(p)+0x50)+1))
    add('function_partial_children',setup=lambda p:put(p,record(p)+0x80,child(p)+1))
    add('child_alias_params',setup=lambda p:vector(p,child(p)+0x10,u(p,record(p)+0x10),1,2,8))
    add('child_alias_sibling',setup=lambda p:vector(p,child(p)+56+0x10,u(p,child(p)+0x10),1,2,8))
    add('cache_alias_function',setup=lambda p:vector(p,CB+0x80,record(p),0,1,64))
    add('source_alias_function_params',setup=lambda p:vector(p,source(p)+0x10,u(p,record(p)+0x10),1,2,8))
    add('function_destructor_invalid',operation='destructor',setup=lambda p:put(p,record(p),base+0x372518))
    add('function_destructor_alias',operation='destructor',setup=lambda p:vector(p,record(p)+0x50,record(p),1,2,16))
    add('cleanup_function_alias',operation='cleanup',setup=lambda p:vector(p,CB+0x30,record(p),1,16))
    for slot,argv in ((0xB8,(0,1,1)),(0xF8,(0,1))):
        add(f'function_spare_active_{slot:x}',dict(slot_offset=slot,arguments=argv),
            setup=lambda p:put(p,CB+0x28,u(p,AST+0x38)),spec=dict(label='guard',function_vector=(1,3)))
    for label,changes,setup,operation,spec in cases:
        pages,_=prepare(args.library,base,spec)
        if setup: setup(pages)
        before={k:bytes(v) for k,v in pages.items()}
        params=dict(callback_address=CB,image_base=base,slot_offset=0x50,arguments=(99,0),allocate=lambda n:HEAP)
        params.update(changes)
        try:
            if operation=='destructor': alternative.destroy_reader_ast_function_record(pages,record_address=record(pages),image_base=base)
            elif operation=='cleanup': alternative.cleanup_reader_callback(pages,callback_address=CB,image_base=base)
            else: alternative.run_reader_ast_callback(pages,**params)
        except (RefillUnsupported,ValueError): pass
        else: raise AssertionError('function guard accepted: '+label)
        assert before=={k:bytes(v) for k,v in pages.items()},label
        rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_invalid_memory_path_compared=False))
    # Both-full/nonempty creation makes six ordered allocation plans. Reject
    # every position and every alias class after valid earlier plans/writes.
    targets=('unmapped','unaligned','partial','callback','output','source','function','cache',
             'params','children','child_payload','frames','image','retained','prior_plan')
    for stage in range(1,7):
        for target in targets:
            if target=='prior_plan' and stage==1: continue
            pages,_=prepare(args.library,base,{**standard,'frames':(1,2)})
            partial=oracle.GUEST+0xAFF8
            if target=='partial': pages[partial>>12]=pages[partial>>12][:4092]
            before={k:bytes(v) for k,v in pages.items()}; plans=[]; next_pointer=HEAP
            def allocate(size):
                nonlocal next_pointer
                result=next_pointer; next_pointer+=(size+15)&~15
                if len(plans)+1==stage:
                    result={'unmapped':0x90000000,'unaligned':HEAP+1,'partial':partial,'callback':CB,'output':AST,
                        'source':source(pages),'function':record(pages),'cache':u(pages,CB+0x80),
                        'params':u(pages,record(pages)+0x10),'children':child(pages),
                        'child_payload':u(pages,child(pages)+0x10),'frames':u(pages,CB+0x30),
                        'image':base+0x375090,'retained':INPUT,'prior_plan':plans[0][1] if plans else HEAP}[target]
                plans.append((size,result)); return result
            try: alternative.run_reader_ast_callback(pages,callback_address=CB,image_base=base,
                slot_offset=0x50,arguments=(99,0),allocate=allocate,reserved_regions=((INPUT,INPUT+2048),))
            except (RefillUnsupported,ValueError): pass
            else: raise AssertionError(('allocation guard accepted',stage,target))
            assert len(plans)==stage and before=={k:bytes(v) for k,v in pages.items()},(stage,target)
            rows.append(dict(label=f'allocation_{stage}_{target}',rejected=True,all_pages_unchanged=True,
                allocation_plans_before_rejection=stage,native_invalid_memory_path_compared=False))
    for fs,fc,cs,cc in ((1,1,1,1),(1,3,1,3)):
        for boundary in ('function_publish','cache_publish','cache_vector','old_function_clear','old_cache_clear'):
            if fc!=fs and boundary.startswith('old_'): continue
            spec={**standard,'function_vector':(fs,fc),'cache_vector':(cs,cc)}
            pages,_=prepare(args.library,base,spec); before={k:bytes(v) for k,v in pages.items()}
            original=alternative._write_span; plans=[]; next_pointer=HEAP
            def allocate(size):
                nonlocal next_pointer
                out=next_pointer; next_pointer+=(size+15)&~15; plans.append((size,out)); return out
            def fail(p,address,data):
                bad=(address==(AST+0x30 if fs==fc else AST+0x38) if boundary=='function_publish' else
                     address==(CB+0x80 if cs==cc else CB+0x88) if boundary=='cache_publish' else
                     (len(plans)>=4 and address==plans[3][1]+cs*64+0x10 if cs==cc else
                      address==u(pages,CB+0x80)+cs*64+0x10) if boundary=='cache_vector' else
                     address==record(pages)+0x10 if boundary=='old_function_clear' else
                     address==u(pages,CB+0x80)+0x10)
                if bad: raise RefillUnsupported('injected late function/cache write')
                original(p,address,data)
            alternative._write_span=fail
            try:
                try: alternative.run_reader_ast_callback(pages,callback_address=CB,image_base=base,
                    slot_offset=0x50,arguments=(99,0),allocate=allocate)
                except RefillUnsupported: pass
                else: raise AssertionError('late write guard accepted: '+boundary)
            finally: alternative._write_span=original
            assert before=={k:bytes(v) for k,v in pages.items()},boundary
            rows.append(dict(label=f'late_{fs}_{fc}_{cs}_{cc}_{boundary}',rejected=True,all_pages_unchanged=True,
                allocation_plans_before_rejection=len(plans),native_invalid_memory_path_compared=False))
    return rows


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    rows=[]; specs=fixtures(); rejected=negatives(args)
    assert len({s['label'] for s in specs})==len(specs)
    for base in (0x122C0000,0x775C205000):
        for index,spec in enumerate(specs,1):
            rows.append(compare(args,base,spec))
            if index%24==0 or index==len(specs): print('B functions:',hex(base),index,'/',len(specs),'passed',flush=True)
    evidence=dict(schema='vm9-alternative-ast-function-fresh-v1',evidence_date='2026-10-09',
        evidence_timezone='Asia/Shanghai',sample_sha256=oracle.LIBRARY_SHA256,generated_fixture_seed=SEED,
        native_Python_AST_function_controls=len(rows),rollback_negative_controls=len(rejected),
        pre_change_behavior_RED_controls=3,recovered_callback_slots_hex=['0x50'],
        actual_native_vtable_offset_hex='0x372370',function_entry_offset_hex='0x31c7b8',
        function_growth_offset_hex='0x31f690',type_clone_offset_hex='0x31eea4',
        cache_growth_offset_hex='0x31ed20',function_destructor_offset_hex='0x2cc470',
        function_output_offset_hex='0x30',cache_offset_hex='0x80',function_record_stride=144,type_cache_stride=64,
        all_fixtures_synthetic=True,native_input_snapshot_used=False,private_payloads_published=False,
        function_entry_output_ownership_and_destructor_implemented=True,function_local_end_layout_implemented=True,
        code_begin_callback_implemented=False,table_count_entry_callbacks_implemented=False,
        parser_AST_composition_implemented=False,attached_parser_implemented=False,
        complete_AST_callbacks_implemented=False,complete_python_reader_implemented=False,independent_Python_factory_implemented=False,
        complete_python_bootstrap_controls=0,complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False,cases=rows,negative_cases=rejected)
    args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    print('B functions:',len(rows),'native/Python +',len(rejected),'rollback checks passed',flush=True)


if __name__=='__main__': main()
