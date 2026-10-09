"""Fresh B global reserve/entry, independent cache and owned record cleanup.

Actual native callbacks/destructor execute on synthetic inputs. Guest bytes
and ordered effects are compared without masking or native input snapshots.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import random

import verify_vm9_alternative_ast_function_20261009 as function
import verify_vm9_signer_objects as oracle
import vm9_alternative_startup as alternative
from vm9_allocator import RefillUnsupported, _read_span, _write_span

CB, AST, INPUT, HEAP = function.CB, function.AST, function.INPUT, function.HEAP
put, vector = function.put, function.vector
FUNCTIONS = {**function.FUNCTIONS,0x78:0x31D004,0x80:0x31D028}
SEED = 0x31D028


def prepare(library,base,spec):
    pages,sizes = function.prepare(library,base,{k:v for k,v in spec.items() if k != 'cleanup'})
    pointer = max([function.controls.OLD]+[p+((max(n,1)+15)&~15) for p,n in sizes.items()])
    def block(size,marker=0xB3):
        nonlocal pointer
        out=pointer; pointer+=(max(size,1)+15)&~15; assert pointer < INPUT
        sizes[out]=size; _write_span(pages,out,bytes([marker])*max(size,1)); return out
    def owned(header,stride,values,capacity):
        out=block(capacity*stride,0xD3); vector(pages,header,out,len(values),capacity,stride)
        if values: _write_span(pages,out,b''.join(v.to_bytes(stride,'little') for v in values))
        return out
    size,capacity=spec.get('globals',(0,0))
    if capacity or spec.get('global_nonnull_empty'):
        begin=block(capacity*176); vector(pages,AST+0x78,begin,size,capacity,176)
        for index in range(size):
            record=begin+index*176
            put(pages,record,base+0x372568); put(pages,record+8,0xD00D0000+index,4)
            put(pages,record+0xC,0x8000000012345600+index); put(pages,record+0x14,0xF0010000+index,4)
            put(pages,record+0x18,base+0x3724F0); put(pages,record+0x20,0xABCD0000+index,4)
            for offset in (0x28,0x40,0x68,0x90): vector(pages,record+offset)
            if spec.get('global_mode','null')=='null': continue
            empty=spec.get('global_mode')=='empty'
            for offset in (0x28,0x40): owned(record+offset,8,[] if empty else [offset+index,0xFFFFFFFFFFFFFFF0],3)
            owned(record+0x68,16,[] if empty else [0x123456789ABCDEF0],2)
            count=spec.get('child_count',2); children=block((count+1)*56,0xD4)
            vector(pages,record+0x90,children,0 if empty else count,count+1,56)
            for child_index in range(0 if empty else count):
                child=children+child_index*56; vector(pages,child+0x10)
                if spec.get('global_mode')!='mixed' or child_index%2:
                    owned(child+0x10,8,list(range(child_index+1)),child_index+2)
    size,capacity=spec.get('global_cache',(0,0))
    if capacity or spec.get('cache_nonnull_empty'):
        begin=block(capacity*24,0xC3); vector(pages,CB+0xC8,begin,size,capacity,24)
        for index in range(size):
            record=begin+index*24
            put(pages,record,base+0x372568); put(pages,record+8,0xD00D1000+index,4)
    return pages,sizes


def minimal_specs():
    return [dict(label='global_reserve_rich_growth',globals=(1,1),global_cache=(1,2),global_mode='rich',callbacks=[(0x78,(3,))]),
        dict(label='global_reserve_high_u32_noop',globals=(1,2),global_cache=(1,2),callbacks=[(0x78,(0xFFFFFFFF00000001,))]),
        dict(label='global_entry_spare_fulltype_mutable',globals=(1,3),global_cache=(1,3),
            callbacks=[(0x80,(0xFFFFFFFFFFFFFFFF,0x8000000012345678,0x100000003))]),
        dict(label='global_entry_both_growth',globals=(1,1),global_cache=(1,1),global_mode='rich',
            callbacks=[(0x80,(0,0xFFFFFFFFFFFFFFF0,0xFFFFFFFFFFFFFFFE))]),
        dict(label='global_rich_record_destructor',globals=(2,3),global_mode='rich',destroy_global=True)]


def fixtures():
    cases=minimal_specs()
    for mode in ('null','empty','rich','mixed'):
        for size,capacity in ((0,0),(0,2),(1,1),(2,3)):
            for count in (0,1,2,5):
                cases.append(dict(label=f'reserve_{mode}_{size}_{capacity}_{count}',globals=(size,capacity),
                    global_cache=(1,2),global_mode=mode,callbacks=[(0x78,((0xFFFFFFFF<<32)|count,))],cleanup=True))
    for globals_vector in ((0,0),(0,2),(1,1),(2,3)):
        for cache in ((0,0),(0,2),(1,1),(2,3)):
            for flag in (0,1,0x100000002,0xFFFFFFFFFFFFFFFF):
                cases.append(dict(label=f'entry_{globals_vector}_{cache}_{flag}',globals=globals_vector,
                    global_cache=cache,global_mode='rich',callbacks=[(0x80,(99,0x8000000012345678,flag))],
                    destroy_global=True,cleanup=True))
    for mode in ('null','empty','rich','mixed'):
        for count in (0,1,3):
            cases.append(dict(label=f'destructor_{mode}_{count}',globals=(2,3),global_mode=mode,
                child_count=count,destroy_global=True,cleanup=True))
    for bits in (0,0xFFFFFFFF,0x100000001,0xFFFFFFFFFFFFFFFF):
        cases.append(dict(label=f'full_type_{bits}',globals=(0,0),global_cache=(0,0),
            callbacks=[(0x80,(bits,bits,bits))],destroy_global=True,cleanup=True))
    for globals_vector,cache,budget in (((1,1),(1,1),7),((0,0),(6,6),12)):
        cases.append(dict(label=f'exact_global_node_budget_{budget}',globals=globals_vector,global_cache=cache,
            definitions=[(0,[],[])],callback_max_nodes=budget,callbacks=[(0x80,(0,7,1))],destroy_global=True,cleanup=True))
    cases += [dict(label='global_nonnull_zero_capacity',globals=(0,0),global_cache=(0,0),
            global_nonnull_empty=True,cache_nonnull_empty=True,callbacks=[(0x78,(0,)),(0x80,(0,7,1))],destroy_global=True,cleanup=True),
        dict(label='global_repeated_reserve',globals=(1,1),global_cache=(1,2),global_mode='rich',
            callbacks=[(0x78,(n,)) for n in (0,2,2,1,5,6)],destroy_global=True,cleanup=True),
        dict(label='global_repeated_append',globals=(1,1),global_cache=(2,2),global_mode='mixed',
            callbacks=[(0x80,(0xFFFFFFFF00000000+i,0x8000000000000000+i,i)) for i in range(7)],destroy_global=True,cleanup=True),
        dict(label='global_reserve_append_reserve',globals=(0,0),global_cache=(1,1),
            callbacks=[(0x78,(3,)),(0x80,(99,7,1)),(0x78,(1,)),(0x80,(77,0xFFFFFFFFFFFFFFF0,2)),(0x78,(5,))],destroy_global=True,cleanup=True),
        dict(label='global_with_owned_functions_and_outputs',globals=(1,1),global_cache=(1,1),global_mode='rich',
            function_vector=(1,1),cache_vector=(1,1),data_vector=(1,1),element_vector=(1,1),owned_mode='rich',
            callbacks=[(0x80,(0,7,1))],destroy_global=True,destroy_function=True,destroy_data=True,destroy_element=True,cleanup=True)]
    rng=random.Random(SEED)
    for index in range(8):
        size,cache_size=rng.randrange(3),rng.randrange(3)
        cases.append(dict(label=f'generated_global_{index}',globals=(size,size+rng.randrange(2)),
            global_cache=(cache_size,cache_size+rng.randrange(2)),global_mode=rng.choice(('null','empty','mixed')),
            callbacks=[(0x80,(rng.getrandbits(64),rng.getrandbits(64),rng.getrandbits(64)))],destroy_global=True,cleanup=True))
    return cases


def compare(args,base,spec):
    row=function.controls.compare(args,base,spec,functions=FUNCTIONS,prepare_case=prepare)
    callback_spec={k:v for k,v in spec.items() if k not in ('destroy_global','destroy_function','destroy_data','destroy_element','cleanup')}
    initial,_=prepare(args.library,base,callback_spec)
    pages,effects,statuses=function.controls.model_case(args,base,callback_spec,prepare_case=prepare)
    if 'callback_max_nodes' in spec:
        bounded,_=prepare(args.library,base,callback_spec); pointer=HEAP; bounded_effects=[]; bounded_statuses=[]
        def allocate(size):
            nonlocal pointer
            out=pointer; pointer+=(size+15)&~15; return out
        for slot,argv in callback_spec['callbacks']:
            result=alternative.run_reader_ast_callback(bounded,callback_address=CB,image_base=base,
                slot_offset=slot,arguments=argv,allocate=allocate,max_nodes=spec['callback_max_nodes'])
            bounded_effects.extend(result.effects); bounded_statuses.append(result.status)
        assert _read_span(bounded,oracle.GUEST,0xA000)==_read_span(pages,oracle.GUEST,0xA000)
        assert [(e.kind,e.address,e.size,e.owner_address,e.owner_bytes) for e in bounded_effects]==effects
        assert bounded_statuses==statuses
    u=lambda p,a,n=8:int.from_bytes(_read_span(p,a,n),'little')
    gs,gc=spec.get('globals',(0,0)); cs,cc=spec.get('global_cache',(0,0))
    expected_allocations=[]; appended=[]
    for slot,argv in spec.get('callbacks',[]):
        if slot==0x78:
            count=argv[0]&0xFFFFFFFF
            if count>gc: gc=count; expected_allocations.append(gc*176)
        else:
            assert slot==0x80
            expected_allocations.extend((8,8,8))
            if gs==gc: gc=max(gs+1,gc*2); expected_allocations.append(gc*176)
            if cs==cc: cc=max(cs+1,cc*2); expected_allocations.append(cc*24)
            appended.append((argv[1],argv[2]&1)); gs+=1; cs+=1
    assert [e[2] for e in effects if e[0]=='allocate']==expected_allocations
    gb,cb=u(pages,AST+0x78),u(pages,CB+0xC8)
    assert (u(pages,AST+0x80)-gb,u(pages,AST+0x88)-gb)==(gs*176,gc*176)
    assert (u(pages,CB+0xD0)-cb,u(pages,CB+0xD8)-cb)==(cs*24,cc*24)
    for begin,stride,initial_size in ((gb,176,spec.get('globals',(0,0))[0]),(cb,24,spec.get('global_cache',(0,0))[0])):
        for index,(bits,mutable) in enumerate(appended,initial_size):
            record=begin+index*stride
            assert u(pages,record)==base+0x372568 and u(pages,record+8,4)==3
            assert u(pages,record+0xC)==bits and u(pages,record+0x14,4)==mutable
            if stride==176:
                assert u(pages,record+0x18)==base+0x3724F0 and u(pages,record+0x20,4)==0
                result=u(pages,record+0x40)
                assert u(pages,result)==bits
                assert (u(pages,record+0x48),u(pages,record+0x50))==(result+8,result+8)
                for offset in (0x28,0x68,0x90): assert _read_span(pages,record+offset,24)==bytes(24)
                assert u(pages,record+0x58)==0 and u(pages,record+0x60,4)==0
                assert u(pages,record+0x80)==0xFFFFFFFF and u(pages,record+0x88,4)==0 and u(pages,record+0xA8)==0
    for index in range(gs):
        for offset in (0x24,0x64,0x8C):
            address=gb+index*176+offset
            assert _read_span(pages,address,4)==_read_span(initial,address,4)
    for header,stride,size in ((AST+0x78,176,spec.get('globals',(0,0))[0]),(CB+0xC8,24,spec.get('global_cache',(0,0))[0])):
        old,new=u(initial,header),u(pages,header)
        for index in range(size):
            source,target=old+index*stride,new+index*stride
            assert _read_span(pages,target,24)==_read_span(initial,source,24)
            if stride==176:
                for offset,width in ((0x20,4),(0x58,8),(0x60,4),(0x80,8),(0x88,4),(0xA8,8)):
                    assert _read_span(pages,target+offset,width)==_read_span(initial,source+offset,width)
                for offset in (0x28,0x40,0x68,0x90):
                    assert _read_span(pages,target+offset,24)==_read_span(initial,source+offset,24)
                    if old!=new: assert _read_span(pages,source+offset,24)==bytes(24)
    assert statuses==[0]*len(statuses)
    row.update(independent_capacity_fulltype_mutable_result_padding_and_allocation_expectations_match=True,
        global_entries_created=len(appended),actual_global_record_destructor_executed=bool(spec.get('destroy_global')),
        guest_bytes_masked=False,native_stack_or_TLS_as_a_whole_compared=False,exact_node_budget_control='callback_max_nodes' in spec,
        **({'exact_node_budget_supported':spec['callback_max_nodes']} if 'callback_max_nodes' in spec else {}))
    return row


def negatives(args):
    base=0x122C0000; rows=[]; cases=[]
    standard=dict(label='guard',globals=(1,1),global_cache=(1,1),global_mode='rich')
    u=lambda p,a,n=8:int.from_bytes(_read_span(p,a,n),'little')
    def add(label,changes=None,setup=None,spec=None,slot=0x80):
        cases.append((label,changes or {},setup,spec or standard,slot))
    for slot in (0x78,0x80):
        add(f'slot_binding_{slot}',setup=lambda p,slot=slot:put(p,base+0x372370+slot,0),slot=slot)
    for offset in (0x3750A8,0x375090):
        add(f'GOT_binding_{offset}',setup=lambda p,offset=offset:put(p,base+offset,0))
    add('attached',setup=lambda p:put(p,CB+8,INPUT))
    for argv in ((0,7),(0,7,1,0),(-1,7,1),(0,1<<64,1),(0,7,-1)):
        add('arity_or_register_'+str(argv),dict(arguments=argv))
    add('output_partial_end',setup=lambda p:put(p,AST+0x80,u(p,AST+0x78)+175))
    add('output_partial_capacity',setup=lambda p:put(p,AST+0x88,u(p,AST+0x78)+177))
    add('global_node_vtable',setup=lambda p:put(p,u(p,AST+0x78),base+0x372540))
    add('inline_type_vtable',setup=lambda p:put(p,u(p,AST+0x78)+0x18,base+0x372568))
    add('global_destructor_binding',setup=lambda p:put(p,base+0x372568,0))
    add('global_cache_alias',setup=lambda p:vector(p,CB+0xC8,u(p,AST+0x78),1,1,24))
    add('global_params_alias',setup=lambda p:vector(p,u(p,AST+0x78)+0x28,u(p,AST+0x78),1,1,8))
    add('unrecovered_output',setup=lambda p:vector(p,AST+0x90,INPUT,0,1,40))
    add('output_capacity_bound',dict(max_nodes=4),spec=dict(label='guard',globals=(0,5)))
    add('reserve_node_bound',dict(arguments=(5,),max_nodes=4),spec=dict(label='guard',globals=(0,0)),slot=0x78)
    add('reserve_byte_bound',dict(arguments=(3,),max_vector_bytes=527),spec=dict(label='guard',globals=(0,0),definitions=[]),slot=0x78)
    add('append_total_node_bound',dict(max_nodes=6),spec=dict(label='guard',globals=(1,1),global_cache=(1,1),definitions=[(0,[],[])]))
    add('append_cache_doubled_capacity_bound',dict(max_nodes=11),spec=dict(label='guard',globals=(0,0),global_cache=(6,6),definitions=[(0,[],[])]))
    add('append_byte_bound',dict(max_vector_bytes=351),spec=dict(label='guard',globals=(1,1),global_cache=(0,0),definitions=[]))
    add('cache_byte_bound',dict(max_vector_bytes=200),spec=dict(label='guard',globals=(0,0),global_cache=(6,6),definitions=[]))
    add('missing_allocator',dict(allocate=None))
    for label,changes,setup,spec,slot in cases:
        pages,_=prepare(args.library,base,spec)
        if setup: setup(pages)
        before={k:bytes(v) for k,v in pages.items()}; pointer=HEAP
        def allocate(size):
            nonlocal pointer
            out=pointer; pointer+=(size+15)&~15; return out
        params=dict(callback_address=CB,image_base=base,slot_offset=slot,
            arguments=(0,7,1) if slot==0x80 else (3,),allocate=allocate); params.update(changes)
        paired=label in ('reserve_node_bound','reserve_byte_bound','append_total_node_bound','append_cache_doubled_capacity_bound','append_byte_bound','cache_byte_bound')
        if paired:
            baseline,_=prepare(args.library,base,spec)
            alternative.run_reader_ast_callback(baseline,callback_address=CB,image_base=base,slot_offset=slot,
                arguments=params['arguments'],allocate=allocate); pointer=HEAP
        try: alternative.run_reader_ast_callback(pages,**params)
        except (RefillUnsupported,ValueError) as exc:
            if label in ('reserve_byte_bound','append_byte_bound','cache_byte_bound'):
                assert str(exc)=='AST requires a bounded pure allocation plan',(label,str(exc))
        else: raise AssertionError('global guard accepted: '+label)
        assert before=={k:bytes(v) for k,v in pages.items()},label
        rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_invalid_memory_path_compared=False,
            **({'same_input_without_budget_restriction_supported':True} if paired else {}),
            **({'allocation_byte_bound_failure_verified':True} if label in ('reserve_byte_bound','append_byte_bound','cache_byte_bound') else {})))
    targets=('unmapped','unaligned','partial','callback','output','global','cache','type_params',
        'global_params','children','image','retained','prior_plan')
    for stage in range(1,6):
        for target in targets:
            if stage==1 and target=='prior_plan': continue
            pages,_=prepare(args.library,base,standard); partial=oracle.GUEST+0xAFF8
            if target=='partial': pages[partial>>12]=pages[partial>>12][:4092]
            before={k:bytes(v) for k,v in pages.items()}; plans=[]; pointer=HEAP
            def allocate(size):
                nonlocal pointer
                out=pointer; pointer+=(size+15)&~15
                if len(plans)+1==stage:
                    out={'unmapped':0x90000000,'unaligned':HEAP+1,'partial':partial,'callback':CB,'output':AST,
                        'global':u(pages,AST+0x78),'cache':u(pages,CB+0xC8),'type_params':u(pages,u(pages,AST)+0x10),
                        'global_params':u(pages,u(pages,AST+0x78)+0x28),'children':u(pages,u(pages,AST+0x78)+0x90),
                        'image':base+0x6E188,'retained':INPUT+0x200,'prior_plan':plans[0][1] if plans else HEAP}[target]
                plans.append((size,out)); return out
            try: alternative.run_reader_ast_callback(pages,callback_address=CB,image_base=base,slot_offset=0x80,
                arguments=(0,7,1),allocate=allocate,reserved_regions=((INPUT+0x200,INPUT+0x300),))
            except (RefillUnsupported,ValueError): pass
            else: raise AssertionError(('global allocation guard accepted',stage,target))
            assert len(plans)==stage and before=={k:bytes(v) for k,v in pages.items()},(stage,target)
            rows.append(dict(label=f'allocation_{stage}_{target}',rejected=True,all_pages_unchanged=True,
                allocation_plans_before_rejection=stage,native_invalid_memory_path_compared=False))
    for boundary in ('original','temporary','result','output_type','output_inline','output_result_header','output_move',
            'output_publish','cache_type','cache_move','cache_publish','reserve_move','reserve_publish',
            'reserve_destructor_vtable','output_spare_end','cache_spare_end'):
        spec={**standard}
        if boundary.endswith('spare_end'): spec.update(globals=(1,3),global_cache=(1,3))
        pages,_=prepare(args.library,base,spec); before={k:bytes(v) for k,v in pages.items()}
        targets={'original':HEAP,'temporary':HEAP+16,'result':HEAP+32,'output_type':HEAP+48+176+0xC,
            'output_inline':HEAP+48+176+0x18,'output_result_header':HEAP+48+176+0x40,'output_move':HEAP+48+0x28,
            'output_publish':AST+0x78,'cache_type':HEAP+400+24+0xC,'cache_move':HEAP+400+8,
            'cache_publish':CB+0xC8,'reserve_move':HEAP+0x28,'reserve_publish':AST+0x78,
            'reserve_destructor_vtable':u(pages,AST+0x78)+0x18,'output_spare_end':AST+0x80,'cache_spare_end':CB+0xD0}
        original=alternative._write_span; pointer=HEAP; plans=[]
        def allocate(size):
            nonlocal pointer
            out=pointer; pointer+=(size+15)&~15; plans.append((size,out)); return out
        def fail(p,address,data):
            if address==targets[boundary]: raise RefillUnsupported('injected late global write')
            original(p,address,data)
        alternative._write_span=fail
        try:
            try: alternative.run_reader_ast_callback(pages,callback_address=CB,image_base=base,
                slot_offset=0x78 if boundary.startswith('reserve_') else 0x80,
                arguments=(3,) if boundary.startswith('reserve_') else (0,7,1),allocate=allocate)
            except RefillUnsupported as exc: assert str(exc)=='injected late global write'
            else: raise AssertionError('late global guard accepted: '+boundary)
        finally: alternative._write_span=original
        assert before=={k:bytes(v) for k,v in pages.items()},boundary
        rows.append(dict(label='late_'+boundary,rejected=True,all_pages_unchanged=True,
            allocation_plans_before_rejection=len(plans),native_invalid_memory_path_compared=False))
    for label,setup,changes in (
            ('record_pointer',None,dict(record_address=0x90000000)),
            ('global_vtable',lambda p,a:put(p,a,base+0x372540),{}),
            ('type_vtable',lambda p,a:put(p,a+0x18,base+0x372568),{}),
            ('locals_partial',lambda p,a:put(p,a+0x70,u(p,a+0x68)+15),{}),
            ('children_partial',lambda p,a:put(p,a+0x98,u(p,a+0x90)+55),{}),
            ('params_alias',lambda p,a:vector(p,a+0x28,a,1,1,8),{}),
            ('shared_child_payload',lambda p,a:vector(p,u(p,a+0x90)+56+0x10,u(p,u(p,a+0x90)+0x10),1,2,8),{}),
            ('node_bound',None,dict(max_nodes=3)),
            ('byte_bound',None,dict(max_vector_bytes=167))):
        pages,_=prepare(args.library,base,standard); address=u(pages,AST+0x78)
        if setup: setup(pages,address)
        before={k:bytes(v) for k,v in pages.items()}
        params=dict(record_address=address,image_base=base); params.update(changes)
        if label=='node_bound':
            baseline,_=prepare(args.library,base,standard)
            alternative.destroy_reader_ast_global_record(baseline,record_address=address,image_base=base)
        try: alternative.destroy_reader_ast_global_record(pages,**params)
        except (RefillUnsupported,ValueError): pass
        else: raise AssertionError('global destructor guard accepted: '+label)
        assert before=={k:bytes(v) for k,v in pages.items()},label
        rows.append(dict(label='destructor_'+label,rejected=True,all_pages_unchanged=True,
            native_invalid_memory_path_compared=False,**({'same_input_without_budget_restriction_supported':True} if label=='node_bound' else {})))
    for offset in (0x98,0x70,0x18,0x48,0x30):
        pages,_=prepare(args.library,base,standard); address=u(pages,AST+0x78)
        before={k:bytes(v) for k,v in pages.items()}; original=alternative._write_span
        def fail(p,target,data):
            if target==address+offset: raise RefillUnsupported('injected global destructor write')
            original(p,target,data)
        alternative._write_span=fail
        try:
            try: alternative.destroy_reader_ast_global_record(pages,record_address=address,image_base=base)
            except RefillUnsupported as exc: assert str(exc)=='injected global destructor write'
            else: raise AssertionError('late global destructor guard accepted: '+str(offset))
        finally: alternative._write_span=original
        assert before=={k:bytes(v) for k,v in pages.items()},offset
        rows.append(dict(label='late_destructor_'+str(offset),rejected=True,all_pages_unchanged=True,native_invalid_memory_path_compared=False))
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
            if index%24==0 or index==len(specs): print('B global:',hex(base),index,'/',len(specs),'passed',flush=True)
    evidence=dict(schema='vm9-alternative-ast-global-fresh-v1',evidence_date='2026-10-09',evidence_timezone='Asia/Shanghai',
        sample_sha256=oracle.LIBRARY_SHA256,generated_fixture_seed=SEED,native_Python_AST_global_controls=len(rows),
        rollback_negative_controls=len(rejected),pre_change_behavior_RED_controls=5,recovered_callback_slots_hex=['0x78','0x80'],
        actual_native_vtable_offset_hex='0x372370',global_reserve_offset_hex='0x31d004',global_entry_offset_hex='0x31d028',
        global_reserve_helper_offset_hex='0x31f90c',global_growth_offset_hex='0x31fae4',global_cache_growth_offset_hex='0x31f2c4',
        global_record_destructor_offset_hex='0x2cc3b4',global_node_vtable_offset_hex='0x372568',global_output_offset_hex='0x78',
        global_cache_offset_hex='0xc8',global_record_stride=176,global_cache_stride=24,destination_padding_bytes=12,
        full_u64_type_preserved=True,mutable_low_bit_only=True,global_count_entry_callbacks_implemented=True,
        global_record_destructor_implemented=True,guest_bytes_masked=False,all_fixtures_synthetic=True,
        native_input_snapshot_used=False,private_payloads_published=False,global_expression_callbacks_implemented=False,
        parser_AST_composition_implemented=False,attached_parser_implemented=False,complete_AST_callbacks_implemented=False,
        complete_output_wrapper_cleanup_implemented=False,complete_python_reader_implemented=False,independent_Python_factory_implemented=False,
        complete_python_bootstrap_controls=0,complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False,cases=rows,negative_cases=rejected)
    args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    print('B global:',len(rows),'native/Python +',len(rejected),'rollback checks passed',flush=True)

if __name__=='__main__': main()
