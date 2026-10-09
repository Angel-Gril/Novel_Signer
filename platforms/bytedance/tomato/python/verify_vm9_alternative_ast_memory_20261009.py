"""Fresh actual B memory reserve/entry on independent synthetic descriptors.

The relocated vtable executes naturally; guest bytes and ordered effects are
compared without masking. Attached parser and output wrapper remain open.
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
FUNCTIONS = {**function.FUNCTIONS,0x68:0x31CCEC,0x70:0x31CDB4}
SEED = 0x31CDB4


def prepare(library,base,spec):
    pages,sizes = function.prepare(library,base,{k:v for k,v in spec.items() if k != 'cleanup'})
    pointer = max([function.controls.OLD]+[p+((max(n,1)+15)&~15) for p,n in sizes.items()])
    for header,(size,capacity),marker in ((AST+0x60,spec.get('memories',(0,0)),0xB2),
            (CB+0xB0,spec.get('memory_cache',(0,0)),0xC2)):
        if not capacity and not spec.get('nonnull_empty'):
            vector(pages,header); continue
        begin = pointer; pointer += (max(capacity*40,1)+15)&~15
        assert pointer < INPUT
        sizes[begin] = capacity*40
        _write_span(pages,begin,bytes([marker])*max(capacity*40,1))
        vector(pages,header,begin,size,capacity,40)
        for index in range(size):
            record = begin+index*40
            put(pages,record,base+0x372540); put(pages,record+8,0xD00D0000+index,4)
    for offset in range(0,0x100,32):
        descriptor = bytearray((i+offset)&255 for i in range(24))
        descriptor[16] = spec.get('descriptor_flag',0)
        descriptor[18] = spec.get('memory64_flag',0)
        _write_span(pages,INPUT+offset+spec.get('descriptor_unaligned',0),descriptor)
    _write_span(pages,oracle.GUEST+0xEE50,bytes([spec.get('stack_marker',0xA5)])*0xB0)
    return pages,sizes


def minimal_specs():
    return [dict(label='memory_reserve_existing_growth',memories=(1,1),memory_cache=(0,0),callbacks=[(0x68,(3,))]),
        dict(label='memory_reserve_high_u32_noop',memories=(1,2),memory_cache=(1,2),callbacks=[(0x68,(0xFFFFFFFF00000001,))]),
        dict(label='memory_entry_spare_default32',memories=(1,3),memory_cache=(1,3),
            callbacks=[(0x70,(0xFFFFFFFFFFFFFFFF,INPUT))]),
        dict(label='memory_entry_output_cache_growth_explicit',memories=(1,1),memory_cache=(1,1),descriptor_flag=9,
            callbacks=[(0x70,(0,INPUT))]),
        dict(label='memory_entry_spare_default64',memories=(1,3),memory_cache=(1,3),memory64_flag=7,
            callbacks=[(0x70,(0xFFFFFFFFFFFFFFFF,INPUT))])]


def fixtures():
    cases = minimal_specs()
    for size,capacity in ((0,0),(0,2),(1,1),(2,3)):
        for count in (0,1,2,5):
            cases.append(dict(label=f'reserve_{size}_{capacity}_{count}',memories=(size,capacity),
                memory_cache=(1,2),callbacks=[(0x68,((0xFFFFFFFF<<32)|count,))],cleanup=True))
    for memories in ((0,0),(0,2),(1,1),(2,3)):
        for cache in ((0,0),(0,2),(1,1),(2,3)):
            for flag in (0,1,9):
                for wide in (0,255):
                    cases.append(dict(label=f'entry_{memories}_{cache}_{flag}_{wide}',memories=memories,
                        memory_cache=cache,descriptor_flag=flag,memory64_flag=wide,
                        callbacks=[(0x70,(99,INPUT))],cleanup=True))
    for marker in (0,0x33,0xFE):
        cases.append(dict(label=f'initialized_descriptor_stack_{marker}',memories=(1,3),memory_cache=(1,3),
            stack_marker=marker,descriptor_flag=1,callbacks=[(0x70,(0,INPUT))],cleanup=True))
    for count,budget in ((1,5),(6,12)):
        cases.append(dict(label=f'exact_memory_node_budget_{count}_{budget}',memories=(count,count),
            memory_cache=(1,1) if count == 1 else (0,0),definitions=[(0,[],[])],
            callback_max_nodes=budget,callbacks=[(0x70,(0,INPUT))],cleanup=True))
    cases += [dict(label='memory_nonnull_zero_capacity',memories=(0,0),memory_cache=(0,0),nonnull_empty=True,
            callbacks=[(0x68,(0,)),(0x70,(0,INPUT))],cleanup=True),
        dict(label='memory_unaligned_descriptor',memories=(1,2),memory_cache=(0,0),descriptor_unaligned=1,
            callbacks=[(0x70,(0x8000000012345678,INPUT+1))],cleanup=True),
        dict(label='memory_repeated_reserve',memories=(1,1),memory_cache=(1,2),
            callbacks=[(0x68,(n,)) for n in (0,2,2,1,5,6)],cleanup=True),
        dict(label='memory_repeated_append',memories=(1,1),memory_cache=(2,2),
            callbacks=[(0x70,(0xFFFFFFFF00000000+i,INPUT+i*32)) for i in range(7)],cleanup=True),
        dict(label='memory_reserve_append_reserve',memories=(0,0),memory_cache=(1,1),
            callbacks=[(0x68,(3,)),(0x70,(99,INPUT)),(0x68,(1,)),(0x70,(77,INPUT+32)),(0x68,(5,))],cleanup=True),
        dict(label='memory_with_owned_functions_and_outputs',memories=(1,1),memory_cache=(1,1),
            function_vector=(1,1),cache_vector=(1,1),data_vector=(1,1),element_vector=(1,1),owned_mode='rich',
            callbacks=[(0x70,(0,INPUT))],destroy_function=True,destroy_data=True,destroy_element=True,cleanup=True)]
    rng = random.Random(SEED)
    for index in range(8):
        size,cache_size = rng.randrange(3),rng.randrange(3)
        cases.append(dict(label=f'generated_memory_{index}',memories=(size,size+rng.randrange(2)),
            memory_cache=(cache_size,cache_size+rng.randrange(2)),descriptor_flag=rng.randrange(256),
            memory64_flag=rng.randrange(256),stack_marker=rng.randrange(256),
            callbacks=[(0x70,(rng.getrandbits(64),INPUT))],cleanup=True))
    return cases


def compare(args,base,spec):
    row = function.controls.compare(args,base,spec,functions=FUNCTIONS,prepare_case=prepare)
    callback_spec = {k:v for k,v in spec.items() if k not in ('destroy_function','destroy_data','destroy_element','cleanup')}
    initial,_ = prepare(args.library,base,callback_spec)
    pages,effects,statuses = function.controls.model_case(args,base,callback_spec,prepare_case=prepare)
    if 'callback_max_nodes' in spec:
        bounded,_ = prepare(args.library,base,callback_spec); pointer=HEAP; bounded_effects=[]; bounded_statuses=[]
        def allocate(size):
            nonlocal pointer
            out=pointer; pointer+=(size+15)&~15; return out
        for slot,argv in callback_spec['callbacks']:
            result=alternative.run_reader_ast_callback(bounded,callback_address=CB,image_base=base,
                slot_offset=slot,arguments=argv,allocate=allocate,max_nodes=spec['callback_max_nodes'])
            bounded_effects.extend(result.effects); bounded_statuses.append(result.status)
        assert _read_span(bounded,oracle.GUEST,0xA000) == _read_span(pages,oracle.GUEST,0xA000)
        assert [(e.kind,e.address,e.size,e.owner_address,e.owner_bytes) for e in bounded_effects] == effects
        assert bounded_statuses == statuses
    u = lambda p,a,n=8:int.from_bytes(_read_span(p,a,n),'little')
    ms,mc = spec.get('memories',(0,0)); cs,cc = spec.get('memory_cache',(0,0))
    expected_allocations = []; appended = []
    for slot,argv in spec.get('callbacks',[]):
        if slot == 0x68:
            requested = argv[0]&0xFFFFFFFF
            if requested > mc: mc=requested; expected_allocations.append(mc*40)
        else:
            assert slot == 0x70
            if ms == mc: mc=max(ms+1,mc*2); expected_allocations.append(mc*40)
            if cs == cc: cc=max(cs+1,cc*2); expected_allocations.append(cc*40)
            descriptor = bytearray(_read_span(initial,argv[1],24))
            if not descriptor[16]: descriptor[8:16]=(0x1000000000000 if descriptor[18] else 0x10000).to_bytes(8,'little')
            appended.append(bytes(descriptor)); ms+=1; cs+=1
    assert [e[2] for e in effects if e[0]=='allocate'] == expected_allocations
    mb,cb = u(pages,AST+0x60),u(pages,CB+0xB0)
    assert (u(pages,AST+0x68)-mb,u(pages,AST+0x70)-mb) == (ms*40,mc*40)
    assert (u(pages,CB+0xB8)-cb,u(pages,CB+0xC0)-cb) == (cs*40,cc*40)
    for begin,header,count in ((mb,AST+0x60,ms),(cb,CB+0xB0,cs)):
        first = u(initial,header); initial_size = (u(initial,header+8)-first)//40
        for index in range(count):
            record = begin+index*40
            assert u(pages,record) == base+0x372540
            assert _read_span(pages,record+0xC,4) == _read_span(initial,record+0xC,4)
            if index < initial_size:
                assert _read_span(pages,record+8,4) == _read_span(initial,first+index*40+8,4)
                assert _read_span(pages,record+0x10,24) == _read_span(initial,first+index*40+0x10,24)
            else:
                assert u(pages,record+8,4) == 2
                assert _read_span(pages,record+0x10,24) == appended[index-initial_size]
        if first: assert _read_span(pages,first,initial_size*40) == _read_span(initial,first,initial_size*40)
    assert _read_span(pages,INPUT,0x101) == _read_span(initial,INPUT,0x101)
    assert statuses == [0]*len(statuses)
    row.update(independent_capacity_descriptor_padding_allocation_and_borrowed_input_expectations_match=True,
        memory_entries_created=len(appended),explicit_entry_stack_context_required=False,guest_bytes_masked=False,
        native_stack_or_TLS_as_a_whole_compared=False,exact_node_budget_control='callback_max_nodes' in spec,
        **({'exact_node_budget_supported':spec['callback_max_nodes']} if 'callback_max_nodes' in spec else {}))
    return row


def negatives(args):
    base=0x122C0000; rows=[]; cases=[]
    standard=dict(label='guard',memories=(1,1),memory_cache=(1,1))
    u=lambda p,a,n=8:int.from_bytes(_read_span(p,a,n),'little')
    def add(label,changes=None,setup=None,spec=None,slot=0x70):
        cases.append((label,changes or {},setup,spec or standard,slot))
    for slot in (0x68,0x70):
        add(f'slot_binding_{slot}',setup=lambda p,slot=slot:put(p,base+0x372370+slot,0),slot=slot)
    add('attached',setup=lambda p:put(p,CB+8,INPUT))
    add('memory_vtable_GOT_binding',setup=lambda p:put(p,base+0x3750A0,0))
    for argv in ((0,),(0,INPUT,0),(-1,INPUT),(1<<64,INPUT)):
        add('arity_or_register_'+str(argv),dict(arguments=argv))
    for pointer in (0,(1<<64)-8,0x90000000,CB,AST):
        add('descriptor_pointer_'+str(pointer),dict(arguments=(0,pointer)))
    add('descriptor_memory_alias',spec={**standard,'callback_descriptor_alias':True})
    add('partial_descriptor',dict(arguments=(0,oracle.GUEST+0xAFF0)),
        setup=lambda p:p.__setitem__((oracle.GUEST+0xA000)>>12,p[(oracle.GUEST+0xA000)>>12][:4092]))
    add('output_partial_end',setup=lambda p:put(p,AST+0x68,u(p,AST+0x60)+39))
    add('output_partial_capacity',setup=lambda p:put(p,AST+0x70,u(p,AST+0x60)+41))
    add('output_node_vtable',setup=lambda p:put(p,u(p,AST+0x60),base+0x372568))
    add('output_node_destructor',setup=lambda p:put(p,base+0x372540,0))
    add('memory_cache_alias',setup=lambda p:vector(p,CB+0xB0,u(p,AST+0x60),1,1,40))
    add('unrecovered_output',setup=lambda p:vector(p,AST+0x78,INPUT,0,1,40))
    add('output_existing_capacity_bound',dict(max_nodes=3),spec=dict(label='guard',memories=(0,4)))
    add('reserve_node_bound',dict(arguments=(4,),max_nodes=3),spec=dict(label='guard',memories=(0,0)),slot=0x68)
    add('reserve_byte_bound',dict(arguments=(3,),max_vector_bytes=119),spec=dict(label='guard',memories=(0,0),definitions=[]),slot=0x68)
    add('append_total_node_bound',dict(max_nodes=4),spec={**standard,'definitions':[(0,[],[])]})
    add('append_doubled_capacity_bound',dict(max_nodes=11),spec=dict(label='guard',memories=(6,6),memory_cache=(0,0),definitions=[(0,[],[])]))
    add('append_byte_bound',dict(max_vector_bytes=79),spec=dict(label='guard',memories=(1,1),memory_cache=(0,0),definitions=[]))
    add('missing_allocator',dict(allocate=None))
    for label,changes,setup,spec,slot in cases:
        pages,_=prepare(args.library,base,spec)
        if setup: setup(pages)
        before={k:bytes(v) for k,v in pages.items()}; pointer=HEAP
        def default_allocate(size):
            nonlocal pointer
            out=pointer; pointer+=(size+15)&~15; return out
        params=dict(callback_address=CB,image_base=base,slot_offset=slot,
            arguments=(0,INPUT) if slot == 0x70 else (3,),allocate=default_allocate)
        if spec.get('callback_descriptor_alias'): params['arguments']=(0,u(pages,AST+0x60))
        params.update(changes)
        paired=label in ('reserve_node_bound','reserve_byte_bound','append_total_node_bound','append_doubled_capacity_bound','append_byte_bound')
        if paired:
            baseline,_=prepare(args.library,base,spec); pointer=HEAP
            alternative.run_reader_ast_callback(baseline,callback_address=CB,image_base=base,slot_offset=slot,
                arguments=params['arguments'],allocate=default_allocate)
            pointer=HEAP
        try: alternative.run_reader_ast_callback(pages,**params)
        except (RefillUnsupported,ValueError) as exc:
            if label in ('reserve_byte_bound','append_byte_bound'):
                assert str(exc) == 'AST requires a bounded pure allocation plan', (label,str(exc))
        else: raise AssertionError('memory guard accepted: '+label)
        assert before=={k:bytes(v) for k,v in pages.items()},label
        rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_invalid_memory_path_compared=False,
            **({'same_input_without_budget_restriction_supported':True} if paired else {}),
            **({'allocation_byte_bound_failure_verified':True} if label in ('reserve_byte_bound','append_byte_bound') else {})))
    targets=('unmapped','unaligned','partial','callback','output','memory','cache','type_params',
        'descriptor','descriptor_tail','image','retained','prior_plan')
    for stage in (1,2):
        for target in targets:
            if stage == 1 and target == 'prior_plan': continue
            pages,_=prepare(args.library,base,standard); partial=oracle.GUEST+0xAFF8
            if target == 'partial': pages[partial>>12]=pages[partial>>12][:4092]
            before={k:bytes(v) for k,v in pages.items()}; plans=[]; pointer=HEAP
            def allocate(size):
                nonlocal pointer
                out=pointer; pointer+=(size+15)&~15
                if len(plans)+1 == stage:
                    out={'unmapped':0x90000000,'unaligned':HEAP+1,'partial':partial,'callback':CB,'output':AST,
                        'memory':u(pages,AST+0x60),'cache':u(pages,CB+0xB0),'type_params':u(pages,u(pages,AST)+0x10),
                        'descriptor':INPUT,'descriptor_tail':INPUT+16,'image':base+0x6E188,
                        'retained':INPUT+0x200,'prior_plan':plans[0][1] if plans else HEAP}[target]
                plans.append((size,out)); return out
            try: alternative.run_reader_ast_callback(pages,callback_address=CB,image_base=base,slot_offset=0x70,
                arguments=(0,INPUT),allocate=allocate,reserved_regions=((INPUT+0x200,INPUT+0x300),))
            except (RefillUnsupported,ValueError): pass
            else: raise AssertionError(('memory allocation guard accepted',stage,target))
            assert len(plans)==stage and before=={k:bytes(v) for k,v in pages.items()},(stage,target)
            rows.append(dict(label=f'allocation_{stage}_{target}',rejected=True,all_pages_unchanged=True,
                allocation_plans_before_rejection=stage,native_invalid_memory_path_compared=False))
    for boundary in ('output_vtable','output_payload','output_move','output_publish','cache_vtable','cache_payload',
            'cache_move','cache_publish','reserve_move','reserve_publish','output_spare_end','cache_spare_end'):
        spec={**standard}
        if boundary.endswith('spare_end'): spec.update(memories=(1,3),memory_cache=(1,3))
        pages,_=prepare(args.library,base,spec); before={k:bytes(v) for k,v in pages.items()}
        targets={'output_vtable':HEAP+40,'output_payload':HEAP+40+0x10,'output_move':HEAP+0x10,
            'output_publish':AST+0x60,'cache_vtable':HEAP+80+40,'cache_payload':HEAP+80+40+0x10,
            'cache_move':HEAP+80+0x10,'cache_publish':CB+0xB0,'reserve_move':HEAP+0x10,
            'reserve_publish':AST+0x60,'output_spare_end':AST+0x68,'cache_spare_end':CB+0xB8}
        original=alternative._write_span; plans=[]; pointer=HEAP
        def allocate(size):
            nonlocal pointer
            out=pointer; pointer+=(size+15)&~15; plans.append((size,out)); return out
        def fail(p,address,data):
            if address==targets[boundary]: raise RefillUnsupported('injected late memory write')
            original(p,address,data)
        alternative._write_span=fail
        try:
            try: alternative.run_reader_ast_callback(pages,callback_address=CB,image_base=base,
                slot_offset=0x68 if boundary.startswith('reserve_') else 0x70,
                arguments=(3,) if boundary.startswith('reserve_') else (0,INPUT),allocate=allocate)
            except RefillUnsupported as exc: assert str(exc)=='injected late memory write'
            else: raise AssertionError('late memory guard accepted: '+boundary)
        finally: alternative._write_span=original
        assert before=={k:bytes(v) for k,v in pages.items()},boundary
        rows.append(dict(label='late_'+boundary,rejected=True,all_pages_unchanged=True,
            allocation_plans_before_rejection=len(plans),native_invalid_memory_path_compared=False))
    return rows


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library',required=True,type=Path); parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == oracle.LIBRARY_SHA256
    rows=[]; specs=fixtures(); rejected=negatives(args)
    assert len({s['label'] for s in specs}) == len(specs)
    for base in (0x122C0000,0x775C205000):
        for index,spec in enumerate(specs,1):
            rows.append(compare(args,base,spec))
            if index%24==0 or index==len(specs): print('B memory:',hex(base),index,'/',len(specs),'passed',flush=True)
    evidence=dict(schema='vm9-alternative-ast-memory-fresh-v1',evidence_date='2026-10-09',evidence_timezone='Asia/Shanghai',
        sample_sha256=oracle.LIBRARY_SHA256,generated_fixture_seed=SEED,native_Python_AST_memory_controls=len(rows),
        rollback_negative_controls=len(rejected),pre_change_behavior_RED_controls=5,
        recovered_callback_slots_hex=['0x68','0x70'],actual_native_vtable_offset_hex='0x372370',
        memory_reserve_offset_hex='0x31ccec',memory_entry_offset_hex='0x31cdb4',memory_cache_growth_offset_hex='0x31f130',
        memory_node_vtable_offset_hex='0x372540',memory_node_destructor_offset_hex='0x321368',
        memory_output_offset_hex='0x60',memory_cache_offset_hex='0xb0',memory_record_stride=40,
        descriptor_native_read_bytes=24,descriptor_copied_bytes=24,destination_padding_bytes=4,
        maximum_default32_hex='0x10000',maximum_default64_hex='0x1000000000000',
        explicit_entry_stack_context_required=False,guest_bytes_masked=False,all_fixtures_synthetic=True,
        native_input_snapshot_used=False,private_payloads_published=False,memory_count_entry_callbacks_implemented=True,
        parser_AST_composition_implemented=False,attached_parser_implemented=False,complete_AST_callbacks_implemented=False,
        complete_output_wrapper_cleanup_implemented=False,complete_python_reader_implemented=False,independent_Python_factory_implemented=False,
        complete_python_bootstrap_controls=0,complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False,cases=rows,negative_cases=rejected)
    args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    print('B memory:',len(rows),'native/Python +',len(rejected),'rollback checks passed',flush=True)


if __name__=='__main__': main()
