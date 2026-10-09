"""Fresh actual B table reserve/entry with explicit native stack padding.

Synthetic fixtures execute the relocated vtable without masking guest bytes.
The real entry SP supplies the unwritten temporary word copied into records.
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
ENTRY_SP = oracle.GUEST+0xEF00
FUNCTIONS = {**function.FUNCTIONS,0x58:0x31C9F4,0x60:0x31CABC}
SEED = 0x31CABC

def prepare(library,base,spec):
    pages,sizes = function.prepare(library,base,{k:v for k,v in spec.items() if k != 'cleanup'})
    pointer = max([function.controls.OLD]+[p+((max(n,1)+15)&~15) for p,n in sizes.items()])
    for header,(size,capacity),marker in ((AST+0x48,spec.get('tables',(0,0)),0xB1),
            (CB+0x98,spec.get('table_cache',(0,0)),0xC1)):
        if not capacity and not spec.get('nonnull_empty'):
            vector(pages,header); continue
        begin = pointer; pointer += (max(capacity*48,1)+15)&~15
        assert pointer < INPUT
        sizes[begin] = capacity*48
        _write_span(pages,begin,bytes([marker])*max(capacity*48,1))
        vector(pages,header,begin,size,capacity,48)
        for index in range(size):
            record = begin+index*48
            put(pages,record,base+0x372518); put(pages,record+8,0xD00D0000+index,4)
    for offset in range(0,0x100,32):
        descriptor = bytearray((i+offset)&255 for i in range(24))
        descriptor[16] = spec.get('descriptor_flag',0)
        _write_span(pages,INPUT+offset+spec.get('descriptor_unaligned',0),descriptor)
    put(pages,ENTRY_SP-0x7C,spec.get('temporary_padding',0xA5A5A5A5),4)
    return pages,sizes

def minimal_specs():
    return [dict(label='table_reserve_existing_growth',tables=(1,1),table_cache=(0,0),callbacks=[(0x58,(3,))]),
        dict(label='table_reserve_high_u32_noop',tables=(1,2),table_cache=(1,2),callbacks=[(0x58,(0xFFFFFFFF00000001,))]),
        dict(label='table_entry_spare_no_maximum',tables=(1,3),table_cache=(1,3),entry_stack_address=ENTRY_SP,
            callbacks=[(0x60,(0xFFFFFFFFFFFFFFFF,0x8000000012345678,INPUT))]),
        dict(label='table_entry_output_cache_growth',tables=(1,1),table_cache=(1,1),descriptor_flag=9,
            entry_stack_address=ENTRY_SP,temporary_padding=0x11223344,callbacks=[(0x60,(0,0xFFFFFFFFFFFFFFF0,INPUT))])]

def fixtures():
    cases = minimal_specs()
    for size,capacity in ((0,0),(0,2),(1,1),(2,3)):
        for count in (0,1,2,5):
            cases.append(dict(label=f'reserve_{size}_{capacity}_{count}',tables=(size,capacity),
                table_cache=(1,2),callbacks=[(0x58,((0xFFFFFFFF<<32)|count,))],cleanup=True))
    for tables in ((0,0),(0,2),(1,1),(2,3)):
        for cache in ((0,0),(0,2),(1,1),(2,3)):
            for flag in (0,1,9):
                cases.append(dict(label=f'entry_{tables}_{cache}_{flag}',tables=tables,table_cache=cache,
                    descriptor_flag=flag,entry_stack_address=ENTRY_SP,callbacks=[(0x60,(99,0xFFFFFFFFFFFFFFF0,INPUT))],cleanup=True))
    for padding in (0,0x11223344,0x88776655,0xFFFFFFFF):
        cases.append(dict(label=f'temporary_padding_{padding}',tables=(1,3),table_cache=(1,3),
            entry_stack_address=ENTRY_SP,temporary_padding=padding,descriptor_flag=1,
            callbacks=[(0x60,(0,0x123456789ABCDEF0,INPUT))],cleanup=True))
    for bits in (0,0xFFFFFFFF,0x100000001,0xFFFFFFFFFFFFFFFF):
        cases.append(dict(label=f'full_type_{bits}',tables=(0,0),table_cache=(0,0),entry_stack_address=ENTRY_SP,
            callbacks=[(0x60,(bits,bits,INPUT))],cleanup=True))
    for count,budget in ((1,5),(6,12)):
        cases.append(dict(label=f'exact_table_node_budget_{count}_{budget}',tables=(count,count),
            table_cache=(1,1) if count == 1 else (0,0),definitions=[(0,[],[])],entry_stack_address=ENTRY_SP,
            callback_max_nodes=budget,callbacks=[(0x60,(0,7,INPUT))],cleanup=True))
    cases += [dict(label='table_nonnull_zero_capacity',tables=(0,0),table_cache=(0,0),nonnull_empty=True,
            entry_stack_address=ENTRY_SP,callbacks=[(0x58,(0,)),(0x60,(0,7,INPUT))],cleanup=True),
        dict(label='table_unaligned_descriptor',tables=(1,2),table_cache=(0,0),descriptor_unaligned=1,
            entry_stack_address=ENTRY_SP,callbacks=[(0x60,(0,0x8000000012345678,INPUT+1))],cleanup=True),
        dict(label='table_repeated_reserve',tables=(1,1),table_cache=(1,2),
            callbacks=[(0x58,(n,)) for n in (0,2,2,1,5,6)],cleanup=True),
        dict(label='table_repeated_append',tables=(1,1),table_cache=(2,2),entry_stack_address=ENTRY_SP,
            callbacks=[(0x60,(i,0x8000000000000000+i,INPUT+i*32)) for i in range(7)],cleanup=True),
        dict(label='table_reserve_append_reserve',tables=(0,0),table_cache=(1,1),entry_stack_address=ENTRY_SP,
            callbacks=[(0x58,(3,)),(0x60,(99,0xFFFFFFFFFFFFFFF0,INPUT)),(0x58,(1,)),
                (0x60,(77,0x8000000012345678,INPUT+32)),(0x58,(5,))],cleanup=True),
        dict(label='table_with_owned_functions_and_outputs',tables=(1,1),table_cache=(1,1),
            function_vector=(1,1),cache_vector=(1,1),data_vector=(1,1),element_vector=(1,1),owned_mode='rich',
            entry_stack_address=ENTRY_SP,callbacks=[(0x60,(0,7,INPUT))],
            destroy_function=True,destroy_data=True,destroy_element=True,cleanup=True)]
    rng = random.Random(SEED)
    for index in range(8):
        size,cache_size = rng.randrange(3),rng.randrange(3)
        cases.append(dict(label=f'generated_table_{index}',tables=(size,size+rng.randrange(2)),
            table_cache=(cache_size,cache_size+rng.randrange(2)),descriptor_flag=rng.randrange(256),
            temporary_padding=rng.getrandbits(32),entry_stack_address=ENTRY_SP,
            callbacks=[(0x60,(rng.getrandbits(64),rng.getrandbits(64),INPUT))],cleanup=True))
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
                slot_offset=slot,arguments=argv,allocate=allocate,entry_stack_address=ENTRY_SP,
                max_nodes=spec['callback_max_nodes'])
            bounded_effects.extend(result.effects); bounded_statuses.append(result.status)
        assert _read_span(bounded,oracle.GUEST,0xA000) == _read_span(pages,oracle.GUEST,0xA000)
        assert [(e.kind,e.address,e.size,e.owner_address,e.owner_bytes) for e in bounded_effects] == effects
        assert bounded_statuses == statuses
    u = lambda p,a,n=8:int.from_bytes(_read_span(p,a,n),'little')
    ts,tc = spec.get('tables',(0,0)); cs,cc = spec.get('table_cache',(0,0))
    expected_allocations = []; appended = []
    for slot,argv in spec.get('callbacks',[]):
        if slot == 0x58:
            requested = argv[0]&0xFFFFFFFF
            if requested > tc: tc=requested; expected_allocations.append(tc*48)
        else:
            assert slot == 0x60
            if ts == tc: tc=max(ts+1,tc*2); expected_allocations.append(tc*48)
            if cs == cc: cc=max(cs+1,cc*2); expected_allocations.append(cc*48)
            descriptor = bytearray(_read_span(initial,argv[2],19))
            if not descriptor[16]: descriptor[8:16]=(0xFFFFFFFF).to_bytes(8,'little')
            appended.append((argv[1],bytes(descriptor))); ts+=1; cs+=1
    assert [e[2] for e in effects if e[0]=='allocate'] == expected_allocations
    tb,cb = u(pages,AST+0x48),u(pages,CB+0x98)
    assert (u(pages,AST+0x50)-tb,u(pages,AST+0x58)-tb) == (ts*48,tc*48)
    assert (u(pages,CB+0xA0)-cb,u(pages,CB+0xA8)-cb) == (cs*48,cc*48)
    for begin,initial_size in ((tb,spec.get('tables',(0,0))[0]),(cb,spec.get('table_cache',(0,0))[0])):
        for index,(bits,descriptor) in enumerate(appended,initial_size):
            record = begin+index*48
            assert u(pages,record) == base+0x372518 and u(pages,record+8,4) == 1
            assert u(pages,record+0xC) == bits
            assert u(pages,record+0x14,4) == spec.get('temporary_padding',0xA5A5A5A5)
            assert _read_span(pages,record+0x18,19) == descriptor
    assert _read_span(pages,INPUT,0x100) == _read_span(initial,INPUT,0x100)
    assert _read_span(pages,ENTRY_SP-0x7C,4) == _read_span(initial,ENTRY_SP-0x7C,4)
    assert statuses == [0]*len(statuses)
    row.update(independent_capacity_type_descriptor_padding_allocation_and_borrowed_input_expectations_match=True,
        table_entries_created=len(appended),native_stack_padding_explicit=bool(appended),
        native_stack_or_TLS_as_a_whole_compared=False,guest_bytes_masked=False,
        exact_node_budget_control='callback_max_nodes' in spec,
        **({'exact_node_budget_supported':spec['callback_max_nodes']} if 'callback_max_nodes' in spec else {}))
    return row

def negatives(args):
    base=0x122C0000; rows=[]; cases=[]
    standard=dict(label='guard',tables=(1,1),table_cache=(1,1),entry_stack_address=ENTRY_SP)
    u=lambda p,a,n=8:int.from_bytes(_read_span(p,a,n),'little')
    def add(label,changes=None,setup=None,spec=None,slot=0x60):
        cases.append((label,changes or {},setup,spec or standard,slot))
    for slot in (0x58,0x60):
        add(f'slot_binding_{slot}',setup=lambda p,slot=slot:put(p,base+0x372370+slot,0),slot=slot)
    add('attached',setup=lambda p:put(p,CB+8,INPUT))
    add('table_vtable_GOT_binding',setup=lambda p:put(p,base+0x375098,0))
    for argv in ((0,7),(0,7,INPUT,0),(-1,7,INPUT),(0,1<<64,INPUT)):
        add('arity_or_register_'+str(argv),dict(arguments=argv))
    for value in (None,[],0x90,ENTRY_SP+1,1<<64,0x90000000,AST+0xB0,CB+0xB0,base+0x1000):
        add('entry_stack_'+str(value),dict(entry_stack_address=value))
    add('partial_stack_frame',setup=lambda p:p.__setitem__(ENTRY_SP>>12,p[ENTRY_SP>>12][:0xE60]))
    for pointer in (0,(1<<64)-8,0x90000000,CB,AST,ENTRY_SP-0x7C):
        add('descriptor_pointer_'+str(pointer),dict(arguments=(0,7,pointer)))
    add('descriptor_table_alias',setup=lambda p:_write_span(p,INPUT,bytes(24)),
        spec={**standard,'callback_descriptor_alias':True})
    add('partial_descriptor',dict(arguments=(0,7,oracle.GUEST+0xAFF0)),
        setup=lambda p:p.__setitem__((oracle.GUEST+0xA000)>>12,p[(oracle.GUEST+0xA000)>>12][:4092]))
    add('output_partial_end',setup=lambda p:put(p,AST+0x50,u(p,AST+0x48)+1))
    add('output_partial_capacity',setup=lambda p:put(p,AST+0x58,u(p,AST+0x48)+49))
    add('cache_partial_end',setup=lambda p:put(p,CB+0xA0,u(p,CB+0x98)+1))
    add('cache_partial_capacity',setup=lambda p:put(p,CB+0xA8,u(p,CB+0x98)+49))
    add('output_unknown_node',setup=lambda p:put(p,u(p,AST+0x48),base))
    add('cache_unknown_node',setup=lambda p:put(p,u(p,CB+0x98),base))
    add('node_destructor_binding',setup=lambda p:put(p,base+0x372518,0))
    add('table_cache_alias',setup=lambda p:vector(p,CB+0x98,u(p,AST+0x48),1,1,48))
    add('output_existing_capacity_bound',dict(max_nodes=3),spec=dict(label='guard',tables=(0,4)))
    add('reserve_node_bound',dict(arguments=(4,),max_nodes=3),spec=dict(label='guard',tables=(0,0)),slot=0x58)
    add('reserve_byte_bound',dict(arguments=(4,),max_vector_bytes=191),spec=dict(label='guard',tables=(0,0),definitions=[]),slot=0x58)
    add('append_total_node_bound',dict(max_nodes=4),spec=dict(label='guard',tables=(1,1),table_cache=(1,1),definitions=[(0,[],[])]))
    add('append_doubled_capacity_bound',dict(max_nodes=11),spec=dict(label='guard',tables=(6,6),table_cache=(0,0),definitions=[(0,[],[])]))
    add('append_byte_bound',dict(max_vector_bytes=95),spec=dict(label='guard',tables=(1,1),table_cache=(0,0),definitions=[]))
    add('missing_allocator',dict(allocate=None))
    for label,changes,setup,spec,slot in cases:
        pages,_=prepare(args.library,base,spec)
        if setup: setup(pages)
        before={k:bytes(v) for k,v in pages.items()}
        next_pointer=HEAP
        def default_allocate(size):
            nonlocal next_pointer
            out=next_pointer; next_pointer+=(size+15)&~15; return out
        params=dict(callback_address=CB,image_base=base,slot_offset=slot,
            arguments=(0,7,INPUT) if slot == 0x60 else (3,),allocate=default_allocate,entry_stack_address=ENTRY_SP)
        if spec.get('callback_descriptor_alias'): params['arguments']=(0,7,u(pages,AST+0x48))
        params.update(changes)
        paired=label in ('reserve_node_bound','reserve_byte_bound','append_total_node_bound','append_doubled_capacity_bound','append_byte_bound')
        if paired:
            baseline,_=prepare(args.library,base,spec); pointer=HEAP
            def planned(size):
                nonlocal pointer
                out=pointer; pointer+=(size+15)&~15; return out
            alternative.run_reader_ast_callback(baseline,callback_address=CB,image_base=base,slot_offset=slot,
                arguments=params['arguments'],allocate=planned,entry_stack_address=ENTRY_SP)
        try: alternative.run_reader_ast_callback(pages,**params)
        except (RefillUnsupported,ValueError) as exc:
            if label in ('reserve_byte_bound','append_byte_bound'):
                assert str(exc) == 'AST requires a bounded pure allocation plan', (label,str(exc))
        else: raise AssertionError('table guard accepted: '+label)
        assert before=={k:bytes(v) for k,v in pages.items()},label
        rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_invalid_memory_path_compared=False,
            **({'same_input_without_budget_restriction_supported':True} if paired else {}),
            **({'allocation_byte_bound_failure_verified':True} if label in ('reserve_byte_bound','append_byte_bound') else {})))
    targets=('unmapped','unaligned','partial','callback','output','table','cache','type_params','frame',
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
                        'table':u(pages,AST+0x48),'cache':u(pages,CB+0x98),
                        'type_params':u(pages,u(pages,AST)+0x10),'frame':ENTRY_SP-0xB0,
                        'descriptor':INPUT,'descriptor_tail':INPUT+16,'image':base+0x6E188,
                        'retained':INPUT+0x200,'prior_plan':plans[0][1] if plans else HEAP}[target]
                plans.append((size,out)); return out
            try: alternative.run_reader_ast_callback(pages,callback_address=CB,image_base=base,slot_offset=0x60,
                arguments=(0,7,INPUT),allocate=allocate,entry_stack_address=ENTRY_SP,
                reserved_regions=((INPUT+0x200,INPUT+0x300),))
            except (RefillUnsupported,ValueError): pass
            else: raise AssertionError(('table allocation guard accepted',stage,target))
            assert len(plans)==stage and before=={k:bytes(v) for k,v in pages.items()},(stage,target)
            rows.append(dict(label=f'allocation_{stage}_{target}',rejected=True,all_pages_unchanged=True,
                allocation_plans_before_rejection=stage,native_invalid_memory_path_compared=False))
    for boundary in ('output_vtable','output_payload','output_move','output_publish','cache_vtable','cache_payload','cache_move','cache_publish','reserve_publish'):
        spec={**standard}; pages,_=prepare(args.library,base,spec); before={k:bytes(v) for k,v in pages.items()}
        targets={'output_vtable':HEAP+48,'output_payload':HEAP+48+0xC,'output_move':HEAP+0xC,'output_publish':AST+0x48,
            'cache_vtable':HEAP+96+48,'cache_payload':HEAP+96+48+0xC,'cache_move':HEAP+96+0xC,
            'cache_publish':CB+0x98,'reserve_publish':AST+0x48}
        original=alternative._write_span; plans=[]; pointer=HEAP
        def allocate(size):
            nonlocal pointer
            out=pointer; pointer+=(size+15)&~15; plans.append((size,out)); return out
        def fail(p,address,data):
            if address==targets[boundary]: raise RefillUnsupported('injected late table write')
            original(p,address,data)
        alternative._write_span=fail
        try:
            try: alternative.run_reader_ast_callback(pages,callback_address=CB,image_base=base,
                slot_offset=0x58 if boundary == 'reserve_publish' else 0x60,
                arguments=(3,) if boundary == 'reserve_publish' else (0,7,INPUT),
                allocate=allocate,entry_stack_address=ENTRY_SP)
            except RefillUnsupported: pass
            else: raise AssertionError('late table guard accepted: '+boundary)
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
            if index%24==0 or index==len(specs): print('B table:',hex(base),index,'/',len(specs),'passed',flush=True)
    evidence=dict(schema='vm9-alternative-ast-table-fresh-v1',evidence_date='2026-10-09',evidence_timezone='Asia/Shanghai',
        sample_sha256=oracle.LIBRARY_SHA256,generated_fixture_seed=SEED,native_Python_AST_table_controls=len(rows),
        rollback_negative_controls=len(rejected),pre_change_behavior_RED_controls=4,
        recovered_callback_slots_hex=['0x58','0x60'],actual_native_vtable_offset_hex='0x372370',
        table_reserve_offset_hex='0x31c9f4',table_entry_offset_hex='0x31cabc',table_cache_growth_offset_hex='0x31ef9c',
        table_node_vtable_offset_hex='0x372518',table_clone_offset_hex='0x3210d0',
        table_output_offset_hex='0x48',table_cache_offset_hex='0x98',table_record_stride=48,
        descriptor_native_read_bytes=24,descriptor_copied_bytes=19,temporary_padding_bytes=4,
        explicit_entry_stack_context_required=True,guest_bytes_masked=False,all_fixtures_synthetic=True,
        native_input_snapshot_used=False,private_payloads_published=False,table_count_entry_callbacks_implemented=True,
        parser_AST_composition_implemented=False,attached_parser_implemented=False,complete_AST_callbacks_implemented=False,
        complete_python_reader_implemented=False,independent_Python_factory_implemented=False,
        complete_python_bootstrap_controls=0,complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False,cases=rows,negative_cases=rejected)
    args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    print('B table:',len(rows),'native/Python +',len(rejected),'rollback checks passed',flush=True)

if __name__=='__main__': main()
