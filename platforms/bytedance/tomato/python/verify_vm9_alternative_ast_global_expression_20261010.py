"""Fresh B global expression frames, full-u64 ends and owned active controls."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

import verify_vm9_alternative_ast_global_20261009 as global_ast
import verify_vm9_alternative_ast_data_expression_20261009 as expression
import verify_vm9_alternative_ast_instruction_20261009 as instruction
import verify_vm9_signer_objects as oracle
import vm9_alternative_startup as alternative
from vm9_allocator import RefillUnsupported, _read_span, _write_span

controls = global_ast.function.controls
CB, AST, INPUT, HEAP = global_ast.CB, global_ast.AST, global_ast.INPUT, global_ast.HEAP
put, vector = global_ast.put, global_ast.vector
FUNCTIONS = {**global_ast.FUNCTIONS, **instruction.FUNCTIONS,
    0x88:0x31D45C, 0x90:0x31D4AC}


def prepare(library, base, spec):
    pages, sizes = global_ast.prepare(library, base, spec)
    if 'active_global' in spec:
        begin = int.from_bytes(_read_span(pages, AST+0x78, 8), 'little')
        put(pages, CB+0x28, begin+spec['active_global']*176+0x18)
    return pages, sizes


def minimal_specs():
    return [dict(label='global_begin_allocates_frame', globals=(1,1), raw_vector=(11,17),
                callbacks=[(0x88,(0xFFFFFFFFFFFFFFFF,))]),
        dict(label='global_begin_resets_rich_frames', globals=(2,3), global_mode='rich', frames=(3,3),
                raw_vector=(3,9), callbacks=[(0x88,(0xFFFFFFFF00000001,))]),
        dict(label='global_end_full_u64_fixup_growth', globals=(1,1), frames=(1,1), raw_vector=(7,9),
                tree=[(0,None,None,1,[1,32])], callbacks=[(0x90,(99,0xFEDCBA9876543210))]),
        dict(label='global_owned_active_local', globals=(1,1), active_global=0,
                callbacks=[(0xB8,(99,0x100000002,0xFFFFFFFFFFFFFFEF))]),
        dict(label='global_owned_active_function_end', globals=(1,1), active_global=0,
                callbacks=[(0xF8,(99,0xFFFFFFFF12345678))])]


def compare(args, base, spec):
    row = controls.compare(args, base, spec, functions=FUNCTIONS, prepare_case=prepare)
    observed = {k:v for k,v in spec.items() if k not in ('destroy_global','cleanup')}
    pages, _, statuses = controls.model_case(args, base, observed, prepare_case=prepare)
    initial, _ = prepare(args.library, base, observed)
    u = lambda p,a,n=8:int.from_bytes(_read_span(p,a,n),'little')
    raw = bytearray(b'\x35'*spec.get('raw_vector',(0,0))[0])
    frames, capacity = spec.get('frames',(0,0))
    count = spec.get('globals',(0,0))[0]
    starts, ends, lengths, local_groups = {}, {}, {}, {}
    active = spec.get('active_global')
    expected_active = u(initial,CB+0x28)
    keys = {node[0]:node[4] for node in spec.get('tree',[])}
    expected_statuses = []; cumulative = u(initial,CB+0x7C,4)
    entry_count = 0
    for slot, argv in spec.get('callbacks',[]):
        status = 0
        if slot == 0x80: count += 1; entry_count += 1
        elif slot == 0x88:
            active = count-1; starts[active] = len(raw)
            frames = 1
            if capacity == 0: capacity = 1
            expected_active = u(pages,AST+0x78)+active*176+0x18
        elif slot == 0x90: ends[count-1] = argv[1]
        elif slot == 0xC0: status = int(not expected_active or not frames)
        elif slot in instruction.TYPES:
            tag, width = instruction.TYPES[slot]
            raw.extend(tag.to_bytes(4,'little'))
            raw.extend((argv[0]&((1<<(width*8))-1)).to_bytes(width,'little'))
        elif slot in (0xF0,0x168):
            raw.extend((0 if slot==0xF0 else argv[0]&0xFFFFFFFF).to_bytes(4,'little'))
        elif slot == 0xB0: cumulative = 0
        elif slot == 0xB8:
            amount = argv[1]&0xFFFFFFFF; cumulative = (cumulative+amount)&0xFFFFFFFF
            local_groups.setdefault(active,[]).append((argv[2],amount,cumulative))
        elif slot == 0xF8:
            lengths[active] = argv[1]&0xFFFFFFFF; expected_active = 0; active = None
        if slot == 0x90 or (slot == 0xC8 and frames != 1):
            for position in keys.pop(frames-1,[]):
                old_length = len(raw)
                if position+4>old_length: raw.extend(bytes(position+4-old_length))
                raw[position:position+4] = old_length.to_bytes(4,'little')
            frames -= 1
        expected_statuses.append(status)
    assert statuses == expected_statuses
    begin = u(pages,AST+0x108)
    assert u(pages,AST+0x110)-begin == len(raw)
    assert _read_span(pages,begin,len(raw)) == raw
    begin = u(pages,CB+0x30)
    assert (u(pages,CB+0x38)-begin,u(pages,CB+0x40)-begin) == (frames*16,capacity*16)
    assert u(pages,CB+0x58) == len(keys)
    assert u(pages,CB+0x28) == expected_active
    if any(slot==0x88 for slot,_ in spec.get('callbacks',[])):
        assert _read_span(pages,begin,16) == _read_span(pages,base+0x6E188,8)+bytes([255])*8
    output_begin = u(pages,AST+0x78)
    original_count = spec.get('globals',(0,0))[0]
    for index in range(count):
        record = output_begin+index*176
        previous = u(initial,AST+0x78)+index*176
        initial_start = u(initial,previous+0x80,4) if index<original_count else 0xFFFFFFFF
        initial_end = u(initial,previous+0xA8) if index<original_count else 0
        assert u(pages,record+0x80,4) == starts.get(index,initial_start)
        assert u(pages,record+0xA8) == ends.get(index,initial_end)
        if index in lengths: assert u(pages,record+0x88,4) == lengths[index]
        if index in local_groups:
            pointer = u(pages,record+0x68); end = u(pages,record+0x70)
            groups = local_groups[index]
            expected = b''.join(t.to_bytes(8,'little')+n.to_bytes(4,'little')+c.to_bytes(4,'little') for t,n,c in groups)
            assert _read_span(pages,end-len(expected),len(expected)) == expected
            assert end-pointer >= len(expected)
    if spec.get('callback_max_nodes') is not None:
        bounded, _ = prepare(args.library,base,observed); pointer = HEAP
        def allocate(size):
            nonlocal pointer
            out=pointer; pointer+=(size+15)&~15; return out
        for slot, argv in spec.get('callbacks',[]):
            alternative.run_reader_ast_callback(bounded,callback_address=CB,image_base=base,
                slot_offset=slot,arguments=argv,allocate=allocate,max_nodes=spec['callback_max_nodes'])
        assert _read_span(bounded,oracle.GUEST,0xA000)==_read_span(pages,oracle.GUEST,0xA000)
    row.update(independent_frame_raw_full_u64_end_active_and_local_expectations_match=True,
        global_entries_created=entry_count,actual_global_record_destructor_executed=bool(spec.get('destroy_global')),
        guest_bytes_masked=False,native_stack_or_TLS_as_a_whole_compared=False,
        exact_node_budget_control='callback_max_nodes' in spec,
        **({'exact_node_budget_supported':spec['callback_max_nodes']} if 'callback_max_nodes' in spec else {}))
    return row


def fixtures():
    cases = minimal_specs()
    for length in (0,1,3,4,11,32):
        for frames in ((0,0),(0,3),(2,3),(3,3)):
            cases.append(dict(label=f'begin_{length}_{frames[0]}_{frames[1]}',globals=(2,3),
                raw_vector=(length,length+5),frames=frames,callbacks=[(0x88,(0xFFFFFFFFFFFFFFFF,))],
                destroy_global=True,cleanup=True))
    for value in (0,1,0xFFFFFFFF,0x100000001,0x8000000012345678,0xFFFFFFFFFFFFFFFF):
        cases.append(dict(label=f'end_full_u64_{value}',globals=(2,3),frames=(1,2),active_global=0,
            callbacks=[(0x90,(0xFFFFFFFFFFFFFFFF,value)),(0xC0,(99,))],callback_statuses=[0,1],
            destroy_global=True,cleanup=True))
    for mode in ('null','empty','rich','mixed'):
        cases.append(dict(label='owned_'+mode,globals=(2,3),global_mode=mode,raw_vector=(3,9),frames=(3,4),
            tree=[(0,None,None,1,[1,32])],callbacks=[(0x88,(99,)),(0xE8,(0xFFFFFFFFFFFFFFEF,)),
                (0xC8,()),(0x90,(77,0xFEDCBA9876543210))],destroy_global=True,cleanup=True))
    for original in expression.fixtures():
        if not any(slot==0x150 for slot,_ in original.get('callbacks',[])): continue
        if any(slot not in (0x148,0x150,0x168) for slot,_ in original['callbacks']): continue
        spec = {k:v for k,v in original.items() if k not in ('data_vector','destroy_data','label','callbacks')}
        spec.update(label='global_'+original['label'],globals=(2,3),destroy_global=True,
            callbacks=[(0x88,argv) if slot==0x148 else (0x90,(argv[0],0x8000000012345678))
                if slot==0x150 else (slot,argv) for slot,argv in original['callbacks']])
        cases.append(spec)
    cases += [dict(label='create_begin_all_constants_end_cleanup',globals=(1,1),global_cache=(1,1),global_mode='rich',
        callbacks=[(0x80,(99,0xFFFFFFFFFFFFFFF0,3)),(0x88,(0,)),(0xC0,(4,)),(0xD0,(0x7FC00001,)),
            (0xD8,(0x7FF8000000000001,)),(0xE0,(0xFFFFFFFF80000000,)),(0xE8,(0x8000000000000000,)),
            (0xF0,()),(0x168,(0x12345678,)),(0xC8,()),(0x90,(1,0xFFFFFFFFFFFFFFFF)),(0xC0,(0,))],
        callback_statuses=[0]*10+[0,1],destroy_global=True,cleanup=True),
        dict(label='repeated_begin_end_preserves_tail_and_active',globals=(1,1),frames=(3,3),raw_vector=(3,9),
            callbacks=[(0x88,(99,)),(0x168,(7,)),(0x90,(0,0x8000000000000000)),
                (0x88,(1,)),(0x168,(9,)),(0x90,(0,0xFFFFFFFFFFFFFFFF)),(0x88,(99,))],destroy_global=True,cleanup=True),
        dict(label='begin_overridden_constant',globals=(1,1),frame_constant=0x8877665544332211,
            callbacks=[(0x88,(0,)),(0x90,(0,0x1122334455667788))],cleanup=True),
        dict(label='owned_other_outputs',globals=(1,1),global_mode='rich',function_vector=(1,1),
            data_vector=(1,1),element_vector=(1,1),owned_mode='rich',
            callbacks=[(0x88,(0,)),(0x90,(0,7))],destroy_global=True,cleanup=True)]
    for mode in ('null','empty','rich'):
        for amount in (0,0x100000002,0xFFFFFFFF):
            cases.append(dict(label=f'global_active_locals_end_{mode}_{amount}',globals=(1,1),global_mode=mode,
                callbacks=[(0x88,(0,)),(0xB0,(0xFFFFFFFF,)),(0xB8,(99,amount,0xFFFFFFFFFFFFFFEF)),
                    (0xB8,(7,2,0x8000000012345678)),(0x90,(0,0xFEDCBA9876543210)),
                    (0xF8,(99,0xFFFFFFFF12345678)),(0xC0,(0,))],callback_statuses=[0]*6+[1],
                destroy_global=True,cleanup=True))
    cases.append(dict(label='exact_global_expression_node_budget',definitions=[],globals=(1,1),frames=(0,0),
        callback_max_nodes=2,callbacks=[(0x88,(0,)),(0x90,(0,7))],destroy_global=True,cleanup=True))
    return cases


def negatives(args):
    base=0x122C0000; rows=[]; cases=[]
    standard=dict(label='guard',globals=(1,1),frames=(1,1),raw_vector=(7,9),tree=[(0,None,None,1,[1,32])])
    u=lambda p,a,n=8:int.from_bytes(_read_span(p,a,n),'little')
    def add(label,changes=None,setup=None,spec=None,slot=0x90):
        cases.append((label,changes or {},setup,standard if spec is None else spec,slot))
    for slot in (0x88,0x90):
        add(f'slot_binding_{slot}',setup=lambda p,slot=slot:put(p,base+0x372370+slot,0),slot=slot)
    add('attached',setup=lambda p:put(p,CB+8,INPUT))
    for slot,values in ((0x88,()),(0x88,(0,1)),(0x88,(-1,)),(0x90,(0,)),
                        (0x90,(0,7,8)),(0x90,(0,1<<64)),(0x90,(-1,7))):
        add('arity_register_'+str((slot,values)),dict(arguments=values),slot=slot)
    add('begin_no_global',spec=dict(label='guard'),slot=0x88)
    add('end_no_global',spec=dict(label='guard',frames=(1,1)))
    add('end_no_frame',spec=dict(label='guard',globals=(1,1)))
    add('partial_global',setup=lambda p:put(p,AST+0x80,u(p,AST+0x78)+175))
    add('global_inline_vtable',setup=lambda p:put(p,u(p,AST+0x78)+0x18,0))
    add('partial_frame',setup=lambda p:put(p,CB+0x38,u(p,CB+0x30)+1))
    add('partial_frame_capacity',setup=lambda p:put(p,CB+0x40,u(p,CB+0x40)+1))
    add('tree_count',setup=lambda p:put(p,CB+0x58,2))
    add('tree_root_parent',setup=lambda p:put(p,u(p,CB+0x50)+0x10,CB))
    add('tree_payload_alias_global',setup=lambda p:vector(p,u(p,CB+0x50)+0x28,u(p,AST+0x78),1,2,4))
    add('frame_alias_global',setup=lambda p:vector(p,CB+0x30,u(p,AST+0x78),1,2,16))
    add('begin_node_budget',dict(max_nodes=1),spec=dict(label='guard',definitions=[],globals=(1,1)),slot=0x88)
    add('frame_capacity_budget',dict(max_nodes=2),spec=dict(label='guard',definitions=[],globals=(1,1),frames=(1,3)))
    add('fixup_byte_budget',dict(max_vector_bytes=200),spec=dict(label='guard',globals=(1,1),
        frames=(1,1),raw_vector=(7,9),tree=[(0,None,None,1,[1,256])]))
    add('fixup_u32_wrap',spec=dict(label='guard',globals=(1,1),frames=(1,1),tree=[(0,None,None,1,[0xFFFFFFFF])]))
    add('missing_allocator',dict(allocate=None))
    add('begin_missing_allocator',dict(allocate=None),spec=dict(label='guard',globals=(1,1)),slot=0x88)
    add('late_duplicate_allocation',dict(allocate=lambda size:HEAP),spec=dict(label='guard',globals=(1,1),
        frames=(1,1),tree=[(0,None,None,1,[0,32,128])]))
    # Pair budget rejections with the same valid input at ordinary bounds.
    paired={'begin_node_budget','frame_capacity_budget','fixup_byte_budget'}
    for label,changes,setup,spec,slot in cases:
        pages,_=prepare(args.library,base,spec)
        if setup: setup(pages)
        before={k:bytes(v) for k,v in pages.items()}; pointer=HEAP
        def allocate(size):
            nonlocal pointer
            out=pointer; pointer+=(size+15)&~15; return out
        params=dict(callback_address=CB,image_base=base,slot_offset=slot,
            arguments=(0,) if slot==0x88 else (0,0xFEDCBA9876543210),allocate=allocate)
        params.update(changes)
        if label in paired:
            baseline,_=prepare(args.library,base,spec)
            alternative.run_reader_ast_callback(baseline,callback_address=CB,image_base=base,
                slot_offset=slot,arguments=params['arguments'],allocate=allocate); pointer=HEAP
        try: alternative.run_reader_ast_callback(pages,**params)
        except (RefillUnsupported,ValueError): pass
        else: raise AssertionError('global expression guard accepted: '+label)
        assert before=={k:bytes(v) for k,v in pages.items()},label
        rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_invalid_memory_path_compared=False,
            **({'same_input_without_budget_restriction_supported':True} if label in paired else {})))
    for slot in (0x88,0x90):
        for label in ('unmapped','unaligned','partial','callback','output','global','frame','tree','payload','raw','image','retained'):
            spec=dict(standard) if slot==0x90 else dict(label='guard',globals=(1,1))
            pages,_=prepare(args.library,base,spec)
            partial=oracle.GUEST+0xAFF8
            if label=='partial': pages[partial>>12]=pages[partial>>12][:4092]
            targets=dict(unmapped=0x90000000,unaligned=HEAP+1,partial=partial,
                callback=CB,output=AST,global_=u(pages,AST+0x78),frame=u(pages,CB+0x30),
                tree=u(pages,CB+0x50),raw=u(pages,AST+0x108),image=base+0x6E188,retained=INPUT)
            targets['global']=targets.pop('global_')
            targets['payload']=u(pages,targets['tree']+0x28) if targets['tree'] else INPUT
            if slot==0x88 and label in ('frame','tree','payload','raw'): continue
            before={k:bytes(v) for k,v in pages.items()}
            try: alternative.run_reader_ast_callback(pages,callback_address=CB,image_base=base,slot_offset=slot,
                arguments=(0,) if slot==0x88 else (0,7),allocate=lambda size:targets[label],
                reserved_regions=((INPUT,32),) if label=='retained' else ())
            except (RefillUnsupported,ValueError): pass
            else: raise AssertionError('allocation guard accepted: '+str((slot,label)))
            assert before=={k:bytes(v) for k,v in pages.items()},(slot,label)
            rows.append(dict(label=f'allocation_{slot}_{label}',rejected=True,all_pages_unchanged=True,native_invalid_memory_path_compared=False))
    # Inject write failures after active/reset or full-u64 publication. The
    # copy-on-write owner must roll back every original page, including tail.
    for slot in (0x88,0x90):
        for field in ('active','start','frame','raw','tree','pop'):
            if (slot==0x88 and field not in ('active','start','frame')) or (slot==0x90 and field not in ('raw','tree','pop')): continue
            pages,_=prepare(args.library,base,standard); before={k:bytes(v) for k,v in pages.items()}
            targets=dict(active=CB+0x28,start=u(pages,AST+0x78)+0x80,frame=u(pages,CB+0x30),
                raw=HEAP+32,tree=CB+0x58,pop=CB+0x38)
            original=alternative._write_span; pointer=HEAP
            def allocate(size):
                nonlocal pointer
                out=pointer; pointer+=(size+15)&~15; return out
            def fail(p,address,data):
                if address==targets[field]: raise RefillUnsupported('injected global expression write')
                original(p,address,data)
            alternative._write_span=fail
            try:
                try: alternative.run_reader_ast_callback(pages,callback_address=CB,image_base=base,slot_offset=slot,
                    arguments=(0,) if slot==0x88 else (0,0xFEDCBA9876543210),allocate=allocate)
                except RefillUnsupported as exc: assert str(exc)=='injected global expression write',(slot,field,str(exc))
                else: raise AssertionError('late guard accepted: '+str((slot,field)))
            finally: alternative._write_span=original
            assert before=={k:bytes(v) for k,v in pages.items()},(slot,field)
            rows.append(dict(label=f'late_write_{slot}_{field}',rejected=True,all_pages_unchanged=True,native_invalid_memory_path_compared=False))
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    specs=fixtures(); rows=[]; rejected=negatives(args)
    assert len({s['label'] for s in specs})==len(specs)
    for base in (0x122C0000,0x775C205000):
        for index,spec in enumerate(specs,1):
            rows.append(compare(args,base,spec))
            if index%24==0 or index==len(specs): print('B global expression:',hex(base),index,'/',len(specs),'passed',flush=True)
    evidence=dict(schema='vm9-alternative-ast-global-expression-fresh-v1',evidence_date='2026-10-10',
        evidence_timezone='Asia/Shanghai',sample_sha256=oracle.LIBRARY_SHA256,
        native_Python_AST_global_expression_controls=len(rows),rollback_negative_controls=len(rejected),
        pre_change_behavior_RED_controls=5,recovered_callback_slots_hex=['0x88','0x90'],
        actual_native_vtable_offset_hex='0x372370',global_expression_begin_offset_hex='0x31d45c',
        global_expression_end_offset_hex='0x31d4ac',global_inline_offset_hex='0x18',
        global_raw_start_offset_hex='0x80',global_end_value_offset_hex='0xa8',
        frame_append_offset_hex='0x31fee4',frame_stride=16,fixup_offset_hex='0x32000c',
        tree_erase_offset_hex='0x2695c0',tree_payload_stride=4,full_u64_end_value_preserved=True,
        expression_end_retains_active=True,global_active_local_and_function_end_supported=True,
        global_expression_callbacks_implemented=True,all_fixtures_synthetic=True,guest_bytes_masked=False,
        native_input_snapshot_used=False,private_payloads_published=False,attached_parser_implemented=False,
        parser_AST_composition_implemented=False,complete_AST_callbacks_implemented=False,
        complete_output_wrapper_cleanup_implemented=False,complete_python_reader_implemented=False,
        independent_Python_factory_implemented=False,complete_python_bootstrap_controls=0,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False,
        cases=rows,negative_cases=rejected)
    args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    print('B global expression:',len(rows),'native/Python +',len(rejected),'rollback checks passed',flush=True)


if __name__ == '__main__': main()
