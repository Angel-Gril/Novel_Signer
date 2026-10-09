"""Fresh B code begin on function output, two fixup trees and child records.

Synthetic inputs execute actual +a8 through its relocated vtable. No native
input snapshot or attached parser substitutes function/frame/tree ownership.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import random

import verify_vm9_alternative_ast_function_20261009 as function
import verify_vm9_alternative_ast_data_expression_20261009 as expression
import verify_vm9_signer_objects as oracle
import vm9_alternative_startup as alternative
from vm9_allocator import RefillUnsupported, _read_span, _write_span

CB, AST, INPUT, HEAP = function.CB, function.AST, function.INPUT, function.HEAP
put, vector = function.put, function.vector
FUNCTIONS = {**function.FUNCTIONS, 0xA8:0x31D7D8}
SEED = 0x31D7D8


def prepare(library,base,spec):
    initial={**spec}
    initial.setdefault('function_vector',(1,2)); initial.setdefault('cache_vector',(1,2))
    pages,sizes=function.prepare(library,base,initial)
    u=lambda a:int.from_bytes(_read_span(pages,a,8),'little')
    pointer=max([function.controls.OLD]+[p+((max(n,1)+15)&~15) for p,n in sizes.items()])
    def block(size,marker=0xA7):
        nonlocal pointer
        out=pointer; pointer+=(max(size,1)+15)&~15; assert pointer<INPUT
        sizes[out]=size; _write_span(pages,out,bytes([marker])*max(size,1)); return out
    if 'children' in spec:
        count,capacity=spec['children']
        for index in range(initial['function_vector'][0]):
            record=u(AST+0x30)+index*144
            old=u(record+0x78); old_end=u(record+0x80)
            for child in range(old,old_end,56):
                payload=u(child+0x10)
                if payload: sizes.pop(payload)
            if old: sizes.pop(old)
            if capacity or spec.get('children_nonnull_empty'):
                begin=block(capacity*56)
                vector(pages,record+0x78,begin,count,capacity,56)
                for i in range(count):
                    child=begin+i*56; vector(pages,child+0x10)
                    if spec.get('child_payloads',True):
                        payload=block((i+2)*8,0xD1)
                        vector(pages,child+0x10,payload,i+1,i+2,8)
            else: vector(pages,record+0x78)
    if spec.get('frames_nonnull_empty') and not spec.get('frames',(0,0))[1]:
        vector(pages,CB+0x30,block(0),0,0,16)
    nodes=spec.get('function_tree',[])
    addresses=[block(64,0xA6) for _ in nodes]; sentinel=CB+0x68
    parents={spec.get('function_tree_root',0):sentinel} if nodes else {}
    for i,(_,left,right,_,_) in enumerate(nodes):
        for child in (left,right):
            if child is not None: parents[child]=addresses[i]
    for i,(key,left,right,black,patches) in enumerate(nodes):
        node=addresses[i]
        put(pages,node,addresses[left] if left is not None else 0)
        put(pages,node+8,addresses[right] if right is not None else 0)
        put(pages,node+0x10,parents[i]); put(pages,node+0x18,black,1)
        put(pages,node+0x20,key,4)
        if patches or spec.get('function_tree_nonnull_payload'):
            capacity=len(patches)+2; payload=block(capacity*4,0xA6)
            vector(pages,node+0x28,payload,len(patches),capacity,4)
            _write_span(pages,payload,b''.join(v.to_bytes(4,'little') for v in patches))
        else: vector(pages,node+0x28)
    if nodes:
        root=spec.get('function_tree_root',0); first=root
        while nodes[first][1] is not None: first=nodes[first][1]
        put(pages,CB+0x60,addresses[first]); put(pages,CB+0x68,addresses[root]); put(pages,CB+0x70,len(nodes))
    return pages,sizes


def minimal_specs():
    return [dict(label='code_begin_spare',children=(1,3),frames=(2,3),raw_vector=(3,9),
                 callbacks=[(0xA8,(0,0xFFFFFFFF12345678,0xFFFFFFFFFFFFFFFF,0xFFFFFFFFABCDEF01))]),
            dict(label='code_begin_frame_child_growth',children=(1,1),frames_nonnull_empty=True,
                 callbacks=[(0xA8,(0,7,9,11))]),
            dict(label='code_begin_two_trees',function_vector=(3,3),cache_vector=(5,5),children=(0,0),
                 tree=[(9,None,None,1,[0,4])],function_tree=[(1,None,None,1,[1,32])],raw_vector=(3,9),
                 callbacks=[(0xA8,(3,17,19,23))])]


def fixtures():
    cases=minimal_specs()
    for frames in ((0,0),(0,2),(2,2),(2,3)):
        for children in ((0,0),(0,2),(1,1),(2,3)):
            for raw in ((0,0),(3,3),(3,9)):
                cases.append(dict(label=f'frames_{frames}_children_{children}_raw_{raw}',frames=frames,
                    children=children,raw_vector=raw,callbacks=[(0xA8,(0,17,19,23))],destroy_function=True,cleanup=True))
    for cache_count in (0,2,3,5):
        for index in range(3):
            imported=(cache_count-3)&0xFFFFFFFF
            cases.append(dict(label=f'function_index_{index}_cache_count_{cache_count}',function_vector=(3,4),
                cache_vector=(cache_count,cache_count+1),children=(1,2),frames=(2,3),raw_vector=(7,9),
                callbacks=[(0xA8,((0xFFFFFFFF<<32)|((imported+index)&0xFFFFFFFF),0xFFFFFFFF12345678,
                    0xFFFFFFFFFFFFFFFF,0xFFFFFFFF87654321))],destroy_function=True,cleanup=True))
    for value in (0,0xFFFFFFFF,0x100000001,0xFFFFFFFFFFFFFFFF):
        cases.append(dict(label=f'code_cursor_metadata_{value}',children=(0,2),frames=(0,2),raw_vector=(3,9),
            callbacks=[(0xA8,(0,value,value,value))],destroy_function=True,cleanup=True))
    for first,second in ((True,False),(False,True),(True,True)):
        cases.append(dict(label=f'nonnull_frame_children_{first}_{second}',frames_nonnull_empty=first,
            children_nonnull_empty=second,children=(0,0),callbacks=[(0xA8,(0,0,0,0))],destroy_function=True,cleanup=True))
    for patches,raw in (([0,4,8],(12,16)),([1,6],(7,9)),([3,10,20],(7,9)),
                        ([0,0,32,0],(0,0)),([],(0,0)),([128],(3,9))):
        cases.append(dict(label='function_fixups_'+str(patches),children=(0,0),function_tree=[(0,None,None,1,patches)],
            function_tree_nonnull_payload=True,raw_vector=raw,callbacks=[(0xA8,(0,7,9,11))],destroy_function=True,cleanup=True))
    originals=expression.fixtures()
    for original in originals:
        if original['label'].startswith('erase_shape'):
            key=original['frames'][0]-1; count=max(n[0] for n in original['tree'])+1
            cases.append(dict(label='function_'+original['label'],function_vector=(count,count),cache_vector=(count+2,count+2),
                function_mode='null',children=(0,0),function_tree=original['tree'],raw_vector=original['raw_vector'],
                callbacks=[(0xA8,(key+2,17,19,23))],destroy_function=True,cleanup=True))
    for original in originals:
        if original['label'].startswith('erase_shape') and original['frames'][0]==1:
            cases.append(dict(label='clear_frame_'+original['label'],children=(1,2),tree=original['tree'],
                raw_vector=(12,16),frames=(2,3),callbacks=[(0xA8,(0,17,19,23))],destroy_function=True,cleanup=True))
    descending=next(s for s in originals if s['label']=='descending_erase_all_keys')
    cases += [dict(label='code_begin_missing_function_fixup',children=(1,2),function_tree=[(1,None,None,1,[0,32])],
        raw_vector=(3,9),callbacks=[(0xA8,(0,7,9,11))],destroy_function=True,cleanup=True),
        dict(label='code_begin_repeated_same_function',children=(1,1),frames=(2,3),function_tree=[(0,None,None,1,[1,32])],
            tree=[(4,None,None,1,[0,8])],raw_vector=(3,9),callbacks=[(0xA8,(0,i,0xFFFFFFFFFFFFFFFF,i+7)) for i in range(6)],
            destroy_function=True,cleanup=True),
        dict(label='code_begin_descending_function_fixups',function_vector=(7,7),cache_vector=(9,9),function_mode='null',
            children=(0,0),function_tree=descending['tree'],raw_vector=(12,16),
            callbacks=[(0xA8,(key+2,17,19,23)) for key in range(6,-1,-1)],destroy_function=True,cleanup=True),
        dict(label='create_code_locals_constants_end_cleanup',function_vector=(0,0),cache_vector=(0,0),
            children=(0,0),callbacks=[(0x50,(99,0)),(0xB0,(3,)),(0xA8,(0,0xFFFFFFFF12345678,19,23)),
                (0xC0,(99,)),(0xB8,(0,0,0xFFFFFFFFFFFFFFF0)),(0xB8,(1,0xFFFFFFFF,0x8000000012345678)),
                (0xE0,(0xFFFFFFFF80000000,)),(0xD8,(0x7FF8000000000001,)),(0xC8,()),
                (0xF8,(0,0xFFFFFFFF12345678)),(0xC0,(0,))],
            callback_statuses=[0,0,0,0,0,0,0,0,0,0,1],destroy_function=True,cleanup=True),
        dict(label='code_begin_after_existing_local_groups',function_vector=(2,2),cache_vector=(4,4),children=(1,1),
            callbacks=[(0xA8,(2,7,9,11)),(0xB0,(1,)),(0xB8,(0,3,0xFFFFFFFFFFFFFFEF)),
                (0xA8,(2,17,19,23)),(0x168,(99,)),(0xF8,(0,88)),(0xA8,(3,27,29,33))],
            destroy_function=True,cleanup=True),
        dict(label='code_begin_frame_image_constant',children=(2,3),frames=(1,2),frame_constant=0x8877665544332211,
            callbacks=[(0xA8,(0,7,9,11))],destroy_function=True,cleanup=True),
        dict(label='code_begin_with_owned_other_outputs',children=(1,1),frames=(1,2),data_vector=(1,1),element_vector=(1,1),
            owned_mode='rich',callbacks=[(0xA8,(0,7,9,11))],destroy_function=True,destroy_data=True,destroy_element=True,cleanup=True)]
    for count,budget in ((2,6),(5,10)):
        cases.append(dict(label=f'exact_child_node_budget_{count}_{budget}',function_vector=(1,1),cache_vector=(1,1),
            definitions=[(0,[],[])],function_mode='null',children=(count,count),child_payloads=False,
            callback_max_nodes=budget,callbacks=[(0xA8,(0,7,9,11))],destroy_function=True,cleanup=True))
    rng=random.Random(SEED)
    for index in range(6):
        count=rng.randrange(1,4); capacity=count+rng.randrange(2); imported=rng.randrange(3)
        selected=rng.randrange(count); child_cap=rng.randrange(1,4); child_count=rng.randrange(child_cap+1)
        cases.append(dict(label=f'generated_code_begin_{index}',function_vector=(count,capacity),
            cache_vector=(count+imported,count+imported+1),children=(child_count,child_cap),
            frames=(2,3),raw_vector=(3,9),function_tree=[(selected,None,None,1,[1,32])],
            callbacks=[(0xA8,((rng.getrandbits(32)<<32)|(imported+selected),rng.getrandbits(64),
                rng.getrandbits(64),rng.getrandbits(64)))],destroy_function=True,cleanup=True))
    return cases


def compare(args,base,spec):
    row=function.controls.compare(args,base,spec,functions=FUNCTIONS,prepare_case=prepare)
    initial,_=prepare(args.library,base,spec)
    callback_spec={k:v for k,v in spec.items() if k not in ('destroy_function','destroy_data','destroy_element','cleanup')}
    pages,_,statuses=function.controls.model_case(args,base,callback_spec,prepare_case=prepare)
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
        _,default_effects,_=function.controls.model_case(args,base,callback_spec,prepare_case=prepare)
        assert [(e.kind,e.address,e.size,e.owner_address,e.owner_bytes) for e in bounded_effects]==default_effects
        assert bounded_statuses==statuses
    u=lambda p,a,n=8:int.from_bytes(_read_span(p,a,n),'little')
    fs=spec.get('function_vector',(1,2))[0]; cs=spec.get('cache_vector',(1,2))[0]
    initial_children=spec.get('children',(0 if spec.get('function_mode')=='null' else spec.get('child_count',2),0))[0]
    counts=[initial_children]*fs
    local_counts=[0 if spec.get('function_mode') in ('null','empty') else 1]*fs
    children=[[] for _ in range(fs)]; fields={}; lengths={}; frame=None; active=None; cumulative=0
    raw=bytearray(b'\x35'*spec.get('raw_vector',(0,0))[0])
    keys={node[0]:node[4] for node in spec.get('function_tree',[])}
    begins=0; expected_statuses=[]
    for slot,argv in spec.get('callbacks',[]):
        status=0
        if slot==0x50:
            fs+=1; cs+=1; counts.append(0); local_counts.append(0); children.append([])
        elif slot==0xA8:
            index=(argv[0]-(cs-fs))&0xFFFFFFFF; active=index; begins+=1
            fields[index]=(argv[3]&0xFFFFFFFF,len(raw),argv[1]&0xFFFFFFFF)
            for offset in keys.pop(index,[]):
                old=len(raw)
                if offset+4>old: raw.extend(bytes(offset+4-old))
                raw[offset:offset+4]=old.to_bytes(4,'little')
            children[index].append((len(raw),local_counts[index]))
            frame=(counts[index],); counts[index]+=1
        elif slot==0xB0: cumulative=0
        elif slot==0xB8:
            assert active is not None; local_counts[active]+=1
            cumulative=(cumulative+(argv[1]&0xFFFFFFFF))&0xFFFFFFFF
        elif slot==0xF8:
            assert active is not None; lengths[active]=argv[1]&0xFFFFFFFF; active=None
        elif slot==0xC0: status=int(active is None or frame is None)
        elif slot in (0xD0,0xD8,0xE0,0xE8):
            tag,width={0xD0:(4,4),0xD8:(5,8),0xE0:(2,4),0xE8:(3,8)}[slot]
            raw.extend(tag.to_bytes(4,'little')+(argv[0]&((1<<(width*8))-1)).to_bytes(width,'little'))
        elif slot in (0x168,0xF0): raw.extend((argv[0]&0xFFFFFFFF if slot==0x168 else 0).to_bytes(4,'little'))
        else: assert slot==0xC8
        expected_statuses.append(status)
    assert statuses==expected_statuses
    fb=u(pages,AST+0x30)
    for index,values in fields.items():
        record=fb+index*144; metadata,start,cursor=values
        assert u(pages,record+0x48,4)==metadata and u(pages,record+0x68,4)==start and u(pages,record+0x6C,4)==cursor
        if index in lengths: assert u(pages,record+0x70,4)==lengths[index]
        assert (u(pages,record+0x58)-u(pages,record+0x50))//16==local_counts[index]
        begin=u(pages,record+0x78); assert (u(pages,record+0x80)-begin)//56==counts[index]
        for number,(raw_start,local_count) in enumerate(children[index],counts[index]-len(children[index])):
            child=begin+number*56
            assert u(pages,child)==raw_start<<32 and u(pages,child+8,4)==0xFFFFFFFF
            assert _read_span(pages,child+0x10,24)==bytes(24)
            assert u(pages,child+0x28)==(local_count<<32)|0xFFFFFFFF and u(pages,child+0x30,4)==0
            for offset in (0x0C,0x34):
                expected=_read_span(initial,child+offset,4) if child<INPUT else b'\xa5'*4
                assert _read_span(pages,child+offset,4)==expected
        for offset in (0x0C,0x4C,0x74):
            assert _read_span(pages,record+offset,4)==_read_span(initial,record+offset,4)
    assert u(pages,CB+0x28)==(fb+active*144 if active is not None else 0)
    assert (u(pages,CB+0x48),u(pages,CB+0x50),u(pages,CB+0x58))==(CB+0x50,0,0)
    assert u(pages,CB+0x70)==len(keys)
    if frame:
        begin=u(pages,CB+0x30); assert u(pages,CB+0x38)-begin==16
        assert _read_span(pages,begin,8)==_read_span(initial,base+0x6E188,8)
        assert u(pages,begin+8,4)==0xFFFFFFFF and u(pages,begin+0x0C,4)==frame[0]
    pointer=u(pages,AST+0x108)
    assert u(pages,AST+0x110)-pointer==len(raw) and _read_span(pages,pointer,len(raw))==raw
    assert u(pages,CB+0x7C,4)==cumulative
    row.update(independent_function_selection_metadata_raw_frame_child_padding_and_tree_expectations_match=True,
        code_begin_count=begins,function_tree_nodes_remaining=len(keys),callback_statuses=statuses,
        exact_node_budget_control='callback_max_nodes' in spec,
        **({'exact_node_budget_supported':spec['callback_max_nodes']} if 'callback_max_nodes' in spec else {}))
    return row


def negatives(args):
    base=0x122C0000; rows=[]; cases=[]
    standard=dict(label='guard',children=(0,0),frames_nonnull_empty=True,raw_vector=(3,9),
        tree=[(9,None,None,1,[0,4])],function_tree=[(0,None,None,1,[16,128])])
    u=lambda p,a:int.from_bytes(_read_span(p,a,8),'little')
    record=lambda p:u(p,AST+0x30)
    root=lambda p:u(p,CB+0x68)
    def add(label,changes=None,setup=None,spec=None): cases.append((label,changes or {},setup,spec or standard))
    add('slot_binding',setup=lambda p:put(p,base+0x372370+0xA8,0))
    add('attached',setup=lambda p:put(p,CB+8,INPUT))
    for argv in ((0,0,0),(0,0,0,0,0),(-1,0,0,0),(0,1<<64,0,0)):
        add('arity_or_register_'+str(argv),dict(arguments=argv))
    add('empty_function',spec=dict(label='guard',function_vector=(0,0),cache_vector=(0,0)))
    add('spare_function_index',dict(arguments=(1,0,0,0)),spec=dict(label='guard',function_vector=(1,3)))
    add('imported_index_underflow',dict(arguments=(1,0,0,0)),spec=dict(label='guard',cache_vector=(3,3)))
    add('relative_index_overflow',dict(arguments=(0xFFFFFFFF,0,0,0)))
    add('frame_partial',setup=lambda p:put(p,CB+0x38,u(p,CB+0x30)+1))
    add('frame_capacity_partial',setup=lambda p:put(p,CB+0x40,u(p,CB+0x30)+1))
    add('frame_capacity_bound',dict(max_nodes=6),spec=dict(label='guard',frames=(0,7),function_mode='null',definitions=[(0,[],[])]))
    add('child_partial_end',setup=lambda p:put(p,record(p)+0x80,u(p,record(p)+0x78)+1))
    add('child_append_total_node_bound',dict(max_nodes=5),spec=dict(label='guard',children=(2,2),child_payloads=False,
        function_mode='null',definitions=[(0,[],[])],function_vector=(1,1),cache_vector=(1,1)))
    add('child_doubled_capacity_bound',dict(max_nodes=9),spec=dict(label='guard',children=(5,5),child_payloads=False,
        function_mode='null',definitions=[(0,[],[])],function_vector=(1,1),cache_vector=(1,1)))
    add('child_growth_bytes',dict(max_vector_bytes=167),spec=dict(label='guard',children=(2,2),function_mode='null',
        definitions=[(0,[],[])],function_vector=(1,1),cache_vector=(1,1)))
    add('tree_count',setup=lambda p:put(p,CB+0x70,2))
    add('tree_begin',setup=lambda p:put(p,CB+0x60,CB+0x68))
    add('tree_root_parent',setup=lambda p:put(p,root(p)+0x10,CB))
    add('tree_red_root',setup=lambda p:put(p,root(p)+0x18,0,1))
    add('tree_cycle',setup=lambda p:put(p,root(p),root(p)))
    add('tree_shared',setup=lambda p:put(p,root(p)+8,root(p)))
    add('tree_partial_payload',setup=lambda p:put(p,root(p)+0x30,u(p,root(p)+0x28)+1))
    add('tree_payload_alias_raw',setup=lambda p:vector(p,root(p)+0x28,u(p,AST+0x108),1,2,4))
    add('two_trees_alias',setup=lambda p:put(p,CB+0x50,root(p)))
    add('fixup_u32_wrap',spec={**standard,'function_tree':[(0,None,None,1,[0xFFFFFFFF])]})
    add('fixup_byte_budget',dict(max_vector_bytes=256),spec={**standard,'function_mode':'null','definitions':[(0,[],[])],
        'function_vector':(1,1),'cache_vector':(1,1),'function_tree':[(0,None,None,1,[256])]})
    add('missing_allocator',dict(allocate=None))
    for label,changes,setup,spec in cases:
        pages,_=prepare(args.library,base,spec)
        if setup: setup(pages)
        before={k:bytes(v) for k,v in pages.items()}
        params=dict(callback_address=CB,image_base=base,slot_offset=0xA8,arguments=(0,7,9,11),allocate=lambda n:HEAP)
        params.update(changes)
        paired=label in ('child_append_total_node_bound','child_doubled_capacity_bound','child_growth_bytes','fixup_byte_budget')
        if paired:
            baseline,_=prepare(args.library,base,spec); next_pointer=HEAP
            def planned(size):
                nonlocal next_pointer
                out=next_pointer; next_pointer+=(size+15)&~15; return out
            alternative.run_reader_ast_callback(baseline,callback_address=CB,image_base=base,
                slot_offset=0xA8,arguments=(0,7,9,11),allocate=planned)
        try: alternative.run_reader_ast_callback(pages,**params)
        except (RefillUnsupported,ValueError): pass
        else: raise AssertionError('code-begin guard accepted: '+label)
        assert before=={k:bytes(v) for k,v in pages.items()},label
        rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_invalid_memory_path_compared=False,
            **({'same_input_without_budget_restriction_supported':True} if paired else {})))
    targets=('unmapped','unaligned','partial','callback','output','function','cache','raw','frame','tree',
        'tree_payload','cleared_tree','type_params','image','retained','prior_plan')
    for stage in range(1,5):
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
                        'function':record(pages),'cache':u(pages,CB+0x80),'raw':u(pages,AST+0x108),
                        'frame':u(pages,CB+0x30),'tree':root(pages),'tree_payload':u(pages,root(pages)+0x28),
                        'cleared_tree':u(pages,CB+0x50),'type_params':u(pages,record(pages)+0x10),
                        'image':base+0x6E188,'retained':INPUT,'prior_plan':plans[0][1] if plans else HEAP}[target]
                plans.append((size,out)); return out
            try: alternative.run_reader_ast_callback(pages,callback_address=CB,image_base=base,slot_offset=0xA8,
                arguments=(0,7,9,11),allocate=allocate,reserved_regions=((INPUT,INPUT+2048),))
            except (RefillUnsupported,ValueError): pass
            else: raise AssertionError(('code allocation guard accepted',stage,target))
            assert len(plans)==stage and before=={k:bytes(v) for k,v in pages.items()},(stage,target)
            rows.append(dict(label=f'allocation_{stage}_{target}',rejected=True,all_pages_unchanged=True,
                allocation_plans_before_rejection=stage,native_invalid_memory_path_compared=False))
    for boundary in ('metadata','raw_start','tree_reset','raw_publish','tree_erase','frame_publish','child_publish','spare_child_end'):
        spec={**standard}
        if boundary=='spare_child_end': spec['children']=(1,3)
        pages,_=prepare(args.library,base,spec); before={k:bytes(v) for k,v in pages.items()}
        addresses={'metadata':record(pages)+0x48,'raw_start':record(pages)+0x68,'tree_reset':CB+0x48,
            'raw_publish':AST+0x108,'tree_erase':CB+0x70,'frame_publish':CB+0x30,
            'child_publish':record(pages)+0x78,'spare_child_end':record(pages)+0x80}
        original=alternative._write_span; plans=[]; pointer=HEAP
        def allocate(size):
            nonlocal pointer
            out=pointer; pointer+=(size+15)&~15; plans.append((size,out)); return out
        def fail(p,address,data):
            if address==addresses[boundary]: raise RefillUnsupported('injected late code begin write')
            original(p,address,data)
        alternative._write_span=fail
        try:
            try: alternative.run_reader_ast_callback(pages,callback_address=CB,image_base=base,
                slot_offset=0xA8,arguments=(0,7,9,11),allocate=allocate)
            except RefillUnsupported: pass
            else: raise AssertionError('late code-begin guard accepted: '+boundary)
        finally: alternative._write_span=original
        assert before=={k:bytes(v) for k,v in pages.items()},boundary
        rows.append(dict(label='late_'+boundary,rejected=True,all_pages_unchanged=True,
            allocation_plans_before_rejection=len(plans),native_invalid_memory_path_compared=False))
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
            if index%24==0 or index==len(specs): print('B code begin:',hex(base),index,'/',len(specs),'passed',flush=True)
    evidence=dict(schema='vm9-alternative-ast-code-begin-fresh-v1',evidence_date='2026-10-09',
        evidence_timezone='Asia/Shanghai',sample_sha256=oracle.LIBRARY_SHA256,generated_fixture_seed=SEED,
        native_Python_AST_code_begin_controls=len(rows),rollback_negative_controls=len(rejected),
        pre_change_behavior_RED_controls=3,recovered_callback_slots_hex=['0xa8'],
        node_budget_behavior_RED_controls=2,
        actual_native_vtable_offset_hex='0x372370',code_begin_offset_hex='0x31d7d8',
        fixup_offset_hex='0x32000c',tree_erase_offset_hex='0x2695c0',tree_cleanup_offset_hex='0x3202f0',
        child_growth_offset_hex='0x320340',frame_append_offset_hex='0x31fee4',
        function_record_stride=144,child_record_stride=56,frame_stride=16,tree_payload_stride=4,
        all_fixtures_synthetic=True,native_input_snapshot_used=False,private_payloads_published=False,
        code_begin_callback_implemented=True,function_output_container_implemented=True,
        table_count_entry_callbacks_implemented=False,parser_AST_composition_implemented=False,attached_parser_implemented=False,
        complete_AST_callbacks_implemented=False,complete_python_reader_implemented=False,independent_Python_factory_implemented=False,
        complete_python_bootstrap_controls=0,complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False,cases=rows,negative_cases=rejected)
    args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    print('B code begin:',len(rows),'native/Python +',len(rejected),'rollback checks passed',flush=True)


if __name__=='__main__': main()
