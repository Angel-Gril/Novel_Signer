"""Fresh five B import AST callbacks with actual register/stack ABI and ownership."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

import verify_vm9_alternative_ast_data_20261009 as controls
import verify_vm9_alternative_ast_export_20261010 as export
import verify_vm9_signer_objects as oracle
import vm9_alternative_startup as alternative
from vm9_allocator import RefillUnsupported,_read_span,_write_span

CB,AST,INPUT,HEAP=controls.CB,controls.AST,controls.INPUT,controls.HEAP
put,vector=controls.put,controls.vector
STACK=oracle.GUEST+0xEF00
MODULE,FIELD,DESCRIPTOR=INPUT,INPUT+0x200,INPUT+0x400
FUNCTIONS={0x28:0x31B870,0x30:0x31BB48,0x38:0x31BE3C,0x40:0x31C144,0x48:0x31C414}
KINDS=export.KINDS
DEFAULT_TYPES=((0xA1234567,(0xFFFFFFFFFFFFFFF0,0x8000000012345678),(7,)),
               (0xB89ABCDE,(1,),(0xFFFFFFFFFFFFFFE0,9)))

def arguments(kind,module_length=7,field_length=23,*,index=1,type_value=0x8000000012345678,mutable=0xFFFFFFFFFFFFFFFE):
    common=(0xFFFFFFFFFFFFFFFF,0x90000000 if not module_length else MODULE,module_length,
            0x90000000 if not field_length else FIELD,field_length,0xFFFFFFFF00000007)
    if kind==0: return common+(0xFFFFFFFF00000000+index,)
    if kind==1: return common+(type_value,DESCRIPTOR)
    if kind==2: return common+(DESCRIPTOR,)
    if kind==3: return common+(type_value,mutable)
    return common+(0xFFFFFFFF00000000+index,)

def prepare(library,base,spec):
    pages,sizes=controls.prepare(library,base,{})
    pointer=controls.OLD
    def block(size,marker=0xD3):
        nonlocal pointer
        out=pointer; pointer+=(max(size,1)+15)&~15; assert pointer<INPUT
        sizes[out]=size; _write_span(pages,out,bytes([marker])*max(size,1)); return out
    def owned(header,values,capacity):
        vector(pages,header)
        if values or spec.get('empty_owned'):
            out=block(capacity*8,0xD4); vector(pages,header,out,len(values),capacity,8)
            _write_span(pages,out,b''.join(n.to_bytes(8,'little') for n in values))
    def node(address,kind,index,definition=None):
        _,stride,table=KINDS[kind]
        put(pages,address,base+table); put(pages,address+8,0xD00D0000+index,4)
        if kind==0:
            scalar,params,results=DEFAULT_TYPES[index%len(DEFAULT_TYPES)] if definition is None else definition
            put(pages,address+8,scalar,4)
            owned(address+0x10,() if spec.get('empty_vectors') else params,len(params)+2)
            owned(address+0x28,() if spec.get('empty_vectors') else results,len(results)+3)
        elif kind==4:
            put(pages,address+0xC,0x12340000+index,4)
            owned(address+0x10,() if spec.get('empty_vectors') else (0x1122334455667788+index,9),3)
        elif kind==1: _write_span(pages,address+0xC,bytes((index+i*7)&255 for i in range(31)))
        elif kind==2: _write_span(pages,address+0x10,bytes((index+i*11)&255 for i in range(24)))
        else:
            put(pages,address+0xC,0xFFFFFFFFFFFFFFF0+index); put(pages,address+0x14,0xF0010000+index,4)
    definitions=spec.get('definitions',DEFAULT_TYPES)
    if definitions:
        begin=block((len(definitions)+1)*64,0xA7); vector(pages,AST,begin,len(definitions),len(definitions)+1,64)
        for index,definition in enumerate(definitions): node(begin+index*64,0,index,definition)
    for kind,(offset,stride,_) in enumerate(KINDS):
        count,capacity=spec.get('cache_vectors',{}).get(kind,spec.get('cache_vector',(1,2)))
        if capacity or spec.get('cache_nonnull_empty'):
            begin=block(capacity*stride,0xB3); vector(pages,CB+offset,begin,count,capacity,stride)
            for index in range(count): node(begin+index*stride,kind,index)
    def string(address,length,index):
        payload=bytes((i*13+index)&255 for i in range(length))+b'\0'
        if length<=22 and not spec.get('old_heap_short'):
            header=bytearray(b'\xb6'*24); header[0]=length*2; header[1:length+2]=payload
            _write_span(pages,address,header)
        else:
            storage=(length+16)&~15; data=block(storage,0xD7); _write_span(pages,data,payload)
            _write_span(pages,address,(storage|1).to_bytes(8,'little')+length.to_bytes(8,'little')+data.to_bytes(8,'little'))
    count,capacity=spec.get('imports',(0,0))
    if capacity or spec.get('nonnull_empty'):
        begin=block(capacity*64,0xC3); vector(pages,AST+0x18,begin,count,capacity,64)
        for index in range(count):
            address=begin+index*64
            lengths=spec.get('old_name_lengths',((3,23),(32,22),(0,32)))
            for off,length in zip((0,24),lengths[index%len(lengths)]): string(address+off,length,index+off)
            kinds=spec.get('old_kinds',(0,4,1,2,3)); kind=kinds[index%len(kinds)]
            data=block(KINDS[kind][1],0xD8); node(data,kind,index)
            put(pages,address+0x30,data); put(pages,address+0x38,0x12340000+index,4); put(pages,address+0x3C,0xABC00000+index,4)
    for _,argv in spec.get('callbacks',[]):
        for which,(name,length) in enumerate(((argv[1],argv[2]),(argv[3],argv[4]))):
            if length: _write_span(pages,name,bytes(((17 if which==0 else 11)*i+(5 if which==0 else 0x63))&255 for i in range(length)))
    descriptor=bytearray((3+i*7)&255 for i in range(24))
    descriptor[16]=spec.get('maximum_flag',0); descriptor[18]=spec.get('memory64',0)
    _write_span(pages,DESCRIPTOR+spec.get('descriptor_unaligned',0),descriptor)
    _write_span(pages,STACK-0x110,bytes([spec.get('stack_pattern',0x96)])*0x110)
    return pages,sizes

def minimal_specs():
    cases=[]
    for kind,slot in enumerate(FUNCTIONS):
        cases.append(dict(label=f'import_{kind}_actual_ABI',imports=(1,1) if kind%2 else (1,3),
            cache_vector=(1,1) if kind%2 else (1,3),entry_stack_address=STACK,
            callbacks=[(slot,arguments(kind))]))
    cases.append(dict(label='import_rich_only_wrapper_cleanup',definitions=(),imports=(5,6),old_kinds=tuple(range(5)),destroy_imports=True))
    return cases

def compare(args,base,spec):
    row=controls.compare(args,base,spec,functions=FUNCTIONS,prepare_case=prepare)
    observed={k:v for k,v in spec.items() if k not in ('destroy_imports','cleanup')}
    initial,_=prepare(args.library,base,observed)
    pages,effects,statuses=controls.model_case(args,base,observed,prepare_case=prepare)
    u=lambda p,a,n=8:int.from_bytes(_read_span(p,a,n),'little')
    def string(p,address):
        h=_read_span(p,address,24)
        return _read_span(p,u(p,address+16),u(p,address+8)+1) if h[0]&1 else h[1:(h[0]>>1)+2]
    def vectors(p,address,table):
        return [tuple(u(p,address+off+n) for n in (0,8,16)) for off in
            ((0x10,0x28) if table==0x3724F0 else (0x10,) if table==0x372590 else ())]
    def clone_equal(source,target):
        table=u(initial,source)-base
        assert u(pages,target)==base+table and u(pages,target+8,4)==u(initial,source+8,4)
        if table in (0x3724F0,0x372590):
            if table==0x372590: assert u(pages,target+8)==u(initial,source+8)
            for old,new in zip(vectors(initial,source,table),vectors(pages,target,table)):
                assert new[1]-new[0]==new[2]-new[0]==old[1]-old[0]
                assert _read_span(pages,new[0],new[1]-new[0])==_read_span(initial,old[0],old[1]-old[0])
                if new[0]: assert new[0]!=old[0]
        else:
            off,n=(0xC,31) if table==0x372518 else (0x10,24) if table==0x372540 else (0xC,12)
            assert _read_span(pages,target+off,n)==_read_span(initial,source+off,n)
        assert target!=source
    size,capacity=spec.get('imports',(0,0)); prior=size
    for _ in spec.get('callbacks',[]):
        if size==capacity: capacity=max(size+1,capacity*2)
        size+=1
    begin=u(pages,AST+0x18)
    assert (u(pages,AST+0x20)-begin,u(pages,AST+0x28)-begin)==(size*64,capacity*64)
    if begin!=u(initial,AST+0x18):
        for index in range(prior):
            old=u(initial,AST+0x18)+index*64; new=begin+index*64
            assert u(pages,old+0x30)==0
            for off in (0,24): assert string(pages,new+off)==string(initial,old+off)
            assert _read_span(pages,new+0x38,8)==_read_span(initial,old+0x38,8)
            clone_equal(u(initial,old+0x30),u(pages,new+0x30))
    counts=[spec.get('cache_vectors',{}).get(k,spec.get('cache_vector',(1,2)))[0] for k in range(5)]
    capacities=[spec.get('cache_vectors',{}).get(k,spec.get('cache_vector',(1,2)))[1] for k in range(5)]
    for position,(slot,argv) in enumerate(spec.get('callbacks',[]),prior):
        kind=(slot-0x28)//8; off,stride,table=KINDS[kind]
        if counts[kind]==capacities[kind]: capacities[kind]=max(counts[kind]+1,capacities[kind]*2)
        cache=u(pages,CB+off)+counts[kind]*stride; counts[kind]+=1
        target=begin+position*64; node=u(pages,target+0x30)
        assert node!=cache and u(pages,node)==u(pages,cache)==base+table
        for which,(name,length) in enumerate(((argv[1],argv[2]),(argv[3],argv[4]))):
            assert string(pages,target+which*24)==bytes(((17 if which==0 else 11)*i+(5 if which==0 else 0x63))&255 for i in range(length))+b'\0'
            if length>22: assert u(pages,target+which*24)&~1==(length+16)&~15
            elif len(spec.get('callbacks',[]))==1 or spec.get('entry_stack_fixture_size'):
                assert _read_span(pages,target+which*24+length+2,22-length)==bytes([spec.get('stack_pattern',0x96)])*(22-length)
        assert _read_span(pages,target+0x38,8)==((argv[6]&0xFFFFFFFF).to_bytes(4,'little')+(argv[5]&0xFFFFFFFF).to_bytes(4,'little') if kind==0 else bytes(8))
        if kind in (0,4):
            src=u(initial,AST)+(argv[6]&0xFFFFFFFF)*64
            expected=vectors(initial,src,0x3724F0)[:1 if kind==4 else 2]
            for outer in (node,cache):
                if kind==0: assert u(pages,outer+8,4)==u(initial,src+8,4)
                else: assert u(pages,outer+8)==4
                for original,new in zip(expected,vectors(pages,outer,table)):
                    assert new[1]-new[0]==new[2]-new[0]==original[1]-original[0]
                    assert _read_span(pages,new[0],new[1]-new[0])==_read_span(initial,original[0],original[1]-original[0])
                    if new[0]: assert new[0]!=original[0]
            for a,b in zip(vectors(pages,node,table),vectors(pages,cache,table)):
                if a[0]: assert a[0]!=b[0]
        elif kind in (1,2):
            descriptor=bytearray(_read_span(initial,argv[7] if kind==1 else argv[6],24))
            if not descriptor[16]: descriptor[8:16]=(0xFFFFFFFF if kind==1 else 0x1000000000000 if descriptor[18] else 0x10000).to_bytes(8,'little')
            for outer in (node,cache):
                assert u(pages,outer+8,4)==kind
                if kind==1:
                    assert u(pages,outer+0xC)==argv[6]
                    if len(spec.get('callbacks',[]))==1 or spec.get('entry_stack_fixture_size'):
                        assert _read_span(pages,outer+0x14,4)==bytes([spec.get('stack_pattern',0x96)])*4
                    assert _read_span(pages,outer+0x18,19)==descriptor[:19]
                else: assert _read_span(pages,outer+0x10,24)==descriptor
        else:
            for outer in (node,cache):
                assert u(pages,outer+8,4)==3 and u(pages,outer+0xC)==argv[6] and u(pages,outer+0x14,4)==argv[7]&1
    for kind,(off,stride,table) in enumerate(KINDS):
        current=u(pages,CB+off)
        assert (u(pages,CB+off+8)-current,u(pages,CB+off+16)-current)==(counts[kind]*stride,capacities[kind]*stride)
        old=u(initial,CB+off); last=u(initial,CB+off+8)
        for index in range((last-old)//stride):
            for old_vec,new_vec in zip(vectors(initial,old+index*stride,table),vectors(pages,current+index*stride,table)):
                assert old_vec==new_vec
    types=u(initial,AST); cap=u(initial,AST+16)
    assert _read_span(pages,AST,24)==_read_span(initial,AST,24)
    if types: assert _read_span(pages,types,cap-types)==_read_span(initial,types,cap-types)
    assert _read_span(pages,DESCRIPTOR+spec.get('descriptor_unaligned',0),24)==_read_span(initial,DESCRIPTOR+spec.get('descriptor_unaligned',0),24)
    if spec.get('callback_max_nodes') is not None or spec.get('callback_max_vector_bytes') is not None:
        bounded,_=prepare(args.library,base,observed); pointer=HEAP
        def allocate(n):
            nonlocal pointer
            out=pointer; pointer+=(n+15)&~15; return out
        for slot,argv in observed.get('callbacks',[]):
            alternative.run_reader_ast_callback(bounded,callback_address=CB,image_base=base,slot_offset=slot,
                arguments=argv,entry_stack_address=STACK,allocate=allocate,
                max_nodes=spec.get('callback_max_nodes',4096),max_vector_bytes=spec.get('callback_max_vector_bytes',16*1024*1024))
        assert _read_span(bounded,oracle.GUEST,0xA000)==_read_span(pages,oracle.GUEST,0xA000)
    row.update(independent_names_indexes_node_copies_cache_moves_and_borrowed_sources_match=True,
        actual_import_only_wrapper_cleanup_executed=bool(spec.get('destroy_imports')),
        guest_bytes_masked=False,native_stack_or_TLS_as_a_whole_compared=False,
        explicit_fresh_entry_frame_fixture_per_callback=bool(spec.get('entry_stack_fixture_size')),
        actual_stack_arguments_executed=any(slot in (0x30,0x40) for slot,_ in spec.get('callbacks',[])),
        exact_node_budget_control='callback_max_nodes' in spec,
        **({'exact_node_budget_supported':spec['callback_max_nodes']} if 'callback_max_nodes' in spec else {}))
    return row

def fixtures():
    cases=minimal_specs()
    for kind,slot in enumerate(FUNCTIONS):
        for imports in ((0,0),(0,3),(1,1),(2,3)):
            for cache in ((0,0),(0,3),(1,1),(2,3)):
                for lengths in ((0,0),(22,23),(23,22),(23,32)):
                    cases.append(dict(label=f'import_{kind}_{imports}_{cache}_{lengths}',imports=imports,
                        cache_vector=cache,entry_stack_address=STACK,callbacks=[(slot,arguments(kind,*lengths))],cleanup=True))
        for lengths in ((1,0),(0,1),(24,22),(22,24),(31,32),(32,31),(64,64)):
            cases.append(dict(label=f'import_{kind}_lengths_{lengths}',imports=(2,2),cache_vector=(1,1),
                entry_stack_address=STACK,callbacks=[(slot,arguments(kind,*lengths))],cleanup=True))
        for mode in ('empty_vectors','empty_owned'):
            cases.append(dict(label=f'import_{kind}_{mode}',imports=(3,3),cache_vector=(1,1),**{mode:True},
                **({'empty_vectors':True} if mode=='empty_owned' else {}),
                entry_stack_address=STACK,callbacks=[(slot,arguments(kind))],cleanup=True))
        for lengths in ((0,0),(22,23),(23,22),(32,32)):
            cases.append(dict(label=f'cleanup_import_{kind}_{lengths}',definitions=(),imports=(3,4),old_kinds=(kind,),
                old_name_lengths=(lengths,),destroy_imports=True,cleanup=True))
        cases.append(dict(label=f'import_{kind}_exact_node_budget',callback_max_nodes=10,
            entry_stack_address=STACK,callbacks=[(slot,arguments(kind,0,0))],cleanup=True))
        cases.append(dict(label=f'import_{kind}_repeated_growth',imports=(1,1),cache_vector=(1,1),
            entry_stack_address=STACK,callbacks=[(slot,arguments(kind,i*7,i*9,index=i%2)) for i in range(6)],cleanup=True))
        cases.append(dict(label=f'import_{kind}_nonnull_zero_capacity',imports=(0,0),cache_vector=(0,0),
            nonnull_empty=True,cache_nonnull_empty=True,entry_stack_address=STACK,callbacks=[(slot,arguments(kind,0,0))],cleanup=True))
    for flag in (0,1,9):
        cases.append(dict(label=f'import_table_maximum_flag_{flag}',imports=(1,1),cache_vector=(1,1),maximum_flag=flag,
            stack_pattern=0xB7,entry_stack_address=STACK,callbacks=[(0x30,arguments(1,7,23,type_value=0xFFFFFFFFFFFFFFF0))],cleanup=True))
        for memory64 in (0,1):
            cases.append(dict(label=f'import_memory_flags_{flag}_{memory64}',imports=(1,1),cache_vector=(1,1),
                maximum_flag=flag,memory64=memory64,entry_stack_address=STACK,callbacks=[(0x38,arguments(2,23,7))],cleanup=True))
    for value in (0,1,0x100,0x101,0xFFFFFFFFFFFFFFFF,0x8000000000000000):
        cases.append(dict(label=f'import_global_full_type_mutable_{value}',imports=(1,1),cache_vector=(1,1),
            entry_stack_address=STACK,callbacks=[(0x40,arguments(3,23,32,type_value=value,mutable=value))],cleanup=True))
    cases += [dict(label='import_all_kinds_fresh_frames',imports=(3,3),cache_vector=(2,2),
            entry_stack_address=STACK,entry_stack_fixture_size=0x110,stack_pattern=0xB7,
            callbacks=[(slot,arguments(k,32-k*7,k*7)) for k,slot in enumerate(FUNCTIONS)],cleanup=True),
        dict(label='import_heap_short_old_names',imports=(3,3),old_heap_short=True,old_name_lengths=((0,22),),
            entry_stack_address=STACK,callbacks=[(0x40,arguments(3,0,0))],cleanup=True),
        dict(label='import_empty_cleanup',definitions=(),imports=(0,0),destroy_imports=True),
        dict(label='import_empty_owned_cleanup',definitions=(),imports=(0,3),destroy_imports=True),
        dict(label='import_nonnull_empty_cleanup',definitions=(),imports=(0,0),nonnull_empty=True,destroy_imports=True)]
    for kind in (1,2):
        argv=list(arguments(kind)); argv[7 if kind==1 else 6]=DESCRIPTOR+1
        cases.append(dict(label=f'import_descriptor_unaligned_{kind}',descriptor_unaligned=1,imports=(1,1),cache_vector=(1,1),
            entry_stack_address=STACK,callbacks=[(0x28+kind*8,tuple(argv))],cleanup=True))
    cases.append(dict(label='import_name_allocation_bound_positive',definitions=((0,(),()),),cache_vector=(0,0),
        callback_max_vector_bytes=144,entry_stack_address=STACK,callbacks=[(0x40,arguments(3,128,0))],cleanup=True))
    return cases

def negatives(args):
    base=0x122C0000; rows=[]; cases=[]
    standard=dict(label='guard',imports=(2,2),cache_vector=(1,1),entry_stack_address=STACK,
        callbacks=[(0x48,arguments(4,23,32))])
    u=lambda p,a,n=8:int.from_bytes(_read_span(p,a,n),'little')
    def add(label,changes=None,setup=None,spec=None,cleanup=False,paired=False):
        cases.append((label,changes or {},setup,standard if spec is None else spec,cleanup,paired))
    for kind,slot in enumerate(FUNCTIONS):
        spec=dict(label='guard',entry_stack_address=STACK,callbacks=[(slot,arguments(kind))])
        add(f'slot_binding_{kind}',setup=lambda p,slot=slot:put(p,base+0x372370+slot,0),spec=spec)
        got=(0x375090,0x375098,0x3750A0,0x3750A8,0x375088)[kind]
        add(f'GOT_binding_{kind}',setup=lambda p,got=got:put(p,base+got,0),spec=spec)
        for off in (0,8,16):
            table=KINDS[kind][2]
            add(f'node_binding_{kind}_{off}',setup=lambda p,table=table,off=off:put(p,base+table+off,0),spec=spec)
        add(f'node_bound_{kind}',dict(max_nodes=9),spec=spec,paired=True)
        if kind in (1,3):
            add(f'allocator_incoming_stack_{kind}',dict(allocate=lambda n:STACK),spec=spec)
    add('unsupported_slot',dict(slot_offset=0x10))
    add('attached',setup=lambda p:put(p,CB+8,MODULE))
    for index,argv in enumerate(((),arguments(4)+(7,),arguments(4)[:-1],(0,MODULE,-1,FIELD,0,0,0),
            (0,MODULE,1<<64,FIELD,0,0,0),(0,MODULE,0,FIELD,0,0,2),(0,MODULE,0,FIELD,0,0,0xFFFFFFFF))):
        add(f'arguments_{index}',dict(arguments=argv))
    for which,arg in (('module',1),('field',3)):
        for label,address in (('callback',CB),('output',AST),('cache',controls.OLD),
                ('frame',STACK-0xE0),('unmapped',0x90000000)):
            argv=list(standard['callbacks'][0][1]); argv[arg]=address
            add(f'{which}_source_{label}',dict(arguments=tuple(argv)))
    for kind in (1,2):
        slot=0x28+kind*8
        for label,address in (('callback',CB),('output',AST),('cache',controls.OLD),
                ('frame',STACK-0xE0),('unmapped',0x90000000),('null',0)):
            argv=list(arguments(kind)); argv[7 if kind==1 else 6]=address
            add(f'descriptor_{kind}_{label}',spec=dict(label='guard',entry_stack_address=STACK,callbacks=[(slot,tuple(argv))]))
    for label,address in (('missing',None),('unaligned',STACK+1),('unmapped',0x90001000),('owner_alias',AST+0x100)):
        add('stack_'+label,dict(entry_stack_address=address))
    add('type_source_vtable',setup=lambda p:put(p,u(p,AST),0))
    add('output_partial_end',setup=lambda p:put(p,AST+0x20,u(p,AST+0x18)+65))
    add('output_partial_capacity',setup=lambda p:put(p,AST+0x28,u(p,AST+0x18)+129))
    add('output_node_null',setup=lambda p:put(p,u(p,AST+0x18)+0x30,0))
    add('output_node_alias_cache',setup=lambda p:put(p,u(p,AST+0x18)+0x30,u(p,CB+0x80)))
    for off in (0,24):
        add(f'output_string_invalid_{off}',setup=lambda p,off=off:put(p,u(p,AST+0x18)+off,46 if off==0 else 1,1))
    add('module_heap_alias_field',setup=lambda p:put(p,u(p,AST+0x18),33) or
        put(p,u(p,AST+0x18)+8,0) or put(p,u(p,AST+0x18)+16,u(p,u(p,AST+0x18)+24+16)))
    wrong=dict(label='guard',entry_stack_address=STACK,callbacks=[(0x38,arguments(2))])
    add('cache_wrong_40_byte_family',setup=lambda p:put(p,u(p,CB+0xB0),base+0x372590) or
        vector(p,u(p,CB+0xB0)+0x10),spec=wrong)
    add('output_growth_node_bound',dict(max_nodes=13),paired=True)
    add('output_growth_byte_bound',dict(max_vector_bytes=255),paired=True)
    name_bound=dict(label='guard',definitions=((0,(),()),),cache_vector=(0,0),entry_stack_address=STACK,
        callbacks=[(0x40,arguments(3,128,0))])
    add('name_allocation_byte_bound',dict(max_vector_bytes=136),spec=name_bound,paired=True)
    add('missing_allocator',dict(allocate=None))
    for label,changes,setup in (
        ('other_output',{},lambda p:vector(p,AST,FIELD,0,1,64)),
        ('node_bound',dict(max_nodes=2),None),('byte_bound',dict(max_vector_bytes=31),None),
        ('root_unmapped',dict(output_address=0x90000000),None),('root_unaligned',dict(output_address=AST+1),None)):
        add('cleanup_'+label,changes,setup,dict(label='guard',definitions=(),imports=(3,4)),True,label=='node_bound')
    for label,changes,setup,spec,cleanup,paired in cases:
        pages,_=prepare(args.library,base,spec)
        if setup: setup(pages)
        before={k:bytes(v) for k,v in pages.items()}; pointer=HEAP
        def allocate(size):
            nonlocal pointer
            out=pointer; pointer+=(size+15)&~15; return out
        params=dict(output_address=AST,image_base=base) if cleanup else dict(callback_address=CB,image_base=base,
            slot_offset=spec['callbacks'][0][0],arguments=spec['callbacks'][0][1],entry_stack_address=STACK,allocate=allocate)
        params.update(changes)
        if paired:
            original,_=prepare(args.library,base,spec)
            if cleanup: alternative.cleanup_reader_ast_import_output(original,output_address=AST,image_base=base)
            else: alternative.run_reader_ast_callback(original,callback_address=CB,image_base=base,
                slot_offset=spec['callbacks'][0][0],arguments=spec['callbacks'][0][1],entry_stack_address=STACK,allocate=allocate)
            pointer=HEAP
        run=alternative.cleanup_reader_ast_import_output if cleanup else alternative.run_reader_ast_callback
        try: run(pages,**params)
        except (RefillUnsupported,ValueError): pass
        else: raise AssertionError('import guard accepted: '+label)
        assert before=={k:bytes(v) for k,v in pages.items()},label
        rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_invalid_memory_path_compared=False,
            **({'same_input_without_budget_restriction_supported':True} if paired else {})))
    final,effects,_=controls.model_case(args,base,standard,prepare_case=prepare)
    allocations=[e for e in effects if e[0]=='allocate']
    for stage in range(1,len(allocations)+1):
        for target in ('callback','output','type','cache','import','node','payload','module','field','descriptor',
                'frame','image','unmapped','unaligned','prior_plan'):
            if stage==1 and target=='prior_plan': continue
            pages,_=prepare(args.library,base,standard); record=u(pages,AST+0x18); node=u(pages,record+0x30)
            targets=dict(callback=CB,output=AST,type=u(pages,AST),cache=u(pages,CB+0xE0),
                **{'import':record},node=node,payload=u(pages,node+0x10),module=MODULE,field=FIELD,
                descriptor=DESCRIPTOR,frame=STACK-0x100,image=base+0x1000,unmapped=0x90000000,
                unaligned=HEAP+1,prior_plan=HEAP)
            # A descriptor is borrowed only by table/memory callbacks. Retain
            # it explicitly in this kind4 allocator fixture as caller input.
            before={k:bytes(v) for k,v in pages.items()}; count=0; pointer=HEAP
            def allocate(size):
                nonlocal count,pointer
                count+=1
                if count==stage: return targets[target]
                out=pointer; pointer+=(size+15)&~15; return out
            try: alternative.run_reader_ast_callback(pages,callback_address=CB,image_base=base,slot_offset=0x48,
                arguments=standard['callbacks'][0][1],entry_stack_address=STACK,allocate=allocate,
                reserved_regions=((DESCRIPTOR,DESCRIPTOR+24),))
            except (RefillUnsupported,ValueError): pass
            else: raise AssertionError('allocation guard accepted: '+str((stage,target)))
            assert before=={k:bytes(v) for k,v in pages.items()},(stage,target)
            rows.append(dict(label=f'allocation_{stage}_{target}',rejected=True,all_pages_unchanged=True,native_invalid_memory_path_compared=False))
    for cleanup in (False,True):
        spec=dict(label='guard',definitions=(),imports=(3,4)) if cleanup else standard
        initial,_=prepare(args.library,base,spec); first=u(initial,AST+0x18); new=u(final,AST+0x18)
        temporary=next(e[1] for e in allocations if e[2]==40)
        targets=(first+0x30,AST+0x20) if cleanup else (new+2*64,new+2*64+24,new+2*64+0x30,
            new+2*64+0x38,AST+0x18,first+0x30,CB+0xE0,temporary+0x18,STACK-0x100+0x78+0x18)
        for target in targets:
            pages,_=prepare(args.library,base,spec); before={k:bytes(v) for k,v in pages.items()}
            original=alternative._write_span; pointer=HEAP
            def allocate(size):
                nonlocal pointer
                out=pointer; pointer+=(size+15)&~15; return out
            def fail(p,address,data):
                if address==target: raise RefillUnsupported('injected import write')
                original(p,address,data)
            alternative._write_span=fail
            try:
                try:
                    if cleanup: alternative.cleanup_reader_ast_import_output(pages,output_address=AST,image_base=base)
                    else: alternative.run_reader_ast_callback(pages,callback_address=CB,image_base=base,slot_offset=0x48,
                        arguments=standard['callbacks'][0][1],entry_stack_address=STACK,allocate=allocate)
                except RefillUnsupported as exc: assert str(exc)=='injected import write'
                else: raise AssertionError('late import guard accepted')
            finally: alternative._write_span=original
            assert before=={k:bytes(v) for k,v in pages.items()}
            rows.append(dict(label=f'late_write_{cleanup}_{target:x}',rejected=True,all_pages_unchanged=True,native_invalid_memory_path_compared=False))
    return rows

def main():
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('--library',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path); args=parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    rows=[]; specs=fixtures(); guards=negatives(args)
    for base in (0x122C0000,0x775C205000):
        for index,spec in enumerate(specs,1):
            rows.append(compare(args,base,spec))
            if index%24==0 or index==len(specs): print('B import:',hex(base),index,'/',len(specs),'passed',flush=True)
    evidence=dict(schema='vm9-alternative-ast-import-fresh-v1',evidence_date='2026-10-10',evidence_timezone='Asia/Shanghai',
        sample_sha256=oracle.LIBRARY_SHA256,native_Python_AST_import_controls=len(rows),pre_change_behavior_RED_controls=6,
        import_callback_slots_hex=['0x28','0x30','0x38','0x40','0x48'],
        import_callback_offsets_hex=['0x31b870','0x31bb48','0x31be3c','0x31c144','0x31c414'],
        import_growth_offset_hex='0x31eb34',import_only_wrapper_cleanup_offset_hex='0x2cbadc',import_output_offset_hex='0x18',
        import_record_stride=64,table_import_default_maximum_hex='0xffffffff',explicit_entry_stack_padding_required=True,
        stack_arguments_follow_AArch64_ABI=True,cache_append_after_temporary_cleanup=True,
        all_fixtures_synthetic=True,native_input_snapshot_used=False,guest_bytes_masked=False,
        import_AST_callbacks_implemented=True,import_only_wrapper_cleanup_implemented=True,complete_output_wrapper_cleanup_implemented=False,
        attached_parser_implemented=False,complete_python_reader_implemented=False,independent_Python_factory_implemented=False,
        complete_python_bootstrap_controls=0,fresh_signer_output_verified=False,private_payloads_published=False,
        rollback_negative_controls=len(guards),cases=rows,negative_cases=guards)
    args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    print('B import:',len(rows),'native/Python +',len(guards),'rollback checks passed',flush=True)

if __name__=='__main__': main()
