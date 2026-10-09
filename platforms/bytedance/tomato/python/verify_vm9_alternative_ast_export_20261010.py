"""Fresh B export callback, five virtual clones and export-only wrapper cleanup."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

import verify_vm9_alternative_ast_data_20261009 as controls
import verify_vm9_signer_objects as oracle
import vm9_alternative_startup as alternative
from vm9_allocator import RefillUnsupported, _read_span, _write_span

CB,AST,INPUT,HEAP=controls.CB,controls.AST,controls.INPUT,controls.HEAP
put,vector=controls.put,controls.vector
STACK=oracle.GUEST+0xEF00
FUNCTIONS={0x98:0x31D500}
KINDS=((0x80,64,0x3724F0),(0x98,48,0x372518),(0xB0,40,0x372540),
       (0xC8,24,0x372568),(0xE0,40,0x372590))

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
    def node(address,kind,index):
        _,stride,table=KINDS[kind]
        put(pages,address,base+table); put(pages,address+8,0xD00D0000+index,4)
        if kind==0:
            owned(address+0x10,[] if spec.get('empty_vectors') else [0x8000000000000000+index],3)
            owned(address+0x28,[] if spec.get('empty_vectors') else [0xFFFFFFFFFFFFFFF0,7+index],4)
        elif kind==4:
            put(pages,address+0xC,0x12340000+index,4)
            owned(address+0x10,[] if spec.get('empty_vectors') else [0x1122334455667788+index,9],3)
        elif kind==1:
            _write_span(pages,address+0xC,bytes((index+i*7)&255 for i in range(31)))
        elif kind==2:
            _write_span(pages,address+0x10,bytes((index+i*11)&255 for i in range(24)))
        else:
            put(pages,address+0xC,0xFFFFFFFFFFFFFFF0+index); put(pages,address+0x14,0xF0010000+index,4)
    for kind,(offset,stride,_) in enumerate(KINDS):
        count,capacity=spec.get('cache_vector',(2,3)); begin=block(capacity*stride,0xB3)
        vector(pages,CB+offset,begin,count,capacity,stride)
        for index in range(count): node(begin+index*stride,kind,index)
    count,capacity=spec.get('exports',(0,0))
    if capacity or spec.get('nonnull_empty'):
        begin=block(capacity*40,0xC3); vector(pages,AST+0xA8,begin,count,capacity,40)
        for index in range(count):
            address=begin+index*40; length=spec.get('old_name_lengths',(3,23,32))[index%len(spec.get('old_name_lengths',(3,23,32)))]
            payload=bytes((i*13+index)&255 for i in range(length))+b'\0'
            if length<=22:
                header=bytearray(b'\xb6'*24); header[0]=length*2; header[1:length+2]=payload
                _write_span(pages,address,header)
            else:
                storage=(length+16)&~15; data=block(storage,0xD7); _write_span(pages,data,payload)
                _write_span(pages,address,(storage|1).to_bytes(8,'little')+length.to_bytes(8,'little')+data.to_bytes(8,'little'))
            kind=spec.get('old_kinds',(0,4,1,2,3))[index%len(spec.get('old_kinds',(0,4,1,2,3)))]
            data=block(KINDS[kind][1],0xD8); node(data,kind,index)
            put(pages,address+0x18,data); put(pages,address+0x20,0x12340000+index,4)
    for _,argv in spec.get('callbacks',[]):
        name,length=argv[3],argv[4]
        if length: _write_span(pages,name,bytes((i*17+5)&255 for i in range(length)))
    _write_span(pages,STACK-0x90,bytes([spec.get('stack_pattern',0x96)])*0x90)
    return pages,sizes

def minimal_specs():
    return [dict(label='export_spare_short_global',exports=(1,3),
            callbacks=[(0x98,(99,0x100000003,0xFFFFFFFF00000001,INPUT,7))],entry_stack_address=STACK),
        dict(label='export_growth_long_type',exports=(2,2),
            callbacks=[(0x98,(0xFFFFFFFFFFFFFFFF,0,0,INPUT,23))],entry_stack_address=STACK),
        dict(label='export_rich_wrapper_cleanup',exports=(3,4),old_kinds=(0,4,3),destroy_exports=True)]

def compare(args,base,spec):
    row=controls.compare(args,base,spec,functions=FUNCTIONS,prepare_case=prepare)
    observed={k:v for k,v in spec.items() if k not in ('destroy_exports','cleanup')}
    initial,_=prepare(args.library,base,observed)
    pages,effects,statuses=controls.model_case(args,base,observed,prepare_case=prepare)
    u=lambda p,a,n=8:int.from_bytes(_read_span(p,a,n),'little')
    def string(p,address):
        header=_read_span(p,address,24)
        if header[0]&1: return _read_span(p,u(p,address+16),u(p,address+8)+1)
        return header[1:(header[0]>>1)+2]
    def check_node(source,target,source_pages=None):
        original=pages if source_pages is None else source_pages
        table=u(original,source)-base
        assert u(pages,target)==base+table and u(pages,target+8,4)==u(original,source+8,4)
        if table in (0x3724F0,0x372590):
            if table==0x372590: assert u(pages,target+0xC,4)==u(original,source+0xC,4)
            for off in ((0x10,0x28) if table==0x3724F0 else (0x10,)):
                old_begin,old_end=u(original,source+off),u(original,source+off+8)
                begin,end,cap=(u(pages,target+off+n) for n in (0,8,16))
                assert end-begin==cap-begin==old_end-old_begin
                assert _read_span(pages,begin,end-begin)==_read_span(original,old_begin,old_end-old_begin)
                if begin: assert begin!=old_begin
        else:
            off,n=(0xC,31) if table==0x372518 else (0x10,24) if table==0x372540 else (0xC,12)
            assert _read_span(pages,target+off,n)==_read_span(original,source+off,n)
        if table in (0x3724F0,0x372540): assert _read_span(pages,target+0xC,4)==b'\xa5'*4
        if table==0x372518: assert _read_span(pages,target+0x2B,5)==b'\xa5'*5
        assert target!=source
    size,capacity=spec.get('exports',(0,0)); prior_size=size
    for _,argv in spec.get('callbacks',[]):
        if size==capacity: capacity=max(size+1,capacity*2)
        size+=1
    begin=u(pages,AST+0xA8)
    assert u(pages,AST+0xB0)-begin==size*40 and u(pages,AST+0xB8)-begin==capacity*40
    for index in range(prior_size):
        source=u(initial,AST+0xA8)+index*40; target=begin+index*40
        assert string(pages,target)==string(initial,source)
        assert u(pages,target+0x20,4)==u(initial,source+0x20,4)
        if begin!=u(initial,AST+0xA8):
            assert u(pages,source+24)==0
            check_node(u(initial,source+24),u(pages,target+24),initial)
    for index,(_,argv) in enumerate(spec.get('callbacks',[]),prior_size):
        _,kind,node_index,name,length=argv; kind&=0xFFFFFFFF; node_index&=0xFFFFFFFF
        target=begin+index*40; selected=u(initial,CB+KINDS[kind][0])+node_index*KINDS[kind][1]
        # Caches remain unchanged, including their independent vector capacity.
        check_node(selected,u(pages,target+24))
        assert string(pages,target)==bytes((i*17+5)&255 for i in range(length))+b'\0'
        assert u(pages,target+32,4)==node_index
        if length<=22:
            assert _read_span(pages,target+length+2,22-length)==bytes([spec.get('stack_pattern',0x96)])*(22-length)
        else: assert u(pages,target)&~1==(length+16)&~15
    for offset,stride,_ in KINDS:
        pointer=u(initial,CB+offset); cap=u(initial,CB+offset+16)
        assert _read_span(pages,CB+offset,24)==_read_span(initial,CB+offset,24)
        assert _read_span(pages,pointer,cap-pointer)==_read_span(initial,pointer,cap-pointer)
    if not spec.get('callbacks'):
        assert not effects and not statuses
    if spec.get('callback_max_nodes') is not None:
        bounded,_=prepare(args.library,base,observed); pointer=HEAP
        def allocate(n):
            nonlocal pointer
            out=pointer; pointer+=(n+15)&~15; return out
        for slot,argv in observed.get('callbacks',[]):
            alternative.run_reader_ast_callback(bounded,callback_address=CB,image_base=base,
                slot_offset=slot,arguments=argv,entry_stack_address=STACK,allocate=allocate,max_nodes=spec['callback_max_nodes'])
        assert _read_span(bounded,oracle.GUEST,0xA000)==_read_span(pages,oracle.GUEST,0xA000)
    row.update(independent_capacity_name_padding_index_node_and_borrowed_cache_expectations_match=True,
        actual_export_only_wrapper_cleanup_executed=bool(spec.get('destroy_exports')),
        guest_bytes_masked=False,native_stack_or_TLS_as_a_whole_compared=False,
        exact_node_budget_control='callback_max_nodes' in spec,
        **({'exact_node_budget_supported':spec['callback_max_nodes']} if 'callback_max_nodes' in spec else {}))
    return row

def fixtures():
    cases=minimal_specs()
    for kind in range(5):
        for exports in ((0,0),(0,3),(1,1),(2,3)):
            for length in (0,1,22,23,24,31,32):
                cases.append(dict(label=f'export_{kind}_{exports}_{length}',exports=exports,
                    callbacks=[(0x98,(0xFFFFFFFFFFFFFFFF,0xFFFFFFFF00000000+kind,0x100000001,
                        0x90000000 if length==0 else INPUT,length))],entry_stack_address=STACK,destroy_exports=True,cleanup=True))
    for kind in range(5):
        for mode in ('empty_vectors','empty_owned'):
            cases.append(dict(label=f'export_{kind}_{mode}',exports=(1,1),**{mode:True},
                callbacks=[(0x98,(99,kind,0,INPUT,23))],entry_stack_address=STACK,destroy_exports=True,cleanup=True))
    for kind in range(5):
        for length in (0,22,23,32):
            cases.append(dict(label=f'cleanup_{kind}_{length}',exports=(3,4),old_kinds=(kind,),
                old_name_lengths=(length,),destroy_exports=True,cleanup=True))
    cases += [dict(label='export_all_kinds_growth_and_padding',exports=(3,3),old_kinds=(0,4,1),stack_pattern=0xB7,
        callbacks=[(0x98,(99,k,1,INPUT,n)) for k,n in enumerate((0,22,23,24,32))],entry_stack_address=STACK,
        destroy_exports=True,cleanup=True),
        dict(label='export_repeated_growth',exports=(1,1),
            callbacks=[(0x98,(99,i%5,i%2,INPUT,i*7)) for i in range(8)],entry_stack_address=STACK,
            destroy_exports=True,cleanup=True),
        dict(label='export_nonnull_zero_capacity',exports=(0,0),nonnull_empty=True,
            callbacks=[(0x98,(0,3,0,INPUT,0))],entry_stack_address=STACK,destroy_exports=True,cleanup=True),
        dict(label='export_empty_cleanup',exports=(0,0),destroy_exports=True),
        dict(label='export_empty_owned_cleanup',exports=(0,3),destroy_exports=True)]
    # Ten input cache nodes plus two global clones, with no output growth node.
    cases.append(dict(label='export_exact_node_budget',exports=(0,3),callback_max_nodes=12,
        callbacks=[(0x98,(0,3,0,INPUT,1))],entry_stack_address=STACK,destroy_exports=True,cleanup=True))
    cases += [dict(label='export_growth_exact_clone_budget',exports=(3,3),callback_max_nodes=18,
        callbacks=[(0x98,(0,3,0,INPUT,0))],entry_stack_address=STACK,destroy_exports=True,cleanup=True),
        dict(label='export_name_allocation_bound_positive',cache_vector=(1,1),
            callbacks=[(0x98,(0,3,0,INPUT,64))],entry_stack_address=STACK,destroy_exports=True,cleanup=True)]
    return cases

def negatives(args):
    base=0x122C0000; rows=[]; cases=[]
    standard=dict(label='guard',exports=(2,2),callbacks=[(0x98,(99,0,0,INPUT,23))],entry_stack_address=STACK)
    u=lambda p,a,n=8:int.from_bytes(_read_span(p,a,n),'little')
    def add(label,changes=None,setup=None,spec=None,cleanup=False):
        cases.append((label,changes or {},setup,standard if spec is None else spec,cleanup))
    add('slot_binding',setup=lambda p:put(p,base+0x372370+0x98,0))
    add('attached',setup=lambda p:put(p,CB+8,INPUT))
    for kind,(_,_,table) in enumerate(KINDS):
        for slot in (0,8,16):
            add(f'node_binding_{kind}_{slot}',dict(arguments=(99,kind,0,INPUT,23)),
                setup=lambda p,table=table,slot=slot:put(p,base+table+slot,0))
    add('type_GOT',setup=lambda p:put(p,base+0x375090,0))
    for argv in ((0,0,0,INPUT),(0,0,0,INPUT,23,7),(0,5,0,INPUT,0),(0,0,2,INPUT,0),
        (0,0,0,INPUT,-1),(0,0,0,INPUT,1<<64),(0,0,0,0x90000000,23)):
        add('arguments_'+str(argv),dict(arguments=argv))
    for name,address in (('callback',CB),('output',AST),('cache',None),('stack',STACK-0x80)):
        add('name_alias_'+name,setup=lambda p,name=name,address=address:None,
            changes=dict(arguments=(0,0,0,controls.OLD if address is None else address,23)))
    add('stack_missing',dict(entry_stack_address=None))
    add('stack_unaligned',dict(entry_stack_address=STACK+1))
    add('stack_unmapped',dict(entry_stack_address=0x90001000))
    add('stack_owner_alias',dict(entry_stack_address=AST+0x90))
    add('output_partial_end',setup=lambda p:put(p,AST+0xB0,u(p,AST+0xA8)+41))
    add('output_partial_capacity',setup=lambda p:put(p,AST+0xB8,u(p,AST+0xA8)+81))
    add('output_node_alias_cache',setup=lambda p:put(p,u(p,AST+0xA8)+24,u(p,CB+0x80)))
    add('output_node_null',setup=lambda p:put(p,u(p,AST+0xA8)+24,0))
    add('output_inline_length',setup=lambda p:put(p,u(p,AST+0xA8),46,1))
    add('output_heap_capacity',setup=lambda p:put(p,u(p,AST+0xA8)+40,1))
    growth=dict(label='guard',exports=(3,3),callbacks=[(0x98,(0,3,0,INPUT,0))],entry_stack_address=STACK)
    name_bound=dict(label='guard',cache_vector=(1,1),callbacks=[(0x98,(0,3,0,INPUT,64))],entry_stack_address=STACK)
    add('node_bound',dict(max_nodes=17),spec=growth)
    add('outer_allocation_byte_bound',dict(max_vector_bytes=200),spec=growth)
    add('name_allocation_byte_bound',dict(max_vector_bytes=72),spec=name_bound)
    add('name_length_bound',dict(arguments=(0,3,0,INPUT,16*1024*1024)))
    add('missing_allocator',dict(allocate=None))
    for label,changes,setup in (
        ('other_output',{},lambda p:vector(p,AST+0xC0,INPUT,0,1,4)),
        ('node_bound',dict(max_nodes=2),None),
        ('byte_bound',dict(max_vector_bytes=31),None),
        ('root_unmapped',dict(output_address=0x90000000),None),
        ('root_unaligned',dict(output_address=AST+1),None)):
        add('cleanup_'+label,changes,setup,dict(label='guard',exports=(3,4)),True)
    for label,changes,setup,spec,cleanup in cases:
        pages,_=prepare(args.library,base,spec)
        if setup: setup(pages)
        before={k:bytes(v) for k,v in pages.items()}; pointer=HEAP
        def allocate(size):
            nonlocal pointer
            out=pointer; pointer+=(size+15)&~15; return out
        params=dict(output_address=AST,image_base=base) if cleanup else dict(callback_address=CB,image_base=base,
            slot_offset=0x98,arguments=spec['callbacks'][0][1],entry_stack_address=STACK,allocate=allocate)
        params.update(changes)
        paired=label in ('node_bound','outer_allocation_byte_bound','name_allocation_byte_bound','cleanup_node_bound')
        if paired:
            original,_=prepare(args.library,base,spec)
            if cleanup: alternative.cleanup_reader_ast_export_output(original,output_address=AST,image_base=base)
            else: alternative.run_reader_ast_callback(original,callback_address=CB,image_base=base,slot_offset=0x98,
                arguments=spec['callbacks'][0][1],entry_stack_address=STACK,allocate=allocate)
            pointer=HEAP
        run=alternative.cleanup_reader_ast_export_output if cleanup else alternative.run_reader_ast_callback
        try: run(pages,**params)
        except (RefillUnsupported,ValueError): pass
        else: raise AssertionError('export guard accepted: '+label)
        assert before=={k:bytes(v) for k,v in pages.items()},label
        rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_invalid_memory_path_compared=False,
            **({'same_input_without_budget_restriction_supported':True} if paired else {})))
    # Exercise every allocation position in a valid growth case. Late plans
    # must retain all original pages, even after string and node clones.
    _,effects,_=controls.model_case(args,base,standard,prepare_case=prepare)
    allocations=[e for e in effects if e[0]=='allocate']
    for stage in range(1,len(allocations)+1):
        for target in ('callback','output','cache','export','node','payload','name','stack','image','unmapped','unaligned','prior_plan'):
            if stage==1 and target=='prior_plan': continue
            pages,_=prepare(args.library,base,standard); record=u(pages,AST+0xA8); node=u(pages,record+24)
            targets=dict(callback=CB,output=AST,cache=u(pages,CB+0x80),export=record,node=node,
                payload=u(pages,node+0x10),name=INPUT,stack=STACK-0x90,image=base+0x1000,
                unmapped=0x90000000,unaligned=HEAP+1,prior_plan=HEAP)
            before={k:bytes(v) for k,v in pages.items()}; count=0; pointer=HEAP
            def allocate(size):
                nonlocal count,pointer
                count+=1
                if count==stage: return targets[target]
                out=pointer; pointer+=(size+15)&~15; return out
            try: alternative.run_reader_ast_callback(pages,callback_address=CB,image_base=base,slot_offset=0x98,
                arguments=standard['callbacks'][0][1],entry_stack_address=STACK,allocate=allocate)
            except (RefillUnsupported,ValueError): pass
            else: raise AssertionError('allocation guard accepted: '+str((stage,target)))
            assert before=={k:bytes(v) for k,v in pages.items()},(stage,target)
            rows.append(dict(label=f'allocation_{stage}_{target}',rejected=True,all_pages_unchanged=True,native_invalid_memory_path_compared=False))
    for cleanup in (False,True):
        spec=dict(label='guard',exports=(3,4)) if cleanup else standard
        final,_,_=controls.model_case(args,base,spec,prepare_case=prepare)
        initial,_=prepare(args.library,base,spec); first=u(initial,AST+0xA8); new=u(final,AST+0xA8)
        targets=(first+24,AST+0xB0) if cleanup else (new+2*40,new+2*40+24,new+2*40+32,AST+0xA8,first+24)
        for target in targets:
            pages,_=prepare(args.library,base,spec); before={k:bytes(v) for k,v in pages.items()}
            original=alternative._write_span; pointer=HEAP
            def allocate(size):
                nonlocal pointer
                out=pointer; pointer+=(size+15)&~15; return out
            def fail(p,address,data):
                if address==target: raise RefillUnsupported('injected export write')
                original(p,address,data)
            alternative._write_span=fail
            try:
                try:
                    if cleanup: alternative.cleanup_reader_ast_export_output(pages,output_address=AST,image_base=base)
                    else: alternative.run_reader_ast_callback(pages,callback_address=CB,image_base=base,
                        slot_offset=0x98,arguments=standard['callbacks'][0][1],entry_stack_address=STACK,allocate=allocate)
                except RefillUnsupported as exc: assert str(exc)=='injected export write'
                else: raise AssertionError('late export guard accepted')
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
            if index%24==0 or index==len(specs): print('B export:',hex(base),index,'/',len(specs),'passed',flush=True)
    evidence=dict(schema='vm9-alternative-ast-export-fresh-v1',evidence_date='2026-10-10',evidence_timezone='Asia/Shanghai',
        sample_sha256=oracle.LIBRARY_SHA256,native_Python_AST_export_controls=len(rows),pre_change_behavior_RED_controls=3,
        export_callback_slot_hex='0x98',export_callback_offset_hex='0x31d500',export_growth_offset_hex='0x320118',
        export_only_wrapper_cleanup_offset_hex='0x2cbadc',export_output_offset_hex='0xa8',export_record_stride=40,
        node_clone_offsets_hex=['0x321090','0x3210d0','0x321120','0x321170','0x3211c0'],
        node_deleting_destructor_offsets_hex=['0x3212b0','0x3212fc','0x321300','0x321304','0x32132c'],
        explicit_entry_stack_padding_required=True,all_fixtures_synthetic=True,native_input_snapshot_used=False,guest_bytes_masked=False,
        export_callback_implemented=True,export_only_wrapper_cleanup_implemented=True,complete_output_wrapper_cleanup_implemented=False,
        import_AST_callbacks_implemented=False,attached_parser_implemented=False,complete_python_reader_implemented=False,
        independent_Python_factory_implemented=False,complete_python_bootstrap_controls=0,fresh_signer_output_verified=False,
        private_payloads_published=False,rollback_negative_controls=len(guards),cases=rows,negative_cases=guards)
    args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    print('B export:',len(rows),'native/Python +',len(guards),'rollback checks passed',flush=True)

if __name__=='__main__': main()
