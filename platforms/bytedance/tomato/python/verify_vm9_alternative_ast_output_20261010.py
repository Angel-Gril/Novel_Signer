"""Fresh complete B output wrapper cleanup with twelve disjoint containers.

Actual +2cbadc executes on synthetic inputs at two image bases. Full guest
bytes and every ordered effect are compared without snapshots or masking.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import random

import verify_vm9_alternative_ast_data_20261009 as controls
import verify_vm9_alternative_ast_global_20261009 as global_controls
import verify_vm9_alternative_ast_export_20261010 as export
import vm9_alternative_startup as alternative
from vm9_allocator import RefillUnsupported,_read_span,_write_span

AST,CB=controls.AST,controls.CB
put,vector=controls.put,controls.vector
STRIDES=(64,64,144,48,40,176,40,40,4,184,176,1)
OFFSETS=tuple(range(0,0x120,24))
BASES=(0x122C0000,0x775C205000)


def prepare(library,base,spec):
    if spec.get('kind')=='mixed':
        count=spec.get('count',1); capacity=count+1; mode=spec.get('mode','rich')
        definitions=((0xABCD1234,[1,2],[3]),)
        if mode=='empty': definitions=((0xABCD1234,[],[]),)
        pages,sizes=global_controls.prepare(library,base,dict(label=spec['label'],definitions=definitions,
            type_empty_storage=mode=='empty',data_vector=(count,capacity),element_vector=(count,capacity),
            function_vector=(count,capacity),globals=(count,capacity),owned_mode=mode,
            function_mode=mode,global_mode=mode,nested_count=spec.get('nested_count',1),
            nested_capacity=spec.get('nested_count',1)+1,child_count=spec.get('child_count',1),raw_vector=(3,5)))
    else:
        pages,sizes=controls.prepare(library,base,{})
    pointer=max([controls.OLD]+[p+((max(n,1)+15)&~15) for p,n in sizes.items()])
    def block(size,marker=0xB5):
        nonlocal pointer
        out=pointer; pointer+=(max(size,1)+15)&~15; assert pointer<controls.INPUT
        sizes[out]=size; _write_span(pages,out,bytes([marker])*max(size,1)); return out
    def owned(header,stride,count,capacity):
        out=block(stride*capacity); vector(pages,header,out,count,capacity,stride); return out
    def node(address,kind):
        _,stride,table=export.KINDS[kind]
        put(pages,address,base+table); put(pages,address+8,kind,4)
        if kind in (0,4):
            for off in ((0x10,0x28) if kind==0 else (0x10,)):
                if spec.get('node_vector_mode')=='null': vector(pages,address+off)
                else: owned(address+off,8,0 if spec.get('node_vector_mode')=='empty' else 1,2)
    def name(address,length):
        payload=bytes((5+i*17)&255 for i in range(length))+b'\0'
        if length<=22 and not spec.get('heap_short_names'):
            h=bytearray(b'\xA3'*24); h[0]=length*2; h[1:length+2]=payload; _write_span(pages,address,h)
        else:
            cap=(length+16)&~15; out=block(cap); _write_span(pages,out,payload)
            _write_span(pages,address,(cap|1).to_bytes(8,'little')+length.to_bytes(8,'little')+out.to_bytes(8,'little'))
    if spec.get('kind') in ('mixed','kind4'):
        count,cap=spec.get('kind4_vector',(2,3)); begin=owned(AST+0x90,40,count,cap)
        for index in range(count):
            node(begin+index*40,4)
            if spec.get('stale_kind4_vtable'): put(pages,begin+index*40,0xFFFFFFFFFFFFFFFF)
    if spec.get('kind')=='mixed':
        for offset,kind in ((0x48,1),(0x60,2)):
            stride=export.KINDS[kind][1]; begin=owned(AST+offset,stride,1,2); node(begin,kind)
            if spec.get('opaque_scalar_records'): _write_span(pages,begin,bytes([0x9D])*stride)
        owned(AST+0xC0,4,2,3)
        for offset,stride in ((0x18,64),(0xA8,40)):
            kinds=spec.get('record_kinds',tuple(range(5))); begin=owned(AST+offset,stride,len(kinds),len(kinds)+1)
            for index,kind in enumerate(kinds):
                address=begin+index*stride
                data=block(export.KINDS[kind][1]); node(data,kind)
                if spec.get('nullable_nodes'): data=0
                lengths=spec.get('name_lengths')
                if offset==0x18:
                    module,field=(32 if kind%2 else 7,23 if kind%2 else 0) if lengths is None else lengths[:2]
                    name(address,module); name(address+24,field)
                    put(pages,address+0x30,data); put(pages,address+0x38,0xABCDE000+kind)
                else:
                    name(address,(23 if kind%2 else 22) if lengths is None else lengths[-1])
                    put(pages,address+24,data); put(pages,address+32,kind,4)
    if spec.get('empty_outer_mode'):
        for offset,stride in zip(OFFSETS,STRIDES):
            vector(pages,AST+offset)
            if spec['empty_outer_mode']!='null':
                owned(AST+offset,stride,0,0 if spec['empty_outer_mode']=='nonnull' else 2)
    if 'only_offset' in spec:
        for offset in OFFSETS:
            if offset!=spec['only_offset']: vector(pages,AST+offset)
    if spec.get('opaque_aggregate_bytes'):
        put(pages,CB+8,controls.INPUT)
        put(pages,CB+0x28,0xFFFFFFFFFFFFFFFF)
    return pages,sizes


def minimal_specs():
    return [dict(label='output_wrapper_mixed',kind='mixed',destroy_imports=True),
        dict(label='output_wrapper_kind4',kind='kind4',destroy_imports=True),
        dict(label='output_wrapper_nullable_nodes',kind='mixed',destroy_imports=True,nullable_nodes=True)]


def fixtures():
    cases=minimal_specs()
    for mode in ('null','nonnull','owned'):
        cases.append(dict(label='empty_all_'+mode,empty_outer_mode=mode))
        if mode=='null': continue
        for offset in OFFSETS:
            cases.append(dict(label=f'empty_{offset:x}_{mode}',empty_outer_mode=mode,only_offset=offset))
    for offset in OFFSETS:
        for mode in ('rich','empty','mixed'):
            cases.append(dict(label=f'isolated_{offset:x}_{mode}',kind='mixed',only_offset=offset,mode=mode))
    for count in (1,2):
        for mode in ('rich','empty','mixed'):
            for nested in (0,1,2):
                cases.append(dict(label=f'mixed_{count}_{mode}_{nested}',kind='mixed',count=count,mode=mode,
                    nested_count=nested,child_count=1,opaque_aggregate_bytes=True))
    for lengths in ((0,0,0),(1,22,23),(22,23,24),(23,22,32),(31,32,64),(64,64,128)):
        for nullable in (False,True):
            for heap_short in (False,True):
                cases.append(dict(label=f'names_{lengths}_{nullable}_{heap_short}',kind='mixed',name_lengths=lengths,
                    nullable_nodes=nullable,heap_short_names=heap_short))
    for kind in range(5):
        for mode in ('null','empty','rich'):
            cases.append(dict(label=f'record_kind_{kind}_{mode}',kind='mixed',record_kinds=(kind,kind),node_vector_mode=mode))
    for count,cap in ((0,0),(0,3),(1,1),(2,4),(3,3)):
        for mode in ('null','empty','rich'):
            for stale in (False,True):
                cases.append(dict(label=f'kind4_{count}_{cap}_{mode}_{stale}',kind='kind4',kind4_vector=(count,cap),
                    node_vector_mode=mode,stale_kind4_vtable=stale))
    cases.append(dict(label='opaque_scalar_records',kind='mixed',opaque_scalar_records=True,stale_kind4_vtable=True))
    cases.extend((dict(label='mixed_exact_budget',kind='mixed',exact_node_budget=24),
        dict(label='nullable_exact_budget',kind='mixed',nullable_nodes=True,exact_node_budget=14),
        dict(label='kind4_exact_budget',kind='kind4',kind4_vector=(2,2),exact_node_budget=2)))
    rng=random.Random(0x2CBADC)
    for index in range(8):
        cases.append(dict(label=f'generated_{index}',kind='mixed',mode=rng.choice(('rich','empty','mixed')),
            count=rng.randrange(1,3),nested_count=rng.randrange(3),child_count=rng.randrange(2),
            record_kinds=tuple(rng.randrange(5) for _ in range(rng.randrange(1,6))),nullable_nodes=bool(index%2)))
    return cases


def compare(args,base,spec):
    initial,_=prepare(args.library,base,spec)
    native,effects,statuses=controls.native_case(args,base,dict(spec,destroy_imports=True),functions={},prepare_case=prepare)
    pages,_=prepare(args.library,base,spec)
    result=alternative.cleanup_reader_ast_output(pages,output_address=AST,image_base=base,
        **({'max_nodes':spec['exact_node_budget']} if 'exact_node_budget' in spec else {}))
    actual=[(e.kind,e.address,e.size,e.owner_address,e.owner_bytes) for e in result.effects]
    assert effects==actual,spec['label']
    assert _read_span(native,controls.oracle.GUEST,0xA000)==_read_span(pages,controls.oracle.GUEST,0xA000),spec['label']
    assert not statuses and result.status is None and all(e[0]!='allocate' for e in effects)
    headers=[]
    for offset in OFFSETS:
        begin,end,cap=(int.from_bytes(_read_span(initial,AST+offset+n,8),'little') for n in (0,8,16))
        assert _read_span(pages,AST+offset,24)==b''.join(n.to_bytes(8,'little') for n in (begin,begin,cap))
        headers.append((offset,begin,end,cap))
    outer=[begin for off,begin,end,cap in reversed(headers) if begin]
    assert [e[1] for e in effects if e[0]=='free' and e[1] in outer]==outer
    assert _read_span(pages,CB,0x108)==_read_span(initial,CB,0x108)
    for offset,stride,node_offset in ((0x18,64,48),(0xA8,40,24)):
        begin,end=(int.from_bytes(_read_span(initial,AST+offset+n,8),'little') for n in (0,8))
        for address in range(begin,end,stride):
            assert not int.from_bytes(_read_span(pages,address+node_offset,8),'little')
            for off in ((0,24) if offset==0x18 else (0,)):
                assert _read_span(pages,address+off,24)==_read_span(initial,address+off,24)
    begin,end=(int.from_bytes(_read_span(initial,AST+0x90+n,8),'little') for n in (0,8))
    for address in range(begin,end,40):
        assert int.from_bytes(_read_span(pages,address,8),'little')==base+0x372590
        pointer=int.from_bytes(_read_span(initial,address+16,8),'little')
        assert int.from_bytes(_read_span(pages,address+24,8),'little')==pointer
    for offset,stride in ((0x48,48),(0x60,40)):
        begin,end,cap=next((b,e,c) for off,b,e,c in headers if off==offset)
        assert _read_span(pages,begin,cap-begin)==_read_span(initial,begin,cap-begin)
    return dict(label=spec['label'],image_base_hex=hex(base),complete_native_wrapper_executed=True,
        natural_native_return_and_SP_verified=True,native_Python_guest_memory_match=True,
        ordered_destruction_free_and_owner_bytes_match=True,
        independent_container_order_end_reset_dangling_headers_names_nullable_nodes_kind4_and_borrowed_callback_match=True,
        destructor_count=sum(e[0]=='destroy' for e in effects),delete_count=sum(e[0]=='delete' for e in effects),
        free_count=sum(e[0]=='free' for e in effects),synthetic_fixture=True,native_input_snapshot_used=False,
        guest_bytes_masked=False,whole_native_stack_TLS_OS_compared=False,
        **({'exact_node_budget_supported':spec['exact_node_budget']} if 'exact_node_budget' in spec else {}))


def negatives(args):
    base=BASES[0]; spec=dict(label='guard',kind='mixed'); rows=[]
    u=lambda p,a:int.from_bytes(_read_span(p,a,8),'little')
    cases=[]
    def add(label,setup=None,changes=None): cases.append((label,setup,changes or {}))
    for label,changes in (('base',dict(image_base=base+1)),('root_unaligned',dict(output_address=AST+1)),
        ('root_unmapped',dict(output_address=0x90000000)),('node_bound',dict(max_nodes=1)),
        ('byte_bound',dict(max_vector_bytes=31)),('root_reserved',dict(reserved_regions=((AST,AST+0x120),)))):
        add(label,changes=changes)
    for offset,stride in zip(OFFSETS,STRIDES):
        for label,change in (('unaligned',lambda b,e,c:(b+1,e,c)),('reverse',lambda b,e,c:(b,e,b)),
                ('unmapped',lambda b,e,c:(0x90000000,0x90000000,0x90000000+stride)),
                ('root_alias',lambda b,e,c:(AST,AST,AST+stride)),('image_alias',lambda b,e,c:(base+0x1000,base+0x1000,base+0x1000+stride))):
            def setup(p,off=offset,change=change):
                values=change(*(u(p,AST+off+n) for n in (0,8,16)))
                _write_span(p,AST+off,b''.join(v.to_bytes(8,'little') for v in values))
            add(f'outer_{offset:x}_{label}',setup)
        if stride>1:
            add(f'outer_{offset:x}_partial',lambda p,off=offset:put(p,AST+off+8,u(p,AST+off)+1))
    for index,left in enumerate(OFFSETS):
        for right in OFFSETS[index+1:]:
            def shared_empty(p,a=left,b=right):
                pointer=u(p,AST+a)
                for off in (a,b): vector(p,AST+off,pointer,0,0)
            add(f'outer_alias_{left:x}_{right:x}',shared_empty)
    for offset,node_offset in ((0x18,48),(0xA8,24)):
        for label,address in (('root',AST),('image',base+0x1000),('unmapped',0x90000000)):
            add(f'node_{offset:x}_{label}',lambda p,o=offset,n=node_offset,a=address:put(p,u(p,AST+o)+n,a))
        add(f'node_{offset:x}_type_alias',lambda p,o=offset,n=node_offset:put(p,u(p,AST+o)+n,u(p,AST)))
        add(f'name_{offset:x}_invalid',lambda p,o=offset:put(p,u(p,AST+o),46,1))
    add('kind4_GOT',lambda p:put(p,base+0x375088,0))
    add('kind4_payload_type_alias',lambda p:vector(p,u(p,AST+0x90)+0x10,u(p,AST),0,1,8))
    add('kind4_payload_outer_alias',lambda p:vector(p,u(p,AST+0x90)+0x10,u(p,AST+0x90),0,1,8))
    for offset,inner in ((0,0x10),(0,0x28),(0x30,0x10),(0x30,0x28),(0x30,0x50),(0x30,0x78),
            (0x78,0x28),(0x78,0x40),(0x78,0x68),(0x78,0x90),(0xD8,0),(0xD8,0x38),
            (0xD8,0x50),(0xD8,0x78),(0xD8,0xA0),(0xF0,0),(0xF0,0x30),(0xF0,0x48),
            (0xF0,0x70),(0xF0,0x98)):
        add(f'inner_alias_{offset:x}_{inner:x}',lambda p,o=offset,n=inner:vector(p,u(p,AST+o)+n,u(p,AST+0x108),0,0))
    def name_alias(p):
        record=u(p,AST+0x18)+64
        _write_span(p,record,_read_span(p,record+24,24))
    add('import_module_field_alias',name_alias)
    for index,budget in enumerate((23,13,1)):
        candidate=(
            dict(label='paired',kind='mixed'),dict(label='paired',kind='mixed',nullable_nodes=True),
            dict(label='paired',kind='kind4',kind4_vector=(2,2)))[index]
        pages,_=prepare(args.library,base,candidate)
        alternative.cleanup_reader_ast_output(pages,output_address=AST,image_base=base)
        pages,_=prepare(args.library,base,candidate); before={k:bytes(v) for k,v in pages.items()}
        try: alternative.cleanup_reader_ast_output(pages,output_address=AST,image_base=base,max_nodes=budget)
        except RefillUnsupported: pass
        else: raise AssertionError('paired output budget accepted')
        assert before=={k:bytes(v) for k,v in pages.items()}
        rows.append(dict(label=f'paired_budget_{index}',rejected=True,all_pages_unchanged=True,native_invalid_path_executed=False,
            same_input_without_budget_restriction_supported=True))
    unlimited,_=prepare(args.library,base,spec)
    alternative.cleanup_reader_ast_output(unlimited,output_address=AST,image_base=base)
    bounded,_=prepare(args.library,base,spec)
    alternative.cleanup_reader_ast_output(bounded,output_address=AST,image_base=base,max_vector_bytes=384)
    assert unlimited==bounded
    pages,_=prepare(args.library,base,spec); before={k:bytes(v) for k,v in pages.items()}
    try: alternative.cleanup_reader_ast_output(pages,output_address=AST,image_base=base,max_vector_bytes=383)
    except RefillUnsupported: pass
    else: raise AssertionError('paired output byte budget accepted')
    assert before=={k:bytes(v) for k,v in pages.items()}
    rows.append(dict(label='paired_byte_budget',rejected=True,all_pages_unchanged=True,native_invalid_path_executed=False,
        same_input_without_budget_restriction_supported=True,exact_positive_byte_budget=384))
    for table in (0x3724F0,0x372518,0x372540,0x372568,0x372590):
        add(f'destructor_binding_{table:x}',lambda p,t=table:put(p,base+t,0))
        add(f'delete_binding_{table:x}',lambda p,t=table:put(p,base+t+8,0))
    initial,_=prepare(args.library,base,spec)
    late=[]
    for offset in OFFSETS:
        late.append(AST+offset+8)
    for offset,node_offset in ((0x18,48),(0xA8,24)):
        late.append(u(initial,AST+offset)+node_offset)
    for offset,node_offset in ((0,0),(0x30,0),(0x78,0x18),(0x90,0),(0xD8,0x28),(0xF0,0x20)):
        late.append(u(initial,AST+offset)+node_offset)
    late.extend((u(initial,AST+0x90)+24,u(initial,AST+0xD8)+0xA8,u(initial,AST+0xF0)+0xA0))
    for label,setup,changes in cases:
        pages,_=prepare(args.library,base,spec)
        if setup: setup(pages)
        before={k:bytes(v) for k,v in pages.items()}
        params=dict(output_address=AST,image_base=base); params.update(changes)
        try: alternative.cleanup_reader_ast_output(pages,**params)
        except (RefillUnsupported,ValueError): pass
        else: raise AssertionError('output guard accepted: '+label)
        assert before=={k:bytes(v) for k,v in pages.items()},label
        rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_invalid_path_executed=False))
    original=alternative._write_span
    for address in dict.fromkeys(late):
        pages,_=prepare(args.library,base,spec); before={k:bytes(v) for k,v in pages.items()}
        def fail(p,a,data):
            if a==address: raise RefillUnsupported('injected output cleanup write')
            original(p,a,data)
        alternative._write_span=fail
        try:
            try: alternative.cleanup_reader_ast_output(pages,output_address=AST,image_base=base)
            except RefillUnsupported as exc: assert str(exc)=='injected output cleanup write'
            else: raise AssertionError('output late write not reached: '+hex(address))
        finally: alternative._write_span=original
        assert before=={k:bytes(v) for k,v in pages.items()}
        rows.append(dict(label=f'late_write_{address:x}',rejected=True,all_pages_unchanged=True,native_invalid_path_executed=False))
    return rows


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library',required=True,type=Path); parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args(); assert hashlib.sha256(args.library.read_bytes()).hexdigest()==controls.oracle.LIBRARY_SHA256
    specs=fixtures(); guards=negatives(args); rows=[]
    for base in BASES:
        for index,spec in enumerate(specs,1):
            rows.append(compare(args,base,spec))
            if index%24==0 or index==len(specs): print('B output wrapper:',hex(base),index,'/',len(specs),'passed',flush=True)
    evidence=dict(schema='vm9-alternative-ast-output-fresh-v1',evidence_date='2026-10-10',evidence_timezone='Asia/Shanghai',
        sample_sha256=controls.oracle.LIBRARY_SHA256,native_Python_output_wrapper_controls=len(rows),rollback_negative_controls=len(guards),
        pre_change_behavior_RED_controls=6,native_wrapper_offset_hex='0x2cbadc',
        container_cleanup_order_hex=[hex(o) for o in reversed(OFFSETS)],container_strides=list(STRIDES),
        complete_output_wrapper_cleanup_implemented=True,nullable_import_export_nodes_supported=True,
        all_fixtures_synthetic=True,native_input_snapshot_used=False,guest_bytes_masked=False,
        attached_parser_implemented=False,complete_python_reader_implemented=False,independent_Python_factory_implemented=False,
        fresh_signer_output_verified=False,private_payloads_published=False,cases=rows,negative_cases=guards)
    args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    print('B output wrapper:',len(rows),'native/Python +',len(guards),'rollback checks passed',flush=True)

if __name__=='__main__': main()
