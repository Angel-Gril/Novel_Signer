"""Actual B attached export AST for heap names and four parser node kinds.

Synthetic inputs execute the module, parser, export clones and cleanup.
Short names remain closed; no native stack snapshots seed the Python model.
"""
from __future__ import annotations
import argparse,hashlib,json,random
from pathlib import Path
from unicorn import arm64_const as arm
import verify_vm9_alternative_ast_module_code_20261011 as code
from vm9_allocator import RefillUnsupported,_read_span,_write_span
previous=code.previous
layout=previous.previous
alternative=previous.alternative
BASES=previous.BASES
section,enc,types=previous.section,previous.enc,previous.types
FUN={**code.FUN,0x98:0x31D500};ARGC={**code.ARGC,0x98:5}
KINDS=((0x80,64,0x3724F0),(0x98,48,0x372518),(0xB0,40,0x372540),(0xC8,24,0x372568))
MASK=(1<<64)-1


def limits(flags,minimum,maximum=0):return bytes([flags])+enc(minimum)+(enc(maximum) if flags&1 else b'')
def export(name,kind,index):return enc(len(name))+name+bytes([kind])+enc(index)
def imported(kind,length=1,index=0):
    return (bytes([109+index%5])*length,bytes([102+index%7])*(length+1),kind,
        (b'\0',b'\x70'+limits(1,3,9),limits(1,3,9),b'\x7f\1')[kind])


def spec(label,exports=(),imports=(),definitions=None,functions=(),tables=(),memories=(),globals_=(),
        bodies=None,before=b'',after=b'',status=0,payload=None,**kw):
    if definitions is None:definitions=[([0x7F],[0x7E])] if functions or any(e[2]==0 for e in imports) else []
    prefix=types(definitions) if definitions else b''
    if imports:prefix+=section(2,enc(len(imports))+b''.join(layout.import_(*e) for e in imports))
    if functions:prefix+=section(3,enc(len(functions))+b''.join(enc(i) for i in functions))
    if tables:prefix+=section(4,enc(len(tables))+b''.join(bytes([v])+limits(f,n,m) for v,f,n,m in tables))
    if memories:prefix+=section(5,enc(len(memories))+b''.join(limits(*e) for e in memories))
    if globals_:prefix+=section(6,enc(len(globals_))+b''.join(e['blob'] for e in globals_))
    prefix+=before
    if bodies is not None:after=section(10,enc(len(bodies))+b''.join(b['blob'] for b in bodies))+after
    payload=enc(len(exports))+b''.join(export(*e) for e in exports) if payload is None else payload
    return dict(label=label,blob=b'A'*8+prefix+section(7,payload)+after,exports=list(exports),imports=list(imports),
        definitions=definitions,functions=list(functions),tables=list(tables),memories=list(memories),globals=list(globals_),
        bodies=bodies,status=status,table_memory=bool(tables or memories),**kw)


def minimal_specs():
    rows=[spec('import_'+str(k),[(b'e'*23,k,0)],imports=[imported(k)]) for k in range(4)]
    rows += [spec('definition_1',[(b'e'*23,1,0)],tables=[(0x70,1,3,9)]),
        spec('definition_2',[(b'e'*23,2,0)],memories=[(1,3,9)]),
        spec('definition_3',[(b'e'*23,3,0)],globals_=[previous.entry(ops=[(2,7)])]),
        spec('four_kinds',[(bytes([97+k])*23,k,0) for k in range(4)],imports=[imported(k) for k in range(4)])]
    return rows


def fixtures():
    rows=minimal_specs()+[spec('empty'),spec('function_definition',[(b'e'*23,0,0)],functions=[0],bodies=[code.body([7])])]
    for kind in range(4):
        for count in (1,2,3,4,5):
            rows.append(spec(f'growth_{kind}_{count}',[(bytes([97+i])*23,kind,i%2) for i in range(count)],imports=[imported(kind,1),imported(kind,23,1)]))
        for n in (23,24,31,32,33,63,64,127,128,255):
            rows.append(spec(f'name_{kind}_{n}',[(bytes((i*17)%256 for i in range(n)),kind,0)],imports=[imported(kind)]))
    for pad in (0,0x39,0xA5,0xFF):
        for warm in (False,True):
            rows.append(spec(f'mixed_{pad}_{warm}',[(bytes([97+i])*n,i%4,i//4) for i,n in enumerate((23,32,24,63,31,33,64,127))],
                imports=[imported(k,0 if pad%2 else 23,k) for k in range(4)],functions=[0],tables=[(0x6F,0,7,0)],memories=[(4,1<<35,0)],
                globals_=[previous.entry(0x7E,1,[(3,MASK)])],bodies=[code.body([3,7],9,[(2,-1)])],
                before=section(0,b'\1x'),after=section(0,b'\1y'),frame_padding=pad,warm_rank=warm))
    for defs in ([([],[])],[([0x7F],[])],[([],[0x7E])],[([0x7F,0x7E],[0x7D,0x7C])]):
        rows.append(spec('type_vectors_'+str(len(rows)),[(b'e'*23,0,1),(b'x'*32,0,0)],definitions=defs,imports=[imported(0)],functions=[0],bodies=[code.body()]))
    for value in (0x7B,0x7C,0x7D,0x7E,0x7F,0x6F,0x70):
        for mutable in (0,1):rows.append(spec(f'global_{value}_{mutable}',[(b'e'*23,3,0)],globals_=[previous.entry(value,mutable)]))
    for value in (0x70,0x6F,0x6B):
        for flags in (0,1):rows.append(spec(f'table_{value}_{flags}',[(b'e'*23,1,0)],tables=[(value,flags,127,0xFFFFFFFF)]))
    for flags in (0,1,4,5):rows.append(spec('memory_'+str(flags),[(b'e'*23,2,0)],memories=[(flags,1<<35 if flags&4 else 128,1<<40 if flags&4 else 0xFFFFFFFF)]))
    first=export(b'e'*23,0,0)
    for label,tail in [('no_name_length',b''),('cut_name_length',b'\x80'),('name_past_end',b'\x7fxx'),('missing_kind',b'\x01x'),
            ('kind_4',b'\x01x\x04\0'),('bad_kind',b'\x01x\xff\0'),('no_index',b'\x01x\0'),('cut_index',b'\x01x\0\x80')]:
        rows.append(spec(label,[(b'e'*23,0,0)],imports=[imported(0)],payload=b'\2'+first+tail,status=1))
    for label,payload in [('count_missing',b''),('count_cut',b'\x80'),('count_bound',b'\x7f')]:rows.append(spec(label,payload=payload,status=1))
    for label,after in [('duplicate',section(7,b'\0')),('backwards',section(6,b'\0')),('unknown',b'\x0d\0'),('envelope',b'\x08\x80')]:
        rows.append(spec(label,[(b'e'*23,0,0)],imports=[imported(0)],after=after,status=1))
    rows.append(spec('trailing',[(b'e'*23,0,0)],imports=[imported(0)],payload=b'\1'+first+b'\0',status=1))
    rows.append(spec('function_count_mismatch',[(b'e'*23,0,0)],functions=[0],status=1))
    rng=random.Random(0x3238B0)
    for i in range(12):
        entries=[imported(k,rng.choice((0,1,22,23)),k) for k in range(4)]
        exports=[(bytes(rng.randrange(256) for _ in range(rng.randrange(23,65))),rng.randrange(4),0) for _ in range(rng.randrange(1,6))]
        rows.append(spec('generated_'+str(i),exports,imports=entries,frame_padding=rng.randrange(256)))
    return rows


def native(args,base,case):
    saved=(previous.FUN,previous.ARGC,layout.heap.oracle.native)
    def instrumented(*a,**kw):
        observe=kw['instruction_observer']
        def observed(cpu,address):
            if address==base+FUN[0x98]:assert cpu.reg_read(arm.UC_ARM64_REG_SP)==layout.STATE-0xD0
            if address-base in code.FUN.values():assert cpu.reg_read(arm.UC_ARM64_REG_SP)==layout.STATE-0xE0
            observe(cpu,address)
        kw['instruction_observer']=observed;return saved[2](*a,**kw)
    try:
        previous.FUN,previous.ARGC={**previous.FUN,**FUN},{**previous.ARGC,**ARGC};layout.heap.oracle.native=instrumented
        return previous.native(args,base,case)
    finally:previous.FUN,previous.ARGC,layout.heap.oracle.native=saved


def options(case):
    return previous.options(case)|dict(enable_global_definitions=bool(case['globals']),enable_code_definitions=case['bodies'] is not None,enable_exports=True)
def model(args,base,case,**changes):return previous.model(args,base,case,**(options(case)|changes))


def cache_specs(case):
    nodes=[[] for _ in range(4)]
    def decode(data):
        cursor=0
        def leb():
            nonlocal cursor
            n=shift=0
            while True:
                b=data[cursor];cursor+=1;n|=(b&127)<<shift;shift+=7
                if b<128:return n
        return leb
    for _,_,kind,payload in case['imports']:
        if kind==0:nodes[0].append(case['definitions'][decode(payload)()])
        elif kind==3:nodes[3].append((payload[0],payload[1]))
        else:
            value=payload[0] if kind==1 else None;data=payload[1:] if kind==1 else payload
            f=data[0];read=decode(data[1:]);n=read();m=read() if f&1 else 0
            nodes[kind].append((value,f,n,m) if kind==1 else (f,n,m))
    nodes[0]+=[case['definitions'][i] for i in case['functions']]
    nodes[1]+=case['tables'];nodes[2]+=case['memories'];nodes[3]+=[(e['value'],e['mutable']) for e in case['globals']]
    return nodes


def compare(args,base,case):
    status,np,ne,nc,snap=native(args,base,case);p,result,state=model(args,base,case)
    assert result.status==status==case['status'],(case['label'],'status',status,result.status)
    assert layout.heap.previous.normalized(result.effects)==ne,(case['label'],'effects')
    assert state==snap['parser'] and _read_span(p,layout.CB,0x120)==snap['callback_final'],(case['label'],'cleanup')
    a=_read_span(p,layout.heap.oracle.GUEST,0xA000);b=_read_span(np,layout.heap.oracle.GUEST,0xA000)
    assert a==b,(case['label'],'guest bytes',[(hex(i),x,y) for i,(x,y) in enumerate(zip(a,b)) if x!=y][:12])
    for (address,width),data in snap['globals'].items():assert _read_span(p,address,width)==data
    events=result.sections.callback_events;assert [(e.slot_offset,e.arguments,e.cursor,e.section_end) for e in events]==nc
    u=lambda a,n=8:int.from_bytes(_read_span(p,a,n),'little')
    begin=u(layout.OUT+0xA8);count=len(case['exports']);capacity=1<<(count-1).bit_length() if count else 0
    assert u(layout.OUT+0xB0)==begin+count*40 and u(layout.OUT+0xB8)==begin+capacity*40
    specs=cache_specs(case);regions=[(begin,begin+capacity*40)] if capacity else []
    for index,(name,kind,target_index) in enumerate(case['exports']):
        record=begin+index*40;name_ptr=u(record+16);node=u(record+24);storage=(len(name)+16)&~15
        expected=(storage|1).to_bytes(8,'little')+len(name).to_bytes(8,'little')+name_ptr.to_bytes(8,'little')+node.to_bytes(8,'little')+target_index.to_bytes(4,'little')+b'\xA5'*4
        assert _read_span(p,record,40)==expected and _read_span(p,name_ptr,len(name)+1)==name+b'\0'
        off,stride,table=KINDS[kind];cache=u(layout.CB+off)+target_index*stride;shape=specs[kind][target_index]
        assert node!=cache and u(node)==u(cache)==base+table and u(node+8,4)==kind
        expected_node=bytearray(_read_span(p,cache,stride));regions.extend(((name_ptr,name_ptr+storage),(node,node+stride)))
        if kind==0:
            for offset,values in zip((0x10,0x28),shape):
                data=b''.join(((t-128)&MASK).to_bytes(8,'little') for t in values);ptr=u(node+offset)
                assert bool(ptr)==bool(data) and u(node+offset+8)==u(node+offset+16)==ptr+len(data)
                assert _read_span(p,ptr,len(data))==data
                expected_node[offset:offset+24]=ptr.to_bytes(8,'little')+(ptr+len(data)).to_bytes(8,'little')*2
                if ptr:regions.append((ptr,ptr+len(data)));assert ptr!=u(cache+offset)
        elif kind==3:
            value,mutable=shape;assert u(node+0xC)==(value-128)&MASK and u(node+0x14,4)==mutable
        else:
            if kind==1:value,flags,minimum,maximum=shape;assert u(node+0xC)==(value-128)&MASK
            else:flags,minimum,maximum=shape
            maximum=maximum if flags&1 else 0xFFFFFFFF if kind==1 else 0x1000000000000 if flags&4 else 0x10000
            descriptor=minimum.to_bytes(8,'little')+maximum.to_bytes(8,'little')+bytes((flags&1,0,(flags>>2)&1 if kind==2 else 0))
            assert _read_span(p,node+(0x18 if kind==1 else 0x10),19)==descriptor
        assert _read_span(p,node,stride)==expected_node,(case['label'],'complete cloned node',index)
    ordered=sorted(regions);assert all(a[1]<=b[0] for a,b in zip(ordered,ordered[1:]))
    for kind,(off,stride,_) in enumerate(KINDS):
        start,cap=u(layout.CB+off),u(layout.CB+off+16)
        if start:assert all(b<=start or cap<=a for a,b in regions)
    exports=[e for e in events if e.slot_offset==0x98];assert len(exports)==count
    for i,(event,(name,kind,index)) in enumerate(zip(exports,case['exports'])):
        assert event.arguments[:3]==(i,kind,index) and event.arguments[4]==len(name)
        assert _read_span(p,event.arguments[3],len(name))==name
    assert [u(layout.STATE+o,4) for o in (0x90,0x94,0x98,0x9C)]==[sum(e[2]==k for e in case['imports']) for k in range(4)]
    for off,_,_ in KINDS:assert u(layout.CB+off)==u(layout.CB+off+8)
    return dict(label=case['label'],image_base_hex=hex(base),entry_stack_address_hex=hex(layout.ENTRY),status=status,
        callback_count=len(nc),**{n+'_count':sum(e[0]==n for e in ne) for n in ('allocate','destroy','delete','free')},
        actual_module_parser_AST_and_cleanup_executed=True,natural_return_and_SP_verified=True,
        complete_guest_0xa000_without_masking_match=True,ordered_effects_and_owner_bytes_match=True,
        parser_exit_callback_cleanup_image_globals_and_arguments_match=True,
        independent_complete_export_records_checked=count,complete_cloned_nodes_checked=count,
        independent_names_indexes_capacities_type_vectors_and_limits_match=True,owned_storage_disjoint_from_borrowed_cache=True,
        synthetic_fixture=True,native_input_snapshot_used=False,whole_native_stack_TLS_OS_compared=False)


def actual_export_names(library):
    """Private real names are used only for a closed-path rollback control."""
    blob=code.section_code.actual_inputs(library)[-1]['blob'];cursor=8;names=[]
    def leb():
        nonlocal cursor
        value=shift=0
        while True:
            b=blob[cursor];cursor+=1;value|=(b&127)<<shift;shift+=7
            if b<128:return value
    while cursor<len(blob):
        number=blob[cursor];cursor+=1;size=leb();end=cursor+size
        if number==7:
            count=leb()
            for _ in range(count):
                size=leb();names.append(blob[cursor:cursor+size]);cursor+=size
                kind=blob[cursor];cursor+=1;leb();assert kind==0
            assert cursor==end
        cursor=end
    assert len(names)==121 and all(len(n)<=22 for n in names)
    return names


def negatives(args):
    rows=[];base=BASES[0];case=spec('guards',[(b'e'*23,0,0)]*4,imports=[imported(0)])
    def reject(label,changes=None,fixture=None,setup=None,fault=None):
        fixture=fixture or case;p=previous.prepare(args,base,fixture);offset=0;in_export=False
        def allocate(size):
            nonlocal offset
            address=layout.HEAP+offset;offset+=(size+15)&~15;return address
        params=dict(image_base=base,input_address=layout.DATA,input_size=len(fixture['blob']),output_address=layout.OUT,
            entry_stack_address=layout.ENTRY,varuint_scratch_address=layout.SCRATCH,allocate=allocate,**options(fixture))
        params.update(changes or {})
        if setup:setup(p)
        before={k:bytes(v) for k,v in p.items()};write=alternative._write_span;callback=alternative.run_reader_ast_callback;hits=[]
        def observed(current,**kw):
            nonlocal in_export
            in_export=kw['slot_offset']==0x98
            try:return callback(current,**kw)
            finally:in_export=False
        def injected(current,address,data):
            if fault(current,address,data,in_export):hits.append(address);raise RefillUnsupported('injected export write failure')
            return write(current,address,data)
        if fault:alternative._write_span=injected;alternative.run_reader_ast_callback=observed
        try:
            try:alternative.run_reader_ast_module(p,**params)
            except (RefillUnsupported,ValueError):pass
            else:raise AssertionError('export guard accepted: '+label)
        finally:alternative._write_span=write;alternative.run_reader_ast_callback=callback
        assert before=={k:bytes(v) for k,v in p.items()},label
        if fault:assert hits,label
        rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_invalid_path_executed=False))
    for label,changes in [('default_closed',dict(enable_exports=False)),('flag_type',dict(enable_exports=1)),
            ('other_opt_ins_do_not_enable_exports',dict(enable_exports=False,enable_code_definitions=True,enable_global_definitions=True)),
            ('input_frame',dict(input_address=layout.STATE-0x210)),('output_frame',dict(output_address=layout.STATE-0x208)),
            ('scratch_frame',dict(varuint_scratch_address=layout.STATE-0x200)),('reserved_frame',dict(reserved_regions=((layout.STATE-0x210,layout.STATE-0x208),))),
            ('allocate_frame',dict(allocate=lambda size:layout.STATE-0x210)),('allocate_input',dict(allocate=lambda size:layout.DATA)),
            ('node_budget',dict(max_nodes=1)),('entry_budget',dict(max_entries=1)),('byte_budget',dict(max_vector_bytes=31))]:reject(label,changes)
    with layout.layout(-0xBC0):reject('lower_frame_unmapped',setup=lambda p:p.pop((layout.STATE-0x210)>>12))
    reject('slot_binding',setup=lambda p:_write_span(p,base+0x372370+0x98,(base+0x31B870).to_bytes(8,'little')))
    for kind,(_,_,table) in enumerate(KINDS):
        fixture=spec('virtual',[(b'e'*23,kind,0)],imports=[imported(kind)])
        for offset in (8,16):reject(f'virtual_{kind}_{offset}',fixture=fixture,setup=lambda p,table=table,offset=offset:_write_span(p,base+table+offset,bytes(8)))
        reject('index_'+str(kind),fixture=spec('index',[(b'e'*23,kind,1)],imports=[imported(kind)]))
    for n in (0,1,7,8,15,21,22):reject('short_name_'+str(n),fixture=spec('short',[(b'e'*n,0,0)],imports=[imported(0)]))
    reject('actual_ELF_short_name',fixture=spec('private_short',[(actual_export_names(args.library)[0],0,0)],imports=[imported(0)]))
    reject('nonempty_output',setup=lambda p:_write_span(p,layout.OUT,b'\x01'))
    reject('imports_still_closed',dict(enable_function_imports=False,enable_inline_function_imports=False,enable_table_memory_global_imports=False,enable_inline_table_memory_global_imports=False))
    reject('definitions_still_closed',dict(enable_table_memory_definitions=False),spec('table',[(b'e'*23,1,0)],tables=[(0x70,1,3,9)]))
    reject('globals_still_closed',dict(enable_global_definitions=False),spec('global',[(b'e'*23,3,0)],globals_=[previous.entry()]))
    reject('code_still_closed',dict(enable_code_definitions=False),spec('code',[(b'e'*23,0,0)],functions=[0],bodies=[code.body()]))
    for label,address,width in [('publish',layout.OUT+0xA8,24),('spare_end',layout.OUT+0xB0,8),('cleanup',layout.CB+0x88,8)]:
        reject('write_failure_'+label,fault=lambda p,a,d,active,address=address,width=width:a==address and len(d)==width)
    reject('write_failure_name_copy',fault=lambda p,a,d,active:active and d==b'e'*23+b'\0')
    reject('write_failure_clone_vector',fault=lambda p,a,d,active:active and layout.HEAP<=a<layout.SCRATCH and d==bytes(24))
    reject('write_failure_index',fault=lambda p,a,d,active:active and layout.HEAP+32<=a<layout.SCRATCH and len(d)==4
        and _read_span(p,a-24,8)==(23).to_bytes(8,'little'))
    sizes=[]
    def alias(size):
        address=layout.HEAP+sum((n+15)&~15 for n in sizes);sizes.append(size)
        return layout.HEAP if len(sizes)==4 else address
    reject('prior_allocation',dict(allocate=alias))
    return rows


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('library','libc','output'):parser.add_argument('--'+name,required=True,type=Path)
    args=parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==layout.heap.oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==layout.heap.LIBC_HASH
    specs=fixtures();guards=negatives(args);rows=[]
    moved=[c for c in specs if c['label'] in ('four_kinds','definition_2','mixed_0_False')]
    for base in BASES:
        for i,case in enumerate(specs,1):
            rows.append(compare(args,base,case))
            if i%16==0:print('B attached heap exports',hex(base),i,'/',len(specs),'passed',flush=True)
        for delta in (-0xC80,0x100):
            with layout.layout(delta):
                for case in moved:rows.append(compare(args,base,{**case,'label':case['label']+'_SP_'+str(delta)}))
        with previous.definitions.guest_layout(0x7000000000):
            for case in moved+[c for c in specs if c['label'] in ('function_definition','growth_0_5','generated_11')]:
                rows.append(compare(args,base,{**case,'label':case['label']+'_high_guest'}))
    evidence=dict(schema='vm9-alternative-ast-module-exports-fresh-v1',evidence_date='2026-10-11',evidence_timezone='Asia/Shanghai',
        sample_sha256=layout.heap.oracle.LIBRARY_SHA256,matching_libc_sha256=layout.heap.LIBC_HASH,
        native_Python_module_export_controls=len(rows),rollback_negative_controls=len(guards),relocated_entry_stack_controls=12,
        relocated_full_guest_controls=12,pre_change_behavior_RED_controls=16,purely_synthetic_controls=len(rows),
        actual_ELF_nonempty_exports_native_controls=0,actual_ELF_short_name_rollback_controls=1,actual_ELF_export_names_are_all_short=True,
        generated_fixture_seed=0x3238B0,enable_exports_default=False,exports_require_other_opt_ins=False,short_export_names_supported=False,
        attached_export_slots_hex=['0x98'],independent_complete_export_records_checked=sum(r['independent_complete_export_records_checked'] for r in rows),
        complete_cloned_nodes_checked=sum(r['complete_cloned_nodes_checked'] for r in rows),
        native_input_snapshot_used=False,private_payloads_published=False,whole_native_stack_TLS_OS_compared=False,
        complete_attached_reader_implemented=False,complete_python_reader_implemented=False,independent_Python_factory_implemented=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False,cases=rows,negative_cases=guards)
    args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    print('B attached heap exports:',len(rows),'native/Python controls,',len(guards),'rollback checks',flush=True)
if __name__=='__main__':main()
