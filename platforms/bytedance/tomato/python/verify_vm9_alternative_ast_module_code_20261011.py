"""Actual B module code AST composition, bounded raw words and cleanup.

Synthetic fixtures and selected complete ELF bodies; words are never executed.
Records, locals, children, offsets and raw bytes are checked independently.
"""
from __future__ import annotations
import argparse,hashlib,json,random
from pathlib import Path
from unicorn import arm64_const as arm
import verify_vm9_alternative_ast_module_globals_20261011 as previous
import verify_vm9_alternative_code_20261008 as section_code
from vm9_allocator import RefillUnsupported,_read_span,_write_span
alternative=previous.alternative
layout=previous.previous
BASES=previous.BASES
section,enc,types=previous.section,previous.enc,previous.types
FUN={0xA8:0x31D7D8,0xB0:0x31D974,0xB8:0x31D984,0xF8:0x31DBB4,0x168:0x31E5D8}
ARGC={0xA8:4,0xB0:1,0xB8:3,0xF8:2,0x168:1}
MASK=(1<<64)-1


def body(words=(),metadata=0,groups=(),size=None,raw=None,begun=True,ended=True,expected_groups=None,expected_words=None):
    header=enc(metadata)+enc(len(groups))
    payload=header+b''.join(enc(n)+previous.signed(t) for n,t in groups)+b''.join(w.to_bytes(4,'little') for w in words)
    size=len(payload) if size is None else size
    return dict(blob=enc(size)+payload if raw is None else raw,metadata=metadata,groups=list(groups),
        expected_groups=list(groups if expected_groups is None else expected_groups),
        expected_words=list(words if expected_words is None else expected_words),begun=begun,ended=ended,
        header_size=len(header),size_size=len(enc(size)),remaining=(size-len(header))&0xFFFFFFFF)


def spec(label,bodies=(),definitions=None,function_types=None,imports=(),globals_=(),before=b'',after=b'',status=0,code_payload=None,**kw):
    function_types=list(range(len(bodies))) if function_types is None else list(function_types)
    if definitions is None:definitions=[([0x7F],[0x7E])]*max([i+1 for i in function_types]+[int(bool(imports))])
    prefix=types(definitions) if definitions else b''
    if imports:prefix+=section(2,enc(len(imports))+b''.join(layout.import_(*e) for e in imports))
    if function_types:prefix+=section(3,enc(len(function_types))+b''.join(enc(i) for i in function_types))
    prefix+=before
    if globals_:prefix+=section(6,enc(len(globals_))+b''.join(e['blob'] for e in globals_))
    payload=enc(len(bodies))+b''.join(b['blob'] for b in bodies) if code_payload is None else code_payload
    return dict(label=label,blob=b'A'*8+prefix+section(10,payload)+after,bodies=list(bodies),definitions=definitions,
        function_types=function_types,imports=imports,globals=globals_,status=status,**kw)


def minimal_specs():
    return [spec('zero_code'),spec('empty',[body()]),spec('words',[body([0,1,0xFFFFFFFF])]),
        spec('locals',[body([7],17,[(2,-1),(3,-2)])]),
        spec('global_then_code',[body([9],17,[(1,-3)])],globals_=[previous.entry(ops=[(3,MASK)])])]


def fixtures():
    rows=minimal_specs()
    for count in (1,2,3,4):
        for pad in (0,0xA5,0xFF):
            rows.append(spec(f'growth_{count}_{pad}',[body([i,0xFFFFFFFF],i,[(j,-1-j%4) for j in range(i+1)]) for i in range(count)],frame_padding=pad))
    for metadata in (0,1,127,128,16384,0xFFFFFFFF):rows.append(spec('metadata_'+str(metadata),[body([7],metadata)]))
    for value in (-5,-4,-3,-2,-1,-17,-16):
        for count in (0,1,0xFFFFFFFF):rows.append(spec(f'local_{value}_{count}',[body([3],groups=[(count,value)])]))
    for count in (0,1,2,3,4,7,8,17,64):rows.append(spec('raw_growth_'+str(count),[body([i*0x1234567 for i in range(count)])]))
    for groups in ([(0,-1),(0,-2)],[(0xFFFFFFFE,-1),(1,-2)],[(1,-1)]*5):rows.append(spec('local_groups_'+str(len(rows)),[body(groups=groups)]))
    for definitions in ([([],[])],[([0x7F],[])],[([],[0x7E])],[([0x7F,0x7E],[0x7D,0x7C])]):
        rows.append(spec('type_vectors_'+str(len(rows)),[body([1]),body([2])],definitions=definitions,function_types=[0,0]))
    for length in (0,23):
        for count in (1,2,4):
            imports=[(b'm'*length,b'f'*(length+1),0,b'\0')]*count
            rows.append(spec(f'function_imports_{length}_{count}',[body([1],groups=[(2,-1)]),body([2])],function_types=[0,0],imports=imports))
    for warm in (False,True):
        imports=[(b'm',b'f',0,b'\0'),(b'',b't',1,b'\x70\0\x01'),(b'm',b'',2,b'\0\x01'),(b'',b'',3,b'\x7f\1')]
        rows.append(spec('all_sections_'+str(warm),[body([7],9,[(2,-1)]),body([8],11)],imports=imports,
            before=section(4,b'\x01\x70\0\x01')+section(5,b'\x01\0\x01')+section(0,b'\x01x'),
            globals_=[previous.entry(ops=[(4,0x7FC00001)])],after=section(0,b'\x01x'),table_memory=True,warm_rank=warm))
    for label,tail in [('duplicate',section(10,b'\0')),('backwards',section(3,b'\0')),('envelope',b'\x08\x80'),('unknown',b'\x0d\0')]:
        rows.append(spec(label,[body([17])],after=tail,status=1))
    for payload in (b'',b'\x80',b'\0',b'\x7f'):
        rows.append(spec('bad_count_'+str(len(rows)),[],function_types=[0],code_payload=payload,status=1))
    for label,raw in [('size_missing',b''),('size_cut',b'\x80'),('meta_missing',b'\x02'),('meta_cut',b'\x02\x80'),
            ('groups_missing',b'\x02\0'),('groups_cut',b'\x02\0\x80'),('groups_bound',b'\x03\0\x02\0')]:
        rows.append(spec(label,[body([1]),body(raw=raw,begun=False,ended=False)],status=1))
    for value in (-22,-21,-20,-18,-15,-6,0,1):
        encoded=enc(1)+previous.signed(value)+(b'\0' if value==-21 else b'')
        raw=b'\0\x02'+b'\x01\x7f'+encoded
        rows.append(spec('bad_local_'+str(value),[body(groups=[(1,-1),(1,value)],size=len(raw),raw=enc(len(raw))+raw,ended=False,expected_groups=[(1,-1)])],status=1))
    overflow=body(groups=[(0xFFFFFFFF,-1),(1,-2)],ended=False,expected_groups=[(0xFFFFFFFF,-1)])
    rows.append(spec('local_sum_overflow',[overflow],status=1))
    for label,tail in [('local_count_cut',b'\x80'),('local_type_missing',b'\x01'),('local_type_cut',b'\x01\xff')]:
        raw=b'\0\x02\x01\x7f'+tail
        rows.append(spec(label,[body(groups=[(1,-1),(1,-1)],size=len(raw),raw=enc(len(raw))+raw,ended=False,expected_groups=[(1,-1)])],status=1))
    for size in (0,1,3,5):rows.append(spec('body_overshoot_'+str(size),[body([1],size=size,ended=False,expected_words=[] if size<2 else [1])],status=1))
    rows.append(spec('trailing_section',[body()],code_payload=b'\x01'+body()['blob']+b'\0',status=1))
    rng=random.Random(0x323CA8)
    for i in range(12):
        bodies=[body([rng.getrandbits(32) for _ in range(rng.randrange(5))],rng.getrandbits(32),[(rng.randrange(20),rng.choice((-1,-2,-3,-4))) for _ in range(rng.randrange(4))]) for _ in range(rng.randrange(1,4))]
        rows.append(spec('generated_'+str(i),bodies,frame_padding=rng.randrange(256)))
    return rows


def actual_specs(library):
    blob=section_code.actual_inputs(library)[0]['blob'];cursor=9
    def leb(signed=False):
        nonlocal cursor
        value=shift=0
        while True:
            byte=blob[cursor];cursor+=1;value|=(byte&127)<<shift;shift+=7
            if byte<128:return value-(1<<shift) if signed and byte&64 else value
    length=leb();assert length==218682 and cursor+length==len(blob)
    count=leb();assert count==121
    selected=[]
    for index in range(count):
        begin=cursor;size=leb();end=cursor+size
        metadata=leb();group_count=leb();groups=[(leb(),leb(True)) for _ in range(group_count)]
        assert (end-cursor)%4==0
        words=[int.from_bytes(blob[a:a+4],'little') for a in range(cursor,end,4)];cursor=end
        if size<=512 and len(selected)<3:
            entry=body(words,metadata,groups);assert entry['blob']==blob[begin:end];selected.append(entry)
    assert cursor==len(blob) and len(selected)==3
    return [spec('fresh_ELF_body_'+str(i),[b],actual=True) for i,b in enumerate(selected)]+[
        spec('fresh_ELF_bodies_after_global',selected,globals_=[previous.entry(ops=[(3,MASK)])],actual=True)]


def native(args,base,case,observe_extra=None):
    saved=(previous.FUN,previous.ARGC,layout.heap.oracle.native)
    def instrumented(*a,**kw):
        observe=kw['instruction_observer']
        def observed(cpu,address):
            if address-base in FUN.values():assert cpu.reg_read(arm.UC_ARM64_REG_SP)==layout.STATE-0xE0
            if observe_extra:observe_extra(cpu,address)
            observe(cpu,address)
        kw['instruction_observer']=observed
        return saved[2](*a,**kw)
    try:
        previous.FUN,previous.ARGC={**previous.FUN,**FUN},{**previous.ARGC,**ARGC}
        layout.heap.oracle.native=instrumented
        return previous.native(args,base,case)
    finally:previous.FUN,previous.ARGC,layout.heap.oracle.native=saved


def options(case):
    return previous.options(case)|dict(enable_global_definitions=bool(case['globals']),enable_code_definitions=True)


def model(args,base,case,**changes):return previous.model(args,base,case,**(options(case)|changes))


def compare(args,base,case):
    status,np,ne,nc,snap=native(args,base,case);p,result,state=model(args,base,case)
    assert result.status==status==case['status'],(case['label'],'status',status,result.status)
    assert layout.heap.previous.normalized(result.effects)==ne,(case['label'],'effects')
    assert state==snap['parser'] and _read_span(p,layout.CB,0x120)==snap['callback_final'],(case['label'],'cleanup')
    a=_read_span(p,layout.heap.oracle.GUEST,0xA000);b=_read_span(np,layout.heap.oracle.GUEST,0xA000)
    assert a==b,(case['label'],'guest bytes',[(hex(i),x,y) for i,(x,y) in enumerate(zip(a,b)) if x!=y][:12])
    for (address,width),data in snap['globals'].items():assert _read_span(p,address,width)==data
    events=result.sections.callback_events
    assert [(e.slot_offset,e.arguments,e.cursor,e.section_end) for e in events]==nc,(case['label'],'events')
    u=lambda a,n=8:int.from_bytes(_read_span(p,a,n),'little')
    start=u(layout.OUT+0x30);assert u(layout.OUT+0x38)-start==len(case['function_types'])*144
    raw=bytearray()
    for g in case['globals']:
        for kind,bits in g['ops']:
            width=4 if kind in (2,4) else 8;raw+=kind.to_bytes(4,'little')+(bits&((1<<(width*8))-1)).to_bytes(width,'little')
    imported=sum(e[2]==0 for e in case['imports']);offset=len(enc(len(case['bodies'])));begins=[];ends=[];locals_args=[];words=[];checked_children=0
    for index,type_index in enumerate(case['function_types']):
        body_=case['bodies'][index] if index<len(case['bodies']) else None
        begun=bool(body_ and body_['begun']);record=start+index*144
        expected=bytearray(b'\xA5'*144)
        def put(off,v,width=8):expected[off:off+width]=v.to_bytes(width,'little')
        put(0,base+0x3724F0);put(8,0,4)
        for off,ts in zip((0x10,0x28),case['definitions'][type_index]):
            ptr=u(record+off);data=b''.join(((t-128)&MASK).to_bytes(8,'little') for t in ts)
            assert u(record+off+8)==u(record+off+16)==ptr+len(data) and bool(ptr)==bool(data)
            assert _read_span(p,ptr,len(data))==data
            for n,value in enumerate((ptr,ptr+len(data),ptr+len(data))):put(off+n*8,value)
        put(0x40,type_index,4);put(0x44,index+imported,4);put(0x48,body_['metadata'] if begun else 0,4)
        groups=body_['expected_groups'] if begun else [];ptr=u(record+0x50);capacity=(1<<(len(groups)-1).bit_length())*16 if groups else 0
        assert u(record+0x58)==ptr+len(groups)*16 and u(record+0x60)==ptr+capacity and bool(ptr)==bool(groups)
        cumulative=0;data=bytearray()
        for i,(n,t) in enumerate(groups):
            cumulative+=n;data+=(t&MASK).to_bytes(8,'little')+n.to_bytes(4,'little')+cumulative.to_bytes(4,'little');locals_args.append((i,n,t&MASK))
        assert _read_span(p,ptr,len(data))==data
        for n,value in enumerate((ptr,ptr+len(data),ptr+capacity)):put(0x50+n*8,value)
        raw_start=len(raw);body_offset=offset+body_['size_size']+body_['header_size'] if begun else 0
        put(0x68,raw_start if begun else 0xFFFFFFFF,4);put(0x6C,body_offset,4);put(0x70,body_['remaining'] if begun and body_['ended'] else 0,4)
        child=u(record+0x78);assert bool(child)==begun and u(record+0x80)==u(record+0x88)==child+(56 if begun else 0)
        for n,value in enumerate((child,child+(56 if begun else 0),child+(56 if begun else 0))):put(0x78+n*8,value)
        if begun:
            begins.append((index+imported,body_offset,body_['remaining'],body_['metadata']))
            if body_['ended']:ends.append((index+imported,body_['remaining']))
            expected_child=(raw_start<<32).to_bytes(8,'little')+b'\xff'*4+b'\xA5'*4+bytes(24)+(0xFFFFFFFF).to_bytes(8,'little')+bytes(4)+b'\xA5'*4
            assert _read_span(p,child,56)==expected_child,(case['label'],'entire child record',index);checked_children+=1
            for word in body_['expected_words']:raw+=word.to_bytes(4,'little');words.append((word,))
        assert _read_span(p,record,144)==expected,(case['label'],'entire function record',index)
        if body_:offset+=len(body_['blob'])
    for slot,want in ((0xB0,[(len(b['groups']),) for b in case['bodies'] if b['begun']]),(0xA8,begins),(0xF8,ends),(0xB8,locals_args),(0x168,words)):
        assert [e.arguments for e in events if e.slot_offset==slot]==want,(case['label'],'independent arguments',hex(slot))
    raw_begin=u(layout.OUT+0x108);assert u(layout.OUT+0x110)-raw_begin==len(raw) and _read_span(p,raw_begin,len(raw))==raw
    assert u(layout.CB+0x80)==u(layout.CB+0x88) and u(layout.CB+0x30)==u(layout.CB+0x38)
    assert [u(layout.STATE+o,4) for o in (0x90,0x94,0x98,0x9C)]==[sum(e[2]==k for e in case['imports']) for k in range(4)]
    return dict(label=case['label'],image_base_hex=hex(base),entry_stack_address_hex=hex(layout.ENTRY),status=status,callback_count=len(nc),
        **{n+'_count':sum(e[0]==n for e in ne) for n in ('allocate','destroy','delete','free')},
        actual_module_parser_AST_and_cleanup_executed=True,natural_return_and_SP_verified=True,
        complete_guest_0xa000_without_masking_match=True,ordered_effects_and_owner_bytes_match=True,
        parser_exit_callback_cleanup_image_globals_and_arguments_match=True,
        independent_complete_function_records_checked=len(case['function_types']),independent_complete_child_records_checked=checked_children,
        independent_raw_locals_metadata_offsets_indexes_and_lengths_match=True,raw_code_words_executed=False,
        synthetic_fixture=not case.get('actual',False),actual_ELF_selected_complete_body_input=case.get('actual',False),
        native_input_snapshot_used=False,whole_native_stack_TLS_OS_compared=False)


def negatives(args):
    rows=[];base=BASES[0];case=spec('guards',[body([7,9],17,[(2,-1),(3,-2)]),body([11])])
    def reject(label,changes=None,fixture=None,setup=None,fault=None):
        fixture=fixture or case;p=previous.prepare(args,base,fixture);offset=0
        def allocate(size):
            nonlocal offset
            address=layout.HEAP+offset;offset+=(size+15)&~15;return address
        params=dict(image_base=base,input_address=layout.DATA,input_size=len(fixture['blob']),output_address=layout.OUT,
            entry_stack_address=layout.ENTRY,varuint_scratch_address=layout.SCRATCH,allocate=allocate,**options(fixture))
        params.update(changes or {})
        if setup:setup(p)
        before={k:bytes(v) for k,v in p.items()};write=alternative._write_span;hits=[]
        def injected(current,address,data):
            if fault(current,address,data):hits.append(address);raise RefillUnsupported('injected code write failure')
            return write(current,address,data)
        if fault:alternative._write_span=injected
        try:
            try:alternative.run_reader_ast_module(p,**params)
            except (RefillUnsupported,ValueError):pass
            else:raise AssertionError('code guard accepted: '+label)
        finally:alternative._write_span=write
        assert before=={k:bytes(v) for k,v in p.items()},label
        if fault:assert hits,label
        rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_invalid_path_executed=False))
    for label,changes in [('default_closed',dict(enable_code_definitions=False)),('flag_type',dict(enable_code_definitions=1)),
            ('other_opt_ins_do_not_enable_code',dict(enable_code_definitions=False,enable_global_definitions=True,enable_table_memory_definitions=True)),
            ('input_frame',dict(input_address=layout.STATE-0x210)),('output_frame',dict(output_address=layout.STATE-0x208)),
            ('scratch_frame',dict(varuint_scratch_address=layout.STATE-0x200)),('reserved_frame',dict(reserved_regions=((layout.STATE-0x210,layout.STATE-0x208),))),
            ('allocate_frame',dict(allocate=lambda size:layout.STATE-0x210)),('allocate_input',dict(allocate=lambda size:layout.DATA)),
            ('allocate_output',dict(allocate=lambda size:layout.OUT)),('node_budget',dict(max_nodes=1)),('entry_budget',dict(max_entries=1)),
            ('byte_budget',dict(max_vector_bytes=143)),('word_bound',dict(max_code_words=1)),('word_bound_across_bodies',dict(max_code_words=2)),
            ('word_zero',dict(max_code_words=0)),('word_large',dict(max_code_words=1048577)),('word_type',dict(max_code_words=1.5))]:reject(label,changes)
    for slot in FUN:
        reject('binding_'+hex(slot),setup=lambda p,slot=slot:_write_span(p,base+0x372370+slot,(base+0x31B870).to_bytes(8,'little')))
    reject('code_frame_constant_unmapped',setup=lambda p:p.pop((base+0x6E188)>>12))
    reject('nonempty_output',setup=lambda p:_write_span(p,layout.OUT,b'\x01'))
    with layout.layout(-0xBC0):
        reject('lower_frame_unmapped',setup=lambda p:p.pop((layout.STATE-0x210)>>12))
    reject('local_group_bound',dict(max_entries=1),spec('groups',[body(groups=[(0,-1),(0,-2)])],function_types=[0]))
    reject('globals_still_closed',dict(enable_global_definitions=False),spec('globals',[body()],globals_=[previous.entry()]))
    reject('definitions_still_closed',dict(enable_table_memory_definitions=False),spec('table',[body()],before=section(4,b'\0')))
    reject('imports_still_closed',dict(enable_function_imports=False,enable_inline_function_imports=False,
        enable_table_memory_global_imports=False,enable_inline_table_memory_global_imports=False),
        spec('imports',[body()],function_types=[0],imports=[(b'm',b'f',0,b'\0')]))
    for label,address,width in [('groups',layout.CB+0x78,8),('cumulative_locals',layout.CB+0x7C,4),
            ('frame_publish',layout.CB+0x30,24),('raw_publish',layout.OUT+0x108,24),('cleanup',layout.CB+0x88,8)]:
        reject('write_failure_'+label,fault=lambda p,a,d,address=address,width=width:a==address and len(d)==width)
    reject('write_failure_code_end',fault=lambda p,a,d:layout.HEAP<=a<layout.SCRATCH and len(d)==4 and d==case['bodies'][0]['remaining'].to_bytes(4,'little'))
    reject('write_failure_clear_active',fault=lambda p,a,d:a==layout.CB+0x28 and d==bytes(8) and bool(int.from_bytes(_read_span(p,a,8),'little')))
    sizes=[]
    def alias(size):
        address=layout.HEAP+sum((n+15)&~15 for n in sizes);sizes.append(size)
        return layout.HEAP if len(sizes)==4 else address
    reject('prior_allocation',dict(allocate=alias))
    for remaining in range(4):
        reject('nonadvancing_'+str(remaining),dict(max_code_words=3),
            spec('short',[body(raw=b'\x06\0\0'+b'\xff'*remaining)],function_types=[0]))
    _,result,_=model(args,base,case,max_code_words=3);assert result.status==0
    return rows


def nonadvancing_controls(args):
    """Stop after four observed word entries; do not claim native completion."""
    class ObservedEnough(Exception):pass
    rows=[]
    for base in BASES:
        for remaining in range(4):
            case=spec('nonadvancing_'+str(remaining),[body(raw=b'\x06\0\0'+b'\xff'*remaining)],function_types=[0]);entries=[]
            def observe(cpu,address):
                if address!=base+FUN[0x168]:return
                word=cpu.reg_read(arm.UC_ARM64_REG_X1)
                cursor=int.from_bytes(cpu.mem_read(layout.STATE+24,8),'little')
                end=int.from_bytes(cpu.mem_read(layout.STATE,8),'little')
                entries.append((word,cursor,end))
                assert word==0 and end-cursor==remaining
                if len(entries)==4:raise ObservedEnough()
            try:native(args,base,case,observe_extra=observe)
            except ObservedEnough:pass
            else:raise AssertionError('short code unexpectedly returned')
            assert len(entries)==4 and len(set(entries))==1
            rows.append(dict(label=case['label'],image_base_hex=hex(base),remaining_bytes=remaining,
                observed_zero_word_entries=4,cursor_unchanged=True,intentionally_interrupted=True,
                natural_return_verified=False,cleanup_verified=False,native_input_snapshot_used=False))
    return rows


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('library','libc','output'):parser.add_argument('--'+name,required=True,type=Path)
    args=parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==layout.heap.oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==layout.heap.LIBC_HASH
    specs=fixtures();actual=actual_specs(args.library);guards=negatives(args);observations=nonadvancing_controls(args);rows=[]
    relocated=[c for c in specs if c['label'] in ('locals','global_then_code','function_imports_23_2')]
    for base in BASES:
        for i,case in enumerate(specs+actual,1):
            rows.append(compare(args,base,case))
            if i%16==0:print('B attached code',hex(base),i,'/',len(specs+actual),'passed',flush=True)
        for delta in (-0xC80,0x100):
            with layout.layout(delta):
                for case in relocated:rows.append(compare(args,base,{**case,'label':case['label']+'_SP_'+str(delta)}))
        with previous.definitions.guest_layout(0x7000000000):
            for case in relocated+[c for c in specs if c['label'] in ('all_sections_False','body_overshoot_3','generated_11')]:
                rows.append(compare(args,base,{**case,'label':case['label']+'_high_guest'}))
    evidence=dict(schema='vm9-alternative-ast-module-code-fresh-v1',evidence_date='2026-10-11',evidence_timezone='Asia/Shanghai',
        sample_sha256=layout.heap.oracle.LIBRARY_SHA256,matching_libc_sha256=layout.heap.LIBC_HASH,
        native_Python_module_code_controls=len(rows),rollback_negative_controls=len(guards),
        bounded_nonadvancing_native_observations=len(observations),relocated_entry_stack_controls=12,relocated_full_guest_controls=12,
        pre_change_behavior_RED_controls=10,actual_ELF_selected_body_controls=sum(r['actual_ELF_selected_complete_body_input'] for r in rows),
        purely_synthetic_controls=sum(r['synthetic_fixture'] for r in rows),actual_ELF_source_code_payload_bytes=218682,
        actual_ELF_source_bodies=121,actual_ELF_selected_distinct_complete_bodies=3,generated_fixture_seed=0x323CA8,
        enable_code_definitions_default=False,code_requires_other_opt_ins=False,raw_code_words_executed=False,
        attached_code_slots_hex=[hex(s) for s in FUN],
        independent_complete_function_records_checked=sum(r['independent_complete_function_records_checked'] for r in rows),
        independent_complete_child_records_checked=sum(r['independent_complete_child_records_checked'] for r in rows),
        native_input_snapshot_used=False,private_payloads_published=False,whole_native_stack_TLS_OS_compared=False,
        complete_attached_reader_implemented=False,complete_python_reader_implemented=False,independent_Python_factory_implemented=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False,
        cases=rows,negative_cases=guards,nonadvancing_observations=observations)
    args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    print('B attached code:',len(rows),'native/Python controls,',len(guards),'rollback checks,',len(observations),'bounded native observations',flush=True)
if __name__=='__main__':main()
