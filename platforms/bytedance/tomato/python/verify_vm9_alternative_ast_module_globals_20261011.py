"""Actual B module global definitions and initializer AST composition controls.

Synthetic and fresh ELF inputs, with independent record/raw/result checks.
Native stack
observations are assertions only and never inputs to the Python model.
"""
from __future__ import annotations
import argparse,hashlib,json,random
from pathlib import Path
from unicorn import arm64_const as arm
import verify_vm9_alternative_ast_module_definitions_20261011 as definitions
from vm9_allocator import RefillUnsupported,_read_span,_write_span
previous=definitions.previous
alternative=previous.alternative
BASES=previous.BASES
FUN={**definitions.FUN,0x78:0x31D004,0x80:0x31D028,0x88:0x31D45C,0x90:0x31D4AC,
    0xC0:0x31DA9C,0xC8:0x31DAB4,0xD0:0x31DB04,0xD8:0x31DB28,0xE0:0x31DB4C,0xE8:0x31DB70}
ARGC={**definitions.ARGC,0x78:1,0x80:3,0x88:1,0x90:2,0xC0:1,0xC8:0,0xD0:1,0xD8:1,0xE0:1,0xE8:1}
SLOTS=(0x78,0x80,0x88,0x90,0xC0,0xC8,0xD0,0xD8,0xE0,0xE8)
section,enc,types=previous.section,previous.enc,previous.types
MASK=(1<<64)-1


def signed(value):
    out=bytearray()
    while True:
        byte=value&127;value>>=7
        if (value==0 and not byte&64) or (value==-1 and byte&64):
            out.append(byte);return bytes(out)
        out.append(byte|128)


def constant(kind,bits):
    width=4 if kind in (2,4) else 8
    bits&=(1<<(width*8))-1
    value=bits-(1<<(width*8)) if bits>>(width*8-1) else bits
    return bytes([{2:0x41,3:0x42,4:0x43,5:0x44}[kind]])+(signed(value) if kind in (2,3) else bits.to_bytes(width,'little'))


def entry(value=0x7F,mutable=0,ops=(),ended=True,tail=b''):
    return dict(value=value,mutable=mutable,ops=list(ops),ended=ended,
        blob=bytes((value,mutable))+b''.join(constant(k,b) for k,b in ops)+(b'\x0b' if ended else tail))


def spec(label,entries=(),before=b'',after=b'',seed='padding',status=0,imports=(),table_memory=False,**kw):
    return dict(label=label,entries=list(entries),blob=b'A'*8+before+section(6,enc(len(entries))+b''.join(e['blob'] for e in entries))+after,
        seed=seed,status=status,imports=imports,table_memory=table_memory,**kw)


def minimal_specs():
    return [spec('empty'),spec('i32',[entry(ops=[(2,0xFFFFFFFF)])]),
        spec('i64',[entry(0x7E,1,[(3,MASK)])]),spec('f32',[entry(0x7D,0,[(4,0x7FC00001)])]),
        spec('f64',[entry(0x7C,1,[(5,0x7FF8000000000001)])]),spec('end_only',[entry()]),
        spec('end_after_type',[entry(0x7E)],before=types([([],[])]),seed='zero'),
        spec('end_after_memory',[entry()],before=section(5,b'\x01\x00\x03'),seed='image',table_memory=True),
        spec('two_end',[entry(0x7E,0,[(3,MASK)]),entry(mutable=1)])]


def fixtures():
    rows=minimal_specs()
    for pad in (0,0x39,0xA5,0xFF):
        for count in (0,1,2,3,4,5):
            rows.append(spec(f'growth_{pad}_{count}',[entry((0x7F,0x7E,0x7D,0x7C)[i%4],i%2,[(2+i%4,(i+1)*0x11223344)]) for i in range(count)],frame_padding=pad))
        rows.append(spec('end_seed_'+str(pad),[entry(0x7E),entry(0x70,1)],frame_padding=pad))
    for kind in (2,3,4,5):
        for bits in (0,1,127,128,0x7FFFFFFF,0x80000000,0xFFFFFFFF,0x8000000000000000,0x7FF800007FC00001,MASK):
            rows.append(spec(f'bits_{kind}_{bits}',[entry(0x81-kind,kind%2,[(kind,bits)]),entry()]))
    for value in (0x7B,0x7C,0x7D,0x7E,0x7F,0x6F,0x70):
        for mutable in (0,1):rows.append(spec(f'type_{value}_{mutable}',[entry(value,mutable)]))
    for count in (1,2,3,4,7):
        rows.append(spec('multiple_constants_'+str(count),[entry(ops=[(2+i%4,(i+1)*0xDEADBEEF) for i in range(count)])]))
    for i,ts in enumerate(([],[([],[])],[([0x7F],[])],[([],[0x7E])],[([0x7F,0x7E],[0x7D])])):
        rows.append(spec('type_prefix_'+str(i),[entry(),entry(0x7E,1,[(3,MASK)])],before=types(ts),seed='zero'))
    for kind,payload in enumerate((b'\0',b'\x70\x01\x03\x09',b'\x01\x03\x09',b'\x7e\x01')):
        for count in (1,2,4):
            for length in (0,23):
                imports=[(b'm'*length,b'f'*(length+1),kind,payload)]*count
                before=types([([0x7F],[0x7E])])+section(2,enc(count)+b''.join(previous.import_(*e) for e in imports))
                rows.append(spec(f'imports_{kind}_{count}_{length}',[entry(),entry(0x7E,1,[(3,0xFEDCBA9876543210)])],before=before,seed='zero',imports=imports))
    for table_count,memory_count in ((0,None),(1,None),(2,None),(None,0),(None,1),(1,1),(2,2)):
        before=b''
        if table_count is not None:before+=section(4,enc(table_count)+b'\x70\x00\x03'*table_count)
        if memory_count is not None:before+=section(5,enc(memory_count)+b'\x00\x03'*memory_count)
        rows.append(spec(f'definitions_{table_count}_{memory_count}',[entry()],before=before,seed='image' if memory_count is not None else 'padding',table_memory=True))
    for count in (0,1,2):
        rows.append(spec('functions_'+str(count),[entry()],before=types([([],[])])+section(3,enc(count)+bytes(count)),seed='zero',status=int(count!=0)))
    for warm in (False,True):
        rows.append(spec('custom_before_'+str(warm),[entry(),entry(ops=[(4,0x80000000)])],before=section(0,b'\x01x'),seed='zero',warm_rank=warm))
        rows.append(spec('custom_after_memory_'+str(warm),[entry()],before=section(5,b'\x01\0\x03')+section(0,b'\x01x'),seed='zero',table_memory=True,warm_rank=warm))
    for label,tail in [('duplicate',section(6,b'\0')),('backwards',section(1,b'\0')),('envelope',b'\x08\x80'),('unknown',b'\x0d\0')]:
        rows.append(spec(label,[entry(ops=[(2,17)])],after=tail,status=1))
    rows.append(spec('surrounding',[entry(),entry(ops=[(5,MASK)])],after=section(0,b'\x01x')+section(7,b'\0')+section(8,b'\x03')+section(12,b'\x02')))
    for kind in (2,3,4,5):
        encoded=constant(kind,MASK)
        for cut in range(1,len(encoded)):
            rows.append(spec(f'truncated_{kind}_{cut}',[entry(ops=[(2,3)]),entry(ended=False,tail=encoded[:cut])],status=1))
    for label,tail in [('missing_end',b''),('zero',b'\0'),('unknown_op',b'\x7f'),('high_op',b'\xff'),('prefix_cut',b'\xfc\x80'),('prefix',b'\xfc\0'),('prefix_clamp',b'\xfd'+enc(512))]:
        rows.append(spec(label,[entry(ended=False,tail=tail)],status=1))
    for label,bad in [('bad_type',b'\x7a\0\x0b'),('indexed_type',b'\x6b\x01\0\x0b'),('type_cut',b'\xff'),('mutable_cut',b'\x7f'),('mutable_bad',b'\x7f\x02\x0b')]:
        row=spec(label,[entry(ops=[(3,MASK)])],status=1)
        row['blob']=b'A'*8+section(6,b'\x02'+row['entries'][0]['blob']+bad);rows.append(row)
    for label,body in [('count_cut',b'\x80'),('count_bound',b'\x7f'),('no_count',b'')]:
        row=spec(label,status=1);row['blob']=b'A'*8+section(6,body);rows.append(row)
    rng=random.Random(0x32365C)
    for i in range(12):
        entries=[entry(rng.choice((0x7F,0x7E,0x7D,0x7C)),rng.randrange(2),[(rng.randrange(2,6),rng.getrandbits(64)) for _ in range(rng.randrange(4))]) for _ in range(rng.randrange(1,5))]
        rows.append(spec('generated_'+str(i),entries,frame_padding=rng.randrange(256)))
    return rows


def actual_specs(library):
 import verify_vm9_alternative_globals_20261008 as global_sections
 blob=global_sections.actual_inputs(library)[0]['blob'];cursor=9
 def leb(signed=False):
  nonlocal cursor
  out=shift=0
  while True:
   byte=blob[cursor];cursor+=1;out|=(byte&127)<<shift;shift+=7
   if byte<128:return out-(1<<shift) if signed and byte&64 else out
 length=leb();end=cursor+length;count=leb();entries=[]
 assert end==len(blob) and length==133 and count==22
 for _ in range(count):
  value=blob[cursor];mutable=blob[cursor+1];cursor+=2;ops=[]
  while True:
   op=blob[cursor];cursor+=1
   if op==0x0B:break
   kind={0x41:2,0x42:3,0x43:4,0x44:5}[op]
   if kind in (2,3):bits=leb(True)
   else:
    width=4 if kind==4 else 8;bits=int.from_bytes(blob[cursor:cursor+width],'little');cursor+=width
   ops.append((kind,bits))
  entries.append(entry(value,mutable,ops))
 assert cursor==end
 plain=spec('fresh_ELF_globals',entries);assert plain['blob']==blob
 imports=[(b'm',b'g',3,b'\x7f\1')]
 prefix=section(2,b'\x01'+previous.import_(*imports[0]))+section(5,b'\x01\0\x03')
 mixed=spec('fresh_ELF_globals_after_synthetic_import_memory',entries,before=prefix,seed='image',table_memory=True,imports=imports)
 return [plain,mixed]


def prepare(args,base,case):
    p=previous.prepare(args,base,case)
    _write_span(p,previous.STATE-0x2A0,bytes([case.get('frame_padding',0xA5)])*0x2A0)
    return p


def native(args,base,case):
    heap=previous.heap;saved=(heap.FUN,heap.ARGC,heap.prepare,heap.oracle.native);entries=[]
    def instrumented(*a,**kw):
        observe=kw['instruction_observer']
        def observed(cpu,address):
            offset=address-base
            if offset in (FUN[s] for s in SLOTS):
                slot=next(s for s in SLOTS if FUN[s]==offset)
                sp=cpu.reg_read(arm.UC_ARM64_REG_SP)
                assert sp==previous.STATE-(0xB0 if slot<=0x90 else 0x110)
                entries.append((slot,int.from_bytes(cpu.mem_read(previous.STATE-0xB0,8),'little')))
            observe(cpu,address)
        kw['instruction_observer']=observed
        return saved[3](*a,**kw)
    try:
        heap.FUN,heap.ARGC,heap.prepare,heap.oracle.native=FUN,ARGC,prepare,instrumented
        status,p,e,c,snap=heap.native(args,base,case)
    finally:heap.FUN,heap.ARGC,heap.prepare,heap.oracle.native=saved
    snap['global_entries']=entries
    return status,p,e,c,snap


def options(case):
    imports=case.get('imports',());function=any(e[2]==0 for e in imports)
    return dict(enable_global_definitions=True,enable_table_memory_definitions=case.get('table_memory',False),
        enable_function_imports=function,enable_inline_function_imports=function,
        enable_table_memory_global_imports=bool(imports),enable_inline_table_memory_global_imports=bool(imports))


def model(args,base,case,**changes):
    saved=previous.prepare
    try:
        # previous.model resolves its prepare at call time. Avoid recursion.
        def prepared(*a):
            p=saved(*a);_write_span(p,previous.STATE-0x2A0,bytes([case.get('frame_padding',0xA5)])*0x2A0);return p
        previous.prepare=prepared
        return previous.model(args,base,case,**(options(case)|changes))
    finally:previous.prepare=saved


def compare(args,base,case):
    status,np,ne,nc,snap=native(args,base,case);p,result,state=model(args,base,case)
    assert result.status==status==case['status'],(case['label'],'status',status,result.status)
    assert previous.heap.previous.normalized(result.effects)==ne,(case['label'],'effects')
    assert state==snap['parser'] and _read_span(p,previous.CB,0x120)==snap['callback_final'],(case['label'],'cleanup')
    a=_read_span(p,previous.heap.oracle.GUEST,0xA000);b=_read_span(np,previous.heap.oracle.GUEST,0xA000)
    assert a==b,(case['label'],'guest bytes',[(hex(i),x,y) for i,(x,y) in enumerate(zip(a,b)) if x!=y][:12])
    for (address,width),data in snap['globals'].items():assert _read_span(p,address,width)==data
    events=result.sections.callback_events
    assert [(e.slot_offset,e.arguments,e.cursor,e.section_end) for e in events]==nc,(case['label'],'events')
    u=lambda a,n=8:int.from_bytes(_read_span(p,a,n),'little')
    count=len(case['entries']);start=u(previous.OUT+0x78);raw=bytearray();expected_args=[];expected_begins=[]
    assert u(previous.OUT+0x80)-start==count*176,(case['label'],'entry count')
    word={'zero':0,'image':base+0x1210F8,'padding':int.from_bytes(bytes([case.get('frame_padding',0xA5)])*8,'little')}[case['seed']]
    imported=sum(e[2]==3 for e in case['imports'])
    for index,e in enumerate(case['entries']):
        value=(e['value']-128)&MASK;word=(word&0xFFFFFFFF00000000)|(value&0xFFFFFFFF)
        expected_begins.append(word);raw_start=len(raw)
        for kind,bits in e['ops']:
            width=4 if kind in (2,4) else 8;word=bits&((1<<(width*8))-1)
            raw+=kind.to_bytes(4,'little')+word.to_bytes(width,'little')
        if e['ended']:expected_args.append((index+imported,word))
        record=start+index*176;expected=bytearray(b'\xA5'*176)
        def put(offset,value,width=8):expected[offset:offset+width]=value.to_bytes(width,'little')
        for offset,value_,width in ((0,base+0x372568,8),(8,3,4),(0xC,value,8),(0x14,e['mutable'],4),
                (0x18,base+0x3724F0,8),(0x20,0,4),(0x58,0,8),(0x60,0,4),
                (0x80,raw_start,4),(0x84,0,4),(0x88,0,4),(0xA8,word if e['ended'] else 0,8)):
            put(offset,value_,width)
        for offset in (0x28,0x68,0x90):expected[offset:offset+24]=bytes(24)
        pointer=u(record+0x40);assert pointer and u(record+0x48)==u(record+0x50)==pointer+8
        assert _read_span(p,pointer,8)==value.to_bytes(8,'little')
        for offset,v in ((0x40,pointer),(0x48,pointer+8),(0x50,pointer+8)):put(offset,v)
        assert _read_span(p,record,176)==expected,(case['label'],'complete global record',index)
    assert [e.arguments for e in events if e.slot_offset==0x90]==expected_args,(case['label'],'independent full u64 ends')
    assert [w for s,w in snap['global_entries'] if s==0x88]==expected_begins,(case['label'],'independent caller high words')
    assert [e.arguments[0] for e in events if e.slot_offset==0x80]==list(range(imported,imported+count))
    assert [u(previous.STATE+o,4) for o in (0x90,0x94,0x98,0x9C)]==[sum(e[2]==k for e in case['imports']) for k in range(4)]
    raw_begin=u(previous.OUT+0x108);assert u(previous.OUT+0x110)-raw_begin==len(raw)
    assert _read_span(p,raw_begin,len(raw))==raw,(case['label'],'independent raw constants')
    assert u(previous.CB+0xC8)==u(previous.CB+0xD0) and u(previous.CB+0x30)==u(previous.CB+0x38)
    assert not any(_read_span(p,previous.CB+0x108,24))
    return dict(label=case['label'],image_base_hex=hex(base),entry_stack_address_hex=hex(previous.ENTRY),status=status,
        callback_count=len(nc),**{n+'_count':sum(e[0]==n for e in ne) for n in ('allocate','destroy','delete','free')},
        actual_module_parser_AST_and_cleanup_executed=True,natural_return_and_SP_verified=True,
        complete_guest_0xa000_without_masking_match=True,ordered_effects_and_owner_bytes_match=True,
        parser_exit_callback_cleanup_image_globals_and_arguments_match=True,
        independent_complete_global_records_checked=count,independent_raw_result_seed_and_import_indexes_match=True,
        synthetic_fixture=True,native_input_snapshot_used=False,whole_native_stack_TLS_OS_compared=False)


def negatives(args):
    rows=[];base=BASES[0];case=spec('guards',[entry(ops=[(3,MASK),(2,7)]),entry()])
    def reject(label,changes=None,fixture=None,setup=None,fault=None):
        fixture=fixture or case;p=prepare(args,base,fixture);offset=0
        def allocate(size):
            nonlocal offset
            address=previous.HEAP+offset;offset+=(size+15)&~15;return address
        params=dict(image_base=base,input_address=previous.DATA,input_size=len(fixture['blob']),output_address=previous.OUT,
            entry_stack_address=previous.ENTRY,varuint_scratch_address=previous.SCRATCH,allocate=allocate,**options(fixture))
        params.update(changes or {})
        if setup:setup(p)
        before={k:bytes(v) for k,v in p.items()};write=alternative._write_span;hits=[]
        def injected(p,address,data):
            if fault(address,data):hits.append(address);raise RefillUnsupported('injected global write failure')
            return write(p,address,data)
        if fault:alternative._write_span=injected
        try:
            try:alternative.run_reader_ast_module(p,**params)
            except (RefillUnsupported,ValueError):pass
            else:raise AssertionError('global guard accepted: '+label)
        finally:alternative._write_span=write
        assert before=={k:bytes(v) for k,v in p.items()},label
        if fault:assert hits,label
        rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_invalid_path_executed=False))
    for label,changes in [('default_closed',dict(enable_global_definitions=False)),('flag_type',dict(enable_global_definitions=1)),
            ('input_frame',dict(input_address=previous.STATE-0x2A0)),('output_frame',dict(output_address=previous.STATE-0x298)),
            ('scratch_frame',dict(varuint_scratch_address=previous.STATE-0x290)),('reserved_frame',dict(reserved_regions=((previous.STATE-0x2A0,previous.STATE-0x298),))),
            ('allocate_frame',dict(allocate=lambda size:previous.STATE-0x2A0)),('allocate_input',dict(allocate=lambda size:previous.DATA)),
            ('node_budget',dict(max_nodes=1)),('entry_budget',dict(max_entries=1)),('byte_budget',dict(max_vector_bytes=175)),
            ('operation_bound',dict(max_initializer_ops=1)),('operation_zero',dict(max_initializer_ops=0)),('operation_large',dict(max_initializer_ops=65537))]:reject(label,changes)
    for slot in SLOTS:
        e=entry(ops=[(2,1),(3,2),(4,3),(5,4)])
        reject('binding_'+hex(slot),fixture=spec('all_slots',[e]),setup=lambda p,slot=slot:_write_span(p,base+0x372370+slot,(base+0x31B870).to_bytes(8,'little')))
    for got in (0x3750A8,0x375090):reject('node_GOT_'+hex(got),setup=lambda p,got=got:_write_span(p,base+got,bytes(8)))
    reject('opcode_table',setup=lambda p:_write_span(p,base+0x3750B0,bytes(8)))
    reject('nonempty_output',setup=lambda p:_write_span(p,previous.OUT,b'\x01'))
    reject('code_closed',fixture=spec('code_closed',[entry()],after=section(10,b'\0')))
    for label,address,width in [('result',previous.STATE-0xB0,8),('read_scratch',previous.STATE-0x108,8),
            ('global_publish',previous.OUT+0x78,24),('cache_publish',previous.CB+0xC8,24),
            ('frame_publish',previous.CB+0x30,24),('raw_publish',previous.OUT+0x108,24),('cleanup',previous.CB+0xD0,8)]:
        reject('write_failure_'+label,fault=lambda a,d,address=address,width=width:a==address and len(d)==width)
    sizes=[]
    def alias(size):
        address=previous.HEAP+sum((n+15)&~15 for n in sizes);sizes.append(size)
        return previous.HEAP if len(sizes)==4 else address
    reject('prior_allocation',dict(allocate=alias))
    # An exact two-op expression (constant + end) fits the bound.
    _,result,_=model(args,base,spec('exact_bound',[entry(ops=[(2,7)])]),max_initializer_ops=2)
    assert result.status==0
    return rows


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('library','libc','output'):parser.add_argument('--'+name,required=True,type=Path)
    args=parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==previous.heap.oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==previous.heap.LIBC_HASH
    specs=fixtures();guards=negatives(args);rows=[]
    for base in BASES:
        for i,case in enumerate(specs,1):
            rows.append(compare(args,base,case))
            if i%16==0:print('B attached globals',hex(base),i,'/',len(specs),'passed',flush=True)
        for delta in (-0xC80,0x100):
            with previous.layout(delta):
                for case in (specs[5],specs[7],specs[8]):rows.append(compare(args,base,{**case,'label':case['label']+'_SP_'+str(delta)}))
        with definitions.guest_layout(0x7000000000):
            for case in [specs[5],specs[7],specs[8]]+[c for c in specs if c['label'] in ('imports_3_4_0','custom_after_memory_False','functions_2')]:
                rows.append(compare(args,base,{**case,'label':case['label']+'_high_guest'}))
        for case in actual_specs(args.library):
            row=compare(args,base,case)
            row.update(synthetic_fixture=False,actual_ELF_global_section_input=True)
            rows.append(row)
    evidence=dict(schema='vm9-alternative-ast-module-globals-fresh-v1',evidence_date='2026-10-11',evidence_timezone='Asia/Shanghai',
        sample_sha256=previous.heap.oracle.LIBRARY_SHA256,matching_libc_sha256=previous.heap.LIBC_HASH,
        native_Python_module_global_controls=len(rows),rollback_negative_controls=len(guards),relocated_entry_stack_controls=12,relocated_full_guest_controls=12,
        pre_change_behavior_RED_controls=18,actual_ELF_global_section_controls=4,purely_synthetic_controls=394,
        actual_ELF_global_section_payload_bytes=133,actual_ELF_global_section_entries=22,generated_fixture_seed=0x32365C,enable_global_definitions_default=False,globals_require_import_or_definition_opt_ins=False,
        attached_global_slots_hex=[hex(s) for s in SLOTS],independent_complete_global_records_checked=sum(r['independent_complete_global_records_checked'] for r in rows),
        native_input_snapshot_used=False,private_payloads_published=False,whole_native_stack_TLS_OS_compared=False,
        complete_attached_reader_implemented=False,complete_python_reader_implemented=False,independent_Python_factory_implemented=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False,cases=rows,negative_cases=guards)
    args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    print('B attached globals:',len(rows),'native/Python controls,',len(guards),'rollback checks',flush=True)
if __name__=='__main__':main()
