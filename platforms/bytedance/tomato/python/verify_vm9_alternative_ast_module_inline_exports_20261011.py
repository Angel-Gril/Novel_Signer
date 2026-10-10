"""Actual B attached inline exports; native frames are assertions, never inputs.

Synthetic cases and fresh ELF export entries with synthetic declarations.
"""
from __future__ import annotations
import argparse,hashlib,json,random
from contextlib import contextmanager
from pathlib import Path
from unicorn import arm64_const as arm
import verify_vm9_alternative_ast_module_exports_20261011 as previous
from vm9_allocator import RefillUnsupported,_read_span,_write_span
layout=previous.layout;alternative=previous.alternative
BASES=previous.BASES;KINDS=previous.KINDS;MASK=previous.MASK
spec=previous.spec;section=previous.section;enc=previous.enc
imported=previous.imported;cache_specs=previous.cache_specs


def native(args,base,case):
    saved=layout.heap.oracle.native;headers=[]
    def instrumented(*a,**kw):
        observe=kw['instruction_observer']
        def observed(cpu,address):
            if address==base+0x31B360:
                cpu.reg_write(arm.UC_ARM64_REG_X28,case.get('entry_x28',0))
            if address==base+0x31D500:
                headers.append(bytes(cpu.mem_read(layout.STATE-0x160,24)))
            observe(cpu,address)
        kw['instruction_observer']=observed;return saved(*a,**kw)
    try:
        layout.heap.oracle.native=instrumented
        status,p,e,c,snap=previous.native(args,base,case)
    finally:layout.heap.oracle.native=saved
    snap['export_headers']=headers
    return status,p,e,c,snap


def options(case):
    return previous.options(case)|dict(enable_inline_exports=True,entry_x28=case.get('entry_x28',0),
        enable_global_definitions=bool(case['globals']) or case.get('empty_globals',False))
def model(args,base,case,**changes):return previous.model(args,base,case,**(options(case)|changes))


def compare(args,base,case):
    status,np,ne,nc,snap=native(args,base,case)
    callback=alternative.run_reader_ast_callback;header_index=0
    def observed(current,**kw):
        nonlocal header_index
        if kw['slot_offset']==0x98:
            assert _read_span(current,layout.STATE-0x160,24)==snap['export_headers'][header_index],(case['label'],'entry header',header_index)
            header_index+=1
        return callback(current,**kw)
    try:
        alternative.run_reader_ast_callback=observed
        p,result,state=model(args,base,case)
    finally:alternative.run_reader_ast_callback=callback
    assert result.status==status==case['status'],(case['label'],'status',status,result.status)
    assert layout.heap.previous.normalized(result.effects)==ne,(case['label'],'effects')
    assert state==snap['parser'] and _read_span(p,layout.CB,0x120)==snap['callback_final'],(case['label'],'cleanup')
    a=_read_span(p,layout.heap.oracle.GUEST,0xA000);b=_read_span(np,layout.heap.oracle.GUEST,0xA000)
    assert a==b,(case['label'],'guest bytes',[(hex(i),x,y) for i,(x,y) in enumerate(zip(a,b)) if x!=y][:12])
    if case.get('large_arena'):
        assert _read_span(p,layout.HEAP,0x100000)==_read_span(np,layout.HEAP,0x100000),(case['label'],'full heap arena')
    for (address,width),data in snap['globals'].items():assert _read_span(p,address,width)==data
    events=result.sections.callback_events;assert [(e.slot_offset,e.arguments,e.cursor,e.section_end) for e in events]==nc
    u=lambda a,n=8:int.from_bytes(_read_span(p,a,n),'little')
    begin=u(layout.OUT+0xA8);count=len(case['exports']);capacity=1<<(count-1).bit_length() if count else 0
    assert u(layout.OUT+0xB0)==begin+count*40 and u(layout.OUT+0xB8)==begin+capacity*40
    specs=cache_specs(case);regions=[(begin,begin+capacity*40)] if capacity else []
    for index,(name,kind,target_index) in enumerate(case['exports']):
        record=begin+index*40;name_ptr=u(record+16);node=u(record+24);storage=(len(name)+16)&~15
        if len(name)>22:
            expected=(storage|1).to_bytes(8,'little')+len(name).to_bytes(8,'little')+name_ptr.to_bytes(8,'little')
            assert _read_span(p,name_ptr,len(name)+1)==name+b'\0'
        else:
            expected=bytearray(snap['export_headers'][index])
            expected[0]=len(name)*2;expected[1:len(name)+2]=name+b'\0'
            assert _read_span(p,record,1)==bytes([len(name)*2])
            assert _read_span(p,record+1,len(name)+1)==name+b'\0'
        expected=bytes(expected)+node.to_bytes(8,'little')+target_index.to_bytes(4,'little')+b'\xA5'*4
        assert _read_span(p,record,40)==expected
        off,stride,table=KINDS[kind];cache=u(layout.CB+off)+target_index*stride;shape=specs[kind][target_index]
        assert node!=cache and u(node)==u(cache)==base+table and u(node+8,4)==kind
        expected_node=bytearray(_read_span(p,cache,stride));regions.append((node,node+stride))
        if len(name)>22:regions.append((name_ptr,name_ptr+storage))
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
        complete_export_records_checked=count,inline_entry_headers_compared=True,complete_cloned_nodes_checked=count,
        independent_names_indexes_capacities_type_vectors_and_limits_match=True,owned_storage_disjoint_from_borrowed_cache=True,
        synthetic_fixture=not case.get('actual',False),actual_ELF_export_entries=case.get('actual',False),
        full_extra_0x100000_heap_compared=bool(case.get('large_arena')),native_input_snapshot_used=False,whole_native_stack_TLS_OS_compared=False)



def large_native(args,base,spec):
 heap=layout.heap;oracle=heap.oracle
 ENTRY,CB,STATE,OUT,DATA,HEAP=layout.ENTRY,layout.CB,layout.STATE,layout.OUT,layout.DATA,layout.HEAP
 FUN,ARGC,GLOBALS=heap.FUN,heap.ARGC,heap.GLOBALS
 prepare,libc_memcmp=heap.prepare,heap.libc_memcmp
 p=prepare(args,base,spec);sizes={};n=0;effects=[];callbacks=[];snap={};mode=('callback_cleanup',CB,0x108)
 def observe(cpu,a):
  nonlocal mode
  o=a-base
  if o==0x324444:
   snap['constructed_callback']=bytes(cpu.mem_read(CB,0x120));assert cpu.reg_read(arm.UC_ARM64_REG_X2)==CB
  if o==0x324540:mode=('parser',cpu.reg_read(arm.UC_ARM64_REG_X0),24)
  if o in FUN.values():
   slot=next(s for s,f in FUN.items() if f==o);sp=cpu.reg_read(arm.UC_ARM64_REG_SP);argv=tuple(cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) if i<8 else int.from_bytes(cpu.mem_read(sp+(i-8)*8,8),'little') for i in range(1,ARGC[slot]+1));assert sp==STATE-0x100 if slot==0x28 else True;callbacks.append((slot,argv,int.from_bytes(cpu.mem_read(STATE+24,8),'little'),int.from_bytes(cpu.mem_read(STATE,8),'little')));mode=('ast',OUT,0x120)
   assert int.from_bytes(cpu.mem_read(CB+8,8),'little')==STATE+8
  if o==0x31b3e8:
   snap['parser']=bytes(cpu.mem_read(STATE,0xb0));snap['parser_status']=cpu.reg_read(arm.UC_ARM64_REG_X0)
  if o==0x31b458:mode=('callback_cleanup',CB,0x108)
  if o in (0x3244e0,0x3244f0,0x324500,0x324510):mode=('parser',STATE+{0x3244e0:0x70,0x3244f0:0x58,0x324500:0x40,0x324510:0x28}[o],24)
  if o in (0x321260,0x321308,0x321368):
   addr=cpu.reg_read(arm.UC_ARM64_REG_X0);table=int.from_bytes(cpu.mem_read(addr,8),'little')-base
   if oracle.GUEST<=addr<oracle.GUEST+0xA000 or HEAP<=addr<oracle.GUEST+oracle.GUEST_SIZE:effects.append(('destroy',addr,{0x3724f0:64,0x372590:40,0x372518:48,0x372540:40,0x372568:24}[table],mode[1],bytes(cpu.mem_read(mode[1],mode[2]))))
  if o in (0x3212B0,0x3212FC,0x321300,0x321304,0x32132C):
   addr=cpu.reg_read(arm.UC_ARM64_REG_X0);effects.append(('delete',addr,{0x3212B0:64,0x3212FC:48,0x321300:40,0x321304:24,0x32132C:40}[o],mode[1],bytes(cpu.mem_read(mode[1],mode[2]))))
  if o==0x2CC470:
   addr=cpu.reg_read(arm.UC_ARM64_REG_X1)
   if oracle.GUEST<=addr<oracle.GUEST+0xA000 or HEAP<=addr<oracle.GUEST+oracle.GUEST_SIZE:
    effects.append(('destroy',addr,144,mode[1],bytes(cpu.mem_read(mode[1],mode[2]))))
  if o==0x31b454:assert cpu.reg_read(arm.UC_ARM64_REG_SP)==ENTRY
 def malloc(cpu,size):
  nonlocal n
  ptr=HEAP+n;n+=(size+15)&~15;assert ptr+size<oracle.GUEST+oracle.GUEST_SIZE
  sizes[ptr]=size;effects.append(('allocate',ptr,size,mode[1],bytes(cpu.mem_read(mode[1],mode[2]))));return ptr
 def free(cpu):
  ptr=cpu.reg_read(arm.UC_ARM64_REG_X0);assert ptr in sizes,('unknown/double',hex(ptr))
  effects.append(('free',ptr,sizes.pop(ptr),mode[1],bytes(cpu.mem_read(mode[1],mode[2]))));return 0
 observed={(CB,0x120):None,(HEAP,0x100000):None,**{(base+offset,64):None for offset in GLOBALS}}
 def memcmp(cpu):
  cpu.reg_write(arm.UC_ARM64_REG_PC,libc_memcmp(args.libc));return None
 status,memory,calls,ledger=oracle.native(args.library,base,0x31b360,[0x123,0x456,DATA,len(spec['blob']),OUT],p,malloc_handler=malloc,host_imports={0x347fa0:free,0x347fe0:memcmp},libc=args.libc,instruction_observer=observe,instruction_limit=5000000,observed_memory=observed)
 assert not calls and not ledger
 _write_span(p,oracle.GUEST,memory)
 _write_span(p,HEAP,observed[HEAP,0x100000])
 snap['callback_final']=observed[CB,0x120]
 snap['globals']={(a,w):data for (a,w),data in observed.items() if a not in (CB,HEAP)}
 return status,p,effects,callbacks,snap


@contextmanager
def arena(case):
    if not case.get('large_arena'):
        yield;return
    heap=layout.heap;oracle=heap.oracle
    saved=heap.native,heap.HEAP,layout.HEAP,oracle.GUEST_SIZE
    try:
        heap.native=large_native;heap.HEAP=layout.HEAP=oracle.GUEST+0x10000
        oracle.GUEST_SIZE=0x110000
        yield
    finally:heap.native,heap.HEAP,layout.HEAP,oracle.GUEST_SIZE=saved


def fixtures():
    rows=[]
    for kind in range(4):
        for length in range(23):
            rows.append(spec(f'name_{kind}_{length}',[(bytes((i*17)%256 for i in range(length)),kind,0)],imports=[imported(kind)]))
        for x28 in (1,0x12345678ABCDEF00,MASK):
            rows.append(spec(f'register_{kind}_{x28:x}',[(b'',kind,0)],imports=[imported(kind)],entry_x28=x28))
        for lengths in ((22,1,0,7,23,0),(0,22,21,1),(23,2,22,0),(1,2,3,4,5)):
            rows.append(spec(f'sequence_{kind}_{len(rows)}',[(bytes([97+i])*n,kind,0) for i,n in enumerate(lengths)],imports=[imported(kind)],entry_x28=0xFEDCBA9876543210))
    for pad in (0,0x39,0xA5,0xFF):
        for ds in ([([],[])],[([0x7F],[])],[([],[0x7E])],[([0x7F],[0x7E])]):
            rows.append(spec('defined_function_'+str(len(rows)),[(b'',0,0),(b'xy',0,0)],definitions=ds,functions=[0],bodies=[previous.code.body()],frame_padding=pad))
        rows.append(spec('mixed_'+str(pad),[(bytes([65+k])*n,k,0) for k,n in enumerate((0,1,2,22))],imports=[imported(k,23 if k%2 else 1) for k in range(4)],
            tables=[(0x70,1,17,19)],memories=[(5,1<<35,1<<40)],globals_=[previous.previous.entry(ops=[(3,19),(2,21)])],frame_padding=pad))
    for f in (0,1):
        rows.append(spec('table_'+str(f),[(b'',1,0)],tables=[(0x6F,f,17,19)]*3))
    for f in (0,1,4,5):rows.append(spec('memory_'+str(f),[(b'',2,0)],memories=[(f,17,19)]*3))
    for ds in ([([],[])],[([0x7F],[])],[([],[0x7E])]):
        rows.append(spec('type_table_'+str(len(rows)),[(b'',1,0)],definitions=ds,tables=[(0x70,0,17,0)]))
        rows.append(spec('type_memory_'+str(len(rows)),[(b'',2,0)],definitions=ds,memories=[(0,17,0)]))
    for ops in ([],[(2,17)],[(3,0x123456789AB)],[(4,0x12345678)],[(5,0x123456789AB)],[(2,17),(3,21)]):
        rows.append(spec('global_'+str(len(rows)),[(b'',3,0)],globals_=[previous.previous.entry(ops=ops)]*3))
    for kind in range(4):
        rows.append(spec('generic_custom_'+str(kind),[(b'',kind,0)],imports=[imported(kind)],before=section(0,b'\x01z')))
        entries=[imported(2),imported(kind)]
        rows.append(spec('memory_then_import_'+str(kind),[(b'',kind,0)],imports=entries,entry_x28=MASK))
    for number in (3,4,5,6):
        row=spec('empty_section_'+str(number),[(b'',0,0)],imports=[imported(0)],before=section(number,b'\0'),empty_globals=number==6)
        row['table_memory']=number in (4,5);rows.append(row)
    first=previous.export(b'',0,0)
    for label,tail in [('missing_name',b''),('name_cut',b'\x80'),('kind_missing',b'\1x'),('kind4',b'\1x\4\0'),('index_cut',b'\1x\0\x80')]:
        rows.append(spec(label,[(b'',0,0)],imports=[imported(0)],payload=b'\2'+first+tail,status=1))
    rng=random.Random(0x31D5C8)
    for i in range(8):
        entries=[imported(k,rng.choice((0,22,23)),k) for k in range(4)]
        exports=[(bytes(rng.randrange(256) for _ in range(rng.randrange(33))),rng.randrange(4),0) for _ in range(5)]
        rows.append(spec('generated_'+str(i),exports,imports=entries,frame_padding=rng.randrange(256),entry_x28=rng.getrandbits(64)))
    return rows


def actual_specs(library):
    blob=previous.code.section_code.actual_inputs(library)[-1]['blob'];cursor=8;entries=[];encoded=None
    def leb():
        nonlocal cursor
        value=shift=0
        while True:
            byte=blob[cursor];cursor+=1;value|=(byte&127)<<shift;shift+=7
            if byte<128:return value
    while cursor<len(blob):
        number=blob[cursor];cursor+=1;size=leb();end=cursor+size
        if number==7:
            encoded=blob[cursor:end];count=leb()
            for _ in range(count):
                length=leb();name=blob[cursor:cursor+length];cursor+=length
                kind=blob[cursor];cursor+=1;index=leb();assert kind==0
                entries.append((name,kind,index))
            assert cursor==end
        cursor=end
    assert len(entries)==121 and all(len(n)<=22 for n,_,_ in entries)
    count=max(i for _,_,i in entries)+1
    case=spec('fresh_ELF_complete_export_payload',entries,definitions=[([],[])],functions=[0]*count,
        bodies=[previous.code.body() for _ in range(count)],actual=True,large_arena=True)
    assert encoded==enc(len(entries))+b''.join(previous.export(*e) for e in entries)
    return [case]


def negatives(args):
    rows=[];base=BASES[0];case=spec('guard',[(b'xy',0,0)]*4,imports=[imported(0)])
    def reject(label,changes=None,fault=None,fixture=None):
        fixture=fixture or case;p=previous.previous.prepare(args,base,fixture);offset=0
        def allocate(size):
            nonlocal offset
            out=layout.HEAP+offset;offset+=(size+15)&~15;return out
        params=dict(image_base=base,input_address=layout.DATA,input_size=len(fixture['blob']),output_address=layout.OUT,
            entry_stack_address=layout.ENTRY,varuint_scratch_address=layout.SCRATCH,allocate=allocate,**options(fixture))
        params.update(changes or {});before={k:bytes(v) for k,v in p.items()};write=alternative._write_span;hits=[]
        def injected(current,address,data):
            if fault(address,data):hits.append(address);raise RefillUnsupported('injected inline export write failure')
            return write(current,address,data)
        try:
            if fault:alternative._write_span=injected
            try:alternative.run_reader_ast_module(p,**params)
            except (RefillUnsupported,ValueError):pass
            else:raise AssertionError('guard accepted: '+label)
        finally:alternative._write_span=write
        assert before=={k:bytes(v) for k,v in p.items()},label
        if fault:assert hits,label
        rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_invalid_path_executed=False))
    for label,changes in [('inline_default',dict(enable_inline_exports=False)),('flag_type',dict(enable_inline_exports=1)),
            ('exports_closed',dict(enable_exports=False)),('register_missing',dict(entry_x28=None)),('register_bool',dict(entry_x28=True)),
            ('register_negative',dict(entry_x28=-1)),('register_overflow',dict(entry_x28=1<<64)),('register_string',dict(entry_x28='0')),
            ('input_frame',dict(input_address=layout.STATE-0x210)),('output_frame',dict(output_address=layout.STATE-0x208)),
            ('scratch_frame',dict(varuint_scratch_address=layout.STATE-0x200)),('allocate_frame',dict(allocate=lambda n:layout.STATE-0x160)),
            ('nodes',dict(max_nodes=1)),('entries',dict(max_entries=1)),('bytes',dict(max_vector_bytes=31))]:reject(label,changes)
    for kind in range(4):reject('index_'+str(kind),fixture=spec('index',[(b'',kind,1)],imports=[imported(kind)]))
    reject('caller_store_failure',fault=lambda a,d:a==layout.STATE-0x160 and len(d)==24)
    reject('first_header_failure',fault=lambda a,d:a==layout.STATE-0x160 and d[:4]==b'\4xy\0')
    reject('output_header_failure',fault=lambda a,d:layout.HEAP<=a<layout.SCRATCH and len(d)==24 and d[:4]==b'\4xy\0')
    reject('publication_failure',fault=lambda a,d:a==layout.OUT+0xA8 and len(d)==24)
    reject('spare_end_failure',fault=lambda a,d:a==layout.OUT+0xB0 and len(d)==8)
    reject('cleanup_failure',fault=lambda a,d:a==layout.CB+0x88 and len(d)==8)
    return rows


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('library','libc','output'):parser.add_argument('--'+name,required=True,type=Path)
    args=parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==layout.heap.oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==layout.heap.LIBC_HASH
    specs=fixtures()+actual_specs(args.library);guards=negatives(args);rows=[]
    moved=[c for c in specs if c['label'] in ('name_0_0','memory_5','mixed_165')]
    for base in BASES:
        for i,case in enumerate(specs,1):
            with arena(case):rows.append(compare(args,base,case))
            if i%16==0:print('B inline exports',hex(base),i,'/',len(specs),'passed',flush=True)
        for delta in (-0xC80,0x100):
            with layout.layout(delta):
                for case in moved:rows.append(compare(args,base,{**case,'label':case['label']+'_SP_'+str(delta)}))
        with previous.previous.definitions.guest_layout(0x7000000000):
            for case in moved:rows.append(compare(args,base,{**case,'label':case['label']+'_high_guest'}))
    evidence=dict(schema='vm9-alternative-ast-module-inline-exports-fresh-v1',evidence_date='2026-10-11',evidence_timezone='Asia/Shanghai',
        sample_sha256=layout.heap.oracle.LIBRARY_SHA256,matching_libc_sha256=layout.heap.LIBC_HASH,
        native_Python_module_inline_export_controls=len(rows),rollback_negative_controls=len(guards),pre_change_behavior_RED_controls=16,
        relocated_entry_stack_controls=12,relocated_full_guest_controls=6,
        complete_actual_ELF_export_payload_controls=sum(r['actual_ELF_export_entries'] for r in rows),actual_ELF_declarations_and_code=False,
        enable_inline_exports_default=False,explicit_entry_x28_required=True,
        complete_export_records_checked=sum(r['complete_export_records_checked'] for r in rows),complete_cloned_nodes_checked=sum(r['complete_cloned_nodes_checked'] for r in rows),
        native_input_snapshot_used=False,private_payloads_published=False,whole_native_stack_TLS_OS_compared=False,
        complete_attached_reader_implemented=False,complete_python_reader_implemented=False,independent_Python_factory_implemented=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False,cases=rows,negative_cases=guards)
    args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    print('B inline exports:',len(rows),'native/Python controls,',len(guards),'rollback checks',flush=True)
if __name__=='__main__':main()
