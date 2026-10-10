"""Fresh attached table/memory definitions through the actual B module.

Synthetic inputs and explicit caller pages; native snapshots are observations.
Descriptors, padding, indexes and owned records are derived independently.
"""
from __future__ import annotations
import argparse,hashlib,json,random
from contextlib import contextmanager
from pathlib import Path
from unicorn import arm64_const as arm
import verify_vm9_alternative_ast_module_other_imports_20261010 as previous
from vm9_allocator import RefillUnsupported,_read_span,_write_span
alternative=previous.alternative
enc,section,types,import_=previous.enc,previous.section,previous.types,previous.import_
BASES=previous.BASES
FUN={**previous.FUN,0x58:0x31C9F4,0x60:0x31CABC,0x68:0x31CCEC,0x70:0x31CDB4}
ARGC={**previous.ARGC,0x58:1,0x60:3,0x68:1,0x70:2}


def table(value=0x70,flags=1,minimum=3,maximum=9):
    return (value,flags,minimum,maximum)


def memory(flags=1,minimum=3,maximum=9):
    return (flags,minimum,maximum)


def payload(kind,entry):
    value,*limits=entry if kind==1 else (None,*entry)
    flags,minimum,maximum=limits
    return (bytes([value]) if kind==1 else b'')+bytes([flags])+enc(minimum)+(enc(maximum) if flags&1 else b'')


def spec(label,tables=None,memories=None,definitions=None,imports=None,before=b'',between=b'',after=b'',status=0,**kw):
    body=(types(definitions) if definitions is not None else b'')
    if imports is not None:body+=section(2,enc(len(imports))+b''.join(import_(*e) for e in imports))
    body+=before
    if tables is not None:body+=section(4,enc(len(tables))+b''.join(payload(1,e) for e in tables))
    body+=between
    if memories is not None:body+=section(5,enc(len(memories))+b''.join(payload(2,e) for e in memories))
    return dict(label=label,blob=b'A'*8+body+after,status=status,tables=tables,memories=memories,definitions=definitions,imports=imports,**kw)


def minimal_specs():
    entries=[(b'',b'x',1,b'\x70\x01\x03\x09'),(b'a',b'',2,b'\x01\x03\x09'),(b'',b'',3,b'\x7f\x01')]
    return [spec('table',[table()]),spec('memory',memories=[memory(0)]),
        spec('both',[table(flags=0),table(0x6F,1,1,9)],[memory(0),memory(5,2**35,2**40)]),
        spec('types_both',[table(flags=0)],[memory()],definitions=[([0x7F,0x7E],[0x7D])]),
        spec('imports_definitions',[table(flags=0,minimum=1),table(0x6F,1,2,3)],[memory(0,1),memory(1,2,3)],definitions=[([0x7F],[0x7E])],imports=entries),
        spec('types_memory',memories=[memory(0)],definitions=[([0x7F],[0x7E])])]


def fixtures():
    rows=minimal_specs()
    for pad in (0,0x39,0xA5,0xFF):
        for count in (0,1,2,3,4,5):
            ts=[table(0x70 if i%2 else 0x6F,i%2,i+1,i+9) for i in range(count)]
            ms=[memory(i%2,i+3,i+12) for i in range(count)]
            rows.append(spec(f'growth_{pad}_{count}',ts,ms,frame_padding=pad))
            rows.append(spec(f'memory_only_{pad}_{count}',memories=ms,frame_padding=pad))
    for value in (0x6B,0x6F,0x70):
        for flags in (0,1,4,5):
            for minimum in (0,127,128,2**32-1):
                rows.append(spec(f'table_limits_{value}_{flags}_{minimum}',[table(value,flags,minimum,minimum)]))
    for flags in (0,1,4,5):
        for minimum in (0,127,128,2**32-1,2**35,2**63,2**64-1):
            rows.append(spec(f'memory_limits_{flags}_{minimum}',memories=[memory(flags,minimum,minimum)]))
    modes=([],[([],[])],[([0x7F],[])],[([],[0x7E])],[([0x7F,0x7E],[0x7D])],[([],[]),([0x7E],[0x7C])])
    for index,defs in enumerate(modes):
        rows.append(spec('type_table_'+str(index),[table()],definitions=defs))
        rows.append(spec('type_memory_'+str(index),memories=[memory()],definitions=defs))
        rows.append(spec('type_both_'+str(index),[table(),table(flags=0)],[memory(),memory(0)],definitions=defs))
    for kind in (0,1,2,3):
        for count in (0,1,2,4):
            for size in (0,23):
                raw=(b'\0',b'\x70\x01\x03\x09',b'\x01\x03\x09',b'\x7f\x01')[kind]
                entries=[(b'm'*size,b'f'*(size+1),kind,raw) for _ in range(count)]
                rows.append(spec(f'import_{kind}_{count}_{size}',[table(),table(flags=0)],[memory(),memory(0)],definitions=[([0x7F],[0x7E])],imports=entries))
    for n in (0,1,2):
        rows.append(spec('defined_functions_'+str(n),[table()],[memory()],definitions=[([0x7F],[0x7E])],before=section(3,enc(n)+bytes(n)),function_count=n,status=int(n!=0)))
        rows.append(spec('defined_functions_memory_'+str(n),memories=[memory()],definitions=[([0x7F],[0x7E])],before=section(3,enc(n)+bytes(n)),function_count=n,status=int(n!=0)))
    for warm in (False,True):
        rows.append(spec('surrounding_'+str(warm),[table()],[memory()],definitions=[([0x7F],[0x7E])],before=section(0,b'\x01x'),between=section(0,b'\x02yz'),between_custom=True,after=section(7,b'\0')+section(8,b'\x03')+section(12,b'\x02'),warm_rank=warm))
    rows.append(spec('custom_only',[table()],[memory()],before=section(0,b'\x01x'),caller_saved=True))
    rows.append(spec('table_custom_memory',[table()],[memory()],between=section(0,b'\x01x'),between_custom=True))
    for kind in (1,2):
        good=payload(kind,table() if kind==1 else memory())
        number=4 if kind==1 else 5
        for cut in range(len(good)):
            blob=b'A'*8+section(number,b'\x02'+good+good[:cut])
            rows.append(dict(label=f'partial_{kind}_{cut}',blob=blob,status=1,tables=[table()] if kind==1 else None,memories=[memory()] if kind==2 else None,definitions=None,imports=None))
        for label,bad in [('bad_flags',b'\x02\x03'),('large_flags',b'\x08\x03'),('truncated_min',b'\x00\x80')]:
            bad=(b'\x70' if kind==1 else b'')+bad
            rows.append(dict(label=f'{label}_{kind}',blob=b'A'*8+section(number,b'\x02'+good+bad),status=1,tables=[table()] if kind==1 else None,memories=[memory()] if kind==2 else None,definitions=None,imports=None))
    for label,tail in [('duplicate_table',section(4,b'\0')),('rank_backwards',section(3,b'\0')),('bad_envelope',b'\x08\x80'),('unknown',b'\x0d\x00')]:
        rows.append(spec(label,[table()],[memory()],after=tail,status=1))
    rng=random.Random(0x3231E4)
    for i in range(16):
        ts=[table(rng.choice((0x6B,0x6F,0x70)),rng.choice((0,1,4,5)),rng.randrange(512),rng.randrange(512)) for _ in range(rng.randrange(5))]
        ms=[memory(rng.choice((0,1,4,5)),rng.getrandbits(48),rng.getrandbits(48)) for _ in range(rng.randrange(5))]
        rows.append(spec('generated_'+str(i),ts,ms,frame_padding=rng.randrange(256)))
    return rows


def native(args,base,case):
    heap=previous.heap
    saved=(heap.FUN,heap.ARGC,heap.prepare,heap.oracle.native)
    entries=[]
    def instrumented(*argv,**kw):
        observe=kw['instruction_observer']
        def observed(cpu,address):
            offset=address-base
            if offset in (0x31C9F4,0x31CABC,0x31CCEC,0x31CDB4):
                sp=cpu.reg_read(arm.UC_ARM64_REG_SP)
                assert sp==previous.STATE-(0xC0 if offset in (0x31C9F4,0x31CABC) else 0xE0)
                if offset in (0x31CABC,0x31CDB4):
                    ptr=cpu.reg_read(arm.UC_ARM64_REG_X3 if offset==0x31CABC else arm.UC_ARM64_REG_X2)
                    assert ptr==sp
                    entries.append(dict(slot=0x60 if offset==0x31CABC else 0x70,
                        descriptor=bytes(cpu.mem_read(ptr,24)),padding=bytes(cpu.mem_read(sp-0x7C,4))))
            observe(cpu,address)
        kw['instruction_observer']=observed
        return saved[3](*argv,**kw)
    try:
        heap.FUN,heap.ARGC,heap.prepare,heap.oracle.native=FUN,ARGC,previous.prepare,instrumented
        status,p,e,c,snap=heap.native(args,base,case)
    finally:heap.FUN,heap.ARGC,heap.prepare,heap.oracle.native=saved
    snap['definition_entries']=entries
    return status,p,e,c,snap


def options(case):
    entries=case.get('imports')
    function=any(e[2]==0 for e in entries or ())
    return dict(enable_table_memory_definitions=True,enable_function_imports=function,
        enable_inline_function_imports=function,enable_table_memory_global_imports=entries is not None,
        enable_inline_table_memory_global_imports=entries is not None)


@contextmanager
def guest_layout(address):
    """Move fresh guest input/output/heap/stack together, preserving ELF bases."""
    objects=(previous,previous.heap,previous.heap.previous)
    names=('ENTRY','CB','STATE','OUT','DATA','HEAP','SCRATCH')
    saved=[{n:getattr(obj,n) for n in names} for obj in objects]
    oracle=previous.heap.oracle;old_guest,old_stop=oracle.GUEST,oracle.STOP
    delta=address-old_guest
    try:
        for obj,values in zip(objects,saved):
            for name,value in values.items():setattr(obj,name,value+delta)
        oracle.GUEST,oracle.STOP=address,old_stop+delta
        yield
    finally:
        oracle.GUEST,oracle.STOP=old_guest,old_stop
        for obj,values in zip(objects,saved):
            for name,value in values.items():setattr(obj,name,value)


def compare(args,base,case):
    status,np,ne,nc,snap=native(args,base,case)
    p,result,state_bytes=previous.model(args,base,case,**options(case))
    assert result.status==status==case['status'],(case['label'],'status')
    assert previous.heap.previous.normalized(result.effects)==ne,(case['label'],'ordered effects and owner bytes')
    assert state_bytes==snap['parser'] and _read_span(p,previous.CB,0x120)==snap['callback_final'],(case['label'],'cleanup')
    a=_read_span(p,previous.heap.oracle.GUEST,0xA000);b=_read_span(np,previous.heap.oracle.GUEST,0xA000)
    assert a==b,(case['label'],'guest bytes',[(hex(i),x,y) for i,(x,y) in enumerate(zip(a,b)) if x!=y][:12])
    for (address,width),data in snap['globals'].items():assert _read_span(p,address,width)==data
    assert [(e.slot_offset,e.arguments,e.cursor,e.section_end) for e in result.sections.callback_events]==nc
    u=lambda a,n=8:int.from_bytes(_read_span(p,a,n),'little')
    pad=bytes([case.get('frame_padding',0xA5)])
    caller=case.get('definitions') is not None or case.get('imports') is not None or case.get('caller_saved')
    table_tail=len(case['blob']).to_bytes(8,'little')[3:] if caller else pad*5
    if case.get('function_count'):table_tail=(case['function_count']-1).to_bytes(8,'little')[3:]
    memory_tail=(len(case['tables']).to_bytes(8,'little')[3:] if case.get('tables') is not None else
        (previous.STATE-0x50).to_bytes(8,'little')[3:] if caller else pad*5)
    if case.get('function_count') and case.get('tables') is None:memory_tail=bytes(5)
    if case.get('between_custom'):memory_tail=(previous.STATE-0x50).to_bytes(8,'little')[3:]
    table_padding=bytes(4) if case.get('definitions') else pad*4
    if case.get('imports'):table_padding=bytes(4) if case['imports'][-1][2]==2 else (previous.STATE-0xF8).to_bytes(8,'little')[4:]
    if case.get('function_count'):table_padding=bytes(4)
    counts=[sum(e[2]==k for e in case.get('imports') or ()) for k in range(4)]
    checked=0
    for slot,kind,header,cache,stride,items,tail in ((0x60,1,0x48,0x98,48,case.get('tables') or [],table_tail),
            (0x70,2,0x60,0xB0,40,case.get('memories') or [],memory_tail)):
        events=[e for e in result.sections.callback_events if e.slot_offset==slot]
        actual=[e for e in snap['definition_entries'] if e['slot']==slot]
        assert len(events)==len(actual)==len(items),(case['label'],'definition count')
        assert u(previous.OUT+header+8)-u(previous.OUT+header)==len(items)*stride
        for index,(entry,event,native_entry) in enumerate(zip(items,events,actual)):
            value,*limits=entry if kind==1 else (None,*entry)
            flags,minimum,maximum=limits
            raw=minimum.to_bytes(8,'little')+(maximum if flags&1 else 0).to_bytes(8,'little')+bytes((flags&1,0,(flags>>2)&1 if kind==2 else 0))
            assert native_entry['descriptor']==raw+tail,(case['label'],'independent descriptor tail',native_entry['descriptor'].hex(),(raw+tail).hex())
            assert event.arguments[0]==index+counts[kind]
            assert event.arguments[-1]==previous.STATE-(0xC0 if kind==1 else 0xE0)
            normalized=bytearray(raw)
            if not flags&1:normalized[8:16]=(0xFFFFFFFF if kind==1 else 0x1000000000000 if flags&4 else 0x10000).to_bytes(8,'little')
            record=u(previous.OUT+header)+index*stride
            prefix=(base+(0x372518 if kind==1 else 0x372540)).to_bytes(8,'little')+kind.to_bytes(4,'little')
            if kind==1:
                assert native_entry['padding']==table_padding,(case['label'],'independent table padding')
                expected=prefix+((value-128)&((1<<64)-1)).to_bytes(8,'little')+table_padding+normalized+b'\xA5'*5
            else:expected=prefix+b'\xA5'*4+normalized+tail
            assert _read_span(p,record,stride)==expected,(case['label'],'independent complete owned record')
            checked+=1
        assert u(previous.CB+cache)==u(previous.CB+cache+8)
    assert [u(previous.STATE+o,4) for o in (0x90,0x94,0x98,0x9C)]==counts
    assert u(previous.CB+8)==previous.STATE+8 and not any(_read_span(p,previous.CB+0x108,24))
    return dict(label=case['label'],image_base_hex=hex(base),entry_stack_address_hex=hex(previous.ENTRY),status=status,
        callback_count=len(nc),**{n+'_count':sum(e[0]==n for e in ne) for n in ('allocate','destroy','delete','free')},
        actual_module_parser_AST_and_cleanup_executed=True,natural_return_and_SP_verified=True,
        complete_guest_0xa000_without_masking_match=True,ordered_effects_and_owner_bytes_match=True,
        parser_exit_callback_cleanup_image_globals_and_arguments_match=True,
        independent_descriptor_tail_padding_indexes_and_complete_records_checked=checked,
        synthetic_fixture=True,native_input_snapshot_used=False,whole_native_stack_TLS_OS_compared=False)


def negatives(args):
    rows=[];base=BASES[0];case=spec('guards',[table(),table()],[memory(),memory()],definitions=[([0x7F],[0x7E])])
    def reject(label,changes=None,fixture=None,setup=None,fault=None):
        fixture=fixture or case;p=previous.prepare(args,base,fixture);offset=0
        def allocate(size):
            nonlocal offset
            address=previous.HEAP+offset;offset+=(size+15)&~15;return address
        params=dict(image_base=base,input_address=previous.DATA,input_size=len(fixture['blob']),output_address=previous.OUT,
            entry_stack_address=previous.ENTRY,varuint_scratch_address=previous.SCRATCH,allocate=allocate,**options(fixture))
        params.update(changes or {})
        if setup:setup(p)
        before={k:bytes(v) for k,v in p.items()};write=alternative._write_span;hits=[]
        def injected(p,address,data):
            if fault(address,data):hits.append(address);raise RefillUnsupported('injected definition write failure')
            return write(p,address,data)
        if fault:alternative._write_span=injected
        try:
            try:alternative.run_reader_ast_module(p,**params)
            except (RefillUnsupported,ValueError):pass
            else:raise AssertionError('definition guard accepted: '+label)
        finally:alternative._write_span=write
        assert before=={k:bytes(v) for k,v in p.items()},label
        if fault:assert hits,label
        rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_invalid_path_executed=False))
    for label,changes in [('default_closed',dict(enable_table_memory_definitions=False)),('flag_type',dict(enable_table_memory_definitions=1)),
            ('entry_alignment',dict(entry_stack_address=previous.ENTRY+1)),('input_frame',dict(input_address=previous.STATE-0x210)),
            ('output_frame',dict(output_address=previous.STATE-0x208)),('scratch_frame',dict(varuint_scratch_address=previous.STATE-0x200)),
            ('reserved_frame',dict(reserved_regions=((previous.STATE-0x210,previous.STATE-0x208),))),
            ('allocate_frame',dict(allocate=lambda size:previous.STATE-0x210)),('allocate_input',dict(allocate=lambda size:previous.DATA)),
            ('node_budget',dict(max_nodes=1)),('entry_budget',dict(max_entries=1)),('byte_budget',dict(max_vector_bytes=47))]:reject(label,changes)
    for slot in (0x58,0x60,0x68,0x70):reject('binding_'+hex(slot),setup=lambda p,slot=slot:_write_span(p,base+0x372370+slot,(base+0x31B870).to_bytes(8,'little')))
    for got in (0x375098,0x3750A0):reject('node_GOT_'+hex(got),setup=lambda p,got=got:_write_span(p,base+got,(base+0x3724E0).to_bytes(8,'little')))
    reject('nonempty_output',setup=lambda p:_write_span(p,previous.OUT,b'\x01'))
    for slot in (0x78,0xA8):
        tail=section(6,b'\x01\x7f\0\x0b') if slot==0x78 else section(10,b'\x01\x01\0')
        reject('unverified_'+hex(slot),fixture=spec('unverified',[table()],[memory()],after=tail))
    for label,offset,width in [('saved_FP',-0xD0,8),('saved_limit',-0xB0,8),('type_clone_clear',-0x140,8),
            ('table_descriptor',-0xC0,19),('memory_descriptor',-0xE0,19),('table_publish',None,24),('table_cache_cleanup',None,8)]:
        address=previous.STATE+offset if offset is not None else previous.OUT+0x48 if label=='table_publish' else previous.CB+0xA0
        reject('write_failure_'+label,fault=lambda a,d,address=address,width=width:a==address and len(d)==width)
    for call in (2,4,7):
        sizes=[]
        def alias(size,call=call,sizes=sizes):
            if len(sizes)+1==call:return previous.HEAP
            address=previous.HEAP+sum((n+15)&~15 for n in sizes);sizes.append(size);return address
        reject('allocation_alias_'+str(call),dict(allocate=alias))
    with previous.layout(-0xC80):reject('missing_frame_page',setup=lambda p:p.pop((previous.STATE-0x210)>>12))
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
            if i%16==0:print('B attached definitions',hex(base),i,'/',len(specs),'passed',flush=True)
        for delta in (-0xC80,0x100):
            with previous.layout(delta):
                for case in (specs[0],specs[4],specs[5]):rows.append(compare(args,base,{**case,'label':case['label']+'_SP_'+str(delta)}))
        with guest_layout(0x7000000000):
            high_cases=[specs[0],specs[4],specs[5]]+[s for s in specs if s['label'] in ('defined_functions_memory_2','surrounding_False','custom_only')]
            for case in high_cases:rows.append(compare(args,base,{**case,'label':case['label']+'_high_guest'}))
    evidence=dict(schema='vm9-alternative-ast-module-definitions-fresh-v1',evidence_date='2026-10-11',evidence_timezone='Asia/Shanghai',
        sample_sha256=previous.heap.oracle.LIBRARY_SHA256,matching_libc_sha256=previous.heap.LIBC_HASH,
        native_Python_module_definition_controls=len(rows),rollback_negative_controls=len(guards),relocated_entry_stack_controls=12,
        relocated_full_guest_controls=12,
        pre_change_behavior_RED_controls=10,generated_fixture_seed=0x3231E4,enable_table_memory_definitions_default=False,
        definitions_require_import_opt_ins=False,attached_definition_slots_hex=['0x58','0x60','0x68','0x70'],
        independent_complete_definition_records_checked=sum(r['independent_descriptor_tail_padding_indexes_and_complete_records_checked'] for r in rows),
        caller_stack_store_sources_hex=['0x322704','0x32270c','0x32298c','0x322994','0x322cfc','0x322d04','0x31b7b8','0x31b87c','0x31bb54','0x31be48','0x31c150','0x31c7c0','0x31c7c8','0x31f798','0x31c9fc'],
        native_input_snapshot_used=False,private_payloads_published=False,whole_native_stack_TLS_OS_compared=False,
        complete_attached_reader_implemented=False,complete_python_reader_implemented=False,independent_Python_factory_implemented=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False,cases=rows,negative_cases=guards)
    args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    print('B attached definitions:',len(rows),'native/Python controls,',len(guards),'rollback checks',flush=True)
if __name__=='__main__':main()
