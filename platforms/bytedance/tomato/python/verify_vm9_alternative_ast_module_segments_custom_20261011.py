"""Fresh attached segment/custom AST and complete actual ELF reader controls.

Native snapshots are assertions only. Private ELF names and payloads stay local.
Allocation is an explicit plan; factory/bootstrap and signer are separate work.
"""
from __future__ import annotations
import argparse,hashlib,json
from contextlib import contextmanager
from pathlib import Path
from time import perf_counter
from unicorn import arm64_const as arm
import verify_vm9_alternative_ast_module_inline_exports_20261011 as previous
import verify_vm9_alternative_segments_20261008 as segments
import verify_vm9_alternative_custom_20261008 as custom
from verify_vm9_alternative_blob_xor_20261008 import constructor_codec_byte
from vm9_allocator import RefillUnsupported,_read_span,_write_span

layout=previous.layout;heap=layout.heap;alternative=previous.alternative
BASES=previous.BASES
FUN={**previous.previous.previous.FUN,**previous.previous.FUN,
    0xF0:0x31DB94,0x100:0x31DBCC,0x108:0x31DBF0,0x110:0x31DE48,
    0x118:0x31DE98,0x120:0x31DEE0,0x128:0x31DEF4,0x130:0x31DF1C,
    0x138:0x31E18C,0x140:0x31E1D4,0x148:0x31E4A4,0x150:0x31E4F4,0x158:0x31E53C}
ARGC={**previous.previous.previous.ARGC,**previous.previous.ARGC,
    0xF0:0,0x100:1,0x108:3,0x110:1,0x118:1,0x120:2,0x128:2,
    0x130:1,0x138:1,0x140:3,0x148:1,0x150:1,0x158:3}


def spec(label,blob,**kw):
    return previous.spec(label,after=blob,large_arena=True,**kw)


def options(case):
    result=dict(enable_element_section=case.get('elements',False),
        enable_data_section=case.get('data',False),
        enable_special_custom_sections=case.get('custom',False),
        expression_scratch_address=layout.SCRATCH+8,custom_scratch_address=layout.SCRATCH+16)
    if case.get('full'):
        result.update(enable_function_imports=True,enable_inline_function_imports=True,
            enable_table_memory_global_imports=True,enable_inline_table_memory_global_imports=True,
            enable_table_memory_definitions=True,enable_global_definitions=True,enable_code_definitions=True)
    return result|case.get('model_settings',{})


@contextmanager
def arena(case):
    with previous.arena(case):
        saved=layout.DATA,heap.DATA,heap.previous.DATA,heap.oracle.GUEST_SIZE
        try:
            if case.get('full'):
                layout.DATA=heap.DATA=heap.previous.DATA=heap.oracle.GUEST+0x120000
                heap.oracle.GUEST_SIZE=0x160000
            yield
        finally:layout.DATA,heap.DATA,heap.previous.DATA,heap.oracle.GUEST_SIZE=saved


def native(args,base,case):
    saved=heap.FUN,heap.ARGC,heap.prepare,heap.oracle.native
    headers=[];sp=[];extra={};missing=[];effect_index=0
    def instrumented(*a,**kw):
        observe=kw['instruction_observer'];malloc=kw['malloc_handler'];free=kw['host_imports'][0x347FA0]
        def observed(cpu,address):
            nonlocal effect_index
            off=address-base
            if off==0x31B360:cpu.reg_write(arm.UC_ARM64_REG_X28,case.get('entry_x28',0))
            if off==0x31D500:headers.append(bytes(cpu.mem_read(layout.STATE-0x160,24)))
            if off in FUN.values():sp.append((next(s for s in FUN if FUN[s]==off),cpu.reg_read(arm.UC_ARM64_REG_SP)))
            # The export harness predates the segment record destructors.
            # Merge these actual native boundaries into its ordered ledger.
            if off in (0x2CC1EC,0x2CC2B8,0x2CC3B4):
                node=cpu.reg_read(arm.UC_ARM64_REG_X0 if off==0x2CC1EC else arm.UC_ARM64_REG_X1)
                if layout.HEAP<=node<layout.HEAP+0x100000:
                    missing.append((effect_index,('destroy',node,184 if off==0x2CC2B8 else 176,
                        layout.OUT,bytes(cpu.mem_read(layout.OUT,0x120)))))
            if off in (0x321260,0x321308,0x321368,0x2CC470):
                node=cpu.reg_read(arm.UC_ARM64_REG_X1 if off==0x2CC470 else arm.UC_ARM64_REG_X0)
                if heap.oracle.GUEST<=node<heap.oracle.GUEST+0xA000 or layout.HEAP<=node<heap.oracle.GUEST+heap.oracle.GUEST_SIZE:effect_index+=1
            if off in (0x3212B0,0x3212FC,0x321300,0x321304,0x32132C):effect_index+=1
            observe(cpu,address)
        def bounded(cpu,size):
            nonlocal effect_index
            pointer=malloc(cpu,size);assert pointer+size<=layout.HEAP+0x100000
            effect_index+=1
            return pointer
        def freed(cpu):
            nonlocal effect_index
            result=free(cpu);effect_index+=1;return result
        kw['instruction_observer']=observed;kw['malloc_handler']=bounded
        kw['host_imports'][0x347FA0]=freed
        if case.get('full'):kw['instruction_limit']=12000000
        kw['observed_memory'][layout.DATA,len(case['blob'])]=None
        result=saved[3](*a,**kw)
        extra['input']=kw['observed_memory'][layout.DATA,len(case['blob'])]
        return result
    try:
        heap.FUN,heap.ARGC,heap.prepare,heap.oracle.native=FUN,ARGC,previous.previous.previous.prepare,instrumented
        status,p,e,c,snap=previous.large_native(args,base,case)
    finally:heap.FUN,heap.ARGC,heap.prepare,heap.oracle.native=saved
    assert effect_index==len(e)
    merged=[];position=0
    for index,event in enumerate(e):
        while position<len(missing) and missing[position][0]==index:
            merged.append(missing[position][1]);position+=1
        merged.append(event)
    merged.extend(row for index,row in missing[position:]);e=merged
    snap.update(export_headers=headers,input=extra['input'],callback_sp=sp)
    # The observer's added input span is not an image global.
    snap['globals'].pop((layout.DATA,len(case['blob'])),None)
    return status,p,e,c,snap


def compare(args,base,case):
    started=perf_counter();status,np,ne,nc,snap=native(args,base,case)
    native_seconds=perf_counter()-started;callback=alternative.run_reader_ast_callback;headers=0
    check_headers=(previous.options(case)|options(case))['enable_inline_exports']
    def observed(current,**kw):
        nonlocal headers
        if kw['slot_offset']==0x98 and check_headers:
            assert _read_span(current,layout.STATE-0x160,24)==snap['export_headers'][headers],(case['label'],'export entry header')
            headers+=1
        return callback(current,**kw)
    try:
        alternative.run_reader_ast_callback=observed;started=perf_counter()
        p,result,state=previous.model(args,base,case,**options(case))
        python_seconds=perf_counter()-started
    finally:alternative.run_reader_ast_callback=callback
    assert result.status==status,(case['label'],'status',result.status,status)
    if case.get('expected_status') is not None:assert status==case['expected_status'],case['label']
    assert heap.previous.normalized(result.effects)==ne,(case['label'],'ordered effects')
    assert state==snap['parser'] and _read_span(p,layout.CB,0x120)==snap['callback_final'],(case['label'],'cleanup')
    for start,length in ((heap.oracle.GUEST,0xA000),(layout.HEAP,0x100000)):
        a=_read_span(p,start,length);b=_read_span(np,start,length)
        assert a==b,(case['label'],'guest',[(hex(start+i),x,y) for i,(x,y) in enumerate(zip(a,b)) if x!=y][:16])
    assert _read_span(p,layout.DATA,len(case['blob']))==snap['input']==case['blob']
    for (address,width),data in snap['globals'].items():assert _read_span(p,address,width)==data,(case['label'],'image globals')
    events=result.sections.callback_events
    assert [(e.slot_offset,e.arguments,e.cursor,e.section_end) for e in events]==nc,(case['label'],'callbacks')
    assert headers==(len(snap['export_headers']) if check_headers else 0)
    raw=sum(e.slot_offset==0x168 for e in events)
    bodies=sum(e.slot_offset==0xB0 for e in events)
    if case.get('full'):
        assert status==0 and raw==54533 and bodies==121 and len(events)==55369
        assert [e.arguments[2] for e in events if e.slot_offset==0x158]==[3632,352,0]
        assert [int.from_bytes(state[o:o+4],'little') for o in (0x90,0x94,0x98,0x9C)]==[18,0,0,22]
        print('FULL ELF',hex(base),'native',round(native_seconds,2),'Python',round(python_seconds,2),'seconds',flush=True)
    for slot,sp in snap['callback_sp']:
        if 0x100<=slot<=0x138:assert sp==layout.STATE-0xC0
        elif 0x140<=slot<=0x158:assert sp==layout.STATE-0xA0
    return dict(label=case['label'],image_base_hex=hex(base),entry_stack_address_hex=hex(layout.ENTRY),
        status=status,callback_count=len(nc),raw_word_count=raw,code_body_count=bodies,
        **{n+'_count':sum(e[0]==n for e in ne) for n in ('allocate','destroy','delete','free')},
        actual_module_parser_AST_and_cleanup_executed=True,natural_return_and_SP_verified=True,
        complete_guest_and_extra_1MiB_heap_without_masking_match=True,
        ordered_effects_parser_exit_callback_cleanup_image_globals_input_and_arguments_match=True,
        inline_export_entry_headers_checked=headers,actual_ELF_complete_module=case.get('full',False),
        actual_ELF_custom_payload=case.get('actual_custom',False),native_input_snapshot_used=False)


def fixtures():
    rows=[]
    for number in (9,11):
        make=segments.element if number==9 else segments.data
        for flags in range(8):
            for index in (0,0xFFFFFFFF):
                rows.append(spec(f'segment_{number}_{flags}_{index}',previous.section(number,b'\1'+make(flags,index)),
                    elements=number==9,data=number==11,expected_status=0))
        for label,expression in [('end',b'\x0b'),('zero',b'\0\x0b'),('i32',b'\x41\x7f\x0b'),
                ('i64',b'\x42\x7f\x0b'),('f32',b'\x43'+b'\xff'*4+b'\x0b'),
                ('f64',b'\x44'+b'\xff'*8+b'\x0b'),
                ('mixed',b'\0\x41\x7f\x42\x7f\x43'+b'\xff'*4+b'\x44'+b'\xff'*8+b'\x0b')]:
            rows.append(spec(f'expression_{number}_{label}',previous.section(number,b'\2'+make(expression=expression)*2),
                elements=number==9,data=number==11,expected_status=0))
        for label,payload in [('empty',b'\0'),('missing',b''),('flags',b'\1\x80'),('invalid_flags',b'\1\x08'),
                ('expression_cut',b'\1\0\x41\x80'),('expression_invalid',b'\1\0\xff'),
                ('partial',b'\2'+make()+b'\x80')]:
            rows.append(spec(f'parse_{number}_{label}',previous.section(number,payload),elements=number==9,data=number==11))
    for size in (0,1,127,128,257):
        rows.append(spec('payload_'+str(size),previous.section(11,b'\1'+segments.data(1,payload=bytes(i%256 for i in range(size)))),data=True,expected_status=0))
    rows.append(spec('elements_then_data',previous.section(9,b'\1'+segments.element())+previous.section(11,b'\1'+segments.data()),elements=True,data=True,expected_status=0))
    for expected in (0,1,2):
        rows.append(spec('data_count_'+str(expected),previous.section(12,bytes([expected]))+previous.section(11,b'\1'+segments.data(1)),data=True))
    for name,body in custom.MINIMAL:
        rows.append(spec('minimal_'+name.decode(),custom.custom(name,body),custom=True,expected_status=0))
    rich=[c for c in custom.fixtures() if c['label'] in ('dylink.0_all_tags','linking_all_tags','reloc_addend_-1')
        or c['label'].startswith(('linking_tag_','linking_symbol_kind_')) and
        (c['label'].endswith(('_flags_0','_flags_16','_flags_80')) or c['label'] in ('linking_tag_5','linking_tag_6','linking_tag_7','linking_tag_8'))]
    prefixes=[('minimal_'+n.decode(),custom.custom(n,b)) for n,b in custom.MINIMAL]+[(c['label'],c['blob'][8:]) for c in rich]
    for tag in (5,6,7,8):prefixes.append(('zero_count_'+str(tag),custom.custom(b'linking',b'\2'+custom.subsection(tag,b'\0'))))
    for label,prefix in prefixes:
        rows.append(previous.spec('prefix_'+label,[(b'',0,0),(b'x',0,0)],imports=[previous.imported(0)],before=prefix,large_arena=True,custom=True,expected_status=0))
    for name,body in (*custom.MINIMAL,(b'linking',b'\2'+custom.subsection(6,b'\1\7\11'))):
        for kind in range(4):
            for early in (False,True):
                prefix=custom.custom(name,body)
                case=previous.spec(f'{name.decode()}_{len(body)}_import_{kind}_{early}',[(b'',kind,0)],imports=[previous.imported(kind)],
                    before=b'' if early else prefix,large_arena=True,custom=True,expected_status=0,entry_x28=0x123456789ABCDEF0)
                if early:case['blob']=case['blob'][:8]+prefix+case['blob'][8:]
                rows.append(case)
    for c in custom.fixtures():
        if c['label'] in ('linking_tag_truncated','linking_size_truncated','linking_tag_7_size_too_short','linking_version_1','reloc_missing_addend'):
            rows.append(spec('custom_partial_'+c['label'],previous.section(11,b'\1'+segments.data())+c['blob'][8:],data=True,custom=True,expected_status=1))
    for name,body in custom.MINIMAL:
        for kind in (1,2,3):
            settings=dict(tables=[(0x70,1,3,9)]) if kind==1 else dict(memories=[(1,3,9)]) if kind==2 else dict(globals_=[previous.previous.previous.entry()])
            case=previous.spec(f'{name.decode()}_defined_{kind}',[(b'',kind,0)],large_arena=True,custom=True,
                entry_x28=0x123456789ABCDEF0,expected_status=0,**settings)
            case['blob']=case['blob'][:8]+custom.custom(name,body)+case['blob'][8:];rows.append(case)
    case=previous.spec('linking_table_without_inline_exports',[(b'x'*23,1,0)],tables=[(0x70,1,3,9)],large_arena=True,
        custom=True,entry_x28=0xABCDEF0123456789,model_settings=dict(enable_inline_exports=False),expected_status=0)
    case['blob']=case['blob'][:8]+custom.custom(b'linking',b'\2')+case['blob'][8:];rows.append(case)
    code=previous.previous.code
    rows.append(previous.spec('raw_runs',definitions=[([],[])],functions=[0,0],
        bodies=[code.body(words=list(range(65))),code.body(words=[0xFFFFFFFF]*33)],large_arena=True,expected_status=0))
    return rows


def actual_specs(library):
    rows=[]
    for index,c in enumerate(custom.actual_inputs(library)[:3]):
        for early in (False,True):
            prefix=c['blob'][8:]
            case=previous.spec(f'actual_custom_{index}_{early}',[(b'',0,0)],imports=[previous.imported(0)],
                before=b'' if early else prefix,large_arena=True,custom=True,expected_status=0,actual_custom=True)
            if early:case['blob']=case['blob'][:8]+prefix+case['blob'][8:]
            rows.append(case)
    image=heap.oracle.image_pages(library,BASES[0]);key=constructor_codec_byte(library)
    blob=bytes(x^key for x in _read_span(image,BASES[0]+0x387D20,0x37FD0))
    assert blob[8:]==custom.actual_inputs(library)[-1]['blob'][8:]
    row=spec('complete_actual_ELF',b'',full=True,elements=True,data=True,custom=True,expected_status=0)
    row['blob']=blob;rows.append(row)
    return rows


def negatives(args):
    rows=[];base=BASES[0]
    default=spec('guard',previous.section(9,b'\1'+segments.element(expression=b'\0\x0b'))+
        previous.section(11,b'\1'+segments.data())+custom.custom(b'linking',b'\2'),elements=True,data=True,custom=True)
    def reject(label,changes=None,case=None,fault=None,prepare_fault=None):
        case=case or default
        with arena(case):
            p=previous.previous.previous.prepare(args,base,case);offset=0
            def allocate(size):
                nonlocal offset
                out=layout.HEAP+offset;offset+=(size+15)&~15;return out
            params=dict(image_base=base,input_address=layout.DATA,input_size=len(case['blob']),output_address=layout.OUT,
                entry_stack_address=layout.ENTRY,varuint_scratch_address=layout.SCRATCH,allocate=allocate,
                **(previous.options(case)|options(case)))
            params.update(changes or {})
            if prepare_fault:prepare_fault(p)
            before={k:bytes(v) for k,v in p.items()};write=alternative._write_span;hits=[]
            def injected(current,address,data):
                if fault(address,data):hits.append(address);raise RefillUnsupported('injected attached segment/custom write failure')
                return write(current,address,data)
            try:
                if fault:alternative._write_span=injected
                try:alternative.run_reader_ast_module(p,**params)
                except (RefillUnsupported,ValueError):pass
                else:raise AssertionError('guard accepted: '+label)
            finally:alternative._write_span=write
            assert before=={k:bytes(v) for k,v in p.items()},label
            if fault:assert hits,label
        rows.append(dict(label=label,rejected=True,all_pages_unchanged=True))
    for name in ('enable_element_section','enable_data_section','enable_special_custom_sections'):
        reject(name+'_closed',{name:False});reject(name+'_type',{name:1})
    for name in ('expression_scratch_address','custom_scratch_address'):
        for label,value in [('missing',None),('unaligned',layout.SCRATCH+1),('input',layout.DATA),('frame',layout.STATE-0x160),('output',layout.OUT),('unmapped',0x12345000)]:reject(name+'_'+label,{name:value})
    reject('scratch_alias',dict(custom_scratch_address=layout.SCRATCH+8))
    for name in ('max_expression_ops','max_custom_records'):
        reject(name+'_zero',{name:0});reject(name+'_type',{name:'1'})
    reject('expression_budget',dict(max_expression_ops=1))
    rich=spec('custom_budget',custom.custom(b'linking',b'\2'+custom.subsection(6,b'\1\0\0')),custom=True)
    reject('custom_budget',dict(max_custom_records=1),case=rich)
    reject('nonempty_element',case=spec('abort',previous.section(9,b'\1'+segments.element(1,count=1,entries=b'\0')),elements=True))
    reject('allocation_scratch',dict(allocate=lambda n:layout.SCRATCH+8))
    reject('wrong_segment_slot',prepare_fault=lambda p:_write_span(p,base+0x372370+0x108,bytes(8)))
    reject('custom_version_write',fault=lambda a,d:a==layout.STATE-0x158 and len(d)==4)
    reject('custom_FP_write',fault=lambda a,d:a==layout.STATE-0x150 and len(d)==8)
    reject('element_publication',fault=lambda a,d:a==layout.OUT+0xD8 and len(d)==24)
    code=previous.previous.code
    raw=previous.spec('raw_guard',definitions=[([],[])],functions=[0],bodies=[code.body(words=[0x1234,0x5678,0x9ABC])],large_arena=True)
    reject('raw_second_word_failure',case=raw,fault=lambda a,d:d==b'\x78\x56\0\0')
    reject('raw_bound',dict(max_code_words=2),case=raw)
    table=next(c for c in fixtures() if c['label']=='linking_table_without_inline_exports')
    for label,value in [('missing',None),('bool',True),('overflow',1<<64)]:
        reject('custom_table_x28_'+label,dict(entry_x28=value),case=table)
    return rows


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('library','libc','output'):parser.add_argument('--'+name,required=True,type=Path)
    args=parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==heap.oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==heap.LIBC_HASH
    cases=fixtures()+actual_specs(args.library);guards=negatives(args);rows=[]
    moved=[c for c in cases if c['label'] in ('expression_9_mixed','elements_then_data','prefix_linking_all_tags')]
    for base in BASES:
        for i,case in enumerate(cases,1):
            with arena(case):rows.append(compare(args,base,case))
            if i%16==0:print('B attached segments/custom',hex(base),i,'/',len(cases),'passed',flush=True)
        for delta in (-0xC80,0x100):
            with layout.layout(delta):
                for case in moved:
                    with arena(case):rows.append(compare(args,base,{**case,'label':case['label']+'_SP_'+str(delta)}))
        with previous.previous.previous.definitions.guest_layout(0x7000000000):
            for case in moved:
                with arena(case):rows.append(compare(args,base,{**case,'label':case['label']+'_high_guest'}))
    evidence=dict(schema='vm9-alternative-ast-module-segments-custom-fresh-v1',evidence_date='2026-10-11',
        evidence_timezone='Asia/Shanghai',sample_sha256=heap.oracle.LIBRARY_SHA256,matching_libc_sha256=heap.LIBC_HASH,
        native_Python_attached_segment_custom_controls=len(rows),rollback_negative_controls=len(guards),pre_change_behavior_RED_controls=26,
        complete_actual_ELF_module_controls=sum(r['actual_ELF_complete_module'] for r in rows),
        actual_ELF_custom_payload_controls=sum(r['actual_ELF_custom_payload'] for r in rows),
        relocated_entry_stack_controls=12,relocated_full_guest_controls=6,
        complete_actual_input_bytes=0x37FD0,complete_actual_code_bodies=121,complete_actual_raw_words=54533,
        native_input_snapshot_used=False,private_payloads_published=False,whole_native_stack_TLS_OS_compared=False,
        nonempty_element_native_abort_unsupported=True,zero_type_incoming_register_boundary_open=True,
        independent_Python_factory_implemented=False,complete_python_medusa=False,
        fresh_signer_output_verified=False,live_server_matrix_verified=False,cases=rows,negative_cases=guards)
    args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    print('B attached segments/custom:',len(rows),'native/Python,',len(guards),'rollback checks',flush=True)


if __name__=='__main__':main()
