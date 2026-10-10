"""Fresh B attached heap-name function import composition controls.

Actual module/parser/import callbacks and owned cleanup execute naturally.
No callback stack snapshots feed the Python model; fixtures are synthetic.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import random
from types import SimpleNamespace
from unicorn import arm64_const as arm
import verify_vm9_alternative_ast_module_20261010 as previous
import vm9_alternative_startup as alternative
from vm9_allocator import RefillUnsupported,_read_span,_write_span
oracle=previous.oracle
ENTRY,CB,STATE,OUT,DATA,HEAP,SCRATCH=previous.ENTRY,previous.CB,previous.STATE,previous.OUT,previous.DATA,previous.HEAP,previous.SCRATCH
BASES,GLOBALS,LIBC_HASH=previous.BASES,previous.GLOBALS,previous.LIBC_HASH
FUN={**previous.FUN,0x28:0x31B870}
ARGC={**previous.ARGC,0x28:7}
enc,section,types,libc_memcmp=previous.enc,previous.section,previous.types,previous.libc_memcmp
def import_(module,field,index):return enc(len(module))+module+enc(len(field))+field+b'\0'+enc(index)
def prepare(args,base,spec):
    pages=previous.prepare(args,base,spec)
    _write_span(pages,STATE-0x1E0,bytes([spec.get('frame_padding',0xA5)])*0x1E0)
    return pages
def native(args,base,spec):
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
   if oracle.GUEST<=addr<oracle.GUEST+0xa000:effects.append(('destroy',addr,{0x3724f0:64,0x372590:40,0x372518:48,0x372540:40,0x372568:24}[table],mode[1],bytes(cpu.mem_read(mode[1],mode[2]))))
  if o in (0x3212B0,0x3212FC,0x321300,0x321304,0x32132C):
   addr=cpu.reg_read(arm.UC_ARM64_REG_X0);effects.append(('delete',addr,{0x3212B0:64,0x3212FC:48,0x321300:40,0x321304:24,0x32132C:40}[o],mode[1],bytes(cpu.mem_read(mode[1],mode[2]))))
  if o==0x2CC470:
   addr=cpu.reg_read(arm.UC_ARM64_REG_X1)
   if oracle.GUEST<=addr<oracle.GUEST+0xA000:
    effects.append(('destroy',addr,144,mode[1],bytes(cpu.mem_read(mode[1],mode[2]))))
  if o==0x31b454:assert cpu.reg_read(arm.UC_ARM64_REG_SP)==ENTRY
 def malloc(cpu,size):
  nonlocal n
  ptr=HEAP+n;n+=(size+15)&~15;assert ptr+size<oracle.GUEST+0xa000
  sizes[ptr]=size;effects.append(('allocate',ptr,size,mode[1],bytes(cpu.mem_read(mode[1],mode[2]))));return ptr
 def free(cpu):
  ptr=cpu.reg_read(arm.UC_ARM64_REG_X0);assert ptr in sizes,('unknown/double',hex(ptr))
  effects.append(('free',ptr,sizes.pop(ptr),mode[1],bytes(cpu.mem_read(mode[1],mode[2]))));return 0
 observed={(CB,0x120):None,**{(base+offset,64):None for offset in GLOBALS}}
 def memcmp(cpu):
  cpu.reg_write(arm.UC_ARM64_REG_PC,libc_memcmp(args.libc));return None
 status,memory,calls,ledger=oracle.native(args.library,base,0x31b360,[0x123,0x456,DATA,len(spec['blob']),OUT],p,malloc_handler=malloc,host_imports={0x347fa0:free,0x347fe0:memcmp},libc=args.libc,instruction_observer=observe,instruction_limit=500000,observed_memory=observed)
 assert not calls and not ledger
 _write_span(p,oracle.GUEST,memory)
 snap['callback_final']=observed[CB,0x120]
 snap['globals']={(a,w):data for (a,w),data in observed.items() if a!=CB}
 return status,p,effects,callbacks,snap



def minimal_specs():
    t=types([([0x7F,0x7E],[0x7D]),([],[])])
    return [dict(label='heap_function_import_23_24',blob=b'A'*8+t+section(2,b'\x01'+import_(b'm'*23,b'f'*24,0)),status=0,expected_names=((b'm'*23,b'f'*24),),type_indexes=(0,)),
        dict(label='heap_function_import_growth',blob=b'A'*8+t+section(2,b'\x03'+b''.join(import_(bytes([97+i])*(23+i),bytes([109+i])*(32+i),i%2) for i in range(3))),status=0,expected_names=tuple((bytes([97+i])*(23+i),bytes([109+i])*(32+i)) for i in range(3)),type_indexes=(0,1,0)),
        dict(label='heap_function_import_and_defined',blob=b'A'*8+t+section(2,b'\x02'+import_(b'm'*32,b'f'*64,0)+import_(b'n'*24,b'g'*23,1))+section(3,b'\x01\x01')+section(8,b'\x02'),status=1,expected_names=((b'm'*32,b'f'*64),(b'n'*24,b'g'*23)),type_indexes=(0,1),defined_count=1)]

def model(args,base,spec,**options):
    pages=prepare(args,base,spec);offset=0;snap=[]
    def allocate(size):
        nonlocal offset
        pointer=HEAP+offset;offset+=(size+15)&~15;return pointer
    params=dict(image_base=base,input_address=DATA,input_size=len(spec['blob']),output_address=OUT,
        entry_stack_address=ENTRY,varuint_scratch_address=SCRATCH,allocate=allocate,
        context_address=0x123,context_size=0x456,enable_function_imports=True)
    params.update(options)
    cleanup=alternative.cleanup_reader_callback
    def observed_cleanup(current,**kw):snap.append(_read_span(current,STATE,0xB0));return cleanup(current,**kw)
    alternative.cleanup_reader_callback=observed_cleanup
    try:result=alternative.run_reader_ast_module(pages,**params)
    finally:alternative.cleanup_reader_callback=cleanup
    return pages,result,snap[0]

def compare(args,base,spec):
    status,np,ne,nc,snap=native(args,base,spec)
    pages,result,state_bytes=model(args,base,spec)
    assert result.status==status==spec['status'],(spec['label'],'status')
    me=previous.normalized(result.effects)
    assert me==ne,(spec['label'],'ordered effects/owner bytes',[(e[:4]) for e in me],[(e[:4]) for e in ne])
    assert state_bytes==snap['parser'],(spec['label'],'parser state')
    assert _read_span(pages,CB,0x120)==snap['callback_final'],(spec['label'],'callback final')
    assert _read_span(pages,oracle.GUEST,0xA000)==_read_span(np,oracle.GUEST,0xA000),(spec['label'],'guest bytes')
    for (address,width),data in snap['globals'].items():assert _read_span(pages,address,width)==data
    events=[] if result.sections is None else [(e.slot_offset,e.arguments,e.cursor,e.section_end) for e in result.sections.callback_events]
    assert events==nc,(spec['label'],'callback arguments')
    u=lambda address,width=8:int.from_bytes(_read_span(pages,address,width),'little')
    begin,end=u(OUT+0x18),u(OUT+0x20)
    expected=spec.get('expected_names')
    if expected is not None:
        assert (end-begin)//64==len(expected)
        assert u(STATE+0x90,4)==len(expected)
        type_begin=u(OUT)
        for index,(module,field) in enumerate(expected):
            record=begin+index*64
            for offset,name in ((0,module),(24,field)):
                header=record+offset
                assert u(header)&1 and u(header,8)&~1==(len(name)+16)&~15
                assert u(header+8)==len(name)
                assert _read_span(pages,u(header+16),len(name)+1)==name+b'\0'
            source=type_begin+spec['type_indexes'][index]*64;node=u(record+48)
            assert node!=source and u(node)==base+0x3724F0
            assert u(record+56,4)==spec['type_indexes'][index] and u(record+60,4)==index
            for offset in (16,40):
                first,last=u(source+offset),u(source+offset+8)
                cloned_first,cloned_last=u(node+offset),u(node+offset+8)
                assert cloned_last-cloned_first==last-first
                assert _read_span(pages,cloned_first,cloned_last-cloned_first)==_read_span(pages,first,last-first)
                if last!=first:assert cloned_first!=first
        assert (u(OUT+0x38)-u(OUT+0x30))//144==spec.get('defined_count',0)
        assert u(CB+0x80)==u(CB+0x88)
    return dict(label=spec['label'],image_base_hex=hex(base),status=status,callback_count=len(nc),
        allocation_count=sum(e[0]=='allocate' for e in ne),free_count=sum(e[0]=='free' for e in ne),
        destructor_count=sum(e[0]=='destroy' for e in ne),delete_count=sum(e[0]=='delete' for e in ne),
        actual_module_parser_import_vtables_and_cleanup_executed=True,natural_return_and_SP_verified=True,
        complete_guest_0xa000_without_masking_match=True,ordered_effects_and_owner_bytes_match=True,
        parser_exit_callback_cleanup_image_globals_and_callback_arguments_match=True,
        independent_names_cloned_nodes_type_import_indexes_partial_output_and_cleanup_match=True,
        synthetic_fixture=True,native_input_snapshot_used=False,whole_native_stack_TLS_OS_compared=False)

def fixtures():
    cases=minimal_specs()
    def add(label,names,indexes,definitions=None,after=b'',status=0,**options):
        definitions=definitions if definitions is not None else [([0x7F,0x7E],[0x7D]),([],[])]
        tail=types(definitions)+section(2,enc(len(names))+b''.join(import_(m,f,t) for (m,f),t in zip(names,indexes)))+after
        cases.append(dict(label=label,blob=b'A'*8+tail,expected_names=tuple(names),type_indexes=tuple(indexes),status=status,**options))
    for length in (23,24,31,32,63,64,127,128):
        for pad in (0,0xA5,0xFF):
            names=((bytes((i*17)&255 for i in range(length)),bytes((255-i*11)&255 for i in range(length+1))),)
            add('name_boundary_'+str(length)+'_'+str(pad),names,(0,),frame_padding=pad)
    for count in (1,2,3,4):
        for mode,definitions in (('empty',[([],[]),([],[])]),('params',[([0x7F,0x7E],[]),([0x7D],[])]),('results',[([],[0x7F]),([],[0x7E,0x7D])]),('rich',[([0x7F,0x7E],[0x7D]),([0x7C],[0x7B])])):
            names=tuple((bytes([0x61+i])*(23+i),bytes([0x71+i])*(31+i)) for i in range(count))
            indexes=tuple(i%2 for i in range(count))
            for defined in (0,2):
                after=b'' if not defined else section(3,b'\x02\x01\x00')
                add(f'growth_{count}_{mode}_{defined}',names,indexes,definitions,after,status=int(defined!=0),defined_count=defined)
    # Combinations retain the existing parser rank and callback behavior.
    names=((b'm'*24,b'f'*24),(b'n'*32,b'g'*23))
    for warm in (False,True):
        add('surrounding_custom_start_count_'+str(warm),names,(0,1),after=section(0,b'\x01x')+section(8,b'\x01')+section(12,b'\x03'),warm_rank=warm)
    full=minimal_specs()[1]
    type_prefix=types([([0x7F,0x7E],[0x7D]),([],[])])
    # Every cut in the last record keeps the two completed imports.
    entries=[import_(bytes([97+i])*(23+i),bytes([109+i])*(32+i),i%2) for i in range(3)]
    prefix=b'A'*8+type_prefix
    for cut in (0,1,2,10,25,26,27,35,len(entries[2])-1):
        payload=b'\x03'+entries[0]+entries[1]+entries[2][:cut]
        cases.append(dict(label='partial_import_'+str(cut),blob=prefix+section(2,payload),status=1,
            expected_names=full['expected_names'][:2],type_indexes=(0,1)))
    for label,after in (('duplicate',section(2,b'\x00')),('rank_backwards',section(1,b'\x00')),('unknown',b'\x0d\x00'),('truncated_envelope',b'\x08\x80')):
        add('after_import_'+label,((b'm'*23,b'f'*24),),(0,),after=after,status=1)
    cases.append(dict(label='empty_import_section',blob=b'A'*8+section(2,b'\x00'),status=0,expected_names=(),type_indexes=()))
    cases.append(dict(label='import_truncated_count',blob=b'A'*8+section(2,b'\x80'),status=1,expected_names=(),type_indexes=()))
    cases.append(dict(label='import_bad_count',blob=b'A'*8+section(2,b'\x7f'),status=1,expected_names=(),type_indexes=()))
    cases.append(dict(label='import_unknown_kind',blob=b'A'*8+section(2,b'\x01\x01a\x01b\x04'),status=1,expected_names=(),type_indexes=()))
    rng=random.Random(0x31B870)
    for index in range(12):
        definitions=[([rng.choice((0x7F,0x7E,0x7D,0x7C)) for _ in range(rng.randrange(4))],
                       [rng.choice((0x7F,0x7E,0x7D,0x7C)) for _ in range(rng.randrange(3))]) for _ in range(3)]
        names=tuple((bytes(rng.randrange(256) for _ in range(rng.randrange(23,41))),
                     bytes(rng.randrange(256) for _ in range(rng.randrange(23,41)))) for _ in range(rng.randrange(1,4)))
        indexes=tuple(rng.randrange(3) for _ in names)
        add('generated_'+str(index),names,indexes,definitions,frame_padding=rng.randrange(256),padding=rng.randrange(256))
    return cases


def negatives(args):
    rows=[];base=BASES[0];spec=minimal_specs()[1]
    def reject(label,changes=None,fixture=None,setup=None,fault=None):
        pages=prepare(args,base,fixture or spec);offset=0
        def allocate(size):
            nonlocal offset
            pointer=HEAP+offset;offset+=(size+15)&~15;return pointer
        params=dict(image_base=base,input_address=DATA,input_size=len((fixture or spec)['blob']),output_address=OUT,
            entry_stack_address=ENTRY,varuint_scratch_address=SCRATCH,allocate=allocate,
            context_address=0x123,context_size=0x456,enable_function_imports=True)
        params.update(changes or {})
        if setup:setup(pages)
        before={k:bytes(v) for k,v in pages.items()};write=alternative._write_span;hits=[]
        def injected(p,address,data):
            if fault(address,data):hits.append(address);raise RefillUnsupported('injected heap import write failure')
            return write(p,address,data)
        if fault:alternative._write_span=injected
        try:
            try:alternative.run_reader_ast_module(pages,**params)
            except (RefillUnsupported,ValueError):pass
            else:raise AssertionError('heap import guard accepted: '+label)
        finally:alternative._write_span=write
        assert before=={k:bytes(v) for k,v in pages.items()},label
        if fault:assert hits,label
        rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_invalid_path_executed=False))
    for label,changes in (('opt_in_required',dict(enable_function_imports=False)),('opt_in_type',dict(enable_function_imports=1)),
            ('input_in_lower_frame',dict(input_address=STATE-0x100)),('output_in_lower_frame',dict(output_address=STATE-0x180)),
            ('scratch_in_lower_frame',dict(varuint_scratch_address=STATE-8)),('reserved_in_lower_frame',dict(reserved_regions=((STATE-8,STATE),))),
            ('entry_frame_underflow',dict(entry_stack_address=0x400)),('allocation_lower_frame',dict(allocate=lambda size:STATE-0x1E0)),
            ('import_entry_budget',dict(max_entries=2)),('clone_node_budget',dict(max_nodes=5)),('name_byte_budget',dict(max_vector_bytes=31))):
        reject(label,changes)
    reject('missing_lower_frame_page',setup=lambda p:p.pop((STATE-0x1E0)>>12))
    for which in (0,1):
        for length in (0,1,7,21,22):
            names=[b'm'*23,b'f'*24];names[which]=b'x'*length
            blob=b'A'*8+types([([],[])])+section(2,b'\x01'+import_(*names,0))
            reject('short_name_'+str(which)+'_'+str(length),fixture=dict(blob=blob))
    # Unsupported kinds after one successful heap import must undo all writes.
    for kind,payload in ((1,b'\x70\x00\x01'),(2,b'\x00\x01'),(3,b'\x7f\x01')):
        rest=enc(23)+b'm'*23+enc(24)+b'f'*24+bytes([kind])+payload
        reject('other_import_kind_'+str(kind),fixture=dict(blob=b'A'*8+types([([],[])])+section(2,b'\x02'+import_(b'm'*23,b'f'*24,0)+rest)))
    reject('type_index_out_of_range',fixture=dict(blob=b'A'*8+types([([],[])])+section(2,b'\x01'+import_(b'm'*23,b'f'*24,1))))
    reject('wrong_import_binding',setup=lambda p:_write_span(p,base+0x372370+0x28,(base+0x31C144).to_bytes(8,'little')))
    reject('wrong_clone_binding',setup=lambda p:_write_span(p,base+0x3724F0+16,(base+0x321368).to_bytes(8,'little')))
    for call in (2,5,10,15,20,25,30,40,50,60):
        count=[0];seen=[]
        def alias(size,call=call,count=count,seen=seen):
            count[0]+=1
            if count[0]==call:return HEAP
            pointer=HEAP+sum((s+15)&~15 for s in seen);seen.append(size);return pointer
        reject('prior_allocation_'+str(call),dict(allocate=alias))
    for label,address,width in (('first_import_publish',OUT+0x18,24),('import_cache_publish',CB+0x80,24),
            ('parser_cleanup',STATE+0x48,8),('cache_cleanup',CB+0x88,8)):
        reject('write_failure_'+label,fault=lambda a,d,address=address,width=width:a==address and len(d)==width)
    spare=next(item for item in fixtures() if item['label']=='growth_4_rich_0')
    reject('write_failure_spare_import_end_publish',fixture=spare,
        fault=lambda address,data:address==OUT+0x20 and len(data)==8)
    # Valid adjacent retained storage is permitted; the same fixture passes.
    pages,result,_=model(args,base,spec,reserved_regions=((STATE-0x200,STATE-0x1E0),))
    assert result.status==0
    return rows


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('library','libc','output'):parser.add_argument('--'+name,required=True,type=Path)
    args=parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==LIBC_HASH
    guards=negatives(args);rows=[];specs=fixtures()
    for base in BASES:
        for index,spec in enumerate(specs,1):
            rows.append(compare(args,base,spec))
            if index%16==0:print('B attached heap function imports:',hex(base),index,'/',len(specs),'passed',flush=True)
    evidence=dict(schema='vm9-alternative-ast-module-function-imports-fresh-v1',evidence_date='2026-10-10',evidence_timezone='Asia/Shanghai',
        sample_sha256=oracle.LIBRARY_SHA256,matching_libc_sha256=LIBC_HASH,native_module_offset_hex='0x31b360',native_parser_offset_hex='0x324444',native_import_offset_hex='0x322cf8',native_callback_offset_hex='0x31b870',
        native_Python_function_import_module_controls=len(rows),rollback_negative_controls=len(guards),pre_change_heap_function_import_RED_controls=6,
        generated_fixture_seed=0x31B870,enable_function_imports_default=False,module_and_field_minimum_bytes=23,
        actual_AST_status_callbacks_substituted=False,parser_and_callback_temporaries_cleaned=True,
        allocation_address_reuse_supported=False,short_name_module_imports_supported=False,other_kind_module_imports_supported=False,
        native_input_snapshot_used=False,private_payloads_published=False,whole_native_stack_TLS_OS_compared=False,
        complete_attached_reader_implemented=False,complete_python_reader_implemented=False,independent_Python_factory_implemented=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False,cases=rows,negative_cases=guards)
    args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    print('B attached heap function imports:',len(rows),'native/Python +',len(guards),'rollback checks passed',flush=True)
if __name__=='__main__':main()
