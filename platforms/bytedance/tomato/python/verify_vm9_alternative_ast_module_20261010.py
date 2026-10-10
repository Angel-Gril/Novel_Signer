"""Fresh bounded B attached parser / real AST module controls.

Actual +31b360, +324444, AST vtable entries and cleanup execute naturally.
Synthetic inputs, fresh ELF, explicit allocation plans; no captured inputs.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import random
from functools import lru_cache
from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as arm
import verify_vm9_alternative_ast_20261009 as controls
import verify_vm9_signer_objects as oracle
import vm9_alternative_startup as alternative
from vm9_allocator import RefillUnsupported,_read_span,_write_span
ENTRY=oracle.GUEST+0xEF00
CB,STATE=ENTRY-0x150,ENTRY-0x220
OUT,DATA,HEAP=oracle.GUEST+0x2000,oracle.GUEST+0x1000,oracle.GUEST+0x4000
SCRATCH=oracle.GUEST+0xB000
BASES=(0x122C0000,0x775C205000)
FUN={0x18:0x31B6B0,0x20:0x31B6D0,0x50:0x31C7B8,0xA0:0x31D6D4,0x160:0x31E5B4}
ARGC={0x18:1,0x20:5,0x50:2,0xA0:1,0x160:1}
GLOBALS=(0x3E2CFC,0x3E2D08,0x3E2D0C,0x3E2D14,0x3E2D18,0x3E2D28,0x3E2D2C,0x3E2D34,0x3E2D38,0x3E2D70)
LIBC_HASH='d2376df6d2ac3e0213f85e3614c4c7ad1d28c84c44926058d5c1b95c855563db'
@lru_cache(maxsize=1)
def libc_memcmp(path):
    with path.open('rb') as stream:
        elf=ELFFile(stream)
        return next(0x51000000+s['st_value'] for section in elf.iter_sections()
            if section['sh_type']=='SHT_DYNSYM' for s in section.iter_symbols()
            if s.name=='memcmp' and s['st_value'])
def enc(n):
    out=bytearray()
    while n>=128:out.append((n&127)|128);n>>=7
    out.append(n);return bytes(out)
def section(number,payload):return bytes([number])+enc(len(payload))+payload
def types(definitions):
    return section(1,enc(len(definitions))+b''.join(b'\x60'+enc(len(p))+bytes(p)+enc(len(r))+bytes(r) for p,r in definitions))
def prepare(args,base,spec):
    pages=oracle.fresh_pages()
    pages.update({k:bytearray(v) for k,v in controls.fresh_image(args.library,base).items()})
    _write_span(pages,OUT,bytes(0x120));_write_span(pages,DATA,spec['blob'])
    _write_span(pages,STATE,bytes([spec.get('padding',0xA5)])*0x220)
    if spec.get('warm_rank'):
        _write_span(pages,base+0x3E2D38,b''.join(v.to_bytes(4,'little') for v in (0,1,2,3,4,5,7,8,9,10,12,13,11,6)))
        _write_span(pages,base+0x3E2D70,(1).to_bytes(4,'little'))
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
   slot=next(s for s,f in FUN.items() if f==o);argv=tuple(cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(1,ARGC[slot]+1));callbacks.append((slot,argv,int.from_bytes(cpu.mem_read(STATE+24,8),'little'),int.from_bytes(cpu.mem_read(STATE,8),'little')));mode=('ast',OUT,0x120)
   assert int.from_bytes(cpu.mem_read(CB+8,8),'little')==STATE+8
  if o==0x31b3e8:
   snap['parser']=bytes(cpu.mem_read(STATE,0xb0));snap['parser_status']=cpu.reg_read(arm.UC_ARM64_REG_X0)
  if o==0x31b458:mode=('callback_cleanup',CB,0x108)
  if o in (0x3244e0,0x3244f0,0x324500,0x324510):mode=('parser',STATE+{0x3244e0:0x70,0x3244f0:0x58,0x324500:0x40,0x324510:0x28}[o],24)
  if o in (0x321260,0x321308,0x321368):
   addr=cpu.reg_read(arm.UC_ARM64_REG_X0);table=int.from_bytes(cpu.mem_read(addr,8),'little')-base
   if oracle.GUEST<=addr<oracle.GUEST+0xa000:effects.append(('destroy',addr,{0x3724f0:64,0x372590:40,0x372518:48,0x372540:40,0x372568:24}[table],mode[1],bytes(cpu.mem_read(mode[1],mode[2]))))
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

def fixtures():
    cases=[]
    def add(label,tail=b'',status=0,prefix=b'A'*8,**options):
        cases.append(dict(label=label,blob=prefix+tail,status=status,**options))
    for n in range(9):add('length_'+str(n),prefix=b'A'*n,status=int(n<8))
    for pad in (0,0x39,0xA5,0xFF):
        add('prefix_padding_'+str(pad),prefix=bytes([pad])*8,padding=pad)
        add('start_padding_'+str(pad),section(8,b'\x07'),padding=pad,start_values=(7,))
        add('type_padding_'+str(pad),types([([0x7F,0x7E],[0x7D])]),padding=pad,type_count=1)
    add('types_function_start',section(1,b'\x02\x60\x02\x7f\x7e\x01\x7d\x60\x00\x00')+section(3,b'\x01\x00')+section(8,b'\x03'),status=1,type_count=2,function_count=1,start_values=(3,))
    add('partial_type_failure',section(1,b'\x02\x60\x01\x7f\x00\x60\x02\x7f'),status=1,type_count=1)
    add('start_then_bad',section(8,b'\x07')+b'\x0d\x00',prefix=b'B'*8,status=1,start_values=(7,))
    for count in (0,1,2,4):
        add('data_reserve_'+str(count),section(12,enc(count)),data_capacity=count)
        add('empty_type_function_'+str(count),types([([],[])]*count)+section(3,enc(count)+b'\x00'*count),status=int(count!=0),type_count=count,function_count=count)
    for values in (([],[]),([0x7F],[]),([],[0x7E]),([0x7F,0x7E,0x7D],[0x7C,0x7B]),([0x70,0x6F],[0x7F])):
        for count in (1,2,4):
            add('types_'+str(values)+'_'+str(count),types([values]*count),type_count=count)
    for defs in ([([0x7F],[]),([0x7F]*4,[0x7E]*3),([],[])], [([],[]),([0x7F]*3,[0x7E]*2),([0x7D],[0x7C])]):
        for warm in (False,True):
            add('type_resize_'+str(len(cases)),types(defs)+section(3,b'\x03\x02\x01\x00')+section(8,b'\x01')+section(12,b'\x02'),status=1,type_count=3,function_count=3,start_values=(1,),data_capacity=2,warm_rank=warm)
    valid=section(1,b'\x02\x60\x02\x7f\x7e\x01\x7d\x60\x00\x00')
    for n in range(1,len(valid)):
        add('type_truncated_'+str(n),valid[:n],status=1)
    for label,tail in (
        ('unknown_13',b'\x0d\x00'),('unknown_14',b'\x0e\x00'),
        ('envelope_truncated',b'\x08\x80'),('envelope_overflow',b'\x08'+b'\x80'*4+b'\x10'),
        ('envelope_past_input',b'\x08\x7f'),('type_wrong_form',section(1,b'\x01\x61\x00\x00')),
        ('type_bad_value',section(1,b'\x01\x60\x01\x01\x00')),
        ('type_bad_count',section(1,b'\x03')),('type_multibyte_form',section(1,b'\x01\x60\x01\x6b\x00\x00')),
        ('start_trailing',section(8,b'\x01\x00')),('start_duplicate',section(8,b'\x01')+section(8,b'\x02')),
        ('rank_backwards',section(8,b'\x01')+section(3,b'\x00')),
        ('data_trailing',section(12,b'\x02\x00')),('exports_trailing',section(7,b'\x00\x00'))):
        add(label,tail,status=1)
    for val in (0,1,127,128,65535,0xFFFFFFFF):add('start_'+str(val),section(8,enc(val)),start_values=(val,))
    for length in (0,1,2,4,9,14):
        add('custom_generic_'+str(length),section(0,enc(length)+b'z'*length+b'\xff\x00'))
    add('custom_around',section(0,b'\x01x')+section(1,b'\x00')+section(0,b'\x01y')+section(7,b'\x00'))
    add('empty_exports',section(7,b'\x00'))
    add('function_count_zero',section(3,b'\x00'))
    rng=random.Random(0x31B360)
    for index in range(16):
        defs=[([rng.choice((0x7F,0x7E,0x7D,0x7C)) for _ in range(rng.randrange(4))],
               [rng.choice((0x7F,0x7E,0x7D,0x7C)) for _ in range(rng.randrange(3))]) for _ in range(rng.randrange(1,5))]
        fcount=rng.randrange(4);data=rng.randrange(4);start=rng.randrange(1<<32)
        add('generated_'+str(index),types(defs)+section(3,enc(fcount)+b''.join(enc(rng.randrange(len(defs))) for _ in range(fcount)))+section(8,enc(start))+section(12,enc(data)),status=int(fcount!=0),type_count=len(defs),function_count=fcount,start_values=(start,),data_capacity=data,padding=rng.randrange(256))
    return cases


def model(args,base,spec,**options):
    pages=prepare(args,base,spec);offset=0;snap=[]
    def allocate(size):
        nonlocal offset
        pointer=HEAP+offset;offset+=(size+15)&~15;return pointer
    params=dict(image_base=base,input_address=DATA,input_size=len(spec['blob']),output_address=OUT,
        entry_stack_address=ENTRY,varuint_scratch_address=SCRATCH,allocate=allocate,
        context_address=0x123,context_size=0x456)
    params.update(options)
    cleanup=alternative.cleanup_reader_callback
    def observed_cleanup(current,**kw):
        snap.append(_read_span(current,STATE,0xB0));return cleanup(current,**kw)
    alternative.cleanup_reader_callback=observed_cleanup
    try:result=alternative.run_reader_ast_module(pages,**params)
    finally:alternative.cleanup_reader_callback=cleanup
    return pages,result,snap[0]


def normalized(effects):
    rows=[]
    for e in effects:
        if isinstance(e,alternative.ReaderVectorEffect):
            rows.append((e.kind,e.address,e.size,e.vector_address,b''.join(v.to_bytes(8,'little') for v in e.vector_words)))
        else:rows.append((e.kind,e.address,e.size,e.owner_address,e.owner_bytes))
    return rows


def compare(args,base,spec):
    status,np,ne,nc,snap=native(args,base,spec)
    pages,result,state_bytes=model(args,base,spec)
    assert result.status==status==spec['status'],(spec['label'],'status',result.status,status,spec['status'])
    assert normalized(result.effects)==ne,(spec['label'],'ordered effects and owner bytes')
    assert state_bytes==snap['parser'],(spec['label'],'parser exit state')
    assert _read_span(pages,CB,0x120)==snap['callback_final'],(spec['label'],'callback cleanup bytes')
    assert _read_span(pages,oracle.GUEST,0xA000)==_read_span(np,oracle.GUEST,0xA000),(spec['label'],'guest bytes')
    for (address,width),data in snap['globals'].items():assert _read_span(pages,address,width)==data
    events=[] if result.sections is None else [(e.slot_offset,e.arguments,e.cursor,e.section_end) for e in result.sections.callback_events]
    assert events==nc,(spec['label'],'callback arguments and parser state')
    u=lambda a:int.from_bytes(_read_span(pages,a,8),'little')
    for offset,key,stride in ((0,'type_count',64),(0x30,'function_count',144)):
        if key in spec:assert (u(OUT+offset+8)-u(OUT+offset))//stride==spec[key]
    if 'start_values' in spec:
        first,last=u(OUT+0xC0),u(OUT+0xC8)
        assert _read_span(pages,first,last-first)==b''.join(v.to_bytes(4,'little') for v in spec['start_values'])
    if 'data_capacity' in spec:
        assert u(OUT+0xF0)==u(OUT+0xF8)
        assert (u(OUT+0x100)-u(OUT+0xF0))//176==spec['data_capacity']
    assert u(CB+8)==STATE+8 and not any(_read_span(pages,CB+0x108,24))
    assert _read_span(pages,CB+0x28,8)==bytes([spec.get('padding',0xA5)])*8
    for offset in (0x28,0x40,0x58,0x70):assert int.from_bytes(state_bytes[offset:offset+8],'little')==int.from_bytes(state_bytes[offset+8:offset+16],'little')
    return dict(label=spec['label'],image_base_hex=hex(base),status=status,callback_count=len(nc),
        allocation_count=sum(e[0]=='allocate' for e in ne),free_count=sum(e[0]=='free' for e in ne),destructor_count=sum(e[0]=='destroy' for e in ne),
        actual_module_parser_vtables_and_cleanup_executed=True,natural_return_and_SP_verified=True,
        complete_guest_0xa000_without_masking_match=True,ordered_effects_and_owner_bytes_match=True,
        parser_exit_callback_cleanup_and_image_globals_match=True,callback_arguments_cursor_limit_match=True,
        independent_partial_output_dangling_headers_padding_and_cleanup_match=True,
        synthetic_fixture=True,native_input_snapshot_used=False,whole_native_stack_TLS_OS_compared=False)


def negatives(args):
    base=BASES[0];spec=dict(label='guard',blob=b'A'*8+types([([0x7F,0x7E],[0x7D])])+section(3,b'\x01\x00')+section(8,b'\x07'))
    rows=[]
    def reject(label,changes=None,setup=None,write_failure=None,fixture=None):
        current=fixture or spec;pages=prepare(args,base,current);offset=0
        def allocate(size):
            nonlocal offset
            ptr=HEAP+offset;offset+=(size+15)&~15;return ptr
        params=dict(image_base=base,input_address=DATA,input_size=len(current['blob']),output_address=OUT,
            entry_stack_address=ENTRY,varuint_scratch_address=SCRATCH,allocate=allocate,context_address=0x123,context_size=0x456)
        params.update(changes or {})
        if setup:setup(pages)
        before={k:bytes(v) for k,v in pages.items()};write=alternative._write_span;hits=[]
        def fault(p,address,data):
            if write_failure(address,data):hits.append(address);raise RefillUnsupported('injected module write failure')
            return write(p,address,data)
        if write_failure:alternative._write_span=fault
        try:
            try:alternative.run_reader_ast_module(pages,**params)
            except (RefillUnsupported,ValueError):pass
            else:raise AssertionError('module guard accepted: '+label)
        finally:alternative._write_span=write
        assert before=={k:bytes(v) for k,v in pages.items()},label
        if write_failure:assert hits,label
        rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_invalid_path_executed=False))
    for label,changes in (
        ('base_unaligned',dict(image_base=base+1)),('base_invalid',dict(image_base=0)),
        ('output_unaligned',dict(output_address=OUT+1)),('stack_unaligned',dict(entry_stack_address=ENTRY+8)),
        ('stack_unmapped',dict(entry_stack_address=0x80000000)),('input_unmapped',dict(input_address=0x80000000)),
        ('input_output_overlap',dict(input_address=OUT)),('input_frame_overlap',dict(input_address=CB)),
        ('output_frame_overlap',dict(output_address=STATE)),('scratch_output_overlap',dict(varuint_scratch_address=OUT)),
        ('scratch_input_overlap',dict(varuint_scratch_address=DATA)),('scratch_frame_overlap',dict(varuint_scratch_address=STATE)),
        ('scratch_image_overlap',dict(varuint_scratch_address=base+0x121110)),
        ('output_image_overlap',dict(output_address=base+0x3E2000)),('input_size_budget',dict(max_input_bytes=8)),
        ('input_size_negative',dict(input_size=-1)),('sections_zero',dict(max_sections=0)),('sections_limit',dict(max_sections=1)),
        ('entries_zero',dict(max_entries=0)),('entries_limit',dict(max_entries=1)),('nodes_zero',dict(max_nodes=0)),
        ('function_nodes_limit',dict(max_nodes=1)),('vector_bytes_limit',dict(max_vector_bytes=63)),
        ('allocation_missing',dict(allocate=None)),('context_invalid',dict(context_size=-1)),
        ('reserved_invalid',dict(reserved_regions=((10,9),))),('reserved_input_overlap',dict(reserved_regions=((DATA,DATA+1),)))):
        reject(label,changes)
    reject('output_not_empty',setup=lambda p:_write_span(p,OUT,b'\x01'))
    reject('wrong_callback_binding',setup=lambda p:_write_span(p,base+0x372370+0x20,(base+0x31D974).to_bytes(8,'little')))
    reject('wrong_node_binding',setup=lambda p:_write_span(p,base+0x3724F0,(base+0x321368).to_bytes(8,'little')))
    for label,target in (('input',DATA),('output',OUT),('callback',CB),('parser',STATE),('scratch',SCRATCH),('image',base+0x3E2000),('unaligned',HEAP+1),('unmapped',0x80000000),('null',0)):
        reject('allocation_'+label,dict(allocate=lambda size,target=target:target))
    for call in range(2,14):
        index=[0];prior=[]
        def reused(size,call=call,index=index,prior=prior):
            index[0]+=1
            if index[0]==call:return HEAP
            ptr=HEAP+sum((s+15)&~15 for s in prior);prior.append(size);return ptr
        reject('allocation_prior_block_'+str(call),dict(allocate=reused))
    for number in (2,4,5,6,9,10,11):
        reject('unsupported_handler_'+str(number),fixture=dict(blob=b'A'*8+types([([],[])])+section(number,b'\x00')))
    reject('nonempty_export',fixture=dict(blob=b'A'*8+types([([],[])])+section(3,b'\x01\x00')+section(7,b'\x01\x01a\x00\x00')))
    for marker in (b'dylink',b'dylink.0',b'linking',b'target_features',b'reloc.CODE'):
        reject('special_custom_'+marker.decode(),fixture=dict(blob=b'A'*8+types([([],[])])+section(0,enc(len(marker))+marker)))
    for label,addr,width in (('construct_callback',CB,8),('construct_state',STATE,8),('first_type_publish',OUT,24),
            ('function_publish',OUT+0x30,24),('start_publish',OUT+0xC0,24),('parser_cleanup',STATE+0x48,8),('callback_cleanup',CB+0x88,8)):
        if label=='construct_callback':pred=lambda a,d:a==CB
        elif label=='parser_cleanup':pred=lambda a,d:a==STATE+0x48 and len(d)==8
        else:pred=lambda a,d,addr=addr,width=width:a==addr and len(d)==width
        reject('write_failure_'+label,write_failure=pred)
    # Valid short inputs must obey resource limits before any constructor writes.
    reject('short_input_resource_guard',dict(max_sections=0),fixture=dict(blob=b'A'))
    # Opt-in binding failures must preserve pages, and default API still rejects it.
    pages,result,_=model(args,base,spec)
    for label,op,changes in (
        ('default_attached_callback','callback',{}),('wrong_attached_callback','callback',dict(attached_state_address=STATE+16)),
        ('unverified_attached_slot','callback',dict(attached_state_address=STATE,slot_offset=0x100,arguments=(0,))),
        ('default_attached_cleanup','cleanup',{}),('wrong_attached_cleanup','cleanup',dict(attached_state_address=STATE+16))):
        before={k:bytes(v) for k,v in pages.items()}
        params=dict(callback_address=CB,image_base=base)
        if op=='callback':params.update(slot_offset=0x18,arguments=(0,),allocate=lambda size:HEAP+0x2000)
        params.update(changes)
        try:
            if op=='callback':alternative.run_reader_ast_callback(pages,**params)
            else:alternative.cleanup_reader_callback(pages,**params)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in pages.items()}
        rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_invalid_path_executed=False))
    for label,address,value in (('attached_input_shared',STATE+8,CB),
            ('attached_input_unmapped',STATE+8,0x80000000),
            ('attached_cursor_past_limit',STATE+24,0xFFFFFFFF),
            ('attached_total_overflow',STATE+16,(1<<64)-1),
            ('attached_reverse_binding',STATE+32,CB+8),
            ('attached_vector_alias',STATE+0x28,OUT)):
        current={k:bytearray(v) for k,v in pages.items()}
        _write_span(current,address,value.to_bytes(8,'little'))
        if label=='attached_vector_alias':
            _write_span(current,STATE+0x30,(OUT+8).to_bytes(8,'little'))
            _write_span(current,STATE+0x38,(OUT+8).to_bytes(8,'little'))
        before={k:bytes(v) for k,v in current.items()}
        try:
            alternative.run_reader_ast_callback(current,callback_address=CB,image_base=base,
                slot_offset=0x18,arguments=(0,),attached_state_address=STATE,
                allocate=lambda size:HEAP+0x2000)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in current.items()}
        rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_invalid_path_executed=False))
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
            if index%16==0:print('B attached AST module:',hex(base),index,'/',len(specs),'passed',flush=True)
    evidence=dict(schema='vm9-alternative-ast-module-fresh-v1',evidence_date='2026-10-10',evidence_timezone='Asia/Shanghai',
        sample_sha256=oracle.LIBRARY_SHA256,matching_libc_sha256=LIBC_HASH,
        native_module_offset_hex='0x31b360',native_parser_offset_hex='0x324444',native_dispatcher_offset_hex='0x324188',
        native_Python_module_controls=len(rows),rollback_negative_controls=len(guards),pre_change_behavior_RED_controls=10,
        generated_fixture_seed=0x31B360,supported_section_ids=[0,1,3,7,8,12],nonempty_exports_supported=False,
        output_must_start_empty=True,attached_slots_hex=[hex(s) for s in FUN],
        allocator_is_explicit_pure_plan=True,allocation_address_reuse_supported=False,free_is_logical_no_poison_or_unmap=True,
        parser_and_callback_temporaries_cleaned=True,actual_AST_status_callbacks_substituted=False,
        native_input_snapshot_used=False,private_payloads_published=False,whole_native_stack_TLS_OS_compared=False,
        complete_attached_reader_implemented=False,complete_python_reader_implemented=False,
        independent_Python_factory_implemented=False,complete_python_bootstrap_controls=0,complete_python_medusa=False,
        fresh_signer_output_verified=False,live_server_matrix_verified=False,cases=rows,negative_cases=guards)
    args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    print('B attached AST module:',len(rows),'native/Python +',len(guards),'rollback checks passed',flush=True)
if __name__=='__main__':main()
