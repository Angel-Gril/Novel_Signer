"""Actual attached table, memory and global imports, using synthetic fixtures."""
from __future__ import annotations
import argparse,hashlib,json,random,sys,itertools
from contextlib import contextmanager
from pathlib import Path
from unicorn import arm64_const as arm
import verify_vm9_alternative_ast_module_function_imports_20261010 as heap
from vm9_allocator import RefillUnsupported,_read_span,_write_span
alternative=heap.alternative
BASES=heap.BASES
ENTRY,CB,STATE,OUT,DATA,HEAP,SCRATCH=heap.ENTRY,heap.CB,heap.STATE,heap.OUT,heap.DATA,heap.HEAP,heap.SCRATCH
enc,section,types=heap.enc,heap.section,heap.types
FUN={**heap.FUN,0x30:0x31BB48,0x38:0x31BE3C,0x40:0x31C144}
ARGC={**heap.ARGC,0x30:8,0x38:7,0x40:8}

def import_(module,field,kind,payload):
 return enc(len(module))+module+enc(len(field))+field+bytes([kind])+payload

def minimal_specs():
 cases=[]
 for label,kind,payload in [('table_min',1,b'\x70\x00\x03'),('table_max',1,b'\x6f\x01\x03\x09'),
   ('memory_min',2,b'\x00\x03'),('memory_max',2,b'\x01\x03\x09'),('memory64_min',2,b'\x04'+enc(2**35)),
   ('global_immutable',3,b'\x7f\x00'),('global_mutable',3,b'\x7e\x01')]:
  entries=((b'm'*23,b'f'*24,kind,payload),)
  cases.append(dict(label=label,blob=b'A'*8+section(2,b'\x01'+import_(*entries[0])),status=0,entries=entries))
 entries=((b'm'*32,b'f'*24,0,b'\x00'),(b'n'*23,b'g'*32,1,b'\x70\x01\x03\x09'),
          (b'o'*24,b'h'*23,2,b'\x05'+enc(2**35)+enc(2**40)),(b'p'*23,b'i'*24,3,b'\x7d\x01'))
 cases.append(dict(label='mixed_four_kinds',blob=b'A'*8+types([([0x7F],[0x7E])])+section(2,b'\x04'+b''.join(import_(*e) for e in entries)),status=0,entries=entries))
 return cases

def prepare(args,base,spec):
 p=heap.previous.prepare(args,base,spec)
 _write_span(p,STATE-0x210,bytes([spec.get('frame_padding',0xA5)])*0x210)
 return p

def native(args,base,spec):
 original=(heap.FUN,heap.ARGC,heap.prepare,heap.oracle.native)
 entries=[]
 def instrumented(*args,**kw):
  observe=kw['instruction_observer']
  def observed(cpu,address):
   offset=address-base
   if offset in FUN.values():
    slot=next(s for s,f in FUN.items() if f==offset)
    if slot in (0x28,0x30,0x38,0x40):
     sp=cpu.reg_read(arm.UC_ARM64_REG_SP);assert sp==STATE-0x100
     desc=bytes(cpu.mem_read(sp+8,24)) if slot in (0x30,0x38) else None
     entries.append(dict(slot=slot,sp=sp,stack_argument=int.from_bytes(cpu.mem_read(sp,8),'little'),descriptor=desc))
   observe(cpu,address)
  kw['instruction_observer']=observed
  return original[3](*args,**kw)
 try:
  heap.FUN,heap.ARGC,heap.prepare,heap.oracle.native=FUN,ARGC,prepare,instrumented
  status,p,e,c,snap=heap.native(args,base,spec)
 finally:heap.FUN,heap.ARGC,heap.prepare,heap.oracle.native=original
 snap['import_entries']=entries
 return status,p,e,c,snap

def model(args,base,spec,**options):
 pages=prepare(args,base,spec);offset=0;snap=[]
 def allocate(size):
  nonlocal offset
  pointer=HEAP+offset;offset+=(size+15)&~15;return pointer
 params=dict(image_base=base,input_address=DATA,input_size=len(spec['blob']),output_address=OUT,
  entry_stack_address=ENTRY,varuint_scratch_address=SCRATCH,allocate=allocate,
  context_address=0x123,context_size=0x456,enable_function_imports=True,enable_table_memory_global_imports=True)
 params.update(options);cleanup=alternative.cleanup_reader_callback
 def observed_cleanup(current,**kw):snap.append(_read_span(current,STATE,0xB0));return cleanup(current,**kw)
 alternative.cleanup_reader_callback=observed_cleanup
 try:result=alternative.run_reader_ast_module(pages,**params)
 finally:alternative.cleanup_reader_callback=cleanup
 return pages,result,snap[0]

def compare(args,base,spec):
 status,np,ne,nc,snap=native(args,base,spec)
 pages,result,state_bytes=model(args,base,spec)
 assert result.status==status==spec['status'],(spec['label'],'status')
 me=heap.previous.normalized(result.effects)
 assert me==ne,(spec['label'],'effects',[(a[:4],b[:4]) for a,b in zip(me,ne) if a!=b])
 assert state_bytes==snap['parser'],(spec['label'],'parser state')
 assert _read_span(pages,CB,0x120)==snap['callback_final'],(spec['label'],'callback final')
 assert _read_span(pages,heap.oracle.GUEST,0xA000)==_read_span(np,heap.oracle.GUEST,0xA000),(spec['label'],'guest bytes',[(hex(heap.oracle.GUEST+i),a,b) for i,(a,b) in enumerate(zip(_read_span(pages,heap.oracle.GUEST,0xA000),_read_span(np,heap.oracle.GUEST,0xA000))) if a!=b][:20])
 for (address,width),data in snap['globals'].items():assert _read_span(pages,address,width)==data
 events=[] if result.sections is None else [(e.slot_offset,e.arguments,e.cursor,e.section_end) for e in result.sections.callback_events]
 assert events==nc,(spec['label'],'arguments',events,nc)
 u=lambda address,width=8:int.from_bytes(_read_span(pages,address,width),'little')
 begin,end=u(OUT+0x18),u(OUT+0x20);expected=spec['entries']
 assert (end-begin)//64==len(expected)
 counts=[0]*4
 table_padding=OUT.to_bytes(8,'little')[4:] if spec.get('definitions') else bytes([spec.get('frame_padding',0xA5)])*4
 for index,(module,field,kind,payload) in enumerate(expected):
  record=begin+index*64
  for offset,name in ((0,module),(24,field)):
   assert u(record+offset)&1 and u(record+offset)&~1==(len(name)+16)&~15
   assert u(record+offset+8)==len(name) and _read_span(pages,u(record+offset+16),len(name)+1)==name+b'\0'
  node=u(record+48);assert u(node)==base+(0x3724F0,0x372518,0x372540,0x372568)[kind]
  if kind==0:
   type_index=payload[0];source=u(OUT)+type_index*64
   assert u(record+56,4)==type_index and u(record+60,4)==counts[0] and node!=source
   for offset in (16,40):
    first,last=u(source+offset),u(source+offset+8);copy_first,copy_last=u(node+offset),u(node+offset+8)
    assert last-first==copy_last-copy_first and _read_span(pages,first,last-first)==_read_span(pages,copy_first,copy_last-copy_first)
    if last!=first:assert first!=copy_first
  else:
   assert _read_span(pages,record+56,8)==bytes(8) and u(node+8,4)==kind
   if kind in (1,2):
    raw=snap['import_entries'][index]['descriptor'];start=node+(24 if kind==1 else 16)
    desc=bytearray(raw)
    if not desc[16]:desc[8:16]=(0xFFFFFFFF if kind==1 else 0x1000000000000 if desc[18] else 0x10000).to_bytes(8,'little')
    width=19 if kind==1 else 24
    assert _read_span(pages,start,width)==desc[:width],(spec['label'],'independent node descriptor')
    if kind==1:
     assert u(node+12)==(payload[0]-128)&((1<<64)-1)
     assert _read_span(pages,node+20,4)==table_padding,(spec['label'],'independent table node padding')
   else:assert u(node+12)==(payload[0]-128)&((1<<64)-1) and u(node+20,4)==payload[1]
  counts[kind]+=1
  if kind in (0,3):table_padding=bytes(4)
  elif kind==2:table_padding=(base+0x372540).to_bytes(8,'little')[4:]
 assert [u(STATE+offset,4) for offset in (0x90,0x94,0x98,0x9C)]==counts
 for offset in (0x80,0x98,0xB0,0xC8):assert u(CB+offset)==u(CB+offset+8)
 # Derive every descriptor from the fixture and initial caller padding.
 # A completed type callback saves its zero-extended index in the tail word.
 tail=bytes(5) if spec.get('definitions') else bytes([spec.get('frame_padding',0xA5)])*5
 stack_word=spec.get('frame_padding',0xA5)*0x0101010101010101
 if spec.get('definitions'):stack_word=len(spec['definitions'][-1][0])
 callback_imports=[e for e in result.sections.callback_events if e.slot_offset in (0x28,0x30,0x38,0x40)]
 for item,entry,event in zip(snap['import_entries'],expected,callback_imports):
  _,_,kind,payload=entry
  if kind in (1,2):
   pos=1 if kind==1 else 0;flags=payload[pos];pos+=1
   def number():
    nonlocal pos
    value=shift=0
    while True:
     byte=payload[pos];pos+=1;value|=(byte&127)<<shift;shift+=7
     if byte<128:return value
   minimum=number();maximum=number() if flags&1 else 0
   desc=minimum.to_bytes(8,'little')+maximum.to_bytes(8,'little')+bytes((flags&1,0,(flags>>2)&1 if kind==2 else 0))+tail
   assert item['descriptor']==desc,(spec['label'],'independent descriptor')
   if kind==1:stack_word=STATE-0xF8
  elif kind==3:stack_word=(stack_word&~255)|payload[1]
  if kind in (1,3):assert event.arguments[-1]==stack_word==item['stack_argument']
 return dict(label=spec['label'],image_base_hex=hex(base),entry_stack_address_hex=hex(ENTRY),status=status,
  callback_count=len(nc),**{name+'_count':sum(e[0]==name for e in ne) for name in ('allocate','destroy','delete','free')},
  actual_module_parser_AST_and_cleanup_executed=True,natural_return_and_SP_verified=True,
  complete_guest_0xa000_without_masking_match=True,ordered_effects_and_owner_bytes_match=True,
  parser_exit_callback_cleanup_image_globals_and_arguments_match=True,
  independent_names_nodes_defaults_counts_and_cleanup_match=True,
  independent_descriptor_tail_and_ninth_argument_match=True,
  synthetic_fixture=True,native_input_snapshot_used=False,whole_native_stack_TLS_OS_compared=False)

def fixtures():
 cases=minimal_specs()
 cases[-1]['definitions']=[([0x7F],[0x7E])]
 def add(label,entries,definitions=None,before=b'',after=b'',status=0,**opts):
  body=(types(definitions) if definitions is not None else b'')+section(2,enc(len(entries))+b''.join(import_(*e) for e in entries))
  cases.append(dict(label=label,blob=b'A'*8+before+body+after,status=status,entries=tuple(entries),definitions=definitions,**opts))
 def entry(kind,index=0,length=23,flag=1):
  payload=(b'\0',b'\x70'+bytes([flag])+enc(index+3)+(enc(index+9) if flag&1 else b''),
    bytes([flag])+enc(index+3)+(enc(index+9) if flag&1 else b''),bytes([0x7F-index%5,index&1]))[kind]
  return bytes([97+index%20])*length,bytes([109+index%10])*(length+1),kind,payload
 for kind in (1,2,3):
  for length in (23,24,31,32,63,64,127):
   add(f'names_{kind}_{length}',[entry(kind,length=length)])
 for flag in (0,1,4,5):
  for value in (0,127,128,2**32-1):
   add(f'table_limits_{flag}_{value}',[(b'm'*23,b'f'*24,1,b'\x6b'+bytes([flag])+enc(value)+(enc(value) if flag&1 else b''))])
  for value in (0,127,128,2**32,2**63,(1<<64)-1):
   add(f'memory_limits_{flag}_{value}',[(b'm'*23,b'f'*24,2,bytes([flag])+enc(value)+(enc(value) if flag&1 else b''))])
 for value in (0x7B,0x7C,0x7D,0x7E,0x7F,0x6F,0x70):
  for mutable in (0,1):add(f'global_type_{value}_{mutable}',[(b'm'*23,b'f'*24,3,bytes([value,mutable]))])
 for kinds in itertools.permutations(range(4)):
  add('order_'+''.join(map(str,kinds)),[entry(k,i) for i,k in enumerate(kinds)],definitions=[([0x7F,0x7E],[0x7D])])
 for kind in (1,2,3):
  for count in (1,2,3,4,5,6):
   add(f'growth_{kind}_{count}',[entry(kind,i,23+i) for i in range(count)],frame_padding=(0,0xA5,0xFF)[count%3])
 for definitions in ([([],[])],[([0x7F],[])],[([],[0x7E])],[([0x7F],[0x7E]),([],[])],[([],[])]*4):
  for kind in (1,2,3):
   add('type_caller_'+str(len(cases)),[entry(kind)],definitions=definitions)
 for pad in (0,0xA5,0xFF):
  for warm in (False,True):
   add('surrounding_'+str(len(cases)),[entry(3),entry(1,1),entry(2,2),entry(3,3)],before=section(0,b'\x01x'),after=section(0,b'\x02yz')+section(8,b'\x03')+section(12,b'\x04'),frame_padding=pad,warm_rank=warm)
 for kind in (1,2,3):
  first=entry(kind);last=import_(*entry(kind,1))
  for cut in sorted({0,1,2,3,26,len(last)-3,len(last)-2,len(last)-1}):
   cases.append(dict(label=f'partial_{kind}_{cut}',blob=b'A'*8+section(2,b'\x02'+import_(*first)+last[:cut]),status=1,entries=(first,)))
 for label,after in [('duplicate',section(2,b'\x00')),('rank',section(1,b'\x00')),('unknown',b'\x0d\x00'),('envelope',b'\x08\x80')]:add('after_'+label,[entry(1),entry(3,1),entry(2,2)],after=after,status=1)
 for kind,payloads in ((1,(b'\x7f\x00\x01',b'\x70\x02\x01',b'\x70\x08\x01',b'\x70\x01\x03')),(2,(b'\x02\x01',b'\x08\x01',b'\x01\x03')),(3,(b'\x7a\x00',b'\x7f\x02',b'\x6b\x00'))):
  for i,payload in enumerate(payloads):
   first=entry(kind);bad=(b'n'*23,b'g'*24,kind,payload)
   cases.append(dict(label=f'parse_error_{kind}_{i}',blob=b'A'*8+section(2,b'\x02'+import_(*first)+import_(*bad)),status=1,entries=(first,)))
 rng=random.Random(0x323028)
 for i in range(12):
  kinds=[rng.randrange(1,4) for _ in range(rng.randrange(1,6))]
  add('generated_'+str(i),[entry(k,j,rng.randrange(23,65),rng.choice((0,1,4,5))) for j,k in enumerate(kinds)],frame_padding=rng.randrange(256),padding=rng.randrange(256))
 add('empty_import_section',[])
 return cases

@contextmanager
def layout(delta):
 objects=(sys.modules[__name__],heap,heap.previous);saved=[{n:getattr(obj,n) for n in ('ENTRY','CB','STATE')} for obj in objects]
 native=heap.oracle.native
 def relocated(*args,**kw):return native(*args,extra_registers={arm.UC_ARM64_REG_SP:ENTRY},**kw)
 try:
  for obj,values in zip(objects,saved):
   for name,value in values.items():setattr(obj,name,value+delta)
  heap.oracle.native=relocated
  yield
 finally:
  heap.oracle.native=native
  for obj,values in zip(objects,saved):
   for name,value in values.items():setattr(obj,name,value)

def negatives(args):
 rows=[];base=BASES[0];spec=next(s for s in fixtures() if s['label']=='growth_1_4')
 def reject(label,changes=None,fixture=None,setup=None,fault=None):
  fixture=fixture or spec;pages=prepare(args,base,fixture);offset=0
  def allocate(size):
   nonlocal offset
   pointer=HEAP+offset;offset+=(size+15)&~15;return pointer
  opts=dict(image_base=base,input_address=DATA,input_size=len(fixture['blob']),output_address=OUT,entry_stack_address=ENTRY,varuint_scratch_address=SCRATCH,allocate=allocate,enable_function_imports=True,enable_table_memory_global_imports=True)
  opts.update(changes or {})
  if setup:setup(pages)
  before={k:bytes(v) for k,v in pages.items()};write=alternative._write_span;hits=[]
  def injected(p,address,data):
   if fault(address,data):hits.append(address);raise RefillUnsupported('injected attached other import write failure')
   return write(p,address,data)
  if fault:alternative._write_span=injected
  try:
   try:alternative.run_reader_ast_module(pages,**opts)
   except (RefillUnsupported,ValueError):pass
   else:raise AssertionError('other import guard accepted: '+label)
  finally:alternative._write_span=write
  assert before=={k:bytes(v) for k,v in pages.items()},label
  if fault:assert hits,label
  rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_invalid_path_executed=False))
 for label,changes in [('opt_in_required',dict(enable_table_memory_global_imports=False)),('opt_in_type',dict(enable_table_memory_global_imports=1)),('input_lower_frame',dict(input_address=STATE-0x210)),('output_lower_frame',dict(output_address=STATE-0x208)),('scratch_lower_frame',dict(varuint_scratch_address=STATE-0x200)),('reserved_lower_frame',dict(reserved_regions=((STATE-0x210,STATE-0x208),))),('allocate_lower_frame',dict(allocate=lambda size:STATE-0x210)),('frame_underflow',dict(entry_stack_address=0x430)),('entry_budget',dict(max_entries=3)),('node_budget',dict(max_nodes=2)),('byte_budget',dict(max_vector_bytes=31))]:reject(label,changes)
 for kind,payload in ((1,b'\x70\x00\x03'),(2,b'\x00\x03'),(3,b'\x7f\x01')):
  for which in (0,1):
   for n in (0,1,7,21,22):
    names=[b'm'*23,b'f'*24];names[which]=b'x'*n
    first=minimal_specs()[0]['entries'][0]
    reject(f'short_{kind}_{which}_{n}',fixture=dict(blob=b'A'*8+section(2,b'\x02'+import_(*first)+import_(*names,kind,payload))))
  slot=(0,0x30,0x38,0x40)[kind]
  reject('wrong_binding_'+str(kind),fixture=minimal_specs()[(0,0,2,5)[kind]],setup=lambda p,slot=slot:_write_span(p,base+0x372370+slot,(base+0x31B870).to_bytes(8,'little')))
 for kind,offset in ((1,0x375098),(2,0x3750A0),(3,0x3750A8)):
  reject('wrong_node_GOT_'+str(kind),fixture=minimal_specs()[(0,0,2,5)[kind]],setup=lambda p,offset=offset:_write_span(p,base+offset,(base+0x3724E0).to_bytes(8,'little')))
 reject('function_opt_in_required',dict(enable_function_imports=False),fixture=minimal_specs()[-1])
 short_function=dict(blob=b'A'*8+types([([],[])])+section(2,b'\x01'+import_(b'm',b'f',0,b'\0')))
 reject('combined_inline_function_unverified',dict(enable_inline_function_imports=True),fixture=short_function)
 reject('definitions_unverified',fixture=dict(blob=spec['blob']+section(4,b'\x01\x70\x00\x03')))
 reject('zero_count_type_section_registers_unverified',fixture=dict(blob=b'A'*8+types([])+section(2,b'\x01'+import_(*minimal_specs()[0]['entries'][0]))))
 for call in (2,5,10,15,20,25,30):
  counter=[0];seen=[]
  def alias(size,call=call,counter=counter,seen=seen):
   counter[0]+=1
   if counter[0]==call:return HEAP
   pointer=HEAP+sum((s+15)&~15 for s in seen);seen.append(size);return pointer
  reject('prior_allocation_'+str(call),dict(allocate=alias))
 for label,address,width,fixture in [('descriptor',STATE-0xF8,19,spec),('table_ninth',STATE-0x100,8,spec),('global_low_byte',STATE-0x100,1,minimal_specs()[5]),('import_publish',OUT+0x18,24,spec),('table_cache_publish',CB+0x98,24,spec),('memory_cache_publish',CB+0xB0,24,minimal_specs()[2]),('global_cache_publish',CB+0xC8,24,minimal_specs()[5]),('spare_import_end',OUT+0x20,8,spec),('table_cache_cleanup',CB+0xA0,8,spec),('type_params_save',STATE-0x100,8,minimal_specs()[-1]),('type_index_save',STATE-0xE8,8,minimal_specs()[-1]),('type_output_save',STATE-0x188,8,minimal_specs()[-1]),('global_temporary_clear',STATE-0x188,8,minimal_specs()[5])]:
  reject('write_failure_'+label,fixture=fixture,fault=lambda a,d,address=address,width=width:a==address and len(d)==width)
 with layout(-0xC80):
  assert STATE>>12!=(STATE-0x210)>>12
  reject('missing_lower_page',setup=lambda p:p.pop((STATE-0x210)>>12))
 # New kinds have their own opt-in; they need no function-import permission.
 pages,result,_=model(args,base,minimal_specs()[0],enable_function_imports=False,reserved_regions=((STATE-0x218,STATE-0x210),))
 assert result.status==0
 return rows

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 for name in ('library','libc','output'):parser.add_argument('--'+name,required=True,type=Path)
 args=parser.parse_args()
 assert hashlib.sha256(args.library.read_bytes()).hexdigest()==heap.oracle.LIBRARY_SHA256 and hashlib.sha256(args.libc.read_bytes()).hexdigest()==heap.LIBC_HASH
 specs=fixtures();rows=[];guards=negatives(args)
 for base in BASES:
  for i,spec in enumerate(specs,1):
   rows.append(compare(args,base,spec))
   if i%16==0:print('B attached other imports',hex(base),i,'/',len(specs),'passed',flush=True)
  for delta in (-0xC80,0x100):
   with layout(delta):
    for spec in (specs[0],specs[5],specs[7]):rows.append(compare(args,base,{**spec,'label':spec['label']+'_SP_'+str(delta)}))
 evidence=dict(schema='vm9-alternative-ast-module-other-imports-fresh-v1',evidence_date='2026-10-10',evidence_timezone='Asia/Shanghai',sample_sha256=heap.oracle.LIBRARY_SHA256,matching_libc_sha256=heap.LIBC_HASH,native_Python_module_other_import_controls=len(rows),rollback_negative_controls=len(guards),relocated_entry_stack_controls=12,pre_change_behavior_RED_controls=16,generated_fixture_seed=0x323028,enable_table_memory_global_imports_default=False,minimum_import_name_bytes=23,caller_stack_store_sources_hex=['0x322f18','0x323024','0x31b6d8','0x31b6dc','0x31e894','0x31c2e0','0x31c2fc'],zero_count_type_section_before_other_imports_supported=False,native_input_snapshot_used=False,private_payloads_published=False,whole_native_stack_TLS_OS_compared=False,complete_attached_reader_implemented=False,complete_python_reader_implemented=False,independent_Python_factory_implemented=False,complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False,cases=rows,negative_cases=guards)
 args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
 print('B attached other imports',len(rows),'controls +',len(guards),'rollback checks passed',flush=True)
if __name__=='__main__':main()
