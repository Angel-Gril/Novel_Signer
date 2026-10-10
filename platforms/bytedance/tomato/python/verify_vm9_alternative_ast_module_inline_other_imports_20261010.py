"""Fresh attached short-name imports with independently derived caller padding.

Actual module/parser/AST and cleanup execute; synthetic fixtures only.
No native frame snapshot is used as a Python input.
"""
from __future__ import annotations
import argparse,hashlib,itertools,json,random
from pathlib import Path
import verify_vm9_alternative_ast_module_other_imports_20261010 as previous
from vm9_allocator import RefillUnsupported,_read_span,_write_span
alternative=previous.alternative
BASES=previous.BASES
enc,section,types,import_=previous.enc,previous.section,previous.types,previous.import_

def entry(kind,ml=1,fl=2,index=0):
 payload=(b'\0',b'\x70\x01\x03\x09',b'\x01\x03\x09',b'\x7f\x01')[kind]
 return bytes([97+index%20])*ml,bytes([109+index%10])*fl,kind,payload

def spec(label,entries,definitions=None,before=b'',after=b'',status=0,**kw):
 body=(types(definitions) if definitions is not None else b'')+section(2,enc(len(entries))+b''.join(import_(*e) for e in entries))
 return dict(label=label,blob=b'A'*8+before+body+after,status=status,entries=tuple(entries),definitions=definitions,**kw)

def minimal_specs():
 rows=[spec(f'short_kind_{k}',[entry(k)]) for k in (1,2,3)]
 rows += [spec(f'type_short_kind_{k}',[entry(k,0,22)],definitions=[([0x7F,0x7E],[0x7D])]) for k in (1,2,3)]
 rows += [spec('four_short_kinds',[entry(k,22 if k%2 else 0,1 if k%2 else 23,k) for k in range(4)],definitions=[([0x7F],[0x7E])])]
 return rows

def fixtures():
 rows=minimal_specs()
 modes=([([],[])],[([0x7F,0x7E],[])],[([],[0x7D])],[([0x7F],[0x7E])])
 for kind in (1,2,3):
  for mode,definitions in enumerate(modes):
   for n in (0,1,7,8,15,16,21,22,23,24):
    rows.append(spec(f'boundary_{kind}_{mode}_{n}',[entry(kind,n,max(0,22-n))],definitions,frame_padding=(0,0xA5,0xFF)[n%3]))
 for order in itertools.permutations(range(4)):
  for n in (0,23):rows.append(spec('order_'+''.join(map(str,order))+'_'+str(n),[entry(k,n,n,i) for i,k in enumerate(order)],modes[3]))
 for kind in range(4):
  for count in (1,2,3,4,5,6):
   entries=[entry(kind,(i*7)%33,(22-i*3)%25,i) for i in range(count)]
   rows.append(spec(f'growth_{kind}_{count}',entries,modes[3],frame_padding=(0,0xA5,0xFF)[count%3]))
 for first in range(4):
  for last in range(4):
   rows.append(spec(f'transition_{first}_{last}',[entry(first,1,23),entry(last,0,1)],modes[3]))
 for kind in (1,2,3):
  for n in (0,8,22):rows.append(spec(f'no_type_{kind}_{n}',[entry(kind,n,22-n)]))
 for definitions in ([([],[]),([],[])],[([0x7F],[]),([],[])],[([],[0x7E]),([],[])],[([],[]),([0x7D],[])],[([0x7F],[]),([],[0x7E])],[([0x7F],[])]*5):
  rows.append(spec('type_lineage_'+str(len(rows)),[entry(3,0,0),entry(2,0,0),entry(1,0,0),entry(0,0,0)],definitions))
 for warm in (False,True):
  for pad in (0,0xA5,0xFF):
   rows.append(spec('surrounding_'+str(len(rows)),[entry(2,0,7),entry(3,1,0),entry(1,22,1),entry(0,0,0)],modes[3],before=section(0,b'\x01x'),after=section(0,b'\x02yz')+section(8,b'\x03')+section(12,b'\x04'),warm_rank=warm,frame_padding=pad))
 for kind in (1,2,3):
  first=entry(kind,0,1);last=import_(*entry(kind,7,8))
  for cut in (0,1,2,3,9,len(last)-3,len(last)-2,len(last)-1):
   rows.append(dict(label=f'partial_{kind}_{cut}',blob=b'A'*8+types(modes[3])+section(2,b'\x02'+import_(*first)+last[:cut]),status=1,entries=(first,),definitions=modes[3]))
 for label,after in [('duplicate',section(2,b'\x00')),('rank',section(1,b'\x00')),('unknown',b'\x0d\x00'),('envelope',b'\x08\x80')]:
  rows.append(spec('after_'+label,[entry(3,0,0),entry(1,1,1),entry(2,22,22)],modes[3],after=after,status=1))
 for kind in (1,2):
  for flag in (0,4):
   for n in (0,22):
    minimum=2**35 if kind==2 and flag&4 else 128
    payload=(b'\x70' if kind==1 else b'')+bytes([flag])+enc(minimum)
    rows.append(spec(f'default_maximum_{kind}_{flag}_{n}',[(b'm'*n,b'f'*(22-n),kind,payload),entry(1,0,0)],modes[3]))
 for value in (0x7B,0x70):
  for mutable in (0,1):rows.append(spec(f'global_value_{value}_{mutable}',[(b'',b'',3,bytes([value,mutable])),entry(2,0,0),entry(1,0,0)],modes[3]))
 for kind,bad in ((1,(b'\x7f\x00\x03',b'\x70\x02\x03')),(2,(b'\x02\x03',b'\x08\x03')),(3,(b'\x7a\x00',b'\x7f\x02'))):
  for i,payload in enumerate(bad):
   first=entry(kind,0,0);last=(b'x',b'y',kind,payload)
   rows.append(dict(label=f'parse_error_{kind}_{i}',blob=b'A'*8+types(modes[3])+section(2,b'\x02'+import_(*first)+import_(*last)),status=1,entries=(first,),definitions=modes[3]))
 for count in (1,2):rows.append(spec('defined_functions_'+str(count),[entry(3,0,0),entry(1,0,0),entry(2,0,0),entry(0,0,0)],modes[3],after=section(3,enc(count)+bytes(count)),status=1))
 rng=random.Random(0x31F2D4)
 for i in range(16):
  definitions=[([rng.choice((0x7F,0x7E,0x7D)) for _ in range(rng.randrange(4))],[rng.choice((0x7F,0x7E)) for _ in range(rng.randrange(3))]) for _ in range(rng.randrange(1,5))]
  entries=[]
  for j in range(rng.randrange(1,7)):
   k=rng.randrange(4);m=bytes(rng.randrange(256) for _ in range(rng.randrange(33)));f=bytes(rng.randrange(256) for _ in range(rng.randrange(33)))
   entries.append((m,f,k,entry(k)[3]))
  rows.append(spec('generated_'+str(i),entries,definitions,frame_padding=rng.randrange(256),padding=rng.randrange(256)))
 return rows

def model(args,base,case,**options):
 inputs=[];original=alternative.run_reader_ast_callback
 def observe(pages,**kw):
  if kw['slot_offset'] in (0x28,0x30,0x38,0x40):
   u=lambda a:int.from_bytes(_read_span(pages,a,8),'little')
   inputs.append((u(previous.OUT+0x20),u(previous.CB+0x88),u(previous.CB+0x90),u(previous.OUT)))
  return original(pages,**kw)
 alternative.run_reader_ast_callback=observe
 opts=dict(enable_inline_function_imports=True,enable_inline_table_memory_global_imports=True);opts.update(options)
 try:pages,result,state=previous.model(args,base,case,**opts)
 finally:alternative.run_reader_ast_callback=original
 return pages,result,state,inputs

def inline_padding(pages,base,case,events,inputs):
 """Derive complete inline headers from initial bytes and caller scalar inputs.

 Pointer/count inputs come from Python AST fields already compared via guest
 and owner bytes. Neither native headers nor Python frame bytes are read here.
 """
 if any(len(name)>22 for e in case['entries'] for name in e[:2]):return False
 state,cb,out=previous.STATE,previous.CB,previous.OUT
 shadow=bytearray([case.get('frame_padding',0xA5)])*0x210
 def put(offset,data):shadow[offset+0x210:offset+0x210+len(data)]=data
 def word(offset,value):put(offset,value.to_bytes(8,'little'))
 def read(offset,n):return bytes(shadow[offset+0x210:offset+0x210+n])
 for index,(params,results) in enumerate(case.get('definitions') or ()):
  word(-0x188,out);word(-0x1C0,state-0x110);word(-0x1B8,base+0x31B778)
  word(-0x1B0,len(params)*8 if params else state+0x40)
  if params or results:
   word(-0x1D0,state-0x150);word(-0x1E0,state-0x1C0)
   word(-0x1D8,base+(0x31E93C if results else 0x31E8E0))
 begin=int.from_bytes(_read_span(pages,out+0x18,8),'little')
 for i,(e,event,caller) in enumerate(zip(case['entries'],events,inputs)):
  module,field,kind,payload=e;frame=(-0x1E0,-0x210,-0x200,-0x1F0)[kind]
  if kind==1:assert _read_span(pages,int.from_bytes(_read_span(pages,begin+i*64+48,8),'little')+20,4)==read(-0x184,4)
  headers=[]
  for offset,name in zip((0x28,0x10) if kind==0 else (0x20,8),(module,field)):
   header=bytearray(read(frame+offset,24));header[0]=len(name)*2;header[1:len(name)+2]=name+b'\0'
   put(frame+offset,header);headers.append(header)
  for n,header in enumerate(headers):
   put(frame+(0x40 if kind==0 else 0x38)+n*24,header)
   assert _read_span(pages,begin+i*64+n*24,24)==header,(case['label'],'independent entire inline header',i,n)
  prior_end,cache_end,cache_cap,type_begin=caller
  if kind==0:
   index=event.arguments[6]&0xFFFFFFFF
   for off,value in zip(range(-0x210,-0x1D0,8),(state-0x160,base+(0x31BB14 if cache_end==cache_cap else 0x31BAB0),index,cache_end,type_begin+index*64,cb,event.arguments[3],0)):word(off,value)
  elif kind==1:word(-0x1A8,0)
  elif kind==2:
   word(-0x188,base+0x372540);word(-0x208,cb);word(-0x200,0)
  else:
   word(-0x188,0);word(-0x208,state-0x1A0);word(-0x200,prior_end);word(-0x1F8,cb)
 return True

def compare(args,base,case):
 status,np,ne,nc,snap=previous.native(args,base,case)
 pages,result,state,inputs=model(args,base,case)
 assert result.status==status==case['status'],(case['label'],'status')
 assert previous.heap.previous.normalized(result.effects)==ne,(case['label'],'effects/owner bytes')
 assert state==snap['parser'] and _read_span(pages,previous.CB,0x120)==snap['callback_final'],(case['label'],'parser/callback')
 assert _read_span(pages,previous.heap.oracle.GUEST,0xA000)==_read_span(np,previous.heap.oracle.GUEST,0xA000),(case['label'],'unmasked guest bytes')
 for (address,width),data in snap['globals'].items():assert _read_span(pages,address,width)==data
 events=[(e.slot_offset,e.arguments,e.cursor,e.section_end) for e in result.sections.callback_events]
 assert events==nc,(case['label'],'arguments/cursor/limit')
 imports=[e for e in result.sections.callback_events if e.slot_offset in (0x28,0x30,0x38,0x40)]
 u=lambda a,w=8:int.from_bytes(_read_span(pages,a,w),'little')
 begin,end=u(previous.OUT+0x18),u(previous.OUT+0x20);counts=[0]*4
 assert (end-begin)//64==len(case['entries'])==len(inputs)
 tail=bytes(5) if case.get('definitions') else bytes([case.get('frame_padding',0xA5)])*5
 stack_word=len(case['definitions'][-1][0]) if case.get('definitions') else case.get('frame_padding',0xA5)*0x0101010101010101
 for i,(e,item,event) in enumerate(zip(case['entries'],snap['import_entries'],imports)):
  module,field,kind,payload=e;record=begin+i*64
  for offset,name in ((0,module),(24,field)):
   if len(name)<=22:assert u(record+offset,1)==len(name)*2 and _read_span(pages,record+offset+1,len(name)+1)==name+b'\0'
   else:assert u(record+offset)&1 and u(record+offset)&~1==(len(name)+16)&~15 and u(record+offset+8)==len(name) and _read_span(pages,u(record+offset+16),len(name)+1)==name+b'\0'
  node=u(record+48);assert u(node)==base+(0x3724F0,0x372518,0x372540,0x372568)[kind]
  if kind==0:
   index=payload[0];source=u(previous.OUT)+index*64
   assert node!=source and u(record+56,4)==index and u(record+60,4)==counts[0]
   for offset in (16,40):
    first,last=u(source+offset),u(source+offset+8);copy_first,copy_last=u(node+offset),u(node+offset+8)
    assert last-first==copy_last-copy_first and _read_span(pages,first,last-first)==_read_span(pages,copy_first,copy_last-copy_first)
    if last!=first:assert first!=copy_first
  else:
   assert _read_span(pages,record+56,8)==bytes(8) and u(node+8,4)==kind
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
    assert item['descriptor']==desc,(case['label'],'independent descriptor')
    expected=bytearray(desc)
    if not flags&1:expected[8:16]=(0xFFFFFFFF if kind==1 else 0x1000000000000 if flags&4 else 0x10000).to_bytes(8,'little')
    start=node+(24 if kind==1 else 16);width=19 if kind==1 else 24
    assert _read_span(pages,start,width)==expected[:width]
    if kind==1:assert u(node+12)==(payload[0]-128)&((1<<64)-1);stack_word=previous.STATE-0xF8
   else:assert u(node+12)==(payload[0]-128)&((1<<64)-1) and u(node+20,4)==payload[1];stack_word=(stack_word&~255)|payload[1]
  if kind in (1,3):assert event.arguments[-1]==stack_word==item['stack_argument']
  counts[kind]+=1
 assert [u(previous.STATE+offset,4) for offset in (0x90,0x94,0x98,0x9C)]==counts
 for offset in (0x80,0x98,0xB0,0xC8):assert u(previous.CB+offset)==u(previous.CB+offset+8)
 checked=inline_padding(pages,base,case,imports,inputs)
 return dict(label=case['label'],image_base_hex=hex(base),entry_stack_address_hex=hex(previous.ENTRY),status=status,callback_count=len(nc),**{n+'_count':sum(e[0]==n for e in ne) for n in ('allocate','destroy','delete','free')},actual_module_parser_AST_and_cleanup_executed=True,natural_return_and_SP_verified=True,complete_guest_0xa000_without_masking_match=True,ordered_effects_and_owner_bytes_match=True,parser_exit_callback_cleanup_image_globals_and_arguments_match=True,independent_names_nodes_defaults_counts_and_cleanup_match=True,independent_descriptor_tail_and_ninth_argument_match=True,independent_entire_inline_padding_checked=checked,synthetic_fixture=True,native_input_snapshot_used=False,whole_native_stack_TLS_OS_compared=False)

def negatives(args):
 rows=[];base=BASES[0];case=spec('guard_chain',[entry(k,0,0) for k in (0,3,2,1,0,1,2,3)],[([0x7F],[0x7E])])
 def reject(label,changes=None,fixture=None,setup=None,fault=None):
  fixture=fixture or case;pages=previous.prepare(args,base,fixture);offset=0
  def allocate(size):
   nonlocal offset
   p=previous.HEAP+offset;offset+=(size+15)&~15;return p
  opts=dict(image_base=base,input_address=previous.DATA,input_size=len(fixture['blob']),output_address=previous.OUT,entry_stack_address=previous.ENTRY,varuint_scratch_address=previous.SCRATCH,allocate=allocate,enable_function_imports=True,enable_inline_function_imports=True,enable_table_memory_global_imports=True,enable_inline_table_memory_global_imports=True)
  opts.update(changes or {})
  if setup:setup(pages)
  before={k:bytes(v) for k,v in pages.items()};write=alternative._write_span;hits=[]
  def injected(p,address,data):
   if fault(address,data):hits.append(address);raise RefillUnsupported('injected short import write failure')
   return write(p,address,data)
  if fault:alternative._write_span=injected
  try:
   try:alternative.run_reader_ast_module(pages,**opts)
   except (RefillUnsupported,ValueError):pass
   else:raise AssertionError('short import guard accepted: '+label)
  finally:alternative._write_span=write
  assert before=={k:bytes(v) for k,v in pages.items()},label
  if fault:assert hits,label
  rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_invalid_path_executed=False))
 for label,changes in [('new_opt_in_required',dict(enable_inline_table_memory_global_imports=False)),('new_opt_in_type',dict(enable_inline_table_memory_global_imports=1)),('other_opt_in_required',dict(enable_table_memory_global_imports=False)),('function_opt_in_required',dict(enable_function_imports=False,enable_inline_function_imports=False)),('inline_function_opt_in_required',dict(enable_inline_function_imports=False)),('input_frame',dict(input_address=previous.STATE-0x210)),('output_frame',dict(output_address=previous.STATE-0x208)),('scratch_frame',dict(varuint_scratch_address=previous.STATE-0x200)),('reserved_frame',dict(reserved_regions=((previous.STATE-0x210,previous.STATE-0x208),))),('allocate_frame',dict(allocate=lambda size:previous.STATE-0x210)),('node_budget',dict(max_nodes=2)),('entry_budget',dict(max_entries=3)),('byte_budget',dict(max_vector_bytes=31))]:reject(label,changes)
 for kind in (1,2,3):
  fixture=spec('single',[entry(kind,0,0)])
  reject('zero_type_registers_'+str(kind),fixture=spec('zero_type',[entry(kind,0,0)],[]))
  slot=(0,0x30,0x38,0x40)[kind];got=(0,0x375098,0x3750A0,0x3750A8)[kind]
  reject('wrong_binding_'+str(kind),fixture=fixture,setup=lambda p,slot=slot:_write_span(p,base+0x372370+slot,(base+0x31B870).to_bytes(8,'little')))
  reject('wrong_node_GOT_'+str(kind),fixture=fixture,setup=lambda p,got=got:_write_span(p,base+got,(base+0x3724E0).to_bytes(8,'little')))
 for call in (2,5,10,15,20):
  counter=[0];sizes=[]
  def alias(size,counter=counter,sizes=sizes,call=call):
   counter[0]+=1
   if counter[0]==call:return previous.HEAP
   pointer=previous.HEAP+sum((n+15)&~15 for n in sizes);sizes.append(size);return pointer
  reject('prior_allocation_'+str(call),dict(allocate=alias))
 for label,offset,width in [('type_vector_FP_LR',-0x1E0,16),('type_copy_FP_LR',-0x1C0,16),('type_copy_node',-0x1D0,8),('function_helper',-0x210,64),('table_clone_clear',-0x1A8,8),('memory_helper_clear',-0x208,16),('global_helper',-0x208,24),('descriptor',-0xF8,19),('table_ninth',-0x100,8),('global_low_byte',-0x100,1)]:
  reject('write_failure_'+label,fault=lambda a,d,offset=offset,width=width:a==previous.STATE+offset and len(d)==width)
 reject('write_failure_output_publish',fault=lambda a,d:a==previous.OUT+0x18 and len(d)==24)
 reject('write_failure_cache_cleanup',fault=lambda a,d:a==previous.CB+0xA0 and len(d)==8)
 reject('definitions_unverified',fixture={**case,'blob':case['blob']+section(4,b'\x01\x70\x00\x03')})
 with previous.layout(-0xC80):reject('missing_lower_page',setup=lambda p:p.pop((previous.STATE-0x210)>>12))
 # Short other imports work without either function flag.
 _,result,_,_=model(args,base,minimal_specs()[0],enable_function_imports=False,enable_inline_function_imports=False)
 assert result.status==0
 return rows

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 for name in ('library','libc','output'):parser.add_argument('--'+name,required=True,type=Path)
 args=parser.parse_args()
 assert hashlib.sha256(args.library.read_bytes()).hexdigest()==previous.heap.oracle.LIBRARY_SHA256 and hashlib.sha256(args.libc.read_bytes()).hexdigest()==previous.heap.LIBC_HASH
 specs=fixtures();guards=negatives(args);rows=[]
 for base in BASES:
  for i,case in enumerate(specs,1):
   rows.append(compare(args,base,case))
   if i%16==0:print('B attached short imports',hex(base),i,'/',len(specs),'passed',flush=True)
  for delta in (-0xC80,0x100):
   with previous.layout(delta):
    for case in (specs[0],specs[5],specs[6]):rows.append(compare(args,base,{**case,'label':case['label']+'_SP_'+str(delta)}))
 evidence=dict(schema='vm9-alternative-ast-module-inline-other-imports-fresh-v1',evidence_date='2026-10-10',evidence_timezone='Asia/Shanghai',sample_sha256=previous.heap.oracle.LIBRARY_SHA256,matching_libc_sha256=previous.heap.LIBC_HASH,native_Python_module_inline_other_import_controls=len(rows),rollback_negative_controls=len(guards),relocated_entry_stack_controls=12,pre_change_behavior_RED_controls=14,generated_fixture_seed=0x31F2D4,enable_inline_table_memory_global_imports_default=False,requires_table_memory_global_import_opt_in=True,short_function_names_require_both_function_opt_ins=True,zero_count_type_section_before_other_imports_supported=False,independent_entire_inline_padding_controls=sum(r['independent_entire_inline_padding_checked'] for r in rows),caller_stack_store_sources_hex=['0x32a1f4','0x31ed20','0x31eea4','0x31b8b8','0x31ba74','0x31bd0c','0x31bd28','0x32a9d4','0x31c058','0x31f140','0x31f2d0','0x31f2d4'],native_input_snapshot_used=False,private_payloads_published=False,whole_native_stack_TLS_OS_compared=False,complete_attached_reader_implemented=False,complete_python_reader_implemented=False,independent_Python_factory_implemented=False,complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False,cases=rows,negative_cases=guards)
 args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
 print('B attached short imports',len(rows),'controls +',len(guards),'rollback checks passed',flush=True)
if __name__=='__main__':main()
