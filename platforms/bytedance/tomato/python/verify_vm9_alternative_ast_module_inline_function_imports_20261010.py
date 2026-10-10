"""Fresh attached function imports with independently recovered inline padding.

Real module/parser/AST and cleanup execute; no captured stack feeds the model.
"""
from __future__ import annotations
import argparse,hashlib,json,random,sys
from contextlib import contextmanager
from pathlib import Path
from unicorn import arm64_const as arm
import verify_vm9_alternative_ast_module_function_imports_20261010 as heap
from vm9_allocator import RefillUnsupported,_read_span,_write_span
alternative=heap.alternative
BASES=heap.BASES
ENTRY,CB,STATE,OUT,DATA,HEAP,SCRATCH=heap.ENTRY,heap.CB,heap.STATE,heap.OUT,heap.DATA,heap.HEAP,heap.SCRATCH
enc,section,types,import_=heap.enc,heap.section,heap.types,heap.import_
def fixtures():
 cases=[]
 def add(label,names,indexes=None,definitions=None,before=b'',after=b'',status=0,**options):
  definitions=definitions if definitions is not None else [([0x7F,0x7E],[0x7D]),([],[])]
  indexes=indexes if indexes is not None else tuple(i%len(definitions) for i in range(len(names)))
  blob=b'A'*8+before+types(definitions)+section(2,enc(len(names))+b''.join(import_(m,f,i) for (m,f),i in zip(names,indexes)))+after
  cases.append(dict(label=label,blob=blob,status=status,expected_names=tuple(names),type_indexes=tuple(indexes),definitions=definitions,**options))
 for label,names,indexes in [('inline_empty',((b'',b''),),(0,)),('inline_one',((b'm',b'f'),),(0,)),('inline_seven',((b'm'*7,b'f'*7),),(0,)),('inline_22',((b'm'*22,b'f'*22),),(0,)),('inline_growth',((b'm0',b'f0'),(b'm1',b'f1'),(b'm2',b'f2'),(b'm3',b'f3')),(0,1,0,1)),('mixed_names',((b'm'*32,b'f'),(b'n',b'g'*32)),(0,1))]:add(label,names,indexes)
 for mode,definitions in [('empty',[([],[])]),('params',[([0x7F,0x7E],[])]),('results',[([],[0x7F])]),('rich',[([0x7F],[0x7E])])]:
  for length in (0,1,7,8,15,16,21,22,23,24,32):
   for pad in (0,0xA5,0xFF):
    add(f'boundary_{mode}_{length}_{pad}',((bytes([0x6D])*length,bytes([0x66])*max(0,22-length)),),definitions=definitions,frame_padding=pad)
 for count in (1,2,3,4,5,6):
  for mode in ('shrink','grow','alternate'):
   lengths=[(22-i*3 if mode=='shrink' else i*3 if mode=='grow' else 32 if i%2 else i) for i in range(count)]
   names=tuple((bytes([0x60+i])*n,bytes([0x70+i])*((n+7)%33)) for i,n in enumerate(lengths))
   for defined in (False,True):
    add(f'chain_{count}_{mode}_{defined}',names,after=section(3,b'\x02\x01\x00') if defined else b'',status=int(defined),defined_count=2 if defined else 0)
 for definitions in ([([],[]),([],[])],[([0x7F],[]),([],[])],[([],[0x7E]),([],[])],[([],[]),([0x7D],[])],[([0x7F],[]),([],[0x7E])],[([0x7F,0x7E],[]),([0x7D],[])], [([0x7F],[]),([0x7E,0x7D,0x7C],[])], [([0x7F],[])]*5):
  add('types_lineage_'+str(len(cases)),((b'm',b'f'),(b'n'*7,b'g'*15)),definitions=definitions)
 for warm in (False,True):
  for before in (b'',section(0,b'\x01x')):
   for after in (b'',section(0,b'\x01x')+section(8,b'\x02')+section(12,b'\x03')):
    add('surrounding_'+str(len(cases)),((b'm',b'f'),(b'n'*22,b'g')),before=before,after=after,warm_rank=warm)
 for cut in (0,1,2,3,5,8,15,23):
  names=((b'm',b'f'),(b'n'*7,b'g'*7));prefix=b'A'*8+types([([0x7F,0x7E],[0x7D]),([],[])])
  final=import_(b'x'*22,b'y'*22,0)
  blob=prefix+section(2,b'\x03'+b''.join(import_(m,f,i) for (m,f),i in zip(names,(0,1)))+final[:cut])
  cases.append(dict(label='partial_'+str(cut),blob=blob,status=1,expected_names=names,type_indexes=(0,1)))
 for label,after in [('duplicate',section(2,b'\x00')),('rank',section(1,b'\x00')),('unknown',b'\x0d\x00'),('envelope',b'\x08\x80')]:add('after_'+label,((b'm',b'f'),),after=after,status=1)
 rng=random.Random(0x31B8D0)
 for index in range(16):
  definitions=[([rng.choice((0x7F,0x7E,0x7D,0x7C)) for _ in range(rng.randrange(4))],[rng.choice((0x7F,0x7E,0x7D,0x7C)) for _ in range(rng.randrange(3))]) for _ in range(rng.randrange(1,5))]
  names=tuple((bytes(rng.randrange(256) for _ in range(rng.randrange(33))),bytes(rng.randrange(256) for _ in range(rng.randrange(33)))) for _ in range(rng.randrange(1,5)))
  add('generated_'+str(index),names,definitions=definitions,padding=rng.randrange(256),frame_padding=rng.randrange(256))
 return cases

def compare(args,base,spec):
 status,np,ne,nc,snap=heap.native(args,base,spec)
 pages,result,state_bytes=heap.model(args,base,spec,enable_inline_function_imports=True)
 assert result.status==status==spec['status'],(spec['label'],'status')
 assert heap.previous.normalized(result.effects)==ne,(spec['label'],'effects/owner bytes')
 assert state_bytes==snap['parser'],(spec['label'],'parser state')
 assert _read_span(pages,CB,0x120)==snap['callback_final'],(spec['label'],'callback final')
 assert _read_span(pages,heap.oracle.GUEST,0xA000)==_read_span(np,heap.oracle.GUEST,0xA000),(spec['label'],'guest bytes')
 for (address,width),data in snap['globals'].items():assert _read_span(pages,address,width)==data
 events=[] if result.sections is None else [(e.slot_offset,e.arguments,e.cursor,e.section_end) for e in result.sections.callback_events]
 assert events==nc,(spec['label'],'arguments')
 u=lambda address,width=8:int.from_bytes(_read_span(pages,address,width),'little')
 begin,end=u(OUT+0x18),u(OUT+0x20);expected=spec['expected_names'];assert (end-begin)//64==len(expected)
 assert u(STATE+0x90,4)==len(expected)
 for i,(module,field) in enumerate(expected):
  record=begin+i*64
  for offset,name in ((0,module),(24,field)):
   header=_read_span(pages,record+offset,24)
   if len(name)<=22:
    assert header[0]==len(name)*2 and header[1:len(name)+2]==name+b'\0'
   else:
    assert u(record+offset)&1 and u(record+offset)&~1==(len(name)+16)&~15
    assert u(record+offset+8)==len(name) and _read_span(pages,u(record+offset+16),len(name)+1)==name+b'\0'
  source=u(OUT)+spec['type_indexes'][i]*64;node=u(record+48)
  assert node!=source and u(node)==base+0x3724F0
  assert u(record+56,4)==spec['type_indexes'][i] and u(record+60,4)==i
  for offset in (16,40):
   first,last=u(source+offset),u(source+offset+8);cloned_first,cloned_last=u(node+offset),u(node+offset+8)
   assert last-first==cloned_last-cloned_first and _read_span(pages,first,last-first)==_read_span(pages,cloned_first,cloned_last-cloned_first)
   if last!=first:assert cloned_first!=first
 assert (u(OUT+0x38)-u(OUT+0x30))//144==spec.get('defined_count',0) and u(CB+0x80)==u(CB+0x88)
 # For entirely inline chains, derive every retained byte independently from
 # the caller frame, type counts and earlier names. No oracle header is input.
 padding_checked=bool(spec.get('definitions') and all(len(n)<=22 for names in expected for n in names))
 if padding_checked:
  module=bytearray([spec.get('frame_padding',0xA5)])*24;field=module[:]
  for params,results in spec['definitions']:
   field[16:24]=(STATE-0x110).to_bytes(8,'little')
   module[:8]=(base+0x31B778).to_bytes(8,'little')
   module[8:16]=(len(params)*8 if params else STATE+0x40).to_bytes(8,'little')
   if params or results:field[:8]=(STATE-0x150).to_bytes(8,'little')
  for i,names in enumerate(expected):
   for offset,name,header in ((0,names[0],module),(24,names[1],field)):
    header[0]=len(name)*2;header[1:len(name)+2]=name+b'\0'
    assert _read_span(pages,begin+i*64+offset,24)==header,(spec['label'],'independent inline padding')
 return dict(label=spec['label'],image_base_hex=hex(base),entry_stack_address_hex=hex(ENTRY),status=status,callback_count=len(nc),allocation_count=sum(e[0]=='allocate' for e in ne),destructor_count=sum(e[0]=='destroy' for e in ne),delete_count=sum(e[0]=='delete' for e in ne),free_count=sum(e[0]=='free' for e in ne),actual_module_parser_AST_and_cleanup_executed=True,natural_return_and_SP_verified=True,complete_guest_0xa000_without_masking_match=True,ordered_effects_and_owner_bytes_match=True,parser_exit_callback_cleanup_image_globals_and_arguments_match=True,independent_names_cloned_nodes_indexes_partial_output_and_cleanup_match=True,independent_entire_inline_padding_checked=padding_checked,synthetic_fixture=True,native_input_snapshot_used=False,whole_native_stack_TLS_OS_compared=False)

@contextmanager
def layout(delta):
 objects=(sys.modules[__name__],heap,heap.previous);saved=[{n:getattr(obj,n) for n in ('ENTRY','CB','STATE')} for obj in objects]
 native=heap.oracle.native
 def relocated(*args,**kw):
  assert 'extra_registers' not in kw
  return native(*args,extra_registers={arm.UC_ARM64_REG_SP:ENTRY},**kw)
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
 rows=heap.negatives(args);base=BASES[0];spec=fixtures()[4]
 def reject(label,changes=None,fixture=None,setup=None,fault=None):
  fixture=fixture or spec;pages=heap.prepare(args,base,fixture);offset=0
  def allocate(size):
   nonlocal offset
   pointer=HEAP+offset;offset+=(size+15)&~15;return pointer
  options=dict(image_base=base,input_address=DATA,input_size=len(fixture['blob']),output_address=OUT,entry_stack_address=ENTRY,varuint_scratch_address=SCRATCH,allocate=allocate,enable_function_imports=True,enable_inline_function_imports=True)
  options.update(changes or {})
  if setup:setup(pages)
  before={k:bytes(v) for k,v in pages.items()};write=alternative._write_span;hits=[]
  def injected(p,address,data):
   if fault(address,data):hits.append(address);raise RefillUnsupported('injected inline import write failure')
   return write(p,address,data)
  if fault:alternative._write_span=injected
  try:
   try:alternative.run_reader_ast_module(pages,**options)
   except (RefillUnsupported,ValueError):pass
   else:raise AssertionError('inline import guard accepted: '+label)
  finally:alternative._write_span=write
  assert before=={k:bytes(v) for k,v in pages.items()},label
  if fault:assert hits,label
  rows.append(dict(label='inline_'+label,rejected=True,all_pages_unchanged=True,native_invalid_path_executed=False))
 for label,changes in [('opt_in_required',dict(enable_inline_function_imports=False)),('opt_in_type',dict(enable_inline_function_imports=1)),('imports_required',dict(enable_function_imports=False)),('node_budget',dict(max_nodes=2)),('byte_budget',dict(max_vector_bytes=31)),('input_frame_alias',dict(input_address=STATE-0x1B0)),('output_frame_alias',dict(output_address=STATE-0x1D0)),('scratch_frame_alias',dict(varuint_scratch_address=STATE-0x1C8)),('allocation_frame_alias',dict(allocate=lambda size:STATE-0x1E0)),('entry_budget',dict(max_entries=3))]:reject(label,changes)
 for label,address,width in [('type_FP_LR',STATE-0x1C0,16),('type_x23',STATE-0x1B0,8),('allocator_x19',STATE-0x1D0,8),('original_module',STATE-0x1B8,24),('original_field',STATE-0x1D0,24),('spare_import_end',OUT+0x20,8)]:
  reject('write_failure_'+label,fault=lambda a,d,address=address,width=width:a==address and len(d)==width)
 for kind,payload in ((1,b'\x70\x00\x01'),(2,b'\x00\x01'),(3,b'\x7f\x01')):
  second=b'\x01n\x01g'+bytes([kind])+payload
  reject('other_kind_'+str(kind),fixture=dict(blob=b'A'*8+types([([],[])])+section(2,b'\x02'+import_(b'm',b'f',0)+second)))
 reject('type_index',fixture=dict(blob=b'A'*8+types([([],[])])+section(2,b'\x01'+import_(b'm',b'f',1))))
 with layout(-0xC80):
  assert STATE>>12!=(STATE-0x1E0)>>12
  reject('missing_separate_lower_page',setup=lambda p:p.pop((STATE-0x1E0)>>12))
 return rows

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 for name in ('library','libc','output'):parser.add_argument('--'+name,required=True,type=Path)
 args=parser.parse_args();assert hashlib.sha256(args.library.read_bytes()).hexdigest()==heap.oracle.LIBRARY_SHA256 and hashlib.sha256(args.libc.read_bytes()).hexdigest()==heap.LIBC_HASH
 rows=[];specs=fixtures();guards=negatives(args)
 for base in BASES:
  for index,spec in enumerate(specs,1):
   rows.append(compare(args,base,spec))
   if index%24==0:print('B inline function imports',hex(base),index,'/',len(specs),'passed',flush=True)
  for delta in (-0xC80,0x100):
   with layout(delta):
    for spec in (specs[0],specs[4],specs[5]):rows.append(compare(args,base,{**spec,'label':spec['label']+'_SP_'+str(delta)}))
 evidence=dict(schema='vm9-alternative-ast-module-inline-function-imports-fresh-v1',evidence_date='2026-10-10',evidence_timezone='Asia/Shanghai',sample_sha256=heap.oracle.LIBRARY_SHA256,matching_libc_sha256=heap.LIBC_HASH,native_Python_module_inline_function_import_controls=len(rows),rollback_negative_controls=len(guards),independent_entire_inline_padding_controls=sum(r['independent_entire_inline_padding_checked'] for r in rows),relocated_entry_stack_controls=12,pre_change_behavior_RED_controls=12,generated_fixture_seed=0x31B8D0,enable_inline_function_imports_default=False,inline_stack_store_sources_hex=['0x31e888','0x31e88c','0x32a1f8'],native_input_snapshot_used=False,private_payloads_published=False,whole_native_stack_TLS_OS_compared=False,complete_attached_reader_implemented=False,complete_python_reader_implemented=False,independent_Python_factory_implemented=False,complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False,cases=rows,negative_cases=guards)
 args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8');print('B inline function imports',len(rows),'controls +',len(guards),'rollback checks passed',flush=True)
if __name__=='__main__':main()
