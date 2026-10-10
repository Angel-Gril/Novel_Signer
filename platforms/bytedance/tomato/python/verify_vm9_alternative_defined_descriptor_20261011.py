"""Fresh defined descriptors, optional moves, ordered allocations and failure cleanup.

Inputs come from synthetic records or fresh ELF -> Python reader/parse. Native
snapshots are assertion outputs only; no sample names or payloads are exported.
"""
from pathlib import Path
import argparse,hashlib,json
import verify_vm9_alternative_runtime_builder_20261011 as builder
from vm9_allocator import _read_span,_write_span,RefillUnsupported
from unicorn import arm64_const as arm
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
oracle=builder.oracle;alternative=builder.alternative
HEAP=0x79A00000;HEAP_SIZE=0x400000
FUNCTION=oracle.GUEST+0xB000;NAMES=oracle.GUEST+0xB500;OUTPUT=oracle.GUEST+0xB600;WORDS=0x79600000

def prepare(args,base,records,*,name=b'unit',long_rep=False,warm=False,padding=0xA5,stack_padding=0xA5,slots=()):
 p=builder.catalog.prepare(args,base,warm=warm,pad=padding)
 for address in range(oracle.GUEST+0x10000,oracle.GUEST+0x160000,4096):p[address>>12]=bytearray(4096)
 for start,size,pad in ((HEAP,HEAP_SIZE,padding),(WORDS,0x10000,padding),(0x78000000,0x200000,stack_padding)):
  for address in range(start,start+size,4096):p[address>>12]=bytearray(bytes([pad])*4096)
 _write_span(p,FUNCTION,bytes([padding])*64);_write_span(p,FUNCTION+8,b'\x12\x34\x56\x78\xaa\xbb\xcc\xdd')
 if len(name)>22 or long_rep:
  source=oracle.GUEST+0xC000;capacity=(len(name)+16)&~15
  _write_span(p,source,name+b'\0')
  header=(capacity|1).to_bytes(8,'little')+len(name).to_bytes(8,'little')+source.to_bytes(8,'little')
 else:
  header=bytearray(bytes([padding])*24);header[0]=len(name)*2;header[1:len(name)+2]=name+b'\0'
 _write_span(p,FUNCTION+16,header)
 begin=WORDS if records else 0
 _write_span(p,FUNCTION+40,b''.join(n.to_bytes(8,'little') for n in (begin,begin+len(records)*12,begin+len(records)*12)))
 if records:_write_span(p,WORDS,b''.join(records))
 _write_span(p,NAMES,bytes(32)+(0x3F800000).to_bytes(4,'little')+bytes(4));_write_span(p,OUTPUT,bytes(8))
 for index,offset in slots:_write_span(p,0x79200000+index*8,(0x79200000+offset if offset is not None else 0).to_bytes(8,'little'))
 return p

def driver():
 # x0=function array, x1=empty names, x2=out slots, x3=count, x4=callee.
 words=[0xA9BC7BFD,0xA90153F3,0xA9025BF5,0xF9001BF7,
  0xAA0003F3,0xAA0103F4,0xAA0203F5,0xAA0303F6,0xAA0403F7,
  0xAA1303E0,0xAA1403E1,0xAA1503E8,0xD63F02E0,
  0x91010273,0x910022B5,0xF10006D6,0x54000001|(((-7)&0x7FFFF)<<5),
  0xF9401BF7,0xA94153F3,0xA9425BF5,0xA8C47BFD,0xD65F03C0]
 raw=b''.join(x.to_bytes(4,'little') for x in words);ins=list(Cs(CS_ARCH_ARM64,CS_MODE_ARM).disasm(raw,0))
 assert ins[16].op_str=='#0x24' and ins[12].op_str=='x23'
 return raw

def native(args,base,p,*,function=FUNCTION,names=NAMES,output=OUTPUT,count=1,sp=0x781FF000,tid=137,batch=False):
 saved=oracle.Uc,oracle.GUEST_SIZE;cpus=[];cursor=HEAP;events=[];finalizers=[];sizes={}
 def factory(*a,**kw):
  cpu=saved[0](*a,**kw)
  for start,size in ((0x78000000,0x200000),(0x79000000,0x700000),(HEAP,HEAP_SIZE)):cpu.mem_map(start,size)
  cpus.append(cpu);return cpu
 def snapshot(cpu):return (bytes(cpu.mem_read(output,count*8)),bytes(cpu.mem_read(base+0x3E2710,8)))
 def allocate(cpu,size):
  nonlocal cursor
  address=cursor;cursor+=(max(size,1)+15)&~15;assert cursor<=HEAP+HEAP_SIZE
  sizes[address]=size;events.append(('allocate',address,size,snapshot(cpu)));return address
 def free(cpu):
  address=cpu.reg_read(arm.UC_ARM64_REG_X0);events.append(('free',address,sizes[address],snapshot(cpu)));return 0
 def gettid(cpu):assert cpu.reg_read(arm.UC_ARM64_REG_X0)==0xB2;return tid
 def register(cpu):finalizers.append(tuple(cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(3)));return 0
 entry=0x2DBF00;argv=[function,names];extra={arm.UC_ARM64_REG_SP:sp,arm.UC_ARM64_REG_X8:output}
 if batch:
  entry=oracle.GUEST+0xA000-base;_write_span(p,base+entry,driver());argv=[function,names,output,count,base+0x2DBF00]
 try:
  oracle.Uc=factory;oracle.GUEST_SIZE=0x160000
  oracle.native(args.library,base,entry,argv,p,libc=args.libc,malloc_handler=allocate,
   host_imports={0x347FA0:free,0x348310:gettid,0x347EA0:register},real_mutexes=True,
   extra_registers=extra,instruction_limit=40000000,code_hook_ranges=((base+0x347E00,base+0x348800),))
 finally:oracle.Uc,oracle.GUEST_SIZE=saved
 cpu=cpus[0];assert cpu.reg_read(arm.UC_ARM64_REG_PC)==oracle.STOP and cpu.reg_read(arm.UC_ARM64_REG_SP)==sp
 return cpu,events,finalizers

def compare(args,base,p,*,function=FUNCTION,names=NAMES,output=OUTPUT,count=1,sp=0x781FF000,tid=137,batch=False,label='case'):
 cpu,events,finalizers=native(args,base,p,function=function,names=names,output=output,count=count,sp=sp,tid=tid,batch=batch)
 cursor=HEAP;calls=[];results=[]
 def allocate(size):
  nonlocal cursor
  address=cursor;cursor+=(size+15)&~15;calls.append((address,size));return address
 for index in range(count):
  result=alternative.construct_parser_defined_descriptor(p,image_base=base,function_address=function+index*64,
   names_address=names,output_address=output+index*8,entry_stack_address=sp-(64 if batch else 0),thread_id=tid,allocate=allocate)
  assert result.address==int.from_bytes(cpu.mem_read(output+index*8,8),'little')
  results.append(result)
  for e in result.effects:
   event=events[len([e2 for r in results[:-1] for e2 in r.effects])+list(result.effects).index(e)]
   output_snapshot,global_snapshot=event[3]
   wanted=global_snapshot if e.owner_address==base+0x3E2710 else output_snapshot[index*8:index*8+8]
   assert e.owner_bytes==wanted,(label,'effect owner publication')
 assert calls==[(a,s) for k,a,s,_ in events if k=='allocate']
 effects=[e for r in results for e in r.effects]
 assert [(e.kind,e.address,e.size) for e in effects]==[(k,a,s) for k,a,s,_ in events]
 assert [f for r in results for f in r.finalizers]==finalizers
 for page,data in p.items():
  if 0x78000000<=page<<12<0x78200000:continue
  wanted=bytes(cpu.mem_read(page<<12,4096))
  assert bytes(data)==wanted,(label,hex(page<<12),[(hex((page<<12)+i),a,b) for i,(a,b) in enumerate(zip(data,wanted)) if a!=b][:12])
 temporary=sp-(64 if batch else 0)-0xC0
 expected=bytes(cpu.mem_read(temporary,96));current=_read_span(p,temporary,96)
 diffs=[(hex(i),a,b) for i,(a,b) in enumerate(zip(current,expected)) if a!=b]
 assert not diffs,(label,'consumed temporary frame',diffs)
 return dict(label=label,base=hex(base),entry_sp=hex(sp),thread_id=tid,descriptors=count,instructions=sum(r.instruction_count for r in results),allocations=len(calls),
  frees=sum(e.kind=='free' for e in effects),constructed=sum(bool(r.address) for r in results),natural_return_SP_and_output_match=True,all_guest_heap_image_pages_match=True,
  consumed_temporary96_match=True,ordered_effects_and_finalizers_match=True,native_snapshot_input=False)


def negatives(args):
 base=0x122C0000;graphs,_,traps=builder.graph_cases(args,base)
 initial=prepare(args,base,graphs[:8]);rows=[]
 def put(p,a,n,width=8):_write_span(p,a,n.to_bytes(width,'little'))
 def reject(label,changes=None,mutation=None,fault=None,warm=False):
  p=prepare(args,base,graphs[:8],warm=True) if warm else {k:bytearray(v) for k,v in initial.items()}
  if mutation:mutation(p)
  before={k:bytes(v) for k,v in p.items()};cursor=HEAP
  def allocate(size):
   nonlocal cursor
   address=cursor;cursor+=(size+15)&~15;return address
  params=dict(image_base=base,function_address=FUNCTION,names_address=NAMES,output_address=OUTPUT,
   entry_stack_address=0x781FF000,thread_id=137,allocate=allocate);params.update(changes or {})
  saved=alternative._write_span;hits=[]
  def write(p,a,data):
   if fault(a,data):hits.append(a);raise RefillUnsupported('injected descriptor write failure')
   return saved(p,a,data)
  try:
   if fault:alternative._write_span=write
   try:alternative.construct_parser_defined_descriptor(p,**params)
   except (RefillUnsupported,ValueError):pass
   else:raise AssertionError('accepted descriptor guard '+label)
  finally:alternative._write_span=saved
  assert before=={k:bytes(v) for k,v in p.items()},label
  if fault:assert hits,label
  rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_fault_path_compared=False))
 for label,changes in (
  ('unaligned_SP',dict(entry_stack_address=0x781FF001)),('boolean_SP',dict(entry_stack_address=True)),
  ('zero_thread',dict(thread_id=0)),('boolean_thread',dict(thread_id=True)),
  ('boolean_instruction_bound',dict(max_instructions=True)),('excess_instruction_bound',dict(max_instructions=1048577)),
  ('instruction_budget',dict(max_instructions=7)),('byte_budget',dict(max_vector_bytes=383)),
  ('unmapped_function',dict(function_address=0x76000000)),('unmapped_names',dict(names_address=0x76000000)),
  ('unmapped_output',dict(output_address=0x76000000)),('output_alias_function',dict(output_address=FUNCTION)),
  ('output_alias_words',dict(output_address=WORDS)),('names_alias_function',dict(names_address=FUNCTION)),
  ('reserved_stack',dict(reserved_regions=((0x781FEF40,0x781FEFA0),))),
  ('reserved_heap',dict(reserved_regions=((HEAP,HEAP+HEAP_SIZE),))),
  ('allocation_alias_function',dict(allocate=lambda n:FUNCTION)),('unmapped_allocation',dict(allocate=lambda n:0x76000000))):reject(label,changes)
 reject('nonempty_names',mutation=lambda p:put(p,NAMES+24,1))
 reject('invalid_empty_load_factor',mutation=lambda p:put(p,NAMES+32,0,4))
 reject('invalid_inline_name',mutation=lambda p:put(p,FUNCTION+16,46,1))
 reject('used_vector_stride',mutation=lambda p:put(p,FUNCTION+48,WORDS+95))
 reject('capacity_below_end',mutation=lambda p:put(p,FUNCTION+56,WORDS+84))
 reject('invalid_long_name_capacity',mutation=lambda p:_write_span(p,FUNCTION+16,(17).to_bytes(8,'little')+(16).to_bytes(8,'little')+(WORDS).to_bytes(8,'little')))
 reject('name_alias_words',mutation=lambda p:_write_span(p,FUNCTION+16,(17).to_bytes(8,'little')+(4).to_bytes(8,'little')+(WORDS).to_bytes(8,'little')))
 reject('busy_catalog',mutation=lambda p:put(p,base+0x3E2718,2))
 reject('primary_opcode',mutation=lambda p:put(p,WORDS+4,64,1))
 reject('native_diagnostic_trap',mutation=lambda p:_write_span(p,WORDS,traps[0]))
 reject('variant_move_table',mutation=lambda p:(_write_span(p,WORDS,builder.decoded(0)),put(p,base+0x367078+42*8,base+0x2E35D8)))
 reject('variant_destructor_table',mutation=lambda p:(_write_span(p,WORDS,builder.decoded(0)),put(p,base+0x3657C0+42*8,base+0x2A98CC)))
 reject('nested_catalog_alias_output',mutation=lambda p:put(p,0x79200200,OUTPUT),warm=True)
 reject('vector_write_failure',fault=lambda a,d:a==HEAP+40)
 reject('catalog_publication_failure',fault=lambda a,d:a==base+0x3E2710)
 reject('descriptor_publication_failure',fault=lambda a,d:a==OUTPUT)
 reject('name_temporary_failure',fault=lambda a,d:a==0x781FEF60)
 return rows


def actual_input(args,base):
 converted=builder.converted;v=converted.v;case=v.actual_specs(args.library)[-1]
 with v.arena(case):p,result=converted.prepare(args,base,case)
 assert result.function_count==139 and result.decoded_word_count==54533
 for address in range(HEAP,HEAP+HEAP_SIZE,4096):p[address>>12]=bytearray(b'\xa5'*4096)
 function=int.from_bytes(_read_span(p,oracle.GUEST+0xB108,8),'little')
 _write_span(p,NAMES,bytes(32)+(0x3F800000).to_bytes(4,'little')+bytes(4));_write_span(p,OUTPUT,bytes(121*8))
 return p,function


def main():
 parser=argparse.ArgumentParser(description=__doc__)
 for name in ('library','libc','output'):parser.add_argument('--'+name,type=Path,required=True)
 args=parser.parse_args()
 assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
 assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==builder.catalog.heap.LIBC_HASH
 rows=[];guards=negatives(args)
 for base in (0x122C0000,0x775C205000):
  graphs,leaves,_=builder.graph_cases(args,base)
  cases=[('empty',[],{}),('all_graph_paths',graphs,{}),('warm_graph',graphs,dict(warm=True)),
   ('missing_first',[builder.decoded(15)],{}),('missing_last',graphs[:8]+[builder.decoded(15)],{}),
   ('missing_middle',graphs[:3]+[builder.decoded(15)]+graphs[3:8],{}),
   ('null_primary',graphs[:1],dict(warm=True,slots=[(graphs[0][4],None)]))]
  for length in (0,22,23,31,32):cases.append(('name_length_'+str(length),graphs[:3],dict(name=b'n'*length)))
  for length in (0,4,22):cases.append(('heap_short_'+str(length),graphs[:3],dict(name=b'h'*length,long_rep=True)))
  for pad in (0,0x39,0xFF):cases.append(('padding_'+str(pad),graphs,dict(padding=pad,stack_padding=pad)))
  for start in range(0,len(leaves),64):
   group=leaves[start:start+64]
   records=[b'\xff\xff\x03\x00'+bytes([i])+b'\x01\x80\x7f\x39\x00\x5a\x5a' for i in range(len(group))]
   cases.append(('all_leaf_moves_'+str(start),records,dict(warm=True,slots=[(i,offset) for i,(_,offset) in enumerate(group)])))
  for label,records,options in cases:
   p=prepare(args,base,records,**options);row=compare(args,base,p,label=label)
   row.update(warm=options.get('warm',False),padding=options.get('padding',0xA5));rows.append(row)
  for delta,tid in ((-0xC80,1),(0x100,0x7FFFFFFF)):
   p=prepare(args,base,graphs[:8]);rows.append(compare(args,base,p,sp=0x781FF000+delta,tid=tid,label='SP_'+str(delta)))
  print('Defined descriptor',hex(base),'synthetic passed',flush=True)
  p,function=actual_input(args,base)
  row=compare(args,base,p,function=function,count=121,batch=True,label='complete_actual_ELF')
  assert row['instructions']==54533 and row['allocations']==244 and row['constructed']==121 and row['frees']==0
  row['actual_ELF_complete_module']=True;rows.append(row)
  print('Defined descriptor',hex(base),'121 actual functions/54533 instructions passed',flush=True)
 evidence=dict(schema='vm9-alternative-defined-descriptor-fresh-v1',evidence_date='2026-10-11',evidence_timezone='Asia/Shanghai',
  sample_sha256=oracle.LIBRARY_SHA256,matching_libc_sha256=builder.catalog.heap.LIBC_HASH,
  native_Python_defined_descriptor_controls=sum(r['descriptors'] for r in rows),native_driver_batches=len(rows),
  total_runtime_instructions_constructed=sum(r['instructions'] for r in rows),rollback_negative_controls=len(guards),
  pre_change_behavior_RED_controls=16,actual_ELF_complete_module_batches=2,actual_ELF_function_controls=242,
  actual_ELF_instruction_records=109066,native_input_snapshot_used=False,private_payloads_published=False,
  consumed_temporary_bytes_per_call=96,whole_native_stack_TLS_OS_compared=False,nonempty_name_filter_implemented=False,
  full_root_construction_implemented=False,independent_Python_factory_implemented=False,complete_python_medusa=False,
  fresh_signer_output_verified=False,live_server_matrix_verified=False,cases=rows,negative_cases=guards)
 args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
 print('Defined descriptors',evidence['native_Python_defined_descriptor_controls'],'instructions',evidence['total_runtime_instructions_constructed'],
  'batches',len(rows),'rollback',len(guards),flush=True)

if __name__=='__main__':main()
