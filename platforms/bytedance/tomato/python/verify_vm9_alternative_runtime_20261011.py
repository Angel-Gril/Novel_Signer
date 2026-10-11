"""Bounded B runtime execution against original ARM64 and explicit providers.

Fresh actual programs are constructed independently from ELF by Python. Native
pages never seed the model. Imported providers here witness calls and mutate
one synthetic register; real imported bodies and OS startup are not executed.
"""
from pathlib import Path
import argparse,hashlib,json
import verify_vm9_alternative_constructor_20261011 as constructor
from vm9_allocator import _read_span,_write_span,RefillUnsupported
v=constructor.v;alternative=v.alternative
CONTEXT=v.oracle.GUEST+0x20000;DESCRIPTOR=v.oracle.GUEST+0x1000
ROOT=v.oracle.GUEST+0x1200;ARRAY=v.oracle.GUEST+0x1400;IMPORTED=v.oracle.GUEST+0x1800
CHILD=v.oracle.GUEST+0x1900;CODE=v.oracle.GUEST+0x4000;CHILD_CODE=v.oracle.GUEST+0x6000;DATA=v.oracle.GUEST+0x30000
RECIPES={250:(134,66),397:(169,188),401:(134,55,66,55),451:(169,134),624:(55,55,169)}


def put(p,a,value,n=8):v.put(p,a,value&((1<<(n*8))-1),n)
def word(first=4,second=6,immediate=0):return first|(second<<8)|((immediate&65535)<<16)
def context(p,padding=0xA5):
 _write_span(p,CONTEXT,bytes([padding])*0x62D0)
 _write_span(p,CONTEXT,bytes(4));_write_span(p,CONTEXT+8,bytes(8));_write_span(p,CONTEXT+0x6050,bytes(0x280))
 put(p,CONTEXT+0x6058,CONTEXT+0x6010)
 for index,value in ((4,DATA+0x100),(5,0x89ABCDEF01234567),(6,0xFEDCBA9876543210)):
  put(p,CONTEXT+0x6050+index*8,value)


def record(p,address,tag,packed=0,pointer=0):
 _write_span(p,address,bytes(48));put(p,address,packed,4);put(p,address+8,pointer);put(p,address+40,tag)


def descriptor(p,address,begin,count):
 _write_span(p,address,bytes(64));v.vector(p,address+8,begin,count*48);put(p,address+56,2)


def synthetic(args,base,label,*,padding=0xA5):
 p=constructor.prepare(args,base,padding,0);context(p,padding)
 _write_span(p,ROOT,bytes(96));v.vector(p,ROOT,ARRAY,24);put(p,ROOT+72,DATA)
 for index,address in enumerate((DESCRIPTOR,IMPORTED,CHILD)):put(p,ARRAY+index*8,address)
 _write_span(p,IMPORTED,bytes(64));put(p,IMPORTED,base+0x29E908)
 selected=DESCRIPTOR
 if label=='imported':selected=IMPORTED;put(p,CONTEXT+0x6068,0xFEDCBA9876543210);count=0
 elif label=='return':record(p,CODE,189,6);count=1
 elif label.startswith('fused_'):
  tag=int(label.split('_')[1]);sequence=RECIPES[tag];count=len(sequence)+2
  record(p,CODE,tag)
  for i,operation in enumerate(sequence):
   a=CODE+(i+1)*48
   packed=1 if operation==188 else word(5,0,8) if operation==169 else word(4,5 if operation==55 else 6,8*i)
   record(p,a,0xFFFFFFFF,packed,ROOT if operation==188 else 0)
   put(p,CODE+(len(sequence)-i-1)*8,a)
  record(p,CODE+(count-1)*48,189)
 elif label=='nested':
  record(p,CODE,188,2,ROOT);record(p,CODE+48,189);count=2
  record(p,CHILD_CODE,66,word(4,7,-8));record(p,CHILD_CODE+48,189,3);descriptor(p,CHILD,CHILD_CODE,2)
 elif label=='call':record(p,CODE,188,1,ROOT);record(p,CODE+48,189);count=2
 else:
  tag,imm=(int(value) for value in label.split('_'))
  packed=word(5,0,7) if tag==169 else word(4,5 if tag==55 else 6,imm)
  record(p,CODE,tag,packed,ROOT+72 if tag==102 else 0);record(p,CODE+48,189);count=2
 if count:descriptor(p,DESCRIPTOR,CODE,count)
 return p,selected,{base+0x29E908}


def native(args,base,p,selected,functions,*,sp=v.SP,mutate=False,entry=0x2A9718):
 old=v.oracle.Uc,v.oracle.GUEST_SIZE;cpus=[];calls=[]
 def make(*a,**kw):
  cpu=old[0](*a,**kw);cpu.mem_map(0x78000000,0x200000);cpu.mem_map(constructor.ARENA,constructor.ARENA_SIZE);cpus.append(cpu);return cpu
 def imported(function):
  def invoke(cpu):
   assert cpu.reg_read(v.arm.UC_ARM64_REG_X0)==CONTEXT
   active=int.from_bytes(cpu.mem_read(CONTEXT+8,8),'little')
   calls.append((function,CONTEXT,cpu.reg_read(v.arm.UC_ARM64_REG_SP),bytes(cpu.mem_read(CONTEXT,0x62D0)),bytes(cpu.mem_read(active,16)) if active else b''))
   if mutate:cpu.mem_write(CONTEXT+0x60A0,(0x13579BDF).to_bytes(8,'little'))
   return 0
  return invoke
 try:
  v.oracle.Uc=make;v.oracle.GUEST_SIZE=0x160000
  v.oracle.native(args.library,base,entry,[selected,CONTEXT] if entry==0x2A9718 else [CONTEXT],p,libc=args.libc,
   host_imports={function-base:imported(function) for function in functions},
   extra_registers={v.arm.UC_ARM64_REG_SP:sp},instruction_limit=1000000,
   code_hook_ranges=(*tuple((a,a) for a in functions),(base+0x347E00,base+0x348800)))
 finally:v.oracle.Uc,v.oracle.GUEST_SIZE=old
 assert cpus[0].reg_read(v.arm.UC_ARM64_REG_SP)==sp
 return cpus[0],calls


def compare(args,base,p,selected,functions,label,*,sp=v.SP,mutate=False):
 cpu,expected=native(args,base,p,selected,functions,sp=sp,mutate=mutate);calls=[]
 def provider(p,function,ctx,entry_sp):
  active=v.u(p,ctx+8);calls.append((function,ctx,entry_sp,_read_span(p,ctx,0x62D0),_read_span(p,active,16) if active else b''))
  if mutate:put(p,ctx+0x60A0,0x13579BDF)
 result=alternative.execute_runtime_descriptor(p,image_base=base,descriptor_address=selected,context_address=CONTEXT,
  entry_stack_address=sp,call_import=provider)
 assert calls==expected,(label,'imported caller context/frame/SP')
 assert result.imported_calls==tuple(row[:3] for row in calls)
 assert result.status_word==int.from_bytes(cpu.mem_read(CONTEXT,4),'little')
 for page,data in p.items():
  if 0x78000000<=page<<12<0x78200000:continue
  actual=bytes(cpu.mem_read(page<<12,4096))
  assert bytes(data)==actual,(label,hex(page<<12),[(hex((page<<12)+i),x,y) for i,(x,y) in enumerate(zip(data,actual)) if x!=y][:12])
 return dict(base=hex(base),label=label,dispatches=result.steps,imported_calls=len(calls),natural_return_SP_and_status_match=True,
  all_guest_heap_image_pages_match=True,imported_context_active_frame_and_SP_match=True,native_snapshot_input=False)


def initializers(args):
 rows=[]
 for base in (0x122C0000,0x775C205000):
  for pad in (0,0x39,0xFF):
   p=constructor.prepare(args,base);_write_span(p,CONTEXT,bytes([pad])*0x62D0)
   cpu,_=native(args,base,p,0,set(),entry=0x2A9754)
   assert alternative.initialize_runtime_context(p,image_base=base,context_address=CONTEXT)==CONTEXT
   assert _read_span(p,CONTEXT,0x62D0)==bytes(cpu.mem_read(CONTEXT,0x62D0))
   assert cpu.reg_read(v.arm.UC_ARM64_REG_X0)==CONTEXT
   rows.append(dict(base=hex(base),padding=pad,all_context_bytes_return_and_SP_match=True,native_snapshot_input=False))
 return rows


def negatives(args):
 base=0x122C0000;initial,selected,_=synthetic(args,base,'call');rows=[]
 def reject(label,changes=None,mutation=None,fault=None,initializer=False):
  p={k:bytearray(data) for k,data in initial.items()}
  if mutation:mutation(p)
  before={k:bytes(data) for k,data in p.items()};saved=alternative._write_span;hits=[]
  def write(p,a,d):
   if fault(a,d):hits.append(a);raise RefillUnsupported('injected runtime write failure')
   return saved(p,a,d)
  kw=dict(image_base=base,context_address=CONTEXT)
  if not initializer:kw.update(descriptor_address=selected,entry_stack_address=v.SP,call_import=lambda *a:None)
  kw.update(changes or {})
  try:
   if fault:alternative._write_span=write
   try:(alternative.initialize_runtime_context if initializer else alternative.execute_runtime_descriptor)(p,**kw)
   except (RefillUnsupported,ValueError):pass
   else:raise AssertionError('accepted runtime guard '+label)
  finally:alternative._write_span=saved
  assert before=={k:bytes(data) for k,data in p.items()},label
  if fault:assert hits,label
  rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_fault_path_compared=False))
 for label,changes in (
  ('unaligned_SP',dict(entry_stack_address=v.SP+1)),('boolean_SP',dict(entry_stack_address=True)),
  ('zero_steps',dict(max_steps=0)),('boolean_steps',dict(max_steps=True)),('step_exhaustion',dict(max_steps=1)),
  ('depth_exhaustion',dict(max_depth=1)),('depth_bound',dict(max_depth=257)),('instruction_bound',dict(max_instructions=1)),
  ('byte_bound',dict(max_vector_bytes=47)),('no_provider',dict(call_import=None)),('invalid_provider',dict(call_import=7)),
  ('frame_alias',dict(entry_stack_address=CONTEXT+0x100)),('context_alias',dict(context_address=DESCRIPTOR))):reject(label,changes)
 for label,a,value,n in (
  ('kind1',DESCRIPTOR+56,1,8),('empty_vector',DESCRIPTOR+16,CODE,8),('bad_opcode',CODE+40,190,8),
  ('call_index',CODE,99,4),('null_import',IMPORTED,0,8),('software_stack',CONTEXT+0x6058,0,8),
  ('invalid_vector_end',DESCRIPTOR+16,CODE+49,8)):
  reject(label,mutation=lambda p,a=a,value=value,n=n:put(p,a,value,n))
 reject('provider_frame_change',dict(call_import=lambda p,f,c,s:put(p,c+8,DATA)))
 def provider_failure(p,f,c,s):put(p,c+0x60A0,1);raise RefillUnsupported('provider rejected after staged write')
 reject('provider_failure',dict(call_import=provider_failure))
 for label,a in (('caller_box',v.SP-0x28),('active_frame',CONTEXT+8),('call_link',CONTEXT+0x6068)):
  reject(label,fault=lambda address,data,target=a:address==target)
 reject('initializer_alias',dict(context_address=base+0x1000),initializer=True)
 reject('initializer_failure',fault=lambda a,d:a==CONTEXT+0x6058,initializer=True)
 return rows


def main():
 parser=argparse.ArgumentParser(description=__doc__)
 for name in ('library','libc','output'):parser.add_argument('--'+name,type=Path,required=True)
 args=parser.parse_args()
 assert hashlib.sha256(args.library.read_bytes()).hexdigest()==v.oracle.LIBRARY_SHA256
 assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==v.defined.builder.catalog.heap.LIBC_HASH
 guards=negatives(args);initialized=initializers(args);rows=[]
 labels=['return','imported','call','nested','169_0']+[f'{tag}_{imm}' for tag in (55,66,102,134) for imm in (-16,0,15)]+['fused_'+str(tag) for tag in RECIPES]
 for base in (0x122C0000,0x775C205000):
  for label in labels:
   p,selected,functions=synthetic(args,base,label);rows.append(compare(args,base,p,selected,functions,label,mutate=True))
  p,selected,functions=synthetic(args,base,'fused_397',padding=0x39)
  rows.append(compare(args,base,p,selected,functions,'relocated_SP_padded',sp=v.SP-0xC80,mutate=True))
  print('Runtime',hex(base),'synthetic execution passed',flush=True)
  p=constructor.prepare(args,base);built=constructor.model(p,base);root=built.address
  selected=v.u(p,base+0x3E1EB8);context(p)
  functions={v.u(p,v.u(p,v.u(p,root)+i*8)) for i in range(v.u(p,root+24))}
  row=compare(args,base,p,selected,functions,'complete_actual_initial_descriptor')
  assert row['dispatches']==19 and row['imported_calls']==2;row['actual_ELF_initial_descriptor']=True;rows.append(row)
  print('Runtime',hex(base),'actual initial descriptor passed',flush=True)
 evidence=dict(schema='vm9-alternative-runtime-fresh-v1',evidence_date='2026-10-11',evidence_timezone='Asia/Shanghai',
  sample_sha256=v.oracle.LIBRARY_SHA256,matching_libc_sha256=v.defined.builder.catalog.heap.LIBC_HASH,
  native_Python_runtime_controls=len(rows),native_Python_context_initialization_controls=len(initialized),
  rollback_negative_controls=len(guards),pre_change_behavior_RED_controls=7,actual_ELF_initial_descriptor_controls=2,
  native_input_snapshot_used=False,private_names_or_payloads_published=False,whole_native_stack_TLS_OS_compared=False,
  imported_callback_bodies_executed=False,explicit_pure_imported_providers=True,bounded_B_runtime_execution_verified=True,
  complete_python_bootstrap_controls=0,complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False,
  cases=rows,context_initializers=initialized,negative_cases=guards)
 args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
 print('Runtime controls',len(rows),'initializers',len(initialized),'guards',len(guards),flush=True)


if __name__=='__main__':main()
