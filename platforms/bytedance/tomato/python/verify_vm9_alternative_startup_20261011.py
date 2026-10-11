"""Fresh B startup and actual imported callback bodies against original ARM64.

Workers are queued through explicit pure services and execute in a later stage.
All original input comes from ELF and independent Python construction. Physical
native stack saves and thread output scratch are outside the compared result.
"""
from pathlib import Path
import argparse,hashlib,json
import verify_vm9_alternative_constructor_20261011 as c
import vm9_startup as shared
from vm9_allocator import _read_span,_write_span,RefillUnsupported
from elftools.elf.elffile import ELFFile
v=c.v;alternative=c.alternative
TLS=v.oracle.GUEST+0xA000;LIBC=0x51000000;ARENA=0x79800000


def setup(p,args,tid=137):
 p.update(v.oracle.image_pages(args.libc,LIBC))
 with args.libc.open('rb') as stream:
  elf=ELFFile(stream)
  for section in elf.iter_sections():
   if section['sh_type']!='SHT_RELA':continue
   symbols=elf.get_section(section['sh_link'])
   for rel in section.iter_relocations():
    if rel['r_info_type'] not in (257,1025,1026):continue
    symbol=symbols.get_symbol(rel['r_info_sym'])
    if symbol['st_shndx']!='SHN_UNDEF':v.put(p,LIBC+rel['r_offset'],LIBC+symbol['st_value']+rel['r_addend'])
 _write_span(p,TLS,bytes(0xB00));v.put(p,TLS+8,TLS+0x200)
 v.put(p,TLS+0x210,tid,4);v.put(p,TLS+0x28,0x183756A9BCDE4200)
 return p


class Services:
 def __init__(self):self.cursor=ARENA;self.effects=[];self.threads=[]
 def allocate(self,p,size):
  a=self.cursor;self.cursor+=(max(size,1)+15)&~15
  assert self.cursor<ARENA+0x10000
  _read_span(p,a,size);self.effects.append(('allocate',size,a));return a
 def free(self,p,a):self.effects.append(('free',a))
 def register(self,p,*args):self.effects.append(('register',*args));return 0
 def create(self,p,out,attr,start,arg):
  assert attr==0;handle=v.oracle.GUEST+0xC800+len(self.threads)*0x100
  v.put(p,out,handle);self.threads.append((handle,start,arg))
  self.effects.append(('thread',attr,start,arg,handle));return 0
 def wake(self,p,*args):self.effects.append(('wake',*args));return 0
 def signal(self,p,a):return shared.signal_condition_no_waiters(p,condition_address=a,wake=self.wake)


def native(args,p,base,sp=v.SP,tid=137,entry=0x2A0028,context=None):
 with args.libc.open('rb') as stream:
  elf=ELFFile(stream)
  exports={s.name:LIBC+s['st_value'] for section in elf.iter_sections() if section['sh_type']=='SHT_DYNSYM'
   for s in section.iter_symbols() if s['st_shndx']!='SHN_UNDEF'}
 old=v.oracle.Uc,v.oracle.GUEST_SIZE;cpus=[];service=Services();calls=[]
 def reg(cpu,i):return cpu.reg_read(getattr(v.arm,'UC_ARM64_REG_X'+str(i)))
 def make(*a,**kw):
  cpu=old[0](*a,**kw);cpu.mem_map(0x78000000,0x200000);cpu.mem_map(c.ARENA,c.ARENA_SIZE);cpus.append(cpu);return cpu
 def alloc(cpu,size):
  a=service.cursor;service.cursor+=(max(size,1)+15)&~15;assert service.cursor<ARENA+0x10000
  service.effects.append(('allocate',size,a));return a
 def free(cpu):service.effects.append(('free',reg(cpu,0)));return 0
 def register(cpu):service.effects.append(('register',*(reg(cpu,i) for i in range(3))));return 0
 def create(cpu):
  out,attr,start,arg=(reg(cpu,i) for i in range(4));assert attr==0
  handle=v.oracle.GUEST+0xC800+len(service.threads)*0x100
  cpu.mem_write(out,handle.to_bytes(8,'little'));service.threads.append((handle,start,arg))
  service.effects.append(('thread',attr,start,arg,handle));return 0
 def signal(cpu):cpu.reg_write(v.arm.UC_ARM64_REG_PC,exports['pthread_cond_signal'])
 def syscall(cpu,number):
  assert number==98 and reg(cpu,1)&0x7f==1
  service.effects.append(('wake',*(reg(cpu,i) for i in range(3))));return 0
 def observe(cpu,a):
  if a-base in (0x29E908,0x29EAF4):
   ctx=reg(cpu,0);calls.append((a,ctx,cpu.reg_read(v.arm.UC_ARM64_REG_SP),int.from_bytes(cpu.mem_read(ctx+0x6090,8),'little')))
 try:
  v.oracle.Uc=make;v.oracle.GUEST_SIZE=0x160000
  v.oracle.native(args.library,base,entry,[] if context is None else [context],p,libc=args.libc,
   malloc_handler=alloc,host_imports={0x347FA0:free,0x347EA0:register,0x348000:create,0x348590:signal},
   real_singletons=True,real_mutexes=True,thread_id=tid,
   extra_registers={v.arm.UC_ARM64_REG_SP:sp,v.arm.UC_ARM64_REG_TPIDR_EL0:TLS},
   instruction_limit=1000000,instruction_observer=observe,syscall_handler=syscall,
   code_hook_ranges=((base+0x29E908,base+0x29E908),(base+0x29EAF4,base+0x29EAF4),(base+0x347E00,base+0x348800)))
 finally:v.oracle.Uc,v.oracle.GUEST_SIZE=old
 assert cpus[0].reg_read(v.arm.UC_ARM64_REG_SP)==sp
 return cpus[0],service,calls


def services(s,tid=137):
 return dict(allocate=s.allocate,free=s.free,create_thread=s.create,
  register_destructor=s.register,thread_id=tid,signal_condition=s.signal)


def callback_input(args,base,label,padding=0xA5):
 p=setup(c.prepare(args,base,padding),args);ctx=v.oracle.GUEST+0x20000;source=ctx+0x5FC0
 v.put(p,ctx+0x6090,source);v.put(p,source,base+0x35FC28)
 kind=label.split('_')[1];pointer=source if kind=='inline' else source+0x100 if kind=='heap' else 0
 v.put(p,source+0x20,pointer)
 if kind=='heap':v.put(p,pointer,base+0x35FC28)
 return p,ctx,source,0x29E908 if label.startswith('enqueue') else 0x29EAF4


def pages_equal(p,cpu):
 for page,data in p.items():
  if 0x78000000<=page<<12<0x78200000:continue
  assert bytes(data)==bytes(cpu.mem_read(page<<12,4096)),hex(page<<12)


def callback_compare(args,base,label,padding):
 p,ctx,source,entry=callback_input(args,base,label,padding)
 cpu,expected,calls=native(args,p,base,entry=entry,context=ctx);s=Services()
 result=alternative.run_startup_imported_callback(p,image_base=base,function_address=base+entry,
  context_address=ctx,entry_stack_address=v.SP,**services(s))
 assert result==source and calls==[(base+entry,ctx,v.SP,source)]
 assert s.effects==expected.effects and s.threads==expected.threads
 pages_equal(p,cpu)
 return dict(base=hex(base),label=label,padding=padding,entry=hex(entry),
  natural_return_SP_and_source_match=True,all_guest_heap_image_libc_pages_match=True,
  ordered_semantic_effects_match=True,effects=len(s.effects),thread_creations=len(s.threads),
  native_snapshot_input=False,worker_execution_deferred=True)


def startup_compare(args,base,initial,sp,tid,label):
 p={k:bytearray(data) for k,data in initial.items()};v.put(p,TLS+0x210,tid,4)
 cpu,expected,calls=native(args,p,base,sp,tid);s=Services()
 result=alternative.initialize_startup_caller(p,image_base=base,entry_stack_address=sp,
  thread_pointer=TLS,**services(s,tid))
 ctx=sp-0x6310
 assert result.context_address==ctx and result.steps==19 and result.status_word==0
 assert result.imported_calls==tuple(row[:3] for row in calls) and len(calls)==2
 assert s.effects==expected.effects and s.threads==expected.threads and len(s.threads)==3
 assert result.executor_address==v.u(p,base+0x3E2D78)
 pages_equal(p,cpu)
 assert _read_span(p,ctx,0x62D0)==bytes(cpu.mem_read(ctx,0x62D0))
 assert _read_span(p,sp-0x38,8)==bytes(cpu.mem_read(sp-0x38,8))
 for offset in (0,8):
  queue=v.u(p,result.executor_address+offset)
  assert v.u(p,queue+0x20)-v.u(p,queue+0x18)==(0 if offset else 48)
 return dict(base=hex(base),label=label,thread_id=tid,dispatches=result.steps,imported_calls=2,
  natural_return_SP_status_and_canary_match=True,full_context_match=True,
  all_guest_heap_image_libc_pages_match=True,ordered_semantic_effects_match=True,
  effects=len(s.effects),thread_creations=len(s.threads),actual_ELF_initial_descriptor=True,
  native_snapshot_input=False,worker_execution_deferred=True)


def negatives(args):
 base=0x122C0000;initial,ctx,source,entry=callback_input(args,base,'enqueue_inline');rows=[]
 def reject(label,changes=None,mutation=None,main=False,fault=None):
  p={k:bytearray(data) for k,data in initial.items()};s=Services()
  if mutation:mutation(p)
  before={k:bytes(data) for k,data in p.items()};saved=alternative._write_span;hits=[]
  def write(p,a,data):
   if fault(a,data):hits.append(a);raise RefillUnsupported('injected startup write failure')
   return saved(p,a,data)
  kw=dict(image_base=base,entry_stack_address=v.SP,**services(s))
  kw.update(dict(thread_pointer=TLS) if main else dict(function_address=base+entry,context_address=ctx))
  kw.update(changes or {})
  try:
   if fault:alternative._write_span=write
   try:(alternative.initialize_startup_caller if main else alternative.run_startup_imported_callback)(p,**kw)
   except (ValueError,RefillUnsupported):pass
   else:raise AssertionError('accepted startup guard '+label)
  finally:alternative._write_span=saved
  assert before=={k:bytes(data) for k,data in p.items()},label
  if fault:assert hits,label
  rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_fault_path_compared=False))
 for label,kw in (
  ('unknown_callback',dict(function_address=base+0x29E920)),('unaligned_SP',dict(entry_stack_address=v.SP+1)),
  ('boolean_SP',dict(entry_stack_address=True)),('unaligned_context',dict(context_address=ctx+1)),
  ('image_context',dict(context_address=base+0x1000)),('invalid_thread',dict(thread_id=-1)),
  ('boolean_thread',dict(thread_id=True)),('missing_allocator',dict(allocate=None)),
  ('missing_free',dict(free=None)),('missing_thread_provider',dict(create_thread=None)),
  ('missing_registration_provider',dict(register_destructor=None)),('missing_signal_provider',dict(signal_condition=None)),
  ('scratch_context_alias',dict(entry_stack_address=ctx+0x1B0)),
  ('allocator_context_alias',dict(allocate=lambda p,n:ctx+0x100)),
  ('allocator_image_alias',dict(allocate=lambda p,n:base+0x1000)),
  ('allocator_null',dict(allocate=lambda p,n:0)),
  ('thread_error',dict(create_thread=lambda *a:11)),
  ('thread_handle_missing',dict(create_thread=lambda p,o,*a:v.put(p,o,0) or 0)),
  ('signal_error',dict(signal_condition=lambda *a:5)),
  ('reserved_context',dict(reserved_regions=((ctx,ctx+0x62D0),)))):reject(label,kw)
 for label,a,value in (
  ('source_null',ctx+0x6090,0),('source_control_alias',ctx+0x6090,ctx),
  ('source_bank_alias',ctx+0x6090,ctx+0x6050),('source_image_alias',ctx+0x6090,base+0x1000),
  ('bad_clone',base+0x35FC40,0),('recursive_guard',base+0x3E2D80,0x200)):
  reject(label,mutation=lambda p,a=a,value=value:v.put(p,a,value))
 for label,kw in (
  ('caller_unaligned_SP',dict(entry_stack_address=v.SP+1)),('caller_low_SP',dict(entry_stack_address=0x1000)),
  ('caller_unmapped_TLS',dict(thread_pointer=0x76000000)),('caller_TLS_context_alias',dict(thread_pointer=v.SP-0x6310)),
  ('caller_zero_step_bound',dict(max_steps=0)),('caller_boolean_depth',dict(max_depth=True))):reject(label,kw,main=True)
 reject('caller_canary_save_failure',main=True,fault=lambda a,data:a==v.SP-0x38)
 return rows


def late_negatives(initial,base):
 rows=[]
 for label in ('late_step_exhaustion','source_destructor_relocation','changed_TLS_canary','changed_saved_canary'):
  p={k:bytearray(data) for k,data in initial.items()};s=Services();kw=services(s)
  if label=='source_destructor_relocation':v.put(p,base+0x35FC48,0)
  if label.startswith('changed_'):
   def signal(p,address):
    result=s.signal(p,address)
    v.put(p,TLS+0x28 if label=='changed_TLS_canary' else v.SP-0x38,0)
    return result
   kw['signal_condition']=signal
  if label=='late_step_exhaustion':kw['max_steps']=18
  before={k:bytes(data) for k,data in p.items()}
  try:alternative.initialize_startup_caller(p,image_base=base,entry_stack_address=v.SP,thread_pointer=TLS,**kw)
  except RefillUnsupported:pass
  else:raise AssertionError('accepted late startup guard '+label)
  assert len(s.effects)==22 and before=={k:bytes(data) for k,data in p.items()},label
  rows.append(dict(label=label,base=hex(base),rejected=True,all_pages_unchanged=True,
   recorded_deferred_effects=22,native_fault_path_compared=False))
 return rows


def main():
 parser=argparse.ArgumentParser(description=__doc__)
 for name in ('library','libc','output'):parser.add_argument('--'+name,type=Path,required=True)
 args=parser.parse_args()
 assert hashlib.sha256(args.library.read_bytes()).hexdigest()==v.oracle.LIBRARY_SHA256
 assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==v.defined.builder.catalog.heap.LIBC_HASH
 guards=negatives(args);rows=[]
 for base in (0x122C0000,0x775C205000):
  for label in ('enqueue_inline','enqueue_heap','enqueue_empty','destroy_inline','destroy_heap','destroy_empty'):
   for pad in (0xA5,0x39):rows.append(callback_compare(args,base,label,pad))
  print('B callback controls passed',hex(base),flush=True)
  p=c.prepare(args,base);c.model(p,base);setup(p,args)
  guards.extend(late_negatives(p,base))
  for sp,tid,label in ((v.SP,137,'actual_initial_startup'),(v.SP-0xC80,1,'actual_relocated_stack')):
   rows.append(startup_compare(args,base,p,sp,tid,label))
  print('B actual startup passed',hex(base),flush=True)
 evidence=dict(schema='vm9-alternative-startup-fresh-v1',evidence_date='2026-10-11',evidence_timezone='Asia/Shanghai',
  sample_sha256=v.oracle.LIBRARY_SHA256,matching_libc_sha256=v.defined.builder.catalog.heap.LIBC_HASH,
  native_Python_startup_controls=len(rows),actual_ELF_startup_controls=4,imported_callback_controls=24,
  rollback_negative_controls=len(guards),pre_change_behavior_RED_controls=6,
  native_input_snapshot_used=False,private_names_or_payloads_published=False,
  real_B_imported_callback_bodies_executed=True,main_thread_B_startup_composed=True,
  whole_native_stack_compared=False,physical_thread_output_scratch_compared=False,worker_execution_deferred=True,
  full_JNI_bootstrap_verified=False,complete_python_medusa=False,fresh_signer_output_verified=False,
  live_server_matrix_verified=False,cases=rows,negative_cases=guards)
 args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
 print('B startup controls',len(rows),'guards',len(guards),flush=True)


if __name__=='__main__':main()
