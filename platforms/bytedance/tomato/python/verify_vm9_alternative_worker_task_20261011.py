"""Fresh complete B initializer and callable comparisons against original ARM64.

All descriptor inputs come from independent ELF construction. Native CAS,
memset, once and matching-libc broadcast bodies execute naturally. Native
pages never become model inputs; queue/TLS cleanup is a subsequent boundary.
"""
from pathlib import Path
import argparse,hashlib,json
import verify_vm9_alternative_startup_20261011 as support
from vm9_allocator import _read_span,_write_span,RefillUnsupported
from elftools.elf.elffile import ELFFile
v=support.v;c=support.c;alternative=support.alternative;shared=support.shared
INITIALIZERS=(0x29E120,0x29E27C,0x29E3C8,0x29E514,0x29E660,0x29E7AC)


class Services:
 def __init__(self,start=support.ARENA):self.cursor=start;self.effects=[]
 def allocate(self,p,size):
  a=self.cursor;self.cursor+=(max(size,1)+15)&~15
  assert self.cursor<=support.ARENA+0x100000
  _read_span(p,a,size);self.effects.append(('allocate',size,a));return a
 def wake(self,p,*args):self.effects.append(('wake',*args));return 0
 def broadcast(self,p,a):
  return shared.objects.broadcast_condition_no_waiters(p,condition_address=a,wake=self.wake)


def native(args,base,p,*,sp=v.SP,entry=0x29E05C,start=support.ARENA):
 with args.libc.open('rb') as stream:
  elf=ELFFile(stream)
  broadcast=next(support.LIBC+s['st_value'] for section in elf.iter_sections() if section['sh_type']=='SHT_DYNSYM'
   for s in section.iter_symbols() if s.name=='pthread_cond_broadcast' and s['st_shndx']!='SHN_UNDEF')
 tags={v.u(p,base+0x363EE8+tag*8) for tag in range(790)}
 external={base+offset for offset in (0x2EAE70,0x29EAA4,0x2EA98C)}
 saved=v.oracle.Uc,v.oracle.GUEST_SIZE;cpus=[];service=Services(start)
 calls=[];contexts=set();entries=[];dispatches=0;canaries=[];initializer_stacks={}
 returns={offset+(0x154 if index==0 else 0x144):offset for index,offset in enumerate(INITIALIZERS)}
 def reg(cpu,i):return cpu.reg_read(getattr(v.arm,'UC_ARM64_REG_X'+str(i)))
 def make(*a,**kw):
  cpu=saved[0](*a,**kw);cpu.mem_map(0x78000000,0x200000);cpu.mem_map(c.ARENA,c.ARENA_SIZE);cpus.append(cpu);return cpu
 def allocate(cpu,size):
  a=service.cursor;service.cursor+=(max(size,1)+15)&~15;assert service.cursor<=support.ARENA+0x100000
  service.effects.append(('allocate',size,a));return a
 def signal(cpu):cpu.reg_write(v.arm.UC_ARM64_REG_PC,broadcast)
 def syscall(cpu,number):
  assert number==98 and reg(cpu,1)&0x7F==1
  service.effects.append(('wake',*(reg(cpu,i) for i in range(3))));return 0
 def observe(cpu,address):
  nonlocal dispatches
  if address-base in INITIALIZERS:initializer_stacks[address-base]=cpu.reg_read(v.arm.UC_ARM64_REG_SP)
  elif address-base in returns:
   entry_sp=initializer_stacks[returns[address-base]];slot=entry_sp-0x48
   canaries.append((slot,bytes(cpu.mem_read(slot,8)),bytes(cpu.mem_read(support.TLS+0x28,8))))
  elif address in tags:dispatches+=1
  elif address in external:
   ctx=reg(cpu,0);active=int.from_bytes(cpu.mem_read(ctx+8,8),'little')
   calls.append((address,ctx,cpu.reg_read(v.arm.UC_ARM64_REG_SP),bytes(cpu.mem_read(ctx,0x62D0)),bytes(cpu.mem_read(active,16))))
  elif address==base+0x2A9718:
   contexts.add(reg(cpu,1));entries.append((reg(cpu,0),reg(cpu,1),cpu.reg_read(v.arm.UC_ARM64_REG_SP)))
 try:
  v.oracle.Uc=make;v.oracle.GUEST_SIZE=0x160000
  v.oracle.native(args.library,base,entry,[],p,libc=args.libc,real_mutexes=True,
   malloc_handler=allocate,host_imports={0x3485A0:signal},syscall_handler=syscall,
   extra_registers={v.arm.UC_ARM64_REG_SP:sp,v.arm.UC_ARM64_REG_TPIDR_EL0:support.TLS},
   instruction_observer=observe,instruction_limit=10000000,
   code_hook_ranges=(*((a,a) for a in sorted(tags|external|{base+0x2A9718}|{base+x for x in (*INITIALIZERS,*returns)})),(base+0x347E00,base+0x348800)))
 finally:v.oracle.Uc,v.oracle.GUEST_SIZE=saved
 cpu=cpus[0];assert cpu.reg_read(v.arm.UC_ARM64_REG_SP)==sp
 return cpu,service,calls,contexts,entries,dispatches,canaries


def model(p,base,*,sp=v.SP,index=None,start=support.ARENA,changes=None):
 service=Services(start);calls=[];entries=[];canaries=[]
 saved_execute=alternative.execute_runtime_descriptor; saved_initializer=alternative.initialize_worker_arena if hasattr(alternative,'initialize_worker_arena') else None
 def execute(p,**kw):
  entries.append((kw['descriptor_address'],kw['context_address'],kw['entry_stack_address']))
  callback=kw['call_import']
  def imported(p,function,ctx,entry_sp):
   active=v.u(p,ctx+8);calls.append((function,ctx,entry_sp,_read_span(p,ctx,0x62D0),_read_span(p,active,16)))
   return callback(p,function,ctx,entry_sp)
  return saved_execute(p,**dict(kw,call_import=imported))
 def initialize(p,**kw):
  result=saved_initializer(p,**kw);slot=result.context_address+0x62D8
  canaries.append((slot,_read_span(p,slot,8),_read_span(p,support.TLS+0x28,8)))
  return result
 kw=dict(image_base=base,entry_stack_address=sp,thread_pointer=support.TLS,allocate=service.allocate)
 if index is None:kw['broadcast']=service.broadcast
 else:kw['table_index']=index
 kw.update(changes or {})
 try:
  alternative.execute_runtime_descriptor=execute;alternative.initialize_worker_arena=initialize
  result=(alternative.run_worker_initialization_task if index is None else alternative.initialize_worker_arena)(p,**kw)
 finally:
  alternative.execute_runtime_descriptor=saved_execute;alternative.initialize_worker_arena=saved_initializer
 return result,service,calls,entries,canaries


def compare(args,base,initial,*,sp=v.SP,index=None,label='cold',start=support.ARENA):
 p={k:bytearray(data) for k,data in initial.items()}
 cpu,expected,calls,contexts,entries,dispatches,canaries=native(args,base,p,sp=sp,entry=0x29E05C if index is None else INITIALIZERS[index],start=start)
 result,service,actual,actual_entries,actual_canaries=model(p,base,sp=sp,index=index,start=start)
 assert service.effects==expected.effects and actual==calls and actual_entries==entries
 assert actual_canaries==canaries and all(a==b for _,a,b in canaries)
 results=result.caller_results+tuple(c for a in result.arena_results for c in a.caller_results) if index is None else result.caller_results
 assert sum(r.steps for r in results)==dispatches and len(results)==len(entries)
 support.pages_equal(p,cpu)
 for ctx in contexts:
  assert _read_span(p,ctx,0x62D0)==bytes(cpu.mem_read(ctx,0x62D0)),hex(ctx)
  # Nested canary storage is retired and reused by the outer native caller.
  # Compare it at initializer RET above; only the live top canary remains here.
  if ctx==result.context_address:assert _read_span(p,ctx+0x62D8,8)==bytes(cpu.mem_read(ctx+0x62D8,8))
 row=dict(base=hex(base),label=label,index=index,dispatches=dispatches,descriptor_calls=len(entries),
  imported_calls=len(calls),allocations=sum(e[0]=='allocate' for e in service.effects),
  wakes=sum(e[0]=='wake' for e in service.effects),natural_return_SP_and_canaries_match=True,
  all_guest_heap_image_libc_pages_match=True,complete_contexts_match=True,
  imported_context_frame_SP_and_descriptor_entries_match=True,ordered_allocation_wakes_match=True,
  original_CAS_memset_once_and_broadcast_bodies_executed=True,native_snapshot_input=False)
 return row,p



def negative_cases(initial,base):
 rows=[]
 def reject(label,*,index=None,changes=None,mutation=None,fault=None):
  p={k:bytearray(data) for k,data in initial.items()}
  if mutation:mutation(p)
  before={k:bytes(data) for k,data in p.items()};saved=alternative._write_span;hits=[]
  def write(p,address,data):
   if fault(address,data):hits.append(address);raise RefillUnsupported('injected B task write failure')
   return saved(p,address,data)
  try:
   if fault:alternative._write_span=write
   try:model(p,base,index=index,changes=changes)
   except (RefillUnsupported,ValueError):pass
   else:raise AssertionError('accepted worker task guard '+label)
  finally:alternative._write_span=saved
  assert before=={k:bytes(data) for k,data in p.items()},label
  if fault:assert hits,label
  rows.append(dict(label=label,rejected=True,all_pages_unchanged=True))
 for label,changes in (
  ('unaligned_SP',dict(entry_stack_address=v.SP+1)),('boolean_SP',dict(entry_stack_address=True)),
  ('low_SP',dict(entry_stack_address=0x1000)),('missing_allocate',dict(allocate=None)),
  ('missing_broadcast',dict(broadcast=None)),('zero_step_budget',dict(max_steps=0)),
  ('boolean_step_budget',dict(max_steps=True)),('excess_step_budget',dict(max_steps=1048577)),
  ('zero_depth',dict(max_depth=0)),('shallow_depth',dict(max_depth=1)),
  ('unmapped_TLS',dict(thread_pointer=0x76000000)),('image_TLS',dict(thread_pointer=base+0x1000)),
  ('retained_context',dict(reserved_regions=((v.SP-0x6310,v.SP-0x40),))),
  ('retained_heap',dict(reserved_regions=((support.ARENA,support.ARENA+0x18000),))),
  ('null_allocate',dict(allocate=lambda *a:0)),('unmapped_allocate',dict(allocate=lambda *a:0x76000000)),
  ('context_allocate',dict(allocate=lambda *a:v.SP-0x6310)),('image_allocate',dict(allocate=lambda *a:base+0x3E2000))):reject(label,changes=changes)
 for index in (-1,6,True):reject('invalid_table_'+str(index),index=0,changes=dict(table_index=index))
 reject('initializer_missing_allocator',index=0,changes=dict(allocate=None))
 reject('initializer_small_budget',index=0,changes=dict(max_steps=30))
 reject('missing_outer_descriptor',mutation=lambda p:v.put(p,base+0x3E21F0,0))
 reject('missing_nested_descriptor',mutation=lambda p:v.put(p,base+0x3E2220,0))
 def kind_one(p):v.put(p,v.u(p,base+0x3E21F0)+56,1)
 reject('kind1_outer_descriptor',mutation=kind_one)
 def bad_import(p):
  root=v.u(p,base+0x3E1EB0);begin,end=v.u(p,root),v.u(p,root+8);found=[]
  for a in range(begin,end,8):
   descriptor=v.u(p,a)
   if v.u(p,descriptor+56)==0 and v.u(p,descriptor)==base+0x29EAA4:found.append(descriptor)
  assert len(found)==1;v.put(p,found[0],base+0x29EAA8)
 reject('unknown_worker_import',mutation=bad_import)
 reject('duplicate_allocation',changes=dict(allocate=lambda *a:support.ARENA))
 def allocator_failure(p,size):v.put(p,support.ARENA,0);raise RefillUnsupported('allocator failed after a staged write')
 reject('allocation_service_failure',changes=dict(allocate=allocator_failure))
 def corrupt_canary(p,size):v.put(p,support.TLS+0x28,0);return support.ARENA
 reject('TLS_canary_changed',changes=dict(allocate=corrupt_canary))
 reject('canary_slot_write_failure',fault=lambda a,d:a==v.SP-0x38)
 reject('first_table_publication_failure',fault=lambda a,d:a==base+0x3E2280)
 reject('broadcast_failure',changes=dict(broadcast=lambda *a:5))
 service=Services();count=0
 def fail_sixth_broadcast(p,address):
  nonlocal count
  count+=1
  if count==6:return 5
  return service.broadcast(p,address)
 reject('sixth_broadcast_failure',changes=dict(broadcast=fail_sixth_broadcast));assert count==6
 reject('sixth_table_publication_failure',fault=lambda a,d:a==base+0x3E2280+5*0x40+7*8)
 reject('combined_step_budget',changes=dict(max_steps=120846))
 print('Full B task',len(rows),'rollback guards passed',flush=True)
 return rows


def main():
 parser=argparse.ArgumentParser(description=__doc__)
 for name in ('library','libc','output'):parser.add_argument('--'+name,type=Path,required=True)
 args=parser.parse_args()
 assert hashlib.sha256(args.library.read_bytes()).hexdigest()==v.oracle.LIBRARY_SHA256
 assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==v.defined.builder.catalog.heap.LIBC_HASH
 rows=[];guards=[]
 for base,sp in ((0x122C0000,v.SP),(0x775C205000,v.SP-0xC80)):
  initial=c.prepare(args,base);c.model(initial,base);support.setup(initial,args)
  print('Fresh independent B constructor completed',hex(base),flush=True)
  if not guards:guards=negative_cases(initial,base)
  for index in range(6):
   row,_=compare(args,base,initial,sp=sp,index=index,label='initializer_'+str(index));rows.append(row)
   assert row['allocations']==1 and row['wakes']==0 and row['descriptor_calls']==8 and row['imported_calls']==1
  row,cold=compare(args,base,initial,sp=sp,label='cold_task');rows.append(row)
  assert (row['dispatches'],row['descriptor_calls'],row['imported_calls'],row['allocations'],row['wakes'])==(120847,54,18,6,6)
  row,_=compare(args,base,cold,sp=sp,label='warm_task',start=support.ARENA+0x18000);rows.append(row)
  assert (row['descriptor_calls'],row['imported_calls'],row['allocations'],row['wakes'])==(6,6,0,0)
  for index in (0,2,4):v.put(cold,base+0x3E1E80+index*8,0)
  row,_=compare(args,base,cold,sp=sp,label='mixed_task',start=support.ARENA+0x18000);rows.append(row)
  assert (row['descriptor_calls'],row['imported_calls'],row['allocations'],row['wakes'])==(30,12,3,3)
  print('Full B initializer/cold/warm/mixed tasks passed',hex(base),flush=True)
 evidence=dict(schema='vm9-alternative-worker-task-fresh-v1',evidence_date='2026-10-11',evidence_timezone='Asia/Shanghai',
  sample_sha256=v.oracle.LIBRARY_SHA256,matching_libc_sha256=v.defined.builder.catalog.heap.LIBC_HASH,
  native_Python_controls=len(rows),individual_initializer_controls=sum(r['index'] is not None for r in rows),
  complete_task_controls=sum(r['index'] is None for r in rows),rollback_negative_controls=len(guards),
  pre_change_behavior_RED_controls=4,actual_CAS_memset_once_and_broadcast_bodies_executed=True,
  independent_ELF_constructor_inputs=True,native_input_snapshot_used=False,private_names_or_payloads_published=False,
  full_B_worker_caller_composed=True,B_queue_worker_and_TLS_cleanup_composed=False,
  full_JNI_bootstrap_verified=False,complete_python_medusa=False,fresh_signer_output_verified=False,
  live_server_matrix_verified=False,cases=rows,negative_cases=guards)
 args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
 print('Full B worker task',len(rows),'controls',len(guards),'guards',flush=True)


if __name__=='__main__':main()
