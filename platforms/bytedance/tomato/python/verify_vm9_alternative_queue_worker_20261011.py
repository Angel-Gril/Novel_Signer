"""Same fresh B startup, deferred queue worker and original guest thread exit.

The native startup and selected worker share one CPU execution. Python uses
independent ELF construction, the B caller and the existing queue/TLS/exit
owners. Explicit allocator, finite futex and OS-exit services create no host
threads. Contexts are compared while live, before native stack storage reuse.
"""
from pathlib import Path
import argparse,hashlib,json
import verify_vm9_alternative_worker_task_20261011 as task
support=task.support;v=task.v;c=task.c;alternative=task.alternative;shared=task.shared
from vm9_allocator import _read_span,_write_span,RefillUnsupported
import vm9_allocator as allocator
import vm9_thread_exit as thread_exit
from elftools.elf.elffile import ELFFile
WORKER_TLS=v.oracle.GUEST+0xD000;WORKER_SP=v.SP-0x20000
SCHEDULE=v.oracle.GUEST+0xF900;DONE=v.oracle.GUEST+0xF980
GENERATIONS=support.LIBC+0xE0200


def setup(p,args):
 support.setup(p,args)
 _write_span(p,WORKER_TLS,bytes(0xC00));v.put(p,WORKER_TLS+8,WORKER_TLS+0x200)
 v.put(p,WORKER_TLS+0x210,203,4);v.put(p,WORKER_TLS+0x28,0xABCDEFAABBCCDD00)
 v.put(p,v.oracle.GUEST+0xBC80,0)
 return p


class Services(support.Services):
 def allocate(self,p,size):
  a=self.cursor;self.cursor+=(max(size,1)+15)&~15;assert self.cursor<support.ARENA+0x100000
  _read_span(p,a,size);self.effects.append(('allocate',size,a));return a
 def key(self,p,address,destructor):
  self.effects.append(('key',))
  return allocator.pthread_key_create(p,key_address=address,destructor=destructor,generation_table=GENERATIONS)
 def specific(self,p,key,value):
  self.effects.append(('specific',))
  return allocator.pthread_setspecific(p,key=key,value=value,thread_pointer=WORKER_TLS,generation_table=GENERATIONS)
 def clock(self,p,clock_id):self.effects.append(('clock',clock_id,1000,1234));return 1000,1234
 def broadcast(self,p,address):return shared.objects.broadcast_condition_no_waiters(p,condition_address=address,wake=self.wake)


def native(args,p,base,cleanup=False):
 with args.libc.open('rb') as stream:
  elf=ELFFile(stream)
  exports={s.name:support.LIBC+s['st_value'] for section in elf.iter_sections() if section['sh_type']=='SHT_DYNSYM'
   for s in section.iter_symbols() if s['st_shndx']!='SHN_UNDEF'}
 old=v.oracle.Uc,v.oracle.GUEST_SIZE;cpus=[];service=Services();contexts=set();task_contexts=set();at_return={}
 switched=False;task_entries=[];task_returns=[];waits=[];cleanup_started=False
 def reg(cpu,i):return cpu.reg_read(getattr(v.arm,'UC_ARM64_REG_X'+str(i)))
 def read(cpu,a,n=8):return int.from_bytes(cpu.mem_read(a,n),'little')
 def make(*a,**kw):
  cpu=old[0](*a,**kw);cpu.mem_map(0x78000000,0x200000);cpu.mem_map(c.ARENA,c.ARENA_SIZE);cpus.append(cpu);return cpu
 def alloc(cpu,size):
  a=service.cursor;service.cursor+=(max(size,1)+15)&~15;assert service.cursor<support.ARENA+0x100000
  service.effects.append(('allocate',size,a));return a
 def free(cpu):service.effects.append(('free',reg(cpu,0)));return 0
 def register(cpu):service.effects.append(('register',*(reg(cpu,i) for i in range(3))));return 0
 def create(cpu):
  out,attr,start,arg=(reg(cpu,i) for i in range(4));assert attr==0
  handle=v.oracle.GUEST+0xC800+len(service.threads)*0x100
  cpu.mem_write(out,handle.to_bytes(8,'little'));service.threads.append((handle,start,arg))
  service.effects.append(('thread',attr,start,arg,handle));return 0
 def redirect(name,label=None):
  def fn(cpu):
   if label:service.effects.append((label,))
   cpu.reg_write(v.arm.UC_ARM64_REG_PC,exports[name])
  return fn
 def clock(cpu):
  service.effects.append(('clock',reg(cpu,0),1000,1234))
  cpu.mem_write(reg(cpu,1),(1000).to_bytes(8,'little')+(1234).to_bytes(8,'little'));return 0
 def syscall(cpu,number):
  if number==93:
   assert cleanup=='pthread_exit' and cleanup_started and reg(cpu,0)==0
   service.effects.append(('os_exit',0));cpu.reg_write(v.arm.UC_ARM64_REG_PC,v.oracle.STOP);return 0
  if number==113:return clock(cpu)
  assert number==98
  address,op,expected=(reg(cpu,i) for i in range(3))
  if op&0x7F==1:service.effects.append(('wake',address,op,expected));return 0
  assert switched and not waits
  queue=read(cpu,service.threads[1][2]+0x18)
  assert address==queue+0x58 and read(cpu,queue+0x30,2)==0 and not reg(cpu,3)
  service.effects.append(('wait',address,op,expected,None,-4));waits.append(True)
  cpu.mem_write(queue+0x88,b'\0');return -4
 def observe(cpu,address):
  nonlocal switched,cleanup_started
  if address==SCHEDULE:
   assert not switched and cpu.reg_read(v.arm.UC_ARM64_REG_SP)==v.SP and len(service.threads)==3
   switched=True;_,entry,arg=service.threads[1];assert entry==base+0x3260A4
   cpu.reg_write(v.arm.UC_ARM64_REG_X0,arg);cpu.reg_write(v.arm.UC_ARM64_REG_PC,entry)
   cpu.reg_write(v.arm.UC_ARM64_REG_X30,DONE if cleanup else v.oracle.STOP)
   cpu.reg_write(v.arm.UC_ARM64_REG_SP,WORKER_SP);cpu.reg_write(v.arm.UC_ARM64_REG_TPIDR_EL0,WORKER_TLS)
   for i in range(19,29):cpu.reg_write(getattr(v.arm,'UC_ARM64_REG_X'+str(i)),0)
  elif address==DONE:
   assert cleanup and not cleanup_started and reg(cpu,0)==0 and cpu.reg_read(v.arm.UC_ARM64_REG_SP)==WORKER_SP
   cleanup_started=True;cpu.reg_write(v.arm.UC_ARM64_REG_PC,support.LIBC+(0x68138 if cleanup=='pthread_exit' else 0x685A0))
   cpu.reg_write(v.arm.UC_ARM64_REG_X30,v.oracle.STOP)
  elif address==base+0x29E05C:task_entries.append(cpu.reg_read(v.arm.UC_ARM64_REG_SP))
  elif address==base+0x326620:
   task_returns.append(True)
   at_return.update({ctx:bytes(cpu.mem_read(ctx,0x62D0)) for ctx in task_contexts})
  elif address==base+0x2A9718:
   contexts.add(reg(cpu,1))
   if switched:task_contexts.add(reg(cpu,1))
 def libc_tls(cpu):
  assert cleanup=='pthread_exit' and reg(cpu,0)==support.LIBC+0xDB3A8
  service.effects.append(('get_libc_tls',));return v.oracle.GUEST+0xBC80
 try:
  v.oracle.Uc=make;v.oracle.GUEST_SIZE=0x160000
  v.oracle.native(args.library,base,0x2A0028,[],p,libc=args.libc,real_singletons=True,real_mutexes=True,
   malloc_handler=alloc,host_imports={0x347FA0:free,0x347EA0:register,0x348000:create,
    0x348590:redirect('pthread_cond_signal'),0x3485A0:redirect('pthread_cond_broadcast'),
    0x348620:redirect('pthread_key_create','key'),0x348580:redirect('pthread_setspecific','specific'),
    0x3485B0:redirect('pthread_cond_wait'),0x3485C0:redirect('pthread_cond_timedwait'),0x348450:clock,
    support.LIBC+0x9BE24-base:libc_tls},
   syscall_handler=syscall,thread_id=lambda cpu:203 if switched else 137,
   extra_registers={v.arm.UC_ARM64_REG_SP:v.SP,v.arm.UC_ARM64_REG_X30:SCHEDULE,v.arm.UC_ARM64_REG_TPIDR_EL0:support.TLS},
   instruction_observer=observe,instruction_limit=10000000,
   code_hook_ranges=tuple((a,a) for a in (SCHEDULE,DONE,base+0x29E05C,base+0x326620,base+0x2A9718))+
    ((base+0x347E00,base+0x348800),(support.LIBC+0x9BE24,support.LIBC+0x9BE24)))
 except Exception:
  cpu=cpus[0];print('Native queue PC/LR/SP',*[hex(cpu.reg_read(r)) for r in (v.arm.UC_ARM64_REG_PC,v.arm.UC_ARM64_REG_LR,v.arm.UC_ARM64_REG_SP)],service.effects[-5:],flush=True);raise
 finally:v.oracle.Uc,v.oracle.GUEST_SIZE=old
 cpu=cpus[0]
 assert switched and len(task_returns)==1 and task_entries==[WORKER_SP-0xD0] and len(waits)==1
 assert (cleanup=='pthread_exit' or cpu.reg_read(v.arm.UC_ARM64_REG_SP)==WORKER_SP) and reg(cpu,0)==0
 assert cleanup_started==bool(cleanup)
 return cpu,service,contexts-task_contexts,at_return


def model(p,base,cleanup=False):
 service=Services()
 alternative.initialize_startup_caller(p,image_base=base,entry_stack_address=v.SP,
  thread_pointer=support.TLS,**support.services(service))
 _,entry,arg=service.threads[1];queue=v.u(p,arg+0x18);results=[];waits=[];at_return={}
 def futex(p,a,op,expected,timeout):
  assert a==queue+0x58 and v.u(p,queue+0x30,2)==0 and not waits
  service.effects.append(('wait',a,op,expected,timeout,-4));waits.append(True);v.put(p,queue+0x88,0,1);return -4
 saved_task=alternative.run_worker_initialization_task
 def record(p,**kw):
  result=saved_task(p,**kw)
  at_return.update({ctx:_read_span(p,ctx,0x62D0) for ctx in {result.context_address,*(r.context_address for r in result.arena_results)}})
  return result
 try:
  alternative.run_worker_initialization_task=record
  worker=alternative.run_queue_worker(p,argument_address=arg,image_base=base,entry_stack_address=WORKER_SP,
   thread_pointer=WORKER_TLS,thread_id=203,allocate=service.allocate,broadcast=service.broadcast,
   create_key=service.key,set_specific=service.specific,clock=service.clock,futex=futex,free=service.free)
 finally:alternative.run_worker_initialization_task=saved_task
 results.extend(worker.tasks);assert worker.return_code==0
 assert len(results)==1 and len(waits)==1
 if cleanup=='pthread_exit':
  def libc_tls(p,descriptor):
   assert descriptor==support.LIBC+0xDB3A8
   service.effects.append(('get_libc_tls',));return v.oracle.GUEST+0xBC80
  def os_call(p,operation,*fields):
   assert operation=='exit' and fields==(0,)
   service.effects.append(('os_exit',0));return 0
  exited=thread_exit.run_pthread_exit(allocator.GuestOS(p),image_base=base,libc_base=support.LIBC,
   thread_pointer=WORKER_TLS,return_value=0,get_libc_tls=libc_tls,free=service.free,os_call=os_call)
  assert not exited.detached and not exited.unmapped_regions
 elif cleanup:
  calls=shared.run_worker_thread_key_cleanup(p,image_base=base,thread_pointer=WORKER_TLS,
   generation_table=GENERATIONS,free=service.free);assert len(calls)==1
 return service,results,at_return



def compare(args,initial,base,cleanup,warm_key):
 p={k:bytearray(data) for k,data in initial.items()}
 if warm_key:
  v.put(p,base+0x3E2F30,0x80000009,4);_write_span(p,base+0x3E2F38,b'\1\1')
  v.put(p,GENERATIONS+9*16,3);v.put(p,GENERATIONS+9*16+8,base+0x32CE6C)
 cpu,expected,contexts,at_return=native(args,p,base,cleanup)
 actual,results,actual_return=model(p,base,cleanup)
 assert actual.effects==expected.effects and actual.threads==expected.threads
 support.pages_equal(p,cpu)
 assert at_return==actual_return and len(at_return)==2 and len(results)==1
 for ctx in contexts:assert _read_span(p,ctx,0x62D0)==bytes(cpu.mem_read(ctx,0x62D0))
 task=results[0]
 assert len(task.caller_results)==6 and len(task.arena_results)==6
 assert sum(r.steps for r in task.caller_results)+sum(r.steps for a in task.arena_results for r in a.caller_results)==120847
 arg=actual.threads[1][2];wrapper=v.u(p,arg)  # Ownership was transferred: argument first word is zero.
 assert wrapper==0
 key=v.u(p,base+0x3E2F30,4)
 retained=allocator.pthread_getspecific(p,key=key,thread_pointer=WORKER_TLS,generation_table=GENERATIONS)
 assert (retained!=0)==(not cleanup)
 frees=[e[1] for e in actual.effects if e[0]=='free']
 assert frees.count(arg)==1 and len(frees)==(3 if cleanup else 1)
 assert sum(e[0]=='wait' for e in actual.effects)==1 and len(actual.threads)==3
 assert sum(e[0]=='key' for e in actual.effects)==(0 if warm_key else 1)
 return dict(base=hex(base),mode='pthread_exit' if cleanup=='pthread_exit' else 'key_cleanup' if cleanup else 'worker_return',
  warm_support_key=warm_key,worker_entry_SP=hex(WORKER_SP),effects=len(actual.effects),thread_creations=3,
  task_dispatches=120847,outer_programs=6,nested_programs=48,worker_waits=1,frees=len(frees),
  startup_generated_arguments_and_deferred_schedule_match=True,complete_B_callable_executed=True,
  natural_worker_return_verified=True,task_contexts_at_live_return_match=True,main_context_match=True,
  all_guest_heap_image_libc_and_both_TLS_pages_match=True,ordered_effects_and_thread_descriptors_match=True,
  support_retained_in_TLS=not bool(cleanup),TLS_key_cleanup_completed=bool(cleanup),
  full_joinable_guest_pthread_exit_body_executed=cleanup=='pthread_exit',actual_OS_exit_executed=False,
  native_snapshot_input=False)


def negative_cases(initial,base):
 seed={k:bytearray(data) for k,data in initial.items()};prepared=Services()
 alternative.initialize_startup_caller(seed,image_base=base,entry_stack_address=v.SP,
  thread_pointer=support.TLS,**support.services(prepared))
 arg=prepared.threads[1][2];queue=v.u(seed,arg+0x18);rows=[]
 def reject(label,changes=None,mutation=None):
  p={k:bytearray(data) for k,data in seed.items()}
  if mutation:mutation(p)
  before={k:bytes(data) for k,data in p.items()};s=Services();s.cursor=prepared.cursor
  def wait(p,a,op,expected,timeout):v.put(p,queue+0x88,0,1);return -4
  kw=dict(argument_address=arg,image_base=base,entry_stack_address=WORKER_SP,
   thread_pointer=WORKER_TLS,thread_id=203,allocate=s.allocate,broadcast=s.broadcast,
   create_key=s.key,set_specific=s.specific,clock=s.clock,futex=wait,free=s.free)
  kw.update(changes or {})
  try:alternative.run_queue_worker(p,**kw)
  except (RefillUnsupported,ValueError):pass
  else:raise AssertionError('accepted queue worker guard '+label)
  assert before=={k:bytes(data) for k,data in p.items()},label
  rows.append(dict(label=label,rejected=True,all_pages_unchanged=True))
 for name in ('allocate','broadcast','create_key','set_specific','clock','futex','free'):
  reject('missing_'+name,{name:None})
 for label,changes in (('unaligned_SP',dict(entry_stack_address=WORKER_SP+1)),
  ('boolean_SP',dict(entry_stack_address=True)),('low_SP',dict(entry_stack_address=0x1000)),
  ('unmapped_argument',dict(argument_address=0x76000000)),('zero_iterations',dict(max_iterations=0)),
  ('task_budget',dict(max_steps=1)),('task_depth',dict(max_depth=1)),
  ('retained_context',dict(reserved_regions=((WORKER_SP-0x63E0,WORKER_SP-0x110),))),
  ('key_service_failure',dict(create_key=lambda *a:5)),('specific_service_failure',dict(set_specific=lambda *a:5))):reject(label,changes)
 reject('wrong_queue_vtable',mutation=lambda p:v.put(p,arg+0x10,base+0x35FC28))
 reject('empty_queue',mutation=lambda p:v.put(p,queue+0x20,v.u(p,queue+0x18)))
 reject('two_queued_tasks',mutation=lambda p:v.put(p,queue+0x20,v.u(p,queue+0x18)+96))
 reject('unknown_task_target',mutation=lambda p:v.put(p,base+0x35FC28+0x30,base+0x280554))
 def free_failure(p,address):v.put(p,address,0x1234);raise RefillUnsupported('argument free failed after write')
 reject('argument_free_failure',dict(free=free_failure))
 def wait_failure(p,*args):v.put(p,queue+0x88,0,1);raise RefillUnsupported('late queue wait failed')
 reject('late_wait_failure',dict(futex=wait_failure))
 reject('queue_wait_budget',dict(futex=lambda *a:0,max_iterations=2))
 print('B queue worker',len(rows),'rollback guards passed',flush=True)
 return rows


def main():
 global WORKER_SP
 parser=argparse.ArgumentParser(description=__doc__)
 for name in ('library','libc','output'):parser.add_argument('--'+name,type=Path,required=True)
 args=parser.parse_args()
 assert hashlib.sha256(args.library.read_bytes()).hexdigest()==v.oracle.LIBRARY_SHA256
 assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==v.defined.builder.catalog.heap.LIBC_HASH
 rows=[];guards=[]
 for base,delta in ((0x122C0000,0),(0x775C205000,-0xC80)):
  WORKER_SP=v.SP-0x20000+delta
  initial=c.prepare(args,base);c.model(initial,base);setup(initial,args)
  print('Fresh B constructor for queue worker',hex(base),flush=True)
  if not guards:guards=negative_cases(initial,base)
  for warm in (False,True):
   for mode in (False,True,'pthread_exit'):
    rows.append(compare(args,initial,base,mode,warm))
    print('B same-startup worker',hex(base),'warm key',warm,'mode',mode,'passed',flush=True)
 evidence=dict(schema='vm9-alternative-queue-worker-fresh-v1',evidence_date='2026-10-11',evidence_timezone='Asia/Shanghai',
  sample_sha256=v.oracle.LIBRARY_SHA256,matching_libc_sha256=v.defined.builder.catalog.heap.LIBC_HASH,
  native_Python_controls=len(rows),rollback_negative_controls=len(guards),pre_change_behavior_RED_controls=2,
  fresh_independent_ELF_constructor_inputs=True,same_startup_generated_worker=True,
  full_B_worker_caller_composed=True,B_queue_worker_and_TLS_cleanup_composed=True,
  full_joinable_guest_pthread_exit_body_verified=True,actual_OS_threads_or_exit_used=False,
  native_input_snapshot_used=False,private_names_or_payloads_published=False,
  full_JNI_bootstrap_verified=False,complete_python_medusa=False,fresh_signer_output_verified=False,
  live_server_matrix_verified=False,cases=rows,negative_cases=guards)
 args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
 print('B queue worker',len(rows),'controls',len(guards),'guards',flush=True)


if __name__=='__main__':main()
