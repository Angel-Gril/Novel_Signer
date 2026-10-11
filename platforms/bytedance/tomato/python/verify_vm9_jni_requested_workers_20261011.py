"""Fresh complete ELF/JNI startup into executor and initialization queue exit.

Native constructors, JNI and both selected workers share one CPU execution.
Python maps its own ELF and uses independent constructor, worker and exit
owners. Finite wait and explicit clock/OS providers create no host threads.
The finalizer queue remains deferred; its actual callback is a later boundary.
"""
from pathlib import Path
import argparse,hashlib,json,os
from unicorn import arm64_const as arm
from elftools.elf.elffile import ELFFile
import verify_vm9_jni_complete_bootstrap_20261011 as full
import vm9_allocator as allocator
import vm9_thread_exit as thread_exit
import vm9_jni_workers as worker_owner
from vm9_allocator import _read_span,_write_span,RefillUnsupported
sequence=full.sequence;cold=full.cold;shared=full.shared
GUEST=full.GUEST;ARENA=full.ARENA;DISPATCH=full.DISPATCH;MASK64=full.MASK64
MAIN_PTHREAD=GUEST+0x40000
WORKERS=tuple(GUEST+0x42000+i*0x2000 for i in range(3))
WORKER_STACKS=tuple(0x781A0000-i*0x20000 for i in range(3))
DONE=GUEST+0xF910;NEXT=GUEST+0xF920
GENERATIONS=sequence.LIBC_BASE+0xE0200

def fresh(args,base,profile,Python=False):
 p=full.fresh(args,base,profile,Python=Python)
 for page in range(MAIN_PTHREAD>>12,(GUEST+0x48000)>>12):p[page]=bytearray(4096)
 def w(a,v,n=8):_write_span(p,a,v.to_bytes(n,'little'))
 w(full.sequence.configuration.TP+8,MAIN_PTHREAD);w(MAIN_PTHREAD+0x10,profile.get('thread_id',137),4)
 for i,tp in enumerate(WORKERS):
  w(tp+8,tp+0x200);w(tp+0x210,203+i,4);w(tp+0x28,0xABCDEFAABBCCDD00+i*0x100)
 w(GUEST+0xBC80,0)
 return p

class Services(full.Services):
 def __init__(self,base,profile):
  super().__init__(base,profile);self.thread_pointer=full.sequence.configuration.TP;self.worker_index=-1
  self.worker_returns=[];self.worker_exits=[];self.waits=[];self.key_calls=[];self.task_entries=[]
 def get(self,p,key):
  self.events.append(('getspecific',key))
  return allocator.pthread_getspecific(p,key=key,thread_pointer=self.thread_pointer,generation_table=GENERATIONS)
 def setvalue(self,p,key,value):
  self.events.append(('setspecific',key,value))
  return allocator.pthread_setspecific(p,key=key,value=value,thread_pointer=self.thread_pointer,generation_table=GENERATIONS)
 def create(self,p,address,fn):
  self.events.append(('key_create',address,fn))
  return allocator.pthread_key_create(p,key_address=address,destructor=fn,generation_table=GENERATIONS)

def native(args,p,base,profile,sp,word):
    service=Services(base,profile);vm=cold.acquisition.Providers(base,None,[(0,cold.ENV)]*4)
    jni=cold.JNI(base,dict(profile,long_word=word));saved=sequence.v.oracle.Uc,sequence.v.oracle.GUEST_SIZE
    cpus=[];pending_once=False;returns=[];scopes=[];startup_entries=[]
    order=[0,1];position=-1;cleanup=False
    entries=sequence.array_entries(args,p,base)+(0x27B41C,)
    with args.libc.open('rb') as stream:
        elf=ELFFile(stream)
        exports={s.name:sequence.LIBC_BASE+s['st_value'] for s in elf.get_section_by_name('.dynsym').iter_symbols() if s['st_shndx']!='SHN_UNDEF'}
    def reg(cpu,i):return cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i)))
    def factory(*a,**kw):
        cpu=saved[0](*a,**kw);cpu.mem_map(0x78000000,0x200000)
        cpu.mem_map(ARENA,sequence.support.previous.ARENA_SIZE);cpus.append(cpu);return cpu
    def clock(cpu):
        status,sec,ns=service.clock(None,reg(cpu,0))
        cpu.mem_write(reg(cpu,1),(sec&MASK64).to_bytes(8,'little')+ns.to_bytes(8,'little'));return status
    def decimal(cpu):
        service.events.append(('strtol',*(reg(cpu,i) for i in range(3))))
        cpu.reg_write(arm.UC_ARM64_REG_PC,exports['strtol']);return None
    def jump(name):
        def call(cpu):cpu.reg_write(arm.UC_ARM64_REG_PC,exports[name]);return None
        return call
    def property(cpu):
        status=profile.get('property_status',0)
        if status>0:cpu.mem_write(reg(cpu,1),bytes(cpu.mem_read(base+0x6EC1E,10)))
        service.events.append(('property',reg(cpu,0),reg(cpu,1),status));return status
    def once(cpu):
        nonlocal pending_once
        assert reg(cpu,0)==base+0x3E31F8 and reg(cpu,1)==base+0x343980
        state=int.from_bytes(cpu.mem_read(base+0x3E31F8,4),'little')
        if state==0:
            cpu.mem_write(base+0x3E31F8,(1).to_bytes(4,'little'));pending_once=True
            cpu.reg_write(arm.UC_ARM64_REG_PC,base+0x343980);return None
        assert state==2;return 0
    def create_key(cpu):
        service.events.append(("key_create",reg(cpu,0),reg(cpu,1)))
        cpu.reg_write(arm.UC_ARM64_REG_PC,exports["pthread_key_create"]);return None
    def realloc(cpu):
        old,n=reg(cpu,0),reg(cpu,1);a=service.allocate(None,n)
        cpu.mem_write(a,bytes(cpu.mem_read(old,min(service.sizes[old],n))));return a
    def broadcast(cpu):
        service.events.append(('broadcast',reg(cpu,0)))
        cpu.reg_write(arm.UC_ARM64_REG_PC,exports['pthread_cond_broadcast']);return None
    def signal(cpu):
        service.events.append(('signal',reg(cpu,0)))
        cpu.reg_write(arm.UC_ARM64_REG_PC,exports['pthread_cond_signal']);return None
    def create_thread(cpu):
        assert reg(cpu,1)==0
        handle=GUEST+0xC800+len(service.threads)*0x100
        service.threads.append((handle,reg(cpu,2),reg(cpu,3)))
        service.events.append(('thread',reg(cpu,1),reg(cpu,2),reg(cpu,3),handle))
        cpu.mem_write(reg(cpu,0),handle.to_bytes(8,'little'));return 0
    def syscall(cpu,number):
        if number==93:
            assert cleanup and reg(cpu,0)==0
            service.worker_exits.append(service.worker_index)
            service.events.append(('os_exit',service.worker_index,0))
            cpu.reg_write(arm.UC_ARM64_REG_PC,NEXT);return 0
        if number==113:return clock(cpu)
        assert number==98,number
        address,operation,expected=(reg(cpu,i) for i in range(3))
        if operation&0x7F==1:return service.wake(None,address,operation,expected)
        assert service.worker_index>=0
        idx=service.worker_index
        timeout=None if not reg(cpu,3) else tuple(int.from_bytes(cpu.mem_read(reg(cpu,3)+i*8,8),'little',signed=True) for i in range(2))
        service.events.append(('wait',idx,address,operation,expected,timeout,-4))
        service.waits.append((idx,address,operation,expected))
        if idx==0:
            ctx=int.from_bytes(cpu.mem_read(service.threads[0][2]+8,8),'little')+0x18
            cpu.mem_write(ctx+0x80,b'\0');cpu.mem_write(ctx+0x84,(1).to_bytes(4,'little'))
        else:
            queue=int.from_bytes(cpu.mem_read(service.threads[idx][2]+0x18,8),'little')
            assert address==queue+0x58
            cpu.mem_write(queue+0x88,b'\0')
        return -4
    def observe(cpu,address):
        nonlocal pending_once,position,cleanup
        if address==NEXT:
            position+=1
            if position==len(order):cpu.reg_write(arm.UC_ARM64_REG_PC,sequence.v.oracle.STOP);return
            idx=order[position];service.worker_index=idx;service.thread_pointer=WORKERS[idx];cleanup=False
            _,entry,arg=service.threads[idx]
            print('Fresh full JNI -> worker',idx,hex(entry-base),flush=True)
            cpu.reg_write(arm.UC_ARM64_REG_TPIDR_EL0,WORKERS[idx]);cpu.reg_write(arm.UC_ARM64_REG_SP,WORKER_STACKS[idx])
            for i in range(19,30):cpu.reg_write(getattr(arm,'UC_ARM64_REG_X'+str(i)),0)
            cpu.reg_write(arm.UC_ARM64_REG_X0,arg);cpu.reg_write(arm.UC_ARM64_REG_X30,DONE)
            cpu.reg_write(arm.UC_ARM64_REG_PC,entry);return
        if address==DONE:
            assert reg(cpu,0)==0 and cpu.reg_read(arm.UC_ARM64_REG_SP)==WORKER_STACKS[service.worker_index]
            service.worker_returns.append(service.worker_index);cleanup=True
            print('Natural worker return',service.worker_index,flush=True)
            cpu.reg_write(arm.UC_ARM64_REG_PC,sequence.LIBC_BASE+0x68138)
            cpu.reg_write(arm.UC_ARM64_REG_X30,NEXT);return
        if address-base in (0x280554,0x29E05C):
            service.task_entries.append((service.worker_index,address-base,cpu.reg_read(arm.UC_ARM64_REG_SP)))
        if pending_once and address==base+0x343818:
            cpu.mem_write(base+0x3E31F8,(2).to_bytes(4,'little'));pending_once=False
        if address==base+0x26C858:scopes.append(reg(cpu,0))
        if address==base+0x26E70C:jni.dispatch_sp=cpu.reg_read(arm.UC_ARM64_REG_SP)
        if address==base+0x270854:jni.long_sp=cpu.reg_read(arm.UC_ARM64_REG_SP)
        if address-base in (0x2A0028,0x28040C):startup_entries.append(address-base)
        if address==DISPATCH:
            assert cpu.reg_read(arm.UC_ARM64_REG_SP)==sp
            returns.append(reg(cpu,0))
            if len(returns)==len(entries):cpu.reg_write(arm.UC_ARM64_REG_PC,NEXT)
            else:
                if len(returns)==13:
                    cpu.reg_write(arm.UC_ARM64_REG_X0,cold.acquisition.VM);cpu.reg_write(arm.UC_ARM64_REG_X1,0)
                cpu.reg_write(arm.UC_ARM64_REG_X30,DISPATCH);cpu.reg_write(arm.UC_ARM64_REG_PC,base+entries[len(returns)])
    def record_specific(name):
        def call(cpu):
            service.events.append(('getspecific',reg(cpu,0)) if name=='pthread_getspecific' else ('setspecific',reg(cpu,0),reg(cpu,1)))
            cpu.reg_write(arm.UC_ARM64_REG_PC,exports[name]);return None
        return call
    def libc_tls(cpu):
        assert reg(cpu,0)==sequence.LIBC_BASE+0xDB3A8
        service.events.append(('libc_tls',service.worker_index));return GUEST+0xBC80
    imports={fn-base:vm.imports()[fn-base] for fn in (cold.acquisition.GET,cold.acquisition.ATTACH,cold.acquisition.DETACH)}
    imports.update(jni.imports());imports.update({0x347EA0:lambda c:service.register(None,*(reg(c,i) for i in range(3))),
        0x348450:clock,0x3484B0:decimal,0x348330:lambda c:service.aux(None,reg(c,0)),
        0x347FE0:jump('memcmp'),0x348400:jump('strncmp'),0x3486D0:property,0x3486B0:once,
        0x348620:create_key,0x3485D0:record_specific("pthread_getspecific"),
        0x348580:record_specific("pthread_setspecific"),0x348320:realloc,
        0x347FA0:lambda c:service.free(None,reg(c,0)),0x3485A0:broadcast,0x348590:signal,0x348000:create_thread})
    imports.update({0x3485B0:jump("pthread_cond_wait"),0x3485C0:jump("pthread_cond_timedwait"),sequence.LIBC_BASE+0x9BE24-base:libc_tls})
    offsets=(0x343818,0x26C858,0x26E70C,0x270854,0x2A0028,0x28040C,0x280554,0x29E05C)
    ranges=((DISPATCH,DISPATCH),(DONE,DONE),(NEXT,NEXT),(sequence.LIBC_BASE+0x9BE24,sequence.LIBC_BASE+0x9BE24),(base+0x347E00,base+0x348800),
        (GUEST+0xF180,GUEST+0xF1A0),(GUEST+0xF210,GUEST+0xF450),*((base+a,base+a) for a in offsets))
    try:
        sequence.v.oracle.Uc=factory;sequence.v.oracle.GUEST_SIZE=0x160000
        sequence.v.oracle.native(args.library,base,entries[0],[],p,libc=args.libc,
            malloc_handler=lambda c,n:service.allocate(None,n),host_imports=imports,
            real_mutexes=True,real_diagnostics=True,real_recursive_mutexes=True,
            real_singletons=True,real_jni_acquisition=True,real_jni_dispatch=True,
            thread_id=lambda c:profile.get('thread_id',137) if service.worker_index<0 else 203+service.worker_index,syscall_handler=syscall,instruction_observer=observe,
            extra_registers={arm.UC_ARM64_REG_SP:sp,arm.UC_ARM64_REG_X30:DISPATCH},
            instruction_limit=900000000,code_hook_ranges=ranges)
    except Exception:
        cpu=cpus[0];print("Native failure PC/LR/SP",*[hex(cpu.reg_read(r)) for r in (arm.UC_ARM64_REG_PC,arm.UC_ARM64_REG_LR,arm.UC_ARM64_REG_SP)],service.events[-8:],flush=True);raise
    finally:sequence.v.oracle.Uc,sequence.v.oracle.GUEST_SIZE=saved
    assert len(returns)==14 and returns[-1]==0x10006 and not vm.responses and not jni.checks
    assert service.worker_returns==service.worker_exits==[0,1]
    assert [r[0] for r in service.task_entries]==[1]
    assert startup_entries==[0x2A0028 if word&0x200 else 0x28040C]
    print('Original all13 +JNI +conditional startup naturally returned',hex(base),hex(word),flush=True)
    return cpus[0],service,vm,jni,scopes

def model(args,p,base,profile,sp,word,vm_module,initial_service,constructors):
 s=Services(base,profile);s.cursor=initial_service.cursor;s.sizes=dict(initial_service.sizes);s.events=list(initial_service.events)
 result,vm,jni=s.jni(p,sp,word,vm_module)
 for idx in (0,1):
  s.worker_index=idx;s.thread_pointer=WORKERS[idx];_,entry,arg=s.threads[idx]
  def clock(p,clock_id):
   # Clock service owns the matching libc lazy cache, as its actual export
   # executes inside condition waits in the native control.
   libc=full.sequence.LIBC_BASE;guard=libc+0xDE810
   if not int.from_bytes(_read_span(p,guard,4),'little'):
    _write_span(p,libc+0xDE820,_read_span(p,libc+0xD9048,8));_write_span(p,guard,(1).to_bytes(4,'little'))
   status,sec,ns=s.clock(p,clock_id);assert status==0;return sec,ns
  def futex(p,address,operation,expected,timeout):
   s.events.append(('wait',idx,address,operation,expected,timeout,-4));s.waits.append((idx,address,operation,expected))
   if idx==0:
    context=int.from_bytes(_read_span(p,arg+8,8),'little')+0x18
    _write_span(p,context+0x80,b'\0');_write_span(p,context+0x84,(1).to_bytes(4,'little'))
   else:
    queue=int.from_bytes(_read_span(p,arg+0x18,8),'little');assert address==queue+0x58
    _write_span(p,queue+0x88,b'\0')
   return -4
  kw=dict(argument_address=arg,image_base=base,thread_pointer=s.thread_pointer,thread_id=203+idx,
   create_key=s.create,set_specific=s.setvalue,get_tls=s.get_tls,clock=clock,futex=futex,free=s.free)
  print('Independent Python -> worker',idx,'branch',hex(word),flush=True)
  def libc_tls(p,descriptor):
   assert descriptor==full.sequence.LIBC_BASE+0xDB3A8
   s.events.append(('libc_tls',idx));return full.GUEST+0xBC80
  def os_call(p,operation,*values):
   assert operation=='exit' and values==(0,)
   s.events.append(('os_exit',idx,0));s.worker_exits.append(idx);return 0
  result=worker_owner.run_requested_worker(p,thread_start_address=entry,libc_base=full.sequence.LIBC_BASE,
   startup_entry=0x2A0028 if word&0x200 else 0x28040C,entry_stack_address=WORKER_STACKS[idx],
   allocate=s.allocate,broadcast=s.broadcast,get_libc_tls=libc_tls,os_call=os_call,vm_module=vm_module,**kw)
  assert result.return_code==0;s.worker_returns.append(idx);exit_result=result.exit_result
  assert not exit_result.detached and exit_result.unmapped_regions==0
  print('Independent Python worker +exit complete',idx,flush=True)
 return s,constructors,vm,jni


def compare_case(args,initial,initial_service,constructors,base,profile,sp,word,vm_module):
 seed=fresh(args,base,profile);p={k:bytearray(v) for k,v in initial.items()}
 cpu,expected,expected_vm,expected_jni,scopes=native(args,seed,base,profile,sp,word)
 actual,constructors,vm,jni=model(args,p,base,profile,sp,word,vm_module,initial_service,constructors)
 modules=[r for r in constructors.constructor_results if hasattr(r,'effects')]
 owners={e.address:i for i,r in enumerate(modules) for e in r.effects if e.kind=='allocate'}
 streams=[[(('allocate',e.size,e.address) if e.kind=='allocate' else ('free',e.address)) for e in r.effects] for r in modules]
 modeled=[];seen=set()
 for event in actual.events:
  if event[0] not in ('allocate','free'):continue
  if event[0]=='allocate' and event[2] in owners:
   index=owners[event[2]]
   if index not in seen:modeled.extend(streams[index]);seen.add(index)
  else:modeled.append(event)
 expected_alloc=[e for e in expected.events if e[0] in ('allocate','free')]
 assert modeled==expected_alloc
 assert vm.events==expected_vm.events and jni.events==expected_jni.events
 for kinds in ({'atexit'},{'thread'},set(e[0] for e in expected.events)-{'allocate','free','atexit','thread'}):
  a=[e for e in actual.events if e[0] in kinds];b=[e for e in expected.events if e[0] in kinds]
  assert a==b,(kinds,a[-5:],b[-5:])
 for page,data in p.items():
  if 0x78000000<=page<<12<0x78200000 or full.GUEST+0xA000<=page<<12<full.GUEST+0x10000:continue
  native_bytes=bytes(cpu.mem_read(page<<12,4096))
  assert data==native_bytes,hex(page<<12)

 assert actual.worker_returns==actual.worker_exits==[0,1]
 assert actual.threads==expected.threads and actual.sizes==expected.sizes
 assert len(actual.waits)==2 and int.from_bytes(_read_span(p,base+0x3E2F30,4),'little')&0x80000000
 for i in (0,1):
  thread=int.from_bytes(_read_span(p,WORKERS[i]+8,8),'little')
  assert int.from_bytes(_read_span(p,thread+0x50,4),'little')==1
  support_key=int.from_bytes(_read_span(p,base+0x3E2F30,4),'little')
  assert allocator.pthread_getspecific(p,key=support_key,thread_pointer=WORKERS[i],generation_table=GENERATIONS)==0
 executor=int.from_bytes(_read_span(p,base+0x3E2D78,8),'little')
 queue=int.from_bytes(_read_span(p,executor+8,8),'little')
 assert int.from_bytes(_read_span(p,queue+0x20,8),'little')-int.from_bytes(_read_span(p,queue+0x18,8),'little')==48
 print('Same full JNI +two workers +guest exit PASS',hex(base),hex(word),flush=True)
 return dict(base=hex(base),switch_word=hex(word),constructors=13,JNI_version='0x10006',
  requested_workers=3,executed_workers=2,worker_waits=2,allocation_free_effect_count=len(modeled),
  natural_same_execution_loader_JNI_and_worker_returns_verified=True,
  executor_and_actual_A_or_B_initialization_queue_composed=True,
  separate_thread_TLS_and_shared_key_generations_match=True,full_joinable_guest_pthread_exit_bodies_match=True,
  all_surviving_guest_heap_image_libc_pages_match=True,ordered_service_groups_match=True,
  finalizer_queue_still_deferred=True,native_snapshot_input=False,
  physical_stack_and_thread_output_scratch_compared=False,module_registration_allocation_interleaving_compared=False)

def negatives(initial,initial_service,base):
 rows=[];s=Services(base,{})
 s.cursor=initial_service.cursor;s.sizes=dict(initial_service.sizes)
 p={k:bytearray(v) for k,v in initial.items()}
 os.environ.setdefault('TOMATO_LIBMETASEC','');import vm_full
 result,_,_=s.jni(p,sequence.v.SP,0x200,vm_full);arg=s.threads[0][2]
 def reject(label,changes=None,mutation=None):
  pages={k:bytearray(v) for k,v in p.items()}
  if mutation:mutation(pages)
  before={k:bytes(v) for k,v in pages.items()}
  index=1 if label=='NULL_allocation' else 0
  selected_arg=s.threads[index][2]
  a=Services(base,{});a.cursor=s.cursor;a.sizes=dict(s.sizes);a.thread_pointer=WORKERS[index]
  def clock(p,key):status,sec,ns=a.clock(p,key);return sec,ns
  def stop(p,address,op,expected,timeout):
   if index==0:
    ctx=int.from_bytes(_read_span(p,selected_arg+8,8),'little')+0x18
    _write_span(p,ctx+0x80,b'\0');_write_span(p,ctx+0x84,(1).to_bytes(4,'little'))
   else:
    queue=int.from_bytes(_read_span(p,selected_arg+0x18,8),'little')
    _write_span(p,queue+0x88,b'\0')
   return -4
  kw=dict(image_base=base,libc_base=sequence.LIBC_BASE,thread_start_address=s.threads[index][1],
   argument_address=selected_arg,startup_entry=result.startup_entry,entry_stack_address=WORKER_STACKS[index],
   thread_pointer=WORKERS[index],thread_id=203+index,allocate=a.allocate,free=a.free,
   create_key=a.create,set_specific=a.setvalue,get_tls=a.get_tls,clock=clock,futex=stop,broadcast=a.broadcast,
   get_libc_tls=lambda *args:GUEST+0xBC80,os_call=lambda *args:0,vm_module=vm_full)
  kw.update(changes or {})
  try:worker_owner.run_requested_worker(pages,**kw)
  except (RefillUnsupported,ValueError):pass
  else:raise AssertionError('accepted guard '+label)
  assert before=={k:bytes(v) for k,v in pages.items()},label
  rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
 for name in ('allocate','free','create_key','set_specific','get_tls','clock','futex','broadcast','get_libc_tls','os_call'):
  reject('missing_'+name,{name:None})
 for label,changes in (
  ('unaligned_image',dict(image_base=base+1)),('unaligned_libc',dict(libc_base=sequence.LIBC_BASE+1)),
  ('unaligned_argument',dict(argument_address=arg+1)),('unaligned_SP',dict(entry_stack_address=WORKER_STACKS[0]+1)),
  ('unaligned_TP',dict(thread_pointer=WORKERS[0]+1)),('zero_tid',dict(thread_id=0)),('boolean_tid',dict(thread_id=True)),
  ('unknown_worker',dict(thread_start_address=base+0x326A30)),('unknown_startup',dict(startup_entry=0)),
  ('zero_iterations',dict(max_iterations=0)),('zero_steps',dict(max_steps=0)),('zero_depth',dict(max_depth=0)),
  ('failed_key',dict(create_key=lambda *args:11)),('failed_specific',dict(set_specific=lambda *args:11)),
  ('NULL_allocation',dict(allocate=lambda *args:0)),('late_exit_failure',dict(os_call=lambda *args:None))):reject(label,changes)
 reject('detached_thread',mutation=lambda p:_write_span(p,WORKERS[0]+0x250,(3).to_bytes(4,'little')))
 reject('initial_executor_task',mutation=lambda p:_write_span(p,base+0x3E2DB8+0x18+0x60,(1).to_bytes(8,'little')))
 print('Worker rollback guards',len(rows),'PASS',flush=True);return rows

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 for name in ('library','libc','output'):parser.add_argument('--'+name,type=Path,required=True)
 parser.add_argument('--image-base',type=lambda v:int(v,0),choices=(0x122C0000,0x775C205000))
 args=parser.parse_args()
 assert hashlib.sha256(args.library.read_bytes()).hexdigest()==sequence.v.oracle.LIBRARY_SHA256
 assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==sequence.v.defined.builder.catalog.heap.LIBC_HASH
 os.environ['TOMATO_LIBMETASEC']=str(args.library);import vm_full
 rows=[];guards=[]
 for base in ((args.image_base,) if args.image_base else (0x122C0000,0x775C205000)):
  profile={} if base==0x122C0000 else dict(allocation_delta=0xC00,thread_id=1,padding=0xFF,stack_padding=0x39)
  sp=sequence.v.SP-(0 if base==0x122C0000 else 0xC80)
  initial=fresh(args,base,profile,Python=True);service=Services(base,profile);constructors=service.sequence(initial,sp)
  print('Fresh Python constructors ready',hex(base),flush=True)
  if not guards:guards=negatives(initial,service,base)
  for word in (0,0x200):rows.append(compare_case(args,initial,service,constructors,base,profile,sp,word,vm_full))
 evidence=dict(schema='vm9-jni-requested-workers-fresh-v1',evidence_date='2026-10-11',evidence_timezone='Asia/Shanghai',
  sample_sha256=sequence.v.oracle.LIBRARY_SHA256,matching_libc_sha256=sequence.v.defined.builder.catalog.heap.LIBC_HASH,
  native_Python_same_full_JNI_workers_controls=len(rows),rollback_controls=len(guards),pre_change_native_RED_controls=2,
  full_loader_JNI_executor_initialization_queue_and_joinable_exit_verified=True,
  native_input_snapshot_used=False,private_names_or_payloads_published=False,actual_OS_threads_or_exit_used=False,
  all_three_requested_workers_and_finalizer_callback_composed=False,complete_python_medusa=False,
  fresh_signer_output_verified=False,live_server_matrix_verified=False,cases=rows,negative_cases=guards)
 args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8',newline='\n')
 print('Full JNI selected workers GREEN',len(rows),'controls',len(guards),'guards',flush=True)

if __name__=='__main__':main()
