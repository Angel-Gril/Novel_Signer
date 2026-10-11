"""Fresh ELF/13 constructors/JNI/three workers and full joinable guest exit.

The native side executes original bodies in one CPU run. Python maps its
own ELF and composes the constructor, JNI, A/B worker and finalizer owners.
Copied probes additionally cover warm/cold page-size cache at both bases.
No native snapshot supplies Python state; providers have finite outcomes.
"""
from pathlib import Path
import argparse,copy,hashlib,json,os
from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as arm
import verify_vm9_jni_requested_workers_20261011 as previous
import vm9_jni_finalizer as owner
from vm9_allocator import _read_span,_write_span,RefillUnsupported
from verify_vm9_outer_signer_native import bind_native_imports

full=previous.full;sequence=full.sequence;cold=full.cold
GUEST=previous.GUEST;ARENA=previous.ARENA;DISPATCH=previous.DISPATCH;MASK64=previous.MASK64
Services=previous.Services;fresh=previous.fresh
WORKERS=previous.WORKERS;WORKER_STACKS=previous.WORKER_STACKS;DONE=previous.DONE;NEXT=previous.NEXT
u=owner._u;w=owner._w

class WorkerJNI(cold.JNI):
 def call(self,target,args,read,write):
  if target==GUEST+0xF250 and args[2]==self.base+0x3DA014:
   assert args==(cold.ENV,cold.initialization.GLOBAL,self.base+0x3DA014,self.base+0x3DA01C)
   self.events.append(['finalizer_GetStaticMethodID',target,list(args),cold.initialization.METHOD])
   return cold.initialization.METHOD
  return super().call(target,args,read,write)

def native(args,p,base,profile,sp,word):
    service=Services(base,profile);vm=cold.acquisition.Providers(base,None,[(0,cold.ENV)]*6)
    jni=WorkerJNI(base,dict(profile,long_word=word,checks=(0,0,0)));saved=sequence.v.oracle.Uc,sequence.v.oracle.GUEST_SIZE
    cpus=[];pending_once=False;returns=[];scopes=[];startup_entries=[]
    order=[0,1,2];position=-1;cleanup=False
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
        if number==101:
            service.events.append(('system',number,*(reg(cpu,i) for i in range(2))));return 0
        if number in (222,215,226):
            values=tuple(reg(cpu,i) for i in range(6));service.events.append(('system',number,*values))
            if number==222:
                assert values==(0,4096,7,33,4294967295,0)
                cpu.mem_map(0x72000000,4096);return 0x72000000
            if number==215:
                assert values[:2]==(0x72000000,4096);cpu.mem_unmap(0x72000000,4096)
            return 0
        if number==167:
            assert reg(cpu,0)==0x53564D41 and reg(cpu,1)==0
            service.events.append(('system',number,*(reg(cpu,i) for i in range(5))));return 0
        if number in (56,57,63,134):
            values=tuple(reg(cpu,i) for i in range(4))
            service.events.append(('system',number,*values))
            if number==56:return -2
            if number in (57,63):return -9
            return -22
        assert number==98,('uncovered finalizer syscall',number,tuple(reg(cpu,i) for i in range(6)))
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
        if address==base+0x1DBA24:
            assert reg(cpu,0)==1
            service.copied_probe_returned=True
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
        if address-base in (0x280554,0x29E05C,0x204348):
            service.task_entries.append((service.worker_index,address-base,cpu.reg_read(arm.UC_ARM64_REG_SP)))
        if service.worker_index==2 and base+0x347E00<=address<base+0x348800 and address-base not in imports and (address-base)%16==0:
            known=(0x347FD0,0x347F20,0x347EC0,0x347ED0,0x347EF0,0x347EE0,0x347F40,0x347F60,0x348410,0x347F00,0x347F10,0x348310)
            if address-base not in known:raise RuntimeError(('uncovered finalizer imported service',hex(address-base),hex(cpu.reg_read(arm.UC_ARM64_REG_LR))))
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
    imports.update({0x3485B0:jump("pthread_cond_wait"),0x3485C0:jump("pthread_cond_timedwait"),0x3483A0:jump("sigaction"),0x348210:jump("pthread_mutex_trylock"),sequence.LIBC_BASE+0x9BE24-base:libc_tls})
    def redirect_address(address):
        def call(cpu):cpu.reg_write(arm.UC_ARM64_REG_PC,address);return None
        return call
    bind_native_imports(args.library,args.libc,redirect_address,imports)
    offsets=(0x343818,0x26C858,0x26E70C,0x270854,0x2A0028,0x28040C,0x280554,0x29E05C,0x204348,0x1DBA24)
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
    assert service.worker_returns==service.worker_exits==[0,1,2] and service.copied_probe_returned
    assert startup_entries==[0x2A0028 if word&0x200 else 0x28040C]
    print('Original all13 +JNI +conditional startup naturally returned',hex(base),hex(word),flush=True)
    return cpus[0],service,vm,jni,scopes


def finalizer_call(p,s,base,profile,vm,vm_module,changes=None):
 idx=2;s.worker_index=idx;s.thread_pointer=WORKERS[idx];_,entry,arg=s.threads[idx]
 vm.responses=[(0,cold.ENV)]*2
 jni=WorkerJNI(base,dict(profile,checks=(0,)))
 def clock(p,key):
  status,sec,ns=s.clock(p,key);assert status==0;return sec,ns
 def stop(p,address,operation,expected,timeout):
  s.events.append(('wait',idx,address,operation,expected,timeout,-4));s.waits.append((idx,address,operation,expected))
  queue=u(p,arg+0x18);assert address==queue+0x58;w(p,queue+0x88,0,1);return -4
 def libc_tls(p,descriptor):
  assert descriptor==sequence.LIBC_BASE+0xDB3A8
  s.events.append(('libc_tls',idx));return GUEST+0xBC80
 def os_call(p,operation,*values):
  assert operation=='exit' and values==(0,)
  s.events.append(('os_exit',idx,0));s.worker_exits.append(idx);return 0
 def system(p,number,values):
  s.events.append(('system',number,*values))
  if number==56:return -2
  if number==134:return -22
  if number==222:return 0x72000000
  if number in (167,101,215):return 0
  raise AssertionError(number)
 kw=dict(thread_start_address=entry,argument_address=arg,image_base=base,libc_base=sequence.LIBC_BASE,
  entry_stack_address=WORKER_STACKS[idx],thread_pointer=WORKERS[idx],thread_id=205,
  allocate=s.allocate,free=s.free,create_key=s.create,set_specific=s.setvalue,get_tls=s.get_tls,
  read_clock=s.clock,clock=clock,futex=stop,broadcast=s.broadcast,initialize_registry=s.initialize,
  register_destructor=s.destructor,invoke_javavm=vm.model_vm,invoke_jni=jni.model,
  system=system,signal_condition=s.signal,get_libc_tls=libc_tls,os_call=os_call,vm_module=vm_module)
 kw.update(changes or {})
 result=owner.run_finalizer_worker(p,**kw)
 s.worker_returns.append(idx)
 return result,jni

def negatives(initial,initial_service,initial_vm,base,profile,vm_module):
 rows=[]
 def reject(label,changes=None,mutation=None):
  p={k:bytearray(v) for k,v in initial.items()}
  if mutation:mutation(p)
  before={k:bytes(v) for k,v in p.items()}
  s=Services(base,profile);s.__dict__.update(copy.deepcopy(initial_service.__dict__))
  vm=copy.deepcopy(initial_vm)
  try:finalizer_call(p,s,base,profile,vm,vm_module,changes)
  except (RefillUnsupported,ValueError):pass
  else:raise AssertionError('accepted finalizer guard '+label)
  assert before=={k:bytes(v) for k,v in p.items()},label
  rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
 for name in ('allocate','free','create_key','set_specific','get_tls','read_clock','clock','futex',
  'broadcast','initialize_registry','register_destructor','invoke_javavm','invoke_jni',
  'system','signal_condition','get_libc_tls','os_call'):
  reject('missing_'+name,{name:None})
 for label,changes in (
  ('unaligned_image',dict(image_base=base+1)),('unaligned_libc',dict(libc_base=sequence.LIBC_BASE+1)),
  ('unaligned_argument',dict(argument_address=initial_service.threads[2][2]+1)),
  ('unaligned_SP',dict(entry_stack_address=WORKER_STACKS[2]+1)),('unaligned_TP',dict(thread_pointer=WORKERS[2]+1)),
  ('zero_tid',dict(thread_id=0)),('boolean_tid',dict(thread_id=True)),
  ('unknown_entry',dict(thread_start_address=base+0x326A2C)),('missing_VM',dict(vm_module=None)),
  ('zero_iterations',dict(max_iterations=0)),('zero_VM_budget',dict(max_steps=0)),
  ('exhausted_VM_budget',dict(max_steps=1)),('NULL_allocation',dict(allocate=lambda *a:0)),
  ('failed_specific',dict(set_specific=lambda *a:11)),('late_exit_failure',dict(os_call=lambda *a:None)),
  ('failed_controller_signal',dict(signal_condition=lambda *a:11))):reject(label,changes)
 def system_failure(target,result):
  def system(p,n,values):
   if n==target:return result
   return {-1:0,56:-2,134:-22,222:0x72000000,167:0,101:0,215:0}[n]
  return system
 for label,n,result in (('file_present',56,3),('successful_sigaction',134,0),
  ('NULL_system_result',56,None),('boolean_system_result',56,True),('mmap_failed',222,-1),
  ('mmap_unaligned',222,0x72000001),('mmap_overlap',222,GUEST),('failed_prctl',167,-1),
  ('failed_sleep',101,-1),('failed_munmap',215,-1)):
  reject(label,dict(system=system_failure(n,result)))
 reject('detached_thread',mutation=lambda p:w(p,WORKERS[2]+0x250,3,4))
 reject('copied_code_changed',mutation=lambda p:w(p,base+0x1DB664,u(p,base+0x1DB664,1)^1,1))
 reject('unknown_image_VM_table',mutation=lambda p:w(p,base+0x37D410,u(p,base+0x37D410)+4))
 reject('invalid_page_size',mutation=lambda p:(w(p,base+0x3E1D58,1,1),w(p,base+0x3E1D50,2048,4)))
 print('Finalizer rollback guards',len(rows),'PASS',flush=True)
 return rows

def copied_controls(args,base):
 oracle=sequence.v.oracle;rows=[]
 with args.libc.open('rb') as stream:
  exports={s.name:sequence.LIBC_BASE+s['st_value'] for s in ELFFile(stream).get_section_by_name('.dynsym').iter_symbols() if s['st_shndx']!='SHN_UNDEF'}
 for cold_cache in (False,True):
  p=oracle.fresh_pages();p.update(oracle.image_pages(args.library,base))
  w(p,base+0x3E1D58,0 if cold_cache else 1,8);w(p,base+0x3E1D50,0 if cold_cache else 4096,4)
  wrapper,payload=GUEST+0x2800,GUEST+0x2A00
  w(p,base+0x3D1680,0x101);w(p,base+0x3D1678,wrapper);w(p,wrapper,payload);_write_span(p,payload,bytes(136))
  thread=GUEST+0x5000;events=[];cpus=[];old=oracle.Uc
  def factory(*a,**kw):cpu=old(*a,**kw);cpus.append(cpu);return cpu
  def reg(cpu,i):return cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i)))
  def redirect(address):
   def call(cpu):cpu.reg_write(arm.UC_ARM64_REG_PC,address);return None
   return call
  def syscall(cpu,n):
   values=tuple(reg(cpu,i) for i in range({222:6,167:5,101:2,215:6}[n]));events.append((n,values))
   if n==222:cpu.mem_map(0x72000000,4096);return 0x72000000
   if n==215:cpu.mem_unmap(0x72000000,4096)
   return 0
  imports={0x348290:redirect(exports['prctl']),0x348070:redirect(exports['munmap'])}
  bind_native_imports(args.library,args.libc,redirect,imports)
  try:
   oracle.Uc=factory
   result,_,_,_=oracle.native(args.library,base,0x1DB934,[],p,libc=args.libc,
    host_imports=imports,syscall_handler=syscall,instruction_limit=200000,
    real_singletons=True,real_mutexes=True,thread_id=205,
    extra_registers={arm.UC_ARM64_REG_TPIDR_EL0:thread})
  finally:oracle.Uc=old
  if not u(p,base+0x3D5C4C,4):
   owner.objects.decode_masked_bytes(p,source_address=base+0x83E30,destination_address=base+0x3D5C44,
    mask_address=base+0x83E38,max_bytes=64);w(p,base+0x3D5C4C,1,4)
  actual=[]
  def system(p,n,values):actual.append((n,values));return 0x72000000 if n==222 else 0
  assert owner._run_copied_probe(p,base,GUEST+0xEF90,thread,system,205)==result==1
  assert actual==events and cpus[0].reg_read(arm.UC_ARM64_REG_SP)==GUEST+0xEF00
  for page,data in p.items():
   if GUEST+0xA000<=page<<12<GUEST+oracle.GUEST_SIZE:continue
   assert bytes(data)==bytes(cpus[0].mem_read(page<<12,4096)),hex(page<<12)
  rows.append(dict(base=hex(base),cold_page_size_cache=cold_cache,probe_result=result,
   original_copied_code_executed_and_returned=True,surviving_pages_match=True,
   ordered_raw_system_effects_and_SP_match=True,native_snapshot_input=False))
  print('Actual copied probe PASS',hex(base),'cold cache',cold_cache,flush=True)
 return rows

def compare_case(args,initial,initial_service,constructors,base,profile,sp,word,vm_module,guards):
 seed=fresh(args,base,profile);p={k:bytearray(v) for k,v in initial.items()}
 cpu,expected,expected_vm,expected_jni,_=native(args,seed,base,profile,sp,word)
 actual,constructors,vm,jni=previous.model(args,p,base,profile,sp,word,vm_module,initial_service,constructors)
 if not guards and word==0x200:guards.extend(negatives(p,actual,vm,base,profile,vm_module))
 result,final_jni=finalizer_call(p,actual,base,profile,vm,vm_module);jni.events.extend(final_jni.events)
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
 assert modeled==[e for e in expected.events if e[0] in ('allocate','free')]
 assert vm.events==expected_vm.events and jni.events==expected_jni.events
 kinds=set(e[0] for e in actual.events+expected.events)-{'allocate','free','atexit','thread','system'}
 for group in ({'atexit'},{'thread'},{'system'},kinds):
  assert [e for e in actual.events if e[0] in group]==[e for e in expected.events if e[0] in group],group
 for page,data in p.items():
  if 0x78000000<=page<<12<0x78200000 or GUEST+0xA000<=page<<12<GUEST+0x10000:continue
  native_bytes=bytes(cpu.mem_read(page<<12,4096));assert bytes(data)==native_bytes,hex(page<<12)
 assert actual.worker_returns==actual.worker_exits==[0,1,2]
 assert actual.threads==expected.threads and actual.sizes==expected.sizes and len(actual.waits)==3
 assert result.return_code==0 and result.finalizer.probe_result==1 and result.finalizer.image_vm_steps==6435
 assert not result.exit_result.detached and result.exit_result.unmapped_regions==0
 for tp in WORKERS:
  assert u(p,u(p,tp+8)+0x50,4)==1
 print('Full JNI +three workers +guest exit PASS',hex(base),hex(word),flush=True)
 return dict(base=hex(base),switch_word=hex(word),constructors=13,executed_workers=3,guest_exits=3,
  worker_waits=3,allocation_free_effect_count=len(modeled),image_VM_steps=result.finalizer.image_vm_steps,
  probe_result=1,natural_same_execution_loader_JNI_all_worker_returns_verified=True,
  all_surviving_guest_heap_image_libc_pages_match=True,all_ordered_service_groups_match=True,
  original_temporary_copied_code_executed=True,actual_finalizer_JNI_and_TLS_destructor_match=True,
  first_delayed_followup_task_and_deque_match=True,complete_joinable_guest_pthread_exit_match=True,
  native_snapshot_input=False,physical_stack_and_thread_output_scratch_compared=False,
  module_registration_allocation_interleaving_compared=False)

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 for name in ('library','libc','output'):parser.add_argument('--'+name,type=Path,required=True)
 parser.add_argument('--image-base',type=lambda v:int(v,0),choices=(0x122C0000,0x775C205000))
 args=parser.parse_args()
 assert hashlib.sha256(args.library.read_bytes()).hexdigest()==sequence.v.oracle.LIBRARY_SHA256
 assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==sequence.v.defined.builder.catalog.heap.LIBC_HASH
 os.environ['TOMATO_LIBMETASEC']=str(args.library);import vm_full
 assert Path(vm_full.__file__).resolve().parent==Path(__file__).resolve().parent
 rows=[];guards=[];copied=[]
 for base in ((args.image_base,) if args.image_base else (0x122C0000,0x775C205000)):
  profile={} if base==0x122C0000 else dict(allocation_delta=0xC00,thread_id=1,padding=0xFF,stack_padding=0x39)
  sp=sequence.v.SP-(0 if base==0x122C0000 else 0xC80)
  copied.extend(copied_controls(args,base))
  initial=fresh(args,base,profile,Python=True);service=Services(base,profile);constructors=service.sequence(initial,sp)
  print('Fresh independent Python constructors ready',hex(base),flush=True)
  for word in (0,0x200):rows.append(compare_case(args,initial,service,constructors,base,profile,sp,word,vm_full,guards))
 evidence=dict(schema='vm9-jni-finalizer-worker-fresh-v1',evidence_date='2026-10-11',evidence_timezone='Asia/Shanghai',
  sample_sha256=sequence.v.oracle.LIBRARY_SHA256,matching_libc_sha256=sequence.v.defined.builder.catalog.heap.LIBC_HASH,
  native_Python_same_full_JNI_three_worker_controls=len(rows),copied_probe_controls=len(copied),
  rollback_controls=len(guards),pre_change_native_RED_controls=2,
  complete_loader_JNI_all_three_workers_and_joinable_guest_exit_verified=True,
  native_input_snapshot_used=False,private_names_or_payloads_published=False,actual_host_threads_or_exit_used=False,
  timed_followup_callback_executed=False,complete_python_medusa=False,fresh_signer_output_verified=False,
  live_server_matrix_verified=False,cases=rows,copied_probe_cases=copied,negative_cases=guards)
 args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8',newline='\n')
 print('Finalizer worker GREEN',len(rows),'full controls',len(copied),'copied controls',len(guards),'guards',flush=True)

if __name__=='__main__':main()
