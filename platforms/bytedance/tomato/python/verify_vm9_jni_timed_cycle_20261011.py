"""Fresh timed poll, callable transfer, queue body and owning cleanup.

Original ELF instructions execute all prerequisites and then a due poll and
the queue body in the same CPU run. Python independently maps ELF and composes
the timed dispatch, generic poll/queue and actual delayed callback owners.
This finite poll/queue driver does not prove an executor worker wait cycle.
"""
from pathlib import Path
import argparse,copy,hashlib,json,os
from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as arm
import verify_vm9_jni_followup_20261011 as previous
import vm9_timed_tasks as timed
import vm9_startup as startup
from vm9_allocator import _read_span,_write_span,RefillUnsupported
from verify_vm9_outer_signer_native import bind_native_imports
full=previous.full;sequence=previous.sequence;cold=previous.cold;owner=previous.owner
GUEST=previous.GUEST;ARENA=previous.ARENA;DISPATCH=previous.DISPATCH;MASK64=previous.MASK64
Services=previous.Services;fresh=previous.fresh;WorkerJNI=previous.WorkerJNI
WORKERS=previous.WORKERS;WORKER_STACKS=previous.WORKER_STACKS;DONE=previous.DONE;NEXT=previous.NEXT
u=owner.u;w=owner.w;LATE_SP=previous.LATE_SP;LATE_DONE=previous.LATE_DONE
CALLBACK_WRAPPERS=previous.CALLBACK_WRAPPERS
POLL_DONE=GUEST+0xF940;QUEUE_DONE=GUEST+0xF950
QUEUE_SP=LATE_SP+0xA0;QUEUE_OBJECT=LATE_SP+0x1000

def native(args,p,base,profile,sp,word):
    service=Services(base,dict(profile));vm=cold.acquisition.Providers(base,None,[(0,cold.ENV)]*6)
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
    def property_find(cpu):
        assert reg(cpu,0)==base+0x3DF150
        service.events.append(('property_find',reg(cpu,0),0));return 0
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
            # close(2) has only the fd argument; the other registers are stale.
            service.events.append(('system',number,*(values[:1] if number==57 else values)))
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
        if getattr(service,'callback_body_driver',False):
            if address-base in (0x203A94,0x203AEC,0x203B14,0x203B70):
                service.delayed_boundaries.append(address-base)
            if address-base in CALLBACK_WRAPPERS:
                argument=reg(cpu,0)
                service.delayed_pairs.append((address-base,int.from_bytes(cpu.mem_read(argument,8),'little')-base))
        nonlocal pending_once,position,cleanup
        if address==base+0x1DBA24:
            assert reg(cpu,0)==1
            service.copied_probe_returned=True
        if address==POLL_DONE:
            assert reg(cpu,0)==0xFFFFFFFF and cpu.reg_read(arm.UC_ARM64_REG_SP)==LATE_SP
            def read(a):return int.from_bytes(cpu.mem_read(a,8),'little')
            assert read(service.timed_context+0x60)==0
            queue=service.timed_queue
            assert read(queue+0x20)-read(queue+0x18)==48
            assert read(read(queue+0x18))==base+0x34F058
            assert ('free',service.timed_task) in service.events and ('free',service.timed_wrapper) in service.events
            service.timed_poll_returned=True
            for offset,value in ((0,base+0x372600),(8,queue),(0x20,QUEUE_OBJECT)):
                cpu.mem_write(QUEUE_OBJECT+offset,value.to_bytes(8,'little'))
            cpu.reg_write(arm.UC_ARM64_REG_SP,QUEUE_SP)
            for i in range(19,30):cpu.reg_write(getattr(arm,'UC_ARM64_REG_X'+str(i)),0)
            cpu.reg_write(arm.UC_ARM64_REG_X0,QUEUE_OBJECT);cpu.reg_write(arm.UC_ARM64_REG_X30,QUEUE_DONE)
            cpu.reg_write(arm.UC_ARM64_REG_PC,base+0x326578);return
        if address==QUEUE_DONE:
            assert cpu.reg_read(arm.UC_ARM64_REG_SP)==QUEUE_SP
            def read(a):return int.from_bytes(cpu.mem_read(a,8),'little')
            assert read(service.timed_queue+0x18)==read(service.timed_queue+0x20)
            service.callback_returned=True;service.timed_queue_returned=True
            cpu.reg_write(arm.UC_ARM64_REG_PC,sequence.v.oracle.STOP);return
        if address==LATE_DONE:
            assert cpu.reg_read(arm.UC_ARM64_REG_SP)==LATE_SP
            service.callback_returned=True
            cpu.reg_write(arm.UC_ARM64_REG_PC,sequence.v.oracle.STOP);return
        if address==NEXT:
            position+=1
            if position==len(order):
                assert not vm.responses and not jni.checks
                def read(a):return int.from_bytes(cpu.mem_read(a,8),'little')
                executor=read(base+0x3E2D78);payload=read(executor+0x10);context=read(payload+8)
                task=read(read(read(context+0x38)));wrapper=read(task+0x20)
                assert read(wrapper)==base+0x3725B8 and read(wrapper+0x18)&255==1
                service.timed_context=context;service.timed_queue=read(executor+8)
                service.timed_task=task;service.timed_wrapper=wrapper
                service.callback_body_driver=True;service.callback_returned=False
                service.delayed_vm_start=len(vm.events);service.delayed_jni_start=len(jni.events)
                service.delayed_pairs=[];service.delayed_boundaries=[]
                service.profile['time']=(184,987654321)
                vm.responses=[(0,cold.ENV)]*2
                service.worker_index=-1;service.thread_pointer=sequence.configuration.TP
                cpu.reg_write(arm.UC_ARM64_REG_TPIDR_EL0,service.thread_pointer)
                cpu.reg_write(arm.UC_ARM64_REG_SP,LATE_SP)
                for i in range(19,30):cpu.reg_write(getattr(arm,'UC_ARM64_REG_X'+str(i)),0)
                cpu.reg_write(arm.UC_ARM64_REG_X0,context);cpu.reg_write(arm.UC_ARM64_REG_X30,POLL_DONE)
                cpu.reg_write(arm.UC_ARM64_REG_PC,base+0x326DFC)
                print('Fresh original due timed poll -> wrapper -> queue',flush=True);return
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
        0x347FE0:jump('memcmp'),0x348400:jump('strncmp'),0x3486D0:property,0x3486B0:once,0x348250:property_find,
        0x348620:create_key,0x3485D0:record_specific("pthread_getspecific"),
        0x348580:record_specific("pthread_setspecific"),0x348320:realloc,
        0x347FA0:lambda c:service.free(None,reg(c,0)),0x3485A0:broadcast,0x348590:signal,0x348000:create_thread})
    imports.update({0x3485B0:jump("pthread_cond_wait"),0x3485C0:jump("pthread_cond_timedwait"),0x3483A0:jump("sigaction"),0x348210:jump("pthread_mutex_trylock"),sequence.LIBC_BASE+0x9BE24-base:libc_tls})
    def redirect_address(address):
        def call(cpu):cpu.reg_write(arm.UC_ARM64_REG_PC,address);return None
        return call
    bind_native_imports(args.library,args.libc,redirect_address,imports)
    offsets=(0x343818,0x26C858,0x26E70C,0x270854,0x2A0028,0x28040C,0x280554,0x29E05C,0x204348,0x1DBA24,0x203A94,0x203AEC,0x203B14,0x203B70,*CALLBACK_WRAPPERS)
    ranges=((DISPATCH,DISPATCH),(DONE,DONE),(NEXT,NEXT),(LATE_DONE,LATE_DONE),(POLL_DONE,POLL_DONE),(QUEUE_DONE,QUEUE_DONE),(sequence.LIBC_BASE+0x9BE24,sequence.LIBC_BASE+0x9BE24),(base+0x347E00,base+0x348800),
        (GUEST+0xF180,GUEST+0xF1A0),(GUEST+0xF210,GUEST+0xF450),*((base+a,base+a) for a in offsets))
    try:
        sequence.v.oracle.Uc=factory;sequence.v.oracle.GUEST_SIZE=0x160000
        sequence.v.oracle.native(args.library,base,entries[0],[],p,libc=args.libc,
            malloc_handler=lambda c,n:service.allocate(None,n),host_imports=imports,
            real_mutexes=True,real_diagnostics=True,real_recursive_mutexes=True,
            real_singletons=True,real_jni_acquisition=True,real_jni_dispatch=True,
            thread_id=lambda c:profile.get('thread_id',137) if service.worker_index<0 else 203+service.worker_index,syscall_handler=syscall,instruction_observer=observe,
            extra_registers={arm.UC_ARM64_REG_SP:sp,arm.UC_ARM64_REG_X30:DISPATCH},
            instruction_limit=1800000000,code_hook_ranges=ranges)
    except Exception:
        cpu=cpus[0];print("Native failure PC/LR/SP",*[hex(cpu.reg_read(r)) for r in (arm.UC_ARM64_REG_PC,arm.UC_ARM64_REG_LR,arm.UC_ARM64_REG_SP)],service.events[-8:],flush=True);raise
    finally:sequence.v.oracle.Uc,sequence.v.oracle.GUEST_SIZE=saved
    assert len(returns)==14 and returns[-1]==0x10006 and not vm.responses and not jni.checks
    assert service.worker_returns==service.worker_exits==[0,1,2] and service.copied_probe_returned
    assert startup_entries==[0x2A0028 if word&0x200 else 0x28040C]
    assert service.callback_returned and len(vm.events)-service.delayed_vm_start==2 and len(jni.events)==service.delayed_jni_start
    assert service.delayed_boundaries==[0x203A94,0x203AEC,0x203B14,0x203B70]
    print('Original all13 +JNI +workers +timed poll/queue naturally returned',hex(base),hex(word),flush=True)
    return cpus[0],service,vm,jni,scopes


def context_and_wrapper(p,base):
 executor=u(p,base+0x3E2D78);ctx=u(p,u(p,executor+0x10)+8)
 task=u(p,u(p,u(p,ctx+0x38)));return ctx,u(p,task+0x20)


def cycle_call(p,s,base,profile,vm,vm_module):
 s.worker_index=-1;s.thread_pointer=sequence.configuration.TP
 s.profile=dict(s.profile,time=(184,987654321));vm.responses=[(0,cold.ENV)]*2
 context,wrapper=context_and_wrapper(p,base);results=[];dispatched=[]
 def clock(p,key):
  status,seconds,nanos=s.clock(p,key);assert status==0;return seconds,nanos
 def transfer(p,function,address):
  assert function==base+0x325950 and address==wrapper
  dispatched.append(timed.dispatch_timed_callable(p,wrapper_address=address,entry_stack_address=LATE_SP-0x40,
   image_base=base,free=s.free,signal_condition=s.signal))
 assert startup.poll_executor(p,context_address=context,image_base=base,clock=clock,free=s.free,invoke=transfer)==-1
 assert len(dispatched)==1 and u(p,context+0x60)==0
 queue=dispatched[0]
 for offset,value in ((0,base+0x372600),(8,queue),(0x20,QUEUE_OBJECT)):w(p,QUEUE_OBJECT+offset,value)
 def system(p,number,values):
  assert number in (56,57) and len(values)==(4 if number==56 else 1)
  s.events.append(('system',number,*values));return -2 if number==56 else -9
 def property(p,name):
  assert name==base+0x3DF150
  s.events.append(('property_find',name,0));return None
 def body(p,function,address):
  assert function==base+0x2043BC and address==LATE_SP+0x10
  results.append(owner.run_delayed_followup_callable(p,callable_address=address,image_base=base,
   entry_stack_address=LATE_SP,thread_pointer=s.thread_pointer,thread_id=profile.get('thread_id',137),
   allocate=s.allocate,free=s.free,read_clock=s.clock,get_tls=s.get_tls,initialize_registry=s.initialize,
   broadcast=s.broadcast,register_destructor=s.destructor,invoke_javavm=vm.model_vm,
   read_property=property,system=system,vm_module=vm_module))
 def wait(*args):raise AssertionError('stopped timed queue unexpectedly waited')
 count=startup.run_queue_callable(p,object_address=QUEUE_OBJECT,task_address=LATE_SP+0x10,image_base=base,
  thread_pointer=s.thread_pointer,clock=clock,futex=wait,free=s.free,invoke=body)
 assert count==1 and len(results)==1 and not vm.responses
 assert u(p,queue+0x18)==u(p,queue+0x20)
 return results[0]


def negatives(initial,initial_service,initial_vm,base,profile,vm_module):
 rows=[]
 def reject(label,changes=None,mutation=None,destructor=False):
  p={k:bytearray(v) for k,v in initial.items()}
  context,wrapper=context_and_wrapper(p,base)
  if mutation:mutation(p,context,wrapper)
  before={k:bytes(v) for k,v in p.items()}
  s=Services(base,profile);s.__dict__.update(copy.deepcopy(initial_service.__dict__))
  if destructor:
   obj=LATE_SP+0x1000;w(p,obj+0x20,wrapper);before={k:bytes(v) for k,v in p.items()}
   call=lambda:startup.destroy_callable(p,object_address=obj,image_base=base,free=s.free,reset=True)
  else:
   kw=dict(wrapper_address=wrapper,entry_stack_address=LATE_SP-0x40,image_base=base,free=s.free,signal_condition=s.signal)
   kw.update(changes or {});call=lambda:timed.dispatch_timed_callable(p,**kw)
  try:call()
  except (RefillUnsupported,ValueError):pass
  else:raise AssertionError('accepted timed cycle guard '+label)
  assert before=={k:bytes(v) for k,v in p.items()},label
  rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
 for name in ('free','signal_condition'):reject('missing_'+name,{name:None})
 for label,changes in (
  ('unaligned_image',dict(image_base=base+1)),('unaligned_wrapper',dict(wrapper_address=context_and_wrapper(initial,base)[1]+1)),
  ('unaligned_SP',dict(entry_stack_address=LATE_SP+1)),('NULL_wrapper',dict(wrapper_address=0))):reject(label,changes)
 for label,mutation in (
  ('unknown_wrapper',lambda p,c,t:w(p,t,base+0x3725C0)),
  ('unknown_dispatch_method',lambda p,c,t:w(p,base+0x3725E8,base+0x325954)),
  ('unknown_nested_callable',lambda p,c,t:w(p,t+0x20,base+0x34F010)),
  ('unknown_nested_self_pointer',lambda p,c,t:w(p,t+0x40,0)),
  ('unknown_queue_selector',lambda p,c,t:w(p,t+0x18,2,1)),
  ('foreign_executor',lambda p,c,t:w(p,t+0x10,0)),
  ('cold_executor',lambda p,c,t:w(p,base+0x3E2D80,0,1)),
  ('no_queue_storage',lambda p,c,t:w(p,u(p,u(p,t+0x10)+8)+0x18,0)),
  ('nonempty_queue',lambda p,c,t:w(p,u(p,u(p,t+0x10)+8)+0x20,u(p,u(p,u(p,t+0x10)+8)+0x18)+48)),
  ('unknown_retained_capacity',lambda p,c,t:w(p,u(p,u(p,t+0x10)+8)+0x28,u(p,u(p,u(p,t+0x10)+8)+0x18)+96)),
  ('contended_queue',lambda p,c,t:w(p,u(p,u(p,t+0x10)+8)+0x30,1,4))):reject(label,mutation=mutation)
 reject('failed_signal',dict(signal_condition=lambda *args:-1))
 for label,mutation in (
  ('unknown_timed_destructor',lambda p,c,t:w(p,base+0x3725E0,base+0x32592C)),
  ('unknown_timed_inner_ownership',lambda p,c,t:w(p,t+0x40,0))):reject(label,mutation=mutation,destructor=True)
 print('Timed transfer and destructor rollback guards',len(rows),'PASS',flush=True)
 return rows

def compare_case(args,initial,initial_service,constructors,base,profile,sp,word,vm_module,guards):
 seed=fresh(args,base,profile);p={k:bytearray(v) for k,v in initial.items()}
 cpu,expected,expected_vm,expected_jni,_=native(args,seed,base,profile,sp,word)
 actual,constructors,vm,jni=full.previous.model(args,p,base,profile,sp,word,vm_module,initial_service,constructors)
 finalizer,final_jni=full.finalizer_call(p,actual,base,profile,vm,vm_module);jni.events.extend(final_jni.events)
 if not guards:guards.extend(negatives(p,actual,vm,base,profile,vm_module))
 vm_start=len(vm.events);jni_start=len(jni.events)
 print('Independent Python -> due poll and actual queue body',hex(base),hex(word),flush=True)
 result=cycle_call(p,actual,base,profile,vm,vm_module)
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
 assert modeled==expected_alloc,('allocation/free',next(((i,a,b) for i,(a,b) in enumerate(zip(modeled,expected_alloc)) if a!=b),None),len(modeled),len(expected_alloc))
 assert vm.events==expected_vm.events and jni.events==expected_jni.events
 assert len(vm.events)-vm_start==2 and len(jni.events)==jni_start
 kinds=set(e[0] for e in actual.events+expected.events)-{'allocate','free','atexit','thread','system'}
 for group in ({'atexit'},{'thread'},{'system'},kinds):
  a=[e for e in actual.events if e[0] in group];b=[e for e in expected.events if e[0] in group]
  assert a==b,(group,next(((i,x,y) for i,(x,y) in enumerate(zip(a,b)) if x!=y),None),len(a),len(b))
 for page,data in p.items():
  if 0x78000000<=page<<12<0x78200000 or GUEST+0xA000<=page<<12<GUEST+0x10000:continue
  native_bytes=bytes(cpu.mem_read(page<<12,4096))
  assert bytes(data)==native_bytes,(hex(page<<12),[(hex(i),x,y) for i,(x,y) in enumerate(zip(data,native_bytes)) if x!=y][:16])
 assert actual.worker_returns==actual.worker_exits==[0,1,2]
 assert actual.threads==expected.threads and actual.sizes==expected.sizes and len(actual.waits)==3
 assert result.callback_pairs==tuple(expected.delayed_pairs) and len(result.callback_pairs)==15
 assert result.checksum_vm_steps==8606106 and result.lookup_vm_steps==301
 assert finalizer.return_code==0 and finalizer.finalizer.probe_result==1
 print('Fresh complete JNI/cleanup/timed transfer/queue body PASS',hex(base),hex(word),flush=True)
 return dict(base=hex(base),switch_word=hex(word),constructors=13,executed_workers=3,guest_exits=3,
  allocation_free_effect_count=len(modeled),checksum_VM_steps=result.checksum_vm_steps,
  lookup_VM_steps=result.lookup_vm_steps,actual_VM_callbacks=len(result.callback_pairs),
  added_JavaVM_GetEnv_calls=2,added_JNI_calls=0,
  all_surviving_guest_heap_image_libc_pages_match=True,all_ordered_service_groups_match=True,
  actual_delayed_callable_naturally_returned=True,configuration_writes_and_owning_cleanup_match=True,
  both_image_VMs_reached_original_exits=True,due_task_popped_and_wrapper_task_cleanup_match=True,queued_body_and_empty_queue_match=True,explicit_poll_and_queue_driver=True,
  complete_executor_worker_wait_cycle_verified=False,native_snapshot_input=False,
  physical_stack_and_thread_output_scratch_compared=False,
  module_registration_allocation_interleaving_compared=False)

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 for name in ('library','libc','output'):parser.add_argument('--'+name,type=Path,required=True)
 parser.add_argument('--image-base',type=lambda v:int(v,0),choices=(0x122C0000,0x775C205000))
 parser.add_argument('--switch-word',type=lambda v:int(v,0),choices=(0,0x200))
 args=parser.parse_args()
 assert hashlib.sha256(args.library.read_bytes()).hexdigest()==sequence.v.oracle.LIBRARY_SHA256
 assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==sequence.v.defined.builder.catalog.heap.LIBC_HASH
 os.environ['TOMATO_LIBMETASEC']=str(args.library);import vm_full
 assert Path(vm_full.__file__).resolve().parent==Path(__file__).resolve().parent
 rows=[];guards=[]
 for base in ((args.image_base,) if args.image_base else (0x122C0000,0x775C205000)):
  profile={} if base==0x122C0000 else dict(allocation_delta=0xC00,thread_id=1,padding=0xFF,stack_padding=0x39)
  sp=sequence.v.SP-(0 if base==0x122C0000 else 0xC80)
  initial=fresh(args,base,profile,Python=True);service=Services(base,profile);constructors=service.sequence(initial,sp)
  print('Fresh independent Python constructors ready',hex(base),flush=True)
  for word in ((args.switch_word,) if args.switch_word is not None else (0,0x200)):
   rows.append(compare_case(args,initial,service,constructors,base,profile,sp,word,vm_full,guards))
 evidence=dict(schema='vm9-jni-timed-cycle-fresh-v1',evidence_date='2026-10-11',evidence_timezone='Asia/Shanghai',
  sample_sha256=sequence.v.oracle.LIBRARY_SHA256,matching_libc_sha256=sequence.v.defined.builder.catalog.heap.LIBC_HASH,
  native_Python_complete_timed_transfer_controls=len(rows),rollback_controls=len(guards),pre_change_native_RED_controls=2,
  complete_loader_JNI_workers_exit_timed_transfer_and_queue_body_verified=True,
  native_input_snapshot_used=False,private_names_or_payloads_published=False,actual_host_threads_or_exit_used=False,
  timed_followup_callback_executed=True,complete_executor_worker_wait_cycle_verified=False,
  live_Java_string_conversion_verified=False,complete_python_medusa=False,fresh_signer_output_verified=False,
  live_server_matrix_verified=False,cases=rows,negative_cases=guards)
 args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8',newline='\n')
 print('Timed transfer and queue body GREEN',len(rows),'full controls',len(guards),'guards',flush=True)

if __name__=='__main__':main()
