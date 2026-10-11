"""Fresh constructors/JNI and three cooperative guest workers through exit.

Original instructions suspend at actual futex boundaries in one CPU run.
Python maps its own ELF and advances the same finite schedule using shared
staged pages. No native snapshot initializes the Python implementation.
"""
from pathlib import Path
import argparse,copy,hashlib,json,os
from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as arm
import verify_vm9_jni_timed_cycle_20261011 as previous
import vm9_worker_scheduler as owner
from vm9_allocator import _read_span,_write_span,RefillUnsupported
from verify_vm9_outer_signer_native import bind_native_imports
full=previous.full;sequence=previous.sequence;cold=previous.cold
GUEST=previous.GUEST;ARENA=previous.ARENA;DISPATCH=previous.DISPATCH;MASK64=previous.MASK64
Services=previous.Services;fresh=previous.fresh;WorkerJNI=previous.WorkerJNI
WORKERS=previous.WORKERS;WORKER_STACKS=previous.WORKER_STACKS;DONE=previous.DONE;NEXT=previous.NEXT
u=previous.u;w=previous.w;LATE_SP=previous.LATE_SP;LATE_DONE=previous.LATE_DONE
CALLBACK_WRAPPERS=previous.CALLBACK_WRAPPERS
POLL_DONE=previous.POLL_DONE;QUEUE_DONE=previous.QUEUE_DONE
QUEUE_SP=previous.QUEUE_SP;QUEUE_OBJECT=previous.QUEUE_OBJECT

def native(args,p,base,profile,sp,word):
    service=Services(base,dict(profile));vm=cold.acquisition.Providers(base,None,[(0,cold.ENV)]*6)
    jni=WorkerJNI(base,dict(profile,long_word=word,checks=(0,0,0)));saved=sequence.v.oracle.Uc,sequence.v.oracle.GUEST_SIZE
    cpus=[];pending_once=False;returns=[];scopes=[];startup_entries=[]
    order=[0,1,2];position=-1;cleanup=False;phase="initial";paused={};paused_pc={};wait_counts=[0,0,0]
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
        nonlocal phase
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
        wait_counts[idx]+=1
        result=-110 if idx==0 and wait_counts[idx]==2 else -4
        service.events.append(('wait',idx,address,operation,expected,timeout,result))
        service.waits.append((idx,address,operation,expected))
        if idx==0:
            ctx=int.from_bytes(cpu.mem_read(service.threads[0][2]+8,8),'little')+0x18
            assert address==ctx+0xB0
            if wait_counts[idx]==1:
                assert timeout is not None
                cpu.reg_write(arm.UC_ARM64_REG_X0,MASK64-3);paused_pc[0]=cpu.reg_read(arm.UC_ARM64_REG_PC);paused[0]=cpu.context_save()
                print('Suspend actual executor at its first wait',hex(cpu.reg_read(arm.UC_ARM64_REG_PC)),flush=True)
                cpu.reg_write(arm.UC_ARM64_REG_PC,NEXT)
            elif wait_counts[idx]==2:
                assert timeout is not None
                service.profile['time']=(184,987654321)
                print('Actual timed executor wait reaches task deadline',flush=True)
            elif wait_counts[idx]==3:
                assert int.from_bytes(cpu.mem_read(ctx+0x60,8),'little')==0
                assert ('free',service.timed_task) in service.events and ('free',service.timed_wrapper) in service.events
                cpu.mem_write(ctx+0x80,b'\0');cpu.mem_write(ctx+0x84,(1).to_bytes(4,'little'))
                cpu.reg_write(arm.UC_ARM64_REG_X0,MASK64-3);paused_pc[0]=cpu.reg_read(arm.UC_ARM64_REG_PC);paused[0]=cpu.context_save()
                phase='resume_queue';cpu.reg_write(arm.UC_ARM64_REG_PC,NEXT)
            else:raise AssertionError(('extra executor wait',wait_counts))
        else:
            queue=int.from_bytes(cpu.mem_read(service.threads[idx][2]+0x18,8),'little')
            assert address==queue+0x58
            if idx==2 and wait_counts[idx]==1:
                cpu.reg_write(arm.UC_ARM64_REG_X0,MASK64-3);paused_pc[2]=cpu.reg_read(arm.UC_ARM64_REG_PC);paused[2]=cpu.context_save()
                print('Suspend actual finalizer queue while it waits for follow-up',flush=True)
                cpu.reg_write(arm.UC_ARM64_REG_PC,NEXT)
            else:
                assert idx==1 or wait_counts[idx]==2
                cpu.mem_write(queue+0x88,b'\0')
        return result
    def observe(cpu,address):
        if getattr(service,'callback_body_driver',False):
            if address-base in (0x203A94,0x203AEC,0x203B14,0x203B70):
                service.delayed_boundaries.append(address-base)
            if address-base in CALLBACK_WRAPPERS:
                argument=reg(cpu,0)
                service.delayed_pairs.append((address-base,int.from_bytes(cpu.mem_read(argument,8),'little')-base))
        nonlocal pending_once,position,cleanup,phase
        if address==base+0x325950:
            service.actual_wrapper_SP=cpu.reg_read(arm.UC_ARM64_REG_SP)
        if address==base+0x2043BC:
            service.actual_followup_SP=cpu.reg_read(arm.UC_ARM64_REG_SP)
            service.actual_followup_callable=reg(cpu,0)
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
            if phase=='resume_queue':
                phase='queue';service.worker_index=2;service.thread_pointer=WORKERS[2];cleanup=False
                cpu.context_restore(paused[2]);cpu.reg_write(arm.UC_ARM64_REG_PC,paused_pc[2]);return
            if phase=='queue':
                phase='finish_executor';service.worker_index=0;service.thread_pointer=WORKERS[0];cleanup=False
                cpu.context_restore(paused[0]);cpu.reg_write(arm.UC_ARM64_REG_PC,paused_pc[0]);return
            if phase=='finish_executor':
                service.callback_returned=True;cpu.reg_write(arm.UC_ARM64_REG_PC,sequence.v.oracle.STOP);return
            position+=1
            if position==len(order):
                assert not vm.responses and not jni.checks
                def read(a):return int.from_bytes(cpu.mem_read(a,8),'little')
                executor=read(base+0x3E2D78);context=read(read(executor+0x10)+8)
                task=read(read(read(context+0x38)));wrapper=read(task+0x20)
                service.timed_context=context;service.timed_queue=read(executor+8)
                service.timed_task=task;service.timed_wrapper=wrapper
                service.callback_body_driver=True;service.callback_returned=False
                service.delayed_vm_start=len(vm.events);service.delayed_jni_start=len(jni.events)
                service.delayed_pairs=[];service.delayed_boundaries=[]
                vm.responses=[(0,cold.ENV)]*2
                phase='executor';service.worker_index=0;service.thread_pointer=WORKERS[0];cleanup=False
                cpu.context_restore(paused[0]);cpu.reg_write(arm.UC_ARM64_REG_PC,paused_pc[0])
                print('Resume original executor after actual timer submission',flush=True);return
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
    offsets=(0x325950,0x2043BC,0x343818,0x26C858,0x26E70C,0x270854,0x2A0028,0x28040C,0x280554,0x29E05C,0x204348,0x1DBA24,0x203A94,0x203AEC,0x203B14,0x203B70,*CALLBACK_WRAPPERS)
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
    assert service.worker_returns==service.worker_exits==[1,2,0] and service.copied_probe_returned
    assert startup_entries==[0x2A0028 if word&0x200 else 0x28040C]
    assert service.callback_returned and len(vm.events)-service.delayed_vm_start==2 and len(jni.events)==service.delayed_jni_start
    assert service.delayed_boundaries==[0x203A94,0x203AEC,0x203B14,0x203B70]
    print('Original all13 +JNI +three workers +full executor waits naturally returned',hex(base),hex(word),flush=True)
    assert wait_counts==[3,1,2],wait_counts
    return cpus[0],service,vm,jni,scopes


def schedule_call(p,s,base,profile,jni_result,vm,vm_module,changes=None):
    selection=iter((0,1,1,2,0,0,2,2,0));counts=[0,0,0]
    vm.responses=[(0,cold.ENV)]*2
    jni=WorkerJNI(base,dict(profile,checks=(0,)))
    def select(p,candidates):return next(selection)
    def activate(p,index,tp):s.worker_index=index;s.thread_pointer=tp
    def clock(p,key):
        libc=sequence.LIBC_BASE;guard=libc+0xDE810
        if not u(p,guard,4):w(p,libc+0xDE820,u(p,libc+0xD9048));w(p,guard,1,4)
        status,sec,ns=s.clock(p,key);assert status==0;return sec,ns
    def futex(p,address,operation,expected,timeout):
        index=s.worker_index;counts[index]+=1
        result=-110 if index==0 and counts[index]==2 else -4
        s.events.append(('wait',index,address,operation,expected,timeout,result))
        s.waits.append((index,address,operation,expected))
        if index==0:
            context=u(p,s.threads[0][2]+8)+0x18
            assert address==context+0xB0 and timeout is not None
            if counts[index]==2:s.profile=dict(s.profile,time=(184,987654321))
            elif counts[index]==3:
                assert u(p,context+0x60)==0
                w(p,context+0x80,0,1);w(p,context+0x84,1,4)
            else:assert counts[index]==1
        else:
            queue=u(p,s.threads[index][2]+0x18);assert address==queue+0x58
            if index==2 and counts[index]==1:
                assert not vm.responses and not jni.checks
                s.delayed_vm_start=len(vm.events);s.delayed_jni_start=len(jni.events)
                vm.responses=[(0,cold.ENV)]*2
            else:
                assert index==1 or counts[index]==2;w(p,queue+0x88,0,1)
        return result
    def libc_tls(p,descriptor):
        assert descriptor==sequence.LIBC_BASE+0xDB3A8
        s.events.append(('libc_tls',s.worker_index));return GUEST+0xBC80
    def os_call(p,operation,*values):
        assert operation=='exit' and values==(0,)
        s.events.append(('os_exit',s.worker_index,0));s.worker_exits.append(s.worker_index);return 0
    def system(p,number,values):
        s.events.append(('system',number,*values))
        if number==56:return -2
        if number==57:return -9
        if number==134:return -22
        if number==222:return 0x72000000
        if number in (167,101,215):return 0
        raise AssertionError(number)
    def property(p,name):
        assert name==base+0x3DF150
        s.events.append(('property_find',name,0));return None
    kw=dict(threads=s.threads,image_base=base,libc_base=sequence.LIBC_BASE,
        startup_entry=jni_result.startup_entry,entry_stack_addresses=WORKER_STACKS,
        thread_pointers=WORKERS,thread_ids=(203,204,205),select_worker=select,activate_thread=activate,
        allocate=s.allocate,free=s.free,create_key=s.create,set_specific=s.setvalue,get_tls=s.get_tls,
        read_clock=s.clock,clock=clock,futex=futex,broadcast=s.broadcast,initialize_registry=s.initialize,
        register_destructor=s.destructor,invoke_javavm=vm.model_vm,invoke_jni=jni.model,read_property=property,
        system=system,signal_condition=s.signal,get_libc_tls=libc_tls,os_call=os_call,vm_module=vm_module)
    kw.update(changes or {})
    result=owner.run_requested_worker_schedule(p,**kw)
    assert counts==[3,1,2] and result.return_order==(1,2,0)
    assert result.futex_waits==6 and result.scheduler_steps==9
    s.worker_returns=list(result.return_order)
    assert not vm.responses and not jni.checks and len(jni.events)==s.delayed_jni_start
    return result,jni


def model(args,p,base,profile,sp,word,vm_module,initial_service,guards=None):
    s=Services(base,dict(profile));s.cursor=initial_service.cursor
    s.sizes=dict(initial_service.sizes);s.events=list(initial_service.events)
    jni_result,vm,jni=s.jni(p,sp,word,vm_module)
    if guards is not None and not guards:guards.extend(negatives(p,s,base,profile,jni_result,vm,vm_module))
    print('Independent Python -> complete cooperative workers',hex(base),hex(word),flush=True)
    result,worker_jni=schedule_call(p,s,base,profile,jni_result,vm,vm_module)
    jni.events.extend(worker_jni.events)
    return s,result,vm,jni


def negatives(initial,initial_service,base,profile,jni_result,initial_vm,vm_module):
    rows=[]
    def reject(label,changes=None,mutation=None):
        p={k:bytearray(v) for k,v in initial.items()}
        if mutation:mutation(p)
        before={k:bytes(v) for k,v in p.items()}
        s=Services(base,dict(profile));s.__dict__.update(copy.deepcopy(initial_service.__dict__))
        vm=copy.deepcopy(initial_vm)
        try:schedule_call(p,s,base,profile,jni_result,vm,vm_module,changes)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError('accepted worker schedule guard '+label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
    for name in ('select_worker','activate_thread','futex','free','invoke_javavm'):
        reject('missing_'+name,{name:None})
    for label,changes in (
        ('zero_worker_bound',dict(max_iterations=0)),('excess_worker_bound',dict(max_iterations=4097)),
        ('zero_scheduler_bound',dict(max_scheduler_steps=0)),('excess_scheduler_bound',dict(max_scheduler_steps=4097)),
        ('unknown_startup',dict(startup_entry=0)),('unaligned_image',dict(image_base=base+1)),
        ('aliased_thread_pointers',dict(thread_pointers=(WORKERS[0],WORKERS[0],WORKERS[2]))),
        ('invalid_thread_id',dict(thread_ids=(0,204,205))),
        ('unknown_worker_entry',dict(threads=((initial_service.threads[0][0],base,initial_service.threads[0][2]),*initial_service.threads[1:]))),
        ('unavailable_worker',dict(select_worker=lambda *args:3)),
        ('invalid_activation',dict(activate_thread=lambda *args:1)),
        ('selection_bound_after_actual_wait',dict(max_scheduler_steps=1)),
        ('invalid_futex_resume',dict(futex=lambda *args:-4096))):reject(label,changes)
    reject('busy_joinable_storage',mutation=lambda p:w(p,u(p,WORKERS[0]+8)+0x50,1,4))
    def fail(*args):raise RefillUnsupported('injected service refusal')
    reject('provider_failure_after_actual_unlock',dict(futex=fail))
    reject('initializer_exit_failure',dict(os_call=fail))
    reject('finalizer_system_failure',dict(system=fail))
    # Let actual finalizer submission signal the controller, then fail the
    # executor's later queue transfer after both earlier workers changed pages.
    def late_signal(p,address):
        if address==u(p,initial_service.threads[2][2]+0x18)+0x58:raise RefillUnsupported('late timed transfer refusal')
        initial_service_copy=Services(base,dict(profile))
        return initial_service_copy.signal(p,address)
    reject('timed_transfer_failure_after_shared_waits',dict(signal_condition=late_signal))
    print('Cooperative schedule rollback guards',len(rows),'PASS',flush=True)
    return rows


def compare_case(args,initial,initial_service,constructors,base,profile,sp,word,vm_module,guards):
    seed=fresh(args,base,profile);p={k:bytearray(v) for k,v in initial.items()}
    cpu,expected,expected_vm,expected_jni,_=native(args,seed,base,profile,sp,word)
    actual,result,vm,jni=model(args,p,base,profile,sp,word,vm_module,initial_service,guards)
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
    kinds=set(e[0] for e in actual.events+expected.events)-{'allocate','free','atexit','thread','system'}
    for group in ({'atexit'},{'thread'},{'system'},kinds):
        a=[e for e in actual.events if e[0] in group];b=[e for e in expected.events if e[0] in group]
        assert a==b,(group,next(((i,x,y) for i,(x,y) in enumerate(zip(a,b)) if x!=y),None),len(a),len(b))
    for page,data in p.items():
        if 0x78000000<=page<<12<0x78200000 or GUEST+0xA000<=page<<12<GUEST+0x10000:continue
        native_bytes=bytes(cpu.mem_read(page<<12,4096))
        assert bytes(data)==native_bytes,(hex(page<<12),[(hex(i),x,y) for i,(x,y) in enumerate(zip(data,native_bytes)) if x!=y][:16])
    assert actual.worker_returns==actual.worker_exits==expected.worker_returns==expected.worker_exits==[1,2,0]
    assert actual.threads==expected.threads and actual.sizes==expected.sizes and len(actual.waits)==6
    delayed=[r for index,function,r in result.task_results if function==base+0x2043BC]
    assert len(delayed)==1;callback=delayed[0]
    assert callback.callback_pairs==tuple(expected.delayed_pairs) and len(callback.callback_pairs)==15
    assert callback.checksum_vm_steps==8606106 and callback.lookup_vm_steps==301
    assert len(vm.events)-actual.delayed_vm_start==2 and len(jni.events)==expected.delayed_jni_start
    assert expected.actual_wrapper_SP==WORKER_STACKS[0]-0xA0
    assert expected.actual_followup_SP==WORKER_STACKS[2]-0xD0
    assert expected.actual_followup_callable==WORKER_STACKS[2]-0xC0
    print('Fresh full cooperative JNI workers PASS',hex(base),hex(word),flush=True)
    return dict(base=hex(base),switch_word=hex(word),constructors=13,executed_workers=3,guest_exits=3,
        worker_return_order=actual.worker_returns,worker_exit_order=actual.worker_exits,
        futex_waits=6,worker_wait_counts=[3,1,2],scheduler_steps=result.scheduler_steps,
        allocation_free_effect_count=len(modeled),checksum_VM_steps=callback.checksum_vm_steps,
        lookup_VM_steps=callback.lookup_vm_steps,actual_VM_callbacks=len(callback.callback_pairs),
        added_JavaVM_GetEnv_calls=2,added_JNI_calls=0,all_surviving_guest_heap_image_libc_pages_match=True,
        all_ordered_service_groups_match=True,complete_executor_worker_wait_cycle_verified=True,
        native_snapshot_input=False,actual_host_threads_used=False,
        physical_stack_and_thread_output_scratch_compared=False,module_registration_allocation_interleaving_compared=False)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('library','libc','output'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--image-base',type=lambda v:int(v,0),choices=(0x122C0000,0x775C205000))
    parser.add_argument('--switch-word',type=lambda v:int(v,0),choices=(0,0x200))
    parser.add_argument('--controls-only',action='store_true',help='Run fresh complete comparisons without the rollback suite')
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
            rows.append(compare_case(args,initial,service,constructors,base,profile,sp,word,vm_full,
                None if args.controls_only else guards))
    evidence=dict(schema='vm9-jni-worker-schedule-fresh-v1',evidence_date='2026-10-11',evidence_timezone='Asia/Shanghai',
        sample_sha256=sequence.v.oracle.LIBRARY_SHA256,matching_libc_sha256=sequence.v.defined.builder.catalog.heap.LIBC_HASH,
        native_Python_complete_worker_schedule_controls=len(rows),rollback_controls=len(guards),pre_change_native_RED_controls=2,
        complete_executor_worker_wait_cycle_verified=True,native_input_snapshot_used=False,
        private_names_or_payloads_published=False,actual_host_threads_or_exit_used=False,
        live_Java_string_conversion_verified=False,complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False,cases=rows,negative_cases=guards)
    args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('Full cooperative worker schedule GREEN',len(rows),'full controls',len(guards),'guards',flush=True)


if __name__=='__main__':main()
