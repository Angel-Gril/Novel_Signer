"""Bounded main-thread async startup from explicit ELF and thread services.

Threads are an environment boundary. This model generates their descriptors,
queues and ownership; it does not silently run or omit worker side effects.
Only the observed serial, successful-create/default-queue path is supported.
"""
from __future__ import annotations
from dataclasses import dataclass
import vm9_objects as objects
from vm9_allocator import _PageTransaction, _read_span, _write_span, RefillUnsupported


def _u(p,a,n=8):return int.from_bytes(_read_span(p,a,n),'little')
def _w(p,a,v,n=8):
    if not isinstance(v,int) or not 0<=v<1<<(n*8):raise RefillUnsupported('startup word outside guest ABI')
    _write_span(p,a,v.to_bytes(n,'little'))


def _guard_acquire(p,address,thread_id):
    guard=_read_span(p,address,8)
    if guard[0] or guard[1]==1:return False
    if guard[1]&2:raise RefillUnsupported('recursive/contended startup guard')
    if not isinstance(thread_id,int) or not 0<=thread_id<=0xFFFFFFFF:
        raise RefillUnsupported('cold startup requires explicit uint32 thread id')
    _w(p,address+1,2,1);_w(p,address+4,thread_id,4);return True


def _guard_release(p,address):_write_span(p,address,b'\1\1')


def move_callable(pages, *, destination_address, source_address, image_base):
    """+0x3259c4 move with two evidenced inline-copy vtables.

    An inline callable stays in its source; a non-inline pointer moves and
    clears source+0x20. Unwritten padding is preserved.
    """
    staged=_PageTransaction(pages)
    _read_span(staged,destination_address,40);pointer=_u(staged,source_address+0x20)
    if not pointer:_w(staged,destination_address+0x20,0)
    elif pointer!=source_address:
        _w(staged,destination_address+0x20,pointer);_w(staged,source_address+0x20,0)
    else:
        table=_u(staged,pointer)
        if table not in (image_base+0x35D630,image_base+0x372600):
            raise RefillUnsupported('unrecovered inline startup callable')
        _w(staged,destination_address+0x20,destination_address)
        _w(staged,destination_address,table)
        if table==image_base+0x372600:_w(staged,destination_address+8,_u(staged,pointer+8))
    staged.commit()


def _thread_support(p,allocate):
    wrapper=objects._allocate(p,allocate,8)
    support=objects._allocate(p,allocate,48)
    _write_span(p,support,bytes(48));_w(p,wrapper,support)
    return wrapper


def _create(p,create_thread,output,start,argument):
    result=create_thread(p,output,0,start,argument)
    if result!=0:raise RefillUnsupported('thread-create failure/exception path is unsupported')
    if not _u(p,output):raise RefillUnsupported('successful create must publish a nonzero thread handle')


def get_executor_reference(pages, *, output_reference_address, scratch_address,
        image_base, allocate, create_thread, register_destructor, thread_id):
    """+0x326710 serial singleton and shared-owner copy, including worker request."""
    p=_PageTransaction(pages);base=image_base;guard=base+0x3E2D90
    if _guard_acquire(p,guard,thread_id):
        obj=base+0x3E2DB8;table=_u(p,base+0x3750B8)
        _read_span(p,obj,256)
        for offset in (0x28,0x38,0x48,0x58,0x68,0x73,0x88,0x98,0xA8,0xB8,0xC8,0xD8,0xE8):
            _write_span(p,obj+offset,bytes(16))
        _w(p,obj+0xF8,0);_w(p,obj,base+0x372648)
        _w(p,obj+8,obj+0x18);_w(p,obj+0x10,0)
        _w(p,obj+0x18,table+0x10);_w(p,obj+0x20,table+0x48)
        wrapper=_thread_support(p,allocate);argument=objects._allocate(p,allocate,16)
        _w(p,argument,wrapper);_w(p,argument+8,obj)
        _create(p,create_thread,scratch_address,base+0x326A2C,argument)
        _w(p,obj+0x10,_u(p,scratch_address));_w(p,scratch_address,0)
        _w(p,base+0x3E2DA8,obj)
        owner=objects._allocate(p,allocate,32)
        _w(p,owner,base+0x372670);_w(p,owner+8,0);_w(p,owner+16,0);_w(p,owner+24,obj)
        _w(p,base+0x3E2DB0,owner)
        register_destructor(p,base+0x326984,base+0x3E2DA8,base+0x34C700)
        _guard_release(p,guard)
    _w(p,output_reference_address,_u(p,base+0x3E2DA8))
    owner=_u(p,base+0x3E2DB0);_w(p,output_reference_address+8,owner)
    if owner:_w(p,owner+8,(_u(p,owner+8)+1)&((1<<64)-1))
    p.commit();return _u(p,output_reference_address)


def construct_async_queue(pages, *, object_address, scratch_address, image_base,
        allocate, create_thread):
    """+0x325a04, one worker, zero queue/mutex/condition and thread ownership."""
    p=_PageTransaction(pages);obj=object_address;base=image_base
    _read_span(p,obj,144);_write_span(p,obj,bytes(136));_w(p,obj+0x88,1,1)
    vector=objects._allocate(p,allocate,8)
    _w(p,obj,vector);_w(p,obj+8,vector);_w(p,obj+16,vector+8)
    wrapper=_thread_support(p,allocate);argument=objects._allocate(p,allocate,64)
    _w(p,argument,wrapper);_w(p,argument+0x10,base+0x372600)
    _w(p,argument+0x18,obj);_w(p,argument+0x30,argument+0x10)
    _create(p,create_thread,vector,base+0x3260A4,argument)
    _w(p,obj+8,vector+8)
    p.commit();return argument


def initialize_async_executor(pages, *, scratch_address, image_base, allocate,
        create_thread, register_destructor, thread_id):
    """Cold part of +0x325454: shared executor reference and two queue workers."""
    p=_PageTransaction(pages);base=image_base;guard=base+0x3E2D80
    if _guard_acquire(p,guard,thread_id):
        get_executor_reference(p,output_reference_address=scratch_address,
            scratch_address=scratch_address+16,image_base=base,allocate=allocate,
            create_thread=create_thread,register_destructor=register_destructor,thread_id=thread_id)
        obj=objects._allocate(p,allocate,32);_write_span(p,obj,bytes(32));_w(p,base+0x3E2D78,obj)
        for offset in (0,8):
            queue=objects._allocate(p,allocate,144)
            construct_async_queue(p,object_address=queue,scratch_address=scratch_address+32,
                image_base=base,allocate=allocate,create_thread=create_thread)
            _w(p,obj+offset,queue)
        _write_span(p,obj+16,_read_span(p,scratch_address,16));_write_span(p,scratch_address,bytes(16))
        register_destructor(p,base+0x325714,base+0x3E2D78,base+0x34C700)
        _guard_release(p,guard)
    obj=_u(p,base+0x3E2D78);_read_span(p,obj,32)
    p.commit();return obj


def submit_default_callable(pages, *, source_address, scratch_address, image_base,
        allocate, create_thread, register_destructor, thread_id, signal_condition):
    """Observed +0x32565c/+0x325454 branch: enqueue one default inline task."""
    p=_PageTransaction(pages)
    # The original std::function moves before the singleton is initialized.
    temporary=scratch_address
    move_callable(p,destination_address=temporary,source_address=source_address,image_base=image_base)
    executor=initialize_async_executor(p,scratch_address=scratch_address+0x40,
        image_base=image_base,allocate=allocate,create_thread=create_thread,
        register_destructor=register_destructor,thread_id=thread_id)
    queue=_u(p,executor)
    objects.lock_uncontended_mutex(p,mutex_address=queue+0x30)
    begin,end,capacity=(_u(p,queue+a) for a in (0x18,0x20,0x28))
    if begin or end or capacity:raise RefillUnsupported('nonempty startup queue/growth is unsupported')
    vector=objects._allocate(p,allocate,48)
    move_callable(p,destination_address=vector,source_address=temporary,image_base=image_base)
    _w(p,queue+0x18,vector);_w(p,queue+0x20,vector+48);_w(p,queue+0x28,vector+48)
    objects.unlock_uncontended_mutex(p,mutex_address=queue+0x30)
    result=signal_condition(p,queue+0x58)
    if result!=0:raise RefillUnsupported('condition-signal error is unsupported')
    p.commit();return executor


def signal_condition_no_waiters(pages, *, condition_address, wake):
    """Matching bionic pthread_cond_signal: generation +=4 and wake at most one."""
    if not isinstance(condition_address,int) or condition_address<0 or condition_address&3:
        raise RefillUnsupported('condition signal requires aligned u32')
    p=_PageTransaction(pages);value=(_u(p,condition_address,4)+4)&0xFFFFFFFF
    _w(p,condition_address,value,4)
    result=wake(p,condition_address,1 if value&1 else 129,1)
    if not isinstance(result,int) or result<0:raise RefillUnsupported('condition-signal syscall error')
    p.commit();return 0


def attach_worker_support(pages, *, argument_address, worker_kind, image_base,
        thread_id, create_key, set_specific):
    """Worker prefix +0x326a2c/+0x3260a4 up to its first dispatch call.

    Lazily initialize +0x32cc40's support key and transfer the argument's
    wrapper to the current thread. This does not execute the queue, callable,
    executor context initialization, support destructor or worker cleanup.
    """
    if worker_kind not in ('executor', 'queue'):
        raise RefillUnsupported('unknown startup worker kind')
    p=_PageTransaction(pages);base=image_base;arg=argument_address
    _read_span(p,arg,16 if worker_kind=='executor' else 64)
    wrapper=_u(p,arg)
    if not wrapper:raise RefillUnsupported('startup worker has no owned support wrapper')
    support=_u(p,wrapper);_read_span(p,support,48)
    if worker_kind=='queue':
        if _u(p,arg+0x10)!=base+0x372600 or _u(p,arg+0x30)!=arg+0x10:
            raise RefillUnsupported('unrecovered queue worker callable')
        dispatch=arg+0x10
    else:
        executor=_u(p,arg+8);_read_span(p,executor,256)
        dispatch=_u(p,executor+8)
        _read_span(p,dispatch,8)
    key_address=base+0x3E2F30;guard=base+0x3E2F38
    if _guard_acquire(p,guard,thread_id):
        status=create_key(p,key_address,base+0x32CE6C)
        if status!=0:raise RefillUnsupported('worker support key creation failed')
        _guard_release(p,guard)
    # Native clears the transferred unique_ptr before publishing it in TLS.
    _w(p,arg,0)
    status=set_specific(p,_u(p,key_address,4),wrapper)
    if status!=0:raise RefillUnsupported('worker support TLS publication failed')
    p.commit();return dispatch


@dataclass(frozen=True)
class StartupResult:
    steps:int
    stop_offset:int
    registers:tuple[int,...]
    modeled_callbacks:list[dict]


class StartupCallbacks:
    def __init__(self, *, image_base, native_stack_address, allocate,
            create_thread, register_destructor, thread_id, signal_condition):
        self.base=image_base;self.stack=native_stack_address;self.allocate=allocate
        self.environment=dict(create_thread=create_thread,register_destructor=register_destructor,
            thread_id=thread_id,signal_condition=signal_condition)
        self.modeled=[]
    def __call__(self,vm,function,argument):
        base=self.base;wrapper=function-base;p=vm.m.pages
        words=[vm.m.u64(argument+i*8) for i in range(4)];target=words[0]-base
        if (wrapper,target)==(0x2813E8,0x347F60):
            # memcpy requires disjoint spans; overlap is not an inferred memmove.
            d,s,n=words[1:4]
            if n>0x100000 or (d<s+n and s<d+n):raise RefillUnsupported('unsupported startup memcpy span')
            _write_span(p,d,_read_span(p,s,n))
        elif (wrapper,target)==(0x2813FC,0x32565C):
            submit_default_callable(p,source_address=words[1],scratch_address=self.stack-0x330,
                image_base=base,allocate=self.allocate,**self.environment)
        elif (wrapper,target)==(0x281408,0x28054C):
            pass  # The exact target consists solely of RET.
        else:raise RefillUnsupported(f'unrecovered startup callback +{wrapper:#x} -> +{target:#x}')
        self.modeled.append(dict(wrapper_offset=hex(wrapper),target_offset=hex(target)))


def initialize_startup_caller(pages, *, entry_stack_address, return_address,
        thread_pointer, image_base, vm_module, allocate, create_thread,
        register_destructor, thread_id, signal_condition, saved_frame_pointer=0,
        saved_x28=0,saved_x19=0,max_steps=100000):
    """Generate +0x28040c caller and run VM +0xa7050 without native snapshots."""
    if not isinstance(max_steps,int) or not 1<=max_steps<=1000000:raise ValueError('invalid startup step bound')
    if not isinstance(entry_stack_address,int) or entry_stack_address&15:raise RefillUnsupported('unaligned startup stack')
    if not isinstance(return_address,int) or not 0<=return_address<1<<56:raise RefillUnsupported('PAC-tagged startup return')
    p=_PageTransaction(pages);base=image_base;stack=entry_stack_address-0x400
    _read_span(p,stack-0x800,0xC00);_read_span(p,base+0xA7050,4)
    _w(p,stack,base+0x281414);_w(p,stack+8,stack+0x3D0);_w(p,stack+16,return_address)
    _w(p,entry_stack_address-0x20,saved_frame_pointer);_w(p,entry_stack_address-0x18,return_address)
    _w(p,entry_stack_address-16,saved_x28);_w(p,entry_stack_address-8,saved_x19)
    _write_span(p,entry_stack_address-0x28,_read_span(p,thread_pointer+0x28,8))
    initial=[_u(p,stack+0x2B8+i*8) for i in range(32)]
    class StrictMem(vm_module.Mem):
        def __init__(self,pages):self.pages=pages
        def _pg(self,address):
            if address>>12 not in self.pages:raise RefillUnsupported('unmapped startup guest page')
            return self.pages[address>>12]
    previous=vm_module.B
    try:
        vm_module.B=base
        vm=vm_module.VM(StrictMem(p),0xA7050,0,base+0x35D670,base+0x35D690,
            base+0x281414,return_address,maxsteps=max_steps)
        vm.R=initial;vm.R[0]=0;vm.R[4:8]=[0,base+0x35D670,base+0x35D690,base+0x281414]
        vm.R[29]=(stack+0x2A0)&~15;vm.R[31]=return_address
        callbacks=StartupCallbacks(image_base=base,native_stack_address=stack,
            allocate=allocate,create_thread=create_thread,register_destructor=register_destructor,
            thread_id=thread_id,signal_condition=signal_condition)
        vm.native_hook=callbacks
        try:vm.run()
        except vm_module.VMExit:pass
        else:raise RefillUnsupported('startup did not reach explicit VM exit')
        if _read_span(p,thread_pointer+0x28,8)!=_read_span(p,entry_stack_address-0x28,8):
            raise RefillUnsupported('startup TLS canary changed')
        result=StartupResult(vm.steps,vm.pc-base,tuple(vm.R),callbacks.modeled)
        p.commit();return result
    finally:vm_module.B=previous
