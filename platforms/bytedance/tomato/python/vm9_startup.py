"""Bounded async startup and serial workers with explicit environment services.

Thread creation, clocks, finite futex outcomes and task invocation belong to
providers. Idle workers can run through normal argument cleanup; serial default
task bodies have their own explicit entry. Same-startup nonempty worker task
attachment, repeating tasks and OS thread-exit destructors remain separate boundaries. No host threads or blocking waits are silently created.
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


def destroy_callable(pages, *, object_address, image_base, free, reset=False):
    """+0x167310 destruction, or +0x2918b0 reset of evidenced callables.

    Inline vtables +0x35d630/+0x372600 have RET destructors. Their deleting
    destructors free non-inline pointees. Plain destruction retains +0x20;
    reset clears it before the destructor, as native does.
    """
    p=_PageTransaction(pages);pointer=_u(p,object_address+0x20)
    if reset:_w(p,object_address+0x20,0)
    if pointer:
        if _u(p,pointer) not in (image_base+0x35D630,image_base+0x372600):
            raise RefillUnsupported('unrecovered callable destructor')
        if pointer!=object_address:free(p,pointer)
    p.commit()


def assign_callable(pages, *, destination_address, source_address, image_base, free):
    """+0x291848 reset destination, then move; self assignment becomes empty."""
    p=_PageTransaction(pages)
    destroy_callable(p,object_address=destination_address,image_base=image_base,free=free,reset=True)
    move_callable(p,destination_address=destination_address,source_address=source_address,image_base=image_base)
    p.commit()


def erase_queue_callable(pages, *, vector_address, element_address, image_base, free, max_items=64):
    """+0x326670/+0x3266c0/+0x325d38: shift, destroy tail, publish end."""
    if not isinstance(max_items,int) or not 1<=max_items<=4096:raise ValueError('invalid callable vector bound')
    p=_PageTransaction(pages);begin=_u(p,vector_address);end=_u(p,vector_address+8);capacity=_u(p,vector_address+16)
    if not begin<=element_address<end<=capacity or (end-begin)%48 or (element_address-begin)%48:
        raise RefillUnsupported('invalid callable vector erase')
    if (end-begin)//48>max_items:raise RefillUnsupported('callable vector bound exceeded')
    _read_span(p,begin,end-begin)
    destination=element_address;source=element_address+48
    while source!=end:
        assign_callable(p,destination_address=destination,source_address=source,image_base=image_base,free=free)
        destination+=48;source+=48
    tail=end-48
    destroy_callable(p,object_address=tail,image_base=image_base,free=free)
    _w(p,vector_address+8,tail)
    p.commit();return element_address


def take_queue_callable(pages, *, queue_address, task_address, image_base,
        thread_pointer, clock, futex, free, max_waits=64):
    """+0x326578 up to invocation: wait, move first task, erase, unlock.

    Return False for the stopped/empty queue, True with an owned local task
    otherwise. Invocation and its destructor belong to the caller.
    """
    if not isinstance(max_waits,int) or not 1<=max_waits<=4096:raise ValueError('invalid queue wait bound')
    p=_PageTransaction(pages);q=queue_address
    _read_span(p,q,144);_read_span(p,task_address,40)
    _w(p,task_address+0x20,0)
    objects.lock_uncontended_mutex(p,mutex_address=q+0x30)
    waits=0
    while _u(p,q+0x18)==_u(p,q+0x20) and _u(p,q+0x88,1):
        if waits>=max_waits:raise RefillUnsupported('queue wait bound exceeded')
        waits+=1
        result=wait_condition(p,condition_address=q+0x58,mutex_address=q+0x30,
            thread_pointer=thread_pointer,absolute_timeout=None,clock=clock,futex=futex)
        if result:raise RefillUnsupported('queue wait exception path is unsupported')
    ready=_u(p,q+0x18)!=_u(p,q+0x20)
    if ready:
        begin=_u(p,q+0x18)
        assign_callable(p,destination_address=task_address,source_address=begin,image_base=image_base,free=free)
        erase_queue_callable(p,vector_address=q+0x18,element_address=begin,image_base=image_base,free=free)
    objects.unlock_uncontended_mutex(p,mutex_address=q+0x30)
    p.commit();return ready


def invoke_callable(pages, *, object_address, image_base, invoke):
    """+0x291934 indirect invoke; no inferred empty-function handling."""
    pointer=_u(pages,object_address+0x20)
    if not pointer:raise RefillUnsupported('empty callable invocation/exception is unsupported')
    table=_u(pages,pointer);function=_u(pages,table+0x30)
    return invoke(pages,function,pointer)


def run_queue_callable(pages, *, object_address, task_address, image_base,
        thread_pointer, clock, futex, free, invoke, max_iterations=64):
    """+0x326578 serial loop with explicit invocation and finite wait services."""
    if not isinstance(max_iterations,int) or not 1<=max_iterations<=4096:raise ValueError('invalid queue iteration bound')
    p=_PageTransaction(pages)
    if _u(p,object_address)!=image_base+0x372600:raise RefillUnsupported('unknown queue callable vtable')
    q=_u(p,object_address+8)
    iterations=0;tasks=0
    while iterations<max_iterations:
        iterations+=1
        if not take_queue_callable(p,queue_address=q,task_address=task_address,image_base=image_base,
                thread_pointer=thread_pointer,clock=clock,futex=futex,free=free,max_waits=max_iterations):
            destroy_callable(p,object_address=task_address,image_base=image_base,free=free)
            p.commit();return tasks
        invoke_callable(p,object_address=task_address,image_base=image_base,invoke=invoke)
        destroy_callable(p,object_address=task_address,image_base=image_base,free=free)
        tasks+=1
    raise RefillUnsupported('queue iteration bound exceeded')


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


def _s64(value):
    value &= (1<<64)-1
    return value-(1<<64) if value>>63 else value


def wait_condition(pages, *, condition_address, mutex_address, thread_pointer,
        absolute_timeout, clock, futex):
    """Matching libc condition wait with serial normal-mutex/futex services.

    Timed waits convert the absolute CLOCK_REALTIME/MONOTONIC deadline to a
    relative timespec before unlocking. Expired deadlines return ETIMEDOUT
    while retaining the lock. A futex wait unlocks and reacquires the mutex;
    syscall errors preserve errno, and only ETIMEDOUT becomes a wait error.
    The environment must return from futex; no host blocking or scheduler is
    supplied. External callback ledgers are outside guest-page rollback.
    """
    for address,alignment in ((condition_address,4),(mutex_address,2),(thread_pointer,8)):
        if not isinstance(address,int) or address<0 or address%alignment:
            raise RefillUnsupported('invalid condition wait address')
    p=_PageTransaction(pages)
    condition=_u(p,condition_address,4)
    state=_u(p,mutex_address,2)
    if state&~0x2000!=1:raise RefillUnsupported('condition wait requires a held normal mutex')
    _read_span(p,thread_pointer+0x10,4)
    relative=None
    if absolute_timeout is not None:
        if not isinstance(absolute_timeout,(tuple,list)) or len(absolute_timeout)!=2 or any(
                not isinstance(v,int) or not -(1<<63)<=v<1<<63 for v in absolute_timeout):
            raise RefillUnsupported('invalid signed timespec')
        now=clock(p,(condition>>1)&1)
        if not isinstance(now,(tuple,list)) or len(now)!=2 or any(not isinstance(v,int) for v in now):
            raise RefillUnsupported('clock must supply a timespec')
        if not -(1<<63)<=now[0]<1<<63 or not 0<=now[1]<1000000000:
            raise RefillUnsupported('invalid virtual clock value')
        seconds=_s64(absolute_timeout[0]-now[0]);nanos=_s64(absolute_timeout[1]-now[1])
        if nanos<0:seconds=_s64(seconds-1);nanos=_s64(nanos+1000000000)
        if seconds<0 or nanos<0:p.commit();return 110
        relative=(seconds,nanos)
    expected=_u(p,condition_address,4)
    objects.unlock_uncontended_mutex(p,mutex_address=mutex_address)
    operation=0 if _u(p,condition_address,4)&1 else 128
    errno=_u(p,thread_pointer+0x10,4)
    result=futex(p,condition_address,operation,expected,relative)
    if not isinstance(result,int) or not -4095<=result<1<<31:
        raise RefillUnsupported('unsupported futex result')
    if result<0:_w(p,thread_pointer+0x10,errno,4)
    objects.lock_uncontended_mutex(p,mutex_address=mutex_address)
    p.commit();return 110 if result==-110 else 0


def wait_owned_condition(pages, *, condition_address, lock_address,
        thread_pointer, deadline_ns, clock, futex):
    """+0x329574/+0x3295c4 wait wrappers; timed clamp and C signed division."""
    p=_PageTransaction(pages)
    if not _u(p,lock_address+8,1):raise RefillUnsupported('condition lock is not owned')
    absolute=None
    if deadline_ns is not None:
        if not isinstance(deadline_ns,int) or not -(1<<63)<=deadline_ns<1<<63:
            raise RefillUnsupported('invalid condition deadline')
        value=min(deadline_ns,0x59682F000000E941)
        seconds=(abs(value)//1000000000)*(1 if value>=0 else -1)
        absolute=(seconds,value-seconds*1000000000)
    result=wait_condition(p,condition_address=condition_address,mutex_address=_u(p,lock_address),
        thread_pointer=thread_pointer,absolute_timeout=absolute,clock=clock,futex=futex)
    if result not in ((0,) if deadline_ns is None else (0,110)):
        raise RefillUnsupported('condition wrapper exception path is unsupported')
    p.commit();return result



def _s32(value):
    value &= (1<<32)-1
    return value-(1<<32) if value>>31 else value


def _trunc_div(value,divisor):
    return (abs(value)//divisor)*(1 if value>=0 else -1)


def _clock_value(p,clock,clock_id,scale):
    value=clock(p,clock_id)
    if not isinstance(value,(tuple,list)) or len(value)!=2 or any(not isinstance(v,int) for v in value):
        raise RefillUnsupported('clock must supply a timespec')
    if not -(1<<63)<=value[0]<1<<63 or not 0<=value[1]<1000000000:
        raise RefillUnsupported('invalid virtual clock value')
    return _s64(value[0]*scale+_trunc_div(value[1],1000000000//scale))


def _executor_head(p,context,max_items):
    count=_u(p,context+0x60)
    if not count:return None
    if count>max_items:raise RefillUnsupported('executor deque bound exceeded')
    origin=_u(p,context+0x38);begin=_u(p,context+0x40);end=_u(p,context+0x48)
    capacity=_u(p,context+0x50);head=_u(p,context+0x58)
    if not origin<=begin<end<=origin+capacity*8 or (begin-origin)%8 or (end-begin)%8:
        raise RefillUnsupported('invalid executor segment map')
    if head>=1024 or head+count>(end-begin)//8*512:
        raise RefillUnsupported('executor head/count exceeds mapped segments')
    segment=_u(p,begin+(head//512)*8)
    slot=segment+(head%512)*8;task=_u(p,slot)
    if not task or task%8:raise RefillUnsupported('invalid executor task pointer')
    _read_span(p,task,64)
    return slot,task


def pop_executor_task(pages, *, context_address, free, max_items=4096):
    """+0x32722c/+0x32725c: clear head, advance, release a spare segment."""
    if not isinstance(max_items,int) or not 1<=max_items<=4096:raise ValueError('invalid executor deque bound')
    p=_PageTransaction(pages);ctx=context_address
    head=_executor_head(p,ctx,max_items)
    if head is None:raise RefillUnsupported('cannot pop an empty executor deque')
    slot,task=head;_w(p,slot,0)
    index=_u(p,ctx+0x58)+1;count=_u(p,ctx+0x60)-1
    _w(p,ctx+0x58,index);_w(p,ctx+0x60,count)
    if index>1023:
        begin=_u(p,ctx+0x40);free(p,_u(p,begin))
        _w(p,ctx+0x40,begin+8);_w(p,ctx+0x58,index-512)
    p.commit();return task


def take_ready_executor_task(pages, *, context_address, free, max_items=4096):
    """+0x326ec8 locked head/deadline check; serial normal mutexes only."""
    p=_PageTransaction(pages);ctx=context_address
    objects.lock_uncontended_mutex(p,mutex_address=ctx+0x10)
    head=_executor_head(p,ctx,max_items);task=None
    if head is not None and _s64(_u(p,head[1]+0x30))<=_s64(_u(p,ctx+0x70)):
        task=pop_executor_task(p,context_address=ctx,free=free,max_items=max_items)
    objects.unlock_uncontended_mutex(p,mutex_address=ctx+0x10)
    p.commit();return task


def next_executor_delay(pages, *, context_address, max_items=4096):
    """+0x326f48 returns signed W32 delay, zero if due, -1 if empty."""
    p=_PageTransaction(pages);ctx=context_address
    objects.lock_uncontended_mutex(p,mutex_address=ctx+0x10)
    head=_executor_head(p,ctx,max_items);delay=-1
    if head is not None:
        deadline=_s64(_u(p,head[1]+0x30));now=_s64(_u(p,ctx+0x70))
        delay=0 if deadline<=now else _s32(deadline-now)
    objects.unlock_uncontended_mutex(p,mutex_address=ctx+0x10)
    p.commit();return delay


def poll_executor(pages, *, context_address, image_base, clock, free, invoke, max_tasks=64):
    """+0x326dfc nonrepeating task poll with explicit callable invocation.

    Repeating-task insertion/sorting remains unsupported. An already repeating
    task is rejected before invocation; callbacks that turn a task into a
    repeating task are also rejected, with guest rollback only.
    """
    if not isinstance(max_tasks,int) or not 1<=max_tasks<=4096:raise ValueError('invalid executor poll bound')
    p=_PageTransaction(pages);ctx=context_address
    if _u(p,ctx+0x68,1):return 0
    completed=0
    while True:
        now=_trunc_div(_clock_value(p,clock,1,1000000000),1000000)
        _w(p,ctx+0x70,now&((1<<64)-1))
        head=_executor_head(p,ctx,4096)
        if head is not None and _s64(_u(p,head[1]+0x30))<=now:
            if completed>=max_tasks:raise RefillUnsupported('executor task poll bound exceeded')
            if _s64(_u(p,head[1]+0x38))>=1:raise RefillUnsupported('executor repeat insertion is unrecovered')
        task=take_ready_executor_task(p,context_address=ctx,free=free)
        if task is None:
            result=next_executor_delay(p,context_address=ctx);p.commit();return result
        invoke_callable(p,object_address=task,image_base=image_base,invoke=invoke)
        if _s64(_u(p,task+0x38))>=1:raise RefillUnsupported('callback enabled unrecovered executor repeat')
        destroy_callable(p,object_address=task,image_base=image_base,free=free)
        free(p,task);completed+=1


def wait_signal_controller(pages, *, controller_address, delay_ms, thread_pointer,
        clock, futex, max_waits=64):
    """+0x328a84 -> +0x328b4c/+0x328bac/+0x328c1c timed signal wait.

    Convert the remaining monotonic duration to a realtime absolute deadline,
    including microsecond truncation, saturation and the owned wait clamp.
    Clock calls and the counter/lock transitions follow the native order.
    """
    if not isinstance(delay_ms,int) or not -(1<<31)<=delay_ms<1<<31:
        raise RefillUnsupported('signal delay must be signed W32')
    if not isinstance(max_waits,int) or not 1<=max_waits<=4096:raise ValueError('invalid signal wait bound')
    p=_PageTransaction(pages);ctrl=controller_address;mutex=ctrl+4;condition=ctrl+0x2c
    objects.lock_uncontended_mutex(p,mutex_address=mutex)
    deadline=_s64(_clock_value(p,clock,1,1000000000)+delay_ms*1000000)
    waits=0;timed_out=False
    while _s32(_u(p,ctrl,4))<1:
        if waits>=max_waits:raise RefillUnsupported('signal wait bound exceeded')
        waits+=1
        timed_out=_clock_value(p,clock,1,1000000000)>=deadline
        if not timed_out:
            duration=_s64(deadline-_clock_value(p,clock,1,1000000000))
            if duration>=1:
                start=_clock_value(p,clock,1,1000000000)
                micros=_clock_value(p,clock,0,1000000)
                realtime=max(-(1<<63),min((1<<63)-1,micros*1000))
                absolute=min((1<<63)-1,realtime+duration)
                value=min(absolute,0x59682F000000E941)
                seconds=_trunc_div(value,1000000000)
                wait_condition(p,condition_address=condition,mutex_address=mutex,
                    thread_pointer=thread_pointer,absolute_timeout=(seconds,value-seconds*1000000000),
                    clock=clock,futex=futex)
                # The elapsed-duration result is calculated by native but its
                # caller discards it; the final until check reads clock again.
                _s64(_clock_value(p,clock,1,1000000000)-start)
            timed_out=_clock_value(p,clock,1,1000000000)>=deadline
        if timed_out:break
    signalled=_s32(_u(p,ctrl,4))>=1
    if signalled:_w(p,ctrl,0,4)
    objects.unlock_uncontended_mutex(p,mutex_address=mutex)
    p.commit();return int(signalled)


def run_executor_context(pages, *, context_address, image_base, thread_pointer,
        clock, futex, free, invoke, max_iterations=64):
    """+0x328958 loop for the evidenced context-owned controller.

    The environment supplies finite wake/stop behavior. This loop creates no
    host thread; running a task still requires its actual invocation provider.
    """
    if not isinstance(max_iterations,int) or not 1<=max_iterations<=4096:raise ValueError('invalid executor iteration bound')
    p=_PageTransaction(pages);ctx=context_address;iterations=0
    while _u(p,ctx+0x80,1):
        if iterations>=max_iterations:raise RefillUnsupported('executor loop bound exceeded')
        iterations+=1
        result=poll_executor(p,context_address=ctx,image_base=image_base,clock=clock,free=free,invoke=invoke)
        if result==0:continue
        if not _u(p,ctx+0x80,1):break
        wait_signal_controller(p,controller_address=ctx+0x84,
            delay_ms=(1<<31)-1 if result==-1 else result,thread_pointer=thread_pointer,
            clock=clock,futex=futex,max_waits=max_iterations)
    p.commit();return iterations


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


def initialize_executor_context(pages, *, context_address, image_base, get_tls):
    """+0x326b18: publish executor context in emulated TLS and initialize it.

    get_tls receives the actual ELF descriptor +0x3d1340. Context fields and
    unwritten padding follow the native body; no executor poll is performed.
    """
    p=_PageTransaction(pages);obj=context_address;base=image_base
    _read_span(p,obj,0xE8)
    slot=get_tls(p,base+0x3D1340)
    table=_u(p,base+0x3750C0)  # Native latches this before publishing fields.
    _w(p,slot,obj)
    _w(p,obj+0x80,1,1)
    _write_span(p,obj+0x84,bytes(0x5C))
    _w(p,obj+0x78,table+0x10)
    _w(p,obj+0xE0,obj+0x78)
    _w(p,obj+0x69,1,1)
    p.commit()


@dataclass(frozen=True)
class ArenaBootPrefixResult:
    region_address: int
    next_caller_offset: int = 0x280970
    once_initialization_pending: bool = False


def _table_initialization_layout(table_index):
    if not isinstance(table_index,int) or isinstance(table_index,bool) or table_index not in range(6):
        raise RefillUnsupported('table initializer index must be in 0..5')
    return (0x280890+table_index*0x1E4,0x3E09A8+table_index*0x48,
        0x280970+table_index*0x1E4,0x2809F8+table_index*0x1E4)


def initialize_arena_boot_prefix(pages, *, image_base, allocate, table_index=0):
    """Selected table allocation/publication prefix, excluding nested VMs."""
    _,table,initial,_=_table_initialization_layout(table_index)
    p=_PageTransaction(pages)
    _read_span(p,image_base+table,0x40)
    region=allocate(p,0x4000)
    if not isinstance(region,int) or not 0<region<(1<<64)-0x4000:
        raise RefillUnsupported('arena prefix requires a non-null guest allocation')
    _read_span(p,region,0x4000)
    _write_span(p,region,bytes(0x4000))
    for index in range(8):_w(p,image_base+table+index*8,region+index*0x800)
    p.commit()
    return ArenaBootPrefixResult(region,next_caller_offset=initial)


def begin_once_arena_boot(pages, *, image_base, allocate):
    """+0x32a0a0 cold path through the first nested initializer call.

    State 1 remains published: +0x280970 and seven +0x2809f8 calls have not
    returned. This prefix must never stand in for a completed once initializer.
    """
    p=_PageTransaction(pages);control=image_base+0x3E09E8;mutex=image_base+0x3E2EB8
    objects.lock_uncontended_mutex(p,mutex_address=mutex)
    state=_u(p,control)
    if state==1:raise RefillUnsupported('arena once wait path remains unrecovered')
    if state:
        objects.unlock_uncontended_mutex(p,mutex_address=mutex)
        p.commit();return None
    _w(p,control,1)
    objects.unlock_uncontended_mutex(p,mutex_address=mutex)
    result=initialize_arena_boot_prefix(p,image_base=image_base,allocate=allocate)
    p.commit()
    return ArenaBootPrefixResult(result.region_address,once_initialization_pending=True)


def call_once_arena_boot(pages, *, image_base, initializer, broadcast, table_index=0):
    """Serial once gate with an explicit complete initializer provider.

    No partial built-in initializer is treated as completion. Broadcast is an
    explicit environment boundary; state 1 waiting remains unsupported.
    """
    if not callable(initializer) or not callable(broadcast):
        raise RefillUnsupported('once gate requires explicit initializer and broadcast')
    _,table,_,_=_table_initialization_layout(table_index)
    p=_PageTransaction(pages);control=image_base+table+0x40;mutex=image_base+0x3E2EB8
    objects.lock_uncontended_mutex(p,mutex_address=mutex)
    state=_u(p,control)
    if state==1:raise RefillUnsupported('arena once wait path remains unrecovered')
    if state:
        objects.unlock_uncontended_mutex(p,mutex_address=mutex)
        p.commit();return None
    _w(p,control,1)
    objects.unlock_uncontended_mutex(p,mutex_address=mutex)
    result=initializer(p)
    if isinstance(result,ArenaBootPrefixResult):
        raise RefillUnsupported('partial arena initializer cannot complete the once gate')
    objects.lock_uncontended_mutex(p,mutex_address=mutex)
    _w(p,control,(1<<64)-1)
    objects.unlock_uncontended_mutex(p,mutex_address=mutex)
    if broadcast(p,image_base+0x3E2EE0)!=0:
        raise RefillUnsupported('once broadcast provider failed')
    p.commit();return result


@dataclass(frozen=True)
class InitializationCallerFrame:
    caller_offset: int
    bytecode_offset: int
    stack_address: int
    backing_address: int
    virtual_stack_address: int
    return_address: int


def prepare_initialization_caller(pages, *, caller_offset, arguments,
        entry_stack_address, return_address, thread_pointer, image_base,
        saved_frame_pointer=0, saved_registers=None):
    """Model wrapper and normal +0x168324 prelude from function-entry inputs.

    All untouched slots come from the caller's supplied pages, including stack
    padding and aliases. No native entry pages or fixed padding values are used.
    """
    default_callers=(0x280590,0x280610,0x280690,0x280710,0x280790,0x280810)
    layouts={caller:(0x350,0xEDCF0+index*0x120,0x35DA00+index*0x30,
        0x35DA20+index*0x30,caller+0x5C) for index,caller in enumerate(default_callers)}
    initial_entries=(0xEE3B0,0xEEE60,0xEF910,0xF03C0,0xF0E40,0xF18F0)
    repeated_entries=(0xEEA70,0xEF520,0xEFFD0,0xF0A50,0xF1500,0xF1FB0)
    initial_callers=tuple(0x280970+index*0x1E4 for index in range(6))
    repeated_callers=tuple(0x2809F8+index*0x1E4 for index in range(6))
    for index,caller in enumerate(initial_callers):
        layouts[caller]=(0x520,initial_entries[index],0x35DB20+index*0x30,
            0x35DB40+index*0x30,caller+0x64)
        repeated=repeated_callers[index]
        layouts[repeated]=(0x300,repeated_entries[index],0,0,repeated+0x58)
    if caller_offset not in layouts:raise RefillUnsupported('unknown initialization caller')
    if not isinstance(entry_stack_address,int) or entry_stack_address&15:
        raise RefillUnsupported('initialization stack must be aligned')
    if not isinstance(return_address,int) or not 0<=return_address<1<<56:
        raise RefillUnsupported('initialization return must be an untagged address')
    args=tuple(arguments);needed=1 if caller_offset in default_callers else 2
    if len(args)!=needed or any(not isinstance(v,int) or not 0<=v<1<<64 for v in args):
        raise RefillUnsupported('invalid initialization caller arguments')
    if caller_offset in initial_callers and args[1]>=1<<32:
        raise RefillUnsupported('arena initialization flag must fit W1')
    size,entry,table_a,table_b,continuation=layouts[caller_offset]
    p=_PageTransaction(pages);S=entry_stack_address;C=S-0x20-size;E=S-0x30
    G=C-0x60;backing=E-0x118;virtual_stack=(E-0x130)&~15
    _read_span(p,C-0x180,S-(C-0x180))
    _read_span(p,image_base+entry,4)
    regs={index:0 for index in range(19,29)}
    if saved_registers is not None:
        if any(index not in regs for index in saved_registers):
            raise RefillUnsupported('caller saved register index outside X19..X28')
        regs.update(saved_registers)
    for adr,value in ((S-0x20,saved_frame_pointer),(S-0x18,return_address),
            (S-0x10,regs[28]),(S-8,regs[19])):_w(p,adr,value)
    _write_span(p,S-0x28,_read_span(p,thread_pointer+0x28,8))
    packed=C+8 if caller_offset in default_callers else C
    _w(p,packed,args[0])
    if caller_offset in initial_callers:_w(p,C+8,args[1],4)
    elif caller_offset in repeated_callers:_w(p,C+8,args[1])
    for adr,value in ((C+0x10,image_base+0x281414),(C+0x18,E),(C+0x20,return_address),
            (G,S-0x20),(G+8,image_base+continuation)):_w(p,adr,value)
    # Generic VM preserves physical callee-saved registers. X19 already owns
    # the wrapper's thread pointer; other registers retain entry values.
    regs[19]=thread_pointer
    for adr,index in ((G+0x10,28),(G+0x18,27),(G+0x20,26),(G+0x28,25),
            (G+0x30,24),(G+0x38,23),(G+0x40,22),(G+0x48,21),
            (G+0x50,20),(G+0x58,19)):_w(p,adr,regs[index])
    for adr,value in ((G-0x48,image_base+entry),(G-8,0x33DC5),(G-0x10,C-0x100),
            (G-0x28,C-0x170),(G-0x20,C-0x180),
            (G-0x58,E-0xF8),(G-0x50,return_address),(G-0x70,E-0xF0),
            (G-0x40,E),(G-0x18,E-0x10),(G-0x38,E-0x18),(G-0x30,E-8),
            (G-0x68,E-0x110),(G-0x60,E-0x108),
            (backing,0),(backing+0x20,packed),
            (backing+0x28,image_base+table_a if table_a else 0),
            (backing+0x30,image_base+table_b if table_b else 0),
            (backing+0x38,image_base+0x281414),(E-0x30,virtual_stack),
            (E-0x20,return_address),(E-0x120,image_base+entry)):_w(p,adr,value)
    _w(p,C-0x100,0,2)
    p.commit()
    return InitializationCallerFrame(caller_offset,entry,C,backing,virtual_stack,return_address)


@dataclass(frozen=True)
class InitializationVMResult:
    steps: int
    stop_offset: int
    registers: tuple[int,...]
    callbacks: tuple[dict,...]
    frame: InitializationCallerFrame
    complete: bool


class _InitializationBoundary(Exception):pass


def run_initialization_vm(pages, *, vm_module, image_base, stop_offset=None,
        once_provider=None, max_steps=200000, **caller_inputs):
    """Run an initialization caller to an explicit VM/callback/return boundary.

    Only the evidenced memset/memcpy wrappers are executed. Other callbacks
    stop before side effects; incomplete calls never mark a once gate complete.
    """
    if not isinstance(max_steps,int) or not 1<=max_steps<=1000000:
        raise ValueError('invalid initialization VM budget')
    p=_PageTransaction(pages)
    frame=prepare_initialization_caller(p,image_base=image_base,**caller_inputs)
    class StrictMem(vm_module.Mem):
        def __init__(self,pages):self.pages=pages
        def _pg(self,address):
            if address>>12 not in self.pages:raise RefillUnsupported('unmapped initialization page')
            return self.pages[address>>12]
    previous=vm_module.B;events=[];complete=False
    try:
        vm_module.B=image_base
        vm=vm_module.VM(StrictMem(p),frame.bytecode_offset,0,0,0,
            image_base+0x281414,frame.return_address,maxsteps=max_steps)
        vm.R=[_u(p,frame.backing_address+index*8) for index in range(32)]
        vm.register_backing_base=frame.backing_address
        vm._vm_tmp32=_u(p,frame.backing_address+0x100)
        vm._vm_tmp33=_u(p,frame.backing_address+0x108)
        def callback(current,function,argument):
            wrapper=function-image_base
            words=tuple(current.m.u64(argument+index*8) for index in range(4))
            target=words[0]-image_base
            event=dict(wrapper_offset=hex(wrapper),target_offset=hex(target),
                step=current.steps,bytecode_offset=hex(current.pc-image_base),
                words=words,executed=False)
            events.append(event)
            if wrapper in tuple(0x281610+i*0x28 for i in range(6)) and target==0x347F20:
                d,fill,n=words[1:];fill&=255
                if n>0x100000:raise RefillUnsupported('unbounded initialization memset')
                _read_span(p,d,n);_write_span(p,d,bytes([fill])*n)
            elif wrapper in tuple(0x281598+i*0x14 for i in range(6)) and target==0x32A0A0 and once_provider is not None:
                table_index=(wrapper-0x281598)//0x14
                initializer,table,_,_=_table_initialization_layout(table_index)
                if frame.caller_offset!=0x280590+table_index*0x80 or words[1]!=image_base+table+0x40 or words[3]!=image_base+initializer:
                    raise RefillUnsupported('default once callback package differs')
                once_provider(current,frame,words)
            elif wrapper in tuple(0x281624+i*0x28 for i in range(6)) and target==0x347F60:
                d,s,n=words[1:]
                if n>0x100000 or (d<s+n and s<d+n):
                    raise RefillUnsupported('unsupported initialization memcpy span')
                _write_span(p,d,_read_span(p,s,n))
            else:raise _InitializationBoundary()
            event['executed']=True
        vm.native_hook=callback
        if stop_offset is not None:
            def boundary(current,*_):
                if current.pc==image_base+stop_offset:raise _InitializationBoundary()
            vm.step_hook=boundary
        try:vm.run()
        except _InitializationBoundary:pass
        except vm_module.VMExit:complete=True
        except RuntimeError as exc:
            if str(exc).startswith('step limit @'):
                raise RefillUnsupported('initialization VM instruction budget exhausted') from exc
            raise
        if complete:
            entry_stack=caller_inputs['entry_stack_address']
            thread_pointer=caller_inputs['thread_pointer']
            if _read_span(p,thread_pointer+0x28,8)!=_read_span(p,entry_stack-0x28,8):
                raise RefillUnsupported('initialization caller TLS canary changed')
            for index,value in enumerate(vm.R):_w(p,frame.backing_address+index*8,value)
        result=InitializationVMResult(vm.steps,vm.pc-image_base,tuple(vm.R),tuple(events),frame,complete)
        p.commit();return result
    finally:vm_module.B=previous



@dataclass(frozen=True)
class ArenaInitializationResult:
    region_address: int
    caller_results: tuple[InitializationVMResult,...]


def initialize_arena_boot(pages, *, image_base, allocate, vm_module,
        entry_stack_address, return_address, thread_pointer,
        saved_frame_pointer=0, saved_registers=None, table_index=0):
    """Selected table initializer through all eight nested VM returns.

    Guest allocator/TLS/ELF inputs remain explicit. This initializes the selected
    default-task table, not jemalloc's complete arena/global/OS boot.
    """
    if not isinstance(entry_stack_address,int) or entry_stack_address&15:
        raise RefillUnsupported('arena initializer stack must be aligned')
    if not isinstance(return_address,int) or not 0<=return_address<1<<56:
        raise RefillUnsupported('arena initializer return must be untagged')
    initializer,table,initial,repeated=_table_initialization_layout(table_index)
    p=_PageTransaction(pages);S=entry_stack_address;F=S-0x20
    _read_span(p,S-0xA00,0xA00)
    regs={i:0 for i in range(19,29)}
    if saved_registers is not None:
        if any(i not in regs for i in saved_registers):
            raise RefillUnsupported('arena saved registers must be X19..X28')
        regs.update(saved_registers)
    _w(p,F,saved_frame_pointer);_w(p,F+8,return_address);_w(p,F+16,regs[19])
    # Native operator-new's preserved spills before the explicit malloc service.
    for address,value in ((F-0x20,F),(F-0x18,image_base+initializer+0x14),
            (F-0x10,regs[19])):_w(p,address,value)
    prefix=initialize_arena_boot_prefix(p,image_base=image_base,allocate=allocate,table_index=table_index)
    regs[19]=image_base+table
    results=[]
    def call(caller,arguments,stack,ret,fp):
        result=run_initialization_vm(p,caller_offset=caller,arguments=arguments,
            entry_stack_address=stack,return_address=image_base+ret,
            thread_pointer=thread_pointer,image_base=image_base,vm_module=vm_module,
            saved_frame_pointer=fp,saved_registers=regs,max_steps=1000000)
        if not result.complete:raise RefillUnsupported('nested arena initializer did not return')
        results.append(result)
    call(initial,(prefix.region_address,0),F,initializer+0xA0,F)
    for index in range(7):
        pair=tuple(_u(p,image_base+table+(index+i)*8) for i in range(2))
        if index<6:call(repeated,pair,F,initializer+0xA8+index*8,F)
        else:
            regs[19]=_u(p,F+16)
            result=run_initialization_vm(p,caller_offset=repeated,arguments=pair,
                entry_stack_address=S,return_address=return_address,
                thread_pointer=thread_pointer,image_base=image_base,vm_module=vm_module,
                saved_frame_pointer=saved_frame_pointer,saved_registers=regs,max_steps=1000000)
            if not result.complete:raise RefillUnsupported('final arena initialization tailcall did not return')
            results.append(result)
    p.commit();return ArenaInitializationResult(prefix.region_address,tuple(results))


def run_default_initialization_caller(pages, *, table_index, allocate, broadcast, vm_module,
        entry_stack_address, return_address, thread_pointer, image_base,
        saved_frame_pointer=0, saved_registers=None):
    """Selected default VM caller with its complete table initializer.

    An individual caller does not synthesize the six-caller task, an OS thread,
    or allocator-global boot. Environment effects remain explicit providers.
    """
    _table_initialization_layout(table_index)
    p=_PageTransaction(pages);nested=[]
    def once_provider(vm,frame,words):
        C=frame.stack_address;G=C-0x60;F=C-0x1C0
        # +0x32a0a0's saved physical registers, from normal generic VM ABI.
        for adr,value in ((F,G),(F+8,image_base+0x16AA4C),
            (F+0x10,C-0x120),(F+0x20,C-0x110),
            (F+0x28,vm.m.u32(vm.pc)),(F+0x30,image_base+0x379000),
            (F+0x38,entry_stack_address-0x150)):_w(vm.m.pages,adr,value)
        regs={index:0 for index in range(19,29)}
        if saved_registers is not None:regs.update(saved_registers)
        regs.update({19:words[1],20:words[3],21:words[2],
            22:C-0x110,23:C-0x120,28:frame.backing_address})
        def initialize(staged):
            result=initialize_arena_boot(staged,image_base=image_base,allocate=allocate,
                vm_module=vm_module,entry_stack_address=F,return_address=image_base+0x32A148,
                thread_pointer=thread_pointer,saved_frame_pointer=F,saved_registers=regs,
                table_index=table_index)
            nested.extend(result.caller_results);return result
        call_once_arena_boot(vm.m.pages,image_base=image_base,initializer=initialize,
            broadcast=broadcast,table_index=table_index)
    result=run_initialization_vm(p,caller_offset=0x280590+table_index*0x80,arguments=(0,),
        entry_stack_address=entry_stack_address,return_address=return_address,
        thread_pointer=thread_pointer,image_base=image_base,vm_module=vm_module,
        saved_frame_pointer=saved_frame_pointer,saved_registers=saved_registers,
        once_provider=once_provider,max_steps=1000000)
    if not result.complete:raise RefillUnsupported('default initialization caller did not return')
    p.commit();return result,tuple(nested)


@dataclass(frozen=True)
class DefaultInitializationTaskResult:
    caller_results: tuple[InitializationVMResult,...]
    nested_results: tuple[tuple[InitializationVMResult,...],...]


def run_default_initialization_task(pages, *, allocate,broadcast,vm_module,
        entry_stack_address,return_address,thread_pointer,image_base,
        saved_frame_pointer=0,saved_registers=None):
    """+0x280554 serial body: five calls then the sixth tailcall.

    All six tables use the supplied allocator and environment services. This
    does not attach a worker, destroy thread TLS, or bootstrap jemalloc/OS.
    """
    if not isinstance(entry_stack_address,int) or entry_stack_address&15:
        raise RefillUnsupported('default task stack must be aligned')
    if not isinstance(return_address,int) or not 0<=return_address<1<<56:
        raise RefillUnsupported('default task return must be untagged')
    p=_PageTransaction(pages);S=entry_stack_address;F=S-0x10
    _read_span(p,F,0x10);_w(p,F,saved_frame_pointer);_w(p,F+8,return_address)
    callers=[];nested=[]
    for index in range(6):
        final=index==5
        result,phases=run_default_initialization_caller(p,table_index=index,
            allocate=allocate,broadcast=broadcast,vm_module=vm_module,
            entry_stack_address=S if final else F,
            return_address=return_address if final else image_base+0x280564+index*8,
            thread_pointer=thread_pointer,image_base=image_base,
            saved_frame_pointer=saved_frame_pointer if final else F,
            saved_registers=saved_registers)
        callers.append(result);nested.append(phases)
    p.commit();return DefaultInitializationTaskResult(tuple(callers),tuple(nested))


def run_first_default_caller(pages, **kwargs):
    """Preserve the first-caller entry point with the verified first layout."""
    return run_default_initialization_caller(pages,table_index=0,**kwargs)


def run_startup_worker(pages, *, argument_address, worker_kind, image_base,
        thread_pointer, thread_id, create_key, set_specific, get_tls,
        clock, futex, free, invoke, task_address, max_iterations=64):
    """Serial +0x326a2c/+0x3260a4 through normal return and argument cleanup.

    Support ownership is transferred to pthread TLS and retained there. The OS
    thread-exit destructor is a separate boundary. Executor cancellation and
    repeating task insertion are unsupported; queue task bodies are supplied
    by the invocation provider and must not be silently replaced with RET.
    """
    p=_PageTransaction(pages);arg=argument_address;base=image_base
    dispatch=attach_worker_support(p,argument_address=arg,worker_kind=worker_kind,
        image_base=base,thread_id=thread_id,create_key=create_key,set_specific=set_specific)
    if worker_kind=='executor':
        initialize_executor_context(p,context_address=dispatch,image_base=base,get_tls=get_tls)
        if not _u(p,dispatch+0x68,1):
            if _u(p,dispatch+0x6a,1):raise RefillUnsupported('executor cancellation is unrecovered')
            if _u(p,dispatch+8)!=_u(p,base+0x3750b8)+0x48:
                raise RefillUnsupported('unknown executor polling vtable')
            run_executor_context(p,context_address=dispatch,image_base=base,
                thread_pointer=thread_pointer,clock=clock,futex=futex,free=free,invoke=invoke,
                max_iterations=max_iterations)
    else:
        run_queue_callable(p,object_address=dispatch,task_address=task_address,
            image_base=base,thread_pointer=thread_pointer,clock=clock,futex=futex,free=free,
            invoke=invoke,max_iterations=max_iterations)
        destroy_callable(p,object_address=dispatch,image_base=base,free=free)
    # The first argument field was cleared before pthread_setspecific. Both
    # argument destructors reset it again, skip its transferred wrapper, then
    # free the argument object itself. The wrapper/support stay in TLS.
    if _u(p,arg):raise RefillUnsupported('worker argument acquired unsupported support ownership')
    _w(p,arg,0);free(p,arg)
    p.commit();return 0


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
