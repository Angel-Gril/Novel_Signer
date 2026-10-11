"""Startup-requested workers and joinable guest exit with explicit services.

The caller supplies the descriptors produced by JNI/startup and independent
thread storage. Executor and A/B initialization queue workers run serially;
the JNI finalizer queue needs its separately recovered callback owner.
"""
from dataclasses import dataclass
from vm9_allocator import _PageTransaction,_read_span,RefillUnsupported,GuestOS
import vm9_startup as startup
import vm9_alternative_startup as alternative
import vm9_thread_exit as thread_exit


@dataclass(frozen=True)
class JniWorkerResult:
    worker_kind: str
    return_code: int
    tasks: tuple
    exit_result: thread_exit.GuestThreadExitResult


def run_requested_worker(pages, *, image_base, libc_base, thread_start_address,
        argument_address, startup_entry, entry_stack_address, thread_pointer,
        thread_id, allocate, free, create_key, set_specific, get_tls, clock,
        futex, broadcast, get_libc_tls, os_call, vm_module=None,
        max_iterations=64, max_steps=1000000, max_depth=64):
    """Execute one startup-generated worker, then the full joinable exit body.

    Providers own allocation, thread-specific key publication, clock effects
    (including any libc cache), finite wait/stop behavior and guest OS effects.
    A/B choice uses the actual JNI result's startup_entry. All guest pages roll
    back on rejection, including a late exit failure; providers must stage
    their external effects. Detached storage reclaim and finalizer tasks are
    outside this entry's contract and reject.
    """
    for value,alignment,label in ((image_base,4096,'image'),(libc_base,4096,'libc'),
            (argument_address,8,'argument'),(entry_stack_address,16,'stack'),
            (thread_pointer,8,'thread')):
        if type(value) is not int or not 0<value<1<<56 or value%alignment:
            raise RefillUnsupported('invalid worker '+label+' address')
    if type(thread_id) is not int or not 0<thread_id<1<<32:
        raise RefillUnsupported('worker requires a nonzero uint32 thread id')
    if type(thread_start_address) is not int or thread_start_address not in (
            image_base+0x326A2C,image_base+0x3260A4):
        raise RefillUnsupported('unknown startup-requested worker entry')
    if type(startup_entry) is not int or startup_entry not in (0x28040C,0x2A0028):
        raise RefillUnsupported('unknown JNI startup entry')
    for provider in (allocate,free,create_key,set_specific,get_tls,clock,futex,
            broadcast,get_libc_tls,os_call):
        if not callable(provider):raise RefillUnsupported('worker requires explicit providers')
    if type(max_iterations) is not int or not 1<=max_iterations<=4096:
        raise ValueError('invalid worker iteration budget')
    if type(max_steps) is not int or not 1<=max_steps<=1000000:
        raise ValueError('invalid worker task budget')
    if type(max_depth) is not int or not 1<=max_depth<=64:
        raise ValueError('invalid worker task depth')
    p=_PageTransaction(pages)
    u=lambda a,n=8:int.from_bytes(_read_span(p,a,n),'little')
    thread=u(thread_pointer+8)
    if not thread or u(thread+0x50,4) or u(thread+0x78) or u(thread+0x58):
        raise RefillUnsupported('worker requires fresh joinable thread exit storage')
    _read_span(p,entry_stack_address-0x8000,0x8000)
    kw=dict(argument_address=argument_address,image_base=image_base,
        thread_pointer=thread_pointer,thread_id=thread_id,create_key=create_key,
        set_specific=set_specific,get_tls=get_tls,clock=clock,futex=futex,free=free,
        max_iterations=max_iterations)
    tasks=()
    if thread_start_address==image_base+0x326A2C:
        executor=u(argument_address+8);context=u(executor+8)
        if u(context+0x60):raise RefillUnsupported('startup executor must initially have no scheduled tasks')
        def idle(*args):raise RefillUnsupported('idle executor invoked an unsupported task')
        returned=startup.run_startup_worker(p,worker_kind='executor',invoke=idle,
            task_address=entry_stack_address-0xC0,**kw)
        kind='executor'
    elif startup_entry==0x2A0028:
        result=alternative.run_queue_worker(p,entry_stack_address=entry_stack_address,
            allocate=allocate,broadcast=broadcast,max_steps=max_steps,max_depth=max_depth,
            **{k:v for k,v in kw.items() if k!='get_tls'})
        returned=result.return_code;tasks=result.tasks;kind='B_queue'
    else:
        if vm_module is None:raise RefillUnsupported('A worker requires its VM owner')
        result=startup.run_default_queue_worker(p,entry_stack_address=entry_stack_address,
            vm_module=vm_module,allocate=allocate,broadcast=broadcast,**kw)
        returned=result.return_code;tasks=result.tasks;kind='A_queue'
    if returned!=0:raise RefillUnsupported('worker return outside verified contract')
    exited=thread_exit.run_pthread_exit(GuestOS(p),image_base=image_base,libc_base=libc_base,
        thread_pointer=thread_pointer,return_value=returned,get_libc_tls=get_libc_tls,
        free=free,os_call=os_call,set_specific=set_specific,get_image_tls=get_tls,
        broadcast=broadcast)
    if exited.detached or exited.unmapped_regions:
        raise RefillUnsupported('worker exit changed joinable ownership')
    p.commit();return JniWorkerResult(kind,returned,tasks,exited)
