"""Cooperative guest workers with finite, explicit futex and scheduling services.

The three startup descriptors keep their own TLS, stack ABI and argument
ownership. Shared staged pages publish changes between guest waits;
the caller stages provider effects separately. No host thread is created.
"""
from dataclasses import dataclass
from vm9_allocator import _PageTransaction, _read_span, _write_span, RefillUnsupported, GuestOS
import vm9_startup as startup
import vm9_alternative_startup as alternative
import vm9_jni_finalizer as finalizer
import vm9_jni_followup as followup
import vm9_jni_environment as environment
import vm9_thread_exit as thread_exit
import vm9_timed_tasks as timed


def u(p,a,n=8):return int.from_bytes(_read_span(p,a,n),'little')
def w(p,a,v,n=8):_write_span(p,a,(v&((1<<(n*8))-1)).to_bytes(n,'little'))


@dataclass(frozen=True)
class WorkerScheduleResult:
    return_order: tuple[int, ...]
    futex_waits: int
    scheduler_steps: int
    task_results: tuple
    exit_results: tuple


def run_requested_worker_schedule(pages, *, threads, image_base, libc_base,
        startup_entry, entry_stack_addresses, thread_pointers, thread_ids,
        select_worker, activate_thread, allocate, free, create_key, set_specific,
        get_tls, read_clock, clock, futex, broadcast, initialize_registry,
        register_destructor, invoke_javavm, invoke_jni, read_property, system,
        signal_condition, get_libc_tls, os_call, vm_module, max_iterations=64,
        max_scheduler_steps=256):
    """Run the three requested guest workers across their actual wait boundaries.

    select_worker(pages, candidates) chooses an index from the unfinished
    workers. activate_thread(pages, index, TP) selects its provider context.
    Each yielded futex calls the finite provider immediately; its result is
    retained until that worker is selected again. Wait responses, clocks and
    stop flags belong to the environment. Every guest page rolls back if any
    worker, service or scheduler selection rejects.
    """
    for value in (image_base,libc_base):
        if type(value) is not int or not 0<value<1<<56 or value%4096:
            raise RefillUnsupported('invalid cooperative image address')
    if startup_entry not in (0x28040C,0x2A0028):
        raise RefillUnsupported('unknown cooperative startup entry')
    if (len(threads)!=3 or len(entry_stack_addresses)!=3 or len(thread_pointers)!=3
            or len(thread_ids)!=3 or len(set(thread_pointers))!=3
            or len(set(entry_stack_addresses))!=3):
        raise RefillUnsupported('cooperative schedule requires three distinct workers')
    if type(max_iterations) is not int or not 1<=max_iterations<=4096:
        raise ValueError('invalid cooperative worker iteration bound')
    if type(max_scheduler_steps) is not int or not 1<=max_scheduler_steps<=4096:
        raise ValueError('invalid cooperative scheduler bound')
    providers=(select_worker,activate_thread,allocate,free,create_key,set_specific,
        get_tls,read_clock,clock,futex,broadcast,initialize_registry,register_destructor,
        invoke_javavm,invoke_jni,read_property,system,signal_condition,get_libc_tls,os_call)
    if not all(callable(f) for f in providers):
        raise RefillUnsupported('cooperative schedule requires explicit providers')
    if vm_module is None or not all(hasattr(vm_module,n) for n in ('VM','Mem','VMExit','B')):
        raise RefillUnsupported('cooperative schedule requires its image VM owner')
    p=_PageTransaction(pages);b=image_base;task_results=[];exit_results=[]
    arguments=[]
    for index,descriptor in enumerate(threads):
        if len(descriptor)!=3:raise RefillUnsupported('invalid cooperative thread descriptor')
        handle,entry,arg=descriptor;expected=b+(0x326A2C if index==0 else 0x3260A4)
        if entry!=expected or type(handle) is not int or not handle:
            raise RefillUnsupported('unknown cooperative worker descriptor')
        for value,alignment in ((arg,8),(entry_stack_addresses[index],16),(thread_pointers[index],8)):
            if type(value) is not int or not 0x10000<value<1<<56 or value%alignment:
                raise RefillUnsupported('invalid cooperative worker address')
        if type(thread_ids[index]) is not int or not 0<thread_ids[index]<1<<32:
            raise RefillUnsupported('invalid cooperative worker thread id')
        thread=u(p,thread_pointers[index]+8)
        if not thread or u(p,thread+0x50,4) or u(p,thread+0x78) or u(p,thread+0x58):
            raise RefillUnsupported('cooperative worker requires fresh joinable storage')
        _read_span(p,entry_stack_addresses[index]-0x8000,0x8000)
        arguments.append(arg)
    if len(set(arguments))!=3:raise RefillUnsupported('cooperative arguments alias')

    def execute(index):
        arg=arguments[index];S=entry_stack_addresses[index];tp=thread_pointers[index];tid=thread_ids[index]
        kind='executor' if index==0 else 'queue'
        dispatch=startup.attach_worker_support(p,argument_address=arg,worker_kind=kind,
            image_base=b,thread_id=tid,create_key=create_key,set_specific=set_specific)
        if index==0:
            startup.initialize_executor_context(p,context_address=dispatch,image_base=b,get_tls=get_tls)
            if u(p,dispatch+0x68,1) or u(p,dispatch+0x6A,1):
                raise RefillUnsupported('cooperative executor cancellation is unsupported')
            if u(p,dispatch+8)!=u(p,b+0x3750B8)+0x48:
                raise RefillUnsupported('unknown cooperative executor polling vtable')
            def transfer(staged,function,address):
                if function!=b+0x325950:raise RefillUnsupported('unknown cooperative timed wrapper')
                return timed.dispatch_timed_callable(staged,wrapper_address=address,
                    entry_stack_address=S-0xA0,image_base=b,free=free,signal_condition=signal_condition)
            yield from startup.iter_executor_context(p,context_address=dispatch,
                image_base=b,thread_pointer=tp,clock=clock,free=free,
                invoke=transfer,max_iterations=max_iterations)
        else:
            queue=u(p,dispatch+8);task=S-0xC0;iterations=0
            while True:
                if iterations>=max_iterations:raise RefillUnsupported('cooperative queue iteration bound exceeded')
                iterations+=1
                ready=yield from startup.iter_take_queue_callable(p,queue_address=queue,
                    task_address=task,image_base=b,thread_pointer=tp,
                    clock=clock,free=free,max_waits=max_iterations)
                if not ready:
                    startup.destroy_callable(p,object_address=task,image_base=b,free=free);break
                pointer=u(p,task+0x20);table=u(p,pointer);function=u(p,table+0x30)
                if pointer!=task:raise RefillUnsupported('unknown cooperative queue task ownership')
                if index==1 and startup_entry==0x28040C and function==b+0x280554:
                    result=startup.run_default_queue_task(p,queue_address=queue,image_base=b,
                        worker_entry_stack_address=S,thread_pointer=tp,vm_module=vm_module,
                        allocate=allocate,broadcast=broadcast)
                elif index==1 and startup_entry==0x2A0028 and function==b+0x29E05C:
                    result=alternative.run_worker_initialization_task(p,image_base=b,
                        entry_stack_address=S-0xD0,thread_pointer=tp,allocate=allocate,
                        broadcast=broadcast,reserved_regions=((task,task+40),(arg,arg+64)))
                elif index==2 and function==b+0x204348:
                    result=finalizer._run_finalizer(p,image_base=b,entry_stack_address=S-0xD0,
                        thread_pointer=tp,thread_id=tid,allocate=allocate,free=free,
                        read_clock=read_clock,get_tls=get_tls,initialize_registry=initialize_registry,
                        broadcast=broadcast,register_destructor=register_destructor,
                        invoke_javavm=invoke_javavm,invoke_jni=invoke_jni,system=system,
                        clock=clock,signal_condition=signal_condition,vm_module=vm_module)
                elif index==2 and function==b+0x2043BC:
                    result=followup.run_delayed_followup_callable(p,callable_address=task,
                        image_base=b,entry_stack_address=S-0xD0,thread_pointer=tp,thread_id=tid,
                        allocate=allocate,free=free,read_clock=read_clock,get_tls=get_tls,
                        initialize_registry=initialize_registry,broadcast=broadcast,
                        register_destructor=register_destructor,invoke_javavm=invoke_javavm,
                        read_property=read_property,system=system,vm_module=vm_module)
                else:raise RefillUnsupported('unknown cooperative queue task')
                task_results.append((index,function,result))
                startup.destroy_callable(p,object_address=task,image_base=b,free=free)
            startup.destroy_callable(p,object_address=dispatch,image_base=b,free=free)
        if u(p,arg):raise RefillUnsupported('cooperative worker acquired unsupported argument ownership')
        w(p,arg,0);free(p,arg)
        def destructor(staged,function,address):
            if function!=b+0x26EF2C:raise RefillUnsupported('unknown cooperative JNI TLS destructor')
            environment.destroy_thread_environment(staged,image_base=b,object_address=address,invoke_javavm=invoke_javavm)
        exited=thread_exit.run_pthread_exit(GuestOS(p),image_base=b,libc_base=libc_base,
            thread_pointer=tp,return_value=0,get_libc_tls=get_libc_tls,free=free,
            os_call=os_call,set_specific=set_specific,get_image_tls=get_tls,broadcast=broadcast,invoke=destructor)
        if exited.detached or exited.unmapped_regions:
            raise RefillUnsupported('cooperative worker changed joinable exit ownership')
        exit_results.append((index,exited))

    generators={index:execute(index) for index in range(3)};started=set();waiting={}
    returned=[];steps=0;waits=0
    try:
        while generators:
            if steps>=max_scheduler_steps:raise RefillUnsupported('cooperative scheduler selection bound exceeded')
            steps+=1;candidates=tuple(sorted(generators));index=select_worker(p,candidates)
            if type(index) is not int or index not in generators:
                raise RefillUnsupported('scheduler selected an unavailable worker')
            if activate_thread(p,index,thread_pointers[index]) is not None:
                raise RefillUnsupported('thread activation returned an unsupported value')
            try:
                if index not in started:
                    started.add(index);pending=next(generators[index])
                else:pending=generators[index].send(waiting.pop(index))
            except StopIteration:
                returned.append(index);del generators[index];continue
            if not isinstance(pending,startup.PendingConditionWait):
                raise RefillUnsupported('worker yielded an unknown scheduler request')
            waits+=1
            waiting[index]=futex(p,pending.condition_address,pending.operation,pending.expected,pending.relative_timeout)
    finally:
        for generator in generators.values():generator.close()
    p.commit();return WorkerScheduleResult(tuple(returned),waits,steps,tuple(task_results),tuple(exit_results))
