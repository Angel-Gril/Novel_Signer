"""First timed task submission and transfer into an existing startup queue.

Guest clock, allocation and condition signaling are explicit providers.
Existing tasks, cancelled executors and concurrent mutation reject.
"""
from dataclasses import dataclass
from vm9_allocator import _PageTransaction,_read_span,_write_span,RefillUnsupported
import vm9_objects as objects
import vm9_startup as startup

MASK64=(1<<64)-1
def _u(p,a,n=8):return int.from_bytes(_read_span(p,a,n),'little')
def _w(p,a,v,n=8):_write_span(p,a,(v&((1<<(n*8))-1)).to_bytes(n,'little'))

@dataclass(frozen=True)
class TimedTaskSubmission:
    callable_address: int
    task_address: int
    deadline_milliseconds: int
    executor_context_address: int


def submit_timed_callable(pages, *, source_address, scratch_address, image_base,
        queue_index, delay_ms, allocate, free, clock, signal_condition):
    """+325454 nonzero-delay branch, +326c00 and first +326d04 insertion.

    Startup must already have published its two queues and initialized the
    executor controller. The supported source is its inline JNI follow-up
    callable. A task owns the heap wrapper after submission. Provider effects
    must be staged by the caller; page rollback cannot undo external calls.
    """
    if type(queue_index) is not int or queue_index not in (0,1):
        raise RefillUnsupported('invalid timed queue index')
    if type(delay_ms) is not int or not -(1<<31)<=delay_ms<1<<31 or not delay_ms:
        raise RefillUnsupported('timed delay requires a nonzero signed W32')
    for address,alignment in ((image_base,4096),(source_address,8),(scratch_address,16)):
        if type(address) is not int or not 0<address<1<<56 or address%alignment:
            raise RefillUnsupported('invalid timed task address')
    if not all(callable(f) for f in (allocate,free,clock,signal_condition)):
        raise RefillUnsupported('timed task requires explicit providers')
    p=_PageTransaction(pages);base=image_base
    _read_span(p,scratch_address,0x120)
    if source_address<scratch_address+0x120 and scratch_address<source_address+40:
        raise RefillUnsupported('timed source overlaps submission scratch')
    if _u(p,source_address)!=base+0x34F058 or _u(p,source_address+0x20)!=source_address:
        raise RefillUnsupported('unsupported timed source callable')
    if not _u(p,base+0x3E2D80,1)&1:
        raise RefillUnsupported('timed executor singleton is not initialized')
    executor=_u(p,base+0x3E2D78);payload=_u(p,executor+0x10)
    context=_u(p,payload+8)
    if (_u(p,context)!=_u(p,base+0x3750B8)+0x10
            or _u(p,context+8)!=_u(p,base+0x3750B8)+0x48
            or _u(p,_u(p,context))!=base+0x326C00):
        raise RefillUnsupported('unsupported timed executor virtual method')
    if _u(p,context+0x68,1) or not _u(p,context+0x69,1):
        raise RefillUnsupported('timed executor controller is not active')
    if any(_u(p,context+a) for a in (0x38,0x40,0x48,0x50,0x58,0x60)):
        raise RefillUnsupported('timed submission requires the first empty deque')
    controller=_u(p,context+0xE0)
    if controller!=context+0x78 or _u(p,controller)!=_u(p,base+0x3750C0)+0x10:
        raise RefillUnsupported('unsupported timed signal controller')
    temporary=scratch_address
    startup.move_callable(p,destination_address=temporary,source_address=source_address,image_base=base)
    startup.move_callable(p,destination_address=temporary+0x30,source_address=temporary,image_base=base)
    startup.move_callable(p,destination_address=temporary+0x60,source_address=temporary+0x30,image_base=base)
    startup.move_callable(p,destination_address=temporary+0x90,source_address=temporary+0x60,image_base=base)
    wrapper=objects._allocate(p,allocate,80)
    _w(p,wrapper,base+0x3725B8);_w(p,wrapper+0x10,executor);_w(p,wrapper+0x18,queue_index,1)
    startup.move_callable(p,destination_address=wrapper+0x20,source_address=temporary+0x90,image_base=base)
    seconds,nanos=clock(p,1)
    if type(seconds) is not int or type(nanos) is not int or not 0<=nanos<1000000000:
        raise RefillUnsupported('invalid timed clock result')
    total=startup._s64(seconds*1000000000+nanos)
    deadline=startup._s64(startup._trunc_div(total,1000000)+delay_ms)
    task=objects._allocate(p,allocate,64)
    _w(p,task+0x20,wrapper);_w(p,task+0x30,deadline);_w(p,task+0x38,MASK64)
    objects.lock_uncontended_mutex(p,mutex_address=context+0x10)
    table=objects._allocate(p,allocate,8);segment=objects._allocate(p,allocate,4096)
    _w(p,table,segment);_w(p,segment,task)
    for offset,value in ((0x38,table),(0x40,table),(0x48,table+8),(0x50,table+8),(0x60,1)):
        _w(p,context+offset,value)
    objects.lock_uncontended_mutex(p,mutex_address=controller+0x10)
    _w(p,controller+0xC,_u(p,controller+0xC,4)+1,4)
    objects.unlock_uncontended_mutex(p,mutex_address=controller+0x10)
    if signal_condition(p,controller+0x38)!=0:
        raise RefillUnsupported('timed controller signal failed')
    objects.unlock_uncontended_mutex(p,mutex_address=context+0x10)
    for offset in (0x90,0x60,0x30,0):
        startup.destroy_callable(p,object_address=temporary+offset,image_base=base,free=free)
    p.commit();return TimedTaskSubmission(wrapper,task,deadline,context)


def dispatch_timed_callable(pages, *, wrapper_address, entry_stack_address,
        image_base, free, signal_condition):
    """+325950 -> +3257e4/+325b88 with the drained queue's retained slot.

    The timed wrapper owns an inline JNI follow-up. Clone it into the native
    temporary, move it into one empty queue slot, signal and destroy the
    temporary. Polling and the wrapper/task destructors stay with startup.
    Vector growth, other nested callable types and concurrent mutation reject.
    Provider effects must be staged separately from guest page rollback.
    """
    for address,alignment in ((image_base,4096),(wrapper_address,8),(entry_stack_address,16)):
        if type(address) is not int or not 0<address<1<<56 or address%alignment:
            raise RefillUnsupported('invalid timed dispatch address')
    if not all(callable(f) for f in (free,signal_condition)):
        raise RefillUnsupported('timed dispatch requires explicit providers')
    p=_PageTransaction(pages);base=image_base;wrapper=wrapper_address
    if (_u(p,wrapper)!=base+0x3725B8 or _u(p,base+0x3725E8)!=base+0x325950
            or _u(p,wrapper+0x20)!=base+0x34F058
            or _u(p,wrapper+0x40)!=wrapper+0x20):
        raise RefillUnsupported('unknown timed dispatch wrapper')
    index=_u(p,wrapper+0x18,1)
    if index not in (0,1):raise RefillUnsupported('unknown timed queue selector')
    executor=_u(p,wrapper+0x10)
    if not _u(p,base+0x3E2D80,1)&1 or executor!=_u(p,base+0x3E2D78):
        raise RefillUnsupported('timed dispatch requires its initialized executor')
    queue=_u(p,executor+index*8);_read_span(p,queue,144)
    temporary=entry_stack_address-0x70
    _read_span(p,temporary,40)
    # For this observed inline type, +325824's clone matches +3259c4's copy.
    startup.move_callable(p,destination_address=temporary,source_address=wrapper+0x20,image_base=base)
    # +325b88 latches x19=temporary. Its +329f3c/matching-libc lock saves x19
    # here; the following image VM retains the word in its register backing,
    # and the final scoped writer copies its upper seven bytes into a TLS node.
    _w(p,entry_stack_address-0xF0,temporary)
    objects.lock_uncontended_mutex(p,mutex_address=queue+0x30)
    begin,end,capacity=(_u(p,queue+a) for a in (0x18,0x20,0x28))
    if not begin or end!=begin or capacity!=begin+48:
        raise RefillUnsupported('timed dispatch requires one retained empty queue slot')
    startup.move_callable(p,destination_address=end,source_address=temporary,image_base=base)
    _w(p,queue+0x20,end+48)
    objects.unlock_uncontended_mutex(p,mutex_address=queue+0x30)
    if signal_condition(p,queue+0x58)!=0:
        raise RefillUnsupported('timed queue signal failed')
    startup.destroy_callable(p,object_address=temporary,image_base=base,free=free)
    p.commit();return queue
