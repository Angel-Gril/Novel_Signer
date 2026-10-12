"""Matching bionic random state, with serialized guest rand/srand wrappers.

State and pointers belong to the caller's loaded libc image. These helpers
restore its observed arithmetic and store order, without a host PRNG or seed
imported from native output. Concurrent/contended execution remains unsupported.
"""
from vm9_allocator import RefillUnsupported, _PageTransaction, _read_span, _write_span
from vm9_objects import lock_uncontended_mutex, unlock_uncontended_mutex

MASK32=(1<<32)-1
MASK64=(1<<64)-1


def _u(p,a,n=8):return int.from_bytes(_read_span(p,a,n),'little')
def _w(p,a,v,n=8):_write_span(p,a,(v&((1<<(n*8))-1)).to_bytes(n,'little'))
def _s32(v):return (v&MASK32)-(1<<32) if v&(1<<31) else v&MASK32


def _base(libc_base):
    if type(libc_base) is not int or not 0<=libc_base<=MASK64-0xDFB40:
        raise RefillUnsupported('random libc base must fit its guest image')


def step_bionic_random_state(pages, *, libc_base):
    """+0x487a8: one live state transition; return the nonnegative W result."""
    _base(libc_base)
    p=_PageTransaction(pages)
    if _u(p,libc_base+0xDA178,4):
        front=_u(p,libc_base+0xDA220)
        rear=_u(p,libc_base+0xDA180)
        end=_u(p,libc_base+0xDA228)
        total=(_u(p,front,4)+_u(p,rear,4))&MASK32
        next_front=(front+4)&MASK64
        next_rear=(rear+4)&MASK64
        _w(p,front,total,4)
        # Native caches both cursors/end, but reloads state after the sum store.
        if next_front>=end:next_front=_u(p,libc_base+0xDA210)
        elif next_rear>=end:next_rear=_u(p,libc_base+0xDA210)
        _w(p,libc_base+0xDA220,next_front)
        result=total>>1
        _w(p,libc_base+0xDA180,next_rear)
    else:
        state=_u(p,libc_base+0xDA210)
        result=(_u(p,state,4)*1103515245+12345)&0x7FFFFFFF
        _w(p,state,result,4)
    p.commit()
    return result


def seed_bionic_random_state(pages, *, libc_base, seed_u32,
        max_degree=4096, max_warmup_steps=40960):
    """+0x4884c: signed W seed expansion, pointer reset and degree*10 warmup.

    Zero seeds remain zero in the first cell. Each following recurrence adds
    0x7fffffff when its signed W result is <=0, as the observed CSEL does.
    Initialization caches the initial state pointer/degree; warmup reads live
    type and pointer fields again on every step.
    """
    _base(libc_base)
    if type(seed_u32) is not int or not 0<=seed_u32<=MASK64:
        raise RefillUnsupported('random seed must fit its ABI word')
    if (type(max_degree) is not int or not 1<=max_degree<=0x100000 or
            type(max_warmup_steps) is not int or not 1<=max_warmup_steps<=0x1000000):
        raise RefillUnsupported('random initialization bounds must be positive')
    p=_PageTransaction(pages)
    state=_u(p,libc_base+0xDA210)
    degree=_s32(_u(p,libc_base+0xDA230,4))
    _w(p,state,seed_u32,4)
    if degree>max_degree:
        raise RefillUnsupported('random seed degree exceeds its explicit bound')
    for index in range(max(0,degree-1)):
        current=_s32(_u(p,state+index*4,4))
        quotient=abs(current)//127773
        if current<0:quotient=-quotient
        remainder=current-quotient*127773
        value=(remainder*16807-quotient*2836)&MASK32
        if _s32(value)<=0:value=(value+0x7FFFFFFF)&MASK32
        _w(p,state+(index+1)*4,value,4)
    separation=_s32(_u(p,libc_base+0xDA218,4))
    warmup=_s32((degree*10)&MASK32)
    _w(p,libc_base+0xDA180,state)
    _w(p,libc_base+0xDA220,(state+separation*4)&MASK64)
    if warmup>max_warmup_steps:
        raise RefillUnsupported('random warmup exceeds its explicit bound')
    for _ in range(max(0,warmup)):
        step_bionic_random_state(p,libc_base=libc_base)
    p.commit()


def bionic_random(pages, *, libc_base):
    """+0x48ce8 / rand+0x23868: serialize one state transition."""
    _base(libc_base)
    p=_PageTransaction(pages)
    mutex=libc_base+0xDFB30
    lock_uncontended_mutex(p,mutex_address=mutex)
    result=step_bionic_random_state(p,libc_base=libc_base)
    unlock_uncontended_mutex(p,mutex_address=mutex)
    p.commit()
    return result


def bionic_srandom(pages, *, libc_base, seed_u32,
        max_degree=4096, max_warmup_steps=40960):
    """+0x48934 / srand+0x2387c: low W seed under the serial libc mutex."""
    _base(libc_base)
    if type(seed_u32) is not int or not 0<=seed_u32<=MASK64:
        raise RefillUnsupported('random seed must fit its ABI word')
    p=_PageTransaction(pages)
    mutex=libc_base+0xDFB30
    lock_uncontended_mutex(p,mutex_address=mutex)
    if _u(p,libc_base+0xDA178,4):
        seed_bionic_random_state(p,libc_base=libc_base,seed_u32=seed_u32,
            max_degree=max_degree,max_warmup_steps=max_warmup_steps)
    else:_w(p,_u(p,libc_base+0xDA210),seed_u32,4)
    unlock_uncontended_mutex(p,mutex_address=mutex)
    p.commit()


def _request_stack(entry_stack_address, thread_pointer):
    if (type(entry_stack_address) is not int or not 0x100<=entry_stack_address<=MASK64
            or entry_stack_address&15 or type(thread_pointer) is not int
            or not 0<=thread_pointer<=MASK64-0x30):
        raise RefillUnsupported('request random stack/TLS must fit the aligned guest ABI')


def get_request_time_seconds(pages, *, output_address, entry_stack_address,
        thread_pointer, syscall, errno_address):
    """+0x2728f4: explicit gettimeofday syscall169 and optional seconds store.

    Timeval lives at entrySP-0x38, canary at entrySP-0x28. The syscall provider
    writes guest bytes; the actual wrapper publishes -1 for a negative result.
    Kernel errno conversion belongs to the existing syscall owner.
    """
    from vm9_configuration_init import _guest_syscall
    _request_stack(entry_stack_address,thread_pointer)
    if not callable(syscall):
        raise RefillUnsupported('request random requires an explicit gettimeofday provider')
    if type(output_address) is not int or not 0<=output_address<=MASK64:
        raise RefillUnsupported('request time output must fit its guest ABI')
    p=_PageTransaction(pages)
    timeval=entry_stack_address-0x38
    saved_canary=entry_stack_address-0x28
    _write_span(p,saved_canary,_read_span(p,thread_pointer+0x28,8))
    status=_guest_syscall(p,syscall,errno_address,169,timeval,0)
    seconds=_u(p,timeval) if status>=0 else MASK64
    if output_address:_w(p,output_address,seconds)
    if _read_span(p,saved_canary,8)!=_read_span(p,thread_pointer+0x28,8):
        raise RefillUnsupported('request time stack canary mismatch')
    p.commit()
    return seconds


def get_request_random(pages, *, image_base, libc_base, entry_stack_address,
        thread_pointer, syscall, errno_address, thread_id=None):
    """+0x26cc8c: seed once from seconds, then return actual guest rand state.

    Guard bit0 selects the warm path; acquisition still tests the whole first
    byte and completed second byte. Contention and provider effects beyond
    guest pages remain outside this serial transactional contract.
    """
    from vm9_startup import acquire_serial_guard,release_serial_guard
    _base(libc_base)
    _request_stack(entry_stack_address,thread_pointer)
    if type(image_base) is not int or not 0<=image_base<=MASK64-0x3E2F50:
        raise RefillUnsupported('request random image base must fit its guard')
    p=_PageTransaction(pages)
    local=entry_stack_address-0x30
    canary=entry_stack_address-0x28
    _write_span(p,canary,_read_span(p,thread_pointer+0x28,8))
    guard=image_base+0x3DEDB0
    if not _u(p,guard,1)&1:
        if acquire_serial_guard(p,guard_address=guard,image_base=image_base,thread_id=thread_id):
            seed=get_request_time_seconds(p,output_address=local,
                entry_stack_address=local,thread_pointer=thread_pointer,
                syscall=syscall,errno_address=errno_address)
            bionic_srandom(p,libc_base=libc_base,seed_u32=seed&MASK32)
            release_serial_guard(p,guard_address=guard,image_base=image_base)
    result=bionic_random(p,libc_base=libc_base)
    if _read_span(p,canary,8)!=_read_span(p,thread_pointer+0x28,8):
        raise RefillUnsupported('request random stack canary mismatch')
    p.commit()
    return result


def store_request_random_callback(pages, *, argument_block_address,
        entry_stack_address, **inputs):
    """+0x288b08: invoke the recovered getter, then write only packed+8 W0."""
    p=_PageTransaction(pages)
    image=inputs.get('image_base')
    if image is None or _u(p,argument_block_address)!=image+0x26CC8C:
        raise RefillUnsupported('request random callback target is unsupported')
    result=get_request_random(p,entry_stack_address=entry_stack_address-0x10,**inputs)
    _w(p,argument_block_address+8,result,4)
    p.commit()
    return result
