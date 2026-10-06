"""Matching libc emulated TLS backed by the actual ready allocator.

The libc ABI has a capacity word followed by indexed pointers. It differs
from the main image's deferred array destructor and header. Growth and abort
branches reject; no native output or allocation-return provider seeds state.
"""
from __future__ import annotations
import vm9_allocator as a
import vm9_objects as objects
from vm9_libc_boot import _u,_w,_indirect
from vm9_libc_base import _allocate_staged
from vm9_libc_tcache import _public_small
import vm9_libc_region as region

MAX_SLOTS=1024
MAX_PAYLOAD=0x3800


def _allocate(tx,p,size,*,zero,libc_base,thread_pointer,scratch_address,os_call):
    if not 1<=size<=MAX_PAYLOAD:
        raise a.RefillUnsupported('libc emutls allocation outside recovered small policy')
    def body(inner,*,request_size,libc_base,thread_pointer,os_call):
        pointer=_public_small(inner,request_size=request_size,libc_base=libc_base,
            thread_pointer=thread_pointer,os_call=os_call,scratch_address=scratch_address)
        if pointer and zero:
            index=region._size_index(inner.pages,libc_base,request_size)
            width=_u(inner.pages,_indirect(inner.pages,libc_base,0xD8EE0)+index*8)
            a._write_span(inner.pages,pointer,bytes(width))
        return pointer
    pointer=_allocate_staged(tx,p,request_size=size,libc_base=libc_base,
        thread_pointer=thread_pointer,os_call=os_call,allocation_body=body)
    if not pointer:raise a.RefillUnsupported('libc emutls malloc/calloc abort is unrecovered')
    return pointer


def _payload(tx,p,control,*,libc_base,thread_pointer,scratch_address,os_call):
    size=_u(p,control);alignment=_u(p,control+8)
    if size>MAX_PAYLOAD or not alignment or alignment&(alignment-1) or alignment>4096:
        raise a.RefillUnsupported('unsupported libc emutls size/alignment')
    request=size+8 if alignment<=8 else size+alignment+7
    raw=_allocate(tx,p,request,zero=False,libc_base=libc_base,thread_pointer=thread_pointer,
        scratch_address=scratch_address,os_call=os_call)
    value=raw+8 if alignment<=8 else (raw+alignment+7)&-alignment
    _w(p,value-8,raw)
    template=_u(p,control+24)
    a._write_span(p,value,a._read_span(p,template,size) if template else bytes(size))
    return value


def _get_thread_variable(tx,p,*,control_address,libc_base,thread_pointer,
        scratch_address,os_call,once_wake):
    if not isinstance(control_address,int) or control_address<0 or control_address&7:
        raise a.RefillUnsupported('invalid libc emutls control address')
    a._read_span(p,control_address,32)
    args=dict(libc_base=libc_base,thread_pointer=thread_pointer,scratch_address=scratch_address,os_call=os_call)
    if not _u(p,libc_base+0xD8DA8):
        value=_u(p,control_address+16)
        if not value:
            value=_payload(tx,p,control_address,**args);_w(p,control_address+16,value)
        return _u(p,control_address+16)
    index=_u(p,control_address+16)
    key_address=libc_base+0xE6AE8
    if not index:
        once=key_address+4;state=_u(p,once,4)
        if state==0:
            _w(p,once,1,4)
            if a.pthread_key_create(p,key_address=key_address,destructor=libc_base+0x9BD3C,
                    generation_table=libc_base+0xE0200):
                raise a.RefillUnsupported('libc emutls key-create abort is unrecovered')
            _w(p,once,2,4)
            result=once_wake(p,once,129,0x7fffffff)
            if not isinstance(result,int) or result<0:
                raise a.RefillUnsupported('libc emutls once wake error is unrecovered')
        elif state!=2:
            raise a.RefillUnsupported('busy libc emutls once is unrecovered')
        mutex=key_address+8
        objects.lock_uncontended_mutex(p,mutex_address=mutex)
        index=_u(p,control_address+16)
        if not index:
            index=_u(p,key_address+0x30)+1
            if not 1<=index<=MAX_SLOTS:
                raise a.RefillUnsupported('libc emutls index exceeds bound')
            _w(p,key_address+0x30,index);_w(p,control_address+16,index)
        objects.unlock_uncontended_mutex(p,mutex_address=mutex)
    if not 1<=index<=MAX_SLOTS:
        raise a.RefillUnsupported('libc emutls index exceeds bound')
    key=_u(p,key_address,4)
    array=a.pthread_getspecific(p,key=key,thread_pointer=thread_pointer,generation_table=libc_base+0xE0200)
    if not array:
        capacity=index+32
        if capacity>MAX_SLOTS:raise a.RefillUnsupported('libc emutls array capacity exceeds bound')
        array=_allocate(tx,p,(capacity+1)*8,zero=True,**args)
        _w(p,array,capacity)
        # The matching ABI ignores setspecific status. Its abort-free error
        # behavior is preserved; key-create still rejects exhausted tables.
        a.pthread_setspecific(p,key=key,value=array,thread_pointer=thread_pointer,generation_table=libc_base+0xE0200)
    elif index>_u(p,array):
        raise a.RefillUnsupported('libc emutls realloc/growth is unrecovered')
    value=_u(p,array+index*8)
    if not value:
        value=_payload(tx,p,control_address,**args);_w(p,array+index*8,value)
    return value


def get_thread_variable(guest_os,*,control_address,libc_base,thread_pointer,
        scratch_address,os_call,once_wake):
    """+0x9be24/+0x9bd90 after real allocator boot; commit only on success.

    Key creation, indexing, zeroed array and aligned/template payload use
    matching guest pages and the actual allocator. The explicit once wake/OS
    services have external effects outside rollback. No host TLS is created.
    """
    tx=guest_os.begin()
    value=_get_thread_variable(tx,tx.pages,control_address=control_address,
        libc_base=libc_base,thread_pointer=thread_pointer,scratch_address=scratch_address,
        os_call=os_call,once_wake=once_wake)
    tx.commit();return value


def destroy_array(pages,*,array_address,free,max_slots=MAX_SLOTS):
    """+0x9bd3c: capture capacity; free each payload backing block then array.

    The key dispatcher clears TLS before this callback. Actual free is a
    required provider, allowing the surrounding GuestOS transaction to own
    allocator/OS effects. No defer counter or key republish belongs to this ABI.
    """
    if not isinstance(max_slots,int) or not 1<=max_slots<=MAX_SLOTS:
        raise ValueError('invalid libc emutls destructor bound')
    p=a._PageTransaction(pages);capacity=_u(p,array_address)
    if capacity>max_slots:raise a.RefillUnsupported('libc emutls array capacity exceeds bound')
    a._read_span(p,array_address,(capacity+1)*8)
    for index in range(1,capacity+1):
        value=_u(p,array_address+index*8)
        if value:free(p,_u(p,value-8))
    free(p,array_address);p.commit()
