"""Matching-libc default malloc initializer with natural ready publication.

Fresh ELF/TLS and explicit virtual OS inputs drive real allocator/FILE bodies.
Nondefault config, diagnostics, real thread creation and standalone Medusa
are separate boundaries; this is not an all-branch libc replacement.
"""
from __future__ import annotations
import vm9_allocator as allocator
import vm9_objects as objects
import vm9_libc_base as base_model
import vm9_libc_boot as boot
import vm9_libc_region as region
from vm9_libc_file import _get_nprocs
from vm9_libc_tcache import _public_small
from vm9_libc_boot import _u,_w,_indirect


def _internal_small(tx, *, request_size, libc_base, thread_pointer, os_call):
    """Actual +0x8e0ec -> +0x8df44 zero=false/account=true in ready state."""
    if _u(tx.pages,libc_base+0xDB6A0,4)!=0:
        raise allocator.RefillUnsupported("cold-tail internal allocation requires natural ready state")
    arena=_u(tx.pages,libc_base+0xE6968)
    if not arena:
        raise allocator.RefillUnsupported("cold-tail internal allocation has no initial arena")
    pointer,width=region._direct_small(tx,arena_address=arena,request_size=request_size,zero=False,
        libc_base=libc_base,thread_pointer=thread_pointer,os_call=os_call)
    if pointer:_w(tx.pages,arena+0x58,(_u(tx.pages,arena+0x58)+width)&((1<<64)-1))
    return pointer


def _initialize_default(tx, *, scratch_address, libc_base, thread_pointer, brk, os_call):
    p=tx.pages
    stop=base_model._cold_prefix_transaction(tx,libc_base=libc_base,thread_pointer=thread_pointer,
        brk=brk,os_call=os_call)
    if stop!=0x8E41C:return 1
    cpus=_get_nprocs(tx,scratch_address=scratch_address,libc_base=libc_base,
        thread_pointer=thread_pointer,os_call=os_call)
    # Actual sysconf(97) sign-extends get_nprocs; only -1 maps to default 1.
    _w(p,libc_base+0xE9F44,1 if cpus==-1 else cpus&0xFFFFFFFF,4)
    def public_allocate(pages,size):
        return base_model._allocate_staged(tx,pages,request_size=size,libc_base=libc_base,
            thread_pointer=thread_pointer,os_call=os_call,allocation_body=_public_small)
    status=boot.register_atfork(p,libc_base=libc_base,prepare=libc_base+0x8D9B4,
        parent=libc_base+0x8DA28,child=libc_base+0x8DA9C,dso=libc_base+0xD9008,
        allocate_public=public_allocate,thread_pointer=thread_pointer)
    if status:
        raise allocator.RefillUnsupported("cold atfork diagnostic/abort path is unrecovered")
    mutex=libc_base+0xE6938
    objects.lock_uncontended_mutex(p,mutex_address=mutex)
    # Matching +0x933ac is literally mov w0,#0; ret, not a supplied callback.
    if _u(p,libc_base+0x933AC)!=0xD65F03C052800000:
        raise allocator.RefillUnsupported("matching cold-tail no-op body changed")
    arenas=_u(p,libc_base+0xE69B0)
    if not arenas:
        count=_u(p,libc_base+0xE9F44,4)
        arenas=1 if count<=1 else (count<<2)&0xFFFFFFFF
        _w(p,libc_base+0xE69B0,arenas)
    if arenas>2:
        arenas=2;_w(p,libc_base+0xE69B0,arenas)
    _w(p,libc_base+0xE6970,arenas,4)
    capacity=_u(p,_indirect(p,libc_base,0xD8FC8))>>3
    if capacity<arenas:
        raise allocator.RefillUnsupported("arena-table truncation diagnostic is unrecovered")
    _w(p,libc_base+0xE6960,arenas,4)
    table=base_model._base_allocate(tx,request_size=arenas*8,libc_base=libc_base,
        thread_pointer=thread_pointer,os_call=os_call)
    _w(p,libc_base+0xE69D0,table)
    if not table:
        objects.unlock_uncontended_mutex(p,mutex_address=mutex)
        return 1
    allocator._write_span(p,table,bytes(arenas*8))
    _w(p,libc_base+0xDB6A0,0,4)
    _w(p,table,_u(p,libc_base+0xE6968))
    objects.unlock_uncontended_mutex(p,mutex_address=mutex)
    def internal_allocate(pages,size):
        return base_model._allocate_staged(tx,pages,request_size=size,libc_base=libc_base,
            thread_pointer=thread_pointer,os_call=os_call,allocation_body=_internal_small)
    boot.migrate_static_tsd(p,libc_base=libc_base,thread_pointer=thread_pointer,
        allocate_internal=internal_allocate)
    return 0


def initialize_default_malloc(guest_os, *, scratch_address, libc_base, thread_pointer, brk, os_call):
    """Actual default +0x8e350 return through CPU/atfork/table/TSD migration."""
    tx=guest_os.begin()
    result=_initialize_default(tx,scratch_address=scratch_address,libc_base=libc_base,
        thread_pointer=thread_pointer,brk=brk,os_call=os_call)
    tx.commit()
    return result


def allocate_default_small(guest_os, *, request_size, scratch_address, libc_base, thread_pointer, brk, os_call):
    """Actual fresh/ready public small malloc using natural default cold init."""
    tx=guest_os.begin()
    if _u(tx.pages,libc_base+0xDB6A0,4)==3:
        status=_initialize_default(tx,scratch_address=scratch_address,libc_base=libc_base,
            thread_pointer=thread_pointer,brk=brk,os_call=os_call)
        if status:
            tx.commit();return 0
    result=_public_small(tx,request_size=request_size,libc_base=libc_base,
        thread_pointer=thread_pointer,os_call=os_call)
    tx.commit()
    return result
