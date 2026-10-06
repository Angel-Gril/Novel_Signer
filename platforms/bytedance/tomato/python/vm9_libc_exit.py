"""Matching allocator TSD destruction with actual small arena releases.

Serialized default key cleanup is bounded to supported small slabs and empty
large cache bins. OS thread unregister/unmap and signing are separate phases.
"""
from __future__ import annotations
import vm9_allocator as a
import vm9_objects as objects
import vm9_startup as startup
from vm9_libc_boot import _u, _w, _indirect
from vm9_libc_tcache import _small_constants, _current_tsd, _fallback_tsd

MASK=(1<<64)-1


def _small_slot(p, pointer, libc_base):
    if not isinstance(pointer,int) or not 0 < pointer <= MASK:
        raise a.RefillUnsupported('invalid internal-free pointer')
    chunk=pointer & ~_u(p,_indirect(p,libc_base,0xD8DD8))
    page=(pointer-chunk)>>12
    bias=_u(p,_indirect(p,libc_base,0xD8F58))
    if chunk==pointer or not bias<=page<_u(p,_indirect(p,libc_base,0xD8E10)):
        raise a.RefillUnsupported('internal free requires an arena small allocation')
    tag=_u(p,chunk+0x68+(page-bias)*8)
    class_id=(tag>>4)&255
    if tag&3!=1 or class_id>=36:
        raise a.RefillUnsupported('large/huge internal free is unrecovered')
    slab=chunk+_u(p,libc_base+0xE9EA0)+(page-(tag>>12)-bias)*96+16
    return _u(p,chunk),class_id,slab


def _return_small(p, pointer, libc_base):
    arena,class_id,slab=_small_slot(p,pointer,libc_base)
    if _u(p,_indirect(p,libc_base,0xD8E80),1):
        raise a.RefillUnsupported('direct free junk fill is unrecovered')
    total=_u(p,libc_base+0xE9120+class_id*96+0x20,4)
    if _u(p,slab+4,4)+1>=total:
        raise a.RefillUnsupported('matching empty-slab extent release is unrecovered')
    lock=arena+0x508+class_id*0xE0
    objects.lock_uncontended_mutex(p,mutex_address=lock)
    a._return_slab_slot(p,arena,pointer,class_id,_small_constants(p,libc_base))
    objects.unlock_uncontended_mutex(p,mutex_address=lock)


def _internal_free(p, pointer, libc_base):
    arena,class_id,_=_small_slot(p,pointer,libc_base)
    width=_u(p,libc_base+0xA6C80+class_id*8)
    before=_u(p,arena+0x58)
    if before<width:
        raise a.RefillUnsupported('internal-free accounting underflow')
    _w(p,arena+0x58,before-width)
    _return_small(p,pointer,libc_base)


def _unlink_cache(p, cache, arena, libc_base):
    """+0x98878/+0x987ac: detach ring and drain counters under mutexes."""
    objects.lock_uncontended_mutex(p,mutex_address=arena+8)
    following=_u(p,cache);previous=_u(p,cache+8)
    if not following or not previous or _u(p,following+8)!=cache or _u(p,previous)!=cache:
        raise a.RefillUnsupported('invalid allocator cache ring')
    if _u(p,arena+0xA8)==cache:
        _w(p,arena+0xA8,0 if following==cache else following)
    _w(p,previous,following);_w(p,following+8,previous)
    _w(p,cache,cache);_w(p,cache+8,cache)
    for i in range(36):
        lock=arena+0x508+i*0xE0;target=cache+0x20+i*32
        objects.lock_uncontended_mutex(p,mutex_address=lock)
        _w(p,lock+0xA8,(_u(p,lock+0xA8)+_u(p,target))&MASK)
        objects.unlock_uncontended_mutex(p,mutex_address=lock)
        _w(p,target,0)
    for i in range(36,_u(p,libc_base+0xE9F48)):
        target=cache+0x20+i*32;row=_u(p,arena+0x98)+(i-36)*32
        value=_u(p,target)
        _w(p,arena+0x78,(_u(p,arena+0x78)+value)&MASK)
        _w(p,row+0x10,(_u(p,row+0x10)+value)&MASK);_w(p,target,0)
    objects.unlock_uncontended_mutex(p,mutex_address=arena+8)


def _destroy_cache(p, tsd, libc_base):
    cache=_u(p,tsd+8)
    if not cache:return
    arena=_u(p,tsd+0x28)
    if not arena:
        raise a.RefillUnsupported('cache destruction requires its bound arena')
    classes=_u(p,libc_base+0xE9F48)
    if not 36<=classes<=45:
        raise a.RefillUnsupported('unsupported exit cache geometry')
    _unlink_cache(p,cache,arena,libc_base)
    for i in range(36):
        target=cache+0x20+i*32;count=_u(p,target+0x10,4)
        capacity=_u(p,_u(p,libc_base+0xE9F50)+i*4,4)
        if count>capacity:
            raise a.RefillUnsupported('exit cache count exceeds capacity')
        pointers=[_u(p,_u(p,target+0x18)+j*8) for j in range(count)]
        if any(_small_slot(p,pointer,libc_base)[1]!=i for pointer in pointers):
            raise a.RefillUnsupported('exit cache pointer has the wrong class')
        preferred_seen=False
        while pointers:
            owner=_small_slot(p,pointers[0],libc_base)[0]
            lock=owner+0x508+i*0xE0
            objects.lock_uncontended_mutex(p,mutex_address=lock)
            if owner==arena:
                preferred_seen=True
                _w(p,lock+0xC0,(_u(p,lock+0xC0)+1)&MASK)
                _w(p,lock+0xA8,(_u(p,lock+0xA8)+_u(p,target))&MASK);_w(p,target,0)
            retained=[];vector=_u(p,target+0x18)
            for pointer in pointers:
                current,_,slab=_small_slot(p,pointer,libc_base)
                if current!=owner:
                    _w(p,vector+len(retained)*8,pointer);retained.append(pointer)
                    continue
                if _u(p,slab+4,4)+1>=_u(p,libc_base+0xE9120+i*96+0x20,4):
                    raise a.RefillUnsupported('matching empty-slab extent release is unrecovered')
                a._return_slab_slot(p,owner,pointer,i,_small_constants(p,libc_base))
            objects.unlock_uncontended_mutex(p,mutex_address=lock)
            pointers=retained
        if not preferred_seen:
            lock=arena+0x508+i*0xE0
            objects.lock_uncontended_mutex(p,mutex_address=lock)
            _w(p,lock+0xC0,(_u(p,lock+0xC0)+1)&MASK)
            _w(p,lock+0xA8,(_u(p,lock+0xA8)+_u(p,target))&MASK);_w(p,target,0)
            objects.unlock_uncontended_mutex(p,mutex_address=lock)
        _w(p,target+0x10,0,4)
        if a._signed32(_u(p,target+8,4))>0:_w(p,target+8,0,4)
    for i in range(36,classes):
        target=cache+0x20+i*32
        if _u(p,target+0x10,4):
            raise a.RefillUnsupported('nonempty large exit cache is unrecovered')
        objects.lock_uncontended_mutex(p,mutex_address=arena+8)
        row=_u(p,arena+0x98)+(i-36)*32;value=_u(p,target)
        _w(p,arena+0x78,(_u(p,arena+0x78)+value)&MASK)
        _w(p,row+0x10,(_u(p,row+0x10)+value)&MASK);_w(p,target,0)
        objects.unlock_uncontended_mutex(p,mutex_address=arena+8)
        if a._signed32(_u(p,target+8,4))>0:_w(p,target+8,0,4)
    _internal_free(p,cache,libc_base)
    _w(p,tsd+8,0)


def _destroy_tsd(tx, p, wrapper, *, libc_base, thread_pointer, scratch_address, os_call):
    """Actual +0x99584/+0x9975c, clear flag and republish only when needed."""
    if _u(p,wrapper,1):
        _w(p,wrapper,0,1);tsd=wrapper+8;state=_u(p,tsd,4)
        if state==1:
            _destroy_cache(p,tsd,libc_base)
            arena=_u(p,tsd+0x28)
            if arena:
                objects.lock_uncontended_mutex(p,mutex_address=libc_base+0xE6980)
                index=_u(p,arena,4);published=_u(p,_u(p,libc_base+0xE69D0)+index*8)
                if published!=arena or not _u(p,arena+4,4):
                    raise a.RefillUnsupported('invalid allocator arena reference')
                _w(p,arena+4,_u(p,arena+4,4)-1,4)
                objects.unlock_uncontended_mutex(p,mutex_address=libc_base+0xE6980)
                _w(p,tsd+0x28,0)
            table=_u(p,tsd+0x30)
            if table:
                _w(p,tsd+0x30,0);_w(p,tsd+0x3C,1,1)
                _internal_free(p,table,libc_base)
            if _u(p,tsd+0x48):
                raise a.RefillUnsupported('nonempty allocator profiling TSD cleanup is unrecovered')
        if state in (1,3):
            _w(p,tsd,2,4)
            key=_u(p,libc_base+0xE9F68,4)
            target=a.pthread_getspecific(p,key=key,thread_pointer=thread_pointer,generation_table=libc_base+0xE0200)
            if not target:
                target=_fallback_tsd(tx,libc_base=libc_base,thread_pointer=thread_pointer,
                    scratch_address=scratch_address,os_call=os_call,pages=p)
            a._write_span(p,target+8,a._read_span(p,tsd,80));_w(p,target,1,1)
    if _u(p,wrapper,1):
        if a.pthread_setspecific(p,key=_u(p,libc_base+0xE9F68,4),value=wrapper,
                thread_pointer=thread_pointer,generation_table=libc_base+0xE0200):
            raise a.RefillUnsupported('allocator exit setspecific diagnostic/abort is unrecovered')
    else:_internal_free(p,wrapper,libc_base)


def cleanup_worker_thread_keys(guest_os, *, image_base, thread_pointer,
        libc_base, scratch_address, os_call):
    """Same-owned pages/mappings: allocator and support keys clear before callbacks.

    Four bionic passes may allocate/re-publish a TSD. Direct/internal releases
    are actual small slab operations. Unknown callbacks, empty-slab release,
    nonempty large caches and profiling reject atomically. OS-thread exit and
    region unregister are not performed. External provider effects persist.
    """
    tx=guest_os.begin()
    def free(p,pointer):
        if not pointer:return
        from vm9_libc_tcache import _release_cached_small_pages
        wrapper=_current_tsd(p,libc_base,thread_pointer,tx=tx,
            scratch_address=scratch_address,os_call=os_call)
        if _u(p,wrapper+0x10):
            return _release_cached_small_pages(p,pointer=pointer,libc_base=libc_base,thread_pointer=thread_pointer)
        _,class_id,_=_small_slot(p,pointer,libc_base)
        _w(p,wrapper+0x20,(_u(p,wrapper+0x20)+_u(p,libc_base+0xA6C80+class_id*8))&MASK)
        if _u(p,libc_base+0xE69C0):
            raise a.RefillUnsupported('exit free profiling is unrecovered')
        _return_small(p,pointer,libc_base)
    def invoke(p,destructor,value):
        if destructor!=libc_base+0x99584:
            raise a.RefillUnsupported('unrecovered matching allocator exit callback')
        _destroy_tsd(tx,p,value,libc_base=libc_base,thread_pointer=thread_pointer,
            scratch_address=scratch_address,os_call=os_call)
    calls=startup.run_worker_thread_key_cleanup(tx.pages,image_base=image_base,
        thread_pointer=thread_pointer,generation_table=libc_base+0xE0200,free=free,invoke_destructor=invoke)
    tx.commit();return calls
