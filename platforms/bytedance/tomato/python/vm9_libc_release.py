"""Matching-libc empty small slab release and bounded advisory purge.

Only the default extent tree, small dirty extents outside the arena's spare
region and explicit successful madvise are supported. Huge/whole-region and
large cached-extent paths reject. The caller owns the GuestOS transaction.
"""
from __future__ import annotations
import vm9_allocator as a
import vm9_objects as objects
import vm9_libc_region as region
from vm9_libc_boot import _u,_w,_indirect

MASK=(1<<64)-1


def _location(p,slab,libc_base):
    node=slab-16;mask=_u(p,libc_base+0xE9EC0)
    chunk=node&~mask;offset=_u(p,libc_base+0xE9EA0)
    delta=node-chunk-offset
    if delta<0 or delta%96:raise a.RefillUnsupported('invalid matching extent placement')
    return chunk,_u(p,libc_base+0xE9EB0)+delta//96


def _account(p,arena,delta,libc_base):
    before=_u(p,arena+0xD8);after=before+delta
    if after<0:raise a.RefillUnsupported('matching extent accounting underflow')
    mask=_u(p,_indirect(p,libc_base,0xD8DD8))
    volume=((mask+(after<<12))&~mask)-((mask+(before<<12))&~mask)
    if volume:
        address=_indirect(p,libc_base,0xD8E38)
        _w(p,address,(_u(p,address)+volume)&MASK)
    _w(p,arena+0xD8,after)


def _release_extent(p,arena,slab,dirty,force_clean,*,libc_base,os_call):
    chunk,page=_location(p,slab,libc_base);bias=_u(p,libc_base+0xE9EB0)
    def tag_address(index):return chunk+0x68+(index-bias)*8
    tag=_u(p,tag_address(page))
    size=(tag&~4095) if tag&2 else _u(p,libc_base+0xE9120+_u(p,slab,4)*96+0x18)
    count=size>>12
    if not count:raise a.RefillUnsupported('empty matching extent geometry')
    _account(p,arena,-count,libc_base)
    dirty=dirty or (not force_clean and bool(tag&8))
    flags=0xFF8 if dirty else 0xFF0
    for index in (page,page+count-1):
        preserved=0 if dirty else _u(p,tag_address(index))&4
        _w(p,tag_address(index),preserved|flags|size)
    tree=region._free_extent_tree(p,arena,libc_base);end=page+count
    if end<_u(p,libc_base+0xE9EC8):
        neighbor=_u(p,tag_address(end))
        if not neighbor&1 and bool(neighbor&8)==dirty:
            extra=neighbor>>12;node=chunk+_u(p,libc_base+0xE9EA0)+(end-bias)*96
            tree.remove(node)
            if dirty:a._unlink_dirty_extent(p,arena,node,extra)
            count+=extra;size=count<<12
            for index in (page,page+count-1):_w(p,tag_address(index),(_u(p,tag_address(index))&4095)|size)
    if page>bias:
        neighbor=_u(p,tag_address(page-1))
        if not neighbor&1 and bool(neighbor&8)==dirty:
            extra=neighbor>>12;page-=extra
            node=chunk+_u(p,libc_base+0xE9EA0)+(page-bias)*96
            tree.remove(node)
            if dirty:a._unlink_dirty_extent(p,arena,node,extra)
            count+=extra;size=count<<12
            for index in (page,page+count-1):_w(p,tag_address(index),(_u(p,tag_address(index))&4095)|size)
    if size==_u(p,libc_base+0xE9EA8):
        raise a.RefillUnsupported('matching whole OS region release is unrecovered')
    node=chunk+_u(p,libc_base+0xE9EA0)+(page-bias)*96
    tree.insert(node)
    if dirty:
        pointer=node+16;sentinel=arena+0x150;previous=_u(p,sentinel+8)
        _w(p,pointer,pointer);_w(p,pointer+8,pointer)
        _w(p,previous,pointer);_w(p,pointer,sentinel)
        _w(p,sentinel+8,pointer);_w(p,pointer+8,previous)
        _w(p,arena+0xE0,_u(p,arena+0xE0)+count)
        _purge(p,arena,libc_base=libc_base,os_call=os_call)


def _purge(p,arena,*,libc_base,os_call):
    """+0x77cf0/+0x7f0b0 with a real ordered explicit madvise service."""
    if _u(p,arena+0x500)!=libc_base+0x7F0B0:
        raise a.RefillUnsupported('custom matching purge callback is unrecovered')
    _w(p,arena+0x38,_u(p,arena+0x38)+1)
    used=_u(p,arena+0xD8);dirty=_u(p,arena+0xE0);shift=_u(p,arena+0xD0)&63
    target=(dirty-max(used>>shift,_u(p,_indirect(p,libc_base,0xD8E10))))&MASK
    sentinel=arena+0x150;pointer=_u(p,sentinel)
    tree=region._free_extent_tree(p,arena,libc_base);selected=[];total=0
    while pointer!=sentinel:
        if len(selected)>=128:raise a.RefillUnsupported('matching dirty queue exceeds bound')
        if pointer==_u(p,arena+0x198)+0x28:
            raise a.RefillUnsupported('large cached-extent purge is unrecovered')
        following=_u(p,pointer);chunk,page=_location(p,pointer,libc_base)
        if chunk==_u(p,arena+0xC8):
            raise a.RefillUnsupported('purge requires a replacement spare region')
        bias=_u(p,libc_base+0xE9EB0);start=chunk+0x68+(page-bias)*8
        size=_u(p,start)&~4095;count=size>>12
        if not count:raise a.RefillUnsupported('invalid dirty extent size')
        tree.remove(pointer-16);a._unlink_dirty_extent(p,arena,pointer-16,count)
        _account(p,arena,count,libc_base)
        for index,value in ((count-1,0xFFB),(0,size|0xFFB)):
            address=start+index*8;_w(p,address,(_u(p,address)&4)|value)
        selected.append((pointer,start,count,chunk+page*4096));total+=count
        if total>=target:break
        pointer=following
    objects.unlock_uncontended_mutex(p,mutex_address=arena+8)
    for pointer,start,count,address in selected:
        result=os_call(p,'madvise',address,count*4096,4)
        if result!=0:raise a.RefillUnsupported('matching madvise failure outcome is unrecovered')
        for i in range(count):_w(p,start+i*8,_u(p,start+i*8)&~4)
    objects.lock_uncontended_mutex(p,mutex_address=arena+8)
    _w(p,arena+0x40,_u(p,arena+0x40)+len(selected))
    _w(p,arena+0x48,_u(p,arena+0x48)+total)
    for pointer,_,_,_ in selected:
        _w(p,pointer,pointer);_w(p,pointer+8,pointer)
        _release_extent(p,arena,pointer,False,True,libc_base=libc_base,os_call=os_call)


def release_empty_small_extent(p,arena,slab,dirty,force_clean,constants,*,libc_base,os_call):
    """Common bitmap owner calls this while holding the small-bin mutex."""
    class_id=_u(p,slab,4);lock=arena+0x508+class_id*0xE0
    objects.unlock_uncontended_mutex(p,mutex_address=lock)
    objects.lock_uncontended_mutex(p,mutex_address=arena+8)
    _release_extent(p,arena,slab,dirty,force_clean,libc_base=libc_base,os_call=os_call)
    objects.unlock_uncontended_mutex(p,mutex_address=arena+8)
    objects.lock_uncontended_mutex(p,mutex_address=lock)
