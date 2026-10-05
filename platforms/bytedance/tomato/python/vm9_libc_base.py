"""Matching-libc base extent allocation from actual Python-owned OS mappings.

The core tree algorithm is reused with verified current globals and links.
No initialized native pages, fake allocation pointers or legacy hard-coded
checkpoint addresses supply cold mapping/tree state. OS outcomes remain
explicit. This is base allocation, not the public malloc/slab allocator.
"""
from __future__ import annotations
import vm9_allocator as allocator
import vm9_objects as objects
from vm9_libc_mapping import _aligned_mapping, MASK
from vm9_libc_boot import _u, _w, _indirect, preinit_until_arena_construct


def _base_allocate(tx, *, request_size, libc_base, thread_pointer, os_call):
    if not isinstance(request_size, int) or not 1 <= request_size <= 0x80000:
        raise allocator.RefillUnsupported("base request outside bounded policy")
    length = (request_size + 63) & ~63
    p = tx.pages
    if length <= 4096:
        index = _u(p, _indirect(p, libc_base, 0xD8ED0) + ((length - 1) >> 3), 1)
        normalized = _u(p, _indirect(p, libc_base, 0xD8EE0) + index * 8)
    else:
        shift = (2 * length - 1).bit_length() - 4
        normalized = (length + (1 << shift) - 1) & -(1 << shift)
    mutex = libc_base + 0xE6860
    root = libc_base + 0xE67E8
    objects.lock_uncontended_mutex(p, mutex_address=mutex)
    tree = allocator._AllocatorTree(p, root,
        lambda node: (_u(p, node + 0x10), _u(p, node + 8)), link_offset=0x48)
    node = tree.lower_bound((normalized, 0))
    if node:
        tree.remove(node)
        pointer = _u(p, node + 8)
        size = _u(p, node + 0x10)
    else:
        node = _u(p, libc_base + 0xE6858)
        mask = _u(p, _indirect(p, libc_base, 0xD8DD8))
        alignment = _u(p, libc_base + 0xE9F38)
        if mask != alignment - 1:
            raise allocator.RefillUnsupported("inconsistent matching base chunk constants")
        recycled = bool(node)
        if recycled:
            _w(p, libc_base + 0xE6858, _u(p, node))
        span = ((length + (0 if recycled else 128) + mask) & MASK) & ~mask
        raw = _aligned_mapping(tx, length=span, alignment=alignment,
                               thread_pointer=thread_pointer, os_call=os_call)
        if not raw:
            if recycled:
                _w(p, node, _u(p, libc_base + 0xE6858))
                _w(p, libc_base + 0xE6858, node)
            objects.unlock_uncontended_mutex(p, mutex_address=mutex)
            return 0
        pointer = raw if recycled else raw + 128
        size = span if recycled else span - 128
        if not recycled:
            node = raw
            _w(p, libc_base + 0xE67D0, (_u(p, libc_base + 0xE67D0) + 128) & MASK)
            _w(p, libc_base + 0xE67D8, (_u(p, libc_base + 0xE67D8) + 4096) & MASK)
        _w(p, libc_base + 0xE67E0, (_u(p, libc_base + 0xE67E0) + span) & MASK)
        _w(p, node, 0)
        _w(p, node + 8, pointer)
        _w(p, node + 0x10, size)
        _w(p, node + 0x18, 1, 1)
        _w(p, node + 0x19, 0, 1)
    allocator._read_span(p, pointer, length)
    if length < size:
        _w(p, node + 8, pointer + length)
        _w(p, node + 0x10, size - length)
        tree.insert(node)
    else:
        _w(p, node, _u(p, libc_base + 0xE6858))
        _w(p, libc_base + 0xE6858, node)
    resident = ((pointer + length + 4095) & ~4095) - ((pointer + 4095) & ~4095)
    _w(p, libc_base + 0xE67D0, (_u(p, libc_base + 0xE67D0) + length) & MASK)
    _w(p, libc_base + 0xE67D8, (_u(p, libc_base + 0xE67D8) + resident) & MASK)
    objects.unlock_uncontended_mutex(p, mutex_address=mutex)
    return pointer


def base_allocate(guest_os, *, request_size, libc_base, thread_pointer, os_call):
    """Actual +0x7d998 including fresh mapping, reuse, tree and accounting."""
    tx = guest_os.begin()
    result = _base_allocate(tx, request_size=request_size, libc_base=libc_base,
                            thread_pointer=thread_pointer, os_call=os_call)
    tx.commit()
    return result


def _allocate_staged(tx, pages, *, request_size, libc_base, thread_pointer, os_call):
    """Bridge component page staging to the outer GuestOS transaction.

    Only an owned staging chain is accepted. New/removed mapping pages enter
    the outer disposable transaction, then bytes feed the staged component.
    The public owner is untouched until the entire composition commits.
    """
    chain = []
    original = pages
    while isinstance(original, allocator._PageTransaction):
        chain.append(original)
        original = original.original
    if original is not tx.pages:
        raise allocator.RefillUnsupported("base provider requires the owning OS staging chain")
    inner = tx.owner.begin()
    inner.pages = {k: bytearray(v) for k, v in pages.items()}
    inner.mappings = list(tx.mappings)
    inner.next_address = tx.next_address
    result = _base_allocate(inner, request_size=request_size, libc_base=libc_base,
                            thread_pointer=thread_pointer, os_call=os_call)
    for key in set(original) - set(inner.pages):
        del original[key]
        for staged in chain:
            staged.staged.pop(key, None)
    for key, data in inner.pages.items():
        if key not in original:
            original[key] = bytearray(data)
        pages[key][:] = data
    tx.mappings = list(inner.mappings)
    tx.next_address = inner.next_address
    return result


def preinit_with_base_allocator(guest_os, *, libc_base, thread_pointer, brk, os_call):
    """Same-fresh preinit through +0x8e31c, with actual base allocation.

    Guest pages, mappings and cursor commit together. Initial arena creation
    +0x8e20c, the remainder of malloc and thread TSD fallback remain separate.
    """
    tx = guest_os.begin()
    def allocate(pages, size):
        return _allocate_staged(tx, pages, request_size=size, libc_base=libc_base,
                                thread_pointer=thread_pointer, os_call=os_call)
    result = preinit_until_arena_construct(tx.pages, libc_base=libc_base,
        thread_pointer=thread_pointer, brk=brk, allocate_base=allocate)
    tx.commit()
    return result



def _preinit_complete_transaction(tx, *, libc_base, thread_pointer, brk, os_call):
    from vm9_libc_boot import get_or_construct_arena
    def allocate(pages, size):
        return _allocate_staged(tx, pages, request_size=size, libc_base=libc_base,
                                thread_pointer=thread_pointer, os_call=os_call)
    prefix = preinit_until_arena_construct(tx.pages, libc_base=libc_base,
        thread_pointer=thread_pointer, brk=brk, allocate_base=allocate)
    result = 1
    if prefix != 1:
        arena = get_or_construct_arena(tx.pages, libc_base=libc_base,
            arena_index=0, allocate_base=allocate)
        if arena:
            _w(tx.pages, libc_base + 0xDB6A0, 2, 4)
            result = 0
    return result


def preinit_complete_with_base_allocator(guest_os, *, libc_base, thread_pointer, brk, os_call):
    """Actual default +0x8e250 return, including initial arena publication.

    Success leaves initialization flag 2, the native PREINIT state. This is
    neither final cold init (flag 0) nor a public malloc/request signature.
    """
    tx = guest_os.begin()
    result = _preinit_complete_transaction(tx, libc_base=libc_base,
        thread_pointer=thread_pointer, brk=brk, os_call=os_call)
    tx.commit()
    return result


def cold_init_until_cpu_query(guest_os, *, libc_base, thread_pointer, brk, os_call):
    """Fresh default +0x8e350 through +0x8e41c, before CPU-count/sysconf.

    Actual preinit, main TSD and init-mutex transitions are composed in one
    transaction. The successful prefix leaves flag 1, the native recursive
    initialization state. Full cold return, reentrant malloc and flag 0 are
    not claimed. Nonfresh/concurrent owner branches reject.
    """
    from vm9_libc_boot import tsd_boot
    tx = guest_os.begin()
    p = tx.pages
    if _u(p, libc_base + 0xDB6A0, 4) != 3 or _u(p, libc_base + 0xE69B8):
        raise allocator.RefillUnsupported("cold prefix requires the fresh unowned state")
    mutex = libc_base + 0xE6938
    objects.lock_uncontended_mutex(p, mutex_address=mutex)
    status = _preinit_complete_transaction(tx, libc_base=libc_base,
        thread_pointer=thread_pointer, brk=brk, os_call=os_call)
    if not status:
        status = tsd_boot(p, libc_base=libc_base, thread_pointer=thread_pointer)
    if not status:
        _w(p, libc_base + 0xDB6A0, 1, 4)
    objects.unlock_uncontended_mutex(p, mutex_address=mutex)
    tx.commit()
    return 1 if status else 0x8E41C
