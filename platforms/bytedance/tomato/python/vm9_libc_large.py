"""Bounded matching-libc clean large extent allocation, not huge/free/GC."""
from __future__ import annotations
import vm9_allocator as allocator
import vm9_objects as objects
import vm9_libc_region as region
from vm9_libc_boot import _u, _w, _indirect

MASK = (1 << 64) - 1


def _direct_large(tx, *, arena_address, request_size, libc_base, thread_pointer, os_call):
    """Actual +0x7a3c8 -> +0x77984/+0x77a68 clean, nonzeroing path."""
    if not isinstance(request_size, int) or not 0x3800 < request_size <= 0x10000:
        raise allocator.RefillUnsupported("large request outside bounded cache-size policy")
    p = tx.pages
    if _u(p, _indirect(p, libc_base, 0xD8ED8), 1) or _u(p, _indirect(p, libc_base, 0xD8EF0), 1):
        raise allocator.RefillUnsupported("large junk/zero option branches are unrecovered")
    class_id = region._size_index(p, libc_base, request_size)
    width = _u(p, _indirect(p, libc_base, 0xD8EE0) + class_id * 8)
    if not 36 <= class_id < 45 or not request_size <= width <= 0x10000 or width & 4095:
        raise allocator.RefillUnsupported("invalid bounded large size class")
    objects.lock_uncontended_mutex(p, mutex_address=arena_address + 8)
    extent = region._find_extent(p, arena_address, width, libc_base)
    if not extent:
        mapped = region._fresh_arena_region(tx, arena_address=arena_address, libc_base=libc_base,
            thread_pointer=thread_pointer, os_call=os_call)
        if mapped:
            extent = mapped + _u(p, libc_base + 0xE9EA0) + 16
    if not extent:
        objects.unlock_uncontended_mutex(p, mutex_address=arena_address + 8)
        return 0, width
    entry, mapped, page, count = region._split_clean_extent(p, arena_address, extent, width, libc_base)
    # Actual +0x77138 preserves interior marks and only publishes endpoints.
    last = entry + (count - 1) * 8
    _w(p, last, (_u(p, last) & 4) | 0xFF3)
    _w(p, entry, (_u(p, entry) & 4) | 0xFF3 | width)
    pointer = mapped + (page << 12)
    allocator._read_span(p, pointer, width)
    for offset in (0x68, 0x78):
        _w(p, arena_address + offset, (_u(p, arena_address + offset) + 1) & MASK)
    _w(p, arena_address + 0x60, (_u(p, arena_address + 0x60) + width) & MASK)
    table = _u(p, arena_address + 0x98) + (class_id - 36) * 32
    for offset in (0, 0x10, 0x18):
        _w(p, table + offset, (_u(p, table + offset) + 1) & MASK)
    objects.unlock_uncontended_mutex(p, mutex_address=arena_address + 8)
    return pointer, width
