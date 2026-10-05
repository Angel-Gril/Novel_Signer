"""Matching libc thread-cache creation and single-arena binding.

Restores bounded +0x98490/+0x98c54/+0x8dda0 paths with actual region
allocation. No native pages or caller-provided allocation results initialize
cache storage. Bounded public small allocation and empty cache refill compose
these owners; full cold init, large allocation, GC and signing remain open.
"""
from __future__ import annotations

import vm9_allocator as allocator
import vm9_objects as objects
import vm9_libc_region as region
from vm9_libc_boot import _u, _w, _indirect

MASK = (1 << 64) - 1


def _bind_arena(pages, *, tsd_address, libc_base):
    """Actual +0x8dda0 single-arena path; tsd points after wrapper +8."""
    if _u(pages, libc_base + 0xE6970, 4) != 1:
        raise allocator.RefillUnsupported("multi-arena selection/construction is unrecovered")
    result = _u(pages, libc_base + 0xE6968)
    if not result:
        raise allocator.RefillUnsupported("arena zero has not been constructed")
    mutex = libc_base + 0xE6980
    objects.lock_uncontended_mutex(pages, mutex_address=mutex)
    table = _u(pages, libc_base + 0xE69D0)
    arena = _u(pages, table)
    if not arena:
        raise allocator.RefillUnsupported("empty first arena table slot")
    _w(pages, arena + 4, (_u(pages, arena + 4, 4) + 1) & 0xFFFFFFFF, 4)
    if _u(pages, tsd_address, 4) == 1:
        _w(pages, tsd_address + 0x28, arena)
    objects.unlock_uncontended_mutex(pages, mutex_address=mutex)
    return result


def bind_thread_arena(guest_os, *, tsd_address, libc_base):
    tx = guest_os.begin()
    result = _bind_arena(tx.pages, tsd_address=tsd_address, libc_base=libc_base)
    tx.commit()
    return result


def _associate_cache(pages, pointer, arena):
    """+0x98428 circular-list publication under the actual arena mutex."""
    objects.lock_uncontended_mutex(pages, mutex_address=arena + 8)
    _w(pages, pointer, pointer)
    _w(pages, pointer + 8, pointer)
    head = _u(pages, arena + 0xA8)
    if head:
        tail = _u(pages, head + 8)
        if not tail or _u(pages, tail) != head:
            raise allocator.RefillUnsupported("invalid arena cache list")
        _w(pages, pointer + 8, tail)
        _w(pages, pointer, head)
        _w(pages, tail, pointer)
        _w(pages, head + 8, pointer)
        pointer = _u(pages, pointer)
    _w(pages, arena + 0xA8, pointer)
    objects.unlock_uncontended_mutex(pages, mutex_address=arena + 8)


def _create_tcache(tx, *, tsd_address, arena_address, libc_base, thread_pointer, os_call):
    """+0x98490 default small, 64-byte-aligned, zeroed storage path."""
    p = tx.pages
    count = _u(p, libc_base + 0xE9F48)
    slots = _u(p, libc_base + 0xE6A9C, 4)
    if not 36 <= count <= 45 or slots > 0x10000:
        raise allocator.RefillUnsupported("unsupported matching tcache geometry")
    offset = (count * 32 + 0x27) & 0xFFFFFFF8
    table = _u(p, libc_base + 0xE9F50)
    capacities = [_u(p, table + i * 4, 4) for i in range(count)]
    if sum(capacities) != slots or any(not c for c in capacities):
        raise allocator.RefillUnsupported("invalid tcache capacity geometry")
    length = offset + slots * 8
    aligned = (length + 63) & ~63
    if not 1 <= aligned <= 0x3800:
        raise allocator.RefillUnsupported("large/huge cache backing allocation is unrecovered")
    index = region._size_index(p, libc_base, aligned)
    width = _u(p, _indirect(p, libc_base, 0xD8EE0) + index * 8)
    if not aligned <= width <= 0x3800 or width & 63:
        raise allocator.RefillUnsupported("cache storage class lacks the required alignment")
    allocation_arena = _u(p, libc_base + 0xE6968)
    if not allocation_arena:
        raise allocator.RefillUnsupported("cache backing allocation requires initial arena")
    pointer, actual_width = region._direct_small(tx, arena_address=allocation_arena,
        request_size=width, zero=True, libc_base=libc_base,
        thread_pointer=thread_pointer, os_call=os_call)
    if not pointer:
        return 0
    if pointer & 63 or actual_width != width:
        raise allocator.RefillUnsupported("cache backing storage alignment mismatch")
    _w(p, allocation_arena + 0x58, (_u(p, allocation_arena + 0x58) + width) & MASK)
    _associate_cache(p, pointer, arena_address)
    for i, capacity in enumerate(capacities):
        _w(p, pointer + i * 32 + 0x2C, 1, 4)
        _w(p, pointer + i * 32 + 0x38, pointer + offset)
        offset += capacity * 8
    return pointer


def create_thread_cache(guest_os, *, tsd_address, arena_address, libc_base, thread_pointer, os_call):
    tx = guest_os.begin()
    result = _create_tcache(tx, tsd_address=tsd_address, arena_address=arena_address,
        libc_base=libc_base, thread_pointer=thread_pointer, os_call=os_call)
    tx.commit()
    return result


def _current_tsd(pages, libc_base, thread_pointer):
    key = _u(pages, _indirect(pages, libc_base, 0xD8F98), 4)
    wrapper = allocator.pthread_getspecific(pages, key=key,
        thread_pointer=thread_pointer, generation_table=libc_base + 0xE0200)
    if not wrapper:
        raise allocator.RefillUnsupported("missing TSD fallback allocation is unrecovered")
    state = _u(pages, wrapper + 8, 4)
    if state in (0, 2):
        _w(pages, wrapper + 8, 1 if state == 0 else 3, 4)
        target = allocator.pthread_getspecific(pages, key=key,
            thread_pointer=thread_pointer, generation_table=libc_base + 0xE0200)
        if not target:
            raise allocator.RefillUnsupported("missing TSD transition destination")
        for offset in range(0, 80, 16):
            allocator._write_span(pages, target + 8 + offset,
                allocator._read_span(pages, wrapper + 8 + offset, 16))
        if _indirect(pages, libc_base, 0xD8F38) != _indirect(pages, libc_base, 0xD8E30):
            _w(pages, target, 1, 1)
    return wrapper


def _get_thread_cache(tx, *, tsd_address, libc_base, thread_pointer, os_call):
    """+0x98c54 recovered nonmissing TSD, enable/disable and create paths."""
    p = tx.pages
    wrapper = _current_tsd(p, libc_base, thread_pointer)
    enabled = _u(p, wrapper + 0x48, 4)
    if enabled == 2:
        enabled = _u(p, libc_base + 0xDB6B0, 1)
        _w(p, wrapper + 0x48, enabled, 4)
    if not enabled:
        if _u(p, tsd_address, 4) == 1:
            target = _current_tsd(p, libc_base, thread_pointer)
            if _u(p, target + 0x10):
                raise allocator.RefillUnsupported("disabled nonempty cache destruction is unrecovered")
            _w(p, target + 0x48, 0, 4)
        return 0
    arena = _u(p, tsd_address + 0x28)
    if not arena:
        arena = _bind_arena(p, tsd_address=tsd_address, libc_base=libc_base)
        if not arena:
            return 0
    return _create_tcache(tx, tsd_address=tsd_address, arena_address=arena,
        libc_base=libc_base, thread_pointer=thread_pointer, os_call=os_call)


def get_thread_cache(guest_os, *, tsd_address, libc_base, thread_pointer, os_call):
    """Actual getter does not store its result at wrapper+0x10; caller does."""
    tx = guest_os.begin()
    result = _get_thread_cache(tx, tsd_address=tsd_address, libc_base=libc_base,
        thread_pointer=thread_pointer, os_call=os_call)
    tx.commit()
    return result


def _small_constants(pages, libc_base):
    return allocator.AllocatorConstants(metadata_table=libc_base + 0xE9120,
        bitmap_mask_address=libc_base + 0xE9EC0,
        region_offset_address=libc_base + 0xE9EA0, page_bias_address=libc_base + 0xE9EB0,
        class_table=_indirect(pages, libc_base, 0xD8ED0),
        class_width_table=_indirect(pages, libc_base, 0xD8EE0))


def _refill_and_pop(tx, *, arena_address, cache_address, class_id, libc_base, thread_pointer, os_call):
    """+0x97ecc -> +0x7970c, clean small batches including partial failure."""
    p = tx.pages
    if not isinstance(class_id, int) or not 0 <= class_id < 36:
        raise allocator.RefillUnsupported("only small tcache refill classes are recovered")
    target = cache_address + 0x20 + class_id * 32
    if _u(p, target + 0x10, 4):
        raise allocator.RefillUnsupported("refill requires an empty bin")
    if _u(p, _indirect(p, libc_base, 0xD8ED8), 1):
        raise allocator.RefillUnsupported("refill junk/redzones are unrecovered")
    constants = _small_constants(p, libc_base)
    capacity = _u(p, _u(p, _indirect(p, libc_base, 0xD8E20)) + class_id * 4, 4)
    batch = capacity >> (_u(p, target + 0xC, 4) & 31)
    if batch > 128:
        raise allocator.RefillUnsupported("refill batch exceeds bounded policy")
    vector = _u(p, target + 0x18)
    allocator._read_span(p, vector, batch * 8)
    control = arena_address + 0x508 + class_id * 0xE0
    objects.lock_uncontended_mutex(p, mutex_address=control)
    completed = 0
    for i in range(batch):
        slab = _u(p, control + 0x28)
        if not slab or not _u(p, slab + 4, 4):
            slab = region._acquire_small_slab(tx, arena_address, control, class_id,
                libc_base, thread_pointer, os_call)
        if not slab:
            break
        if _u(p, slab, 4) != class_id:
            raise allocator.RefillUnsupported("refill slab class mismatch")
        result = allocator.pop_slab_slot(p, arena_address=arena_address,
            bin_address=target, class_id=class_id, slab_address=slab, constants=constants)
        _w(p, vector + (batch - i - 1) * 8, result.object_address)
        completed += 1
    if 0 < completed < batch:
        allocator._write_span(p, vector,
            allocator._read_span(p, vector + (batch - completed) * 8, completed * 8))
    state = arena_address + class_id * 0xE0
    for offset in (0x5A0, 0x5B8):
        _w(p, state + offset, (_u(p, state + offset) + completed) & MASK)
    _w(p, state + 0x5B0, (_u(p, state + 0x5B0) + _u(p, target)) & MASK)
    _w(p, state + 0x5C0, (_u(p, state + 0x5C0) + 1) & MASK)
    _w(p, target, 0)
    objects.unlock_uncontended_mutex(p, mutex_address=control)
    _w(p, target + 0x10, completed, 4)
    if not completed:
        _w(p, target + 8, 0xFFFFFFFF, 4)
        return 0
    count = completed - 1
    _w(p, target + 0x10, count, 4)
    floor = allocator._signed32(_u(p, target + 8, 4))
    if count < floor:
        _w(p, target + 8, count, 4)
    return _u(p, vector + count * 8)


def refill_small_cache_bin(guest_os, *, arena_address, cache_address, class_id, libc_base, thread_pointer, os_call):
    tx = guest_os.begin()
    result = _refill_and_pop(tx, arena_address=arena_address, cache_address=cache_address,
        class_id=class_id, libc_base=libc_base, thread_pointer=thread_pointer, os_call=os_call)
    tx.commit()
    return result


def _public_small(tx, *, request_size, libc_base, thread_pointer, os_call):
    """+0x8f00c positive/zero small entry on ready or same-owner recursive init."""
    if not isinstance(request_size, int) or not 0 <= request_size <= 0x3800:
        raise allocator.RefillUnsupported("public entry only recovers nonnegative small sizes")
    p = tx.pages
    flag = _u(p, libc_base + 0xDB6A0, 4)
    if flag == 1:
        # Actual +0x8e350 same-owner recursive success; other owner waits reject.
        mutex = libc_base + 0xE6938
        objects.lock_uncontended_mutex(p, mutex_address=mutex)
        if _u(p, thread_pointer + 8) != _u(p, libc_base + 0xE69B8):
            raise allocator.RefillUnsupported("other-thread cold initialization wait is unrecovered")
        objects.unlock_uncontended_mutex(p, mutex_address=mutex)
    elif flag != 0:
        raise allocator.RefillUnsupported("public allocator cold initialization is unfinished")
    if _u(p, libc_base + 0xE69C0):
        raise allocator.RefillUnsupported("public profiling hooks are unrecovered")
    wrapper = _current_tsd(p, libc_base, thread_pointer)
    tsd = wrapper + 8
    size = max(request_size, 1)
    class_id = region._size_index(p, libc_base, size)
    width = _u(p, _indirect(p, libc_base, 0xD8EE0) + class_id * 8)
    cache = _u(p, wrapper + 0x10)
    if not cache and _u(p, tsd, 4) == 1:
        cache = _get_thread_cache(tx, tsd_address=tsd, libc_base=libc_base,
            thread_pointer=thread_pointer, os_call=os_call)
        _w(p, wrapper + 0x10, cache)
    arena = _u(p, wrapper + 0x30)
    if not arena:
        arena = _bind_arena(p, tsd_address=tsd, libc_base=libc_base)
    pointer = 0
    if arena and cache:
        target = cache + class_id * 32
        count = _u(p, target + 0x30, 4)
        if not count:
            _w(p, target + 0x28, 0xFFFFFFFF, 4)
            pointer = _refill_and_pop(tx, arena_address=arena, cache_address=cache,
                class_id=class_id, libc_base=libc_base, thread_pointer=thread_pointer,
                os_call=os_call)
        else:
            capacity = _u(p, _u(p, libc_base + 0xE9F50) + class_id * 4, 4)
            if count > capacity:
                raise allocator.RefillUnsupported("public cache count exceeds capacity")
            count -= 1
            _w(p, target + 0x30, count, 4)
            if count < allocator._signed32(_u(p, target + 0x28, 4)):
                _w(p, target + 0x28, count, 4)
            pointer = _u(p, _u(p, target + 0x38) + count * 8)
        if pointer:
            if _u(p, libc_base + 0xE69A8, 1):
                raise allocator.RefillUnsupported("cached allocation junk/redzones are unrecovered")
            allocator._read_span(p, pointer, width)
            if _u(p, libc_base + 0xE69C9, 1):
                allocator._write_span(p, pointer, bytes(width))
            _w(p, target + 0x20, (_u(p, target + 0x20) + 1) & MASK)
            event = (_u(p, cache + 0x18, 4) + 1) & 0xFFFFFFFF
            _w(p, cache + 0x18, event, 4)
            if event == 228:
                raise allocator.RefillUnsupported("tcache GC event is unrecovered")
    elif arena:
        pointer, actual_width = region._direct_small(tx, arena_address=arena,
            request_size=size, zero=False, libc_base=libc_base,
            thread_pointer=thread_pointer, os_call=os_call)
        if actual_width != width:
            raise allocator.RefillUnsupported("public size-class mismatch")
    if not pointer:
        _w(p, thread_pointer + 0x10, 12, 4)
        return 0
    _w(p, wrapper + 0x18, (_u(p, wrapper + 0x18) + width) & MASK)
    return pointer


def allocate_public_small(guest_os, *, request_size, libc_base, thread_pointer, os_call):
    """Recovered public small path; complete cold startup and GC remain open."""
    tx = guest_os.begin()
    result = _public_small(tx, request_size=request_size, libc_base=libc_base,
        thread_pointer=thread_pointer, os_call=os_call)
    tx.commit()
    return result


def release_cached_small(guest_os, *, pointer, libc_base, thread_pointer):
    """Actual free +0x1bac0 -> +0x91990, NULL or nonfull clean small cache.

    C free has a void ABI; no native X0 value is part of this contract. The
    bitmap remains allocated while the object is owned by the thread cache.
    Full-bin flush, direct arena release, profiling and GC explicitly reject.
    """
    if pointer == 0:
        return None
    if not isinstance(pointer, int) or not 0 < pointer <= MASK:
        raise allocator.RefillUnsupported("free pointer outside uint64 ABI")
    tx = guest_os.begin()
    p = tx.pages
    wrapper = _current_tsd(p, libc_base, thread_pointer)
    cache = _u(p, wrapper + 0x10)
    mask = _u(p, _indirect(p, libc_base, 0xD8DD8))
    chunk = pointer & ~mask
    page = (pointer - chunk) >> 12
    bias = _u(p, _indirect(p, libc_base, 0xD8F58))
    limit = _u(p, _indirect(p, libc_base, 0xD8E10))
    if chunk == pointer or not bias <= page < limit:
        raise allocator.RefillUnsupported("huge/non-arena free is unrecovered")
    tag = _u(p, chunk + 0x68 + (page - bias) * 8)
    class_id = (tag >> 4) & 255
    if tag & 3 != 1 or not 0 <= class_id < 36:
        raise allocator.RefillUnsupported("free requires an allocated small page tag")
    width = _u(p, libc_base + 0xA6C80 + class_id * 8)
    # Valid C free input must identify a live allocated slot, not an interior
    # address or a never-issued bitmap slot. Invalid frees are not emulated.
    first_page = page - (tag >> 12)
    row = libc_base + 0xE9120 + class_id * 96
    stride = _u(p, row + 0x10)
    delta = pointer - chunk - (first_page << 12) - _u(p, row + 0x58, 4)
    if first_page < bias or not stride or delta < 0 or delta % stride:
        raise allocator.RefillUnsupported("free pointer is not a slab slot boundary")
    slot = delta // stride
    slab = chunk + _u(p, libc_base + 0xE9EA0) + (first_page - bias) * 96 + 16
    if slot >= _u(p, row + 0x20, 4) or _u(p, slab, 4) != class_id:
        raise allocator.RefillUnsupported("free pointer is outside the matching slab")
    if _u(p, slab + 8 + (slot >> 6) * 8) & (1 << (slot & 63)):
        raise allocator.RefillUnsupported("free pointer names a never-issued slab slot")
    allocator._read_span(p, pointer, width)
    _w(p, wrapper + 0x20, (_u(p, wrapper + 0x20) + width) & MASK)
    if _u(p, libc_base + 0xE69C0):
        raise allocator.RefillUnsupported("free profiling callback is unrecovered")
    if not cache:
        raise allocator.RefillUnsupported("direct arena small release is unrecovered")
    if _u(p, libc_base + 0xE69CA, 1):
        raise allocator.RefillUnsupported("free junk fill is unrecovered")
    target = cache + class_id * 32
    capacity = _u(p, _u(p, _indirect(p, libc_base, 0xD8E20)) + class_id * 4, 4)
    count = _u(p, target + 0x30, 4)
    if count >= capacity:
        raise allocator.RefillUnsupported("full/corrupt free bin flush is unrecovered")
    vector = _u(p, target + 0x38)
    for i in range(count):
        if _u(p, vector + i * 8) == pointer:
            raise allocator.RefillUnsupported("object already belongs to the cache")
    _w(p, vector + count * 8, pointer)
    _w(p, target + 0x30, count + 1, 4)
    event = (_u(p, cache + 0x18, 4) + 1) & 0xFFFFFFFF
    _w(p, cache + 0x18, event, 4)
    if event == 228:
        raise allocator.RefillUnsupported("free tcache GC event is unrecovered")
    tx.commit()
    return None
