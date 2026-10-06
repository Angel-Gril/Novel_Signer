"""Matching-libc cold arena regions and radix registration using real base maps.

This owner recovers the empty chunk-cache/default-callback path of +0x765b0.
It also recovers bounded clean-slab carving and direct/internal small allocation.
Its shared clean-extent split also feeds the separate large owner. Public malloc
and CPU composition live in their own modules. Unknown DSS, nonempty chunk caches
and failed registration cleanup reject atomically.
"""
from __future__ import annotations
import vm9_allocator as allocator
import vm9_objects as objects
from vm9_libc_boot import _u, _w, _indirect, _size_index, pop_available_slab
from vm9_libc_base import _allocate_staged, _preinit_complete_transaction
from vm9_libc_mapping import _aligned_mapping, MASK


def _rtree_node(tx, *, link, level, tree, libc_base, thread_pointer, os_call):
    pointer = _u(tx.pages, link)
    if pointer == 1:
        raise allocator.RefillUnsupported("concurrent/pending rtree node allocation is unrecovered")
    if pointer:
        return pointer
    if _u(tx.pages, tree) != libc_base + 0x7DE34:
        raise allocator.RefillUnsupported("unknown rtree allocation callback")
    bits = _u(tx.pages, tree + 0x30 + level * 16, 4)
    if not 1 <= bits <= 16:
        raise allocator.RefillUnsupported("unrecovered rtree node width")
    # +0x94e78 owns the serialized 0 -> 1 -> pointer transition. A NULL
    # allocation returns failure with the link still 1, exactly as native.
    _w(tx.pages, link, 1)
    pointer = _allocate_staged(tx, tx.pages, request_size=(1 << bits) * 8,
        libc_base=libc_base, thread_pointer=thread_pointer, os_call=os_call)
    if pointer:
        _w(tx.pages, link, pointer)
    return pointer


def _store_chunk_reference(tx, *, key, value, libc_base, thread_pointer, os_call):
    if any(not isinstance(v, int) or not 0 <= v <= MASK for v in (key, value)):
        raise allocator.RefillUnsupported("rtree key/value outside uint64 ABI")
    tree = libc_base + 0xE9ED0
    levels = _u(tx.pages, tree + 0x10, 4)
    if not 1 <= levels <= 4:
        raise allocator.RefillUnsupported("unrecovered rtree depth")
    level = _u(tx.pages, tree + 0x14 + ((key.bit_length() - 1) >> 4) * 4, 4) if key else levels - 1
    if not 0 <= level < levels:
        raise allocator.RefillUnsupported("invalid rtree cached start level")
    link = tree + 0x28 + level * 16
    for index in range(level, levels):
        # +0x9503c passes the parent level to +0x94e78 for a child.
        # Its allocation can therefore exceed the child's indexed span.
        allocation_level = index if index == level else index - 1
        node = _rtree_node(tx, link=link, level=allocation_level, tree=tree,
            libc_base=libc_base, thread_pointer=thread_pointer, os_call=os_call)
        if not node:
            return 1
        width = _u(tx.pages, tree + 0x30 + index * 16, 4)
        cumulative = _u(tx.pages, tree + 0x34 + index * 16, 4)
        if not 1 <= width <= 16 or not width <= cumulative <= 64:
            raise allocator.RefillUnsupported("invalid rtree level geometry")
        slot = (key >> (64 - cumulative)) & ((1 << width) - 1)
        link = node + slot * 8
        if index == levels - 1:
            _w(tx.pages, link, value)
            return 0
    raise allocator.RefillUnsupported("missing rtree terminal level")


def store_chunk_reference(guest_os, *, key, value, libc_base, thread_pointer, os_call):
    """Actual +0x7e14c with +0x94e78/+0x7de34 and real base allocation."""
    tx = guest_os.begin()
    status = _store_chunk_reference(tx, key=key, value=value, libc_base=libc_base,
        thread_pointer=thread_pointer, os_call=os_call)
    tx.commit()
    return status


def _normalize_extent(pages, size, libc_base):
    limit = _u(pages, libc_base + 0xE67C0)
    if size <= limit:
        table = _u(pages, libc_base + 0xE67B8)
        if _u(pages, table + (size >> 12), 1): return size
    if size < 4096 or size & 4095 or size >= (1 << 62):
        raise allocator.RefillUnsupported("unrecovered extent normalization size")
    exponent = ((size + 1) * 2 - 1).bit_length() - 1
    index = ((exponent - 6) << 2) + ((size >> (exponent - 3)) & 3)
    width = _u(pages, _indirect(pages, libc_base, 0xD8EE0) + index * 8)
    if width <= 0x3800:
        raise allocator.RefillUnsupported("small extent normalization loop is unrecovered")
    return width


def _free_extent_tree(pages, arena, libc_base):
    mask = _u(pages, libc_base + 0xE9EC0)
    offset = _u(pages, libc_base + 0xE9EA0)
    def key(node):
        region = node & ~mask
        delta = node - region - offset
        if delta < 0 or delta % 96:
            raise allocator.RefillUnsupported("invalid matching extent node placement")
        size = _u(pages, region + 0x68 + delta // 96 * 8) & ~4095
        return _normalize_extent(pages, size, libc_base), node
    return allocator._AllocatorTree(pages, arena + 0xE8, key)


def _empty_chunk_cache(pages, arena, roots):
    mutex = arena + 0x498
    objects.lock_uncontended_mutex(pages, mutex_address=mutex)
    for offset, link_offset in roots:
        tree = allocator._AllocatorTree(pages, arena + offset,
            lambda node: node, link_offset=link_offset)
        if tree.first():
            raise allocator.RefillUnsupported("nonempty chunk cache allocation is unrecovered")
    objects.unlock_uncontended_mutex(pages, mutex_address=mutex)


def _fresh_arena_region(tx, *, arena_address, libc_base, thread_pointer, os_call):
    p = tx.pages
    arena = arena_address
    if _u(p, arena + 0xC8):
        raise allocator.RefillUnsupported("spare arena chunk reuse is unrecovered")
    if _u(p, arena, 4) != 0 or arena != _u(p, libc_base + 0xE6968):
        raise allocator.RefillUnsupported("cold region currently requires initial arena zero")
    if _u(p, arena + 0x4F0) != _indirect(p, libc_base, 0xD8F30):
        raise allocator.RefillUnsupported("unknown arena chunk allocation callback")
    mode = _u(p, arena + 0xC0, 4)
    if mode not in (0, 2):
        raise allocator.RefillUnsupported("primary DSS allocation is unrecovered")
    # +0x7ed7c and the default +0x7edc4 callback try separate cache trees.
    _empty_chunk_cache(p, arena, ((0x1F8, 0x48), (0x268, 0x58)))
    objects.unlock_uncontended_mutex(p, mutex_address=arena + 8)
    _empty_chunk_cache(p, arena, ((0x2D8, 0x48), (0x348, 0x58)))
    length = _u(p, libc_base + 0xE9F38)
    region = _aligned_mapping(tx, length=length, alignment=length,
        thread_pointer=thread_pointer, os_call=os_call)
    if not region:
        if mode == 2:
            raise allocator.RefillUnsupported("secondary DSS fallback after mmap failure is unrecovered")
        objects.lock_uncontended_mutex(p, mutex_address=arena + 8)
        return 0
    # The successful aligned mmap is zeroed; default callback writes flag 1.
    _w(p, region, arena)
    _w(p, region + 8, region)
    _w(p, region + 0x10, length)
    _w(p, region + 0x18, 1, 1)
    _w(p, region + 0x19, 1, 1)
    if _store_chunk_reference(tx, key=region, value=region, libc_base=libc_base,
            thread_pointer=thread_pointer, os_call=os_call):
        raise allocator.RefillUnsupported("failed chunk registration cleanup is unrecovered")
    objects.lock_uncontended_mutex(p, mutex_address=arena + 8)
    bias = _u(p, libc_base + 0xE9EB0)
    payload = _u(p, libc_base + 0xE9EA8)
    pages = _u(p, libc_base + 0xE9EC8)
    if length != pages * 4096 or payload != length - bias * 4096 or not 0 < bias < pages:
        raise allocator.RefillUnsupported("invalid matching region geometry")
    _w(p, arena + 0x30, (_u(p, arena + 0x30) + length) & MASK)
    _w(p, arena + 0x50, (_u(p, arena + 0x50) + bias * 4096) & MASK)
    tag = payload | 0xFF0
    _w(p, region + 0x68, tag)
    _w(p, region + 0x68 + (pages - 1 - bias) * 8, tag)
    tree = _free_extent_tree(p, arena, libc_base)
    tree.insert(region + _u(p, libc_base + 0xE9EA0))
    return region


def allocate_fresh_arena_region(guest_os, *, arena_address, libc_base, thread_pointer, os_call):
    """Bounded +0x765b0, caller holds arena mutex; it remains held on return."""
    tx = guest_os.begin()
    result = _fresh_arena_region(tx, arena_address=arena_address, libc_base=libc_base,
        thread_pointer=thread_pointer, os_call=os_call)
    tx.commit()
    return result


def preinit_with_initial_regions(guest_os, *, region_count, libc_base, thread_pointer, brk, os_call):
    """Same-fresh default preinit then actual initial-region helper(s), flag 2.

    The explicit sequence matches a caller taking/releasing the arena mutex.
    No native snapshots or allocation pointers supply any phase. This is not
    a full public malloc call or cold-init flag 0.
    """
    if not isinstance(region_count, int) or not 1 <= region_count <= 2:
        raise allocator.RefillUnsupported("unsupported region sequence length")
    tx = guest_os.begin()
    if _preinit_complete_transaction(tx, libc_base=libc_base,
            thread_pointer=thread_pointer, brk=brk, os_call=os_call):
        raise allocator.RefillUnsupported("region sequence preinit failed")
    arena = _u(tx.pages, libc_base + 0xE6968)
    objects.lock_uncontended_mutex(tx.pages, mutex_address=arena + 8)
    result = [_fresh_arena_region(tx, arena_address=arena, libc_base=libc_base,
        thread_pointer=thread_pointer, os_call=os_call) for _ in range(region_count)]
    objects.unlock_uncontended_mutex(tx.pages, mutex_address=arena + 8)
    tx.commit()
    return result


def preinit_with_chunk_references(guest_os, *, references, libc_base, thread_pointer, brk, os_call):
    """Same-fresh default preinit then controlled key/value registration(s)."""
    if not 1 <= len(references) <= 2:
        raise allocator.RefillUnsupported("unsupported rtree reference sequence length")
    tx = guest_os.begin()
    if _preinit_complete_transaction(tx, libc_base=libc_base,
            thread_pointer=thread_pointer, brk=brk, os_call=os_call):
        raise allocator.RefillUnsupported("rtree sequence preinit failed")
    result = [_store_chunk_reference(tx, key=k, value=v, libc_base=libc_base,
        thread_pointer=thread_pointer, os_call=os_call) for k,v in references]
    tx.commit()
    return result



def _extent_location(pages, pointer, libc_base):
    node = pointer - 16
    mask = _u(pages, libc_base + 0xE9EC0)
    region = node & ~mask
    delta = node - region - _u(pages, libc_base + 0xE9EA0)
    if delta < 0 or delta % 96:
        raise allocator.RefillUnsupported("invalid slab extent record")
    bias = _u(pages, libc_base + 0xE9EB0)
    return node, region, bias + delta // 96


def _find_extent(pages, arena, size, libc_base):
    """+0x7779c, normalized-class lower bound with actual marked-page search."""
    if not isinstance(size, int) or size < 4096 or size & 4095 or size > 0x100000:
        raise allocator.RefillUnsupported("extent request outside matching page policy")
    normalized = _normalize_extent(pages, size, libc_base)
    if normalized < size:
        normalized = MASK
        if size > 0x3800:
            index = _size_index(pages, libc_base, size) + 1
            normalized = (_u(pages, _indirect(pages, libc_base, 0xD8EE0) + index * 8) + 4095) & ~4095
        limit = _u(pages, libc_base + 0xE67C0)
        if size < limit:
            table = _u(pages, libc_base + 0xE67B8)
            for page in range(size // 4096 + 1, limit // 4096 + 1):
                if _u(pages, table + page, 1):
                    normalized = min(normalized, page << 12)
                    break
            else:
                raise allocator.RefillUnsupported("unbounded marked-page extent search")
    threshold = _normalize_extent(pages, normalized & ~4095, libc_base)
    node = _free_extent_tree(pages, arena, libc_base).lower_bound((threshold, 0))
    return node + 16 if node else 0


def _split_clean_extent(pages, arena, pointer, size, libc_base):
    """Shared clean +0x76f3c/+0x76f10 free-tree split and page accounting."""
    node, region, page = _extent_location(pages, pointer, libc_base)
    if _u(pages, region) != arena:
        raise allocator.RefillUnsupported("clean extent arena mismatch")
    bias = _u(pages, libc_base + 0xE9EB0)
    entry = region + 0x68 + (page - bias) * 8
    tag = _u(pages, entry)
    span = tag & ~4095
    if tag & 8:
        raise allocator.RefillUnsupported("dirty slab extent cleanup is unrecovered")
    if size < 4096 or size & 4095 or size > span:
        raise allocator.RefillUnsupported("invalid clean slab consumption")
    tree = _free_extent_tree(pages, arena, libc_base)
    tree.remove(node)
    used = _u(pages, arena + 0xD8)
    count = size >> 12
    mask = _u(pages, libc_base + 0xE9EC0)
    delta = ((mask + ((used + count) << 12)) & ~mask) - ((mask + (used << 12)) & ~mask)
    if delta:
        counter = _indirect(pages, libc_base, 0xD8E38)
        _w(pages, counter, (_u(pages, counter) + delta) & MASK)
    _w(pages, arena + 0xD8, (used + count) & MASK)
    remaining = span - size
    if remaining:
        for target_page in (page + count, page + (span >> 12) - 1):
            address = region + 0x68 + (target_page - bias) * 8
            _w(pages, address, (_u(pages, address) & 4) | 0xFF0 | remaining)
        remainder = region + _u(pages, libc_base + 0xE9EA0) + (page + count - bias) * 96
        tree.insert(remainder)
    return entry, region, page, count


def _consume_slab_extent(pages, arena, pointer, size, class_id, libc_base):
    """Clean +0x772b0 slab markers after the shared extent split."""
    if not 0 <= class_id < 36:
        raise allocator.RefillUnsupported("slab extent arena/class mismatch")
    entry, _, _, count = _split_clean_extent(pages, arena, pointer, size, libc_base)
    for index in range(count):
        address = entry + index * 8
        _w(pages, address, (_u(pages, address) & 4) | 1 | (class_id << 4) | (index << 12))


def _acquire_small_slab(tx, arena, control, class_id, libc_base, thread_pointer, os_call):
    """Serialized cold +0x787dc path, before the actual bitmap pop."""
    p = tx.pages
    _w(p, control + 0x28, 0)
    slab = pop_available_slab(p, control_address=control)
    if not slab:
        objects.unlock_uncontended_mutex(p, mutex_address=control)
        objects.lock_uncontended_mutex(p, mutex_address=arena + 8)
        row = libc_base + 0xE9120 + class_id * 96
        size = _u(p, row + 0x18)
        slab = _find_extent(p, arena, size, libc_base)
        if not slab:
            region = _fresh_arena_region(tx, arena_address=arena, libc_base=libc_base,
                thread_pointer=thread_pointer, os_call=os_call)
            if region:
                slab = region + _u(p, libc_base + 0xE9EA0) + 16
        if slab:
            _consume_slab_extent(p, arena, slab, size, class_id, libc_base)
            _w(p, slab, class_id, 4)
            _w(p, slab + 4, _u(p, row + 0x20, 4), 4)
            allocator.initialize_slab_bitmap(p, bitmap_address=slab + 8,
                descriptor_address=row + 0x28)
        objects.unlock_uncontended_mutex(p, mutex_address=arena + 8)
        objects.lock_uncontended_mutex(p, mutex_address=control)
        if not slab:
            return 0
        for offset in (0xC8, 0xD8):
            _w(p, control + offset, (_u(p, control + offset) + 1) & MASK)
    if _u(p, control + 0x28):
        raise allocator.RefillUnsupported("concurrent small-slab publication is unrecovered")
    if _u(p, slab, 4) != class_id or not _u(p, slab + 4, 4):
        raise allocator.RefillUnsupported("invalid available/current small slab")
    _w(p, control + 0x28, slab)
    return slab


def _direct_small(tx, *, arena_address, request_size, zero, libc_base, thread_pointer, os_call):
    """+0x79fa4 hot bitmap path and recovered cold clean-slab acquisition."""
    if not isinstance(request_size, int) or not 1 <= request_size <= 0x3800:
        raise allocator.RefillUnsupported("direct small request outside bounded positive policy")
    p = tx.pages
    if _u(p, _indirect(p, libc_base, 0xD8ED8), 1):
        raise allocator.RefillUnsupported("small junk/redzone fill is unrecovered")
    constants = allocator.AllocatorConstants(metadata_table=libc_base + 0xE9120,
        bitmap_mask_address=libc_base + 0xE9EC0,
        region_offset_address=libc_base + 0xE9EA0, page_bias_address=libc_base + 0xE9EB0,
        class_table=_indirect(p, libc_base, 0xD8ED0),
        class_width_table=_indirect(p, libc_base, 0xD8EE0))
    class_id, width = allocator._round_small_size(p, request_size, constants)
    control = arena_address + 0x508 + class_id * 0xE0
    objects.lock_uncontended_mutex(p, mutex_address=control)
    slab = _u(p, control + 0x28)
    if not slab or not _u(p, slab + 4, 4):
        slab = _acquire_small_slab(tx, arena_address, control, class_id,
            libc_base, thread_pointer, os_call)
    if not slab:
        objects.unlock_uncontended_mutex(p, mutex_address=control)
        return 0, width
    if _u(p, slab, 4) != class_id:
        raise allocator.RefillUnsupported("hot small slab class mismatch")
    popped = allocator.pop_slab_slot(p, arena_address=arena_address,
        bin_address=control, class_id=class_id, slab_address=slab, constants=constants)
    pointer = popped.object_address
    allocator._read_span(p, pointer, width)
    for offset in (0x98, 0xA8, 0xB0):
        _w(p, control + offset, (_u(p, control + offset) + 1) & MASK)
    objects.unlock_uncontended_mutex(p, mutex_address=control)
    if zero or _u(p, _indirect(p, libc_base, 0xD8EF0), 1):
        allocator._write_span(p, pointer, bytes(width))
    return pointer, width


def allocate_arena_small(guest_os, *, arena_address, request_size, zero=False, libc_base, thread_pointer, os_call):
    tx = guest_os.begin()
    result, _ = _direct_small(tx, arena_address=arena_address, request_size=request_size,
        zero=bool(zero), libc_base=libc_base, thread_pointer=thread_pointer, os_call=os_call)
    tx.commit()
    return result


def preinit_with_small_allocations(guest_os, *, requests, zero=False, account=False, libc_base, thread_pointer, brk, os_call):
    """Same-fresh preinit plus +0x79fa4 or +0x8df44 small allocation sequence.

    account selects actual internal allocation accounting (+0x8df44 W2=1).
    No public malloc/tcache entry or final cold-init flag 0 is claimed.
    """
    if not 1 <= len(requests) <= 128:
        raise allocator.RefillUnsupported("small allocation sequence outside bounded policy")
    tx = guest_os.begin()
    if _preinit_complete_transaction(tx, libc_base=libc_base, thread_pointer=thread_pointer,
            brk=brk, os_call=os_call):
        raise allocator.RefillUnsupported("small sequence preinit failed")
    arena = _u(tx.pages, libc_base + 0xE6968)
    result = []
    for size in requests:
        pointer, width = _direct_small(tx, arena_address=arena, request_size=size,
            zero=bool(zero), libc_base=libc_base, thread_pointer=thread_pointer, os_call=os_call)
        if account and pointer:
            _w(tx.pages, arena + 0x58, (_u(tx.pages, arena + 0x58) + width) & MASK)
        result.append(pointer)
    tx.commit()
    return result



def allocate_internal_small(guest_os, *, request_size, zero=False, account=True, libc_base, thread_pointer, brk, os_call):
    """Bounded actual +0x8df44 small entry, including flag-3 default preinit.

    The internal entry uses initial arena zero directly. It does not initialize
    the full public malloc/TSD/tcache lifecycle. A normal preinit failure returns
    NULL and retains native partial writes; unsupported branches roll back.
    """
    if not isinstance(request_size, int) or not 1 <= request_size <= 0x3800:
        raise allocator.RefillUnsupported("internal entry only supports positive small sizes")
    tx = guest_os.begin()
    flag = _u(tx.pages, libc_base + 0xDB6A0, 4)
    if flag == 3:
        mutex = libc_base + 0xE6938
        objects.lock_uncontended_mutex(tx.pages, mutex_address=mutex)
        status = _preinit_complete_transaction(tx, libc_base=libc_base,
            thread_pointer=thread_pointer, brk=brk, os_call=os_call)
        objects.unlock_uncontended_mutex(tx.pages, mutex_address=mutex)
        if status:
            tx.commit()
            return 0
    elif flag not in (0, 1, 2):
        raise allocator.RefillUnsupported("unknown internal allocator initialization state")
    arena = _u(tx.pages, libc_base + 0xE6968)
    if not arena:
        raise allocator.RefillUnsupported("internal allocator has no initial arena")
    pointer, width = _direct_small(tx, arena_address=arena, request_size=request_size,
        zero=bool(zero), libc_base=libc_base, thread_pointer=thread_pointer, os_call=os_call)
    if account and pointer:
        _w(tx.pages, arena + 0x58, (_u(tx.pages, arena + 0x58) + width) & MASK)
    tx.commit()
    return pointer
