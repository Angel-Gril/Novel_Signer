"""Recovered base, DSS and chunk boot bodies in the matching libc.

Default empty-config preinit pieces and runtime dependencies are recovered.
All-branch preinit and complete Python malloc remain unsupported.
All globals use matching-libc offsets; old checkpoint addresses are unused.
"""
from __future__ import annotations
from vm9_allocator import _PageTransaction, _read_span, _write_span, RefillUnsupported
from vm9_libc_mapping import sbrk


def _u(pages, address, width=8):
    return int.from_bytes(_read_span(pages, address, width), "little")


def _w(pages, address, value, width=8):
    _write_span(pages, address, value.to_bytes(width, "little"))


def _mutex(pages, address):
    # +0x932ec executes attr_init, settype(0), mutex_init and attr_destroy.
    # Actual matching pthread_mutex_init zeroes exactly 40 bytes for this attr.
    _write_span(pages, address, bytes(40))


def initialize_allocator_mutex(pages, *, mutex_address):
    """+0x932ec for the actual normal attr, preserving bytes after +0x28."""
    p = _PageTransaction(pages)
    _mutex(p, mutex_address)
    p.commit()
    return 0


def initialize_base_tree(pages, *, tree_address):
    """+0x89460 writes exactly three pointers; all other bytes survive."""
    p = _PageTransaction(pages)
    sentinel = tree_address + 8
    _w(p, tree_address, sentinel)
    _w(p, tree_address + 0x50, sentinel)
    _w(p, tree_address + 0x58, sentinel & ~1)
    p.commit()


def initialize_rtree(pages, *, tree_address, bits, allocate_address, free_address):
    """+0x94ef4 for 1..64 bits, including level padding and cached indices."""
    if not isinstance(bits, int) or not 1 <= bits <= 64:
        raise RefillUnsupported("rtree bit count outside bounded matching ABI")
    if any(not isinstance(v, int) or not 0 <= v < 1 << 64
           for v in (tree_address, allocate_address, free_address)):
        raise RefillUnsupported("rtree pointer outside uint64 ABI")
    p = _PageTransaction(pages)
    head = bits % 16 or 16
    levels = (bits + 15) // 16
    _w(p, tree_address, allocate_address)
    _w(p, tree_address + 8, free_address)
    _w(p, tree_address + 0x10, levels, 4)
    for index in range(levels):
        entry = tree_address + 0x28 + index * 16
        last = index == levels - 1
        _w(p, entry, 0)
        _w(p, entry + 8, head if last else 16, 4)
        _w(p, entry + 12, bits if last else (index + 1) * 16, 4)
    _w(p, tree_address + 0x14, min(levels - 1, 3), 4)
    _w(p, tree_address + 0x18, min(levels - 1, 2), 4)
    _w(p, tree_address + 0x1C, int(levels > 1), 4)
    _w(p, tree_address + 0x20, 0, 4)
    p.commit()
    return 0


def base_boot(pages, *, libc_base):
    """+0x7dc7c: normal mutex, base extent tree, allocation counter."""
    p = _PageTransaction(pages)
    _mutex(p, libc_base + 0xE6860)
    initialize_base_tree(p, tree_address=libc_base + 0xE67E8)
    _w(p, libc_base + 0xE6858, 0)
    p.commit()
    return 0


def dss_boot(pages, *, libc_base, thread_pointer, brk):
    """+0x7f46c: normal mutex, actual sbrk(0), three DSS pointers."""
    p = _PageTransaction(pages)
    _mutex(p, libc_base + 0xE6898)
    program_break = sbrk(p, increment=0, libc_base=libc_base,
                        thread_pointer=thread_pointer, brk=brk)
    for offset in (0xE6888, 0xE68C0, 0xE6890):
        _w(p, libc_base + offset, program_break)
    p.commit()
    return 0


def chunk_boot(pages, *, libc_base, thread_pointer, brk):
    """+0x7f13c: chunk constants, DSS boot, callback-bound radix tree."""
    p = _PageTransaction(pages)
    bits = _u(p, libc_base + 0xDB668)
    if not 12 <= bits <= 63:
        raise RefillUnsupported("unrecovered chunk exponent outside bounded policy")
    size = 1 << bits
    _w(p, libc_base + 0xE9F38, size)
    _w(p, libc_base + 0xE9EC0, size - 1)
    _w(p, libc_base + 0xE9EC8, size >> 12)
    dss_boot(p, libc_base=libc_base, thread_pointer=thread_pointer, brk=brk)
    initialize_rtree(p, tree_address=libc_base + 0xE9ED0, bits=64 - bits,
                     allocate_address=libc_base + 0x7DE34, free_address=0)
    p.commit()
    return 0


def configuration_preinit(pages, *, libc_base):
    """+0x8ce70 null/empty malloc-conf branch; nonempty parser rejects.

    The actual null branch selects a one-byte empty local string. Neither
    this branch nor an explicit empty string changes allocator globals.
    """
    pointer = _u(pages, libc_base + 0xE6978)
    if pointer and _read_span(pages, pointer, 1) != b"\0":
        raise RefillUnsupported("nonempty matching-libc malloc configuration parser is unrecovered")


def extent_boot(pages, *, libc_base):
    """+0x89410 normal mutex +0xe68c8, then clear one byte +0xe6928."""
    p = _PageTransaction(pages)
    _mutex(p, libc_base + 0xE68C8)
    _w(p, libc_base + 0xE6928, 0, 1)
    p.commit()
    return 0


def preinit_prefix(pages, *, libc_base, thread_pointer, brk):
    """Actual +0x8e250 prefix, stopping before arena/bin boot +0x7cf2c.

    Default empty configuration and disabled atfork-registration flag are
    supported. A different configuration/registration branch rejects; there
    is no fabricated callback or claim that full preinit has returned.
    """
    p = _PageTransaction(pages)
    pthread = _u(p, thread_pointer + 8)
    _w(p, libc_base + 0xE69B8, pthread)
    configuration_preinit(p, libc_base=libc_base)
    registration_flag = _u(p, libc_base + 0xD8DE0)
    if _u(p, registration_flag, 1):
        raise RefillUnsupported("allocator atfork registration branch is unrecovered")
    base_boot(p, libc_base=libc_base)
    chunk_boot(p, libc_base=libc_base, thread_pointer=thread_pointer, brk=brk)
    extent_boot(p, libc_base=libc_base)
    p.commit()
    return 0x8E2C4


BIN_WIDTHS = (8, 16, 32, 48, 64, 80, 96, 112, 128, 160, 192, 224,
              256, 320, 384, 448, 512, 640, 768, 896, 1024, 1280,
              1536, 1792, 2048, 2560, 3072, 3584, 4096, 5120,
              6144, 7168, 8192, 10240, 12288, 14336)


def _indirect(pages, libc_base, offset):
    return _u(pages, libc_base + offset)


def _size_index(pages, libc_base, size):
    if not isinstance(size, int) or not 1 <= size <= 0x100000:
        raise RefillUnsupported("size class outside bounded matching-libc policy")
    if size <= 4096:
        return _u(pages, _indirect(pages, libc_base, 0xD8ED0) + ((size - 1) >> 3), 1)
    exponent = (2 * size - 1).bit_length() - 1
    shift = exponent - 3
    return exponent * 4 - 23 + (((size - 1) >> shift) & 3)


def initialize_bin_layout(pages, *, bin_address, libc_base, max_pages=256):
    """+0x75dc0: size-derived span, redzones, count and waste.

    Plain and actual redzone branches are supported. Page search is bounded;
    native arithmetic at extreme uint64 values is outside this policy.
    """
    if not isinstance(max_pages, int) or not 1 <= max_pages <= 256:
        raise RefillUnsupported("invalid bin layout page-search budget")
    p = _PageTransaction(pages)
    width = _u(p, bin_address)
    limit = _u(p, libc_base + 0xE9EA8)
    if not 1 <= width <= 0x3800 or not 0x1000 <= limit <= 0x100000:
        raise RefillUnsupported("unsupported bin width or region payload limit")
    redzone_flag = _indirect(p, libc_base, 0xD8DE8)
    overhead = skip = 0
    if _u(p, redzone_flag, 1):
        alignment = width & -width
        if alignment <= 16:
            overhead = 16
        else:
            overhead = skip = alignment >> 1
    stride = width + overhead * 2
    _w(p, bin_address + 8, overhead)
    _w(p, bin_address + 0x10, stride)
    span = 4096
    while span % width:
        span += 4096
        if span > max_pages * 4096:
            raise RefillUnsupported("bin layout page-search budget exhausted")
    while (span - skip) // stride == 0:
        span += 4096
        if span > max_pages * 4096:
            raise RefillUnsupported("bin layout page-search budget exhausted")
    while span > limit:
        span -= 4096
    count = (span - skip) // stride
    if count < 0 or count > 0xFFFFFFFF:
        raise RefillUnsupported("bin count outside bounded uint32 ABI")
    _w(p, bin_address + 0x18, span)
    _w(p, bin_address + 0x20, count, 4)
    waste = ((overhead if skip == 0 else 0) + span - count * stride) & 0xFFFFFFFF
    _w(p, bin_address + 0x58, waste, 4)
    if span > _u(p, libc_base + 0xE67C0):
        _w(p, libc_base + 0xE67C0, span)
    p.commit()


def initialize_bitmap_description(pages, *, descriptor_address, bits):
    """+0x7dce8: u32 bits, level count, cumulative bitmap word offsets."""
    if not isinstance(bits, int) or not 0 <= bits <= 0x1000000:
        raise RefillUnsupported("bitmap description outside bounded bit policy")
    p = _PageTransaction(pages)
    count = (bits + 63) >> 6
    offsets = [0]
    while count > 1:
        offsets.append(offsets[-1] + count)
        count = (count + 63) >> 6
    offsets.append(offsets[-1] + count)
    _w(p, descriptor_address, bits)
    _w(p, descriptor_address + 8, len(offsets) - 1, 4)
    for index, value in enumerate(offsets):
        _w(p, descriptor_address + 0x10 + index * 8, value)
    p.commit()


def _base_result(pages, allocate_base, size):
    pointer = allocate_base(pages, size)
    if not isinstance(pointer, int) or not 0 <= pointer < 1 << 64:
        raise RefillUnsupported("base allocator returned an invalid guest pointer")
    if pointer:
        _read_span(pages, pointer, size)
    return pointer


def arena_bin_boot(pages, *, libc_base, allocate_base):
    """+0x7cf2c: layout globals, 36 bins, bitmap descriptors and page marks.

    allocate_base(staged_pages, size) is an explicit +0x7d998 boundary.
    Null is ordinary native allocation failure (return 1), not rejection.
    No initialized native table or old checkpoint addresses are used.
    """
    p = _PageTransaction(pages)
    option = _u(p, libc_base + 0xDB658)
    if ((option + 1) & ((1 << 64) - 1)) <= 64:
        _w(p, libc_base + 0xE67C8, option)
    chunk_pages = _u(p, _indirect(p, libc_base, 0xD8E10))
    chunk_size = _u(p, _indirect(p, libc_base, 0xD8FC8))
    if chunk_size != chunk_pages * 4096 or not 0x10000 <= chunk_size <= 0x100000:
        raise RefillUnsupported("unrecovered arena chunk geometry")
    count = chunk_pages + 1
    estimate = (count * 104 + 4095) >> 12
    estimate = ((count - estimate) * 104 + 4095) >> 12
    bias = ((count - estimate) * 104 + 4095) >> 12
    payload = chunk_size - bias * 4096
    _w(p, libc_base + 0xE9EB0, bias)
    _w(p, libc_base + 0xE9EA8, payload)
    _w(p, libc_base + 0xE9EA0, (chunk_pages + 13 - bias) * 8)
    index = _size_index(p, libc_base, chunk_size)
    previous = _u(p, _indirect(p, libc_base, 0xD8EE0) + (index - 1) * 8)
    maximum = previous if payload >= previous else payload
    _w(p, libc_base + 0xE9118, maximum)
    index = _size_index(p, libc_base, maximum)
    if not 35 <= index <= 235:
        raise RefillUnsupported("unrecovered arena large/huge class counts")
    _w(p, libc_base + 0xE9110, 235 - index, 4)
    _w(p, libc_base + 0xE9EB8, index - 35, 4)
    first = libc_base + 0xE9120
    for i, width in enumerate(BIN_WIDTHS):
        row = first + i * 96
        _w(p, row, width)
        initialize_bin_layout(p, bin_address=row, libc_base=libc_base)
        initialize_bitmap_description(p, descriptor_address=row + 0x28, bits=_u(p, row + 0x20, 4))
    requested = _u(p, libc_base + 0xE67C0) >> 12
    if not 0 < requested <= 256:
        raise RefillUnsupported("unsupported arena page-mark array size")
    pointer = _base_result(p, allocate_base, requested)
    _w(p, libc_base + 0xE67B8, pointer)
    if pointer:
        for i in range(36):
            page_count = _u(p, first + i * 96 + 0x18) >> 12
            _w(p, pointer + page_count, 1, 1)
    p.commit()
    return 0 if pointer else 1


def tcache_boot(pages, *, libc_base, allocate_base):
    """+0x99378: cache size/index, capacities, summed capacity.

    Actual nonnegative log option uses W32 shift modulo 32. Negative or small
    results select 0x3800. Allocation/null behavior and unwritten padding match.
    """
    p = _PageTransaction(pages)
    option = _u(p, libc_base + 0xDB6A8)
    maximum = 1 << (option & 31)
    if option & (1 << 63) or maximum <= 0x37FF:
        maximum = 0x3800
    else:
        maximum = min(maximum, _u(p, _indirect(p, libc_base, 0xD8EF8)))
    count = _size_index(p, libc_base, maximum) + 1
    if not 36 <= count <= 256:
        raise RefillUnsupported("unsupported tcache capacity-table class count")
    _w(p, libc_base + 0xE9F60, maximum)
    _w(p, libc_base + 0xE9F48, count)
    pointer = _base_result(p, allocate_base, count * 4)
    _w(p, libc_base + 0xE9F50, pointer)
    if not pointer:
        p.commit()
        return 1
    _w(p, libc_base + 0xE6A9C, 0, 4)
    first = _indirect(p, libc_base, 0xD8F08)
    total = 0
    for i in range(count):
        capacity = 16
        if i < 36:
            objects = _u(p, first + i * 96 + 0x20, 4)
            capacity = 8 if ((objects << 1) & 0xFFFFFFFF) > 20 else 20
        _w(p, pointer + i * 4, capacity, 4)
        total = (total + capacity) & 0xFFFFFFFF
    _w(p, libc_base + 0xE6A9C, total, 4)
    p.commit()
    return 0



def tsd_boot(pages, *, libc_base, thread_pointer):
    """+0x99938 main/static TSD branch with actual matching bionic keys.

    Serialized key creation/setspecific/getspecific use +0xe0200, not old
    checkpoint generations. Empty key tables and exhausted tables are modeled.
    A missing TSD reaches unrecovered fallback allocation and explicitly
    rejects. No allocation callback is replaced with a fabricated RET.
    """
    from vm9_allocator import pthread_key_create, pthread_setspecific, pthread_getspecific
    p = _PageTransaction(pages)
    table = libc_base + 0xE0200
    key_address = libc_base + 0xE9F68
    static = libc_base + 0xDB6B8
    _w(p, libc_base + 0xE6AAC, 0, 4)
    status = pthread_key_create(p, key_address=key_address,
        destructor=libc_base + 0x99584, generation_table=table)
    if status:
        p.commit()
        return 1
    key = _u(p, key_address, 4)
    status = pthread_setspecific(p, key=key, value=static,
        thread_pointer=thread_pointer, generation_table=table)
    if status:
        raise RefillUnsupported("TSD setspecific diagnostic/abort branch is unrecovered")
    _w(p, libc_base + 0xE6AB0, 1, 1)
    current = pthread_getspecific(p, key=key, thread_pointer=thread_pointer, generation_table=table)
    if not current:
        raise RefillUnsupported("TSD empty fallback list/allocation branch is unrecovered")
    state = _u(p, current + 8, 4)
    if state in (0, 2):
        _w(p, current + 8, 1 if state == 0 else 3, 4)
        target = pthread_getspecific(p, key=key, thread_pointer=thread_pointer, generation_table=table)
        if not target:
            raise RefillUnsupported("TSD missing destination fallback allocation is unrecovered")
        # Native performs five 16-byte ldp/stp pairs, re-reading source each
        # time; preserve alias behavior and untouched wrapper padding.
        for offset in range(0, 80, 16):
            _write_span(p, target + 8 + offset, _read_span(p, current + 8 + offset, 16))
        _w(p, target, 1, 1)
    _w(p, current + 0x44, 1, 1)
    p.commit()
    return 0



def preinit_until_arena_construct(pages, *, libc_base, thread_pointer, brk, allocate_base):
    """+0x8e250 through bin/tcache boot, before initial arena +0x8e20c.

    The default branches publish counts and an empty arena-zero slot exactly
    as native does. A null base allocation returns failure instead of reaching
    the continuation. This is a prefix result, not completed preinit.
    """
    p = _PageTransaction(pages)
    preinit_prefix(p, libc_base=libc_base, thread_pointer=thread_pointer, brk=brk)
    if arena_bin_boot(p, libc_base=libc_base, allocate_base=allocate_base):
        p.commit()
        return 1
    if tcache_boot(p, libc_base=libc_base, allocate_base=allocate_base):
        p.commit()
        return 1
    _mutex(p, libc_base + 0xE6980)
    _w(p, libc_base + 0xE6970, 1, 4)
    _w(p, libc_base + 0xE6960, 1, 4)
    _w(p, libc_base + 0xE69D0, libc_base + 0xE6968)
    _w(p, libc_base + 0xE6968, 0)
    p.commit()
    return 0x8E31C



def construct_arena(pages, *, libc_base, arena_index, allocate_base):
    """+0x7cce8, actual current layout and callback pointer fields."""
    from vm9_objects import lock_uncontended_mutex, unlock_uncontended_mutex
    if not isinstance(arena_index, int) or not 0 <= arena_index <= 0xFFFFFFFF:
        raise RefillUnsupported("arena index outside uint32 ABI")
    p = _PageTransaction(pages)
    large = _u(p, libc_base + 0xE9EB8, 4)
    huge = _u(p, libc_base + 0xE9110, 4)
    length = 0x24C0 + ((huge + 15 + large * 32) & ~15) * 24
    if length > 0x80000:
        raise RefillUnsupported("arena configuration exceeds actual base allocation policy")
    arena = _base_result(p, allocate_base, length)
    if not arena:
        p.commit()
        return 0
    _w(p, arena, arena_index, 4)
    _w(p, arena + 4, 0, 4)
    _mutex(p, arena + 8)
    for off in range(0x30, 0xA0, 16):
        _write_span(p, arena + off, bytes(16))
    _w(p, arena + 0xA0, 0)
    large_stats = arena + 0x24C0
    huge_stats = large_stats + large * 32
    _w(p, arena + 0x98, large_stats)
    _write_span(p, large_stats, bytes(large * 32))
    _w(p, arena + 0xA0, huge_stats)
    _write_span(p, huge_stats, bytes(huge * 24))
    _w(p, arena + 0xA8, 0)
    lock_uncontended_mutex(p, mutex_address=libc_base + 0xE6898)
    decay = _u(p, libc_base + 0xDB690, 4)
    unlock_uncontended_mutex(p, mutex_address=libc_base + 0xE6898)
    _w(p, arena + 0xC8, 0)
    _w(p, arena + 0xC0, decay, 4)
    _w(p, arena + 0xD0, _u(p, libc_base + 0xE67C8))
    _w(p, arena + 0xD8, 0)
    _w(p, arena + 0xE0, 0)
    sentinel = arena + 0xF0
    _w(p, arena + 0xE8, sentinel)
    _w(p, arena + 0xF0, sentinel)
    _w(p, arena + 0xF8, sentinel & ~1)
    _w(p, arena + 0x150, arena + 0x150)
    _w(p, arena + 0x158, arena + 0x150)
    _w(p, arena + 0x198, arena + 0x160)
    _w(p, arena + 0x1A0, arena + 0x160)
    _w(p, arena + 0x1C8, 0)
    _mutex(p, arena + 0x1D0)
    for root, link in ((0x1F8, 0x48), (0x268, 0x58), (0x2D8, 0x48),
                       (0x348, 0x58), (0x3B8, 0x48), (0x428, 0x58)):
        nil = arena + root + 8
        _w(p, arena + root, nil)
        _w(p, nil + link, nil)
        _w(p, nil + link + 8, nil & ~1)
    _mutex(p, arena + 0x498)
    _w(p, arena + 0x4C0, 0)
    _mutex(p, arena + 0x4C8)
    for destination, source in ((0x4F0, 0xD8F30), (0x4F8, 0xD8F90), (0x500, 0xD8E98)):
        _w(p, arena + destination, _indirect(p, libc_base, source))
    for i in range(36):
        control = arena + 0x508 + i * 0xE0
        _mutex(p, control)
        _w(p, control + 0x28, 0)
        nil = control + 0x38
        _w(p, control + 0x30, nil)
        _w(p, control + 0x38, nil)
        _w(p, control + 0x40, nil & ~1)
        _write_span(p, control + 0x98, bytes(72))
    p.commit()
    return arena


def get_or_construct_arena(pages, *, libc_base, arena_index, allocate_base):
    """+0x8e20c/+0x8e0f8 bounded existing-table branch and publication.

    Growing the arena table uses public allocator functions and remains
    unsupported. The fresh slot for index zero is implemented and measured.
    """
    from vm9_objects import lock_uncontended_mutex, unlock_uncontended_mutex
    p = _PageTransaction(pages)
    mutex = libc_base + 0xE6980
    lock_uncontended_mutex(p, mutex_address=mutex)
    if not isinstance(arena_index, int) or not 0 <= arena_index <= 0xFFFFFFFF:
        raise RefillUnsupported("arena index outside uint32 ABI")
    pointer = 0
    if arena_index <= 0xFFE:
        count = _u(p, libc_base + 0xE6960, 4)
        if arena_index >= count:
            raise RefillUnsupported("arena table resize/index branch is unrecovered")
        table = _u(p, libc_base + 0xE69D0)
        slot = table + arena_index * 8
        pointer = _u(p, slot)
        if not pointer:
            pointer = construct_arena(p, libc_base=libc_base,
                arena_index=arena_index, allocate_base=allocate_base)
            _w(p, slot, pointer)
    unlock_uncontended_mutex(p, mutex_address=mutex)
    p.commit()
    return pointer



def _allocation_boundary(pages, provider, size):
    if not callable(provider):
        raise RefillUnsupported("explicit allocation provider is required")
    pointer = provider(pages, size)
    if not isinstance(pointer, int) or not 0 <= pointer < (1 << 64):
        raise RefillUnsupported("invalid allocation boundary pointer")
    if pointer:
        _read_span(pages, pointer, size)
    return pointer


def register_atfork(pages, *, libc_base, prepare, parent, child, dso, allocate_public, thread_pointer=None):
    """Actual +0x67374 registration with an explicit public malloc boundary.

    This constructs the real 48-byte node and appends it to the matching libc
    list. It does not emulate malloc or invoke any fork callback. A NULL
    allocation is the ordinary native ENOMEM return; mutex contention rejects.
    """
    from vm9_objects import lock_uncontended_mutex, unlock_uncontended_mutex
    p = _PageTransaction(pages)
    node = _allocation_boundary(p, allocate_public, 48)
    if not node:
        p.commit()
        return 12
    _w(p, node + 0x10, prepare)
    _w(p, node + 0x20, parent)
    _w(p, node + 0x18, child)
    _w(p, node + 0x28, dso)
    mutex = libc_base + 0xDB380
    head = libc_base + 0xE01C0
    if _u(p, mutex, 2) & 0xC000 == 0x4000:
        from vm9_libc_stdio import lock_recursive_mutex, unlock_recursive_mutex
        if thread_pointer is None:
            raise RefillUnsupported("fresh atfork recursive mutex requires explicit guest TLS")
        lock = lambda: lock_recursive_mutex(p, mutex_address=mutex, thread_pointer=thread_pointer)
        unlock = lambda: unlock_recursive_mutex(p, mutex_address=mutex, thread_pointer=thread_pointer)
    else:
        lock = lambda: lock_uncontended_mutex(p, mutex_address=mutex)
        unlock = lambda: unlock_uncontended_mutex(p, mutex_address=mutex)
    lock()
    _w(p, node, 0)
    tail = _u(p, head + 8)
    _w(p, node + 8, tail)
    if tail:
        _w(p, tail, node)
    if not _u(p, head):
        _w(p, head, node)
    _w(p, head + 8, node)
    unlock()
    p.commit()
    return 0


def migrate_static_tsd(pages, *, libc_base, thread_pointer, allocate_internal):
    """+0x99c78 static-to-dynamic TSD migration, without a malloc substitute.

    The explicit +0x8e0ec allocation must supply a mapped 128-byte wrapper.
    Only 88 bytes are copied from static storage, in actual ldp/stp order.
    Main-key publication and states 0/1/2/other follow the matching body;
    missing-key fallback lists and diagnostic/abort paths remain unsupported.
    This void body is a component result, not a complete cold-init result.
    """
    from vm9_allocator import pthread_setspecific, pthread_getspecific
    p = _PageTransaction(pages)
    destination = _allocation_boundary(p, allocate_internal, 128)
    if not destination:
        raise RefillUnsupported("TSD allocation diagnostic/abort branch is unrecovered")
    static = libc_base + 0xDB6B8
    for offset in range(0, 80, 16):
        _write_span(p, destination + offset, _read_span(p, static + offset, 16))
        if offset == 16:
            key = _u(p, libc_base + 0xE9F68, 4)
    _write_span(p, destination + 80, _read_span(p, static + 80, 8))
    table = libc_base + 0xE0200
    status = pthread_setspecific(p, key=key, value=destination,
        thread_pointer=thread_pointer, generation_table=table)
    if status:
        raise RefillUnsupported("TSD migration setspecific diagnostic/abort branch is unrecovered")
    current = pthread_getspecific(p, key=_u(p, libc_base + 0xE9F68, 4),
        thread_pointer=thread_pointer, generation_table=table)
    if not current:
        raise RefillUnsupported("TSD migration fallback list/allocation is unrecovered")
    state = _u(p, current + 8, 4)
    if state in (0, 2):
        key = _u(p, libc_base + 0xE9F68, 4)
        _w(p, current + 8, 1 if state == 0 else 3, 4)
        target = pthread_getspecific(p, key=key, thread_pointer=thread_pointer,
                                    generation_table=table)
        if not target:
            raise RefillUnsupported("TSD migration missing destination fallback is unrecovered")
        for offset in range(0, 80, 16):
            _write_span(p, target + 8 + offset, _read_span(p, current + 8 + offset, 16))
        _w(p, target, 1, 1)
    _w(p, current + 0x44, 0, 1)
    p.commit()



def pop_available_slab(pages, *, control_address):
    """Actual +0x75d44, selecting/removing the leftmost available-slab node.

    An empty tree returns NULL and performs no allocation. The cold caller
    continues at +0x78d7c; this helper never creates a slab or an OS region.
    Tree layout and removal reuse the algorithm with matching control offsets.
    """
    from vm9_allocator import _AllocatorTree
    p = _PageTransaction(pages)
    tree = _AllocatorTree(p, control_address + 0x30, lambda node: node)
    node = tree.first()
    if node:
        tree.remove(node)
        _w(p, control_address + 0xD0,
            (_u(p, control_address + 0xD0) + 1) & ((1 << 64) - 1))
    p.commit()
    return node + 0x10 if node else 0
