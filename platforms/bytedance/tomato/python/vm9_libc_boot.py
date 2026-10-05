"""Recovered base, DSS and chunk boot bodies in the matching libc.

These bounded pieces do not constitute preinit or complete Python malloc.
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
