"""Fresh matching-libc mapping and program-break helpers.

These are bounded recovered function bodies, not Python malloc cold boot.
Kernel outcomes are supplied explicitly. Unknown munmap diagnostic/abort paths
reject and roll back guest state; external provider effects cannot roll back.
"""
from __future__ import annotations
from vm9_allocator import RefillUnsupported, _PageTransaction, _read_span, _write_span

MASK = (1 << 64) - 1


def _word(value):
    if not isinstance(value, int) or not 0 <= value <= MASK:
        raise RefillUnsupported("value outside matching-libc uint64 ABI")
    return value


def _kernel(value):
    if not isinstance(value, int) or not -4095 <= value <= MASK:
        raise RefillUnsupported("invalid explicit kernel outcome")
    return value


def _errno(pages, thread_pointer, value):
    _write_span(pages, _word(thread_pointer) + 0x10, value.to_bytes(4, "little"))


def _mapping(tx, length, thread_pointer, os_call):
    result = _kernel(os_call(tx, "mmap", 0, length, 3, 0x22, 0xFFFFFFFF, 0))
    if result < 0:
        _errno(tx.pages, thread_pointer, -result)
        return 0
    if result == 0:
        return 0
    tx.map_anonymous(length, address=result, prot=3, flags=0x22, fd=0xFFFFFFFF,
                     offset=0, anonymous_name=b"")
    named = _kernel(os_call(tx, "prctl", 0x53564D41, 0, result, length, b"libc_malloc"))
    if named < 0:
        _errno(tx.pages, thread_pointer, -named)
    else:
        tx.name_exact(result, length, b"libc_malloc")
    return result


def _length(length):
    if not isinstance(length, int) or not 0 < length <= 0x100000 or length & 0xFFF:
        raise RefillUnsupported("unsupported bounded libc mapping length")


def map_allocator(guest_os, *, length, thread_pointer, os_call):
    """+0x7f56c: mmap, then ignored-result anonymous naming.

    os_call(transaction, operation, *fields) returns a raw signed kernel
    outcome; successful mmap returns a policy-approved address. The model
    applies mapping/name mutations after that outcome. Zero mmap results are
    the native null-result control and create no mapping in this bounded owner.
    """
    _length(length)
    tx = guest_os.begin()
    result = _mapping(tx, length, thread_pointer, os_call)
    tx.commit()
    return result


def _aligned_mapping(tx, *, length, alignment, thread_pointer, os_call):
    """Shared +0x7f600 body; caller owns transaction and output flag."""
    _length(length)
    if (not isinstance(alignment, int) or not 0x1000 <= alignment <= 0x100000
            or alignment & (alignment - 1)):
        raise RefillUnsupported("unsupported bounded libc mapping alignment")
    def unmap(address, size):
        outcome = _kernel(os_call(tx, "munmap", address, size))
        if outcome < 0:
            raise RefillUnsupported("libc munmap diagnostic/abort path is unrecovered")
        tx.unmap_range(address, size)

    first = _mapping(tx, length, thread_pointer, os_call)
    result = first
    if first and first & (alignment - 1):
        expanded = (length + alignment - 0x1000) & MASK
        unmap(first, length)
        if length > expanded:
            result = 0
        else:
            _length(expanded)
            raw = _mapping(tx, expanded, thread_pointer, os_call)
            if raw:
                result = ((raw + alignment - 1) & MASK) & ((-alignment) & MASK)
                if not result:
                    raise RefillUnsupported("libc zero-alignment retry is outside address policy")
                prefix = result - raw
                suffix = expanded - prefix - length
                if prefix:
                    unmap(raw, prefix)
                if suffix:
                    unmap(result + length, suffix)
            else:
                result = 0
    return result


def map_aligned_allocator(guest_os, *, length, alignment, flag_address,
                          thread_pointer, os_call):
    """+0x7f600: map, retry expanded span, trim prefix/suffix, set one byte.

    Alignment is a bounded page-size power of two. A failing munmap reaches
    unrecovered logging/abort callbacks and therefore explicitly rejects.
    """
    tx = guest_os.begin()
    _read_span(tx.pages, _word(flag_address), 1)
    result = _aligned_mapping(tx, length=length, alignment=alignment,
                             thread_pointer=thread_pointer, os_call=os_call)
    if result:
        _write_span(tx.pages, flag_address, b"\1")
    tx.commit()
    return result


def sbrk(pages, *, increment, libc_base, thread_pointer, brk):
    """+0x1e6c8 with cache +0xde840 and observed unsigned result test.

    brk(staged_pages, target) supplies the actual uint64 program-break result.
    Its service owns any heap growth/shrink policy; this helper changes only
    the cache and guest errno, never host process memory.
    """
    increment = _word(increment)
    p = _PageTransaction(pages)
    cache = _word(libc_base) + 0xDE840
    old = int.from_bytes(_read_span(p, cache, 8), "little")
    if not old:
        old = _word(brk(p, 0))
        _write_span(p, cache, old.to_bytes(8, "little"))
    result = old
    signed = increment if increment < 1 << 63 else increment - (1 << 64)
    if signed:
        error = signed > 0 and increment > MASK - old or signed < 0 and old < -signed
        if not error:
            target = (old + increment) & MASK
            actual = _word(brk(p, target))
            _write_span(p, cache, actual.to_bytes(8, "little"))
            error = target > actual
        if error:
            _errno(p, thread_pointer, 12)
            result = MASK
    p.commit()
    return result
