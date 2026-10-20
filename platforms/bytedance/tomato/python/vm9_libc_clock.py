"""Matching bionic clock_gettime cache on the serialized syscall fallback."""
from vm9_allocator import RefillUnsupported, _PageTransaction, _read_span, _write_span


def prepare_bionic_clock_cache(pages, *, libc_base):
    """Recover +1d854's guard/cache effects before an explicit clock service.

    Cold guard acquisition/release writes only its low 32 bits. The fast path
    tests bit zero of the guard and uses the cached pointer without rereading
    the source table. Only the matching +6a864 syscall fallback is recovered;
    vDSO execution and contended guard waits remain explicit boundaries.
    Physical stack spills and provider effects are outside this page helper.
    """
    if (type(libc_base) is not int or libc_base <= 0 or libc_base & 4095
            or libc_base > (1 << 64) - 0xDE828):
        raise RefillUnsupported('clock cache requires an aligned matching libc base')
    p = _PageTransaction(pages)
    guard_address, cache_address = libc_base + 0xDE810, libc_base + 0xDE820
    guard = int.from_bytes(_read_span(p, guard_address, 8), 'little')
    cold = not guard & 1
    if cold and guard & 0xFFFFFFFF:
        raise RefillUnsupported('clock cache guard wait is unrecovered')
    source = libc_base + 0xD9048 if cold else cache_address
    target = int.from_bytes(_read_span(p, source, 8), 'little')
    if target != libc_base + 0x6A864:
        raise RefillUnsupported('clock cache target is outside the syscall fallback')
    if cold:
        _read_span(p, cache_address, 8)
        _write_span(p, guard_address, (0x100).to_bytes(4, 'little'))
        _write_span(p, cache_address, target.to_bytes(8, 'little'))
        _write_span(p, guard_address, (1).to_bytes(4, 'little'))
    p.commit()
    return target
