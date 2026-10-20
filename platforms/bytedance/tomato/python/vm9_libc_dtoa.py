"""Bounded matching bionic dtoa pool effects for small integral doubles."""
import math
import struct
from vm9_allocator import RefillUnsupported, _PageTransaction, _read_span, _write_span
from vm9_objects import lock_uncontended_mutex, unlock_uncontended_mutex


def format_bionic_integer(pages, *, number, precision, libc_base):
    """Model mode2/15-digit dtoa plus freedtoa for abs(integer)<1e9.

    Recover static Balloc(1)/d2b and Balloc(0)/result/free effects from inputs.
    Fractions, larger values, other precision, heap fallback and contended
    locks refuse. No native execution or physical stack effects are supplied.
    """
    if (type(number) is not float or not math.isfinite(number)
            or not number.is_integer() or abs(number) >= 1e9
            or type(precision) is not int or precision != 15):
        raise RefillUnsupported('bionic number service requires a small integral double and precision15')
    if (type(libc_base) is not int or libc_base <= 0 or libc_base & 4095
            or libc_base > (1 << 64) - 0xDFB30):
        raise RefillUnsupported('dtoa requires an aligned matching libc base')
    p = _PageTransaction(pages)
    def u(a, n=8):return int.from_bytes(_read_span(p, a, n), 'little')
    def w(a, value, n=8):_write_span(p, a, value.to_bytes(n, 'little'))
    pool, end, free = libc_base + 0xDF1E0, libc_base + 0xDFAE0, libc_base + 0xDFAE0
    mutex = u(libc_base + 0xD8FC0)
    if mutex != libc_base + 0xDF188:
        raise RefillUnsupported('dtoa lock binding is unrecovered')
    def check(pointer, k):
        size = (32 + 4 * ((1 << k) - 1) + 7) & ~7
        if pointer & 7 or not pool <= pointer <= end - size:
            raise RefillUnsupported('dtoa pool allocation requires the static buffer')
        _read_span(p, pointer, size)
        return size
    def allocate(k):
        lock_uncontended_mutex(p, mutex_address=mutex)
        head = u(free + k * 8)
        if head:
            check(head, k)
            if u(head + 8, 4) != k or u(head + 12, 4) != 1 << k:
                raise RefillUnsupported('dtoa free block class is inconsistent')
            following = u(head)
            if following:
                check(following, k)
                if following == head:
                    raise RefillUnsupported('dtoa free list is cyclic')
            w(free + k * 8, following)
        else:
            head = u(libc_base + 0xDA110)
            size = check(head, k)
            w(libc_base + 0xDA110, head + size)
            w(head + 8, k, 4)
            w(head + 12, 1 << k, 4)
        unlock_uncontended_mutex(p, mutex_address=mutex)
        _write_span(p, head + 16, bytes(8))
        return head
    def release(pointer, k):
        lock_uncontended_mutex(p, mutex_address=mutex)
        head = u(free + k * 8)
        if head == pointer:
            raise RefillUnsupported('dtoa duplicate free is unrecovered')
        if head:check(head, k)
        w(pointer, head)
        w(free + k * 8, pointer)
        unlock_uncontended_mutex(p, mutex_address=mutex)
    bits = struct.unpack('<Q', struct.pack('<d', number))[0]
    integer = abs(int(number))
    big = 0
    if integer:
        big = allocate(1)
        odd = integer // (integer & -integer)
        w(big + 20, 1, 4)
        w(big + 24, odd, 4)
        # d2b's nonzero low significand branch stores both limbs. Its other
        # branch stores only the low limb, preserving the upper pool bytes.
        if bits & 0xFFFFFFFF:w(big + 28, 0, 4)
    result = allocate(0)
    w(result, 0, 4)
    digits = str(integer).rstrip('0') if integer else '0'
    _write_span(p, result + 4, digits.encode() + b'\0')
    if big:release(big, 1)
    # freedtoa restores the two header words overwritten by the digit buffer.
    w(result + 8, 0, 4)
    w(result + 12, 1, 4)
    release(result, 0)
    text = (b'-' if bits >> 63 else b'') + str(integer).encode()
    p.commit()
    return text
