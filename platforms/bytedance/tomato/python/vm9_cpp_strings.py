"""Owned 24-byte C++ strings used by request event/log wrappers.

These have an inline/heap tagged layout, distinct from the Medusa
vtable/capacity/length/pointer StringObject. Allocator and free are explicit.
"""
from __future__ import annotations
from vm9_allocator import RefillUnsupported, _PageTransaction, _read_span, _write_span
import vm9_objects as objects

MASK64 = (1 << 64) - 1


def _check_length(length, max_bytes):
    if not isinstance(length, int) or not 0 <= length < MASK64 - 15:
        raise RefillUnsupported('C++ string length/abort path is unsupported')
    if not isinstance(max_bytes, int) or not 0 <= max_bytes <= 0x100000:
        raise ValueError('invalid C++ string bound')
    if length > max_bytes:
        raise RefillUnsupported('C++ string exceeds explicit bound')


def construct_cpp_string(pages, *, object_address, source_address, length=None,
        allocate, max_bytes=0x100000):
    """+0x165b78/32aba0 construction; helper returns the object, not native X0."""
    p = _PageTransaction(pages)
    _read_span(p, object_address, 24)
    if length is None:
        if not source_address:
            raise RefillUnsupported('C++ C-string constructor requires non-NULL source')
        length = len(objects._cstring(p, source_address, max_bytes + 1)) - 1
    _check_length(length, max_bytes)
    if length < 23:
        _write_span(p, object_address, bytes([length * 2]))
        destination = object_address + 1
    else:
        capacity = (length + 16) & ~15
        destination = allocate(p, capacity)
        if not destination:
            raise RefillUnsupported('C++ string operator-new failure is unsupported')
        _read_span(p, destination, capacity)
        _write_span(p, object_address + 8, length.to_bytes(8, 'little') + destination.to_bytes(8, 'little'))
        _write_span(p, object_address, (capacity | 1).to_bytes(8, 'little'))
    if length:
        _write_span(p, destination, _read_span(p, source_address, length))
    _write_span(p, destination + length, b'\0')
    p.commit()
    return object_address


def clone_cpp_string(pages, *, object_address, source_object_address, allocate, max_bytes=0x100000):
    """+0x32a9c4 copies all 24 short bytes, or declared heap length+NUL."""
    p = _PageTransaction(pages)
    _read_span(p, object_address, 24)
    tag = _read_span(p, source_object_address, 1)[0]
    if not tag & 1:
        _write_span(p, object_address, _read_span(p, source_object_address, 24))
    else:
        fields = _read_span(p, source_object_address + 8, 16)
        length, source = (int.from_bytes(fields[i:i + 8], 'little') for i in (0, 8))
        _check_length(length, max_bytes)
        if length <= 22:
            _write_span(p, object_address, bytes([length * 2]))
            destination = object_address + 1
        else:
            capacity = (length + 16) & ~15
            destination = allocate(p, capacity)
            if not destination:
                raise RefillUnsupported('C++ string clone operator-new failure is unsupported')
            _read_span(p, destination, capacity)
            _write_span(p, object_address + 8, length.to_bytes(8, 'little') + destination.to_bytes(8, 'little'))
            _write_span(p, object_address, (capacity | 1).to_bytes(8, 'little'))
        _write_span(p, destination, _read_span(p, source, length + 1))
    p.commit()
    return object_address


def destroy_cpp_string(pages, *, object_address, free):
    """+0x32aa70 does not clear the object; it frees only tagged heap storage."""
    p = _PageTransaction(pages)
    if _read_span(p, object_address, 1)[0] & 1:
        pointer = int.from_bytes(_read_span(p, object_address + 16, 8), 'little')
        free(p, pointer)
    p.commit()


def move_assign_cpp_string(pages, *, object_address, source_object_address, free):
    """+0x17f5bc/180ce4: release destination, transfer 24 bytes, empty source.

    Only the source's first two bytes clear; its tail is retained. Object
    self-alias and overlap are outside this recovered distinct-owner path.
    """
    if not isinstance(object_address,int) or not isinstance(source_object_address,int):
        raise RefillUnsupported('C++ move requires integer object addresses')
    if max(object_address,source_object_address) < min(object_address,source_object_address)+24:
        raise RefillUnsupported('C++ move overlapping/self-alias objects are unsupported')
    p = _PageTransaction(pages)
    _read_span(p,object_address,24)
    _read_span(p,source_object_address,24)
    destroy_cpp_string(p,object_address=object_address,free=free)
    _write_span(p,object_address,_read_span(p,source_object_address,24))
    _write_span(p,source_object_address,bytes(2))
    p.commit()
    return object_address
