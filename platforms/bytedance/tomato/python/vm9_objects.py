"""Input-driven host object constructors for the observed VM9 build.

The caller supplies guest allocation. No native constructor, copied output
object or captured string payload is used. Global vtables still belong to the
loaded guest image. Unsupported memory/allocator branches leave pages intact.
"""
from __future__ import annotations

from collections.abc import Callable
from vm9_allocator import (
    RefillUnsupported, _PageTransaction, _read_span, _write_span,
)


def _cstring(pages, address, limit):
    result = bytearray()
    while len(result) < limit:
        width = min(limit - len(result), 4096 - (address & 4095))
        data = _read_span(pages, address, width)
        end = data.find(b'\0')
        if end >= 0:
            result.extend(data[:end + 1])
            return bytes(result)
        result.extend(data)
        address += width
    raise RefillUnsupported("source string exceeds the explicit constructor bound")


def construct_string_object(
    pages, *, object_address: int, source_address: int,
    allocate: Callable, vtable_address: int = 0x1260F5F8,
    empty_descriptor_address: int = 0x1232E168, max_source_bytes: int = 0x100000,
) -> int:
    """Model 0x12508344, including NULL source and allocation failure.

    ``allocate(staged_pages, requested_size)`` returns a guest pointer or NULL.
    It must change only the supplied page map; external effects cannot be
    rolled back by the transaction. Pass the Python allocator in normal use.
    The result is the native X0 value (payload pointer), not object_address.
    """
    if not 1 <= max_source_bytes <= 0x100000:
        raise ValueError("invalid constructor source bound")
    transaction = _PageTransaction(pages)
    _read_span(transaction, object_address, 24)
    _write_span(transaction, object_address, vtable_address.to_bytes(8, 'little'))
    if source_address:
        payload = _cstring(transaction, source_address, max_source_bytes)
        length = len(payload) - 1
        requested = len(payload)
        _write_span(transaction, object_address + 8,
                    requested.to_bytes(4, 'little') + length.to_bytes(4, 'little'))
        pointer = allocate(transaction, requested)
        _write_span(transaction, object_address + 0x10, pointer.to_bytes(8, 'little'))
        if pointer:
            _write_span(transaction, pointer, payload)
    else:
        _write_span(transaction, object_address + 8,
                    _read_span(transaction, empty_descriptor_address, 8))
        pointer = allocate(transaction, 8)
        _write_span(transaction, object_address + 0x10, pointer.to_bytes(8, 'little'))
        if pointer:
            _write_span(transaction, pointer, bytes(1))
        else:
            _write_span(transaction, object_address + 8, bytes(4))
    transaction.commit()
    return pointer
