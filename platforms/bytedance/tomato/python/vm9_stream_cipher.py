"""Guest-memory RC4 state and configuration reference transformation.

Native +0x2592b8 tails to +0x258fd8; this is separate from the neighboring
AES encryption callback. All state, source and cleanup reads retain ordering.
"""
from __future__ import annotations
from typing import Callable
from vm9_allocator import RefillUnsupported, _PageTransaction, _read_span, _write_span
import vm9_objects as objects


def _u32(pages, address):
    return int.from_bytes(_read_span(pages, address, 4), "little")


def _pointer(pages, address):
    return int.from_bytes(_read_span(pages, address, 8), "little")


def _byte(pages, address):
    return _read_span(pages, address, 1)[0]


def _bound(value, bound, message):
    if not isinstance(value, int) or not 0 <= value <= bound:
        raise RefillUnsupported(message)


def construct_stream_state(pages, *, state_address: int, key_address: int,
                           key_size: int, drop: int = 0, max_drop: int = 0x100000) -> None:
    """Model +0x243cac's ordered 256-byte permutation and discard steps.

    key_size is W2. A zero divisor produces remainder=i, matching ARM UDIV,
    so that raw helper still reads 256 key bytes rather than rejecting zero.
    The upper reference helper rejects zero declared key/data lengths.
    """
    _bound(key_size, 0xFFFFFFFF, "stream key size must fit w2")
    objects._string_bound(max_drop)
    _bound(drop, max_drop, "stream drop exceeds the explicit bound")
    transaction = _PageTransaction(pages)
    table = state_address + 8
    for index in range(256):
        _write_span(transaction, table + index, bytes([index]))
    second = 0
    for index in range(256):
        current = _byte(transaction, table + index)
        offset = index % key_size if key_size else index
        second = (second + current + _byte(transaction, key_address + offset)) & 255
        other = _byte(transaction, table + second)
        _write_span(transaction, table + index, bytes([other]))
        _write_span(transaction, table + second, bytes([current]))
    first = second = 0
    for _ in range(drop):
        first = (first + 1) & 255
        current = _byte(transaction, table + first)
        second = (second + current) & 255
        other = _byte(transaction, table + second)
        _write_span(transaction, table + first, bytes([other]))
        _write_span(transaction, table + second, bytes([current]))
    _write_span(transaction, state_address, first.to_bytes(4, "little") + second.to_bytes(4, "little"))
    transaction.commit()


def process_stream_bytes(pages, *, state_address: int, source_address: int,
                         output_address: int, length: int, max_bytes: int = 0x100000) -> None:
    """Model +0x243d50's state updates and forward input/output aliases."""
    objects._string_bound(max_bytes)
    _bound(length, min(max_bytes, 0xFFFFFFFF), "stream length exceeds the explicit bound")
    transaction = _PageTransaction(pages)
    table = state_address + 8
    for offset in range(length):
        first = (_u32(transaction, state_address) + 1) & 255
        current = _byte(transaction, table + first)
        second = (_u32(transaction, state_address + 4) + current) & 255
        other = _byte(transaction, table + second)
        _write_span(transaction, state_address, first.to_bytes(4, "little") + second.to_bytes(4, "little"))
        _write_span(transaction, table + first, bytes([other]))
        _write_span(transaction, table + second, bytes([current]))
        at_first = _byte(transaction, table + first)
        value = _byte(transaction, source_address + offset)
        key_byte = _byte(transaction, table + ((at_first + current) & 255))
        _write_span(transaction, output_address + offset, bytes([value ^ key_byte]))
    transaction.commit()


def transform_stream_bytes(pages, *, key_address: int, key_size: int, drop: int,
                           source_address: int, output_address: int, length: int,
                           entry_stack_address: int, max_bytes: int = 0x100000) -> None:
    """Model +0x243dac; scratch state lives at original entry SP-0x150."""
    transaction = _PageTransaction(pages)
    state = entry_stack_address - 0x150
    construct_stream_state(transaction, state_address=state, key_address=key_address,
        key_size=key_size, drop=drop, max_drop=max_bytes)
    process_stream_bytes(transaction, state_address=state, source_address=source_address,
        output_address=output_address, length=length, max_bytes=max_bytes)
    transaction.commit()


def release_string_reference(pages, *, reference_address: int, image_base: int,
                             free: Callable) -> None:
    """Model +0x166e74's retained/string-deleting reference cleanup.

    Positive signed decremented counts retain both wrapper words; NULL count
    is a no-op. Otherwise free count first, then dispatch the guest deleting
    string destructor. Other destructor targets reject rather than guessing.
    """
    transaction = _PageTransaction(pages)
    counter = _pointer(transaction, reference_address + 8)
    if counter:
        count = (_u32(transaction, counter) - 1) & 0xFFFFFFFF
        _write_span(transaction, counter, count.to_bytes(4, "little"))
        if count == 0 or count & 0x80000000:
            free(transaction, counter)
            pointer = _pointer(transaction, reference_address)
            _write_span(transaction, reference_address + 8, bytes(8))
            if pointer:
                vtable = _pointer(transaction, pointer)
                target = _pointer(transaction, vtable + 8)
                if target != objects._image_address(image_base, 0x2484FC):
                    raise RefillUnsupported("unrecovered reference deleting-destructor target")
                objects.destroy_string_object(transaction, object_address=pointer,
                    image_base=image_base, free=free, delete_object=True)
                _write_span(transaction, reference_address, bytes(8))
    transaction.commit()


def transform_configuration_reference(pages, *, output_reference_address: int,
                                      data_object_address: int, key_object_address: int,
                                      entry_stack_address: int, image_base: int,
                                      allocate: Callable, free: Callable,
                                      max_bytes: int = 0x100000) -> int:
    """Model +0x258fd8/+0x2592b8's filled string, RC4 and reference lifecycle.

    X8 selects output reference. An empty key or data produces NULL/count=1.
    A nonempty result allocates string/payload/count in that order, transforms
    original source into the zero-filled payload, copies the temporary shared
    reference and releases it. Native X0 has no result contract here.
    """
    objects._string_bound(max_bytes)
    transaction = _PageTransaction(pages)
    key_length = _u32(transaction, key_object_address + 12)
    if not key_length or not _u32(transaction, data_object_address + 12):
        objects.construct_reference_wrapper(transaction, object_address=output_reference_address,
            referenced_address=0, allocate=allocate)
        transaction.commit()
        return output_reference_address
    length = _u32(transaction, data_object_address + 12)
    _bound(length, max_bytes, "stream string length exceeds the explicit bound")
    string = objects._allocate(transaction, allocate, 24)
    objects._sized_string_object(transaction, string, length, image_base, allocate,
                                lambda staged, size: bytes(size))
    temporary_reference = entry_stack_address - 0x78
    objects.construct_reference_wrapper(transaction, object_address=temporary_reference,
        referenced_address=string, allocate=allocate)
    # Reload pointers/lengths after allocations and reference construction.
    output_string = _pointer(transaction, temporary_reference)
    transform_stream_bytes(transaction, key_address=_pointer(transaction, key_object_address + 16),
        key_size=_u32(transaction, key_object_address + 12), drop=0,
        source_address=_pointer(transaction, data_object_address + 16),
        output_address=_pointer(transaction, output_string + 16),
        length=_u32(transaction, data_object_address + 12),
        entry_stack_address=entry_stack_address - 0xD0, max_bytes=max_bytes)
    objects.copy_reference_wrapper(transaction, object_address=output_reference_address,
                                   source_address=temporary_reference)
    release_string_reference(transaction, reference_address=temporary_reference,
                             image_base=image_base, free=free)
    transaction.commit()
    return output_reference_address
