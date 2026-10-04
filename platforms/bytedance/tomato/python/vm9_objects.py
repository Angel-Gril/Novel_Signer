"""Input-driven host object constructors for the observed VM9 build.

The caller supplies guest allocation. No native constructor, copied output
object or captured string payload is used. Global vtables still belong to the
loaded guest image. Unsupported memory/allocator branches leave pages intact.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import struct
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


def decode_masked_bytes(
    pages, *, source_address: int, destination_address: int, mask_address: int,
    max_bytes: int = 4096,
) -> int:
    """Model +0x167e54; return the number of bytes written.

    Read mask and source one byte at a time, including when output aliases
    either input. A zero mask stops without writing a terminator. The explicit
    output bound and mapped-memory checks reject with page rollback.
    """
    if not isinstance(max_bytes, int) or not 0 <= max_bytes <= 0x100000:
        raise ValueError("invalid masked decoder output bound")
    transaction = _PageTransaction(pages)
    for index in range(max_bytes + 1):
        mask = _read_span(transaction, mask_address + index, 1)[0]
        if not mask:
            transaction.commit()
            return index
        if index == max_bytes:
            raise RefillUnsupported("masked decoder exceeds the explicit output bound")
        value = _read_span(transaction, source_address + index, 1)[0] ^ mask
        _write_span(transaction, destination_address + index, bytes([value]))
    raise AssertionError("unreachable masked decoder state")


def _normal_mutex_transition(pages, mutex_address, *, lock):
    if not isinstance(mutex_address, int) or mutex_address < 0 or mutex_address & 1:
        raise RefillUnsupported("normal mutex requires an aligned guest halfword")
    transaction = _PageTransaction(pages)
    state = int.from_bytes(_read_span(transaction, mutex_address, 2), "little")
    if state & ~0x2000 != (0 if lock else 1):
        raise RefillUnsupported("only uncontended normal mutex transitions are modeled")
    next_state = (state & 0x2000) | (1 if lock else 0)
    _write_span(transaction, mutex_address, next_state.to_bytes(2, "little"))
    transaction.commit()
    return 0


def lock_uncontended_mutex(pages, *, mutex_address: int) -> int:
    """Measured bionic normal mutex 0/0x2000 -> 1/0x2001 fast path.

    This models one serialized transition, not atomicity or host concurrency.
    Recursive, error-checking, destroyed and contended states are rejected.
    """
    return _normal_mutex_transition(pages, mutex_address, lock=True)


def unlock_uncontended_mutex(pages, *, mutex_address: int) -> int:
    """Measured bionic normal mutex 1/0x2001 -> 0/0x2000 fast path."""
    return _normal_mutex_transition(pages, mutex_address, lock=False)


def _shared_reader_transition(pages, mutex_address, *, acquire):
    transaction = _PageTransaction(pages)
    lock_uncontended_mutex(transaction, mutex_address=mutex_address)
    readers = int.from_bytes(_read_span(transaction, mutex_address + 0x88, 4), "little")
    if readers >= 0x7FFF_FFFF or not acquire and readers == 0:
        raise RefillUnsupported("shared reader transition requires waiting, signaling or underflow")
    readers += 1 if acquire else -1
    _write_span(transaction, mutex_address + 0x88, readers.to_bytes(4, "little"))
    unlock_uncontended_mutex(transaction, mutex_address=mutex_address)
    transaction.commit()
    return readers


def acquire_uncontended_shared_reader(pages, *, mutex_address: int) -> int:
    """Model +0x32a444 without writer/wait state; return the new reader count.

    The native helper locks a normal mutex, increments u32 at +0x88 and
    unlocks. This serial memory model does not supply host atomicity.
    """
    return _shared_reader_transition(pages, mutex_address, acquire=True)


def release_uncontended_shared_reader(pages, *, mutex_address: int) -> int:
    """Model +0x32a4fc without writer/signal state; reject zero or saturated count."""
    return _shared_reader_transition(pages, mutex_address, acquire=False)


def clone_string_object(
    pages, *, object_address: int, source_object_address: int,
    allocate: Callable, image_base: int, max_payload_bytes: int = 0x100000,
) -> int:
    """Model +0x2483e0, cloning the declared u32 length rather than a C string.

    Read length before modifying the destination and read the source pointer
    after allocation. Negative int32 length stores the wrapped capacity and
    NULL payload without allocating. Successful copies append one zero byte;
    malloc NULL leaves the declared lengths and NULL payload. Return X0.
    """
    if not isinstance(max_payload_bytes, int) or not 0 <= max_payload_bytes <= 0x100000:
        raise ValueError("invalid string clone payload bound")
    transaction = _PageTransaction(pages)
    length = int.from_bytes(_read_span(transaction, source_object_address + 12, 4), "little")
    if length < 0x8000_0000 and length > max_payload_bytes:
        raise RefillUnsupported("string clone exceeds the explicit payload bound")
    capacity = (length + 1) & 0xFFFF_FFFF
    _write_span(transaction, object_address,
                _word(_image_address(image_base, 0x34F5F8))
                + capacity.to_bytes(4, "little") + length.to_bytes(4, "little") + bytes(8))
    pointer = 0
    if length < 0x8000_0000:
        pointer = allocate(transaction, capacity)
        _word(pointer)
        _write_span(transaction, object_address + 0x10, _word(pointer))
        if pointer:
            source = int.from_bytes(_read_span(transaction, source_object_address + 0x10, 8), "little")
            if length:
                _write_span(transaction, pointer, _read_span(transaction, source, length))
            _write_span(transaction, pointer + length, bytes(1))
    transaction.commit()
    return capacity if length >= 0x8000_0000 else pointer


def _s32(value):
    value &= 0xFFFF_FFFF
    return value - 0x100000000 if value & 0x80000000 else value


def round_string_capacity(requested: int) -> int:
    """Model +0x2469fc W0, including signed overflow and strict power rounding."""
    if not isinstance(requested, int) or not 0 <= requested <= 0xFFFF_FFFF:
        raise RefillUnsupported("capacity request must fit w0")
    if _s32(requested) < 8:
        return 8
    spread = requested
    for shift in (1, 2, 4, 8, 16):
        spread |= spread >> shift
    candidate = (spread + 1) & 0xFFFF_FFFF
    return requested if _s32(candidate) < _s32(requested) else candidate


def _string_bound(limit):
    if not isinstance(limit, int) or not 0 <= limit <= 0x100000:
        raise ValueError("invalid string operation bound")


def _malloc(pages, allocate, size):
    pointer = allocate(pages, size)
    _word(pointer)
    if pointer:
        _read_span(pages, pointer, size)
    return pointer


def _reserve_string_fields(pages, fields, requested, allocate, reallocate, free, limit):
    if not fields:
        return -1
    pointer = int.from_bytes(_read_span(pages, fields + 8, 8), "little")
    if not pointer:
        return -1
    length = int.from_bytes(_read_span(pages, fields + 4, 4), "little")
    capacity = int.from_bytes(_read_span(pages, fields, 4), "little")
    if _s32(length) < 0 or _s32(capacity) < 1 or _s32(requested) < 1 or capacity < length:
        return -1
    if capacity > requested:
        return 0
    rounded = round_string_capacity(requested)
    if _s32(rounded) <= _s32(capacity):
        return 0
    if max(length, rounded) > limit:
        raise RefillUnsupported("string reserve exceeds the explicit operation bound")
    result = 0
    if _s32(capacity * 7) >= _s32(length * 8):
        result = _malloc(pages, allocate, rounded)
        if result:
            if length:
                _write_span(pages, result, _read_span(pages, pointer, length))
            free(pages, pointer)
    if not result:
        result = reallocate(pages, pointer, rounded)
        _word(result)
        if not result:
            pointer = int.from_bytes(_read_span(pages, fields + 8, 8), "little")
            result = reallocate(pages, pointer, requested)
            _word(result)
            rounded = requested
        if not result:
            return -1
        _read_span(pages, result, rounded)
    # Native reloads length after allocator/free effects and before publishing.
    current_length = _s32(int.from_bytes(_read_span(pages, fields + 4, 4), "little"))
    _write_span(pages, fields + 8, _word(result))
    _write_span(pages, fields, rounded.to_bytes(4, "little"))
    _write_span(pages, result + current_length, bytes(1))
    return 0


def reserve_string_fields(
    pages, *, fields_address: int, requested: int, allocate: Callable,
    reallocate: Callable, free: Callable, max_bytes: int = 0x100000,
) -> int:
    """Model +0x2468e8 on capacity/u32 length/pointer fields; return 0 or -1.

    malloc/realloc NULL and native validation failures are represented results.
    Unsupported pages/effects roll back. Host allocator ledgers are external.
    All three effects must operate only on the staged pages they receive.
    """
    _string_bound(max_bytes)
    if not isinstance(requested, int) or not 0 <= requested <= 0xFFFF_FFFF:
        raise RefillUnsupported("reserve request must fit w1")
    transaction = _PageTransaction(pages)
    status = _reserve_string_fields(transaction, fields_address, requested,
                                    allocate, reallocate, free, max_bytes)
    transaction.commit()
    return status


def _destroy_string_fields(pages, fields, free):
    if not fields:
        return -1
    capacity = _s32(int.from_bytes(_read_span(pages, fields, 4), "little"))
    length = _s32(int.from_bytes(_read_span(pages, fields + 4, 4), "little"))
    if length < 0 or capacity < 1 or capacity < length:
        return -1
    pointer = int.from_bytes(_read_span(pages, fields + 8, 8), "little")
    if not pointer:
        return -1
    free(pages, pointer)
    free(pages, fields)
    return 0


def destroy_string_fields(pages, *, fields_address: int, free: Callable) -> int:
    """Model +0x246d7c clone cleanup, freeing payload then field structure."""
    transaction = _PageTransaction(pages)
    status = _destroy_string_fields(transaction, fields_address, free)
    transaction.commit()
    return status


def _clone_string_fields(pages, fields, allocate, free, limit):
    length = int.from_bytes(_read_span(pages, fields + 4, 4), "little")
    if _s32(length) < 0:
        return 0
    pointer = int.from_bytes(_read_span(pages, fields + 8, 8), "little")
    if not pointer:
        return 0
    if length + 1 > limit:
        raise RefillUnsupported("alias clone exceeds the explicit operation bound")
    clone = _malloc(pages, allocate, 16)
    if not clone:
        return 0
    capacity = round_string_capacity((length + 1) & 0xFFFF_FFFF)
    if capacity > limit:
        raise RefillUnsupported("alias clone capacity exceeds the explicit operation bound")
    payload = _malloc(pages, allocate, capacity)
    _write_span(pages, clone + 8, _word(payload))
    if not payload:
        capacity = length + 1
        payload = _malloc(pages, allocate, capacity)
        _write_span(pages, clone + 8, _word(payload))
        if not payload:
            free(pages, clone)
            return 0
    _write_span(pages, clone, capacity.to_bytes(4, "little") + length.to_bytes(4, "little"))
    if length:
        _write_span(pages, payload, _read_span(pages, pointer, length))
    _write_span(pages, payload + length, bytes(1))
    return clone


def append_string_fields(
    pages, *, destination_fields: int, source_fields: int, allocate: Callable,
    reallocate: Callable, free: Callable, max_bytes: int = 0x100000,
) -> int:
    """Model +0x246ba0, including aliases, allocator failures and temp cleanup.

    Fields are capacity/u32 length/pointer (16 bytes). Return native signed
    status 0/-1. Append uses memmove semantics; source inside the destination
    buffer is cloned before a growth attempt. Reject unmodeled memory/effects
    with rollback, while preserving modeled native failure effects.
    """
    _string_bound(max_bytes)
    transaction = _PageTransaction(pages)
    if not destination_fields or not source_fields:
        return -1
    destination = int.from_bytes(_read_span(transaction, destination_fields + 8, 8), "little")
    if not destination:
        return -1
    source = int.from_bytes(_read_span(transaction, source_fields + 8, 8), "little")
    if not source:
        return -1
    capacity = int.from_bytes(_read_span(transaction, destination_fields, 4), "little")
    previous = int.from_bytes(_read_span(transaction, destination_fields + 4, 4), "little")
    length = int.from_bytes(_read_span(transaction, source_fields + 4, 4), "little")
    total = (previous + length) & 0xFFFF_FFFF
    if (previous | length | total | ((capacity - previous) & 0xFFFF_FFFF)) & 0x80000000:
        return -1
    if max(previous, length, total + 1) > max_bytes:
        raise RefillUnsupported("string append exceeds the explicit operation bound")
    requested = (total + 1) & 0xFFFF_FFFF
    selected, clone = source_fields, 0
    status = 0
    if _s32(capacity) <= _s32(requested):
        delta = (source - destination) & 0xFFFF_FFFF_FFFF_FFFF
        if delta < 0x8000000000000000 and delta < _s32(capacity):
            clone = _clone_string_fields(transaction, source_fields, allocate, free, max_bytes)
            if not clone:
                transaction.commit()
                return -1
            selected = clone
        status = _reserve_string_fields(transaction, destination_fields, requested,
                                        allocate, reallocate, free, max_bytes)
    if status == 0:
        if length:
            pointer = int.from_bytes(_read_span(transaction, destination_fields + 8, 8), "little")
            source = int.from_bytes(_read_span(transaction, selected + 8, 8), "little")
            _write_span(transaction, pointer + previous, _read_span(transaction, source, length))
        pointer = int.from_bytes(_read_span(transaction, destination_fields + 8, 8), "little")
        _write_span(transaction, pointer + total, bytes(1))
        _write_span(transaction, destination_fields + 4, total.to_bytes(4, "little"))
    if clone:
        _destroy_string_fields(transaction, clone, free)
    transaction.commit()
    return status


def append_string_object(
    pages, *, object_address: int, source_object_address: int, allocate: Callable,
    reallocate: Callable, free: Callable, max_bytes: int = 0x100000,
) -> int:
    """Model +0x248684: append fields at +8 and return destination even on -1."""
    append_string_fields(pages, destination_fields=object_address + 8,
        source_fields=source_object_address + 8, allocate=allocate,
        reallocate=reallocate, free=free, max_bytes=max_bytes)
    return object_address


def _append_string_byte(pages, fields, value, allocate, reallocate, free, limit):
    capacity = int.from_bytes(_read_span(pages, fields, 4), "little")
    length = int.from_bytes(_read_span(pages, fields + 4, 4), "little")
    if (length | ((capacity - length) & 0xFFFF_FFFF)) & 0x80000000:
        return -1
    if length + 2 > limit:
        raise RefillUnsupported("byte append exceeds the explicit string bound")
    status = _reserve_string_fields(pages, fields, (length + 2) & 0xFFFF_FFFF,
                                    allocate, reallocate, free, limit)
    if status:
        return -1
    pointer = int.from_bytes(_read_span(pages, fields + 8, 8), "little")
    _write_span(pages, pointer + length, bytes([value & 255]))
    pointer = int.from_bytes(_read_span(pages, fields + 8, 8), "little")
    _write_span(pages, pointer + length + 1, bytes(1))
    current_length = int.from_bytes(_read_span(pages, fields + 4, 4), "little")
    _write_span(pages, fields + 4, ((current_length + 1) & 0xFFFF_FFFF).to_bytes(4, "little"))
    return 0


def destroy_string_object(
    pages, *, object_address: int, image_base: int, free: Callable, delete_object: bool = False,
) -> None:
    """Model +0x2484b8/+0x2484fc, restoring empty fields after payload free."""
    transaction = _PageTransaction(pages)
    pointer = int.from_bytes(_read_span(transaction, object_address + 0x10, 8), "little")
    _write_span(transaction, object_address, _word(_image_address(image_base, 0x34F5F8)))
    if pointer:
        free(transaction, pointer)
        _write_span(transaction, object_address + 0x10, bytes(8))
    _write_span(transaction, object_address + 8,
                _read_span(transaction, _image_address(image_base, 0x6E208), 8))
    if delete_object:
        free(transaction, object_address)
    transaction.commit()


def _decode_configuration_base64(
    pages, *, destination_address: int, destination_size: int,
    source_address: int, source_size: int, image_base: int, max_source_bytes: int = 0x100000,
) -> int:
    """Return native signed status and optional output length on staged pages."""
    if not isinstance(max_source_bytes, int) or not 0 <= max_source_bytes <= 0x100000:
        raise ValueError("invalid base64 source bound")
    if not isinstance(source_size, int) or not 0 <= source_size <= max_source_bytes:
        raise RefillUnsupported("base64 input exceeds the explicit source bound")
    _word(destination_size)
    transaction = pages
    table = _image_address(image_base, 0x95CC0)
    index, digits, padding = 0, 0, 0
    while index < source_size:
        spaces = False
        while index < source_size and _read_span(transaction, source_address + index, 1)[0] == 32:
            index += 1
            spaces = True
        if index == source_size:
            break
        char = _read_span(transaction, source_address + index, 1)[0]
        if char == 13 and source_size - index >= 2 and _read_span(transaction, source_address + index + 1, 1)[0] == 10:
            index += 1
            continue
        if char == 10:
            index += 1
            continue
        if spaces:
            return -44, None
        if char == 61:
            padding += 1
            if padding > 2:
                return -44, None
        elif char & 128:
            return -44, None
        value = _read_span(transaction, table + char, 1)[0]
        if value == 127 or value <= 63 and padding:
            return -44, None
        digits += 1
        index += 1
    needed = ((digits * 6 + 7) // 8 - padding) & 0xFFFF_FFFF_FFFF_FFFF if digits else 0
    if digits and (not destination_address or needed > destination_size):
        return -42, needed
    written, group, accumulator, output_width = 0, 0, 0, 3
    for index in range(source_size if digits else 0):
        char = _read_span(transaction, source_address + index, 1)[0]
        if char in (10, 13, 32):
            continue
        value = _read_span(transaction, table + char, 1)[0]
        output_width -= int(char == 61)
        accumulator = ((accumulator << 6) | value) & 0xFFFF_FFFF
        group += 1
        if group == 4:
            for shift in (16, 8, 0)[:output_width]:
                _write_span(transaction, destination_address + written, bytes([(accumulator >> shift) & 255]))
                written += 1
            group = 0
    return 0, written


def decode_configuration_base64(
    pages, *, destination_address: int, destination_size: int, length_address: int,
    source_address: int, source_size: int, image_base: int, max_source_bytes: int = 0x100000,
) -> int:
    """Model +0x245814; status 0/-42/-44, native output-length writes and rollback.

    Invalid input does not write length. Buffer queries use the native ceil
    bound, while successful partial groups are discarded. Spaces are accepted
    only at line ends/end of input, and CR requires LF. The private ELF lookup
    table is read from the guest image; no standard decoder is substituted.
    """
    transaction = _PageTransaction(pages)
    status, length = _decode_configuration_base64(transaction,
        destination_address=destination_address, destination_size=destination_size,
        source_address=source_address, source_size=source_size, image_base=image_base,
        max_source_bytes=max_source_bytes)
    if length is not None:
        _write_span(transaction, length_address, _word(length))
        transaction.commit()
    return status


def construct_sized_string_object(
    pages, *, object_address: int, source_address: int, length: int, image_base: int,
    allocate: Callable, max_payload_bytes: int = 0x100000,
) -> int:
    """Model +0x2481fc from an explicit w2 length; malloc NULL clears both lengths."""
    if not isinstance(length, int) or not 0 <= length <= 0xFFFF_FFFF:
        raise RefillUnsupported("sized string length must fit w2")
    if not isinstance(max_payload_bytes, int) or not 0 <= max_payload_bytes <= 0x100000:
        raise ValueError("invalid sized string payload bound")
    if length < 0x8000_0000 and length > max_payload_bytes:
        raise RefillUnsupported("sized string exceeds the explicit payload bound")
    transaction = _PageTransaction(pages)
    pointer = _sized_string_object(transaction, object_address, length, image_base,
        allocate, lambda staged, size: _read_span(staged, source_address, size))
    transaction.commit()
    return pointer


def _sized_string_object(pages, object_address, length, image_base, allocate, read_source):
    _write_span(pages, object_address, _word(_image_address(image_base, 0x34F5F8)))
    _write_span(pages, object_address + 0x10, bytes(8))
    pointer = 0
    if length < 0x8000_0000:
        capacity = length + 1
        _write_span(pages, object_address + 8,
                    capacity.to_bytes(4, "little") + length.to_bytes(4, "little"))
        pointer = allocate(pages, capacity)
        _write_span(pages, object_address + 0x10, _word(pointer))
        if pointer:
            if length:
                _write_span(pages, pointer, read_source(pages, length))
            _write_span(pages, pointer + length, bytes(1))
    if not pointer:
        _write_span(pages, object_address + 8, bytes(8))
    return pointer


def construct_digest_reference(
    pages, *, object_address: int, source_object_address: int, algorithm: str,
    flag: int, image_base: int, allocate: Callable, reallocate: Callable, free: Callable,
    max_source_bytes: int = 0x100000,
) -> int:
    """Model +0x25874c (MD5) / +0x258780 (SHA-1) reference construction.

    Flag bit0 selects the guest ELF's hexadecimal alphabet; otherwise store
    raw bytes. Hex builds an empty string/count then reserves and appends
    characters in native order. Host allocation/free effects are explicit.
    Diagnostic scopes and native temporary stack references are excluded.
    Return the referenced string pointer, not the native X0 return value.
    """
    _string_bound(max_source_bytes)
    if algorithm not in ("md5", "sha1") or not isinstance(flag, int) or not 0 <= flag <= 0xFFFFFFFF:
        raise RefillUnsupported("unsupported digest algorithm or flag")
    transaction = _PageTransaction(pages)
    length = int.from_bytes(_read_span(transaction, source_object_address + 12, 4), "little")
    pointer = int.from_bytes(_read_span(transaction, source_object_address + 16, 8), "little")
    if length > max_source_bytes:
        raise RefillUnsupported("digest source exceeds the explicit bound")
    if not pointer and algorithm == "md5":
        data = b""  # Measured MD5 wrapper's explicit NULL-source branch.
    else:
        data = _read_span(transaction, pointer, length) if length else b""
    if algorithm == "sha1":
        # +0x2450ac lazily decodes the padding byte before finalization.
        padding = _image_address(image_base, 0x3DE27C)
        flag_address = _image_address(image_base, 0x3DE280)
        if not int.from_bytes(_read_span(transaction, flag_address, 4), "little"):
            decode_masked_bytes(transaction,
                source_address=_image_address(image_base, 0x95B78),
                destination_address=padding, mask_address=_image_address(image_base, 0x95B7C))
            _write_span(transaction, flag_address, (1).to_bytes(4, "little"))
        if _read_span(transaction, padding, 1) != b"\x80" or _read_span(transaction, _image_address(image_base, 0x95B7A), 1) != bytes(1):
            raise RefillUnsupported("nonstandard SHA-1 padding is not modeled")
    digest = hashlib.new(algorithm, data).digest()
    _write_span(transaction, object_address, bytes(16))
    string = _allocate(transaction, allocate, 24)
    if not flag & 1:
        _sized_string_object(transaction, string, len(digest), image_base,
            allocate, lambda staged, size: digest[:size])
        _reference_wrapper(transaction, object_address, string, allocate)
    else:
        construct_string_object(transaction, object_address=string, source_address=0,
            allocate=allocate, vtable_address=_image_address(image_base, 0x34F5F8),
            empty_descriptor_address=_image_address(image_base, 0x6E168))
        # Native constructs a temporary stack reference/count before reserve;
        # its pair is not published to the caller until conversion finishes.
        count = _allocate(transaction, allocate, 4)
        _write_span(transaction, count, (1).to_bytes(4, "little"))
        _reserve_string_fields(transaction, string + 8, len(digest) * 2 + 1,
                               allocate, reallocate, free, 0x100000)
        for value in digest:
            for nibble in (value >> 4, value & 15):
                alphabet = int.from_bytes(_read_span(transaction,
                    _image_address(image_base, 0x37A068), 8), "little")
                char = _read_span(transaction, alphabet + nibble, 1)[0]
                _append_string_byte(transaction, string + 8, char,
                                    allocate, reallocate, free, 0x100000)
        current_length = int.from_bytes(_read_span(transaction, string + 12, 4), "little")
        if _s32(current_length) > len(digest) * 2:
            pointer = int.from_bytes(_read_span(transaction, string + 16, 8), "little")
            _write_span(transaction, string + 12, (len(digest) * 2).to_bytes(4, "little"))
            _write_span(transaction, pointer + len(digest) * 2, bytes(1))
        if int.from_bytes(_read_span(transaction, count, 4), "little") != 1:
            raise RefillUnsupported("digest temporary reference count was changed by host effects")
        _write_span(transaction, object_address, _word(string) + _word(count))
        # Copy increments 1 -> 2, then temporary cleanup decrements 2 -> 1.
        # No host effects occur between these two measured count operations.
    transaction.commit()
    return string


def construct_decoded_configuration_reference(
    pages, *, object_address: int, source_object_address: int, image_base: int,
    allocate: Callable, free: Callable, max_source_bytes: int = 0x100000,
) -> int:
    """Model +0x258e7c: base64 decode, optional sized string, free, reference.

    Caller supplies both allocation and free effects on staged pages. This
    does not execute the later parser or its cryptographic callbacks.
    Return the new referenced string pointer (NULL for empty/invalid decode).
    """
    transaction = _PageTransaction(pages)
    length = int.from_bytes(_read_span(transaction, source_object_address + 12, 4), "little")
    if not isinstance(max_source_bytes, int) or not 0 <= max_source_bytes <= 0x100000:
        raise ValueError("invalid decoded reference source bound")
    if length > max_source_bytes:
        raise RefillUnsupported("decoded reference requires a bounded nonnegative length")
    buffer = allocate(transaction, length)
    _word(buffer)
    source = int.from_bytes(_read_span(transaction, source_object_address + 0x10, 8), "little")
    status, decoded_length = _decode_configuration_base64(transaction, destination_address=buffer,
        destination_size=length, source_address=source,
        source_size=length, image_base=image_base, max_source_bytes=max_source_bytes)
    string = 0
    if status == 0 and decoded_length:
        string = _allocate(transaction, allocate, 24)
        construct_sized_string_object(transaction, object_address=string,
            source_address=buffer, length=decoded_length, image_base=image_base, allocate=allocate)
    free(transaction, buffer)
    _reference_wrapper(transaction, object_address, string, allocate)
    transaction.commit()
    return string


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


@dataclass(frozen=True)
class SignerChild:
    object_address: int
    state_address: int
    container_address: int
    reference_count_address: int
    callback_pair_address: int


@dataclass(frozen=True)
class SignerRoot:
    object_address: int
    configuration_a: int
    configuration_b: int
    child_a: int
    child_b: int


@dataclass(frozen=True)
class LazyReference:
    """A guarded singleton wrapper and the payload it owns."""

    guard_address: int
    slot_address: int
    wrapper_address: int
    payload_address: int
    payload_size: int
    counter_address: int


@dataclass(frozen=True)
class ServicePayload:
    object_address: int
    controller_address: int
    string_address: int
    reference_count_address: int
    mutex_address: int
    state_address: int


@dataclass(frozen=True)
class RootConfigurationLayout:
    """264-byte configuration prefix before the +0x257308 initializer."""

    object_address: int
    container_addresses: tuple[int, int]
    string_addresses: tuple[int, ...]
    state_address: int


@dataclass(frozen=True)
class ConfigurationObjectLayout88:
    """+0x26194c prefix; the +0x261c54/+0x261cb0 initializer is not executed."""

    object_address: int
    cloned_string_address: int
    container_address: int
    reference_count_addresses: tuple[int, int, int]


@dataclass(frozen=True)
class SingletonLayout136:
    """+0x166370 through +0x166544; registry initialization is still excluded."""

    object_address: int
    mutex_addresses: tuple[int, int]
    helper_address: int
    helper_mutex_address: int
    table_value: int


@dataclass(frozen=True)
class RegistryLayout320:
    """+0x2566ec through +0x256808; clock and configuration writes excluded."""

    object_address: int
    controller_addresses: tuple[int, int, int]
    empty_string_payload: int


# The two service getters used by the measured ``service_refs`` handler.
# Offsets are image-relative and come from the A/B=2 native artifact.
SERVICE_A_GUARD_OFFSET = 0x3D1568
SERVICE_A_SLOT_OFFSET = 0x3D1560
SERVICE_A_PAYLOAD_SIZE = 0x2D0
SERVICE_B_GUARD_OFFSET = 0x3DEBC0
SERVICE_B_SLOT_OFFSET = 0x3DEBB8
SERVICE_B_PAYLOAD_SIZE = 2
CONFIG_GUARD_OFFSET = 0x3D15D0
CONFIG_SLOT_OFFSET = 0x3D15C8
CONFIG_PAYLOAD_SIZE = 8
CONFIG_VTABLE_OFFSET = 0x34C798


def _word(value):
    if not isinstance(value, int) or not 0 <= value <= 0xFFFF_FFFF_FFFF_FFFF:
        raise RefillUnsupported("pointer is outside the guest ABI")
    return value.to_bytes(8, "little")


def _image_address(image_base, offset):
    if image_base <= 0:
        raise RefillUnsupported("invalid native image base")
    value = image_base + offset
    _word(value)
    return value


def _allocate(pages, allocate, size):
    pointer = allocate(pages, size)
    _word(pointer)
    if not pointer:
        # The native operator-new path retries or throws. Those C++ runtime
        # effects are unsupported; leave the caller's page map intact.
        raise RefillUnsupported("native constructor allocation did not succeed")
    _read_span(pages, pointer, size)
    return pointer


def read_singleton136_table_value(pages, *, image_base: int) -> int:
    """Model +0x173470's relocated table read, including changed GOT inputs.

    The bitwise address expression simplifies to the constant signed index
    -0xe6fde0. Read the table pointer through GOT +0x379968, not its default
    effective slot +0x3d1900. The resulting value need not be a mapped pointer.
    """
    table = int.from_bytes(_read_span(pages, _image_address(image_base, 0x379968), 8), "little")
    slot = (table - 0xE6FDE0) & 0xFFFF_FFFF_FFFF_FFFF
    return int.from_bytes(_read_span(pages, slot, 8), "little")


def construct_normal_mutex_object(pages, *, object_address: int, image_base: int) -> None:
    """Model +0x15dea8 with flag bit0 clear (48 bytes, NULL bionic attrs).

    Recursive mutex attributes and host failures are outside this branch.
    Like the other mutex constructors this is a serialized guest layout,
    not a host synchronization primitive.
    """
    transaction = _PageTransaction(pages)
    _write_span(transaction, object_address, _word(_image_address(image_base, 0x34C738)))
    _write_span(transaction, object_address + 8, bytes(40))
    transaction.commit()


def construct_singleton_helper56(pages, *, object_address: int, image_base: int,
                                 allocate: Callable) -> int:
    """Model the full +0x1666e8 constructor; return its new 48-byte mutex.

    Zero three words at +8, byte +0x20 and word +0x28, preserving padding.
    Allocate/initialize the mutex before publishing its pointer at +0x30.
    Native X0 is not this API's return value.
    """
    transaction = _PageTransaction(pages)
    _write_span(transaction, object_address, _word(_image_address(image_base, 0x34C7D8)))
    _write_span(transaction, object_address + 8, bytes(24))
    _write_span(transaction, object_address + 0x20, bytes(1))
    _write_span(transaction, object_address + 0x28, bytes(8))
    mutex = _allocate(transaction, allocate, 48)
    construct_normal_mutex_object(transaction, object_address=mutex, image_base=image_base)
    _write_span(transaction, object_address + 0x30, _word(mutex))
    transaction.commit()
    return mutex


def construct_singleton_layout136(pages, *, object_address: int, image_base: int,
                                  allocate: Callable) -> SingletonLayout136:
    """Model +0x166370 through +0x166544; do not publish a singleton.

    Decode five flag-controlled constants, generate object/mutex/helper fields
    and preserve unwritten padding. The subsequent +0x15e694 registry getter
    and +0x2568c8 configuration writes are NOT performed by this prefix.
    Allocator effects act on staged pages; external ledgers are not rolled back.
    """
    transaction = _PageTransaction(pages)
    for source, mask, destination, flag in (
        (0x70360, 0x70530, 0x3D1690, 0x3D16B4),
        (0x70390, 0x70500, 0x3D16C0, 0x3D16E4),
        (0x703C0, 0x704D0, 0x3D16F0, 0x3D1714),
        (0x703F0, 0x704A0, 0x3D1720, 0x3D1744),
        (0x70420, 0x70470, 0x3D1750, 0x3D1774),
    ):
        flag_address = _image_address(image_base, flag)
        if not int.from_bytes(_read_span(transaction, flag_address, 4), "little"):
            decode_masked_bytes(transaction, source_address=_image_address(image_base, source),
                mask_address=_image_address(image_base, mask),
                destination_address=_image_address(image_base, destination))
            _write_span(transaction, flag_address, (1).to_bytes(4, "little"))
    _write_span(transaction, object_address + 0x30, bytes(4))
    _write_span(transaction, object_address, _word(_image_address(image_base, 0x34C7B8)))
    _write_span(transaction, object_address + 8, (255).to_bytes(4, "little") * 2)
    _write_span(transaction, object_address + 0x10, bytes(32))
    value = read_singleton136_table_value(transaction, image_base=image_base)
    _write_span(transaction, object_address + 0x38, _word(value) + bytes(8))
    _write_span(transaction, object_address + 0x50, bytes(4))
    _write_span(transaction, object_address + 0x48, bytes([255]) * 8)
    mutex_a = _allocate(transaction, allocate, 48)
    construct_normal_mutex_object(transaction, object_address=mutex_a, image_base=image_base)
    _write_span(transaction, object_address + 0x58, _word(mutex_a))
    mutex_b = _allocate(transaction, allocate, 48)
    construct_normal_mutex_object(transaction, object_address=mutex_b, image_base=image_base)
    _write_span(transaction, object_address + 0x60, _word(mutex_b) + bytes(8))
    _write_span(transaction, object_address + 0x70, bytes(16))
    helper = _allocate(transaction, allocate, 56)
    helper_mutex = construct_singleton_helper56(transaction, object_address=helper,
                                               image_base=image_base, allocate=allocate)
    _write_span(transaction, object_address + 0x80, _word(helper))
    transaction.commit()
    return SingletonLayout136(object_address, (mutex_a, mutex_b), helper, helper_mutex, value)


def construct_registry_layout320(pages, *, object_address: int, image_base: int,
                                 allocate: Callable) -> RegistryLayout320:
    """Model +0x2566ec through +0x256808 from ELF/guest inputs.

    Generate three distinct inline containers, a cleared inline 152-byte
    mutex state and an empty string. Stop before the +0x256898 clock wrapper,
    +0x26cc60 realtime getter and initial +0x2568c8 map insertion.
    This prefix cannot be published as a complete registry singleton.
    """
    transaction = _PageTransaction(pages)
    address = lambda offset: _image_address(image_base, offset)
    if not int.from_bytes(_read_span(transaction, address(0x3DE6B0), 4), "little"):
        decode_masked_bytes(transaction, source_address=address(0x98D00),
            destination_address=address(0x3DE690), mask_address=address(0x98D30))
        _write_span(transaction, address(0x3DE6B0), (1).to_bytes(4, "little"))
    _write_span(transaction, object_address, _word(address(0x35B5B8)))
    controllers = []
    for offset, context in ((8, 0x165334), (0x30, 0x182D6C), (0x58, 0x25686C)):
        controllers.append(_callback_container(transaction, object_address + offset,
            (address(0x182D6C), address(context), address(0x188A94)), image_base, allocate,
            vtable_offset=0x35B7C0, hook_offset=0x24B560))
    _write_span(transaction, object_address + 0x80, bytes(152))
    _mutex_state(transaction, object_address + 0x80, image_base)
    string = construct_string_object(transaction, object_address=object_address + 0x118,
        source_address=0, allocate=allocate, vtable_address=address(0x34F5F8),
        empty_descriptor_address=address(0x6E168))
    transaction.commit()
    return RegistryLayout320(object_address, tuple(controllers), string)


def construct_registry_clock_reference(pages, *, object_address: int, allocate: Callable,
                                       read_clock: Callable) -> int:
    """Model +0x256898/+0x256f90; allocate a 16-byte realtime millisecond pair.

    read_clock(staged_pages, 0) supplies explicit clock_gettime status/sec/nsec.
    Native converts to wrapped signed microseconds, then divides by 1000 with
    truncation toward zero. Publish the pointer only after the clock call and
    two payload words. Clock failure/invalid timespec branches reject with
    page rollback; C++ error/exception handling is not replaced with success.
    Return the generated payload pointer, not native X0.
    """
    transaction = _PageTransaction(pages)
    clock = _allocate(transaction, allocate, 16)
    status, seconds, nanoseconds = read_clock(transaction, 0)
    if status != 0:
        raise RefillUnsupported("failed native realtime clock branch is not modeled")
    if (not isinstance(seconds, int) or not -(1 << 63) <= seconds < 1 << 63
            or not isinstance(nanoseconds, int) or not 0 <= nanoseconds < 1000000000):
        raise RefillUnsupported("invalid realtime timespec")
    micros = (seconds * 1000000 + nanoseconds // 1000) & 0xFFFF_FFFF_FFFF_FFFF
    signed = micros - (1 << 64) if micros >= 1 << 63 else micros
    milliseconds = (abs(signed) // 1000) * (-1 if signed < 0 else 1)
    _write_span(transaction, clock, _word(milliseconds & 0xFFFF_FFFF_FFFF_FFFF) + bytes(8))
    _write_span(transaction, object_address, _word(clock))
    transaction.commit()
    return clock


def get_emulated_tls_address(
    pages, *, control_address: int, image_base: int, allocate: Callable,
    reallocate: Callable, get_specific: Callable, set_specific: Callable,
    create_key: Callable | None = None, once_wake: Callable | None = None, max_slots: int = 4096,
    max_payload_bytes: int = 0x100000,
) -> int:
    """Model +0x34377c with explicit serialized pthread/allocator boundaries.

    Control is size/alignment/index/template (four u64 words). Cold once/key
    initialization is performed, then descriptor indexing, per-thread pointer
    array growth and aligned variable initialization. pthread operations act
    on staged pages; create_key(pages, key_address, destructor) supplies the
    OS result. Cold once completion also calls once_wake(pages, address, 129,
    0x7fffffff); matching bionic performs this wake even with no waiters. Actual
    key allocation, futex and concurrency are outside this component.
    malloc/realloc NULL, bad alignment, in-progress once, unsupported
    mutex states and key-create failure reject with page rollback. Native's
    unchecked pthread_setspecific status is preserved. Return native X0.
    """
    if not isinstance(max_slots, int) or not 1 <= max_slots <= 0x100000:
        raise ValueError("invalid emulated TLS slot bound")
    _string_bound(max_payload_bytes)
    transaction = _PageTransaction(pages)
    address = lambda offset: _image_address(image_base, offset)
    read_word = lambda pointer: int.from_bytes(_read_span(transaction, pointer, 8), "little")
    index = read_word(control_address + 16)
    if not index:
        once, key_address = address(0x3E31F8), address(0x3E31F4)
        state = int.from_bytes(_read_span(transaction, once, 4), "little")
        if state == 0:
            if create_key is None or once_wake is None:
                raise RefillUnsupported("cold emulated TLS requires key-create and once-wake boundaries")
            _write_span(transaction, once, (1).to_bytes(4, "little"))
            if create_key(transaction, key_address, address(0x3439BC)) != 0:
                raise RefillUnsupported("emulated TLS pthread key creation failed")
            _write_span(transaction, address(0x3E31F0), bytes([1]))
            _write_span(transaction, once, (2).to_bytes(4, "little"))
            wake_result = once_wake(transaction, once, 129, 0x7FFF_FFFF)
            if not isinstance(wake_result, int) or wake_result < 0:
                raise RefillUnsupported("emulated TLS once wake requires the libc errno path")
        elif state != 2:
            raise RefillUnsupported("in-progress or unknown emulated TLS once state")
        mutex = address(0x3E3208)
        lock_uncontended_mutex(transaction, mutex_address=mutex)
        index = read_word(control_address + 16)
        if not index:
            index = (read_word(address(0x3E3200)) + 1) & 0xFFFF_FFFF_FFFF_FFFF
            if not 1 <= index <= max_slots:
                raise RefillUnsupported("emulated TLS index exceeds the explicit bound")
            _write_span(transaction, address(0x3E3200), _word(index))
            _write_span(transaction, control_address + 16, _word(index))
        unlock_uncontended_mutex(transaction, mutex_address=mutex)
    if not 1 <= index <= max_slots:
        raise RefillUnsupported("emulated TLS index exceeds the explicit bound")
    key = int.from_bytes(_read_span(transaction, address(0x3E31F4), 4), "little")
    array = get_specific(transaction, key)
    _word(array)
    capacity = read_word(array + 8) if array else 0
    if not array or capacity < index:
        new_capacity = ((index + 17) & ~15) - 2
        if new_capacity > max_slots:
            raise RefillUnsupported("emulated TLS array exceeds the explicit bound")
        request = new_capacity * 8 + 16
        if array:
            array = reallocate(transaction, array, request)
            _word(array)
            if not array:
                raise RefillUnsupported("emulated TLS realloc NULL abort branch")
            _write_span(transaction, array + 16 + capacity * 8, bytes((new_capacity - capacity) * 8))
        else:
            array = _allocate(transaction, allocate, request)
            _write_span(transaction, array + 16, bytes(new_capacity * 8))
            _write_span(transaction, array, (1).to_bytes(8, "little"))
        _write_span(transaction, array + 8, _word(new_capacity))
        set_specific(transaction, key, array)  # Native ignores this return value.
    slot = array + 16 + (index - 1) * 8
    result = read_word(slot)
    if not result:
        alignment = max(read_word(control_address + 8), 8)
        if alignment & (alignment - 1):
            raise RefillUnsupported("emulated TLS alignment is not a power of two")
        size = read_word(control_address)
        request = size + alignment + 7
        if size > max_payload_bytes or request > max_payload_bytes:
            raise RefillUnsupported("emulated TLS variable exceeds the explicit bound")
        block = _allocate(transaction, allocate, request)
        result = (block + alignment + 7) & -alignment
        _write_span(transaction, result - 8, _word(block))
        template = read_word(control_address + 24)  # Native reloads after malloc.
        if size:
            _write_span(transaction, result, _read_span(transaction, template, size) if template else bytes(size))
        _write_span(transaction, slot, _word(result))
    transaction.commit()
    return result


def register_emulated_thread_destructor(
    pages, *, destructor_address: int, object_address: int, image_base: int,
    allocate: Callable, get_tls: Callable, create_key: Callable,
    set_specific: Callable, register_atexit: Callable, thread_id: int | None = None,
) -> int:
    """Model +0x34265c's local fallback, including its cold key and TLS list.

    get_tls(pages, control_address) supplies the emulated TLS component. The
    bionic key and process atexit calls are explicit staged-page boundaries;
    process/thread destructors are registered, never executed here. The
    imported __cxa_thread_atexit branch, contention and key-create abort are
    rejected. Supported malloc/setspecific failures return uint32 -1, as
    native does. Page rollback cannot undo external callback ledgers.
    """
    _word(destructor_address)
    _word(object_address)
    transaction = _PageTransaction(pages)
    address = lambda offset: _image_address(image_base, offset)
    if int.from_bytes(_read_span(transaction, address(0x3751A0), 8), "little"):
        raise RefillUnsupported("imported thread-destructor registration is outside the local fallback")
    guard_address = address(0x3E2FA8)
    guard = _read_span(transaction, guard_address, 8)
    if not guard[0] & 1:
        if guard[0] or guard[1] not in (0, 1):
            raise RefillUnsupported("unsupported thread-destructor singleton guard")
        if guard[1] == 0:
            if not isinstance(thread_id, int) or not 0 <= thread_id <= 0xFFFF_FFFF:
                raise RefillUnsupported("cold thread-destructor key requires explicit gettid")
            mutex = address(0x3E2F40)
            lock_uncontended_mutex(transaction, mutex_address=mutex)
            _write_span(transaction, guard_address + 4, thread_id.to_bytes(4, "little"))
            _write_span(transaction, guard_address + 1, bytes([2]))
            unlock_uncontended_mutex(transaction, mutex_address=mutex)
            if create_key(transaction, address(0x3E2FB0), address(0x342854)) != 0:
                raise RefillUnsupported("thread-destructor pthread key-create abort branch")
            register_atexit(transaction, address(0x3427C8), address(0x3E2FA0), address(0x34C700))
            lock_uncontended_mutex(transaction, mutex_address=mutex)
            _write_span(transaction, guard_address, bytes([1, 1]))
            unlock_uncontended_mutex(transaction, mutex_address=mutex)
    flag = get_tls(transaction, address(0x3D13A0))
    if not _read_span(transaction, flag, 1)[0] & 1:
        key_address = address(0x3E2FB0)
        key = int.from_bytes(_read_span(transaction, key_address, 4), "little")
        if set_specific(transaction, key, key_address) != 0:
            transaction.commit()
            return 0xFFFF_FFFF
        flag = get_tls(transaction, address(0x3D13A0))
        _write_span(transaction, flag, bytes([1]))
    node = allocate(transaction, 24)
    _word(node)
    if not node:
        transaction.commit()
        return 0xFFFF_FFFF
    _write_span(transaction, node, _word(destructor_address) + _word(object_address))
    head_address = get_tls(transaction, address(0x3D13C0))
    previous = _read_span(transaction, head_address, 8)
    _write_span(transaction, head_address, _word(node))
    _write_span(transaction, node + 16, previous)
    transaction.commit()
    return 0


def initialize_scoped_tls_registry(
    pages, *, image_base: int, get_tls: Callable, register_destructor: Callable,
) -> None:
    """Model +0x269880: one-byte TLS guard, empty tree and destructor registration.

    register_destructor(pages, destructor, object, dso) must own registration
    side effects; its result is ignored by native. The tree header stores
    leftmost/sentinel at +0, root at +8 and count at +16. Its nodes and the
    scoped lock operations are separate components. Return no native X0.
    """
    transaction = _PageTransaction(pages)
    address = lambda offset: _image_address(image_base, offset)
    flag = get_tls(transaction, address(0x382470))
    if not _read_span(transaction, flag, 1)[0]:
        flag = get_tls(transaction, address(0x382470))
        _write_span(transaction, flag, bytes([1]))
        tree = get_tls(transaction, address(0x382450))
        _write_span(transaction, tree + 16, bytes(8))
        _write_span(transaction, tree + 8, bytes(8))
        _write_span(transaction, tree, _word(tree + 8))
        register_destructor(transaction, address(0x268CF0), tree, address(0x34C700))
    transaction.commit()


def broadcast_condition_no_waiters(pages, *, condition_address: int, wake: Callable) -> int:
    """Matching bionic broadcast: add four to u32, then explicit FUTEX_WAKE.

    wake(pages, condition_address, operation, count) must supply the no-waiter
    OS boundary and return a nonnegative result. No host waiter or atomicity
    is implemented. Unknown/error wake results reject with page rollback.
    """
    if not isinstance(condition_address, int) or condition_address < 0 or condition_address & 3:
        raise RefillUnsupported("condition broadcast requires aligned guest u32")
    transaction = _PageTransaction(pages)
    state = (int.from_bytes(_read_span(transaction, condition_address, 4), "little") + 4) & 0xFFFF_FFFF
    _write_span(transaction, condition_address, state.to_bytes(4, "little"))
    result = wake(transaction, condition_address, 1 if state & 1 else 129, 0x7FFF_FFFF)
    if not isinstance(result, int) or result < 0:
        raise RefillUnsupported("condition wake error requires the libc errno path")
    transaction.commit()
    return 0


def _single_scoped_tls_node(pages, tree, mutex):
    leftmost, root, count = (int.from_bytes(_read_span(pages, tree + i * 8, 8), "little") for i in range(3))
    if count == 0 and root == 0 and leftmost == tree + 8:
        return 0
    if count != 1 or not root or leftmost != root:
        raise RefillUnsupported("scoped TLS tree requires zero or one live mutex entry")
    if (_read_span(pages, root, 16) != bytes(16)
            or int.from_bytes(_read_span(pages, root + 16, 8), "little") != tree + 8
            or _read_span(pages, root + 24, 1) != bytes([1])
            or int.from_bytes(_read_span(pages, root + 32, 8), "little") != mutex):
        raise RefillUnsupported("unknown scoped TLS node or another live mutex key")
    return root


def construct_single_scoped_lock(
    pages, *, object_address: int, mutex_address: int, scratch_address: int,
    image_base: int, allocate: Callable, get_tls: Callable, initialize_registry: Callable,
) -> int:
    """Model +0x268eb0 for zero/one live TLS mutex entry and an idle writer.

    Native copies a 16-byte stack pair into a new 48-byte TLS node, including
    seven padding bytes. scratch_address names caller-supplied working memory
    with its original padding, read AFTER allocation as native does. No native
    output is an input. Nested acquisition of the same active entry preserves
    the outer ownership. Another live mutex, readers or waiting writer rejects
    with page rollback. Return the stored u32 status, not native X0.
    """
    transaction = _PageTransaction(pages)
    address = lambda offset: _image_address(image_base, offset)
    _write_span(transaction, object_address, _word(address(0x35D2A0)) + _word(mutex_address))
    status = (-0x91D) & 0xFFFF_FFFF
    _write_span(transaction, object_address + 16, status.to_bytes(4, "little"))
    initialize_registry(transaction)
    _write_span(transaction, scratch_address, _word(mutex_address))
    tree = get_tls(transaction, address(0x382450))
    node = _single_scoped_tls_node(transaction, tree, mutex_address)
    initialize_registry(transaction)
    if not node:
        initialize_registry(transaction)
        _write_span(transaction, scratch_address + 8, bytes([0]))
        _write_span(transaction, scratch_address, _word(mutex_address))
        tree = get_tls(transaction, address(0x382450))
        if _single_scoped_tls_node(transaction, tree, mutex_address):
            raise RefillUnsupported("scoped TLS tree changed before insertion")
        node = _allocate(transaction, allocate, 48)
        pair = _read_span(transaction, scratch_address, 16)
        _write_span(transaction, node + 32, pair)
        _write_span(transaction, node, bytes(16) + _word(tree + 8))
        _write_span(transaction, tree + 8, _word(node))
        _write_span(transaction, tree, _word(node))
        _write_span(transaction, node + 24, bytes([1]))
        _write_span(transaction, tree + 16, (1).to_bytes(8, "little"))
    # +0x268cf4 repeats lookup before testing the thread-local ownership bit.
    initialize_registry(transaction)
    _write_span(transaction, scratch_address, _word(mutex_address))
    tree = get_tls(transaction, address(0x382450))
    _single_scoped_tls_node(transaction, tree, mutex_address)
    initialize_registry(transaction)
    initialize_registry(transaction)
    _write_span(transaction, scratch_address, _word(mutex_address))
    tree = get_tls(transaction, address(0x382450))
    node = _single_scoped_tls_node(transaction, tree, mutex_address)
    if not _read_span(transaction, node + 40, 1)[0]:
        primitive = mutex_address + 8
        lock_uncontended_mutex(transaction, mutex_address=primitive)
        readers = int.from_bytes(_read_span(transaction, mutex_address + 0x90, 4), "little")
        if readers:
            raise RefillUnsupported("scoped writer acquisition requires waiting")
        _write_span(transaction, mutex_address + 0x90, (0x80000000).to_bytes(4, "little"))
        unlock_uncontended_mutex(transaction, mutex_address=primitive)
        _write_span(transaction, mutex_address + 0x94, bytes([0]))
        status = 0
        _write_span(transaction, object_address + 16, bytes(4))
        initialize_registry(transaction)
        _write_span(transaction, scratch_address, _word(mutex_address))
        tree = get_tls(transaction, address(0x382450))
        node = _single_scoped_tls_node(transaction, tree, mutex_address)
        _write_span(transaction, node + 40, bytes([1]))
    transaction.commit()
    return status


def destroy_single_scoped_lock(
    pages, *, object_address: int, image_base: int, free: Callable,
    get_tls: Callable, initialize_registry: Callable, broadcast: Callable,
    entry_stack_address: int | None = None,
) -> None:
    """Model +0x268fbc for the matching one-entry writer-owned TLS tree.

    Clear the writer count, broadcast at mutex+0x30, remove the TLS node and
    free it. Nested nonzero-status guards perform no release. Other layouts,
    shared-reader ownership and waiter states reject with page rollback.
    When the native entry stack is supplied, preserve +0x2694f4's saved
    guard pointer before erase/free; later acquisitions copy its upper
    seven bytes as stack padding. This is a measured stack effect, not a
    complete native call-stack emulator.
    """
    transaction = _PageTransaction(pages)
    address = lambda offset: _image_address(image_base, offset)
    status = int.from_bytes(_read_span(transaction, object_address + 16, 4), "little")
    _write_span(transaction, object_address, _word(address(0x35D2A0)))
    if not status:
        mutex = int.from_bytes(_read_span(transaction, object_address + 8, 8), "little")
        if _read_span(transaction, mutex + 0x94, 1)[0]:
            raise RefillUnsupported("scoped shared-reader release is outside the writer branch")
        lock_uncontended_mutex(transaction, mutex_address=mutex + 8)
        if int.from_bytes(_read_span(transaction, mutex + 0x90, 4), "little") != 0x80000000:
            raise RefillUnsupported("scoped writer release requires exactly one active writer")
        _write_span(transaction, mutex + 0x90, bytes(4))
        broadcast(transaction, mutex + 0x30)
        unlock_uncontended_mutex(transaction, mutex_address=mutex + 8)
        initialize_registry(transaction)
        tree = get_tls(transaction, address(0x382450))
        if entry_stack_address is not None:
            _write_span(transaction, entry_stack_address - 0x40, _word(object_address))
        node = _single_scoped_tls_node(transaction, tree, mutex)
        if not node:
            raise RefillUnsupported("scoped writer has no TLS entry to erase")
        _write_span(transaction, tree, _word(tree + 8))
        _write_span(transaction, tree + 16, bytes(8))
        _write_span(transaction, tree + 8, bytes(8))
        free(transaction, node)
    transaction.commit()


def _reference_wrapper(pages, object_address, referenced_address, allocate):
    _read_span(pages, object_address, 16)
    _write_span(pages, object_address, _word(referenced_address) + bytes(8))
    counter = _allocate(pages, allocate, 4)
    _write_span(pages, object_address + 8, _word(counter))
    _write_span(pages, counter, (1).to_bytes(4, "little"))
    return counter


def construct_reference_wrapper(
    pages, *, object_address: int, referenced_address: int, allocate: Callable,
) -> int:
    """Construct the shared 16-byte reference/count layout; return count pointer.

    Measured at +0x165968, +0x27d188 and +0x1a4494. Diagnostic scope entry
    and exit are outside this object-memory model. The allocated count is a
    four-byte integer set to 1, including when the referenced pointer is NULL.
    """
    transaction = _PageTransaction(pages)
    counter = _reference_wrapper(transaction, object_address, referenced_address, allocate)
    transaction.commit()
    return counter


def construct_lazy_reference(
    pages, *, guard_address: int, slot_address: int, payload_size: int,
    allocate: Callable, initialize_payload: Callable | None = None,
    thread_id: int | None = None,
) -> LazyReference:
    """Construct one measured guard/slot singleton from fresh input.

    The native getters use an acquire guard, allocate a 16-byte wrapper and
    the payload, initialize the payload, then construct the wrapper and
    publish the wrapper pointer before releasing the guard.  This model is
    single-threaded with successful host mutex calls. Any nonzero byte0 or
    byte1==1 returns the slot; byte1 bit1 (recursive/contended initialization)
    is unsupported. Cold acquisition records explicit gettid at guard+4 and
    byte1=2; release sets byte0=byte1=1. Other guard bytes are preserved.
    ``initialize_payload(staged_pages, address)`` is needed only on the cold
    path. All page writes are transactional; no host mutex is invoked here.
    """
    if not isinstance(payload_size, int) or payload_size <= 0:
        raise RefillUnsupported("singleton payload size must be positive")
    transaction = _PageTransaction(pages)
    guard = _read_span(transaction, guard_address, 8)
    slot = int.from_bytes(_read_span(transaction, slot_address, 8), "little")
    if guard[0]:
        return LazyReference(guard_address, slot_address, slot, 0, 0, 0)
    if guard[1] & 2:
        raise RefillUnsupported("recursive/contended singleton guard is unsupported")
    if guard[1] == 1:
        return LazyReference(guard_address, slot_address, slot, 0, 0, 0)
    if not isinstance(thread_id, int) or not 0 <= thread_id <= 0xFFFF_FFFF:
        raise RefillUnsupported("cold singleton requires an explicit uint32 thread id")
    if initialize_payload is None:
        raise RefillUnsupported("cold singleton requires a payload initializer")
    _write_span(transaction, guard_address + 4, thread_id.to_bytes(4, "little"))
    _write_span(transaction, guard_address + 1, bytes((2,)))
    wrapper = _allocate(transaction, allocate, 16)
    payload = _allocate(transaction, allocate, payload_size)
    initialize_payload(transaction, payload)
    _reference_wrapper(transaction, wrapper, payload, allocate)
    _write_span(transaction, slot_address, _word(wrapper))
    _write_span(transaction, guard_address, bytes((1,)))
    _write_span(transaction, guard_address + 1, bytes((1,)))
    counter = int.from_bytes(_read_span(transaction, wrapper + 8, 8), "little")
    transaction.commit()
    return LazyReference(guard_address, slot_address, wrapper, payload,
                         payload_size, counter)


def construct_service_reference(
    pages, *, image_base: int, kind: str, allocate: Callable,
    initialize_payload: Callable | None = None, thread_id: int | None = None,
) -> LazyReference:
    """Construct one of the two service singleton references.

    ``kind='flag'`` is the small native 2-byte, zero-initialized payload from
    ``+0x264158``.  ``kind='service'`` is the 0x2d0-byte object from
    ``+0x15f094``. Its default initializer generates the measured service
    graph from loaded ELF constants/GOT and caller memory. Cold getters need
    explicit gettid; warm getters neither allocate nor require an initializer.
    """
    if image_base <= 0:
        raise RefillUnsupported("invalid native image base")
    if kind == "service":
        guard = image_base + SERVICE_A_GUARD_OFFSET
        slot = image_base + SERVICE_A_SLOT_OFFSET
        size = SERVICE_A_PAYLOAD_SIZE
        if initialize_payload is None:
            def initialize_payload(staged, address):
                construct_service_payload(staged, object_address=address,
                    image_base=image_base, allocate=allocate)
    elif kind == "flag":
        guard = image_base + SERVICE_B_GUARD_OFFSET
        slot = image_base + SERVICE_B_SLOT_OFFSET
        size = SERVICE_B_PAYLOAD_SIZE

        def initialize_payload(pages, address):
            _write_span(pages, address, bytes(size))
    else:
        raise RefillUnsupported("unsupported service singleton kind")
    return construct_lazy_reference(
        pages, guard_address=guard, slot_address=slot, payload_size=size,
        allocate=allocate, initialize_payload=initialize_payload, thread_id=thread_id)


def construct_configuration_reference(
    pages, *, image_base: int, allocate: Callable, thread_id: int | None = None,
) -> LazyReference:
    """Construct the measured 8-byte root configuration singleton.

    Native ``+0x15f608`` allocates a 16-byte wrapper and an 8-byte payload,
    writes only the image-relative vtable at payload+0, then publishes the
    wrapper through its guard/slot.  No configuration strings are implied by
    this object; those belong to the separate service payload constructor.
    """
    if image_base <= 0:
        raise RefillUnsupported("invalid native image base")

    def initialize_payload(pages, address):
        _write_span(pages, address, _word(image_base + CONFIG_VTABLE_OFFSET))

    return construct_lazy_reference(
        pages, guard_address=image_base + CONFIG_GUARD_OFFSET,
        slot_address=image_base + CONFIG_SLOT_OFFSET,
        payload_size=CONFIG_PAYLOAD_SIZE, allocate=allocate,
        initialize_payload=initialize_payload, thread_id=thread_id)


def construct_signer_root(
    pages, *, object_address: int, configuration_a: int, configuration_b: int,
    child_a: int, child_b: int,
) -> SignerRoot:
    """Assemble the measured 40-byte root from explicit object dependencies.

    The native +0x27c930 trace clears root+0x08/+0x10, later stores the two
    configuration/reference addresses there, then stores constructed child
    addresses at +0x18/+0x20. Root+0x00 is not written by this constructor;
    its observed zero value is therefore not synthesized here. Singleton
    construction, lazy strings, diagnostic flags, and publication are caller
    responsibilities.
    """
    pointers = (configuration_a, configuration_b, child_a, child_b)
    if any(not isinstance(value, int) or value <= 0 for value in pointers):
        raise RefillUnsupported("root dependencies must be non-null guest pointers")
    transaction = _PageTransaction(pages)
    _read_span(transaction, object_address, 0x28)
    _write_span(transaction, object_address + 8, bytes(16))
    _write_span(transaction, object_address + 8, _word(configuration_a) + _word(configuration_b))
    _write_span(transaction, object_address + 0x18, _word(child_a) + _word(child_b))
    transaction.commit()
    return SignerRoot(object_address, configuration_a, configuration_b, child_a, child_b)


def _mutex_state(pages, object_address, image_base):
    _read_span(pages, object_address, 0x98)
    vtable = _image_address(image_base, 0x34D838)
    _write_span(pages, object_address, _word(vtable))
    _write_span(pages, object_address + 8, bytes(0x8C))
    _write_span(pages, object_address + 0x94, bytes(1))


def construct_mutex_state(pages, *, object_address: int, image_base: int) -> None:
    """Model +0x17d7e0 and +0x32a330; preserve the last three padding bytes."""
    transaction = _PageTransaction(pages)
    _mutex_state(transaction, object_address, image_base)
    transaction.commit()


def _callback_container(pages, object_address, descriptor, image_base, allocate,
                        *, vtable_offset=0x35B828, hook_offset=0x24B548):
    _read_span(pages, object_address, 0x28)
    callback, context, comparator = descriptor
    _write_span(pages, object_address,
                _word(_image_address(image_base, vtable_offset))
                + _word(callback) + _word(context) + _word(comparator))
    controller = _allocate(pages, allocate, 0x28)
    sentinel = _allocate(pages, allocate, 0x28)
    # +0x24bcec writes u32 at +0 and two 16-byte vectors from +8. It
    # preserves padding +4..+7 even on a newly allocated poisoned page.
    _write_span(pages, sentinel, bytes(4))
    _write_span(pages, sentinel + 8, bytes(0x20))
    _write_span(pages, sentinel + 0x10, _word(sentinel) + _word(sentinel))
    _write_span(pages, controller, _word(sentinel) + bytes(8)
                + _word(comparator) + _word(_image_address(image_base, hook_offset)) + bytes(8))
    _write_span(pages, object_address + 0x20, _word(controller))
    return controller


def construct_callback_container(
    pages, *, object_address: int, descriptor_address: int,
    image_base: int, allocate: Callable,
) -> int:
    """Model +0x25cad4 and its empty controller/sentinel constructors.

    Three input descriptor words are copied from fresh caller memory. Both
    nested allocations are 40 bytes. Returns the generated controller address.
    """
    transaction = _PageTransaction(pages)
    data = _read_span(transaction, descriptor_address, 24)
    descriptor = tuple(int.from_bytes(data[i:i+8], "little") for i in range(0, 24, 8))
    result = _callback_container(transaction, object_address, descriptor, image_base, allocate)
    transaction.commit()
    return result


def construct_configuration_container_reference(
    pages, *, object_address: int, image_base: int, allocate: Callable,
) -> int:
    """Model +0x25c8fc: a new 48-byte container with a 24-byte empty sentinel.

    Its +0x20/+0x28 fields embed comparator and an allocated 8-byte sentinel
    holder. This layout differs from the 40-byte callback controller variant.
    Return the generated container pointer; the output is a 16-byte reference.
    """
    transaction = _PageTransaction(pages)
    address = lambda offset: _image_address(image_base, offset)
    container = _allocate(transaction, allocate, 48)
    _write_span(transaction, container,
                _word(address(0x35B808)) + _word(address(0x182D6C)) + bytes(8)
                + _word(address(0x188A94)) + _word(address(0x188A94)))
    sentinel = _allocate(transaction, allocate, 24)
    _write_span(transaction, sentinel, _word(sentinel) + _word(sentinel) + bytes(8))
    holder = _allocate(transaction, allocate, 8)
    _write_span(transaction, holder, _word(sentinel))
    _write_span(transaction, container + 0x28, _word(holder))
    _reference_wrapper(transaction, object_address, container, allocate)
    transaction.commit()
    return container


def construct_configuration_object_layout(
    pages, *, object_address: int, first_string_address: int, second_string_address: int,
    image_base: int, allocate: Callable, max_payload_bytes: int = 0x100000,
) -> ConfigurationObjectLayout88:
    """Model +0x26194c through +0x261a1c, before the nontrivial initializer.

    Generate the 88-byte object and nine allocations for nonnegative string
    lengths. Decode/publish the lazy constant only if its u32 flag is zero.
    Padding +0x40..+0x47 remains unchanged. No captured object is used.
    """
    transaction = _PageTransaction(pages)
    address = lambda offset: _image_address(image_base, offset)
    _read_span(transaction, object_address, 88)
    flag = address(0x3DEB68)
    if int.from_bytes(_read_span(transaction, flag, 4), "little") == 0:
        decode_masked_bytes(transaction, source_address=address(0x9A68C),
                            destination_address=address(0x3DEB60), mask_address=address(0x9A6DC))
        _write_span(transaction, flag, (1).to_bytes(4, "little"))
    _write_span(transaction, object_address, _word(address(0x35BA78)))
    string = _allocate(transaction, allocate, 24)
    clone_string_object(transaction, object_address=string, source_object_address=first_string_address,
                        allocate=allocate, image_base=image_base, max_payload_bytes=max_payload_bytes)
    first_count = _reference_wrapper(transaction, object_address + 8, string, allocate)
    null_count = _reference_wrapper(transaction, object_address + 0x18, 0, allocate)
    clone_string_object(transaction, object_address=object_address + 0x28,
                        source_object_address=second_string_address, allocate=allocate,
                        image_base=image_base, max_payload_bytes=max_payload_bytes)
    container = construct_configuration_container_reference(transaction,
        object_address=object_address + 0x48, image_base=image_base, allocate=allocate)
    container_count = int.from_bytes(_read_span(transaction, object_address + 0x50, 8), "little")
    transaction.commit()
    return ConfigurationObjectLayout88(object_address, string, container,
                                       (first_count, null_count, container_count))


def construct_service_payload(
    pages, *, object_address: int, image_base: int, allocate: Callable,
) -> ServicePayload:
    """Model +0x281700 from fresh memory, including strings and nested state.

    Image inputs are readonly constants and relocated GOT pointers, not a
    captured service object. The shared string pointer is dereferenced anew
    for every string, while the numeric inputs are latched at native's read
    points. Unwritten padding remains unchanged. NULL-attribute bionic mutex
    initialization is modeled; logging/allocator global effects are separate.
    """
    transaction = _PageTransaction(pages)
    _read_span(transaction, object_address, SERVICE_A_PAYLOAD_SIZE)

    def address(offset):
        return _image_address(image_base, offset)

    def read_word(pointer):
        return int.from_bytes(_read_span(transaction, pointer, 8), "little")

    def string(target, source):
        construct_string_object(transaction, object_address=target,
            source_address=source, allocate=allocate,
            vtable_address=address(0x34F5F8), empty_descriptor_address=address(0x6E168))

    _write_span(transaction, object_address + 8, bytes(8))
    _write_span(transaction, object_address + 0x10, bytes(1))
    descriptor = (address(0x25686C), address(0x165334), address(0x281958))
    controller = _callback_container(transaction, object_address + 0x18,
        descriptor, image_base, allocate, vtable_offset=0x35B7C0, hook_offset=0x24B560)
    for offset, width in ((0x40, 16), (0xA0, 16), (0x68, 48)):
        _write_span(transaction, object_address + offset, bytes(width))
    _write_span(transaction, object_address + 0x50, (0x10000).to_bytes(4, "little"))
    _write_span(transaction, object_address + 0xB0, bytes(4))
    _write_span(transaction, object_address + 0x58, _read_span(transaction, address(0x6E500), 16))
    string_address = _allocate(transaction, allocate, 24)
    string(string_address, address(0x6FE64))
    count = _reference_wrapper(transaction, object_address + 0xB8, string_address, allocate)

    string_slot = read_word(address(0x374FC0))
    _write_span(transaction, object_address + 0xC8, bytes(8))
    _write_span(transaction, object_address + 0xD0, bytes(4))
    for offset in (0xD8, 0xF0):
        string(object_address + offset, read_word(string_slot))
    integer_pointer = read_word(address(0x375020))
    # Native reads the source pointer before latching the integer.
    source = read_word(string_slot)
    integer = _read_span(transaction, integer_pointer, 4)
    _write_span(transaction, object_address + 0x108, integer * 4)
    string(object_address + 0x118, source)
    for offset in (0x130, 0x148):
        string(object_address + offset, read_word(string_slot))
    source = read_word(string_slot)
    _write_span(transaction, object_address + 0x160, integer)
    string(object_address + 0x168, source)
    floating = struct.pack("<f", int.from_bytes(integer, "little", signed=True))
    source = read_word(string_slot)
    _write_span(transaction, object_address + 0x190, floating * 2)
    _write_span(transaction, object_address + 0x180, floating * 4)
    string(object_address + 0x198, source)
    wide_pointer = read_word(address(0x375030))
    _write_span(transaction, object_address + 0x1B0, integer * 2)
    source = read_word(string_slot)
    _write_span(transaction, object_address + 0x1C8, integer)
    wide = _read_span(transaction, wide_pointer, 8)
    _write_span(transaction, object_address + 0x1B8, wide * 2)
    string(object_address + 0x1D0, source)
    for offset in (0x1E8, 0x200, 0x218, 0x230, 0x248, 0x260, 0x278):
        string(object_address + offset, read_word(string_slot))
    _write_span(transaction, object_address + 0x290, wide)
    string(object_address + 0x298, address(0x6FE64))
    source = read_word(string_slot)
    _write_span(transaction, object_address + 0x2B0, _read_span(transaction, address(0x3E0B58), 8))
    string(object_address + 0x2B8, source)

    mutex = _allocate(transaction, allocate, 0x30)
    construct_normal_mutex_object(transaction, object_address=mutex, image_base=image_base)
    _write_span(transaction, object_address + 0x98, _word(mutex))
    state = _allocate(transaction, allocate, 0x98)
    _write_span(transaction, state, bytes(0x98))
    _mutex_state(transaction, state, image_base)
    _write_span(transaction, object_address, _word(state))
    transaction.commit()
    return ServicePayload(object_address, controller, string_address, count, mutex, state)


def construct_root_configuration_layout(
    pages, *, object_address: int, initial_reference_address: int,
    first_reference_address: int, second_reference_address: int, flag: int,
    image_base: int, allocate: Callable,
) -> RootConfigurationLayout:
    """Model +0x257084 up to +0x257240, before initializer input copying.

    Generate the 264-byte layout and 30 nested allocations from fresh inputs.
    The third configuration string, +0x257308 VM initialization and its global
    effects are not executed. This prefix is not a usable complete root.
    """
    if not isinstance(flag, int) or not 0 <= flag <= 0xFFFF_FFFF:
        raise RefillUnsupported("configuration flag is outside the native u32 ABI")
    transaction = _PageTransaction(pages)
    _read_span(transaction, object_address, 264)
    _write_span(transaction, object_address, _word(_image_address(image_base, 0x35B688)))
    _copy_reference_wrapper(transaction, object_address + 8, initial_reference_address)
    containers, strings = [], []

    def container(offset):
        pointer = _allocate(transaction, allocate, 40)
        _callback_container(transaction, pointer,
            (_image_address(image_base, 0x182D6C), _image_address(image_base, 0x182D6C),
             _image_address(image_base, 0x188A94)), image_base, allocate,
            vtable_offset=0x35B7C0, hook_offset=0x24B560)
        _reference_wrapper(transaction, object_address + offset, pointer, allocate)
        containers.append(pointer)

    def string(offset):
        pointer = _allocate(transaction, allocate, 24)
        construct_string_object(transaction, object_address=pointer,
            source_address=_image_address(image_base, 0x6FE64), allocate=allocate,
            vtable_address=_image_address(image_base, 0x34F5F8), max_source_bytes=0x100000)
        _reference_wrapper(transaction, object_address + offset, pointer, allocate)
        strings.append(pointer)

    container(0x18)
    for offset in (0x28, 0x38, 0x48, 0x58):
        string(offset)
    _write_span(transaction, object_address + 0x68, b"\xff" * 8)
    string(0x70)
    _copy_reference_wrapper(transaction, object_address + 0x80, first_reference_address)
    _copy_reference_wrapper(transaction, object_address + 0x90, second_reference_address)
    _reference_wrapper(transaction, object_address + 0xA0, 0, allocate)
    string(0xB0)
    container(0xC0)
    _write_span(transaction, object_address + 0xD0, flag.to_bytes(4, "little"))
    _reference_wrapper(transaction, object_address + 0xD8, 0, allocate)
    _write_span(transaction, object_address + 0xE8, bytes(4))
    _reference_wrapper(transaction, object_address + 0xF0, 0, allocate)
    state = _allocate(transaction, allocate, 152)
    _write_span(transaction, state, bytes(152))
    _mutex_state(transaction, state, image_base)
    _write_span(transaction, object_address + 0x100, _word(state))
    transaction.commit()
    return RootConfigurationLayout(object_address, tuple(containers), tuple(strings), state)


def construct_signer_child(
    pages, *, object_address: int, image_base: int, allocate: Callable,
) -> SignerChild:
    """Construct +0x27d0c4's child and nested empty state from explicit inputs.

    The final 16-byte callback pair is allocated but left untouched, as native
    does. Root construction later binds the pair to a generated handler.
    Allocator and diagnostic global side effects are separate dependencies.
    """
    transaction = _PageTransaction(pages)
    _read_span(transaction, object_address, 0x28)
    _write_span(transaction, object_address, _word(_image_address(image_base, 0x35D5F0)))
    state = _allocate(transaction, allocate, 0x98)
    _write_span(transaction, state, bytes(0x98))
    _mutex_state(transaction, state, image_base)
    _write_span(transaction, object_address + 8, _word(state))
    container = _allocate(transaction, allocate, 0x28)
    descriptor = (_image_address(image_base, 0x27EC20), 0,
                  _image_address(image_base, 0x17CD3C))
    _callback_container(transaction, container, descriptor, image_base, allocate)
    count = _reference_wrapper(transaction, object_address + 0x10, container, allocate)
    pair = _allocate(transaction, allocate, 0x10)
    _write_span(transaction, object_address + 0x20, _word(pair))
    transaction.commit()
    return SignerChild(object_address, state, container, count, pair)


def _copy_reference_wrapper(pages, object_address, source_address):
    _read_span(pages, object_address, 16)
    _read_span(pages, source_address, 16)
    # Preserve native load/store order, including destination/source aliases.
    _write_span(pages, object_address, bytes(16))
    _write_span(pages, object_address, _read_span(pages, source_address, 8))
    count = int.from_bytes(_read_span(pages, source_address + 8, 8), "little")
    _write_span(pages, object_address + 8, _word(count))
    if count:
        value = int.from_bytes(_read_span(pages, count, 4), "little")
        _write_span(pages, count, ((value + 1) & 0xFFFF_FFFF).to_bytes(4, "little"))


def copy_reference_wrapper(pages, *, object_address: int, source_address: int) -> None:
    """Model +0x264404/+0x2641d8/+0x15f690's copy and u32 count increment.

    Diagnostic scope effects are excluded. NULL count skips increment; the
    native count addition wraps at 32 bits. The source and object may alias.
    """
    transaction = _PageTransaction(pages)
    _copy_reference_wrapper(transaction, object_address, source_address)
    transaction.commit()


def construct_signer_handler(
    pages, *, object_address: int, image_base: int, allocate: Callable,
    kind: str, service_reference_address: int = 0, flag_reference_address: int = 0,
    initialize_services: bool = False, thread_id: int | None = None,
) -> None:
    """Construct +0x288e98 or +0x263fb8 with explicit service dependencies.

    ``embedded_state`` is the 0xe8-byte object with a generated 0x98-byte
    state at +0x50. ``service_refs`` is the 0x80-byte object, copying the
    two supplied singleton references at +0x50 and +0x60. Alternatively,
    ``initialize_services=True`` calls the recovered getters in native order
    before each reference copy. Cold getters require explicit gettid.
    Fresh NULL wrappers each allocate a count,
    and the 0x30-byte mutex holder gets the verified NULL-attribute bionic
    pthread_mutex_init layout. This is an uncontended initialization model.
    """
    if kind not in ("embedded_state", "service_refs"):
        raise RefillUnsupported("unsupported signer handler constructor")
    if initialize_services and (kind != "service_refs" or
                                service_reference_address or flag_reference_address):
        raise RefillUnsupported("automatic getters require unsupplied service_refs dependencies")
    transaction = _PageTransaction(pages)
    width = 0xE8 if kind == "embedded_state" else 0x80
    _read_span(transaction, object_address, width)
    # The temporary base vtable is overwritten by the final derived vtable.
    _reference_wrapper(transaction, object_address + 8, 0, allocate)
    _reference_wrapper(transaction, object_address + 0x18, 0, allocate)
    mutex = _allocate(transaction, allocate, 0x30)
    _write_span(transaction, mutex,
                _word(_image_address(image_base, 0x34C738)) + bytes(40))
    _write_span(transaction, object_address + 0x28, _word(mutex))
    _write_span(transaction, object_address + 0x30, bytes(0x20))
    if kind == "embedded_state":
        _write_span(transaction, object_address, _word(_image_address(image_base, 0x35F7E0)))
        _mutex_state(transaction, object_address + 0x50, image_base)
    else:
        # ELF R_AARCH64_RELATIVE at +0x375050 contains +0x35dc40;
        # +0x263fe0 adds the vtable header width of 0x10.
        _write_span(transaction, object_address, _word(_image_address(image_base, 0x35DC50)))
        if initialize_services:
            service_reference_address = construct_service_reference(transaction,
                image_base=image_base, kind="service", allocate=allocate,
                thread_id=thread_id).wrapper_address
        _copy_reference_wrapper(transaction, object_address + 0x50, service_reference_address)
        if initialize_services:
            flag_reference_address = construct_service_reference(transaction,
                image_base=image_base, kind="flag", allocate=allocate,
                thread_id=thread_id).wrapper_address
        _copy_reference_wrapper(transaction, object_address + 0x60, flag_reference_address)
        _write_span(transaction, object_address + 0x70, bytes(0x10))
    transaction.commit()


def bind_signer_child_callback(
    pages, *, child_address: int, handler_address: int, image_base: int, kind: str,
) -> int:
    """Bind the constructor-generated child pair to the measured handler.

    Root+0x18's 0x80-byte handler exposes +0x2830c4 via vtable+0x68;
    root+0x20's 0xe8-byte handler exposes +0x289190 via vtable+0x60.
    This only implements those two measured derived types. Return pair address.
    """
    variants = {"embedded_state": (0x35F7E0, 0x289190),
                "service_refs": (0x35DC50, 0x2830C4)}
    if kind not in variants:
        raise RefillUnsupported("unsupported signer handler binding")
    vtable, entry = variants[kind]
    transaction = _PageTransaction(pages)
    actual_vtable = int.from_bytes(_read_span(transaction, handler_address, 8), "little")
    if actual_vtable != _image_address(image_base, vtable):
        raise RefillUnsupported("handler does not match the measured derived type")
    pair = int.from_bytes(_read_span(transaction, child_address + 0x20, 8), "little")
    if not pair:
        raise RefillUnsupported("child has no allocated callback pair")
    _read_span(transaction, pair, 16)
    _write_span(transaction, pair, _word(_image_address(image_base, entry)) + _word(handler_address))
    transaction.commit()
    return pair
