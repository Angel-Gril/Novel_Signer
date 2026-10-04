"""Recovered ECB configuration callback and checked forward copy.

Caller memory, matching guest ELF tables and explicit allocator/singleton
boundaries drive all results. No captured key or native output is supplied.
Stream/CBC initialization and nonzero environment checks remain unsupported.
"""
from __future__ import annotations

from typing import Callable
import vm9_cipher as cipher
import vm9_objects as objects
from vm9_allocator import RefillUnsupported, _PageTransaction, _read_span, _write_span

MASK64 = 0xFFFFFFFFFFFFFFFF


def _pointer(pages, address):
    return int.from_bytes(_read_span(pages, address, 8), "little")


def _length(pages, address):
    return int.from_bytes(_read_span(pages, address + 12, 4), "little")


def checked_forward_copy(pages, *, output_address: int, source_address: int,
                         length: int, entry_stack_address: int,
                         get_singleton: Callable, max_bytes: int = 0x100000) -> int:
    """Model +0x276b9c with both real getter calls and the zero-check path.

    get_singleton(staged_pages, getter_entry_sp) returns the shared reference
    address, using the recovered +0x161068 implementation when cold. The first
    payload+0x10 read precedes the second getter. With nonzero first field,
    native reads payload+0x18; unknown environment checks reject. Copy reads
    and writes one byte at a time, preserving forward overlap behavior.
    """
    objects._string_bound(max_bytes)
    if not isinstance(length, int) or not 0 <= length <= max_bytes:
        raise RefillUnsupported("checked copy exceeds the explicit byte bound")
    transaction = _PageTransaction(pages)
    reference = get_singleton(transaction, entry_stack_address - 0x40)
    first = _pointer(transaction, _pointer(transaction, reference) + 0x10)
    reference = get_singleton(transaction, entry_stack_address - 0x40)
    if first and _pointer(transaction, _pointer(transaction, reference) + 0x18):
        raise RefillUnsupported("unrecovered checked-copy environment branch")
    for index in range(length):
        _write_span(transaction, output_address + index,
                    _read_span(transaction, source_address + index, 1))
    transaction.commit()
    return output_address


def initialize_cipher_context(pages, *, descriptor_address: int,
                              context_address: int, image_base: int) -> int:
    """Model +0x25aa48's mode-0 constructor, including bytewise clearing.

    Read descriptor and key fields after clearing the full 0x210-byte context.
    Guest jump-table changes and other initialization targets reject.
    """
    transaction = _PageTransaction(pages)
    for index in range(0x210):
        _write_span(transaction, context_address + index, bytes(1))
    mode = int.from_bytes(_read_span(transaction, _pointer(transaction, descriptor_address), 4), "little")
    if mode > 3:
        raise RefillUnsupported("unrecovered no-constructor cipher mode")
    jump = _read_span(transaction, objects._image_address(image_base, 0x9A0B4) + mode, 1)[0]
    if 0x25AA94 + jump * 4 != 0x25AA94:
        raise RefillUnsupported("unrecovered cipher initialization branch")
    key_object = _pointer(transaction, descriptor_address + 8)
    result = cipher.construct_cipher_schedule(transaction, context_address=context_address,
        key_address=_pointer(transaction, key_object + 0x10),
        key_size=_length(transaction, key_object), image_base=image_base)
    transaction.commit()
    return result


def _dispatch_offset(image_base):
    # +0x259e54..+0x259ee0; mixed address masks simplify to -0xe213e0
    # for the observed relocations. Evaluate the guest expression explicitly.
    address = objects._image_address(image_base, 0x259DBC)
    mixed = (address & 0x10400040400) + ((0xA060400A021040 | ~address) & 0xA061440A061440)
    return ((mixed | 0x1010104) ^ 0xFF5F9EBBF41AF964) & MASK64


def _check_dispatch(pages, base, slot, target):
    actual = (_pointer(pages, objects._image_address(base, slot)) + _dispatch_offset(base)) & MASK64
    if actual != objects._image_address(base, target):
        raise RefillUnsupported("unrecovered configuration cipher callback target")


def decrypt_configuration_reference(pages, *, output_reference_address: int,
                                    data_object_address: int, key_object_address: int,
                                    iv_object_address: int, mode_address: int,
                                    entry_stack_address: int, image_base: int,
                                    allocate: Callable, free: Callable,
                                    get_singleton: Callable,
                                    max_bytes: int = 0x100000) -> int:
    """Model +0x259dbc's verified mode-0 configuration string/reference path.

    Return the output reference address; native X0 is not a semantic result.
    The temporary clone validates key length; scheduling reads the original
    key object through the stack descriptor after clone allocation.
    Empty data/key and invalid cloned key sizes/data multiples create a NULL
    reference with count=1. Padding is ONLY the last byte: values 0..16 trim
    that many bytes, even if preceding padding differs; >16 creates NULL.
    The temporary buffer is freed before reference publication, then the
    temporary key is destroyed. No full TLS/guard/diagnostic OS claim is made.
    """
    objects._string_bound(max_bytes)
    transaction = _PageTransaction(pages)
    stack = entry_stack_address - 0x320
    temporary_key = stack + 0x68
    _write_span(transaction, stack + 0x80, objects._word(mode_address))
    _write_span(transaction, stack + 0x88, objects._word(mode_address)
                + objects._word(key_object_address) + objects._word(iv_object_address))
    key_length = _length(transaction, key_object_address)
    data_length = _length(transaction, data_object_address)
    result_string = 0
    if key_length and data_length:
        objects.clone_string_object(transaction, object_address=temporary_key,
            source_object_address=key_object_address, allocate=allocate,
            image_base=image_base, max_payload_bytes=max_bytes)
        key_length = _length(transaction, temporary_key)
        data_length = _length(transaction, data_object_address)
        if key_length in (16, 24, 32) and not data_length & 15:
            if data_length >= 0x80000000 or data_length > max_bytes:
                raise RefillUnsupported("configuration cipher data exceeds the explicit bound")
            _check_dispatch(transaction, image_base, 0x381CF0, 0x25AA48)
            initialize_cipher_context(transaction, descriptor_address=stack + 0x88,
                context_address=stack + 0xA0, image_base=image_base)
            # Native uses the originally stored key object in its descriptor.
            buffer = objects._allocate(transaction, allocate, data_length)
            checked_forward_copy(transaction, output_address=buffer,
                source_address=_pointer(transaction, data_object_address + 0x10),
                length=data_length, entry_stack_address=stack, get_singleton=get_singleton,
                max_bytes=max_bytes)
            _check_dispatch(transaction, image_base, 0x381CF8, 0x25AB1C)
            cipher.process_cipher_blocks(transaction, mode_descriptor_address=stack + 0x80,
                context_address=stack + 0xA0, source_address=buffer, output_address=buffer,
                length=_length(transaction, data_object_address),
                entry_stack_address=stack, image_base=image_base, max_bytes=max_bytes)
            data_length = _length(transaction, data_object_address)
            if not 0 < data_length <= max_bytes:
                raise RefillUnsupported("configuration data changed beyond the explicit bound")
            padding = _read_span(transaction, buffer + data_length - 1, 1)[0]
            if padding <= 16:
                result_string = objects._allocate(transaction, allocate, 24)
                objects.construct_sized_string_object(transaction, object_address=result_string,
                    source_address=buffer, length=(data_length - padding) & 0xFFFFFFFF,
                    image_base=image_base, allocate=allocate, max_payload_bytes=max_bytes)
            free(transaction, buffer)
        objects.construct_reference_wrapper(transaction, object_address=output_reference_address,
            referenced_address=result_string, allocate=allocate)
        objects.destroy_string_object(transaction, object_address=temporary_key,
            image_base=image_base, free=free)
    else:
        objects.construct_reference_wrapper(transaction, object_address=output_reference_address,
            referenced_address=0, allocate=allocate)
    transaction.commit()
    return output_reference_address
