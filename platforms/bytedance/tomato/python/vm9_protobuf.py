"""Bounded descriptor-driven Protobuf-C unpack/free for the VM9 configuration.

Read generated defaults and descriptors from the caller's relocated guest ELF.
No native output, private field name, schema constant or payload is embedded.
Supports the three observed configuration descriptors and their scalar, string
and repeated-message/string fields. Unsupported schemas and resource limits
reject transactionally; malformed wire data and allocation NULL follow native
cleanup. Host allocation/free effects are explicit and cannot be rolled back.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from vm9_allocator import RefillUnsupported, _PageTransaction, _read_span, _write_span

MAGIC = 0x28AAEEF9
# Generated immutable initializer templates, read from the provided ELF pages.
_LAYOUTS = {0x350D68: (112, 0x256078, 0x350CF8),
            0x350C80: (56, 0x256054, 0x350C48),
            0x350BD0: (40, 0x256038, 0x350BA8)}


@dataclass(frozen=True)
class Field:
    address: int
    tag: int
    label: int
    kind: int
    quantifier: int
    offset: int
    descriptor: int
    default: int

    @property
    def size(self):
        return 4 if self.kind in (0, 1, 2, 6, 7, 10, 12, 13) else 16 if self.kind == 15 else 8


class _WireFailure(Exception):
    pass


def _varint(raw):
    return sum((value & 127) << (7 * i) for i, value in enumerate(raw))


class _Decoder:
    def __init__(self, pages, base, allocate, free, max_bytes, max_members):
        self.pages, self.base = pages, base
        self.allocate, self.free = allocate, free
        self.max_bytes, self.max_members = max_bytes, max_members

    def read(self, address, size):
        return _read_span(self.pages, address, size)

    def write(self, address, data):
        _write_span(self.pages, address, data)

    def u(self, address, size=8):
        return int.from_bytes(self.read(address, size), 'little')

    def w(self, address, value, size=8):
        self.write(address, (value & ((1 << (size * 8)) - 1)).to_bytes(size, 'little'))

    def alloc(self, size):
        if not 0 <= size <= self.max_bytes:
            raise RefillUnsupported('protobuf allocation exceeds explicit bound')
        pointer = self.allocate(self.pages, size)
        if pointer:
            self.read(pointer, size)
        return pointer

    def release(self, pointer):
        if pointer:
            self.free(self.pages, pointer)

    def schema(self, address):
        layout = _LAYOUTS.get(address - self.base)
        if layout is None or self.u(address, 4) != MAGIC:
            raise RefillUnsupported('unsupported protobuf message descriptor')
        size, initializer, template = layout
        if self.u(address + 40) != size or self.u(address + 88) != self.base + initializer:
            raise RefillUnsupported('unsupported protobuf initialization layout')
        count, table = self.u(address + 48, 4), self.u(address + 56)
        if count > 128:
            raise RefillUnsupported('protobuf required bitmap heap path is not supported')
        fields = []
        for i in range(count):
            at = table + i * 72
            f = Field(at, *(self.u(at + off, 4) for off in (8, 12, 16, 20, 24)),
                      self.u(at + 32), self.u(at + 40))
            if f.label not in (0, 1, 2, 3) or f.kind > 16 or self.u(at + 48, 4):
                raise RefillUnsupported('protobuf packed/oneof/unknown schema is unsupported')
            if f.label == 2 and f.kind not in (14, 16):
                raise RefillUnsupported('protobuf repeated numeric/bytes schema is unsupported')
            if f.offset + f.size > size or (f.quantifier and f.quantifier + (8 if f.label == 2 else 4) > size):
                raise RefillUnsupported('protobuf member is outside the generated message')
            fields.append(f)
        initial = self.read(self.base + template, size)
        if int.from_bytes(initial[:8], 'little') != address:
            raise RefillUnsupported('protobuf template descriptor mismatch')
        return fields, initial

    def free_message(self, message, depth=0):
        if not message:
            return
        if depth > 16:
            raise RefillUnsupported('protobuf cleanup exceeds nesting bound')
        fields, _ = self.schema(self.u(message))
        self.w(message, 0)
        for f in fields:
            at = message + f.offset
            if f.label == 2:
                count, array = self.u(message + f.quantifier), self.u(at)
                if count > self.max_members:
                    raise RefillUnsupported('protobuf cleanup exceeds repeated bound')
                if array:
                    for i in range(count):
                        if f.kind == 14:
                            self.release(self.u(array + i * 8))
                        elif f.kind == 16:
                            self.free_message(self.u(array + i * 8), depth + 1)
                    self.release(array)
            elif f.kind == 14:
                value = self.u(at)
                if value and value != f.default:
                    self.release(value)
            elif f.kind == 15:
                value = self.u(at + 8)
                if value and (not f.default or value != self.u(f.default + 8)):
                    self.release(value)
            elif f.kind == 16:
                value = self.u(at)
                if value and value != f.default:
                    self.free_message(value, depth + 1)
        count, unknown = self.u(message + 8, 4), self.u(message + 16)
        if count > self.max_members:
            raise RefillUnsupported('protobuf unknown-field cleanup exceeds bound')
        for i in range(count):
            self.release(self.u(unknown + i * 24 + 16))
        if unknown:
            self.release(unknown)
        self.release(message)

    def member(self, f, message, wire, pointer, length, prefix, depth):
        at = message + f.offset
        if f.label == 2:
            count = self.u(message + f.quantifier)
            at = self.u(at) + f.size * count
        raw = self.read(pointer, length)
        kind = f.kind
        if kind in (0, 1, 3, 4, 6, 8, 13):
            if wire != 0:
                return False
            bits = 32 if f.size == 4 else 64
            value = _varint(raw) & ((1 << bits) - 1)
            if kind in (1, 4):
                value = (value >> 1) ^ -(value & 1)
            self.w(at, value, f.size)
        elif kind in (2, 7, 10, 5, 9, 11):
            if wire != (5 if f.size == 4 else 1):
                return False
            self.write(at, raw)
        elif kind == 12:
            # Protobuf-C accepts any scanned wire type for BOOL.
            self.w(at, int(any(value & 127 for value in raw)), 4)
        elif kind == 14:
            if wire != 2:
                return False
            if f.label != 2:
                previous = self.u(at)
                if previous and previous != f.default:
                    self.release(previous)
            value = self.alloc(length - prefix + 1)
            self.w(at, value)
            if not value:
                return False
            self.write(value, self.read(pointer + prefix, length - prefix) + b'\0')
        elif kind == 15:
            if wire != 2:
                return False
            previous = self.u(at + 8)
            if previous and (not f.default or previous != self.u(f.default + 8)):
                self.release(previous)
            value = self.alloc(length - prefix) if length > prefix else 0
            self.w(at + 8, value)
            if length > prefix and not value:
                return False
            if value:
                self.write(value, self.read(pointer + prefix, length - prefix))
            self.w(at, length - prefix)
        elif kind == 16:
            if wire != 2:
                return False
            if f.label != 2 and self.u(at) not in (0, f.default):
                raise RefillUnsupported('singular protobuf message merge is unsupported')
            value = self.unpack(f.descriptor, pointer + prefix, length - prefix, depth + 1)
            self.w(at, value)
            if not value:
                return False
        else:
            raise RefillUnsupported('unsupported protobuf scalar')
        if f.label == 2:
            self.w(message + f.quantifier, count + 1)
        elif f.label in (1, 3) and f.quantifier:
            self.w(message + f.quantifier, 1, 4)
        return True

    def unpack(self, descriptor, data, length, depth=0):
        if depth > 16 or length > self.max_bytes:
            raise RefillUnsupported('protobuf input exceeds explicit bound')
        fields, initial = self.schema(descriptor)
        message = self.alloc(len(initial))
        if not message:
            return 0
        self.write(message, initial)
        by_tag = {f.tag: f for f in fields}
        scanned, seen = [], set()
        cursor, end = data, data + length
        unknown_count = 0
        try:
            while cursor < end:
                first = self.u(cursor, 1)
                if not first & 0xF8:
                    raise _WireFailure()
                wire, tag, shift = first & 7, (first & 127) >> 3, 4
                cursor += 1
                if first & 128:
                    for _ in range(4):
                        if cursor >= end:
                            raise _WireFailure()
                        byte = self.u(cursor, 1); cursor += 1
                        tag = (tag | ((byte & 127) << shift)) & 0xFFFFFFFF
                        if not byte & 128:
                            break
                        shift += 7
                    else:
                        raise _WireFailure()
                pointer, prefix = cursor, 0
                if wire == 0:
                    for _ in range(min(10, end - cursor)):
                        byte = self.u(cursor, 1); cursor += 1
                        if not byte & 128:
                            break
                    else:
                        raise _WireFailure()
                elif wire in (1, 5):
                    cursor += 8 if wire == 1 else 4
                    if cursor > end:
                        raise _WireFailure()
                elif wire == 2:
                    width = 0
                    for i in range(min(5, end - cursor)):
                        byte = self.u(cursor, 1); cursor += 1
                        width |= (byte & 127) << (i * 7)
                        if not byte & 128:
                            break
                    else:
                        raise _WireFailure()
                    prefix = cursor - pointer
                    if width > 0x7FFFFFFF or cursor + width > end:
                        raise _WireFailure()
                    cursor += width
                else:
                    raise _WireFailure()
                if len(scanned) >= self.max_members:
                    raise RefillUnsupported('protobuf scanned-member bound exceeded')
                # 16 members fit the native stack; heap slabs need stack padding
                # provenance before their whole-buffer effects can be modeled.
                if len(scanned) >= 16:
                    raise RefillUnsupported('protobuf heap scanned-member slab is unsupported')
                f = by_tag.get(tag)
                if f is None:
                    unknown_count += 1
                else:
                    seen.add(f.tag)
                    if f.label == 2:
                        self.w(message + f.quantifier, self.u(message + f.quantifier) + 1)
                scanned.append((tag, wire, f, pointer, cursor - pointer, prefix))
        except _WireFailure:
            self.release(message)
            return 0
        for i, f in enumerate(fields):
            if f.label == 2:
                at = message + f.quantifier
                count = self.u(at)
                if count:
                    self.w(at, 0)
                    array = self.alloc(f.size * count)
                    if not array:
                        for rest in fields[i + 1:]:
                            if rest.label == 2:
                                self.w(message + rest.quantifier, 0)
                        self.free_message(message, depth)
                        return 0
                    self.w(message + f.offset, array)
            elif f.label == 0 and not f.default and f.tag not in seen:
                for rest in fields[i + 1:]:
                    if rest.label == 2:
                        self.w(message + rest.quantifier, 0)
                self.free_message(message, depth)
                return 0
        if unknown_count:
            unknown = self.alloc(unknown_count * 24)
            self.w(message + 16, unknown)
            if not unknown:
                self.free_message(message, depth)
                return 0
        for tag, wire, f, pointer, size, prefix in scanned:
            if f is None:
                index = self.u(message + 8, 4)
                self.w(message + 8, index + 1, 4)
                at = self.u(message + 16) + index * 24
                self.w(at, tag, 4); self.w(at + 4, wire, 4); self.w(at + 8, size)
                value = self.alloc(size)
                self.w(at + 16, value)
                ok = bool(value)
                if ok:
                    self.write(value, self.read(pointer, size))
            else:
                ok = self.member(f, message, wire, pointer, size, prefix, depth)
            if not ok:
                self.free_message(message, depth)
                return 0
        return message


def _bounds(max_bytes, max_members):
    if not isinstance(max_bytes, int) or not 0 <= max_bytes <= 0x100000:
        raise ValueError('invalid protobuf byte bound')
    if not isinstance(max_members, int) or not 0 <= max_members <= 0x10000:
        raise ValueError('invalid protobuf member bound')


def unpack_configuration_message(pages, *, data_address: int, length: int,
        image_base: int, allocate: Callable, free: Callable, allocator_address: int = 0,
        descriptor_address: int = 0, max_bytes: int = 0x100000, max_members: int = 16) -> int:
    """Model +0x256088 / +0x254330 for the default allocator and known schemas."""
    _bounds(max_bytes, max_members)
    if not isinstance(length, int) or not 0 <= length <= max_bytes:
        raise RefillUnsupported('protobuf length exceeds explicit input bound')
    if allocator_address not in (0, image_base + 0x381BF0):
        raise RefillUnsupported('custom protobuf allocator is unsupported')
    transaction = _PageTransaction(pages)
    decoder = _Decoder(transaction, image_base, allocate, free, max_bytes, max_members)
    _read_span(transaction, data_address, length)
    allocator = image_base + 0x381BF0
    if decoder.u(allocator) != image_base + 0x255324 or decoder.u(allocator + 8) != image_base + 0x25532C or decoder.u(allocator + 16):
        raise RefillUnsupported('default protobuf allocator has changed')
    result = decoder.unpack(descriptor_address or image_base + 0x350D68, data_address, length)
    transaction.commit()
    return result


def free_configuration_message(pages, *, message_address: int, image_base: int,
        free: Callable, max_bytes: int = 0x100000, max_members: int = 16) -> None:
    """Model +0x2550cc recursive free with generated defaults retained."""
    _bounds(max_bytes, max_members)
    transaction = _PageTransaction(pages)
    decoder = _Decoder(transaction, image_base, None, free, max_bytes, max_members)
    decoder.free_message(message_address)
    transaction.commit()
