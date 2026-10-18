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


class _PackedSize:
    """Read-only proto3 size contract, separate from configuration decoding."""
    def __init__(self, pages, max_bytes, max_fields, max_nodes, max_depth, forbidden_ranges):
        self.pages = pages
        self.max_bytes, self.max_fields = max_bytes, max_fields
        self.max_nodes, self.max_depth = max_nodes, max_depth
        self.forbidden = tuple(forbidden_ranges)
        self.fields = self.nodes = self.scanned = 0
        self.active = set()

    def span(self, address, size):
        if (type(address) is not int or type(size) is not int or
                not 0 < address < 1 << 64 or size < 0 or address + size > 1 << 64):
            raise RefillUnsupported('protobuf size address wraps uint64')
        if any(address < end and start < address + size for start, end in self.forbidden):
            raise RefillUnsupported('protobuf size input aliases native spills')

    def read(self, address, size):
        self.span(address, size)
        return _read_span(self.pages, address, size)

    def u(self, address, size=8):
        return int.from_bytes(self.read(address, size), 'little')

    @staticmethod
    def varint(value):
        return max(1, (value.bit_length() + 6) // 7)

    def bounded(self, value):
        if value > self.max_bytes:
            raise RefillUnsupported('protobuf encoded size exceeds explicit byte bound')
        return value

    def string_size(self, pointer):
        length = 0
        while True:
            if self.scanned >= self.max_bytes:
                raise RefillUnsupported('protobuf string scan exceeds explicit byte bound')
            self.scanned += 1
            if not self.u(pointer + length, 1):
                return length
            length += 1

    def message(self, message, depth=0, expected_descriptor=None):
        if depth > self.max_depth or message in self.active:
            raise RefillUnsupported('protobuf size cycle or nesting bound')
        self.nodes += 1
        if self.nodes > self.max_nodes:
            raise RefillUnsupported('protobuf size node bound')
        descriptor = self.u(message)
        if expected_descriptor is not None and descriptor != expected_descriptor:
            raise RefillUnsupported('protobuf nested message descriptor mismatch')
        if self.u(descriptor, 4) != MAGIC:
            raise RefillUnsupported('unsupported protobuf size descriptor magic')
        size = self.u(descriptor + 40)
        if not 24 <= size <= 1 << 20:
            raise RefillUnsupported('unsupported protobuf size message extent')
        self.span(message, size)
        if self.u(message + 8, 4):
            raise RefillUnsupported('protobuf size unknown fields are unsupported')
        count, table = self.u(descriptor + 48, 4), self.u(descriptor + 56)
        self.fields += count
        if self.fields > self.max_fields:
            raise RefillUnsupported('protobuf size field bound')
        if count:
            self.span(table, count * 72)
        fields, tags = [], set()
        for i in range(count):
            at = table + 72 * i
            f = Field(at, *(self.u(at + off, 4) for off in (8, 12, 16, 20, 24)),
                      self.u(at + 32), self.u(at + 40))
            if not 0 < f.tag < 1 << 29 or f.tag in tags:
                raise RefillUnsupported('unsupported protobuf size field tag')
            tags.add(f.tag)
            if f.label != 3 or f.quantifier or f.kind > 16 or self.u(at + 48, 4):
                raise RefillUnsupported('protobuf size supports only singular proto3 fields without flags')
            if f.offset < 24 or f.offset + f.size > size:
                raise RefillUnsupported('protobuf size field outside message')
            fields.append(f)
        self.active.add(message)
        try:
            total = 0
            for f in fields:
                at, kind = message + f.offset, f.kind
                value = self.u(at, 8 if kind == 15 else f.size)
                # Native zero test treats both signs of floating zero as absent.
                zero = value & ((1 << (31 if kind == 10 else 63)) - 1) if kind in (10, 11) else value
                if not zero:
                    continue
                if kind == 14:
                    length = self.string_size(value)
                    if not length:
                        continue
                    payload = length + self.varint(length)
                elif kind == 15:
                    # No payload pointer dereference: this function computes size only.
                    length = self.bounded(value)
                    payload = length + self.varint(length)
                elif kind == 16:
                    length = self.message(value, depth + 1, f.descriptor)
                    payload = length + self.varint(length)
                elif kind in (2, 7, 10):
                    payload = 4
                elif kind in (5, 9, 11):
                    payload = 8
                elif kind == 12:
                    payload = 1
                elif kind in (0, 13):
                    payload = 10 if value & (1 << 31) else self.varint(value)
                elif kind in (1, 4):
                    bits = 32 if kind == 1 else 64
                    signed = value - (1 << bits) if value & (1 << (bits - 1)) else value
                    payload = self.varint((signed << 1) ^ (signed >> (bits - 1)))
                else:
                    payload = self.varint(value)
                total = self.bounded(total + self.varint(f.tag << 3) + payload)
            return total
        finally:
            self.active.remove(message)


def get_packed_size(pages, *, message_address, max_bytes=1 << 20, max_fields=4096,
        max_nodes=1024, max_depth=16, forbidden_ranges=()):
    """Bound +253888 for singular proto3 scalars, bytes, strings and messages.

    Caller supplies relocated descriptors and constructed messages. No native
    output or configuration schema is embedded. Repeated, oneof, unknown-field
    and non-proto3 paths reject. Bytes payloads are not read. Physical stack
    spills are excluded by the callback; no memory is changed by this owner.
    """
    for name, value, upper, lower in (('bytes', max_bytes, 1 << 20, 1),
            ('fields', max_fields, 4096, 1), ('nodes', max_nodes, 1024, 1),
            ('depth', max_depth, 16, 0)):
        if type(value) is not int or not lower <= value <= upper:
            raise RefillUnsupported('invalid protobuf size ' + name + ' bound')
    for region in forbidden_ranges:
        if (not isinstance(region, tuple) or len(region) != 2 or
                any(type(v) is not int for v in region) or not 0 <= region[0] < region[1] <= 1 << 64):
            raise RefillUnsupported('invalid protobuf size forbidden range')
    return _PackedSize(pages, max_bytes, max_fields, max_nodes, max_depth,
                       forbidden_ranges).message(message_address)


class _PackedEncoder(_PackedSize):
    """Encode validated immutable inputs, refusing output/input overlap."""
    def __init__(self, pages, output, width, *bounds):
        super().__init__(pages, *bounds)
        self.output, self.width = output, width

    def span(self, address, size):
        super().span(address, size)
        if self.width and address < self.output + self.width and self.output < address + size:
            raise RefillUnsupported('protobuf pack output aliases message input')

    @staticmethod
    def wire_varint(value):
        result = bytearray()
        while value >= 128:
            result.append((value & 127) | 128)
            value >>= 7
        result.append(value)
        return result

    def encode(self, message, depth=0):
        if depth > self.max_depth or message in self.active:
            raise RefillUnsupported('protobuf pack cycle or nesting bound')
        self.active.add(message)
        try:
            descriptor = self.u(message)
            self.span(descriptor, 64)
            self.span(message, self.u(descriptor + 40))
            count, table = self.u(descriptor + 48, 4), self.u(descriptor + 56)
            if count:
                self.span(table, count * 72)
            output = bytearray()
            for i in range(count):
                at = table + 72 * i
                # Schema acceptance belongs to get_packed_size, called before
                # this read-only pass. No second schema/label/flags policy.
                f = Field(at, *(self.u(at + off, 4) for off in (8, 12, 16, 20, 24)),
                          self.u(at + 32), self.u(at + 40))
                member, kind = message + f.offset, f.kind
                value = self.u(member, 8 if kind == 15 else f.size)
                zero = value & ((1 << (31 if kind == 10 else 63)) - 1) if kind in (10, 11) else value
                if not zero:
                    continue
                if kind == 14:
                    length = self.string_size(value)
                    if not length:
                        continue
                    payload = self.read(value, length)
                elif kind == 15:
                    payload = self.read(self.u(member + 8), value)
                elif kind == 16:
                    payload = self.encode(value, depth + 1)
                elif kind in (2, 7, 10, 5, 9, 11):
                    payload = value.to_bytes(f.size, 'little')
                else:
                    if kind in (0, 13) and value & (1 << 31):
                        value |= ((1 << 32) - 1) << 32
                    elif kind in (1, 4):
                        bits = 32 if kind == 1 else 64
                        signed = value - (1 << bits) if value & (1 << (bits - 1)) else value
                        value = (signed << 1) ^ (signed >> (bits - 1))
                    elif kind == 12:
                        value = int(bool(value))
                    payload = self.wire_varint(value)
                wire = 5 if kind in (2, 7, 10) else 1 if kind in (5, 9, 11) else 2 if kind in (14, 15, 16) else 0
                output.extend(self.wire_varint((f.tag << 3) | wire))
                if wire == 2:
                    output.extend(self.wire_varint(len(payload)))
                output.extend(payload)
                self.bounded(len(output))
            return output
        finally:
            self.active.remove(message)


def pack_message(pages, *, message_address, output_address, max_bytes=1 << 20,
        max_fields=4096, max_nodes=1024, max_depth=16, forbidden_ranges=()):
    """Bound +253d08 using the existing singular proto3 size acceptance owner.

    Caller supplies constructed messages and a separate mapped output buffer.
    Full message/table extents and all accessed input ranges must be separate
    from output. Encode before publication; unmapped output rolls back pages.
    The scalar/string/bytes/nested wire bytes match the native nonalias path.
    """
    forbidden_ranges = tuple(forbidden_ranges)
    p = _PageTransaction(pages)
    width = get_packed_size(p, message_address=message_address, max_bytes=max_bytes,
        max_fields=max_fields, max_nodes=max_nodes, max_depth=max_depth,
        forbidden_ranges=forbidden_ranges)
    encoder = _PackedEncoder(p, output_address, width, max_bytes, max_fields,
                             max_nodes, max_depth, forbidden_ranges)
    _PackedSize.span(encoder, output_address, width)
    payload = encoder.encode(message_address)
    if len(payload) != width:
        raise RefillUnsupported('protobuf packed size and encoder disagree')
    _write_span(p, output_address, payload)
    p.commit()
    return width


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
