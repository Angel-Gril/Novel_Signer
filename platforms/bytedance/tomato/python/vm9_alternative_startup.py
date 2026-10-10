"""B short descriptor selection, factory XOR and bounded reader sections.

The module root/array/hash buckets are explicit inputs. Native factory and
publication observations are verified separately; independent Python factory
+0x2cbdc8, constructor input generation and complete B VM remain open.
Reader sections 0 (generic), 1, 3, 7, 8 and 12, plus opted-in section 2
imports, section 4/5/6 definitions, section 9 empty element vectors,
section 10 code words and section 11 data segments, run with explicit
status-only callbacks.
Opted-in special custom handlers parse metadata. Recovered actual AST callbacks,
including imports/exports and owned output cleanup, have separate bounded APIs.
A bounded module wrapper composes these sections with real AST callbacks and
parser/callback cleanup, including the complete actual ELF module. Nonempty
element vectors and independent factory remain open.
Unsupported branches fail closed.
"""
from __future__ import annotations
from dataclasses import dataclass
from vm9_allocator import RefillUnsupported, _PageTransaction, _read_span, _write_span

MASK64=(1<<64)-1


def hash_short_descriptor_name(payload):
    """Actual +0x2aa744 length 0..8 branches, including its uint32 LSL.

    The 4..8 branch truncates first_u32 << 3 to uint32 before adding length;
    replacing it with an unbounded or uint64 shift changes high-bit inputs.
    This is the recovered function's hash, not a full std::hash API.
    """
    if not isinstance(payload,(bytes,bytearray)) or len(payload)>8:
        raise RefillUnsupported('descriptor hash supports only 0..8 byte inputs')
    length=len(payload);k2=0x9AE16A3B2F90404F
    if not length:return k2
    if length<4:
        first,middle,last=payload[0],payload[length//2],payload[-1]
        value=(((first | (middle<<8))*k2)&MASK64) ^ (((length+(last<<2))*0xC949D7C7509E6557)&MASK64)
        return ((value ^ (value>>47))*k2)&MASK64
    first=int.from_bytes(payload[:4],'little');last=int.from_bytes(payload[-4:],'little')
    multiplier=0x9DDFEA08EB382D69
    a=length+((first<<3)&0xFFFFFFFF)
    mixed=((a^last)*multiplier)&MASK64
    mixed=((last^mixed^(mixed>>47))*multiplier)&MASK64
    return ((mixed^(mixed>>47))*multiplier)&MASK64


def _u(p,a,n=8):return int.from_bytes(_read_span(p,a,n),'little')


def convert_parser_instruction_word(pages, *, source_codec_address,
        target_codec_address, word, max_fields=1024):
    """Actual +0x2db778 instruction-format conversion, without page writes.

    Each 24-byte codec record has two compared header bytes, an ignored XOR
    byte, a triples pointer at +8 and a uint32 field count at +16. Each source
    triple selects a target triple and supplies a source shift and width.
    The target triple's second byte supplies its destination shift. Native
    indexed reads are not constrained by the target's declared field count;
    every used byte must nevertheless be mapped. The explicit count budget
    bounds traversal. Bytes +2..+7 and +20..+23 do not affect conversion.

    Matching headers/triples return the original word. Otherwise byte +1
    rotates the word, followed by the native scalar or SIMD bit operations.
    SIMD consumes complete groups of eight; remaining fields use scalar
    shifts modulo 32. This distinction matters for zero widths and other
    unusual field bytes. No catalog initialization or function parsing is
    performed here, and native snapshots are not inputs.
    """
    for address in (source_codec_address,target_codec_address):
        if type(address) is not int or not 0<address<=MASK64-23:
            raise RefillUnsupported('parser codec record is outside the guest ABI')
    if type(word) is not int or not 0<=word<=0xFFFFFFFF:
        raise RefillUnsupported('parser instruction must be a uint32')
    if type(max_fields) is not int or not 0<=max_fields<=0xFFFFFFFF:
        raise RefillUnsupported('parser codec field budget is invalid')
    source_count=_u(pages,source_codec_address+16,4)
    target_count=_u(pages,target_codec_address+16,4)
    if source_count>max_fields or target_count>max_fields:
        raise RefillUnsupported('parser codec field count exceeds the budget')

    def field_byte(pointer,index,offset):
        address=pointer+index*3+offset
        if not pointer or address>MASK64:
            raise RefillUnsupported('parser codec triples address is null or overflows')
        return _u(pages,address,1)

    source_pointer=target_pointer=None
    if source_count:
        source_pointer=_u(pages,source_codec_address+8)
        target_pointer=_u(pages,target_codec_address+8)
    same=source_count==target_count
    if same:
        for index in range(source_count):
            for offset in range(3):
                if field_byte(source_pointer,index,offset)!=field_byte(target_pointer,index,offset):
                    same=False;break
            if not same:break
        if same and (_u(pages,source_codec_address,1)==_u(pages,target_codec_address,1)
                and _u(pages,source_codec_address+1,1)==_u(pages,target_codec_address+1,1)):
            return word
    rotation=_u(pages,source_codec_address+1,1)&31
    rotated=((word<<rotation)|(word>>((-rotation)&31)))&0xFFFFFFFF
    result=0;vector_fields=source_count&~7

    def vector_shift(value,shift):
        shift=((shift+128)&255)-128
        if not -32<shift<32:return 0
        return ((value<<shift)&0xFFFFFFFF) if shift>=0 else value>>-shift

    for index in range(source_count):
        selected=field_byte(source_pointer,index,0)
        source_shift=field_byte(source_pointer,index,1)
        width=field_byte(source_pointer,index,2)
        target_shift=field_byte(target_pointer,selected,1)
        if index<vector_fields:
            mask=vector_shift(0xFFFFFFFF,32-width)
            value=vector_shift(rotated,32-source_shift-width)
            result|=vector_shift(value&mask,-(32-target_shift-width))
        else:
            mask=(0xFFFFFFFF<<((32-width)&31))&0xFFFFFFFF
            value=(rotated<<((32-source_shift-width)&31))&0xFFFFFFFF
            result|=(value&mask)>>((32-width-target_shift)&31)
    return result


@dataclass(frozen=True)
class ReaderVaruint32Result:
    bytes_consumed: int
    value: int | None
    output_written: bool


def read_reader_varuint32(pages, *, start_address, end_address, output_address):
    """Actual +0x324870 bounded u32 helper, including failure-side writes.

    Accept redundant encodings through five bytes. A terminating fifth byte
    above 0x0f returns zero without accessing the output pointer; value is then
    None. Truncation or five continuation bytes returns zero and writes zero.
    This primitive does not parse sections or construct reader nodes/ASTs.
    """
    if any(not isinstance(address, int) or not 0 <= address <= MASK64
           for address in (start_address, end_address, output_address)):
        raise RefillUnsupported('reader u32 helper requires uint64 addresses')
    p = _PageTransaction(pages)
    value = 0
    consumed = 0
    for index in range(5):
        address = start_address + index
        if address >= end_address:
            value = 0
            break
        byte = _read_span(p, address, 1)[0]
        if byte < 128:
            if index == 4 and byte > 15:
                return ReaderVaruint32Result(0, None, False)
            value |= byte << (index * 7)
            consumed = index + 1
            break
        value |= (byte & 127) << (index * 7)
    if not consumed:
        value = 0
    if not output_address or output_address > MASK64 - 3:
        raise RefillUnsupported('reader u32 output word address overflows or is null')
    _write_span(p, output_address, value.to_bytes(4, 'little'))
    p.commit()
    return ReaderVaruint32Result(consumed, value, True)


@dataclass(frozen=True)
class ReaderVaruint64Result:
    bytes_consumed: int
    value: int | None
    output_written: bool


def read_reader_varuint64(pages, *, start_address, end_address, output_address):
    """Actual +0x3249b0 u64 reader, with distinct failure-side writes.

    Redundant encodings through ten bytes are accepted. A terminating tenth
    byte above 1 preserves output without accessing it. Missing termination
    returns zero and clears the output word. The scan cannot wrap uint64.
    """
    if any(not isinstance(address, int) or not 0 <= address <= MASK64
           for address in (start_address, end_address, output_address)):
        raise RefillUnsupported('reader u64 helper requires uint64 addresses')
    if start_address > MASK64-9:
        raise RefillUnsupported('reader u64 scan address wraps the bounded guest ABI')
    p = _PageTransaction(pages)
    value, consumed = 0, 0
    for index in range(10):
        address = start_address+index
        if address >= end_address:
            break
        byte = _read_span(p, address, 1)[0]
        if byte < 128:
            if index == 9 and byte > 1:
                return ReaderVaruint64Result(0, None, False)
            value |= byte << (index*7)
            consumed = index+1
            break
        value |= (byte & 127) << (index*7)
    if not consumed:
        value = 0
    if not output_address or output_address > MASK64-7:
        raise RefillUnsupported('reader u64 output word address overflows or is null')
    _write_span(p, output_address, value.to_bytes(8, 'little'))
    p.commit()
    return ReaderVaruint64Result(consumed, value, True)


@dataclass(frozen=True)
class ReaderVarint32Result:
    bytes_consumed: int
    value: int | None
    output_written: bool


def read_reader_varint32(pages, *, start_address, end_address, output_address):
    """Actual +0x324e0c signed word reader, preserving output on failure.

    Accept redundant encodings through five bytes. A fifth terminator must
    be 0x00..0x07 or 0x78..0x7f, with the upper bits extending its sign.
    Missing/invalid termination returns zero without accessing output.
    The bounded ABI excludes input pointers whose five-byte scan wraps.
    """
    if any(not isinstance(address, int) or not 0 <= address <= MASK64
           for address in (start_address, end_address, output_address)):
        raise RefillUnsupported('reader i32 helper requires uint64 addresses')
    if start_address > MASK64 - 4:
        raise RefillUnsupported('reader i32 scan address wraps the bounded guest ABI')
    p = _PageTransaction(pages)
    bits = 0
    for index in range(5):
        address = start_address + index
        if address >= end_address:
            return ReaderVarint32Result(0, None, False)
        byte = _read_span(p, address, 1)[0]
        bits |= (byte & 127) << (index * 7)
        if byte & 128:
            continue
        if index == 4 and not (byte <= 7 or byte >= 0x78):
            return ReaderVarint32Result(0, None, False)
        if byte & 64:
            bits |= -(1 << ((index + 1) * 7))
        bits &= 0xFFFFFFFF
        if not output_address or output_address > MASK64 - 3:
            raise RefillUnsupported('reader i32 output word address overflows or is null')
        _write_span(p, output_address, bits.to_bytes(4, 'little'))
        p.commit()
        value = bits if bits < 0x80000000 else bits - (1 << 32)
        return ReaderVarint32Result(index + 1, value, True)
    return ReaderVarint32Result(0, None, False)


@dataclass(frozen=True)
class ReaderVarint64Result:
    bytes_consumed: int
    value: int | None
    output_written: bool


def read_reader_varint64(pages, *, start_address, end_address, output_address):
    """Actual +0x324f6c signed64 helper, preserving unused output on failure.

    Redundant encodings through ten bytes are accepted. The tenth terminator
    must be 0 or 127. Truncation, ten continuations and invalid termination
    return zero without accessing output. The scan cannot wrap uint64.
    """
    if any(not isinstance(address, int) or not 0 <= address <= MASK64
           for address in (start_address, end_address, output_address)):
        raise RefillUnsupported('reader i64 helper requires uint64 addresses')
    if start_address > MASK64-9:
        raise RefillUnsupported('reader i64 scan address wraps the bounded guest ABI')
    p = _PageTransaction(pages)
    bits = 0
    for index in range(10):
        address = start_address+index
        if address >= end_address:
            return ReaderVarint64Result(0, None, False)
        byte = _read_span(p, address, 1)[0]
        bits |= (byte & 127) << (index*7)
        if byte & 128:
            continue
        if index == 9 and byte not in (0, 127):
            return ReaderVarint64Result(0, None, False)
        if byte & 64:
            bits |= -(1 << ((index+1)*7))
        bits &= MASK64
        if not output_address or output_address > MASK64-7:
            raise RefillUnsupported('reader i64 output word address overflows or is null')
        _write_span(p, output_address, bits.to_bytes(8, 'little'))
        p.commit()
        value = bits if bits < (1 << 63) else bits-(1 << 64)
        return ReaderVarint64Result(index+1, value, True)
    return ReaderVarint64Result(0, None, False)


@dataclass(frozen=True)
class ReaderVectorEffect:
    kind: str
    address: int
    size: int
    vector_address: int
    vector_words: tuple[int, int, int]


@dataclass(frozen=True)
class ReaderVectorResult:
    begin: int
    end: int
    capacity_end: int
    effects: tuple[ReaderVectorEffect, ...]


def _reader_vector_words(pages, address, max_elements, reserved_regions=()):
    if (not isinstance(address, int) or not 0 < address <= MASK64-23
            or address & 7 or not isinstance(max_elements, int)
            or not 1 <= max_elements <= 65536):
        raise RefillUnsupported('reader vector header or capacity bound is invalid')
    begin, end, capacity_end = (_u(pages, address+offset) for offset in (0, 8, 16))
    if (not 0 <= begin <= end <= capacity_end <= MASK64
            or (begin | end | capacity_end) & 7 or (not begin and capacity_end)
            or (capacity_end-begin)//8 > max_elements):
        raise RefillUnsupported('reader vector requires coherent bounded word pointers')
    for start, stop in ((address, address+24), *reserved_regions):
        if begin < stop and start < capacity_end:
            raise RefillUnsupported('reader vector storage overlaps retained state')
    _read_span(pages, begin, capacity_end-begin)
    return begin, end, capacity_end


def grow_reader_word_vector(pages, *, vector_address, additional_count,
        allocate=None, max_elements=4096, reserved_regions=()):
    """Bounded +0x324540 append, with pure allocation planning and free effects.

    allocate(size) returns an aligned pointer into already mapped pages; it
    must not mutate memory or perform real allocation. Reallocation publishes
    begin/end/capacity before recording the old block's free effect. Free does
    not poison or unmap pages. Exception/allocator boot paths remain unsupported.
    This native void helper's incidental X0 return value is not an API result.
    """
    p = _PageTransaction(pages)
    reserved_regions = tuple(reserved_regions)
    if any(not isinstance(start, int) or not isinstance(stop, int)
           or not 0 <= start <= stop <= MASK64+1 for start, stop in reserved_regions):
        raise RefillUnsupported('reader vector retained regions are invalid')
    begin, end, capacity_end = _reader_vector_words(
        p, vector_address, max_elements, reserved_regions)
    size, capacity = (end-begin)//8, (capacity_end-begin)//8
    if (not isinstance(additional_count, int) or additional_count < 0
            or size+additional_count > max_elements):
        raise RefillUnsupported('reader vector append exceeds the element bound')
    effects = []
    if additional_count <= capacity-size:
        _write_span(p, end, bytes(additional_count*8))
        end += additional_count*8
        _write_span(p, vector_address+8, end.to_bytes(8, 'little'))
    else:
        new_capacity = max(size+additional_count, capacity*2)
        if new_capacity > max_elements or not callable(allocate):
            raise RefillUnsupported('reader vector needs a bounded explicit allocation service')
        new_begin = allocate(new_capacity*8)
        if (not isinstance(new_begin, int) or not 0 < new_begin <= MASK64-new_capacity*8
                or new_begin & 7):
            raise RefillUnsupported('reader vector allocation pointer is invalid')
        new_capacity_end = new_begin+new_capacity*8
        for start, stop in ((vector_address, vector_address+24),
                            (begin, capacity_end), *reserved_regions):
            if new_begin < stop and start < new_capacity_end:
                raise RefillUnsupported('reader vector allocation overlaps retained storage')
        _read_span(p, new_begin, new_capacity*8)
        effects.append(ReaderVectorEffect('allocate', new_begin, new_capacity*8,
                                         vector_address, (begin, end, capacity_end)))
        _write_span(p, new_begin+size*8, bytes(additional_count*8))
        _write_span(p, new_begin, _read_span(p, begin, size*8))
        new_end = new_begin+(size+additional_count)*8
        _write_span(p, vector_address, b''.join(value.to_bytes(8, 'little')
                    for value in (new_begin, new_end, new_capacity_end)))
        if begin:
            effects.append(ReaderVectorEffect('free', begin, capacity*8,
                vector_address, (new_begin, new_end, new_capacity_end)))
        begin, end, capacity_end = new_begin, new_end, new_capacity_end
    p.commit()
    return ReaderVectorResult(begin, end, capacity_end, tuple(effects))


@dataclass(frozen=True)
class ReaderCallbackEvent:
    slot_offset: int
    arguments: tuple[int, ...]
    cursor: int
    section_end: int
    type_vectors: tuple[tuple[int, ...], ...] = ()
    import_counts: tuple[int, ...] = ()
    import_limits: tuple[int, ...] = ()


@dataclass(frozen=True)
class ReaderSectionsResult:
    status: int
    cursor: int
    last_section: int
    sections_entered: tuple[int, ...]
    callback_events: tuple[ReaderCallbackEvent, ...]
    vector_effects: tuple[ReaderVectorEffect, ...] = ()


class _ReaderParseFailure(Exception):
    pass


@dataclass(frozen=True)
class ReaderAstEffect:
    kind: str
    address: int
    size: int
    owner_address: int
    owner_bytes: bytes


@dataclass(frozen=True)
class ReaderAstResult:
    status: int | None
    effects: tuple[ReaderAstEffect, ...]


_AST_NODE_TABLES = {0x3724F0: (64, 0x321260), 0x372518: (48, 0x321368),
                    0x372540: (40, 0x321368), 0x372568: (24, 0x321368),
                    0x372590: (40, 0x321308)}


class _ReaderAstMemory:
    """One transaction and ownership graph for the recovered native objects."""
    def __init__(self, pages, base, root, width, max_nodes, max_vector_bytes, reserved):
        if (not isinstance(base, int) or not 0 < base <= MASK64-0x400000 or base & 4095
                or not isinstance(max_nodes, int) or not 1 <= max_nodes <= 65536
                or not isinstance(max_vector_bytes, int) or not 1 <= max_vector_bytes <= 16*1024*1024):
            raise RefillUnsupported('AST image or resource bounds are invalid')
        self.p = _PageTransaction(pages)
        self.base, self.root, self.width = base, root, width
        self.max_nodes, self.max_bytes = max_nodes, max_vector_bytes
        self.regions, self.pointers, self.effects, self.nodes = [], set(), [], 0
        self.reserved = [(base, base+0x400000)]
        for start, stop in reserved:
            if (not isinstance(start, int) or not isinstance(stop, int)
                    or not 0 <= start <= stop <= MASK64+1):
                raise RefillUnsupported('AST retained region is invalid')
            self.reserved.append((start, stop))

    def claim(self, address, size, *, alignment=8):
        if (not isinstance(address, int) or not 0 < address <= MASK64-size
                or address & (alignment-1) or address in self.pointers):
            raise RefillUnsupported('AST storage pointer is invalid or shared')
        for begin, end in (*self.reserved, *self.regions):
            if (address < end and begin < address+size) or begin <= address < end:
                raise RefillUnsupported('AST owned storage overlaps retained memory')
        # A nonnull zero-capacity pointer can still reach free. Require its
        # address to be mapped even though the owned byte span is empty.
        _read_span(self.p, address, max(size, 1))
        self.pointers.add(address); self.regions.append((address, address+size))

    def vector(self, address, stride=1, *, own=True):
        begin, end, cap = (_u(self.p, address+offset) for offset in (0, 8, 16))
        if (not 0 <= begin <= end <= cap <= MASK64 or (not begin and cap)
                or begin & 7 or (end-begin) % stride or (cap-begin) % stride
                or cap-begin > self.max_bytes):
            raise RefillUnsupported('AST vector has invalid or unbounded pointers')
        if begin:
            if own: self.claim(begin, cap-begin)
            else: _read_span(self.p, begin, cap-begin)
        return begin, end, cap

    def node(self, address, stride):
        self.nodes += 1
        if self.nodes > self.max_nodes:
            raise RefillUnsupported('AST node bound reached')
        table = _u(self.p, address)-self.base
        if table not in _AST_NODE_TABLES or _AST_NODE_TABLES[table][0] != stride:
            raise RefillUnsupported('AST node vtable is unsupported')
        if _u(self.p, self.base+table) != self.base+_AST_NODE_TABLES[table][1]:
            raise RefillUnsupported('AST node destructor relocation is unsupported')
        if table == 0x3724F0:
            self.vector(address+0x10, 8); self.vector(address+0x28, 8)
        elif table == 0x372590:
            self.vector(address+0x10, 8)

    def tree(self, root):
        # Native postorder is left, right, payload, node. A stack avoids host
        # recursion limits; claiming nodes rejects cycles and shared subtrees.
        pending = [(root, False)]; order = []
        while pending:
            address, visited = pending.pop()
            if not address: continue
            if visited:
                order.append(address); continue
            self.nodes += 1
            if self.nodes > self.max_nodes:
                raise RefillUnsupported('AST tree node bound reached')
            self.claim(address, 64); self.vector(address+0x28, 4)
            pending.extend(((address, True), (_u(self.p, address+8), False),
                            (_u(self.p, address), False)))
        return order

    def fixup_tree(self, header, order):
        """Validate the libc++ links before +32000c can erase a keyed node."""
        root, sentinel = _u(self.p,header+8), header+8
        if _u(self.p,header+16) != len(order):
            raise RefillUnsupported('AST fixup tree count is inconsistent')
        if not root:
            if _u(self.p,header) != sentinel:
                raise RefillUnsupported('AST empty fixup tree begin is inconsistent')
            return
        if _u(self.p,root+0x10) != sentinel or _u(self.p,root+0x18,1) != 1:
            raise RefillUnsupported('AST fixup tree root is invalid')
        heights, ranges = {0:0}, {}
        for node in order:
            left,right = _u(self.p,node),_u(self.p,node+8)
            key,black = _u(self.p,node+0x20,4),_u(self.p,node+0x18,1)
            if black not in (0,1) or heights[left] != heights[right]:
                raise RefillUnsupported('AST fixup tree colors or black heights are invalid')
            for child in (left,right):
                if child and (_u(self.p,child+0x10) != node
                        or not black and not _u(self.p,child+0x18,1)):
                    raise RefillUnsupported('AST fixup tree parent or red links are invalid')
            if left and ranges[left][1] >= key or right and ranges[right][0] <= key:
                raise RefillUnsupported('AST fixup tree keys are unordered or duplicated')
            ranges[node] = (ranges[left][0] if left else key,ranges[right][1] if right else key)
            heights[node] = heights[left]+black
        first = root
        while _u(self.p,first): first = _u(self.p,first)
        if _u(self.p,header) != first:
            raise RefillUnsupported('AST fixup tree begin is inconsistent')

    def erase_fixup(self, root, node):
        """Actual +2695c0 links/colors, including the erased node's stale bytes."""
        def read(address): return _u(self.p,address)
        def put(address,value): _write_span(self.p,address,value.to_bytes(8,'little'))
        def black(address): return not address or bool(_u(self.p,address+0x18,1))
        def paint(address,color): _write_span(self.p,address+0x18,bytes([color]))
        def rotate(address,left):
            nonlocal root
            outer,inner = (8,0) if left else (0,8)
            other = read(address+outer); child = read(other+inner)
            put(address+outer,child)
            if child: put(child+0x10,address)
            parent = read(address+0x10); put(other+0x10,parent)
            put(parent+(0 if read(parent)==address else 8),other)
            put(other+inner,address); put(address+0x10,other)
            if root == address: root = other
        removed = node
        if read(node) and read(node+8):
            removed = read(node+8)
            while read(removed): removed = read(removed)
        child = read(removed) or read(removed+8)
        parent = read(removed+0x10)
        if child: put(child+0x10,parent)
        if read(parent) == removed:
            put(parent,child)
            if removed == root: sibling,root = 0,child
            else: sibling = read(parent+8)
        else:
            put(parent+8,child); sibling = read(parent)
        removed_black = black(removed)
        if removed != node:
            parent = read(node+0x10); put(removed+0x10,parent)
            put(parent+(0 if read(parent)==node else 8),removed)
            left,right = read(node),read(node+8)
            put(left+0x10,removed); put(removed,left); put(removed+8,right)
            if right: put(right+0x10,removed)
            if root == node: root = removed
            paint(removed,int(black(node)))
        if not removed_black or not root: return
        if child:
            paint(child,1); return
        for _ in range(self.max_nodes+1):
            parent = read(sibling+0x10)
            right_sibling = read(parent) != sibling
            near,far = (0,8) if right_sibling else (8,0)
            if not black(sibling):
                paint(sibling,1); paint(parent,0); rotate(parent,right_sibling)
                sibling = read(parent+far)
            if black(read(sibling+near)) and black(read(sibling+far)):
                paint(sibling,0); parent = read(sibling+0x10)
                if parent == root or not black(parent):
                    paint(parent,1); return
                grand = read(parent+0x10)
                sibling = read(grand+(8 if read(grand)==parent else 0))
                continue
            if black(read(sibling+far)):
                paint(read(sibling+near),1); paint(sibling,0)
                rotate(sibling,not right_sibling)
                sibling = read(sibling+0x10)
            parent = read(sibling+0x10)
            paint(sibling,int(black(parent))); paint(parent,1); paint(read(sibling+far),1)
            rotate(parent,right_sibling); return
        raise RefillUnsupported('AST fixup tree erase exceeds its node bound')

    def grow_bytes(self, header, length, service):
        begin,end,cap = self.vector(header,own=False)
        size,capacity = end-begin,cap-begin
        if not size <= length <= self.max_bytes:
            raise RefillUnsupported('AST fixup raw buffer growth is unbounded')
        if length > capacity:
            new_capacity = max(length,capacity*2)
            new = self.allocate(new_capacity,service)
            _write_span(self.p,new+size,bytes(length-size))
            _write_span(self.p,new,_read_span(self.p,begin,size))
            self.publish(header,(new,new+length,new+new_capacity))
            if begin: self.emit('free',begin,capacity)
        else:
            _write_span(self.p,end,bytes(length-size))
            _write_span(self.p,header+8,(begin+length).to_bytes(8,'little'))

    def apply_fixup(self, header, order, key, service):
        """Actual +32000c: patch one key's raw positions, then erase/free it."""
        self.fixup_tree(header,order)
        root = _u(self.p,header+8); node = root; found = 0
        while node:
            value = _u(self.p,node+0x20,4)
            if value >= key: found,node = node,_u(self.p,node)
            else: node = _u(self.p,node+8)
        if found and _u(self.p,found+0x20,4) == key:
            payload,stop,_ = self.vector(found+0x28,4,own=False)
            raw_header = self.root+0x108
            for position in range(payload,stop,4):
                offset = _u(self.p,position,4)
                if offset > self.max_bytes-4:
                    raise RefillUnsupported('AST fixup offset exceeds the byte bound')
                # All fixups in callbacks target the output's shared raw vector.
                raw_begin,raw_end,_ = self.vector(raw_header,own=False)
                size = raw_end-raw_begin
                if size < offset+4:
                    self.grow_bytes(raw_header,offset+4,service)
                    raw_begin = _u(self.p,raw_header)
                _write_span(self.p,raw_begin+offset,(size&0xFFFFFFFF).to_bytes(4,'little'))
            right = _u(self.p,found+8)
            if right:
                successor = right
                while _u(self.p,successor): successor = _u(self.p,successor)
            else:
                child = found; successor = _u(self.p,child+0x10)
                while _u(self.p,successor) != child:
                    child,successor = successor,_u(self.p,successor+0x10)
            if _u(self.p,header) == found:
                _write_span(self.p,header,successor.to_bytes(8,'little'))
            _write_span(self.p,header+16,(len(order)-1).to_bytes(8,'little'))
            self.erase_fixup(root,found)
            self.free_vector(found+0x28); self.emit('free',found,64)

    def data_record(self, address):
        # The inline type counts as one record; each 56-byte child owns only
        # its +10 u64 vector. Its other fields are copied as scalars by 31fdb4.
        self.vector(address)
        self.node(address+0x20, 64)
        self.vector(address+0x70, 16)
        begin, end, _ = self.vector(address+0x98, 56)
        for child in range(begin, end, 56):
            self.nodes += 1
            if self.nodes > self.max_nodes:
                raise RefillUnsupported('AST data child bound reached')
            self.vector(child+0x10, 8)

    def element_children(self, header):
        begin, end, _ = self.vector(header, 56)
        for child in range(begin, end, 56):
            self.nodes += 1
            if self.nodes > self.max_nodes:
                raise RefillUnsupported('AST element child bound reached')
            self.vector(child+0x10, 8)

    def element_record(self, address):
        begin, end, _ = self.vector(address, 144)
        self.node(address+0x28, 64)
        self.vector(address+0x78, 16)
        self.element_children(address+0xA0)
        for nested in range(begin, end, 144):
            self.function_record(nested)

    def function_record(self, address):
        # Function output and element nested nodes share the +2cc470 layout.
        self.node(address, 64)
        self.vector(address+0x50, 16)
        self.element_children(address+0x78)

    def global_record(self, address):
        self.node(address,24)
        self.function_record(address+0x18)

    def callback(self, address, *, output=True, attached_state_address=None):
        self.claim(address, 0x108)
        if _u(self.p, address) != self.base+0x372370:
            raise RefillUnsupported('AST callback requires its actual vtable')
        if attached_state_address is not None:
            if (not isinstance(attached_state_address,int) or attached_state_address & 15
                    or not 0 < attached_state_address <= MASK64-0xAF
                    or _u(self.p,address+8) != attached_state_address+8
                    or _u(self.p,attached_state_address+0x20) != address):
                raise RefillUnsupported('AST attached parser binding is inconsistent')
            self.claim(attached_state_address,0xB0,alignment=16)
            for offset in (0x28,0x40,0x58,0x70):
                self.vector(attached_state_address+offset,8)
            limit,data,total,cursor = (_u(self.p,attached_state_address+offset)
                                      for offset in (0,8,16,24))
            if (not data or data+total > MASK64+1 or total > self.max_bytes
                    or not 0 <= cursor <= limit <= total
                    or any(data < stop and start < data+total for start,stop in self.regions)):
                raise RefillUnsupported('AST attached parser input is invalid or shared')
            _read_span(self.p,data,total)
            self.reserved.append((data,data+total))
        elif _u(self.p, address+8):
            raise RefillUnsupported('AST callback attached parser state remains unsupported')
        ast = _u(self.p, address+0x18)
        if output:
            self.claim(ast, 0x120)
            if _u(self.p, address+0x20) != ast+0x108:
                raise RefillUnsupported('AST raw-word target is inconsistent')
            for offset in range(0, 0x120, 24):
                if offset not in (0,0x18,0x30,0x48,0x60,0x78,0xA8,0xC0,0xD8,0xF0,0x108) and any(
                        _u(self.p,ast+offset+word) for word in (0,8,16)):
                    raise RefillUnsupported('AST unrecovered output containers must be empty')
                stride = (64 if offset in (0,0x18) else 144 if offset == 0x30 else 48 if offset == 0x48 else 40 if offset in (0x60,0xA8) else 4 if offset == 0xC0 else
                          184 if offset == 0xD8 else 176 if offset in (0x78,0xF0) else 1)
                begin, end, cap = self.vector(ast+offset, stride)
                if offset == 0:
                    for node in range(begin, end, 64): self.node(node, 64)
                elif offset == 0x30:
                    if (cap-begin)//144 > self.max_nodes:
                        raise RefillUnsupported('AST function capacity exceeds its node bound')
                    for record in range(begin, end, 144): self.function_record(record)
                elif offset == 0x48:
                    if (cap-begin)//48 > self.max_nodes:
                        raise RefillUnsupported('AST table capacity exceeds its node bound')
                    for record in range(begin,end,48): self.node(record,48)
                elif offset == 0x60:
                    if (cap-begin)//40 > self.max_nodes:
                        raise RefillUnsupported('AST memory capacity exceeds its node bound')
                    for record in range(begin,end,40): self.node(record,40)
                elif offset == 0x78:
                    if (cap-begin)//176 > self.max_nodes:
                        raise RefillUnsupported('AST global capacity exceeds its node bound')
                    for record in range(begin,end,176): self.global_record(record)
                elif offset == 0xA8:
                    if (cap-begin)//40 > self.max_nodes:
                        raise RefillUnsupported('AST export capacity exceeds its node bound')
                    for record in range(begin,end,40): self.export_record(record)
                elif offset == 0x18:
                    if (cap-begin)//64 > self.max_nodes:
                        raise RefillUnsupported('AST import capacity exceeds its node bound')
                    for record in range(begin,end,64): self.import_record(record)
                elif offset == 0xF0:
                    for record in range(begin, end, 176): self.data_record(record)
                elif offset == 0xD8:
                    for record in range(begin, end, 184): self.element_record(record)
        records = _u(self.p, address+0x10)
        if records:
            self.claim(records, 24)
            begin, end, _ = self.vector(records, 64)
            if (end-begin)//64 > self.max_nodes:
                raise RefillUnsupported('AST retained record bound reached')
            for record in range(begin, end, 64):
                flags = _u(self.p, record+40)
                if flags & 1:
                    capacity = flags & ~1
                    if capacity > self.max_bytes or _u(self.p, record+48) >= capacity:
                        raise RefillUnsupported('AST retained string is unbounded')
                    self.claim(_u(self.p, record+56), capacity)
        self.vector(address+0x30)
        lists = []
        for offset, stride in ((0xE0,40),(0xC8,24),(0xB0,40),(0x98,48),(0x80,64)):
            begin, end, cap = self.vector(address+offset, stride)
            for node in range(begin, end, stride): self.node(node, stride)
            lists.append((address+offset, stride, begin, end, cap))
        trees = [self.tree(_u(self.p, address+offset)) for offset in (0x68,0x50)]
        return ast, lists, trees

    def emit(self, kind, address, size):
        self.effects.append(ReaderAstEffect(kind, address, size, self.root,
                                           _read_span(self.p, self.root, self.width)))

    def allocate(self, size, service):
        if not 0 < size <= self.max_bytes or not callable(service):
            raise RefillUnsupported('AST requires a bounded pure allocation plan')
        pointer = service(size)
        self.claim(pointer, size); self.emit('allocate', pointer, size)
        return pointer

    def append_word(self, ast, slot_offset, word, allocate):
        """Native start/raw word append; callers retain the ownership graph."""
        word = 0 if slot_offset == 0xF0 else word&0xFFFFFFFF
        raw = slot_offset in (0xF0,0x168)
        vector = ast+0xC0 if slot_offset == 0xA0 else ast+0x108
        begin,end,cap = self.vector(vector,4 if slot_offset == 0xA0 else 1,own=False)
        size,capacity = end-begin,cap-begin
        if size+4 > self.max_bytes or (raw and size+4 >= 1<<32):
            raise RefillUnsupported('AST word append exceeds the byte bound')
        if cap-end < 4:
            new_capacity = max(size+4,capacity*2)
            new = self.allocate(new_capacity,allocate)
            _write_span(self.p,new+size, word.to_bytes(4,'little')
                        if slot_offset == 0xA0 else bytes(4))
            _write_span(self.p,new,_read_span(self.p,begin,size))
            self.publish(vector,(new,new+size+4,new+new_capacity))
            if begin: self.emit('free',begin,capacity)
            begin = new
        else:
            if raw: _write_span(self.p,end,bytes(4))
            # The raw helper publishes its zero-filled extension before the
            # caller stores the word; start publishes after storing its word.
            if raw: _write_span(self.p,vector+8,(end+4).to_bytes(8,'little'))
        _write_span(self.p,begin+size,word.to_bytes(4,'little'))
        if slot_offset == 0xA0 and cap-end >= 4:
            _write_span(self.p,vector+8,(end+4).to_bytes(8,'little'))

    def copy_string(self, destination, source, service):
        """Actual +32a9c4 copy; the source representation selects the path."""
        self.claim(source,24)
        header = _read_span(self.p,source,24)
        if not header[0]&1:
            _write_span(self.p,destination,header)
            return destination
        length = int.from_bytes(header[8:16],'little')
        if length >= MASK64-15 or length+1 > self.max_bytes:
            raise RefillUnsupported('AST string copy length exceeds its byte bound')
        pointer = int.from_bytes(header[16:24],'little')
        self.claim(pointer,length+1,alignment=1)
        return self.copy_string_value(destination,header,service)

    def copy_string_value(self, destination, header, service):
        # Header/payload ownership was retained by the caller. This permits
        # owned output strings and caller-frame temporaries to share the copy.
        if not header[0]&1:
            _write_span(self.p,destination,header)
            return destination
        length = int.from_bytes(header[8:16],'little')
        if length >= MASK64-15 or length+1 > self.max_bytes:
            raise RefillUnsupported('AST string copy length exceeds its byte bound')
        pointer = int.from_bytes(header[16:24],'little')
        payload = _read_span(self.p,pointer,length+1)
        if length <= 22:
            _write_span(self.p,destination,bytes([length*2]))
            target = destination+1
        else:
            capacity = (length+16)&~15
            target = self.allocate(capacity,service)
            _write_span(self.p,destination+8,length.to_bytes(8,'little')+target.to_bytes(8,'little'))
            _write_span(self.p,destination,(capacity|1).to_bytes(8,'little'))
        _write_span(self.p,target,payload)
        return target

    def free_vector(self, address):
        begin, _, cap = self.vector(address, own=False)
        if begin:
            _write_span(self.p, address+8, begin.to_bytes(8, 'little'))
            self.emit('free', begin, cap-begin)

    def destroy(self, address, stride):
        self.emit('destroy', address, stride)
        self.destroy_node_storage(address)

    def destroy_node_storage(self, address):
        table = _u(self.p, address)-self.base
        if table == 0x3724F0:
            _write_span(self.p, address, (self.base+0x3724F0).to_bytes(8, 'little'))
            self.free_vector(address+0x28); self.free_vector(address+0x10)
        elif table == 0x372590:
            _write_span(self.p, address, (self.base+0x372590).to_bytes(8, 'little'))
            self.free_vector(address+0x10)

    def clone_node(self, source, service):
        table = _u(self.p,source)-self.base
        clones = {0x3724F0:0x321090,0x372518:0x3210D0,0x372540:0x321120,
                  0x372568:0x321170,0x372590:0x3211C0}
        if table not in clones or _u(self.p,self.base+table+16) != self.base+clones[table]:
            raise RefillUnsupported('AST node clone relocation is unsupported')
        if table == 0x3724F0 and _u(self.p,self.base+0x375090) != self.base+0x3724E0:
            raise RefillUnsupported('AST type clone vtable source is unsupported')
        if self.nodes+1 > self.max_nodes:
            raise RefillUnsupported('AST node clone exceeds its node bound')
        self.nodes += 1
        stride = _AST_NODE_TABLES[table][0]
        target = self.allocate(stride,service)
        self.copy_node(target,source,table,service)
        return target

    def copy_node(self, target, source, table, service):
        # The caller retains the source and chooses the actual node family.
        _write_span(self.p,target,(self.base+table).to_bytes(8,'little'))
        _write_span(self.p,target+8,_read_span(self.p,source+8,4 if table != 0x372590 else 8))
        if table in (0x3724F0,0x372590):
            for offset in ((0x10,0x28) if table == 0x3724F0 else (0x10,)):
                self.publish(target+offset,(0,0,0))
                first,last,_ = self.vector(source+offset,8,own=False)
                size = last-first
                if size:
                    pointer = self.allocate(size,service)
                    _write_span(self.p,pointer,_read_span(self.p,first,size))
                    self.publish(target+offset,(pointer,pointer+size,pointer+size))
        else:
            offset,size = (0xC,31) if table == 0x372518 else (0x10,24) if table == 0x372540 else (0xC,12)
            _write_span(self.p,target+offset,_read_span(self.p,source+offset,size))

    def delete_node(self, address):
        table = _u(self.p,address)-self.base
        deletes = {0x3724F0:0x3212B0,0x372518:0x3212FC,0x372540:0x321300,
                   0x372568:0x321304,0x372590:0x32132C}
        if table not in deletes or _u(self.p,self.base+table+8) != self.base+deletes[table]:
            raise RefillUnsupported('AST node deleting destructor relocation is unsupported')
        stride = _AST_NODE_TABLES[table][0]
        self.emit('delete',address,stride)
        self.destroy_node_storage(address)
        self.emit('free',address,stride)

    def export_record(self, address, *, allow_null_node=False):
        header = _read_span(self.p,address,24)
        if header[0]&1:
            capacity = int.from_bytes(header[:8],'little')&~1
            length = int.from_bytes(header[8:16],'little')
            if not length < capacity <= self.max_bytes:
                raise RefillUnsupported('AST export string length/capacity is unsupported')
            self.claim(int.from_bytes(header[16:24],'little'),capacity)
        elif header[0]>>1 > 22:
            raise RefillUnsupported('AST export inline string length is unsupported')
        node = _u(self.p,address+24)
        if allow_null_node and not node: return
        table = _u(self.p,node)-self.base
        if table not in _AST_NODE_TABLES:
            raise RefillUnsupported('AST export node vtable is unsupported')
        stride = _AST_NODE_TABLES[table][0]
        self.claim(node,stride); self.node(node,stride)

    def free_string_value(self, header):
        if header[0]&1:
            self.emit('free',int.from_bytes(header[16:24],'little'),int.from_bytes(header[:8],'little')&~1)

    def destroy_export(self, address):
        node = _u(self.p,address+24)
        _write_span(self.p,address+24,bytes(8))
        if node: self.delete_node(node)
        self.free_string_value(_read_span(self.p,address,24))

    def import_record(self, address, *, allow_null_node=False):
        # The field string and node share the recovered export-record prefix.
        self.export_record(address+24,allow_null_node=allow_null_node)
        header = _read_span(self.p,address,24)
        if header[0]&1:
            capacity = int.from_bytes(header[:8],'little')&~1
            length = int.from_bytes(header[8:16],'little')
            if not length < capacity <= self.max_bytes:
                raise RefillUnsupported('AST import module length/capacity is unsupported')
            self.claim(int.from_bytes(header[16:24],'little'),capacity)
        elif header[0]>>1 > 22:
            raise RefillUnsupported('AST import inline module length is unsupported')

    def destroy_import(self, address):
        self.destroy_export(address+24)
        self.free_string_value(_read_span(self.p,address,24))

    def construct_string(self, address, pointer, length, service):
        header = bytearray(_read_span(self.p,address,24))
        if length >= MASK64-15 or length+1 > self.max_bytes:
            raise RefillUnsupported('AST import name exceeds its byte bound')
        payload = _read_span(self.p,pointer,length)+b'\0' if length else b'\0'
        if length > 22:
            capacity = (length+16)&~15
            data = self.allocate(capacity,service); _write_span(self.p,data,payload)
            header[:] = (capacity|1).to_bytes(8,'little')+length.to_bytes(8,'little')+data.to_bytes(8,'little')
        else:
            header[0] = length*2; header[1:length+2] = payload
        _write_span(self.p,address,header)
        return header

    def append_import_cache(self, header, source, table, service):
        stride = _AST_NODE_TABLES[table][0]
        begin,end,cap = self.vector(header,stride,own=False)
        size,capacity = (end-begin)//stride,(cap-begin)//stride
        new_capacity = max(size+1,capacity*2) if size == capacity else capacity
        if self.nodes+1 > self.max_nodes or new_capacity > self.max_nodes:
            raise RefillUnsupported('AST import cache append exceeds its node bound')
        self.nodes += 1
        new = self.allocate(new_capacity*stride,service) if size == capacity else begin
        self.copy_node(new+size*stride,source,table,service)
        if size == capacity:
            if table == 0x3724F0: self.move_types(begin,end,new)
            elif table == 0x372518: self.move_tables(begin,end,new)
            elif table == 0x372540: self.move_memories(begin,end,new)
            else:
                for old in range(end-stride,begin-1,-stride):
                    target = new+old-begin
                    _write_span(self.p,target,(self.base+table).to_bytes(8,'little'))
                    _write_span(self.p,target+8,_read_span(self.p,old+8,16 if table == 0x372568 else 8))
                    if table == 0x372590:
                        _write_span(self.p,target+0x10,_read_span(self.p,old+0x10,24))
                        _write_span(self.p,old+0x10,bytes(24))
            self.publish(header,(new,new+(size+1)*stride,new+new_capacity*stride))
            for old in range(end-stride,begin-1,-stride): self.destroy(old,stride)
            if begin: self.emit('free',begin,cap-begin)
        else: _write_span(self.p,header+8,(end+stride).to_bytes(8,'little'))

    def publish(self, address, words):
        _write_span(self.p, address, b''.join(value.to_bytes(8,'little') for value in words))

    def move_types(self, begin, end, destination):
        for source in range(end-64, begin-1, -64):
            target = destination+source-begin
            _write_span(self.p, target, (self.base+0x3724F0).to_bytes(8,'little'))
            _write_span(self.p, target+8, _read_span(self.p, source+8, 4))
            _write_span(self.p, target+0x10, _read_span(self.p, source+0x10, 48))
            _write_span(self.p, source+0x10, bytes(48))

    def move_tables(self, begin, end, destination):
        for source in range(end-48,begin-1,-48):
            target = destination+source-begin
            _write_span(self.p,target,(self.base+0x372518).to_bytes(8,'little'))
            _write_span(self.p,target+8,_read_span(self.p,source+8,4))
            _write_span(self.p,target+0xC,_read_span(self.p,source+0xC,31))

    def move_memories(self, begin, end, destination):
        for source in range(end-40,begin-1,-40):
            target = destination+source-begin
            _write_span(self.p,target,(self.base+0x372540).to_bytes(8,'little'))
            _write_span(self.p,target+8,_read_span(self.p,source+8,4))
            _write_span(self.p,target+0x10,_read_span(self.p,source+0x10,24))

    def move_data(self, begin, end, destination):
        for source in range(end-176, begin-1, -176):
            target = destination+source-begin
            for offset in (0,0x30,0x48,0x70,0x98):
                _write_span(self.p, target+offset, _read_span(self.p, source+offset, 24))
                _write_span(self.p, source+offset, bytes(24))
            _write_span(self.p, target+0x20, (self.base+0x3724F0).to_bytes(8,'little'))
            for offset, size in ((0x18,8),(0x28,4),(0x60,8),(0x68,4),(0x88,8),(0x90,4)):
                _write_span(self.p, target+offset, _read_span(self.p, source+offset, size))

    def move_globals(self, begin, end, destination):
        for source in range(end-176,begin-1,-176):
            target = destination+source-begin
            _write_span(self.p,target,(self.base+0x372568).to_bytes(8,'little'))
            _write_span(self.p,target+8,_read_span(self.p,source+8,4))
            _write_span(self.p,target+0xC,_read_span(self.p,source+0xC,12))
            self.move_nested(source+0x18,source+0x18+144,target+0x18)
            _write_span(self.p,target+0xA8,_read_span(self.p,source+0xA8,8))

    def destroy_global(self, address):
        self.emit('destroy',address,176)
        self.destroy_element_children(address+0x90)
        self.free_vector(address+0x68)
        _write_span(self.p,address+0x18,(self.base+0x3724F0).to_bytes(8,'little'))
        self.free_vector(address+0x40); self.free_vector(address+0x28)

    def destroy_data(self, address):
        self.emit('destroy', address, 176)
        begin, end, cap = self.vector(address+0x98, 56, own=False)
        if begin:
            for child in range(end-56, begin-1, -56): self.free_vector(child+0x10)
            _write_span(self.p, address+0xA0, begin.to_bytes(8,'little'))
            self.emit('free', begin, cap-begin)
        self.free_vector(address+0x70)
        _write_span(self.p, address+0x20, (self.base+0x3724F0).to_bytes(8,'little'))
        self.free_vector(address+0x48); self.free_vector(address+0x30)
        self.free_vector(address)

    def move_element(self, begin, end, destination):
        for source in range(end-184, begin-1, -184):
            target = destination+source-begin
            for offset in (0,0x38,0x50,0x78,0xA0):
                _write_span(self.p, target+offset, _read_span(self.p, source+offset, 24))
                _write_span(self.p, source+offset, bytes(24))
            _write_span(self.p, target+0x28, (self.base+0x3724F0).to_bytes(8,'little'))
            for offset, size in ((0x18,16),(0x30,4),(0x68,8),(0x70,4),(0x90,8),(0x98,4)):
                _write_span(self.p, target+offset, _read_span(self.p, source+offset, size))

    def destroy_element_children(self, header):
        begin, end, cap = self.vector(header, 56, own=False)
        if begin:
            for child in range(end-56, begin-1, -56): self.free_vector(child+0x10)
            _write_span(self.p, header+8, begin.to_bytes(8,'little'))
            self.emit('free',begin,cap-begin)

    def move_nested(self, begin, end, destination):
        for source in range(end-144,begin-1,-144):
            target = destination+source-begin
            _write_span(self.p,target,(self.base+0x3724F0).to_bytes(8,'little'))
            for offset in (0x10,0x28,0x50,0x78):
                _write_span(self.p,target+offset,_read_span(self.p,source+offset,24))
                _write_span(self.p,source+offset,bytes(24))
            for offset,size in ((8,4),(0x40,8),(0x48,4),(0x68,8),(0x70,4)):
                _write_span(self.p,target+offset,_read_span(self.p,source+offset,size))

    def move_children(self, begin, end, destination):
        for source in range(end-56,begin-1,-56):
            target = destination+source-begin
            _write_span(self.p,target+0x10,_read_span(self.p,source+0x10,24))
            _write_span(self.p,source+0x10,bytes(24))
            for offset,size in ((0,8),(8,4),(0x28,8),(0x30,4)):
                _write_span(self.p,target+offset,_read_span(self.p,source+offset,size))

    def destroy_nested(self, address):
        self.emit('destroy',address,144)
        self.destroy_element_children(address+0x78)
        self.free_vector(address+0x50)
        _write_span(self.p,address,(self.base+0x3724F0).to_bytes(8,'little'))
        self.free_vector(address+0x28); self.free_vector(address+0x10)

    def destroy_element(self, address):
        self.emit('destroy',address,184)
        self.destroy_element_children(address+0xA0)
        self.free_vector(address+0x78)
        _write_span(self.p,address+0x28,(self.base+0x3724F0).to_bytes(8,'little'))
        self.free_vector(address+0x50); self.free_vector(address+0x38)
        begin, end, cap = self.vector(address,144,own=False)
        if begin:
            for nested in range(end-144,begin-1,-144): self.destroy_nested(nested)
            _write_span(self.p,address+8,begin.to_bytes(8,'little'))
            self.emit('free',begin,cap-begin)


def run_reader_ast_callback(pages, *, callback_address, image_base, slot_offset,
        arguments, allocate=None, max_nodes=4096, max_vector_bytes=16*1024*1024,
        reserved_regions=(), entry_stack_address=None, attached_state_address=None):
    """Recovered actual B vtable callbacks with transactional owned effects.

    Type count reserves capacity without resizing. Type entry ignores its
    index, duplicates the two input u64 vectors into temporaries, copies them
    again into an owned 64-byte node, then frees results/params temporaries.
    Growth moves old nodes backwards and publishes before destroying them.
    Data count reserves 176-byte records without resizing. Growth transfers
    their five owned vectors, preserves destination padding, publishes the
    new header, then destroys old records backwards before freeing the block.
    Data entry ignores index, truncates memory index/flags to u32 and appends
    a record with one -1 type result. It copies that result through three
    temporaries, releases the first before append, and the last two after it.
    Data expression begin ignores index, saves raw BYTE length and resets the
    16-byte frame stack before appending its image-supplied sentinel. End uses
    the last frame index to patch raw bytes from a u32-offset tree, erases the
    matching node with native links/colors, frees payload/node and pops a frame.
    Element count/entry operate on 184-byte records with the same sentinel
    type-copy sequence, an image-supplied +18 constant and five owned vectors.
    Element expression begin/end use the shared frame/raw/tree owner. The
    first vector owns 144-byte nested records with their own type/locals/children.
    Element result type stores a full u64 at +18. Nested reserve keeps size;
    nested begin copies that type into a temporary result, moves the result
    into a new 144-byte record, frees the original result and begins its frame.
    Nested end shares the same raw fixup/tree/pop implementation.
    Instruction predicate ignores kind, returns 1 when the active pointer
    is null or frames are empty, and never dereferences that pointer.
    Instruction end retains the last frame; inner frames share fixup/erase.
    Typed constants append a u32 tag, then the raw u32/u64 bits, with separate
    resize/publication/free stages. Floating values are preserved as bits.
    Local groups append u64 type/u32 count/u32 cumulative count to an owned
    active 144-byte layout. Function end clears active and stores u32 length.
    Function entry appends an owned 144-byte function and independently clones
    its source type into the callback type cache. Both index arguments truncate
    to u32; type index must select a logical output type. The two containers
    grow independently and destroy their moved records after publication.
    Table reserve keeps size and frees its old output block without node
    destruction. Table entry ignores index, retains a full u64 type and copies
    a borrowed 24-byte descriptor into separate output/cache 48-byte records.
    A zero maximum flag replaces the descriptor's maximum with u64 ffffffff.
    Entry requires the actual entry_stack_address: it reads the unwritten
    temporary word at SP-7c into both records' +14 padding, retaining the
    mapped b0-byte frame through allocation. No stack value is invented;
    other stack effects are outside this model. Cache growth destroys old
    nodes after publication; output growth does not. Five tail bytes remain.
    Memory reserve/entry use output+60 and callback+b0 with 40-byte records.
    Entry ignores index and copies all 24 descriptor bytes to record+10;
    record+c padding retains its destination bytes. A zero maximum flag at
    descriptor+10 selects u64 10000, or 1000000000000 when +12 is nonzero.
    No unwritten stack bytes enter the records. Both containers grow
    independently; only cache growth destroys old nodes after publication.
    Global reserve/entry use output+78 with 176-byte records and a separate
    callback+c8 cache of 24-byte global nodes. Entry ignores index, stores
    full u64 type and mutable&1, builds three 8-byte result copies, transfers
    the last to the output inline type, and releases the other two at their
    native stages. Output growth transfers four owned vectors and destroys
    old records backwards after publication. Cache growth also destroys old
    nodes after publication. Padding stays in the destination; tail+a8 is 0.
    Global expression begin selects the last global's inline AST at +18,
    resets/appends the shared frame and saves raw byte length at record+80.
    End stores the full u64 second argument at record+a8, applies frame
    fixups and pops the frame, retaining active. Global inline layouts also
    support the existing local-group and function-end consumers.
    Export ignores its first index and selects one of five callback caches
    using the low u32 kind/index. Its 40-byte output record owns an independent
    name and cloned node. Growth copies names and clones old nodes backwards,
    publishes the new vector, then deletes old records backwards. Short names
    retain unwritten padding from the explicit entry_stack_address-0x90;
    other stack effects are outside this model. Temporary nodes/names are
    released at their native stages; callback caches remain borrowed.
    Five import callbacks append 64-byte records owning module/field names,
    a cloned node and two u32 words. Only function imports retain type/function
    indexes; the others store zero. Growth copies both names and clones old
    nodes backwards, then publishes/deletes them. Cache append follows all
    temporary name/node cleanup; old cache vectors transfer ownership on growth.
    All entries require explicit native frame padding. Table/global arguments
    beyond X7 are supplied in arguments and retain their incoming stack word.
    Table import defaults to zero-extended u32 ffffffff; memory shares its
    recovered default rules. Kind4 copies a selected type's params vector.
    Original/second temporary string headers and constructed temporary nodes
    occupy their actual frame positions; whole stack effects remain unmodeled.
    Data/global/element inline, element nested and function layouts are supported;
    Code begin selects a logical function after subtracting cache/function
    count difference from its u32 index. It stores metadata/raw start, clears
    the frame fixup tree, applies the function fixup tree, resets/appends one
    frame, then appends an owned 56-byte child. The body-length argument is
    ignored; cursor offset and metadata truncate to u32. Existing locals remain.
    Data payload ignores index and uses the full u64 length. Zero length
    leaves existing storage/size intact; nonzero resizes the last record's
    byte vector, then copies a disjoint borrowed span. Growth zero-fills the
    extension, copies old bytes, publishes and frees before the payload copy.
    Start appends u32; local group count writes callback+78 and clears +7c;
    raw word appends four bytes to callback+20, including unaligned byte
    lengths. F0 takes no arguments and appends a zero word. Arguments use
    uint64 registers and native w-register truncation. Other slots fail closed.

    attached_state_address explicitly opts into verified slots +18/+20/+28/
    +30/+38/+40/+50/+58/+60/+68/+70/+78/+80/+88/+90/+a0/+c0/+c8/+d0/+d8/
    +e0/+e8/+98/+a8/+b0/+b8/+f8/+160/+168. Import/export slots also need entry_stack_address and mapped
    callback frame bytes; the module bridge admits inline names only with
    its additional enable_inline_function_imports opt-in.
    The attached pointer must equal state+8 and state+20 must bind
    this callback. Parser vectors and input are retained through allocation.
    The default continues to reject nonzero attached pointers.

    allocate(size) must only plan an aligned address in mapped pages. It must
    not mutate pages or allocate externally. Frees are logical effects: pages
    stay mapped and unpoisoned. Guard failures roll back all model writes;
    allocator exceptions/abort, allocator boot and complete reader remain open.
    Without attached_state_address the helper pointer +8 must be zero.
    Unrecovered output containers must be empty so ownership cannot alias.
    The standalone section parser uses its supplied status service.
    """
    counts = {0x18:1,0x20:5,0x28:7,0x30:8,0x38:7,0x40:8,0x48:7,0x50:2,0x58:1,0x60:3,0x68:1,0x70:2,0x78:1,0x80:3,0x88:1,0x90:2,0x98:5,0xA0:1,0xA8:4,0xB0:1,0xB8:3,0xC0:1,0xC8:0,0xD0:1,0xD8:1,0xE0:1,0xE8:1,
              0xF8:2,
              0xF0:0,0x100:1,0x108:3,0x110:1,0x118:1,
              0x120:2,0x128:2,0x130:1,0x138:1,
              0x140:3,0x148:1,0x150:1,0x158:3,0x160:1,0x168:1}
    if (not isinstance(slot_offset,int) or slot_offset not in counts
            or not isinstance(arguments, (tuple,list))
            or len(arguments) != counts[slot_offset]
            or any(not isinstance(value,int) or not 0 <= value <= MASK64 for value in arguments)):
        raise RefillUnsupported('AST callback slot or uint64 arguments are unsupported')
    if not isinstance(callback_address,int) or not 0 < callback_address <= MASK64-0x108:
        raise RefillUnsupported('AST callback address is invalid')
    if attached_state_address is not None and slot_offset not in (0x18,0x20,0x28,0x30,0x38,0x40,0x50,0x58,0x60,0x68,0x70,0x78,0x80,0x88,0x90,0x98,0xA0,0xA8,0xB0,0xB8,0xC0,0xC8,0xD0,0xD8,0xE0,0xE8,0xF0,0xF8,0x100,0x108,0x110,0x118,0x120,0x128,0x130,0x138,0x140,0x148,0x150,0x158,0x160,0x168):
        raise RefillUnsupported('AST attached callback slot has not been verified')
    # Local group count has no output-object access in the native function.
    root, width = (callback_address,0x108) if slot_offset == 0xB0 else (
        _u(pages,callback_address+0x18),0x120)
    m = _ReaderAstMemory(pages,image_base,root,width,max_nodes,max_vector_bytes,reserved_regions)
    ast, _, trees = m.callback(callback_address, output=slot_offset != 0xB0,
                             attached_state_address=attached_state_address)
    entries = {0x18:0x31B6B0,0x20:0x31B6D0,0x28:0x31B870,0x30:0x31BB48,0x38:0x31BE3C,0x40:0x31C144,0x48:0x31C414,0x50:0x31C7B8,0x58:0x31C9F4,0x60:0x31CABC,0x68:0x31CCEC,0x70:0x31CDB4,0x78:0x31D004,0x80:0x31D028,0x88:0x31D45C,0x90:0x31D4AC,0x98:0x31D500,0xA0:0x31D6D4,0xA8:0x31D7D8,
               0xB8:0x31D984,0xF8:0x31DBB4,
               0xC0:0x31DA9C,0xC8:0x31DAB4,0xD0:0x31DB04,0xD8:0x31DB28,
               0xE0:0x31DB4C,0xE8:0x31DB70,
               0xB0:0x31D974,0xF0:0x31DB94,0x100:0x31DBCC,0x108:0x31DBF0,
               0x120:0x31DEE0,0x128:0x31DEF4,0x130:0x31DF1C,0x138:0x31E18C,
               0x110:0x31DE48,0x118:0x31DE98,0x140:0x31E1D4,0x148:0x31E4A4,0x150:0x31E4F4,
               0x158:0x31E53C,0x160:0x31E5B4,0x168:0x31E5D8}
    if _u(m.p,image_base+0x372370+slot_offset) != image_base+entries[slot_offset]:
        raise RefillUnsupported('AST callback slot relocation is unsupported')
    if slot_offset in (0x18,0x20,0x50,0x108,0x128,0x130,0x140):
        if _u(m.p,image_base+0x375090) != image_base+0x3724E0:
            raise RefillUnsupported('AST type move vtable source is unsupported')
    status = 0
    if slot_offset in (0x28,0x30,0x38,0x40,0x48):
        kind = (slot_offset-0x28)//8
        frame_size = (0xE0,0x110,0x100,0xF0,0x100)[kind]
        if (not isinstance(entry_stack_address,int) or not frame_size <= entry_stack_address <= MASK64-8
                or entry_stack_address&15):
            raise RefillUnsupported('AST import requires its aligned native entry stack address')
        frame = entry_stack_address-frame_size
        m.claim(frame,frame_size+(8 if kind in (1,3) else 0),alignment=16)
        for pointer,length in ((arguments[1],arguments[2]),(arguments[3],arguments[4])):
            if length >= MASK64-15 or length+1 > max_vector_bytes:
                raise RefillUnsupported('AST import name exceeds its byte bound')
            if length:
                if any(pointer < stop and start < pointer+length for start,stop in m.regions):
                    raise RefillUnsupported('AST import name overlaps retained state')
                _read_span(m.p,pointer,length); m.reserved.append((pointer,pointer+length))
        offset,stride,table = ((0x80,64,0x3724F0),(0x98,48,0x372518),(0xB0,40,0x372540),
                               (0xC8,24,0x372568),(0xE0,40,0x372590))[kind]
        got = (0x375090,0x375098,0x3750A0,0x3750A8,0x375088)[kind]
        if _u(m.p,image_base+got) != image_base+table-16:
            raise RefillUnsupported('AST import node vtable source is unsupported')
        cache_begin,cache_end,_ = m.vector(callback_address+offset,stride,own=False)
        if any(_u(m.p,node) != image_base+table for node in range(cache_begin,cache_end,stride)):
            raise RefillUnsupported('AST import cache contains an incompatible node family')
        if kind in (0,4):
            first,last,_ = m.vector(ast,64,own=False)
            index = arguments[6]&0xFFFFFFFF
            if index >= (last-first)//64:
                raise RefillUnsupported('AST import requires a logical output type')
            source = first+index*64
        else:
            source = frame+0x78
        if kind in (1,2):
            pointer = arguments[7] if kind == 1 else arguments[6]
            if not pointer or pointer > MASK64-23 or max_vector_bytes < 24:
                raise RefillUnsupported('AST import descriptor pointer or byte bound is invalid')
            if any(pointer < stop and start < pointer+24 for start,stop in m.regions):
                raise RefillUnsupported('AST import descriptor overlaps retained state')
            descriptor = bytearray(_read_span(m.p,pointer,24)); m.reserved.append((pointer,pointer+24))
            if not descriptor[16]:
                descriptor[8:16]=(0xFFFFFFFF if kind == 1 else 0x1000000000000 if descriptor[18] else 0x10000).to_bytes(8,'little')
            _write_span(m.p,source,(image_base+table).to_bytes(8,'little'))
            _write_span(m.p,source+8,kind.to_bytes(4,'little'))
            if kind == 1: _write_span(m.p,source+0xC,arguments[6].to_bytes(8,'little'))
            _write_span(m.p,source+(0x18 if kind == 1 else 0x10),descriptor)
        elif kind == 3:
            _write_span(m.p,source,(image_base+table).to_bytes(8,'little'))
            _write_span(m.p,source+8,(3).to_bytes(4,'little'))
            _write_span(m.p,source+0xC,arguments[6].to_bytes(8,'little')+(arguments[7]&1).to_bytes(4,'little'))
        elif kind == 4:
            first,last,_ = m.vector(source+0x10,8,own=False)
            payload = _read_span(m.p,first,last-first)
            source = frame+0x78
            _write_span(m.p,source,(image_base+table).to_bytes(8,'little'))
            _write_span(m.p,source+8,(4).to_bytes(8,'little'))
            m.publish(source+0x10,(0,0,0))
            if payload:
                pointer = m.allocate(len(payload),allocate); _write_span(m.p,pointer,payload)
                m.publish(source+0x10,(pointer,pointer+len(payload),pointer+len(payload)))
        original_offsets = (0x28,0x10) if kind == 0 else (0x20,8)
        originals = [m.construct_string(frame+n,pointer,length,allocate) for n,pointer,length in
            zip(original_offsets,(arguments[1],arguments[3]),(arguments[2],arguments[4]))]
        temporary = m.clone_node(source,allocate)
        second = frame+(0x40 if kind == 0 else 0x38)
        for n,header in enumerate(originals): m.copy_string_value(second+n*24,header,allocate)
        begin,end,cap = m.vector(ast+0x18,64,own=False)
        size,capacity = (end-begin)//64,(cap-begin)//64
        new_capacity = max(size+1,capacity*2) if size == capacity else capacity
        if new_capacity > max_nodes:
            raise RefillUnsupported('AST import output growth exceeds its node bound')
        new = m.allocate(new_capacity*64,allocate) if size == capacity else begin
        target = new+size*64
        for n in (0,24): m.copy_string_value(target+n,_read_span(m.p,second+n,24),allocate)
        _write_span(m.p,target+0x30,m.clone_node(temporary,allocate).to_bytes(8,'little'))
        indexes = (arguments[6]&0xFFFFFFFF).to_bytes(4,'little')+(arguments[5]&0xFFFFFFFF).to_bytes(4,'little') if kind == 0 else bytes(8)
        _write_span(m.p,target+0x38,indexes)
        if size == capacity:
            for old in range(end-64,begin-1,-64):
                destination = new+old-begin
                for n in (0,24): m.copy_string_value(destination+n,_read_span(m.p,old+n,24),allocate)
                _write_span(m.p,destination+0x30,m.clone_node(_u(m.p,old+0x30),allocate).to_bytes(8,'little'))
                _write_span(m.p,destination+0x38,_read_span(m.p,old+0x38,8))
            m.publish(ast+0x18,(new,new+(size+1)*64,new+new_capacity*64))
            for old in range(end-64,begin-1,-64): m.destroy_import(old)
            if begin: m.emit('free',begin,cap-begin)
        else: _write_span(m.p,ast+0x20,(end+64).to_bytes(8,'little'))
        m.delete_node(temporary)
        for n in (24,0): m.free_string_value(_read_span(m.p,second+n,24))
        for header in reversed(originals): m.free_string_value(header)
        m.append_import_cache(callback_address+offset,source,table,allocate)
        if kind == 4:
            _write_span(m.p,source,(image_base+table).to_bytes(8,'little'))
            m.free_vector(source+0x10)
    elif slot_offset == 0x98:
        _,kind,index,name,length = arguments
        kind &= 0xFFFFFFFF; index &= 0xFFFFFFFF
        selections = ((0x80,64),(0x98,48),(0xB0,40),(0xC8,24),(0xE0,40))
        if kind >= len(selections):
            raise RefillUnsupported('AST export kind is unsupported')
        offset,stride = selections[kind]
        first,last,_ = m.vector(callback_address+offset,stride,own=False)
        if index >= (last-first)//stride:
            raise RefillUnsupported('AST export index is outside its logical cache')
        if (not isinstance(entry_stack_address,int) or not 0x90 <= entry_stack_address <= MASK64
                or entry_stack_address&15):
            raise RefillUnsupported('AST export requires its aligned native entry stack address')
        frame = entry_stack_address-0x90
        m.claim(frame,0x90,alignment=16)
        header = bytearray(_read_span(m.p,frame,24))
        if length >= MASK64-15 or length > max_vector_bytes-1:
            raise RefillUnsupported('AST export name exceeds its byte bound')
        if length:
            if any(name < stop and start < name+length for start,stop in m.regions):
                raise RefillUnsupported('AST export name overlaps retained state')
            payload = _read_span(m.p,name,length)+b'\0'
            m.reserved.append((name,name+length))
        else: payload = b'\0'
        temporary = m.clone_node(first+index*stride,allocate)
        if length > 22:
            capacity = (length+16)&~15
            pointer = m.allocate(capacity,allocate); _write_span(m.p,pointer,payload)
            header[:] = (capacity|1).to_bytes(8,'little')+length.to_bytes(8,'little')+pointer.to_bytes(8,'little')
            second_pointer = m.allocate(capacity,allocate); _write_span(m.p,second_pointer,payload)
            second = header[:]; second[16:24] = second_pointer.to_bytes(8,'little')
        else:
            header[0] = length*2; header[1:length+2] = payload; second = header[:]
        if attached_state_address is not None:
            # +31d5c8/+31d5ec/+31d5f0/+31d60c leave the first string
            # header in this caller frame for the next export.
            _write_span(m.p,frame,header)
        begin,end,cap = m.vector(ast+0xA8,40,own=False)
        size,capacity = (end-begin)//40,(cap-begin)//40
        new_capacity = max(size+1,capacity*2) if size == capacity else capacity
        if new_capacity > max_nodes:
            raise RefillUnsupported('AST export growth exceeds its node bound')
        new = m.allocate(new_capacity*40,allocate) if size == capacity else begin
        target = new+size*40
        m.copy_string_value(target,second,allocate)
        _write_span(m.p,target+24,m.clone_node(temporary,allocate).to_bytes(8,'little'))
        _write_span(m.p,target+32,index.to_bytes(4,'little'))
        if size == capacity:
            for source in range(end-40,begin-1,-40):
                dest = new+source-begin
                m.copy_string_value(dest,_read_span(m.p,source,24),allocate)
                _write_span(m.p,dest+24,m.clone_node(_u(m.p,source+24),allocate).to_bytes(8,'little'))
                _write_span(m.p,dest+32,_read_span(m.p,source+32,4))
            m.publish(ast+0xA8,(new,new+(size+1)*40,new+new_capacity*40))
            for source in range(end-40,begin-1,-40): m.destroy_export(source)
            if begin: m.emit('free',begin,cap-begin)
        else: _write_span(m.p,ast+0xB0,(end+40).to_bytes(8,'little'))
        m.delete_node(temporary)
        m.free_string_value(second); m.free_string_value(header)
    elif slot_offset == 0xC0:
        begin,end,cap = m.vector(callback_address+0x30,16,own=False)
        if (cap-begin)//16 > max_nodes:
            raise RefillUnsupported('AST instruction frame capacity exceeds its node bound')
        status = int(not _u(m.p,callback_address+0x28) or begin == end)
    elif slot_offset in (0xB8,0xF8):
        target = _u(m.p,callback_address+0x28)
        first,last,_ = m.vector(ast+0x30,144,own=False)
        active = first <= target < last and (target-first)%144 == 0
        for header,stride,inline in ((ast+0x78,176,0x18),(ast+0xF0,176,0x20),(ast+0xD8,184,0x28)):
            begin,end,_ = m.vector(header,stride,own=False)
            for record in range(begin,end,stride):
                active |= target == record+inline
                if stride == 184:
                    first,last,_ = m.vector(record,144,own=False)
                    active |= first <= target < last and (target-first)%144 == 0
        if not active:
            raise RefillUnsupported('AST local/end callback requires an owned active 144-byte layout')
        if slot_offset == 0xF8:
            _write_span(m.p,callback_address+0x28,bytes(8))
            _write_span(m.p,target+0x70,(arguments[1]&0xFFFFFFFF).to_bytes(4,'little'))
        else:
            count = arguments[1]&0xFFFFFFFF
            cumulative = (_u(m.p,callback_address+0x7C,4)+count)&0xFFFFFFFF
            _write_span(m.p,callback_address+0x7C,cumulative.to_bytes(4,'little'))
            value = arguments[2].to_bytes(8,'little')+count.to_bytes(4,'little')+cumulative.to_bytes(4,'little')
            begin,end,cap = m.vector(target+0x50,16,own=False)
            size,capacity = (end-begin)//16,(cap-begin)//16
            if size+1 > max_nodes or capacity > max_nodes:
                raise RefillUnsupported('AST local group capacity exceeds its node bound')
            if size == capacity:
                new_capacity = max(size+1,capacity*2)
                if new_capacity > max_nodes:
                    raise RefillUnsupported('AST local group growth exceeds its node bound')
                new = m.allocate(new_capacity*16,allocate)
                _write_span(m.p,new+size*16,value)
                _write_span(m.p,new,_read_span(m.p,begin,size*16))
                m.publish(target+0x50,(new,new+(size+1)*16,new+new_capacity*16))
                if begin: m.emit('free',begin,cap-begin)
            else:
                _write_span(m.p,end,value)
                _write_span(m.p,target+0x58,(end+16).to_bytes(8,'little'))
    elif slot_offset in (0x18,0x20):
        begin,end,cap = m.vector(ast,64,own=False)
        size,capacity = (end-begin)//64,(cap-begin)//64
        if slot_offset == 0x18:
            count = arguments[0]&0xFFFFFFFF
            if count > max_nodes:
                raise RefillUnsupported('AST type reserve exceeds the node bound')
            if count > capacity:
                new = m.allocate(count*64,allocate)
                m.move_types(begin,end,new)
                m.publish(ast,(new,new+size*64,new+count*64))
                for node in range(end-64,begin-1,-64): m.destroy(node,64)
                if begin: m.emit('free',begin,cap-begin)
        else:
            if m.nodes+1 > max_nodes or size+1 > max_nodes:
                raise RefillUnsupported('AST type append exceeds the node bound')
            sources=[]
            for count,pointer in ((arguments[1]&0xFFFFFFFF,arguments[2]),
                                  (arguments[3]&0xFFFFFFFF,arguments[4])):
                if count*8 > max_vector_bytes:
                    raise RefillUnsupported('AST type input exceeds the vector bound')
                if count:
                    if not pointer or pointer > MASK64-count*8:
                        raise RefillUnsupported('AST type input pointer is invalid')
                    # Input spans are retained through all allocation plans.
                    m.reserved.append((pointer,pointer+count*8))
                sources.append(_read_span(m.p,pointer,count*8))
            temporary=[]; children=[]
            for payload in sources:
                pointer = m.allocate(len(payload),allocate) if payload else 0
                if payload: _write_span(m.p,pointer,payload)
                temporary.append(pointer)
            for payload in sources:
                pointer = m.allocate(len(payload),allocate) if payload else 0
                if payload: _write_span(m.p,pointer,payload)
                children.extend((pointer,pointer+len(payload) if pointer else 0,
                                 pointer+len(payload) if pointer else 0))
            if size == capacity:
                new_capacity = max(size+1,capacity*2)
                if new_capacity > max_nodes:
                    raise RefillUnsupported('AST type growth exceeds the node bound')
                new = m.allocate(new_capacity*64,allocate); target = new+size*64
            else: new,new_capacity,target = begin,capacity,end
            _write_span(m.p,target,(image_base+0x3724F0).to_bytes(8,'little'))
            _write_span(m.p,target+8,bytes(4))
            _write_span(m.p,target+0x10,b''.join(value.to_bytes(8,'little') for value in children))
            if size == capacity:
                m.move_types(begin,end,new)
                m.publish(ast,(new,new+(size+1)*64,new+new_capacity*64))
                for node in range(end-64,begin-1,-64): m.destroy(node,64)
                if begin: m.emit('free',begin,cap-begin)
            else: _write_span(m.p,ast+8,(end+64).to_bytes(8,'little'))
            for pointer,payload in reversed(list(zip(temporary,sources))):
                if pointer: m.emit('free',pointer,len(payload))
    elif slot_offset == 0x50:
        type_index = arguments[1]&0xFFFFFFFF
        type_begin,type_end,_ = m.vector(ast,64,own=False)
        if type_index >= (type_end-type_begin)//64:
            raise RefillUnsupported('AST function requires a logical source type')
        source = type_begin+type_index*64
        begin,end,cap = m.vector(ast+0x30,144,own=False)
        size,capacity = (end-begin)//144,(cap-begin)//144
        cache_begin,cache_end,cache_cap = m.vector(callback_address+0x80,64,own=False)
        cache_size,cache_capacity = (cache_end-cache_begin)//64,(cache_cap-cache_begin)//64
        new_capacity = max(size+1,capacity*2) if size == capacity else capacity
        new_cache_capacity = max(cache_size+1,cache_capacity*2) if cache_size == cache_capacity else cache_capacity
        if m.nodes+2 > max_nodes or max(new_capacity,new_cache_capacity) > max_nodes:
            raise RefillUnsupported('AST function/type cache append exceeds the node bound')
        sources = []
        for offset in (0x10,0x28):
            first,last,_ = m.vector(source+offset,8,own=False)
            sources.append(_read_span(m.p,first,last-first))
        children = []
        for payload in sources:
            pointer = m.allocate(len(payload),allocate) if payload else 0
            if payload: _write_span(m.p,pointer,payload)
            children.extend((pointer,pointer+len(payload) if pointer else 0,pointer+len(payload) if pointer else 0))
        new = m.allocate(new_capacity*144,allocate) if size == capacity else begin
        target = new+size*144
        _write_span(m.p,target,(image_base+0x3724F0).to_bytes(8,'little'))
        _write_span(m.p,target+8,_read_span(m.p,source+8,4))
        m.publish(target+0x10,children[:3]); m.publish(target+0x28,children[3:])
        _write_span(m.p,target+0x40,type_index.to_bytes(4,'little')+(arguments[0]&0xFFFFFFFF).to_bytes(4,'little'))
        _write_span(m.p,target+0x48,bytes(4))
        m.publish(target+0x50,(0,0,0)); m.publish(target+0x78,(0,0,0))
        _write_span(m.p,target+0x68,(0xFFFFFFFF).to_bytes(8,'little'))
        _write_span(m.p,target+0x70,bytes(4))
        if size == capacity:
            m.move_nested(begin,end,new)
            m.publish(ast+0x30,(new,new+(size+1)*144,new+new_capacity*144))
            for record in range(end-144,begin-1,-144): m.destroy_nested(record)
            if begin: m.emit('free',begin,cap-begin)
        else: _write_span(m.p,ast+0x38,(end+144).to_bytes(8,'little'))
        # Native cache growth allocates the outer block before cloning vectors.
        cache_new = m.allocate(new_cache_capacity*64,allocate) if cache_size == cache_capacity else cache_begin
        target = cache_new+cache_size*64
        _write_span(m.p,target,(image_base+0x3724F0).to_bytes(8,'little'))
        _write_span(m.p,target+8,_read_span(m.p,source+8,4))
        for offset,payload in zip((0x10,0x28),sources):
            m.publish(target+offset,(0,0,0))
            pointer = m.allocate(len(payload),allocate) if payload else 0
            if payload: _write_span(m.p,pointer,payload)
            m.publish(target+offset,(pointer,pointer+len(payload) if pointer else 0,pointer+len(payload) if pointer else 0))
        if cache_size == cache_capacity:
            m.move_types(cache_begin,cache_end,cache_new)
            m.publish(callback_address+0x80,(cache_new,cache_new+(cache_size+1)*64,cache_new+new_cache_capacity*64))
            for node in range(cache_end-64,cache_begin-1,-64): m.destroy(node,64)
            if cache_begin: m.emit('free',cache_begin,cache_cap-cache_begin)
        else: _write_span(m.p,callback_address+0x88,(cache_end+64).to_bytes(8,'little'))
    elif slot_offset in (0x58,0x60):
        begin,end,cap = m.vector(ast+0x48,48,own=False)
        size,capacity = (end-begin)//48,(cap-begin)//48
        if slot_offset == 0x58:
            count = arguments[0]&0xFFFFFFFF
            if count > max_nodes:
                raise RefillUnsupported('AST table reserve exceeds its node bound')
            if count > capacity:
                new = m.allocate(count*48,allocate)
                m.move_tables(begin,end,new)
                m.publish(ast+0x48,(new,new+size*48,new+count*48))
                if begin: m.emit('free',begin,cap-begin)
        else:
            if _u(m.p,image_base+0x375098) != image_base+0x372508:
                raise RefillUnsupported('AST table node vtable relocation is unsupported')
            if (not isinstance(entry_stack_address,int) or not 0xB0 <= entry_stack_address <= MASK64
                    or entry_stack_address&15):
                raise RefillUnsupported('AST table entry requires its aligned native entry stack address')
            m.claim(entry_stack_address-0xB0,0xB0,alignment=16)
            padding = _read_span(m.p,entry_stack_address-0x7C,4)
            pointer = arguments[2]
            if not pointer or pointer > MASK64-23 or max_vector_bytes < 24:
                raise RefillUnsupported('AST table descriptor pointer or byte bound is invalid')
            if any(pointer < stop and start < pointer+24 for start,stop in m.regions):
                raise RefillUnsupported('AST table descriptor overlaps owned state or its frame')
            descriptor = bytearray(_read_span(m.p,pointer,24)[:19])
            m.reserved.append((pointer,pointer+24))
            if not descriptor[16]: descriptor[8:16]=(0xFFFFFFFF).to_bytes(8,'little')
            value = arguments[1].to_bytes(8,'little')+padding+descriptor
            cache_begin,cache_end,cache_cap = m.vector(callback_address+0x98,48,own=False)
            cache_size,cache_capacity = (cache_end-cache_begin)//48,(cache_cap-cache_begin)//48
            new_capacity = max(size+1,capacity*2) if size == capacity else capacity
            new_cache_capacity = max(cache_size+1,cache_capacity*2) if cache_size == cache_capacity else cache_capacity
            if m.nodes+2 > max_nodes or max(new_capacity,new_cache_capacity) > max_nodes:
                raise RefillUnsupported('AST table/cache append exceeds its node bound')
            for header,first,last,limit,count,old_capacity,new_count,is_cache in (
                    (ast+0x48,begin,end,cap,size,capacity,new_capacity,False),
                    (callback_address+0x98,cache_begin,cache_end,cache_cap,cache_size,cache_capacity,new_cache_capacity,True)):
                new = m.allocate(new_count*48,allocate) if count == old_capacity else first
                target = new+count*48
                _write_span(m.p,target,(image_base+0x372518).to_bytes(8,'little'))
                _write_span(m.p,target+8,(1).to_bytes(4,'little'))
                _write_span(m.p,target+0xC,value)
                if count == old_capacity:
                    m.move_tables(first,last,new)
                    m.publish(header,(new,new+(count+1)*48,new+new_count*48))
                    if is_cache:
                        for record in range(last-48,first-1,-48): m.destroy(record,48)
                    if first: m.emit('free',first,limit-first)
                else: _write_span(m.p,header+8,(last+48).to_bytes(8,'little'))
    elif slot_offset in (0x68,0x70):
        begin,end,cap = m.vector(ast+0x60,40,own=False)
        size,capacity = (end-begin)//40,(cap-begin)//40
        if slot_offset == 0x68:
            count = arguments[0]&0xFFFFFFFF
            if count > max_nodes:
                raise RefillUnsupported('AST memory reserve exceeds its node bound')
            if count > capacity:
                new = m.allocate(count*40,allocate)
                m.move_memories(begin,end,new)
                m.publish(ast+0x60,(new,new+size*40,new+count*40))
                if begin: m.emit('free',begin,cap-begin)
        else:
            if _u(m.p,image_base+0x3750A0) != image_base+0x372530:
                raise RefillUnsupported('AST memory node vtable relocation is unsupported')
            pointer = arguments[1]
            if not pointer or pointer > MASK64-23 or max_vector_bytes < 24:
                raise RefillUnsupported('AST memory descriptor pointer or byte bound is invalid')
            if any(pointer < stop and start < pointer+24 for start,stop in m.regions):
                raise RefillUnsupported('AST memory descriptor overlaps owned state')
            descriptor = bytearray(_read_span(m.p,pointer,24))
            m.reserved.append((pointer,pointer+24))
            if not descriptor[16]:
                descriptor[8:16]=(0x1000000000000 if descriptor[18] else 0x10000).to_bytes(8,'little')
            cache_begin,cache_end,cache_cap = m.vector(callback_address+0xB0,40,own=False)
            cache_size,cache_capacity = (cache_end-cache_begin)//40,(cache_cap-cache_begin)//40
            new_capacity = max(size+1,capacity*2) if size == capacity else capacity
            new_cache_capacity = max(cache_size+1,cache_capacity*2) if cache_size == cache_capacity else cache_capacity
            if m.nodes+2 > max_nodes or max(new_capacity,new_cache_capacity) > max_nodes:
                raise RefillUnsupported('AST memory/cache append exceeds its node bound')
            for header,first,last,limit,count,old_capacity,new_count,is_cache in (
                    (ast+0x60,begin,end,cap,size,capacity,new_capacity,False),
                    (callback_address+0xB0,cache_begin,cache_end,cache_cap,cache_size,cache_capacity,new_cache_capacity,True)):
                new = m.allocate(new_count*40,allocate) if count == old_capacity else first
                target = new+count*40
                _write_span(m.p,target,(image_base+0x372540).to_bytes(8,'little'))
                _write_span(m.p,target+8,(2).to_bytes(4,'little'))
                _write_span(m.p,target+0x10,descriptor)
                if count == old_capacity:
                    m.move_memories(first,last,new)
                    m.publish(header,(new,new+(count+1)*40,new+new_count*40))
                    if is_cache:
                        for record in range(last-40,first-1,-40): m.destroy(record,40)
                    if first: m.emit('free',first,limit-first)
                else: _write_span(m.p,header+8,(last+40).to_bytes(8,'little'))
    elif slot_offset in (0x78,0x80):
        if (_u(m.p,image_base+0x3750A8) != image_base+0x372558
                or _u(m.p,image_base+0x375090) != image_base+0x3724E0):
            raise RefillUnsupported('AST global/type vtable relocation is unsupported')
        begin,end,cap = m.vector(ast+0x78,176,own=False)
        size,capacity = (end-begin)//176,(cap-begin)//176
        if slot_offset == 0x78:
            count = arguments[0]&0xFFFFFFFF
            if count > max_nodes:
                raise RefillUnsupported('AST global reserve exceeds its node bound')
            if count > capacity:
                new = m.allocate(count*176,allocate)
                m.move_globals(begin,end,new)
                m.publish(ast+0x78,(new,new+size*176,new+count*176))
                for record in range(end-176,begin-1,-176): m.destroy_global(record)
                if begin: m.emit('free',begin,cap-begin)
        else:
            cache_begin,cache_end,cache_cap = m.vector(callback_address+0xC8,24,own=False)
            cache_size,cache_capacity = (cache_end-cache_begin)//24,(cache_cap-cache_begin)//24
            new_capacity = max(size+1,capacity*2) if size == capacity else capacity
            new_cache_capacity = max(cache_size+1,cache_capacity*2) if cache_size == cache_capacity else cache_capacity
            if m.nodes+3 > max_nodes or max(new_capacity,new_cache_capacity) > max_nodes:
                raise RefillUnsupported('AST global/cache append exceeds its node bound')
            result_bytes = arguments[1].to_bytes(8,'little')
            original = m.allocate(8,allocate); _write_span(m.p,original,result_bytes)
            temporary = m.allocate(8,allocate); _write_span(m.p,temporary,result_bytes)
            m.emit('free',original,8)
            result = m.allocate(8,allocate); _write_span(m.p,result,result_bytes)
            new = m.allocate(new_capacity*176,allocate) if size == capacity else begin
            target = new+size*176
            value = result_bytes+(arguments[2]&1).to_bytes(4,'little')
            _write_span(m.p,target,(image_base+0x372568).to_bytes(8,'little'))
            _write_span(m.p,target+8,(3).to_bytes(4,'little'))
            _write_span(m.p,target+0xC,value)
            _write_span(m.p,target+0x18,(image_base+0x3724F0).to_bytes(8,'little'))
            _write_span(m.p,target+0x20,bytes(4))
            m.publish(target+0x28,(0,0,0)); m.publish(target+0x40,(result,result+8,result+8))
            _write_span(m.p,target+0x58,bytes(8)); _write_span(m.p,target+0x60,bytes(4))
            m.publish(target+0x68,(0,0,0))
            _write_span(m.p,target+0x80,(0xFFFFFFFF).to_bytes(8,'little'))
            _write_span(m.p,target+0x88,bytes(4)); m.publish(target+0x90,(0,0,0))
            _write_span(m.p,target+0xA8,bytes(8))
            if size == capacity:
                m.move_globals(begin,end,new)
                m.publish(ast+0x78,(new,new+(size+1)*176,new+new_capacity*176))
                for record in range(end-176,begin-1,-176): m.destroy_global(record)
                if begin: m.emit('free',begin,cap-begin)
            else: _write_span(m.p,ast+0x80,(end+176).to_bytes(8,'little'))
            cache_new = m.allocate(new_cache_capacity*24,allocate) if cache_size == cache_capacity else cache_begin
            target = cache_new+cache_size*24
            _write_span(m.p,target,(image_base+0x372568).to_bytes(8,'little'))
            _write_span(m.p,target+8,(3).to_bytes(4,'little'))
            _write_span(m.p,target+0xC,value)
            if cache_size == cache_capacity:
                for source in range(cache_end-24,cache_begin-1,-24):
                    destination = cache_new+source-cache_begin
                    _write_span(m.p,destination,(image_base+0x372568).to_bytes(8,'little'))
                    _write_span(m.p,destination+8,_read_span(m.p,source+8,16))
                m.publish(callback_address+0xC8,(cache_new,cache_new+(cache_size+1)*24,cache_new+new_cache_capacity*24))
                for record in range(cache_end-24,cache_begin-1,-24): m.destroy(record,24)
                if cache_begin: m.emit('free',cache_begin,cache_cap-cache_begin)
            else: _write_span(m.p,callback_address+0xD0,(cache_end+24).to_bytes(8,'little'))
            m.emit('free',temporary,8)
    elif slot_offset == 0xA8:
        first,last,_ = m.vector(ast+0x30,144,own=False)
        cache_begin,cache_end,_ = m.vector(callback_address+0x80,64,own=False)
        size = (last-first)//144
        imported = ((cache_end-cache_begin)//64-size)&0xFFFFFFFF
        index = (arguments[0]-imported)&0xFFFFFFFF
        if index >= size:
            raise RefillUnsupported('AST code begin requires a logical function index')
        begin,end,cap = m.vector(callback_address+0x30,16,own=False)
        if (cap-begin)//16 > max_nodes:
            raise RefillUnsupported('AST code frame capacity exceeds its node bound')
        target = first+index*144
        _write_span(m.p,callback_address+0x28,target.to_bytes(8,'little'))
        _write_span(m.p,target+0x48,(arguments[3]&0xFFFFFFFF).to_bytes(4,'little'))
        raw_begin,raw_end,_ = m.vector(ast+0x108,own=False)
        _write_span(m.p,target+0x68,((raw_end-raw_begin)&0xFFFFFFFF).to_bytes(4,'little')+
                    (arguments[1]&0xFFFFFFFF).to_bytes(4,'little'))
        for node in trees[1]:
            m.free_vector(node+0x28); m.emit('free',node,64)
        m.publish(callback_address+0x48,(callback_address+0x50,0,0))
        _write_span(m.p,callback_address+0x38,begin.to_bytes(8,'little'))
        m.apply_fixup(callback_address+0x60,trees[0],index,allocate)
        child_begin,child_end,child_cap = m.vector(target+0x78,56,own=False)
        child_size,child_capacity = (child_end-child_begin)//56,(child_cap-child_begin)//56
        value = _read_span(m.p,image_base+0x6E188,8)+(0xFFFFFFFF).to_bytes(4,'little')+child_size.to_bytes(4,'little')
        if begin < cap:
            _write_span(m.p,begin,value)
            _write_span(m.p,callback_address+0x38,(begin+16).to_bytes(8,'little'))
        else:
            capacity = max(1,(cap-begin)//8)
            if capacity > max_nodes:
                raise RefillUnsupported('AST code frame growth exceeds the node bound')
            new = m.allocate(capacity*16,allocate); _write_span(m.p,new,value)
            m.publish(callback_address+0x30,(new,new+16,new+capacity*16))
            if begin: m.emit('free',begin,cap-begin)
        new_capacity = max(child_size+1,child_capacity*2) if child_size == child_capacity else child_capacity
        if m.nodes+1 > max_nodes or new_capacity > max_nodes:
            raise RefillUnsupported('AST code child append exceeds the node bound')
        new = m.allocate(new_capacity*56,allocate) if child_size == child_capacity else child_begin
        child = new+child_size*56
        raw_begin,raw_end,_ = m.vector(ast+0x108,own=False)
        locals_begin,locals_end,_ = m.vector(target+0x50,16,own=False)
        _write_span(m.p,child,(((raw_end-raw_begin)&0xFFFFFFFF)<<32).to_bytes(8,'little'))
        _write_span(m.p,child+8,(0xFFFFFFFF).to_bytes(4,'little'))
        m.publish(child+0x10,(0,0,0))
        _write_span(m.p,child+0x28,(0xFFFFFFFF|(((locals_end-locals_begin)//16)<<32)).to_bytes(8,'little'))
        _write_span(m.p,child+0x30,bytes(4))
        if child_size == child_capacity:
            m.move_children(child_begin,child_end,new)
            m.publish(target+0x78,(new,new+(child_size+1)*56,new+new_capacity*56))
            if child_begin: m.emit('free',child_begin,child_cap-child_begin)
        else: _write_span(m.p,target+0x80,(child_end+56).to_bytes(8,'little'))
    elif slot_offset == 0xB0:
        _write_span(m.p,callback_address+0x78,(arguments[0]&0xFFFFFFFF).to_bytes(4,'little')+bytes(4))
    elif slot_offset in (0x108,0x140):
        element = slot_offset == 0x108
        header,stride = (ast+0xD8,184) if element else (ast+0xF0,176)
        shift = 8 if element else 0
        begin,end,cap = m.vector(header,stride,own=False)
        size,capacity = (end-begin)//stride,(cap-begin)//stride
        if m.nodes+1 > max_nodes or size+1 > max_nodes:
            raise RefillUnsupported('AST data append exceeds the node bound')
        sentinel = MASK64.to_bytes(8,'little')
        original = m.allocate(8,allocate); _write_span(m.p,original,sentinel)
        temporary_type = m.allocate(8,allocate); _write_span(m.p,temporary_type,sentinel)
        m.emit('free',original,8)
        temporary_data = m.allocate(8,allocate); _write_span(m.p,temporary_data,sentinel)
        if size == capacity:
            new_capacity = max(size+1,capacity*2)
            if new_capacity > max_nodes:
                raise RefillUnsupported('AST data growth exceeds the node bound')
            new = m.allocate(new_capacity*stride,allocate); target = new+size*stride
        else: new,new_capacity,target = begin,capacity,end
        result = m.allocate(8,allocate); _write_span(m.p,result,sentinel)
        flags = arguments[2]&0xFFFFFFFF
        classification = 2 if flags&3 == 3 else flags&1
        m.publish(target,(0,0,0))
        for offset in (0x30,0x70,0x98): m.publish(target+offset+shift,(0,0,0))
        m.publish(target+0x48+shift,(result,result+8,result+8))
        if element: _write_span(m.p,target+0x18,_read_span(m.p,image_base+0x6E210,8))
        for offset,value in ((0x18,classification | ((arguments[1]&0xFFFFFFFF)<<32)),
                             (0x20,image_base+0x3724F0),(0x60,0),(0x88,0xFFFFFFFF)):
            offset += shift
            _write_span(m.p,target+offset,value.to_bytes(8,'little'))
        for offset in (0x28,0x68,0x90): _write_span(m.p,target+offset+shift,bytes(4))
        if size == capacity:
            (m.move_element if element else m.move_data)(begin,end,new)
            m.publish(header,(new,new+(size+1)*stride,new+new_capacity*stride))
            for record in range(end-stride,begin-1,-stride):
                (m.destroy_element if element else m.destroy_data)(record)
            if begin: m.emit('free',begin,cap-begin)
        else: _write_span(m.p,header+8,(end+stride).to_bytes(8,'little'))
        # 108 calls the real stack element destructor; 140 inlines it. Stack
        # temporaries are outside guest ownership; their frees remain effects.
        m.emit('free',temporary_data,8); m.emit('free',temporary_type,8)
    elif slot_offset in (0x120,0x128):
        record_begin,record_end,_ = m.vector(ast+0xD8,184,own=False)
        if record_begin == record_end:
            raise RefillUnsupported('AST nested operation requires an active element')
        record = record_end-184
        if slot_offset == 0x120:
            _write_span(m.p,record+0x18,arguments[1].to_bytes(8,'little'))
        else:
            begin,end,cap = m.vector(record,144,own=False)
            size,capacity = (end-begin)//144,(cap-begin)//144
            count = arguments[1]&0xFFFFFFFF
            if count > max_nodes:
                raise RefillUnsupported('AST nested reserve exceeds the node bound')
            if count > capacity:
                new = m.allocate(count*144,allocate)
                m.move_nested(begin,end,new)
                m.publish(record,(new,new+size*144,new+count*144))
                for node in range(end-144,begin-1,-144): m.destroy_nested(node)
                if begin: m.emit('free',begin,cap-begin)
    elif slot_offset in (0x88,0x90,0xC8,0x110,0x118,0x130,0x138,0x148,0x150):
        begin,end,cap = m.vector(callback_address+0x30,16,own=False)
        if (cap-begin)//16 > max_nodes:
            raise RefillUnsupported('AST expression frame capacity exceeds its node bound')
        if slot_offset in (0x88,0x110,0x130,0x148):
            header,stride = (ast+0xD8,184) if slot_offset == 0x110 else (ast+0xF0,176)
            if slot_offset == 0x130: header,stride = ast+0xD8,184
            if slot_offset == 0x88: header,stride = ast+0x78,176
            record_begin,record_end,_ = m.vector(header,stride,own=False)
            if record_begin == record_end:
                raise RefillUnsupported('AST expression requires an active record')
            if slot_offset == 0x130:
                header = record_end-184
                nested_begin,nested_end,nested_cap = m.vector(header,144,own=False)
                size,capacity = (nested_end-nested_begin)//144,(nested_cap-nested_begin)//144
                if m.nodes+1 > max_nodes or size+1 > max_nodes:
                    raise RefillUnsupported('AST nested append exceeds the node bound')
                value = _read_span(m.p,header+0x18,8)
                original = m.allocate(8,allocate); _write_span(m.p,original,value)
                result = m.allocate(8,allocate); _write_span(m.p,result,value)
                if size == capacity:
                    new_capacity = max(size+1,capacity*2)
                    if new_capacity > max_nodes:
                        raise RefillUnsupported('AST nested growth exceeds the node bound')
                    new = m.allocate(new_capacity*144,allocate); target = new+size*144
                else: new,new_capacity,target = nested_begin,capacity,nested_end
                _write_span(m.p,target,(image_base+0x3724F0).to_bytes(8,'little'))
                for offset in (8,0x48,0x70): _write_span(m.p,target+offset,bytes(4))
                for offset in (0x10,0x50,0x78): m.publish(target+offset,(0,0,0))
                m.publish(target+0x28,(result,result+8,result+8))
                _write_span(m.p,target+0x40,bytes(8))
                _write_span(m.p,target+0x68,(0xFFFFFFFF).to_bytes(8,'little'))
                if size == capacity:
                    m.move_nested(nested_begin,nested_end,new)
                    m.publish(header,(new,new+(size+1)*144,new+new_capacity*144))
                    for node in range(nested_end-144,nested_begin-1,-144): m.destroy_nested(node)
                    if nested_begin: m.emit('free',nested_begin,nested_cap-nested_begin)
                else: _write_span(m.p,header+8,(nested_end+144).to_bytes(8,'little'))
                # The temporary type's result was moved into the new node.
                # Its destructor owns no storage; only the original is freed.
                m.emit('free',original,8)
            else: target = record_end-(0x98 if slot_offset == 0x88 else 0x90)
            raw_begin,raw_end,_ = m.vector(ast+0x108,own=False)
            _write_span(m.p,callback_address+0x38,begin.to_bytes(8,'little'))
            _write_span(m.p,callback_address+0x28,target.to_bytes(8,'little'))
            _write_span(m.p,target+0x68,((raw_end-raw_begin)&0xFFFFFFFF).to_bytes(4,'little'))
            value = _read_span(m.p,image_base+0x6E188,8)+bytes([255])*8
            if begin < cap:
                _write_span(m.p,begin,value)
                _write_span(m.p,callback_address+0x38,(begin+16).to_bytes(8,'little'))
            else:
                capacity = max(1,(cap-begin)//8)
                if capacity > max_nodes:
                    raise RefillUnsupported('AST expression frame growth exceeds its node bound')
                new = m.allocate(capacity*16,allocate)
                _write_span(m.p,new,value)
                m.publish(callback_address+0x30,(new,new+16,new+capacity*16))
                if begin: m.emit('free',begin,cap-begin)
        elif slot_offset == 0xC8 and end-begin == 16:
            pass
        else:
            if begin == end:
                raise RefillUnsupported('AST expression frame stack is empty')
            if slot_offset == 0x90:
                record_begin,record_end,_ = m.vector(ast+0x78,176,own=False)
                if record_begin == record_end:
                    raise RefillUnsupported('AST global expression end requires a global record')
                _write_span(m.p,record_end-8,arguments[1].to_bytes(8,'little'))
            m.apply_fixup(callback_address+0x48,trees[1],(end-begin)//16-1,allocate)
            _write_span(m.p,callback_address+0x38,(end-16).to_bytes(8,'little'))
    elif slot_offset == 0x158:
        _,pointer,length = arguments
        if length:
            record_begin,record_end,_ = m.vector(ast+0xF0,176,own=False)
            if record_end == record_begin:
                raise RefillUnsupported('AST data payload requires an active record')
            if length > max_vector_bytes or not pointer or pointer > MASK64-length:
                raise RefillUnsupported('AST data input exceeds the bounded guest span')
            if any(pointer < stop and start < pointer+length or pointer <= start < pointer+length
                   for start,stop in m.regions):
                raise RefillUnsupported('AST data input overlaps owned storage')
            payload = _read_span(m.p,pointer,length)
            m.reserved.append((pointer,pointer+length))
            target = record_end-176
            begin,end,cap = m.vector(target,own=False)
            size,capacity = end-begin,cap-begin
            if length > capacity:
                new_capacity = max(length,capacity*2)
                new = m.allocate(new_capacity,allocate)
                _write_span(m.p,new+size,bytes(length-size))
                _write_span(m.p,new,_read_span(m.p,begin,size))
                m.publish(target,(new,new+length,new+new_capacity))
                if begin: m.emit('free',begin,capacity)
                begin = new
            elif length != size:
                if length > size: _write_span(m.p,end,bytes(length-size))
                _write_span(m.p,target+8,(begin+length).to_bytes(8,'little'))
            _write_span(m.p,begin,payload)
    elif slot_offset in (0x100,0x160):
        element = slot_offset == 0x100
        header,stride = (ast+0xD8,184) if element else (ast+0xF0,176)
        begin,end,cap = m.vector(header,stride,own=False)
        size,capacity = (end-begin)//stride,(cap-begin)//stride
        count = arguments[0]&0xFFFFFFFF
        if count > max_nodes:
            raise RefillUnsupported('AST data reserve exceeds the node bound')
        if count > capacity:
            new = m.allocate(count*stride,allocate)
            (m.move_element if element else m.move_data)(begin,end,new)
            m.publish(header,(new,new+size*stride,new+count*stride))
            for record in range(end-stride,begin-1,-stride):
                (m.destroy_element if element else m.destroy_data)(record)
            if begin: m.emit('free',begin,cap-begin)
    elif slot_offset in (0xD0,0xD8,0xE0,0xE8):
        tag,width = {0xD0:(4,4),0xD8:(5,8),0xE0:(2,4),0xE8:(3,8)}[slot_offset]
        for value,size in ((tag,4),(arguments[0]&((1<<(width*8))-1),width)):
            begin,end,_ = m.vector(ast+0x108,own=False)
            length = end-begin
            m.grow_bytes(ast+0x108,length+size,allocate)
            begin = _u(m.p,ast+0x108)
            _write_span(m.p,begin+length,value.to_bytes(size,'little'))
    else:
        m.append_word(ast,slot_offset,0 if slot_offset == 0xF0 else arguments[0],allocate)
    m.p.commit()
    return ReaderAstResult(status,tuple(m.effects))


def cleanup_reader_ast_export_output(pages, *, output_address, image_base,
                                     max_nodes=4096, max_vector_bytes=16*1024*1024,
                                     reserved_regions=()):
    """Actual +2cbadc cleanup for an output owning only export records.

    Each 40-byte record owns a name and independently cloned node. Delete
    nodes, then release names, backwards; reset end and free the outer block.
    Other output containers must be empty. Begin/capacity remain dangling,
    so consume logical frees once. Mixed containers use cleanup_reader_ast_output.
    """
    m = _ReaderAstMemory(pages,image_base,output_address,0x120,max_nodes,max_vector_bytes,reserved_regions)
    m.claim(output_address,0x120)
    for offset in range(0,0x120,24):
        if offset != 0xA8 and any(_u(m.p,output_address+offset+n) for n in (0,8,16)):
            raise RefillUnsupported('AST export-only cleanup requires other output containers empty')
    begin,end,cap = m.vector(output_address+0xA8,40)
    if (cap-begin)//40 > max_nodes:
        raise RefillUnsupported('AST export cleanup capacity exceeds its node bound')
    for address in range(begin,end,40): m.export_record(address)
    for address in range(end-40,begin-1,-40): m.destroy_export(address)
    if begin:
        _write_span(m.p,output_address+0xB0,begin.to_bytes(8,'little'))
        m.emit('free',begin,cap-begin)
    m.p.commit()
    return ReaderAstResult(None,tuple(m.effects))


def cleanup_reader_ast_import_output(pages, *, output_address, image_base,
                                     max_nodes=4096, max_vector_bytes=16*1024*1024,
                                     reserved_regions=()):
    """Actual +2cbadc cleanup for an output owning only 64-byte imports.

    Delete each node, then release field and module names, backwards. Reset
    end and free the outer block, retaining dangling begin/capacity. Every
    other output header must be zero; mixed containers use cleanup_reader_ast_output.
    """
    m = _ReaderAstMemory(pages,image_base,output_address,0x120,max_nodes,max_vector_bytes,reserved_regions)
    m.claim(output_address,0x120)
    for offset in range(0,0x120,24):
        if offset != 0x18 and any(_u(m.p,output_address+offset+n) for n in (0,8,16)):
            raise RefillUnsupported('AST import-only cleanup requires other output containers empty')
    begin,end,cap = m.vector(output_address+0x18,64)
    if (cap-begin)//64 > max_nodes:
        raise RefillUnsupported('AST import cleanup capacity exceeds its node bound')
    for address in range(begin,end,64): m.import_record(address)
    for address in range(end-64,begin-1,-64): m.destroy_import(address)
    if begin:
        _write_span(m.p,output_address+0x20,begin.to_bytes(8,'little'))
        m.emit('free',begin,cap-begin)
    m.p.commit()
    return ReaderAstResult(None,tuple(m.effects))


def cleanup_reader_ast_output(pages, *, output_address, image_base,
                              max_nodes=4096, max_vector_bytes=16*1024*1024,
                              reserved_regions=()):
    """Recover actual +2cbadc cleanup of the twelve output vector headers.

    Validate disjoint ownership before consuming containers from +108 to +0.
    Records are destroyed backwards through their recovered native owners;
    +90 kind4 records reset/free their vector directly without a destructor
    call. Import/export node pointers may be null. Scalar table/memory/start
    and raw containers free only their outer storage. All logical frees must
    be consumed once; begin/capacity remain dangling while end resets to begin.
    Guard or write failure rolls back pages. This API does not free the output
    object, borrowed callback caches, or attached parser state. Real allocator,
    exception, stack/TLS/OS and parser composition remain outside its proof.
    """
    m = _ReaderAstMemory(pages,image_base,output_address,0x120,max_nodes,max_vector_bytes,reserved_regions)
    m.claim(output_address,0x120)
    strides = (64,64,144,48,40,176,40,40,4,184,176,1)
    containers = []
    for offset,stride in zip(range(0,0x120,24),strides):
        begin,end,cap = m.vector(output_address+offset,stride)
        if offset not in (0xC0,0x108) and (cap-begin)//stride > max_nodes:
            raise RefillUnsupported('AST output cleanup capacity exceeds its node bound')
        for address in range(begin,end,stride) if offset not in (0x48,0x60,0xC0,0x108) else ():
            if offset == 0: m.node(address,64)
            elif offset == 0x90:
                m.nodes += 1
                if m.nodes > max_nodes:
                    raise RefillUnsupported('AST output kind4 node bound reached')
                m.vector(address+0x10,8)
                if _u(m.p,image_base+0x375088) != image_base+0x372580:
                    raise RefillUnsupported('AST output kind4 vtable source is unsupported')
            elif offset == 0x18: m.import_record(address,allow_null_node=True)
            elif offset == 0x30: m.function_record(address)
            elif offset == 0x78: m.global_record(address)
            elif offset == 0xA8: m.export_record(address,allow_null_node=True)
            elif offset == 0xD8: m.element_record(address)
            elif offset == 0xF0: m.data_record(address)
        containers.append((offset,stride,begin,end))
    for offset,stride,begin,end in reversed(containers):
        for address in range(end-stride,begin-1,-stride) if offset not in (0x48,0x60,0xC0,0x108) else ():
            if offset == 0: m.destroy(address,64)
            elif offset == 0x18: m.destroy_import(address)
            elif offset == 0x30: m.destroy_nested(address)
            elif offset == 0x78: m.destroy_global(address)
            elif offset == 0x90:
                _write_span(m.p,address,(image_base+0x372590).to_bytes(8,'little'))
                m.free_vector(address+0x10)
            elif offset == 0xA8: m.destroy_export(address)
            elif offset == 0xD8: m.destroy_element(address)
            elif offset == 0xF0: m.destroy_data(address)
        m.free_vector(output_address+offset)
    m.p.commit()
    return ReaderAstResult(None,tuple(m.effects))


def copy_reader_ast_string(pages, *, destination_address, source_address, image_base,
                           allocate=None, max_vector_bytes=16*1024*1024,
                           reserved_regions=()):
    """Copy the actual B +32a9c4 string representation into fresh storage.

    Headers are disjoint mapped 24-byte spans. Borrowed long payloads retain
    length+1 bytes through allocation; the source capacity word is ignored.
    Inline sources copy every header byte, including padding. Long sources
    of length <=22 become inline and retain unused destination bytes. Other
    copies own a new rounded buffer; the source remains borrowed. This is
    construction, so the destination must own no existing heap allocation.
    The caller must release the resulting buffer through its owning object.
    status contains the native X0 return address. Allocation is a pure plan;
    any guard/write failure rolls back all pages. Import/export callbacks and
    output cleanup are separate entry points in this owner.
    """
    m = _ReaderAstMemory(pages,image_base,destination_address,24,4096,max_vector_bytes,reserved_regions)
    m.claim(destination_address,24)
    value = m.copy_string(destination_address,source_address,allocate)
    m.p.commit()
    return ReaderAstResult(value,tuple(m.effects))


def destroy_reader_ast_type_node(pages, *, node_address, image_base,
        max_nodes=4096, max_vector_bytes=16*1024*1024, reserved_regions=()):
    """Actual +321260 non-deleting destructor: results, then params free.

    Begin/capacity remain unchanged and end resets to begin. This does not
    free the 64-byte node itself. Consume the effects once; destroyed storage
    must not be reused as a live object. Incidental native void X0 is ignored.
    """
    m = _ReaderAstMemory(pages,image_base,node_address,64,max_nodes,max_vector_bytes,reserved_regions)
    m.claim(node_address,64); m.node(node_address,64); m.destroy(node_address,64)
    m.p.commit()
    return ReaderAstResult(None,tuple(m.effects))


def destroy_reader_ast_data_record(pages, *, record_address, image_base,
        max_nodes=4096, max_vector_bytes=16*1024*1024, reserved_regions=()):
    """Actual +2cc1ec non-deleting destructor for one 176-byte data record.

    Free +98 children backwards (each +10 u64 vector), the child block,
    +70 locals, inline type results/params, then +00 payload. Each vector end
    resets to begin before free; the inline type vtable resets to +3724f0.
    The record itself is retained. Consume logical effects once and do not
    reuse destroyed storage as a live object. Native void X0 is ignored.
    """
    m = _ReaderAstMemory(pages,image_base,record_address,176,max_nodes,max_vector_bytes,reserved_regions)
    m.claim(record_address,176); m.data_record(record_address); m.destroy_data(record_address)
    m.p.commit()
    return ReaderAstResult(None,tuple(m.effects))


def destroy_reader_ast_global_record(pages, *, record_address, image_base,
        max_nodes=4096, max_vector_bytes=16*1024*1024, reserved_regions=()):
    """Actual +2cc3b4 non-deleting destructor, with the record in native X1.

    Free child payloads/block, locals, type results and params. Reset ends
    and inline type vtable; retain the outer record, scalars and padding.
    Logical free effects must be consumed once; native void X0 is ignored.
    """
    m = _ReaderAstMemory(pages,image_base,record_address,176,max_nodes,max_vector_bytes,reserved_regions)
    m.claim(record_address,176); m.global_record(record_address); m.destroy_global(record_address)
    m.p.commit()
    return ReaderAstResult(None,tuple(m.effects))


def destroy_reader_ast_function_record(pages, *, record_address, image_base,
        max_nodes=4096, max_vector_bytes=16*1024*1024, reserved_regions=()):
    """Actual +2cc470 non-deleting destructor for a 144-byte function.

    Free child payloads backwards, child block, locals, results, then params.
    Reset vector ends/type vtable; retain the record and scalar/padding bytes.
    Consume logical effects once. Native receives the address in X1.
    """
    m = _ReaderAstMemory(pages,image_base,record_address,144,max_nodes,max_vector_bytes,reserved_regions)
    m.claim(record_address,144); m.function_record(record_address); m.destroy_nested(record_address)
    m.p.commit()
    return ReaderAstResult(None,tuple(m.effects))


def destroy_reader_ast_element_record(pages, *, record_address, image_base,
        max_nodes=4096, max_vector_bytes=16*1024*1024, reserved_regions=()):
    """Actual +2cc2b8 non-deleting destructor for one 184-byte element.

    Free +a0 children backwards, +78 locals and inline type results/params,
    then destroy +00 nested 144-byte records backwards through +2cc470.
    Each nested record frees children, locals, type results and type params.
    Reset vector ends and type vtables exactly; retain the element itself.
    Consume logical effects once; native void X0 is ignored.
    """
    m = _ReaderAstMemory(pages,image_base,record_address,184,max_nodes,max_vector_bytes,reserved_regions)
    m.claim(record_address,184); m.element_record(record_address); m.destroy_element(record_address)
    m.p.commit()
    return ReaderAstResult(None,tuple(m.effects))


def cleanup_reader_callback(pages, *, callback_address, image_base,
        max_nodes=4096, max_vector_bytes=16*1024*1024, reserved_regions=(),
        attached_state_address=None):
    """Actual +31b458 cleanup: five reverse node lists, two trees, buffer.

    The five strides are 40/24/40/48/64 at e0/c8/b0/98/80. Supported node
    destructors execute their owned-vector resets/frees. Trees use left/right
    postorder +3202f0; payload end resets before its free, then node is freed.
    Tree payload vectors contain u32 offsets with four-byte element widths.
    Begin/capacity and tree roots remain dangling as in native destruction.
    The caller consumes logical free effects once. The independent record
    list and output AST are retained. An explicit attached_state_address
    retains the parser/input graph; the default rejects attached callbacks.
    The bounded module wrapper handles its empty retained-record list.
    """
    m = _ReaderAstMemory(pages,image_base,callback_address,0x108,max_nodes,max_vector_bytes,reserved_regions)
    _,lists,trees = m.callback(callback_address,attached_state_address=attached_state_address)
    _write_span(m.p,callback_address,(image_base+0x372370).to_bytes(8,'little'))
    for header,stride,begin,end,cap in lists:
        if begin:
            for node in range(end-stride,begin-1,-stride): m.destroy(node,stride)
            _write_span(m.p,header+8,begin.to_bytes(8,'little'))
            m.emit('free',begin,cap-begin)
    for tree in trees:
        for node in tree:
            m.free_vector(node+0x28); m.emit('free',node,64)
    m.free_vector(callback_address+0x30)
    m.p.commit()
    return ReaderAstResult(None,tuple(m.effects))


def run_reader_sections(pages, *, state_address, image_base,
        varuint_scratch_address, callback, max_sections=512, max_entries=4096,
        max_input_bytes=16*1024*1024, vector_allocate=None,
        enable_function_global_imports=False, enable_table_memory_imports=False,
        import_scratch_address=None, enable_table_memory_sections=False,
        enable_global_section=False, global_scratch_address=None,
        max_initializer_ops=4096, enable_code_section=False, max_code_words=65536,
        enable_element_section=False, enable_data_section=False,
        expression_scratch_address=None, max_expression_ops=4096,
        enable_special_custom_sections=False, custom_scratch_address=None,
        max_custom_records=4096, _ast_callback=None, _attached_import_stack_address=None,
        _attached_definition_stack_address=None, _attached_global_stack_address=None,
        _attached_custom_stack_address=None, _attached_custom_entry_x28=None):
    """Bounded +0x324188 dispatch with handlers 0/1/2/3/4/5/6/7/8/9/10/11/12.

    State layout: limit/data/total/cursor/callback at +0/+8/+16/+24/+32;
    previous nonzero section at +0x88, import counts at +0x90/94/98/9c,
    function count at +0xa4, data count at +0xac. Generic custom sections
    skip unrecognized payload; special custom handlers require explicit opt-in.

    callback receives immutable numeric arguments and current parser state,
    and returns an explicit uint32 status. It must be a pure status service;
    actual AST allocation/callback effects are not modeled here. Parse errors
    commit native-observable partial state with status 1. Unsupported branches
    and guard failures leave the original pages unchanged.

    The private _ast_callback bridge is used by run_reader_ast_module to run
    verified AST callbacks inside this transaction and preserve interleaved
    vector effects. The ordinary callback contract remains a status service.
    Its private attached-import stack binding retains the real ninth ABI word:
    table writes the descriptor pointer, global writes only its low byte.
    It requires the verified caller SP and descriptor at SP+8.
    The private definition binding selects the actual table SP=state-0xc0
    and memory SP=state-0xe0, with descriptors at SP. It also retains the
    type/import caller saves consumed by subsequent definition padding.
    The private global binding uses caller result=state-0xb0 and integer read
    scratch=state-0x108. Its result may reuse prior descriptor storage; saved
    dispatcher X25 from a preceding memory handler supplies its upper half.

    Section 1 requires vector_allocate(size), a pure allocation plan into
    already mapped pages. Recorded allocation/free effects are logical service
    boundaries; actual allocator boot/free and AST callbacks remain open.

    enable_function_global_imports=True opts into section 2 kinds 0 and 3.
    Events snapshot all four import counts before each callback; successful
    import callbacks increment their
    uint32 count afterward. Import names are opaque guest spans in arguments.

    enable_table_memory_imports=True requires a mapped, aligned, disjoint
    import_scratch_address with 32 bytes. Table/memory callbacks receive a
    transient descriptor pointer there and immutable import_limits values
    (minimum, maximum, has_maximum, flag_bit1, flag_bit2). This explicit model
    work region is not the original native caller's stack address.

    enable_table_memory_sections=True independently opts into sections 4/5,
    using the same scratch and descriptor contract as table/memory imports.
    Count callbacks use slots +0x58/+0x68; entry callbacks +0x60/+0x70 snapshot
    import_limits and add existing imports to the uint32 definition index.
    Definition callbacks do not increment the import counts.

    enable_global_section=True independently opts into section 6. Its mapped,
    aligned, disjoint 16-byte global_scratch_address holds an explicit caller
    local/result word followed by initializer read scratch. The caller writes
    only the low four bytes before each expression; end alone retains its high
    bytes. Initializer kinds follow the GOT pointer at image+0x3750b0, accept
    end/i32/i64/f32/f64 and stop after max_initializer_ops. This is not an AST
    interpreter or a reconstruction of naturally initialized native stack bytes.

    enable_code_section=True independently opts into section 10 +0x323ca8.
    It checks the body count against the function count, reads metadata/local
    groups and emits raw 32-bit code words. It does not execute instructions.
    max_code_words bounds all word callbacks, including native zero-word retries
    when fewer than four input bytes remain and the cursor does not advance.

    enable_element_section and enable_data_section independently opt into
    sections 9/11. Their distinct +0x3215f0 expression helper uses a mapped,
    aligned, disjoint eight-byte expression_scratch_address and a per-expression
    max_expression_ops bound. Kind zero emits +0xf0; constants emit status
    callbacks without writing a result word. Section 9 supports only empty
    element vectors: the native nonempty-vector abort remains unsupported.
    Section 11 sends +0x158(index, payload_pointer, payload_length).

    enable_special_custom_sections opts into dylink/dylink.0/linking,
    target_features and reloc prefixes. These parse metadata without AST callbacks.
    A mapped, aligned, disjoint eight-byte custom_scratch_address holds integer
    reads; decoder storage, the opcode table pointer and active expression
    opcode tables are retained.
    max_custom_records bounds the sum of subsections, list entries and
    nested pairs in EACH custom section. Unknown subsections skip opaque bytes;
    known subsections must consume their exact size. Temporary limits and the
    custom flag are restored on parse failure as well as success.
    The private attached-custom binding requires caller SP=state-0xf0 and
    retains linking's local fields/saved FP in [state-0x160,state-0x148),
    where subsequent inline exports consume them. It models those stores
    during the existing parse, without a second parser or native snapshots.
    With attached table/memory definitions, explicit incoming X28 is also
    required: linking saves it at state-0x140, later table node padding.
    """
    if (not isinstance(state_address, int) or not 0 < state_address <= MASK64-0xAF
            or state_address & 7 or not isinstance(image_base, int)
            or not 0 < image_base <= MASK64-0x3E2D74 or image_base & 4095
            or not isinstance(varuint_scratch_address, int)
            or not 0 < varuint_scratch_address <= MASK64-3):
        raise RefillUnsupported('reader section addresses exceed the bounded guest ABI')
    if (not callable(callback) or (_ast_callback is not None and not callable(_ast_callback))
            or not isinstance(max_sections, int)
            or not 1 <= max_sections <= 4096 or not isinstance(max_entries, int)
            or not 1 <= max_entries <= 65536 or not isinstance(max_input_bytes, int)
            or not 0 <= max_input_bytes <= 16*1024*1024
            or not isinstance(enable_function_global_imports, bool)
            or not isinstance(enable_table_memory_imports, bool)
            or not isinstance(enable_table_memory_sections, bool)
            or not isinstance(enable_global_section, bool)
            or not isinstance(max_initializer_ops, int)
            or not 1 <= max_initializer_ops <= 65536
            or not isinstance(enable_code_section, bool)
            or not isinstance(max_code_words, int) or not 1 <= max_code_words <= 1048576
            or not isinstance(enable_element_section, bool)
            or not isinstance(enable_data_section, bool)
            or not isinstance(max_expression_ops, int) or not 1 <= max_expression_ops <= 65536
            or not isinstance(enable_special_custom_sections, bool)
            or not isinstance(max_custom_records, int) or not 1 <= max_custom_records <= 65536):
        raise RefillUnsupported('reader section service or traversal limits are invalid')
    p = _PageTransaction(pages)
    data, total, initial_limit, initial_cursor = (_u(p, state_address+offset)
                                                 for offset in (8, 16, 0, 24))
    if (not data or data+total > MASK64+1 or not 0 <= initial_cursor <= total
            or not initial_cursor <= initial_limit <= total or total > max_input_bytes):
        raise RefillUnsupported('reader section state requires bounded initial input')
    regions = [(state_address, state_address+0xB0), (data, data+total)]
    if any(start < varuint_scratch_address+4 and varuint_scratch_address < end
           for start, end in regions):
        raise RefillUnsupported('reader varuint scratch overlaps retained input or state')
    if regions[0][0] < regions[1][1] and regions[1][0] < regions[0][1]:
        raise RefillUnsupported('reader input and state must be disjoint')
    if _attached_import_stack_address is not None:
        if (_ast_callback is None or _attached_import_stack_address != state_address-0x100
                or not enable_table_memory_imports
                or import_scratch_address != _attached_import_stack_address+8):
            raise RefillUnsupported('reader attached import caller frame is inconsistent')
        _read_span(p, _attached_import_stack_address, 8)
    if _attached_definition_stack_address is not None:
        if (_ast_callback is None or not enable_table_memory_sections
                or _attached_definition_stack_address != state_address-0xC0
                or _attached_definition_stack_address & 15):
            raise RefillUnsupported('reader attached definition caller frame is inconsistent')
        if any(start < _attached_definition_stack_address+32
               and _attached_definition_stack_address-0x20 < end
               for start,end in (*regions,(varuint_scratch_address,varuint_scratch_address+4))):
            raise RefillUnsupported('reader attached definition frame overlaps retained storage')
        _read_span(p,_attached_definition_stack_address-0x20,64)
    if enable_table_memory_imports or enable_table_memory_sections:
        if (not isinstance(import_scratch_address, int) or import_scratch_address & 7
                or not 0 < import_scratch_address <= MASK64-31):
            raise RefillUnsupported('reader table/memory imports need an aligned scratch region')
        scratch_end = import_scratch_address+32
        retained = (*regions, (varuint_scratch_address, varuint_scratch_address+4))
        for offset in (0x28, 0x40):
            begin, _, capacity_end = _reader_vector_words(p, state_address+offset, max_entries, retained)
            retained += ((begin, capacity_end),)
        if any(start < scratch_end and import_scratch_address < end for start, end in retained):
            raise RefillUnsupported('reader import scratch overlaps retained storage')
        _read_span(p, import_scratch_address, 32)
        regions.append((import_scratch_address, scratch_end))
    if _attached_definition_stack_address is not None:
        regions.append((_attached_definition_stack_address-0x20,
                        _attached_definition_stack_address+32))
    if enable_global_section:
        global_read_scratch = global_scratch_address+8 if isinstance(global_scratch_address,int) else None
        if _attached_global_stack_address is not None:
            if (_ast_callback is None or _attached_global_stack_address != state_address-0xB0
                    or global_scratch_address != _attached_global_stack_address
                    or _attached_global_stack_address & 15):
                raise RefillUnsupported('reader attached global caller frame is inconsistent')
            # +32365c's 0x60-byte frame; integer reads use SP+8.
            global_read_scratch = _attached_global_stack_address-0x58
            _read_span(p,global_read_scratch,8)
        if (not isinstance(global_scratch_address, int) or global_scratch_address & 7
                or not 0 < global_scratch_address <= MASK64-15):
            raise RefillUnsupported('reader globals need an aligned 16-byte scratch region')
        scratch_end = global_scratch_address+16
        retained = (*regions, (varuint_scratch_address, varuint_scratch_address+4))
        for offset in (0x28, 0x40):
            begin, _, capacity_end = _reader_vector_words(p, state_address+offset, max_entries, retained)
            retained += ((begin, capacity_end),)
        if any(start < scratch_end and global_scratch_address < end for start, end in retained
               if not (_attached_global_stack_address is not None
                   and _attached_definition_stack_address is not None
                   and (start,end) in ((import_scratch_address,import_scratch_address+32),
                       (_attached_definition_stack_address-0x20,_attached_definition_stack_address+32)))):
            raise RefillUnsupported('reader global scratch overlaps retained storage')
        if _attached_global_stack_address is not None:
            if any(start < global_read_scratch+8 and global_read_scratch < end for start,end in retained):
                raise RefillUnsupported('reader global read scratch overlaps retained storage')
            regions.append((global_read_scratch,global_read_scratch+8))
        _read_span(p, global_scratch_address, 16)
        regions.append((global_scratch_address, scratch_end))
    elif _attached_global_stack_address is not None:
        raise RefillUnsupported('reader attached globals require the global section opt-in')
    if _attached_custom_stack_address is not None:
        if (_ast_callback is None or not enable_special_custom_sections
                or _attached_custom_stack_address != state_address-0xF0
                or _attached_custom_stack_address & 15):
            raise RefillUnsupported('reader attached custom caller frame is inconsistent')
        if _attached_custom_entry_x28 is not None and (isinstance(_attached_custom_entry_x28,bool)
                or not isinstance(_attached_custom_entry_x28,int) or not 0 <= _attached_custom_entry_x28 <= MASK64):
            raise RefillUnsupported('reader attached custom saved X28 is invalid')
        if _attached_definition_stack_address is not None and _attached_custom_entry_x28 is None:
            raise RefillUnsupported('reader custom/table composition needs explicit incoming X28')
        # +322130's 0x90-byte linking frame: these locals and saved FP
        # become the first inline export string at state-0x160.
        header = _attached_custom_stack_address-0x70
        for start,end in ((header,header+24),(_attached_custom_stack_address-0x10,_attached_custom_stack_address-8),
                          (_attached_custom_stack_address-0x50,_attached_custom_stack_address-0x48)):
            if any(a < end and start < b for a,b in (*regions,(varuint_scratch_address,varuint_scratch_address+4))):
                raise RefillUnsupported('reader attached custom caller saves overlap retained storage')
            _read_span(p,start,end-start)
            regions.append((start,end))
    if enable_element_section or enable_data_section:
        if (not isinstance(expression_scratch_address, int) or expression_scratch_address & 7
                or not 0 < expression_scratch_address <= MASK64-7):
            raise RefillUnsupported('reader segment expressions need an aligned eight-byte scratch region')
        scratch_end = expression_scratch_address+8
        retained = (*regions, (varuint_scratch_address, varuint_scratch_address+4))
        for offset in (0x28, 0x40):
            begin, _, capacity_end = _reader_vector_words(p, state_address+offset, max_entries, retained)
            retained += ((begin, capacity_end),)
        if any(start < scratch_end and expression_scratch_address < end for start, end in retained):
            raise RefillUnsupported('reader expression scratch overlaps retained storage')
        _read_span(p, expression_scratch_address, 8)
        regions.append((expression_scratch_address, scratch_end))
    if enable_special_custom_sections:
        if (not isinstance(custom_scratch_address, int) or custom_scratch_address & 7
                or not 0 < custom_scratch_address <= MASK64-7):
            raise RefillUnsupported('reader custom handlers need an aligned eight-byte scratch region')
        scratch_end = custom_scratch_address+8
        retained = (*regions, (varuint_scratch_address, varuint_scratch_address+4),
                    (image_base+0x3750B0, image_base+0x3750B8),
                    (image_base+0x121110, image_base+0x121218),
                    (image_base+0x3E2CFC, image_base+0x3E2D74))
        if enable_global_section or enable_element_section or enable_data_section:
            table = _u(p, image_base+0x3750B0)
            retained += ((table, table+512),)
        for offset in (0x28, 0x40):
            begin, _, capacity_end = _reader_vector_words(p, state_address+offset, max_entries, retained)
            retained += ((begin, capacity_end),)
        if any(start < scratch_end and custom_scratch_address < end for start, end in retained):
            raise RefillUnsupported('reader custom scratch overlaps retained storage')
        _read_span(p, custom_scratch_address, 8)
        regions.append((custom_scratch_address, scratch_end))
    entered = []
    events = []
    vector_effects = []
    seen = set()

    def store(offset, value, width=8):
        _write_span(p, state_address+offset, value.to_bytes(width, 'little'))

    def cursor():
        return _u(p, state_address+24)

    def limit():
        return _u(p, state_address)

    def read_u32(output_address=varuint_scratch_address):
        result = read_reader_varuint32(p, start_address=data+cursor(),
            end_address=data+limit(), output_address=output_address)
        if not result.bytes_consumed:
            raise _ReaderParseFailure()
        store(24, cursor()+result.bytes_consumed)
        return result.value

    def read_i32(output_address=varuint_scratch_address):
        result = read_reader_varint32(p, start_address=data+cursor(),
            end_address=data+limit(), output_address=output_address)
        if not result.bytes_consumed:
            raise _ReaderParseFailure()
        store(24, cursor()+result.bytes_consumed)
        return result.value

    def read_u64():
        result = read_reader_varuint64(p, start_address=data+cursor(),
            end_address=data+limit(), output_address=import_scratch_address+24)
        if not result.bytes_consumed:
            raise _ReaderParseFailure()
        store(24, cursor()+result.bytes_consumed)
        return result.value

    def emit(slot, *arguments, type_vectors=()):
        if _attached_import_stack_address is not None:
            if slot == 0x30:
                # +322f18 publishes the descriptor as the ninth ABI argument.
                _write_span(p,_attached_import_stack_address,import_scratch_address.to_bytes(8,'little'))
            elif slot == 0x40:
                # +323024 only replaces the low byte of the incoming word.
                _write_span(p,_attached_import_stack_address,bytes((arguments[-1],)))
                arguments = (*arguments[:-1],_u(p,_attached_import_stack_address))
        counts = tuple(_u(p, state_address+offset, 4) for offset in (0x90, 0x94, 0x98, 0x9C))
        import_limits = ()
        if slot in (0x30, 0x38, 0x60, 0x70):
            descriptor = _read_span(p, import_scratch_address, 19)
            import_limits = (int.from_bytes(descriptor[:8], 'little'),
                             int.from_bytes(descriptor[8:16], 'little'), *descriptor[16:])
        event = ReaderCallbackEvent(slot, tuple(arguments), cursor(), limit(), type_vectors,
                                    counts, import_limits)
        status = (callback(event) if _ast_callback is None else
                  _ast_callback(p,event,tuple(vector_effects)))
        if not isinstance(status, int) or not 0 <= status <= 0xFFFFFFFF:
            raise RefillUnsupported('reader callback must return an explicit uint32 status')
        events.append(event)
        if status:
            raise _ReaderParseFailure()

    def decode(source_offset, key_size, size, destination_offset, flag_offset):
        flag_address = image_base+flag_offset
        target = image_base+destination_offset
        if _u(p, flag_address, 4) != 1:
            raw = _read_span(p, image_base+source_offset, key_size+size)
            _write_span(p, target, bytes(raw[key_size+i] ^ raw[i % key_size]
                                        for i in range(size)))
            _write_span(p, flag_address, (1).to_bytes(4, 'little'))
        return _read_span(p, target, size)

    def rank(number):
        if number >= 14:
            raise RefillUnsupported('reader previous-section rank abort path is unrecovered')
        table = decode(0x1211D0, 16, 56, 0x3E2D38, 0x3E2D70)
        return int.from_bytes(table[number*4:number*4+4], 'little', signed=True)

    def bounded_count(count):
        if count > (limit()-cursor()) & MASK64:
            raise _ReaderParseFailure()
        if count > max_entries:
            raise RefillUnsupported('reader section entry bound reached')

    def resize_types(offset, count):
        other = state_address+(0x40 if offset == 0x28 else 0x28)
        other_begin, _, other_cap = _reader_vector_words(p, other, max_entries, regions)
        retained = (*regions, (varuint_scratch_address, varuint_scratch_address+4),
                    (other_begin, other_cap))
        address = state_address+offset
        begin, end, cap = _reader_vector_words(p, address, max_entries, retained)
        size = (end-begin)//8
        if count > size:
            result = grow_reader_word_vector(p, vector_address=address,
                additional_count=count-size, allocate=vector_allocate,
                max_elements=max_entries, reserved_regions=retained)
            vector_effects.extend(result.effects)
            begin = result.begin
        elif count < size:
            store(offset+8, begin+count*8)
        return begin if count else 0

    def type_vector(offset):
        count = read_u32()
        bounded_count(count)
        begin = resize_types(offset, count)
        values = []
        for index in range(count):
            value = read_i32()
            if value == -21:
                read_i32()
                raise _ReaderParseFailure()
            if value not in (-5, -4, -3, -2, -1, -17, -16):
                raise _ReaderParseFailure()
            word = value & MASK64
            _write_span(p, begin+index*8, word.to_bytes(8, 'little'))
            values.append(word)
        return count, begin, tuple(values)

    def table_memory_descriptor(kind):
        _write_span(p, import_scratch_address, bytes(19))
        value = None
        if kind == 1:
            value = read_i32()
            if value not in (-21, -17, -16):
                raise _ReaderParseFailure()
        if cursor()+1 > limit():
            raise _ReaderParseFailure()
        flags = _u(p, data+cursor(), 1)
        store(24, cursor()+1)
        if flags > 7 or flags & 2:
            raise _ReaderParseFailure()
        read_bound = read_u32 if kind == 1 else read_u64
        minimum = read_bound()
        maximum = read_bound() if flags & 1 else 0
        flag_bytes = bytes((flags & 1, 0, (flags >> 2) & 1 if kind == 2 else 0))
        descriptor = minimum.to_bytes(8, 'little')+maximum.to_bytes(8, 'little')+flag_bytes
        _write_span(p, import_scratch_address, descriptor)
        return value

    def initializer():
        if cursor() >= limit():
            raise _ReaderParseFailure()
        table = _u(p, image_base+0x3750B0)
        if not table or table > MASK64-511 or table & 3:
            raise RefillUnsupported('reader initializer opcode table pointer is invalid')
        if any(start < table+512 and table < end for start, end in
               ((global_scratch_address, global_scratch_address+16),
                (global_read_scratch, global_read_scratch+8),
                (varuint_scratch_address, varuint_scratch_address+4))):
            raise RefillUnsupported('reader initializer opcode table overlaps scratch')
        for _ in range(max_initializer_ops):
            if cursor() >= limit():
                raise _ReaderParseFailure()
            opcode = _u(p, data+cursor(), 1)
            store(24, cursor()+1)
            if opcode in (0xFC, 0xFD, 0xFE):
                subopcode = read_u32(global_read_scratch)
                kind = -((opcode << 9) | min(subopcode, 511)) & 0xFFFFFFFF
            else:
                kind = _u(p, table+opcode*4, 4) if opcode < 128 else 0
                if opcode and not kind:
                    kind = -opcode & 0xFFFFFFFF
            emit(0xC0, kind)
            if kind == 1:
                emit(0xC8)
                return
            if kind == 2:
                bits = read_i32(global_read_scratch) & 0xFFFFFFFF
                emit(0xE0, bits)
            elif kind == 3:
                result = read_reader_varint64(p, start_address=data+cursor(),
                    end_address=data+limit(), output_address=global_read_scratch)
                if not result.bytes_consumed:
                    raise _ReaderParseFailure()
                store(24, cursor()+result.bytes_consumed)
                bits = result.value & MASK64
                emit(0xE8, bits)
            elif kind in (4, 5):
                width = 4 if kind == 4 else 8
                if cursor()+width > limit():
                    raise _ReaderParseFailure()
                bits = _u(p, data+cursor(), width)
                store(24, cursor()+width)
                emit(0xD0 if kind == 4 else 0xD8, bits)
            else:
                raise _ReaderParseFailure()
            _write_span(p, global_scratch_address, bits.to_bytes(8, 'little'))
        if cursor() >= limit():
            raise _ReaderParseFailure()
        raise RefillUnsupported('reader initializer operation bound reached')

    def segment_expression():
        if cursor() >= limit():
            raise _ReaderParseFailure()
        table = _u(p, image_base+0x3750B0)
        if not table or table > MASK64-511 or table & 3:
            raise RefillUnsupported('reader expression opcode table pointer is invalid')
        if any(start < table+512 and table < end for start, end in
               ((expression_scratch_address, expression_scratch_address+8),
                (varuint_scratch_address, varuint_scratch_address+4))):
            raise RefillUnsupported('reader expression opcode table overlaps scratch')
        for _ in range(max_expression_ops):
            if cursor() >= limit():
                raise _ReaderParseFailure()
            opcode = _u(p, data+cursor(), 1)
            store(24, cursor()+1)
            if opcode in (0xFC, 0xFD, 0xFE):
                subopcode = read_u32(expression_scratch_address)
                kind = -((opcode << 9) | min(subopcode, 511)) & 0xFFFFFFFF
            else:
                kind = _u(p, table+opcode*4, 4) if opcode < 128 else 0
                if opcode and not kind:
                    kind = -opcode & 0xFFFFFFFF
            emit(0xC0, kind)
            if kind == 0:
                emit(0xF0)
            elif kind == 1:
                emit(0xC8)
                return
            elif kind == 2:
                emit(0xE0, read_i32(expression_scratch_address) & 0xFFFFFFFF)
            elif kind == 3:
                result = read_reader_varint64(p, start_address=data+cursor(),
                    end_address=data+limit(), output_address=expression_scratch_address)
                if not result.bytes_consumed:
                    raise _ReaderParseFailure()
                store(24, cursor()+result.bytes_consumed)
                emit(0xE8, result.value & MASK64)
            elif kind in (4, 5):
                width = 4 if kind == 4 else 8
                if cursor()+width > limit():
                    raise _ReaderParseFailure()
                bits = _u(p, data+cursor(), width)
                store(24, cursor()+width)
                emit(0xD0 if kind == 4 else 0xD8, bits)
            else:
                raise _ReaderParseFailure()
        if cursor() >= limit():
            raise _ReaderParseFailure()
        raise RefillUnsupported('reader expression operation bound reached')

    def special_custom(kind,name_size):
        if not enable_special_custom_sections:
            raise RefillUnsupported('reader special custom-section handler needs explicit opt-in')
        records = 0
        if _attached_custom_stack_address is not None:
            # +321f10/+322064 save x19=state; +321b3c/+322148/+3219a0
            # save x20=name size. A later global import replaces only byte 0.
            saved = state_address if kind in ('dylink','target_features') else name_size
            _write_span(p,_attached_custom_stack_address-0x10,saved.to_bytes(8,'little'))
        linking = kind == 'linking'
        if linking and _attached_custom_stack_address is not None and _attached_custom_entry_x28 is not None:
            # +322138 retains X28 at state-0x140; its high word becomes
            # table definition node padding at state-0x13c (+31cb34).
            _write_span(p,_attached_custom_stack_address-0x50,_attached_custom_entry_x28.to_bytes(8,'little'))
        header = _attached_custom_stack_address-0x70 if linking and _attached_custom_stack_address is not None else None

        def header_store(offset,value,width=4):
            if header is not None:
                _write_span(p,header+offset,value.to_bytes(width,'little'))

        # +322134 saves the caller FP before the version read.
        header_store(16,state_address-0xD0,8)

        def record():
            nonlocal records
            if records >= max_custom_records:
                raise RefillUnsupported('reader custom record bound reached')
            records += 1

        def u32(offset=None,clear=False):
            if offset is not None and clear:
                header_store(offset,0)
            value = read_u32(custom_scratch_address)
            if offset is not None:
                header_store(offset,value)
            return value

        def string():
            size = u32(12 if linking else None,clear=True)
            start = cursor()
            if start+size > limit():
                raise _ReaderParseFailure()
            store(24, start+size)

        if kind == 'dylink':
            for _ in range(4):
                u32()
            for _ in range(u32()):
                record()
                string()
        elif kind == 'target_features':
            for _ in range(u32()):
                record()
                if cursor()+1 > limit():
                    raise _ReaderParseFailure()
                store(24, cursor()+1)
                string()
        elif kind == 'reloc':
            u32()
            count = u32()
            if count > limit()-cursor():
                raise _ReaderParseFailure()
            for _ in range(count):
                record()
                relocation = u32()
                u32()
                u32()
                if relocation > 34:
                    raise _ReaderParseFailure()
                if not (1 << relocation) & 0x7F81C34C7:
                    if not (1 << relocation) & 0x63CB38:
                        raise _ReaderParseFailure()
                    result = read_reader_varint64(p, start_address=data+cursor(),
                        end_address=data+limit(), output_address=custom_scratch_address)
                    if not result.bytes_consumed:
                        raise _ReaderParseFailure()
                    store(24, cursor()+result.bytes_consumed)
        else:
            if linking and u32(8) != 2:
                raise _ReaderParseFailure()
            while cursor() < limit():
                record()
                tag, size = u32(4 if linking else None), u32(12 if linking else None)
                end = cursor()+size
                old_limit = limit()
                if end > old_limit:
                    raise _ReaderParseFailure()
                store(0, end)
                try:
                    if not linking and tag == 1:
                        for _ in range(4):
                            u32()
                    elif (not linking and tag in (2, 3, 4)) or (linking and tag in (5, 6, 7, 8)):
                        count = u32(0 if linking else None)
                        countdown = linking and tag in (6,7)
                        if countdown:
                            header_store(0,(count-1)&0xFFFFFFFF)
                        for index in range(count):
                            record()
                            if not linking:
                                string()
                                if tag == 4:
                                    string()
                                if tag in (3, 4):
                                    u32()
                            elif tag == 5:
                                string()
                                if u32(12) >= 32:
                                    raise _ReaderParseFailure()
                                u32()
                            elif tag == 6:
                                u32(12)
                                u32()
                            elif tag == 7:
                                string()
                                u32()
                                for _ in range(u32()):
                                    record()
                                    u32(12)
                                    u32()
                            else:
                                symbol, flags = u32(), u32()
                                if symbol in (0, 2, 4, 5):
                                    u32()
                                    if flags & 0x50 != 0x10:
                                        string()
                                elif symbol == 1:
                                    string()
                                    if not flags & 0x10:
                                        for _ in range(3):
                                            u32()
                                elif symbol == 3:
                                    u32(12,clear=True)
                            if countdown:
                                # +322338/+3223ac/+322494 decrement before
                                # the next test, retaining -1 on completion.
                                header_store(0,(count-index-2)&0xFFFFFFFF)
                    else:
                        store(24, end)
                    if cursor() != end:
                        raise _ReaderParseFailure()
                finally:
                    store(0, old_limit)

    def handler(number):
        nonlocal import_scratch_address
        if (_attached_definition_stack_address is not None or _attached_global_stack_address is not None) and number in (0,1,2):
            # +322704/+32270c, +32298c/+322994 and +322cfc/+322d04 save the dispatcher's
            # FP and x26 (the input limit) in later descriptor tail bytes.
            _write_span(p,state_address-0xD0,(state_address-0x50).to_bytes(8,'little'))
            _write_span(p,state_address-0xB0,initial_limit.to_bytes(8,'little'))
        if _attached_global_stack_address is not None and number == 5:
            # +3232e4 saves dispatcher X25 (+3241cc/+3241d0) here.
            # A following end-only global retains this word's upper half.
            _write_span(p,state_address-0xB0,(image_base+0x1210F8).to_bytes(8,'little'))
        if number == 0:
            size = read_u32()
            start = cursor()
            if start+size > limit():
                raise _ReaderParseFailure()
            store(24, start+size)
            old_flag = _u(p, state_address+0x8C, 1)
            store(0x8C, 1, 1)
            name = _read_span(p, data+start, size)
            markers = {
                6: (0x12112F, 30, 7, 0x3E2D0C, 0x3E2D14),
                8: (0x121110, 22, 9, 0x3E2CFC, 0x3E2D08),
                7: (0x12117F, 27, 8, 0x3E2D2C, 0x3E2D34),
                15: (0x121154, 27, 16, 0x3E2D18, 0x3E2D28),
            }
            try:
                kind = None
                if size in (6, 8) and name == decode(*markers[size])[:-1]:
                    kind = 'dylink' if size == 6 else 'dylink.0'
                elif size >= 5 and name[:5] == b'reloc':
                    kind = 'reloc'
                elif size in (7, 15) and name == decode(*markers[size])[:-1]:
                    kind = 'linking' if size == 7 else 'target_features'
                if kind is None:
                    store(24, limit())
                else:
                    special_custom(kind,size)
            finally:
                store(0x8C, old_flag, 1)
        elif number == 1:
            if not callable(vector_allocate):
                raise RefillUnsupported('reader type section needs an explicit vector allocation service')
            retained = (*regions, (varuint_scratch_address, varuint_scratch_address+4))
            params_begin, _, params_cap = _reader_vector_words(
                p, state_address+0x28, max_entries, retained)
            _reader_vector_words(p, state_address+0x40, max_entries,
                                 (*retained, (params_begin, params_cap)))
            count = read_u32()
            bounded_count(count)
            emit(0x18, count)
            for index in range(count):
                if cursor()+1 > limit():
                    raise _ReaderParseFailure()
                form = _u(p, data+cursor(), 1)
                store(24, cursor()+1)
                if form != 0x60:
                    raise _ReaderParseFailure()
                nparams, params, param_values = type_vector(0x28)
                nresults, results, result_values = type_vector(0x40)
                emit(0x20, index, nparams, params, nresults, results,
                     type_vectors=(param_values, result_values))
        elif number == 2:
            if not (enable_function_global_imports or enable_table_memory_imports):
                raise RefillUnsupported('reader imports need explicit opt-in')
            count = read_u32()
            bounded_count(count)
            for index in range(count):
                names = []
                for _ in range(2):
                    size = read_u32()
                    start = cursor()
                    if start+size > limit():
                        raise _ReaderParseFailure()
                    store(24, start+size)
                    names.extend((data+start, size))
                if cursor()+1 > limit():
                    raise _ReaderParseFailure()
                kind = _u(p, data+cursor(), 1)
                store(24, cursor()+1)
                if kind > 3:
                    raise _ReaderParseFailure()
                if kind == 0:
                    if not enable_function_global_imports:
                        raise RefillUnsupported('reader function imports need explicit opt-in')
                    type_index = read_u32()
                    imported = _u(p, state_address+0x90, 4)
                    emit(0x28, index, *names, imported, type_index)
                    store(0x90, (imported+1) & 0xFFFFFFFF, 4)
                elif kind == 3:
                    if not enable_function_global_imports:
                        raise RefillUnsupported('reader global imports need explicit opt-in')
                    value = read_i32()
                    if value == -21:
                        read_i32()
                        raise _ReaderParseFailure()
                    if value not in (-5, -4, -3, -2, -1, -17, -16):
                        raise _ReaderParseFailure()
                    if cursor()+1 > limit():
                        raise _ReaderParseFailure()
                    mutable = _u(p, data+cursor(), 1)
                    store(24, cursor()+1)
                    if mutable > 1:
                        raise _ReaderParseFailure()
                    imported = _u(p, state_address+0x9C, 4)
                    emit(0x40, index, *names, imported, value & MASK64, mutable)
                    store(0x9C, (imported+1) & 0xFFFFFFFF, 4)
                else:
                    if not enable_table_memory_imports:
                        raise RefillUnsupported('reader table/memory imports need explicit opt-in')
                    value = table_memory_descriptor(kind)
                    offset = 0x94 if kind == 1 else 0x98
                    imported = _u(p, state_address+offset, 4)
                    if kind == 1:
                        emit(0x30, index, *names, imported, value & MASK64,
                             import_scratch_address)
                    else:
                        emit(0x38, index, *names, imported, import_scratch_address)
                    store(offset, (imported+1) & 0xFFFFFFFF, 4)
        elif number == 3:
            count = read_u32()
            store(0xA4, count, 4)
            bounded_count(count)
            for index in range(count):
                imported = _u(p, state_address+0x90, 4)
                type_index = read_u32()
                emit(0x50, (index+imported) & 0xFFFFFFFF, type_index)
        elif number in (4, 5):
            if not enable_table_memory_sections:
                raise RefillUnsupported('reader table/memory sections need explicit opt-in')
            if _attached_definition_stack_address is not None:
                import_scratch_address = _attached_definition_stack_address-(0x20 if number == 5 else 0)
            count = read_u32()
            bounded_count(count)
            emit(0x58 if number == 4 else 0x68, count)
            for index in range(count):
                imported = _u(p, state_address+(0x94 if number == 4 else 0x98), 4)
                value = table_memory_descriptor(1 if number == 4 else 2)
                entry_index = (index+imported) & 0xFFFFFFFF
                if number == 4:
                    emit(0x60, entry_index, value & MASK64, import_scratch_address)
                else:
                    emit(0x70, entry_index, import_scratch_address)
        elif number == 6:
            if not enable_global_section:
                raise RefillUnsupported('reader global section needs explicit opt-in')
            count = read_u32(global_scratch_address)
            bounded_count(count)
            emit(0x78, count)
            for index in range(count):
                imported = _u(p, state_address+0x9C, 4)
                _write_span(p, global_scratch_address, bytes(4))
                value = read_i32(global_scratch_address)
                if value == -21:
                    read_i32()
                    raise _ReaderParseFailure()
                if value not in (-5, -4, -3, -2, -1, -17, -16):
                    raise _ReaderParseFailure()
                if cursor()+1 > limit():
                    raise _ReaderParseFailure()
                mutable = _u(p, data+cursor(), 1)
                store(24, cursor()+1)
                if mutable > 1:
                    raise _ReaderParseFailure()
                entry_index = (index+imported) & 0xFFFFFFFF
                emit(0x80, entry_index, value & MASK64, mutable)
                emit(0x88, entry_index)
                initializer()
                emit(0x90, entry_index, _u(p, global_scratch_address))
        elif number == 7:
            count = read_u32()
            bounded_count(count)
            for index in range(count):
                size = read_u32()
                start = cursor()
                if start+size > limit():
                    raise _ReaderParseFailure()
                store(24, start+size)
                if cursor()+1 > limit():
                    raise _ReaderParseFailure()
                kind = _u(p, data+cursor(), 1)
                store(24, cursor()+1)
                if kind > 4:
                    raise _ReaderParseFailure()
                target = read_u32()
                if kind == 4:
                    raise _ReaderParseFailure()
                emit(0x98, index, kind, target, data+start, size)
        elif number == 9:
            if not enable_element_section:
                raise RefillUnsupported('reader element section needs explicit opt-in')
            count = read_u32()
            bounded_count(count)
            emit(0x100, count)
            for index in range(count):
                flags = read_u32()
                if flags > 7:
                    raise _ReaderParseFailure()
                table_index = read_u32() if flags & 3 == 2 else 0
                emit(0x108, index, table_index, flags)
                if not flags & 1:
                    emit(0x110, index)
                    segment_expression()
                    emit(0x118, index)
                value = -16
                if flags & 3:
                    if flags & 4:
                        value = read_i32()
                        if value not in (-21, -17, -16):
                            raise _ReaderParseFailure()
                    else:
                        if cursor()+1 > limit():
                            raise _ReaderParseFailure()
                        element_kind = _u(p, data+cursor(), 1)
                        store(24, cursor()+1)
                        if element_kind:
                            raise _ReaderParseFailure()
                emit(0x120, index, value & MASK64)
                size = read_u32()
                bounded_count(size)
                emit(0x128, index, size)
                if size:
                    raise RefillUnsupported('reader nonempty element vector native abort is unsupported')
        elif number == 11:
            if not enable_data_section:
                raise RefillUnsupported('reader data section needs explicit opt-in')
            count = read_u32()
            bounded_count(count)
            expected = _u(p, state_address+0xAC, 4)
            if expected != 0xFFFFFFFF and expected != count:
                raise _ReaderParseFailure()
            for index in range(count):
                flags = read_u32()
                if flags > 7:
                    raise _ReaderParseFailure()
                memory_index = read_u32() if flags & 2 else 0
                emit(0x140, index, memory_index, flags)
                if not flags & 1:
                    emit(0x148, index)
                    segment_expression()
                    emit(0x150, index)
                size = read_u32()
                start = cursor()
                if start+size > limit():
                    raise _ReaderParseFailure()
                store(24, start+size)
                emit(0x158, index, data+start, size)
        elif number == 10:
            if not enable_code_section:
                raise RefillUnsupported('reader code section needs explicit opt-in')
            payload_start = cursor()
            count = read_u32()
            store(0xA8, count, 4)
            bounded_count(count)
            if count != _u(p, state_address+0xA4, 4):
                raise _ReaderParseFailure()
            word_callbacks = 0
            for index in range(count):
                imported = _u(p, state_address+0x90, 4)
                body_size = read_u32()
                body_start = cursor()
                metadata = read_u32()
                groups = read_u32()
                bounded_count(groups)
                emit(0xB0, groups)
                entry_index = (index+imported) & 0xFFFFFFFF
                remaining_body_bytes = (body_size-(cursor()-body_start)) & 0xFFFFFFFF
                emit(0xA8, entry_index, cursor()-payload_start, remaining_body_bytes, metadata)
                total_locals = 0
                for group in range(groups):
                    local_count = read_u32()
                    total_locals += local_count
                    if total_locals > 0xFFFFFFFF:
                        raise _ReaderParseFailure()
                    value = read_i32()
                    if value == -21:
                        read_i32()
                        raise _ReaderParseFailure()
                    if value not in (-5, -4, -3, -2, -1, -17, -16):
                        raise _ReaderParseFailure()
                    emit(0xB8, group, local_count, value & MASK64)
                body_end = body_start+body_size
                while cursor() < body_end:
                    if word_callbacks >= max_code_words:
                        raise RefillUnsupported('reader code word callback bound reached')
                    word_callbacks += 1
                    bits = 0
                    if cursor()+4 <= limit():
                        bits = _u(p, data+cursor(), 4)
                        store(24, cursor()+4)
                    emit(0x168, bits)
                if cursor() != body_end:
                    raise _ReaderParseFailure()
                emit(0xF8, entry_index, remaining_body_bytes)
        elif number in (8, 12):
            value = read_u32()
            emit(0xA0 if number == 8 else 0x160, value)
            if number == 12:
                store(0xAC, value, 4)
        else:
            raise RefillUnsupported('reader section handler is unrecovered: '+str(number))

    status = 0
    outer_limit = initial_limit
    try:
        while cursor() < total:
            if len(entered) >= max_sections:
                raise RefillUnsupported('reader section traversal bound reached')
            if cursor() >= limit():
                raise _ReaderParseFailure()
            number = _u(p, data+cursor(), 1)
            store(24, cursor()+1)
            size = read_u32()
            outer_limit = limit()
            section_end = cursor()+size
            store(0, section_end)
            entered.append(number)
            try:
                if number > 13 or number in seen or section_end > total:
                    raise _ReaderParseFailure()
                if number:
                    seen.add(number)
                previous = _u(p, state_address+0x88, 4)
                if previous != 0xFFFFFFFF and number and rank(number) <= rank(previous):
                    raise _ReaderParseFailure()
                if number == 13:
                    raise _ReaderParseFailure()
                handler(number)
                if cursor() != section_end:
                    raise _ReaderParseFailure()
                if number:
                    store(0x88, number, 4)
            finally:
                store(0, outer_limit)
    except _ReaderParseFailure:
        status = 1
    result = ReaderSectionsResult(status, cursor(), _u(p, state_address+0x88, 4),
                                  tuple(entered), tuple(events), tuple(vector_effects))
    p.commit()
    return result


@dataclass(frozen=True)
class ReaderAstModuleResult:
    status: int
    sections: ReaderSectionsResult | None
    effects: tuple[ReaderAstEffect | ReaderVectorEffect, ...]


def run_reader_ast_module(pages, *, image_base, input_address, input_size,
        output_address, entry_stack_address, varuint_scratch_address, allocate,
        context_address=0, context_size=0, max_sections=512, max_entries=4096,
        max_input_bytes=16*1024*1024, max_nodes=4096,
        max_vector_bytes=16*1024*1024, reserved_regions=(), enable_function_imports=False,
        enable_inline_function_imports=False, enable_table_memory_global_imports=False,
        enable_inline_table_memory_global_imports=False, enable_table_memory_definitions=False,
        enable_global_definitions=False, max_initializer_ops=4096,
        enable_code_definitions=False, max_code_words=65536, enable_exports=False,
        enable_inline_exports=False, entry_x28=None,
        enable_element_section=False, enable_data_section=False,
        expression_scratch_address=None, max_expression_ops=4096,
        enable_special_custom_sections=False, custom_scratch_address=None,
        max_custom_records=4096, entry_x22=None):
    """Bounded actual +31b360 / +324444 with real AST effects and cleanup.

    Supports generic custom, type, function, start, data-count and empty export
    sections. enable_function_imports=False preserves that default scope.
    True also composes function imports at slot +28 when both module and field
    names are at least 23 bytes. enable_inline_function_imports=True additionally
    restores type-callback stack stores retained by inline names and permits
    shorter names; it requires enable_function_imports=True.
    enable_table_memory_global_imports=True independently opts into slots
    +30/+38/+40 with the actual descriptor and ninth ABI argument. In this
    combined scope all import names must be at least 23 bytes, including
    function names. enable_inline_table_memory_global_imports=True restores
    caller/helper stores retained by shorter names in this combined scope;
    it requires enable_table_memory_global_imports=True. Short function names
    still require both function opt-ins. Other imports after a zero-count type section require
    unrecovered incoming registers and fail closed. Empty type vectors work.
    enable_table_memory_definitions=True independently composes sections 4/5
    and slots +58/+60/+68/+70, including existing imported indexes. The table
    descriptor is at state-0xc0; the memory descriptor is at state-0xe0.
    Their five tail bytes and table node padding retain verified caller stores.
    enable_global_definitions=True independently composes section 6, global
    reserve/entry/expression callbacks and end/i32/i64/f32/f64 initializers.
    max_initializer_ops bounds each expression. The actual caller result is
    at state-0xb0; integer read scratch is state-0x108. End-only expressions
    retain the caller result's high four bytes; constants replace all eight.
    enable_code_definitions=True independently composes section 10 and slots
    +a8/+b0/+b8/+f8/+168, including metadata, local groups, raw words and the
    function end. It requires matching function definitions. Raw words are
    stored without interpretation. max_code_words bounds all word callbacks
    across this section, including nonadvancing zero words on short input.
    The first word in each consecutive run validates the entire ownership
    graph. Following words use the same append implementation and validate
    their slot, vector, mapped storage, allocation plan and byte bounds. Only
    the module's raw vector changes within such a run; any other callback
    resets this state. This relies on allocate being a pure allocation plan.
    enable_exports=True independently composes section 7 slot +98 for names
    of at least 23 bytes and export kinds 0..3. Each index must name an existing
    logical callback cache entry. Short names require enable_inline_exports=True.
    That opt-in requires enable_exports and
    an explicit entry_x28 (the incoming callee-saved register); import callbacks
    can retain it in the inline string tail. Invalid kind 4 remains a native
    parse failure.
    enable_element_section and enable_data_section independently compose the
    section 9/11 AST and expression callbacks. Nonempty element vectors retain
    their bounded rejection at the native abort boundary. Segment expressions
    require a mapped, aligned, disjoint eight-byte expression_scratch_address;
    it is explicit model scratch, not a native caller pointer. Likewise,
    enable_special_custom_sections composes the five metadata handlers using
    an explicit eight-byte custom_scratch_address. The two scratch regions
    cannot alias each other, input, output, frames, allocations or other state.
    max_expression_ops and max_custom_records bound their existing parsers.
    With inline exports, linking restores version/tag/size/count and field
    reads plus the saved caller FP; tags 6/7 leave their countdown at -1.
    Combining custom sections with table/memory definitions requires explicit
    entry_x28 as well, including when inline exports are disabled: linking's
    saved X28 supplies the high padding word of subsequent table nodes.
    All opt-ins default False. Remaining handlers fail closed. The output starts empty.
    Eight prefix bytes are skipped without checking their magic.
    Parse errors return 1 and commit partial AST output. Guard failures roll
    back all pages. Function/code count mismatch returns 1 after dispatch.

    Explicit mapped native frames retain untouched callback/state padding.
    Their callback/retained headers and parser object fields are modeled.
    Inline function imports model three type-helper saves. The combined inline
    opt-in also restores vector-copy FP/LR, import-helper saves and clone clears
    that feed later string padding;
    other saved registers and stack/TLS bytes remain outside the contract.
    Function imports retain the additional [state-0x1e0, state) caller frame:
    callback entry SP is state-0x100, with a 0xe0-byte callback frame below it.
    Table/memory/global imports retain [state-0x210, state), covering their
    0x110/0x100/0xf0-byte callback frames. Descriptor scratch is at state-0xf8;
    its last five bytes remain from the caller. Type callbacks save their
    parameter count and type index into bytes consumed by subsequent imports.
    Their copy helper saves the output pointer retained by table node padding.
    With a zero-count type section, later table/memory/global imports require
    explicit entry_x22. The type reserve helper retains incoming X22 at
    state-0x100 and the parser state pointer at state-0xe8; no type entry
    follows to replace these words. Omission preserves the bounded rejection.
    Input/output/scratch/reservations/allocations cannot overlap that range.
    Varuint scratch is explicit model storage; the import descriptor uses
    the verified native caller address. Other native stack writes stay open.
    The definition opt-in retains [state-0x210, state) as well. Table/memory
    callbacks have 0xb0-byte frames below state-0xc0/state-0xe0; table padding
    comes from state-0x13c. Type/import parser FP/input-limit saves, type clone
    clear, import descriptor-pointer saves and table count save are restored.
    The global opt-in retains [state-0x2a0,state), including the global entry's
    0x1f0-byte frame below state-0xb0. Its result word can reuse preceding
    descriptor storage. The memory handler's saved dispatcher X25 is restored
    from image_base+0x1210f8; custom/type/import/function saves also feed it.
    The code opt-in retains [state-0x210,state) (or the larger global frame).
    Its handler frame is 0x70 bytes below the dispatcher, so all code callbacks
    enter at state-0xe0; code begin's direct 0x70 frame ends at state-0x150.
    The export opt-in also retains [state-0x210,state) (or the global frame).
    Export handler +3238b0 has a 0x60 frame: callback entry SP is state-0xd0,
    and +31d500's direct 0x90 frame starts at state-0x160. Heap names overwrite
    all 24 header bytes. The inline opt-in restores type/import/function/table/
    memory/global writes into that header and retains preceding export tails.
    Import X28 starts at entry_x28 and changes to memory flags within section 2;
    global imports save X27=image_base+0x1210ef instead. No native snapshot is
    used. This is the recovered consumed frame, not the entire native stack.
    allocate must be a pure plan for distinct aligned blocks, including freed
    temporaries: this bounded contract does not support address reuse. Effects
    include parser vectors, AST callbacks, parser cleanup then callback cleanup.
    Consume logical frees once. The output and its allocations remain owned.
    """
    if (not isinstance(image_base,int) or image_base & 4095
            or not 0 < image_base <= MASK64-0x400000
            or not isinstance(max_sections,int) or not 1 <= max_sections <= 4096
            or not isinstance(max_entries,int) or not 1 <= max_entries <= 65536
            or not isinstance(max_input_bytes,int) or not 0 <= max_input_bytes <= 16*1024*1024
            or not isinstance(entry_stack_address,int) or entry_stack_address & 15
            or not 0x220 < entry_stack_address <= MASK64
            or not isinstance(input_address,int) or not 0 < input_address <= MASK64
            or not isinstance(input_size,int) or not 0 <= input_size <= max_input_bytes
            or input_address+input_size > MASK64+1
            or not isinstance(output_address,int) or output_address & 7
            or not 0 < output_address <= MASK64-0x11F
            or not isinstance(varuint_scratch_address,int)
            or not 0 < varuint_scratch_address <= MASK64-3
            or any(not isinstance(v,int) or not 0 <= v <= MASK64
                   for v in (context_address,context_size))
            or not isinstance(enable_function_imports,bool)
            or not isinstance(enable_inline_function_imports,bool)
            or not isinstance(enable_table_memory_global_imports,bool)
            or not isinstance(enable_inline_table_memory_global_imports,bool)
            or not isinstance(enable_table_memory_definitions,bool)
            or not isinstance(enable_global_definitions,bool)
            or not isinstance(max_initializer_ops,int) or not 1 <= max_initializer_ops <= 65536
            or not isinstance(enable_code_definitions,bool)
            or not isinstance(max_code_words,int) or not 1 <= max_code_words <= 1048576
            or not isinstance(enable_exports,bool)
            or not isinstance(enable_element_section,bool)
            or not isinstance(enable_data_section,bool)
            or not isinstance(enable_special_custom_sections,bool)
            or not isinstance(max_expression_ops,int) or not 1 <= max_expression_ops <= 65536
            or not isinstance(max_custom_records,int) or not 1 <= max_custom_records <= 65536
            or not isinstance(enable_inline_exports,bool)
            or enable_inline_exports and (not enable_exports or not isinstance(entry_x28,int)
                or isinstance(entry_x28,bool) or not 0 <= entry_x28 <= MASK64)
            or entry_x28 is not None and (not isinstance(entry_x28,int)
                or isinstance(entry_x28,bool) or not 0 <= entry_x28 <= MASK64)
            or entry_x22 is not None and (not isinstance(entry_x22,int)
                or isinstance(entry_x22,bool) or not 0 <= entry_x22 <= MASK64)
            or enable_inline_function_imports and not enable_function_imports
            or enable_inline_table_memory_global_imports and not enable_table_memory_global_imports
            or not callable(allocate)):
        raise RefillUnsupported('AST module requires bounded input, output and native frames')
    extra_scratch = []
    for enabled,address in ((enable_element_section or enable_data_section,expression_scratch_address),
                            (enable_special_custom_sections,custom_scratch_address)):
        if enabled:
            if not isinstance(address,int) or address&7 or not 0 < address <= MASK64-7:
                raise RefillUnsupported('AST module segment/custom scratch must be an aligned eight-byte region')
            extra_scratch.append((address,address+8))
    cb, state = entry_stack_address-0x150, entry_stack_address-0x220
    import_frame_size = 0x2A0 if enable_global_definitions or enable_element_section or enable_data_section else 0x210 if enable_table_memory_global_imports or enable_table_memory_definitions or enable_code_definitions or enable_exports else 0x1E0
    retain_frame = enable_function_imports or enable_table_memory_global_imports or enable_table_memory_definitions or enable_global_definitions or enable_code_definitions or enable_exports or enable_element_section or enable_data_section
    if retain_frame and state <= import_frame_size:
        raise RefillUnsupported('AST module import frame address is invalid')
    retained = [(image_base,image_base+0x400000), (input_address,input_address+input_size),
                (output_address,output_address+0x120), (state,entry_stack_address),
                (varuint_scratch_address,varuint_scratch_address+4), *extra_scratch, *reserved_regions]
    if retain_frame:
        retained.append((state-import_frame_size,state))
    if any(not isinstance(a,int) or not isinstance(b,int) or not 0 <= a <= b <= MASK64+1
           for a,b in retained):
        raise RefillUnsupported('AST module retained region is invalid')
    if any(a < d and c < b for i,(a,b) in enumerate(retained)
           for c,d in retained[i+1:]):
        raise RefillUnsupported('AST module retained regions overlap')
    p = _PageTransaction(pages)
    _read_span(p,input_address,input_size); _read_span(p,state,0x220)
    if retain_frame:
        _read_span(p,state-import_frame_size,import_frame_size)
    _read_span(p,varuint_scratch_address,4)
    for start,end in extra_scratch: _read_span(p,start,end-start)
    if any(_read_span(p,output_address,0x120)):
        raise RefillUnsupported('AST module requires empty output containers')
    # Match constructor stores rather than zeroing unwritten +28/+78 padding.
    for offset,length in ((0x30,0x18),(0x50,0x10),(0x68,0x10),(0x80,0x78),(0x108,0x18)):
        _write_span(p,cb+offset,bytes(length))
    for offset,value in ((0,image_base+0x372370),(8,0),(0x10,cb+0x108),
            (0x18,output_address),(0x20,output_address+0x108),
            (0x48,cb+0x50),(0x60,cb+0x68),(0xF8,context_address),(0x100,context_size)):
        _write_span(p,cb+offset,value.to_bytes(8,'little'))
    _write_span(p,state+0x28,bytes(0x60))
    _write_span(p,state+0x88,bytes.fromhex('ffffffff00'))
    _write_span(p,state+0x90,bytes(0x20))
    _write_span(p,state+0xAC,bytes.fromhex('ffffffff'))
    for offset,value in ((0,input_size),(8,input_address),(16,input_size),
            (24,8 if input_size >= 8 else 4 if input_size >= 4 else 0),(32,cb)):
        _write_span(p,state+offset,value.to_bytes(8,'little'))
    _write_span(p,cb+8,(state+8).to_bytes(8,'little'))
    # Validate resource bounds and the fresh graph even when no sections run.
    m = _ReaderAstMemory(p,image_base,output_address,0x120,max_nodes,max_vector_bytes,reserved_regions)
    m.callback(cb,attached_state_address=state)
    blocks, effects, vector_count = [], [], 0
    empty_type_section = False
    import_x28 = entry_x28
    word_run = False
    def plan(size):
        if not isinstance(size,int) or not 0 < size <= max_vector_bytes:
            raise RefillUnsupported('AST module allocation exceeds its byte bound')
        address = allocate(size)
        if (not isinstance(address,int) or address & 7 or not 0 < address <= MASK64-size
                or any(address < b and a < address+size for a,b in (*retained,*blocks))):
            raise RefillUnsupported('AST module allocation overlaps retained or planned storage')
        _read_span(p,address,size); blocks.append((address,address+size)); return address
    def collect(vectors):
        nonlocal vector_count
        effects.extend(vectors[vector_count:]); vector_count=len(vectors)
    def callback(current,event,vectors):
        nonlocal empty_type_section, import_x28, word_run
        collect(vectors)
        if event.slot_offset == 0x18:
            empty_type_section = event.arguments[0] == 0
        if event.slot_offset == 0x28:
            if not enable_function_imports or (not enable_inline_function_imports
                    and min(event.arguments[2],event.arguments[4]) <= 22):
                raise RefillUnsupported('AST module function imports require two heap names')
            if (enable_table_memory_global_imports and not enable_inline_table_memory_global_imports
                    and min(event.arguments[2],event.arguments[4]) <= 22):
                raise RefillUnsupported('AST module combined import kinds require two heap names')
        elif event.slot_offset in (0x30,0x38,0x40):
            if (not enable_table_memory_global_imports or empty_type_section and entry_x22 is None
                    or not enable_inline_table_memory_global_imports
                    and min(event.arguments[2],event.arguments[4]) <= 22):
                raise RefillUnsupported('AST module other imports require verified type caller and two heap names')
        elif event.slot_offset in (0x58,0x60,0x68,0x70):
            if not enable_table_memory_definitions:
                raise RefillUnsupported('AST module table/memory definitions need explicit opt-in')
        elif event.slot_offset in (0x78,0x80,0x88,0x90):
            if not enable_global_definitions:
                raise RefillUnsupported('AST module global definitions need explicit opt-in')
        elif event.slot_offset in (0xC0,0xC8,0xD0,0xD8,0xE0,0xE8):
            if not (enable_global_definitions or enable_element_section or enable_data_section):
                raise RefillUnsupported('AST module expressions need an enabled owning section')
        elif event.slot_offset == 0xF0:
            if not (enable_element_section or enable_data_section):
                raise RefillUnsupported('AST module segment zero words need explicit opt-in')
        elif event.slot_offset in (0x100,0x108,0x110,0x118,0x120,0x128,0x130,0x138):
            if not enable_element_section:
                raise RefillUnsupported('AST module elements need explicit opt-in')
        elif event.slot_offset in (0x140,0x148,0x150,0x158):
            if not enable_data_section:
                raise RefillUnsupported('AST module data segments need explicit opt-in')
        elif event.slot_offset in (0xA8,0xB0,0xB8,0xF8,0x168):
            if not enable_code_definitions:
                raise RefillUnsupported('AST module code definitions need explicit opt-in')
        elif event.slot_offset == 0x98:
            if not enable_exports or not enable_inline_exports and event.arguments[4] <= 22:
                raise RefillUnsupported('AST module exports require explicit opt-in and heap names')
        elif event.slot_offset not in (0x18,0x20,0x50,0xA0,0x160):
            raise RefillUnsupported('AST module callback needs further native frame verification')
        if enable_inline_table_memory_global_imports and event.slot_offset in (0x28,0x40):
            prior_import_end = _u(current,output_address+0x20)
            prior_function_end, prior_function_cap = _u(current,cb+0x88), _u(current,cb+0x90)
        if event.slot_offset == 0x168 and word_run:
            # The module owns every mutation, and plan retains all earlier
            # allocation extents. Between consecutive raw words only this
            # vector can change; rebuilding the whole graph per word would
            # scan every function/import/export repeatedly on actual code.
            if (_u(current,cb) != image_base+0x372370 or _u(current,cb+0x18) != output_address
                    or _u(current,cb+0x20) != output_address+0x108
                    or _u(current,image_base+0x372370+0x168) != image_base+0x31E5D8):
                raise RefillUnsupported('AST module raw-word binding is inconsistent')
            raw = _ReaderAstMemory(current,image_base,output_address,0x120,
                max_nodes,max_vector_bytes,retained)
            raw.vector(output_address+0x108)
            raw.append_word(output_address,0x168,event.arguments[0],plan)
            raw.p.commit()
            result = ReaderAstResult(0,tuple(raw.effects))
        else:
            result = run_reader_ast_callback(current,callback_address=cb,image_base=image_base,
                slot_offset=event.slot_offset,arguments=event.arguments,allocate=plan,
                entry_stack_address=(state-0x100 if event.slot_offset in (0x28,0x30,0x38,0x40)
                    else state-0xC0 if event.slot_offset == 0x60
                    else state-0xD0 if event.slot_offset == 0x98 else None),
                attached_state_address=state,max_nodes=max_nodes,max_vector_bytes=max_vector_bytes,
                reserved_regions=((input_address,input_address+input_size),
                    (varuint_scratch_address,varuint_scratch_address+4),*extra_scratch,*reserved_regions))
        word_run = event.slot_offset == 0x168
        if enable_inline_exports:
            # Recover stores into +31d500's first string at state-0x160.
            # Each source is an earlier native store, not an oracle snapshot.
            frame = state-0x160
            if event.slot_offset == 0x20:
                # +31b6f4/+31b724/+31b72c/+31b84c: the original parameter
                # vector's released begin/capacity; +31b7ac: type vtable.
                count = event.arguments[1]&0xFFFFFFFF
                pointer = next(e.address for e in result.effects if e.kind == 'allocate') if count else 0
                _write_span(current,frame,pointer.to_bytes(8,'little')
                    +(pointer+count*8).to_bytes(8,'little')+(image_base+0x3724F0).to_bytes(8,'little'))
            elif event.slot_offset in (0x28,0x30,0x38,0x40):
                # Import prologues +31b874/+31bb4c/+31be40/+31c148 save
                # FP/LR and X28 (global saves X27). +322f40 replaces X28
                # with memory flags within this section; the handler restores
                # the incoming register when it returns.
                if event.arguments[0] == 0: import_x28 = entry_x28
                if event.slot_offset == 0x38:
                    descriptor = event.arguments[6]
                    import_x28 = _u(current,descriptor+16,1)|(_u(current,descriptor+18,1)<<2)
                lr = {0x28:0x322EBC,0x30:0x322F20,0x38:0x3230B0,0x40:0x32302C}[event.slot_offset]
                tail = image_base+0x1210EF if event.slot_offset == 0x40 else import_x28
                _write_span(current,frame,(state-0xD0).to_bytes(8,'little')
                    +(image_base+lr).to_bytes(8,'little')+tail.to_bytes(8,'little'))
            elif event.slot_offset == 0x50:
                # +31f778/+31f794 clear the moved function's type vector.
                _write_span(current,frame,bytes(24))
            elif event.slot_offset == 0x60:
                # +31cb44 copies descriptor[4:19]; +31cb10 leaves its
                # vtable. Byte 15 retains the previous caller byte.
                descriptor = bytearray(_read_span(current,event.arguments[2],19))
                if not descriptor[16]: descriptor[8:16]=(0xFFFFFFFF).to_bytes(8,'little')
                _write_span(current,frame,descriptor[4:19])
                _write_span(current,frame+16,(image_base+0x372518).to_bytes(8,'little'))
            elif event.slot_offset == 0x70:
                # +31cdec writes kind; +31ce0c/+31ce3c copy/normalize limits.
                descriptor = bytearray(_read_span(current,event.arguments[1],19))
                if not descriptor[16]:
                    descriptor[8:16]=(0x1000000000000 if descriptor[18] else 0x10000).to_bytes(8,'little')
                _write_span(current,frame,(2).to_bytes(4,'little'))
                _write_span(current,frame+8,descriptor[:16])
            elif event.slot_offset == 0x80:
                # +31d0b8/+31d0c0/+31d0c4 initialize nested function fields.
                _write_span(current,frame,bytes(8)+(0xFFFFFFFF).to_bytes(8,'little')+bytes(4))
            elif event.slot_offset in (0xD0,0xD8,0xE0,0xE8):
                # +32140c/+321494 save the initializer callback FP.
                _write_span(current,frame+16,(state-0x120).to_bytes(8,'little'))
                if event.slot_offset in (0xD0,0xE0):
                    # +2db2c4 in both raw-vector extensions saves X20/X19.
                    _write_span(current,frame,(event.arguments[0]&0xFFFFFFFF).to_bytes(8,'little')
                        +(output_address+0x108).to_bytes(8,'little'))
                else:
                    # +3214b4 stores the 64-bit opcode before its payload.
                    tag = 5 if event.slot_offset == 0xD8 else 3
                    _write_span(current,frame+12,tag.to_bytes(4,'little'))
        if enable_table_memory_definitions or enable_global_definitions:
            if event.slot_offset == 0x20:
                # +31b7b8 clears the moved parameter clone. The type section
                # reserves all entries, so its appends use spare capacity.
                _write_span(current,state-0x140,bytes(8))
            elif event.slot_offset in (0x28,0x30,0x38,0x40):
                # +31b87c/+31bb54/+31be48/+31c150 save x26: the import
                # descriptor pointer, except memory's rejected flag bit 1.
                saved = 0 if event.slot_offset == 0x38 else state-0xF8
                _write_span(current,state-0x140,saved.to_bytes(8,'little'))
            elif event.slot_offset == 0x50:
                # +31c7c0/+31c7c8 save dispatcher x24=1 and the local
                # function index. +31f798 clears the moved local vector.
                local_index = (event.arguments[0]-_u(current,state+0x90,4))&0xFFFFFFFF
                _write_span(current,state-0xD0,(1).to_bytes(8,'little'))
                _write_span(current,state-0xB0,local_index.to_bytes(8,'little'))
                _write_span(current,state-0x140,bytes(8))
            elif event.slot_offset == 0x58:
                # +31c9fc saves the section count in the memory tail word.
                _write_span(current,state-0xD0,(event.arguments[0]&0xFFFFFFFF).to_bytes(8,'little'))
        if (enable_table_memory_global_imports and event.slot_offset == 0x18
                and empty_type_section and entry_x22 is not None):
            # +31e760/+31e764 in the zero-count reserve helper save X22
            # and X19=state. Later descriptors retain their unmodified bytes.
            _write_span(current,state-0x100,entry_x22.to_bytes(8,'little'))
            _write_span(current,state-0xE8,state.to_bytes(8,'little'))
        if enable_table_memory_global_imports and event.slot_offset == 0x20:
            # +31b6d8/+31b6dc retain the caller's parameter count/type index.
            # Later imports consume this saved parameter word and the high
            # five type-index bytes as ABI/descriptor padding.
            _write_span(current,state-0x100,(event.arguments[1]&0xFFFFFFFF).to_bytes(8,'little'))
            _write_span(current,state-0xE8,(event.arguments[0]&0xFFFFFFFF).to_bytes(8,'little'))
            # +31e894 saves the output pointer in the type-copy helper;
            # table imports later retain its high word as node padding.
            _write_span(current,state-0x188,output_address.to_bytes(8,'little'))
        if enable_table_memory_global_imports and event.slot_offset == 0x40:
            # +31c2e0/+31c2fc release the temporary clone and clear its word;
            # the next table import retains the high half as node padding.
            _write_span(current,state-0x188,bytes(8))
        if enable_inline_table_memory_global_imports and event.slot_offset == 0x28:
            # +31ed20/+31eea4 save the function caller's FP/LR, type index,
            # previous cache end, source type and callback pointer. The LR
            # distinguishes cache growth from an append into spare capacity.
            # +31b8b8 saves the field input pointer; +31ba74 clears its clone.
            words = (state-0x160,
                image_base+(0x31BB14 if prior_function_end == prior_function_cap else 0x31BAB0),
                event.arguments[6]&0xFFFFFFFF,prior_function_end,
                _u(current,output_address)+(event.arguments[6]&0xFFFFFFFF)*64,
                cb,event.arguments[3],0)
            _write_span(current,state-0x210,b''.join(word.to_bytes(8,'little') for word in words))
        if enable_inline_table_memory_global_imports and event.slot_offset == 0x30:
            # +31bd0c/+31bd28 clear the released second temporary clone.
            _write_span(current,state-0x1A8,bytes(8))
        if enable_inline_table_memory_global_imports and event.slot_offset == 0x38:
            # +32a9d4/+31f140 save x19; +31c058 clears the temporary clone.
            _write_span(current,state-0x208,cb.to_bytes(8,'little')+bytes(8))
        if enable_inline_table_memory_global_imports and event.slot_offset == 0x40:
            # +32a9d4/+31f2d0/+31f2d4 retain the second field header pointer,
            # previous output end and callback pointer in later name padding.
            _write_span(current,state-0x208,(state-0x1A0).to_bytes(8,'little')
                +prior_import_end.to_bytes(8,'little')+cb.to_bytes(8,'little'))
        if enable_inline_table_memory_global_imports and event.slot_offset == 0x20:
            if event.arguments[1]&0xFFFFFFFF or event.arguments[3]&0xFFFFFFFF:
                # +32a1f4 in +31e888's last nonempty vector copy saves its
                # FP/LR. Empty vectors leave earlier caller bytes untouched.
                _write_span(current,state-0x1E0,(state-0x1C0).to_bytes(8,'little')
                    +(image_base+(0x31E93C if event.arguments[3]&0xFFFFFFFF else 0x31E8E0)).to_bytes(8,'little'))
        if (enable_inline_function_imports or enable_inline_table_memory_global_imports) and event.slot_offset == 0x20:
            # +31e888 saves the type callback FP/LR and x23 in bytes later
            # copied by inline import strings. +32a1f8 saves its node pointer
            # when either type vector is copied. Recover these stores from
            # this caller's frame/counts, never a captured native stack.
            frame = state-0x1E0
            _write_span(current,frame+0x20,(state-0x110).to_bytes(8,'little')
                +(image_base+0x31B778).to_bytes(8,'little'))
            params = event.arguments[1]&0xFFFFFFFF
            _write_span(current,frame+0x30,(params*8 if params else state+0x40).to_bytes(8,'little'))
            if params or event.arguments[3]&0xFFFFFFFF:
                _write_span(current,frame+0x10,(state-0x150).to_bytes(8,'little'))
        effects.extend(result.effects); return result.status
    sections = None
    status = 1
    if input_size >= 8:
        sections = run_reader_sections(p,state_address=state,image_base=image_base,
            varuint_scratch_address=varuint_scratch_address,callback=lambda event: 0,
            vector_allocate=plan,max_sections=max_sections,max_entries=max_entries,
            max_input_bytes=max_input_bytes,_ast_callback=callback,
            enable_function_global_imports=enable_function_imports or enable_table_memory_global_imports,
            enable_table_memory_imports=enable_table_memory_global_imports,
            enable_table_memory_sections=enable_table_memory_definitions,
            import_scratch_address=(state-0xF8 if enable_table_memory_global_imports
                else state-0xC0 if enable_table_memory_definitions else None),
            _attached_import_stack_address=state-0x100 if enable_table_memory_global_imports else None,
            _attached_definition_stack_address=state-0xC0 if enable_table_memory_definitions else None,
            enable_global_section=enable_global_definitions,
            global_scratch_address=state-0xB0 if enable_global_definitions else None,
            _attached_global_stack_address=state-0xB0 if enable_global_definitions else None,
            max_initializer_ops=max_initializer_ops,
            enable_code_section=enable_code_definitions,max_code_words=max_code_words,
            enable_element_section=enable_element_section,enable_data_section=enable_data_section,
            expression_scratch_address=expression_scratch_address,max_expression_ops=max_expression_ops,
            enable_special_custom_sections=enable_special_custom_sections,
            custom_scratch_address=custom_scratch_address,max_custom_records=max_custom_records,
            _attached_custom_stack_address=state-0xF0 if enable_special_custom_sections and
                (enable_inline_exports or enable_table_memory_global_imports or enable_table_memory_definitions) else None,
            _attached_custom_entry_x28=entry_x28)
        collect(sections.vector_effects)
        status = int(sections.status == 1 or _u(p,state+0xA4,4) != _u(p,state+0xA8,4))
    for offset in (0x70,0x58,0x40,0x28):
        begin,end,cap = (_u(p,state+offset+n) for n in (0,8,16))
        if begin:
            _write_span(p,state+offset+8,begin.to_bytes(8,'little'))
            effects.append(ReaderVectorEffect('free',begin,cap-begin,state+offset,(begin,begin,cap)))
    result = cleanup_reader_callback(p,callback_address=cb,image_base=image_base,
        attached_state_address=state,max_nodes=max_nodes,max_vector_bytes=max_vector_bytes,
        reserved_regions=((input_address,input_address+input_size),
            (varuint_scratch_address,varuint_scratch_address+4),*reserved_regions))
    effects.extend(result.effects)
    # Supported callbacks never populate the independent retained-record list.
    if any(_read_span(p,cb+0x108,24)):
        raise RefillUnsupported('AST module retained-record construction remains unsupported')
    p.commit()
    return ReaderAstModuleResult(status,sections,tuple(effects))


@dataclass(frozen=True)
class ShortDescriptorLookupResult:
    descriptor_address: int
    hash_word: int
    bucket_index: int | None
    query_length: int
    visited_nodes: tuple[int,...]


def lookup_short_descriptor(pages, *, root_address, name_address,
        entry_stack_address, max_nodes=4096):
    """+0x2a9620 -> +0x2aa528 for short queries, with short/long stored keys.

    root[0] is the descriptor pointer array; root+0x20 owns hash buckets.
    Each bucket points to a predecessor node, whose next word is the first
    candidate. Node+8 caches the hash, +0x10 is a libc++ string, and +0x28 is
    the descriptor array index. Stop at another bucket, not at array count.
    Synthetic hash metadata may be supplied for differential controls.
    Waiting/throw paths, long queries and factory decoding are not recovered.
    """
    if (not isinstance(entry_stack_address,int) or entry_stack_address<0xC0
            or entry_stack_address>MASK64 or entry_stack_address&15):
        raise RefillUnsupported('descriptor selector stack must be aligned with scratch space')
    if (not isinstance(root_address,int) or not 0<root_address<=MASK64-0x30
            or not isinstance(name_address,int) or not 0<name_address<=MASK64-9):
        raise RefillUnsupported('descriptor selector requires mapped nonzero uint64 addresses')
    if not isinstance(max_nodes,int) or not 1<=max_nodes<=4096:
        raise RefillUnsupported('descriptor selector node bound must be 1..4096')
    p=_PageTransaction(pages);query=bytearray()
    for index in range(9):
        value=_read_span(p,name_address+index,1)[0]
        if value==0:break
        query.append(value)
    else:raise RefillUnsupported('descriptor selector query exceeds eight bytes')
    if len(query)>8:raise RefillUnsupported('descriptor selector query exceeds eight bytes')
    temporary=entry_stack_address-0x58
    _write_span(p,temporary,bytes([len(query)*2])+bytes(query)+b'\0')
    hashed=hash_short_descriptor_name(query);count=_u(p,root_address+0x28)
    if count>4096:raise RefillUnsupported('descriptor bucket count exceeds the explicit bound')
    bucket=None;visited=[];descriptor=0
    if count:
        power=(count&(count-1))==0
        bucket=(hashed&(count-1)) if power else hashed%count
        predecessor=_u(p,_u(p,root_address+0x20)+bucket*8)
        node=_u(p,predecessor) if predecessor else 0
        while node:
            if node in visited or len(visited)>=max_nodes:
                raise RefillUnsupported('descriptor node cycle or visit bound reached')
            visited.append(node);node_hash=_u(p,node+8)
            node_bucket=(node_hash&(count-1)) if power else node_hash%count
            if node_bucket!=bucket:break
            if node_hash==hashed:
                tag=_u(p,node+0x10,1)
                length=_u(p,node+0x18) if tag&1 else tag>>1
                if length==len(query):
                    data_address=_u(p,node+0x20) if tag&1 else node+0x11
                    if _read_span(p,data_address,length)==bytes(query):
                        index=_u(p,node+0x28)
                        address=(_u(p,root_address)+((index<<3)&MASK64))&MASK64
                        descriptor=_u(p,address)
                        break
            node=_u(p,node)
    result=ShortDescriptorLookupResult(descriptor,hashed,bucket,len(query),tuple(visited))
    p.commit();return result


@dataclass(frozen=True)
class FactoryBlobXorResult:
    blob_size: int
    selected_codec_row: int | None
    key_was_zero: bool | None


def decode_factory_blob_xor(pages, *, blob_address, blob_size,
        codec_table_address, codec_table_count, max_blob_bytes=16*1024*1024):
    """Bounded +0x2cbdc8 entry through +0x2cbf24, before the reader call.

    The extra stack arguments select row size % count from 24-byte codec
    records, using byte +2. For count zero the native unsigned division leaves
    quotient zero, selecting row size. Size zero skips the table entirely.
    This is only the in-place XOR prefix, not parsing or a module factory.
    Pages commit together; missing input/destination pages fail closed.
    """
    if (not isinstance(blob_address,int) or not 0<blob_address<=MASK64
            or not isinstance(blob_size,int) or not 0<=blob_size<=MASK64
            or not isinstance(max_blob_bytes,int) or not 0<=max_blob_bytes<=MASK64
            or blob_size>max_blob_bytes or blob_address+blob_size>MASK64+1):
        raise RefillUnsupported('factory XOR blob exceeds the explicit address/size bound')
    if (not isinstance(codec_table_count,int) or not 0<=codec_table_count<=MASK64
            or not isinstance(codec_table_address,int) or not 0<=codec_table_address<=MASK64):
        raise RefillUnsupported('factory XOR codec metadata is outside the guest ABI')
    if not blob_size:return FactoryBlobXorResult(0,None,None)
    row=blob_size%codec_table_count if codec_table_count else blob_size
    key_address=codec_table_address+row*24+2
    if not codec_table_address or key_address>MASK64:
        raise RefillUnsupported('factory XOR codec row address overflows or is null')
    p=_PageTransaction(pages)
    key=_u(p,key_address,1)
    if key:
        payload=_read_span(p,blob_address,blob_size)
        _write_span(p,blob_address,bytes(value^key for value in payload))
    p.commit()
    return FactoryBlobXorResult(blob_size,row,key==0)


@dataclass(frozen=True)
class ParserConversionResult:
    status: int
    effects: tuple[ReaderAstEffect, ...]
    finalizers: tuple[tuple[int, int, int], ...]
    function_count: int
    decoded_word_count: int


class _ParserConversionMemory(_ReaderAstMemory):
    def put(self, address, value, width=8):
        _write_span(self.p,address,value.to_bytes(width,'little'))

    def decoded_literal(self, source, destination, size, period, guard):
        if _u(self.p,self.base+guard,4)!=1:
            encoded=_read_span(self.p,self.base+source,period+size)
            _write_span(self.p,self.base+destination,
                bytes(encoded[i%period]^encoded[period+i] for i in range(size)))
            self.put(self.base+guard,1,4)
        return _read_span(self.p,self.base+destination,size)

    def assign_string(self, destination, source, allocate):
        # +32b49c, including retained capacity and +32a884 growth.
        old=_read_span(self.p,destination,24)
        header=_read_span(self.p,source,24)
        if not (old[0]|header[0])&1:
            _write_span(self.p,destination,header);return
        length=int.from_bytes(header[8:16],'little') if header[0]&1 else header[0]>>1
        pointer=int.from_bytes(header[16:24],'little') if header[0]&1 else source+1
        if length+1>self.max_bytes:
            raise RefillUnsupported('converted string exceeds the byte bound')
        payload=_read_span(self.p,pointer,length)
        capacity=int.from_bytes(old[:8],'little')&~1 if old[0]&1 else 23
        if capacity>length:
            target=int.from_bytes(old[16:24],'little') if old[0]&1 else destination+1
            self.put(destination+8,length) if old[0]&1 else self.put(destination,length*2,1)
            _write_span(self.p,target,payload+b'\0');return
        capacity=(max(length,2*(capacity-1))+16)&~15
        target=self.allocate(capacity,allocate)
        _write_span(self.p,target,payload+b'\0')
        self.free_string_value(old)
        self.put(destination,capacity|1)
        self.put(destination+8,length);self.put(destination+16,target)

    def builtin_catalog(self, entry_sp, thread_id, allocate):
        # +2ab500 under explicit serial guard/gettid/finalizer services.
        finalizers=[]
        def cold(offset):
            value=_u(self.p,self.base+offset)
            if value&1:return False
            if value:
                raise RefillUnsupported('parser catalog guard is busy or unsupported')
            return True
        def released(offset):self.put(self.base+offset,(thread_id<<32)|0x101)
        for guard,destination,literal,tail in (
                (0x3E2548,0x3E25B0,(0x6E4B0,16),b'\x1a\x06'),
                (0x3E2550,0x3E2570,(0x6E1B0,8),b'\x05\x03\x10\x10'),
                (0x3E2558,0x3E2530,None,b'\x00\x00\x06\x01\x06\x1a')):
            if cold(guard):
                data=(_read_span(self.p,self.base+literal[0],literal[1]) if literal else b'')+tail
                _write_span(self.p,self.base+destination,data);released(guard)
        created=False
        if cold(0x3E2560):
            frame=entry_sp-0x68
            if frame<=0 or frame+72>MASK64:
                raise RefillUnsupported('parser catalog frame is outside the guest ABI')
            self.claim(frame,72)
            for index,(tag,pointer,count) in enumerate(((0x52,0x3E25B0,6),(0x49,0x3E2570,4),(0x4A,0x3E2530,2))):
                address=frame+index*24
                self.put(address,tag,2);self.put(address+2,0,1)
                self.put(address+8,self.base+pointer);self.put(address+16,count,4)
            address=self.allocate(72,allocate)
            _write_span(self.p,address,_read_span(self.p,frame,72))
            self.publish(self.base+0x3E25E0,(address,address+72,address+72))
            finalizers.append((self.base+0x2AB7B4,self.base+0x3E25E0,self.base+0x34C700))
            released(0x3E2560);created=True
        if cold(0x3E2568):
            begin,end,cap=(_u(self.p,self.base+0x3E25E0+n) for n in (0,8,16))
            if not begin or end!=begin+72 or cap!=end:
                raise RefillUnsupported('parser builtin catalog vector is inconsistent')
            self.put(self.base+0x3E2580,begin);self.put(self.base+0x3E2588,3)
            released(0x3E2568)
        address,count=_u(self.p,self.base+0x3E2580),_u(self.p,self.base+0x3E2588)
        if count!=3 or not address:
            raise RefillUnsupported('parser builtin catalog must contain three records')
        if not created:self.claim(address,72)
        return address,count,finalizers


def run_parser_conversion(pages, *, image_base, ast_address, codec_pair_address,
        output_address, error_address, entry_stack_address, thread_id, allocate=None,
        max_nodes=4096, max_vector_bytes=16*1024*1024, max_code_words=1048576,
        reserved_regions=()):
    """Bounded actual +2cd5a4 AST-to-converted-module transformation.

    The AST and codec pointer/count pair are independent caller inputs. Output
    is fresh zeroed 128-byte storage and error is a fresh zeroed 24-byte string.
    Imports, functions, exports, global values and concatenated data retain
    native layout and allocation order. Global-count mismatch and out-of-range
    function exports return native failure (0) with the partial converted
    object and error string. Imported-function exports, native codec aborts,
    malformed graphs and exhausted budgets reject with all pages rolled back.
    The native word reader ignores vector end/capacity. Bounded mapped trailing
    bytes are retained as inputs; a final partial word returns native failure
    after destroying its temporary converted function.

    entry_stack_address supplies the actual incoming aligned SP. Only consumed
    C++ temporary records and the builtin catalog source frame are represented;
    native flattened control cells and other incidental stack stores are not
    outputs. Cold catalog guards require zero words and an explicit positive
    thread_id from the serial gettid service; ready guards skip initialization.
    Finalizer registrations and allocations/frees are returned as logical
    effects. Allocation is a pure address plan, never a real allocator call.
    This entry does not execute root construction, VM code, TLS or OS services.
    """
    if type(entry_stack_address) is not int or not 0x2000<entry_stack_address<=MASK64 or entry_stack_address&15:
        raise RefillUnsupported('parser conversion requires an aligned incoming SP')
    if type(thread_id) is not int or not 1<=thread_id<=0x7FFFFFFF:
        raise RefillUnsupported('parser conversion requires a positive serial thread ID')
    if type(max_code_words) is not int or not 0<=max_code_words<=0xFFFFFFFF:
        raise RefillUnsupported('parser conversion word budget is invalid')
    m=_ParserConversionMemory(pages,image_base,output_address,128,max_nodes,max_vector_bytes,reserved_regions)
    for address,width in ((ast_address,0x120),(codec_pair_address,16),(output_address,128),(error_address,24)):
        m.claim(address,width)
    if any(_read_span(m.p,output_address,128)) or any(_read_span(m.p,error_address,24)):
        raise RefillUnsupported('parser conversion requires fresh output and error objects')
    temporaries=(entry_stack_address-0xA58,entry_stack_address-0xA98,entry_stack_address-0xAB8)
    for address,width in zip(temporaries,(64,64,32)):m.claim(address,width)
    containers={}
    for offset in range(0,0x120,24):
        stride={0:64,0x18:64,0x30:144,0x48:48,0x60:40,0x78:176,0x90:40,
            0xA8:40,0xC0:4,0xD8:184,0xF0:176,0x108:1}[offset]
        begin,end,cap=m.vector(ast_address+offset,stride)
        if offset not in (0xC0,0x108) and (cap-begin)//stride>max_nodes:
            raise RefillUnsupported('parser AST container exceeds the node bound')
        if offset==0x90 and cap!=begin:
            raise RefillUnsupported('parser auxiliary AST nodes remain unsupported')
        containers[offset]=(begin,end,cap,stride)
        for record in range(begin,end,stride) if offset not in (0x48,0x60,0xC0,0x90,0x108) else ():
            if offset==0:m.node(record,64)
            elif offset==0x18:m.import_record(record)
            elif offset==0x30:m.function_record(record)
            elif offset==0x78:m.global_record(record)
            elif offset==0xA8:m.export_record(record)
            elif offset==0xD8:m.element_record(record)
            elif offset==0xF0:m.data_record(record)
    source_table,source_count=_u(m.p,codec_pair_address),_u(m.p,codec_pair_address+8)
    if source_count>max_nodes:
        raise RefillUnsupported('parser source codec count exceeds the node bound')
    if source_count:
        m.claim(source_table,source_count*24)
        for index in range(source_count):
            record=source_table+index*24;pointer,count=_u(m.p,record+8),_u(m.p,record+16,4)
            if count>1024:raise RefillUnsupported('parser source codec field count exceeds its bound')
            if count:m.claim(pointer,count*3,alignment=1)
    def records(offset):
        begin,end,_,stride=containers[offset];return range(begin,end,stride)
    raw_begin,raw_end,raw_capacity,_=containers[0x108]
    for record in records(0x30):
        start,size=_u(m.p,record+0x68,4),_u(m.p,record+0x70,4);width=((size+3)//4)*4
        if start+width>max_vector_bytes or start+size>0xFFFFFFFF:
            raise RefillUnsupported('parser function raw range exceeds its byte bound')
        if width:
            begin,end=raw_begin+start,raw_begin+start+width
            if not raw_begin or end>MASK64+1:
                raise RefillUnsupported('parser function raw pointer is invalid')
            for destination,length in ((output_address,128),(error_address,24),*zip(temporaries,(64,64,32))):
                if begin<destination+length and destination<end:
                    raise RefillUnsupported('parser raw input overlaps converted storage')
            _read_span(m.p,begin,width);m.reserved.append((begin,end))
    def reserve(offset,count,stride):
        pointer=m.allocate(count*stride,allocate) if count else 0
        m.publish(output_address+offset,(pointer,pointer,pointer+count*stride));return pointer
    def kind(node):
        native=_u(m.p,node+8,4)
        if native>3:raise RefillUnsupported('parser import/export kind is unsupported')
        ranks=m.decoded_literal(0x1206E0,0x3E275C,20,30,0x3E2770)
        mapped=int.from_bytes(ranks[native*4:native*4+4],'little')
        if mapped!=native:raise RefillUnsupported('parser kind mapping is unsupported')
        return native
    imported_functions=imported_globals=0;decoded_words=0;finalizers=[]
    def finish(status):
        if not status:
            message=m.decoded_literal(0x120600,0x3E2750,6,26,0x3E2758)
            if message[-1] or b'\0' in message[:-1]:
                raise RefillUnsupported('parser error literal is malformed')
            m.construct_string(error_address,image_base+0x3E2750,5,allocate)
        result=ParserConversionResult(status,tuple(m.effects),tuple(finalizers),
            _u(m.p,output_address,4),decoded_words)
        m.p.commit();return result
    imports=list(records(0x18));cursor=reserve(0x20,len(imports),64);temporary=temporaries[0]
    parser_sp=entry_stack_address-0x1600
    for record in imports:
        for offset in (0,24):m.copy_string_value(temporary+offset,_read_span(m.p,record+offset,24),allocate)
        tag=kind(_u(m.p,record+48));m.put(temporary+48,tag,4)
        _write_span(m.p,temporary+52,_read_span(m.p,record+56,8) if tag==0 else b'\xff'*8)
        if tag in (0,3):
            _write_span(m.p,cursor,_read_span(m.p,temporary,60));cursor+=64
            m.put(output_address+0x28,cursor);_write_span(m.p,temporary,bytes(48))
        m.free_string_value(_read_span(m.p,temporary+24,24));m.free_string_value(_read_span(m.p,temporary,24))
        imported_functions+=tag==0;imported_globals+=tag==3
        parser_sp-=(0x270,0x1C0,0x1C0,0x1E0)[tag]
    functions=list(records(0x30));cursor=reserve(8,len(functions),64);temporary=temporaries[1]
    builtin=None
    for record in functions:
        _write_span(m.p,temporary,_read_span(m.p,record+0x40,8)+_read_span(m.p,record+0x6C,4)+_read_span(m.p,record+0x48,4))
        name=m.decoded_literal(0x120720,0x3E2774,8,20,0x3E277C)
        _write_span(m.p,temporary+16,b'\x0e'+name[:7]+b'\0');m.publish(temporary+40,(0,0,0))
        if builtin is None:
            table,count,registrations=m.builtin_catalog(parser_sp-0x90,thread_id,allocate)
            builtin=(table,count);finalizers.extend(registrations)
        start,size=_u(m.p,record+0x68,4),_u(m.p,record+0x70,4)
        word_count=(size+3)//4
        if decoded_words+word_count>max_code_words:
            raise RefillUnsupported('parser decoded word budget exhausted')
        first=m.allocate((size//4+1)*12,allocate);m.publish(temporary+40,(first,first,first+(size//4+1)*12))
        index=0
        for offset in range(0,size,4):
            if index>=source_count or index>=builtin[1]:
                raise RefillUnsupported('parser codec index would reach native abort')
            word=convert_parser_instruction_word(m.p,source_codec_address=source_table+index*24,
                target_codec_address=builtin[0]+index*24,word=_u(m.p,raw_begin+start+offset,4))
            decoded=word.to_bytes(4,'little')+bytes([word>>26,*((word>>shift)&31 for shift in (21,16,11,6)),word&63])
            _write_span(m.p,first+offset//4*12,decoded);m.put(temporary+48,first+(offset//4+1)*12)
            index=word%source_count;decoded_words+=1
        if size%4:
            m.free_vector(temporary+40);m.free_string_value(_read_span(m.p,temporary+16,24))
            return finish(0)
        _write_span(m.p,cursor,_read_span(m.p,temporary,64));cursor+=64;m.put(output_address+16,cursor)
        _write_span(m.p,temporary+16,bytes(48))
    m.put(output_address,imported_functions+len(functions),4)
    globals_=list(records(0x78))
    if len(globals_)!=imported_globals:return finish(0)
    cursor=reserve(0x50,len(globals_),4)
    for record in globals_:
        m.put(cursor,_u(m.p,record+0xA8,4),4);cursor+=4;m.put(output_address+0x58,cursor)
    exports=list(records(0xA8));cursor=reserve(0x38,len(exports),32);temporary=temporaries[2]
    for record in exports:
        m.copy_string_value(temporary,_read_span(m.p,record,24),allocate)
        tag=kind(_u(m.p,record+24));index=_u(m.p,record+32,4) if tag==0 else 0xFFFFFFFF
        m.put(temporary+24,tag,4);m.put(temporary+28,index,4)
        if tag==0:
            if index>=imported_functions+len(functions):
                m.free_string_value(_read_span(m.p,temporary,24));return finish(0)
            if index<imported_functions:
                raise RefillUnsupported('parser imported-function export has no defined destination')
            destination=_u(m.p,output_address+8)+(index-imported_functions)*64+16
            m.assign_string(destination,temporary,allocate)
            _write_span(m.p,cursor,_read_span(m.p,temporary,32));cursor+=32;m.put(output_address+0x40,cursor)
            _write_span(m.p,temporary,bytes(24))
        m.free_string_value(_read_span(m.p,temporary,24))
    spans=[(_u(m.p,record),_u(m.p,record+8)) for record in records(0xF0)]
    size=sum(end-begin for begin,end in spans)
    if size>max_vector_bytes:raise RefillUnsupported('parser concatenated data exceeds the byte bound')
    cursor=reserve(0x68,size,1)
    for begin,end in spans:
        _write_span(m.p,cursor,_read_span(m.p,begin,end-begin));cursor+=end-begin
        m.put(output_address+0x70,cursor)
    return finish(1)


def cleanup_parser_conversion(pages, *, output_address, image_base,
        max_nodes=4096, max_vector_bytes=16*1024*1024, reserved_regions=()):
    """Actual +2cb968 destructor for the 128-byte converted module.

    Validate disjoint ownership, then release data, globals, exports, imports
    and functions. Records are consumed backwards; a function releases its
    decoded vector before its name. Each vector end resets to begin before
    the block is freed. The scalar count, begin/capacity and string headers
    retain native dangling bytes. Consume logical frees once and never reuse
    destroyed storage as a live object. The output object, error string and
    builtin catalog remain owned by their callers. Any guard/write failure
    rolls back all pages; actual allocator and native stack are not outputs.
    """
    m=_ReaderAstMemory(pages,image_base,output_address,128,max_nodes,max_vector_bytes,reserved_regions)
    m.claim(output_address,128)
    def string(address):
        header=_read_span(m.p,address,24)
        if header[0]&1:
            capacity=int.from_bytes(header[:8],'little')&~1
            length=int.from_bytes(header[8:16],'little')
            if not length<capacity<=max_vector_bytes:
                raise RefillUnsupported('converted cleanup string length/capacity is invalid')
            m.claim(int.from_bytes(header[16:24],'little'),capacity)
        elif header[0]>>1>22:
            raise RefillUnsupported('converted cleanup inline string length is invalid')
    containers=[];nodes=0
    for offset,stride in ((8,64),(0x20,64),(0x38,32),(0x50,4),(0x68,1)):
        begin,end,cap=m.vector(output_address+offset,stride)
        if offset in (8,0x20,0x38):
            nodes+=(cap-begin)//stride
            if nodes>max_nodes:
                raise RefillUnsupported('converted cleanup record bound exceeded')
            for record in range(begin,end,stride):
                if offset==8:
                    string(record+16);m.vector(record+40,12)
                elif offset==0x20:
                    string(record);string(record+24)
                else:string(record)
        containers.append((offset,stride,begin,end))
    for offset,stride,begin,end in reversed(containers):
        if offset in (8,0x20,0x38):
            for record in range(end-stride,begin-1,-stride):
                if offset==8:
                    m.free_vector(record+40);m.free_string_value(_read_span(m.p,record+16,24))
                elif offset==0x20:
                    m.free_string_value(_read_span(m.p,record+24,24))
                    m.free_string_value(_read_span(m.p,record,24))
                else:m.free_string_value(_read_span(m.p,record,24))
        m.free_vector(output_address+offset)
    m.p.commit()
    return ReaderAstResult(None,tuple(m.effects))
