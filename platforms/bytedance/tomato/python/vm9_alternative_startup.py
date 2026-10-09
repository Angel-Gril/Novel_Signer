"""B short descriptor selection, factory XOR and bounded reader sections.

The module root/array/hash buckets are explicit inputs. Native factory and
publication observations are verified separately; independent Python factory
+0x2cbdc8, constructor input generation and complete B VM remain open.
Reader sections 0 (generic), 1, 3, 7, 8 and 12, plus opted-in section 2
imports, section 4/5/6 definitions, section 9 empty element vectors,
section 10 code words and section 11 data segments, run with explicit
status-only callbacks.
Opted-in special custom handlers parse metadata. Actual type/start/local-count/
raw-word/data reserve/create callbacks and cleanup have separate bounded APIs;
they are not yet composed with the section parser. Other AST callbacks,
nonempty element vectors and complete AST/reader/factory remain open.
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
            self.claim(address, 64); self.vector(address+0x28, 8)
            pending.extend(((address, True), (_u(self.p, address+8), False),
                            (_u(self.p, address), False)))
        return order

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

    def callback(self, address, *, output=True):
        self.claim(address, 0x108)
        if _u(self.p, address) != self.base+0x372370:
            raise RefillUnsupported('AST callback requires its actual vtable')
        if _u(self.p, address+8):
            raise RefillUnsupported('AST callback attached parser state remains unsupported')
        ast = _u(self.p, address+0x18)
        if output:
            self.claim(ast, 0x120)
            if _u(self.p, address+0x20) != ast+0x108:
                raise RefillUnsupported('AST raw-word target is inconsistent')
            for offset in range(0, 0x120, 24):
                if offset not in (0,0xC0,0xF0,0x108) and any(
                        _u(self.p,ast+offset+word) for word in (0,8,16)):
                    raise RefillUnsupported('AST unrecovered output containers must be empty')
                stride = 64 if offset == 0 else 4 if offset == 0xC0 else 176 if offset == 0xF0 else 1
                begin, end, _ = self.vector(ast+offset, stride)
                if offset == 0:
                    for node in range(begin, end, 64): self.node(node, 64)
                elif offset == 0xF0:
                    for record in range(begin, end, 176): self.data_record(record)
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

    def free_vector(self, address):
        begin, _, cap = self.vector(address, own=False)
        if begin:
            _write_span(self.p, address+8, begin.to_bytes(8, 'little'))
            self.emit('free', begin, cap-begin)

    def destroy(self, address, stride):
        self.emit('destroy', address, stride)
        table = _u(self.p, address)-self.base
        if table == 0x3724F0:
            _write_span(self.p, address, (self.base+0x3724F0).to_bytes(8, 'little'))
            self.free_vector(address+0x28); self.free_vector(address+0x10)
        elif table == 0x372590:
            _write_span(self.p, address, (self.base+0x372590).to_bytes(8, 'little'))
            self.free_vector(address+0x10)

    def publish(self, address, words):
        _write_span(self.p, address, b''.join(value.to_bytes(8,'little') for value in words))

    def move_types(self, begin, end, destination):
        for source in range(end-64, begin-1, -64):
            target = destination+source-begin
            _write_span(self.p, target, (self.base+0x3724F0).to_bytes(8,'little'))
            _write_span(self.p, target+8, _read_span(self.p, source+8, 4))
            _write_span(self.p, target+0x10, _read_span(self.p, source+0x10, 48))
            _write_span(self.p, source+0x10, bytes(48))

    def move_data(self, begin, end, destination):
        for source in range(end-176, begin-1, -176):
            target = destination+source-begin
            for offset in (0,0x30,0x48,0x70,0x98):
                _write_span(self.p, target+offset, _read_span(self.p, source+offset, 24))
                _write_span(self.p, source+offset, bytes(24))
            _write_span(self.p, target+0x20, (self.base+0x3724F0).to_bytes(8,'little'))
            for offset, size in ((0x18,8),(0x28,4),(0x60,8),(0x68,4),(0x88,8),(0x90,4)):
                _write_span(self.p, target+offset, _read_span(self.p, source+offset, size))

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


def run_reader_ast_callback(pages, *, callback_address, image_base, slot_offset,
        arguments, allocate=None, max_nodes=4096, max_vector_bytes=16*1024*1024,
        reserved_regions=()):
    """Actual slots 18/20/a0/b0/140/160/168, with allocation and free effects.

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
    Start appends u32; local group count writes callback+78 and clears +7c;
    raw word appends four
    bytes to callback+20, including unaligned byte lengths. Arguments use
    uint64 registers and native w-register truncation. Other slots fail closed.

    allocate(size) must only plan an aligned address in mapped pages. It must
    not mutate pages or allocate externally. Frees are logical effects: pages
    stay mapped and unpoisoned. Guard failures roll back all model writes;
    allocator exceptions/abort, allocator boot and complete reader remain open.
    The callback must be detached (helper pointer +8 is zero); unrecovered
    output containers must be empty so their nested ownership cannot alias.
    The section parser still uses its separately supplied status service.
    """
    counts = {0x18:1,0x20:5,0xA0:1,0xB0:1,0x140:3,0x160:1,0x168:1}
    if (not isinstance(slot_offset,int) or slot_offset not in counts
            or not isinstance(arguments, (tuple,list))
            or len(arguments) != counts[slot_offset]
            or any(not isinstance(value,int) or not 0 <= value <= MASK64 for value in arguments)):
        raise RefillUnsupported('AST callback slot or uint64 arguments are unsupported')
    if not isinstance(callback_address,int) or not 0 < callback_address <= MASK64-0x108:
        raise RefillUnsupported('AST callback address is invalid')
    # Local group count has no output-object access in the native function.
    root, width = (callback_address,0x108) if slot_offset == 0xB0 else (
        _u(pages,callback_address+0x18),0x120)
    m = _ReaderAstMemory(pages,image_base,root,width,max_nodes,max_vector_bytes,reserved_regions)
    ast, _, _ = m.callback(callback_address, output=slot_offset != 0xB0)
    entries = {0x18:0x31B6B0,0x20:0x31B6D0,0xA0:0x31D6D4,
               0xB0:0x31D974,0x140:0x31E1D4,0x160:0x31E5B4,0x168:0x31E5D8}
    if _u(m.p,image_base+0x372370+slot_offset) != image_base+entries[slot_offset]:
        raise RefillUnsupported('AST callback slot relocation is unsupported')
    if slot_offset in (0x18,0x20,0x140):
        if _u(m.p,image_base+0x375090) != image_base+0x3724E0:
            raise RefillUnsupported('AST type move vtable source is unsupported')
    if slot_offset in (0x18,0x20):
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
    elif slot_offset == 0xB0:
        _write_span(m.p,callback_address+0x78,(arguments[0]&0xFFFFFFFF).to_bytes(4,'little')+bytes(4))
    elif slot_offset == 0x140:
        begin,end,cap = m.vector(ast+0xF0,176,own=False)
        size,capacity = (end-begin)//176,(cap-begin)//176
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
            new = m.allocate(new_capacity*176,allocate); target = new+size*176
        else: new,new_capacity,target = begin,capacity,end
        result = m.allocate(8,allocate); _write_span(m.p,result,sentinel)
        flags = arguments[2]&0xFFFFFFFF
        classification = 2 if flags&3 == 3 else flags&1
        for offset in (0,0x30,0x70,0x98): m.publish(target+offset,(0,0,0))
        m.publish(target+0x48,(result,result+8,result+8))
        for offset,value in ((0x18,classification | ((arguments[1]&0xFFFFFFFF)<<32)),
                             (0x20,image_base+0x3724F0),(0x60,0),(0x88,0xFFFFFFFF)):
            _write_span(m.p,target+offset,value.to_bytes(8,'little'))
        for offset in (0x28,0x68,0x90): _write_span(m.p,target+offset,bytes(4))
        if size == capacity:
            m.move_data(begin,end,new)
            m.publish(ast+0xF0,(new,new+(size+1)*176,new+new_capacity*176))
            for record in range(end-176,begin-1,-176): m.destroy_data(record)
            if begin: m.emit('free',begin,cap-begin)
        else: _write_span(m.p,ast+0xF8,(end+176).to_bytes(8,'little'))
        # Native temporary destructors are inlined; only their frees are effects.
        m.emit('free',temporary_data,8); m.emit('free',temporary_type,8)
    elif slot_offset == 0x160:
        begin,end,cap = m.vector(ast+0xF0,176,own=False)
        size,capacity = (end-begin)//176,(cap-begin)//176
        count = arguments[0]&0xFFFFFFFF
        if count > max_nodes:
            raise RefillUnsupported('AST data reserve exceeds the node bound')
        if count > capacity:
            new = m.allocate(count*176,allocate)
            m.move_data(begin,end,new)
            m.publish(ast+0xF0,(new,new+size*176,new+count*176))
            for record in range(end-176,begin-1,-176): m.destroy_data(record)
            if begin: m.emit('free',begin,cap-begin)
    else:
        vector = ast+0xC0 if slot_offset == 0xA0 else ast+0x108
        begin,end,cap = m.vector(vector,4 if slot_offset == 0xA0 else 1,own=False)
        size,capacity = end-begin,cap-begin
        if size+4 > max_vector_bytes or (slot_offset == 0x168 and size+4 >= 1<<32):
            raise RefillUnsupported('AST word append exceeds the byte bound')
        if cap-end < 4:
            new_capacity = max(size+4,capacity*2)
            new = m.allocate(new_capacity,allocate)
            _write_span(m.p,new+size, (arguments[0]&0xFFFFFFFF).to_bytes(4,'little')
                        if slot_offset == 0xA0 else bytes(4))
            _write_span(m.p,new,_read_span(m.p,begin,size))
            m.publish(vector,(new,new+size+4,new+new_capacity))
            if begin: m.emit('free',begin,capacity)
            begin = new
        else:
            if slot_offset == 0x168: _write_span(m.p,end,bytes(4))
            # The raw helper publishes its zero-filled extension before the
            # caller stores the word; start publishes after storing its word.
            if slot_offset == 0x168: _write_span(m.p,vector+8,(end+4).to_bytes(8,'little'))
        _write_span(m.p,begin+size,(arguments[0]&0xFFFFFFFF).to_bytes(4,'little'))
        if slot_offset == 0xA0 and cap-end >= 4:
            _write_span(m.p,vector+8,(end+4).to_bytes(8,'little'))
    m.p.commit()
    return ReaderAstResult(0,tuple(m.effects))


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


def cleanup_reader_callback(pages, *, callback_address, image_base,
        max_nodes=4096, max_vector_bytes=16*1024*1024, reserved_regions=()):
    """Actual +31b458 cleanup: five reverse node lists, two trees, buffer.

    The five strides are 40/24/40/48/64 at e0/c8/b0/98/80. Supported node
    destructors execute their owned-vector resets/frees. Trees use left/right
    postorder +3202f0; payload end resets before its free, then node is freed.
    Begin/capacity and tree roots remain dangling as in native destruction.
    The caller consumes logical free effects once. The independent record
    list and output AST are retained; wrapper +31b360 cleanup remains open.
    """
    m = _ReaderAstMemory(pages,image_base,callback_address,0x108,max_nodes,max_vector_bytes,reserved_regions)
    _,lists,trees = m.callback(callback_address)
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
        max_custom_records=4096):
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
    Section 11 sends +0x158(index, payload_pointer) without a length argument.

    enable_special_custom_sections opts into dylink/dylink.0/linking,
    target_features and reloc prefixes. These parse metadata without AST callbacks.
    A mapped, aligned, disjoint eight-byte custom_scratch_address holds integer
    reads; decoder storage, the opcode table pointer and active expression
    opcode tables are retained.
    max_custom_records bounds the sum of subsections, list entries and
    nested pairs in EACH custom section. Unknown subsections skip opaque bytes;
    known subsections must consume their exact size. Temporary limits and the
    custom flag are restored on parse failure as well as success.
    """
    if (not isinstance(state_address, int) or not 0 < state_address <= MASK64-0xAF
            or state_address & 7 or not isinstance(image_base, int)
            or not 0 < image_base <= MASK64-0x3E2D74 or image_base & 4095
            or not isinstance(varuint_scratch_address, int)
            or not 0 < varuint_scratch_address <= MASK64-3):
        raise RefillUnsupported('reader section addresses exceed the bounded guest ABI')
    if (not callable(callback) or not isinstance(max_sections, int)
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
    if enable_global_section:
        if (not isinstance(global_scratch_address, int) or global_scratch_address & 7
                or not 0 < global_scratch_address <= MASK64-15):
            raise RefillUnsupported('reader globals need an aligned 16-byte scratch region')
        scratch_end = global_scratch_address+16
        retained = (*regions, (varuint_scratch_address, varuint_scratch_address+4))
        for offset in (0x28, 0x40):
            begin, _, capacity_end = _reader_vector_words(p, state_address+offset, max_entries, retained)
            retained += ((begin, capacity_end),)
        if any(start < scratch_end and global_scratch_address < end for start, end in retained):
            raise RefillUnsupported('reader global scratch overlaps retained storage')
        _read_span(p, global_scratch_address, 16)
        regions.append((global_scratch_address, scratch_end))
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
        counts = tuple(_u(p, state_address+offset, 4) for offset in (0x90, 0x94, 0x98, 0x9C))
        import_limits = ()
        if slot in (0x30, 0x38, 0x60, 0x70):
            descriptor = _read_span(p, import_scratch_address, 19)
            import_limits = (int.from_bytes(descriptor[:8], 'little'),
                             int.from_bytes(descriptor[8:16], 'little'), *descriptor[16:])
        event = ReaderCallbackEvent(slot, tuple(arguments), cursor(), limit(), type_vectors,
                                    counts, import_limits)
        status = callback(event)
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
                (varuint_scratch_address, varuint_scratch_address+4))):
            raise RefillUnsupported('reader initializer opcode table overlaps scratch')
        for _ in range(max_initializer_ops):
            if cursor() >= limit():
                raise _ReaderParseFailure()
            opcode = _u(p, data+cursor(), 1)
            store(24, cursor()+1)
            if opcode in (0xFC, 0xFD, 0xFE):
                subopcode = read_u32(global_scratch_address+8)
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
                bits = read_i32(global_scratch_address+8) & 0xFFFFFFFF
                emit(0xE0, bits)
            elif kind == 3:
                result = read_reader_varint64(p, start_address=data+cursor(),
                    end_address=data+limit(), output_address=global_scratch_address+8)
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

    def special_custom(kind):
        if not enable_special_custom_sections:
            raise RefillUnsupported('reader special custom-section handler needs explicit opt-in')
        records = 0

        def record():
            nonlocal records
            if records >= max_custom_records:
                raise RefillUnsupported('reader custom record bound reached')
            records += 1

        def u32():
            return read_u32(custom_scratch_address)

        def string():
            size = u32()
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
            linking = kind == 'linking'
            if linking and u32() != 2:
                raise _ReaderParseFailure()
            while cursor() < limit():
                record()
                tag, size = u32(), u32()
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
                        for _ in range(u32()):
                            record()
                            if not linking:
                                string()
                                if tag == 4:
                                    string()
                                if tag in (3, 4):
                                    u32()
                            elif tag == 5:
                                string()
                                if u32() >= 32:
                                    raise _ReaderParseFailure()
                                u32()
                            elif tag == 6:
                                u32()
                                u32()
                            elif tag == 7:
                                string()
                                u32()
                                for _ in range(u32()):
                                    record()
                                    u32()
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
                                    u32()
                    else:
                        store(24, end)
                    if cursor() != end:
                        raise _ReaderParseFailure()
                finally:
                    store(0, old_limit)

    def handler(number):
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
                    special_custom(kind)
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
                emit(0x158, index, data+start)
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
