"""B short descriptor selection, factory XOR and bounded reader sections.

The module root/array/hash buckets are explicit inputs. Native factory and
publication observations are verified separately; independent Python factory
+0x2cbdc8, constructor input generation and complete B VM remain open.
Reader sections 0 (generic), 1, 3, 7, 8 and 12, plus opted-in section 2
imports, section 4/5/6 definitions and section 10 code words, run with explicit
status-only callbacks.
Other handlers,
actual callbacks and AST remain open; unsupported
branches fail closed. These components do not implement a full factory.
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


def run_reader_sections(pages, *, state_address, image_base,
        varuint_scratch_address, callback, max_sections=512, max_entries=4096,
        max_input_bytes=16*1024*1024, vector_allocate=None,
        enable_function_global_imports=False, enable_table_memory_imports=False,
        import_scratch_address=None, enable_table_memory_sections=False,
        enable_global_section=False, global_scratch_address=None,
        max_initializer_ops=4096, enable_code_section=False, max_code_words=65536):
    """Bounded +0x324188 dispatch with handlers 0/1/2/3/4/5/6/7/8/10/12.

    State layout: limit/data/total/cursor/callback at +0/+8/+16/+24/+32;
    previous nonzero section at +0x88, import counts at +0x90/94/98/9c,
    function count at +0xa4, data count at +0xac. Generic custom sections
    skip unrecognized payload; dylink/linking/reloc/target_features reject.

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
            or not isinstance(max_code_words, int) or not 1 <= max_code_words <= 1048576):
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
            marker = decode(*markers[size])[:-1] if size in markers else None
            if name == marker or (size >= 5 and name[:5] == b'reloc'):
                raise RefillUnsupported('reader special custom-section handler is unrecovered')
            store(24, limit())
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
