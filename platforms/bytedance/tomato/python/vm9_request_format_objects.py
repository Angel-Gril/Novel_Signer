"""Bounded native format objects for the request's signed-int32 mode path.

Restore token/argument vectors, inline rendering/conversion and cleanup.
Token padding is unspecified native stack data and is not a semantic field.
No native output, prebuilt JSON result or allocation return seeds the model.
"""
from __future__ import annotations
from dataclasses import dataclass
import vm9_objects as objects
from vm9_allocator import RefillUnsupported, _PageTransaction, _read_span, _write_span
from vm9_cpp_strings import construct_cpp_string

MAX_FORMAT_BYTES = 1024
MAX_TOKENS = 32
TOKEN_BYTES = 64


def _u(p, address, width=8):
    return int.from_bytes(_read_span(p, address, width), 'little')


def _w(p, address, value, width=8):
    _write_span(p, address, value.to_bytes(width, 'little'))


def _lazy(p, image, source, destination, mask, flag):
    if _u(p, image + flag, 4) == 0:
        objects.decode_masked_bytes(p, source_address=image + source,
            destination_address=image + destination, mask_address=image + mask)
        _w(p, image + flag, 1, 4)


def _allocate(p, size, allocate):
    pointer = allocate(p, size)
    if not isinstance(pointer, int) or not 0 < pointer < 1 << 64:
        raise RefillUnsupported('format object operator-new failure is not recovered')
    _read_span(p, pointer, size)
    return pointer


def _format_tokens(data):
    """Recovered plain-literal/{0} branch, excluding escapes and specs."""
    if b'{{' in data or b'}}' in data.replace(b'{0}', b''):
        raise RefillUnsupported('format escapes are outside the recovered mode branch')
    result = []
    start = 0
    while True:
        offset = data.find(b'{0}', start)
        if offset < 0:
            if start < len(data):
                result.append((2, start, len(data) - start))
            break
        if offset > start:
            result.append((2, start, offset - start))
        result.append((1, offset + 1, 1))
        start = offset + 3
    # A single outer JSON brace in a literal is supported by the actual mode
    # sample; other brace syntax is refused rather than silently reinterpreted.
    for tag, offset, length in result:
        if tag == 2:
            literal = data[offset:offset + length]
            if b'{' in literal and not (offset == 0 and literal.startswith(b'{"')
                    and literal.count(b'{') == 1 and literal.endswith(b':')):
                raise RefillUnsupported('format argument/spec syntax is outside the recovered mode branch')
            if b'}' in literal and not (offset + length == len(data) and literal == b'}'):
                raise RefillUnsupported('format closing brace syntax is outside the recovered mode branch')
    if len(result) > MAX_TOKENS:
        raise RefillUnsupported('format token vector exceeds explicit bound')
    return result


def _parser_names(p, image):
    _lazy(p,image,0x11F5C0,0x3E1E10,0x11F5D4,0x3E1E14)
    _lazy(p,image,0x11F5C4,0x3E1E18,0x11F5CC,0x3E1E20)
    if (objects._cstring(p,image+0x3E1E10,3) != b'{}\0' or
            objects._cstring(p,image+0x3E1E18,7) != b' \t\n\v\f\r\0'):
        raise RefillUnsupported('format parser character sets do not match recovered branch')
    # +0x186fec -> +0x294ab0/294b90 initializes five radix prefixes
    # even for the single digit zero used by the supported {0} field.
    for index in range(5):
        _lazy(p,image,0x11F4E0+index*4,0x3E1D60+index*8,0x11F504-index*4,0x3E1D64+index*8)
        if objects._cstring(p,image+0x3E1D60+index*8,3) != (b'0x',b'0X',b'0b',b'0B',b'0o')[index]+b'\0':
            raise RefillUnsupported('format parser radix prefixes do not match recovered branch')


def _write_token(p, address, tag, source, length):
    # +4..7 and literal +44..47 are unspecified copied stack padding.
    # Keep them untouched. Only fields consumed by the native renderer belong
    # to this contract; verifier never masks any initialized semantic field.
    _w(p,address,tag,4)
    _w(p,address+8,source)
    _w(p,address+16,length)
    _write_span(p,address+24,bytes(16))
    _w(p,address+40,2,4)
    if tag == 1:
        _write_span(p,address+44,b' ')
    _write_span(p,address+48,bytes(16))


def build_mode_format_object(pages, *, image_base, object_address,
        format_address, argument_address, allocate, free):
    """+0x28f0f4/28f16c for one borrowed signed-int32 argument.

    Original reserve, temporary pointer vector, ownership move and cleanup
    preserve allocation order. Empty/literal-only inputs do not read the mode.
    Return is the helper API object address, not a native X0 ABI assertion.
    """
    p = _PageTransaction(pages)
    _read_span(p, object_address, 80)
    data = objects._cstring(p,format_address,MAX_FORMAT_BYTES+1)[:-1] if format_address else b''
    plan = _format_tokens(data)
    _w(p,object_address,format_address)
    _w(p,object_address+8,len(data))
    _write_span(p,object_address+16,bytes(24))
    vector = object_address + 40
    _write_span(p,vector,bytes(24))
    count, capacity, begin = 0, 0, 0
    for tag, offset, length in plan:
        if tag == 1:
            _parser_names(p,image_base)
        if count == capacity:
            new_capacity = max(1,capacity*2)
            new_begin = _allocate(p,new_capacity*TOKEN_BYTES,allocate)
            _write_token(p,new_begin+count*TOKEN_BYTES,tag,format_address+offset,length)
            if count:
                _write_span(p,new_begin,_read_span(p,begin,count*TOKEN_BYTES))
            old_begin = begin
            begin, capacity = new_begin, new_capacity
            _w(p,vector,begin)
            _w(p,vector+8,begin+(count+1)*TOKEN_BYTES)
            _w(p,vector+16,begin+capacity*TOKEN_BYTES)
            if old_begin:
                free(p,old_begin)
        else:
            _write_token(p,begin+count*TOKEN_BYTES,tag,format_address+offset,length)
            _w(p,vector+8,begin+(count+1)*TOKEN_BYTES)
        count += 1
    reserved = _allocate(p,8,allocate)
    _w(p,object_address+16,reserved)
    _w(p,object_address+24,reserved)
    _w(p,object_address+32,reserved+8)
    # Typed argument cell borrows the live uint32 address and does not copy it.
    _w(p,object_address+64,image_base+0x35F858)
    _w(p,object_address+72,argument_address)
    temporary = _allocate(p,8,allocate)
    _w(p,temporary,object_address+64)
    # +0x187710 destroys the reserved destination, then moves the temporary.
    free(p,reserved)
    _w(p,object_address+16,temporary)
    _w(p,object_address+24,temporary+8)
    _w(p,object_address+32,temporary+8)
    p.commit()
    return object_address


def _signed32_bytes(p, address, image):
    for source, destination, mask, flag in (
            (0x11F1BC,0x3E1AB0,0x11F1F0,0x3E1AB4),
            (0x11F1C0,0x3E1AB8,0x11F1EC,0x3E1ABC),
            (0x11F1C4,0x3E1AC0,0x11F1E8,0x3E1AC4),
            (0x11F1C8,0x3E1AC8,0x11F1E4,0x3E1ACC)):
        _lazy(p,image,source,destination,mask,flag)
    for offset,expected in ((0x3E1AB0,b'N'),(0x3E1AB8,b'n'),(0x3E1AC0,b'D'),(0x3E1AC8,b'd')):
        if objects._cstring(p,image+offset,2) != expected+b'\0':
            raise RefillUnsupported('mode renderer selectors do not match recovered branch')
    raw = _u(p,address,4)
    value = raw - (1 << 32) if raw & (1 << 31) else raw
    return str(value).encode('ascii')


def render_mode_format_to_buffer(pages, *, image_base, format_object_address,
        buffer_object_address, max_output_bytes=128):
    """+0x1b40d4 inline buffer path through +0x295528/+0x28e9b4.

    The 144-byte object has pointer, uint32 length/capacity, and 128 inline
    bytes. Heap/growth and format specifications are explicit refusals.
    """
    if not isinstance(max_output_bytes,int) or not 0 <= max_output_bytes <= 128:
        raise ValueError('invalid inline format output bound')
    p = _PageTransaction(pages)
    _read_span(p,buffer_object_address,144)
    _w(p,buffer_object_address,buffer_object_address+16)
    _w(p,buffer_object_address+8,0,4)
    _w(p,buffer_object_address+12,128,4)
    begin,end,capacity = (_u(p,format_object_address+n) for n in (40,48,56))
    if (not (begin <= end <= capacity) or (end-begin)%64 or
            (end-begin)//64 > MAX_TOKENS):
        raise RefillUnsupported('invalid format token vector')
    arg_begin,arg_end = (_u(p,format_object_address+n) for n in (16,24))
    if arg_end-arg_begin != 8:
        raise RefillUnsupported('mode format requires exactly one argument')
    for token in range(begin,end,64):
        tag = _u(p,token,4)
        if tag == 0:
            continue
        if tag == 2:
            size = _u(p,token+16)
            if size > MAX_FORMAT_BYTES:
                raise RefillUnsupported('format literal exceeds bound')
            piece = _read_span(p,_u(p,token+8),size)
        elif tag == 1:
            if (_u(p,token+24) or _u(p,token+32) or _u(p,token+40,4)!=2
                    or _u(p,token+44,1)!=32 or _u(p,token+56)):
                raise RefillUnsupported('format spec is outside recovered mode renderer')
            cell = _u(p,arg_begin)
            if _u(p,cell) != image_base+0x35F858:
                raise RefillUnsupported('unsupported mode format argument vtable')
            piece = _signed32_bytes(p,_u(p,cell+8),image_base)
        else:
            raise RefillUnsupported('unsupported format token kind')
        length = _u(p,buffer_object_address+8,4)
        if length+len(piece) > max_output_bytes:
            raise RefillUnsupported('mode format inline buffer growth is not recovered')
        if piece:
            _write_span(p,buffer_object_address+16+length,piece)
            _w(p,buffer_object_address+8,length+len(piece),4)
    p.commit()
    return _u(p,buffer_object_address+8,4)


def destroy_mode_format_object(pages, *, object_address, free):
    """+0x186780: token vector, then argument vector; end resets, begin stays."""
    p = _PageTransaction(pages)
    for offset in (40,16):
        pointer = _u(p,object_address+offset)
        if pointer:
            _w(p,object_address+offset+8,pointer)
            free(p,pointer)
    p.commit()


@dataclass(frozen=True)
class ModeFormatResult:
    object_address: int
    format_object_address: int
    conversion_object_address: int
    rendered_length: int


def execute_event_mode(pages, *, image_base, entry_stack_address,
        output_object_address, mode, allocate, free, observer=None):
    """Bounded +0x28e788 complete mode construction/conversion/cleanup.

    Does not claim generic format grammar, whole native stack, or request
    callback completion. The observer receives mode/body result only.
    """
    if not isinstance(entry_stack_address,int) or entry_stack_address < 0x140 or entry_stack_address&15:
        raise RefillUnsupported('event mode stack must be aligned with scratch space')
    if not isinstance(mode,int) or not 0 <= mode < 1 << 32:
        raise RefillUnsupported('event mode must fit uint32')
    p = _PageTransaction(pages)
    _lazy(p,image_base,0x11F1CC,0x3E1AD0,0x11F1D8,0x3E1ADC)
    argument,fmt,buffer = (entry_stack_address-n for n in (0x60,0xB0,0x140))
    _w(p,argument,mode,4)
    build_mode_format_object(p,image_base=image_base,object_address=fmt,
        format_address=image_base+0x3E1AD0,argument_address=argument,
        allocate=allocate,free=free)
    length = render_mode_format_to_buffer(p,image_base=image_base,
        format_object_address=fmt,buffer_object_address=buffer)
    construct_cpp_string(p,object_address=output_object_address,
        source_address=_u(p,buffer),length=length,allocate=allocate)
    # +0x1b4320 only frees a heap pointer; this supported buffer is inline.
    if _u(p,buffer) != buffer+16:
        raise RefillUnsupported('mode conversion buffer ownership is unsupported')
    destroy_mode_format_object(p,object_address=fmt,free=free)
    if observer:
        observer(p,phase='mode_body_completed',output_object_address=output_object_address,
            format_object_address=fmt,conversion_object_address=buffer,
            rendered_length=length,mode=mode,bounded_mode_body_completed=True,
            whole_request_callback_completed=False)
    p.commit()
    return ModeFormatResult(output_object_address,fmt,buffer,length)
