"""Literal-only +0x26e9e0/+0x271ec8 logger and +0x271ddc input model.

Read the real 24-byte string object while its payload is alive. All text comes
from guest inputs; this owner never writes a tag, chooses a pointer from a
ledger, copies stack padding, or executes a native instruction. Conversion
formats, live sinks and concurrent dispatch remain explicit boundaries.
"""
from __future__ import annotations
from dataclasses import dataclass

from vm9_allocator import RefillUnsupported, _PageTransaction, _read_span, _write_span


def cstring(pages, address, *, max_bytes=0x100000):
    # +0x27617c(NULL) returns 0. Other callers decide whether NULL is valid.
    if not address:
        return b""
    out = bytearray()
    for offset in range(max_bytes):
        byte = _read_span(pages, address + offset, 1)[0]
        if byte == 0:
            return bytes(out)
        out.append(byte)
    raise RefillUnsupported("logger C string exceeds explicit bound")


@dataclass(frozen=True)
class LiteralLogResult:
    tag_address: int
    output_address: int
    level: int
    tag: bytes
    message: bytes
    formatted_length: int
    dispatch_mode: int
    callback_address: int
    return_value: int


def format_literal(pages, *, format_address, output_address, capacity=0x400):
    """Observed +0x2772a4 path with no '%' conversions; writes C terminator.

    This target helper is not libc vsnprintf. Truncation, percent processing
    and format instrumentation are not generalized from the literal control.
    """
    if not format_address or not 1 <= capacity <= 0x400:
        raise RefillUnsupported("invalid bounded logger format inputs")
    text = cstring(pages, format_address)
    if b"%" in text or len(text) >= capacity:
        raise RefillUnsupported("conversion or truncated logger format is unrecovered")
    _write_span(pages, output_address, text + bytes(1))
    return text


def log_literal_unavailable(pages, *, object_address, format_address,
                            entry_stack_address, image_base, read_property,
                            syscall, errno_address, observer=None):
    """+0x26e9e0 object -> literal format -> unavailable sink, in native order.

    entry_stack_address is SP on entry to +0x26e9e0, not the root VM stack.
    The object and its owned payload are read here; construction/destruction
    remain with construct_default_shared_reference. The sink initializer is
    the previously verified configuration owner and receives its actual SDK
    scratch address.
    """
    from vm9_configuration_init import initialize_unavailable_logger, _u
    if entry_stack_address & 15:
        raise RefillUnsupported("logger SP must be 16-byte aligned")
    staged = _PageTransaction(pages)
    payload = _u(staged, object_address + 16)
    if not payload:
        raise RefillUnsupported("NULL borrowed logger tag is not covered")
    tag = cstring(staged, payload)
    # Wrapper -0x120; formatter saves -0x30 and reserves -0x430.
    formatter_sp = entry_stack_address - 0x120 - 0x30 - 0x430
    output = formatter_sp + 0x28
    message = format_literal(staged, format_address=format_address,
                             output_address=output)
    # +0x271ddc creates a one-byte level plus two NUL-terminated strings.
    sink_sp = formatter_sp - 0x70
    _write_span(staged, sink_sp + 4, (6).to_bytes(4, "little"))
    fields = (sink_sp + 4, 1, payload, len(tag) + 1,
              output, len(message) + 1)
    _write_span(staged, sink_sp + 8,
                b"".join(value.to_bytes(8, "little") for value in fields))
    if observer:
        observer(staged, phase="before_sink", object_address=object_address,
                 tag_address=payload, output_address=output, level=6,
                 sink_stack_address=sink_sp, format_address=format_address)
    # SDK query +0x271ba8: sink SP-0x40, then a 0x60-byte property buffer.
    initialize_unavailable_logger(staged, image_base=image_base,
        read_property=read_property, syscall=syscall, errno_address=errno_address,
        property_buffer_address=sink_sp-0xA0)
    mode = _u(staged, image_base+0x382600, 4)
    callback = _u(staged, image_base + (0x382610 if mode == 1 else 0x382618))
    if mode == 1:
        if callback != image_base + 0x27220C:
            raise RefillUnsupported("unrecovered file sink callback")
        result = 0xFFFFFFFF
    elif mode == 0:
        if callback != image_base + 0x272214:
            raise RefillUnsupported("unrecovered socket sink callback")
        # Native returns the failed socket syscall result for the socket profile.
        result = 0xFFFFFF9F
    else:
        result = 0
    if observer:
        observer(staged, phase="after_sink", object_address=object_address,
                 tag_address=payload, output_address=output, level=6,
                 sink_stack_address=sink_sp, format_address=format_address,
                 return_value=result)
    staged.commit()
    return LiteralLogResult(payload, output, 6, tag, message, len(message),
                            mode, callback, result)
