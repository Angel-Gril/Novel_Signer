"""Bounded model of the post-VM unavailable logger handoff.

The native outer path enters ``+0x26e9e0`` with a stack-local logger object.
This module materializes only fields directly supported by the fresh register
trace and the ``+0x271ec8 -> +0x271ddc`` formatting boundary. It does not
claim to recover the final sink callback, file/socket writes, or descriptor
publication.
"""
from __future__ import annotations

import struct

from vm9_allocator import _PageTransaction, _read_span, _write_span, RefillUnsupported

MASK64 = (1 << 64) - 1
POISON = 0xA5A5A5A5A5A5A5A5
MESSAGE_FALLBACK = b"Invalid JavaVM, fallback to test path."
TAG_FALLBACK = b"METASEC"


def _u64(value: int) -> bytes:
    if not isinstance(value, int) or not 0 <= value <= MASK64:
        raise RefillUnsupported("logger field is outside uint64")
    return value.to_bytes(8, "little")


def _read_cstring(pages, address: int, limit: int = 0x400) -> bytes:
    raw = _read_span(pages, address, limit)
    return raw.split(b"\0", 1)[0]


def _write_words(pages, address: int, words: list[int]) -> None:
    _write_span(pages, address, b"".join(_u64(word) for word in words))


def choose_tag_payload(allocation_calls, allocation_sites, free_calls, *,
                       tag_length: int, allocator_events=None) -> int:
    """Find the live payload made by the shared logger string constructor.

    The caller supplies the same allocator ledger used by the fresh Python
    constructor. This avoids hard-coding the matching-libc heap address while
    still identifying the allocation by the recovered native construction
    site and exact ``strlen(tag)+1`` size.
    """
    live = set()
    if allocator_events is not None:
        for event in allocator_events:
            if event and event[0] == "alloc" and len(event) >= 3:
                live.add(event[2])
            elif event and event[0] == "free" and len(event) >= 2:
                live.discard(event[1])
    else:
        live = {pointer for _, pointer in allocation_calls} - set(free_calls)
    for index in range(len(allocation_calls) - 1, -1, -1):
        size, pointer = allocation_calls[index]
        sites = allocation_sites[index] if index < len(allocation_sites) else ()
        site_text = " ".join(str(item) for item in sites)
        if (size == tag_length + 1 and pointer in live
                and "construct_default_shared_reference" in site_text
                and "construct_string_object" in site_text):
            return pointer
    raise RefillUnsupported("fresh shared logger tag payload is not in allocator ledger")


def materialize_post_vm_logger(pages, *, vm_stack: int, image_base: int,
                               object_address: int, format_object_address: int,
                               tag_address: int, thread_pointer: int,
                               output_address: int | None = None) -> dict:
    """Materialize the proven logger object/formatter boundary.

    ``vm_stack`` is the stack value observed at the generic VM prelude. The
    native logger object is ``vm_stack-0xAE0``. The field offsets and scratch
    relationships below are taken from four fresh native controls at two image
    bases and two property profiles. The formatter output is the exact
    fallback message observed at ``+0x271ddc``.
    """
    if object_address != vm_stack - 0xAE0:
        raise RefillUnsupported("logger object is not vm_stack-0xAE0")
    if format_object_address != image_base + 0x3DEDD0:
        raise RefillUnsupported("logger format object is not image+0x3DEDD0")
    if output_address is None:
        # +0x271ec8 allocates 0x430 bytes below its entry frame; the buffer
        # passed to +0x271ddc is entry-vm-stack-0x1048.
        output_address = vm_stack - 0x1048

    source = _read_cstring(pages, format_object_address)
    message = source or MESSAGE_FALLBACK
    if message != MESSAGE_FALLBACK:
        raise RefillUnsupported("unrecovered non-fallback logger format string")

    words = [
        image_base + 0x34F5F8,
        (7 << 32) | 8,
        tag_address,
        vm_stack - 0x970,
        vm_stack - 0xA70,
        POISON,
        vm_stack - 0xA70,
        image_base + 0x26CD98,
        vm_stack - 0x960,
        image_base + 0x3DEE20,
        thread_pointer,
        vm_stack - 0xA40,
        vm_stack - 0xA50,
        POISON,
        vm_stack - 0xA20,
        image_base + 0x25EEF4,
    ]
    staged = _PageTransaction(pages)
    _write_words(staged, object_address, words)
    _write_span(staged, tag_address, TAG_FALLBACK + b"\0")
    _write_span(staged, output_address, message + b"\0")
    staged.commit()
    return {
        "object_address": hex(object_address),
        "object_bytes_0x80": _read_span(pages, object_address, 0x80).hex(),
        "tag_address": hex(tag_address),
        "tag_bytes_0x40": _read_span(pages, tag_address, 0x40).hex(),
        "format_object_address": hex(format_object_address),
        "format_bytes_0x80": _read_span(pages, format_object_address, 0x80).hex(),
        "log_level": 6,
        "tag_length": len(TAG_FALLBACK),
        "format_width": 3,
        "output_address": hex(output_address),
        "output_bytes_0x420": _read_span(pages, output_address, 0x420).hex(),
        "output_text": message.decode("ascii"),
        "logger_object_fields_recovered": True,
        "formatter_payload_recovered": True,
        "sink_dispatch_recovered": False,
        "native_callback_published": False,
        "fresh_medusa_output_verified": False,
    }
