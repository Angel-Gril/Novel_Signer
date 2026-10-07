"""+0x28dc38/28dc40 request event wrappers with explicit formatter boundary."""
from __future__ import annotations
from dataclasses import dataclass
import vm9_objects as objects
from vm9_cpp_strings import construct_cpp_string, clone_cpp_string, destroy_cpp_string
from vm9_allocator import RefillUnsupported, _PageTransaction, _read_span, _write_span


@dataclass(frozen=True)
class RequestEventResult:
    first_object_address: int
    second_object_address: int
    formatter_calls: int
    emit_error_event: bool


def execute_request_event(pages, *, image_base, entry_stack_address,
        argument_words, emit_error_event=0, allocate, free, format_event=None, observer=None):
    """Construct/copy/destroy C++ strings in native order.

    format_event(pages, cpp_string_address, x1,x2,x3,x4,w5) supplies +0x28ddd0.
    Missing formatter rejects at the real call and leaves caller pages unchanged.
    Observers may record the proven staged prefix without committing it.
    """
    if (not isinstance(entry_stack_address, int) or entry_stack_address < 0xF0
            or entry_stack_address & 15):
        raise RefillUnsupported('request event stack must be aligned')
    if len(argument_words) != 4 or any(not isinstance(w, int) or not 0 <= w < 1 << 64 for w in argument_words):
        raise RefillUnsupported('request event requires four uint64 ABI words')
    if not isinstance(emit_error_event, int) or not 0 <= emit_error_event < 1 << 32:
        raise RefillUnsupported('request event mode must fit uint32')
    p = _PageTransaction(pages)
    globals_ledger = []
    for source, mask, destination, flag in ((0x11F0C0, 0x11F2E0, 0x3E1990, 0x3E19A4),
            (0x11F0E0, 0x11F2C0, 0x3E19B0, 0x3E19C4)):
        before = int.from_bytes(_read_span(p, image_base + flag, 4), 'little')
        length = None
        if before == 0:
            length = objects.decode_masked_bytes(p, source_address=image_base + source,
                destination_address=image_base + destination, mask_address=image_base + mask)
            _write_span(p, image_base + flag, (1).to_bytes(4, 'little'))
        globals_ledger.append(dict(flag_address=image_base + flag, flag_before=before,
            decode_performed=before == 0, decoded_length=length))
    first, second, first_copy, second_copy = (entry_stack_address - n for n in (0x90, 0xB0, 0xD0, 0xF0))
    construct_cpp_string(p, object_address=first, source_address=image_base + 0x3E1990, allocate=allocate)
    construct_cpp_string(p, object_address=second, source_address=image_base + 0x3E19B0, allocate=allocate)
    clone_cpp_string(p, object_address=first_copy, source_object_address=first, allocate=allocate)
    context = dict(globals=globals_ledger, first_object_address=first,
        second_object_address=second, first_copy_address=first_copy,
        second_copy_address=second_copy, argument_words=list(argument_words),
        emit_error_event=emit_error_event)
    if observer:
        observer(p, phase='before_first_formatter', **context)
    if format_event is None:
        raise RefillUnsupported('request event formatter +0x28ddd0 is not recovered')
    format_event(p, first_copy, *argument_words, emit_error_event)
    destroy_cpp_string(p, object_address=first_copy, free=free)
    calls = 1
    if emit_error_event:
        clone_cpp_string(p, object_address=second_copy, source_object_address=second, allocate=allocate)
        if observer:
            observer(p, phase='before_second_formatter', **context)
        format_event(p, second_copy, *argument_words, emit_error_event)
        destroy_cpp_string(p, object_address=second_copy, free=free)
        calls += 1
    destroy_cpp_string(p, object_address=second, free=free)
    destroy_cpp_string(p, object_address=first, free=free)
    p.commit()
    return RequestEventResult(first, second, calls, bool(emit_error_event))
