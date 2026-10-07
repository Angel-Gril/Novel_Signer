"""Bounded request VM store loop, sub-dispatch, and OR64 composition.

All ABI addresses are explicit or derived from the fresh caller frame. Native
snapshots are oracle outputs only. The composed dispatcher/store/OR helper stops before +0x16e158.
MOVhi is a separate transition.
"""
from __future__ import annotations

from dataclasses import dataclass

from vm9_allocator import RefillUnsupported, _PageTransaction, _read_span, _write_span
from vm9_request_dispatcher import (
    RequestDispatchFrame, dispatch_request_word, initialize_request_dispatch_scratch,
)
from vm9_request_or64 import prepare_or64_state, apply_or64

MASK64 = (1 << 64) - 1
STORE_OFFSET = 0x171138
STORE_END = 0x1712C8
SUBDISPATCH_OFFSET = 0x16855C
SUBDISPATCH_END = 0x168598
NORMAL_KEY = 0xFF5F9EBBF5FE033C


def _guard(image_base, mask, additive, limit):
    low = (image_base + 0x168324) & 0xFFFFFFFF
    discriminator = (~(((low + 1) & 0xFFFFFFFF) & (~low & 0xFFFFFFFF))) & 0xFFFFFFFF
    if (((discriminator & mask) + additive) & MASK64) < limit:
        raise RefillUnsupported("nested VM repair path is not recovered")


def _dispatch_mask(image_base):
    base_word = (image_base + 0x168324) & MASK64
    folded = ((0x00A060400A021040 | (~base_word & MASK64)) & 0x00A061440A061440)
    folded = (folded + (base_word & 0x0000010400040400)) & MASK64
    return (folded | 0x01010104) ^ NORMAL_KEY


@dataclass(frozen=True)
class Store64State:
    image_base: int
    x0: int
    x1: int
    x4: int
    x5: int
    x19: int
    x20: int
    x23: int
    x28: int
    x29: int


def prepare_store64_state(**inputs):
    state = Store64State(**inputs)
    if any(not isinstance(v, int) or not 0 <= v <= MASK64 for v in vars(state).values()):
        raise RefillUnsupported("store loop inputs must fit uint64")
    return state


def store_request_word(pages, state: Store64State):
    """Execute one normal +0x171138 iteration, preserving native load/store order."""
    _guard(state.image_base, 0x14830140, 0x005040016C882885, 0x0049FD9D)
    staged = _PageTransaction(pages)
    writes = []

    def read(address, width):
        return int.from_bytes(_read_span(staged, address, width), "little")

    def write(address, value, width):
        _write_span(staged, address, value.to_bytes(width, "little"))
        writes.append((address, width))

    current = read(state.x19, 8)
    word = read(current, 4)
    if word & 0x3F != 26:
        raise RefillUnsupported("store loop word is not VM op26")
    next_pointer = (current + 4) & MASK64
    next_word = read(next_pointer, 4)
    write(state.x19, next_pointer, 8)
    encoded_disp = ((word >> 16) & 0x1F) | ((word >> 6) & 0x3E0)
    encoded_disp |= (((word >> 6) & 1) << 10) | ((word << 4) & 0x7800)
    encoded_disp |= (word >> 11) & 0x8000
    signed_disp = encoded_disp - 0x10000 if encoded_disp & 0x8000 else encoded_disp
    base_slot = ((word >> 22) & 0xF) | (((word >> 31) & 1) << 4)
    source_slot = ((word >> 27) & 0xF) | (((word >> 21) & 1) << 4)
    base_value = read(state.x28 + base_slot * 8, 8)
    source_value = read(state.x28 + source_slot * 8, 8)
    target_address = (base_value + signed_disp) & MASK64
    write(target_address, source_value, 8)
    table_base = read(state.x20 + 0x8D8, 8)
    frame_reference = read(state.x29 - 0x38, 8)
    table_entry = (table_base + _dispatch_mask(state.image_base) + (next_word & 0x3F) * 8) & MASK64
    return_key = read(state.x29 - 8, 8)
    write(state.x1, base_slot, 4)
    write(state.x23, source_slot, 4)
    encoded_target = read(table_entry, 8)
    next_handler = (encoded_target - return_key) & MASK64
    scratch_pointer = read(state.x29 - 0x10, 8)
    write(scratch_pointer, encoded_disp, 2)
    staged.commit()
    return {
        "word_address": current, "word": word, "next_word": next_word,
        "base_slot": base_slot, "source_slot": source_slot,
        "encoded_displacement": encoded_disp, "signed_displacement": signed_disp,
        "target_address": target_address, "source_value": source_value,
        "next_handler": next_handler, "next_handler_offset": next_handler - state.image_base,
        "register_updates": {"x0": state.x0, "x4": NORMAL_KEY, "x5": state.x5,
            "x8": next_handler, "x9": scratch_pointer, "x10": table_base,
            "x11": encoded_disp, "x12": NORMAL_KEY, "x13": base_slot,
            "x14": source_slot, "x15": source_value, "x16": signed_disp & MASK64,
            "x17": frame_reference},
        "writes": writes,
    }


def subdispatch_request_word(pages, *, image_base, x19, x29, x4, x5):
    """Select one op17 sub-handler at +0x16855c; this block writes no memory."""
    values = (image_base, x19, x29, x4, x5)
    if any(not isinstance(v, int) or not 0 <= v <= MASK64 for v in values):
        raise RefillUnsupported("sub-dispatch inputs must fit uint64")
    current = int.from_bytes(_read_span(pages, x19, 8), "little")
    word = int.from_bytes(_read_span(pages, current, 4), "little")
    if word & 0x3F != 17:
        raise RefillUnsupported("sub-dispatch word is not VM op17")
    sub = (word >> 6) & 0x3F
    table_base = int.from_bytes(_read_span(pages, image_base + 0x3798E0, 8), "little")
    entry = (table_base + ((x5 | 0x01010104) ^ x4) + sub * 8) & MASK64
    return_key = int.from_bytes(_read_span(pages, x29 - 8, 8), "little")
    encoded = int.from_bytes(_read_span(pages, entry, 8), "little")
    target = (encoded - return_key) & MASK64
    return {"word_address": current, "word": word, "op": 17, "sub": sub,
            "next_handler": target, "next_handler_offset": target - image_base,
            "register_updates": {"x8": target, "x9": return_key, "x10": sub, "x21": word},
            "writes": []}


def initialize_request_nested_frame(pages, frame: RequestDispatchFrame):
    """Generate the two extra prelude pointers consumed by the normal store loop.

    These follow the stack allocations and descriptor top in +0x168324.
    Other generic prelude spills are outside this bounded memory contract.
    """
    initialize_request_dispatch_scratch(pages, frame)
    top = frame.x19 + 0x120
    _write_span(pages, frame.x29 - 0x38, (top - 0x18).to_bytes(8, "little"))
    _write_span(pages, frame.x29 - 0x10, (frame.x22 + 0x10).to_bytes(8, "little"))


def execute_request_nested_prefix(pages, frame: RequestDispatchFrame, *, max_store_words=64):
    """Compose dispatcher -> repeated stores -> sub-dispatch -> one OR64.

    The caller backing slots must have been generated from explicit inputs.
    Execution is transactional: any new boundary or budget limit leaves pages
    untouched rather than publishing a partially successful prefix.
    """
    if not isinstance(max_store_words, int) or max_store_words < 1:
        raise RefillUnsupported("store loop budget must be positive")
    staged = _PageTransaction(pages)
    initialize_request_nested_frame(staged, frame)
    first = dispatch_request_word(staged, frame)
    if first["next_handler_offset"] != STORE_OFFSET:
        raise RefillUnsupported("request prefix did not select the known store loop")
    # Prelude derives x5 before OR with the dispatch constant.
    base_word = (frame.image_base + 0x168324) & MASK64
    x5 = (((0x00A060400A021040 | (~base_word & MASK64)) & 0x00A061440A061440)
          + (base_word & 0x0000010400040400)) & MASK64
    store_state = prepare_store64_state(image_base=frame.image_base, x0=frame.x0,
        x1=frame.x1, x4=frame.x4, x5=x5, x19=frame.x19, x20=frame.x20,
        x23=frame.x23, x28=frame.x28, x29=frame.x29)
    stores = []
    for _ in range(max_store_words):
        result = store_request_word(staged, store_state)
        stores.append(result)
        if result["next_handler_offset"] == STORE_OFFSET:
            continue
        if result["next_handler_offset"] != SUBDISPATCH_OFFSET:
            raise RefillUnsupported("store loop selected an unimplemented next boundary")
        break
    else:
        raise RefillUnsupported("store loop budget exhausted before sub-dispatch")
    subdispatch = subdispatch_request_word(staged, image_base=frame.image_base,
        x19=frame.x19, x29=frame.x29, x4=NORMAL_KEY, x5=x5)
    if subdispatch["next_handler_offset"] != 0x16A5A8:
        raise RefillUnsupported("request sub-dispatch did not select OR64")
    or_state = prepare_or64_state(image_base=frame.image_base,
        stream_slot_address=frame.x19, backing_address=frame.x28, x20=frame.x20,
        x22=frame.x22, x23=frame.x23, x24=frame.x24, x25=frame.x24 - 0x10,
        x29=frame.x29, x4=NORMAL_KEY, x5=x5, word_register=subdispatch["word"])
    or64 = apply_or64(staged, or_state)
    staged.commit()
    return {"dispatcher": first, "stores": stores, "subdispatch": subdispatch,
            "or64": or64, "next_handler": or64["next_handler"],
            "next_handler_offset": or64["next_handler_offset"]}


def movhi_request_word(pages, *, image_base, x19, x20, x22, x23, x28, x29, x30):
    """Execute the normal +0x16e158 op52 signed MOVhi transition."""
    values = (image_base, x19, x20, x22, x23, x28, x29, x30)
    if any(not isinstance(v, int) or not 0 <= v <= MASK64 for v in values):
        raise RefillUnsupported("MOVhi inputs must fit uint64")
    _guard(image_base, 0x008F128C, 0x000041041838AA94, 0x09B01E3C)
    staged = _PageTransaction(pages)
    writes = []

    def read(address, width):
        return int.from_bytes(_read_span(staged, address, width), "little")

    def write(address, value, width):
        _write_span(staged, address, value.to_bytes(width, "little"))
        writes.append((address, width))

    current = read(x19, 8)
    word = read(current, 4)
    if word & 0x3F != 52:
        raise RefillUnsupported("MOVhi word is not VM op52")
    immediate = ((word >> 16) & 0x1F) | ((word >> 21) & 0x3E0)
    immediate |= (((word >> 6) & 1) << 10) | ((word << 4) & 0x7800)
    immediate |= (word >> 6) & 0x8000
    dst = ((word >> 22) & 15) | (((word >> 11) & 1) << 4)
    value32 = immediate << 16
    value = (value32 - (1 << 32) if value32 & (1 << 31) else value32) & MASK64
    write(x23, dst, 4)
    write(x28 + dst * 8, value, 8)
    next_pointer = (current + 4) & MASK64
    next_word = read(next_pointer, 4)
    write(x19, next_pointer, 8)
    table_base = read(x20 + 0x8D8, 8)
    write(x30, immediate, 2)
    table_entry = (table_base + _dispatch_mask(image_base) + (next_word & 0x3F) * 8) & MASK64
    scratch_field = ((word >> 27) & 0x10) | ((word >> 12) & 15)
    return_key = read(x29 - 8, 8)
    encoded_target = read(table_entry, 8)
    write(x22, scratch_field, 4)
    target = (encoded_target - return_key) & MASK64
    staged.commit()
    return {"word_address": current, "word": word, "next_word": next_word,
        "immediate": immediate, "dst": dst, "value": value,
        "next_handler": target, "next_handler_offset": target - image_base,
        "register_updates": {"x8": target, "x9": word, "x10": scratch_field,
            "x11": immediate, "x12": return_key, "x13": dst, "x14": next_word,
            "x15": 0x01010104}, "writes": writes}
