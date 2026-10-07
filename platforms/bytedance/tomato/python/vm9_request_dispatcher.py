"""Bounded fresh-input model of request nested-VM dispatcher +0x16d7d0.

The native block decodes one 32-bit word at the current VM stream pointer,
updates the VM slot backing table and three scratch fields, then selects the
next native handler through the relocated dispatch table.  This module models
that one transition from explicit caller/frame inputs.  It does not claim the
following handler, complete Medusa, or signature generation.
"""
from __future__ import annotations

from dataclasses import dataclass

from vm9_allocator import RefillUnsupported, _read_span, _write_span

MASK64 = (1 << 64) - 1
DISPATCH_OFFSET = 0x16D7D0
NEXT_HANDLER_OFFSET = 0x171138
BYTECODE_OFFSET = 0x99020
DISPATCH_TABLE_OFFSET = 0x379000
DISPATCH_TABLE_SLOT_OFFSET = 0x8D8
RETURN_KEY = 0x33DC5
WORD = 0xFF7BDC0F


def _u16(value: int) -> int:
    return value & 0xFFFF


def _sx16(value: int) -> int:
    value &= 0xFFFF
    return value - 0x10000 if value & 0x8000 else value


@dataclass(frozen=True)
class RequestDispatchFrame:
    """Fresh frame addresses observed at +0x16d7d0's entry."""

    entry_stack_address: int
    image_base: int
    sp: int
    x0: int
    x1: int
    x2: int
    x3: int
    x4: int
    x8: int
    x19: int
    x20: int
    x22: int
    x23: int
    x24: int
    x28: int
    x29: int
    x30: int
    return_key: int = RETURN_KEY

    @property
    def bytecode_address(self) -> int:
        return self.image_base + BYTECODE_OFFSET

    @property
    def dispatch_table_address(self) -> int:
        return self.image_base + DISPATCH_TABLE_OFFSET


def prepare_request_dispatch_frame(*, entry_stack_address: int,
                                   image_base: int,
                                   return_key: int = RETURN_KEY
                                   ) -> RequestDispatchFrame:
    """Build the fresh nested-VM ABI frame from caller inputs.

    The offsets are derived from the +0x256ed4 caller and the generic VM
    prelude.  They are address formulas, not copied native stack bytes.
    ``return_key`` is the explicit VM frame key consumed by the dispatcher.
    """
    values = (entry_stack_address, image_base, return_key)
    if any(not isinstance(v, int) or not 0 <= v <= MASK64 for v in values):
        raise RefillUnsupported("dispatcher inputs must fit uint64")
    if entry_stack_address & 15:
        raise RefillUnsupported("dispatcher entry stack must be aligned")
    if return_key > MASK64:
        raise RefillUnsupported("dispatcher return key must fit uint64")
    return RequestDispatchFrame(
        entry_stack_address=entry_stack_address,
        image_base=image_base,
        sp=entry_stack_address - 0x530,
        x0=image_base + 0x257050,
        x1=entry_stack_address - 0x510,
        x2=image_base + 0x6E000,
        x3=image_base + 0x6E000,
        x4=0xFF5F9EBBF5FE033C,
        x8=entry_stack_address - 0x4A0,
        x19=entry_stack_address - 0x150,
        x20=image_base + DISPATCH_TABLE_OFFSET,
        x22=entry_stack_address - 0x4C0,
        x23=entry_stack_address - 0x4D0,
        x24=entry_stack_address - 0x4E0,
        x28=entry_stack_address - 0x148,
        x29=entry_stack_address - 0x410,
        x30=entry_stack_address - 0x500,
        return_key=return_key,
    )


def initialize_request_dispatch_scratch(pages, frame: RequestDispatchFrame) -> None:
    """Publish only the fresh VM fields needed by the dispatcher.

    This is the defined output of the generic VM prelude for this bounded
    transition.  Unwritten bytes retain the caller's fresh page fill.
    """
    p = frame
    # The VM caller already owns the backing slots at x28 == x19 + 8.
    # Only the stream pointer and the frame return key are published here.
    _write_span(pages, p.x19 + 0x00, p.bytecode_address.to_bytes(8, "little"))
    _write_span(pages, p.x29 - 8, p.return_key.to_bytes(8, "little"))


def dispatch_request_word(pages, frame: RequestDispatchFrame, *,
                          word_address: int | None = None,
                          require_known_word: bool = True) -> dict:
    """Execute one +0x16d7d0 transition and return its observable effects."""
    p = frame
    current = word_address if word_address is not None else int.from_bytes(
        _read_span(pages, p.x19, 8), "little")
    if current != p.bytecode_address:
        raise RefillUnsupported("dispatcher stream pointer is not the fresh VM entry")
    word = int.from_bytes(_read_span(pages, current, 4), "little")
    if require_known_word and word != WORD:
        raise RefillUnsupported("dispatcher word is outside the verified request sample")
    next_word = int.from_bytes(_read_span(pages, current + 4, 4), "little")

    # The first guard is an image-alignment discriminator.  Both verified
    # image bases take the normal +0x16d810 decode path.
    base_word = (p.image_base + 0x168324) & MASK64
    low = base_word & 0xFFFFFFFF
    guard = ((~(((low + 1) & 0xFFFFFFFF) & (~low & 0xFFFFFFFF)))
             & 0xFFFFFFFF)
    guard = (guard & 0x20420980) + 0x0003000058B907A5
    if guard < 0x4E031ED4:
        raise RefillUnsupported("dispatcher repair path is not independently recovered")

    high = (word >> 16) & 0xFFFF
    slot_index = ((word >> 22) & 0xF) | (((word >> 31) & 1) << 4)
    slot2_index = (word >> 17) & 0x1F
    encoded_disp = ((word >> 6) & 0x3FF) | (((word >> 26) & 0x3F) << 10)
    slot_base = p.x28 + slot_index * 8
    slot_value = int.from_bytes(_read_span(pages, slot_base, 8), "little")
    slot_result = (slot_value + _sx16(encoded_disp)) & MASK64
    _write_span(pages, p.x22, slot_index.to_bytes(4, "little"))
    _write_span(pages, p.x28 + slot2_index * 8,
                slot_result.to_bytes(8, "little"))
    _write_span(pages, p.x19, (current + 4).to_bytes(8, "little"))

    # Reconstruct the obfuscated dispatch-table byte address exactly as the
    # native block's mask/OR/XOR sequence does.
    mask_a = 0x0000010400040400
    mask_b = 0x00A060400A021040
    mask_c = 0x00A061440A061440
    x8 = (mask_b | (~base_word & MASK64)) & MASK64
    x8 &= mask_c
    x8 = (x8 + (base_word & mask_a)) & MASK64
    x8 = (x8 | 0x01010104) ^ 0xFF5F9EBBF5FE033C
    table_base = int.from_bytes(
        _read_span(pages, p.x20 + DISPATCH_TABLE_SLOT_OFFSET, 8), "little")
    table_index = next_word & 0x3F
    table_entry = (table_base + x8 + (table_index << 3)) & MASK64
    encoded_target = int.from_bytes(_read_span(pages, table_entry, 8), "little")
    next_handler = (encoded_target - p.return_key) & MASK64
    _write_span(pages, p.x23, slot2_index.to_bytes(4, "little"))
    _write_span(pages, p.x30, _u16(encoded_disp).to_bytes(2, "little"))
    return {
        "word_address": current,
        "word": word,
        "next_word": next_word,
        "slot_index": slot_index,
        "slot2_index": slot2_index,
        "encoded_displacement": encoded_disp,
        "signed_displacement": _sx16(encoded_disp),
        "table_index": table_index,
        "table_entry": table_entry,
        "encoded_target": encoded_target,
        "next_handler": next_handler,
        "next_handler_offset": next_handler - p.image_base,
    }
