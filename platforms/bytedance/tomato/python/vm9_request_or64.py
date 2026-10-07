"""Bounded fresh-input model of +0x16a5a8 (VM op17/sub44 OR64).

The native handler consumes x21, which +0x16855c loads before selection.
Stream memory is a separate input. This is not a Medusa signer.
"""
from __future__ import annotations

from dataclasses import dataclass

from vm9_allocator import RefillUnsupported, _PageTransaction, _read_span, _write_span

MASK64 = (1 << 64) - 1
HANDLER_OFFSET = 0x16A5A8
HANDLER_END = 0x16A614
BYTECODE_OP = 17
BYTECODE_SUB = 44


@dataclass(frozen=True)
class Or64State:
    image_base: int
    stream_slot_address: int
    backing_address: int
    x20: int
    x22: int
    x23: int
    x24: int
    x25: int
    x29: int
    x4: int
    x5: int
    word_register: int


def prepare_or64_state(**inputs) -> Or64State:
    state = Or64State(**inputs)
    if any(not isinstance(v, int) or not 0 <= v <= MASK64
           for v in vars(state).values()):
        raise RefillUnsupported("OR handler inputs must fit uint64")
    if state.word_register > 0xFFFFFFFF:
        raise RefillUnsupported("OR handler x21 must be a zero-extended word")
    return state


def apply_or64(pages, state: Or64State) -> dict:
    """Apply one native handler in instruction memory order.

    Source/destination slots, scratch fields, and the stream may alias. Reads
    occur at the same points as native loads. Unmapped inputs or another opcode
    fail before publication; no native stack or entry snapshot is imported.
    """
    word = state.word_register
    op, sub = word & 0x3F, (word >> 6) & 0x3F
    if (op, sub) != (BYTECODE_OP, BYTECODE_SUB):
        raise RefillUnsupported("word is not VM op17/sub44")
    staged = _PageTransaction(pages)
    writes = []

    def read(address, width):
        return int.from_bytes(_read_span(staged, address, width), "little")

    def write(address, value, width):
        _write_span(staged, address, value.to_bytes(width, "little"))
        writes.append((address, width))

    src_a = (word >> 22) & 0x1F
    src_b = word >> 27
    dst = (word >> 12) & 0x1F
    scratch_field = (word >> 17) & 0x1F
    word_address = read(state.stream_slot_address, 8)
    left = read(state.backing_address + src_a * 8, 8)
    write(state.x22, src_a, 4)
    right = read(state.backing_address + src_b * 8, 8)
    write(state.x23, src_b, 4)
    write(state.x24, dst, 4)
    result = (left | right) & MASK64
    write(state.backing_address + dst * 8, result, 8)
    next_pointer = (word_address + 4) & MASK64
    next_word = read(next_pointer, 4)
    write(state.stream_slot_address, next_pointer, 8)
    mask = (state.x5 | 0x01010104) ^ state.x4
    table_base = read(state.x20 + 0x8D8, 8)
    entry = (table_base + mask + (next_word & 0x3F) * 8) & MASK64
    return_key = read(state.x29 - 8, 8)
    encoded = read(entry, 8)
    target = (encoded - return_key) & MASK64
    write(state.x25, scratch_field, 4)
    staged.commit()
    return {
        "word_address": word_address, "word": word, "next_word": next_word,
        "src_a": src_a, "src_b": src_b, "dst": dst,
        "left": left, "right": right, "result": result,
        "next_pointer": next_pointer, "table_entry": entry,
        "encoded_target": encoded, "return_key": return_key,
        "next_handler": target, "next_handler_offset": target - state.image_base,
        "register_updates": {"x8": target, "x9": src_b, "x10": scratch_field,
                             "x11": return_key, "x12": dst, "x13": table_base},
        "writes": writes,
    }
