"""Input-driven decoder for the VM9 ``STORE64`` callback writer.

The native routine at ``+0x171268`` is the VM implementation of the bytecode
STORE64 operation.  It does not manufacture a callback pointer: it decodes one
32-bit VM word, reads two virtual-register slots, and writes one 64-bit value
at ``register[base_slot] + signed_immediate``.  This module exposes only that
instruction-level boundary.  It deliberately does not construct the owner
frame, callback object, or branch continuation.
"""
from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Sequence

from vm9_allocator import RefillUnsupported, _PageTransaction, _read_span, _write_span

MASK32 = 0xFFFF_FFFF
MASK64 = 0xFFFF_FFFF_FFFF_FFFF
STORE64_OPCODE = 26


@dataclass(frozen=True)
class Store64Fields:
    """Decoded fields of one VM STORE64 word."""

    word: int
    base_slot: int
    value_slot: int
    immediate: int


@dataclass(frozen=True)
class Store64Result:
    """The concrete memory effect of one parameterized STORE64."""

    fields: Store64Fields
    base_value: int
    value: int
    destination: int
    previous: int


def _signed16(value: int) -> int:
    value &= 0xFFFF
    return value - 0x1_0000 if value & 0x8000 else value


def decode_store64(word: int) -> Store64Fields:
    """Decode the exact field permutation used by native ``+0x171268``."""
    if not isinstance(word, int) or not 0 <= word <= MASK32:
        raise RefillUnsupported("VM word must be an unsigned 32-bit integer")
    if (word & 0x3F) != STORE64_OPCODE:
        raise RefillUnsupported("VM word is not STORE64")
    base_slot = ((word >> 22) & 0x0F) | ((word >> 27) & 0x10)
    value_slot = ((word >> 27) & 0x0F) | ((word >> 17) & 0x10)
    immediate = _signed16(
        ((word >> 16) & 0x1F)
        | (((word >> 11) & 0x1F) << 5)
        | (((word >> 6) & 0x1F) << 10)
        | (((word >> 26) & 0x01) << 15)
    )
    return Store64Fields(word, base_slot, value_slot, immediate)


def encode_store64(*, base_slot: int, value_slot: int, immediate: int) -> int:
    """Encode a STORE64 word for synthetic and regression controls.

    This encoder is only for tests and controlled VM inputs.  It does not
    choose any callback values or object addresses.
    """
    if not 0 <= base_slot < 32 or not 0 <= value_slot < 32:
        raise RefillUnsupported("STORE64 register slot must be in [0, 31]")
    if not -0x8000 <= immediate <= 0x7FFF:
        raise RefillUnsupported("STORE64 immediate must fit signed 16 bits")
    imm = immediate & 0xFFFF
    word = STORE64_OPCODE
    word |= (imm & 0x1F) << 16
    word |= ((imm >> 5) & 0x1F) << 11
    word |= ((imm >> 10) & 0x1F) << 6
    word |= ((imm >> 15) & 0x01) << 26
    word |= (base_slot & 0x0F) << 22
    word |= ((base_slot >> 4) & 0x01) << 27
    word |= (value_slot & 0x0F) << 27
    word |= ((value_slot >> 4) & 0x01) << 17
    return word & MASK32


def execute_store64(pages, *, word: int, virtual_registers: Sequence[int]) -> Store64Result:
    """Apply one STORE64 against an explicit guest page map and register file.

    Reads the destination before writing so missing pages fail without a guest
    mutation.  The source is a VM register value, never an executable pointer.
    """
    if not isinstance(virtual_registers, Sequence) or len(virtual_registers) != 32:
        raise RefillUnsupported("STORE64 needs exactly 32 virtual-register values")
    if any(not isinstance(value, int) or not 0 <= value <= MASK64 for value in virtual_registers):
        raise RefillUnsupported("virtual-register values must be unsigned 64-bit integers")
    fields = decode_store64(word)
    base_value = virtual_registers[fields.base_slot]
    value = virtual_registers[fields.value_slot]
    destination = (base_value + fields.immediate) & MASK64
    transaction = _PageTransaction(pages)
    previous = int.from_bytes(_read_span(transaction, destination, 8), "little")
    _write_span(transaction, destination, value.to_bytes(8, "little"))
    transaction.commit()
    return Store64Result(fields, base_value, value, destination, previous)


def execute_descriptor_store(
    pages,
    *,
    word: int,
    virtual_registers: Sequence[int],
    descriptor_address: int,
    field_offset: int,
) -> Store64Result:
    """Apply STORE64 only when its computed target is the requested descriptor field."""
    if not isinstance(descriptor_address, int) or descriptor_address <= 0:
        raise RefillUnsupported("descriptor address must be positive")
    if descriptor_address & 7:
        raise RefillUnsupported("descriptor address must be 8-byte aligned")
    if field_offset not in (0, 8):
        raise RefillUnsupported("descriptor field offset must be 0 or 8")
    result = execute_store64(pages, word=word, virtual_registers=virtual_registers)
    expected = (descriptor_address + field_offset) & MASK64
    if result.destination != expected:
        raise RefillUnsupported("STORE64 target is outside the requested descriptor field")
    return result
