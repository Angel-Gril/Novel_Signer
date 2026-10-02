"""Small, fail-closed VM9 allocator primitives.

This module models only the observed free-list pop.  It intentionally refuses
the zero-count slab/refill branch until that branch is independently modeled.
The input page map is a trusted local checkpoint (the same shape used by
``vm9_handoff_rule.py``), not an online request or a general heap.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, MutableMapping


class RefillUnsupported(RuntimeError):
    """The requested bin is empty and the slab/refill model is not complete."""


class BitmapExhausted(RefillUnsupported):
    """The captured slab bitmap has no set bit available for allocation."""


def _read(pages: Mapping[int, bytes | bytearray], address: int, size: int) -> bytes:
    page, offset = address >> 12, address & 0xFFF
    if offset + size > 0x1000:
        raise ValueError("allocator field crosses a page boundary")
    try:
        data = pages[page]
    except KeyError as exc:
        raise ValueError(f"missing checkpoint page {page:#x}") from exc
    return bytes(data[offset:offset + size])


def read_u32(pages: Mapping[int, bytes | bytearray], address: int) -> int:
    return int.from_bytes(_read(pages, address, 4), "little")


def read_u64(pages: Mapping[int, bytes | bytearray], address: int) -> int:
    return int.from_bytes(_read(pages, address, 8), "little")


def _write(pages: MutableMapping[int, bytearray], address: int, value: bytes) -> None:
    page, offset = address >> 12, address & 0xFFF
    if offset + len(value) > 0x1000:
        raise ValueError("allocator field crosses a page boundary")
    try:
        target = pages[page]
    except KeyError as exc:
        raise ValueError(f"missing checkpoint page {page:#x}") from exc
    target[offset:offset + len(value)] = value


def write_u32(pages: MutableMapping[int, bytearray], address: int, value: int) -> None:
    _write(pages, address, int(value & 0xFFFF_FFFF).to_bytes(4, "little"))


def write_u64(pages: MutableMapping[int, bytearray], address: int, value: int) -> None:
    _write(pages, address, int(value & 0xFFFF_FFFF_FFFF_FFFF).to_bytes(8, "little"))


@dataclass(frozen=True)
class FreeListPop:
    """Observed result of one non-empty size-class free-list pop."""

    bin_address: int
    count_before: int
    count_after: int
    list_address: int
    list_index: int
    object_address: int


@dataclass(frozen=True)
class BitmapSlotPop:
    """The directly observed one-word slab bitmap allocation step."""

    bitmap_before: int
    bitmap_after: int
    bit_index: int
    counter_before: int
    counter_after: int


@dataclass(frozen=True)
class SlabSlotPop:
    """One fully resolved bitmap/slab allocation from the native helper."""

    arena_address: int
    bin_address: int
    class_id: int
    slab_address: int
    metadata_address: int
    level_count: int
    selected_index: int
    bitmap_address: int
    bitmap_before: int
    bitmap_after: int
    counter_before: int
    counter_after: int
    object_stride: int
    object_address: int
    propagated_bitmap_updates: tuple[tuple[int, int, int], ...]


@dataclass(frozen=True)
class AllocatorConstants:
    """Runtime constants read by the observed ``0x1216970c`` helper."""

    metadata_table: int = 0x121D9120
    metadata_entry_stride: int = 0x60
    bitmap_mask_address: int = 0x121D9EC0
    region_offset_address: int = 0x121D9EA0
    page_bias_address: int = 0x121D9EB0
    reciprocal: int = 0xAAAA_AAAA_AAAA_AAAB


def pop_bitmap_slot(bitmap: int, counter: int) -> BitmapSlotPop:
    """Consume the lowest set bit used by the native refill path.

    The native code uses ``RBIT``/``CLZ`` to find ``ctz(bitmap)`` and then
    XORs that bit out.  It maintains the separate slab counter in parallel.
    This helper intentionally stops at the bitmap-word boundary: the slab
    address calculation and higher-level bitmap propagation remain unmodeled.
    """

    bitmap &= 0xFFFF_FFFF_FFFF_FFFF
    if bitmap == 0:
        raise BitmapExhausted("slab bitmap has no set bit")
    if counter <= 0:
        raise ValueError(f"invalid slab counter {counter}")
    bit_index = (bitmap & -bitmap).bit_length() - 1
    bitmap_after = bitmap ^ (1 << bit_index)
    return BitmapSlotPop(
        bitmap_before=bitmap,
        bitmap_after=bitmap_after,
        bit_index=bit_index,
        counter_before=counter,
        counter_after=counter - 1,
    )


def _ctz64(value: int) -> int:
    value &= 0xFFFF_FFFF_FFFF_FFFF
    if value == 0:
        raise BitmapExhausted("slab bitmap has no set bit")
    return (value & -value).bit_length() - 1


def _umulh64(left: int, right: int) -> int:
    """Return the unsigned high half of a 64-bit multiplication."""

    return ((left & 0xFFFF_FFFF_FFFF_FFFF) * (right & 0xFFFF_FFFF_FFFF_FFFF)) >> 64


def _class_metadata_address(class_id: int, constants: AllocatorConstants) -> int:
    if class_id < 0:
        raise ValueError("class_id must be non-negative")
    # The native code forms ``0x121d9120 + ((class_id * 3) << 5)``.
    return constants.metadata_table + class_id * constants.metadata_entry_stride


def _select_slab_index(
    pages: Mapping[int, bytes | bytearray],
    slab_address: int,
    class_id: int,
    metadata_address: int,
    constants: AllocatorConstants,
) -> tuple[int, int, int, int]:
    """Replay the native multi-level bitmap walk.

    The first table lookup chooses a bitmap word.  Each remaining level uses
    the preceding selected word as a 6-bit radix and a table-provided word
    offset.  The returned tuple is ``(slot_index, leaf_bitmap_address,
    level_count, first_word_index)``.
    """

    level_count = read_u32(pages, metadata_address + 0x30)
    if level_count <= 0 or level_count > 4:
        raise ValueError(f"unsupported bitmap level count {level_count}")
    table_base = constants.metadata_table
    class_word_base = class_id * 12
    # x17 = [table_base + (class_id*12 + (levels-1))*8 + 0x38]
    word_index = read_u64(
        pages,
        table_base + (class_word_base + level_count - 1) * 8 + 0x38,
    )
    bitmap_base = slab_address + 0x8
    bitmap_address = bitmap_base + word_index * 8
    bitmap = read_u64(pages, bitmap_address)
    selected_index = _ctz64(bitmap)

    remaining = level_count - 1
    while remaining:
        # x4 = [table_base + (class_id*12 + (remaining-1))*8 + 0x38]
        offset = read_u64(
            pages,
            table_base + (class_word_base + remaining - 1) * 8 + 0x38,
        )
        word_index = selected_index + offset
        bitmap_address = bitmap_base + word_index * 8
        bitmap = read_u64(pages, bitmap_address)
        selected_index = _ctz64(bitmap) + (selected_index << 6)
        remaining -= 1

    # Recompute the leaf address from the final slot index.  This is the
    # address cleared by the native XOR at 0x12169978.
    leaf_address = bitmap_base + (selected_index >> 6) * 8
    return selected_index, leaf_address, level_count, word_index


def pop_slab_slot(
    pages: MutableMapping[int, bytearray],
    *,
    arena_address: int,
    bin_address: int,
    class_id: int,
    slab_address: int,
    constants: AllocatorConstants = AllocatorConstants(),
) -> SlabSlotPop:
    """Replay the captured class-slab allocation path.

    This models the observed body of ``0x1216970c`` after the caller has
    already selected a slab record.  It includes the multi-level bitmap walk,
    zero-word propagation, slab counter decrement, and the native address
    formula.  Slab discovery, node allocation, and constructor/free history
    remain caller responsibilities.
    """

    metadata_address = _class_metadata_address(class_id, constants)
    counter_before = read_u32(pages, slab_address + 0x4)
    if counter_before <= 0:
        raise BitmapExhausted("slab counter is exhausted")

    selected_index, bitmap_address, level_count, _ = _select_slab_index(
        pages, slab_address, class_id, metadata_address, constants
    )
    bitmap_before = read_u64(pages, bitmap_address)
    bit_index = selected_index & 0x3F
    bitmap_after = bitmap_before ^ (1 << bit_index)
    write_u64(pages, bitmap_address, bitmap_after)
    counter_after = counter_before - 1
    write_u32(pages, slab_address + 0x4, counter_after)

    propagated: list[tuple[int, int, int]] = []
    bitmap_base = slab_address + 0x8
    if bitmap_after == 0:
        # The native helper clears parent summary bits only when a child word
        # becomes empty.  Offsets are stored at +0x40/+0x48/+0x50.
        for level, (shift, field_offset) in enumerate(
            ((12, 0x40), (18, 0x48), (24, 0x50)),
            start=1,
        ):
            if level >= level_count:
                break
            parent_word = (selected_index >> shift) + read_u64(
                pages, metadata_address + field_offset
            )
            parent_address = bitmap_base + parent_word * 8
            parent_before = read_u64(pages, parent_address)
            parent_bit = (selected_index >> (shift - 6)) & 0x3F
            parent_after = parent_before ^ (1 << parent_bit)
            write_u64(pages, parent_address, parent_after)
            propagated.append((parent_address, parent_before, parent_after))
            if parent_after != 0:
                break

    # Native address calculation at 0x12169a18..0x12169a74.
    slab_header = slab_address - 0x10
    align_mask = read_u64(pages, constants.bitmap_mask_address)
    region_offset = read_u64(pages, constants.region_offset_address)
    page_bias = read_u64(pages, constants.page_bias_address)
    aligned_base = slab_header & ~align_mask
    delta = (slab_header - region_offset) - aligned_base
    page_index = page_bias + (_umulh64(delta, constants.reciprocal) >> 6)
    object_stride = read_u64(pages, metadata_address + 0x10)
    base_offset = read_u64(pages, metadata_address + 0x58)
    object_address = aligned_base + base_offset + (page_index << 12) + selected_index * object_stride

    return SlabSlotPop(
        arena_address=arena_address,
        bin_address=bin_address,
        class_id=class_id,
        slab_address=slab_address,
        metadata_address=metadata_address,
        level_count=level_count,
        selected_index=selected_index,
        bitmap_address=bitmap_address,
        bitmap_before=bitmap_before,
        bitmap_after=bitmap_after,
        counter_before=counter_before,
        counter_after=counter_after,
        object_stride=object_stride,
        object_address=object_address,
        propagated_bitmap_updates=tuple(propagated),
    )


def pop_free_list(
    pages: Mapping[int, bytes | bytearray],
    bin_address: int,
    *,
    object_min: int = 0x10000,
    object_max: int = 1 << 64,
) -> FreeListPop:
    """Read the allocator branch used when ``bin.count != 0``.

    The native fast path reads ``[bin+0x30]``, decrements it, then selects
    ``[read64(bin+0x38) + (count_after * 8)]``.  A zero count is deliberately
    rejected because it enters the slab/bitmap refill path, which is not yet a
    fresh-input implementation.
    """

    count_before = read_u32(pages, bin_address + 0x30)
    if count_before == 0:
        slab_counter = read_u32(pages, 0x1294_110C)
        slab_bitmap = read_u64(pages, 0x1294_1128)
        raise RefillUnsupported(
            f"bin {bin_address:#x} is empty; refill remains unmodeled "
            f"(slab_counter={slab_counter:#x}, slab_bitmap={slab_bitmap:#x})"
        )
    list_address = read_u64(pages, bin_address + 0x38)
    count_after = count_before - 1
    object_address = read_u64(pages, list_address + count_after * 8)
    if not object_min <= object_address < object_max or object_address & 7:
        raise ValueError(f"unsupported allocator object pointer {object_address:#x}")
    return FreeListPop(
        bin_address=bin_address,
        count_before=count_before,
        count_after=count_after,
        list_address=list_address,
        list_index=count_after,
        object_address=object_address,
    )


def apply_free_list_pop(
    pages: MutableMapping[int, bytearray], bin_address: int
) -> FreeListPop:
    """Apply only the observed count decrement to a mutable checkpoint."""

    result = pop_free_list(pages, bin_address)
    write_u32(pages, bin_address + 0x30, result.count_after)
    return result
