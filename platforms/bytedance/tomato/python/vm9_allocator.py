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


@dataclass(frozen=True)
class FreeListPop:
    """Observed result of one non-empty size-class free-list pop."""

    bin_address: int
    count_before: int
    count_after: int
    list_address: int
    list_index: int
    object_address: int


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
