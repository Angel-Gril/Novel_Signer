"""Small, fail-closed VM9 allocator primitives.

This module models the observed small-object allocation/free fast paths,
existing-slab batch refill, and selection of an initialized slab from a
singleton available-node tree. It refuses general tree balancing and fresh
allocator initialization. The input page map has the same shape used by
``vm9_handoff_rule.py``; it is not an online request or a general heap.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, MutableMapping


class RefillUnsupported(RuntimeError):
    """The requested refill needs state outside the supported checkpoint model."""


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
class FreeListPush:
    """The ordinary small-object branch of native void ``free``."""

    thread_state_address: int
    object_address: int
    region_base: int
    region_entry_address: int
    region_entry: int
    class_id: int
    bin_address: int
    list_address: int
    count_before: int
    count_after: int
    capacity: int
    freed_bytes_before: int
    freed_bytes_after: int
    sweep_count_before: int
    sweep_count_after: int


@dataclass(frozen=True)
class SmallObjectAllocation:
    """A normal nonempty-bin allocation including native accounting."""

    request_size: int
    effective_size: int
    class_id: int
    class_width: int
    thread_state_address: int
    free_list: FreeListPop
    allocated_bytes_before: int
    allocated_bytes_after: int
    allocation_count_before: int
    allocation_count_after: int
    sweep_count_before: int
    sweep_count_after: int
    floor_before: int
    floor_after: int


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
class SlabRefillPop:
    """A captured empty-bin refill followed by the wrapper's first pop.

    The native pair is split between ``0x1216970c`` (publish a batch) and
    ``0x12187ecc`` (decrement the published count and return the last list
    entry).  This result keeps both counts so a checkpoint replay can be
    compared with the native write trace without confusing the two stages.
    """

    arena_address: int
    bin_address: int
    class_id: int
    slab_address: int
    list_address: int
    batch_size: int
    published_count: int
    count_after_pop: int
    returned_object: int
    object_addresses: tuple[int, ...]
    slab_pops: tuple[SlabSlotPop, ...]


@dataclass(frozen=True)
class AvailableSlabSelection:
    """Removal of the sole initialized node by native ``0x12165d44``."""

    class_control_address: int
    root_field_address: int
    sentinel_address: int
    node_address: int
    slab_address: int
    selection_count_before: int
    selection_count_after: int


@dataclass(frozen=True)
class AvailableSlabRefillPop:
    """Singleton-node selection followed by a captured batch refill/pop."""

    selection: AvailableSlabSelection
    refill: SlabRefillPop


@dataclass(frozen=True)
class AllocatorConstants:
    """Captured runtime constants used by the observed allocator branches."""

    metadata_table: int = 0x121D9120
    metadata_entry_stride: int = 0x60
    bitmap_mask_address: int = 0x121D9EC0
    region_offset_address: int = 0x121D9EA0
    page_bias_address: int = 0x121D9EB0
    reciprocal: int = 0xAAAA_AAAA_AAAA_AAAB
    region_page_limit_address: int = 0x121D9EC8
    class_table: int = 0x12196A80
    class_width_table: int = 0x12196C80
    free_capacity_table_pointer_address: int = 0x121D9F50
    free_hook_address: int = 0x121D69C0
    free_debug_flag_address: int = 0x121D69CA
    free_sweep_period: int = 0xE4
    malloc_initialization_flag_address: int = 0x121CB6A0
    malloc_debug_flag_address: int = 0x121D69A8
    malloc_fill_flag_address: int = 0x121D69C9


def allocate_small_object_fast(
    pages: MutableMapping[int, bytearray],
    *,
    thread_state_address: int,
    request_size: int,
    constants: AllocatorConstants = AllocatorConstants(),
) -> SmallObjectAllocation:
    """Replay the verified nonempty-bin malloc branch and its accounting.

    Native ``0x1217f00c`` treats zero size as one, looks up the class at
    ``class_table[(size-1)>>3]``, and enters ``0x1217f0e8``. This primitive
    requires an initialized normal thread state and a nonempty bin; refill,
    hooks, debug/fill flags, large objects, and periodic cleanup are rejected.
    It neither discovers TLS nor generates a fresh allocator.
    """

    if request_size < 0:
        raise ValueError("request_size must be non-negative")
    size = request_size or 1
    if size > 0x1000:
        raise RefillUnsupported("large-object allocation is not modeled")
    if read_u32(pages, constants.malloc_initialization_flag_address):
        raise RefillUnsupported("allocator initialization is pending")
    if read_u64(pages, constants.free_hook_address):
        raise RefillUnsupported("allocator hook is active")
    if read_u32(pages, thread_state_address + 8) != 1:
        raise RefillUnsupported("thread state is outside the captured normal malloc path")
    if read_u64(pages, thread_state_address + 0x30) == 0:
        raise RefillUnsupported("thread arena initialization is not modeled")
    if _read(pages, constants.malloc_debug_flag_address, 1) != b"\x00":
        raise RefillUnsupported("allocator debug malloc path is active")
    if _read(pages, constants.malloc_fill_flag_address, 1) != b"\x00":
        raise RefillUnsupported("allocator fill path is active")

    class_id = _read(pages, constants.class_table + ((size - 1) >> 3), 1)[0]
    width = read_u64(pages, constants.class_width_table + class_id * 8)
    bins = read_u64(pages, thread_state_address + 0x10)
    if bins < 0x10000 or bins & 7:
        raise RefillUnsupported("thread state has no captured bin table")
    bin_address = bins + class_id * 0x20
    if read_u32(pages, bin_address + 0x30) == 0:
        raise RefillUnsupported("empty malloc bin requires a separate refill path")
    result = pop_free_list(pages, bin_address)
    sweep_count = read_u32(pages, bins + 0x18)
    if sweep_count >= constants.free_sweep_period - 1:
        raise RefillUnsupported("malloc needs unmodeled periodic cleanup")
    floor_word = read_u32(pages, bin_address + 0x28)
    floor = floor_word if floor_word < 0x8000_0000 else floor_word - 0x1_0000_0000
    floor_after = min(result.count_after, floor)
    allocation_count = read_u64(pages, bin_address + 0x20)
    allocation_count_after = (allocation_count + 1) & 0xFFFF_FFFF_FFFF_FFFF
    allocated_bytes = read_u64(pages, thread_state_address + 0x18)
    allocated_bytes_after = (allocated_bytes + width) & 0xFFFF_FFFF_FFFF_FFFF

    write_u32(pages, bin_address + 0x30, result.count_after)
    if floor_after != floor:
        write_u32(pages, bin_address + 0x28, floor_after)
    write_u64(pages, bin_address + 0x20, allocation_count_after)
    write_u32(pages, bins + 0x18, sweep_count + 1)
    write_u64(pages, thread_state_address + 0x18, allocated_bytes_after)
    return SmallObjectAllocation(
        request_size=request_size,
        effective_size=size,
        class_id=class_id,
        class_width=width,
        thread_state_address=thread_state_address,
        free_list=result,
        allocated_bytes_before=allocated_bytes,
        allocated_bytes_after=allocated_bytes_after,
        allocation_count_before=allocation_count,
        allocation_count_after=allocation_count_after,
        sweep_count_before=sweep_count,
        sweep_count_after=sweep_count + 1,
        floor_before=floor,
        floor_after=floor_after,
    )


def publish_small_object_free(
    pages: MutableMapping[int, bytearray],
    *,
    thread_state_address: int,
    object_address: int,
    constants: AllocatorConstants = AllocatorConstants(),
) -> FreeListPush:
    """Replay the verified normal small-object free-list publication.

    The caller supplies a trusted initialized checkpoint and its thread state;
    TLS discovery and ownership of the object are outside this primitive. The
    class is derived from the object's region page metadata, not from an
    expected pointer or a supplied class. Hooks, debug paths, large objects,
    full bins, and periodic cleanup are rejected before writes. Native free is
    void; this result describes state changes rather than an ABI return value.
    """

    if object_address < 0x10000 or object_address & 7:
        raise ValueError(f"invalid small-object pointer {object_address:#x}")
    if read_u32(pages, thread_state_address + 8) != 1:
        raise RefillUnsupported("thread state is outside the captured normal free path")
    if read_u64(pages, constants.free_hook_address):
        raise RefillUnsupported("allocator free hook is active")
    if _read(pages, constants.free_debug_flag_address, 1) != b"\x00":
        raise RefillUnsupported("allocator debug free path is active")

    mask = read_u64(pages, constants.bitmap_mask_address)
    region_base = object_address & ~mask
    if object_address == region_base:
        raise RefillUnsupported("region-base objects do not use the small-object path")
    page_index = (object_address - region_base) >> 12
    page_bias = read_u64(pages, constants.page_bias_address)
    page_limit = read_u64(pages, constants.region_page_limit_address)
    if not page_bias <= page_index < page_limit:
        raise RefillUnsupported("object page is outside the captured small-object region")
    entry_address = region_base + (page_index - page_bias) * 8 + 0x68
    entry = read_u64(pages, entry_address)
    class_id = (entry >> 4) & 0xFF
    if (entry & 3) != 1 or class_id == 0xFF:
        raise RefillUnsupported("region page is not a normal small-object slab")

    bins = read_u64(pages, thread_state_address + 0x10)
    if bins < 0x10000 or bins & 7:
        raise RefillUnsupported("thread state has no captured bin table")
    bin_address = bins + class_id * 0x20
    count = read_u32(pages, bin_address + 0x30)
    capacity_table = read_u64(pages, constants.free_capacity_table_pointer_address)
    capacity = read_u32(pages, capacity_table + class_id * 4)
    if count >= capacity:
        raise RefillUnsupported("free-list bin needs an unmodeled flush")
    sweep_count = read_u32(pages, bins + 0x18)
    if sweep_count >= constants.free_sweep_period - 1:
        raise RefillUnsupported("free publication needs unmodeled periodic cleanup")
    list_address = read_u64(pages, bin_address + 0x38)
    if list_address < 0x10000 or list_address & 7:
        raise ValueError(f"invalid free list address {list_address:#x}")
    _read(pages, list_address + count * 8, 8)
    freed_bytes = read_u64(pages, thread_state_address + 0x20)
    width = read_u64(pages, constants.class_width_table + class_id * 8)
    freed_bytes_after = (freed_bytes + width) & 0xFFFF_FFFF_FFFF_FFFF

    # Exactly the four ordinary nonstack writes at 0x12181a38/ae0/aec/af8.
    write_u64(pages, thread_state_address + 0x20, freed_bytes_after)
    write_u64(pages, list_address + count * 8, object_address)
    write_u32(pages, bin_address + 0x30, count + 1)
    write_u32(pages, bins + 0x18, sweep_count + 1)
    return FreeListPush(
        thread_state_address=thread_state_address,
        object_address=object_address,
        region_base=region_base,
        region_entry_address=entry_address,
        region_entry=entry,
        class_id=class_id,
        bin_address=bin_address,
        list_address=list_address,
        count_before=count,
        count_after=count + 1,
        capacity=capacity,
        freed_bytes_before=freed_bytes,
        freed_bytes_after=freed_bytes_after,
        sweep_count_before=sweep_count,
        sweep_count_after=sweep_count + 1,
    )


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
    # LDR W8 zero-extends the 32-bit field; +0x5c is not part of it.
    base_offset = read_u32(pages, metadata_address + 0x58)
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


def _singleton_available_slab(
    pages: Mapping[int, bytes | bytearray], class_control_address: int
) -> AvailableSlabSelection:
    """Validate the observed tree shape before changing checkpoint memory."""

    root_field = class_control_address + 0x30
    sentinel = class_control_address + 0x38
    node = read_u64(pages, root_field)
    if node == sentinel:
        raise RefillUnsupported("available-node tree is empty; fresh slab creation is unsupported")
    if node < 0x10000 or node & 7:
        raise ValueError(f"invalid available-node pointer {node:#x}")
    # +8 also carries the red/black bit. Only the exact captured singleton
    # shape is supported: two sentinel children and no tagged right link.
    if read_u64(pages, node) != sentinel or read_u64(pages, node + 8) != sentinel:
        raise RefillUnsupported("available-node tree is not the captured singleton shape")
    if read_u64(pages, sentinel) != sentinel or read_u64(pages, sentinel + 8) != sentinel:
        raise RefillUnsupported("available-node sentinel differs from the captured shape")
    count = read_u64(pages, class_control_address + 0xD0)
    return AvailableSlabSelection(
        class_control_address=class_control_address,
        root_field_address=root_field,
        sentinel_address=sentinel,
        node_address=node,
        slab_address=node + 0x10,
        selection_count_before=count,
        selection_count_after=(count + 1) & 0xFFFF_FFFF_FFFF_FFFF,
    )


def select_singleton_available_slab(
    pages: MutableMapping[int, bytearray], *, class_control_address: int
) -> AvailableSlabSelection:
    """Replay the observed singleton branch of native ``0x12165d44``.

    The native helper follows left links to the lowest node, removes it with
    ``0x121657f4``, increments ``[control+0xd0]``, and returns ``node+0x10``.
    This implementation accepts only the verified singleton tree. It does
    not allocate or initialize the returned slab, or publish it as current.
    Empty and larger trees are rejected before any writes.
    """

    result = _singleton_available_slab(pages, class_control_address)
    write_u64(pages, result.root_field_address, result.sentinel_address)
    write_u64(pages, class_control_address + 0xD0, result.selection_count_after)
    return result


def refill_singleton_available_slab_and_pop(
    pages: MutableMapping[int, bytearray],
    *,
    arena_address: int,
    bin_address: int,
    class_id: int,
    batch_size: int,
    constants: AllocatorConstants = AllocatorConstants(),
) -> AvailableSlabRefillPop:
    """Replay the available-node branch, without creating a fresh slab.

    The current slab must be absent/exhausted, the target bin empty, and the
    available tree a captured singleton containing enough initialized slots
    for the entire batch. The caller still supplies the arena, bin, class,
    batch width, and trusted checkpoint. Tree rotations, slab creation, and
    refills crossing into another slab remain unsupported.
    """

    if class_id < 0 or batch_size <= 0:
        raise ValueError("class_id must be non-negative and batch_size positive")
    control = arena_address + class_id * 0xE0 + 0x508
    slab_slot = control + 0x28
    current_slab = read_u64(pages, slab_slot)
    if current_slab and read_u32(pages, current_slab + 4):
        raise RefillUnsupported("current slab still has slots; use the existing-slab path")
    if read_u32(pages, bin_address + 0x10):
        raise RefillUnsupported("target bin already has published entries")
    list_address = read_u64(pages, bin_address + 0x18)
    if list_address == 0 or list_address & 7:
        raise ValueError(f"invalid refill list address {list_address:#x}")
    selection = _singleton_available_slab(pages, control)
    slab = selection.slab_address
    if read_u32(pages, slab) != class_id:
        raise RefillUnsupported("available slab belongs to a different size class")
    if read_u32(pages, slab + 4) < batch_size:
        raise RefillUnsupported("batch would require another slab")
    # The native acquire helper clears the old current slot, selects an
    # already initialized node, then publishes its record before slot use.
    write_u64(pages, slab_slot, 0)
    selection = select_singleton_available_slab(pages, class_control_address=control)
    write_u64(pages, slab_slot, slab)
    refill = refill_existing_slab_and_pop(
        pages,
        arena_address=arena_address,
        bin_address=bin_address,
        class_id=class_id,
        slab_address=slab,
        batch_size=batch_size,
        constants=constants,
    )
    return AvailableSlabRefillPop(selection=selection, refill=refill)


def refill_existing_slab_and_pop(
    pages: MutableMapping[int, bytearray],
    *,
    arena_address: int,
    bin_address: int,
    class_id: int,
    slab_address: int,
    batch_size: int,
    constants: AllocatorConstants = AllocatorConstants(),
) -> SlabRefillPop:
    """Replay the observed existing-slab batch refill and wrapper pop.

    This is the captured ``0x1216970c`` + ``0x12187ecc`` pair.  The caller
    must provide an already selected slab record and a zero-count target bin;
    slab/node discovery, region allocation, constructor history, and fresh
    input state remain intentionally unsupported.
    """

    if batch_size <= 0:
        raise ValueError("batch_size must be positive")
    published_before = read_u32(pages, bin_address + 0x10)
    if published_before != 0:
        raise RefillUnsupported(
            f"target bin {bin_address:#x} already has published count "
            f"{published_before}; append/refill merge is not modeled"
        )
    list_address = read_u64(pages, bin_address + 0x18)
    if list_address == 0 or list_address & 7:
        raise ValueError(f"invalid refill list address {list_address:#x}")

    slab_pops: list[SlabSlotPop] = []
    # The native helper fills the list backwards.  The wrapper then decrements
    # the count and reads list[count-1], returning the first selected object.
    for index in range(batch_size):
        slab_pop = pop_slab_slot(
            pages,
            arena_address=arena_address,
            bin_address=bin_address,
            class_id=class_id,
            slab_address=slab_address,
            constants=constants,
        )
        write_u64(pages, list_address + (batch_size - 1 - index) * 8, slab_pop.object_address)
        slab_pops.append(slab_pop)

    active_bin_head = read_u64(pages, bin_address)
    # 0x1216983c clears the active-bin head and 0x12169844 publishes the
    # helper's batch count.  The wrapper at 0x12187ef0 then consumes one item.
    write_u64(pages, bin_address, 0)
    write_u32(pages, bin_address + 0x10, batch_size)

    class_state = arena_address + class_id * 0xE0
    write_u64(pages, class_state + 0x5A0, read_u64(pages, class_state + 0x5A0) + batch_size)
    write_u64(pages, class_state + 0x5B8, read_u64(pages, class_state + 0x5B8) + batch_size)
    write_u64(
        pages,
        class_state + 0x5B0,
        active_bin_head + read_u64(pages, class_state + 0x5B0),
    )
    write_u64(pages, class_state + 0x5C0, read_u64(pages, class_state + 0x5C0) + 1)

    count_after_pop = batch_size - 1
    write_u32(pages, bin_address + 0x10, count_after_pop)
    floor = read_u32(pages, bin_address + 0x8)
    floor_signed = floor if floor < 0x8000_0000 else floor - 0x1_0000_0000
    if count_after_pop < floor_signed:
        write_u32(pages, bin_address + 0x8, count_after_pop)
    returned_object = read_u64(pages, list_address + count_after_pop * 8)

    return SlabRefillPop(
        arena_address=arena_address,
        bin_address=bin_address,
        class_id=class_id,
        slab_address=slab_address,
        list_address=list_address,
        batch_size=batch_size,
        published_count=batch_size,
        count_after_pop=count_after_pop,
        returned_object=returned_object,
        object_addresses=tuple(item.object_address for item in slab_pops),
        slab_pops=tuple(slab_pops),
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
