"""Small, fail-closed VM9 allocator primitives.

This module models normal small-object allocation/free, empty-bin refill,
compact allocator trees, new slab initialization from mapped free extents,
periodic bin cleanup, and slab release/purge with an explicit guest OS result.
TLS generation checks, mapped base allocation, fresh TSD/arena/tcache creation
and an explicit guest OS region owner are also modeled. Global boot is split
into a state report and a bounded initialization contract; unknown boot fields
remain unsupported.
The input page map has the same shape used by
``vm9_handoff_rule.py``; it is not an online request or a general heap.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Callable, Mapping, MutableMapping
from collections.abc import MutableMapping as MutableMappingABC


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
    result = bytes(data[offset:offset + size])
    if len(result) != size:
        raise ValueError("truncated allocator checkpoint page")
    return result


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
    if len(target) != 0x1000:
        raise ValueError("truncated allocator checkpoint page")
    target[offset:offset + len(value)] = value


def write_u32(pages: MutableMapping[int, bytearray], address: int, value: int) -> None:
    _write(pages, address, int(value & 0xFFFF_FFFF).to_bytes(4, "little"))


def write_u64(pages: MutableMapping[int, bytearray], address: int, value: int) -> None:
    _write(pages, address, int(value & 0xFFFF_FFFF_FFFF_FFFF).to_bytes(8, "little"))


def _read_span(pages, address, length):
    """Read an explicitly bounded guest byte range, including page crossings."""
    if address < 0 or length < 0 or address + length > 1 << 64:
        raise ValueError("invalid guest byte range")
    result = bytearray()
    while length:
        width = min(length, 4096 - (address & 4095))
        result.extend(_read(pages, address, width))
        address += width
        length -= width
    return bytes(result)


def _write_span(pages, address, data):
    if address < 0 or address + len(data) > 1 << 64:
        raise ValueError("invalid guest byte range")
    offset = 0
    while offset < len(data):
        width = min(len(data) - offset, 4096 - (address & 4095))
        _write(pages, address, data[offset:offset + width])
        address += width
        offset += width


def pthread_getspecific(pages, *, key, thread_pointer, generation_table=0x121D0200):
    """Bionic's generation-checked lookup, including stale-value clearing."""
    key &= 0xFFFF_FFFF
    if _signed32(key) >= _signed32(0x8000008D):
        return 0
    transaction = _PageTransaction(pages)
    offset = (key & 0x7FFF_FFFF) * 16
    generation = int.from_bytes(_read_span(transaction, generation_table + offset, 8), 'little')
    pthread = int.from_bytes(_read_span(transaction, thread_pointer + 8, 8), 'little')
    slot = pthread + 0xE8 + offset
    if generation & 1 and int.from_bytes(_read_span(transaction, slot, 8), 'little') == generation:
        return int.from_bytes(_read_span(transaction, slot + 8, 8), 'little')
    _write_span(transaction, slot + 8, bytes(8))
    transaction.commit()
    return 0


def pthread_setspecific(pages, *, key, value, thread_pointer, generation_table=0x121D0200):
    """Publish generation/value atomically in the checkpoint model."""
    key &= 0xFFFF_FFFF
    if _signed32(key) >= _signed32(0x8000008D):
        return 22
    transaction = _PageTransaction(pages)
    offset = (key & 0x7FFF_FFFF) * 16
    generation = int.from_bytes(_read_span(transaction, generation_table + offset, 8), 'little')
    if not generation & 1:
        return 22
    pthread = int.from_bytes(_read_span(transaction, thread_pointer + 8, 8), 'little')
    slot = pthread + 0xE8 + offset
    _write_span(transaction, slot, generation.to_bytes(8, 'little'))
    _write_span(transaction, slot + 8, (value & ((1 << 64) - 1)).to_bytes(8, 'little'))
    transaction.commit()
    return 0


def pthread_key_clean_all(pages, *, thread_pointer, generation_table, invoke):
    """Matching bionic's serialized +0x685a0 TSD destructor phase.

    Scan 141 keys in ascending order for up to four passes. An active key
    needs a matching generation, nonzero value and destructor. Clear value
    before invocation; callbacks may republish it for a later pass. Inactive
    and stale slots are retained, unlike pthread_getspecific. No OS thread
    termination or concurrent generation mutation is implied.
    """
    for address in (thread_pointer,generation_table):
        if not isinstance(address,int) or address<0 or address&7:
            raise RefillUnsupported('invalid pthread key-cleanup address')
    transaction=_PageTransaction(pages)
    pthread=int.from_bytes(_read_span(transaction,thread_pointer+8,8),'little')
    slots=pthread+0xe8;calls=[]
    _read_span(transaction,generation_table,141*16)
    _read_span(transaction,slots,141*16)
    for iteration in range(4):
        invoked=0
        for index in range(141):
            entry=generation_table+index*16;slot=slots+index*16
            generation=int.from_bytes(_read_span(transaction,entry,8),'little')
            if not generation&1:continue
            saved=int.from_bytes(_read_span(transaction,slot,8),'little')
            if saved!=generation:continue
            value=int.from_bytes(_read_span(transaction,slot+8,8),'little')
            if not value:continue
            destructor=int.from_bytes(_read_span(transaction,entry+8,8),'little')
            if not destructor:continue
            if int.from_bytes(_read_span(transaction,entry,8),'little')!=saved:continue
            _write_span(transaction,slot+8,bytes(8))
            invoke(transaction,destructor,value)
            calls.append((iteration,index,destructor,value));invoked+=1
        if not invoked:break
    transaction.commit();return tuple(calls)


def pthread_key_create(pages, *, key_address, destructor, generation_table):
    """Model matching bionic's serialized generation-table key allocation.

    Scan 141 entries for an even/free generation, increment that generation,
    store the destructor, then publish index|0x80000000 as a u32 key. Return
    0 or EAGAIN=11. No actual host key, atomicity or destructor execution is
    supplied. Unsupported pages/ABI inputs roll back guest pages.
    """
    if (not isinstance(generation_table, int) or generation_table < 0 or generation_table & 7
            or not isinstance(key_address, int) or not 0 <= key_address < 1 << 64
            or not isinstance(destructor, int) or not 0 <= destructor < 1 << 64):
        raise RefillUnsupported("invalid pthread key-create ABI input")
    transaction = _PageTransaction(pages)
    for index in range(141):
        entry = generation_table + index * 16
        generation = int.from_bytes(_read_span(transaction, entry, 8), "little")
        if generation & 1:
            continue
        _write_span(transaction, entry, ((generation + 1) & ((1 << 64) - 1)).to_bytes(8, "little"))
        _write_span(transaction, entry + 8, destructor.to_bytes(8, "little"))
        _write_span(transaction, key_address, (index | 0x80000000).to_bytes(4, "little"))
        transaction.commit()
        return 0
    return 11


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
    class_count_address: int = 0x121D9F48
    # Explicit guest OS outcome, not a default fake success. None rejects any
    # slab release which reaches madvise; native differential probes supply
    # the observed result for their isolated guest runtime.
    purge_madvise_result: int | None = None
    guest_errno_address: int | None = None


@dataclass(frozen=True)
class GuestMapping:
    """One guest mapping owned by :class:`GuestOS`."""

    base: int
    length: int
    prot: int
    flags: int
    fd: int
    offset: int
    anonymous_name: bytes = b""

    @property
    def end(self) -> int:
        return self.base + self.length


class GuestOS:
    """Deterministic owner for bounded guest anonymous mapping operations.

    New pages are created only through this owner. Unsupported requests are
    rejected before the caller's page map or mapping list is changed.
    """

    def __init__(
        self,
        pages: MutableMapping[int, bytearray],
        *,
        next_address: int = 0x1360_0000,
        address_limit: int = 0x1400_0000,
    ):
        self.pages = pages
        self.next_address = next_address
        self.address_limit = address_limit
        self.mappings: list[GuestMapping] = []

    def begin(self):
        return _GuestOSTransaction(self)

    def map_anonymous(
        self,
        length: int,
        *,
        address: int | None = None,
        prot: int = 3,
        flags: int = 0x22,
        fd: int = -1,
        offset: int = 0,
        anonymous_name: bytes = b"vm9-region",
    ) -> GuestMapping:
        transaction = self.begin()
        result = transaction.map_anonymous(
            length,
            address=address,
            prot=prot,
            flags=flags,
            fd=fd,
            offset=offset,
            anonymous_name=anonymous_name,
        )
        transaction.commit()
        return result

    def unmap_exact(self, address: int, length: int) -> None:
        """Release one complete owned guest mapping; never touch host memory."""
        transaction = self.begin()
        transaction.unmap_exact(address, length)
        transaction.commit()

    def unmap_range(self, address: int, length: int) -> None:
        """Trim page-aligned bytes within one owned mapping atomically."""
        transaction = self.begin()
        transaction.unmap_range(address, length)
        transaction.commit()

    def name_exact(self, address: int, length: int, name: bytes) -> None:
        """Name a complete owned mapping; never infer success for an OS call."""
        transaction = self.begin()
        transaction.name_exact(address, length, name)
        transaction.commit()

    def protect_exact(self, address: int, length: int, prot: int) -> None:
        """Update whole-mapping protection metadata.

        The byte-page helpers do not enforce this metadata on each access.
        A CPU provider must apply the corresponding hardware permissions.
        """
        transaction = self.begin()
        transaction.protect_exact(address, length, prot)
        transaction.commit()

    def mapping_for(self, address: int) -> GuestMapping | None:
        return next((item for item in self.mappings if item.base <= address < item.end), None)


class _GuestOSTransaction:
    """Copy-on-write mapping transaction for atomic OS/allocator setup."""

    def __init__(self, owner: GuestOS):
        self.owner = owner
        self.pages = {key: bytearray(value) for key, value in owner.pages.items()}
        self.mappings = list(owner.mappings)
        self.next_address = owner.next_address

    @staticmethod
    def _validate_name(value: bytes) -> bytes:
        if not isinstance(value, (bytes, bytearray)) or len(value) > 255:
            raise RefillUnsupported("anonymous VMA name is not supported")
        if b"\x00" in value:
            raise RefillUnsupported("anonymous VMA name must be NUL-free")
        return bytes(value)

    def map_anonymous(
        self,
        length: int,
        *,
        address: int | None,
        prot: int,
        flags: int,
        fd: int,
        offset: int,
        anonymous_name: bytes,
    ) -> GuestMapping:
        if length <= 0 or length & 0xFFF or length > 0x100000:
            raise RefillUnsupported("unsupported guest mmap length")
        if prot != 3 or flags != 0x22 or fd not in (-1, 0xFFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF) or offset:
            raise RefillUnsupported("unsupported guest mmap request")
        name = self._validate_name(anonymous_name)
        base = self.next_address if address is None else address
        if base & 0xFFF or base < 0x1360_0000 or base + length > self.owner.address_limit:
            raise RefillUnsupported("guest mapping is outside the isolated address policy")
        if any(base < item.end and item.base < base + length for item in self.mappings):
            raise RefillUnsupported("guest mapping overlaps an existing region")
        page_keys = range(base >> 12, (base + length) >> 12)
        if any(key in self.pages for key in page_keys):
            raise RefillUnsupported("guest mapping would overwrite an existing page")
        for key in page_keys:
            self.pages[key] = bytearray(0x1000)
        result = GuestMapping(base, length, prot, flags, fd, offset, name)
        self.mappings.append(result)
        self.next_address = base + length
        return result

    def unmap_exact(self, address: int, length: int) -> None:
        """Bounded whole-mapping release used by the guest thread exit path."""
        mapping = next((item for item in self.mappings
            if item.base == address and item.length == length), None)
        if mapping is None:
            raise RefillUnsupported("guest munmap requires a complete owned mapping")
        keys = tuple(range(address >> 12, (address + length) >> 12))
        if any(key not in self.pages for key in keys):
            raise RefillUnsupported("owned guest mapping contains missing pages")
        for key in keys:
            del self.pages[key]
        self.mappings.remove(mapping)

    def _owned_span(self, address: int, length: int, *, exact: bool) -> GuestMapping:
        if (not isinstance(address, int) or not isinstance(length, int)
                or address < 0 or length <= 0 or (address | length) & 0xFFF
                or address + length > 1 << 64):
            raise RefillUnsupported("invalid owned guest mapping span")
        mapping = next((item for item in self.mappings
            if item.base <= address and address + length <= item.end), None)
        if mapping is None or (exact and (mapping.base != address or mapping.length != length)):
            raise RefillUnsupported("operation requires one owned guest mapping")
        if any(key not in self.pages or len(self.pages[key]) != 0x1000
                for key in range(mapping.base >> 12, mapping.end >> 12)):
            raise RefillUnsupported("owned guest mapping contains missing or truncated pages")
        return mapping

    def unmap_range(self, address: int, length: int) -> None:
        mapping = self._owned_span(address, length, exact=False)
        remaining = []
        if address > mapping.base:
            remaining.append(replace(mapping, length=address - mapping.base))
        if address + length < mapping.end:
            remaining.append(replace(mapping, base=address + length,
                                     length=mapping.end - address - length))
        index = self.mappings.index(mapping)
        self.mappings[index:index + 1] = remaining
        for key in range(address >> 12, (address + length) >> 12):
            del self.pages[key]

    def name_exact(self, address: int, length: int, name: bytes) -> None:
        mapping = self._owned_span(address, length, exact=True)
        name = self._validate_name(name)
        self.mappings[self.mappings.index(mapping)] = replace(mapping, anonymous_name=name)

    def protect_exact(self, address: int, length: int, prot: int) -> None:
        mapping = self._owned_span(address, length, exact=True)
        if prot not in (1, 3):
            raise RefillUnsupported("unsupported guest mapping protection")
        self.mappings[self.mappings.index(mapping)] = replace(mapping, prot=prot)

    def commit(self) -> None:
        original = self.owner.pages
        for key in list(original):
            if key not in self.pages:
                del original[key]
        for key, value in self.pages.items():
            if key in original:
                original[key][:] = value
            else:
                original[key] = bytearray(value)
        self.owner.mappings = list(self.mappings)
        self.owner.next_address = self.next_address


@dataclass(frozen=True)
class GlobalBootState:
    """Observed global allocator state, kept separate from captured bytes."""

    initialization_flag: int
    arena_count: int
    arena_capacity: int
    arena_zero: int
    arena_table: int
    tls_key: int
    tls_generation: int
    base_tree_root: int
    base_tree_sentinel: int
    cache_enabled: int

    @property
    def ready(self) -> bool:
        return (
            self.initialization_flag == 0
            and self.arena_count > 0
            and self.arena_count <= self.arena_capacity
            and self.arena_zero != 0
            and self.arena_table != 0
            and self.tls_generation & 1 == 1
        )


@dataclass(frozen=True)
class GlobalBootConfig:
    """Only globals whose initialization contract is independently known."""

    arena_zero: int
    arena_table: int
    arena_count: int = 1
    arena_capacity: int = 1
    cache_enabled: int = 1
    generation_table: int = 0x121D0200
    tls_key: int | None = None


@dataclass(frozen=True)
class GlobalBootComponent:
    symbol: str
    status: str
    owner: str
    boundary: str


GLOBAL_BOOT_COMPONENTS = (
    GlobalBootComponent("je_base_boot", "captured-input", "base_allocate", "base tree/table boot"),
    GlobalBootComponent("je_chunk_boot", "partial", "GuestOS/register_os_region", "chunk hooks and lookup cache"),
    GlobalBootComponent("je_tcache_boot", "captured-input", "create_tcache", "capacity table boot"),
    GlobalBootComponent("je_arena_boot", "partial", "create_arena", "global arena table publication"),
    GlobalBootComponent("je_malloc_tsd_boot0", "partial", "initialize_thread_state", "TLS key generation"),
    GlobalBootComponent("je_malloc_tsd_boot1", "partial", "prepare_thread_allocator", "state transition and cache"),
    GlobalBootComponent("je_mutex_boot", "captured-input", "_require_unlocked_mutex", "mutex attributes/init"),
    GlobalBootComponent("je_ctl_boot", "captured-input", "read_global_boot_state", "control tree/config tables"),
)


def global_boot_inventory() -> tuple[GlobalBootComponent, ...]:
    """Return the explicit boot ownership boundary used by this module."""
    return GLOBAL_BOOT_COMPONENTS


def read_global_boot_state(pages, *, generation_table: int = 0x121D0200) -> GlobalBootState:
    """Read global boot without inferring missing native initialization."""
    key_pointer = read_u64(pages, 0x121C8F98)
    key = read_u32(pages, key_pointer)
    generation = read_u64(pages, generation_table + (key & 0x7FFF_FFFF) * 16)
    root = 0x121D67E8
    return GlobalBootState(
        initialization_flag=read_u32(pages, 0x121CB6A0),
        arena_count=read_u32(pages, 0x121D6970),
        arena_capacity=read_u32(pages, 0x121D6960),
        arena_zero=read_u64(pages, 0x121D6968),
        arena_table=read_u64(pages, 0x121D69D0),
        tls_key=key,
        tls_generation=generation,
        base_tree_root=read_u64(pages, root),
        base_tree_sentinel=read_u64(pages, root + 8),
        cache_enabled=read_u32(pages, 0x121CB6B0),
    )


def initialize_global_boot(pages, *, config: GlobalBootConfig) -> GlobalBootState:
    """Publish the bounded global fields required by fresh TLS.

    Arena construction, mutex boot, lookup-cache generation and callback
    tables remain outside this contract and must be supplied separately.
    """
    transaction = _PageTransaction(pages)
    if not 1 <= config.arena_count <= config.arena_capacity <= 4095:
        raise RefillUnsupported("unsupported global arena count")
    if config.arena_zero == 0 or config.arena_table < 0x10000 or config.arena_table & 7:
        raise RefillUnsupported("global boot requires an explicit arena table")
    key_pointer = read_u64(transaction, 0x121C8F98)
    key = read_u32(transaction, key_pointer) if config.tls_key is None else config.tls_key
    generation = read_u64(transaction, config.generation_table + (key & 0x7FFF_FFFF) * 16)
    if not generation & 1:
        raise RefillUnsupported("global boot TLS key is inactive")
    _read_span(transaction, config.arena_table, 8 * config.arena_count)
    write_u64(transaction, config.arena_table, config.arena_zero)
    write_u64(transaction, 0x121D6968, config.arena_zero)
    write_u32(transaction, 0x121D6960, config.arena_capacity)
    write_u32(transaction, 0x121D6970, config.arena_count)
    write_u64(transaction, 0x121D69D0, config.arena_table)
    write_u32(transaction, 0x121CB6B0, config.cache_enabled)
    write_u32(transaction, 0x121CB6A0, 0)
    transaction.commit()
    return read_global_boot_state(pages, generation_table=config.generation_table)


class _PageTransaction(MutableMappingABC):
    """Stage touched pages so unsupported lifecycle branches leave no writes."""

    def __init__(self, pages):
        self.original = pages
        self.staged = {}

    def __getitem__(self, key):
        if key not in self.staged:
            self.staged[key] = bytearray(self.original[key])
        return self.staged[key]

    def __setitem__(self, key, value):
        if key not in self.original:
            raise RefillUnsupported("OS page mapping is not modeled")
        self.staged[key] = bytearray(value)

    def __delitem__(self, key):
        raise RefillUnsupported("OS page unmapping is not modeled")

    def __iter__(self):
        return iter(self.original)

    def __len__(self):
        return len(self.original)

    def commit(self):
        self.original.update(self.staged)


class _AllocatorTree:
    """Compact 2-3 LLRB links used by the observed allocator.

    Balance operations follow jemalloc 3.6.0 rb.h (BSD-2-Clause; see
    jemalloc-BSD-2-Clause.txt), checked against native trees.
    The right link's bit zero is the node color; the sentinel is root+8.
    """

    def __init__(self, pages, root: int, key: Callable[[int], object], *, link_offset: int = 0):
        self.pages, self.root, self.key = pages, root, key
        self.link_offset = link_offset
        self.nil = root + 8
        if self.left(self.nil) != self.nil or self.right(self.nil) != self.nil or self.red(self.nil):
            raise RefillUnsupported("invalid allocator tree sentinel")

    def left(self, node):
        return read_u64(self.pages, node + self.link_offset)

    def right(self, node):
        return read_u64(self.pages, node + self.link_offset + 8) & ~1

    def red(self, node):
        return bool(read_u64(self.pages, node + self.link_offset + 8) & 1)

    def set_left(self, node, left):
        write_u64(self.pages, node + self.link_offset, left)

    def set_right(self, node, right):
        write_u64(self.pages, node + self.link_offset + 8, right | int(self.red(node)))

    def color(self, node, red):
        write_u64(self.pages, node + self.link_offset + 8, self.right(node) | int(red))

    def rotate_left(self, node):
        other = self.right(node)
        self.set_right(node, self.left(other))
        self.set_left(other, node)
        return other

    def rotate_right(self, node):
        other = self.left(node)
        self.set_left(node, self.right(other))
        self.set_right(other, node)
        return other

    def first(self):
        node = read_u64(self.pages, self.root)
        for _ in range(128):
            if node == self.nil:
                return 0
            left = self.left(node)
            if left == self.nil:
                return node
            node = left
        raise RefillUnsupported("allocator tree is cyclic or too deep")

    def lower_bound(self, key):
        node = read_u64(self.pages, self.root)
        found = 0
        for _ in range(128):
            if node == self.nil:
                return found
            if self.key(node) < key:
                node = self.right(node)
            else:
                found, node = node, self.left(node)
        raise RefillUnsupported("allocator tree is cyclic or too deep")

    def insert(self, node):
        path = []
        current = read_u64(self.pages, self.root)
        key = self.key(node)
        while current != self.nil:
            if len(path) >= 128:
                raise RefillUnsupported("allocator tree is cyclic or too deep")
            other = self.key(current)
            if key == other:
                raise RefillUnsupported("duplicate allocator tree key")
            left = key < other
            path.append((current, left))
            current = self.left(current) if left else self.right(current)
        self.set_left(node, self.nil)
        write_u64(self.pages, node + self.link_offset + 8, self.nil | 1)
        child = node
        for current, left in reversed(path):
            if left:
                self.set_left(current, child)
                if not self.red(child):
                    return
                ll = self.left(child)
                if self.red(ll):
                    self.color(ll, False)
                    current = self.rotate_right(current)
            else:
                self.set_right(current, child)
                if not self.red(child):
                    return
                other = self.left(current)
                if self.red(other):
                    self.color(other, False)
                    self.color(child, False)
                    self.color(current, True)
                else:
                    red = self.red(current)
                    other = self.rotate_left(current)
                    self.color(other, red)
                    self.color(current, True)
                    current = other
            child = current
        write_u64(self.pages, self.root, child)
        self.color(child, False)

    def remove(self, node):
        # Keep the exact removed node's stale links: rebuilding an equivalent
        # tree would lose memory effects used by subsequent native operations.
        path, directions = [], []
        current = read_u64(self.pages, self.root)
        key = self.key(node)
        while current != self.nil:
            if len(path) >= 128:
                raise RefillUnsupported("allocator tree is cyclic or too deep")
            path.append(current)
            other = self.key(current)
            if key == other:
                if current != node:
                    raise RefillUnsupported("allocator tree key aliases another node")
                node_index = len(path) - 1
                directions.append(False)
                current = self.right(current)
                while current != self.nil:
                    if len(path) >= 128:
                        raise RefillUnsupported("allocator tree is cyclic or too deep")
                    path.append(current)
                    directions.append(True)
                    current = self.left(current)
                break
            left = key < other
            directions.append(left)
            current = self.left(current) if left else self.right(current)
        else:
            raise RefillUnsupported("allocator tree does not contain requested node")
        index = len(path) - 1
        if path[index] != node:
            successor = path[index]
            red = self.red(successor)
            self.color(successor, self.red(node))
            self.set_left(successor, self.left(node))
            self.set_right(successor, self.right(node))
            self.color(node, red)
            path[node_index], path[index] = successor, node
            self._replace(path, directions, node_index, successor)
        else:
            left = self.left(node)
            if left != self.nil:
                self.color(left, False)
                self._replace(path, directions, index, left)
                return
            if index == 0:
                write_u64(self.pages, self.root, self.nil)
                return
        if self.red(path[index]):
            self.set_left(path[index - 1], self.nil)
            return
        path[index] = self.nil
        for i in range(index - 1, -1, -1):
            current = path[i]
            if directions[i]:
                self.set_left(current, path[i + 1])
                right = self.right(current)
                rl = self.left(right)
                if self.red(current):
                    if self.red(rl):
                        self.color(current, False)
                        self.set_right(current, self.rotate_right(right))
                    other = self.rotate_left(current)
                    self._replace(path, directions, i, other)
                    return
                if self.red(rl):
                    self.color(rl, False)
                    self.set_right(current, self.rotate_right(right))
                    other = self.rotate_left(current)
                    self._replace(path, directions, i, other)
                    return
                self.color(current, True)
                path[i] = self.rotate_left(current)
            else:
                self.set_right(current, path[i + 1])
                left = self.left(current)
                if self.red(left):
                    lr = self.right(left)
                    lrl = self.left(lr)
                    if self.red(lrl):
                        self.color(lrl, False)
                        other = self.rotate_right(current)
                        self.set_right(other, self.rotate_right(current))
                        other = self.rotate_left(other)
                    else:
                        self.color(lr, True)
                        other = self.rotate_right(current)
                        self.color(other, False)
                    self._replace(path, directions, i, other)
                    return
                ll = self.left(left)
                if self.red(current):
                    self.color(left, True)
                    self.color(current, False)
                    if self.red(ll):
                        self.color(ll, False)
                        other = self.rotate_right(current)
                        self._replace(path, directions, i, other)
                    return
                if self.red(ll):
                    self.color(ll, False)
                    other = self.rotate_right(current)
                    self._replace(path, directions, i, other)
                    return
                self.color(left, True)
        write_u64(self.pages, self.root, path[0])

    def _replace(self, path, directions, index, node):
        if index == 0:
            write_u64(self.pages, self.root, node)
        elif directions[index - 1]:
            self.set_left(path[index - 1], node)
        else:
            self.set_right(path[index - 1], node)


def _new_allocator_tree(pages, root, link_offset=0):
    nil = root + 8
    write_u64(pages, root, nil)
    write_u64(pages, nil + link_offset, nil)
    write_u64(pages, nil + link_offset + 8, nil & ~1)


def _require_unlocked_mutex(pages, address):
    if int.from_bytes(_read_span(pages, address, 2), 'little'):
        raise RefillUnsupported("contended or non-normal mutex is not modeled")


def _round_small_size(pages, size, constants):
    if not 1 <= size <= 0x3800:
        raise RefillUnsupported("only normal small size classes are modeled")
    if size <= 4096:
        class_id = _read(pages, constants.class_table + ((size - 1) >> 3), 1)[0]
    else:
        quantum = 1 << ((2 * size - 1).bit_length() - 4)
        width = (size + quantum - 1) & -quantum
        widths = [read_u64(pages, constants.class_width_table + i * 8) for i in range(36)]
        try:
            class_id = widths.index(width)
        except ValueError as exc:
            raise RefillUnsupported("unsupported small class table") from exc
    return class_id, read_u64(pages, constants.class_width_table + class_id * 8)


def _base_allocate(pages, request_size, constants):
    if not 1 <= request_size <= (1 << 63) - 64:
        raise RefillUnsupported("invalid or oversized base allocation")
    length = (request_size + 63) & ~63
    if length <= 4096:
        _, normalized = _round_small_size(pages, length, constants)
    else:
        quantum = 1 << ((2 * length - 1).bit_length() - 4)
        normalized = (length + quantum - 1) & -quantum
    _require_unlocked_mutex(pages, 0x121D6860)
    tree = _AllocatorTree(pages, 0x121D67E8,
                          lambda node: (read_u64(pages, node + 0x10), read_u64(pages, node + 8)),
                          link_offset=0x48)
    node = tree.lower_bound((normalized, 0))
    if not node:
        raise RefillUnsupported("base allocation needs a new OS mapping")
    pointer = read_u64(pages, node + 8)
    size = read_u64(pages, node + 0x10)
    # Prove the result exists in guest memory before mutating its owner tree.
    _read_span(pages, pointer, length)
    tree.remove(node)
    if size > length:
        write_u64(pages, node + 8, pointer + length)
        write_u64(pages, node + 0x10, size - length)
        tree.insert(node)
    else:
        write_u64(pages, node, read_u64(pages, 0x121D6858))
        write_u64(pages, 0x121D6858, node)
    write_u64(pages, 0x121D67D0, read_u64(pages, 0x121D67D0) + length)
    resident = ((pointer + length + 4095) & ~4095) - ((pointer + 4095) & ~4095)
    write_u64(pages, 0x121D67D8, read_u64(pages, 0x121D67D8) + resident)
    return pointer


def base_allocate(pages, *, request_size, constants=AllocatorConstants()):
    """Allocate from mapped base extents; preserve payload and padding bytes."""
    transaction = _PageTransaction(pages)
    result = _base_allocate(transaction, request_size, constants)
    transaction.commit()
    return result


def _create_arena(pages, arena_index, constants):
    large_count = read_u32(pages, 0x121D9EB8)
    huge_count = read_u32(pages, 0x121D9110)
    length = 0x24C0 + ((huge_count + 15 + large_count * 32) & ~15) * 24
    if length > 0x100000:
        raise RefillUnsupported("arena configuration exceeds the supported bound")
    arena = _base_allocate(pages, length, constants)
    write_u32(pages, arena, arena_index)
    write_u32(pages, arena + 4, 0)
    for offset in (8, 0x1D0, 0x498, 0x4C8):
        _write_span(pages, arena + offset, bytes(40))
    _write_span(pages, arena + 0x30, bytes(0x78))
    large_stats = arena + 0x24C0
    huge_stats = large_stats + large_count * 32
    write_u64(pages, arena + 0x98, large_stats)
    write_u64(pages, arena + 0xA0, huge_stats)
    _write_span(pages, large_stats, bytes(large_count * 32))
    _write_span(pages, huge_stats, bytes(huge_count * 24))
    write_u64(pages, arena + 0xA8, 0)
    _require_unlocked_mutex(pages, 0x121D6898)
    write_u32(pages, arena + 0xC0, read_u32(pages, 0x121CB690))
    write_u64(pages, arena + 0xC8, 0)
    write_u64(pages, arena + 0xD0, read_u64(pages, 0x121D67C8))
    write_u64(pages, arena + 0xD8, 0)
    write_u64(pages, arena + 0xE0, 0)
    _new_allocator_tree(pages, arena + 0xE8)
    for offset in (0x150,):
        write_u64(pages, arena + offset, arena + offset)
        write_u64(pages, arena + offset + 8, arena + offset)
    write_u64(pages, arena + 0x198, arena + 0x160)
    write_u64(pages, arena + 0x1A0, arena + 0x160)
    write_u64(pages, arena + 0x1C8, 0)
    for offset in (0x1F8, 0x2D8, 0x3B8):
        _new_allocator_tree(pages, arena + offset, 0x48)
    for offset in (0x268, 0x348, 0x428):
        _new_allocator_tree(pages, arena + offset, 0x58)
    write_u64(pages, arena + 0x4C0, 0)
    for destination, source in ((0x4F0, 0x121C8F30), (0x4F8, 0x121C8F90), (0x500, 0x121C8E98)):
        write_u64(pages, arena + destination, read_u64(pages, source))
    for class_id in range(36):
        control = arena + 0x508 + class_id * 0xE0
        _write_span(pages, control, bytes(40))
        write_u64(pages, control + 0x28, 0)
        _new_allocator_tree(pages, control + 0x30)
        _write_span(pages, control + 0x98, bytes(0x48))
    return arena


def create_arena(pages, *, arena_index, constants=AllocatorConstants()):
    """Construct a new arena from boot configuration, without copying an arena."""
    transaction = _PageTransaction(pages)
    result = _create_arena(transaction, arena_index & 0xFFFF_FFFF, constants)
    transaction.commit()
    return result


def _allocate_arena_small(pages, arena, request_size, zero, constants):
    class_id, width = _round_small_size(pages, request_size, constants)
    control = arena + 0x508 + class_id * 0xE0
    _require_unlocked_mutex(pages, control)
    junk_flag = read_u64(pages, 0x121C8ED8)
    if _read(pages, junk_flag, 1)[0]:
        raise RefillUnsupported("arena junk-fill allocation is not modeled")
    slab = read_u64(pages, control + 0x28)
    if not slab or not read_u32(pages, slab + 4):
        slab = _acquire_slab(pages, arena, class_id, constants)
    if read_u32(pages, slab) != class_id:
        raise RefillUnsupported("current arena slab class mismatch")
    result = pop_slab_slot(pages, arena_address=arena, bin_address=control,
                           class_id=class_id, slab_address=slab, constants=constants)
    pointer = result.object_address
    _read_span(pages, pointer, width)
    for offset in (0x98, 0xA8, 0xB0):
        write_u64(pages, control + offset, read_u64(pages, control + offset) + 1)
    fill_zero = _read(pages, read_u64(pages, 0x121C8EF0), 1)[0]
    if zero or fill_zero:
        _write_span(pages, pointer, bytes(width))
    return pointer, width


def allocate_arena_small(pages, *, arena_address, request_size, zero=False, constants=AllocatorConstants()):
    """Direct small allocation, without an already initialized thread cache."""
    transaction = _PageTransaction(pages)
    result, _ = _allocate_arena_small(transaction, arena_address, request_size, bool(zero), constants)
    transaction.commit()
    return result


def _associate_tcache(pages, tcache, arena):
    _require_unlocked_mutex(pages, arena + 8)
    write_u64(pages, tcache, tcache)
    write_u64(pages, tcache + 8, tcache)
    head = read_u64(pages, arena + 0xA8)
    if head:
        tail = read_u64(pages, head + 8)
        if not tail or read_u64(pages, tail) != head:
            raise RefillUnsupported("invalid arena tcache list")
        write_u64(pages, tcache + 8, tail)
        write_u64(pages, tcache, head)
        write_u64(pages, tail, tcache)
        write_u64(pages, head + 8, tcache)
    write_u64(pages, arena + 0xA8, head or tcache)


def _create_tcache(pages, arena, constants):
    count = read_u64(pages, constants.class_count_address)
    slots = read_u32(pages, 0x121D6A9C)
    if not 1 <= count <= 45 or slots > 0x10000:
        raise RefillUnsupported("unsupported tcache configuration")
    list_offset = (count * 32 + 0x27) & 0xFFFF_FFF8
    capacity_table = read_u64(pages, constants.free_capacity_table_pointer_address)
    capacities = [read_u32(pages, capacity_table + i * 4) for i in range(count)]
    if sum(capacities) > slots:
        raise RefillUnsupported("tcache lists exceed configured storage")
    length = (list_offset + slots * 8 + 63) & ~63
    allocation_arena = read_u64(pages, 0x121D6968)
    if not allocation_arena:
        raise RefillUnsupported("arena zero is not initialized")
    pointer, width = _allocate_arena_small(pages, allocation_arena, length, True, constants)
    write_u64(pages, allocation_arena + 0x58, read_u64(pages, allocation_arena + 0x58) + width)
    _associate_tcache(pages, pointer, arena)
    for i, capacity in enumerate(capacities):
        write_u32(pages, pointer + i * 32 + 0x2C, 1)
        write_u64(pages, pointer + i * 32 + 0x38, pointer + list_offset)
        list_offset += capacity * 8
    return pointer


def create_tcache(pages, *, arena_address, constants=AllocatorConstants()):
    """Generate cache storage and all configured bins, including large bins.

    Creating their empty lists does not add support for large malloc/free.
    The backing allocation uses arena zero; association uses arena_address.
    """
    transaction = _PageTransaction(pages)
    result = _create_tcache(transaction, arena_address, constants)
    transaction.commit()
    return result


def _malloc_tls_key(pages):
    return read_u32(pages, read_u64(pages, 0x121C8F98))


def _initialize_thread_state(pages, thread_pointer, constants):
    key = _malloc_tls_key(pages)
    current = pthread_getspecific(pages, key=key, thread_pointer=thread_pointer)
    if current:
        return current
    guard = read_u64(pages, 0x121C8DF8)
    _require_unlocked_mutex(pages, guard + 8)
    if read_u64(pages, guard):
        raise RefillUnsupported("recursive or concurrent TSD initialization is not modeled")
    if read_u32(pages, constants.malloc_initialization_flag_address) != 0:
        raise RefillUnsupported("malloc global boot is not initialized")
    arena = read_u64(pages, 0x121D6968)
    if not arena:
        raise RefillUnsupported("arena zero is not initialized")
    pointer, width = _allocate_arena_small(pages, arena, 0x80, False, constants)
    write_u64(pages, arena + 0x58, read_u64(pages, arena + 0x58) + width)
    _write_span(pages, pointer, bytes(1))
    write_u32(pages, pointer + 8, 0)
    for offset in (0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x50):
        write_u64(pages, pointer + offset, 0)
    write_u32(pages, pointer + 0x40, 0)
    _write_span(pages, pointer + 0x44, bytes(1))
    write_u32(pages, pointer + 0x48, 2)
    if pthread_setspecific(pages, key=key, value=pointer, thread_pointer=thread_pointer):
        raise RefillUnsupported("malloc TLS key is inactive")
    return pointer


def initialize_thread_state(pages, *, thread_pointer, constants=AllocatorConstants()):
    """Generate and publish a fresh state-0 TSD; preserve native padding.

    This boundary precedes the state-0 to state-1 transition, arena selection
    and tcache creation. It requires an initialized global boot and arena zero.
    """
    transaction = _PageTransaction(pages)
    result = _initialize_thread_state(transaction, thread_pointer, constants)
    transaction.commit()
    return result


def _choose_thread_arena(pages, thread, constants):
    _require_unlocked_mutex(pages, 0x121D6980)
    count = read_u32(pages, 0x121D6970)
    capacity = read_u32(pages, 0x121D6960)
    table = read_u64(pages, 0x121D69D0)
    if not 1 <= count <= 4095 or count > capacity:
        raise RefillUnsupported("unsupported arena table configuration")
    first = read_u64(pages, table)
    if not first:
        raise RefillUnsupported("arena zero is absent from its table")
    selected = first
    threads = read_u32(pages, first + 4)
    first_empty = count
    if count > 1:
        for index in range(1, count):
            arena = read_u64(pages, table + index * 8)
            if not arena:
                if first_empty == count:
                    first_empty = index
            else:
                other = read_u32(pages, arena + 4)
                if other < threads:
                    selected, threads = arena, other
        if threads and first_empty < count:
            selected = _create_arena(pages, first_empty, constants)
            write_u64(pages, table + first_empty * 8, selected)
            threads = read_u32(pages, selected + 4)
    write_u32(pages, selected + 4, threads + 1)
    if read_u32(pages, thread + 8) == 1:
        write_u64(pages, thread + 0x30, selected)
    # The single-arena branch returns a0 independently from table[0].
    return read_u64(pages, 0x121D6968) if count <= 1 else selected


def choose_thread_arena(pages, *, thread_state_address, constants=AllocatorConstants()):
    """Choose the least occupied arena, constructing the first empty slot."""
    transaction = _PageTransaction(pages)
    result = _choose_thread_arena(transaction, thread_state_address, constants)
    transaction.commit()
    return result


def prepare_thread_allocator(pages, *, thread_pointer, constants=AllocatorConstants()):
    """Fresh TLS -> TSD -> arena -> cache, stopping before user allocation.

    Global boot tables and mapped arena-zero extents remain inputs. A fresh
    arena has no OS region yet; its first refill can still reject without
    writes. Recursive TSD states, disabled caches and OS mappings are rejected.
    """
    transaction = _PageTransaction(pages)
    thread = _initialize_thread_state(transaction, thread_pointer, constants)
    state = read_u32(transaction, thread + 8)
    if state not in (0, 1):
        raise RefillUnsupported("recursive TSD state transition is not modeled")
    if state == 0:
        write_u32(transaction, thread + 8, 1)
        if read_u64(transaction, 0x121C8F38) != read_u64(transaction, 0x121C8E30):
            _write_span(transaction, thread, bytes([1]))
    cache = read_u64(transaction, thread + 0x10)
    if not cache:
        enabled = read_u32(transaction, thread + 0x48)
        if enabled == 2:
            enabled = _read(transaction, 0x121CB6B0, 1)[0]
            write_u32(transaction, thread + 0x48, enabled)
        if not enabled:
            raise RefillUnsupported("disabled thread cache is not modeled")
        arena = read_u64(transaction, thread + 0x30)
        if not arena:
            arena = _choose_thread_arena(transaction, thread, constants)
        cache = _create_tcache(transaction, arena, constants)
        write_u64(transaction, thread + 0x10, cache)
    transaction.commit()
    return thread


@dataclass(frozen=True)
class RegionRegistration:
    """Fresh anonymous region registered in an arena available tree."""

    arena_address: int
    region_base: int
    region_length: int
    first_free_page: int
    free_page_count: int
    free_node: int
    mapping: GuestMapping


def _register_os_region(
    pages,
    os_transaction: _GuestOSTransaction,
    *,
    arena_address: int,
    base: int | None,
    length: int,
    constants: AllocatorConstants,
    anonymous_name: bytes,
):
    """Implement chunk registration after the guest mapping is staged."""
    page_limit = read_u64(pages, constants.region_page_limit_address)
    page_bias = read_u64(pages, constants.page_bias_address)
    region_offset = read_u64(pages, constants.region_offset_address)
    bitmap_mask = read_u64(pages, constants.bitmap_mask_address)
    if page_limit < 4 or page_bias >= page_limit or region_offset < 0x20:
        raise RefillUnsupported("invalid region geometry")
    if length != page_limit * 0x1000 or length & 0xFFF:
        raise RefillUnsupported("guest region length does not match allocator geometry")
    if bitmap_mask != length - 1:
        raise RefillUnsupported("region mask does not match guest mapping length")
    if arena_address < 0x10000 or arena_address & 7:
        raise RefillUnsupported("invalid arena address")
    _require_unlocked_mutex(pages, arena_address + 8)

    mapping = os_transaction.map_anonymous(
        length,
        address=base,
        prot=3,
        flags=0x22,
        fd=-1,
        offset=0,
        anonymous_name=anonymous_name,
    )
    region = mapping.base
    # The native chunk header is four scalar fields; the remaining bytes are
    # zero from mmap and must stay zero until a slab consumes pages.
    write_u64(pages, region, arena_address)
    write_u64(pages, region + 8, region)
    write_u64(pages, region + 0x10, length)
    _write(pages, region + 0x18, b"\x01")
    _write(pages, region + 0x19, b"\x01")

    first_page = page_bias
    free_pages = page_limit - page_bias
    free_size = free_pages * 0x1000
    first_entry = region + 0x68
    last_entry = first_entry + (free_pages - 1) * 8
    # 0xff0 is the clean free-extent marker. The region reserves the pages
    # before ``page_bias`` for its header and slab metadata.
    write_u64(pages, first_entry, free_size | 0xFF0)
    write_u64(pages, last_entry, free_size | 0xFF0)

    root = arena_address + 0xE8
    # The extent node occupies the first 0x10 bytes of the descriptor at
    # ``region + region_offset``; the slab payload starts at ``node + 0x10``.
    node = region + region_offset
    tree = _AllocatorTree(pages, root, lambda item: (free_size, item))
    tree.insert(node)
    write_u64(pages, arena_address + 0x30, length)
    write_u64(pages, arena_address + 0x50, 0x2000)
    return RegionRegistration(
        arena_address=arena_address,
        region_base=region,
        region_length=length,
        first_free_page=first_page,
        free_page_count=free_pages,
        free_node=node,
        mapping=mapping,
    )


def register_os_region(
    pages: MutableMapping[int, bytearray],
    *,
    arena_address: int,
    guest_os: GuestOS,
    base: int | None = None,
    length: int = 0x40000,
    anonymous_name: bytes = b"vm9-region",
    constants: AllocatorConstants = AllocatorConstants(),
) -> RegionRegistration:
    """Map and register one fresh anonymous allocator region atomically."""
    if guest_os.pages is not pages:
        raise ValueError("guest_os must own the supplied page map")
    transaction = guest_os.begin()
    result = _register_os_region(
        transaction.pages,
        transaction,
        arena_address=arena_address,
        base=base,
        length=length,
        constants=constants,
        anonymous_name=anonymous_name,
    )
    transaction.commit()
    return result


def initialize_slab_bitmap(pages, *, bitmap_address: int, descriptor_address: int) -> int:
    """Execute the descriptor-derived initialization of native 0x1216dd70."""

    bits = read_u64(pages, descriptor_address)
    levels = read_u32(pages, descriptor_address + 8)
    if not 1 <= levels <= 4 or bits == 0:
        raise RefillUnsupported("unsupported bitmap initialization descriptor")
    offsets = [read_u64(pages, descriptor_address + (i + 2) * 8) for i in range(levels + 1)]
    if offsets[0] != 0 or offsets[1] != (bits + 63) // 64:
        raise RefillUnsupported("invalid bitmap leaf descriptor")
    for i in range(1, levels):
        child_words = offsets[i] - offsets[i - 1]
        if offsets[i + 1] - offsets[i] != (child_words + 63) // 64:
            raise RefillUnsupported("invalid bitmap summary descriptor")
    # Validate every target before the first write.
    for i in range(offsets[-1]):
        _read(pages, bitmap_address + i * 8, 8)
    for i in range(offsets[-1]):
        write_u64(pages, bitmap_address + i * 8, 0xFFFF_FFFF_FFFF_FFFF)
    shift = (-bits) & 63
    if shift:
        write_u64(pages, bitmap_address + (offsets[1] - 1) * 8, (1 << (64 - shift)) - 1)
    for i in range(2, levels + 1):
        shift = (offsets[i - 2] - offsets[i - 1]) & 63
        if shift:
            write_u64(pages, bitmap_address + (offsets[i] - 1) * 8, (1 << (64 - shift)) - 1)
    return offsets[-1]


def _slab_page(pages, slab, constants):
    node = slab - 0x10
    region = node & ~read_u64(pages, constants.bitmap_mask_address)
    delta = node - region - read_u64(pages, constants.region_offset_address)
    if delta < 0 or delta % 0x60:
        raise RefillUnsupported("invalid slab record placement")
    return region, read_u64(pages, constants.page_bias_address) + delta // 0x60


def _extent_size(pages, node, constants):
    region, page = _slab_page(pages, node + 0x10, constants)
    bias = read_u64(pages, constants.page_bias_address)
    return read_u64(pages, region + 0x68 + (page - bias) * 8) & ~0xFFF


def _normalize_extent(pages, size):
    """Native 0x121661e0 for observed page-aligned region extents."""
    limit = read_u64(pages, 0x121D67C0)
    table = read_u64(pages, 0x121D67B8)
    if size <= limit and _read(pages, table + (size >> 12), 1)[0]:
        return size
    if size < 0x1000 or size & 0xFFF or size >= 1 << 62:
        raise RefillUnsupported("extent normalization outside the mapped page domain")
    # 0x12166290..b8 computes the preceding size-class table index.
    lg = ((size + 1) * 2 - 1).bit_length() - 1
    index = ((lg - 6) << 2) + ((size >> (lg - 3)) & 3)
    widths = read_u64(pages, 0x121C8EE0)
    value = read_u64(pages, widths + index * 8)
    if value <= 0x3800:
        raise RefillUnsupported("unobserved small extent normalization loop")
    return value


def _free_extent_tree(pages, arena, constants):
    return _AllocatorTree(pages, arena + 0xE8,
                          lambda node: (_normalize_extent(pages, _extent_size(pages, node, constants)), node))


def _initialize_slab_from_extent(pages, arena, class_id, constants):
    metadata = _class_metadata_address(class_id, constants)
    size = read_u64(pages, metadata + 0x18)
    if size == 0 or size & 0xFFF:
        raise RefillUnsupported("unsupported slab extent size")
    normalized = _normalize_extent(pages, size)
    if normalized < size:
        # 0x1216779c rounds its search to the next supported page class.
        normalized = 0xFFFF_FFFF_FFFF_FFFF
        if size > 0x3800:
            lg = (size * 2 - 1).bit_length() - 1
            index = 4 * lg - 0x17 + (((size - 1) >> (lg - 3)) & 3)
            widths = read_u64(pages, 0x121C8EE0)
            normalized = (read_u64(pages, widths + (index + 1) * 8) + 4095) & ~4095
        if size < read_u64(pages, 0x121D67C0):
            table = read_u64(pages, 0x121D67B8)
            for page in range(size // 4096 + 1, read_u64(pages, constants.region_page_limit_address) + 1):
                if _read(pages, table + page, 1)[0]:
                    normalized = min(normalized, page << 12)
                    break
    tree = _free_extent_tree(pages, arena, constants)
    node = tree.lower_bound((normalized, 0))
    if not node:
        raise RefillUnsupported("fresh region mapping / arena initialization is not modeled")
    extent_size = _extent_size(pages, node, constants)
    if extent_size < size:
        raise RefillUnsupported("selected extent is shorter than slab")
    slab = node + 0x10
    region, page = _slab_page(pages, slab, constants)
    if read_u64(pages, region) != arena:
        raise RefillUnsupported("extent belongs to another arena")
    bias = read_u64(pages, constants.page_bias_address)
    entry = region + 0x68 + (page - bias) * 8
    if read_u64(pages, entry) & 8:
        raise RefillUnsupported("dirty extent cleanup is not modeled")
    tree.remove(node)
    used_pages = read_u64(pages, arena + 0xD8)
    mask = read_u64(pages, constants.bitmap_mask_address)
    region_delta = ((mask + ((used_pages + size // 4096) << 12)) & ~mask) - ((mask + (used_pages << 12)) & ~mask)
    if region_delta:
        global_bytes = read_u64(pages, 0x121C8E38)
        write_u64(pages, global_bytes, read_u64(pages, global_bytes) + region_delta)
    write_u64(pages, arena + 0xD8, used_pages + size // 4096)
    remaining = extent_size - size
    if remaining:
        remainder_page = page + size // 4096
        tail_page = page + extent_size // 4096 - 1
        for index in (remainder_page, tail_page):
            address = region + 0x68 + (index - bias) * 8
            write_u64(pages, address, (read_u64(pages, address) & 4) | 0xFF0 | remaining)
        remainder_node = region + read_u64(pages, constants.region_offset_address) + (remainder_page - bias) * 0x60
        tree.insert(remainder_node)
    for offset in range(size // 4096):
        address = entry + offset * 8
        write_u64(pages, address, (read_u64(pages, address) & 4) | 1 | (class_id << 4) | (offset << 12))
    write_u32(pages, slab, class_id)
    write_u32(pages, slab + 4, read_u32(pages, metadata + 0x20))
    initialize_slab_bitmap(pages, bitmap_address=slab + 8, descriptor_address=metadata + 0x28)
    control = arena + class_id * 0xE0 + 0x508
    for offset in (0xC8, 0xD8):
        write_u64(pages, control + offset, read_u64(pages, control + offset) + 1)
    return slab


def _acquire_slab(pages, arena, class_id, constants):
    control = arena + class_id * 0xE0 + 0x508
    write_u64(pages, control + 0x28, 0)
    tree = _AllocatorTree(pages, control + 0x30, lambda node: node)
    node = tree.first()
    if node:
        tree.remove(node)
        write_u64(pages, control + 0xD0, read_u64(pages, control + 0xD0) + 1)
        slab = node + 0x10
        if read_u32(pages, slab) != class_id:
            raise RefillUnsupported("available slab class mismatch")
    else:
        slab = _initialize_slab_from_extent(pages, arena, class_id, constants)
    write_u64(pages, control + 0x28, slab)
    return slab


def _refill_empty_bin(pages, arena, caller_bin, class_id, constants):
    target = caller_bin + 0x20
    table = read_u64(pages, constants.free_capacity_table_pointer_address)
    batch = read_u32(pages, table + class_id * 4) >> (read_u32(pages, target + 0xC) & 31)
    if batch == 0:
        raise RefillUnsupported("zero refill batch is outside supported normal bins")
    list_address = read_u64(pages, target + 0x18)
    control = arena + class_id * 0xE0 + 0x508
    for i in range(batch):
        _read(pages, list_address + i * 8, 8)
    for i in range(batch):
        slab = read_u64(pages, control + 0x28)
        if not slab or not read_u32(pages, slab + 4):
            slab = _acquire_slab(pages, arena, class_id, constants)
        result = pop_slab_slot(pages, arena_address=arena, bin_address=target,
                               class_id=class_id, slab_address=slab, constants=constants)
        write_u64(pages, list_address + (batch - i - 1) * 8, result.object_address)
    state = arena + class_id * 0xE0
    write_u64(pages, state + 0x5A0, read_u64(pages, state + 0x5A0) + batch)
    write_u64(pages, state + 0x5B8, read_u64(pages, state + 0x5B8) + batch)
    write_u64(pages, state + 0x5B0, read_u64(pages, state + 0x5B0) + read_u64(pages, target))
    write_u64(pages, state + 0x5C0, read_u64(pages, state + 0x5C0) + 1)
    write_u64(pages, target, 0)
    write_u32(pages, target + 0x10, batch)
    result = pop_free_list(pages, caller_bin)
    write_u32(pages, caller_bin + 0x30, result.count_after)
    floor = _signed32(read_u32(pages, caller_bin + 0x28))
    if result.count_after < floor:
        write_u32(pages, caller_bin + 0x28, result.count_after)
    return result


def _signed32(value):
    return value if value < 0x8000_0000 else value - 0x1_0000_0000


def _region_node(pages, region, page, constants):
    return region + read_u64(pages, constants.region_offset_address) + (page - read_u64(pages, constants.page_bias_address)) * 0x60


def _account_extent_pages(pages, arena, delta, constants):
    before = read_u64(pages, arena + 0xD8)
    after = before + delta
    if after < 0:
        raise RefillUnsupported("invalid arena page accounting")
    mask = read_u64(pages, constants.bitmap_mask_address)
    region_delta = ((mask + (after << 12)) & ~mask) - ((mask + (before << 12)) & ~mask)
    if region_delta:
        address = read_u64(pages, 0x121C8E38)
        write_u64(pages, address, read_u64(pages, address) + region_delta)
    write_u64(pages, arena + 0xD8, after)


def _unlink_dirty_extent(pages, arena, node, count):
    pointer = node + 0x10
    following = read_u64(pages, pointer)
    previous = read_u64(pages, pointer + 8)
    write_u64(pages, previous, following)
    write_u64(pages, following + 8, previous)
    write_u64(pages, pointer, pointer)
    write_u64(pages, pointer + 8, pointer)
    dirty = read_u64(pages, arena + 0xE0)
    if dirty < count:
        raise RefillUnsupported("invalid dirty extent accounting")
    write_u64(pages, arena + 0xE0, dirty - count)


def _release_extent(pages, arena, slab, mark_dirty, force_clean, constants):
    region, page = _slab_page(pages, slab, constants)
    bias = read_u64(pages, constants.page_bias_address)
    def address(index):
        return region + 0x68 + (index - bias) * 8
    entry = read_u64(pages, address(page))
    if entry & 2:
        size = entry & ~0xFFF
    else:
        size = read_u64(pages, _class_metadata_address(read_u32(pages, slab), constants) + 0x18)
    count = size >> 12
    if not count:
        raise RefillUnsupported("zero extent release")
    _account_extent_pages(pages, arena, -count, constants)
    dirty = mark_dirty or (not force_clean and bool(entry & 8))
    flags = 0xFF8 if dirty else 0xFF0
    for index in (page, page + count - 1):
        a = address(index)
        write_u64(pages, a, (read_u64(pages, a) & 4) | flags | size)
    tree = _free_extent_tree(pages, arena, constants)
    end = page + count
    if end < read_u64(pages, constants.region_page_limit_address):
        neighbor = read_u64(pages, address(end))
        if not neighbor & 1 and bool(neighbor & 8) == dirty:
            neighbor_count = neighbor >> 12
            node = _region_node(pages, region, end, constants)
            tree.remove(node)
            if dirty:
                _unlink_dirty_extent(pages, arena, node, neighbor_count)
            count += neighbor_count
            size = count << 12
            for index in (page, page + count - 1):
                a = address(index)
                write_u64(pages, a, (read_u64(pages, a) & 0xFFF) | size)
    if page > bias:
        neighbor = read_u64(pages, address(page - 1))
        if not neighbor & 1 and bool(neighbor & 8) == dirty:
            neighbor_count = neighbor >> 12
            page -= neighbor_count
            node = _region_node(pages, region, page, constants)
            tree.remove(node)
            if dirty:
                _unlink_dirty_extent(pages, arena, node, neighbor_count)
            count += neighbor_count
            size = count << 12
            for index in (page, page + count - 1):
                a = address(index)
                write_u64(pages, a, (read_u64(pages, a) & 0xFFF) | size)
    if size == read_u64(pages, 0x121D9EA8):
        raise RefillUnsupported("release of an entire OS region is not modeled")
    node = _region_node(pages, region, page, constants)
    tree.insert(node)
    if dirty:
        pointer = node + 0x10
        sentinel = arena + 0x150
        previous = read_u64(pages, sentinel + 8)
        write_u64(pages, pointer, pointer)
        write_u64(pages, pointer + 8, pointer)
        write_u64(pages, previous, pointer)
        write_u64(pages, pointer, sentinel)
        write_u64(pages, sentinel + 8, pointer)
        write_u64(pages, pointer + 8, previous)
        write_u64(pages, arena + 0xE0, read_u64(pages, arena + 0xE0) + count)
        _purge_dirty_extents(pages, arena, constants)


def _purge_dirty_extents(pages, arena, constants):
    if constants.purge_madvise_result is None:
        raise RefillUnsupported("slab purge needs an explicit guest madvise outcome")
    if not -4095 <= constants.purge_madvise_result <= 0:
        raise RefillUnsupported("invalid guest madvise result")
    if constants.purge_madvise_result < 0 and constants.guest_errno_address is None:
        raise RefillUnsupported("failed guest madvise requires its TLS errno address")
    if read_u64(pages, arena + 0x500) != 0x1216F0B0:
        raise RefillUnsupported("custom extent purge hook is not modeled")
    write_u64(pages, arena + 0x38, read_u64(pages, arena + 0x38) + 1)
    used = read_u64(pages, arena + 0xD8)
    dirty = read_u64(pages, arena + 0xE0)
    shift = read_u64(pages, arena + 0xD0) & 63
    target = (dirty - max(used >> shift, read_u64(pages, constants.region_page_limit_address))) & 0xFFFF_FFFF_FFFF_FFFF
    sentinel = arena + 0x150
    pointer = read_u64(pages, sentinel)
    tree = _free_extent_tree(pages, arena, constants)
    selected, total = [], 0
    while pointer != sentinel:
        if len(selected) >= 128:
            raise RefillUnsupported("dirty extent queue is cyclic or too long")
        if pointer == read_u64(pages, arena + 0x198) + 0x28:
            raise RefillUnsupported("purge of a large cached extent is not modeled")
        following = read_u64(pages, pointer)
        region, page = _slab_page(pages, pointer, constants)
        if region == read_u64(pages, arena + 0xC8):
            raise RefillUnsupported("purge needs another OS region")
        bias = read_u64(pages, constants.page_bias_address)
        start = region + 0x68 + (page - bias) * 8
        size = read_u64(pages, start) & ~0xFFF
        count = size >> 12
        tree.remove(pointer - 0x10)
        _unlink_dirty_extent(pages, arena, pointer - 0x10, count)
        _account_extent_pages(pages, arena, count, constants)
        for index, value in ((count - 1, 0xFFB), (0, size | 0xFFB)):
            address = start + index * 8
            write_u64(pages, address, (read_u64(pages, address) & 4) | value)
        selected.append((pointer, start, count))
        total += count
        if total >= target:
            break
        pointer = following
    # The isolated native oracle models madvise as an advisory syscall. Its
    # outcome changes metadata bit 2; no captured post-call pages are copied.
    # This models that guest runtime, not Linux's physical page contents.
    for pointer, start, count in selected:
        if constants.purge_madvise_result < 0:
            write_u32(pages, constants.guest_errno_address, -constants.purge_madvise_result)
        for index in range(count):
            address = start + index * 8
            flag = 0 if constants.purge_madvise_result == 0 else 4
            write_u64(pages, address, (read_u64(pages, address) & ~4) | flag)
    write_u64(pages, arena + 0x40, read_u64(pages, arena + 0x40) + len(selected))
    write_u64(pages, arena + 0x48, read_u64(pages, arena + 0x48) + total)
    for pointer, _, _ in selected:
        write_u64(pages, pointer, pointer)
        write_u64(pages, pointer + 8, pointer)
        _release_extent(pages, arena, pointer, False, True, constants)


def _return_slab_slot(pages, arena, pointer, class_id, constants, *, release_extent=None):
    region = pointer & ~read_u64(pages, constants.bitmap_mask_address)
    bias = read_u64(pages, constants.page_bias_address)
    entry_address = region + 0x68 + (((pointer - region) >> 12) - bias) * 8
    entry = read_u64(pages, entry_address)
    if (entry & 3) != 1 or ((entry >> 4) & 0xFF) != class_id:
        raise RefillUnsupported("flush object is not in the requested slab class")
    page = ((pointer - region) >> 12) - (entry >> 12)
    slab = region + read_u64(pages, constants.region_offset_address) + (page - bias) * 0x60 + 0x10
    if read_u32(pages, slab) != class_id:
        raise RefillUnsupported("flush slab class mismatch")
    metadata = _class_metadata_address(class_id, constants)
    stride = read_u64(pages, metadata + 0x10)
    delta = pointer - region - (page << 12) - read_u32(pages, metadata + 0x58)
    if stride == 0 or delta < 0 or delta % stride:
        raise RefillUnsupported("flush pointer is not a slab slot boundary")
    index = delta // stride
    total = read_u32(pages, metadata + 0x20)
    if index >= total:
        raise RefillUnsupported("flush pointer is outside the slab")
    count = read_u32(pages, slab + 4)
    bitmap_address = slab + 8 + (index >> 6) * 8
    before = read_u64(pages, bitmap_address)
    bit = 1 << (index & 63)
    if before & bit:
        raise RefillUnsupported("flush attempts to return an already free slab slot")
    write_u64(pages, bitmap_address, before ^ bit)
    levels = read_u32(pages, metadata + 0x30)
    if before == 0:
        for level in range(1, levels):
            parent_address = slab + 8 + (read_u64(pages, metadata + 0x38 + level * 8) + (index >> (6 * (level + 1)))) * 8
            parent = read_u64(pages, parent_address)
            write_u64(pages, parent_address, parent ^ (1 << ((index >> (6 * level)) & 63)))
            if parent:
                break
    write_u32(pages, slab + 4, count + 1)
    state = arena + class_id * 0xE0
    if count + 1 == total:
        if slab == read_u64(pages, state + 0x530):
            write_u64(pages, state + 0x530, 0)
        elif total != 1:
            tree = _AllocatorTree(pages, state + 0x538, lambda node: node)
            tree.remove(slab - 0x10)
        release = _release_extent if release_extent is None else release_extent
        release(pages, arena, slab, True, False, constants)
        write_u64(pages, state + 0x5E0, read_u64(pages, state + 0x5E0) - 1)
    elif count == 0:
        current = read_u64(pages, state + 0x530)
        if slab != current:
            tree = _AllocatorTree(pages, state + 0x538, lambda node: node)
            if slab < current:
                if read_u32(pages, current + 4):
                    tree.insert(current - 0x10)
                write_u64(pages, state + 0x530, slab)
                write_u64(pages, state + 0x5D8, read_u64(pages, state + 0x5D8) + 1)
            else:
                tree.insert(slab - 0x10)
    write_u64(pages, state + 0x5A8, read_u64(pages, state + 0x5A8) + 1)
    write_u64(pages, state + 0x5B8, read_u64(pages, state + 0x5B8) - 1)


def _flush_small_bin(pages, arena, bins, class_id, retain, constants):
    if class_id > 0x23:
        raise RefillUnsupported("large-bin flush is not modeled")
    target = bins + (class_id + 1) * 0x20
    count = read_u32(pages, target + 0x10)
    if not 0 <= retain <= count:
        raise RefillUnsupported("flush retention exceeds bin count")
    list_address = read_u64(pages, target + 0x18)
    state = arena + class_id * 0xE0
    pointers = [read_u64(pages, list_address + i * 8) for i in range(count)]
    # Native groups by arena. The supported thread has one live arena.
    mask = read_u64(pages, constants.bitmap_mask_address)
    if any(read_u64(pages, pointer & ~mask) != arena for pointer in pointers[:count - retain]):
        raise RefillUnsupported("flush spans another arena")
    write_u64(pages, state + 0x5C8, read_u64(pages, state + 0x5C8) + 1)
    write_u64(pages, state + 0x5B0, read_u64(pages, state + 0x5B0) + read_u64(pages, target))
    write_u64(pages, target, 0)
    for pointer in pointers[:count - retain]:
        _return_slab_slot(pages, arena, pointer, class_id, constants)
    # memmove preserves trailing list cells, including those now inactive.
    for i, pointer in enumerate(pointers[count - retain:]):
        write_u64(pages, list_address + i * 8, pointer)
    write_u32(pages, target + 0x10, retain)
    if retain < _signed32(read_u32(pages, target + 8)):
        write_u32(pages, target + 8, retain)


def _cleanup_bins(pages, thread, constants):
    bins = read_u64(pages, thread + 0x10)
    arena = read_u64(pages, thread + 0x30)
    class_id = read_u32(pages, bins + 0x1C)
    class_count = read_u64(pages, constants.class_count_address)
    if class_id >= class_count:
        raise RefillUnsupported("cleanup cursor exceeds class table")
    caller = bins + class_id * 0x20
    floor = _signed32(read_u32(pages, caller + 0x28))
    shift = read_u32(pages, caller + 0x2C)
    if floor > 0:
        count = read_u32(pages, caller + 0x30)
        _flush_small_bin(pages, arena, bins, class_id, count + (floor >> 2) - floor, constants)
        capacity = read_u32(pages, read_u64(pages, constants.free_capacity_table_pointer_address) + class_id * 4)
        if capacity >> ((shift + 1) & 31):
            write_u32(pages, caller + 0x2C, shift + 1)
    elif floor < 0 and shift > 1:
        write_u32(pages, caller + 0x2C, shift - 1)
    write_u32(pages, caller + 0x28, read_u32(pages, caller + 0x30))
    write_u32(pages, bins + 0x1C, (class_id + 1) % class_count)
    write_u32(pages, bins + 0x18, 0)


def cleanup_small_object_bins(pages, *, thread_state_address, constants=AllocatorConstants()):
    """One native periodic sweep; unsupported branches are atomic failures."""
    staged = _PageTransaction(pages)
    _cleanup_bins(staged, thread_state_address, constants)
    staged.commit()


def allocate_small_object(
    pages,
    *,
    thread_state_address,
    request_size,
    guest_os: GuestOS | None = None,
    constants=AllocatorConstants(),
):
    """Normal malloc including empty-bin refill, new slab setup and cleanup.

    Requires initialized TLS/arena. Pass ``guest_os`` to let the first refill
    register one fresh region in the same transaction; without it, a fresh
    arena rejects instead of invoking an implicit host syscall. No native
    code, expected pointers, supplied batch widths or captured post-call bytes
    are used. Large objects fail atomically; purge requires an explicit guest
    madvise result in constants.
    """
    if guest_os is not None:
        if guest_os.pages is not pages:
            raise ValueError("guest_os must own the supplied page map")
        staged = guest_os.begin()
        arena = read_u64(staged.pages, thread_state_address + 0x30)
        if not arena:
            raise RefillUnsupported("thread arena initialization is not modeled")
        # A fresh arena has an empty available tree. Registration is part of
        # this same transaction so allocation failure cannot leak a mapping.
        if read_u64(staged.pages, arena + 0xE8) == arena + 0xF0:
            _register_os_region(
                staged.pages,
                staged,
                arena_address=arena,
                base=None,
                length=0x40000,
                constants=constants,
                anonymous_name=b"vm9-region",
            )
        result = _allocate_small_object(
            staged.pages,
            thread_state_address=thread_state_address,
            request_size=request_size,
            constants=constants,
            lifecycle=True,
        )
        staged.commit()
    else:
        staged = _PageTransaction(pages)
        result = _allocate_small_object(
            staged,
            thread_state_address=thread_state_address,
            request_size=request_size,
            constants=constants,
            lifecycle=True,
        )
        staged.commit()
    return result


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

    return _allocate_small_object(pages, thread_state_address=thread_state_address,
                                 request_size=request_size, constants=constants, lifecycle=False)


def _allocate_small_object(pages, *, thread_state_address, request_size, constants, lifecycle):
    if request_size < 0:
        raise ValueError("request_size must be non-negative")
    size = request_size or 1
    if size > (0x3800 if lifecycle else 0x1000):
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

    if size <= 0x1000:
        class_id = _read(pages, constants.class_table + ((size - 1) >> 3), 1)[0]
    else:
        lg = (size * 2 - 1).bit_length() - 1
        class_id = 4 * lg - 0x17 + (((size - 1) >> (lg - 3)) & 3)
    width = read_u64(pages, constants.class_width_table + class_id * 8)
    bins = read_u64(pages, thread_state_address + 0x10)
    if bins < 0x10000 or bins & 7:
        raise RefillUnsupported("thread state has no captured bin table")
    bin_address = bins + class_id * 0x20
    sweep_count = read_u32(pages, bins + 0x18)
    if sweep_count >= constants.free_sweep_period:
        raise RefillUnsupported("invalid cleanup counter")
    if not lifecycle and sweep_count >= constants.free_sweep_period - 1:
        raise RefillUnsupported("malloc needs unmodeled periodic cleanup")
    floor_word = read_u32(pages, bin_address + 0x28)
    floor = floor_word if floor_word < 0x8000_0000 else floor_word - 0x1_0000_0000
    if read_u32(pages, bin_address + 0x30) == 0:
        if not lifecycle:
            raise RefillUnsupported("empty malloc bin requires a separate refill path")
        write_u32(pages, bin_address + 0x28, -1)
        result = _refill_empty_bin(pages, read_u64(pages, thread_state_address + 0x30),
                                   bin_address, class_id, constants)
    else:
        result = pop_free_list(pages, bin_address)
        write_u32(pages, bin_address + 0x30, result.count_after)
        if result.count_after < floor:
            write_u32(pages, bin_address + 0x28, result.count_after)
    floor_after = _signed32(read_u32(pages, bin_address + 0x28))
    allocation_count = read_u64(pages, bin_address + 0x20)
    allocation_count_after = (allocation_count + 1) & 0xFFFF_FFFF_FFFF_FFFF
    allocated_bytes = read_u64(pages, thread_state_address + 0x18)
    allocated_bytes_after = (allocated_bytes + width) & 0xFFFF_FFFF_FFFF_FFFF

    write_u64(pages, bin_address + 0x20, allocation_count_after)
    write_u32(pages, bins + 0x18, sweep_count + 1)
    if lifecycle and sweep_count + 1 == constants.free_sweep_period:
        _cleanup_bins(pages, thread_state_address, constants)
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
        sweep_count_after=read_u32(pages, bins + 0x18),
        floor_before=floor,
        floor_after=_signed32(read_u32(pages, bin_address + 0x28)),
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

    return _publish_small_object_free(pages, thread_state_address=thread_state_address,
                                      object_address=object_address, constants=constants, lifecycle=False)


def free_small_object(pages, *, thread_state_address, object_address, constants=AllocatorConstants()):
    """Normal void free with full-bin flush and periodic cleanup, atomically."""
    if object_address == 0:
        return None
    staged = _PageTransaction(pages)
    result = _publish_small_object_free(staged, thread_state_address=thread_state_address,
                                       object_address=object_address, constants=constants, lifecycle=True)
    staged.commit()
    return result


def _publish_small_object_free(pages, *, thread_state_address, object_address, constants, lifecycle):
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
    if class_id > 0x23:
        raise RefillUnsupported("small-object class exceeds slab metadata table")

    bins = read_u64(pages, thread_state_address + 0x10)
    if bins < 0x10000 or bins & 7:
        raise RefillUnsupported("thread state has no captured bin table")
    bin_address = bins + class_id * 0x20
    count = read_u32(pages, bin_address + 0x30)
    count_before = count
    capacity_table = read_u64(pages, constants.free_capacity_table_pointer_address)
    capacity = read_u32(pages, capacity_table + class_id * 4)
    if count > capacity:
        raise RefillUnsupported("free-list count exceeds capacity")
    if not lifecycle and count == capacity:
        raise RefillUnsupported("free-list bin needs an unmodeled flush")
    sweep_count = read_u32(pages, bins + 0x18)
    if sweep_count >= constants.free_sweep_period:
        raise RefillUnsupported("invalid cleanup counter")
    if not lifecycle and sweep_count >= constants.free_sweep_period - 1:
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
    if lifecycle and count == capacity:
        _flush_small_bin(pages, read_u64(pages, thread_state_address + 0x30),
                         bins, class_id, capacity >> 1, constants)
        count = read_u32(pages, bin_address + 0x30)
    write_u64(pages, list_address + count * 8, object_address)
    write_u32(pages, bin_address + 0x30, count + 1)
    write_u32(pages, bins + 0x18, sweep_count + 1)
    if lifecycle and sweep_count + 1 == constants.free_sweep_period:
        _cleanup_bins(pages, thread_state_address, constants)
    return FreeListPush(
        thread_state_address=thread_state_address,
        object_address=object_address,
        region_base=region_base,
        region_entry_address=entry_address,
        region_entry=entry,
        class_id=class_id,
        bin_address=bin_address,
        list_address=list_address,
        count_before=count_before,
        count_after=count + 1,
        capacity=capacity,
        freed_bytes_before=freed_bytes,
        freed_bytes_after=freed_bytes_after,
        sweep_count_before=sweep_count,
        sweep_count_after=read_u32(pages, bins + 0x18),
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
