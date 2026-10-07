"""Fresh diagnostic lock scopes for the matching image and bionic ABI.

This is serialized guest-memory behavior. Allocation remains an explicit
provider; contention, guard waits and host concurrency are not implemented.
No signature or captured diagnostic state is an input.
"""
from __future__ import annotations
from dataclasses import dataclass
from vm9_allocator import RefillUnsupported, _PageTransaction, _read_span, _write_span
import vm9_objects as objects
import vm9_libc_stdio as mutex

GUARD = 0x3DEDA0
GLOBAL_LOCK = 0x3DED98
TABLE = 0x3DEDA8
GUARD_MUTEX = 0x3E2F40


def _u(pages, address, width=8):
    return int.from_bytes(_read_span(pages, address, width), "little")


def _w(pages, address, value, width=8):
    _write_span(pages, address, (value & ((1 << (8 * width)) - 1)).to_bytes(width, "little"))


@dataclass(frozen=True)
class DiagnosticScope:
    object_address: int
    input_word: int
    table_index: int
    entry_address: int
    lock_result: int
    allocation_sizes: tuple[int, ...]


def enter_diagnostic_scope(pages, *, object_address: int, input_word: int,
        image_base: int, thread_pointer: int, allocate, thread_id=None,
        observer=None) -> DiagnosticScope:
    """Model +0x26c858, +0x15dea8 and +0x15f778, including lazy locks.

    The scope preserves object+12 padding; it holds the selected recursive
    mutex until +0x26c9d0. The lock table is process-owned and is not freed at
    scope exit. Providers' external ledgers are not rolled back with pages.
    """
    if not isinstance(input_word, int) or not 0 <= input_word < 1 << 64:
        raise RefillUnsupported("diagnostic input must fit uint64")
    objects._image_address(image_base, GUARD)
    tx = _PageTransaction(pages)
    _read_span(tx, object_address, 24)
    allocations = []
    def emit(kind, *values):
        if observer is not None:
            observer(kind, *values)
    def alloc(size):
        pointer = objects._allocate(tx, allocate, size)
        allocations.append(size)
        return pointer
    def normal(address, lock):
        emit("pthread_mutex_lock" if lock else "pthread_mutex_unlock", address)
        operation = objects.lock_uncontended_mutex if lock else objects.unlock_uncontended_mutex
        return operation(tx, mutex_address=address)
    def construct_lock(address, recursive):
        _w(tx, address, image_base + 0x34C738)
        if recursive:
            mutex.initialize_recursive_mutex(tx, mutex_address=address + 8)
        else:
            _write_span(tx, address + 8, bytes(40))
    _w(tx, object_address, image_base + 0x35D410)
    _w(tx, object_address + 8, -0xE9, 4)
    _w(tx, object_address + 16, input_word)
    guard = image_base + GUARD
    # Outer code tests bit0, while __cxa_guard_acquire tests the entire byte.
    if not _u(tx, guard, 1) & 1 and not _u(tx, guard, 1):
        normal(image_base + GUARD_MUTEX, True)
        flag = _u(tx, guard + 1, 1)
        if flag & 2:
            raise RefillUnsupported("diagnostic guard wait/recursive branch is unrecovered")
        if flag != 1:
            if not isinstance(thread_id, int) or not 0 <= thread_id <= 0xFFFFFFFF:
                raise RefillUnsupported("cold diagnostic guard requires an explicit uint32 thread id")
            emit("gettid", thread_id)
            _w(tx, guard + 4, thread_id, 4)
            _w(tx, guard + 1, 2, 1)
            normal(image_base + GUARD_MUTEX, False)
            global_lock = alloc(48)
            construct_lock(global_lock, False)
            _w(tx, image_base + GLOBAL_LOCK, global_lock)
            _w(tx, guard, 1, 1)
            normal(image_base + GUARD_MUTEX, True)
            _w(tx, guard + 1, 1, 1)
        normal(image_base + GUARD_MUTEX, False)
    table = _u(tx, image_base + TABLE)
    if not table:
        global_lock = _u(tx, image_base + GLOBAL_LOCK)
        normal(global_lock + 8, True)
        # Preserve native's second read under the lock.
        table = _u(tx, image_base + TABLE)
        if not table:
            table = alloc(0x800)
            _write_span(tx, table, bytes(0x800))
            _w(tx, image_base + TABLE, table)
        normal(global_lock + 8, False)
        table = _u(tx, image_base + TABLE)
    index = (_u(tx, object_address + 16) >> 4) & 0xFF
    slot = table + index * 8
    entry = _u(tx, slot)
    if not entry:
        global_lock = _u(tx, image_base + GLOBAL_LOCK)
        normal(global_lock + 8, True)
        entry = _u(tx, slot)
        if not entry:
            entry = alloc(48)
            construct_lock(entry, True)
            _w(tx, slot, entry)
        normal(global_lock + 8, False)
        entry = _u(tx, slot)
    emit("pthread_mutex_lock", entry + 8)
    result = mutex.lock_recursive_mutex(tx, mutex_address=entry + 8,
        thread_pointer=thread_pointer)
    _w(tx, object_address + 8, result, 4)
    tx.commit()
    return DiagnosticScope(object_address, input_word, index, entry, result,
        tuple(allocations))


def leave_diagnostic_scope(pages, *, object_address: int, image_base: int,
        thread_pointer: int, observer=None) -> int | None:
    """Model +0x26c9d0; nonzero saved lock result suppresses unlock."""
    tx = _PageTransaction(pages)
    _w(tx, object_address, image_base + 0x35D410)
    if _u(tx, object_address + 8, 4):
        tx.commit()
        return None
    index = (_u(tx, object_address + 16) >> 4) & 0xFF
    table = _u(tx, image_base + TABLE)
    entry = _u(tx, table + index * 8)
    result = None
    if entry:
        if observer is not None:
            observer("pthread_mutex_unlock", entry + 8)
        result = mutex.unlock_recursive_mutex(tx, mutex_address=entry + 8,
            thread_pointer=thread_pointer)
    tx.commit()
    return result
