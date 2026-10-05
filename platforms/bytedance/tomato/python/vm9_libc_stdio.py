"""Matching libc stdio boot, static FILE acquisition and cleanup registration.

Inputs are fresh relocated ELF pages and explicit guest OS outcomes. No native
boot pages supply these constructors. CPU file parsing/full malloc cold return,
dynamic FILE growth and destructor execution are still separate boundaries.
"""
from __future__ import annotations
import vm9_allocator as allocator
import vm9_objects as objects
from vm9_libc_boot import _u, _w, _indirect
from vm9_libc_mapping import _kernel, _errno

PAGE = 4096  # Actual matching getpagesize +0x264fc is mov w0,#0x1000; ret.


def initialize_recursive_mutex(pages, *, mutex_address):
    """Actual pthread_mutex_init with attr_init -> settype(1), 40-byte ABI."""
    tx = allocator._PageTransaction(pages)
    allocator._write_span(tx, mutex_address, bytes(40))
    _w(tx, mutex_address, 0x4000, 2)
    tx.commit()


def _initialize_extension(pages, extension):
    allocator._write_span(pages, extension, bytes(0x38))
    initialize_recursive_mutex(pages, mutex_address=extension + 0x38)
    _w(pages, extension + 0x60, 1, 1)
    # +0x61..+0x67 padding is not initialized by these native functions.


def _protect_cleanup(tx, address, protection, thread_pointer, os_call):
    if not any(r.base == address and r.length == PAGE for r in tx.mappings):
        raise allocator.RefillUnsupported("cleanup page is not an owned single-page mapping")
    outcome = _kernel(os_call(tx, "mprotect", address, PAGE, protection))
    if outcome < 0:
        _errno(tx.pages, thread_pointer, -outcome)
        return -1
    if outcome:
        raise allocator.RefillUnsupported("invalid mprotect success result")
    tx.protect_exact(address, PAGE, protection)
    return 0


def _register_cleanup(tx, *, callback_address, libc_base, thread_pointer, os_call):
    """Actual +0x75550 reserves/overwrites cleanup slot at the list tail."""
    if not isinstance(callback_address, int) or not 0 <= callback_address < (1 << 64):
        raise allocator.RefillUnsupported("cleanup callback outside uint64 ABI")
    p = tx.pages
    mutex = libc_base + 0xDE9B8
    objects.lock_uncontended_mutex(p, mutex_address=mutex)
    head = _u(p, libc_base + 0xE67A8)
    if head:
        tail, seen = head, set()
        while _u(p, tail):
            if tail in seen or len(seen) >= 64:
                raise allocator.RefillUnsupported("invalid or oversized cleanup chain")
            seen.add(tail)
            tail = _u(p, tail)
        if tail in seen:
            raise allocator.RefillUnsupported("cyclic cleanup chain")
        if _protect_cleanup(tx, tail, 3, thread_pointer, os_call):
            objects.unlock_uncontended_mutex(p, mutex_address=mutex)
            return
    else:
        outcome = _kernel(os_call(tx, "mmap", 0, PAGE, 3, 0x22, 0xFFFFFFFF, 0))
        if outcome < 0:
            _errno(p, thread_pointer, -outcome)
            objects.unlock_uncontended_mutex(p, mutex_address=mutex)
            return
        tx.map_anonymous(PAGE, address=outcome, prot=3, flags=0x22,
            fd=0xFFFFFFFF, offset=0, anonymous_name=b"")
        tail = outcome
        _w(p, tail, head)
        _w(p, tail + 8, 1, 4)
        _w(p, tail + 0xC, (PAGE - 16) // 24, 4)
        _w(p, libc_base + 0xE67A8, tail)
    _w(p, tail + 0x10, callback_address)
    _w(p, tail + 0x18, 0)
    _w(p, tail + 0x20, 0)
    _protect_cleanup(tx, tail, 1, thread_pointer, os_call)  # Native ignores failure.
    _w(p, libc_base + 0xE67B0, 1, 4)
    objects.unlock_uncontended_mutex(p, mutex_address=mutex)


def register_stdio_cleanup(guest_os, *, callback_address, libc_base, thread_pointer, os_call):
    tx = guest_os.begin()
    _register_cleanup(tx, callback_address=callback_address, libc_base=libc_base,
        thread_pointer=thread_pointer, os_call=os_call)
    tx.commit()


def _initialize_stdio(tx, *, libc_base, thread_pointer, os_call):
    """Actual +0x74868 standard and 17 static FILE extension constructors."""
    p = tx.pages
    mutex = libc_base + 0xDB618
    objects.lock_uncontended_mutex(p, mutex_address=mutex)
    if not _u(p, libc_base + 0xE9108, 4):
        standard = _indirect(p, libc_base, 0xD8F00)
        if not standard:
            raise allocator.RefillUnsupported("stdio __sF ELF symbol relocation is unresolved")
        for i in range(3):
            extension = libc_base + 0xE6668 + i * 0x68
            _w(p, standard + i * 0x98 + 0x58, extension)
            _initialize_extension(p, extension)
        for i in range(17):
            extension = libc_base + 0xE54D0 + i * 0x68
            _w(p, libc_base + 0xE5BB8 + i * 0x98 + 0x58, extension)
            _initialize_extension(p, extension)
        _register_cleanup(tx, callback_address=libc_base + 0x7485C,
            libc_base=libc_base, thread_pointer=thread_pointer, os_call=os_call)
        _w(p, libc_base + 0xE9108, 1, 4)
    objects.unlock_uncontended_mutex(p, mutex_address=mutex)


def initialize_stdio(guest_os, *, libc_base, thread_pointer, os_call):
    tx = guest_os.begin()
    _initialize_stdio(tx, libc_base=libc_base, thread_pointer=thread_pointer, os_call=os_call)
    tx.commit()


def _acquire_file(tx, *, libc_base, thread_pointer, os_call):
    """+0x749dc existing-glue/free-FILE selection; malloc growth rejects."""
    p = tx.pages
    if not _u(p, libc_base + 0xE9108, 4):
        _initialize_stdio(tx, libc_base=libc_base, thread_pointer=thread_pointer, os_call=os_call)
    mutex = libc_base + 0xDB5B0
    objects.lock_uncontended_mutex(p, mutex_address=mutex)
    node, seen, selected = libc_base + 0xDB5F8, set(), 0
    while node and not selected:
        if node in seen or len(seen) >= 64:
            raise allocator.RefillUnsupported("invalid or oversized FILE glue chain")
        seen.add(node)
        count = _u(p, node + 8, 4)
        if count > 64:
            raise allocator.RefillUnsupported("unsupported FILE glue count")
        files = _u(p, node + 0x10)
        for i in range(count):
            candidate = files + i * 0x98
            if not _u(p, candidate + 0x10, 4):
                selected = candidate
                _w(p, selected + 0x10, 1, 4)
                break
        node = _u(p, node) if not selected else node
    objects.unlock_uncontended_mutex(p, mutex_address=mutex)
    if not selected:
        raise allocator.RefillUnsupported("dynamic FILE malloc/glue publication is unrecovered")
    _w(p, selected, 0)
    _w(p, selected + 8, 0, 4)
    _w(p, selected + 0xC, 0, 4)
    _w(p, selected + 0x14, 0xFFFFFFFF, 4)
    _w(p, selected + 0x18, 0)
    _w(p, selected + 0x20, 0)
    _w(p, selected + 0x28, 0, 4)
    _w(p, selected + 0x78, 0)
    _w(p, selected + 0x80, 0)
    _initialize_extension(p, _u(p, selected + 0x58))
    return selected


def acquire_stdio_file(guest_os, *, libc_base, thread_pointer, os_call):
    tx = guest_os.begin()
    result = _acquire_file(tx, libc_base=libc_base, thread_pointer=thread_pointer, os_call=os_call)
    tx.commit()
    return result


def _recursive_mutex_transition(pages, *, mutex_address, thread_pointer, lock):
    tx = allocator._PageTransaction(pages)
    state = _u(tx, mutex_address, 2)
    if state & 0xE000 != 0x4000 or state & 3 not in (0, 1):
        raise allocator.RefillUnsupported("recursive mutex requires private uncontended state")
    pthread = _u(tx, thread_pointer + 8)
    tid = _u(tx, pthread + 0x10, 4)
    if not tid:
        raise allocator.RefillUnsupported("recursive mutex requires explicit nonzero guest tid")
    owner = _u(tx, mutex_address + 4, 4)
    if lock:
        if owner == tid:
            if state & 3 != 1:
                raise allocator.RefillUnsupported("inconsistent recursive mutex ownership")
            if state & 0x1FFC == 0x1FFC: return 11
            _w(tx, mutex_address, state + 4, 2)
        else:
            if state != 0x4000 or owner:
                raise allocator.RefillUnsupported("recursive mutex wait/futex branch is unrecovered")
            _w(tx, mutex_address, 0x4001, 2)
            _w(tx, mutex_address + 4, tid, 4)
    else:
        if owner != tid: return 1
        if state & 3 != 1:
            raise allocator.RefillUnsupported("inconsistent recursive mutex ownership")
        if state & 0x1FFC:
            _w(tx, mutex_address, state - 4, 2)
        else:
            _w(tx, mutex_address + 4, 0, 4)
            _w(tx, mutex_address, 0x4000, 2)
    tx.commit()
    return 0


def lock_recursive_mutex(pages, *, mutex_address, thread_pointer):
    """Actual private recursive lock, including same-owner depth and EAGAIN."""
    return _recursive_mutex_transition(pages, mutex_address=mutex_address,
        thread_pointer=thread_pointer, lock=True)


def unlock_recursive_mutex(pages, *, mutex_address, thread_pointer):
    """Actual private recursive unlock, including wrong-owner EPERM."""
    return _recursive_mutex_transition(pages, mutex_address=mutex_address,
        thread_pointer=thread_pointer, lock=False)
