"""Bounded matching-libc read-only FILE open, buffer constructor and close.

OS outcomes remain explicit. Write/update/append/seek, buffered release,
stream refill/parsing and dynamic FILE growth are separate boundaries.
"""
from __future__ import annotations
import vm9_allocator as allocator
import vm9_libc_stdio as stdio
from vm9_libc_tcache import _public_small
from vm9_libc_boot import _u, _w
from vm9_libc_mapping import _kernel, _errno


def _path(value):
    if not isinstance(value, bytes) or len(value) > 255 or b"\0" in value:
        raise allocator.RefillUnsupported("file path requires bounded NUL-free bytes")
    return value


def _readonly_mode(pages, mode, thread_pointer):
    if not isinstance(mode, bytes) or len(mode) > 64 or b"\0" in mode:
        raise allocator.RefillUnsupported("stdio mode requires bounded NUL-free bytes")
    if not mode or mode[:1] not in (b"r", b"w", b"a"):
        _errno(pages, thread_pointer, 22)
        return None
    if mode[:1] != b"r" or b"+" in mode:
        raise allocator.RefillUnsupported("write/update/append fopen is unrecovered")
    # Matching parse ignores other suffix bytes; e enables CLOEXEC, and x
    # changes flags only with O_CREAT. Plain r does not enable CLOEXEC.
    return 0x80000 if b"e" in mode[1:] else 0


def _close_descriptor(tx, fd, thread_pointer, os_call):
    outcome = _kernel(os_call(tx, "close", fd))
    if outcome < 0:
        _errno(tx.pages, thread_pointer, -outcome)
        # Actual close wrapper +0x1ecd8 treats EINTR as success, retaining errno.
        return 0 if outcome == -4 else -1
    if outcome:
        raise allocator.RefillUnsupported("invalid close success outcome")
    return 0


def _open_readonly(tx, *, path, mode, libc_base, thread_pointer, os_call):
    path = _path(path)
    p = tx.pages
    open_flags = _readonly_mode(p, mode, thread_pointer)
    if open_flags is None: return 0
    file = stdio._acquire_file(tx, libc_base=libc_base, thread_pointer=thread_pointer, os_call=os_call)
    outcome = _kernel(os_call(tx, "openat", 0xFFFFFF9C, path, open_flags, 0))
    if outcome < 0:
        _errno(p, thread_pointer, -outcome)
        _w(p, file + 0x10, 0, 4)
        return 0
    if outcome > 0x7FFFFFFF:
        raise allocator.RefillUnsupported("open fd outside signed32 ABI")
    if outcome > 0x7FFF:
        _w(p, file + 0x10, 0, 4)
        _close_descriptor(tx, outcome, thread_pointer, os_call)
        _errno(p, thread_pointer, 24)
        return 0
    _w(p, file + 0x14, outcome, 4)
    _w(p, file + 0x10, 4, 4)
    _w(p, file + 0x30, file)
    for field, offset in ((0x38, 0x7524C), (0x40, 0x75090), (0x48, 0x751BC), (0x50, 0x7511C)):
        _w(p, file + field, libc_base + offset)
    return file


def open_readonly_stdio_file(guest_os, *, path, mode=b"r", libc_base, thread_pointer, os_call):
    """Actual +0x57cd8 read-only open, including failure and fd>32767 cleanup."""
    tx = guest_os.begin()
    result = _open_readonly(tx, path=path, mode=mode, libc_base=libc_base,
        thread_pointer=thread_pointer, os_call=os_call)
    tx.commit()
    return result


def _close_unbuffered(tx, *, file_address, libc_base, thread_pointer, os_call):
    p = tx.pages
    flags = _u(p, file_address + 0x10, 4)
    if not flags:
        _errno(p, thread_pointer, 9)
        return -1
    if flags != 4 or _u(p, file_address + 0x18) or _u(p, file_address + 0x78):
        raise allocator.RefillUnsupported("buffered/write/auxiliary fclose is unrecovered")
    if _u(p, file_address + 0x30) != file_address or _u(p, file_address + 0x38) != libc_base + 0x7524C:
        raise allocator.RefillUnsupported("foreign FILE close callback is unrecovered")
    extension = _u(p, file_address + 0x58)
    if _u(p, extension):
        raise allocator.RefillUnsupported("fclose ungetc buffer cleanup is unrecovered")
    locking = _u(p, extension + 0x60, 1)
    if locking:
        stdio.lock_recursive_mutex(p, mutex_address=extension + 0x38, thread_pointer=thread_pointer)
    _w(p, extension + 0x30, 0, 4)
    _w(p, extension + 0x28, 0)
    result = _close_descriptor(tx, _u(p, file_address + 0x14, 4), thread_pointer, os_call)
    _w(p, file_address + 0xC, 0, 4)
    _w(p, file_address + 8, 0, 4)
    _w(p, file_address + 0x10, 0, 4)
    if locking:
        stdio.unlock_recursive_mutex(p, mutex_address=extension + 0x38, thread_pointer=thread_pointer)
    return result


def close_unbuffered_stdio_file(guest_os, *, file_address, libc_base, thread_pointer, os_call):
    """Actual +0x56c78 fresh read-only fclose; allocated buffers reject."""
    tx = guest_os.begin()
    result = _close_unbuffered(tx, file_address=file_address, libc_base=libc_base,
        thread_pointer=thread_pointer, os_call=os_call)
    tx.commit()
    return result


def _create_readonly_buffer(tx, *, file_address, libc_base, thread_pointer, os_call):
    """Actual +0x597b8/+0x5986c for regular files and fstat failure."""
    p = tx.pages
    if _u(p, file_address + 0x10, 4) != 4 or _u(p, file_address + 0x18):
        raise allocator.RefillUnsupported("stdio buffer constructor requires fresh readonly FILE")
    if _u(p, file_address + 0x48) != libc_base + 0x751BC:
        raise allocator.RefillUnsupported("foreign stdio write callback is unrecovered")
    outcome = os_call(tx, "fstat", _u(p, file_address + 0x14, 4))
    if not isinstance(outcome, tuple) or len(outcome) != 2:
        raise allocator.RefillUnsupported("fstat requires explicit kernel result and stat bytes")
    status, data = outcome
    status = _kernel(status)
    flags, size = 0x800, 1024
    if status < 0:
        _errno(p, thread_pointer, -status)
    else:
        if status or not isinstance(data, bytes) or len(data) != 128:
            raise allocator.RefillUnsupported("fstat requires matching 128-byte ABI")
        mode = int.from_bytes(data[16:20], "little") & 0xF000
        if mode == 0x2000:
            raise allocator.RefillUnsupported("character-file isatty/ioctl is unrecovered")
        block_size = int.from_bytes(data[56:60], "little", signed=True)
        if block_size:
            if block_size < 0 or block_size > 14335:
                raise allocator.RefillUnsupported("file block size outside bounded small allocation")
            size = block_size
            _w(p, file_address + 0x88, size, 4)
            if mode == 0x8000: flags = 0x400
    pointer = _public_small(tx, request_size=size, libc_base=libc_base,
        thread_pointer=thread_pointer, os_call=os_call)
    if pointer:
        _w(p, file_address, pointer)
        _w(p, file_address + 0x18, pointer)
        _w(p, file_address + 0x20, size)
        _w(p, file_address + 0x10, _u(p, file_address + 0x10, 4) | flags | 0x80, 4)
    else:
        pointer = file_address + 0x77
        _w(p, file_address, pointer)
        _w(p, file_address + 0x18, pointer)
        _w(p, file_address + 0x20, 1)
        _w(p, file_address + 0x10, _u(p, file_address + 0x10, 4) | 2, 4)


def create_readonly_stdio_buffer(guest_os, *, file_address, libc_base, thread_pointer, os_call):
    """Initialize an actual malloc-backed FILE buffer; no file read is supplied."""
    tx = guest_os.begin()
    _create_readonly_buffer(tx, file_address=file_address, libc_base=libc_base,
        thread_pointer=thread_pointer, os_call=os_call)
    tx.commit()
