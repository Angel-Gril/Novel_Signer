"""Bounded matching-libc read-only FILE open, buffer constructor and close.

OS outcomes remain explicit. Clean readonly fgets/refill and cached-buffer
release are recovered. Write/update/append/seek, flush, ungetc, arbitrary
allocator release and dynamic FILE growth remain separate boundaries.
"""
from __future__ import annotations
import vm9_allocator as allocator
import vm9_libc_stdio as stdio
from vm9_libc_tcache import _public_small, _release_cached_small
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
    if flags and (flags != 4 or _u(p, file_address + 0x18) or _u(p, file_address + 0x78)):
        raise allocator.RefillUnsupported("unbuffered close requires fresh readonly FILE")
    return _close_readonly(tx, file_address=file_address, libc_base=libc_base,
        thread_pointer=thread_pointer, os_call=os_call)


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


def _read_callback(tx, *, file_address, buffer_address, count, libc_base, thread_pointer, os_call):
    """Actual +0x75090: retry EINTR and maintain FILE offset validity."""
    p = tx.pages
    if _u(p, file_address + 0x30) != file_address or _u(p, file_address + 0x40) != libc_base + 0x75090:
        raise allocator.RefillUnsupported("foreign FILE read callback is unrecovered")
    if not 1 <= count <= 14335:
        raise allocator.RefillUnsupported("read buffer size outside bounded small FILE policy")
    allocator._read_span(p, buffer_address, count)
    for _ in range(16):
        outcome = os_call(tx, "read", _u(p, file_address + 0x14, 4), count)
        if not isinstance(outcome, tuple) or len(outcome) != 2:
            raise allocator.RefillUnsupported("read requires explicit kernel status and bytes")
        status, data = outcome
        status = _kernel(status)
        if status < 0:
            _errno(p, thread_pointer, -status)
            if status == -4: continue
            _w(p, file_address + 0x10, _u(p, file_address + 0x10, 4) & ~0x1000, 4)
            return -1
        if status > count or not isinstance(data, bytes) or len(data) != status:
            raise allocator.RefillUnsupported("read bytes do not match bounded kernel outcome")
        allocator._write_span(p, buffer_address, data)
        _w(p, file_address + 0x90, (_u(p, file_address + 0x90) + status) & ((1<<64)-1))
        return status
    raise allocator.RefillUnsupported("read EINTR retry budget exhausted")


def _refill_readonly(tx, *, file_address, libc_base, thread_pointer, os_call):
    """Actual +0x5a960 clean read branch; flush/update/ungetc reject."""
    p = tx.pages
    if not _u(p, libc_base + 0xE9108, 4):
        stdio._initialize_stdio(tx, libc_base=libc_base, thread_pointer=thread_pointer, os_call=os_call)
    flags = _u(p, file_address + 0x10, 4)
    _w(p, file_address + 8, 0, 4)
    if flags & 0x20: return -1
    if not flags & 4:
        raise allocator.RefillUnsupported("non-read/update FILE refill is unrecovered")
    extension = _u(p, file_address + 0x58)
    if _u(p, extension):
        raise allocator.RefillUnsupported("ungetc restore/refill is unrecovered")
    if not _u(p, file_address + 0x18):
        _create_readonly_buffer(tx, file_address=file_address, libc_base=libc_base,
            thread_pointer=thread_pointer, os_call=os_call)
    flags = _u(p, file_address + 0x10, 4)
    if flags & 3:
        raise allocator.RefillUnsupported("line/unbuffered stdio flush traversal is unrecovered")
    pointer = _u(p, file_address + 0x18)
    count = _u(p, file_address + 0x20, 4)
    _w(p, file_address, pointer)
    read = _read_callback(tx, file_address=file_address, buffer_address=pointer, count=count,
        libc_base=libc_base, thread_pointer=thread_pointer, os_call=os_call)
    flags = _u(p, file_address + 0x10, 4) & ~0x2000
    if read > 0:
        _w(p, file_address + 8, read, 4)
        _w(p, file_address + 0x10, flags, 4)
        return 0
    _w(p, file_address + 0x10, flags | (0x20 if read == 0 else 0x40), 4)
    _w(p, file_address + 8, 0, 4)
    return -1


def _fgets(tx, *, file_address, output_address, size, libc_base, thread_pointer, os_call):
    """Actual +0x573e4 byte-oriented line/truncation/partial-error behavior."""
    p = tx.pages
    if not isinstance(size, int) or not -(1<<31) <= size < (1<<31):
        raise allocator.RefillUnsupported("fgets size outside signed32 ABI")
    if size <= 0:
        _errno(p, thread_pointer, 22)
        return 0
    if size > 65536:
        raise allocator.RefillUnsupported("fgets caller output exceeds bounded policy")
    allocator._read_span(p, output_address, size)
    extension = _u(p, file_address + 0x58)
    locking = _u(p, extension + 0x60, 1)
    if locking:
        stdio.lock_recursive_mutex(p, mutex_address=extension + 0x38, thread_pointer=thread_pointer)
    if not _u(p, extension + 0x30, 4): _w(p, extension + 0x30, 0xFFFFFFFF, 4)
    used, remaining, result = 0, size - 1, output_address
    while remaining:
        available = _u(p, file_address + 8, 4)
        if available > 0x7FFFFFFF:
            raise allocator.RefillUnsupported("corrupt negative FILE read count")
        if not available:
            if _refill_readonly(tx, file_address=file_address, libc_base=libc_base,
                    thread_pointer=thread_pointer, os_call=os_call):
                if not used: result = 0
                break
            available = _u(p, file_address + 8, 4)
        width = min(available, remaining)
        source = _u(p, file_address)
        data = allocator._read_span(p, source, width)
        newline = data.find(b"\n")
        if newline >= 0: data = data[:newline + 1]
        copied = len(data)
        if not copied: raise allocator.RefillUnsupported("zero-progress FILE refill")
        allocator._write_span(p, output_address + used, data)
        _w(p, file_address, source + copied)
        _w(p, file_address + 8, available - copied, 4)
        used += copied; remaining -= copied
        if newline >= 0: break
    if result: _w(p, output_address + used, 0, 1)
    if locking:
        stdio.unlock_recursive_mutex(p, mutex_address=extension + 0x38, thread_pointer=thread_pointer)
    return result


def fgets_stdio_line(guest_os, *, file_address, output_address, size, libc_base, thread_pointer, os_call):
    tx = guest_os.begin()
    result = _fgets(tx, file_address=file_address, output_address=output_address, size=size,
        libc_base=libc_base, thread_pointer=thread_pointer, os_call=os_call)
    tx.commit()
    return result


def _close_readonly(tx, *, file_address, libc_base, thread_pointer, os_call):
    """Actual +0x56c78 clean readonly close with actual cached-small free."""
    p = tx.pages
    flags = _u(p, file_address + 0x10, 4)
    if not flags:
        _errno(p, thread_pointer, 9)
        return -1
    allowed = 4 | 0x20 | 0x40 | 0x80 | 0x400 | 0x800 | 0x1000 | 0x2000
    if not flags & 4 or flags & ~allowed or _u(p, file_address + 0x78):
        raise allocator.RefillUnsupported("write/auxiliary/inline-buffer fclose is unrecovered")
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
    if flags & 0x80:
        _release_cached_small(tx, pointer=_u(p, file_address + 0x18), libc_base=libc_base, thread_pointer=thread_pointer)
    _w(p, file_address + 0xC, 0, 4)
    _w(p, file_address + 8, 0, 4)
    _w(p, file_address + 0x10, 0, 4)
    if locking:
        stdio.unlock_recursive_mutex(p, mutex_address=extension + 0x38, thread_pointer=thread_pointer)
    return result


def close_readonly_stdio_file(guest_os, *, file_address, libc_base, thread_pointer, os_call):
    tx = guest_os.begin()
    result = _close_readonly(tx, file_address=file_address, libc_base=libc_base,
        thread_pointer=thread_pointer, os_call=os_call)
    tx.commit()
    return result


def _elf_string(pages, address, limit=64):
    data = bytearray()
    for i in range(limit):
        byte = _u(pages, address + i, 1)
        if not byte: return bytes(data)
        data.append(byte)
    raise allocator.RefillUnsupported("unbounded matching-libc string")


def _cpu_scan_countable(pages, line, thread_pointer):
    """Observed cpu%u%c lexical/conversion-count subset, not general scanf."""
    if not line.startswith(b"cpu"): return False
    i = 3
    while i < len(line) and line[i] in b" \t\n\r\v\f": i += 1
    if i < len(line) and line[i] in b"+-": i += 1
    start, value = i, 0
    while i < len(line) and 48 <= line[i] <= 57:
        value = value * 10 + line[i] - 48
        i += 1
    if i == start: return False
    if value > (1<<64)-1: _errno(pages, thread_pointer, 34)
    # %c reads the next byte without whitespace skipping. A trailing byte
    # produces two conversions and does not count as a cpuN row.
    return i == len(line)


def _get_nprocs(tx, *, scratch_address, libc_base, thread_pointer, os_call):
    """Actual +0x2669c FILE loop and cpu%u%c conversion-count decision."""
    p = tx.pages
    guard_address = _u(p, libc_base + 0xD8DC8)
    if not guard_address:
        raise allocator.RefillUnsupported("CPU query stack-guard ELF binding is unresolved")
    guard = _u(p, guard_address)
    path = _elf_string(p, libc_base + 0x9DEB0)
    mode = _elf_string(p, libc_base + 0xA2C10)
    if _elf_string(p, libc_base + 0x9DEA8) != b"cpu%u%c" or path != b"/proc/stat" or mode != b"re":
        raise allocator.RefillUnsupported("matching CPU query format/path/mode changed")
    file = _open_readonly(tx, path=path, mode=mode, libc_base=libc_base,
        thread_pointer=thread_pointer, os_call=os_call)
    count = 1
    if file:
        count = 0
        for _ in range(16384):
            result = _fgets(tx, file_address=file, output_address=scratch_address, size=256,
                libc_base=libc_base, thread_pointer=thread_pointer, os_call=os_call)
            if not result: break
            data = allocator._read_span(p, scratch_address, 256)
            space = data.find(b" ")
            if space >= 0: _w(p, scratch_address + space, 0, 1)
            line = allocator._read_span(p, scratch_address, 256).split(b"\0", 1)[0]
            if _cpu_scan_countable(p, line, thread_pointer): count += 1
        else:
            raise allocator.RefillUnsupported("CPU query line budget exhausted")
        _close_readonly(tx, file_address=file, libc_base=libc_base,
            thread_pointer=thread_pointer, os_call=os_call)
    if _u(p, guard_address) != guard:
        raise allocator.RefillUnsupported("CPU query stack-check failure branch is unrecovered")
    return count


def query_cpu_count(guest_os, *, scratch_address, libc_base, thread_pointer, os_call):
    """Read supplied proc bytes through actual FILE and allocator bodies."""
    tx = guest_os.begin()
    result = _get_nprocs(tx, scratch_address=scratch_address, libc_base=libc_base,
        thread_pointer=thread_pointer, os_call=os_call)
    tx.commit()
    return result
