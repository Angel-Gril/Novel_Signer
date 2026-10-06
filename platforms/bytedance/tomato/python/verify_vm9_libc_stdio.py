"""Fresh ELF/native controls for matching libc stdio and default cold return.

Component controls use an explicit +0x8e41c caller continuation. Cold/public
malloc controls execute the actual default initializer to its natural return;
they never patch the frontier or ready flag. Python binds __sF and the CPU
stack guard from ELF definitions, never from native output.
"""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X30, UC_ARM64_REG_PC, UC_ARM64_REG_TPIDR_EL0
import vm9_allocator as allocator
import vm9_libc_base as base_model
import vm9_libc_stdio as model
import vm9_libc_file as file_model
from verify_vm9_thread_key_cleanup import fresh, TABLE, WORKER_TLS
from verify_vm9_pthread_exit import inputs
from verify_vm9_signer_objects import native, GUEST, STOP, LIBRARY_SHA256
from verify_vm9_libc_mapping import LIBC_SHA256, REGS
from verify_vm9_libc_cold_malloc import cstring
from verify_vm9_libc_arena_boot import LIBC, put, get

CONTINUE = GUEST + 0xF720
ENTRIES = {0x8E250, 0x8E350, 0x74868, 0x749DC, 0x75550, 0x68C8C,
    0x68CF8, 0x68D5C, 0x68890, 0x57CD8, 0x5786C, 0x56C78, 0x1F86C, 0x1F8F0, 0x597B8, 0x5986C, 0x1BB08, 0x8F00C, 0x573E4, 0x5A960, 0x75090, 0x1BAC0, 0x91990, 0x2669C, 0x67374, 0x99C78, 0x933AC, 0x8E41C, 0x8E51C, 0x8DF44, 0x8E0EC, 0x7D998, 0x1BDD0}
CASE_LABELS = (
    "init", "init_twice", "acquire", "acquire_twice", "acquire_all17",
    "extension_padding", "file_core", "cleanup_fresh", "cleanup_twice", "cleanup_replace",
    "cleanup_chain", "init_mmap_failure", "cleanup_mmap_failure", "init_ro_failure",
    "cleanup_ro_failure", "cleanup_rw_failure", "cleanup_retry", "recursive_mutex",
    "recursive_mutex_cross_page",
)

LOCK_CASE_LABELS = ("lock_once", "lock_depth", "lock_overflow", "unlock_once", "unlock_depth", "unlock_wrong_owner", "unlock_idle")
FILE_CASE_LABELS = ("open", "open_twice", "open_close", "open_reuse", "close_twice",
    "open_failure", "open_fd_zero", "open_fd_limit", "open_fd_overflow", "open_fd_overflow_close_failure",
    "close_failure", "close_eintr", "mode_binary", "mode_cloexec", "mode_exclusive_ignored", "mode_invalid",
    "file_nested_lock", "file_lock_disabled", "buffer_regular", "buffer_block1k", "buffer_block8k", "buffer_stat_failure", "buffer_zero_block", "buffer_malloc_failure")

FRESH_MALLOC_CASE_LABELS = ("fresh_zero","fresh_128","fresh_4096","fresh_14336","fresh_repeat")


def fresh_requests(label):
    return {"fresh_zero":[0],"fresh_128":[128],"fresh_4096":[4096],"fresh_14336":[14336],"fresh_repeat":[128,48,4096,14336]}.get(label,[])


COLD_CASE_LABELS = ("cold_one", "cold_two", "cold_eight", "cold_empty", "cold_open_failure",
    "cold_read_failure", "cold_short_reads", "cold_eintr")


CPU_CASE_LABELS = ("cpu_one", "cpu_two", "cpu_eight", "cpu_empty", "cpu_open_failure", "cpu_read_failure",
    "cpu_short_reads", "cpu_eintr", "cpu_nonmatching", "cpu_decimal_sign", "cpu_overflow32", "cpu_overflow64")


STREAM_CASE_LABELS = ("stream_lines", "stream_last_line", "stream_empty", "stream_crlf", "stream_nul",
    "stream_short_reads", "stream_long_line", "stream_size_one", "stream_size_zero", "stream_size_negative",
    "stream_truncation", "stream_eintr", "stream_two_eintr", "stream_read_error", "stream_error_partial",
    "stream_error_retry", "stream_eof_twice", "stream_offset_wrap", "stream_prebuffer",
    "stream_nested_lock", "stream_no_lock", "stream_close_error", "stream_close_eintr")


def stream_spec(label):
    contents, sizes = b"alpha\nbeta\n", [256, 256, 256]
    if label == "stream_last_line": contents, sizes = b"alpha\nbeta", [256,256,256]
    if label == "stream_empty": contents, sizes = b"", [256,256]
    if label == "stream_crlf": contents = b"alpha\r\nbeta\r\n"
    if label == "stream_nul": contents = b"a\0b\nnext\n"
    if label == "stream_long_line": contents, sizes = b"x"*600+b"\nlast\n", [128]*8
    if label == "stream_size_one": sizes = [1,256,256,256]
    if label == "stream_size_zero": sizes = [0,256,256,256]
    if label == "stream_size_negative": sizes = [-2,256,256,256]
    if label == "stream_truncation": sizes = [4]*6
    if label == "stream_error_partial": contents, sizes = b"abcdef", [256,256]
    if label == "stream_error_retry": sizes = [256,256,256,256]
    if label == "stream_eof_twice": contents,sizes = b"only\n", [256,256,256]
    if label == "stream_offset_wrap": contents,sizes = b"abc\n", [256,256]
    return contents,sizes


def stream_read(label, cursor, calls, size):
    contents, _ = stream_spec(label)
    calls[0] += 1
    if label == "stream_eintr" and calls[0] == 1 or label == "stream_two_eintr" and calls[0] <= 2:
        return (-4, None)
    if label == "stream_read_error" or label == "stream_error_partial" and calls[0] >= 2 or label == "stream_error_retry" and calls[0] == 1:
        return (-5,None)
    limit = 3 if label in ("stream_short_reads", "stream_error_partial") else size
    data = contents[cursor[0]:cursor[0]+min(size,limit)]
    cursor[0] += len(data)
    return (len(data), data)


def cpu_contents(label):
    if label.startswith("cold_"):label="cpu_"+label[5:]
    if label=="cpu_empty":return b""
    if label=="cpu_nonmatching":return b"cpu 0 0\ncpu0 0\ncpu1x 0\nCpu2 0\nfoo 0\ncpu3\ncpu4 0\n"
    if label=="cpu_decimal_sign":return b"cpu+0 0\ncpu-1 0\ncpu\t2 0\ncpuq 0\n"
    if label=="cpu_overflow32":return b"cpu4294967296 0\n"
    if label=="cpu_overflow64":return b"cpu184467440737095516160 0\n"
    count={"cpu_one":1,"cpu_eight":8}.get(label,2)
    return b"cpu 0 0 0\n"+b"".join(("cpu%d 0 0\n"%i).encode("ascii") for i in range(count))


def cpu_read(label,cursor,calls,size):
    if label.startswith("cold_"):label="cpu_"+label[5:]
    calls[0]+=1
    if label=="cpu_read_failure":return (-5,None)
    if label=="cpu_eintr" and calls[0]==1:return (-4,None)
    contents=cpu_contents(label)
    size=min(size,3) if label=="cpu_short_reads" else size
    data=contents[cursor[0]:cursor[0]+size];cursor[0]+=len(data)
    return (len(data),data)


def cpu_fresh(library,libc,image):
    p=stdio_fresh(library,libc,image);bound=[]
    with libc.open("rb") as stream:
        elf=ELFFile(stream)
        for sec in elf.iter_sections():
            if sec["sh_type"]!="SHT_RELA":continue
            symbols=elf.get_section(sec["sh_link"])
            for r in sec.iter_relocations():
                if r["r_offset"]!=0xD8DC8:continue
                symbol=symbols.get_symbol(r["r_info_sym"])
                assert r["r_info_type"]==1025 and symbol.name=="__stack_chk_guard" and symbol["st_value"]==0xDE888 and r["r_addend"]==0
                put(p,LIBC+0xD8DC8,LIBC+symbol["st_value"]);bound.append(r["r_offset"])
    assert bound==[0xD8DC8]
    return p


def file_mode(label):
    if label in CPU_CASE_LABELS+COLD_CASE_LABELS+FRESH_MALLOC_CASE_LABELS:return b"re"
    return {"mode_binary": b"rb", "mode_cloexec": b"re", "mode_exclusive_ignored": b"rx", "mode_invalid": b"x"}.get(label, b"r")


def stdio_fresh(library, libc, image):
    p = fresh(library, libc, image)
    bound = {}
    expected = {0xD8F00: (1025, 0), 0xDB418: (257, 0), 0xDB4B0: (257, 0x98),
        0xDB548: (257, 0x130), 0xDB608: (257, 0), 0xDB610: (257, 0x98), 0xDB648: (257, 0)}
    with libc.open("rb") as stream:
        elf = ELFFile(stream)
        for section in elf.iter_sections():
            if section["sh_type"] != "SHT_RELA":
                continue
            symbols = elf.get_section(section["sh_link"])
            for relocation in section.iter_relocations():
                offset, kind = relocation["r_offset"], relocation["r_info_type"]
                if offset not in expected:
                    continue
                symbol = symbols.get_symbol(relocation["r_info_sym"])
                assert symbol.name == "__sF" and symbol["st_shndx"] != "SHN_UNDEF"
                assert (kind, relocation["r_addend"]) == expected[offset]
                assert symbol["st_value"] == 0xDB3E8
                value = LIBC + symbol["st_value"] + relocation["r_addend"]
                put(p, LIBC + offset, value)
                bound[offset] = value
    assert set(bound) == set(expected)
    return p


def observed_spans():
    return {(LIBC + 0xE67B8, 0x370): None, (LIBC + 0xE9110, 0xE60): None,
        (LIBC + 0xDB650, 0xF0): None, (LIBC + 0xDE840, 8): None,
        (WORKER_TLS, 0xB00): None, (TABLE, 141 * 16): None,
        (LIBC + 0xDB3E8, 0x268): None, (LIBC + 0xD8F00, 8): None,
        (LIBC + 0xE5400, 0x13B8): None, (LIBC + 0xDE9B8, 40): None,
        (LIBC + 0xE9108, 4): None}


def prepare(label, read, write, guest_os, map_cpu=None):
    if label == "buffer_zero_block": write(LIBC + 0xE5BB8 + 0x88, (0xA5A5A5A5).to_bytes(4, "little"))
    if label in STREAM_CASE_LABELS:
        write(GUEST + 0x5000, bytes([0xA5])*0x2000)
        if label == "stream_offset_wrap": write(LIBC+0xE5BB8+0x90,((1<<64)-3).to_bytes(8,"little"))
    if label in FILE_CASE_LABELS or label in STREAM_CASE_LABELS:
        write(GUEST + 0x4000, b"/proc/stat\0")
        write(GUEST + 0x4100, file_mode(label) + b"\0")
    if label in LOCK_CASE_LABELS:
        address = GUEST + 0x1000
        state, owner = {"lock_overflow": (0x5FFD, 137), "unlock_once": (0x4001, 137),
            "unlock_depth": (0x4009, 137), "unlock_wrong_owner": (0x4001, 138)}.get(label, (0x4000, 0))
        write(address, state.to_bytes(2, "little") + bytes([0xA5, 0xA5]) + owner.to_bytes(4, "little") + bytes(32))
    if label == "extension_padding":
        for address, count in ((LIBC + 0xE6668, 3), (LIBC + 0xE54D0, 17)):
            write(address, bytes([0xA5]) * (count * 0x68))
    if label == "file_core":
        address = LIBC + 0xE5BB8
        write(address, bytes([0xA5]) * 0x98)
        write(address + 0x10, bytes(4))
        write(address + 0x58, (LIBC + 0xE54D0).to_bytes(8, "little"))
    if label == "cleanup_chain":
        first = guest_os.map_anonymous(4096, anonymous_name=b"")
        second = guest_os.map_anonymous(4096, anonymous_name=b"")
        if map_cpu:
            map_cpu(first); map_cpu(second)
        write(first.base, second.base.to_bytes(8, "little"))
        write(first.base + 8, (1).to_bytes(4, "little") + (170).to_bytes(4, "little"))
        write(first.base + 0x10, (LIBC + 0x7485C).to_bytes(8, "little"))
        write(second.base + 8, (1).to_bytes(4, "little") + (170).to_bytes(4, "little"))
        write(LIBC + 0xE67A8, first.base.to_bytes(8, "little"))
    if label.startswith("recursive_mutex"):
        address = GUEST + (0x1FF0 if label.endswith("cross_page") else 0x1000)
        write(address - 8, bytes([0xA5]) * 56)
        write(GUEST + 0x3000, (1).to_bytes(8, "little"))


def actions_for(label):
    if label in FRESH_MALLOC_CASE_LABELS:return [("fresh_malloc",size) for size in fresh_requests(label)]
    if label in COLD_CASE_LABELS:return [("cold_init",0)]
    if label in CPU_CASE_LABELS:return [("cpu_query",0)]
    if label in STREAM_CASE_LABELS:
        _,sizes = stream_spec(label)
        actions=[("open",0)]
        if label=="stream_prebuffer": actions.append(("buffer",("result",0)))
        if label=="stream_nested_lock": actions.append(("flock",("result",0)))
        actions.extend(("fgets",("result",0)) for _ in sizes)
        actions.append(("stream_close",("result",0)))
        if label=="stream_nested_lock": actions.append(("funlock",("result",0)))
        return actions
    if label in LOCK_CASE_LABELS:
        if label == "lock_depth": return [("lock", GUEST + 0x1000)] * 3 + [("unlock", GUEST + 0x1000)] * 3
        if label == "unlock_depth": return [("unlock", GUEST + 0x1000)] * 3
        return [("unlock" if label.startswith("unlock") else "lock", GUEST + 0x1000)]
    if label in FILE_CASE_LABELS:
        if label.startswith("buffer_"): return [("open", 0), ("buffer", ("result", 0))]
        if label == "open_twice": return [("open", 0)] * 2
        if label == "open_reuse": return [("open", 0), ("close", ("result", 0)), ("open", 0)]
        if label == "close_twice": return [("open", 0), ("close", ("result", 0)), ("close", ("result", 0))]
        if label == "file_nested_lock": return [("open", 0), ("flock", ("result", 0)), ("close", ("result", 0)), ("funlock", ("result", 0))]
        if label in ("open_close", "open_fd_zero", "open_fd_limit", "close_failure", "close_eintr", "file_lock_disabled"):
            return [("open", 0), ("close", ("result", 0))]
        return [("open", 0)]
    if label.startswith("recursive_mutex"):
        return [("mutex", GUEST + (0x1FF0 if label.endswith("cross_page") else 0x1000))]
    if label in ("acquire", "extension_padding", "file_core"):
        return [("acquire", 0)]
    if label == "acquire_twice": return [("acquire", 0)] * 2
    if label == "acquire_all17": return [("acquire", 0)] * 17
    if label == "init_twice": return [("init", 0)] * 2
    if label == "cleanup_retry": return [("init", 0), ("cleanup", LIBC + 0x7485C)]
    if label == "cleanup_replace": return [("init", 0), ("cleanup", GUEST + 0xF210)]
    if label in ("cleanup_twice", "cleanup_rw_failure"):
        return [("cleanup", LIBC + 0x7485C), ("cleanup", GUEST + 0xF210)]
    if label.startswith("cleanup_"): return [("cleanup", GUEST + 0xF210)]
    return [("init", 0)]


def case(library, libc, image, label):
    fresh_malloc=label in FRESH_MALLOC_CASE_LABELS
    natural=label in COLD_CASE_LABELS or fresh_malloc
    fresh_function=cpu_fresh if label in CPU_CASE_LABELS+COLD_CASE_LABELS+FRESH_MALLOC_CASE_LABELS else stdio_fresh
    p, seed = fresh_function(library, libc, image), fresh_function(library, libc, image)
    if label == "buffer_malloc_failure":
        for pages in (p, seed): put(pages, LIBC + 0xDB690, 0, 4)
    os, nos = allocator.GuestOS(p), allocator.GuestOS(seed)
    observed = observed_spans()
    if label in CPU_CASE_LABELS+COLD_CASE_LABELS+FRESH_MALLOC_CASE_LABELS:observed.update({(LIBC+0xD8DC8,8):None,(LIBC+0xDE888,8):None})
    if natural:observed.update({(LIBC+0xDB380,40):None,(LIBC+0xE01C0,16):None})
    counts = Counter()
    n_calls, m_calls, results = [], [], []
    n_maps, m_maps = [0], [0]
    n_opens, m_opens = [0], [0]
    n_cursor,m_cursor,n_reads,m_reads=[0],[0],[0],[0]
    n_lines,m_lines=[0],[0]
    actions = actions_for(label)
    pending = list(actions[1:] if fresh_malloc else actions)
    initialized_fixture = [False]

    def descriptor(opens):
        opens[0] += 1
        if label in ("open_failure","cpu_open_failure","cold_open_failure"): return -2
        if label == "open_fd_zero": return 0
        if label == "open_fd_limit": return 0x7FFF
        if label.startswith("open_fd_overflow"): return 0x8000
        return 52 + opens[0]

    def stat_result():
        if label == "buffer_stat_failure": return (-5, None)
        data = bytearray(128)
        data[16:20] = (0x8124).to_bytes(4, "little")
        size = {"buffer_block1k": 1024, "buffer_block8k": 8192, "buffer_zero_block": 0}.get(label, 4096)
        data[56:60] = size.to_bytes(4, "little")
        return (0, bytes(data))

    def close_result():
        return -5 if label in ("close_failure", "open_fd_overflow_close_failure", "stream_close_error") else -4 if label in ("close_eintr", "stream_close_eintr") else 0

    def map_failure(number):
        return (label in ("init_mmap_failure", "cleanup_mmap_failure", "cleanup_retry") and number == 2 or label == "buffer_malloc_failure" and number >= 3)

    def protect_failure(prot):
        return label in ("init_ro_failure", "cleanup_ro_failure") and prot == 1 or label == "cleanup_rw_failure" and prot == 3

    def map_cpu(cpu, record):
        cpu.mem_map(record.base, record.length)
        observed.update({(k << 12, 4096): None for k in range(record.base >> 12, record.end >> 12)})

    def syscall(cpu, number):
        fields = [cpu.reg_read(reg) for reg in REGS]
        if number == 214:
            assert fields[0] == 0
            n_calls.append(["brk", 0]); return 0x13600000
        if number == 222:
            n_calls.append(["mmap", *fields]); n_maps[0] += 1
            if map_failure(n_maps[0]): return -12
            assert fields[0] == 0 and fields[2:] == [3, 0x22, 0xFFFFFFFF, 0]
            record = nos.map_anonymous(fields[1], prot=3, flags=0x22, fd=0xFFFFFFFF, anonymous_name=b"")
            map_cpu(cpu, record)
            return record.base
        if number == 167:
            name = cstring(cpu, fields[4]); assert name == b"libc_malloc"
            n_calls.append(["prctl", *fields[:4], name])
            nos.name_exact(fields[2], fields[3], name); return 0
        if number == 56:
            path = cstring(cpu, fields[1])
            n_calls.append(["openat", fields[0], path, fields[2], fields[3]])
            assert fields[0] == 0xFFFFFF9C and path == b"/proc/stat" and fields[2:4] == [0x80000 if b"e" in file_mode(label) else 0, 0], (fields[:4], path)
            return descriptor(n_opens)
        if number == 63:
            n_calls.append(["read",fields[0],fields[2]])
            assert label in STREAM_CASE_LABELS or label in CPU_CASE_LABELS+COLD_CASE_LABELS+FRESH_MALLOC_CASE_LABELS
            fn=cpu_read if label in CPU_CASE_LABELS+COLD_CASE_LABELS+FRESH_MALLOC_CASE_LABELS else stream_read
            status,data=fn(label,n_cursor,n_reads,fields[2])
            if status>=0: cpu.mem_write(fields[1],data)
            return status
        if number == 80:
            n_calls.append(["fstat", fields[0]])
            status, data = stat_result()
            if not status: cpu.mem_write(fields[1], data)
            return status
        if number == 215:
            n_calls.append(["munmap", *fields[:2]])
            nos.unmap_range(*fields[:2]); cpu.mem_unmap(*fields[:2])
            for key in range(fields[0] >> 12, (fields[0] + fields[1]) >> 12): observed.pop((key << 12, 4096), None)
            return 0
        if number == 57:
            n_calls.append(["close", fields[0]])
            return close_result()
        assert number == 226, number
        n_calls.append(["mprotect", *fields[:3]])
        if protect_failure(fields[2]): return -13
        nos.protect_exact(*fields[:3]); cpu.mem_protect(*fields[:3]); return 0

    def os_call(tx, operation, *fields):
        m_calls.append([operation, *fields])
        if operation == "mmap":
            m_maps[0] += 1
            return -12 if map_failure(m_maps[0]) else tx.next_address
        if operation == "mprotect": return -13 if protect_failure(fields[2]) else 0
        if operation == "openat": return descriptor(m_opens)
        if operation == "close": return close_result()
        if operation == "fstat": return stat_result()
        if operation == "read": return (cpu_read if label in CPU_CASE_LABELS+COLD_CASE_LABELS+FRESH_MALLOC_CASE_LABELS else stream_read)(label,m_cursor,m_reads,fields[1])
        if operation == "munmap": return 0
        assert operation == "prctl"
        return 0

    def observe(cpu, pc):
        offset = pc - LIBC
        if offset in ENTRIES: counts[offset] += 1
        if offset == 0x8E250 and not initialized_fixture[0]:
            initialized_fixture[0] = True
            cpu.mem_write(TABLE, allocator._read_span(seed, TABLE, 141 * 16))
            if label == "buffer_malloc_failure": cpu.mem_write(LIBC + 0xDB690, bytes(4))

    def dispatch(cpu):
        if not pending:
            cpu.reg_write(UC_ARM64_REG_PC, STOP); return None
        op, value = pending.pop(0)
        if isinstance(value, tuple): value = results[value[1]]
        output,size=0,0
        if op=="fgets":
            _,sizes=stream_spec(label)
            output,size=GUEST+0x5000+n_lines[0]*0x100,sizes[n_lines[0]]
            n_lines[0]+=1
        offset, arguments = {"init": (0x74868, []), "acquire": (0x749DC, []),
            "cleanup": (0x75550, [value]), "mutex": (0x68C8C, [value, GUEST + 0x3000]),
            "lock": (0x68CF8, [value]), "unlock": (0x68D5C, [value]),
            "open": (0x57CD8, [GUEST + 0x4000, GUEST + 0x4100]), "close": (0x56C78, [value]),
            "flock": (0x1F86C, [value]), "funlock": (0x1F8F0, [value]), "buffer": (0x5986C, [value]), "fgets": (0x573E4,[output,size,value]), "stream_close": (0x56C78,[value]), "cpu_query":(0x2669C,[]), "fresh_malloc":(0x1BB08,[value])}[op]
        for reg, argument in zip(REGS, arguments): cpu.reg_write(reg, argument & ((1<<64)-1))
        cpu.reg_write(UC_ARM64_REG_X30, CONTINUE)
        cpu.reg_write(UC_ARM64_REG_PC, LIBC + offset)
        return None

    def cold_continuation(cpu):
        prepare(label, cpu.mem_read, cpu.mem_write, nos, lambda rec: map_cpu(cpu, rec))
        return dispatch(cpu)

    def continuation(cpu):
        results.append(cpu.reg_read(UC_ARM64_REG_X0))
        if label in ("file_lock_disabled", "stream_no_lock") and len(results) == 1:
            ext = int.from_bytes(cpu.mem_read(results[0] + 0x58, 8), "little")
            cpu.mem_write(ext + 0x60, bytes(1))
        return dispatch(cpu)

    native_result, memory, allocations, ledger = native(library, image, LIBC + (0x1BB08 if fresh_malloc else 0x8E350) - image,
        [fresh_requests(label)[0]] if fresh_malloc else [], inputs(seed), libc=libc, real_mutexes=True, instruction_observer=observe,
        syscall_handler=syscall, host_imports={CONTINUE-image:continuation} if fresh_malloc else {} if natural else {LIBC + 0x8E41C - image: cold_continuation,
            CONTINUE - image: continuation}, extra_registers={UC_ARM64_REG_TPIDR_EL0: WORKER_TLS,UC_ARM64_REG_X30:CONTINUE if fresh_malloc else STOP},
        observed_memory=observed, instruction_limit=300000)
    if natural and not fresh_malloc:results.append(native_result)
    assert not allocations and not ledger and len(results) == len(actions)
    if not natural:
        assert base_model.cold_init_until_cpu_query(os, libc_base=LIBC, thread_pointer=WORKER_TLS,
            brk=lambda *args: m_calls.append(["brk", 0]) or 0x13600000, os_call=os_call) == 0x8E41C
    prepare(label, lambda a,n: allocator._read_span(p,a,n), lambda a,b: allocator._write_span(p,a,b), os)
    actual = []
    for i, (op, value) in enumerate(actions):
        if isinstance(value, tuple): value = actual[value[1]]
        if op == "init":
            result = model.initialize_stdio(os, libc_base=LIBC, thread_pointer=WORKER_TLS, os_call=os_call)
        elif op == "acquire":
            result = model.acquire_stdio_file(os, libc_base=LIBC, thread_pointer=WORKER_TLS, os_call=os_call)
        elif op == "cleanup":
            result = model.register_stdio_cleanup(os, callback_address=value, libc_base=LIBC,
                thread_pointer=WORKER_TLS, os_call=os_call)
        elif op == "open":
            result = file_model.open_readonly_stdio_file(os, path=b"/proc/stat", mode=file_mode(label),
                libc_base=LIBC, thread_pointer=WORKER_TLS, os_call=os_call)
        elif op == "buffer":
            result = file_model.create_readonly_stdio_buffer(os, file_address=value,
                libc_base=LIBC, thread_pointer=WORKER_TLS, os_call=os_call)
        elif op == "fresh_malloc":
            cold_model=__import__("vm9_libc_cold")
            result=cold_model.allocate_default_small(os,request_size=value,scratch_address=GUEST+0xED98,
                libc_base=LIBC,thread_pointer=WORKER_TLS,
                brk=lambda *args:m_calls.append(["brk",0]) or 0x13600000,os_call=os_call)
        elif op == "cold_init":
            cold_model=__import__("vm9_libc_cold")
            result=cold_model.initialize_default_malloc(os,scratch_address=GUEST+0xED98,
                libc_base=LIBC,thread_pointer=WORKER_TLS,
                brk=lambda *args:m_calls.append(["brk",0]) or 0x13600000,os_call=os_call)
        elif op == "cpu_query":
            result=file_model.query_cpu_count(os,scratch_address=GUEST+0xEDB8,
                libc_base=LIBC,thread_pointer=WORKER_TLS,os_call=os_call)
        elif op == "fgets":
            _,sizes=stream_spec(label)
            output,size=GUEST+0x5000+m_lines[0]*0x100,sizes[m_lines[0]]
            m_lines[0]+=1
            result=file_model.fgets_stdio_line(os,file_address=value,output_address=output,size=size,
                libc_base=LIBC,thread_pointer=WORKER_TLS,os_call=os_call)
        elif op == "stream_close":
            result=file_model.close_readonly_stdio_file(os,file_address=value,
                libc_base=LIBC,thread_pointer=WORKER_TLS,os_call=os_call)
        elif op == "close":
            result = file_model.close_unbuffered_stdio_file(os, file_address=value,
                libc_base=LIBC, thread_pointer=WORKER_TLS, os_call=os_call)
        elif op in ("lock", "unlock", "flock", "funlock"):
            address = get(p, value + 0x58) + 0x38 if op in ("flock", "funlock") else value
            fn = model.lock_recursive_mutex if op in ("lock", "flock") else model.unlock_recursive_mutex
            result = fn(p, mutex_address=address, thread_pointer=WORKER_TLS)
        else:
            model.initialize_recursive_mutex(p, mutex_address=value); result = 0
        actual.append(result)
        if op in ("acquire", "mutex", "open", "fgets", "cpu_query", "cold_init", "fresh_malloc"): assert result == results[i], (label, "defined return", result, results[i])
        if op in ("lock", "unlock", "close", "stream_close"): assert result & 0xFFFFFFFF == results[i] & 0xFFFFFFFF, (label, "int return", result, results[i])
        if label in ("file_lock_disabled", "stream_no_lock") and i == 0: put(p, get(p, result + 0x58) + 0x60, 0, 1)
    assert n_cursor == m_cursor and n_reads == m_reads, (label,"read provider state")
    assert n_calls == m_calls, (label, "ordered OS calls", n_calls, m_calls)
    assert os.mappings == nos.mappings and os.next_address == nos.next_address, (label, "OS metadata")
    assert allocator._read_span(p, GUEST, 0xA000) == memory, (label, "guest objects")
    for (address, width), value in observed.items():
        data = allocator._read_span(p, address, width)
        if data != value:
            diffs = [(hex(address + i - LIBC), x, y) for i,(x,y) in enumerate(zip(data,value)) if x != y]
            raise AssertionError((label, "global/TLS/owned mapping mismatch", diffs[:16]))
    assert counts[0x8E250] == 1 and get(p, LIBC + 0xDB6A0, 4) == (0 if natural else 1)
    if label == "acquire_all17": assert actual == [LIBC + 0xE5BB8 + i * 0x98 for i in range(17)]
    if label == "cleanup_chain": assert get(p, get(p, LIBC + 0xE67A8) + 0x10) == LIBC + 0x7485C
    if natural:
        key=get(p,LIBC+0xE9F68,4)&0x7FFFFFFF
        dynamic=get(p,get(p,WORKER_TLS+8)+0xE8+key*16+8)
        assert dynamic and dynamic!=LIBC+0xDB6B8 and get(p,dynamic+0x44,1)==0
        assert counts[0x8E41C]==counts[0x8E51C]==counts[0x99C78]==1
    return dict(case=label, image_base=hex(image), same_fresh_cold_prefix_composed=True, natural_default_cold_return=natural,
        natural_ready_flag_zero=natural,static_to_dynamic_tsd_verified=natural,
        fresh_public_small_malloc_control=fresh_malloc,
        derived_cpu_count=get(p,LIBC+0xE9F44,4) if natural else actual[0] if label in CPU_CASE_LABELS else 0,
        defined_returns_stdio_globals_tls_guest_bytes_all_mapping_bytes_and_metadata_match=True,
        ordered_os_calls=len(m_calls), retained_owned_mappings=len(os.mappings),
        actual_entry_counts={hex(k):v for k,v in sorted(counts.items())},
        elf_defined_sF_relocations_bound=True, void_init_and_cleanup_returns_ignored=True,
        readonly_file_control=label in FILE_CASE_LABELS or label in STREAM_CASE_LABELS,
        readonly_stream_control=label in STREAM_CASE_LABELS, cpu_query_control=label in CPU_CASE_LABELS, recursive_lock_control=label in LOCK_CASE_LABELS,
        allocation_provider_used=False, native_input_snapshot_used=False, explicit_virtual_os=True,
        explicit_stdio_continuation=not natural, bounded_default_malloc_cold_boot_verified=natural,
        python_malloc_all_branches_complete=False)


def rejection_cases(library, libc):
    labels = ("init_mutex_busy", "pool_mutex_busy", "cleanup_mutex_busy", "unbound_sF",
        "glue_cycle", "glue_bad_count", "glue_unmapped", "dynamic_growth", "cleanup_foreign",
        "cleanup_cycle", "callback_negative", "callback_oversized", "late_provider_failure")
    rows = []
    for label in labels:
        p = stdio_fresh(library, libc, 0x122C0000)
        os = allocator.GuestOS(p)
        call = lambda tx,op,*args: tx.next_address if op == "mmap" else 0
        assert base_model.cold_init_until_cpu_query(os, libc_base=LIBC, thread_pointer=WORKER_TLS,
            brk=lambda *args: 0x13600000, os_call=call) == 0x8E41C
        op, callback, external = "init", LIBC + 0x7485C, []
        if label in ("pool_mutex_busy", "glue_cycle", "glue_bad_count", "glue_unmapped", "dynamic_growth"):
            model.initialize_stdio(os, libc_base=LIBC, thread_pointer=WORKER_TLS, os_call=call)
            op = "acquire"
        if label == "init_mutex_busy": put(p, LIBC + 0xDB618, 1, 4)
        if label == "pool_mutex_busy": put(p, LIBC + 0xDB5B0, 1, 4)
        if label == "cleanup_mutex_busy": put(p, LIBC + 0xDE9B8, 1, 4)
        if label == "unbound_sF": put(p, LIBC + 0xD8F00, 0)
        if label in ("glue_cycle", "dynamic_growth"):
            for i in range(17): put(p, LIBC + 0xE5BB8 + i * 0x98 + 0x10, 1, 4)
            if label == "glue_cycle": put(p, LIBC + 0xDB5E0, LIBC + 0xDB5F8)
        if label == "glue_bad_count": put(p, LIBC + 0xDB600, 65, 4)
        if label == "glue_unmapped": put(p, LIBC + 0xDB608, 0)
        if label == "cleanup_foreign": put(p, LIBC + 0xE67A8, GUEST + 0x1000)
        if label == "cleanup_cycle":
            record = os.map_anonymous(4096, anonymous_name=b"")
            put(p, record.base, record.base); put(p, LIBC + 0xE67A8, record.base)
        if label.startswith("callback_"):
            op = "cleanup"; callback = -1 if label == "callback_negative" else 1 << 64
        if label == "late_provider_failure":
            def call(tx, operation, *args):
                external.append(operation)
                if operation == "mprotect": raise allocator.RefillUnsupported("explicit late provider rejection")
                return tx.next_address
        before = {k:bytes(v) for k,v in p.items()}
        records, cursor = list(os.mappings), os.next_address
        try:
            if op == "init": model.initialize_stdio(os, libc_base=LIBC, thread_pointer=WORKER_TLS, os_call=call)
            elif op == "acquire": model.acquire_stdio_file(os, libc_base=LIBC, thread_pointer=WORKER_TLS, os_call=call)
            else: model.register_stdio_cleanup(os, callback_address=callback, libc_base=LIBC, thread_pointer=WORKER_TLS, os_call=call)
        except (allocator.RefillUnsupported, ValueError): pass
        else: raise AssertionError((label, "expected rejection"))
        assert before == {k:bytes(v) for k,v in p.items()} and records == os.mappings and cursor == os.next_address
        if label == "late_provider_failure": assert external == ["mmap", "mprotect"]
        rows.append(dict(case=label, rejected=True, guest_pages_records_and_cursor_unchanged=True,
            external_provider_effects_not_rolled_back=label == "late_provider_failure"))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--library", type=Path, required=True)
    ap.add_argument("--libc", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--case", action="append", choices=CASE_LABELS)
    args = ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest() == LIBC_SHA256
    rows = []
    for image in (0x122C0000, 0x775C205000):
        for label in args.case or CASE_LABELS:
            rows.append(case(args.library, args.libc, image, label))
            print("fresh libc stdio", hex(image), label, "PASS", flush=True)
    rejected = rejection_cases(args.library, args.libc)
    print("stdio rejection/rollback", len(rejected), "PASS", flush=True)
    report = dict(schema="vm9-libc-fresh-stdio-v1", sample_sha256=LIBRARY_SHA256, libc_sha256=LIBC_SHA256,
        cases=rows, rejection_cases=rejected, full_case_set_verified=set(args.case or CASE_LABELS) == set(CASE_LABELS),
        native_input_snapshot_used=False, static_stdio_constructors_restored=any(c["actual_entry_counts"].get("0x74868") for c in rows),
        dynamic_file_growth_restored=False, full_recursive_mutex_waiting_and_shared_paths_restored=False,
        file_os_and_cpu_parsing_restored=False, python_malloc_cold_boot_complete=False,
        standalone_medusa_complete=False, current_online_header_matrix_verified=False)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__": main()
