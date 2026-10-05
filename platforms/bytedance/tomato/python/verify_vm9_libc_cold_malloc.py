"""Real native malloc cold boot with synthetic OS inputs, no malloc hooks.

This proves the matching binary under bounded virtual OS services. It does
not implement Python malloc, read a host /proc file, or produce Medusa headers.
"""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
    UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X30,
    UC_ARM64_REG_TPIDR_EL0)
import vm9_allocator as allocator
import verify_vm9_root_configuration as root
from verify_vm9_thread_key_cleanup import fresh, TABLE, WORKER_TLS
from verify_vm9_pthread_exit import inputs
from verify_vm9_signer_objects import native, LIBRARY_SHA256, STOP
from verify_vm9_libc_mapping import LIBC_SHA256, REGS

ENTRY = root.LIBC_BASE + 0x1BB08
PHASES = {0x8F00C, 0x8E350, 0x8E250, 0x7DC7C, 0x7F13C, 0x89410,
          0x7CF2C, 0x99378, 0x99938, 0x933AC, 0x99C78}
ALLOCATION_PATH = {0x1BB08, 0x8DF44, 0x79FA4, 0x787DC, 0x7A3C8,
                   0x2669C, 0x67374, 0x99C78, 0x75D44, 0x7779C,
                   0x765B0, 0x772B0, 0x7ED7C, 0x7E14C, 0x7DD70}


def cstring(cpu, address, limit=255):
    data = bytearray()
    for i in range(limit):
        value = bytes(cpu.mem_read(address + i, 1))
        if value == b"\0":
            return bytes(data)
        data.extend(value)
    raise allocator.RefillUnsupported("unbounded native OS string")


def cold_case(library, libc, base, size, cpus, *, naming_failure=False):
    seed = fresh(library, libc, base)
    os = allocator.GuestOS(seed)
    counters = Counter()
    phases = Counter()
    allocation_path = []
    initial = [False]
    snapshot = {}
    file_cursor = [0]
    file_open = [False]
    contents = b"cpu 0 0 0 0 0 0 0 0 0 0\n" + b"".join(
        ("cpu%d 0 0 0 0 0 0 0 0 0 0\n" % i).encode("ascii") for i in range(cpus))

    def read(cpu, address, width=8):
        return int.from_bytes(cpu.mem_read(address, width), "little")

    def observe(cpu, pc):
        if pc == ENTRY and not initial[0]:
            # The initial fixture has inactive keys. Preserve all keys later
            # created by cold boot and reentrant malloc; never reset on reentry.
            cpu.mem_write(TABLE, allocator._read_span(seed, TABLE, 141 * 16))
            assert read(cpu, root.LIBC_BASE + 0xDB6A0, 4) == 3
            initial[0] = True
        offset = pc - root.LIBC_BASE
        if offset in PHASES:
            phases[offset] += 1
        if offset in ALLOCATION_PATH:
            event = {"entry_offset": hex(offset)}
            if offset in (0x1BB08, 0x8DF44):
                event["request_size"] = cpu.reg_read(UC_ARM64_REG_X0)
            elif offset in (0x79FA4, 0x7A3C8):
                event["request_size"] = cpu.reg_read(UC_ARM64_REG_X1)
            allocation_path.append(event)
        if offset == 0x1BB24 and cpu.reg_read(UC_ARM64_REG_X30) == STOP:
            pointer = cpu.reg_read(UC_ARM64_REG_X0)
            record = os.mapping_for(pointer)
            assert pointer and record is not None and pointer + max(size, 1) <= record.end
            # A cold small allocation can span more than the requested bytes;
            # prove the returned request span is readable in its owned mapping.
            cpu.mem_read(pointer, max(size, 1))
            snapshot.update(flag=read(cpu, root.LIBC_BASE + 0xDB6A0, 4),
                arena_count=read(cpu, root.LIBC_BASE + 0xE6960, 4),
                arena_limit=read(cpu, root.LIBC_BASE + 0xE6970, 4),
                cpu_count=read(cpu, root.LIBC_BASE + 0xE9F44, 4),
                arena_zero=read(cpu, root.LIBC_BASE + 0xE6968),
                arena_table=read(cpu, root.LIBC_BASE + 0xE69D0),
                chunk_size=read(cpu, root.LIBC_BASE + 0xE9F38),
                lg_chunk=read(cpu, root.LIBC_BASE + 0xDB668),
                errno=read(cpu, WORKER_TLS + 0x10, 4))
            snapshot['first_arena'] = read(cpu, snapshot['arena_table'])

    def syscall(cpu, number):
        counters[number] += 1
        fields = [cpu.reg_read(reg) for reg in REGS]
        if number == 214:
            if fields[0] != 0:
                raise allocator.RefillUnsupported("program-break mutation is not supplied by this probe")
            return 0x13600000
        if number == 222:
            address, length, prot, flags, fd, offset = fields
            if address or offset:
                raise allocator.RefillUnsupported("unknown cold malloc mmap ABI")
            record = os.map_anonymous(length, prot=prot, flags=flags, fd=fd, anonymous_name=b"")
            cpu.mem_map(record.base, record.length)
            return record.base
        if number == 167:
            if fields[:2] != [0x53564D41, 0] or cstring(cpu, fields[4]) != b"libc_malloc":
                raise allocator.RefillUnsupported("unknown cold malloc prctl")
            if naming_failure:
                return -22
            os.name_exact(fields[2], fields[3], b"libc_malloc")
            return 0
        if number == 226:
            address, length, prot = fields[:3]
            tx = os.begin()
            tx.protect_exact(address, length, prot)
            cpu.mem_protect(address, length, prot)
            tx.commit()
            return 0
        if number == 215:
            tx = os.begin()
            tx.unmap_range(*fields[:2])
            cpu.mem_unmap(*fields[:2])
            tx.commit()
            return 0
        if number == 56:
            if (fields[0] != 0xFFFFFF9C or fields[2:4] != [524288, 0]
                    or cstring(cpu, fields[1]) != b"/proc/stat" or file_open[0]):
                raise allocator.RefillUnsupported("unknown cold malloc openat")
            file_cursor[0] = 0
            file_open[0] = True
            return 53
        if number not in (80, 63, 57) or fields[0] != 53 or not file_open[0]:
            raise allocator.RefillUnsupported("unknown cold malloc OS operation")
        if number == 80:
            stat = bytearray(128)
            stat[16:20] = (0x8124).to_bytes(4, "little")
            stat[20:24] = (1).to_bytes(4, "little")
            stat[48:56] = len(contents).to_bytes(8, "little")
            stat[56:60] = (4096).to_bytes(4, "little")
            stat[64:72] = (1).to_bytes(8, "little")
            cpu.mem_write(fields[1], bytes(stat))
            return 0
        if number == 57:
            file_open[0] = False
            return 0
        data = contents[file_cursor[0]:file_cursor[0] + fields[2]]
        cpu.mem_write(fields[1], data)
        file_cursor[0] += len(data)
        return len(data)

    result, _, allocations, ledger = native(library, base, ENTRY - base, [size], inputs(seed),
        libc=libc, real_mutexes=True, instruction_observer=observe, syscall_handler=syscall,
        extra_registers={UC_ARM64_REG_TPIDR_EL0: WORKER_TLS}, instruction_limit=200000)
    assert result and not allocations and not ledger
    assert snapshot and snapshot['flag'] == 0 and not file_open[0]
    assert 0 < snapshot['arena_count'] <= snapshot['arena_limit']
    assert snapshot['cpu_count'] == cpus
    assert snapshot['first_arena'] == snapshot['arena_zero'] and snapshot['arena_zero']
    assert snapshot['chunk_size'] == 1 << snapshot['lg_chunk']
    assert phases[0x8E250] == 1 and phases[0x8F00C] >= 2
    assert phases[0x99C78] == 1
    assert snapshot['errno'] == (22 if naming_failure else 37)
    return dict(case="anonymous_name_failure" if naming_failure else "cold_malloc", image_base=hex(base),
        request_size=size, synthetic_cpu_count=cpus, returned_request_span_owned_and_readable=True,
        initialization_flag_zero=True, arena_zero_and_table_published=True,
        chunk_constants_consistent=True, native_reentrant_malloc_entries=phases[0x8F00C],
        initial_key_fixture_applied_once=True, kernel_errno_preserved=True,
        phase_entries={hex(k): v for k, v in sorted(phases.items())},
        syscall_counts={str(k): v for k, v in sorted(counters.items())},
        surviving_owned_mappings=len(os.mappings), malloc_hook_calls=0,
        actual_allocation_entry_trace=allocation_path,
        native_input_snapshot_used=False, explicit_virtual_os=True,
        python_malloc_cold_boot_complete=False, fresh_medusa_signature_generated=False)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--library", type=Path, required=True)
    ap.add_argument("--libc", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest() == LIBC_SHA256
    cases = []
    for base in (0x122C0000, 0x775C205000):
        for size, cpus in ((0, 1), (32, 2), (4096, 4), (8192, 2)):
            cases.append(cold_case(args.library, args.libc, base, size, cpus))
            print("cold malloc", hex(base), size, cpus, "PASS", flush=True)
        cases.append(cold_case(args.library, args.libc, base, 32, 2, naming_failure=True))
        print("cold malloc", hex(base), "naming failure PASS", flush=True)
    report = dict(schema="vm9-native-libc-cold-malloc-v1", sample_sha256=LIBRARY_SHA256,
        libc_sha256=LIBC_SHA256, cases=cases, native_malloc_cold_boot_under_virtual_os=True,
        python_malloc_cold_boot_complete=False, standalone_medusa_complete=False,
        current_online_header_matrix_verified=False)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(dict(cold_malloc=len(cases))))


if __name__ == "__main__":
    main()
