"""Bounded native root configuration oracle from fresh ELF inputs.

The native constructor executes in Unicorn. This is not a Python replacement
for it. Files, properties, clock and destructor registration are explicit
virtual-environment boundaries; no host file or network operation is performed.
Only counts and offsets are exported. Private decoded strings stay in memory.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

from elftools.elf.elffile import ELFFile
from unicorn.arm64_const import (
    UC_ARM64_REG_PC, UC_ARM64_REG_SP, UC_ARM64_REG_X0, UC_ARM64_REG_X1,
    UC_ARM64_REG_X2, UC_ARM64_REG_X8, UC_ARM64_REG_TPIDR_EL0,
)

import vm9_objects as objects
from vm9_allocator import RefillUnsupported, _read_span, _write_span
from verify_vm9_signer_objects import GUEST, LIBRARY_SHA256, fresh_pages, image_pages, native

LIBC_BASE = 0x51000000
LIBC_PTHREAD_GENERATION_OFFSET = 0xE0200  # Matching libc, not the older checkpoint ABI.
TLS = GUEST + 0xA000
PROPERTY = GUEST + 0xB800


def probe(library, libc, *, base, property_value, seconds=1791023800,
          instruction_observer=None, allocation_effect=None, registration_effect=None,
          free_effect=None, wake_effect=None):
    pages = fresh_pages()
    pages.update(image_pages(library, base))
    # Resolve only evidenced external allocator relocations, using their PLTs
    # so the existing bounded allocation/free oracle still owns the calls.
    bindings = {"malloc": base + 0x347FD0, "free": base + 0x347FA0}
    with library.open("rb") as stream:
        elf = ELFFile(stream)
        for section in elf.iter_sections():
            if section["sh_type"] != "SHT_RELA":
                continue
            symbols = elf.get_section(section["sh_link"])
            for relocation in section.iter_relocations():
                if relocation["r_info_type"] not in (257, 1025, 1026):
                    continue
                symbol = symbols.get_symbol(relocation["r_info_sym"])
                if symbol.name in bindings:
                    _write_span(pages, base + relocation["r_offset"],
                        (bindings[symbol.name] + relocation["r_addend"]).to_bytes(8, "little"))
    exports = {}
    with libc.open("rb") as stream:
        elf = ELFFile(stream)
        for section in elf.iter_sections():
            if section["sh_type"] == "SHT_DYNSYM":
                exports.update({s.name: LIBC_BASE + s["st_value"] for s in section.iter_symbols()
                                if s["st_shndx"] != "SHN_UNDEF"})

    _write_span(pages, TLS + 8, (TLS + 0x200).to_bytes(8, "little"))
    _write_span(pages, TLS + 0x200, bytes(0x900))
    _write_span(pages, TLS + 0x210, (137).to_bytes(4, "little"))
    inputs = []
    for source, mask, destination in ((0xA62C8, 0xA6534, GUEST + 0x1400),
                                      (0xA62D0, 0xA6440, GUEST + 0x1C00),
                                      (0xA5A60, 0xA5A80, GUEST + 0x2400)):
        _write_span(pages, destination, bytes(1024))
        count = objects.decode_masked_bytes(pages, source_address=base + source,
            destination_address=destination, mask_address=base + mask, max_bytes=1023)
        raw = _read_span(pages, destination, count).split(b"\0", 1)[0]
        inputs.append(raw)
    sdk_name = inputs.pop()
    for index, value in enumerate(inputs):
        reference = GUEST + (0x1000 if index == 0 else 0x1020)
        counter = GUEST + 0x1100 + index * 0x10
        string = GUEST + 0x1200 + index * 0x20
        data = GUEST + (0x1400 if index == 0 else 0x1C00)
        _write_span(pages, reference, string.to_bytes(8, "little") + counter.to_bytes(8, "little"))
        _write_span(pages, counter, (7).to_bytes(4, "little"))
        _write_span(pages, string, (base + 0x34F5F8).to_bytes(8, "little")
                    + (len(value) + 1).to_bytes(4, "little") + len(value).to_bytes(4, "little")
                    + data.to_bytes(8, "little"))
    _write_span(pages, GUEST + 0x1010, _read_span(pages, GUEST + 0x1000, 16))
    if property_value is not None and (len(property_value) > 91 or b"\0" in property_value):
        raise ValueError("property fixture must fit the 92-byte native buffer")

    calls, registrations = Counter(), []
    root_pointer, before, after = None, None, None
    min_stack = GUEST + 0xEF00
    sdk_cache = None
    def observe(cpu, address):
        nonlocal root_pointer, before, after, min_stack, sdk_cache
        min_stack = min(min_stack, cpu.reg_read(UC_ARM64_REG_SP))
        if min_stack <= TLS + 0xB00:
            raise RefillUnsupported("native stack overlaps the isolated TLS fixture")
        if address == base + 0x257308:
            root_pointer = cpu.reg_read(UC_ARM64_REG_X0)
            before = bytes(cpu.mem_read(root_pointer, 264))
        elif address == base + 0x257250:
            after = bytes(cpu.mem_read(root_pointer, 264))
            sdk_cache = int.from_bytes(cpu.mem_read(base + 0x3DF148, 4), "little")
        if instruction_observer:
            instruction_observer(cpu, address)

    def redirect(name):
        def call(cpu):
            calls[name + ":matching_libc"] += 1
            cpu.reg_write(UC_ARM64_REG_PC, exports[name])
        return call

    def free(cpu):
        if free_effect:
            free_effect(cpu, cpu.reg_read(UC_ARM64_REG_X0))
        calls["free:nonreusing_allocator"] += 1
        return 0

    def atexit(cpu):
        values = [cpu.reg_read(reg) for reg in (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2)]
        if not base <= values[0] < base + 0x348000:
            raise RefillUnsupported("destructor is outside the loaded image")
        registrations.append([hex(value - base) for value in values])
        if registration_effect:
            registration_effect(cpu, *values)
        calls["__cxa_atexit:register_only"] += 1
        return 0

    def clock(cpu):
        clock_id = cpu.reg_read(UC_ARM64_REG_X0)
        if clock_id not in (0, 1):
            raise RefillUnsupported("unknown virtual clock")
        cpu.mem_write(cpu.reg_read(UC_ARM64_REG_X1), seconds.to_bytes(8, "little")
                      + (500000000).to_bytes(8, "little"))
        calls["clock_gettime:" + str(clock_id)] += 1
        return 0

    def mkdir(cpu):
        cpu.mem_write(TLS + 0x100, (17).to_bytes(4, "little"))
        calls["mkdir:EEXIST"] += 1
        return 0xFFFF_FFFF

    def property_find(cpu):
        name_pointer = cpu.reg_read(UC_ARM64_REG_X0)
        if bytes(cpu.mem_read(name_pointer, len(sdk_name) + 1)) != sdk_name + b"\0":
            raise RefillUnsupported("unexpected system property name")
        calls["property_find"] += 1
        return PROPERTY if property_value is not None else 0

    def property_read(cpu):
        if cpu.reg_read(UC_ARM64_REG_X0) != PROPERTY or cpu.reg_read(UC_ARM64_REG_X1):
            raise RefillUnsupported("unexpected system property read arguments")
        cpu.mem_write(cpu.reg_read(UC_ARM64_REG_X2), property_value + b"\0")
        calls["property_read"] += 1
        return len(property_value)

    def syscall(cpu, number):
        calls["syscall:" + str(number)] += 1
        if number in (48, 56, 79):  # faccessat, openat, newfstatat
            return -2
        if number in (57, 63):  # close/read after failed open
            return -9
        if number == 198:  # socket; explicit unsupported virtual family
            return -97
        if number == 98 and cpu.reg_read(UC_ARM64_REG_X1) & 0x7F == 1:
            if wake_effect:
                wake_effect(cpu, *[cpu.reg_read(reg) for reg in (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2)])
            return 0  # FUTEX_WAKE with no virtual waiters
        raise RefillUnsupported("unknown virtual syscall " + str(number))

    imports = {0x347FA0: free, 0x347EA0: atexit, 0x348450: clock,
               0x3484A0: mkdir, 0x3481A0: lambda cpu: TLS + 0x100,
               0x348250: property_find, 0x348260: property_read}
    for offset, name in ((0x3484B0, "strtol"), (0x3486B0, "pthread_once"),
                         (0x348620, "pthread_key_create"), (0x3485D0, "pthread_getspecific"),
                         (0x348580, "pthread_setspecific"), (0x3485A0, "pthread_cond_broadcast"),
                         (0x347FE0, "memcmp"), (0x347F70, "vsnprintf")):
        imports[offset] = redirect(name)
    _, memory, allocations, ledger = native(library, base, 0x257578,
        [GUEST + 0x1000, GUEST + 0x1010, GUEST + 0x1020, 5], pages, libc=libc,
        real_singletons=True, real_mutexes=True, thread_id=137,
        extra_registers={UC_ARM64_REG_X8: GUEST + 0x1800, UC_ARM64_REG_TPIDR_EL0: TLS},
        host_imports=imports, instruction_limit=500000, instruction_observer=observe,
        syscall_handler=syscall, allocation_effect=allocation_effect)
    assert before is not None and after is not None
    assert int.from_bytes(memory[0x1800:0x1808], "little") == root_pointer
    counter = int.from_bytes(memory[0x1808:0x1810], "little")
    assert int.from_bytes(memory[counter - GUEST:counter - GUEST + 4], "little") == 1
    mutex_counts = Counter(item[0] for item in ledger)
    assert mutex_counts["pthread_mutex_lock"] == mutex_counts["pthread_mutex_unlock"]
    return {"image_base": hex(base), "returned": True,
            "input_string_lengths": [len(inputs[0]), len(inputs[0]), len(inputs[1])],
            "first_two_inputs_share_reference": True,
            "allocations": len(allocations), "sdk_cache_after": sdk_cache,
            "initializer_changed_byte_offsets": [hex(i) for i, (a, b) in enumerate(zip(before, after)) if a != b],
            "mutex_lock_count": mutex_counts["pthread_mutex_lock"],
            "mutex_unlock_count": mutex_counts["pthread_mutex_unlock"],
            "minimum_stack_offset": hex(min_stack - GUEST),
            "destructor_registrations": registrations, "host_call_counts": dict(calls)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--libc", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == LIBRARY_SHA256
    profiles = (("absent", None, 0), ("sdk_30", b"30", 30),
                ("sdk_zero", b"0", 0), ("sdk_negative", b"-1", 0),
                ("sdk_signed_suffix", b"  +31suffix", 31),
                ("sdk_u32_wrap", b"4294967326", 30),
                ("sdk_i32_negative_wrap", b"2147483648", 0),
                ("sdk_i64_overflow", b"9223372036854775808", 0))
    cases = []
    for base in (0x122C0000, 0x775C205000):
        for label, value, expected in profiles:
            result = probe(args.library, args.libc, base=base, property_value=value)
            assert result["sdk_cache_after"] == expected, label
            result["case"] = label
            cases.append(result)
    report = {"fresh_memory": True, "captured_pages_used": False, "jvm_used": False,
              "library_sha256": LIBRARY_SHA256,
              "libc_sha256": hashlib.sha256(args.libc.read_bytes()).hexdigest(),
              "verification_kind": "native_constructor_with_explicit_virtual_environment",
              "native_cases": len(cases), "cases": cases,
              "complete_python_root_configuration": False, "complete_python_medusa": False,
              "host_boundaries": ["bounded_nonreusing_malloc/free", "virtual_property_find/read",
                  "virtual_clock/errno", "missing_files/EEXIST_directory/unsupported_socket_family",
                  "futex_wake_no_waiters", "destructor_registration_without_execution",
                  "diagnostic_scope/thread_attachment/JNI_from_component_oracle"]}
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"native_cases": len(cases), "complete_python_medusa": False}))


if __name__ == "__main__":
    main()
