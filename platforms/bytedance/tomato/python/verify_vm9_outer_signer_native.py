"""Native-only cold outer signer control using actual matching-libc allocation.

ELF/TLS/stack inputs are new. OS, clock, property, virtual thread descriptors,
logging scopes and JNI dispatch/reference cleanup are explicit services.
Only counts, static offsets and boolean assertions are exported. No native
memory seeds Python; this does not verify a Python outer constructor or signing.
"""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from elftools.elf.elffile import ELFFile
from unicorn.arm64_const import (
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
    UC_ARM64_REG_X30, UC_ARM64_REG_SP, UC_ARM64_REG_PC, UC_ARM64_REG_TPIDR_EL0,
)
import vm9_allocator as a
from vm9_libc_boot import _w
import verify_vm9_worker_allocator as h
import verify_vm9_libc_stdio as io
import verify_vm9_root_configuration as root_fixture
import verify_vm9_signer_objects as oracle

PROFILES = {'absent': None, 'sdk_30': b'30', 'sdk_negative': b'-1', 'sdk_signed_suffix': b'  +31suffix'}
ENTRIES = (0x1658E4, 0x27C930, 0x28040C, 0x257578, 0x27CEAC, 0x27D0C4,
           0x288E98, 0x263FB8, 0x28C268, 0x329F88)


def fresh(library, libc, image, property_value):
    pages = h.fresh(library, libc, image)
    inputs, _, sdk_name = root_fixture.fresh_inputs(library, base=image, property_value=property_value)
    for key, value in inputs.items():
        if io.GUEST <= key << 12 < io.GUEST + 0xC000: pages[key] = bytearray(value)
    _w(pages, io.GUEST + 0x7800, io.GUEST + 0xB000)
    for offset, target in ((0x740, io.GUEST + 0xF100), (0xB8, io.GUEST + 0xF110),
                           (0xB0, io.GUEST + 0xF120), (0x718, io.GUEST + 0xF130)):
        _w(pages, io.GUEST + 0xB000 + offset, target)
    return pages, sdk_name


def bind_native_imports(library, libc, redirect, imports):
    with libc.open('rb') as stream:
        elf = ELFFile(stream)
        exports = {symbol.name: io.LIBC + symbol['st_value'] for symbol in elf.get_section_by_name('.dynsym').iter_symbols()
                   if symbol['st_shndx'] != 'SHN_UNDEF'}
    with library.open('rb') as stream:
        elf = ELFFile(stream); relocations = {}
        for section in elf.iter_sections():
            if section['sh_type'] != 'SHT_RELA': continue
            symbols = elf.get_section(section['sh_link'])
            for rel in section.iter_relocations():
                relocations[rel['r_offset']] = symbols.get_symbol(rel['r_info_sym']).name
        section = elf.get_section_by_name('.plt'); data = section.data()
        md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        for index in range(32, len(data), 16):
            instructions = list(md.disasm(data[index:index + 16], section['sh_addr'] + index))
            if len(instructions) != 4 or instructions[0].mnemonic != 'adrp' or instructions[1].mnemonic != 'ldr': continue
            page = int(instructions[0].op_str.split('#')[1], 16)
            offset = int(instructions[1].op_str.split('#')[1].split(']')[0], 16)
            name = relocations.get(page + offset)
            if name in exports: imports.setdefault(section['sh_addr'] + index, redirect(exports[name]))
    return exports


def case(library, libc, image, property_value, *, stack_address=h.TOP, mapping_address=None, canary=None):
    pages, sdk_name = fresh(library, libc, image, property_value)
    if canary is not None: _w(pages, root_fixture.TLS + 0x28, canary)
    environment = h.Environment(pages, 2)
    if mapping_address is not None: environment.os.next_address = mapping_address
    observed = io.observed_spans()
    counts = Counter(); entries = Counter(); root_inputs = {}; pending = []
    state = {'mapped': False, 'booted': False, 'returned': False, 'last_pc': 0}
    virtual_threads = []; services = Counter(); returned_graph = {}

    def u(cpu, address, width=8): return int.from_bytes(cpu.mem_read(address, width), 'little')

    def observe(cpu, pc):
        state['last_pc'] = pc
        offset = pc - image
        if offset in ENTRIES: entries[hex(offset)] += 1
        if offset == 0x1658E4 and not state['mapped']:
            state['mapped'] = True; cpu.mem_map(h.STACK, h.STACK_BYTES)
            for address in range(h.STACK, h.STACK + h.STACK_BYTES, 4096):
                cpu.mem_write(address, bytes(pages[address >> 12]))
        if pc == io.LIBC + 0x8E250 and not state['booted']:
            state['booted'] = True; cpu.mem_write(io.TABLE, a._read_span(pages, io.TABLE, 141 * 16))
        if pending and pc == pending[-1]: pending.pop()
        if offset in (0x347FD0, 0x347FA0):
            counts['malloc' if offset == 0x347FD0 else 'free'] += 1
            pending.append(cpu.reg_read(UC_ARM64_REG_X30))
        if pc == io.LIBC + 0x9833C: counts['gc'] += 1
        if pc == io.LIBC + 0x97F40: counts['flush'] += 1
        if offset == 0x257578:
            args = [cpu.reg_read(reg) for reg in (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3)]
            assert args[3] == 5 and u(cpu, args[0]) == u(cpu, args[1]) and u(cpu, args[0]) != u(cpu, args[2])
            root_inputs.update(root_entry_stack_displacement=cpu.reg_read(UC_ARM64_REG_SP) - stack_address,
                root_flag=5, constructor_generated_reference_arguments_verified=True,
                malloc_calls_before_root=counts['malloc'], free_calls_before_root=counts['free'])

    def redirect(entry):
        def run(cpu): cpu.reg_write(UC_ARM64_REG_PC, entry)
        return run

    def create(cpu):
        output, attribute, entry, argument = [cpu.reg_read(reg) for reg in
            (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3)]
        assert not attribute and entry - image in (0x326A2C, 0x3260A4)
        handle = io.GUEST + 0xC800 + len(virtual_threads) * 0x100
        cpu.mem_write(output, handle.to_bytes(8, 'little')); virtual_threads.append((handle, entry, argument))
        services['virtual_pthread_create'] += 1
        return 0

    def register(cpu): services['destructor_registration'] += 1; return 0

    def clock(cpu):
        assert cpu.reg_read(UC_ARM64_REG_X0) in (0, 1)
        cpu.mem_write(cpu.reg_read(UC_ARM64_REG_X1),
            (1791023800).to_bytes(8, 'little') + (500000000).to_bytes(8, 'little'))
        services['clock'] += 1
        return 0

    def mkdir(cpu):
        cpu.mem_write(root_fixture.TLS + 0x100, (17).to_bytes(4, 'little'))
        services['mkdir_exists'] += 1
        return 0xFFFFFFFF

    def property_find(cpu):
        assert bytes(cpu.mem_read(cpu.reg_read(UC_ARM64_REG_X0), len(sdk_name) + 1)) == sdk_name + b'\0'
        services['property_find'] += 1
        return root_fixture.PROPERTY if property_value is not None else 0

    def property_read(cpu):
        assert property_value is not None and cpu.reg_read(UC_ARM64_REG_X0) == root_fixture.PROPERTY
        assert not cpu.reg_read(UC_ARM64_REG_X1)
        cpu.mem_write(cpu.reg_read(UC_ARM64_REG_X2), property_value + b'\0')
        services['property_read'] += 1
        return len(property_value)

    def syscall(cpu, number):
        services['syscall_' + str(number)] += 1
        if number == 98:
            assert cpu.reg_read(UC_ARM64_REG_X1) & 0x7F == 1
            return 0
        if number == 56 and io.cstring(cpu, cpu.reg_read(UC_ARM64_REG_X1)) != b'/proc/stat': return -2
        if number in (57, 63) and cpu.reg_read(UC_ARM64_REG_X0) != 53: return -9
        if number in (48, 79): return -2
        if number == 198: return -97
        if number == 233:
            address, length, advice = [cpu.reg_read(reg) for reg in (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2)]
            assert address % 4096 == 0 and length > 0 and length % 4096 == 0 and advice == 4
            assert any(rec.base <= address and address + length <= rec.end for rec in environment.os.mappings)
            environment.calls.append(['madvise', address, length, advice]); return 0
        return environment.syscall(cpu, number, observed)

    def returned(cpu):
        assert not pending
        wrapper = cpu.reg_read(UC_ARM64_REG_X0)
        if state['returned']:
            assert wrapper == state['wrapper'] and counts == state['cold_counts']
            assert services == state['cold_services'] and len(virtual_threads) == 3
            returned_graph['warm_getter_reuses_wrapper_without_allocator_or_provider_effects'] = True
            cpu.reg_write(UC_ARM64_REG_PC, io.STOP)
            return
        root = u(cpu, wrapper)
        assert u(cpu, u(cpu, wrapper + 8), 4) == 1
        assert u(cpu, image + 0x3D15D8) == wrapper and u(cpu, image + 0x3D15E0, 1) == 1
        assert u(cpu, root + 8) and u(cpu, u(cpu, root + 0x10), 4) == 1
        children = [u(cpu, root + offset) for offset in (0x18, 0x20)]
        assert all(children) and children[0] != children[1]
        for child, function, vtable in zip(children, (0x2830C4, 0x289190), (0x35DC50, 0x35F7E0)):
            pair = u(cpu, child + 0x20)
            assert u(cpu, pair) == image + function
            assert u(cpu, u(cpu, pair + 8)) == image + vtable
        recursive = u(cpu, image + 0x3E1E08)
        assert recursive and u(cpu, recursive, 2) == 0x4000 and u(cpu, recursive + 4, 4) == 0
        returned_graph.update(root=root, wrapper_count_is_one=True, configuration_count_is_one=True,
            child_handler_callback_pairs_verified=True, outer_singleton_and_guard_published=True,
            publication_support_recursive_mutex_released=True)
        state.update(returned=True, wrapper=wrapper, cold_counts=dict(counts), cold_services=dict(services))
        # Re-enter the actual warm getter; no native output is input to Python.
        cpu.reg_write(UC_ARM64_REG_X30, io.CONTINUE)
        cpu.reg_write(UC_ARM64_REG_PC, image + 0x1658E4)

    imports = {0x348000: create, 0x347EA0: register, 0x348450: clock, 0x3484A0: mkdir,
        0x3481A0: lambda cpu: root_fixture.TLS + 0x100, 0x348250: property_find,
        0x348260: property_read, io.CONTINUE - image: returned}
    bind_native_imports(library, libc, redirect, imports)
    initial = {key: value for key, value in io.inputs(pages).items()
        if not h.STACK <= key << 12 < h.STACK + h.STACK_BYTES
        and not h.WORKERS[0] <= key << 12 < h.WORKERS[-1] + 0x2000}
    try:
        _, _, allocations, ledger = oracle.native(library, image, 0x1658E4, [], initial,
            references=(io.GUEST + 0x8000, io.GUEST + 0x8010), env=io.GUEST + 0x7800,
            ref_types={io.GUEST + 0x8000: 2, io.GUEST + 0x8010: 3}, libc=libc, real_malloc=True,
            real_mutexes=True, real_recursive_mutexes=True, real_singletons=True, thread_id=137,
            host_imports=imports, syscall_handler=syscall, instruction_observer=observe,
            extra_registers={UC_ARM64_REG_SP: stack_address, UC_ARM64_REG_TPIDR_EL0: root_fixture.TLS,
                UC_ARM64_REG_X30: io.CONTINUE}, instruction_limit=10000000)
    except Exception:
        print('outer native control failed at', hex(state['last_pc'] - image), 'counts', dict(counts), flush=True)
        raise
    assert state['returned'] and not allocations and state['booted']
    root = returned_graph.pop('root')
    invokes = [item for item in ledger if item[0] == 'invoke']
    assert invokes == [['invoke', tag, 0, root, 0, 0] for tag in (0x2000001, 0x2000002)]
    references = [item for item in ledger if item[0] in ('get_type', 'delete')]
    assert references == [['get_type', io.GUEST + 0x7800, io.GUEST + 0x8000],
        ['delete', 'global', io.GUEST + 0x7800, io.GUEST + 0x8000],
        ['get_type', io.GUEST + 0x7800, io.GUEST + 0x8010],
        ['delete', 'weak_global', io.GUEST + 0x7800, io.GUEST + 0x8010]]
    assert [entry - image for _, entry, _ in virtual_threads] == [0x326A2C, 0x3260A4, 0x3260A4]
    assert counts == {'malloc': 310, 'free': 115, 'gc': 1, 'flush': 3}
    assert entries['0x1658e4'] == 2 and all(entries[hex(offset)] == (2 if offset == 0x27D0C4 else 1) for offset in ENTRIES[1:])
    return dict(image_base=hex(image), function_offset='0x1658e4', native_outer_getter_returned=True,
        actual_allocator_counts=dict(counts), actual_entry_counts=dict(entries), **root_inputs, **returned_graph,
        virtual_thread_entry_offsets=[hex(entry - image) for _, entry, _ in virtual_threads],
        explicit_service_counts=dict(services), ordered_callback_publication_and_jni_cleanup_verified=True,
        virtual_descriptors_not_executed=True, physical_stack_compared=False, substituted_allocations=0,
        native_input_snapshot_used=False, python_outer_comparison_passed=False)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--library', type=Path, required=True)
    parser.add_argument('--libc', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--profile', action='append', choices=PROFILES)
    parser.add_argument('--base', action='append', type=lambda value: int(value, 0))
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest() == h.LIBC_SHA256
    rows = []
    for base in args.base or (0x122C0000, 0x775C205000):
        for label in args.profile or PROFILES:
            row = case(args.library, args.libc, base, PROFILES[label]); row['property_profile'] = label
            rows.append(row); print('native outer', hex(base), label, 'PASS', flush=True)
    if not args.base and not args.profile:
        for base in (0x122C0000, 0x775C205000):
            row = case(args.library, args.libc, base, None, stack_address=h.TOP - 0x1000,
                mapping_address=0x13A00000, canary=0x3F71A29C5DE408B6)
            row.update(property_profile='absent', input_profile='relocated_stack_mapping_changed_canary')
            rows.append(row); print('native outer', hex(base), 'relocated inputs PASS', flush=True)
    report = dict(schema='vm9-outer-signer-native-control-v1', sample_sha256=oracle.LIBRARY_SHA256,
        libc_sha256=h.LIBC_SHA256, cases=rows, native_controls=len(rows), native_input_snapshot_used=False,
        actual_os_threads_created=False, jvm_used=False, explicit_virtual_os_and_jni=True,
        python_outer_constructor_verified=False, complete_python_medusa=False,
        fresh_input_signer_output_verified=False, current_online_header_matrix_verified=False)
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('outer native control', len(rows), 'PASS; Python outer/signing unverified', flush=True)


if __name__ == '__main__': main()
