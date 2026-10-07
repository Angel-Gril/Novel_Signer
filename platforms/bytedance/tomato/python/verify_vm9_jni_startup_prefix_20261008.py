"""Original JNI_OnLoad into both startup caller prefixes, without VM replay.

One explicit ctor-exit driver invokes the original ELF-defined JNI_OnLoad.
JVM/JNI/OS/allocator inputs and two old warm reference states remain explicit.
Base prefixes stop before A's first VM instruction or after B's constructor.
Separate memcpy binding observations enter A's VM prefix to its next import.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from unicorn import arm64_const as arm
from elftools.elf.elffile import ELFFile
import verify_vm9_jni_cold_once_fresh_20261008 as cold
import verify_vm9_jni_initialization_fresh_20261007 as initialization
from vm9_allocator import _read_span, _write_span
from verify_vm9_signer_objects import LIBRARY_SHA256, GUEST

TABLE = GUEST + 0x6000
THREAD = GUEST + 0x3000
STARTUP_SP = cold.SP - 0x200


def case(args, base, word, *, bind_memcpy=None):
    target = (0x1684F0 if word == 0 else 0x2A0050) if bind_memcpy is None else (0x348000 if bind_memcpy else 0x2813E8)
    memcpy_slots = []
    with args.library.open('rb') as stream:
        elf = ELFFile(stream)
        plt = elf.get_section_by_name('.plt')
        relocations = elf.get_section_by_name('.rela.plt')
        symbols = elf.get_section(relocations['sh_link'])
        plt_symbols = {symbols.get_symbol(reloc['r_info_sym']).name: plt['sh_addr'] + 32 + index * 16
            for index, reloc in enumerate(relocations.iter_relocations())}
        assert plt_symbols['memcpy'] == 0x347F60 and plt_symbols['pthread_create'] == 0x348000
        for section in elf.iter_sections():
            if section['sh_type'] == 'SHT_RELA':
                symbols = elf.get_section(section['sh_link'])
                for relocation in section.iter_relocations():
                    symbol = symbols.get_symbol(relocation['r_info_sym'])
                    if symbol.name == 'memcpy' and relocation['r_info_type'] == 257:
                        assert symbol['st_shndx'] == 'SHN_UNDEF' and relocation['r_addend'] == 0
                        memcpy_slots.append(relocation['r_offset'])
    assert len(memcpy_slots) == 16
    original_fixture, original_native = cold.fixture, cold.native
    entries = []
    observed_regions = {}
    memcpy_packets = []

    def fixture(library, image, profile, **options):
        pages, blocks = original_fixture(library, image, profile, **options)
        _write_span(pages, TABLE, _read_span(pages, cold.TABLE, 4096))
        cold.w(pages, cold.ENV, TABLE)
        cold.w(pages, cold.INNER_ENV, TABLE)
        # Permanent TLS storage must be below B's 0x62e0-byte local state.
        _write_span(pages, THREAD, _read_span(pages, GUEST + 0xD000, 0x50))
        if bind_memcpy:
            for offset in memcpy_slots:
                assert cold.u(pages, image + offset) == 0
                cold.w(pages, image + offset, image + plt_symbols['memcpy'])
        return pages, blocks

    def execute(library, image, function, arguments, pages, **options):
        original_observer = options['instruction_observer']
        options['stop_offset'] = target
        options['instruction_limit'] = 500000
        options['extra_registers'] = {arm.UC_ARM64_REG_TPIDR_EL0: THREAD}
        regions = options['observed_memory']
        regions[TABLE, 4096] = None
        regions[THREAD, 0x50] = None
        if word == 0:
            stack = STARTUP_SP - 0x400
            regions[stack + 0x2B0, 0x108] = None
            if bind_memcpy is not None:regions[stack + 0x230, 32] = None
        else:
            state = STARTUP_SP - 0x6310
            regions[state, 16] = None
            regions[state + 0x6050, 0x280] = None

        def observe(cpu, address):
            original_observer(cpu, address)
            offset = address - image
            if offset == 0x2813E8:
                packet = cpu.reg_read(arm.UC_ARM64_REG_X0)
                values = [int.from_bytes(cpu.mem_read(packet + index * 8, 8), 'little') for index in range(4)]
                memcpy_packets.append(values)
            if offset in (0x28040C, 0x168324, 0x2A0028, 0x2A02D4):
                entries.append(dict(offset_hex=hex(offset),
                    stack_address_hex=hex(cpu.reg_read(arm.UC_ARM64_REG_SP)),
                    x0_x4_hex=[hex(cpu.reg_read(getattr(arm, 'UC_ARM64_REG_X' + str(i)))) for i in range(5)],
                    return_address_hex=hex(cpu.reg_read(arm.UC_ARM64_REG_X30))))
        options['instruction_observer'] = observe
        result = original_native(library, image, function, arguments, pages, **options)
        observed_regions.update(regions)
        return result

    cold.fixture, cold.native = fixture, execute
    try:
        result = cold.run_native(args, base, {'long_word': word}, bootstrap=True)
    finally:
        cold.fixture, cold.native = original_fixture, original_native
    pages, blocks, effects, vm, jni, exits, drivers = result[:7]
    assert drivers == [['ctor_exit_to', '0x27b41c']]
    assert len(exits) == 1 and len(jni.wake_events) == 1
    read = lambda address, width=8: int.from_bytes(observed_regions[base + (address & ~4095), 4096]
        [address & 4095:(address & 4095) + width], 'little')
    assert read(0x3D1570) == (1 << 64) - 1 and read(0x3D1578) == word
    assert [entry['offset_hex'] for entry in entries] == (
        ['0x28040c', '0x168324'] if word == 0 else ['0x2a0028', '0x2a02d4'])
    assert int(entries[0]['stack_address_hex'], 16) == STARTUP_SP
    assert observed_regions[TABLE, 4096] == _read_span(pages, TABLE, 4096)
    assert observed_regions[THREAD, 0x50] == _read_span(pages, THREAD, 0x50)
    if bind_memcpy is not None:
        for offset in memcpy_slots:
            assert read(offset) == (base + plt_symbols['memcpy'] if bind_memcpy else 0)
        if bind_memcpy:
            assert len(memcpy_packets) == 2
            assert all(values[0] == base + plt_symbols['memcpy'] and values[3] == 8 for values in memcpy_packets)
        else:
            packet = observed_regions[STARTUP_SP - 0x400 + 0x230, 32]
            values = [int.from_bytes(packet[index:index + 8], 'little') for index in range(0, 32, 8)]
            assert values[0] == 0 and values[3] == 8 and not memcpy_packets
        return dict(image_base_hex=hex(base), memcpy_ABS64_bound=bind_memcpy,
            ABS64_binding_count=len(memcpy_slots), resolved_service_plt_offset_hex=hex(plt_symbols['memcpy']),
            ELF_import_slot_offsets_hex=[hex(offset) for offset in memcpy_slots],
            next_stop_offset_hex=hex(target), native_stop_reached=True,
            same_native_execution=True, explicit_driver_continuations=drivers,
            copied_packet_calls=len(memcpy_packets), packet_arguments_verified=True,
            zero_unresolved_callback_target_observed=not bind_memcpy,
            pthread_create_PLT_reached=bind_memcpy, pthread_create_executed=False,
            startup_VM_prefix_executed=True, entire_startup_VM_return_verified=False,
            explicit_memory_copy_service_used=bind_memcpy,
            Python_full_bootstrap_compared=False, complete_python_medusa=False)
    details = {}
    if word == 0:
        stack = STARTUP_SP - 0x400
        assert entries[1]['x0_x4_hex'] == [hex(value) for value in
            (base + 0xA7050, 0, base + 0x35D670, base + 0x35D690, stack)]
        raw = observed_regions[stack + 0x2B0, 0x108]
        words = [int.from_bytes(raw[index:index + 8], 'little') for index in range(0, len(raw), 8)]
        assert words[0] == base + 0xA7050
        registers = words[1:]
        expected = {0: 0, 4: 0, 5: base + 0x35D670, 6: base + 0x35D690,
            7: base + 0x281414, 29: (stack + 0x2A0) & ~15, 31: base + 0x27BCC0}
        assert all(registers[index] == value for index, value in expected.items())
        details = dict(bytecode_offset_hex='0xa7050', metadata_offset_hex='0x35d670',
            callbacks_offset_hex='0x35d690', defined_prelude_slot_values_verified=True,
            first_VM_instruction_executed=False)
    else:
        state = STARTUP_SP - 0x6310
        assert entries[1]['x0_x4_hex'][0] == hex(state)
        raw = observed_regions[state, 16]
        assert raw[:4] == bytes(4) and raw[8:16] == bytes(8)
        tail = bytearray(0x280)
        tail[8:16] = (state + 0x6010).to_bytes(8, 'little')
        assert observed_regions[state + 0x6050, 0x280] == bytes(tail)
        assert read(0x3E1EB8) == 0
        details = dict(state_address_hex=hex(state), actual_constructor_returned=True,
            constructor_u32_and_u64_fields_verified=True, zeroed_tail_size=0x280,
            tail_saved_pointer_delta_hex='0x6010', explicit_memset_service_used=True,
            next_descriptor_global_offset_hex='0x3e1eb8', descriptor_NULL_in_current_fixture=True,
            descriptor_dispatch_body_executed=False)
    return dict(image_base_hex=hex(base), java_switch_word_hex=hex(word),
        native_stop_offset_hex=hex(target), native_stop_reached=True, startup_entries=entries,
        explicit_driver_continuations=drivers, once_completed=True, same_native_execution=True,
        JNI_table_and_thread_storage_avoid_large_stack=True, details=details,
        controlled_allocation_sizes=[call[1] for call in effects.calls if call[0] == 'malloc'],
        no_waiter_futex_events=jni.wake_events, native_input_snapshot_used=False,
        Python_full_bootstrap_compared=False, full_JNI_OnLoad_return_verified=False,
        all_startup_VM_bodies_executed=False)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--library', type=Path, required=True)
    parser.add_argument('--libc', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest() == initialization.LIBC_SHA256
    cases = []
    for base in (0x122C0000, 0x775C205000):
        for word in (0, 0x200):
            cases.append(case(args, base, word))
            print('startup prefix:', hex(base), hex(word), 'passed', flush=True)
    binding_cases = []
    for base in (0x122C0000, 0x775C205000):
        for bound in (False, True):
            binding_cases.append(case(args, base, 0, bind_memcpy=bound))
            print('startup memcpy binding:', hex(base), bound, 'passed', flush=True)
    evidence = dict(schema='vm9-jni-original-startup-prefix-v1', evidence_date='2026-10-08',
        evidence_timezone='Asia/Shanghai', sample_sha256=LIBRARY_SHA256,
        matching_libc_sha256=initialization.LIBC_SHA256, original_startup_prefix_observations=len(cases),
        Python_full_bootstrap_comparison_controls=0, cases=cases,
        unbound_vs_memcpy_bound_observations=len(binding_cases), binding_cases=binding_cases,
        JNI_table_offset_hex=hex(TABLE - GUEST), thread_pointer_offset_hex=hex(THREAD - GUEST),
        explicit_driver_continuations_used=True, explicit_allocator_VM_JNI_OS_exit_services_used=True,
        warm_reference_and_TLS_global_OS_key_inputs_used=True,
        matching_libc_condition_broadcast_executed=True, native_input_snapshot_used=False,
        all_ELF_constructors_recovered=False, full_cold_TLS_subsystem_boot_verified=False,
        full_JNI_OnLoad_recovered=False, all_startup_VM_bodies_verified=False,
        complete_python_medusa=False, fresh_signer_output_verified=False, live_server_matrix_verified=False)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2) + '\n', encoding='utf-8')
    print('original startup prefixes:', len(cases), '; import binding observations:', len(binding_cases), '; full Python bootstrap controls: 0')


if __name__ == '__main__':main()
