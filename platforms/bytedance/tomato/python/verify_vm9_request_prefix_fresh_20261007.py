"""Fresh request VM prefix versus original native VM instructions.

Compare three constant decodes, a controlled monotonic clock and a 24-byte
copy; stop before the allocating +0x25c324 callback. ABI objects are synthetic.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from unicorn.arm64_const import UC_ARM64_REG_SP, UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X8, UC_ARM64_REG_X19, UC_ARM64_REG_X28, UC_ARM64_REG_X29
import verify_vm9_signer_objects as oracle
import vm9_objects as objects
from elftools.elf.elffile import ELFFile
from vm9_allocator import RefillUnsupported, _PageTransaction, _read_span, _write_span
from vm9_request_caller import prepare_request_caller


from vm9_request_vm import (
    PrefixBoundary, RequestContinuationBoundary,
    resolve_request_memory_imports, apply_request_configuration_set_callback,
    execute_request_vm as execute_prefix,
)


def case(library, image, flag, seconds, nanoseconds, vm_module):
    pages = oracle.image_pages(library, image)
    pages.update(oracle.fresh_pages())
    memory_imports = resolve_request_memory_imports(pages, library, image)
    inputs = dict(entry_stack_address=oracle.GUEST + 0xEF00,
        return_address=oracle.STOP, thread_pointer=oracle.GUEST + 0xD000,
        image_base=image, argument_x0=oracle.GUEST + 0x2000,
        argument_x1=oracle.GUEST + 0x2100, argument_x2=flag,
        argument_x3=oracle.GUEST + 0x2200, output_x8=oracle.GUEST + 0x2300)
    _write_span(pages, inputs["argument_x0"], bytes(128))
    _write_span(pages, inputs["argument_x0"], (image + 0x35DC50).to_bytes(8, "little"))
    initial = {key: bytearray(value) for key, value in pages.items()}
    staged, frame, vm, ledger, decoded = execute_prefix(pages, inputs, vm_module, seconds, nanoseconds)
    assert vm.steps == 599 and vm.pc - image == 0xF8078
    observed = {(address, length): None for address, length in decoded}
    observed[frame.register_backing_address, 0x100] = None
    observed[ledger[-1][2], 0x20] = None
    native_ledger, clock_calls, physical_frames = [], [], []
    def observe(cpu, address):
        offset = address - image
        if offset in (0x285888, 0x28589C, 0x2858A8):
            argument = cpu.reg_read(UC_ARM64_REG_X0)
            words = tuple(int.from_bytes(cpu.mem_read(argument + i * 8, 8), 'little') for i in range(4))
            native_ledger.append((offset, words[0] - image, argument, words))
            physical = tuple(cpu.reg_read(reg) for reg in (UC_ARM64_REG_SP,
                UC_ARM64_REG_X29, UC_ARM64_REG_X28, UC_ARM64_REG_X19))
            expected = (frame.native_stack_address - 0x180,
                frame.native_stack_address - 0x60,
                frame.register_backing_address, frame.register_backing_address - 8)
            assert physical == expected, (offset, physical, expected)
            physical_frames.append(physical)
    def clock(cpu):
        assert cpu.reg_read(UC_ARM64_REG_X0) == 1
        pointer = cpu.reg_read(UC_ARM64_REG_X1)
        cpu.mem_write(pointer, seconds.to_bytes(8, 'little', signed=True) + nanoseconds.to_bytes(8, 'little', signed=True))
        clock_calls.append(1)
        return 0
    result, _, allocations, services = oracle.native(library, image, 0x2830C4,
        [inputs['argument_x0'], inputs['argument_x1'], flag, inputs['argument_x3']],
        initial, extra_registers={UC_ARM64_REG_SP: inputs['entry_stack_address'],
            UC_ARM64_REG_X8: inputs['output_x8']}, stop_offset=0x2858BC,
        instruction_limit=100000, observed_memory=observed, instruction_observer=observe,
        host_imports={0x348450: clock})
    assert not allocations and not services and clock_calls == [1]
    assert native_ledger == ledger[:-1], 'request callback input ledger differs'
    assert result == ledger[-1][2], 'request boundary descriptor differs'
    native_words = [int.from_bytes(observed[frame.register_backing_address, 0x100][i * 8:(i + 1) * 8], 'little') for i in range(32)]
    mismatches = [i for i in range(32) if native_words[i] != vm.R[i]]
    assert not mismatches, 'VM prefix register mismatch: ' + str(mismatches)
    assert all(observed[address, length] == _read_span(staged, address, length) for address, length in decoded)
    assert observed[ledger[-1][2], 0x20] == _read_span(staged, ledger[-1][2], 0x20)
    return dict(image_base=hex(image), input_w2=flag,
        explicit_monotonic_seconds=seconds, explicit_monotonic_nanoseconds=nanoseconds,
        steps=vm.steps, stop_bytecode_offset=hex(vm.pc - image),
        boundary_wrapper_offset='0x2858bc', boundary_target_offset='0x25c324',
        native_input_snapshot_used=False, callback_ledger_equal=True,
        all_32_virtual_registers_equal=True, decoded_global_bytes_equal=True,
        request_vm_physical_callback_frame_verified=bool(physical_frames),
        physical_callback_frame_observations=len(physical_frames),
        decoded_lengths=[length for _, length in decoded],
        boundary_descriptor_equal=True, clock_calls=1,
        request_objects_are_synthetic=True,
        handler_profile='synthetic 128-byte handler with current service vtable',
        memcpy_imports_resolved_to_explicit_plt_service=True,
        memset_imports_resolved_to_explicit_plt_service=True,
        memory_import_relocations=memory_imports)


def outer_handoff(library, libc, image, label, value, vm_module):
    import verify_vm9_outer_constructor_boundary as boundary
    import verify_vm9_worker_allocator as worker
    import verify_vm9_root_configuration as fixture
    observation = []
    def terminal(pages, *, result, **unused):
        # Start with this run's independent Python constructor output. Extra
        # request pages are explicit synthetic inputs, never native snapshots.
        cloned = {key: bytearray(data) for key, data in pages.items()}
        request_address = 0x64000000
        for address in range(request_address, request_address + 0x2000, 4096):
            cloned[address >> 12] = bytearray(4096)
        pair = result.callback_pair_addresses[0]
        target = int.from_bytes(_read_span(cloned, pair, 8), 'little')
        handler = int.from_bytes(_read_span(cloned, pair + 8, 8), 'little')
        assert target == image + 0x2830C4
        inputs = dict(entry_stack_address=worker.TOP, return_address=0xDEAD0000,
            thread_pointer=fixture.TLS, image_base=image, argument_x0=handler,
            argument_x1=request_address, argument_x2=0,
            argument_x3=request_address + 0x1000, output_x8=request_address + 0x1800)
        staged, frame, vm, ledger, decoded = execute_prefix(cloned, inputs, vm_module,
                                                          1791023800, 500000000)
        assert vm.steps == 599 and vm.pc - image == 0xF8078
        assert [length for _, length in decoded] == [19, 32, 9]
        assert ledger[-1][:2] == (0x2858BC, 0x25C324)
        observation.append(dict(image_base=hex(image), property_profile=label,
            same_python_outer_output_used=True, child_a_callback_pair_used=True,
            native_input_snapshot_used=False, fresh_elf_inputs=True,
            virtual_jni_publication_applied=result.publication_result is True,
            request_objects_are_synthetic=True, steps=vm.steps,
            stop_bytecode_offset=hex(vm.pc - image),
            boundary_wrapper_offset='0x2858bc', boundary_target_offset='0x25c324',
            decoded_lengths=[length for _, length in decoded],
            actual_allocator_request_callback_executed=False,
            native_whole_handoff_differential_verified=False,
            prefix_state_committed=False))
    result = boundary.case(library, libc, image, label, value, vm_module,
        apply_logger_model=True, apply_handoff_model=True, apply_publication=True,
        terminal_observer=terminal)
    assert result['python_constructor_returned'] and result['publication_applied']
    assert len(observation) == 1
    return observation[0]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--library', type=Path, default=Path(r'C:\AI\6\libmetasec_ml_71332.so'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--outer-libc', type=Path, help='also probe the same fresh Python outer handoff')
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == oracle.LIBRARY_SHA256
    os.environ['TOMATO_LIBMETASEC'] = str(args.library.resolve())
    import vm_full
    rows = []
    for image in (0x122C0000, 0x775C205000):
        for flag, seconds, nanoseconds in ((0, 0, 0), (1, 1234, 567890123), (0xFFFFFFFF, 1791023800, 500000000)):
            rows.append(case(args.library, image, flag, seconds, nanoseconds, vm_full))
            print('request prefix', hex(image), flag, 'PASS', flush=True)
    memory_imports = rows[0]['memory_import_relocations']
    for row in rows:
        assert row.pop('memory_import_relocations') == memory_imports
    handoffs = []
    if args.outer_libc is not None:
        import verify_vm9_worker_allocator as worker
        assert hashlib.sha256(args.outer_libc.read_bytes()).hexdigest() == worker.LIBC_SHA256
        for image in (0x122C0000, 0x775C205000):
            for label, value in (('absent', None), ('sdk_30', b'30')):
                handoffs.append(outer_handoff(args.library, args.outer_libc, image, label, value, vm_full))
                print('same fresh outer/request prefix', hex(image), label, 'PASS', flush=True)
    report = dict(schema='vm9-request-prefix-fresh-differential-v1', evidence_date='2026-10-07',
        sample_sha256=oracle.LIBRARY_SHA256, controls=len(rows), cases=rows,
        memory_import_relocations=memory_imports,
        memory_import_resolution_kind='parsed matching ELF relocations to explicit PLT services',
        same_python_outer_handoff_controls=len(handoffs), same_python_outer_handoff_cases=handoffs,
        fresh_input_signer_output_verified=False, complete_python_medusa=False,
        current_online_header_matrix_verified=False,
        limitations=['Request ABI objects are synthetic; URL/header/JNI conversion is not verified.',
            'Stops before allocating +0x25c324; later request callbacks are unsupported.',
            'Original native VM is expected-only; Python does not import native memory.',
            'Defined decodes/registers/callback descriptors are compared; physical scratch is not.',
            'No actual JVM, OS thread or server request is used.'])
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('request prefix', len(rows), 'native differences and', len(handoffs),
          'Python outer handoffs PASS; fresh signing remains open')


if __name__ == '__main__':
    main()
