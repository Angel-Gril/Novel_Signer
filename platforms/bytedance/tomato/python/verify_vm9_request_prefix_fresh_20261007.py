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


class PrefixBoundary(Exception):
    pass


class RequestContinuationBoundary(Exception):
    def __init__(self, *, staged, frame, vm, ledger, decoded, cause):
        super().__init__(str(cause))
        self.staged, self.frame, self.vm = staged, frame, vm
        self.ledger, self.decoded, self.cause = ledger, decoded, cause


def resolve_request_memory_imports(pages, library, image):
    """Resolve matching ELF memset/memcpy imports to explicit PLT services.

    Derive PLT entries from this file's jump relocations, then bind matching
    ABS64/GLOB_DAT/JUMP_SLOT sites. This is loader input, not native output.
    The VM callback hooks implement the declared PLT services separately.
    """
    targets, relocations = {}, []
    with library.open('rb') as stream:
        elf = ELFFile(stream)
        plt = elf.get_section_by_name('.plt')
        jumps = elf.get_section_by_name('.rela.plt')
        if plt is None or jumps is None:
            raise RefillUnsupported('request ELF lacks the expected PLT relocations')
        symbols = elf.get_section(jumps['sh_link'])
        for index, relocation in enumerate(jumps.iter_relocations()):
            name = symbols.get_symbol(relocation['r_info_sym']).name
            if name in ('memset', 'memcpy'):
                targets[name] = image + plt['sh_addr'] + 32 + index * 16
        if targets != {'memset': image + 0x347F20, 'memcpy': image + 0x347F60}:
            raise RefillUnsupported('request ELF memory import layout does not match this sample')
        for section in elf.iter_sections():
            if section['sh_type'] != 'SHT_RELA':
                continue
            symbols = elf.get_section(section['sh_link'])
            for relocation in section.iter_relocations():
                name = symbols.get_symbol(relocation['r_info_sym']).name
                if relocation['r_info_type'] in (257, 1025, 1026) and name in targets:
                    relocations.append((name, relocation['r_offset'],
                        targets[name] + relocation['r_addend'], relocation['r_info_type']))
    staged = _PageTransaction(pages)
    for name, offset, target, kind in relocations:
        _write_span(staged, image + offset, target.to_bytes(8, 'little'))
    staged.commit()
    return [dict(symbol=name, relocation_offset=hex(offset),
        target_offset=hex(target-image), relocation_kind=kind) for name, offset, target, kind in relocations]


def execute_prefix(pages, inputs, vm_module, seconds, nanoseconds, *, allocate=None,
                   diagnostic_scope=None, reallocate=None, free=None, prepare_format=None,
                   read_clock=None, acquire_environment=None):
    staged = _PageTransaction(pages)
    frame = prepare_request_caller(staged, **inputs)
    image = inputs['image_base']
    ledger, decoded = [], []
    class StrictMem(vm_module.Mem):
        def __init__(self):
            self.pages = staged
        def _pg(self, address):
            if address >> 12 not in self.pages:
                raise RefillUnsupported(f'unmapped request prefix page {address:#x}')
            return self.pages[address >> 12]
    previous = vm_module.B
    try:
        vm_module.B = image
        vm = vm_module.VM(StrictMem(), frame.bytecode_offset,
            frame.packed_arguments_address, image + 0x35E230,
            image + 0x35E690, image + 0x28587C,
            inputs['return_address'], maxsteps=2000)
        vm.R = list(frame.registers)
        def callback(vm, function, argument):
            words = [vm.m.u64(argument + i * 8) for i in range(4)]
            wrapper, target = function - image, words[0] - image
            ledger.append((wrapper, target, argument, tuple(words)))
            if (wrapper, target) == (0x285888, 0x167E54):
                length = objects.decode_masked_bytes(vm.m.pages,
                    source_address=words[1], destination_address=words[2], mask_address=words[3])
                decoded.append((words[2], length))
            elif (wrapper, target) == (0x28589C, 0x291440):
                import vm9_callbacks
                provider = read_clock
                if provider is None:
                    provider = lambda _p, clock_id: (0, seconds, nanoseconds)
                value = vm9_callbacks.store_monotonic_start(vm.m.pages,
                    object_address=words[1], read_clock=provider)
                if diagnostic_scope is not None:
                    diagnostic_scope.setdefault('clock_stores', []).append(dict(
                        object_address=words[1], clock_id=1, stored_nanoseconds=value,
                        owning_clock_provider_used=read_clock is not None))
            elif allocate is not None and (wrapper, target) == (0x285FB4, 0x28DC38):
                if diagnostic_scope is None or free is None:
                    raise PrefixBoundary()
                import vm9_request_event
                import vm9_request_leaf_prefixes as leaf
                def event_observer(p, *, phase, **context):
                    diagnostic_scope.setdefault('request_event_prefixes', []).append(dict(
                        phase=phase, **context,
                        first_object_hex=_read_span(p, context['first_object_address'], 24).hex(),
                        second_object_hex=_read_span(p, context['second_object_address'], 24).hex(),
                        first_copy_hex=_read_span(p, context['first_copy_address'], 24).hex(),
                        formatter_target_offset='0x28ddd0',
                        supported_prefix_staged=True, body_transaction_committed=False,
                        native_input_snapshot_used=False))
                def event_leaf_observer(p, **context):
                    diagnostic_scope.setdefault('request_event_leaf_prefixes', []).append(dict(
                        **context, native_input_snapshot_used=False,
                        whole_callback_transaction_committed=False))
                def format_event(p, obj, x1, x2, x3, x4, mode):
                    return leaf.execute_event_formatter_prefix(p, image_base=image,
                        entry_stack_address=frame.native_stack_address - 0x270,
                        event_object_address=obj, argument_words=(x1, x2, x3, x4),
                        mode=mode, observer=event_leaf_observer, allocate=allocate, free=free)
                event_result = vm9_request_event.execute_request_event(vm.m.pages, image_base=image,
                    entry_stack_address=frame.native_stack_address - 0x180,
                    argument_words=(words[1], words[2], words[3], vm.m.u64(argument + 32)),
                    allocate=allocate, free=free, format_event=format_event, observer=event_observer)
                diagnostic_scope.setdefault('request_event_completed', []).append(dict(
                    wrapper_offset=hex(wrapper),target_offset=hex(target),
                    formatter_calls=event_result.formatter_calls,
                    emit_error_event=event_result.emit_error_event,
                    bounded_request_event_returned=True,callback_transaction_committed_to_request_stage=True))
            elif allocate is not None and (wrapper, target) == (0x285A80, 0x28BB5C):
                if diagnostic_scope is None or read_clock is None:
                    raise PrefixBoundary()
                import vm9_request_boolean_gate
                import vm9_request_leaf_prefixes as leaf
                def gate_observer(p, *, phase, **context):
                    diagnostic_scope.setdefault('request_boolean_prefixes', []).append(dict(
                        phase=phase, **context,
                        scope_hex=_read_span(p, context['scope_address'], 16).hex(),
                        evaluator_descriptor_hex=_read_span(p, context['evaluator_argument_address'], 16).hex(),
                        unresolved_leaf_target_offset='0x28b05c' if context['evaluator_needed'] else '0x28c09c',
                        supported_prefix_staged=True, body_transaction_committed=False,
                        native_input_snapshot_used=False))
                def evaluator_observer(p, **context):
                    diagnostic_scope.setdefault('request_evaluator_prefixes', []).append(dict(
                        **context, native_input_snapshot_used=False))
                def evaluate(p, descriptor, count, name):
                    return leaf.execute_stack_evaluator_prefix(p, image_base=image,
                        entry_stack_address=frame.native_stack_address - 0x290,
                        descriptor_address=descriptor, descriptor_count=count,
                        method_name_address=name, observer=evaluator_observer,
                        acquire_environment=acquire_environment)
                vm9_request_boolean_gate.execute_boolean_gate(vm.m.pages,
                    object_address=words[1], image_base=image,
                    entry_stack_address=frame.native_stack_address - 0x190,
                    read_clock=read_clock, evaluate=evaluate, observer=gate_observer)
            elif allocate is not None and (wrapper, target) == (0x285F60, 0x2914D0):
                if diagnostic_scope is None or read_clock is None:
                    raise PrefixBoundary()
                import vm9_callbacks
                value = vm9_callbacks.elapsed_monotonic_microseconds(vm.m.pages,
                    object_address=words[1], read_clock=read_clock)
                _write_span(vm.m.pages, argument + 16, (value & ((1 << 64) - 1)).to_bytes(8, 'little'))
                diagnostic_scope.setdefault('elapsed_clocks', []).append(dict(
                    object_address=words[1], clock_id=1, elapsed_microseconds=value,
                    owning_clock_provider_used=True))
            elif allocate is not None and (wrapper, target) == (0x2859EC, 0x172CA4):
                if diagnostic_scope is None:
                    raise PrefixBoundary()
                readers = vm.m.u32(words[1] + 0x88)
                pointer = objects.read_shared_state_pointer(vm.m.pages, object_address=words[1])
                _write_span(vm.m.pages, argument + 16, pointer.to_bytes(8, 'little'))
                diagnostic_scope.setdefault('shared_state_pointers', []).append(dict(
                    object_address=words[1], pointer=pointer, readers_before=readers,
                    readers_after=vm.m.u32(words[1] + 0x88),
                    pointer_field_offset='0x90', pointed_value_dereferenced=False))
            elif allocate is not None and (wrapper, target) == (0x2859E0, 0x32A330):
                if diagnostic_scope is None:
                    raise PrefixBoundary()
                objects.initialize_mutex_storage(vm.m.pages, storage_address=words[1])
                diagnostic_scope.setdefault('raw_mutex_states', []).append(dict(
                    storage_address=words[1], cleared_bytes=140,
                    outer_vtable_and_flag_written=False))
            elif (wrapper, target) == (0x2858A8, 0x347F60):
                _write_span(vm.m.pages, words[1], _read_span(vm.m.pages, words[2], words[3]))
            elif (wrapper, target) == (0x2858BC, 0x25C324):
                if allocate is None:
                    raise PrefixBoundary()
                import vm9_registry as registry
                registry.construct_configuration_tree_reference(vm.m.pages,
                    output_reference_address=words[1], image_base=image, allocate=allocate)
            elif allocate is not None and (wrapper, target) == (0x2858D0, 0x26C858):
                if diagnostic_scope is None:
                    raise PrefixBoundary()
                import vm9_diagnostics
                scope = vm9_diagnostics.enter_diagnostic_scope(vm.m.pages,
                    object_address=words[1], input_word=words[2], image_base=image,
                    thread_pointer=inputs['thread_pointer'],
                    thread_id=diagnostic_scope.get('thread_id'), allocate=allocate,
                    observer=lambda *event: diagnostic_scope.setdefault('events', []).append(list(event)))
                diagnostic_scope.setdefault('scopes', []).append(scope)
            elif allocate is not None and (wrapper, target) == (0x2858E0, 0x26C9D0):
                if diagnostic_scope is None:
                    raise PrefixBoundary()
                import vm9_diagnostics
                result = vm9_diagnostics.leave_diagnostic_scope(vm.m.pages,
                    object_address=words[1], image_base=image,
                    thread_pointer=inputs['thread_pointer'],
                    observer=lambda *event: diagnostic_scope.setdefault('events', []).append(list(event)))
                diagnostic_scope.setdefault('leaves', []).append(result)
            elif allocate is not None and (wrapper, target) == (0x285928, 0x32A1F0):
                pointer = allocate(vm.m.pages, words[1])
                _write_span(vm.m.pages, argument + 0x10, pointer.to_bytes(8, 'little'))
                diagnostic_scope.setdefault('allocation_callbacks', []).append([words[1], pointer])
            elif allocate is not None and (wrapper, target) == (0x28591C, 0x2481AC):
                import vm9_objects
                vm9_objects.construct_string_object(vm.m.pages, object_address=words[1],
                    source_address=0, allocate=allocate,
                    vtable_address=image + 0x34F5F8,
                    empty_descriptor_address=image + 0x6E168)
                diagnostic_scope.setdefault('string_callbacks', []).append(words[1])
            elif allocate is not None and (wrapper, target) == (0x2859CC, 0x347F20):
                if diagnostic_scope is None:
                    raise PrefixBoundary()
                fill, size = words[2] & 255, words[3]
                if size > 0x100000:
                    raise RefillUnsupported('request memset exceeds the explicit bound')
                _write_span(vm.m.pages, words[1], bytes([fill]) * size)
                diagnostic_scope.setdefault('memory_fills', []).append(dict(
                    destination_address=words[1], value=fill, length=size))
            elif allocate is not None and (wrapper, target) == (0x2859B8, 0x25BF3C):
                if diagnostic_scope is None or free is None:
                    raise PrefixBoundary()
                import vm9_registry
                pair = vm9_registry.insert_configuration_pair(vm.m.pages,
                    container_address=words[1], key_address=words[2], value_address=words[3],
                    image_base=image, allocate=allocate, free=free)
                diagnostic_scope.setdefault('configuration_insertions', []).append(dict(
                    container_address=words[1], key_address=words[2],
                    value_address=words[3], pair_address=pair))
            elif allocate is not None and (wrapper, target) == (0x2859A8, 0x248344):
                objects.construct_string_object(vm.m.pages, object_address=words[1],
                    source_address=words[2], allocate=allocate,
                    vtable_address=image + 0x34F5F8,
                    empty_descriptor_address=image + 0x6E168)
                diagnostic_scope.setdefault('cstring_constructors', []).append(dict(
                    object_address=words[1], source_address=words[2],
                    declared_length=vm.m.u32(words[1] + 12), native_input_snapshot_used=False))
            elif allocate is not None and (wrapper, target) == (0x28591C, 0x2484B8):
                if free is None or diagnostic_scope is None:
                    raise PrefixBoundary()
                pointer = vm.m.u64(words[1] + 16)
                objects.destroy_string_object(vm.m.pages, object_address=words[1],
                    image_base=image, free=free)
                diagnostic_scope.setdefault('string_cleanups', []).append(dict(
                    object_address=words[1], released_payload=pointer))
            elif allocate is not None and (wrapper, target) == (0x28596C, 0x32D4F8):
                if diagnostic_scope is None:
                    raise PrefixBoundary()
                import vm9_startup
                before = _read_span(vm.m.pages, words[1], 8)
                vm9_startup.release_serial_guard(vm.m.pages,
                    guard_address=words[1], image_base=image)
                diagnostic_scope.setdefault('guard_releases', []).append(dict(
                    guard_address=words[1], guard_before_hex=before.hex(),
                    guard_after_hex=_read_span(vm.m.pages, words[1], 8).hex(),
                    broadcast_executed=False))
            elif allocate is not None and (wrapper, target) == (0x285944, 0x32D3A0):
                if diagnostic_scope is None:
                    raise PrefixBoundary()
                import vm9_startup
                before = _read_span(vm.m.pages, words[1], 8)
                acquired = vm9_startup.acquire_serial_guard(vm.m.pages,
                    guard_address=words[1], image_base=image,
                    thread_id=diagnostic_scope.get('thread_id'))
                _write_span(vm.m.pages, argument + 16, int(acquired).to_bytes(4, 'little'))
                diagnostic_scope.setdefault('guard_acquires', []).append(dict(
                    guard_address=words[1], acquired=acquired,
                    guard_before_hex=before.hex(),
                    guard_after_hex=_read_span(vm.m.pages, words[1], 8).hex()))
            elif allocate is not None and (wrapper, target) == (0x2858EC, 0x24880C):
                import vm9_configuration_init
                equal = vm9_configuration_init.string_equals_cstring(vm.m.pages,
                    object_address=words[1], cstring_address=words[2])
                # +0x285900 AND W8,W0,#1 and STRB at argument+0x18.
                _write_span(vm.m.pages, argument + 0x18, bytes([int(equal)]))
                diagnostic_scope.setdefault('string_comparisons', []).append(dict(
                    object_address=words[1], cstring_address=words[2], equal=equal,
                    argument_address=argument))
            elif allocate is not None and (wrapper, target) == (0x285990, 0x248908):
                if diagnostic_scope is None or reallocate is None or free is None:
                    raise PrefixBoundary()
                import vm9_configuration_init
                string_word = vm.m.u64(argument + 0x20)
                result = vm9_configuration_init.format_string_object(vm.m.pages,
                    object_address=words[1], format_address=words[2],
                    argument_addresses=(words[3] & 0xFFFFFFFF, string_word, words[0]),
                    image_base=image, allocate=allocate, reallocate=reallocate,
                    free=free, prepare_format=prepare_format)
                length = vm.m.u32(result + 12)
                pointer = vm.m.u64(result + 16)
                payload = _read_span(vm.m.pages, pointer, length) if pointer else b''
                diagnostic_scope.setdefault('formatted_strings', []).append(dict(
                    object_address=result, format_address=words[2],
                    signed_int32=objects._s32(words[3] & 0xFFFFFFFF),
                    string_argument_address=string_word, declared_length=length,
                    payload_sha256=hashlib.sha256(payload).hexdigest(),
                    format_bytes_hex=objects._cstring(vm.m.pages, words[2], 4096)[:-1].hex(),
                    native_input_snapshot_used=False))
            elif allocate is not None and (wrapper, target) == (0x285978, 0x256ED4):
                if diagnostic_scope is None:
                    raise PrefixBoundary()
                from vm9_request_nested_callbacks import (execute_nested_string_getter,
                    nested_getter_inputs_from_request)
                nested_inputs = nested_getter_inputs_from_request(vm.m.pages,
                    request_frame=frame, callback_argument_address=argument,
                    thread_pointer=inputs['thread_pointer'], image_base=image)
                result = execute_nested_string_getter(vm.m.pages, nested_inputs,
                    vm_module, allocate=allocate)
                output = result['output_address']
                source_length = result['declared_length']
                output_pointer = int.from_bytes(_read_span(vm.m.pages, output + 16, 8), 'little')
                source_pointer = int.from_bytes(_read_span(vm.m.pages, result['source_address'] + 16, 8), 'little')
                if source_length < 0x80000000 and output_pointer:
                    source_bytes = _read_span(vm.m.pages, source_pointer, source_length)
                    output_bytes = _read_span(vm.m.pages, output_pointer, source_length)
                    if source_bytes != output_bytes or _read_span(vm.m.pages, output_pointer + source_length, 1) != b'\0':
                        raise RefillUnsupported('nested getter output does not match its owning receiver')
                    payload_digest = hashlib.sha256(output_bytes).hexdigest()
                else:
                    payload_digest = None
                diagnostic_scope.setdefault('nested_getters', []).append(dict(
                    caller_inputs=nested_inputs,
                    source_address=result['source_address'], output_address=output,
                    declared_length=result['declared_length'], vm_steps=result['vm_steps'],
                    vm_exit_pc=result['vm_exit_pc'],
                    callbacks=[dict(kind=c['kind'], wrapper=c['wrapper_offset'],
                        target=c['target_offset'], words=list(c['words'])) for c in result['callbacks']],
                    output_bytes=list(_read_span(vm.m.pages, output, 24)),
                    payload_sha256=payload_digest, output_matches_receiver=payload_digest is not None,
                    acquire_reader_count=result['callbacks'][0]['reader_count'],
                    released_reader_count=result['callbacks'][2]['reader_count'],
                    source_state_injected=False, native_input_snapshot_used=False,
                    python_full_native_caller_abi_modeled=False))
            else:
                if not words[0]:
                    raise RefillUnsupported(f'NULL request callback target at wrapper +{wrapper:#x}')
                raise RefillUnsupported(f'unknown request callback +{wrapper:#x} -> +{target:#x}')
        vm.native_hook = callback
        try:
            vm.run()
        except PrefixBoundary:
            return staged, frame, vm, ledger, decoded
        except vm_module.VMExit:
            from vm9_request_caller import validate_request_vm_exit
            if diagnostic_scope is None:
                raise RefillUnsupported('request VM completion requires its owning diagnostic context')
            result = validate_request_vm_exit(staged,image_base=image,pc=vm.pc,
                registers=tuple(vm.R),return_address=inputs['return_address'])
            result.update(vm_steps=vm.steps,all_dispatched_callback_models_returned=True,
                whole_native_request_equivalence_verified=False,
                request_transaction_committed_to_supplied_pages=True)
            staged.commit()
            diagnostic_scope['request_vm_return'] = result
            return staged, frame, vm, ledger, decoded
        except Exception as exc:
            if diagnostic_scope is not None:
                raise RequestContinuationBoundary(staged=staged, frame=frame, vm=vm,
                    ledger=ledger, decoded=decoded, cause=exc) from exc
            print("prefix failed at",vm.steps,hex(vm.pc-image),flush=True)
            raise
        raise AssertionError('request prefix did not reach the allocation boundary')
    finally:
        vm_module.B = previous


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
