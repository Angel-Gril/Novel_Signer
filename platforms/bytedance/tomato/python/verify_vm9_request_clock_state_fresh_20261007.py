"""Fresh native differences for request monotonic time and raw mutex storage.

The original ELF bodies execute under Unicorn. clock_gettime is an explicit
status/sec/nsec service; these controls do not execute the Android OS clock.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from unicorn import arm64_const as arm

import vm9_callbacks as callbacks
import vm9_objects as objects
import vm9_startup as startup
from verify_vm9_libc_mapping import LIBC_SHA256
from vm9_allocator import RefillUnsupported, _read_span, _write_span
from verify_vm9_signer_objects import GUEST, LIBRARY_SHA256, fresh_pages, image_pages, native

BASES = (0x122C0000, 0x775C205000)
MASK64 = (1 << 64) - 1
OBJECT, PACKED = GUEST + 0x2000, GUEST + 0x3800


def clock_case(library, image, control, operation, wrapper):
    pages = {**image_pages(library, image), **fresh_pages()}
    seconds, nanoseconds = control['seconds'], control['nanoseconds']
    current = (seconds * 1_000_000_000 + nanoseconds) & MASK64
    delta = control.get('delta', 0)
    start = (current - delta) & MASK64
    _write_span(pages, OBJECT, start.to_bytes(8, 'little') + bytes([0xD3]) * 32)
    target = 0x291440 if operation == 'store' else 0x2914D0
    entry = (0x28589C if operation == 'store' else 0x285F60) if wrapper else target
    _write_span(pages, PACKED, b''.join(v.to_bytes(8, 'little') for v in
        (image + target, OBJECT, 0xA5A5A5A5A5A5A5A5, 0x5A5A5A5A5A5A5A5)))
    model = {k: bytearray(v) for k, v in pages.items()}
    native_calls, model_calls = [], []
    def read_native(cpu):
        clock_id = cpu.reg_read(arm.UC_ARM64_REG_X0)
        assert clock_id == 1
        native_calls.append([clock_id, 0, seconds, nanoseconds])
        if control.get('provider_updates_start'):
            cpu.mem_write(OBJECT, start.to_bytes(8, 'little'))
        cpu.mem_write(cpu.reg_read(arm.UC_ARM64_REG_X1),
            seconds.to_bytes(8, 'little', signed=True) + nanoseconds.to_bytes(8, 'little', signed=True))
        return 0
    def read_model(p, clock_id):
        assert clock_id == 1
        model_calls.append([clock_id, 0, seconds, nanoseconds])
        if control.get('provider_updates_start'):
            _write_span(p, OBJECT, start.to_bytes(8, 'little'))
        return 0, seconds, nanoseconds
    if control.get('provider_updates_start'):
        # The initial slot differs from the start published inside the provider.
        _write_span(pages, OBJECT, (current - 10000 & MASK64).to_bytes(8, 'little'))
        _write_span(model, OBJECT, (current - 10000 & MASK64).to_bytes(8, 'little'))
    returned, memory, allocations, services = native(library, image, entry,
        [PACKED] if wrapper else [OBJECT], pages,
        host_imports={0x348450: read_native}, instruction_limit=10000)
    if operation == 'store':
        result = callbacks.store_monotonic_start(model, object_address=OBJECT, read_clock=read_model)
        expected = current
    else:
        result = callbacks.elapsed_monotonic_microseconds(model, object_address=OBJECT, read_clock=read_model)
        expected = (-1 if delta < 0 else 1) * (abs(delta) // 1000)
    assert result & MASK64 == expected & MASK64
    assert returned == result & MASK64
    if wrapper and operation == 'elapsed':
        _write_span(model, PACKED + 16, (result & MASK64).to_bytes(8, 'little'))
    assert _read_span(model, GUEST, 0xA000) == memory
    assert model_calls == native_calls == [[1, 0, seconds, nanoseconds]]
    assert not allocations and not services
    return dict(image_base=hex(image), case=control['name'], operation=operation,
        wrapper_executed=wrapper, explicit_clock_id=1, seconds=seconds, nanoseconds=nanoseconds,
        delta_nanoseconds=delta if operation == 'elapsed' else None,
        result_signed_or_raw=str(result), full_payload_and_packed_memory_match=True,
        native_return_matches=True, provider_order_verified=True,
        native_input_snapshot_used=False, actual_os_clock_executed=False)


def storage_case(library, image, offset, wrapper):
    pages = {**image_pages(library, image), **fresh_pages()}
    target = GUEST + offset
    poison = bytes((i * 17 + 91) & 255 for i in range(0xD0))
    _write_span(pages, target - 16, poison)
    _write_span(pages, PACKED, b''.join(v.to_bytes(8, 'little') for v in
        (image + 0x32A330, target, 0xA5A5A5A5A5A5A5A5, 0x5A5A5A5A5A5A5A5)))
    returned, memory, allocations, services = native(library, image,
        0x2859E0 if wrapper else 0x32A330, [PACKED] if wrapper else [target], pages)
    objects.initialize_mutex_storage(pages, storage_address=target)
    assert returned == target
    assert _read_span(pages, target, 140) == bytes(140)
    assert _read_span(pages, target - 16, 16) == poison[:16]
    assert _read_span(pages, target + 140, len(poison) - 156) == poison[156:]
    assert _read_span(pages, GUEST, 0xA000) == memory
    assert not allocations and not services
    return dict(image_base=hex(image), storage_offset=hex(offset), wrapper_executed=wrapper,
        cleared_bytes=140, prefix_and_suffix_preserved=True, full_payload_memory_match=True,
        native_return_matches=True, outer_vtable_and_flag_not_written=True,
        native_input_snapshot_used=False)


def pointer_getter_case(library, libc, image, control, wrapper):
    pages = {**image_pages(library, image), **fresh_pages()}
    target = GUEST + control['offset']
    _write_span(pages, target, bytes((i * 17 + 91) & 255 for i in range(0xA0)))
    _write_span(pages, target, control['mutex'].to_bytes(2, 'little'))
    _write_span(pages, target + 0x88, control['readers'].to_bytes(4, 'little'))
    _write_span(pages, target + 0x90, control['pointer'].to_bytes(8, 'little'))
    _write_span(pages, PACKED, b''.join(v.to_bytes(8, 'little') for v in
        (image + 0x172CA4, target, 0xA5A5A5A5A5A5A5A5, 0x5A5A5A5A5A5A5A5)))
    read_observations = []
    def observe(cpu, address):
        if address == image + 0x172858:
            read_observations.append(int.from_bytes(cpu.mem_read(target + 0x88, 4), 'little'))
    returned, memory, allocations, services = native(library, image,
        0x2859EC if wrapper else 0x172CA4, [PACKED] if wrapper else [target], pages,
        libc=libc, real_mutexes=True, instruction_observer=observe, instruction_limit=100000)
    result = objects.read_shared_state_pointer(pages, object_address=target)
    assert result == returned == control['pointer']
    if wrapper:
        _write_span(pages, PACKED + 16, result.to_bytes(8, 'little'))
    assert _read_span(pages, GUEST, 0xA000) == memory
    assert int.from_bytes(_read_span(pages, target + 0x88, 4), 'little') == control['readers']
    assert read_observations == [control['readers'] + 1]
    assert services == [['pthread_mutex_lock', target], ['pthread_mutex_unlock', target]] * 2
    assert not allocations
    return dict(image_base=hex(image), case=control['name'], wrapper_executed=wrapper,
        pointer_field_offset='0x90', returned_word=hex(result), pointed_value_dereferenced=False,
        full_payload_and_packed_memory_match=True, native_return_matches=True,
        reader_acquire_load_release_observed=True, readers_before_and_after=control['readers'],
        matching_libc_mutex_executed=True, native_input_snapshot_used=False)


def outer_constructor_regression(library, image, offset):
    pages = fresh_pages()
    target = GUEST + offset
    _, memory, allocations, services = native(library, image, 0x17D7E0, [target], pages)
    objects.construct_mutex_state(pages, object_address=target, image_base=image)
    assert _read_span(pages, GUEST, 0xA000) == memory
    assert not allocations and not services
    return dict(image_base=hex(image), object_offset=hex(offset),
        full_payload_memory_match=True, existing_outer_constructor_behavior_preserved=True)


def guard_release_case(library, libc, image, byte0, byte1, mutex):
    pages = {**image_pages(library, image), **fresh_pages()}
    _write_span(pages, OBJECT, bytes([byte0, byte1]) + bytes.fromhex('5aa534120000'))
    _write_span(pages, image + 0x3E2F40, mutex.to_bytes(2, 'little'))
    _write_span(pages, PACKED, b''.join(v.to_bytes(8, 'little') for v in
        (image + 0x32D4F8, OBJECT, 0xA5A5A5A5A5A5A5A5)))
    observed = {(image + 0x3E2F40, 40): None}
    writes, model_writes = [], []
    def watch(cpu, address, width):
        if OBJECT <= address < OBJECT + 8:
            writes.append([address - OBJECT, width, int.from_bytes(cpu.mem_read(image + 0x3E2F40, 2), 'little')])
    _, memory, allocations, services = native(library, image, 0x28596C, [PACKED], pages,
        libc=libc, real_mutexes=True, real_singletons=True, observed_memory=observed,
        memory_write_observer=watch)
    original_write = startup._write_span
    def observe_model(p, address, data):
        if OBJECT <= address < OBJECT + 8:
            model_writes.append([address - OBJECT, len(data),
                int.from_bytes(_read_span(p, image + 0x3E2F40, 2), 'little')])
        return original_write(p, address, data)
    startup._write_span = observe_model
    try:
        startup.release_serial_guard(pages, guard_address=OBJECT, image_base=image)
    finally:
        startup._write_span = original_write
    assert model_writes == writes
    assert _read_span(pages, GUEST, 0xA000) == memory
    assert _read_span(pages, image + 0x3E2F40, 40) == observed[image + 0x3E2F40, 40]
    assert services == [['pthread_mutex_lock', image + 0x3E2F40], ['pthread_mutex_unlock', image + 0x3E2F40]]
    assert not allocations
    # Native stores byte0 before acquiring the mutex and byte1 while locked.
    assert writes == [[0, 1, mutex], [1, 1, mutex | 1]], writes
    return dict(image_base=hex(image), initial_byte0=byte0, initial_byte1=byte1,
        initial_mutex=mutex, full_payload_guard_and_global_mutex_match=True,
        matching_libc_mutex_executed=True, publish_before_lock_order_observed=True,
        guard_padding_preserved=True, no_waiter_broadcast=True, native_input_snapshot_used=False)


def negatives(library, image):
    names = []
    for label, provider in (
        ('clock_error', lambda p, i: (-1, 0, 0)),
        ('bad_shape', lambda p, i: (0, 1)),
        ('fractional_seconds', lambda p, i: (0, 1.5, 0)),
        ('seconds_overflow', lambda p, i: (0, 1 << 63, 0)),
        ('negative_nanoseconds', lambda p, i: (0, 0, -1)),
        ('nanoseconds_overflow', lambda p, i: (0, 0, 1_000_000_000)),
    ):
        for operation in ('store', 'elapsed'):
            p = {**image_pages(library, image), **fresh_pages()}
            before = {k: bytes(v) for k, v in p.items()}
            function = callbacks.store_monotonic_start if operation == 'store' else callbacks.elapsed_monotonic_microseconds
            try:
                function(p, object_address=OBJECT, read_clock=provider)
            except RefillUnsupported:
                pass
            else:
                raise AssertionError(label + ' accepted')
            assert {k: bytes(v) for k, v in p.items()} == before
            names.append(operation + '_' + label + '_refused_without_page_changes')
    # Partial page access must not clear the mapped prefix on failure.
    p = {1: bytearray([0xD3]) * 4096}
    before = {k: bytes(v) for k, v in p.items()}
    try:
        objects.initialize_mutex_storage(p, storage_address=0x1FC0)
    except (RefillUnsupported, ValueError):
        pass
    else:
        raise AssertionError('unmapped state accepted')
    assert {k: bytes(v) for k, v in p.items()} == before
    names.append('unmapped_storage_refused_without_page_changes')
    for label, byte1, mutex in (('waiting_release', 6, 0), ('contended_release', 2, 1)):
        p = {**image_pages(library, image), **fresh_pages()}
        _write_span(p, OBJECT, bytes([0, byte1]) + bytes(6))
        _write_span(p, image + 0x3E2F40, mutex.to_bytes(2, 'little'))
        before = {k: bytes(v) for k, v in p.items()}
        try:
            startup.release_serial_guard(p, guard_address=OBJECT, image_base=image)
        except RefillUnsupported:
            pass
        else:
            raise AssertionError(label + ' accepted')
        assert {k: bytes(v) for k, v in p.items()} == before
        names.append(label + '_refused_without_page_changes')
    for label, readers, mutex in (('writer_pointer_getter', 0x80000000, 0),
            ('saturated_pointer_getter', 0x7FFFFFFF, 0), ('contended_pointer_getter', 0, 1)):
        p = {**image_pages(library, image), **fresh_pages()}
        _write_span(p, OBJECT, bytes(0xA0))
        _write_span(p, OBJECT, mutex.to_bytes(2, 'little'))
        _write_span(p, OBJECT + 0x88, readers.to_bytes(4, 'little'))
        before = {k: bytes(v) for k, v in p.items()}
        try:
            objects.read_shared_state_pointer(p, object_address=OBJECT)
        except RefillUnsupported:
            pass
        else:
            raise AssertionError(label + ' accepted')
        assert {k: bytes(v) for k, v in p.items()} == before
        names.append(label + '_refused_without_page_changes')
    return names


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--library', type=Path, required=True)
    parser.add_argument('--libc', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest() == LIBC_SHA256
    clocks, storage, guards, regressions, pointers = [], [], [], [], []
    stores = [dict(name=name, seconds=s, nanoseconds=n) for name, s, n in
        (('zero', 0, 0), ('nanosecond_tail', 1, 999999999),
         ('madd_wrap', (1 << 63) - 1, 731), ('signed_timespec', -1, 123))]
    elapsed = [dict(name=name, seconds=42, nanoseconds=731, delta=delta) for name, delta in
        (('zero', 0), ('positive_submicro', 999), ('positive_exact', 1000),
         ('negative_submicro', -999), ('negative_truncation', -1001),
         ('sub_wrap_positive', 9223372036854775807), ('sub_wrap_negative', -(1 << 63)))]
    elapsed.append(dict(name='provider_updates_start', seconds=42, nanoseconds=731,
        delta=1500, provider_updates_start=True))
    pointer_controls = [
        dict(name='null', offset=0x2300, readers=0, mutex=0, pointer=0),
        dict(name='ordinary', offset=0x2300, readers=7, mutex=0, pointer=GUEST + 0x1000),
        dict(name='shared_high_pointer', offset=0x2300, readers=17, mutex=0x2000, pointer=0x775C5545F8),
        dict(name='raw_max_word', offset=0x2300, readers=0, mutex=0, pointer=MASK64),
        dict(name='cross_page', offset=0x2FF8, readers=8, mutex=0, pointer=GUEST + 0x1000),
    ]
    for image in BASES:
        for operation, controls in (('store', stores), ('elapsed', elapsed)):
            for control in controls:
                for wrapper in (False, True):
                    clocks.append(clock_case(args.library, image, control, operation, wrapper))
                print('request clock', hex(image), operation, control['name'], 'PASS', flush=True)
        for offset in (0x2100, 0x2FF8):
            for wrapper in (False, True):
                storage.append(storage_case(args.library, image, offset, wrapper))
            print('request raw state', hex(image), hex(offset), 'PASS', flush=True)
        for offset in (0x1000, 0x1FF0):
            regressions.append(outer_constructor_regression(args.library, image, offset))
            print('outer state constructor', hex(image), hex(offset), 'PASS', flush=True)
        for byte0, byte1, mutex in ((0, 2, 0), (1, 1, 0), (2, 0, 0x2000)):
            guards.append(guard_release_case(args.library, args.libc, image, byte0, byte1, mutex))
            print('request guard release', hex(image), byte0, byte1, mutex, 'PASS', flush=True)
        for control in pointer_controls:
            for wrapper in (False, True):
                pointers.append(pointer_getter_case(args.library, args.libc, image, control, wrapper))
            print('request shared pointer', hex(image), control['name'], 'PASS', flush=True)
    negative = negatives(args.library, BASES[0])
    report = dict(schema='vm9-request-clock-state-fresh-differential-v1', evidence_date='2026-10-07',
        sample_sha256=LIBRARY_SHA256, libc_sha256=LIBC_SHA256,
        clock_controls=len(clocks), storage_controls=len(storage), guard_release_controls=len(guards),
        negative_controls=len(negative), outer_constructor_regression_controls=len(regressions),
        outer_constructor_regressions=regressions, shared_pointer_controls=len(pointers),
        shared_pointer_cases=pointers, clock_cases=clocks, storage_cases=storage,
        guard_release_cases=guards, negative_checks=negative,
        signed_subtract_and_truncating_divide_verified=True, monotonic_clock_id=1,
        raw_state_bytes=140, actual_os_clock_executed=False, native_input_snapshot_used=False,
        whole_handoff_native_differential_verified=False, complete_python_medusa=False,
        fresh_input_signer_output_verified=False, current_online_header_matrix_verified=False,
        limitations=['Successful clock path uses explicit provider status/sec/nsec, not Android OS execution.',
            'Native clock error/abort path is refused; external provider side effects are not rolled back.',
            'Only payload/packed slots and returns are compared; native stack/TLS/image full state is not compared.',
            'Component differences do not establish real URL/header/JNI or complete request equivalence.'])
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('request clock/state/guard', len(clocks), '+', len(storage), '+', len(guards), '+', len(pointers), 'native controls;', len(negative), 'negative PASS')


if __name__ == '__main__':
    main()
