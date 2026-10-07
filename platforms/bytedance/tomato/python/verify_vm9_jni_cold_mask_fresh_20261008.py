"""Fresh native cold-once getter/mask controls with explicit JVM/OS services.

Actual ctor and JNI initializer are joined by two explicit continuations.
Matching libc executes mutex and condition broadcast bodies. Waiting once,
C++ unwind, startup VM bodies and complete JNI_OnLoad remain out of scope.
"""
from __future__ import annotations
import argparse
import collections
import hashlib
import json
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as arm
import vm9_jni_environment as environment
import vm9_objects as objects
import verify_vm9_jni_cold_once_fresh_20261008 as cold
import verify_vm9_jni_environment_fresh_20261007 as acquisition
import verify_vm9_jni_initialization_fresh_20261007 as initialization
from verify_vm9_root_configuration import LIBC_BASE
from verify_vm9_signer_objects import GUEST, STOP, LIBRARY_SHA256, native
from verify_vm9_strings import Effects
from vm9_allocator import RefillUnsupported, _read_span, _write_span

MASK64 = (1 << 64) - 1
SP = cold.SP
TABLE = GUEST + 0x6000


def fixture(library, base, profile):
    pages, blocks = cold.fixture(library, base, profile)
    # Permanent JNI data stays below both startup callers' stack footprints.
    _write_span(pages, TABLE, _read_span(pages, cold.TABLE, 4096))
    cold.w(pages, cold.ENV, TABLE)
    cold.w(pages, cold.INNER_ENV, TABLE)
    cold.w(pages, base + 0x3D1570, profile.get('once', 0))
    cold.w(pages, base + 0x3D1578, profile.get('cached', 0))
    cold.w(pages, base + 0x3E2EB8, profile.get('mutex', 0), 2)
    cold.w(pages, base + 0x3E2EE0, profile.get('condition', 0), 4)
    return pages, blocks


def run_native(args, base, profile, entry, mask):
    pages, blocks = fixture(args.library, base, profile)
    effects = Effects(blocks=blocks)
    needs_caller = profile.get('once', 0) == 0
    responses = [(0, cold.ENV)] * ((2 if profile.get('warm_tls') else 3) if needs_caller else 0)
    vm = acquisition.Providers(base, effects, responses)
    jni = cold.JNI(base, profile)
    if not needs_caller:
        jni.checks = []
    imports = vm.imports()
    imports.update(jni.imports())
    exits, drivers, entries, mutex_events, wake_events = [], [], [], [], []
    trace = collections.deque(maxlen=24)
    caller_pairs = []
    original_exit = imports[0x347EA0]
    with args.libc.open('rb') as stream:
        elf = ELFFile(stream)
        broadcast_address = next(LIBC_BASE + symbol['st_value']
            for section in elf.iter_sections() if section['sh_type'] == 'SHT_DYNSYM'
            for symbol in section.iter_symbols() if symbol.name == 'pthread_cond_broadcast')

    def broadcast(cpu):
        assert cpu.reg_read(arm.UC_ARM64_REG_X0) == base + 0x3E2EE0
        cpu.reg_write(arm.UC_ARM64_REG_PC, broadcast_address)
        return None

    def syscall(cpu, number):
        assert number == 98
        values = [cpu.reg_read(getattr(arm, 'UC_ARM64_REG_X' + str(i))) for i in range(3)]
        expected_operation = 1 if profile.get('condition', 0) & 1 else 129
        assert values == [base + 0x3E2EE0, expected_operation, 0x7FFFFFFF]
        assert int.from_bytes(cpu.mem_read(base + 0x3D1570, 8), 'little') == MASK64
        assert int.from_bytes(cpu.mem_read(base + 0x3E2EB8, 2), 'little') & ~0x2000 == 0
        wake_events.append([number, *values, 0])
        return 0

    def constructor_exit(cpu):
        values = [cpu.reg_read(getattr(arm, 'UC_ARM64_REG_X' + str(i))) for i in range(3)]
        if values == [base + 0x165388, base + 0x3DF118, base + 0x34C700]:
            assert not exits and cpu.reg_read(arm.UC_ARM64_REG_SP) == SP
            exits.append([*values, 0])
            cpu.reg_write(arm.UC_ARM64_REG_X0, cold.ENV)
            cpu.reg_write(arm.UC_ARM64_REG_X1, cold.NAME)
            cpu.reg_write(arm.UC_ARM64_REG_X30, cold.INIT_RETURN)
            cpu.reg_write(arm.UC_ARM64_REG_PC, base + 0x26E19C)
            drivers.append(['ctor_exit_to', '0x26e19c'])
            return None
        return original_exit(cpu)

    def initialization_return(cpu):
        assert cpu.reg_read(arm.UC_ARM64_REG_SP) == SP
        cpu.reg_write(arm.UC_ARM64_REG_X0, mask)
        cpu.reg_write(arm.UC_ARM64_REG_X30, STOP)
        cpu.reg_write(arm.UC_ARM64_REG_PC, base + entry)
        drivers.append(['initializer_return_to', hex(entry)])
        return None

    imports.update({0x347EA0: constructor_exit, cold.INIT_RETURN - base: initialization_return,
                    0x3485A0: broadcast})

    def observe(cpu, address):
        offset = address - base
        trace.append(hex(offset))
        if offset == 0x26E70C:
            jni.dispatch_sp = cpu.reg_read(arm.UC_ARM64_REG_SP)
        if offset == 0x270854:
            jni.long_sp = cpu.reg_read(arm.UC_ARM64_REG_SP)
        if offset == 0x165658:
            assert int.from_bytes(cpu.mem_read(base + 0x3D1570, 8), 'little') == 1
            assert int.from_bytes(cpu.mem_read(base + 0x3E2EB8, 2), 'little') & ~0x2000 == 0
        if offset == 0x165680:
            frame = cpu.reg_read(arm.UC_ARM64_REG_SP)
            caller_pairs.append(bytes(cpu.mem_read(frame + 8, 16)).hex())
        if offset in (0x165560, 0x165588, 0x1655E0, 0x32A0A0, 0x165644,
                      0x165648, 0x165658, 0x1658DC):
            entries.append(hex(offset))
        if offset in (0x347F00, 0x347F10):
            pointer = cpu.reg_read(arm.UC_ARM64_REG_X0)
            if pointer == base + 0x3E2EB8:
                mutex_events.append(['lock' if offset == 0x347F00 else 'unlock', pointer])

    observed = {(key << 12, 4096): None for key in pages if base <= key << 12 < base + 0x400000}
    # Caller and wrapper data are live effects, unlike saved registers/canary.
    getter_entry = SP if entry == 0x165588 else SP - 0x20
    wrapper_frame = getter_entry - 0x70
    if profile.get('once', 0) != MASK64:
        observed[wrapper_frame + 8, 16] = None
    try:
        result, memory, allocations, ledger = native(args.library, base, 0x271940, [], pages,
            libc=args.libc, real_singletons=True, real_mutexes=True, thread_id=137,
            real_jni_acquisition=True, real_jni_dispatch=True, host_imports=imports,
            malloc_handler=lambda cpu, size: effects.native(cpu, 'malloc', size),
            instruction_observer=observe, observed_memory=observed, syscall_handler=syscall,
            instruction_limit=300000)
    except Exception:
        print('last PCs:', list(trace), flush=True)
        raise
    assert not vm.responses and not jni.checks and not allocations
    assert len(wake_events) == int(needs_caller)
    return pages, blocks, effects, vm, jni, exits, drivers, entries, mutex_events, wake_events, caller_pairs, observed, memory, result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--library', type=Path, required=True)
    parser.add_argument('--libc', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest() == initialization.LIBC_SHA256
    controls, negatives = [], []
    profiles = [
        ('cold_zero', {}, 0x200, 0x165560),
        ('cold_flag', {'long_word': 0x200}, 0x200, 0x165560),
        ('zero_mask_still_initializes', {'long_word': 0x55}, 0, 0x165560),
        ('full_u64_mask', {'long_word': 0x200}, (1 << 40) | 0x200, 0x165560),
        ('high_word_subset', {'long_word': 0xF123456789ABCDEF}, 0x8100000000000400, 0x165560),
        ('null_object_retains_cache', {'null_object': True, 'cached': 0x200}, 0x200, 0x165560),
        ('missing_method_overwrites_cache', {'missing_method': True, 'cached': 0x200}, 0x200, 0x165560),
        ('dispatcher_exception_retains_cache', {'checks': (1, 0), 'cached': 0x200}, 0x200, 0x165560),
        ('warm_tls', {'warm_tls': True, 'long_word': 0x200}, 0x200, 0x165560),
        ('shared_mutex_and_condition', {'mutex': 0x2000, 'condition': 1, 'long_word': 0x200}, 0x200, 0x165560),
        ('condition_u32_wrap', {'condition': 0xFFFFFFFC, 'long_word': 0x200}, 0x200, 0x165560),
        ('completed_fast_path', {'once': MASK64, 'cached': 0x200}, 0x200, 0x165560),
        ('completed_without_JNI_OS_services', {'once': MASK64, 'cached': 0x200, 'no_getter_services': True}, 0x200, 0x165560),
        ('other_nonzero_once', {'once': 2, 'cached': 0x200}, 0x200, 0x165560),
        ('direct_word_getter', {'long_word': 0xF123456789ABCDEF}, 0, 0x165588),
        ('startup_fixed_mask_false', {}, MASK64, 0x1658DC),
        ('startup_fixed_mask_true', {'long_word': 0x200}, MASK64, 0x1658DC),
    ]
    for base in (0x122C0000, 0x775C205000):
        for label, profile, mask, entry in profiles:
            (pages, blocks, expected_effects, expected_vm, expected_jni, expected_exits, drivers,
             entries, expected_mutex, expected_wake, expected_pairs, observed, memory, result) = run_native(args, base, profile, entry, mask)
            effects = Effects(blocks=blocks)
            # Response count depends on the fixture profile, never on native output.
            vm = acquisition.Providers(base, effects, [(0, cold.ENV)] *
                ((2 if profile.get('warm_tls') else 3) if profile.get('once', 0) == 0 else 0))
            jni = cold.JNI(base, profile)
            if profile.get('once', 0) != 0:
                jni.checks = []
            exits, actual_mutex, actual_wake, actual_pairs = [], [], [], []
            def register(p, fn, obj, dso):
                exits.append([fn, obj, dso, 0]);return 0
            environment.initialize_java_cache_mutexes(pages, image_base=base, allocate=effects.malloc, register_exit=register)
            environment.initialize_java_dispatch(pages, image_base=base, entry_stack_address=SP,
                environment_pointer=cold.ENV, class_name_address=cold.NAME, invoke_jni=jni.model)
            getter_entry = SP if entry == 0x165588 else SP - 0x20
            caller_frame = getter_entry - 0x70 - 0x40 - 0x50
            jni.dispatch_sp = jni.long_sp = caller_frame
            def acquire(p, *, entry_stack_address, output_pair_address):
                assert cold.u(p, base + 0x3D1570) == 1
                assert cold.u(p, base + 0x3E2EB8, 2) & ~0x2000 == 0
                result = environment.acquire_thread_environment(p, image_base=base,
                    entry_stack_address=entry_stack_address, output_pair_address=output_pair_address,
                    get_tls=vm.tls, register_destructor=vm.register, invoke_javavm=vm.model_vm)
                if output_pair_address == caller_frame + 8:
                    actual_pairs.append(_read_span(p, output_pair_address, 16).hex())
                return result
            def wake(p, pointer, operation, count):
                assert cold.u(p, base + 0x3D1570) == MASK64
                assert cold.u(p, base + 0x3E2EB8, 2) & ~0x2000 == 0
                actual_wake.append([98, pointer, operation, count, 0]);return 0
            # Observe only the once mutex operations; the production owner uses the existing mutex owner.
            saved_lock, saved_unlock = objects.lock_uncontended_mutex, objects.unlock_uncontended_mutex
            def lock(p, *, mutex_address):
                if mutex_address == base + 0x3E2EB8:actual_mutex.append(['lock', mutex_address])
                return saved_lock(p, mutex_address=mutex_address)
            def unlock(p, *, mutex_address):
                if mutex_address == base + 0x3E2EB8:actual_mutex.append(['unlock', mutex_address])
                return saved_unlock(p, mutex_address=mutex_address)
            objects.lock_uncontended_mutex, objects.unlock_uncontended_mutex = lock, unlock
            services = dict(acquire_environment=acquire, invoke_jni=jni.model, wake_condition=wake)
            if profile.get('no_getter_services'):
                services = {key: None for key in services}
            try:
                if entry == 0x165588:
                    modeled = environment.read_cold_java_switch(pages, image_base=base, entry_stack_address=SP,
                        **services)
                    actual_result = modeled.switch_word
                else:
                    effective_mask = 0x200 if entry == 0x1658DC else mask
                    modeled = environment.check_cold_java_switch_mask(pages, image_base=base, entry_stack_address=SP,
                        mask=effective_mask, acquire_environment=acquire, invoke_jni=jni.model, wake_condition=wake)
                    actual_result = int(modeled.matched)
            finally:
                objects.lock_uncontended_mutex, objects.unlock_uncontended_mutex = saved_lock, saved_unlock
            assert actual_result == result, (label, hex(actual_result), hex(result))
            assert memory == _read_span(pages, GUEST, 0xA000), label
            assert expected_effects.calls == effects.calls and expected_vm.events == vm.events
            assert expected_jni.events == jni.events and expected_exits == exits
            assert expected_mutex == actual_mutex and expected_wake == actual_wake
            assert expected_pairs == actual_pairs
            assert not vm.responses and not jni.checks
            for (address, width), data in observed.items():
                assert data == _read_span(pages, address, width), (label, hex(address))
            read_result = modeled if entry == 0x165588 else modeled.switch
            controls.append(dict(label=label, image_base=hex(base), entry=hex(entry), input_mask_hex=hex(mask), profile=profile,
                native_result_hex=hex(result), switch_word_hex=hex(read_result.switch_word), initialized=read_result.initialized,
                once_state_before_hex=hex(read_result.once_state_before), once_state_after_hex=hex(cold.u(pages, base + 0x3D1570)),
                condition_u32_after=cold.u(pages, base + 0x3E2EE0, 4), once_mutex_events=actual_mutex,
                no_waiter_futex_events=actual_wake, native_entries=entries, explicit_driver_continuations=drivers,
                native_python_return_and_guest_match=True, all_main_image_pages_match=True,
                live_wrapper_links_and_consumed_caller_pair_match=True,
                expired_caller_pair_compared_at_final_return=False, consumed_JNI_variadic_parameters_match=True,
                allocator_VM_JNI_exit_effect_groups_match=True,
                initializer_runs_unlocked_with_once_one_verified=True,
                completion_published_and_mutex_unlocked_before_wake_verified=True,
                unused_GP_SIMD_and_physical_ABI_compared=False,
                native_input_snapshot_used=False, whole_JNI_OnLoad_compared=False))
            print('once/mask:', hex(base), label, 'passed', flush=True)
    base = 0x122C0000
    for label, profile, overrides in [
        ('unaligned_stack', {}, {'entry_stack_address': SP - 1}),
        ('negative_mask', {}, {'mask': -1}),
        ('oversize_mask', {}, {'mask': 1 << 64}),
        ('once_waiter', {'once': 1}, {}),
        ('contended_mutex', {'mutex': 2}, {}),
        ('missing_acquisition', {}, {'acquire_environment': None}),
        ('missing_JNI', {}, {'invoke_jni': None}),
        ('late_missing_wake', {}, {'wake_condition': None}),
        ('late_wake_failure', {}, {}),
    ]:
        pages, blocks = fixture(args.library, base, profile)
        effects = Effects(blocks=blocks)
        vm = acquisition.Providers(base, effects, [(0, cold.ENV)] * 3)
        jni = cold.JNI(base, profile)
        environment.initialize_java_cache_mutexes(pages, image_base=base, allocate=effects.malloc, register_exit=lambda *x: 0)
        environment.initialize_java_dispatch(pages, image_base=base, entry_stack_address=SP,
            environment_pointer=cold.ENV, class_name_address=cold.NAME, invoke_jni=jni.model)
        jni.dispatch_sp = jni.long_sp = SP - 0x120
        def acquire(p, *, entry_stack_address, output_pair_address):
            return environment.acquire_thread_environment(p, image_base=base,
                entry_stack_address=entry_stack_address, output_pair_address=output_pair_address,
                get_tls=vm.tls, register_destructor=vm.register, invoke_javavm=vm.model_vm)
        def wake(p, pointer, operation, count):
            if label == 'late_wake_failure':return -1
            return 0
        options = dict(image_base=base, entry_stack_address=SP, mask=0x200,
            acquire_environment=acquire, invoke_jni=jni.model, wake_condition=wake)
        options.update(overrides)
        before = {key: bytes(value) for key, value in pages.items()}
        previous_events = len(jni.events)
        try:
            environment.check_cold_java_switch_mask(pages, **options)
        except (RefillUnsupported, ValueError):pass
        else:raise AssertionError('negative accepted: ' + label)
        assert before == {key: bytes(value) for key, value in pages.items()}
        external_events = len(jni.events) > previous_events
        assert external_events == (label in ('late_wake_failure', 'late_missing_wake'))
        negatives.append(dict(label=label, pages_unchanged=True, external_JNI_events_retained=external_events))
    evidence = dict(schema='vm9-jni-cold-once-mask-fresh-differential-v1', evidence_date='2026-10-08',
        evidence_timezone='Asia/Shanghai', sample_sha256=LIBRARY_SHA256, matching_libc_sha256=initialization.LIBC_SHA256,
        native_python_controls=len(controls), negative_controls=len(negatives), cases=controls, negative_checks=negatives,
        JNI_table_offset_hex=hex(TABLE - GUEST), explicit_driver_continuations_used=True,
        matching_libc_mutex_and_condition_bodies_executed=True, explicit_allocator_VM_JNI_OS_exit_services_used=True,
        native_input_snapshot_used=False, legacy_acquisition_and_dispatch_stubs_disabled=True,
        waiting_once_and_CPP_unwind_recovered=False, host_concurrency_verified=False,
        all_ELF_constructors_recovered=False, full_cold_TLS_subsystem_boot_verified=False,
        full_JNI_OnLoad_recovered=False, startup_VM_body_verified=False, complete_python_medusa=False,
        fresh_signer_output_verified=False, live_server_matrix_verified=False)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2) + '\n', encoding='utf-8')
    print('once/mask controls:', len(controls), '; negatives:', len(negatives), 'passed')


if __name__ == '__main__':main()
