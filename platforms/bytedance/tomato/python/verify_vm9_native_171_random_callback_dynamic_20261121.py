"""Continue the captured request into its already-owned random callback."""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from unicorn import arm64_const as arm

import verify_vm9_native_171_gettimeofday_dynamic_20261121 as prefix

EVIDENCE = prefix.EVIDENCE.with_name('vm9_native_171_random_callback_dynamic_20261121.json')
SCHEMA = 'vm9-native-171-random-callback-dynamic-20261121-v1'
WRAPPER_CALL = 0x288648
WRAPPER_POST_STORE = 0x288650
RANDOM_GETTER = 0x26CC8C
RAND_PLT = 0x348020
SRAND_PLT = 0x348040
RANDOM_GUARD = 0x3DEDB0


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parent_evidence() -> dict:
    data = json.loads(prefix.EVIDENCE.read_text())
    prefix.validate(data)
    return data


def source_fingerprints() -> dict:
    owner = prefix.digest.context.outer
    return {
        'random_callback_verifier_sha256': sha256(Path(__file__)),
        'gettimeofday_verifier_sha256': sha256(Path(prefix.__file__)),
        'suffix_digest_verifier_sha256': sha256(Path(prefix.digest.__file__)),
        'context_verifier_sha256': sha256(Path(prefix.digest.context.__file__)),
        'outer_runtime_sha256': sha256(Path(owner.__file__)),
        'worker_allocator_sha256': sha256(Path(owner.h.__file__)),
        'random_component_verifier_sha256': sha256(Path(
            __import__('verify_vm9_request_random_getter_fresh_20261013').__file__)),
        'random_model_sha256': sha256(Path(
            __import__('vm9_request_random').__file__)),
    }


class RandomCallbackScenario(prefix.DynamicScenario):
    def __init__(self, control):
        super().__init__(control)
        self.callback = None
        self.random_entry = None
        self.random_plt_calls = []
        self.target_return = None
        self.callback_complete = False
        self.callback_stop_reason = None
        self._callback_started = False
        self._canary_saved = False

    def observe(self, cpu, pc, state):
        if not self._gettimeofday_entered:
            return super().observe(cpu, pc, state)
        offset = pc - self.image
        if offset == WRAPPER_CALL:
            object_address = self._reg(cpu, 0)
            target = self._reg(cpu, 8)
            object_first_word = int.from_bytes(cpu.mem_read(object_address, 8), 'little')
            guard = int.from_bytes(cpu.mem_read(self.image + RANDOM_GUARD, 1), 'little')
            before = bytes(cpu.mem_read(object_address + 8, 8))
            assert bytes(cpu.mem_read(pc, 4)).hex() == '00013fd6'
            assert self._reg(cpu, 19) == object_address
            assert target == object_first_word == self.image + RANDOM_GETTER
            mapped = any(start <= object_address and object_address + 16 <= end
                         for start, end, _ in cpu.mem_regions())
            assert mapped
            self.callback = dict(
                wrapper_offset=hex(WRAPPER_CALL - 0xC),
                call_offset=hex(WRAPPER_CALL),
                call_instruction='blr x8',
                call_instruction_bytes='00013fd6',
                return_offset=hex(WRAPPER_CALL + 4),
                target_offset=hex(target - self.image),
                callback_object_offset=hex(object_address - prefix.digest.context.outer.io.GUEST),
                callback_object_first_word_matches_target=True,
                callback_object_result_slot_before_sha256=hashlib.sha256(before).hexdigest(),
                callback_object_adjacent_padding_sha256=hashlib.sha256(before[4:]).hexdigest(),
                callback_object_in_mapped_memory=True,
                random_guard_address_offset=hex(RANDOM_GUARD),
                random_guard_value=guard,
                random_guard_warm=bool(guard & 1),
            )
            self.svc_boundary = dict(pc_offset=hex(WRAPPER_CALL))
            if not guard & 1:
                self.callback_stop_reason = 'random_guard_cold_before_indirect_call'
                self.continuation_boundary = dict(
                    kind=self.callback_stop_reason,
                    stop_before=hex(WRAPPER_CALL),
                    callback_target_executed=False,
                )
                cpu.emu_stop()
                cpu.reg_write(arm.UC_ARM64_REG_PC, prefix.digest.context.outer.oracle.STOP)
                return
            self._callback_started = True
            # Bypass the parent's stop at this address; retain its ordinary
            # observer for subsequent native and matching-libc instructions.
            prefix.digest.Scenario.observe(self, cpu, pc, state)
            return

        if self._callback_started and offset == RANDOM_GETTER:
            tp = cpu.reg_read(arm.UC_ARM64_REG_TPIDR_EL0)
            guard = int.from_bytes(cpu.mem_read(self.image + RANDOM_GUARD, 1), 'little')
            assert guard & 1
            self.random_entry = dict(
                target_offset=hex(offset),
                entry_sp=hex(cpu.reg_read(arm.UC_ARM64_REG_SP)),
                thread_pointer_in_guest=prefix.digest.context.outer.io.GUEST <= tp <
                    prefix.digest.context.outer.io.GUEST + 0x10000,
                guard_still_warm=bool(guard & 1),
                stack_canary_matches_thread_pointer=None,
                stack_canary_saved_by_instruction_offset='0x26cca4',
                stack_canary_checked_after_save_at='0x26cca8',
            )
            assert self.random_entry['thread_pointer_in_guest']
            assert any(start <= tp + 0x28 and tp + 0x30 <= end
                       for start, end, _ in cpu.mem_regions())

        # The getter's prologue stores TP+0x28 at [SP+8] in the instruction
        # immediately before this PC. Observe at the next instruction boundary
        # so the comparison cannot accidentally read the pre-save stack bytes.
        if self._callback_started and offset == 0x26CCA8:
            assert self.random_entry is not None and not self._canary_saved
            tp = cpu.reg_read(arm.UC_ARM64_REG_TPIDR_EL0)
            sp = cpu.reg_read(arm.UC_ARM64_REG_SP)
            saved = bytes(cpu.mem_read(sp + 8, 8))
            tls_value = bytes(cpu.mem_read(tp + 0x28, 8))
            assert saved == tls_value
            self.random_entry['stack_canary_matches_thread_pointer'] = True
            self.random_entry['saved_stack_canary_sha256'] = hashlib.sha256(saved).hexdigest()
            self._canary_saved = True

        if self._callback_started and offset in (RAND_PLT, SRAND_PLT):
            symbol = 'rand' if offset == RAND_PLT else 'srand'
            lr = self._reg(cpu, 30) - self.image
            self.random_plt_calls.append(dict(symbol=symbol, plt_offset=hex(offset),
                caller_offset=hex(lr)))
            expected_lr = 0x26CCBC if symbol == 'rand' else 0x26CCF8
            assert lr == expected_lr

        if self._callback_started and offset == WRAPPER_POST_STORE:
            assert self.callback is not None and self.random_entry is not None
            assert self._canary_saved
            assert bytes(cpu.mem_read(self.image + WRAPPER_POST_STORE - 4, 4)).hex() == '600a00b9'
            assert bytes(cpu.mem_read(pc, 4)).hex() == 'fe4fc1a8'
            object_address = prefix.digest.context.outer.io.GUEST + int(
                self.callback['callback_object_offset'], 16)
            result_word = self._reg(cpu, 0) & 0xFFFFFFFF
            result_bytes = result_word.to_bytes(4, 'little')
            stored = bytes(cpu.mem_read(object_address + 8, 4))
            after_padding = bytes(cpu.mem_read(object_address + 12, 4))
            assert stored == result_bytes
            assert hashlib.sha256(after_padding).hexdigest() == \
                self.callback['callback_object_adjacent_padding_sha256']
            assert [call['symbol'] for call in self.random_plt_calls] == ['rand']
            self.target_return = dict(
                target_returned_to_wrapper=True,
                wrapper_result_store_executed=True,
                result_store_matches_return_register=True,
                result_word_sha256=hashlib.sha256(result_bytes).hexdigest(),
                result_slot_sha256=hashlib.sha256(stored).hexdigest(),
                adjacent_padding_preserved=True,
                wrapper_epilogue_executed=False,
            )
            self.callback_complete = True
            self.callback_stop_reason = 'random_result_stored_before_wrapper_epilogue'
            self.continuation_boundary = dict(
                kind=self.callback_stop_reason,
                stop_before=hex(WRAPPER_POST_STORE),
                callback_target_executed=True,
            )
            self.svc_boundary = dict(pc_offset=hex(WRAPPER_CALL))
            super().observe(cpu, pc, state)
            cpu.emu_stop()
            cpu.reg_write(arm.UC_ARM64_REG_PC, prefix.digest.context.outer.oracle.STOP)
            return
        return super().observe(cpu, pc, state)

    def finish(self, result, state, proof):
        assert self.callback is not None
        assert self.callback_stop_reason is not None
        if self.callback_complete:
            assert self.random_entry is not None and self.target_return is not None
            assert self._canary_saved
            assert self.callback['random_guard_warm']
            assert self.random_plt_calls == [dict(
                symbol='rand', plt_offset=hex(RAND_PLT), caller_offset='0x26ccbc')]
        else:
            assert not self._callback_started
            assert self.callback_stop_reason == 'random_guard_cold_before_indirect_call'
            assert self.random_plt_calls == []
        row = super().finish(result, state, proof)
        row.pop('unsupported_callback_boundary', None)
        row.pop('main_image_svc_count_at_callback_boundary', None)
        row['random_callback'] = dict(
            status=self.callback_stop_reason,
            entry_boundary=self.callback,
            random_getter_entry=self.random_entry,
            matching_libc_plt_calls=self.random_plt_calls,
            target_return_and_store=self.target_return,
            callback_target_executed=self.callback_complete,
            callback_wrapper_returned_to_interpreter=False,
            native_memory_used_as_python_model_input=False,
            main_image_svc_count_at_boundary=len(proof['main_image_SVC_boundaries']),
        )
        return row


def replay(path: Path, libc: Path) -> list[dict]:
    digest = prefix.digest
    scenarios = []

    def create(control):
        scenario = RandomCallbackScenario(control)
        scenario.path = path
        scenario.continue_to_svc = True
        scenarios.append(scenario)
        return scenario

    return digest.context.replay(
        path, libc, case_controls=[prefix.CONTROL], _extension_factory=create,
        _request_profile=digest.previous.previous.name.previous.previous.PROFILE['name'],
        _handler_read_profile=digest.context.NULL_PAYLOAD_READ_PROFILE['name'])


def claims_for(row: dict) -> dict:
    callback = row['random_callback']
    completed = callback['callback_target_executed']
    return dict(
        inherited_gettimeofday_dynamic_prefix_replayed=True,
        exact_existing_random_getter_target_reached=True,
        guard_state_checked_before_indirect_call=True,
        warm_random_getter_executed_in_same_native_cpu=completed,
        matching_Bionic_rand_import_called=completed,
        random_W_result_stored_by_original_wrapper=completed,
        wrapper_epilogue_and_interpreter_return_verified=False,
        current_native_suffix_return_verified=False,
        ordinary_Cronet_six_headers_verified=False,
        online_acceptance_verified=False,
        complete_standalone_signer_verified=False,
        actual_ART_or_JVM_execution=False,
        native_memory_used_as_python_model_input=False,
    )


def providers_for(row: dict, parent: dict) -> dict:
    callback = row['random_callback']
    return dict(
        inherited_evidence='vm9_native_171_gettimeofday_dynamic_20261121.json',
        inherited_evidence_sha256=sha256(prefix.EVIDENCE),
        random_component_owner='verify_vm9_request_random_getter_fresh_20261013.py',
        random_model_owner='vm9_request_random.py',
        matching_Bionic_import_owner='verify_vm9_outer_signer_native.py:bind_native_imports',
        explicit_time_provider_owner='verify_vm9_worker_allocator.py:Environment.syscall(169)',
        random_getter_target='0x26cc8c',
        wrapper_callsite='0x288648',
        random_guard_before_call=callback['entry_boundary']['random_guard_value'],
        callback_status=callback['status'],
        new_time_or_random_provider=False,
        parent_control=parent['case_result']['control'],
    )


def run(path: Path, libc: Path) -> dict:
    parent = parent_evidence()
    prefix.digest.verify_images(path, libc)
    assert sha256(path) == parent['input_provenance']['Metasec_sha256']
    assert sha256(libc) == parent['input_provenance']['Bionic_sha256']
    rows = replay(path, libc)
    assert len(rows) == 1
    row = rows[0]
    callback = row['random_callback']
    return dict(
        schema=SCHEMA,
        claims=claims_for(row),
        providers=providers_for(row, parent),
        input_provenance=dict(
            inherited_dynamic_evidence_sha256=sha256(prefix.EVIDENCE),
            Metasec_sha256=sha256(path),
            Bionic_sha256=sha256(libc),
        ),
        source_fingerprints=source_fingerprints(),
        case_result=row,
    )


def validate(data: dict) -> None:
    parent = parent_evidence()
    assert data['schema'] == SCHEMA
    row = data['case_result']
    callback = row['random_callback']
    assert data['claims'] == claims_for(row)
    assert data['providers'] == providers_for(row, parent)
    assert data['input_provenance'] == dict(
        inherited_dynamic_evidence_sha256=sha256(prefix.EVIDENCE),
        Metasec_sha256=parent['input_provenance']['Metasec_sha256'],
        Bionic_sha256=parent['input_provenance']['Bionic_sha256'])
    assert data['source_fingerprints'] == source_fingerprints()
    assert row['control'] == prefix.CONTROL
    assert row['gettimeofday']['post_svc']['timeval_seconds'] == 1791023800
    assert row['gettimeofday']['post_svc']['timeval_microseconds'] == 500000
    assert row['post_digest_service_delta']['syscall_169'] == 1
    assert callback['entry_boundary']['target_offset'] == '0x26cc8c'
    assert callback['entry_boundary']['call_offset'] == '0x288648'
    assert callback['entry_boundary']['callback_object_first_word_matches_target'] is True
    assert callback['entry_boundary']['callback_object_in_mapped_memory'] is True
    assert callback['native_memory_used_as_python_model_input'] is False
    assert callback['callback_wrapper_returned_to_interpreter'] is False
    if callback['callback_target_executed']:
        assert callback['status'] == 'random_result_stored_before_wrapper_epilogue'
        assert callback['entry_boundary']['random_guard_warm'] is True
        assert callback['random_getter_entry']['target_offset'] == '0x26cc8c'
        assert callback['random_getter_entry']['guard_still_warm'] is True
        assert callback['random_getter_entry']['stack_canary_matches_thread_pointer'] is True
        assert callback['random_getter_entry']['stack_canary_saved_by_instruction_offset'] == '0x26cca4'
        assert callback['random_getter_entry']['stack_canary_checked_after_save_at'] == '0x26cca8'
        assert len(callback['random_getter_entry']['saved_stack_canary_sha256']) == 64
        assert callback['matching_libc_plt_calls'] == [dict(
            symbol='rand', plt_offset='0x348020', caller_offset='0x26ccbc')]
        assert callback['target_return_and_store']['target_returned_to_wrapper'] is True
        assert callback['target_return_and_store']['wrapper_result_store_executed'] is True
        assert callback['target_return_and_store']['result_store_matches_return_register'] is True
        assert callback['target_return_and_store']['adjacent_padding_preserved'] is True
        assert callback['target_return_and_store']['wrapper_epilogue_executed'] is False
    else:
        assert callback['status'] == 'random_guard_cold_before_indirect_call'
        assert callback['entry_boundary']['random_guard_warm'] is False
        assert callback['random_getter_entry'] is None
        assert callback['matching_libc_plt_calls'] == []
        assert callback['target_return_and_store'] is None


def damaged_evidence_rejected(data: dict) -> int:
    paths = [
        ('claims', 'random_W_result_stored_by_original_wrapper'),
        ('providers', 'random_getter_target'),
        ('input_provenance', 'Metasec_sha256'),
        ('case_result', 'random_callback', 'entry_boundary', 'target_offset'),
        ('case_result', 'random_callback', 'native_memory_used_as_python_model_input'),
    ]
    values = [not data['claims']['random_W_result_stored_by_original_wrapper'],
              '0xdeadbeef', '0' * 64, '0xdeadbeef', True]
    for path, value in zip(paths, values):
        bad = deepcopy(data)
        target = bad
        for part in path[:-1]:
            target = target[part]
        target[path[-1]] = value
        try:
            validate(bad)
        except (AssertionError, KeyError, TypeError, ValueError):
            continue
        raise AssertionError(f'damaged random callback evidence accepted: {path}')
    return len(paths)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf', type=Path)
    parser.add_argument('--libc', type=Path)
    parser.add_argument('--capture', action='store_true')
    parser.add_argument('--replay', action='store_true')
    args = parser.parse_args()
    if args.capture and args.replay:
        parser.error('--capture and --replay are mutually exclusive')
    if (args.capture or args.replay) and (not args.elf or not args.libc):
        parser.error('--capture/--replay require --elf and --libc')
    if args.capture:
        if EVIDENCE.exists():
            parser.error('refusing to overwrite frozen random-callback evidence')
        data = run(args.elf, args.libc)
        validate(data)
        rejected = damaged_evidence_rejected(data)
        EVIDENCE.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n')
    else:
        data = json.loads(EVIDENCE.read_text())
        validate(data)
        rejected = damaged_evidence_rejected(data)
        if args.replay:
            assert run(args.elf, args.libc) == data
    callback = data['case_result']['random_callback']
    print(json.dumps(dict(schema=SCHEMA, damaged_evidence_rejected=rejected,
        callback_status=callback['status'],
        random_getter_target=callback['entry_boundary']['target_offset'],
        callback_target_executed=callback['callback_target_executed'],
        complete_standalone_signer_verified=False)))


if __name__ == '__main__':
    main()
