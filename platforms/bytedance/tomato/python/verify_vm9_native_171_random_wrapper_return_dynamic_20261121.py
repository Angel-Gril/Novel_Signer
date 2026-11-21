"""Continue the accepted random callback through its original wrapper return."""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from unicorn import arm64_const as arm

import verify_vm9_native_171_random_callback_dynamic_20261121 as previous

EVIDENCE = previous.EVIDENCE.with_name(
    'vm9_native_171_random_wrapper_return_dynamic_20261121.json')
SCHEMA = 'vm9-native-171-random-wrapper-return-dynamic-20261121-v1'
WRAPPER_STORE_NEXT = previous.WRAPPER_POST_STORE
WRAPPER_RET = 0x288654
WRAPPER_CALL = previous.WRAPPER_CALL


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prior_evidence() -> dict:
    data = json.loads(previous.EVIDENCE.read_text())
    previous.validate(data)
    return data


def source_fingerprints() -> dict:
    return {
        'wrapper_return_verifier_sha256': sha256(Path(__file__)),
        'random_callback_verifier_sha256': sha256(Path(previous.__file__)),
        'gettimeofday_verifier_sha256': sha256(Path(previous.prefix.__file__)),
        'suffix_digest_verifier_sha256': sha256(Path(previous.prefix.digest.__file__)),
        'context_verifier_sha256': sha256(Path(previous.prefix.digest.context.__file__)),
    }


class WrapperReturnScenario(previous.RandomCallbackScenario):
    def __init__(self, control):
        super().__init__(control)
        self.wrapper_frame = None
        self.epilogue = None
        self.wrapper_return = None
        self._result_word = None

    def _reg(self, cpu, index):
        return cpu.reg_read(getattr(arm, f'UC_ARM64_REG_X{index}'))

    def observe(self, cpu, pc, state):
        offset = pc - self.image

        if not self._callback_started and offset == WRAPPER_CALL:
            sp = cpu.reg_read(arm.UC_ARM64_REG_SP)
            saved_lr = int.from_bytes(cpu.mem_read(sp, 8), 'little')
            saved_x19 = int.from_bytes(cpu.mem_read(sp + 8, 8), 'little')
            assert self._reg(cpu, 30) == saved_lr
            self.wrapper_frame = dict(
                stack_pointer_at_indirect_call=sp,
                saved_caller_return=saved_lr,
                saved_caller_x19=saved_x19,
            )

        if self._callback_started and offset == WRAPPER_STORE_NEXT:
            assert self.callback is not None and self.random_entry is not None
            assert self._canary_saved
            assert bytes(cpu.mem_read(self.image + WRAPPER_STORE_NEXT - 4, 4)).hex() == '600a00b9'
            assert bytes(cpu.mem_read(pc, 4)).hex() == 'fe4fc1a8'
            object_address = previous.prefix.digest.context.outer.io.GUEST + int(
                self.callback['callback_object_offset'], 16)
            result_word = self._reg(cpu, 0) & 0xFFFFFFFF
            self._result_word = result_word
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
            self.callback_stop_reason = 'random_result_stored_continuing_wrapper'
            self.svc_boundary = dict(pc_offset=hex(WRAPPER_CALL))
            # Bypass the previous verifier's intentional stop-before-epilogue
            # while retaining the inherited native instruction observers.
            previous.prefix.DynamicScenario.observe(self, cpu, pc, state)
            return

        if self._callback_started and offset == WRAPPER_RET:
            assert self.wrapper_frame is not None and self.callback_complete
            assert bytes(cpu.mem_read(pc, 4)).hex() == 'c0035fd6'
            sp = cpu.reg_read(arm.UC_ARM64_REG_SP)
            assert sp == self.wrapper_frame['stack_pointer_at_indirect_call'] + 0x10
            assert self._reg(cpu, 30) == self.wrapper_frame['saved_caller_return']
            assert self._reg(cpu, 19) == self.wrapper_frame['saved_caller_x19']
            self.epilogue = dict(
                ldp_instruction_offset=hex(WRAPPER_RET - 4),
                ldp_instruction_bytes='fe4fc1a8',
                ret_instruction_offset=hex(WRAPPER_RET),
                ret_instruction_bytes='c0035fd6',
                callee_saved_registers_restored=True,
                stack_pointer_restored=True,
            )
            previous.prefix.DynamicScenario.observe(self, cpu, pc, state)
            return

        if (self._callback_started and self.epilogue is not None
                and self.wrapper_frame is not None
                and pc == self.wrapper_frame['saved_caller_return']):
            assert self.callback_complete and self.target_return is not None
            assert self._result_word is not None
            assert self._reg(cpu, 0) & 0xFFFFFFFF == self._result_word
            sp = cpu.reg_read(arm.UC_ARM64_REG_SP)
            expected_sp = self.wrapper_frame['stack_pointer_at_indirect_call'] + 0x10
            assert sp == expected_sp
            assert self._reg(cpu, 30) == self.wrapper_frame['saved_caller_return']
            assert self._reg(cpu, 19) == self.wrapper_frame['saved_caller_x19']
            instruction = bytes(cpu.mem_read(pc, 4))
            self.wrapper_return = dict(
                saved_caller_offset=hex(pc - self.image),
                caller_instruction_length=len(instruction),
                caller_instruction_sha256=hashlib.sha256(instruction).hexdigest(),
                ret_instruction_executed=True,
                returned_value_preserved=True,
                callee_saved_x19_restored=True,
                stack_pointer_restored=True,
                returned_before_caller_instruction=True,
            )
            self.target_return['wrapper_epilogue_executed'] = True
            self.target_return['wrapper_returned_to_saved_caller'] = True
            self.callback_stop_reason = 'random_wrapper_returned_before_saved_caller_instruction'
            self.continuation_boundary = dict(
                kind=self.callback_stop_reason,
                stop_before=hex(pc - self.image),
                ret_executed=True,
                callback_target_executed=True,
            )
            self.svc_boundary = dict(pc_offset=hex(WRAPPER_CALL))
            previous.prefix.DynamicScenario.observe(self, cpu, pc, state)
            cpu.emu_stop()
            cpu.reg_write(arm.UC_ARM64_REG_PC,
                          previous.prefix.digest.context.outer.oracle.STOP)
            return

        return super().observe(cpu, pc, state)

    def finish(self, result, state, proof):
        assert self.wrapper_frame is not None
        assert self.epilogue is not None
        assert self.wrapper_return is not None
        row = super().finish(result, state, proof)
        row['random_callback']['callback_wrapper_returned_to_saved_caller'] = True
        row['random_callback']['wrapper_epilogue'] = self.epilogue
        row['random_callback']['wrapper_return'] = self.wrapper_return
        return row


def replay(path: Path, libc: Path) -> list[dict]:
    digest = previous.prefix.digest

    def create(control):
        scenario = WrapperReturnScenario(control)
        scenario.path = path
        scenario.continue_to_svc = True
        return scenario

    return digest.context.replay(
        path, libc, case_controls=[previous.prefix.CONTROL],
        _extension_factory=create,
        _request_profile=digest.previous.previous.name.previous.previous.PROFILE['name'],
        _handler_read_profile=digest.context.NULL_PAYLOAD_READ_PROFILE['name'])


def claims_for(row: dict) -> dict:
    callback = row['random_callback']
    return dict(
        prior_random_callback_evidence_revalidated=True,
        warm_native_random_getter_and_matching_Bionic_rand_reexecuted=True,
        original_wrapper_store_and_epilogue_executed=True,
        wrapper_ret_reached_saved_caller_instruction=True,
        caller_body_or_next_AST_callback_executed=False,
        cleanup_after_current_native_suffix_verified=False,
        current_native_suffix_return_verified=False,
        ordinary_Cronet_six_headers_verified=False,
        complete_standalone_signer_verified=False,
        online_acceptance_verified=False,
        Android_execution=False,
        native_memory_used_as_python_model_input=False,
        callback_return_offset=callback['wrapper_return']['saved_caller_offset'],
    )


def run(path: Path, libc: Path) -> dict:
    parent = prior_evidence()
    previous.prefix.digest.verify_images(path, libc)
    assert sha256(path) == parent['input_provenance']['Metasec_sha256']
    assert sha256(libc) == parent['input_provenance']['Bionic_sha256']
    rows = replay(path, libc)
    assert len(rows) == 1
    row = rows[0]
    callback = row['random_callback']
    assert callback['callback_target_executed'] is True
    assert callback['callback_wrapper_returned_to_saved_caller'] is True
    return dict(
        schema=SCHEMA,
        claims=claims_for(row),
        providers=dict(
            inherited_evidence='vm9_native_171_random_callback_dynamic_20261121.json',
            inherited_evidence_sha256=sha256(previous.EVIDENCE),
            random_getter_target='0x26cc8c',
            wrapper_store_offset='0x28864c',
            wrapper_epilogue_offset='0x288650',
            wrapper_return_offset='0x288654',
            new_time_or_random_provider=False,
        ),
        input_provenance=dict(
            inherited_random_callback_evidence_sha256=sha256(previous.EVIDENCE),
            Metasec_sha256=sha256(path),
            Bionic_sha256=sha256(libc),
        ),
        source_fingerprints=source_fingerprints(),
        case_result=row,
    )


def validate(data: dict) -> None:
    parent = prior_evidence()
    assert data['schema'] == SCHEMA
    assert data['providers'] == dict(
        inherited_evidence='vm9_native_171_random_callback_dynamic_20261121.json',
        inherited_evidence_sha256=sha256(previous.EVIDENCE),
        random_getter_target='0x26cc8c',
        wrapper_store_offset='0x28864c',
        wrapper_epilogue_offset='0x288650',
        wrapper_return_offset='0x288654',
        new_time_or_random_provider=False)
    assert data['input_provenance'] == dict(
        inherited_random_callback_evidence_sha256=sha256(previous.EVIDENCE),
        Metasec_sha256=parent['input_provenance']['Metasec_sha256'],
        Bionic_sha256=parent['input_provenance']['Bionic_sha256'])
    assert data['source_fingerprints'] == source_fingerprints()
    row = data['case_result']
    callback = row['random_callback']
    assert row['control'] == previous.prefix.CONTROL
    assert callback['entry_boundary']['target_offset'] == '0x26cc8c'
    assert callback['entry_boundary']['random_guard_warm'] is True
    assert callback['matching_libc_plt_calls'] == [dict(
        symbol='rand', plt_offset='0x348020', caller_offset='0x26ccbc')]
    assert callback['target_return_and_store']['wrapper_epilogue_executed'] is True
    assert callback['target_return_and_store']['wrapper_returned_to_saved_caller'] is True
    assert callback['wrapper_epilogue'] == dict(
        ldp_instruction_offset='0x288650',
        ldp_instruction_bytes='fe4fc1a8',
        ret_instruction_offset='0x288654',
        ret_instruction_bytes='c0035fd6',
        callee_saved_registers_restored=True,
        stack_pointer_restored=True)
    wrapper_return = callback['wrapper_return']
    assert wrapper_return['saved_caller_offset'].startswith('0x')
    assert wrapper_return['caller_instruction_length'] == 4
    assert len(wrapper_return['caller_instruction_sha256']) == 64
    assert wrapper_return['ret_instruction_executed'] is True
    assert wrapper_return['returned_value_preserved'] is True
    assert wrapper_return['callee_saved_x19_restored'] is True
    assert wrapper_return['stack_pointer_restored'] is True
    assert wrapper_return['returned_before_caller_instruction'] is True
    assert callback['callback_wrapper_returned_to_saved_caller'] is True
    assert callback['callback_wrapper_returned_to_interpreter'] is False
    assert callback['native_memory_used_as_python_model_input'] is False
    assert data['claims'] == claims_for(row)


def damaged_evidence_rejected(data: dict) -> int:
    paths = [
        ('claims', 'original_wrapper_store_and_epilogue_executed'),
        ('providers', 'wrapper_return_offset'),
        ('input_provenance', 'Metasec_sha256'),
        ('case_result', 'random_callback', 'wrapper_epilogue', 'ret_instruction_bytes'),
        ('case_result', 'random_callback', 'wrapper_return', 'ret_instruction_executed'),
        ('case_result', 'random_callback', 'wrapper_return', 'saved_caller_offset'),
    ]
    values = [False, '0xdeadbeef', '0' * 64, 'ffffffff', False, '0xdeadbeef']
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
        raise AssertionError(f'damaged wrapper-return evidence accepted: {path}')
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
            parser.error('refusing to overwrite frozen wrapper-return evidence')
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
    print(json.dumps(dict(
        schema=SCHEMA,
        damaged_evidence_rejected=rejected,
        wrapper_returned_to_saved_caller=callback[
            'callback_wrapper_returned_to_saved_caller'],
        caller_offset=callback['wrapper_return']['saved_caller_offset'],
        caller_instruction_length=callback['wrapper_return'][
            'caller_instruction_length'],
        caller_body_executed=False,
        complete_standalone_signer_verified=False)))


if __name__ == '__main__':
    main()
