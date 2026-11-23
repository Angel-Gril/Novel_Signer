"""Resume VM dispatch after the random getter and stop at the next BLR."""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from unicorn import arm64_const as arm

import verify_vm9_native_171_random_wrapper_return_dynamic_20261121 as previous

EVIDENCE = previous.EVIDENCE.with_name(
    'vm9_native_171_next_vm_indirect_call_dynamic_20261121.json')
SCHEMA = 'vm9-native-171-next-vm-indirect-call-dynamic-20261121-v1'
VM_RESUME = 0x16AA4C
BLR_MASK = 0xFFFFFC1F
BLR_BASE = 0xD63F0000


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prior_evidence() -> dict:
    data = json.loads(previous.EVIDENCE.read_text())
    previous.validate(data)
    return data


def source_fingerprints() -> dict:
    return {
        'next_vm_call_verifier_sha256': sha256(Path(__file__)),
        'wrapper_return_verifier_sha256': sha256(Path(previous.__file__)),
        'random_callback_verifier_sha256': sha256(Path(previous.previous.__file__)),
        'gettimeofday_verifier_sha256': sha256(Path(previous.previous.prefix.__file__)),
        'suffix_digest_verifier_sha256': sha256(Path(previous.previous.prefix.digest.__file__)),
        'context_verifier_sha256': sha256(Path(
            previous.previous.prefix.digest.context.__file__)),
    }


class NextVmCallScenario(previous.WrapperReturnScenario):
    def __init__(self, control):
        super().__init__(control)
        self.vm_resume = None
        self.next_indirect_call = None
        self._post_return_instruction_count = 0
        self._post_return_first_pcs = []
        self._post_return_tail = []
        self._resume_instruction_pending = False

    def _reg(self, cpu, index):
        return cpu.reg_read(getattr(arm, f'UC_ARM64_REG_X{index}'))

    def _resume_from_wrapper_return(self, cpu, pc, state):
        assert self.wrapper_frame is not None and self.epilogue is not None
        assert self.wrapper_return is None
        assert pc == self.wrapper_frame['saved_caller_return']
        assert self._reg(cpu, 0) == self._result_word
        sp = cpu.reg_read(arm.UC_ARM64_REG_SP)
        assert sp == self.wrapper_frame['stack_pointer_at_indirect_call'] + 0x10
        assert self._reg(cpu, 30) == self.wrapper_frame['saved_caller_return']
        assert self._reg(cpu, 19) == self.wrapper_frame['saved_caller_x19']
        instruction = bytes(cpu.mem_read(pc, 4))
        self.wrapper_return = dict(
            saved_caller_offset=hex(pc - self.image),
            caller_instruction_length=4,
            caller_instruction_sha256=hashlib.sha256(instruction).hexdigest(),
            ret_instruction_executed=True,
            returned_value_preserved=True,
            callee_saved_x19_restored=True,
            stack_pointer_restored=True,
            returned_before_caller_instruction=False,
        )
        self.target_return['wrapper_epilogue_executed'] = True
        self.target_return['wrapper_returned_to_saved_caller'] = True
        self.callback_stop_reason = 'resumed_vm_dispatch_after_random_wrapper'
        self.continuation_boundary = None
        self.svc_boundary = dict(pc_offset=hex(previous.previous.WRAPPER_CALL))
        previous.previous.prefix.DynamicScenario.observe(self, cpu, pc, state)
        self.vm_resume = dict(
            resume_offset=hex(pc - self.image),
            first_instruction_bytes=instruction.hex(),
            first_instruction_sha256=hashlib.sha256(instruction).hexdigest(),
            first_instruction_executed=False,
        )
        self._post_return_instruction_count = 1
        self._post_return_first_pcs = [hex(pc - self.image)]
        self._post_return_tail = [hex(pc - self.image)]
        self._resume_instruction_pending = True

    def observe(self, cpu, pc, state):
        offset = pc - self.image
        saved_return = (self.wrapper_frame['saved_caller_return']
                        if self.wrapper_frame is not None else None)

        # Replace the previous verifier's stop at the first VM resume PC.
        if (self._callback_started and self.epilogue is not None
                and self.wrapper_return is None and saved_return is not None
                and pc == saved_return):
            self._resume_from_wrapper_return(cpu, pc, state)
            return

        if self.vm_resume is not None and self.next_indirect_call is None:
            if self._resume_instruction_pending:
                assert pc != self.image + VM_RESUME
                self.vm_resume['first_instruction_executed'] = True
                self._resume_instruction_pending = False
            self._post_return_instruction_count += 1
            if len(self._post_return_first_pcs) < 32:
                self._post_return_first_pcs.append(hex(offset))
            self._post_return_tail.append(hex(offset))
            if len(self._post_return_tail) > 32:
                self._post_return_tail.pop(0)
            try:
                instruction = bytes(cpu.mem_read(pc, 4))
            except Exception:
                instruction = b''
            if len(instruction) == 4:
                word = int.from_bytes(instruction, 'little')
                if word & BLR_MASK == BLR_BASE:
                    rn = (word >> 5) & 0x1F
                    target = cpu.reg_read(getattr(arm, f'UC_ARM64_REG_X{rn}'))
                    target_region = next((dict(start=start, end=end, perms=perms)
                        for start, end, perms in cpu.mem_regions()
                        if start <= target < end), None)
                    self.next_indirect_call = dict(
                        callsite_offset=hex(offset),
                        instruction='blr x%d' % rn,
                        instruction_bytes=instruction.hex(),
                        target_in_main_image=(self.image <= target <
                            self.image + len(self.path.read_bytes())),
                        target_offset=(hex(target - self.image) if
                            self.image <= target < self.image + len(self.path.read_bytes())
                            else None),
                        target_is_mapped=target_region is not None,
                        target_is_null=target == 0,
                        target_mapping_permissions=(target_region['perms']
                            if target_region is not None else None),
                        link_register_offset=hex(self._reg(cpu, 30) - self.image),
                        nonzero_argument_registers=[
                            'x%d' % index for index in range(8)
                            if self._reg(cpu, index) != 0],
                    )
                    assert target != 0 and target_region is not None
                    self.callback_stop_reason = 'next_vm_indirect_call_before_target'
                    self.continuation_boundary = dict(
                        kind=self.callback_stop_reason,
                        stop_before=hex(offset),
                        instruction= 'blr x%d' % rn,
                        target_executed=False,
                    )
                    self.svc_boundary = dict(
                        pc_offset=hex(previous.previous.WRAPPER_CALL))
                    previous.previous.prefix.DynamicScenario.observe(
                        self, cpu, pc, state)
                    cpu.emu_stop()
                    cpu.reg_write(arm.UC_ARM64_REG_PC,
                        previous.previous.prefix.digest.context.outer.oracle.STOP)
                    return

        return super().observe(cpu, pc, state)

    def finish(self, result, state, proof):
        assert self.vm_resume is not None
        assert self.next_indirect_call is not None
        row = super().finish(result, state, proof)
        row['random_callback']['callback_wrapper_returned_to_interpreter'] = True
        row['random_callback']['wrapper_return']['returned_before_caller_instruction'] = False
        row['vm_resume'] = self.vm_resume
        row['post_return_dispatch'] = dict(
            instruction_observation_count=self._post_return_instruction_count,
            first_pc_offsets=self._post_return_first_pcs,
            tail_pc_offsets=self._post_return_tail,
            next_indirect_call=self.next_indirect_call,
            next_call_target_executed=False,
        )
        return row


def replay(path: Path, libc: Path) -> list[dict]:
    digest = previous.previous.prefix.digest

    def create(control):
        scenario = NextVmCallScenario(control)
        scenario.path = path
        scenario.continue_to_svc = True
        return scenario

    return digest.context.replay(
        path, libc, case_controls=[previous.previous.prefix.CONTROL],
        _extension_factory=create,
        _request_profile=digest.previous.previous.name.previous.previous.PROFILE['name'],
        _handler_read_profile=digest.context.NULL_PAYLOAD_READ_PROFILE['name'])


def claims_for(row: dict) -> dict:
    next_call = row['post_return_dispatch']['next_indirect_call']
    return dict(
        random_getter_and_wrapper_return_replayed=True,
        wrapper_ret_reached_vm_dispatch_resume=True,
        vm_dispatch_body_executed=True,
        next_indirect_call_boundary_reached=True,
        next_indirect_target_executed=False,
        cleanup_after_current_native_suffix_verified=False,
        current_native_suffix_return_verified=False,
        ordinary_Cronet_six_headers_verified=False,
        complete_standalone_signer_verified=False,
        online_acceptance_verified=False,
        Android_execution=False,
        native_memory_used_as_python_model_input=False,
        next_callsite_offset=next_call['callsite_offset'],
        next_call_target_offset=next_call['target_offset'],
    )


def run(path: Path, libc: Path) -> dict:
    parent = prior_evidence()
    previous.previous.prefix.digest.verify_images(path, libc)
    assert sha256(path) == parent['input_provenance']['Metasec_sha256']
    assert sha256(libc) == parent['input_provenance']['Bionic_sha256']
    rows = replay(path, libc)
    assert len(rows) == 1
    row = rows[0]
    next_call = row['post_return_dispatch']['next_indirect_call']
    return dict(
        schema=SCHEMA,
        claims=claims_for(row),
        providers=dict(
            inherited_evidence='vm9_native_171_random_wrapper_return_dynamic_20261121.json',
            inherited_evidence_sha256=sha256(previous.EVIDENCE),
            interpreter_resume_offset='0x16aa4c',
            native_indirect_target_provider='none; stop before target',
            new_time_or_random_provider=False),
        input_provenance=dict(
            inherited_wrapper_return_evidence_sha256=sha256(previous.EVIDENCE),
            Metasec_sha256=sha256(path),
            Bionic_sha256=sha256(libc)),
        source_fingerprints=source_fingerprints(),
        case_result=row,
    )


def validate(data: dict) -> None:
    parent = prior_evidence()
    assert data['schema'] == SCHEMA
    assert data['providers'] == dict(
        inherited_evidence='vm9_native_171_random_wrapper_return_dynamic_20261121.json',
        inherited_evidence_sha256=sha256(previous.EVIDENCE),
        interpreter_resume_offset='0x16aa4c',
        native_indirect_target_provider='none; stop before target',
        new_time_or_random_provider=False)
    assert data['input_provenance'] == dict(
        inherited_wrapper_return_evidence_sha256=sha256(previous.EVIDENCE),
        Metasec_sha256=parent['input_provenance']['Metasec_sha256'],
        Bionic_sha256=parent['input_provenance']['Bionic_sha256'])
    assert data['source_fingerprints'] == source_fingerprints()
    row = data['case_result']
    callback = row['random_callback']
    assert row['control'] == previous.previous.prefix.CONTROL
    assert callback['entry_boundary']['target_offset'] == '0x26cc8c'
    assert callback['callback_wrapper_returned_to_interpreter'] is True
    assert callback['wrapper_return']['saved_caller_offset'] == '0x16aa4c'
    assert callback['wrapper_return']['ret_instruction_executed'] is True
    resume = row['vm_resume']
    assert resume['resume_offset'] == '0x16aa4c'
    assert resume['first_instruction_executed'] is True
    assert resume['first_instruction_sha256'] == hashlib.sha256(bytes.fromhex(
        resume['first_instruction_bytes'])).hexdigest()
    dispatch = row['post_return_dispatch']
    assert dispatch['instruction_observation_count'] > 1
    assert dispatch['first_pc_offsets'][0] == '0x16aa4c'
    assert dispatch['next_call_target_executed'] is False
    next_call = dispatch['next_indirect_call']
    assert next_call['callsite_offset'].startswith('0x')
    assert next_call['instruction'].startswith('blr x')
    assert len(next_call['instruction_bytes']) == 8
    instruction_word = int.from_bytes(bytes.fromhex(
        next_call['instruction_bytes']), 'little')
    assert instruction_word & BLR_MASK == BLR_BASE
    assert next_call['instruction'] == 'blr x%d' % ((instruction_word >> 5) & 0x1F)
    assert next_call['target_is_mapped'] is True
    assert next_call['target_is_null'] is False
    assert next_call['link_register_offset'].startswith('0x')
    assert data['claims'] == claims_for(row)


def damaged_evidence_rejected(data: dict) -> int:
    paths = [
        ('claims', 'vm_dispatch_body_executed'),
        ('providers', 'interpreter_resume_offset'),
        ('input_provenance', 'Bionic_sha256'),
        ('case_result', 'vm_resume', 'resume_offset'),
        ('case_result', 'post_return_dispatch', 'next_call_target_executed'),
        ('case_result', 'post_return_dispatch', 'next_indirect_call', 'instruction_bytes'),
    ]
    values = [False, '0xdeadbeef', '0' * 64, '0xdeadbeef', True, 'ffffffff']
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
        raise AssertionError(f'damaged next-VM-call evidence accepted: {path}')
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
            parser.error('refusing to overwrite frozen next-VM-call evidence')
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
    next_call = data['case_result']['post_return_dispatch']['next_indirect_call']
    print(json.dumps(dict(
        schema=SCHEMA,
        damaged_evidence_rejected=rejected,
        interpreter_resume_offset='0x16aa4c',
        post_return_instruction_observations=data['case_result']['post_return_dispatch'][
            'instruction_observation_count'],
        next_callsite=next_call['callsite_offset'],
        next_target_offset=next_call['target_offset'],
        next_target_executed=False,
        complete_standalone_signer_verified=False)))


if __name__ == '__main__':
    main()
