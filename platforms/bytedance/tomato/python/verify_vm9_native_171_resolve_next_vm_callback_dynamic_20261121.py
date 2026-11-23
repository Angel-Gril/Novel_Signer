"""Resolve the VM's known indirect wrapper to its next callback target."""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from unicorn import arm64_const as arm

import verify_vm9_native_171_next_vm_indirect_call_dynamic_20261121 as previous

EVIDENCE = previous.EVIDENCE.with_name(
    'vm9_native_171_resolve_next_vm_callback_dynamic_20261121.json')
SCHEMA = 'vm9-native-171-resolve-next-vm-callback-dynamic-20261121-v1'
VM_RESUME = previous.VM_RESUME
VM_CALL = 0x16AA48
CALL_WRAPPER = 0x2885E0
TAIL_BRANCH = 0x2885E8
GUEST = previous.previous.previous.prefix.digest.context.outer.io.GUEST
GUEST_SIZE = 0x10000
BLR_MASK = previous.BLR_MASK
BLR_BASE = previous.BLR_BASE
BR_MASK = 0xFFFFFC1F
BR_BASE = 0xD61F0000


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prior_evidence() -> dict:
    data = json.loads(previous.EVIDENCE.read_text())
    previous.validate(data)
    return data


def module_prefix():
    return previous.previous.previous.prefix


def source_fingerprints() -> dict:
    return {
        'callback_resolution_verifier_sha256': sha256(Path(__file__)),
        'next_vm_call_verifier_sha256': sha256(Path(previous.__file__)),
        'wrapper_return_verifier_sha256': sha256(Path(previous.previous.__file__)),
        'random_callback_verifier_sha256': sha256(Path(previous.previous.previous.__file__)),
        'gettimeofday_verifier_sha256': sha256(Path(module_prefix().__file__)),
        'suffix_digest_verifier_sha256': sha256(Path(module_prefix().digest.__file__)),
    }


class ResolveVmCallbackScenario(previous.NextVmCallScenario):
    def __init__(self, control):
        super().__init__(control)
        self.vm_wrapper_call = None
        self.callback_descriptor = None
        self.callback_tail_branch = None
        self._vm_wrapper_entered = False
        self._resume_instruction_pending = False
        self._descriptor_address = None

    def _reg(self, cpu, index):
        return cpu.reg_read(getattr(arm, f'UC_ARM64_REG_X{index}'))

    @staticmethod
    def _relative(value, image):
        if image <= value < image + 0x400000:
            return dict(space='main_image', offset=hex(value - image))
        if GUEST <= value < GUEST + GUEST_SIZE:
            return dict(space='guest', offset=hex(value - GUEST))
        return dict(space='other', offset=None)

    def _base_observe(self, cpu, pc, state):
        module_prefix().DynamicScenario.observe(self, cpu, pc, state)

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
        self._base_observe(cpu, pc, state)
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

    def _record_vm_indirect_call(self, cpu, pc, state):
        word_bytes = bytes(cpu.mem_read(pc, 4))
        word = int.from_bytes(word_bytes, 'little')
        assert word & BLR_MASK == BLR_BASE
        rn = (word >> 5) & 0x1F
        target = cpu.reg_read(getattr(arm, f'UC_ARM64_REG_X{rn}'))
        assert target == self.image + CALL_WRAPPER
        self.vm_wrapper_call = dict(
            callsite_offset=hex(pc - self.image),
            instruction='blr x%d' % rn,
            instruction_bytes=word_bytes.hex(),
            target_offset=hex(target - self.image),
            target_wrapper_entered=False,
            return_offset=hex(self._reg(cpu, 30) - self.image),
            argument_registers_nonzero=[
                'x%d' % index for index in range(8) if self._reg(cpu, index) != 0],
        )
        self.next_indirect_call = deepcopy(self.vm_wrapper_call)
        self._base_observe(cpu, pc, state)

    def observe(self, cpu, pc, state):
        offset = pc - self.image
        saved_return = (self.wrapper_frame['saved_caller_return']
                        if self.wrapper_frame is not None else None)

        if (self._callback_started and self.epilogue is not None
                and self.wrapper_return is None and saved_return is not None
                and pc == saved_return):
            self._resume_from_wrapper_return(cpu, pc, state)
            return

        if self.vm_resume is None:
            return super().observe(cpu, pc, state)

        if self._resume_instruction_pending:
            assert offset != VM_RESUME
            self.vm_resume['first_instruction_executed'] = True
            self._resume_instruction_pending = False

        if not self._vm_wrapper_entered:
            self._post_return_instruction_count += 1
            if len(self._post_return_first_pcs) < 32:
                self._post_return_first_pcs.append(hex(offset))
            self._post_return_tail.append(hex(offset))
            if len(self._post_return_tail) > 32:
                self._post_return_tail.pop(0)

            if offset == VM_CALL:
                self._record_vm_indirect_call(cpu, pc, state)
                return

            if offset == CALL_WRAPPER:
                assert self.vm_wrapper_call is not None
                descriptor = self._reg(cpu, 0)
                assert any(start <= descriptor and descriptor + 16 <= end
                           for start, end, _ in cpu.mem_regions())
                descriptor_bytes = bytes(cpu.mem_read(descriptor, 16))
                descriptor_first = int.from_bytes(descriptor_bytes[:8], 'little')
                descriptor_second = int.from_bytes(descriptor_bytes[8:], 'little')
                assert descriptor_first != 0 and descriptor_second != 0
                assert self._reg(cpu, 30) == self.image + VM_CALL + 4
                self._descriptor_address = descriptor
                self.callback_descriptor = dict(
                    wrapper_entry_offset=hex(offset),
                    descriptor_address=self._relative(descriptor, self.image),
                    descriptor_is_mapped=True,
                    descriptor_sha256=hashlib.sha256(descriptor_bytes).hexdigest(),
                    descriptor_first_word=self._relative(descriptor_first, self.image),
                    descriptor_second_word=self._relative(descriptor_second, self.image),
                    return_offset=hex(self._reg(cpu, 30) - self.image),
                )
                self.vm_wrapper_call['target_wrapper_entered'] = True
                self._vm_wrapper_entered = True
                self._base_observe(cpu, pc, state)
                return

            self._base_observe(cpu, pc, state)
            return

        if offset == TAIL_BRANCH:
            instruction = bytes(cpu.mem_read(pc, 4))
            word = int.from_bytes(instruction, 'little')
            assert word & BR_MASK == BR_BASE
            rn = (word >> 5) & 0x1F
            target = cpu.reg_read(getattr(arm, f'UC_ARM64_REG_X{rn}'))
            assert self._descriptor_address is not None
            descriptor_words = bytes(cpu.mem_read(self._descriptor_address, 16))
            descriptor_first = int.from_bytes(descriptor_words[:8], 'little')
            descriptor_second = int.from_bytes(descriptor_words[8:], 'little')
            callback_argument = self._reg(cpu, 0)
            assert target == descriptor_first
            assert callback_argument == descriptor_second
            target_region = next((dict(start=start, end=end, perms=perms)
                for start, end, perms in cpu.mem_regions() if start <= target < end), None)
            assert target_region is not None and target != 0
            self.callback_tail_branch = dict(
                branch_offset=hex(offset),
                instruction='br x%d' % rn,
                instruction_bytes=instruction.hex(),
                target=self._relative(target, self.image),
                target_is_mapped=True,
                target_is_null=False,
                target_mapping_permissions=target_region['perms'],
                callback_argument=self._relative(callback_argument, self.image),
                target_matches_descriptor_first_word=True,
                callback_argument_matches_descriptor_second_word=True,
                branch_target_executed=False,
            )
            self.continuation_boundary = dict(
                kind='resolved_vm_callback_before_target',
                stop_before=hex(offset),
                instruction='br x%d' % rn,
                callback_target_executed=False,
            )
            self.callback_stop_reason = 'resolved_next_vm_callback_before_target'
            self.svc_boundary = dict(pc_offset=hex(previous.previous.WRAPPER_CALL))
            self._base_observe(cpu, pc, state)
            cpu.emu_stop()
            cpu.reg_write(arm.UC_ARM64_REG_PC,
                module_prefix().digest.context.outer.oracle.STOP)
            return

        self._base_observe(cpu, pc, state)

    def finish(self, result, state, proof):
        assert self.vm_resume is not None and self.vm_resume['first_instruction_executed']
        assert self.vm_wrapper_call is not None
        assert self.callback_descriptor is not None
        assert self.callback_tail_branch is not None
        row = super().finish(result, state, proof)
        row['random_callback']['callback_wrapper_returned_to_interpreter'] = True
        row['random_callback']['wrapper_return']['returned_before_caller_instruction'] = False
        row['vm_resume'] = self.vm_resume
        dispatch = row['post_return_dispatch']
        dispatch['next_indirect_call'] = self.vm_wrapper_call
        dispatch['next_call_target_executed'] = True
        dispatch['instruction_observation_count'] = self._post_return_instruction_count
        dispatch['first_pc_offsets'] = self._post_return_first_pcs
        dispatch['tail_pc_offsets'] = self._post_return_tail
        row['callback_resolution'] = dict(
            wrapper_call=self.vm_wrapper_call,
            descriptor=self.callback_descriptor,
            tail_branch=self.callback_tail_branch,
            tail_branch_target_executed=False,
        )
        return row


def replay(path: Path, libc: Path) -> list[dict]:
    p = module_prefix()
    digest = p.digest

    def create(control):
        scenario = ResolveVmCallbackScenario(control)
        scenario.path = path
        scenario.continue_to_svc = True
        return scenario

    return digest.context.replay(
        path, libc, case_controls=[p.CONTROL], _extension_factory=create,
        _request_profile=digest.previous.previous.name.previous.previous.PROFILE['name'],
        _handler_read_profile=digest.context.NULL_PAYLOAD_READ_PROFILE['name'])


def claims_for(row: dict) -> dict:
    callback = row['callback_resolution']
    tail = callback['tail_branch']
    return dict(
        prior_random_getter_wrapper_and_vm_dispatch_replayed=True,
        native_VM_dispatch_resume_executed=True,
        known_native_trampoline_wrapper_executed=True,
        next_callback_descriptor_resolved=True,
        next_callback_tail_branch_reached=True,
        resolved_callback_target_executed=False,
        cleanup_after_current_native_suffix_verified=False,
        current_native_suffix_return_verified=False,
        ordinary_Cronet_six_headers_verified=False,
        complete_standalone_signer_verified=False,
        online_acceptance_verified=False,
        Android_execution=False,
        native_memory_used_as_python_model_input=False,
        next_vm_callsite=callback['wrapper_call']['callsite_offset'],
        callback_descriptor_sha256=callback['descriptor']['descriptor_sha256'],
        resolved_callback_target_offset=tail['target']['offset'],
        resolved_callback_target_space=tail['target']['space'],
    )


def run(path: Path, libc: Path) -> dict:
    parent = prior_evidence()
    p = module_prefix()
    p.digest.verify_images(path, libc)
    assert sha256(path) == parent['input_provenance']['Metasec_sha256']
    assert sha256(libc) == parent['input_provenance']['Bionic_sha256']
    rows = replay(path, libc)
    assert len(rows) == 1
    row = rows[0]
    callback = row['callback_resolution']
    return dict(
        schema=SCHEMA,
        claims=claims_for(row),
        providers=dict(
            inherited_evidence='vm9_native_171_next_vm_indirect_call_dynamic_20261121.json',
            inherited_evidence_sha256=sha256(previous.EVIDENCE),
            interpreter_resume_offset='0x16aa4c',
            resolved_wrapper_offset='0x2885e0',
            callback_target_provider='none; stop before target',
        ),
        input_provenance=dict(
            inherited_next_call_evidence_sha256=sha256(previous.EVIDENCE),
            Metasec_sha256=sha256(path),
            Bionic_sha256=sha256(libc)),
        source_fingerprints=source_fingerprints(),
        case_result=row,
    )


def validate(data: dict) -> None:
    parent = prior_evidence()
    assert data['schema'] == SCHEMA
    assert data['providers'] == dict(
        inherited_evidence='vm9_native_171_next_vm_indirect_call_dynamic_20261121.json',
        inherited_evidence_sha256=sha256(previous.EVIDENCE),
        interpreter_resume_offset='0x16aa4c',
        resolved_wrapper_offset='0x2885e0',
        callback_target_provider='none; stop before target')
    assert data['input_provenance'] == dict(
        inherited_next_call_evidence_sha256=sha256(previous.EVIDENCE),
        Metasec_sha256=parent['input_provenance']['Metasec_sha256'],
        Bionic_sha256=parent['input_provenance']['Bionic_sha256'])
    assert data['source_fingerprints'] == source_fingerprints()
    row = data['case_result']
    p = module_prefix()
    assert row['control'] == p.CONTROL
    assert row['random_callback']['callback_wrapper_returned_to_interpreter'] is True
    assert row['vm_resume']['resume_offset'] == '0x16aa4c'
    assert row['vm_resume']['first_instruction_executed'] is True
    dispatch = row['post_return_dispatch']
    call = dispatch['next_indirect_call']
    assert call['callsite_offset'] == '0x16aa48'
    assert call['instruction'] == 'blr x8'
    assert call['target_offset'] == '0x2885e0'
    assert call['target_wrapper_entered'] is True
    resolved = row['callback_resolution']
    descriptor = resolved['descriptor']
    assert descriptor['wrapper_entry_offset'] == '0x2885e0'
    assert descriptor['descriptor_is_mapped'] is True
    assert len(descriptor['descriptor_sha256']) == 64
    assert descriptor['return_offset'] == '0x16aa4c'
    tail = resolved['tail_branch']
    assert tail['branch_offset'] == '0x2885e8'
    assert tail['instruction'] == 'br x1'
    branch_word = int.from_bytes(bytes.fromhex(tail['instruction_bytes']), 'little')
    assert branch_word & BR_MASK == BR_BASE
    assert tail['target_matches_descriptor_first_word'] is True
    assert tail['callback_argument_matches_descriptor_second_word'] is True
    assert tail['target_is_mapped'] is True and tail['target_is_null'] is False
    assert tail['branch_target_executed'] is False
    assert resolved['tail_branch_target_executed'] is False
    assert dispatch['next_call_target_executed'] is True
    assert data['claims'] == claims_for(row)


def damaged_evidence_rejected(data: dict) -> int:
    paths = [
        ('claims', 'known_native_trampoline_wrapper_executed'),
        ('providers', 'resolved_wrapper_offset'),
        ('input_provenance', 'Metasec_sha256'),
        ('case_result', 'callback_resolution', 'descriptor', 'descriptor_sha256'),
        ('case_result', 'callback_resolution', 'tail_branch', 'instruction_bytes'),
        ('case_result', 'callback_resolution', 'tail_branch', 'branch_target_executed'),
        ('case_result', 'callback_resolution', 'tail_branch', 'target', 'offset'),
        ('claims', 'callback_descriptor_sha256'),
    ]
    values = [False, '0xdeadbeef', '0' * 64, '0' * 64, 'ffffffff', True,
              '0xdeadbeef', '0' * 64]
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
        raise AssertionError(f'damaged resolved-callback evidence accepted: {path}')
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
            parser.error('refusing to overwrite frozen callback-resolution evidence')
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
    row = data['case_result']['callback_resolution']
    print(json.dumps(dict(
        schema=SCHEMA,
        damaged_evidence_rejected=rejected,
        vm_callsite=row['wrapper_call']['callsite_offset'],
        resolved_target=row['tail_branch']['target'],
        callback_target_executed=False,
        complete_standalone_signer_verified=False)))


if __name__ == '__main__':
    main()
