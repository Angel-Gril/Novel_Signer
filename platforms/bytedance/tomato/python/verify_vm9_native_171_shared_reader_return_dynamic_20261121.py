"""Execute the resolved shared-reader callback and stop before VM resumption."""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from unicorn import arm64_const as arm

import verify_vm9_native_171_resolve_next_vm_callback_dynamic_20261121 as previous

EVIDENCE = previous.EVIDENCE.with_name(
    'vm9_native_171_shared_reader_return_dynamic_20261121.json')
SCHEMA = 'vm9-native-171-shared-reader-return-dynamic-20261121-v1'
READER = 0x32A444
READER_SIZE = 0x90
COUNT_OFFSET = 0x88
READER_RETURN = 0x32A4F4
LOCK = 0x329F3C
UNLOCK = 0x329F68
EXPECTED_PATH = (
    *range(READER, 0x32A48C, 4), 0x32A4C0, 0x32A4C4,
    0x32A4C8, 0x32A4CC, *range(0x32A4D0, READER_RETURN + 4, 4))
PRESERVED_KEYS = (
    'allocator_counts', 'post_digest_allocator_counts',
    'post_digest_allocator_event_count', 'post_digest_allocator_events_sha256',
    'post_digest_service_counts', 'post_digest_service_delta', 'JNI_calls',
    'libc_SVC_boundaries', 'main_image_SVC_boundaries',
    'gettimeofday', 'late_jni', 'java_dispatch')


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prior_evidence() -> dict:
    data = json.loads(previous.EVIDENCE.read_text())
    previous.validate(data)
    return data


def source_fingerprints() -> dict:
    return dict(
        shared_reader_verifier_sha256=sha256(Path(__file__)),
        callback_resolution_verifier_sha256=sha256(Path(previous.__file__)),
        inherited_source_fingerprints=previous.source_fingerprints())


class SharedReaderScenario(previous.ResolveVmCallbackScenario):
    def __init__(self, control):
        super().__init__(control)
        self.reader = None
        self.reader_path = []
        self.lock_events = []
        self._reader_branch_seen = False
        self._receiver = None
        self._before = None
        self._entry_sp = None
        self._saved_registers = None

    @staticmethod
    def _half(cpu, address):
        return int.from_bytes(cpu.mem_read(address, 2), 'little')

    def _continue_tail_branch(self, cpu, pc, state):
        assert self.callback_descriptor is not None
        descriptor = bytes(cpu.mem_read(self._descriptor_address, 16))
        target = self._reg(cpu, 1)
        receiver = self._reg(cpu, 0)
        assert target == self.image + READER
        assert int.from_bytes(descriptor[:8], 'little') == target
        assert int.from_bytes(descriptor[8:], 'little') == receiver
        assert bytes(cpu.mem_read(pc, 4)).hex() == '20001fd6'
        region = next((perms for start, end, perms in cpu.mem_regions()
                       if start <= target < end), None)
        assert region is not None and region & 4
        assert self._reg(cpu, 30) == self.image + previous.VM_RESUME
        self.callback_tail_branch = dict(
            branch_offset=hex(previous.TAIL_BRANCH), instruction='br x1',
            instruction_bytes='20001fd6',
            target=self._relative(target, self.image),
            target_is_mapped=True, target_is_null=False,
            target_mapping_permissions=region,
            callback_argument=self._relative(receiver, self.image),
            target_matches_descriptor_first_word=True,
            callback_argument_matches_descriptor_second_word=True,
            branch_target_executed=False)
        self._reader_branch_seen = True
        self._receiver = receiver
        self._base_observe(cpu, pc, state)

    def _enter_reader(self, cpu):
        assert self.reader is None and self._reg(cpu, 0) == self._receiver
        self._before = bytes(cpu.mem_read(self._receiver, READER_SIZE))
        readers = int.from_bytes(self._before[COUNT_OFFSET:COUNT_OFFSET + 4], 'little')
        mutex = self._half(cpu, self._receiver)
        assert readers < 0x7FFFFFFF and mutex in (0, 0x2000)
        self._entry_sp = cpu.reg_read(arm.UC_ARM64_REG_SP)
        self._saved_registers = [self._reg(cpu, n) for n in range(19, 30)]
        self.reader = dict(
            target_offset=hex(READER),
            receiver_matches_descriptor=True,
            reader_count_offset=hex(COUNT_OFFSET),
            reader_count_before=readers,
            mutex_state_before=mutex,
            observed_object_size=READER_SIZE,
            object_before_sha256=hashlib.sha256(self._before).hexdigest(),
            canary_saved_and_matches_thread_pointer=False,
            reader_increment_observed=False,
            internal_mutex_restored=False,
            returned_to_vm=False)

    def _stop_after_return(self, cpu, pc, state):
        assert self.reader is not None
        assert self.reader_path == list(EXPECTED_PATH)
        assert self.lock_events == [
            dict(helper_offset=hex(LOCK), caller_offset='0x32a47c',
                 receiver_matches_descriptor=True),
            dict(helper_offset=hex(UNLOCK), caller_offset='0x32a4d0',
                 receiver_matches_descriptor=True)]
        assert cpu.reg_read(arm.UC_ARM64_REG_SP) == self._entry_sp
        assert [self._reg(cpu, n) for n in range(19, 30)] == self._saved_registers
        assert self._reg(cpu, 30) == self.image + previous.VM_RESUME
        after = bytes(cpu.mem_read(self._receiver, READER_SIZE))
        expected = bytearray(self._before)
        count = self.reader['reader_count_before'] + 1
        expected[COUNT_OFFSET:COUNT_OFFSET + 4] = count.to_bytes(4, 'little')
        assert after == expected
        assert self.reader['canary_saved_and_matches_thread_pointer']
        assert self.reader['reader_increment_observed']
        self.reader.update(
            reader_count_after=count,
            mutex_state_after=self._half(cpu, self._receiver),
            object_after_sha256=hashlib.sha256(after).hexdigest(),
            bytes_outside_reader_count_preserved=True,
            internal_mutex_restored=True,
            stack_pointer_restored=True,
            callee_saved_registers_restored=True,
            executed_target_offsets=[hex(offset) for offset in self.reader_path],
            mutex_helper_calls=self.lock_events,
            returned_to_vm=True,
            return_offset=hex(previous.VM_RESUME),
            stopped_before_returned_caller_instruction=True,
            physical_PAC_authentication_verified=False)
        self.continuation_boundary = dict(
            kind='shared_reader_return_before_vm_resume',
            stop_before=hex(previous.VM_RESUME),
            caller_instruction_executed=False)
        # Inherited finish uses this marker only to retire its older SVC stop.
        self.svc_boundary = dict(pc_offset='0x288648')
        self._base_observe(cpu, pc, state)
        cpu.emu_stop()
        cpu.reg_write(arm.UC_ARM64_REG_PC,
                      previous.module_prefix().digest.context.outer.oracle.STOP)

    def observe(self, cpu, pc, state):
        offset = pc - self.image
        if (self._vm_wrapper_entered and not self._reader_branch_seen
                and offset == previous.TAIL_BRANCH):
            return self._continue_tail_branch(cpu, pc, state)
        if not self._reader_branch_seen:
            return super().observe(cpu, pc, state)
        if self.reader is not None and offset == previous.VM_RESUME:
            return self._stop_after_return(cpu, pc, state)
        if offset == READER:
            self._enter_reader(cpu)
        assert self.reader is not None, 'tail branch did not reach the pinned reader'
        if READER <= offset < 0x32A4FC:
            self.reader_path.append(offset)
            assert offset in EXPECTED_PATH, 'reader wait/error branch is outside this control'
        if offset in (LOCK, UNLOCK):
            assert self._reg(cpu, 0) == self._receiver
            self.lock_events.append(dict(
                helper_offset=hex(offset),
                caller_offset=hex(self._reg(cpu, 30) - self.image),
                receiver_matches_descriptor=True))
        if offset == 0x32A478:
            tp = cpu.reg_read(arm.UC_ARM64_REG_TPIDR_EL0)
            saved = bytes(cpu.mem_read(self._entry_sp - 0x38, 8))
            assert saved == bytes(cpu.mem_read(tp + 0x28, 8))
            self.reader['canary_saved_and_matches_thread_pointer'] = True
        if offset == 0x32A47C:
            assert self._half(cpu, self._receiver) == self.reader['mutex_state_before'] | 1
        if offset == 0x32A4C8:
            count = int.from_bytes(cpu.mem_read(self._receiver + COUNT_OFFSET, 4), 'little')
            assert count == self.reader['reader_count_before'] + 1
            self.reader['reader_increment_observed'] = True
        self._base_observe(cpu, pc, state)

    def finish(self, result, state, proof):
        assert self.reader is not None and self.reader['returned_to_vm']
        row = super().finish(result, state, proof)
        parent = prior_evidence()['case_result']
        for key in PRESERVED_KEYS:
            assert row[key] == parent[key], key
        for key in ('vm_resume', 'post_return_dispatch', 'callback_resolution'):
            assert row[key] == parent[key], key
        row['callback_resolution']['tail_branch']['branch_target_executed'] = True
        row['callback_resolution']['tail_branch_target_executed'] = True
        row['shared_reader_callback'] = self.reader
        row['stop_boundary'] = self.continuation_boundary
        return row


def replay(path: Path, libc: Path) -> list[dict]:
    prefix = previous.module_prefix()
    digest = prefix.digest

    def create(control):
        scenario = SharedReaderScenario(control)
        scenario.path = path
        scenario.continue_to_svc = True
        return scenario

    return digest.context.replay(
        path, libc, case_controls=[prefix.CONTROL], _extension_factory=create,
        _request_profile=digest.previous.previous.name.previous.previous.PROFILE['name'],
        _handler_read_profile=digest.context.NULL_PAYLOAD_READ_PROFILE['name'])


def claims_for() -> dict:
    return dict(
        evidence_label='Sample verified',
        resolved_shared_reader_callback_executed=True,
        uncontended_reader_increment_and_mutex_restore_verified=True,
        callback_return_to_vm_verified=True,
        allocator_service_JNI_SVC_ledgers_preserved=True,
        post_reader_VM_instruction_executed=False,
        current_native_suffix_return_verified=False,
        complete_standalone_signer_verified=False,
        ordinary_Cronet_six_headers_verified=False,
        online_acceptance_verified=False,
        Android_execution=False,
        native_memory_used_as_python_model_input=False,
        physical_PAC_authentication_verified=False)


def provenance(parent: dict) -> dict:
    return dict(
        inherited_callback_resolution_sha256=sha256(previous.EVIDENCE),
        Metasec_sha256=parent['input_provenance']['Metasec_sha256'],
        Bionic_sha256=parent['input_provenance']['Bionic_sha256'])


def run(path: Path, libc: Path) -> dict:
    parent = prior_evidence()
    previous.module_prefix().digest.verify_images(path, libc)
    assert sha256(path) == parent['input_provenance']['Metasec_sha256']
    assert sha256(libc) == parent['input_provenance']['Bionic_sha256']
    rows = replay(path, libc)
    assert len(rows) == 1
    return dict(schema=SCHEMA, claims=claims_for(),
                input_provenance=provenance(parent),
                source_fingerprints=source_fingerprints(), case_result=rows[0])


def validate(data: dict) -> None:
    parent = prior_evidence()
    assert data['schema'] == SCHEMA
    assert data['claims'] == claims_for()
    assert data['input_provenance'] == provenance(parent)
    assert data['source_fingerprints'] == source_fingerprints()
    row = data['case_result']
    old = parent['case_result']
    for key in (*PRESERVED_KEYS, 'control', 'vm_resume',
                'post_return_dispatch'):
        assert row[key] == old[key], key
    random_callback = deepcopy(old['random_callback'])
    random_callback['status'] = 'resumed_vm_dispatch_after_random_wrapper'
    assert row['random_callback'] == random_callback
    resolved = deepcopy(old['callback_resolution'])
    resolved['tail_branch']['branch_target_executed'] = True
    resolved['tail_branch_target_executed'] = True
    assert row['callback_resolution'] == resolved
    reader = row['shared_reader_callback']
    assert reader['target_offset'] == hex(READER)
    assert reader['reader_count_offset'] == hex(COUNT_OFFSET)
    assert type(reader['reader_count_before']) is int
    assert 0 <= reader['reader_count_before'] < 0x7FFFFFFF
    assert reader['reader_count_after'] == reader['reader_count_before'] + 1
    assert reader['mutex_state_before'] in (0, 0x2000)
    assert reader['mutex_state_after'] == reader['mutex_state_before']
    assert reader['observed_object_size'] == READER_SIZE
    for key in ('object_before_sha256', 'object_after_sha256'):
        assert len(reader[key]) == 64 and len(bytes.fromhex(reader[key])) == 32
    assert reader['object_before_sha256'] != reader['object_after_sha256']
    for key in ('receiver_matches_descriptor', 'canary_saved_and_matches_thread_pointer',
                'reader_increment_observed', 'bytes_outside_reader_count_preserved',
                'internal_mutex_restored', 'stack_pointer_restored',
                'callee_saved_registers_restored', 'returned_to_vm',
                'stopped_before_returned_caller_instruction'):
        assert reader[key] is True, key
    assert reader['physical_PAC_authentication_verified'] is False
    assert reader['executed_target_offsets'] == [hex(offset) for offset in EXPECTED_PATH]
    assert reader['mutex_helper_calls'] == [
        dict(helper_offset=hex(LOCK), caller_offset='0x32a47c',
             receiver_matches_descriptor=True),
        dict(helper_offset=hex(UNLOCK), caller_offset='0x32a4d0',
             receiver_matches_descriptor=True)]
    assert reader['return_offset'] == hex(previous.VM_RESUME)
    assert row['stop_boundary'] == dict(
        kind='shared_reader_return_before_vm_resume',
        stop_before=hex(previous.VM_RESUME), caller_instruction_executed=False)


def damaged_evidence_rejected(data: dict) -> int:
    mutations = [
        (('claims', 'complete_standalone_signer_verified'), True),
        (('claims', 'resolved_shared_reader_callback_executed'), False),
        (('input_provenance', 'Metasec_sha256'), '0' * 64),
        (('source_fingerprints', 'shared_reader_verifier_sha256'), '0' * 64),
        (('case_result', 'shared_reader_callback', 'reader_count_after'), -1),
        (('case_result', 'shared_reader_callback', 'reader_count_before'), 0x7FFFFFFF),
        (('case_result', 'shared_reader_callback', 'mutex_state_after'), 1),
        (('case_result', 'shared_reader_callback', 'executed_target_offsets'), []),
        (('case_result', 'shared_reader_callback', 'mutex_helper_calls'), []),
        (('case_result', 'shared_reader_callback', 'object_before_sha256'), 'invalid'),
        (('case_result', 'shared_reader_callback', 'return_offset'), '0xdeadbeef'),
        (('case_result', 'shared_reader_callback', 'physical_PAC_authentication_verified'), True),
        (('case_result', 'callback_resolution', 'tail_branch_target_executed'), False),
        (('case_result', 'stop_boundary', 'caller_instruction_executed'), True),
    ]
    for key in ('receiver_matches_descriptor', 'canary_saved_and_matches_thread_pointer',
                'reader_increment_observed', 'bytes_outside_reader_count_preserved',
                'internal_mutex_restored', 'stack_pointer_restored',
                'callee_saved_registers_restored', 'returned_to_vm',
                'stopped_before_returned_caller_instruction'):
        mutations.append((('case_result', 'shared_reader_callback', key), False))
    for path, value in mutations:
        bad = deepcopy(data)
        target = bad
        for part in path[:-1]:
            target = target[part]
        target[path[-1]] = value
        try:
            validate(bad)
        except (AssertionError, KeyError, TypeError, ValueError):
            continue
        raise AssertionError(f'damaged shared-reader evidence accepted: {path}')
    return len(mutations)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf', type=Path)
    parser.add_argument('--libc', type=Path)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--capture', action='store_true')
    group.add_argument('--replay', action='store_true')
    args = parser.parse_args()
    if (args.capture or args.replay) and (not args.elf or not args.libc):
        parser.error('--capture/--replay require --elf and --libc')
    if args.capture:
        if EVIDENCE.exists():
            parser.error('refusing to overwrite frozen shared-reader evidence')
        data = run(args.elf, args.libc)
        validate(data)
        rejected = damaged_evidence_rejected(data)
        with EVIDENCE.open('x', encoding='utf-8') as output:
            output.write(json.dumps(data, ensure_ascii=False, indent=2) + '\n')
    else:
        data = json.loads(EVIDENCE.read_text())
        validate(data)
        rejected = damaged_evidence_rejected(data)
        if args.replay:
            assert run(args.elf, args.libc) == data
    reader = data['case_result']['shared_reader_callback']
    print(json.dumps(dict(schema=SCHEMA, damaged_evidence_rejected=rejected,
                          reader_count_before=reader['reader_count_before'],
                          reader_count_after=reader['reader_count_after'],
                          returned_to_vm=reader['returned_to_vm'],
                          complete_standalone_signer_verified=False)))


if __name__ == '__main__':
    main()
