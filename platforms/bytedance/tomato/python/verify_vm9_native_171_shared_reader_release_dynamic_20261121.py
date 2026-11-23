"""Execute the shared-reader release selected after diagnostic cleanup."""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from unicorn import arm64_const as arm

import verify_vm9_native_171_diagnostic_cleanup_return_dynamic_20261121 as previous
import verify_vm9_native_171_resolve_next_vm_callback_dynamic_20261121 as callback_prefix

EVIDENCE = previous.EVIDENCE.with_name(
    'vm9_native_171_shared_reader_release_dynamic_20261121.json')
SCHEMA = 'vm9-native-171-shared-reader-release-dynamic-20261121-v1'
RELEASE = 0x32A4FC
CALLSITE = 0x16AA48
WRAPPER = 0x2885E0
VM_RESUME = previous.VM_RESUME
COUNT_OFFSET = 0x88
OBJECT_SIZE = 0x90
LOCK = 0x329F3C
UNLOCK = 0x329F68
BLR_X8 = 0xD63F0100
EXPECTED_PATH = (
    *range(RELEASE, 0x32A514, 4),
    *range(0x329F3C, 0x329F4C, 4), 0x347F00,
    *range(0x3EDA8CF8, 0x3EDA8D18, 4),
    *range(0x3EDA8D28, 0x3EDA8D54, 4),
    *range(0x329F4C, 0x329F5C, 4),
    *range(0x32A514, 0x32A53C, 4),
    *range(0x32A550, 0x32A564, 4),
    *range(0x329F68, 0x329F78, 4), 0x347F10,
    *range(0x3EDA8D5C, 0x3EDA8D88, 4),
    *range(0x3EDA8DBC, 0x3EDA8DEC, 4),
    *range(0x329F78, 0x329F84, 4), VM_RESUME)
READER_BEFORE_SHA256 = '764db798293aec7d3640916011ea7aff9a97fb62332270083148fe75501d7718'
READER_AFTER_SHA256 = '9618aacf80bfb89d35db5870cf3713b72f667e3bec638abc00a0e45932ff183e'


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prior_evidence() -> dict:
    data = json.loads(previous.EVIDENCE.read_text(encoding='utf-8'))
    previous.validate(data)
    return data


def source_fingerprints() -> dict:
    return dict(
        reader_release_verifier_sha256=sha256(Path(__file__)),
        diagnostic_cleanup_return_verifier_sha256=sha256(Path(previous.__file__)),
        inherited_source_fingerprints=previous.source_fingerprints())


def _delta(before: dict, after: dict) -> dict:
    return {key: after.get(key, 0) - before.get(key, 0)
            for key in sorted(set(before) | set(after))}


class ReaderReleaseScenario(previous.CleanupReturnScenario):
    def __init__(self, control):
        super().__init__(control)
        self._resume_active = False
        self._resume_pcs = []
        self._next_call = None
        self._release_callback = None
        self._wrapper_path = []
        self._release_active = False
        self._release_returned = False
        self._release_path = []
        self._release_events = []
        self._release_object_before = None
        self._release_object_after = None
        self._release_mutex_before = None
        self._release_mutex_after = None
        self._release_sp = None
        self._release_saved_registers = None
        self._release_stop = None

    def _stop_cleanup_body(self, cpu, pc, state):
        assert self._cleanup_path == [hex(offset) for offset in previous.CLEANUP_PATH]
        assert self._reg(cpu, 30) == self.image + VM_RESUME
        assert self._reg(cpu, 0) == 0
        self._cleanup_body_returned = True
        address = int(self._next_callback['callback_object_address'], 16)
        self._cleanup_object_after = bytes(cpu.mem_read(address, 24))
        self._mutex_after = bytes(cpu.mem_read(self._mutex_address, 8))
        assert self._cleanup_object_after.hex() == previous.OBJECT
        assert self._mutex_before.hex() == previous.MUTEX_BEFORE
        assert self._mutex_after.hex() == previous.MUTEX_AFTER
        self._body_stop = dict(cleanup_returned=True,
                               target_return_register=self._reg(cpu, 0))
        self._resume_active = True
        self._next_call = None
        self._wrapper_path = []
        self._base_observe(cpu, pc, state)

    def _record_release_call(self, cpu, pc):
        raw = bytes(cpu.mem_read(pc, 4))
        assert int.from_bytes(raw, 'little') == BLR_X8
        target = self._reg(cpu, 8)
        descriptor = self._reg(cpu, 0)
        assert target == self.image + WRAPPER
        assert any(a <= descriptor and descriptor + 16 <= b
                   for a, b, _ in cpu.mem_regions())
        self._next_call = dict(
            callsite_offset=hex(CALLSITE), instruction='blr x8',
            instruction_bytes=raw.hex(), target=self._relative(target, self.image),
            descriptor_address=self._relative(descriptor, self.image),
            descriptor_is_mapped=True)

    def _record_release_wrapper(self, cpu):
        descriptor = self._reg(cpu, 0)
        raw = bytes(cpu.mem_read(descriptor, 16))
        target = int.from_bytes(raw[:8], 'little')
        receiver = int.from_bytes(raw[8:], 'little')
        assert target == self.image + RELEASE and receiver != 0
        self._release_callback = dict(
            wrapper_offset=hex(WRAPPER),
            descriptor_address=self._relative(descriptor, self.image),
            descriptor_sha256=hashlib.sha256(raw).hexdigest(),
            descriptor_first_word=self._relative(target, self.image),
            descriptor_second_word=self._relative(receiver, self.image),
            descriptor_is_mapped=True,
            target_is_mapped=True,
            receiver_address=hex(receiver),
            target_matches_descriptor_first_word=True,
            receiver_matches_descriptor_second_word=True)
        self._wrapper_path = [hex(WRAPPER)]

    def _enter_release(self, cpu):
        assert self._release_callback is not None
        receiver = int(self._release_callback['receiver_address'], 16)
        assert self._reg(cpu, 0) == receiver
        assert receiver == self._receiver
        self._release_object_before = bytes(cpu.mem_read(receiver, OBJECT_SIZE))
        count = int.from_bytes(self._release_object_before[
            COUNT_OFFSET:COUNT_OFFSET + 4], 'little')
        assert count == 1
        self._release_mutex_before = bytes(cpu.mem_read(receiver, 8))
        assert self._release_mutex_before == bytes(8)
        self._release_sp = cpu.reg_read(arm.UC_ARM64_REG_SP)
        self._release_saved_registers = [self._reg(cpu, n) for n in range(19, 30)]
        self._release_active = True

    def _stop_release_return(self, cpu, pc, state):
        receiver = int(self._release_callback['receiver_address'], 16)
        assert self._release_path == [hex(offset) for offset in EXPECTED_PATH]
        assert self._reg(cpu, 30) == self.image + VM_RESUME
        assert cpu.reg_read(arm.UC_ARM64_REG_SP) == self._release_sp
        assert [self._reg(cpu, n) for n in range(19, 30)] == self._release_saved_registers
        self._release_object_after = bytes(cpu.mem_read(receiver, OBJECT_SIZE))
        self._release_mutex_after = bytes(cpu.mem_read(receiver, 8))
        expected = bytearray(self._release_object_before)
        expected[COUNT_OFFSET:COUNT_OFFSET + 4] = (0).to_bytes(4, 'little')
        assert self._release_object_after == expected
        assert self._release_object_after == self._before
        assert self._release_mutex_after == self._release_mutex_before
        assert self._release_events == [
            dict(helper_offset=hex(LOCK), caller_offset='0x32a514',
                 receiver_matches_descriptor=True),
            dict(helper_offset=hex(UNLOCK), caller_offset=hex(VM_RESUME),
                 receiver_matches_descriptor=True)]
        self._release_returned = True
        self._release_stop = dict(
            kind='shared_reader_release_return_before_vm_resume',
            stop_before=hex(VM_RESUME),
            callback_returned=True,
            target_return_register=self._reg(cpu, 0),
            reader_count_before=1,
            reader_count_after=0,
            reader_count_offset=hex(COUNT_OFFSET),
            observed_object_size=OBJECT_SIZE,
            same_receiver_as_acquisition=True,
            object_restored_to_pre_acquisition_bytes=True,
            object_before_sha256=hashlib.sha256(self._release_object_before).hexdigest(),
            object_after_sha256=hashlib.sha256(self._release_object_after).hexdigest(),
            bytes_outside_reader_count_preserved=True,
            mutex_before=self._release_mutex_before.hex(),
            mutex_after=self._release_mutex_after.hex(),
            stack_pointer_restored=True,
            callee_saved_registers_restored=True,
            return_offset=hex(VM_RESUME),
            observed_path_offsets=list(self._release_path),
            mutex_helper_calls=self._release_events)
        self._base_observe(cpu, pc, state)
        cpu.emu_stop()
        cpu.reg_write(
            arm.UC_ARM64_REG_PC,
            callback_prefix.module_prefix().digest.context.outer.oracle.STOP)

    def observe(self, cpu, pc, state):
        offset = pc - self.image
        if not self._diagnostic_returned:
            return super().observe(cpu, pc, state)
        if not self._cleanup_body_returned:
            return super().observe(cpu, pc, state)
        if self._release_returned:
            return super().observe(cpu, pc, state)
        if not self._release_active:
            self._resume_pcs.append(hex(offset))
            if offset == CALLSITE and self._next_call is None:
                self._record_release_call(cpu, pc)
            if self._next_call is not None and self._release_callback is None:
                target_offset = int(self._next_call['target']['offset'], 16)
                if offset == target_offset:
                    self._record_release_wrapper(cpu)
            elif self._release_callback is not None and offset in (WRAPPER, WRAPPER + 4, WRAPPER + 8):
                self._wrapper_path.append(hex(offset))
            if offset == RELEASE and self._release_callback is not None:
                assert self._wrapper_path == [hex(value) for value in
                                               (WRAPPER, WRAPPER + 4, WRAPPER + 8)]
                self._enter_release(cpu)
                self._release_path.append(hex(offset))
            self._base_observe(cpu, pc, state)
            return
        self._release_path.append(hex(offset))
        if offset in (LOCK, UNLOCK):
            assert self._reg(cpu, 0) == int(self._release_callback['receiver_address'], 16)
            self._release_events.append(dict(
                helper_offset=hex(offset),
                caller_offset=hex(self._reg(cpu, 30) - self.image),
                receiver_matches_descriptor=True))
        if offset == VM_RESUME:
            return self._stop_release_return(cpu, pc, state)
        self._base_observe(cpu, pc, state)

    def finish(self, result, state, proof):
        assert self._release_returned
        parent = prior_evidence()['case_result']
        allocator_before = parent['allocator_counts_after']
        service_before = parent['service_counts_after']
        jni_before = parent['jni_calls_after']
        libc_before = parent['libc_svc_after']
        main_before = parent['main_svc_after']
        allocator_after = result['actual_allocator_counts']
        service_after = result['explicit_service_counts']
        jni_after = proof['JNI_calls']
        libc_after = proof['libc_SVC_boundaries']
        main_after = proof['main_image_SVC_boundaries']
        return dict(
            control=parent['control'],
            prior_diagnostic_cleanup_return_verified=True,
            vm_instruction_count=len(self._resume_pcs),
            vm_pc_prefix=self._resume_pcs[:16], vm_pc_suffix=self._resume_pcs[-16:],
            next_call=self._next_call, release_callback=self._release_callback,
            wrapper_instruction_path=self._wrapper_path,
            shared_reader_release=self._release_stop,
            allocator_counts_before=allocator_before, allocator_counts_after=allocator_after,
            allocator_delta=_delta(allocator_before, allocator_after),
            service_counts_before=service_before, service_counts_after=service_after,
            service_delta=_delta(service_before, service_after),
            jni_calls_before=jni_before, jni_calls_after=jni_after,
            jni_call_count_delta=len(jni_after) - len(jni_before),
            libc_svc_before=libc_before, libc_svc_after=libc_after,
            libc_svc_count_delta=len(libc_after) - len(libc_before),
            main_svc_before=main_before, main_svc_after=main_after,
            main_svc_count_delta=len(main_after) - len(main_before))


def replay(path: Path, libc: Path) -> list[dict]:
    prefix = callback_prefix.module_prefix()
    digest = prefix.digest

    def create(control):
        scenario = ReaderReleaseScenario(control)
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
        post_cleanup_shared_reader_release_wrapper_resolved=True,
        original_shared_reader_release_executed=True,
        reader_count_decremented_from_one_to_zero=True,
        reader_object_outside_count_preserved=True,
        reader_mutex_restored=True,
        shared_reader_release_return_to_vm_verified=True,
        allocator_service_JNI_SVC_ledgers_unchanged=True,
        next_vm_instruction_executed=False,
        current_native_suffix_return_verified=False,
        complete_standalone_signer_verified=False,
        ordinary_Cronet_six_headers_verified=False,
        online_acceptance_verified=False,
        Android_execution=False,
        native_memory_used_as_python_model_input=False,
        physical_PAC_authentication_verified=False)


def run(path: Path, libc: Path) -> dict:
    parent = prior_evidence()
    prefix = callback_prefix.module_prefix()
    prefix.digest.verify_images(path, libc)
    assert sha256(path) == parent['input_provenance']['Metasec_sha256']
    assert sha256(libc) == parent['input_provenance']['Bionic_sha256']
    rows = replay(path, libc)
    assert len(rows) == 1
    return dict(schema=SCHEMA, claims=claims_for(),
        input_provenance=dict(
            inherited_cleanup_return_evidence_sha256=sha256(previous.EVIDENCE),
            Metasec_sha256=sha256(path), Bionic_sha256=sha256(libc)),
        source_fingerprints=source_fingerprints(), case_result=rows[0])


def validate(data: dict) -> None:
    parent = prior_evidence()
    assert data['schema'] == SCHEMA
    assert data['claims'] == claims_for()
    assert data['input_provenance'] == dict(
        inherited_cleanup_return_evidence_sha256=sha256(previous.EVIDENCE),
        Metasec_sha256=parent['input_provenance']['Metasec_sha256'],
        Bionic_sha256=parent['input_provenance']['Bionic_sha256'])
    assert data['source_fingerprints'] == source_fingerprints()
    row = data['case_result']
    assert row['control'] == parent['case_result']['control']
    assert row['prior_diagnostic_cleanup_return_verified'] is True
    assert row['vm_instruction_count'] == 863
    assert row['vm_pc_prefix'] == parent['case_result']['vm_pc_prefix']
    assert row['vm_pc_suffix'][-4:] == ['0x2885e0', '0x2885e4', '0x2885e8', '0x32a4fc']
    assert row['next_call']['callsite_offset'] == hex(CALLSITE)
    assert row['next_call']['target'] == {'space': 'main_image', 'offset': hex(WRAPPER)}
    assert row['next_call']['instruction'] == 'blr x8'
    assert row['next_call']['instruction_bytes'] == '00013fd6'
    assert row['next_call']['descriptor_is_mapped'] is True
    callback = row['release_callback']
    assert callback['wrapper_offset'] == hex(WRAPPER)
    assert callback['descriptor_sha256'] == '93fa796001add214ea687f3c7667dbc09213f8c5b2a7bee7c6a8c0a913d7e977'
    assert callback['descriptor_first_word'] == {'space': 'main_image', 'offset': hex(RELEASE)}
    assert callback['descriptor_is_mapped'] is True and callback['target_is_mapped'] is True
    assert callback['target_matches_descriptor_first_word'] is True
    assert callback['receiver_matches_descriptor_second_word'] is True
    assert callback['receiver_address'] == '0x136da148'
    assert row['wrapper_instruction_path'] == [hex(v) for v in (WRAPPER, WRAPPER + 4, WRAPPER + 8)]
    release = row['shared_reader_release']
    assert release['kind'] == 'shared_reader_release_return_before_vm_resume'
    assert release['stop_before'] == hex(VM_RESUME)
    assert release['callback_returned'] is True
    assert release['target_return_register'] == 0
    assert release['reader_count_before'] == 1 and release['reader_count_after'] == 0
    assert release['reader_count_offset'] == hex(COUNT_OFFSET)
    assert release['observed_object_size'] == OBJECT_SIZE
    assert release['same_receiver_as_acquisition'] is True
    assert release['object_restored_to_pre_acquisition_bytes'] is True
    assert release['object_before_sha256'] == READER_BEFORE_SHA256
    assert release['object_after_sha256'] == READER_AFTER_SHA256
    assert release['bytes_outside_reader_count_preserved'] is True
    assert release['mutex_before'] == '0000000000000000'
    assert release['mutex_after'] == '0000000000000000'
    assert release['stack_pointer_restored'] is True
    assert release['callee_saved_registers_restored'] is True
    assert release['return_offset'] == hex(VM_RESUME)
    assert release['observed_path_offsets'] == [hex(v) for v in EXPECTED_PATH]
    assert release['mutex_helper_calls'] == [
        dict(helper_offset=hex(LOCK), caller_offset='0x32a514', receiver_matches_descriptor=True),
        dict(helper_offset=hex(UNLOCK), caller_offset=hex(VM_RESUME), receiver_matches_descriptor=True)]
    assert row['allocator_delta'] == {'flush': 0, 'free': 0, 'gc': 0, 'malloc': 0}
    for stem in ('allocator_counts', 'service_counts', 'jni_calls', 'libc_svc', 'main_svc'):
        assert row[stem + '_before'] == parent['case_result'][stem + '_after'], stem
        assert row[stem + '_after'] == row[stem + '_before'], stem
    assert row['allocator_delta'] == _delta(row['allocator_counts_before'], row['allocator_counts_after'])
    assert row['service_delta'] == _delta(row['service_counts_before'], row['service_counts_after'])
    assert row['service_delta'] == {key: 0 for key in sorted(row['service_counts_before'])}
    assert row['jni_call_count_delta'] == 0 and row['jni_calls_after'] == row['jni_calls_before']
    assert row['libc_svc_count_delta'] == 0 and row['libc_svc_after'] == row['libc_svc_before']
    assert row['main_svc_count_delta'] == 0 and row['main_svc_after'] == row['main_svc_before']


def damaged_evidence_rejected(data: dict) -> int:
    mutations = [
        (('claims', 'original_shared_reader_release_executed'), False),
        (('claims', 'complete_standalone_signer_verified'), True),
        (('input_provenance', 'Metasec_sha256'), '0' * 64),
        (('source_fingerprints', 'reader_release_verifier_sha256'), '0' * 64),
        (('case_result', 'vm_instruction_count'), 0),
        (('case_result', 'next_call', 'target', 'offset'), '0xdeadbeef'),
        (('case_result', 'release_callback', 'descriptor_sha256'), '0' * 64),
        (('case_result', 'wrapper_instruction_path'), []),
        (('case_result', 'shared_reader_release', 'reader_count_after'), 1),
        (('case_result', 'shared_reader_release', 'object_after_sha256'), '0' * 64),
        (('case_result', 'shared_reader_release', 'bytes_outside_reader_count_preserved'), False),
        (('case_result', 'shared_reader_release', 'mutex_after'), '0100000000000000'),
        (('case_result', 'shared_reader_release', 'observed_path_offsets'), []),
        (('case_result', 'shared_reader_release', 'callback_returned'), False),
        (('case_result', 'shared_reader_release', 'target_return_register'), 1),
        (('case_result', 'shared_reader_release', 'stop_before'), '0xdeadbeef'),
        (('case_result', 'shared_reader_release', 'stack_pointer_restored'), False),
        (('case_result', 'shared_reader_release', 'callee_saved_registers_restored'), False),
        (('case_result', 'shared_reader_release', 'same_receiver_as_acquisition'), False),
        (('case_result', 'shared_reader_release', 'object_restored_to_pre_acquisition_bytes'), False),
        (('case_result', 'allocator_counts_after', 'malloc'), 0),
        (('case_result', 'service_counts_after', 'syscall_169'), 0),
        (('case_result', 'allocator_delta', 'malloc'), 1),
        (('case_result', 'service_delta', 'syscall_169'), 1),
        (('case_result', 'jni_call_count_delta'), 1),
        (('case_result', 'libc_svc_count_delta'), 1),
        (('case_result', 'main_svc_count_delta'), 1),
    ]
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
        raise AssertionError(f'damaged shared-reader release evidence accepted: {path}')
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
            parser.error('refusing to overwrite frozen reader-release evidence')
        data = run(args.elf, args.libc)
        validate(data)
        rejected = damaged_evidence_rejected(data)
        with EVIDENCE.open('x', encoding='utf-8') as output:
            output.write(json.dumps(data, ensure_ascii=False, indent=2) + '\n')
    else:
        data = json.loads(EVIDENCE.read_text(encoding='utf-8'))
        validate(data)
        rejected = damaged_evidence_rejected(data)
        if args.replay:
            assert run(args.elf, args.libc) == data
    release = data['case_result']['shared_reader_release']
    print(json.dumps(dict(
        schema=SCHEMA, damaged_evidence_rejected=rejected,
        reader_count_before=release['reader_count_before'],
        reader_count_after=release['reader_count_after'],
        mutex_before=release['mutex_before'], mutex_after=release['mutex_after'],
        callback_returned=True, allocator_delta=data['case_result']['allocator_delta'],
        complete_standalone_signer_verified=False)))


if __name__ == '__main__':
    main()
