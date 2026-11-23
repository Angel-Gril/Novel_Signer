"""Execute the next VM diagnostic callback and stop before VM resumption."""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from unicorn import arm64_const as arm

import verify_vm9_native_171_shared_reader_return_dynamic_20261121 as previous

EVIDENCE = previous.EVIDENCE.with_name(
    'vm9_native_171_diagnostic_scope_entry_dynamic_20261121.json')
SCHEMA = 'vm9-native-171-diagnostic-scope-entry-dynamic-20261121-v1'
WRAPPER = 0x288530
TARGET = 0x26C858
VM_RESUME = previous.previous.VM_RESUME
TARGET_PATH = tuple(range(TARGET, 0x26C8C4, 4)) + tuple(
    range(0x26C908, 0x26C990, 4))


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prior_evidence() -> dict:
    data = json.loads(previous.EVIDENCE.read_text(encoding='utf-8'))
    previous.validate(data)
    return data


def source_fingerprints() -> dict:
    return dict(
        diagnostic_scope_verifier_sha256=sha256(Path(__file__)),
        shared_reader_verifier_sha256=sha256(Path(previous.__file__)),
        inherited_source_fingerprints=previous.source_fingerprints())


def _delta(before: dict, after: dict) -> dict:
    return {key: after.get(key, 0) - before.get(key, 0)
            for key in sorted(set(before) | set(after))}


class DiagnosticScenario(previous.SharedReaderScenario):
    def __init__(self, control):
        super().__init__(control)
        self._post_reader_active = False
        self._diagnostic_descriptor = None
        self._diagnostic_target_entered = False
        self._diagnostic_returned = False
        self._diagnostic_object_before = None
        self._diagnostic_object_after = None
        self._diagnostic_path = []
        self._diagnostic_stop = None

    def _finish_reader_without_stop(self, cpu, pc, state):
        assert self.reader_path == list(previous.EXPECTED_PATH)
        assert len(self.lock_events) == 2
        assert cpu.reg_read(arm.UC_ARM64_REG_SP) == self._entry_sp
        assert [self._reg(cpu, n) for n in range(19, 30)] == self._saved_registers
        assert self._reg(cpu, 30) == self.image + previous.previous.VM_RESUME
        after = bytes(cpu.mem_read(self._receiver, previous.READER_SIZE))
        expected = bytearray(self._before)
        count = self.reader['reader_count_before'] + 1
        expected[previous.COUNT_OFFSET:previous.COUNT_OFFSET + 4] = count.to_bytes(4, 'little')
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
            return_offset=hex(previous.previous.VM_RESUME),
            stopped_before_returned_caller_instruction=False,
            physical_PAC_authentication_verified=False)
        self._post_reader_active = True
        self._base_observe(cpu, pc, state)

    def _record_diagnostic_entry(self, cpu):
        descriptor = self._reg(cpu, 0)
        assert any(a <= descriptor and descriptor + 24 <= b
                   for a, b, _ in cpu.mem_regions())
        raw = bytes(cpu.mem_read(descriptor, 24))
        first = int.from_bytes(raw[:8], 'little')
        callback_object = int.from_bytes(raw[8:16], 'little')
        input_word = int.from_bytes(raw[16:24], 'little')
        assert first == self.image + TARGET
        assert callback_object != 0 and input_word != 0
        self._diagnostic_descriptor = dict(
            wrapper_offset=hex(WRAPPER),
            descriptor_sha256=hashlib.sha256(raw).hexdigest(),
            descriptor_address=self._relative(descriptor, self.image),
            target=self._relative(first, self.image),
            callback_object=self._relative(callback_object, self.image),
            input_word=hex(input_word),
            target_is_mapped=True,
            target_matches_descriptor_first_word=True,
            callback_object_matches_descriptor_second_word=True,
            input_matches_descriptor_third_word=True,
            wrapper_instruction_path=[hex(offset) for offset in range(WRAPPER, WRAPPER + 16, 4)],
            callback_object_address=hex(callback_object),
            input_word_u64=input_word)
        self._diagnostic_object_before = bytes(cpu.mem_read(callback_object, 24))

    def _record_diagnostic_target(self, cpu, pc):
        assert self._diagnostic_descriptor is not None
        assert self._reg(cpu, 0) == int(
            self._diagnostic_descriptor['callback_object_address'], 16)
        assert self._reg(cpu, 1) == self._diagnostic_descriptor['input_word_u64']
        self._diagnostic_target_entered = True
        self._diagnostic_path.append(hex(pc - self.image))

    def _record_target_instruction(self, pc):
        offset = pc - self.image
        self._diagnostic_path.append(hex(offset))

    def _stop_diagnostic_return(self, cpu, pc, state):
        assert self._diagnostic_target_entered
        assert self._diagnostic_path == [hex(offset) for offset in TARGET_PATH]
        assert self._reg(cpu, 30) == self.image + VM_RESUME
        self._diagnostic_returned = True
        self._diagnostic_object_after = bytes(cpu.mem_read(
            int(self._diagnostic_descriptor['callback_object_address'], 16), 24))
        self._diagnostic_stop = dict(
            kind='diagnostic_callback_return_before_vm_resume',
            stop_before=hex(VM_RESUME),
            callback_returned=True,
            target_return_register=self._reg(cpu, 0),
            object_before_sha256=hashlib.sha256(self._diagnostic_object_before).hexdigest(),
            object_after_sha256=hashlib.sha256(self._diagnostic_object_after).hexdigest(),
            object_before=self._diagnostic_object_before.hex(),
            object_after=self._diagnostic_object_after.hex(),
            diagnostic_path=self._diagnostic_path)
        self._base_observe(cpu, pc, state)
        cpu.emu_stop()
        cpu.reg_write(arm.UC_ARM64_REG_PC,
                      previous.previous.module_prefix().digest.context.outer.oracle.STOP)

    def observe(self, cpu, pc, state):
        offset = pc - self.image
        if not self._post_reader_active:
            if self.reader is not None and offset == VM_RESUME:
                return self._finish_reader_without_stop(cpu, pc, state)
            return super().observe(cpu, pc, state)
        if self._diagnostic_returned:
            return super().observe(cpu, pc, state)
        if self._diagnostic_descriptor is None and offset == WRAPPER:
            self._record_diagnostic_entry(cpu)
        elif (self._diagnostic_descriptor is not None
              and not self._diagnostic_target_entered and offset == TARGET):
            self._record_diagnostic_target(cpu, pc)
        elif self._diagnostic_target_entered and offset == VM_RESUME:
            return self._stop_diagnostic_return(cpu, pc, state)
        elif self._diagnostic_target_entered and TARGET <= offset <= 0x26C98C:
            self._record_target_instruction(pc)
        self._base_observe(cpu, pc, state)

    def finish(self, result, state, proof):
        assert self._diagnostic_returned
        parent = prior_evidence()['case_result']
        allocator_before = parent['post_digest_allocator_counts']
        service_before = parent['post_digest_service_counts']
        allocator_after = result['actual_allocator_counts']
        service_after = result['explicit_service_counts']
        jni_before = parent['JNI_calls']
        jni_after = proof['JNI_calls']
        libc_before = parent['libc_SVC_boundaries']
        libc_after = proof['libc_SVC_boundaries']
        main_before = parent['main_image_SVC_boundaries']
        main_after = proof['main_image_SVC_boundaries']
        return dict(
            control=prior_evidence()['case_result']['control'],
            descriptor=self._diagnostic_descriptor,
            target_path=self._diagnostic_path,
            stop=self._diagnostic_stop,
            allocator_counts_before=allocator_before,
            allocator_counts_after=allocator_after,
            allocator_delta=_delta(allocator_before, allocator_after),
            service_counts_before=service_before,
            service_counts_after=service_after,
            service_delta=_delta(service_before, service_after),
            jni_calls_before=jni_before,
            jni_calls_after=jni_after,
            jni_call_count_delta=len(jni_after) - len(jni_before),
            libc_svc_before=libc_before,
            libc_svc_after=libc_after,
            libc_svc_count_delta=len(libc_after) - len(libc_before),
            main_svc_before=main_before,
            main_svc_after=main_after,
            main_svc_count_delta=len(main_after) - len(main_before))


def replay(path: Path, libc: Path) -> list[dict]:
    prefix = previous.previous.module_prefix()
    digest = prefix.digest

    def create(control):
        scenario = DiagnosticScenario(control)
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
        diagnostic_callback_descriptor_verified=True,
        diagnostic_callback_target_executed=True,
        diagnostic_callback_return_before_vm_resume_verified=True,
        diagnostic_object_counter_update_verified=True,
        allocator_malloc_delta=1,
        service_JNI_SVC_ledgers_unchanged=True,
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
    prefix = previous.previous.module_prefix()
    prefix.digest.verify_images(path, libc)
    assert sha256(path) == parent['input_provenance']['Metasec_sha256']
    assert sha256(libc) == parent['input_provenance']['Bionic_sha256']
    rows = replay(path, libc)
    assert len(rows) == 1
    row = rows[0]
    return dict(
        schema=SCHEMA,
        claims=claims_for(),
        input_provenance=dict(
            inherited_shared_reader_evidence_sha256=sha256(previous.EVIDENCE),
            Metasec_sha256=sha256(path),
            Bionic_sha256=sha256(libc)),
        source_fingerprints=source_fingerprints(),
        case_result=row)


def validate(data: dict) -> None:
    parent = prior_evidence()
    assert data['schema'] == SCHEMA
    assert data['claims'] == claims_for()
    assert data['input_provenance'] == dict(
        inherited_shared_reader_evidence_sha256=sha256(previous.EVIDENCE),
        Metasec_sha256=parent['input_provenance']['Metasec_sha256'],
        Bionic_sha256=parent['input_provenance']['Bionic_sha256'])
    assert data['source_fingerprints'] == source_fingerprints()
    row = data['case_result']
    assert row['control'] == parent['case_result']['control']
    descriptor = row['descriptor']
    assert descriptor['wrapper_offset'] == hex(WRAPPER)
    assert descriptor['target'] == {'space': 'main_image', 'offset': hex(TARGET)}
    assert descriptor['input_word'] == '0x136d9140'
    assert descriptor['input_word_u64'] == 0x136D9140
    assert descriptor['target_is_mapped'] is True
    assert descriptor['target_matches_descriptor_first_word'] is True
    assert descriptor['callback_object_matches_descriptor_second_word'] is True
    assert descriptor['input_matches_descriptor_third_word'] is True
    assert descriptor['wrapper_instruction_path'] == [
        hex(offset) for offset in range(WRAPPER, WRAPPER + 16, 4)]
    assert len(descriptor['descriptor_sha256']) == 64
    assert descriptor['descriptor_sha256'] == '3956aa449c8c0198a7da5166d881ce65d7893f297b996b9c50a706be51476656'
    assert len(descriptor['callback_object_address']) > 2
    assert row['target_path'] == [hex(offset) for offset in TARGET_PATH]
    stop = row['stop']
    assert stop['kind'] == 'diagnostic_callback_return_before_vm_resume'
    assert stop['stop_before'] == hex(VM_RESUME)
    assert stop['callback_returned'] is True
    assert stop['target_return_register'] == 0
    assert stop['object_before'] == '10d4611200000000000000000000000040906d1300000000'
    assert stop['object_after'] == '10d4611200000000000000000000000040916d1300000000'
    assert stop['object_before_sha256'] == '5d27f97202ef305fc482227a060c64eab96e045d3405300c0a8c85313dffe960'
    assert stop['object_after_sha256'] == '16bf9cb3f46e0fb506034e2f9f92a93809f24c34ee181d7823697b9614f2007c'
    assert row['allocator_delta'] == {'flush': 0, 'free': 0, 'gc': 0, 'malloc': 1}
    assert row['service_delta'] == {key: 0 for key in sorted(row['service_counts_before'])}
    assert row['jni_call_count_delta'] == 0
    assert row['jni_calls_after'] == row['jni_calls_before']
    assert row['libc_svc_count_delta'] == 0
    assert row['libc_svc_after'] == row['libc_svc_before']
    assert row['main_svc_count_delta'] == 0
    assert row['main_svc_after'] == row['main_svc_before']


def damaged_evidence_rejected(data: dict) -> int:
    mutations = [
        (('claims', 'diagnostic_callback_target_executed'), False),
        (('claims', 'complete_standalone_signer_verified'), True),
        (('input_provenance', 'Metasec_sha256'), '0' * 64),
        (('source_fingerprints', 'diagnostic_scope_verifier_sha256'), '0' * 64),
        (('case_result', 'descriptor', 'input_word'), '0xdeadbeef'),
        (('case_result', 'descriptor', 'descriptor_sha256'), '0' * 64),
        (('case_result', 'descriptor', 'target_is_mapped'), False),
        (('case_result', 'target_path'), []),
        (('case_result', 'stop', 'callback_returned'), False),
        (('case_result', 'stop', 'target_return_register'), 1),
        (('case_result', 'stop', 'object_after_sha256'), '0' * 64),
        (('case_result', 'allocator_delta', 'malloc'), 0),
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
        raise AssertionError(f'damaged diagnostic evidence accepted: {path}')
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
            parser.error('refusing to overwrite frozen diagnostic evidence')
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
    row = data['case_result']
    print(json.dumps(dict(
        schema=SCHEMA,
        damaged_evidence_rejected=rejected,
        descriptor_sha256=row['descriptor']['descriptor_sha256'],
        input_word=row['descriptor']['input_word'],
        target_path_length=len(row['target_path']),
        malloc_delta=row['allocator_delta']['malloc'],
        service_delta=row['service_delta'],
        callback_returned=row['stop']['callback_returned'],
        stopped_before_vm_resume=row['stop']['stop_before'] == hex(VM_RESUME),
        complete_standalone_signer_verified=False)))


if __name__ == '__main__':
    main()
