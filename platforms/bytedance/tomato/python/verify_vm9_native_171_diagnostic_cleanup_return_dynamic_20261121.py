"""Execute diagnostic cleanup and stop before VM resumption."""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from unicorn import arm64_const as arm

import verify_vm9_native_171_diagnostic_cleanup_entry_dynamic_20261121 as previous

EVIDENCE = previous.EVIDENCE.with_name(
    'vm9_native_171_diagnostic_cleanup_return_dynamic_20261121.json')
SCHEMA = 'vm9-native-171-diagnostic-cleanup-return-dynamic-20261121-v1'
TARGET = previous.TARGET
CALLSITE = previous.CALLSITE
WRAPPER = previous.WRAPPER
VM_RESUME = previous.VM_RESUME
WRAPPER_PATH = previous.WRAPPER_PATH
BLR_X8 = previous.BLR_X8
MUTEX_BEFORE = '0140000089000000'
MUTEX_AFTER = '0040000000000000'
OBJECT = '10d4611200000000000000000000000040916d1300000000'
OBJECT_SHA256 = '16bf9cb3f46e0fb506034e2f9f92a93809f24c34ee181d7823697b9614f2007c'
CLEANUP_PATH = (
    *range(TARGET, 0x26C9E4, 4),
    0x26C9E8, 0x26C9EC, 0x26C9F0, 0x26C9F4, 0x26C9F8,
    0x26C9FC, 0x26CA00, 0x26CA04, 0x347F10,
    *range(0x3EDA8D5C, 0x3EDA8DA8, 4),
    *range(0x3EDA8E3C, 0x3EDA8E68, 4),
    *range(0x3EDA8DD4, 0x3EDA8DEC, 4), VM_RESUME)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prior_evidence() -> dict:
    data = json.loads(previous.EVIDENCE.read_text(encoding='utf-8'))
    previous.validate(data)
    return data


def source_fingerprints() -> dict:
    return dict(
        diagnostic_cleanup_return_verifier_sha256=sha256(Path(__file__)),
        diagnostic_cleanup_entry_verifier_sha256=sha256(Path(previous.__file__)),
        inherited_source_fingerprints=previous.source_fingerprints())


def _delta(before: dict, after: dict) -> dict:
    return {key: after.get(key, 0) - before.get(key, 0)
            for key in sorted(set(before) | set(after))}


class CleanupReturnScenario(previous.CleanupEntryScenario):
    def __init__(self, control):
        super().__init__(control)
        self._cleanup_body_active = False
        self._cleanup_body_returned = False
        self._cleanup_path = []
        self._cleanup_object_before = None
        self._cleanup_object_after = None
        self._cleanup_entry = None
        self._cleanup_events = []
        self._cleanup_samples = []
        self._mutex_address = None
        self._mutex_before = None
        self._mutex_after = None
        self._body_stop = None

    def _stop_diagnostic_return(self, cpu, pc, state):
        assert self._diagnostic_target_entered
        assert self._diagnostic_path == [hex(offset)
                                         for offset in previous.previous.TARGET_PATH]
        assert self._reg(cpu, 30) == self.image + VM_RESUME
        self._diagnostic_returned = True
        self._diagnostic_object_after = bytes(cpu.mem_read(
            int(self._diagnostic_descriptor['callback_object_address'], 16), 24))
        self._base_observe(cpu, pc, state)

    def _enter_cleanup_body(self, cpu, pc):
        assert self._next_callback is not None
        assert self._wrapper_path == [hex(offset) for offset in WRAPPER_PATH]
        callback_object = int(self._next_callback['callback_object_address'], 16)
        assert self._reg(cpu, 0) == callback_object
        assert self._reg(cpu, 30) == self.image + VM_RESUME
        self._cleanup_body_active = True
        self._cleanup_entry = dict(
            target_offset=hex(TARGET),
            target_argument=self._relative(self._reg(cpu, 0), self.image),
            return_offset=hex(self._reg(cpu, 30) - self.image),
            object_before_sha256=hashlib.sha256(self._cleanup_object).hexdigest(),
            object_before=self._cleanup_object.hex())
        self._cleanup_object_before = self._cleanup_object

    def _stop_cleanup_body(self, cpu, pc, state):
        assert self._cleanup_path == [hex(offset) for offset in CLEANUP_PATH]
        assert self._reg(cpu, 30) == self.image + VM_RESUME
        callback_object = int(self._next_callback['callback_object_address'], 16)
        self._cleanup_body_returned = True
        self._cleanup_object_after = bytes(cpu.mem_read(callback_object, 24))
        assert self._mutex_address is not None
        self._mutex_after = bytes(cpu.mem_read(self._mutex_address, 8))
        assert self._mutex_before.hex() == MUTEX_BEFORE
        assert self._mutex_after.hex() == MUTEX_AFTER
        self._body_stop = dict(
            kind='diagnostic_cleanup_return_before_vm_resume',
            stop_before=hex(VM_RESUME),
            cleanup_returned=True,
            target_return_register=self._reg(cpu, 0),
            cleanup_path=self._cleanup_path,
            cleanup_events=self._cleanup_events,
            cleanup_samples=self._cleanup_samples,
            object_before_sha256=hashlib.sha256(self._cleanup_object_before).hexdigest(),
            object_after_sha256=hashlib.sha256(self._cleanup_object_after).hexdigest(),
            object_before=self._cleanup_object_before.hex(),
            object_after=self._cleanup_object_after.hex(),
            mutex_address=hex(self._mutex_address),
            mutex_before=self._mutex_before.hex(),
            mutex_after=self._mutex_after.hex())
        self._base_observe(cpu, pc, state)
        cpu.emu_stop()
        cpu.reg_write(
            arm.UC_ARM64_REG_PC,
            previous.previous.previous.previous.module_prefix().digest.context.outer.oracle.STOP)

    def observe(self, cpu, pc, state):
        offset = pc - self.image
        if not self._diagnostic_returned:
            return super().observe(cpu, pc, state)
        if self._cleanup_body_returned:
            return super().observe(cpu, pc, state)
        if not self._cleanup_body_active:
            self._vm_pcs.append(hex(offset))
            if offset == CALLSITE and self._next_call is None:
                self._record_next_call(cpu)
            if self._next_call is not None and self._next_callback is None:
                target_offset = int(self._next_call['target']['offset'], 16)
                if offset == target_offset:
                    self._record_wrapper_entry(cpu)
            elif self._next_callback is not None and offset in WRAPPER_PATH:
                self._wrapper_path.append(hex(offset))
            if offset == TARGET and self._next_callback is not None:
                self._enter_cleanup_body(cpu, pc)
                self._cleanup_path.append(hex(offset))
            self._base_observe(cpu, pc, state)
            return
        self._cleanup_path.append(hex(offset))
        if offset in (0x26C9FC, 0x26CA00, 0x347F10):
            self._cleanup_samples.append(dict(
                pc=hex(offset), x0=hex(self._reg(cpu, 0)),
                x8=hex(self._reg(cpu, 8)), x9=hex(self._reg(cpu, 9))))
        if offset == 0x347F10:
            mutex = self._reg(cpu, 0)
            self._mutex_address = mutex
            self._mutex_before = bytes(cpu.mem_read(mutex, 8))
            self._cleanup_events.append(dict(
                kind='pthread_mutex_unlock', pc='0x347f10',
                mutex_address=hex(mutex), mutex_before=self._mutex_before.hex()))
        if offset == VM_RESUME:
            return self._stop_cleanup_body(cpu, pc, state)
        self._base_observe(cpu, pc, state)

    def finish(self, result, state, proof):
        assert self._cleanup_body_returned
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
            prior_cleanup_entry_verified=True,
            vm_instruction_count=len(self._vm_pcs),
            vm_pc_prefix=self._vm_pcs[:16],
            vm_pc_suffix=self._vm_pcs[-16:],
            cleanup_entry=self._cleanup_entry,
            cleanup_path=self._cleanup_path,
            body_stop=self._body_stop,
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
    prefix = previous.previous.previous.previous.module_prefix()
    digest = prefix.digest

    def create(control):
        scenario = CleanupReturnScenario(control)
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
        diagnostic_cleanup_body_executed=True,
        diagnostic_cleanup_unlock_executed=True,
        diagnostic_cleanup_return_to_vm_verified=True,
        diagnostic_object_preserved_during_cleanup=True,
        mutex_state_restored_after_unlock=True,
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
    prefix = previous.previous.previous.previous.module_prefix()
    prefix.digest.verify_images(path, libc)
    assert sha256(path) == parent['input_provenance']['Metasec_sha256']
    assert sha256(libc) == parent['input_provenance']['Bionic_sha256']
    rows = replay(path, libc)
    assert len(rows) == 1
    return dict(
        schema=SCHEMA, claims=claims_for(),
        input_provenance=dict(
            inherited_cleanup_entry_evidence_sha256=sha256(previous.EVIDENCE),
            Metasec_sha256=sha256(path), Bionic_sha256=sha256(libc)),
        source_fingerprints=source_fingerprints(), case_result=rows[0])


def validate(data: dict) -> None:
    parent = prior_evidence()
    assert data['schema'] == SCHEMA
    assert data['claims'] == claims_for()
    assert data['input_provenance'] == dict(
        inherited_cleanup_entry_evidence_sha256=sha256(previous.EVIDENCE),
        Metasec_sha256=parent['input_provenance']['Metasec_sha256'],
        Bionic_sha256=parent['input_provenance']['Bionic_sha256'])
    assert data['source_fingerprints'] == source_fingerprints()
    row = data['case_result']
    assert row['control'] == parent['case_result']['control']
    assert row['prior_cleanup_entry_verified'] is True
    assert row['cleanup_path'] == [hex(offset) for offset in CLEANUP_PATH]
    assert row['body_stop']['cleanup_returned'] is True
    assert row['body_stop']['stop_before'] == hex(VM_RESUME)
    assert row['body_stop']['target_return_register'] == 0
    assert row['body_stop']['object_before'] == OBJECT
    assert row['body_stop']['object_after'] == OBJECT
    assert row['body_stop']['object_before_sha256'] == OBJECT_SHA256
    assert row['body_stop']['object_after_sha256'] == OBJECT_SHA256
    assert row['body_stop']['mutex_before'] == MUTEX_BEFORE
    assert row['body_stop']['mutex_after'] == MUTEX_AFTER
    assert row['body_stop']['cleanup_events'] == [dict(
        kind='pthread_mutex_unlock', pc='0x347f10',
        mutex_address='0x136d3f38', mutex_before=MUTEX_BEFORE)]
    assert row['allocator_delta'] == {'flush': 0, 'free': 0, 'gc': 0, 'malloc': 0}
    assert row['service_delta'] == {key: 0 for key in sorted(row['service_counts_before'])}
    assert row['jni_call_count_delta'] == 0 and row['jni_calls_after'] == row['jni_calls_before']
    assert row['libc_svc_count_delta'] == 0 and row['libc_svc_after'] == row['libc_svc_before']
    assert row['main_svc_count_delta'] == 0 and row['main_svc_after'] == row['main_svc_before']


def damaged_evidence_rejected(data: dict) -> int:
    mutations = [
        (('claims', 'diagnostic_cleanup_body_executed'), False),
        (('claims', 'diagnostic_cleanup_unlock_executed'), False),
        (('input_provenance', 'Metasec_sha256'), '0' * 64),
        (('source_fingerprints', 'diagnostic_cleanup_return_verifier_sha256'), '0' * 64),
        (('case_result', 'cleanup_path'), []),
        (('case_result', 'body_stop', 'cleanup_returned'), False),
        (('case_result', 'body_stop', 'target_return_register'), 1),
        (('case_result', 'body_stop', 'object_after'), '00'),
        (('case_result', 'body_stop', 'mutex_before'), MUTEX_AFTER),
        (('case_result', 'body_stop', 'mutex_after'), MUTEX_BEFORE),
        (('case_result', 'body_stop', 'cleanup_events'), []),
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
        raise AssertionError(f'damaged diagnostic-cleanup-return evidence accepted: {path}')
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
            parser.error('refusing to overwrite frozen cleanup-return evidence')
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
        schema=SCHEMA, damaged_evidence_rejected=rejected,
        cleanup_path_length=len(row['cleanup_path']),
        mutex_before=row['body_stop']['mutex_before'],
        mutex_after=row['body_stop']['mutex_after'],
        cleanup_returned=row['body_stop']['cleanup_returned'],
        malloc_delta=row['allocator_delta']['malloc'],
        complete_standalone_signer_verified=False)))


if __name__ == '__main__':
    main()
