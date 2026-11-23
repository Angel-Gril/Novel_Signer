"""Continue diagnostic scope entry to the following cleanup target entry."""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from unicorn import arm64_const as arm

import verify_vm9_native_171_diagnostic_scope_entry_dynamic_20261121 as previous

EVIDENCE = previous.EVIDENCE.with_name(
    'vm9_native_171_diagnostic_cleanup_entry_dynamic_20261121.json')
SCHEMA = 'vm9-native-171-diagnostic-cleanup-entry-dynamic-20261121-v1'
VM_RESUME = previous.VM_RESUME
CALLSITE = 0x16AA48
WRAPPER = 0x288540
TARGET = 0x26C9D0
WRAPPER_PATH = (WRAPPER, WRAPPER + 4, WRAPPER + 8)
BLR_X8 = 0xD63F0100


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prior_evidence() -> dict:
    data = json.loads(previous.EVIDENCE.read_text(encoding='utf-8'))
    previous.validate(data)
    return data


def source_fingerprints() -> dict:
    return dict(
        diagnostic_cleanup_verifier_sha256=sha256(Path(__file__)),
        diagnostic_scope_verifier_sha256=sha256(Path(previous.__file__)),
        inherited_source_fingerprints=previous.source_fingerprints())


def _delta(before: dict, after: dict) -> dict:
    return {key: after.get(key, 0) - before.get(key, 0)
            for key in sorted(set(before) | set(after))}


class CleanupEntryScenario(previous.DiagnosticScenario):
    def __init__(self, control):
        super().__init__(control)
        self._next_call = None
        self._next_callback = None
        self._wrapper_path = []
        self._vm_pcs = []
        self._cleanup_object = None
        self._cleanup_stop = None

    def _stop_diagnostic_return(self, cpu, pc, state):
        assert self._diagnostic_target_entered
        assert self._diagnostic_path == [hex(offset)
                                         for offset in previous.TARGET_PATH]
        assert self._reg(cpu, 30) == self.image + VM_RESUME
        self._diagnostic_returned = True
        self._diagnostic_object_after = bytes(cpu.mem_read(
            int(self._diagnostic_descriptor['callback_object_address'], 16), 24))
        self._base_observe(cpu, pc, state)

    def _record_next_call(self, cpu):
        instruction = bytes(cpu.mem_read(cpu.reg_read(arm.UC_ARM64_REG_PC), 4))
        word = int.from_bytes(instruction, 'little')
        assert word == BLR_X8
        target = self._reg(cpu, 8)
        descriptor = self._reg(cpu, 0)
        assert target == self.image + WRAPPER
        assert any(a <= descriptor and descriptor + 16 <= b
                   for a, b, _ in cpu.mem_regions())
        self._next_call = dict(
            callsite_offset=hex(CALLSITE),
            instruction='blr x8',
            instruction_bytes=instruction.hex(),
            target=self._relative(target, self.image),
            descriptor_address=self._relative(descriptor, self.image),
            target_matches_expected_wrapper=True,
            descriptor_is_mapped=True)

    def _record_wrapper_entry(self, cpu):
        assert self._next_call is not None
        descriptor = self._reg(cpu, 0)
        raw = bytes(cpu.mem_read(descriptor, 16))
        target = int.from_bytes(raw[:8], 'little')
        callback_object = int.from_bytes(raw[8:], 'little')
        assert target == self.image + TARGET
        assert callback_object != 0
        self._next_callback = dict(
            wrapper_offset=hex(WRAPPER),
            descriptor_address=self._relative(descriptor, self.image),
            descriptor_sha256=hashlib.sha256(raw).hexdigest(),
            descriptor_first_word=self._relative(target, self.image),
            descriptor_second_word=self._relative(callback_object, self.image),
            descriptor_is_mapped=True,
            target_is_mapped=True,
            callback_object_address=hex(callback_object),
            target_matches_descriptor_first_word=True,
            callback_argument_matches_descriptor_second_word=True)
        self._cleanup_object = bytes(cpu.mem_read(callback_object, 24))
        self._wrapper_path = [hex(WRAPPER)]

    def _stop_cleanup_entry(self, cpu, pc, state):
        assert self._next_callback is not None
        assert self._wrapper_path == [hex(offset) for offset in WRAPPER_PATH]
        callback_object = int(self._next_callback['callback_object_address'], 16)
        assert self._reg(cpu, 0) == callback_object
        assert self._reg(cpu, 30) == self.image + VM_RESUME
        self._next_callback.update(
            target_entry_offset=hex(TARGET),
            target_argument=self._relative(self._reg(cpu, 0), self.image),
            target_return_offset=hex(self._reg(cpu, 30) - self.image),
            wrapper_instruction_path=self._wrapper_path,
            target_body_executed=False)
        self._cleanup_stop = dict(
            kind='diagnostic_cleanup_target_entry_before_body',
            stop_before=hex(TARGET),
            target_body_executed=False,
            object_sha256=hashlib.sha256(self._cleanup_object).hexdigest(),
            object_bytes=self._cleanup_object.hex())
        self._base_observe(cpu, pc, state)
        cpu.emu_stop()
        cpu.reg_write(
            arm.UC_ARM64_REG_PC,
            previous.previous.previous.module_prefix().digest.context.outer.oracle.STOP)

    def observe(self, cpu, pc, state):
        offset = pc - self.image
        if not self._diagnostic_returned:
            return super().observe(cpu, pc, state)
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
            return self._stop_cleanup_entry(cpu, pc, state)
        self._base_observe(cpu, pc, state)

    def finish(self, result, state, proof):
        assert self._diagnostic_returned and self._next_call is not None
        assert self._next_callback is not None and self._cleanup_stop is not None
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
            prior_diagnostic_callback_returned=True,
            vm_instruction_count=len(self._vm_pcs),
            vm_pc_prefix=self._vm_pcs[:16],
            vm_pc_suffix=self._vm_pcs[-16:],
            next_call=self._next_call,
            next_callback=self._next_callback,
            stop=self._cleanup_stop,
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
    prefix = previous.previous.previous.module_prefix()
    digest = prefix.digest

    def create(control):
        scenario = CleanupEntryScenario(control)
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
        diagnostic_cleanup_wrapper_resolved=True,
        diagnostic_cleanup_descriptor_verified=True,
        diagnostic_cleanup_target_entry_reached=True,
        diagnostic_cleanup_body_executed=False,
        diagnostic_object_unchanged_at_cleanup_entry=True,
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
    prefix = previous.previous.previous.module_prefix()
    prefix.digest.verify_images(path, libc)
    assert sha256(path) == parent['input_provenance']['Metasec_sha256']
    assert sha256(libc) == parent['input_provenance']['Bionic_sha256']
    rows = replay(path, libc)
    assert len(rows) == 1
    return dict(
        schema=SCHEMA,
        claims=claims_for(),
        input_provenance=dict(
            inherited_diagnostic_scope_evidence_sha256=sha256(previous.EVIDENCE),
            Metasec_sha256=sha256(path),
            Bionic_sha256=sha256(libc)),
        source_fingerprints=source_fingerprints(),
        case_result=rows[0])


def validate(data: dict) -> None:
    parent = prior_evidence()
    assert data['schema'] == SCHEMA
    assert data['claims'] == claims_for()
    assert data['input_provenance'] == dict(
        inherited_diagnostic_scope_evidence_sha256=sha256(previous.EVIDENCE),
        Metasec_sha256=parent['input_provenance']['Metasec_sha256'],
        Bionic_sha256=parent['input_provenance']['Bionic_sha256'])
    assert data['source_fingerprints'] == source_fingerprints()
    row = data['case_result']
    assert row['control'] == parent['case_result']['control']
    assert row['prior_diagnostic_callback_returned'] is True
    assert row['vm_instruction_count'] == 1168
    assert row['vm_pc_prefix'] == [
        '0x16aa50', '0x16aa54', '0x16aa58', '0x16aa5c',
        '0x16aa60', '0x16aa64', '0x16aa68', '0x16aa6c',
        '0x16aa70', '0x16aa74', '0x16aa78', '0x16aa7c',
        '0x16aa80', '0x16aa84', '0x16a9ac', '0x16a9b0']
    assert row['vm_pc_suffix'][-3:] == ['0x288544', '0x288548', '0x26c9d0']
    call = row['next_call']
    assert call['callsite_offset'] == hex(CALLSITE)
    assert call['instruction'] == 'blr x8'
    assert int.from_bytes(bytes.fromhex(call['instruction_bytes']), 'little') == BLR_X8
    assert call['target'] == {'space': 'main_image', 'offset': hex(WRAPPER)}
    callback = row['next_callback']
    assert callback['wrapper_offset'] == hex(WRAPPER)
    assert callback['descriptor_first_word'] == {'space': 'main_image', 'offset': hex(TARGET)}
    assert callback['descriptor_is_mapped'] is True
    assert callback['target_is_mapped'] is True
    assert callback['target_matches_descriptor_first_word'] is True
    assert callback['callback_argument_matches_descriptor_second_word'] is True
    assert callback['wrapper_instruction_path'] == [hex(offset) for offset in WRAPPER_PATH]
    assert len(callback['descriptor_sha256']) == 64
    assert callback['descriptor_sha256'] == 'a9c8a54d166a6f85ebb76d1e2379d54122730be28354de813df30506df4b0f5a'
    stop = row['stop']
    assert stop == dict(
        kind='diagnostic_cleanup_target_entry_before_body',
        stop_before=hex(TARGET), target_body_executed=False,
        object_sha256='16bf9cb3f46e0fb506034e2f9f92a93809f24c34ee181d7823697b9614f2007c',
        object_bytes='10d4611200000000000000000000000040916d1300000000')
    assert row['allocator_delta'] == {'flush': 0, 'free': 0, 'gc': 0, 'malloc': 0}
    assert row['service_delta'] == {key: 0 for key in sorted(row['service_counts_before'])}
    assert row['jni_call_count_delta'] == 0 and row['jni_calls_after'] == row['jni_calls_before']
    assert row['libc_svc_count_delta'] == 0 and row['libc_svc_after'] == row['libc_svc_before']
    assert row['main_svc_count_delta'] == 0 and row['main_svc_after'] == row['main_svc_before']


def damaged_evidence_rejected(data: dict) -> int:
    mutations = [
        (('claims', 'diagnostic_cleanup_target_entry_reached'), False),
        (('claims', 'diagnostic_cleanup_body_executed'), True),
        (('input_provenance', 'Metasec_sha256'), '0' * 64),
        (('source_fingerprints', 'diagnostic_cleanup_verifier_sha256'), '0' * 64),
        (('case_result', 'vm_instruction_count'), 0),
        (('case_result', 'next_call', 'instruction'), 'br x0'),
        (('case_result', 'next_call', 'target', 'offset'), '0xdeadbeef'),
        (('case_result', 'next_callback', 'descriptor_sha256'), '0' * 64),
        (('case_result', 'next_callback', 'wrapper_instruction_path'), []),
        (('case_result', 'next_callback', 'target_is_mapped'), False),
        (('case_result', 'stop', 'stop_before'), '0xdeadbeef'),
        (('case_result', 'stop', 'target_body_executed'), True),
        (('case_result', 'stop', 'object_sha256'), '0' * 64),
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
        raise AssertionError(f'damaged diagnostic-cleanup evidence accepted: {path}')
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
            parser.error('refusing to overwrite frozen diagnostic-cleanup evidence')
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
        vm_instruction_count=row['vm_instruction_count'],
        cleanup_target=row['next_callback']['descriptor_first_word'],
        cleanup_body_executed=row['stop']['target_body_executed'],
        malloc_delta=row['allocator_delta']['malloc'],
        callback_returned_before_body=True,
        complete_standalone_signer_verified=False)))


if __name__ == '__main__':
    main()
