"""Replay eight native VM callbacks after the paired shared-reader release."""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from unicorn import arm64_const as arm

import verify_vm9_native_171_shared_reader_release_dynamic_20261121 as previous

EVIDENCE = previous.EVIDENCE.with_name(
    'vm9_native_171_post_reader_callbacks_dynamic_20261122.json')
SCHEMA = 'vm9-native-171-post-reader-callbacks-dynamic-20261122-v1'
VM_RESUME = previous.VM_RESUME
CALLSITE = previous.CALLSITE
MAX_OBSERVATIONS = 400000
# wrapper, target, descriptor SHA-256 (32 observed bytes), call/return index,
# returned X0 and reader count. Indices include the final unexecuted VM boundary.
SPECS = (
    (0x2885E0, 0x32A444, '9f48084980355d73e54b54269f3f9e218df048196a4fc09a92751cfa759743fc', 762, 857, 0, 1),
    (0x288530, 0x26C858, 'adecd9288bf24e50024f57353ff82ead78f53fe580a5f8495a9b957a9d05b8dd', 1719, 2109, 0, 1),
    (0x288540, 0x26C9D0, 'e782c5c31933262cebdc5795c8d33713ffe81a8b83a2a14dec75dae2128b77bc', 3573, 3627, 0, 1),
    (0x2885E0, 0x32A4FC, '942d8e1d68aed213db9f069e6119bd06fa5cc702d2670dc03c2a32925909a58b', 4444, 4528, 0, 0),
    (0x288658, 0x257804, 'a790a159bebe90a46d4953d942cd746341c80f73504462e318aafd2b870043e1', 5435, 5865, 0, 0),
    (0x288670, 0x257880, '1d7fe70c05db6a0f93c67715c167a2db274a3b79c49192382f379755ff9e7b31', 6379, 6617, 0, 0),
    (0x2885D0, 0x248344, '686e7d660aff31b1de0de1e006cc42535bdb51d69dcd02b1d9d943cf1b6cbdd4', 7619, 7775, 0x136D82B0, 0),
    (0x288530, 0x26C858, 'd62609342cafe342fedb5548218ae91be6e8f10a291198571ea49340088f9d12', 8455, 8566, 0, 0),
)
WRAPPERS = {
    0x2885E0: '012040a9e00308aa20001fd6',
    0x288530: '088440a9020040f9e00308aa40001fd6',
    0x288540: '012040a9e00308aa20001fd6',
    0x288658: 'fe0f1ff8092040a9000840f920013fd6fe0741f8c0035fd6',
    0x288670: 'fe4fbfa9f30300aa080040a900013fd6601200b9fe4fc1a8c0035fd6',
    0x2885D0: '088440a9020040f9e00308aa40001fd6',
}
LEDGERS = ('service_counts', 'jni_calls', 'libc_svc', 'main_svc')


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def prior_evidence() -> dict:
    data = json.loads(previous.EVIDENCE.read_text(encoding='utf-8'))
    previous.validate(data)
    return data


def source_fingerprints() -> dict:
    return dict(post_reader_verifier_sha256=sha256(Path(__file__)),
                inherited_source_fingerprints=previous.source_fingerprints())


def provenance(parent: dict) -> dict:
    return dict(inherited_reader_release_evidence_sha256=sha256(previous.EVIDENCE),
        Metasec_sha256=parent['input_provenance']['Metasec_sha256'],
        Bionic_sha256=parent['input_provenance']['Bionic_sha256'])


class PostReaderScenario(previous.ReaderReleaseScenario):
    def __init__(self, control):
        super().__init__(control)
        self._post_active = False
        self._calls = []
        self._active_call = None
        self._post_count = 0
        self._post_trace = hashlib.sha256()
        self._post_code = {}
        self._post_first = []
        self._post_tail = []
        self._prefix_summary = None
        self._allocator_prefix = None
        self._call_sp = None
        self._call_registers = None
        self._descriptor_pointer = None
        self._words = None
        self._done = False
        self._late_jni_before = None
        self._java_dispatch_before = None

    def _stop_release_return(self, cpu, pc, state):
        receiver = int(self._release_callback['receiver_address'], 16)
        assert self._release_path == [hex(v) for v in previous.EXPECTED_PATH]
        assert self._reg(cpu, 30) == self.image + VM_RESUME
        assert self._reg(cpu, 0) == 0
        assert cpu.reg_read(arm.UC_ARM64_REG_SP) == self._release_sp
        assert [self._reg(cpu, n) for n in range(19, 30)] == self._release_saved_registers
        after = bytes(cpu.mem_read(receiver, previous.OBJECT_SIZE))
        expected = bytearray(self._release_object_before)
        expected[previous.COUNT_OFFSET:previous.COUNT_OFFSET + 4] = bytes(4)
        assert after == expected == self._before
        assert bytes(cpu.mem_read(receiver, 8)) == self._release_mutex_before
        assert self._release_events == [
            dict(helper_offset=hex(previous.LOCK), caller_offset='0x32a514', receiver_matches_descriptor=True),
            dict(helper_offset=hex(previous.UNLOCK), caller_offset=hex(VM_RESUME), receiver_matches_descriptor=True)]
        self._prefix_summary = dict(
            release_path_verified=True, stack_and_saved_registers_restored=True,
            acquire_receiver_restored=True,
            object_sha256=hashlib.sha256(after).hexdigest(), reader_count=0,
            mutex_hex=bytes(cpu.mem_read(receiver, 8)).hex())
        self._allocator_prefix = deepcopy(state['allocator_events_ref'])
        self._late_jni_before = deepcopy(self.late_jni_calls)
        self._java_dispatch_before = deepcopy(self.java_dispatch_calls)
        self._release_returned = True
        self._post_active = True
        self.observe(cpu, pc, state)

    def _start_call(self, cpu, pc, state):
        assert self._active_call is None and len(self._calls) < len(SPECS)
        wrapper, target, descriptor_hash, call_index, _, _, _ = SPECS[len(self._calls)]
        assert self._post_count == call_index
        assert bytes(cpu.mem_read(pc, 4)).hex() == '00013fd6'
        assert self._reg(cpu, 8) == self.image + wrapper
        self._descriptor_pointer = self._reg(cpu, 0)
        assert any(a <= self._descriptor_pointer and self._descriptor_pointer + 32 <= b
                   for a, b, _ in cpu.mem_regions())
        raw = bytes(cpu.mem_read(self._descriptor_pointer, 32))
        self._words = [int.from_bytes(raw[i:i+8], 'little') for i in range(0, 32, 8)]
        assert self._words[0] == self.image + target
        assert hashlib.sha256(raw).hexdigest() == descriptor_hash
        self._call_sp = cpu.reg_read(arm.UC_ARM64_REG_SP)
        self._call_registers = [self._reg(cpu, n) for n in range(19, 30)]
        self._active_call = dict(
            ordinal=len(self._calls), callsite_offset=hex(CALLSITE),
            call_instruction_bytes='00013fd6', wrapper_offset=hex(wrapper),
            target_offset=hex(target), call_observation_index=self._post_count,
            outer_bytecode=hex(int.from_bytes(cpu.mem_read(state['PC_slot'], 8), 'little')-self.image),
            descriptor_observed_size=32, descriptor_before_hex=raw.hex(),
            descriptor_before_sha256=hashlib.sha256(raw).hexdigest(),
            descriptor_words=[hex(word) for word in self._words],
            descriptor_mapped=True, wrapper_path=[], wrapper_code_verified=False,
            target_entered=False, argument_binding_verified=False,
            target_body_observations=0)

    def _target_entry(self, cpu):
        call = self._active_call
        wrapper = int(call['wrapper_offset'], 16)
        expected = {0: self._words[1]}
        if wrapper in (0x288530, 0x2885D0):
            expected[1] = self._words[2]
        elif wrapper == 0x288658:
            expected = {0: self._words[2], 8: self._words[1]}
        for n, value in expected.items():
            assert self._reg(cpu, n) == value
        return_offset = {0x288658: 0x288668, 0x288670: 0x288680}.get(wrapper, VM_RESUME)
        assert self._reg(cpu, 30) == self.image + return_offset
        call.update(target_entered=True, argument_binding_verified=True,
                    target_argument_registers={f'x{n}': hex(v) for n, v in expected.items()},
                    target_return_offset=hex(return_offset))

    def _return_call(self, cpu, pc):
        call = self._active_call
        wrapper, _, _, _, return_index, returned, readers = SPECS[len(self._calls)]
        assert call['target_entered'] and call['argument_binding_verified']
        assert self._post_count == return_index and self._reg(cpu, 0) == returned
        assert cpu.reg_read(arm.UC_ARM64_REG_SP) == self._call_sp
        assert [self._reg(cpu, n) for n in range(19, 30)] == self._call_registers
        after = bytes(cpu.mem_read(self._descriptor_pointer, 32))
        before = bytes.fromhex(call['descriptor_before_hex'])
        expected = bytearray(before)
        if wrapper == 0x288670:
            expected[16:20] = returned.to_bytes(4, 'little')
        assert after == expected
        assert call['wrapper_path'] == [hex(a) for a in range(wrapper, wrapper + len(bytes.fromhex(WRAPPERS[wrapper])), 4)]
        actual_readers = int.from_bytes(cpu.mem_read(self._receiver + previous.COUNT_OFFSET, 4), 'little')
        assert actual_readers == readers
        call.update(return_offset=hex(VM_RESUME), return_observation_index=self._post_count,
            returned_x0=hex(returned), reader_count=actual_readers,
            descriptor_after_hex=after.hex(), descriptor_after_sha256=hashlib.sha256(after).hexdigest(),
            descriptor_output_and_padding_verified=True,
            stack_pointer_restored=True, callee_saved_registers_restored=True,
            callback_returned=True)
        self._calls.append(call)
        self._active_call = None
        self._done = len(self._calls) == len(SPECS)

    def observe(self, cpu, pc, state):
        if not self._post_active:
            return super().observe(cpu, pc, state)
        offset = pc - self.image
        self._post_count += 1
        assert self._post_count < MAX_OBSERVATIONS
        raw = bytes(cpu.mem_read(pc, 4))
        self._post_trace.update(offset.to_bytes(8, 'little', signed=True) + raw)
        self._post_code[hex(offset)] = raw.hex()
        if len(self._post_first) < 16:
            self._post_first.append(hex(offset))
        self._post_tail = (self._post_tail + [hex(offset)])[-16:]
        if offset == CALLSITE:
            self._start_call(cpu, pc, state)
        if self._active_call is not None:
            call = self._active_call
            wrapper = int(call['wrapper_offset'], 16)
            if offset == wrapper:
                code = bytes(cpu.mem_read(pc, len(bytes.fromhex(WRAPPERS[wrapper]))))
                assert code.hex() == WRAPPERS[wrapper]
                call['wrapper_code_verified'] = True
            if wrapper <= offset < wrapper + len(bytes.fromhex(WRAPPERS[wrapper])):
                call['wrapper_path'].append(hex(offset))
            if offset == int(call['target_offset'], 16) and not call['target_entered']:
                self._target_entry(cpu)
            if call['target_entered']:
                call['target_body_observations'] += 1
            if offset == VM_RESUME and call['target_entered']:
                self._return_call(cpu, pc)
        self._base_observe(cpu, pc, state)
        if self._done:
            cpu.emu_stop()
            cpu.reg_write(arm.UC_ARM64_REG_PC,
                previous.callback_prefix.module_prefix().digest.context.outer.oracle.STOP)

    def finish(self, result, state, proof):
        assert self._done and self._active_call is None
        prefix = self._allocator_prefix
        events = result['allocator_events']
        assert events[:len(prefix)] == prefix
        new_events = events[len(prefix):]
        assert len(new_events) == 2 and all(event[0] == 'alloc' for event in new_events)
        assert self.late_jni_calls == self._late_jni_before
        assert self.java_dispatch_calls == self._java_dispatch_before
        parent = prior_evidence()['case_result']
        return dict(control=parent['control'], retained_release=self._prefix_summary,
            instruction_observations=self._post_count,
            instruction_trace_sha256=self._post_trace.hexdigest(),
            observed_code_sha256=digest(self._post_code),
            first_pc_offsets=self._post_first, tail_pc_offsets=self._post_tail,
            callbacks=self._calls,
            allocator_counts_before=parent['allocator_counts_after'],
            allocator_counts_after=result['actual_allocator_counts'],
            allocator_delta=previous._delta(parent['allocator_counts_after'], result['actual_allocator_counts']),
            retained_allocator_prefix_sha256=digest(prefix),
            new_allocator_events=new_events,
            new_allocator_events_sha256=digest(new_events),
            service_counts_before=parent['service_counts_after'], service_counts_after=result['explicit_service_counts'],
            jni_calls_before=parent['jni_calls_after'], jni_calls_after=proof['JNI_calls'],
            libc_svc_before=parent['libc_svc_after'], libc_svc_after=proof['libc_SVC_boundaries'],
            main_svc_before=parent['main_svc_after'], main_svc_after=proof['main_image_SVC_boundaries'],
            late_jni_calls_before=self._late_jni_before, late_jni_calls_after=self.late_jni_calls,
            java_dispatch_before=self._java_dispatch_before, java_dispatch_after=self.java_dispatch_calls,
            stop_boundary=dict(kind='eighth_post_reader_callback_return_before_vm_resume',
                stop_before=hex(VM_RESUME), next_vm_instruction_executed=False,
                final_scope_cleanup_pending=True))


def claims_for() -> dict:
    return dict(evidence_label='Sample verified', native_post_reader_callbacks_returned=8,
        callback_descriptors_and_argument_registers_verified=True,
        original_wrapper_code_verified=True,
        paired_reader_count_returns_to_zero=True,
        callback_SP_and_callee_saved_registers_restored=True,
        allocator_malloc_delta=2, service_JNI_SVC_ledgers_unchanged=True,
        next_vm_instruction_executed=False, final_scope_cleanup_verified=False,
        current_native_suffix_return_verified=False, complete_standalone_signer_verified=False,
        ordinary_Cronet_six_headers_verified=False, online_acceptance_verified=False,
        Android_execution=False, native_memory_used_as_python_model_input=False,
        physical_PAC_authentication_verified=False)


def run(path: Path, libc: Path) -> dict:
    parent = prior_evidence()
    p = previous.callback_prefix.module_prefix()
    p.digest.verify_images(path, libc)
    assert sha256(path) == parent['input_provenance']['Metasec_sha256']
    assert sha256(libc) == parent['input_provenance']['Bionic_sha256']
    def create(control):
        scenario = PostReaderScenario(control)
        scenario.path = path
        scenario.continue_to_svc = True
        return scenario
    rows = p.digest.context.replay(path, libc, case_controls=[p.CONTROL], _extension_factory=create,
        _request_profile=p.digest.previous.previous.name.previous.previous.PROFILE['name'],
        _handler_read_profile=p.digest.context.NULL_PAYLOAD_READ_PROFILE['name'])
    assert len(rows) == 1
    return dict(schema=SCHEMA, claims=claims_for(), input_provenance=provenance(parent),
        source_fingerprints=source_fingerprints(), case_result=rows[0])


def validate(data: dict) -> None:
    parent = prior_evidence()
    old = parent['case_result']
    assert data['schema'] == SCHEMA and data['claims'] == claims_for()
    assert data['input_provenance'] == provenance(parent)
    assert data['source_fingerprints'] == source_fingerprints()
    row = data['case_result']
    assert row['control'] == old['control']
    assert row['retained_release'] == dict(release_path_verified=True,
        stack_and_saved_registers_restored=True, acquire_receiver_restored=True,
        object_sha256=previous.READER_AFTER_SHA256, reader_count=0, mutex_hex='0000000000000000')
    assert row['instruction_observations'] == 8566 < MAX_OBSERVATIONS
    assert row['first_pc_offsets'][0] == hex(VM_RESUME)
    assert row['tail_pc_offsets'][-1] == hex(VM_RESUME)
    for key in ('instruction_trace_sha256', 'observed_code_sha256', 'retained_allocator_prefix_sha256'):
        assert len(row[key]) == 64 and len(bytes.fromhex(row[key])) == 32
    calls = row['callbacks']
    assert len(calls) == len(SPECS)
    for index, (call, spec) in enumerate(zip(calls, SPECS)):
        wrapper, target, expected_hash, call_index, return_index, returned, readers = spec
        assert call['ordinal'] == index
        assert call['callsite_offset'] == hex(CALLSITE)
        assert call['call_instruction_bytes'] == '00013fd6'
        assert call['wrapper_offset'] == hex(wrapper) and call['target_offset'] == hex(target)
        assert call['call_observation_index'] == call_index
        assert call['return_observation_index'] == return_index
        assert call['outer_bytecode'] == '0xfe2d0'
        before = bytes.fromhex(call['descriptor_before_hex'])
        after = bytes.fromhex(call['descriptor_after_hex'])
        assert call['descriptor_observed_size'] == len(before) == len(after) == 32
        assert call['descriptor_before_sha256'] == hashlib.sha256(before).hexdigest() == expected_hash
        assert call['descriptor_after_sha256'] == hashlib.sha256(after).hexdigest()
        words = [int.from_bytes(before[i:i+8], 'little') for i in range(0, 32, 8)]
        assert call['descriptor_words'] == [hex(word) for word in words]
        assert words[0] == old['control']['base'] + target
        expected_arguments = {'x0': hex(words[1])}
        if wrapper in (0x288530, 0x2885D0):
            expected_arguments['x1'] = hex(words[2])
        elif wrapper == 0x288658:
            expected_arguments = {'x0': hex(words[2]), 'x8': hex(words[1])}
        assert call['target_argument_registers'] == expected_arguments
        assert call['target_return_offset'] == hex({0x288658: 0x288668, 0x288670: 0x288680}.get(wrapper, VM_RESUME))
        expected_after = bytearray(before)
        if wrapper == 0x288670:
            expected_after[16:20] = returned.to_bytes(4, 'little')
        assert after == expected_after
        assert call['wrapper_path'] == [hex(a) for a in range(wrapper, wrapper+len(bytes.fromhex(WRAPPERS[wrapper])), 4)]
        assert call['return_offset'] == hex(VM_RESUME) and call['returned_x0'] == hex(returned)
        assert call['reader_count'] == readers
        assert type(call['target_body_observations']) is int and call['target_body_observations'] > 0
        for key in ('descriptor_mapped', 'wrapper_code_verified', 'target_entered',
                    'argument_binding_verified', 'descriptor_output_and_padding_verified',
                    'stack_pointer_restored', 'callee_saved_registers_restored', 'callback_returned'):
            assert call[key] is True, (index, key)
    assert row['allocator_counts_before'] == old['allocator_counts_after']
    expected_counts = dict(row['allocator_counts_before'])
    expected_counts['malloc'] += 2
    assert row['allocator_counts_after'] == expected_counts
    assert row['allocator_delta'] == dict(flush=0, free=0, gc=0, malloc=2)
    assert row['allocator_delta'] == previous._delta(row['allocator_counts_before'], row['allocator_counts_after'])
    events = row['new_allocator_events']
    assert len(events) == 2 and all(len(e) == 4 and e[0] == 'alloc' and type(e[1]) is int and e[1] > 0 for e in events)
    assert row['new_allocator_events_sha256'] == digest(events)
    for stem in LEDGERS:
        assert row[stem+'_before'] == old[stem+'_after'] == row[stem+'_after'], stem
    assert len(row['late_jni_calls_before']) == 2
    assert row['late_jni_calls_before'] == row['late_jni_calls_after']
    assert row['java_dispatch_before'] == row['java_dispatch_after'] == []
    assert row['stop_boundary'] == dict(kind='eighth_post_reader_callback_return_before_vm_resume',
        stop_before=hex(VM_RESUME), next_vm_instruction_executed=False, final_scope_cleanup_pending=True)


def damaged_evidence_rejected(data: dict) -> int:
    mutations = [
        (('claims', 'complete_standalone_signer_verified'), True),
        (('claims', 'final_scope_cleanup_verified'), True),
        (('claims', 'native_post_reader_callbacks_returned'), 7),
        (('input_provenance', 'Metasec_sha256'), '0'*64),
        (('source_fingerprints', 'post_reader_verifier_sha256'), '0'*64),
        (('case_result', 'retained_release', 'reader_count'), 1),
        (('case_result', 'instruction_observations'), 0),
        (('case_result', 'allocator_counts_after', 'malloc'), 558),
        (('case_result', 'new_allocator_events'), []),
        (('case_result', 'service_counts_after', 'syscall_169'), 2),
        (('case_result', 'jni_calls_after'), []),
        (('case_result', 'libc_svc_after'), []),
        (('case_result', 'main_svc_after'), []),
        (('case_result', 'late_jni_calls_after'), []),
        (('case_result', 'java_dispatch_after'), [{}]),
        (('case_result', 'stop_boundary', 'final_scope_cleanup_pending'), False),
        (('case_result', 'stop_boundary', 'next_vm_instruction_executed'), True),
    ]
    for i in range(len(SPECS)):
        for key, value in (('target_offset', '0x0'), ('wrapper_offset', '0x0'),
            ('descriptor_before_sha256', '0'*64), ('descriptor_words', []),
            ('target_argument_registers', {}), ('wrapper_path', []),
            ('return_observation_index', 0), ('returned_x0', '0xdeadbeef'),
            ('reader_count', -1), ('target_entered', False),
            ('callee_saved_registers_restored', False), ('callback_returned', False)):
            mutations.append((('case_result', 'callbacks', i, key), value))
    for path, value in mutations:
        bad = deepcopy(data)
        obj = bad
        for key in path[:-1]:
            obj = obj[key]
        obj[path[-1]] = value
        try:
            validate(bad)
        except (AssertionError, KeyError, TypeError, ValueError):
            continue
        raise AssertionError(f'damaged post-reader evidence accepted: {path}')
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
            parser.error('refusing to overwrite frozen post-reader evidence')
        data = run(args.elf, args.libc)
        validate(data)
        rejected = damaged_evidence_rejected(data)
        with EVIDENCE.open('x', encoding='utf-8', newline='\n') as output:
            output.write(json.dumps(data, ensure_ascii=False, indent=2)+'\n')
    else:
        data = json.loads(EVIDENCE.read_text(encoding='utf-8'))
        validate(data)
        rejected = damaged_evidence_rejected(data)
        if args.replay:
            assert run(args.elf, args.libc) == data, 'fresh post-reader replay differs'
    row = data['case_result']
    print(json.dumps(dict(schema=SCHEMA, damaged_evidence_rejected=rejected,
        returned_callbacks=len(row['callbacks']), instruction_observations=row['instruction_observations'],
        allocator_delta=row['allocator_delta'], final_scope_cleanup_pending=True,
        current_native_suffix_return_verified=False, complete_standalone_signer_verified=False)))


if __name__ == '__main__':
    main()
