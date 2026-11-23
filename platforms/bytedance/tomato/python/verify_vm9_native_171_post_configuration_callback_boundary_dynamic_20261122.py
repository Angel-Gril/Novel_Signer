"""Replay configuration cleanup to the next unresolved callback, before BLR."""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from unicorn import arm64_const as arm

import verify_vm9_native_171_post_scope_configuration_dynamic_20261122 as previous
import verify_vm9_native_171_post_reader_callbacks_dynamic_20261122 as callbacks
import verify_vm9_native_171_shared_reader_release_dynamic_20261121 as reader

SPECS = (
    (0x2884cc, 0x2484b8, '01ab59204811b97d85fc7d181c287ed428611569ae6c748701694518db32744c', 681, 834, 0x108bdc, 0x136c2680, 0),
    (0x2885d0, 0x248344, '383a7d1f9a9137b0cf1b7dc921fd125adec0e32fcdee893e975a208732240f74', 1896, 2052, 0x108d58, 0x136d3fc0, 0),
    (0x28874c, 0x256a18, 'e328fb2871f0f1241aea1c9d3c6769955eae5f5160f144e8d2a1bec569f30d77', 2666, 3775, 0x108d78, 0x0, 0),
    (0x2884cc, 0x2484b8, '01ab59204811b97d85fc7d181c287ed428611569ae6c748701694518db32744c', 4448, 4601, 0x108d9c, 0x136c2680, 0),
    (0x2885d0, 0x248344, 'c3a02b30c6dda7f1d828ca3653bab8e007c5c670e78271ffb68f5bc054be02fe', 5913, 6069, 0x108f28, 0x136d3fc0, 0),
    (0x28874c, 0x256a18, 'e328fb2871f0f1241aea1c9d3c6769955eae5f5160f144e8d2a1bec569f30d77', 6683, 7792, 0x108f48, 0x0, 0),
    (0x2884cc, 0x2484b8, '01ab59204811b97d85fc7d181c287ed428611569ae6c748701694518db32744c', 8465, 8618, 0x108f6c, 0x136c2680, 0),
    (0x2885d0, 0x248344, '720f7b96ea9e037ad6523357fc32aba9c02c48acbca4f3b63228943da602f67e', 9680, 9836, 0x1090e8, 0x136d3fc0, 0),
    (0x28874c, 0x256a18, 'e328fb2871f0f1241aea1c9d3c6769955eae5f5160f144e8d2a1bec569f30d77', 10450, 11559, 0x109108, 0x0, 0),
    (0x2884cc, 0x2484b8, '01ab59204811b97d85fc7d181c287ed428611569ae6c748701694518db32744c', 12232, 12385, 0x10912c, 0x136c2680, 0),
    (0x28876c, 0x26cc64, '886967413520f1bebe0b45499784d0359b249fcad049be1f94307e9ec1f2a64d', 12811, 12866, 0x109144, 0x6ac0dab8, 0),
    (0x2885d0, 0x248344, '287662b1359755155a02bdfedc50fb5659585e1630e1da8f7abc3b1241d332a2', 13982, 14138, 0x1092c8, 0x136d3fc0, 0),
    (0x28874c, 0x256a18, 'e328fb2871f0f1241aea1c9d3c6769955eae5f5160f144e8d2a1bec569f30d77', 14752, 15277, 0x1092e8, 0xa985f, 0),
    (0x2884cc, 0x2484b8, '01ab59204811b97d85fc7d181c287ed428611569ae6c748701694518db32744c', 16031, 16184, 0x109310, 0x136c2680, 0),
    (0x2885e0, 0x32a444, '56837487c9ed72817afb08119f29b73261c9185963c59b9737f78077d99035c5', 16893, 16988, 0x109338, 0x0, 1),
    (0x288530, 0x26c858, '882a10df790882ecc009381c523423caa45ae872fc11cb7f01bb108180f2786c', 17850, 18240, 0x109364, 0x0, 1),
    (0x288540, 0x26c9d0, 'e782c5c31933262cebdc5795c8d33713ffe81a8b83a2a14dec75dae2128b77bc', 19258, 19312, 0x10939c, 0x0, 1),
    (0x2885e0, 0x32a4fc, '606cf77bdd214ccf1d732327b901ee4de07d837e7f1b8833893694f71b823311', 20129, 20213, 0x1093c8, 0x0, 0),
    (0x288530, 0x26c858, '882a10df790882ecc009381c523423caa45ae872fc11cb7f01bb108180f2786c', 20957, 21068, 0x109410, 0x0, 0),
    (0x288540, 0x26c9d0, 'e782c5c31933262cebdc5795c8d33713ffe81a8b83a2a14dec75dae2128b77bc', 22067, 22121, 0x109488, 0x0, 0),
    (0x2885e0, 0x32a444, '56837487c9ed72817afb08119f29b73261c9185963c59b9737f78077d99035c5', 22977, 23072, 0x1094b8, 0x0, 1),
    (0x288530, 0x26c858, '882a10df790882ecc009381c523423caa45ae872fc11cb7f01bb108180f2786c', 24009, 24120, 0x1094e8, 0x0, 1),
    (0x288540, 0x26c9d0, 'e782c5c31933262cebdc5795c8d33713ffe81a8b83a2a14dec75dae2128b77bc', 25084, 25138, 0x10951c, 0x0, 1),
    (0x2885e0, 0x32a4fc, '606cf77bdd214ccf1d732327b901ee4de07d837e7f1b8833893694f71b823311', 25955, 26039, 0x109548, 0x0, 0),
    (0x288530, 0x26c858, '882a10df790882ecc009381c523423caa45ae872fc11cb7f01bb108180f2786c', 26991, 27102, 0x1095ac, 0x0, 0),
    (0x288540, 0x26c9d0, 'e782c5c31933262cebdc5795c8d33713ffe81a8b83a2a14dec75dae2128b77bc', 28023, 28077, 0x109620, 0x0, 0),
)

EVIDENCE = previous.EVIDENCE.with_name('vm9_native_171_post_configuration_callback_boundary_dynamic_20261122.json')
SCHEMA = 'vm9-native-171-post-configuration-callback-boundary-dynamic-20261122-v1'
VM_RESUME, CALLSITE = previous.VM_RESUME, previous.CALLSITE
MAX_OBSERVATIONS = 400000
WRAPPERS = {key: value for key, value in (previous.WRAPPERS | callbacks.WRAPPERS).items()
            if key in (0x2884CC, 0x2885D0, 0x28874C, 0x2885E0, 0x288530, 0x288540)}
WRAPPERS[0x28876C] = 'fe4fbfa9080040f9f30300aa00013fd6600600f9fe4fc1a8c0035fd6'
NULL_WRAPPER = 0x28863C
NULL_CALL = 0x288648
NULL_CODE = 'fe4fbfa9080040f9f30300aa00013fd6600a00b9fe4fc1a8c0035fd6'
NULL_DESCRIPTOR_HASH = '7b067e0929ca22f7eea22b18de3c974b2d8598661a59e298fea3f1c88ae23eff'
EVENTS_SHA256 = '527b68da1fd3e1c20788139d936f40e10a690301acec7379d000d33ea7dc20ce'
sha256, raw_hash, digest = previous.sha256, previous.raw_hash, callbacks.digest


def prior_evidence():
    data = json.loads(previous.EVIDENCE.read_text(encoding='utf-8'))
    previous.validate(data)
    return data


def source_fingerprints():
    return dict(callback_boundary_verifier_sha256=sha256(Path(__file__)),
                inherited_source_fingerprints=previous.source_fingerprints())


def provenance(parent):
    return dict(inherited_configuration_evidence_sha256=sha256(previous.EVIDENCE),
                Metasec_sha256=parent['input_provenance']['Metasec_sha256'],
                Bionic_sha256=parent['input_provenance']['Bionic_sha256'])


def arguments_for(wrapper, words, descriptor):
    if wrapper == 0x28876C:
        return {'x0': hex(descriptor)}
    if wrapper == 0x288530:
        return {'x0': hex(words[1]), 'x1': hex(words[2])}
    return previous.arguments_for(wrapper, words, descriptor)


def output_for(wrapper, raw, returned):
    if wrapper == 0x28876C:
        out = bytearray(raw)
        out[8:16] = returned.to_bytes(8, 'little')
        return bytes(out)
    return previous.expected_descriptor_after(wrapper, raw, returned)


def target_return(wrapper):
    return 0x28877C if wrapper == 0x28876C else previous.TARGET_RETURNS.get(wrapper, VM_RESUME)


def providers():
    return dict(inherited=previous.providers(), new_providers=[],
                clock='inherited explicit clock_gettime provider: status=0, seconds=1791023800, nanoseconds=500000000',
                unresolved_callback='stop before BLR; no NULL replacement or invented callback',
                maximum_instruction_observations=MAX_OBSERVATIONS)


def claims_for():
    return dict(evidence_label='Sample verified', returned_callbacks=26,
                descriptor_arguments_outputs_and_padding_verified=True,
                returned_callback_SP_and_X19_X29_restored=True,
                two_shared_reader_pairs_verified=True, native_time_conversion_verified=True,
                clock_provider_delta=1, malloc_delta=5, free_delta=5,
                JNI_Java_dispatch_and_SVC_ledgers_unchanged=True,
                next_callback_pointer_is_null=True, next_indirect_call_executed=False,
                next_callback_return_verified=False, real_Android_callback_provenance_verified=False,
                current_native_suffix_return_verified=False, complete_standalone_signer_verified=False,
                ordinary_Cronet_six_headers_verified=False, online_acceptance_verified=False,
                Android_execution=False, native_memory_used_as_python_model_input=False,
                physical_PAC_authentication_verified=False)


class CallbackBoundaryScenario(previous.ConfigurationScenario):
    def __init__(self, control):
        super().__init__(control)
        self._tail_active = False
        self._tail_state = None
        self._tail_parent = None
        self._tail_events_before = None
        self._tail_count = 0
        self._tail_trace = hashlib.sha256()
        self._tail_code = {}
        self._tail_first, self._tail_pcs = [], []
        self._tail_calls, self._tail_call = [], None
        self._pending, self._clock = None, None
        self._tail_done = False

    def _track_pc(self, cpu, pc):
        off = pc-self.image
        self._tail_count += 1
        assert self._tail_count < MAX_OBSERVATIONS
        raw = bytes(cpu.mem_read(pc, 4))
        self._tail_trace.update(off.to_bytes(8, 'little', signed=True)+raw)
        self._tail_code[hex(off)] = raw.hex()
        if len(self._tail_first) < 16:
            self._tail_first.append(hex(off))
        self._tail_pcs = (self._tail_pcs+[hex(off)])[-16:]

    def _return_config_call(self, cpu):
        super()._return_config_call(cpu)
        if not self._config_done:
            return
        old = prior_evidence()['case_result']
        assert self._config_calls == old['callbacks']
        assert self._config_count == old['instruction_observations']
        assert self._config_trace.hexdigest() == old['instruction_trace_sha256']
        assert digest(self._config_code) == old['observed_code_sha256']
        assert self._config_first == old['first_pc_offsets'] and self._config_tail == old['tail_pc_offsets']
        events = self._tail_state['allocator_events_ref']
        assert events[:len(self._config_events_before)] == self._config_events_before
        assert events[len(self._config_events_before):] == old['new_allocator_events']
        assert digest(events[len(self._config_events_before):]) == old['new_allocator_events_sha256']
        assert self.late_jni_calls == old['late_jni_calls_after']
        assert self.java_dispatch_calls == old['java_dispatch_after']
        self._tail_parent = dict(callbacks_verified=32,
            instruction_observations=self._config_count,
            instruction_trace_sha256=self._config_trace.hexdigest(),
            observed_code_sha256=digest(self._config_code),
            new_allocator_events_sha256=old['new_allocator_events_sha256'])
        self._tail_events_before = deepcopy(events)
        self._config_done = False
        self._tail_active = True
        self._track_pc(cpu, self.image+VM_RESUME)

    def _start_tail_call(self, cpu, pc):
        assert self._tail_call is None and self._pending is None
        assert bytes(cpu.mem_read(pc, 4)).hex() == '00013fd6'
        self._descriptor = self._reg(cpu, 0)
        assert any(a <= self._descriptor and self._descriptor+32 <= b for a, b, _ in cpu.mem_regions())
        raw = bytes(cpu.mem_read(self._descriptor, 32))
        self._words = [int.from_bytes(raw[i:i+8], 'little') for i in range(0, 32, 8)]
        self._sp = cpu.reg_read(arm.UC_ARM64_REG_SP)
        self._saved = [self._reg(cpu, n) for n in range(19, 30)]
        cursor = self._u(cpu, self._reg(cpu, 19))-self.image
        if len(self._tail_calls) == len(SPECS):
            assert self._tail_count == 28557 and cursor == 0x10963C
            assert self._reg(cpu, 8) == self.image+NULL_WRAPPER
            assert raw_hash(raw) == NULL_DESCRIPTOR_HASH and self._words[0] == 0
            self._pending = dict(callsite_offset=hex(CALLSITE), call_instruction_bytes='00013fd6',
                call_observation_index=self._tail_count, VM_cursor_offset=hex(cursor),
                wrapper_offset=hex(NULL_WRAPPER), wrapper_code_hex=NULL_CODE, wrapper_path=[],
                descriptor_address=hex(self._descriptor), descriptor_before_hex=raw.hex(),
                descriptor_before_sha256=raw_hash(raw), stack_pointer_at_vm_call=hex(self._sp),
                saved_caller_x19=hex(self._saved[0]))
            return
        wrapper, target, expected_hash, start, _, expected_cursor, _, _ = SPECS[len(self._tail_calls)]
        assert self._tail_count == start and cursor == expected_cursor
        assert self._reg(cpu, 8) == self.image+wrapper and self._words[0] == self.image+target
        assert raw_hash(raw) == expected_hash
        self._tail_call = dict(ordinal=len(self._tail_calls), callsite_offset=hex(CALLSITE),
            call_instruction_bytes='00013fd6', call_observation_index=start,
            VM_cursor_offset=hex(cursor), wrapper_offset=hex(wrapper), target_offset=hex(target),
            descriptor_address=hex(self._descriptor), descriptor_before_hex=raw.hex(),
            descriptor_before_sha256=raw_hash(raw), descriptor_words=[hex(w) for w in self._words],
            wrapper_path=[], wrapper_code_verified=False, target_entered=False, target_observations=0)
        if target in (0x32A444, 0x32A4FC):
            assert self._words[1] == self._receiver
            self._reader_before = bytes(cpu.mem_read(self._receiver, 0x90))
            self._tail_call['reader_object_before_hex'] = self._reader_before.hex()

    def _return_tail_call(self, cpu):
        call = self._tail_call
        wrapper, target, _, _, end, _, returned, readers = SPECS[len(self._tail_calls)]
        assert call['target_entered'] and self._tail_count == end and self._reg(cpu, 0) == returned
        assert cpu.reg_read(arm.UC_ARM64_REG_SP) == self._sp
        assert [self._reg(cpu, n) for n in range(19, 30)] == self._saved
        assert call['wrapper_path'] == [hex(a) for a in range(wrapper, wrapper+len(bytes.fromhex(WRAPPERS[wrapper])), 4)]
        after = bytes(cpu.mem_read(self._descriptor, 32))
        assert after == output_for(wrapper, bytes.fromhex(call['descriptor_before_hex']), returned)
        assert self._u(cpu, self._receiver+0x88, 4) == readers
        if target in (0x32A444, 0x32A4FC):
            expected = bytearray(self._reader_before)
            assert int.from_bytes(expected[0x88:0x8C], 'little') == 1-readers
            expected[0x88:0x8C] = readers.to_bytes(4, 'little')
            actual = bytes(cpu.mem_read(self._receiver, 0x90))
            assert actual == expected
            call.update(reader_object_after_hex=actual.hex(), reader_other_bytes_preserved=True)
        call.update(return_observation_index=end, returned_x0=hex(returned), reader_count=readers,
            return_offset=hex(VM_RESUME), descriptor_after_hex=after.hex(),
            descriptor_after_sha256=raw_hash(after), descriptor_output_and_padding_verified=True,
            stack_pointer_restored=True, callee_saved_registers_restored=True, callback_returned=True)
        self._tail_calls.append(call)
        self._tail_call = None

    def _observe_clock(self, cpu, off):
        if off == 0x348450:
            assert self._clock is None and self._reg(cpu, 0) == 0
            assert self._reg(cpu, 30) == self.image+0x329430
            assert self._reg(cpu, 1) == cpu.reg_read(arm.UC_ARM64_REG_SP)+8
            self._clock_address = self._reg(cpu, 1)
            self._clock = dict(import_offset=hex(off), clock_id=0,
                caller_return_offset='0x329430', provider='inherited explicit clock_gettime',
                output_address=hex(self._clock_address))
        elif off == 0x329430:
            assert self._clock is not None and self._reg(cpu, 0) == 0
            raw = bytes(cpu.mem_read(self._clock_address, 16))
            assert raw == (1791023800).to_bytes(8, 'little')+(500000000).to_bytes(8, 'little')
            self._clock.update(status=0, timespec_hex=raw.hex(), seconds=1791023800, nanoseconds=500000000)
        for offset, name, value in ((0x329480, 'native_microseconds', 1791023800500000),
                                    (0x29196C, 'native_milliseconds', 1791023800500),
                                    (0x26CC78, 'native_seconds', 1791023800)):
            if off == offset:
                assert self._clock is not None and self._reg(cpu, 0) == value
                self._clock[name] = value

    def _observe_pending(self, cpu, pc):
        off = pc-self.image
        if off == NULL_WRAPPER:
            assert bytes(cpu.mem_read(pc, len(bytes.fromhex(NULL_CODE)))).hex() == NULL_CODE
        if NULL_WRAPPER <= off <= NULL_CALL:
            self._pending['wrapper_path'].append(hex(off))
        if off != NULL_CALL:
            return
        assert self._tail_count == 28561
        assert self._pending['wrapper_path'] == [hex(a) for a in range(NULL_WRAPPER, NULL_CALL+4, 4)]
        assert self._reg(cpu, 0) == self._reg(cpu, 19) == self._descriptor
        assert self._reg(cpu, 8) == 0 and self._reg(cpu, 30) == self.image+VM_RESUME
        assert cpu.reg_read(arm.UC_ARM64_REG_SP) == self._sp-16
        assert self._u(cpu, self._sp-16) == self.image+VM_RESUME
        assert self._u(cpu, self._sp-8) == self._saved[0]
        after = bytes(cpu.mem_read(self._descriptor, 32))
        assert after.hex() == self._pending['descriptor_before_hex']
        self._pending.update(stop_observation_index=self._tail_count, stop_before=hex(NULL_CALL),
            instruction_bytes=bytes(cpu.mem_read(pc, 4)).hex(),
            function_pointer='0x0', object_first_word='0x0', x0_matches_descriptor=True,
            x19_matches_descriptor=True, wrapper_frame_size=16, saved_caller_frame_verified=True,
            stack_pointer_at_stop=hex(self._sp-16), link_register_offset=hex(VM_RESUME),
            descriptor_after_hex=after.hex(), descriptor_preserved=True,
            result_store_offset='0x28864c', indirect_call_executed=False,
            callback_target_executed=False, result_store_executed=False, callback_returned=False)
        self._tail_done = True

    def observe(self, cpu, pc, state):
        self._tail_state = state
        if not self._tail_active:
            return super().observe(cpu, pc, state)
        off = pc-self.image
        self._track_pc(cpu, pc)
        if off == CALLSITE:
            self._start_tail_call(cpu, pc)
        call = self._tail_call
        if call is not None:
            wrapper, target = int(call['wrapper_offset'], 16), int(call['target_offset'], 16)
            if off == wrapper:
                assert bytes(cpu.mem_read(pc, len(bytes.fromhex(WRAPPERS[wrapper])))).hex() == WRAPPERS[wrapper]
                call['wrapper_code_verified'] = True
            if wrapper <= off < wrapper+len(bytes.fromhex(WRAPPERS[wrapper])):
                call['wrapper_path'].append(hex(off))
            if off == target and not call['target_entered']:
                args = arguments_for(wrapper, self._words, self._descriptor)
                assert all(self._reg(cpu, int(reg[1:])) == int(value, 16) for reg, value in args.items())
                assert self._reg(cpu, 30) == self.image+target_return(wrapper)
                call.update(target_entered=True, target_arguments=args, argument_binding_verified=True,
                            target_return_offset=hex(target_return(wrapper)))
            if call['target_entered']:
                call['target_observations'] += 1
                if target == 0x26CC64:
                    self._observe_clock(cpu, off)
                if off == VM_RESUME:
                    self._return_tail_call(cpu)
        if self._pending is not None:
            self._observe_pending(cpu, pc)
        # The inherited observer owns the stop-before-NULL-BLR policy.
        self._base_observe(cpu, pc, state)

    def finish(self, result, state, proof):
        assert self._tail_done and self._tail_call is None and len(self._tail_calls) == 26
        old = prior_evidence()['case_result']
        assert result['allocator_events'][:len(self._tail_events_before)] == self._tail_events_before
        added = result['allocator_events'][len(self._tail_events_before):]
        assert digest(added) == EVENTS_SHA256
        boundary = self.continuation_boundary
        assert boundary['stop_before'] == hex(NULL_CALL) and boundary['function_pointer_is_null']
        assert boundary['callback_target_executed'] is False
        return dict(control=old['control'], retained_prefix=self._tail_parent,
            instruction_observations=self._tail_count, instruction_trace_sha256=self._tail_trace.hexdigest(),
            observed_code_sha256=digest(self._tail_code), first_pc_offsets=self._tail_first,
            tail_pc_offsets=self._tail_pcs, callbacks=self._tail_calls, pending_callback=self._pending,
            inherited_stop_boundary=boundary, clock=self._clock,
            allocator_counts_before=old['allocator_counts_after'], allocator_counts_after=result['actual_allocator_counts'],
            allocator_delta=reader._delta(old['allocator_counts_after'], result['actual_allocator_counts']),
            new_allocator_events=added, new_allocator_events_sha256=digest(added),
            service_counts_before=old['service_counts_after'], service_counts_after=result['explicit_service_counts'],
            service_delta=reader._delta(old['service_counts_after'], result['explicit_service_counts']),
            jni_calls_before=old['jni_calls_after'], jni_calls_after=proof['JNI_calls'],
            libc_svc_before=old['libc_svc_after'], libc_svc_after=proof['libc_SVC_boundaries'],
            main_svc_before=old['main_svc_after'], main_svc_after=proof['main_image_SVC_boundaries'],
            late_jni_calls_before=old['late_jni_calls_after'], late_jni_calls_after=self.late_jni_calls,
            java_dispatch_before=old['java_dispatch_after'], java_dispatch_after=self.java_dispatch_calls)


def validate_call(call, spec, ordinal, base):
    wrapper, target, expected_hash, start, end, cursor, returned, readers = spec
    assert call['ordinal'] == ordinal and call['callsite_offset'] == hex(CALLSITE)
    assert call['call_instruction_bytes'] == '00013fd6'
    assert call['wrapper_offset'] == hex(wrapper) and call['target_offset'] == hex(target)
    assert call['call_observation_index'] == start and call['return_observation_index'] == end
    assert call['VM_cursor_offset'] == hex(cursor) and call['returned_x0'] == hex(returned)
    raw, after = bytes.fromhex(call['descriptor_before_hex']), bytes.fromhex(call['descriptor_after_hex'])
    assert len(raw) == len(after) == 32 and raw_hash(raw) == call['descriptor_before_sha256'] == expected_hash
    assert after == output_for(wrapper, raw, returned) and raw_hash(after) == call['descriptor_after_sha256']
    words = [int.from_bytes(raw[j:j+8], 'little') for j in range(0, 32, 8)]
    assert words[0] == base+target and call['descriptor_words'] == [hex(w) for w in words]
    assert call['target_arguments'] == arguments_for(wrapper, words, int(call['descriptor_address'], 16))
    assert call['target_return_offset'] == hex(target_return(wrapper))
    assert call['wrapper_path'] == [hex(a) for a in range(wrapper, wrapper+len(bytes.fromhex(WRAPPERS[wrapper])), 4)]
    assert call['reader_count'] == readers and call['return_offset'] == hex(VM_RESUME)
    assert type(call['target_observations']) is int and call['target_observations'] > 0
    for key in ('wrapper_code_verified', 'target_entered', 'argument_binding_verified',
                'descriptor_output_and_padding_verified', 'stack_pointer_restored',
                'callee_saved_registers_restored', 'callback_returned'):
        assert call[key] is True
    if target in (0x32A444, 0x32A4FC):
        before = bytearray.fromhex(call['reader_object_before_hex'])
        assert len(before) == 0x90 and int.from_bytes(before[0x88:0x8C], 'little') == 1-readers
        before[0x88:0x8C] = readers.to_bytes(4, 'little')
        assert bytes(before).hex() == call['reader_object_after_hex']
        assert call['reader_other_bytes_preserved'] is True


def validate(data):
    parent = prior_evidence()
    old = parent['case_result']
    assert data['schema'] == SCHEMA and data['claims'] == claims_for() and data['providers'] == providers()
    assert data['input_provenance'] == provenance(parent) and data['source_fingerprints'] == source_fingerprints()
    row = data['case_result']
    assert data['case_result_sha256'] == digest(row)
    assert row['control'] == old['control']
    assert row['retained_prefix'] == dict(callbacks_verified=32,
        instruction_observations=old['instruction_observations'],
        instruction_trace_sha256=old['instruction_trace_sha256'], observed_code_sha256=old['observed_code_sha256'],
        new_allocator_events_sha256=old['new_allocator_events_sha256'])
    assert row['instruction_observations'] == 28561 < MAX_OBSERVATIONS
    assert row['first_pc_offsets'][0] == hex(VM_RESUME) and row['tail_pc_offsets'][-1] == hex(NULL_CALL)
    for key in ('instruction_trace_sha256', 'observed_code_sha256'):
        assert len(row[key]) == 64 and len(bytes.fromhex(row[key])) == 32
    assert len(row['callbacks']) == len(SPECS) == 26
    for i, (call, spec) in enumerate(zip(row['callbacks'], SPECS)):
        validate_call(call, spec, i, old['control']['base'])
    assert row['new_allocator_events_sha256'] == digest(row['new_allocator_events']) == EVENTS_SHA256
    assert [e[1] for e in row['new_allocator_events'] if e[0] == 'alloc'] == [33, 33, 33, 33, 48]
    assert len([e for e in row['new_allocator_events'] if e[0] == 'free']) == 5
    for label, delta in (('allocator', {'malloc': 5, 'free': 5}), ('service', {'clock': 1})):
        before, after = row[f'{label}_counts_before'], row[f'{label}_counts_after']
        assert before == old[f'{label}_counts_after']
        actual_delta = reader._delta(before, after)
        assert row[f'{label}_delta'] == actual_delta
        assert {k: v for k, v in actual_delta.items() if v} == delta
    for key in ('jni_calls', 'libc_svc', 'main_svc', 'late_jni_calls', 'java_dispatch'):
        assert row[key+'_before'] == row[key+'_after'] == old[key+'_after']
    clock = row['clock']
    assert clock['import_offset'] == '0x348450' and clock['clock_id'] == clock['status'] == 0
    assert clock['caller_return_offset'] == '0x329430' and clock['provider'] == 'inherited explicit clock_gettime'
    assert clock['seconds'] == clock['native_seconds'] == 1791023800 and clock['nanoseconds'] == 500000000
    assert clock['native_microseconds'] == 1791023800500000 and clock['native_milliseconds'] == 1791023800500
    assert bytes.fromhex(clock['timespec_hex']) == (1791023800).to_bytes(8, 'little')+(500000000).to_bytes(8, 'little')
    pending = row['pending_callback']
    raw = bytes.fromhex(pending['descriptor_before_hex'])
    assert len(raw) == 32 and raw_hash(raw) == pending['descriptor_before_sha256'] == NULL_DESCRIPTOR_HASH
    assert pending['descriptor_after_hex'] == raw.hex() and int.from_bytes(raw[:8], 'little') == 0
    assert pending['callsite_offset'] == hex(CALLSITE) and pending['call_instruction_bytes'] == '00013fd6'
    assert pending['call_observation_index'] == 28557 and pending['stop_observation_index'] == 28561
    assert pending['VM_cursor_offset'] == '0x10963c' and pending['wrapper_offset'] == hex(NULL_WRAPPER)
    assert pending['wrapper_code_hex'] == NULL_CODE and pending['instruction_bytes'] == '00013fd6'
    assert pending['wrapper_path'] == [hex(a) for a in range(NULL_WRAPPER, NULL_CALL+4, 4)]
    assert pending['stop_before'] == hex(NULL_CALL) and pending['function_pointer'] == pending['object_first_word'] == '0x0'
    assert pending['wrapper_frame_size'] == 16 and pending['link_register_offset'] == hex(VM_RESUME)
    assert int(pending['stack_pointer_at_vm_call'], 16)-16 == int(pending['stack_pointer_at_stop'], 16)
    assert pending['result_store_offset'] == '0x28864c'
    for key in ('x0_matches_descriptor', 'x19_matches_descriptor', 'saved_caller_frame_verified', 'descriptor_preserved'):
        assert pending[key] is True
    for key in ('indirect_call_executed', 'callback_target_executed', 'result_store_executed', 'callback_returned'):
        assert pending[key] is False
    boundary = row['inherited_stop_boundary']
    assert boundary == dict(kind='unsupported_indirect_callback', stop_before=hex(NULL_CALL), instruction='blr x8',
        instruction_bytes='00013fd6', return_pc='0x28864c', link_register_before_call=hex(VM_RESUME),
        callback_object_register='x19', callback_object_address=pending['descriptor_address'],
        callback_object_in_mapped_memory=True, callback_object_first_word='0x0', function_pointer='0x0',
        function_pointer_matches_object_first_word=True, function_pointer_is_null=True, callback_target_executed=False)


def damaged_evidence_rejected(data):
    changes = [
        (('claims', 'complete_standalone_signer_verified'), True),
        (('claims', 'next_indirect_call_executed'), True),
        (('providers', 'new_providers'), ['NULL callback replacement']),
        (('case_result', 'instruction_trace_sha256'), '0'*64),
        (('case_result', 'observed_code_sha256'), '0'*64),
        (('case_result', 'allocator_delta', 'malloc'), 0),
        (('case_result', 'service_delta', 'clock'), 0),
        (('case_result', 'clock', 'native_seconds'), 0),
        (('case_result', 'pending_callback', 'function_pointer'), '0x1'),
        (('case_result', 'pending_callback', 'descriptor_after_hex'), '00'*32),
        (('case_result', 'pending_callback', 'callback_returned'), True),
        (('case_result', 'pending_callback', 'indirect_call_executed'), True),
        (('case_result', 'pending_callback', 'result_store_executed'), True),
        (('case_result', 'pending_callback', 'saved_caller_frame_verified'), False),
        (('case_result', 'inherited_stop_boundary', 'function_pointer_is_null'), False)]
    for key in ('jni_calls', 'libc_svc', 'main_svc', 'late_jni_calls', 'java_dispatch'):
        changes.append((('case_result', key+'_after'), []))
    for i in range(len(SPECS)):
        for key, value in (('target_offset', '0x0'), ('target_arguments', {}), ('wrapper_path', []),
                           ('descriptor_before_sha256', '0'*64), ('returned_x0', '0xdeadbeef'),
                           ('return_observation_index', 0), ('stack_pointer_restored', False),
                           ('callee_saved_registers_restored', False), ('callback_returned', False)):
            changes.append((('case_result', 'callbacks', i, key), value))
    for path, value in changes:
        bad = deepcopy(data)
        obj = bad
        for key in path[:-1]:
            obj = obj[key]
        obj[path[-1]] = value
        # Exercise semantic checks even when the attacker repairs the row digest.
        if path[0] == 'case_result' and path[1] not in ('instruction_trace_sha256', 'observed_code_sha256'):
            bad['case_result_sha256'] = digest(bad['case_result'])
        try:
            validate(bad)
        except (AssertionError, KeyError, TypeError, ValueError):
            continue
        raise AssertionError(f'damaged callback-boundary evidence accepted: {path}')
    return len(changes)


def run(path, libc):
    parent = prior_evidence()
    p = previous.bootstrap.module_prefix()
    p.digest.verify_images(path, libc)
    assert sha256(path) == parent['input_provenance']['Metasec_sha256']
    assert sha256(libc) == parent['input_provenance']['Bionic_sha256']
    def create(control):
        scenario = CallbackBoundaryScenario(control)
        scenario.path = path
        scenario.continue_to_svc = True
        return scenario
    rows = p.digest.context.replay(path, libc, case_controls=[p.CONTROL], _extension_factory=create,
        _request_profile=p.digest.previous.previous.name.previous.previous.PROFILE['name'],
        _handler_read_profile=p.digest.context.NULL_PAYLOAD_READ_PROFILE['name'])
    assert len(rows) == 1
    return dict(schema=SCHEMA, claims=claims_for(), providers=providers(), input_provenance=provenance(parent),
                source_fingerprints=source_fingerprints(), case_result_sha256=digest(rows[0]), case_result=rows[0])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf', type=Path)
    parser.add_argument('--libc', type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--capture', action='store_true')
    mode.add_argument('--replay', action='store_true')
    args = parser.parse_args()
    if (args.capture or args.replay) and (not args.elf or not args.libc):
        parser.error('--capture and --replay require --elf and --libc')
    if args.capture:
        if EVIDENCE.exists():
            raise FileExistsError('frozen evidence already exists; refusing overwrite')
        data = run(args.elf, args.libc)
        validate(data)
        rejected = damaged_evidence_rejected(data)
        with EVIDENCE.open('x', encoding='utf-8', newline='\n') as output:
            output.write(json.dumps(data, indent=2)+'\n')
    else:
        data = json.loads(EVIDENCE.read_text(encoding='utf-8'))
        validate(data)
        rejected = damaged_evidence_rejected(data)
        if args.replay:
            assert run(args.elf, args.libc) == data, 'fresh callback-boundary replay differs'
    row = data['case_result']
    print(json.dumps(dict(schema=SCHEMA, damaged_evidence_rejected=rejected,
        returned_callbacks=len(row['callbacks']), instruction_observations=row['instruction_observations'],
        allocator_delta=row['allocator_delta'], service_delta=row['service_delta'],
        stop_before=hex(NULL_CALL), next_callback_pointer='0x0', next_indirect_call_executed=False,
        complete_standalone_signer_verified=False)))


if __name__ == '__main__':
    main()
