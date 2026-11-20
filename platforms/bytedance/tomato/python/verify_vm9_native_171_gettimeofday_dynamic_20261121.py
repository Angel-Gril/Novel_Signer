"""Continue the native VM9 request through gettimeofday to an unsupported callback.

The 2026-11-20 receipt stopped before syscall 169.  This verifier keeps that
receipt as an immutable prefix, services exactly the observed timeval ABI, and
stops before an unsupported indirect callback.  It does not claim suffix return,
ordinary Cronet headers, a standalone signer, or online acceptance.
"""
from __future__ import annotations

import argparse
from collections import Counter, deque
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from unicorn import arm64_const as arm

import verify_vm9_native_171_suffix_digest_20261120 as digest

EVIDENCE = digest.EVIDENCE.with_name('vm9_native_171_gettimeofday_dynamic_20261121.json')
SCHEMA = 'vm9-native-171-gettimeofday-dynamic-20261121-v1'
MAX_WINDOW = 4000000
CONTROL = {'base': 0x122C0000, 'property_profile': 'absent', 'null_at': 'class0'}
GETTIME_SVC = 0x271DBC
GETTIME_POST = (0x271DC0, 0x271DC4, 0x271DC8, 0x271DCC)
GETTIME_CALLER = (0x272920, 0x272924, 0x272928, 0x27292C, 0x272930,
                  0x272934, 0x272938, 0x27293C, 0x272940, 0x272944,
                  0x272948, 0x27294C, 0x272950, 0x272954)
CLAIMS = dict(
    inherited_gettimeofday_pre_svc_prefix_verified=True,
    fixed_guest_timeval_provider_explicit=True,
    gettimeofday_svc_169_dynamically_entered=True,
    gettimeofday_return_thunk_dynamically_executed=True,
    gettimeofday_caller_return_path_dynamically_executed=True,
    old_four_main_image_svcs_preserved=True,
    next_unpermitted_main_image_svc_reached=False,
    unsupported_indirect_callback_boundary_reached=True,
    native_memory_used_as_python_model_input=False,
    current_native_suffix_return_verified=False,
    complete_configuration_provenance_verified=False,
    ordinary_Cronet_six_headers_verified=False,
    online_acceptance_verified=False,
    complete_standalone_signer_verified=False,
    synthetic_late_jni_providers_explicit=True,
    new_providers=True,
    Android_execution=False,
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def baseline() -> dict:
    data = json.loads(digest.EVIDENCE.read_text())
    digest.validate(data)
    return data


def source_fingerprints() -> dict:
    return {
        'dynamic_verifier_sha256': sha256(Path(__file__)),
        'digest_verifier_sha256': sha256(Path(digest.__file__)),
        'context_verifier_sha256': sha256(Path(digest.context.__file__)),
        'worker_allocator_sha256': sha256(Path(digest.context.outer.h.__file__)),
    }


class DynamicScenario(digest.Scenario):
    """Retain the digest boundary while allowing one precisely bound SVC."""

    def __init__(self, control):
        super().__init__(control)
        self.gettimeofday_pre = None
        self.gettimeofday_return = None
        self.gettimeofday_path = []
        self._gettimeofday_entered = False
        self._resume_after_gettimeofday = False
        self.suppress_handler_read_observation = False
        self._post_syscall_pc_counts = Counter()
        self._post_syscall_pc_tail = deque(maxlen=64)
        self._post_syscall_pc_first = []
        self._post_syscall_dispatch_first = []
        self._post_syscall_dispatch_tail = deque(maxlen=24)
        self._post_syscall_dispatch_state_counts = Counter()
        self._post_syscall_cursor_first = None
        self._post_syscall_cursor_last = None
        self._post_syscall_cursor_monotonic_steps = 0
        self._post_syscall_dispatch_stop = None
        self.compact_trace_requested = False
        self.instruction_window_limit = MAX_WINDOW
        self.late_jni_calls = []
        self.java_dispatch_calls = []
        self.continuation_boundary = None
        self._late_jni_pending = False
        # The observed getter has a void method descriptor. Use the established
        # class0 control, which previously reached the same callback boundary.
        self.continuation_references = (0,)
        self.continuation_reference_types = {}
        self.extra_jni_slots = (0x88,)

    def _reg(self, cpu, index):
        return cpu.reg_read(getattr(arm, f'UC_ARM64_REG_X{index}'))

    def late_jni(self, cpu, slot, args, state):
        """Service only the observed method lookup check after syscall 169."""
        if not self._gettimeofday_entered or state.get('evaluator_active', False):
            return False, None
        lr_offset = self._reg(cpu, 30) - self.image
        expected_env = digest.context.outer.io.GUEST + 0x7800
        if slot == 0x388 and lr_offset == 0x204D84:
            assert args[0] == expected_env
            name = self._bounded_cstring(cpu, args[2])
            signature = self._bounded_cstring(cpu, args[3])
            return_descriptor = signature[signature.find(b')') + 1:]
            return_kind = ('reference' if return_descriptor.startswith((b'L', b'['))
                           else 'void' if return_descriptor == b'V' else 'primitive')
            self._late_jni_pending = False
            result = digest.context.stack.h.METHOD
            label = 'GetStaticMethodID_method_fixture'
            details = dict(name_length=len(name), name_sha256=hashlib.sha256(name).hexdigest(),
                           signature_length=len(signature),
                           signature_sha256=hashlib.sha256(signature).hexdigest(),
                           return_kind=return_kind,
                           class_argument_is_null=args[1] == 0)
        elif slot == 0x720 and lr_offset == 0x204D94:
            assert args == (expected_env,) and not self._late_jni_pending
            result = 0
            label = 'ExceptionCheck_clear'
            details = {}
        elif slot == 0x88 and lr_offset == 0x204DAC:
            assert args == (expected_env,) and self._late_jni_pending
            self._late_jni_pending = False
            result = 0
            label = 'ExceptionClear'
            details = {}
        else:
            return False, None
        self.late_jni_calls.append(dict(slot=hex(slot), label=label,
            caller=hex(lr_offset), args=[hex(value) for value in args],
            result=hex(result), **details))
        return True, result

    @staticmethod
    def _bounded_cstring(cpu, address, limit=1024):
        assert address != 0
        value = bytearray()
        for index in range(limit):
            byte = bytes(cpu.mem_read(address + index, 1))
            if byte == b'\0':
                return bytes(value)
            value.extend(byte)
        raise AssertionError('late JNI string exceeded bounded read')

    def _record_path(self, cpu, pc):
        # The same thunk is used by the inherited synthetic AID file profile
        # (syscall 48).  Its post-SVC instructions must remain owned by the
        # inherited observers until this scenario has seen syscall 169.
        if not self._gettimeofday_entered:
            return
        offset = pc - self.image
        if offset not in GETTIME_POST + GETTIME_CALLER:
            return
        if offset not in self.gettimeofday_path:
            self.gettimeofday_path.append(offset)
        if offset == 0x271DC0:
            assert self._gettimeofday_entered
            assert self._reg(cpu, 0) == 0
            sp = cpu.reg_read(arm.UC_ARM64_REG_SP)
            timeval = sp + 8
            self.suppress_handler_read_observation = True
            try:
                timeval_bytes = bytes(cpu.mem_read(timeval, 16))
            finally:
                self.suppress_handler_read_observation = False
            self.gettimeofday_return = dict(
                status=0,
                status_register_x0=hex(self._reg(cpu, 0)),
                timeval_address=hex(timeval),
                timeval_bytes=timeval_bytes.hex(),
                timeval_seconds=int.from_bytes(timeval_bytes[:8], 'little'),
                timeval_microseconds=int.from_bytes(timeval_bytes[8:], 'little'),
            )
            # digest.Scenario deliberately returns early after the old
            # boundary. Keep its continuation guard armed while the normal
            # post-SVC instructions execute; the inherited observer will
            # therefore remain inactive here and stop again at the next SVC.
            self._resume_after_gettimeofday = True
            self.continue_to_svc = True

    def instruction_window_diagnostics(self):
        common = sorted(self._post_syscall_pc_counts.items(), key=lambda item: (-item[1], item[0]))[:12]
        dispatch_common = sorted(self._post_syscall_dispatch_state_counts.items(),
                                  key=lambda item: (-item[1], item[0]))[:8]
        return 'gettimeofday post-SVC diagnostics: first=%r frequent=%r tail=%r' % (
            [hex(offset) for offset in self._post_syscall_pc_first],
            [(hex(offset), count) for offset, count in common],
            [hex(offset) for offset in self._post_syscall_pc_tail]) + '; dispatch=%r/%r' % (
                self._post_syscall_dispatch_first, list(self._post_syscall_dispatch_tail)) + \
            '; dispatch_states=%r stop=%r cursor_monotonic_steps=%d' % (
                dispatch_common, self._post_syscall_dispatch_stop,
                self._post_syscall_cursor_monotonic_steps)

    def pre_observe(self, cpu, pc, state):
        offset = pc - self.image
        if (self.continue_to_svc and self.digest_boundary_seen
                and not self._gettimeofday_entered and offset == GETTIME_SVC):
            sp = cpu.reg_read(arm.UC_ARM64_REG_SP)
            assert self._reg(cpu, 8) == 169
            assert self._reg(cpu, 0) == sp + 8
            assert self._reg(cpu, 1) == 0
            assert self._reg(cpu, 30) == self.image + 0x272924
            self.gettimeofday_pre = dict(
                pc_offset=hex(offset), syscall_number=169,
                x0=hex(self._reg(cpu, 0)), x1=hex(self._reg(cpu, 1)),
                x8=hex(self._reg(cpu, 8)), sp=hex(sp),
                lr_offset=hex(self._reg(cpu, 30) - self.image),
                timeval_sp_offset=hex(self._reg(cpu, 0) - sp),
                timezone_is_null=True,
            )
            self._gettimeofday_entered = True
            self.compact_trace_requested = True
            # Do not let the context observer classify this as the old
            # synthetic AID/cache SVC. The Unicorn instruction still executes;
            # keep the inherited continuation guard armed for the instructions
            # after the syscall.
            self.continue_to_svc = True
            self._record_path(cpu, pc)
            return True
        return super().pre_observe(cpu, pc, state)

    def observe(self, cpu, pc, state):
        if self._gettimeofday_entered:
            offset = pc - self.image
            if offset == 0x288648:
                x0=self._reg(cpu,0);x8=self._reg(cpu,8)
                lr_offset=self._reg(cpu,30)-self.image
                assert bytes(cpu.mem_read(pc,4)).hex()=='00013fd6'
                assert self._reg(cpu,19)==x0
                object_first_word=int.from_bytes(cpu.mem_read(x0,8),'little')
                mapped=any(start<=x0<end for start,end,_ in cpu.mem_regions())
                self.continuation_boundary=dict(
                    kind='unsupported_indirect_callback',
                    stop_before='0x288648',instruction='blr x8',
                    instruction_bytes='00013fd6',return_pc='0x28864c',
                    link_register_before_call=hex(lr_offset),
                    callback_object_register='x19',
                    callback_object_address=hex(x0),
                    callback_object_in_mapped_memory=mapped,
                    callback_object_first_word=hex(object_first_word),
                    function_pointer=hex(x8),
                    function_pointer_matches_object_first_word=x8==object_first_word,
                    function_pointer_is_null=x8==0,
                    callback_target_executed=False)
                self.svc_boundary=dict(kind='unsupported_indirect_callback',pc_offset='0x288648')
                cpu.emu_stop()
                cpu.reg_write(arm.UC_ARM64_REG_PC,digest.context.outer.oracle.STOP)
                return
            if offset == 0x26E70C:
                self.java_dispatch_calls.append(dict(
                    arguments=[hex(self._reg(cpu, index)) for index in range(5)],
                    entry_sp=hex(cpu.reg_read(arm.UC_ARM64_REG_SP)),
                    caller=hex(self._reg(cpu, 30) - self.image)))
            self._post_syscall_pc_counts[offset] += 1
            self._post_syscall_pc_tail.append(offset)
            if len(self._post_syscall_pc_first) < 32:
                self._post_syscall_pc_first.append(offset)
            if offset in (0x16855C, 0x16D8B8):
                x19 = self._reg(cpu, 19)
                try:
                    cursor = int.from_bytes(cpu.mem_read(x19, 8), 'little')
                    stream_word = int.from_bytes(cpu.mem_read(cursor, 4), 'little')
                except Exception:
                    cursor = None
                    stream_word = None
                opcode = self._reg(cpu, 21) & 0xFFFFFFFF
                cursor_candidate = self._reg(cpu, 9) if offset == 0x16D8B8 else None
                sample = dict(pc=hex(offset), cursor_slot=hex(x19), cursor=hex(cursor) if cursor is not None else None,
                    stream_word=hex(stream_word) if stream_word is not None else None,
                    opcode_x21=hex(opcode), opcode_low6=opcode & 0x3F,
                    opcode_sub6=(opcode >> 6) & 0x3F,
                    cursor_candidate_x9=hex(cursor_candidate) if cursor_candidate is not None else None,
                    x21=hex(self._reg(cpu, 21)), x28=hex(self._reg(cpu, 28)),
                    x29=hex(self._reg(cpu, 29)), x30=hex(self._reg(cpu, 30)))
                self._post_syscall_dispatch_state_counts[
                    (offset, cursor, opcode, self._reg(cpu, 28), self._reg(cpu, 30))] += 1
                if cursor is not None:
                    if self._post_syscall_cursor_last is not None and cursor >= self._post_syscall_cursor_last:
                        self._post_syscall_cursor_monotonic_steps += 1
                    if self._post_syscall_cursor_first is None:
                        self._post_syscall_cursor_first = cursor
                    self._post_syscall_cursor_last = cursor
                if len(self._post_syscall_dispatch_first) < 16:
                    self._post_syscall_dispatch_first.append(sample)
                self._post_syscall_dispatch_tail.append(sample)
            if offset == 0x16974C:
                x19 = self._reg(cpu, 19)
                try:
                    cursor = int.from_bytes(cpu.mem_read(x19, 8), 'little')
                    stream_word = int.from_bytes(cpu.mem_read(cursor, 4), 'little')
                except Exception:
                    cursor = None
                    stream_word = None
                self._post_syscall_dispatch_stop = dict(
                    pc=hex(offset), cursor_slot=hex(x19),
                    cursor=hex(cursor) if cursor is not None else None,
                    stream_word=hex(stream_word) if stream_word is not None else None,
                    opcode_x21=hex(self._reg(cpu, 21) & 0xFFFFFFFF),
                    x12=hex(self._reg(cpu, 12)), x19=hex(x19),
                    x21=hex(self._reg(cpu, 21)), x22=hex(self._reg(cpu, 22)),
                    x28=hex(self._reg(cpu, 28)), x30=hex(self._reg(cpu, 30)))
        self._record_path(cpu, pc)
        if self._resume_after_gettimeofday and pc - self.image == 0x271DC0:
            # Let the inherited inactive observers run once, then arm the
            # normal stop-before-next-SVC policy again.
            super().observe(cpu, pc, state)
            state['start_new_instruction_window'] = True
            self._resume_after_gettimeofday = False
            self.continue_to_svc = True
            self.digest_boundary_seen = True
            return
        super().observe(cpu, pc, state)

    def finish(self, result, state, proof):
        assert self.gettimeofday_pre is not None
        assert self.gettimeofday_return is not None
        assert self._gettimeofday_entered
        assert not self._late_jni_pending
        assert len(self.java_dispatch_calls) in (0, 1)
        if self.java_dispatch_calls:
            assert self.java_dispatch_calls[0]['arguments'] == [
                '0x1000011', '0x0', '0x0', '0x0', '0x0']
            assert self.java_dispatch_calls[0]['caller'] == '0x1cf6c8'
        assert len(self.late_jni_calls) in (0, 2)
        if self.late_jni_calls:
            assert [call['slot'] for call in self.late_jni_calls] == ['0x388', '0x720']
            assert [call['caller'] for call in self.late_jni_calls] == [
                '0x204d84', '0x204d94']
            assert [call['result'] for call in self.late_jni_calls] == [
                hex(digest.context.stack.h.METHOD), '0x0']
            assert self.late_jni_calls[0]['name_length'] > 0
            assert self.late_jni_calls[0]['signature_length'] > 0
        assert self.gettimeofday_path[:1] == [0x271DC0]
        for offset in GETTIME_POST + GETTIME_CALLER[1:]:
            assert offset in self.gettimeofday_path, hex(offset)
        row = super().finish(result, state, proof)
        assert row['post_digest_service_delta'].get('syscall_169') == 1
        if self.continuation_boundary is not None:
            assert self.svc_boundary['pc_offset']=='0x288648'
            row.pop('svc_boundary',None)
            row.pop('observation_stop_before_svc',None)
            row.pop('entered_svc_handler',None)
            row['unsupported_callback_boundary']=self.continuation_boundary
            row['main_image_svc_count_at_callback_boundary']=len(proof['main_image_SVC_boundaries'])
            row.pop('target_suffix_svc_reached',None)
        else:
            assert row['svc_boundary']['pc_offset'] == '0x286ec8'
        row.update(
            gettimeofday=dict(
                pre_svc=self.gettimeofday_pre,
                provider=dict(status=0, seconds=1791023800,
                              microseconds=500000),
                post_svc=self.gettimeofday_return,
                executed_offsets=[hex(offset) for offset in self.gettimeofday_path],
                return_thunk_offsets=[hex(offset) for offset in GETTIME_POST],
                caller_return_offsets=[hex(offset) for offset in GETTIME_CALLER],
            ),
            dynamic_main_image_svc_count_before=4,
            dynamic_main_image_svc_count_after=5,
            dynamic_main_image_svc_number=169,
            late_jni=dict(calls=self.late_jni_calls,
                          provider_kind=('explicit synthetic provider; no ART/JVM execution'
                              if self.late_jni_calls else 'no matching late JNI call observed')),
            java_dispatch=dict(
                inputs=self.java_dispatch_calls,
                observed=bool(self.java_dispatch_calls),
                method_return_kind='void' if self.java_dispatch_calls else 'not_reached',
                synthetic_object_reference_result=0 if self.java_dispatch_calls else None,
                provider_kind=('explicit NULL dispatch-result control'
                    if self.java_dispatch_calls else 'not applicable before callback boundary')),
            dispatcher_diagnostics=dict(
                observed_pc_counts={hex(offset):count for offset,count in sorted(self._post_syscall_pc_counts.items())
                                    if offset in (0x16855C,0x16D8B8,0x16974C)},
                dispatch_state_count=sum(self._post_syscall_dispatch_state_counts.values()),
                distinct_dispatch_state_count=len(self._post_syscall_dispatch_state_counts),
                dispatch_state_repeats=sum(count-1 for count in self._post_syscall_dispatch_state_counts.values()),
                first_dispatch_samples=self._post_syscall_dispatch_first,
                last_dispatch_samples=list(self._post_syscall_dispatch_tail),
                first_stream_cursor=hex(self._post_syscall_cursor_first) if self._post_syscall_cursor_first is not None else None,
                last_stream_cursor=hex(self._post_syscall_cursor_last) if self._post_syscall_cursor_last is not None else None,
                monotonic_cursor_steps=self._post_syscall_cursor_monotonic_steps,
                bound_pc_state=self._post_syscall_dispatch_stop,
            ),
        )
        return row


def dynamic_replay(path: Path, libc: Path, *, case_controls=None):
    scenarios = []
    def create(control):
        scenario = DynamicScenario(control)
        scenario.path = path
        scenario.continue_to_svc = True
        scenarios.append(scenario)
        return scenario

    try:
        return digest.context.replay(
            path, libc, case_controls=case_controls, _extension_factory=create,
            _request_profile=digest.previous.previous.name.previous.previous.PROFILE['name'],
            _handler_read_profile=digest.context.NULL_PAYLOAD_READ_PROFILE['name'])
    except Exception:
        for scenario in scenarios:
            print('dynamic replay boundary diagnostics', json.dumps(dict(
                late_jni=scenario.late_jni_calls,
                java_dispatch=scenario.java_dispatch_calls,
                continuation_boundary=scenario.continuation_boundary,
                gettimeofday_path=[hex(x) for x in scenario.gettimeofday_path],
                post_syscall_tail=[hex(x) for x in scenario._post_syscall_pc_tail]),
                sort_keys=True), flush=True)
        raise


def provider_manifest(row: dict) -> dict:
    late_calls = row['late_jni']['calls']
    dispatch = row['java_dispatch']
    return dict(
        inherited_owner='vm9_native_171_gettimeofday_return_20261120.json',
        late_jni_provider=('explicit synthetic provider bound to observed slot/LR pairs'
                           if late_calls else 'no matching late JNI call observed'),
        late_jni_sequence=[call['slot']+'@'+call['caller'] for call in late_calls],
        late_jni_results=[call['result'] for call in late_calls],
        continuation_java_dispatch=('tag 0x01000011, five words, void descriptor'
                                    if dispatch['observed'] else 'not reached before callback boundary'),
        continuation_java_dispatch_result=(0 if dispatch['observed'] else None),
        continuation_java_dispatch_result_control=('existing NULL_dispatch-result control'
                                                   if dispatch['observed'] else 'not applicable'),
        explicit_syscall_number=169,
        explicit_timeval_seconds=1791023800,
        explicit_timeval_microseconds=500000,
        maximum_handler_reads=2, inherited_main_image_svc_count=4,
        dynamic_main_image_svc_count=5, public_instruction_window_limit=MAX_WINDOW,
        stop_policy='after one gettimeofday SVC and before unsupported indirect callback',
        original_scope_kept=True)


def run(path: Path, libc: Path, inherited=None) -> dict:
    inherited = inherited or baseline()
    digest.verify_images(path, libc)
    assert sha256(path) == inherited['provenance']['Metasec_sha256']
    assert sha256(libc) == inherited['provenance']['Bionic_sha256']
    rows = dynamic_replay(path, libc, case_controls=[CONTROL])
    assert len(rows) == 1
    row = rows[0]
    old=next(item for item in inherited['case_results'] if item['control']==CONTROL)
    assert row['main_image_SVC_boundaries'] == old['main_image_SVC_boundaries']
    assert row['unsupported_callback_boundary']['stop_before'] == '0x288648'
    assert row['dynamic_main_image_svc_count_after'] == 5
    return dict(
        schema=SCHEMA,
        claims=dict(CLAIMS),
        providers=provider_manifest(row),
        input_provenance=dict(
            inherited_native_provenance=inherited['provenance'],
            Metasec_sha256=sha256(path), Bionic_sha256=sha256(libc),
        ),
        source_fingerprints=source_fingerprints(),
        case_result=row,
    )


def validate(data: dict) -> None:
    inherited = baseline()
    assert data['schema'] == SCHEMA
    assert data['claims'] == CLAIMS
    row = data['case_result']
    assert data['providers'] == provider_manifest(row)
    assert data['input_provenance'] == dict(
        inherited_native_provenance=inherited['provenance'],
        Metasec_sha256=inherited['provenance']['Metasec_sha256'],
        Bionic_sha256=inherited['provenance']['Bionic_sha256'])
    assert data['source_fingerprints'] == source_fingerprints()
    old = next(item for item in inherited['case_results'] if item['control']==CONTROL)
    assert row['control'] == CONTROL
    assert row['main_image_SVC_boundaries'] == old['main_image_SVC_boundaries']
    assert row['dynamic_main_image_svc_count_before'] == 4
    assert row['dynamic_main_image_svc_count_after'] == 5
    assert row['dynamic_main_image_svc_number'] == 169
    callback=row['unsupported_callback_boundary']
    assert {key:value for key,value in callback.items()
            if key!='link_register_before_call'} == dict(
        kind='unsupported_indirect_callback', stop_before='0x288648',
        instruction='blr x8', instruction_bytes='00013fd6',
        return_pc='0x28864c', callback_object_register='x19',
        callback_object_address=callback['callback_object_address'],
        callback_object_in_mapped_memory=callback['callback_object_in_mapped_memory'],
        callback_object_first_word=callback['callback_object_first_word'],
        function_pointer=callback['function_pointer'],
        function_pointer_matches_object_first_word=True,
        function_pointer_is_null=int(callback['function_pointer'],16)==0,
        callback_target_executed=False)
    assert callback['link_register_before_call'].startswith('0x')
    assert int(callback['link_register_before_call'],16)<0x400000
    assert callback['function_pointer']==callback['callback_object_first_word']
    assert row['main_image_svc_count_at_callback_boundary']==len(row['main_image_SVC_boundaries'])
    assert 'svc_boundary' not in row
    assert 'observation_stop_before_svc' not in row
    assert 'entered_svc_handler' not in row
    assert row['post_digest_service_delta']['syscall_169'] == 1
    late_jni = row['late_jni']
    calls = late_jni['calls']
    assert len(calls) in (0, 2)
    if calls:
        assert late_jni['provider_kind'] == 'explicit synthetic provider; no ART/JVM execution'
        assert [(call['slot'], call['caller'], call['result']) for call in calls] == [
            ('0x388', '0x204d84', hex(digest.context.stack.h.METHOD)),
            ('0x720', '0x204d94', '0x0')]
        assert calls[0]['name_length'] > 0 and digest.context.graph.inputs.is_digest(calls[0]['name_sha256'])
        assert calls[0]['signature_length'] > 0 and digest.context.graph.inputs.is_digest(calls[0]['signature_sha256'])
        assert calls[0]['class_argument_is_null'] is True
    else:
        assert late_jni['provider_kind'] == 'no matching late JNI call observed'
    dispatch = row['java_dispatch']
    if dispatch['observed']:
        assert dispatch['inputs'] == [dict(arguments=['0x1000011','0x0','0x0','0x0','0x0'],
            entry_sp=dispatch['inputs'][0]['entry_sp'],caller='0x1cf6c8')]
        assert dispatch['method_return_kind'] == 'void'
        assert dispatch['synthetic_object_reference_result'] == 0
        assert dispatch['provider_kind'] == 'explicit NULL dispatch-result control'
    else:
        assert dispatch == dict(inputs=[], observed=False, method_return_kind='not_reached',
            synthetic_object_reference_result=None,
            provider_kind='not applicable before callback boundary')
    windows = row['instruction_observation_windows']
    assert len(windows) == 3 and all(0 < value < MAX_WINDOW for value in windows)
    assert row['post_digest_instruction_observations'] == windows[-1]
    gettime = row['gettimeofday']
    assert gettime['pre_svc'] == dict(
        pc_offset='0x271dbc', syscall_number=169,
        x0=gettime['pre_svc']['x0'], x1='0x0', x8='0xa9',
        sp=gettime['pre_svc']['sp'], lr_offset='0x272924',
        timeval_sp_offset='0x8', timezone_is_null=True)
    assert gettime['provider'] == dict(status=0, seconds=1791023800,
                                       microseconds=500000)
    post = gettime['post_svc']
    assert post['status'] == 0 and post['status_register_x0'] == '0x0'
    assert post['timeval_seconds'] == 1791023800
    assert post['timeval_microseconds'] == 500000
    assert len(post['timeval_bytes']) == 32
    assert gettime['return_thunk_offsets'] == [hex(offset) for offset in GETTIME_POST]
    assert gettime['caller_return_offsets'] == [hex(offset) for offset in GETTIME_CALLER]
    executed = set(gettime['executed_offsets'])
    assert set(gettime['return_thunk_offsets']) <= executed
    assert set(gettime['caller_return_offsets'][1:]) <= executed
    assert row['current_native_suffix_return_verified'] is False
    assert 'svc_boundary' not in row


def damaged_evidence_rejected(data: dict) -> int:
    cases = [
        (('claims', 'gettimeofday_svc_169_dynamically_entered'), False),
        (('providers', 'explicit_syscall_number'), 170),
        (('case_result', 'dynamic_main_image_svc_count_after'), 4),
        (('case_result', 'post_digest_service_delta', 'syscall_169'), 0),
        (('case_result', 'late_jni', 'calls', 1, 'result'), '0x1'),
        (('case_result', 'late_jni', 'calls', 0, 'signature_length'), 0),
        (('case_result', 'gettimeofday', 'provider', 'seconds'), 0),
        (('case_result', 'gettimeofday', 'post_svc', 'timeval_seconds'), 0),
        (('case_result', 'unsupported_callback_boundary', 'stop_before'), '0x271dbc'),
        (('case_result', 'gettimeofday', 'return_thunk_offsets'), []),
    ]
    for path, value in cases:
        bad = deepcopy(data)
        target = bad
        for part in path[:-1]:
            target = target[part]
        target[path[-1]] = value
        try:
            validate(bad)
        except (AssertionError, KeyError, TypeError, ValueError):
            continue
        raise AssertionError(f'damaged dynamic evidence accepted: {path}')
    return len(cases)


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
            parser.error('refusing to overwrite frozen dynamic evidence')
        data = run(args.elf, args.libc)
        validate(data)
        rejected = damaged_evidence_rejected(data)
        EVIDENCE.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n')
    else:
        data = json.loads(EVIDENCE.read_text())
        validate(data)
        rejected = damaged_evidence_rejected(data)
        if args.replay:
            assert run(args.elf, args.libc, baseline()) == data
    print(json.dumps(dict(schema=SCHEMA, damaged_evidence_rejected=rejected,
        gettimeofday_svc=169,
        next_boundary=data['case_result']['unsupported_callback_boundary']['stop_before'],
        dynamic_main_image_svc_count=data['case_result']['dynamic_main_image_svc_count_after'],
        current_native_suffix_return_verified=False,
        ordinary_Cronet_six_headers_verified=False,
        complete_standalone_signer_verified=False)))


if __name__ == '__main__':
    main()
