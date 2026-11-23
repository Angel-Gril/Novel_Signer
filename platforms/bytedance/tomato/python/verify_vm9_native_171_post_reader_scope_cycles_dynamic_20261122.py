"""Close the pending diagnostic scope and seven further native scope pairs."""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from unicorn import arm64_const as arm

import verify_vm9_native_171_post_reader_callbacks_dynamic_20261122 as previous

EVIDENCE = previous.EVIDENCE.with_name('vm9_native_171_post_reader_scope_cycles_dynamic_20261122.json')
SCHEMA = 'vm9-native-171-post-reader-scope-cycles-dynamic-20261122-v1'
VM_RESUME = previous.VM_RESUME
CALLSITE = previous.CALLSITE
ENTER, LEAVE, GETTER = 0x26C858, 0x26C9D0, 0x2633A4
TABLE = 0x3DEDA8
TABLE_SIZE = 2048
LOCKED = '0140000089000000'
UNLOCKED = '0040000000000000'
LEAVE_HASH = 'e782c5c31933262cebdc5795c8d33713ffe81a8b83a2a14dec75dae2128b77bc'
ENTER_A = 'd62609342cafe342fedb5548218ae91be6e8f10a291198571ea49340088f9d12'
ENTER_B = 'adecd9288bf24e50024f57353ff82ead78f53fe580a5f8495a9b957a9d05b8dd'
ENTER_NULL = 'acaac8a94b38ba3494ceb8e9d97922023ab60a4e08a8aaca798ca008aa1e1424'
ENTER_C = '21b83da8d9e6a2f57d5f7bf2652902245d89b2f52d0e19d1f9a952bf03d3b4f6'
# wrapper, target, descriptor hash, call/return observation index, VM cursor.
SPECS = (
    (0x288540, LEAVE, LEAVE_HASH, 965, 1019, 0x1070A4),
    (0x288530, ENTER, ENTER_A, 2029, 2140, 0x10710C),
    (0x288540, LEAVE, LEAVE_HASH, 3204, 3258, 0x107188),
    (0x288530, ENTER, ENTER_NULL, 4139, 4250, 0x1071E4),
    (0x288540, LEAVE, LEAVE_HASH, 5214, 5268, 0x107218),
    (0x288530, ENTER, ENTER_NULL, 6131, 6242, 0x107280),
    (0x288540, LEAVE, LEAVE_HASH, 7252, 7306, 0x1072F8),
    (0x288530, ENTER, ENTER_B, 8187, 8298, 0x107358),
    (0x288540, LEAVE, LEAVE_HASH, 9208, 9262, 0x107388),
    (0x288530, ENTER, ENTER_B, 10326, 10437, 0x1073F4),
    (0x288540, LEAVE, LEAVE_HASH, 11501, 11555, 0x107478),
    (0x288530, ENTER, ENTER_C, 13380, 13491, 0x107514),
    (0x288540, LEAVE, LEAVE_HASH, 14951, 15005, 0x10756C),
    (0x28868C, GETTER, '6d1545b1d9df47d3ade21f530476b0f5a6358f59eb001b742536d227e9965e71', 15794, 15993, 0x107594),
    (0x288530, ENTER, ENTER_C, 16619, 16730, 0x1075B4),
    (0x288540, LEAVE, LEAVE_HASH, 18635, 18689, 0x10766C),
)
WRAPPERS = {0x288530: previous.WRAPPERS[0x288530],
            0x288540: previous.WRAPPERS[0x288540],
            0x28868C: 'fe0f1ff8092040a9000840f920013fd6fe0741f8c0035fd6'}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def raw_hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def prior_evidence() -> dict:
    data = json.loads(previous.EVIDENCE.read_text(encoding='utf-8'))
    previous.validate(data)
    return data


def source_fingerprints() -> dict:
    return dict(scope_cycles_verifier_sha256=sha256(Path(__file__)),
                inherited_source_fingerprints=previous.source_fingerprints())


def provenance(parent: dict) -> dict:
    return dict(inherited_post_reader_callbacks_evidence_sha256=sha256(previous.EVIDENCE),
        Metasec_sha256=parent['input_provenance']['Metasec_sha256'],
        Bionic_sha256=parent['input_provenance']['Bionic_sha256'])


class ScopeCyclesScenario(previous.PostReaderScenario):
    def __init__(self, control):
        super().__init__(control)
        self._cycles_active = False
        self._cycles_count = 0
        self._cycles_calls = []
        self._cycles_call = None
        self._cycles_trace = hashlib.sha256()
        self._cycles_code = {}
        self._cycles_first = []
        self._cycles_tail = []
        self._cycles_state = None
        self._cycles_allocator_before = None
        self._cycles_late_jni = None
        self._cycles_java = None
        self._cycles_parent = None
        self._cycles_table_address = None
        self._cycles_table_before = None
        self._cycles_scope_address = None
        self._cycles_scope_open = False
        self._cycles_pairs = 0
        self._cycles_sp = None
        self._cycles_regs = None
        self._cycles_descriptor = None
        self._cycles_words = None
        self._cycles_done = False

    @staticmethod
    def _u(cpu, address, size=8):
        return int.from_bytes(cpu.mem_read(address, size), 'little')

    def _observe_pc(self, cpu, pc):
        offset = pc-self.image
        self._cycles_count += 1
        assert self._cycles_count < previous.MAX_OBSERVATIONS
        raw = bytes(cpu.mem_read(pc, 4))
        self._cycles_trace.update(offset.to_bytes(8, 'little', signed=True)+raw)
        self._cycles_code[hex(offset)] = raw.hex()
        if len(self._cycles_first) < 16:
            self._cycles_first.append(hex(offset))
        self._cycles_tail = (self._cycles_tail+[hex(offset)])[-16:]

    def _return_call(self, cpu, pc):
        super()._return_call(cpu, pc)
        if not self._done:
            return
        parent = prior_evidence()['case_result']
        assert self._calls == parent['callbacks']
        assert self._post_count == parent['instruction_observations']
        assert self._post_trace.hexdigest() == parent['instruction_trace_sha256']
        assert previous.digest(self._post_code) == parent['observed_code_sha256']
        assert self._post_first == parent['first_pc_offsets']
        assert self._post_tail == parent['tail_pc_offsets']
        events = self._cycles_state['allocator_events_ref']
        assert events[:len(self._allocator_prefix)] == self._allocator_prefix
        assert events[len(self._allocator_prefix):] == parent['new_allocator_events']
        assert self.late_jni_calls == parent['late_jni_calls_after']
        assert self.java_dispatch_calls == parent['java_dispatch_after']
        self._cycles_parent = dict(callbacks_verified=8,
            instruction_observations=self._post_count,
            instruction_trace_sha256=self._post_trace.hexdigest(),
            observed_code_sha256=previous.digest(self._post_code),
            allocation_prefix_preserved=True)
        self._cycles_allocator_before = deepcopy(events)
        self._cycles_late_jni = deepcopy(self.late_jni_calls)
        self._cycles_java = deepcopy(self.java_dispatch_calls)
        self._cycles_scope_address = int(parent['callbacks'][-1]['descriptor_words'][1], 16)
        self._cycles_table_address = self._u(cpu, self.image+TABLE)
        self._cycles_table_before = bytes(cpu.mem_read(self._cycles_table_address, TABLE_SIZE))
        self._cycles_scope_open = True
        self._cycles_active = True
        self._done = False
        # The parent observes this boundary once, then lets its instruction run.
        self._observe_pc(cpu, pc)

    def _start_cycle_call(self, cpu, pc):
        assert self._cycles_call is None and len(self._cycles_calls) < len(SPECS)
        wrapper, target, descriptor_hash, call_index, _, cursor = SPECS[len(self._cycles_calls)]
        assert self._cycles_count == call_index
        assert bytes(cpu.mem_read(pc, 4)).hex() == '00013fd6'
        assert self._reg(cpu, 8) == self.image+wrapper
        descriptor = self._reg(cpu, 0)
        assert any(a <= descriptor and descriptor+32 <= b for a, b, _ in cpu.mem_regions())
        raw = bytes(cpu.mem_read(descriptor, 32))
        words = [int.from_bytes(raw[i:i+8], 'little') for i in range(0, 32, 8)]
        assert words[0] == self.image+target
        assert raw_hash(raw) == descriptor_hash
        assert self._u(cpu, self._reg(cpu, 19)) == self.image+cursor
        self._cycles_sp = cpu.reg_read(arm.UC_ARM64_REG_SP)
        self._cycles_regs = [self._reg(cpu,n) for n in range(19,30)]
        self._cycles_descriptor = descriptor
        self._cycles_words = words
        self._cycles_call = dict(ordinal=len(self._cycles_calls),
            callsite_offset=hex(CALLSITE), call_instruction_bytes='00013fd6',
            wrapper_offset=hex(wrapper), target_offset=hex(target),
            call_observation_index=call_index, VM_cursor_offset=hex(cursor),
            descriptor_before_hex=raw.hex(), descriptor_before_sha256=raw_hash(raw),
            descriptor_words=[hex(w) for w in words],
            wrapper_path=[], wrapper_code_verified=False, target_entered=False,
            target_body_observations=0, mutex_events=[])
        if target in (ENTER, LEAVE):
            assert words[1] == self._cycles_scope_address
            scope = bytes(cpu.mem_read(words[1],24))
            input_word = words[2] if target == ENTER else int.from_bytes(scope[16:], 'little')
            index = (input_word >> 4) & 255
            entry = self._u(cpu, self._cycles_table_address+index*8)
            assert entry != 0
            entry_raw = bytes(cpu.mem_read(entry,48))
            self._cycles_call['scope'] = dict(address=hex(words[1]), input_word=hex(input_word),
                table_index=index, selected_entry=hex(entry),
                object_before_hex=scope.hex(), entry_before_hex=entry_raw.hex(),
                entry_before_sha256=raw_hash(entry_raw))
            assert entry_raw[8:16].hex() == (UNLOCKED if target == ENTER else LOCKED), entry_raw.hex()
        else:
            raw_output = bytes(cpu.mem_read(words[1],16))
            self._cycles_call['getter_output_before_hex'] = raw_output.hex()

    def _enter_cycle_target(self, cpu):
        call = self._cycles_call
        target = int(call['target_offset'],16)
        words = self._cycles_words
        expected = {0: words[1]}
        if target == ENTER:
            expected[1] = words[2]
        elif target == GETTER:
            expected = {0: words[2], 8: words[1]}
        for n,v in expected.items():
            assert self._reg(cpu,n) == v
        target_return = 0x28869C if target == GETTER else VM_RESUME
        assert self._reg(cpu,30) == self.image+target_return
        call.update(target_entered=True, argument_binding_verified=True,
            target_arguments={f'x{n}':hex(v) for n,v in expected.items()},
            target_return_offset=hex(target_return))

    def _return_cycle_call(self, cpu):
        call = self._cycles_call
        ordinal = len(self._cycles_calls)
        wrapper, target, _, _, return_index, _ = SPECS[ordinal]
        assert self._cycles_count == return_index
        assert call['target_entered'] and call['argument_binding_verified']
        assert self._reg(cpu,0) == 0
        assert cpu.reg_read(arm.UC_ARM64_REG_SP) == self._cycles_sp
        assert [self._reg(cpu,n) for n in range(19,30)] == self._cycles_regs
        after = bytes(cpu.mem_read(self._cycles_descriptor,32))
        assert after.hex() == call['descriptor_before_hex']
        assert call['wrapper_path'] == [hex(a) for a in range(wrapper,wrapper+len(bytes.fromhex(WRAPPERS[wrapper])),4)]
        assert self._u(cpu,self._receiver+0x88,4) == 0
        assert bytes(cpu.mem_read(self._cycles_table_address,TABLE_SIZE)) == self._cycles_table_before
        if target in (ENTER,LEAVE):
            scope = call['scope']
            object_after = bytes(cpu.mem_read(self._cycles_scope_address,24))
            entry_after = bytes(cpu.mem_read(int(scope['selected_entry'],16),48))
            object_before = bytes.fromhex(scope['object_before_hex'])
            expected_object = bytearray(object_before)
            if target == ENTER:
                assert not self._cycles_scope_open
                expected_object[:8] = (self.image+0x35D410).to_bytes(8,'little')
                expected_object[8:12] = bytes(4)
                expected_object[16:] = int(scope['input_word'],16).to_bytes(8,'little')
                self._cycles_scope_open = True
            else:
                assert self._cycles_scope_open
                self._cycles_scope_open = False
                if ordinal != 0:
                    self._cycles_pairs += 1
            assert object_after == expected_object
            expected_entry = bytearray.fromhex(scope['entry_before_hex'])
            expected_entry[8:16] = bytes.fromhex(LOCKED if target == ENTER else UNLOCKED)
            assert entry_after == expected_entry
            kind = 'pthread_mutex_lock' if target == ENTER else 'pthread_mutex_unlock'
            assert call['mutex_events'] == [dict(kind=kind,
                callsite_offset='0x347f00' if target == ENTER else '0x347f10',
                mutex_address=hex(int(scope['selected_entry'],16)+8))]
            scope.update(object_after_hex=object_after.hex(),
                object_after_sha256=raw_hash(object_after),
                entry_after_hex=entry_after.hex(), entry_after_sha256=raw_hash(entry_after),
                object_update_and_padding_verified=True, selected_mutex_transition_verified=True,
                entry_bytes_outside_mutex_preserved=True)
        else:
            output = bytes(cpu.mem_read(self._cycles_words[1],16))
            call.update(getter_output_after_hex=output.hex(), getter_output_after_sha256=raw_hash(output))
            assert not self._cycles_scope_open
        call.update(return_observation_index=return_index, returned_x0='0x0',
            return_offset=hex(VM_RESUME), reader_count=0,
            descriptor_after_hex=after.hex(), descriptor_after_sha256=raw_hash(after),
            descriptor_preserved=True, stack_pointer_restored=True,
            callee_saved_registers_restored=True, callback_returned=True)
        self._cycles_calls.append(call)
        self._cycles_call = None
        self._cycles_done = len(self._cycles_calls) == len(SPECS)

    def observe(self,cpu,pc,state):
        self._cycles_state = state
        if not self._cycles_active:
            return super().observe(cpu,pc,state)
        offset = pc-self.image
        self._observe_pc(cpu,pc)
        if offset == CALLSITE:
            self._start_cycle_call(cpu,pc)
        call = self._cycles_call
        if call is not None:
            wrapper = int(call['wrapper_offset'],16)
            if offset == wrapper:
                assert bytes(cpu.mem_read(pc,len(bytes.fromhex(WRAPPERS[wrapper])))).hex() == WRAPPERS[wrapper]
                call['wrapper_code_verified'] = True
            if wrapper <= offset < wrapper+len(bytes.fromhex(WRAPPERS[wrapper])):
                call['wrapper_path'].append(hex(offset))
            if offset == int(call['target_offset'],16) and not call['target_entered']:
                self._enter_cycle_target(cpu)
            if call['target_entered']:
                call['target_body_observations'] += 1
                if offset in (0x347F00,0x347F10):
                    call['mutex_events'].append(dict(
                        kind='pthread_mutex_lock' if offset == 0x347F00 else 'pthread_mutex_unlock',
                        callsite_offset=hex(offset),mutex_address=hex(self._reg(cpu,0))))
                if offset == VM_RESUME:
                    self._return_cycle_call(cpu)
        self._base_observe(cpu,pc,state)
        if self._cycles_done:
            assert not self._cycles_scope_open and self._cycles_pairs == 7
            cpu.emu_stop()
            cpu.reg_write(arm.UC_ARM64_REG_PC,
                previous.previous.callback_prefix.module_prefix().digest.context.outer.oracle.STOP)

    def finish(self,result,state,proof):
        assert self._cycles_done and self._cycles_call is None
        parent = prior_evidence()['case_result']
        assert result['allocator_events'] == self._cycles_allocator_before
        assert self.late_jni_calls == self._cycles_late_jni
        assert self.java_dispatch_calls == self._cycles_java
        return dict(control=parent['control'],retained_prefix=self._cycles_parent,
            instruction_observations=self._cycles_count,
            instruction_trace_sha256=self._cycles_trace.hexdigest(),
            observed_code_sha256=previous.digest(self._cycles_code),
            first_pc_offsets=self._cycles_first,tail_pc_offsets=self._cycles_tail,
            callbacks=self._cycles_calls,
            scope_summary=dict(previous_pending_scope_cleaned=True,
                new_scope_pairs_completed=self._cycles_pairs,observed_scope_open=False,
                scope_address=hex(self._cycles_scope_address),
                table_sha256=raw_hash(self._cycles_table_before),table_bytes_preserved=True),
            allocator_events_sha256=previous.digest(result['allocator_events']),new_allocator_events=[],
            allocator_counts_before=parent['allocator_counts_after'],allocator_counts_after=result['actual_allocator_counts'],
            allocator_delta=previous.previous._delta(parent['allocator_counts_after'],result['actual_allocator_counts']),
            service_counts_before=parent['service_counts_after'],service_counts_after=result['explicit_service_counts'],
            jni_calls_before=parent['jni_calls_after'],jni_calls_after=proof['JNI_calls'],
            libc_svc_before=parent['libc_svc_after'],libc_svc_after=proof['libc_SVC_boundaries'],
            main_svc_before=parent['main_svc_after'],main_svc_after=proof['main_image_SVC_boundaries'],
            late_jni_calls_before=self._cycles_late_jni,late_jni_calls_after=self.late_jni_calls,
            java_dispatch_before=self._cycles_java,java_dispatch_after=self.java_dispatch_calls,
            stop_boundary=dict(kind='sixteenth_scope_cycle_callback_return_before_vm_resume',
                stop_before=hex(VM_RESUME),next_vm_instruction_executed=False))


def claims_for() -> dict:
    return dict(evidence_label='Sample verified',native_callbacks_returned=16,
        previous_pending_scope_cleanup_verified=True,new_scope_pairs_completed=7,
        selected_scope_objects_mutexes_and_table_verified=True,
        callback_descriptors_argument_registers_and_wrappers_verified=True,
        callback_SP_and_callee_saved_registers_restored=True,
        allocator_service_JNI_SVC_ledgers_unchanged=True,
        next_vm_instruction_executed=False,current_native_suffix_return_verified=False,
        complete_standalone_signer_verified=False,ordinary_Cronet_six_headers_verified=False,
        online_acceptance_verified=False,Android_execution=False,
        native_memory_used_as_python_model_input=False,physical_PAC_authentication_verified=False)


def run(path:Path,libc:Path) -> dict:
    parent = prior_evidence()
    p = previous.previous.callback_prefix.module_prefix()
    p.digest.verify_images(path,libc)
    assert sha256(path) == parent['input_provenance']['Metasec_sha256']
    assert sha256(libc) == parent['input_provenance']['Bionic_sha256']
    def create(control):
        scenario=ScopeCyclesScenario(control);scenario.path=path;scenario.continue_to_svc=True;return scenario
    rows=p.digest.context.replay(path,libc,case_controls=[p.CONTROL],_extension_factory=create,
        _request_profile=p.digest.previous.previous.name.previous.previous.PROFILE['name'],
        _handler_read_profile=p.digest.context.NULL_PAYLOAD_READ_PROFILE['name'])
    assert len(rows)==1
    return dict(schema=SCHEMA,claims=claims_for(),input_provenance=provenance(parent),
                source_fingerprints=source_fingerprints(),case_result=rows[0])


def validate(data:dict) -> None:
    parent=prior_evidence();old=parent['case_result']
    assert data['schema']==SCHEMA and data['claims']==claims_for()
    assert data['input_provenance']==provenance(parent)
    assert data['source_fingerprints']==source_fingerprints()
    row=data['case_result']
    assert row['control']==old['control']
    assert row['retained_prefix']==dict(callbacks_verified=8,
        instruction_observations=old['instruction_observations'],
        instruction_trace_sha256=old['instruction_trace_sha256'],
        observed_code_sha256=old['observed_code_sha256'],allocation_prefix_preserved=True)
    assert row['instruction_observations']==18689 < previous.MAX_OBSERVATIONS
    assert row['first_pc_offsets'][0]==row['tail_pc_offsets'][-1]==hex(VM_RESUME)
    for key in ('instruction_trace_sha256','observed_code_sha256','allocator_events_sha256'):
        assert len(row[key])==64 and len(bytes.fromhex(row[key]))==32
    assert len(row['callbacks'])==len(SPECS)
    scope_open=True;pairs=0
    for i,(call,spec) in enumerate(zip(row['callbacks'],SPECS)):
        wrapper,target,descriptor_hash,start,end,cursor=spec
        assert call['ordinal']==i and call['callsite_offset']==hex(CALLSITE)
        assert call['call_instruction_bytes']=='00013fd6'
        assert call['wrapper_offset']==hex(wrapper) and call['target_offset']==hex(target)
        assert call['call_observation_index']==start and call['return_observation_index']==end
        assert call['VM_cursor_offset']==hex(cursor)
        before=bytes.fromhex(call['descriptor_before_hex']);after=bytes.fromhex(call['descriptor_after_hex'])
        assert len(before)==len(after)==32 and before==after
        assert raw_hash(before)==call['descriptor_before_sha256']==descriptor_hash
        assert raw_hash(after)==call['descriptor_after_sha256']
        words=[int.from_bytes(before[j:j+8],'little') for j in range(0,32,8)]
        assert call['descriptor_words']==[hex(w) for w in words]
        assert words[0]==old['control']['base']+target
        args={'x0':hex(words[1])}
        if target==ENTER:args['x1']=hex(words[2])
        elif target==GETTER:args={'x0':hex(words[2]),'x8':hex(words[1])}
        assert call['target_arguments']==args
        assert call['target_return_offset']==hex(0x28869C if target==GETTER else VM_RESUME)
        assert call['wrapper_path']==[hex(a) for a in range(wrapper,wrapper+len(bytes.fromhex(WRAPPERS[wrapper])),4)]
        assert call['returned_x0']=='0x0' and call['reader_count']==0
        assert call['return_offset']==hex(VM_RESUME)
        assert type(call['target_body_observations']) is int and call['target_body_observations']>0
        for key in ('wrapper_code_verified','target_entered','argument_binding_verified',
                    'descriptor_preserved','stack_pointer_restored','callee_saved_registers_restored','callback_returned'):
            assert call[key] is True,(i,key)
        if target in (ENTER,LEAVE):
            scope=call['scope']
            assert scope['address']==row['scope_summary']['scope_address']==hex(words[1])
            obj_before=bytes.fromhex(scope['object_before_hex']);obj_after=bytes.fromhex(scope['object_after_hex'])
            entry_before=bytes.fromhex(scope['entry_before_hex']);entry_after=bytes.fromhex(scope['entry_after_hex'])
            assert len(obj_before)==len(obj_after)==24 and len(entry_before)==len(entry_after)==48
            input_word=words[2] if target==ENTER else int.from_bytes(obj_before[16:],'little')
            assert scope['input_word']==hex(input_word) and scope['table_index']==(input_word>>4)&255
            assert scope['entry_before_sha256']==raw_hash(entry_before)
            assert scope['entry_after_sha256']==raw_hash(entry_after)
            assert scope['object_after_sha256']==raw_hash(obj_after)
            expected_object=bytearray(obj_before);expected_entry=bytearray(entry_before)
            if target==ENTER:
                assert not scope_open;scope_open=True
                expected_object[:8]=(old['control']['base']+0x35D410).to_bytes(8,'little')
                expected_object[8:12]=bytes(4);expected_object[16:]=input_word.to_bytes(8,'little')
            else:
                assert scope_open;scope_open=False
                pairs+=int(i!=0)
            assert entry_before[8:16].hex()==(UNLOCKED if target==ENTER else LOCKED)
            expected_entry[8:16]=bytes.fromhex(LOCKED if target==ENTER else UNLOCKED)
            assert obj_after==expected_object and entry_after==expected_entry
            assert call['mutex_events']==[dict(kind='pthread_mutex_lock' if target==ENTER else 'pthread_mutex_unlock',
                callsite_offset='0x347f00' if target==ENTER else '0x347f10',
                mutex_address=hex(int(scope['selected_entry'],16)+8))]
            for key in ('object_update_and_padding_verified','selected_mutex_transition_verified','entry_bytes_outside_mutex_preserved'):
                assert scope[key] is True
        else:
            assert not scope_open
            assert len(bytes.fromhex(call['getter_output_before_hex']))==16
            output=bytes.fromhex(call['getter_output_after_hex'])
            assert len(output)==16 and raw_hash(output)==call['getter_output_after_sha256']
    assert not scope_open and pairs==7
    summary=row['scope_summary']
    assert summary['previous_pending_scope_cleaned'] is True
    assert summary['new_scope_pairs_completed']==7 and summary['observed_scope_open'] is False
    assert summary['table_bytes_preserved'] is True
    assert len(summary['table_sha256'])==64 and len(bytes.fromhex(summary['table_sha256']))==32
    assert row['new_allocator_events']==[] and row['allocator_delta']==dict(flush=0,free=0,gc=0,malloc=0)
    for stem in ('allocator_counts',*previous.LEDGERS,'late_jni_calls','java_dispatch'):
        assert row[stem+'_before']==old[stem+'_after']==row[stem+'_after'],stem
    assert row['stop_boundary']==dict(kind='sixteenth_scope_cycle_callback_return_before_vm_resume',
        stop_before=hex(VM_RESUME),next_vm_instruction_executed=False)


def damaged_evidence_rejected(data:dict) -> int:
    changes=[
        (('claims','complete_standalone_signer_verified'),True),
        (('claims','previous_pending_scope_cleanup_verified'),False),
        (('input_provenance','Metasec_sha256'),'0'*64),
        (('source_fingerprints','scope_cycles_verifier_sha256'),'0'*64),
        (('case_result','retained_prefix','callbacks_verified'),7),
        (('case_result','instruction_observations'),0),
        (('case_result','scope_summary','observed_scope_open'),True),
        (('case_result','scope_summary','new_scope_pairs_completed'),6),
        (('case_result','new_allocator_events'),[['alloc',1,0,'0x0']]),
        (('case_result','allocator_counts_after','malloc'),561),
        (('case_result','service_counts_after','syscall_169'),2),
        (('case_result','jni_calls_after'),[]),
        (('case_result','late_jni_calls_after'),[]),
        (('case_result','libc_svc_after'),[]),
        (('case_result','main_svc_after'),[]),
        (('case_result','java_dispatch_after'),[{}]),
        (('case_result','stop_boundary','next_vm_instruction_executed'),True)]
    for i,spec in enumerate(SPECS):
        for key,value in (('target_offset','0x0'),('descriptor_before_sha256','0'*64),
            ('wrapper_path',[]),('target_arguments',{}),('VM_cursor_offset','0x0'),
            ('return_observation_index',0),('returned_x0','0x1'),('reader_count',1),
            ('stack_pointer_restored',False),('callback_returned',False)):
            changes.append((('case_result','callbacks',i,key),value))
        if spec[1] in (ENTER,LEAVE):
            changes.append((('case_result','callbacks',i,'scope','entry_after_hex'),'00'*48))
            changes.append((('case_result','callbacks',i,'scope','object_after_hex'),'00'*24))
    for path,value in changes:
        bad=deepcopy(data);obj=bad
        for key in path[:-1]:obj=obj[key]
        obj[path[-1]]=value
        try:validate(bad)
        except (AssertionError,KeyError,TypeError,ValueError):continue
        raise AssertionError(f'damaged scope-cycle evidence accepted: {path}')
    return len(changes)


def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf',type=Path);parser.add_argument('--libc',type=Path)
    mode=parser.add_mutually_exclusive_group()
    mode.add_argument('--capture',action='store_true');mode.add_argument('--replay',action='store_true')
    args=parser.parse_args()
    if (args.capture or args.replay) and (not args.elf or not args.libc):
        parser.error('--capture/--replay require --elf and --libc')
    if args.capture:
        if EVIDENCE.exists():parser.error('refusing to overwrite frozen scope-cycle evidence')
        data=run(args.elf,args.libc);validate(data);rejected=damaged_evidence_rejected(data)
        with EVIDENCE.open('x',encoding='utf-8',newline='\n') as f:
            f.write(json.dumps(data,ensure_ascii=False,indent=2)+'\n')
    else:
        data=json.loads(EVIDENCE.read_text(encoding='utf-8'))
        validate(data);rejected=damaged_evidence_rejected(data)
        if args.replay:assert run(args.elf,args.libc)==data,'fresh scope-cycle replay differs'
    row=data['case_result']
    print(json.dumps(dict(schema=SCHEMA,damaged_evidence_rejected=rejected,
        returned_callbacks=len(row['callbacks']),instruction_observations=row['instruction_observations'],
        previous_pending_scope_cleaned=True,new_scope_pairs_completed=7,
        allocator_delta=row['allocator_delta'],current_native_suffix_return_verified=False,
        complete_standalone_signer_verified=False)))


if __name__=='__main__':
    main()
