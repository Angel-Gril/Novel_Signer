"""Replay the bounded configuration continuation after closed diagnostic scopes."""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from unicorn import arm64_const as arm

import verify_vm9_native_171_post_reader_scope_cycles_dynamic_20261122 as previous
import verify_vm9_native_171_resolve_next_vm_callback_dynamic_20261121 as bootstrap

EVIDENCE = previous.EVIDENCE.with_name('vm9_native_171_post_scope_configuration_dynamic_20261122.json')
SCHEMA = 'vm9-native-171-post-scope-configuration-dynamic-20261122-v1'
VM_RESUME = previous.VM_RESUME
CALLSITE = previous.CALLSITE
MAX_OBSERVATIONS = 400000
# wrapper, target, descriptor first-32-byte hash, call/return index, cursor, X0.
SPECS = (
    (0x2886B0, 0x1CF55C, 'e08d334293b81e1defa1759ec0fbc4ba5a768e779ddcff79b8d892437121e4c9', 898, 3666, 0x10769C, 0),
    (0x2884EC, 0x32D3A0, '941115d58a0507632c0a4429fb7f0523f65e4bb5ad731f545cc1e03e92ee47ac', 6060, 6155, 0x107B24, 1),
    (0x2884B8, 0x167E54, '837bdfa79975dc71c0a59c83e93ee49c9d087ac5f8d86891787bf607f333f7a4', 8018, 8093, 0x107B94, 0x123BFF60),
    (0x2886FC, 0x256330, '1ae30382e7d4c683dfdd690787d1ce7be72dd937beb5a9ff9ea282bad4d40c10', 10146, 10166, 0x107D54, 0x1269E4D4),
    (0x2884B8, 0x167E54, 'b5af82635c22f776a82e0600cf37cda5f2fe6a15429a414d6400f494f5cc0a9d', 11387, 11454, 0x107D9C, 0x123BFD34),
    (0x288718, 0x2781F4, '817945ce235a8e68477051d70424029882a77d8b8d376314800741f46b8433de', 12873, 13887, 0x107DE4, 0x14),
    (0x28854C, 0x32D4F8, '780264b175924bbc1f18fe056bffe3d157b13eb6d5b3f251277cf524966e49c9', 14800, 14872, 0x107E18, 0),
    (0x2884D8, 0x347F60, '6f72731715f4c60030999094aa7235295f92c1b86b0906e7754a70324046801e', 16944, 16951, 0x107E90, 0x7004CF08),
    (0x2884D8, 0x347F60, '89ac9f641a731c323f379b22bf03bccefe25c9eb9b3047006136e61a4cddf195', 18272, 18279, 0x107ED4, 0x7004CF28),
    (0x2884D8, 0x347F60, 'e30be8f93b1584dca4fd21e998ffb1309c543eecd79feb88fb32c40e9ba76f34', 19364, 19371, 0x107F0C, 0x7004CF38),
    (0x2884D8, 0x347F60, '22985fb4be1fb8d952d7e621f3c96867f42cf6e3f4929252a1528c555e907dfb', 20356, 20363, 0x107F40, 0x7004D028),
    (0x2885D0, 0x248344, '14eb13f806bba8d0b046125852abee6fdc619d670c805b9bd33de86adba14aa5', 21479, 22070, 0x1080BC, 0x136D3FC0),
    (0x28874C, 0x256A18, '22ac9a4d7fb7f41d42f8aa30482a1528bc1b9d4788a7027d839d5300190fa867', 22738, 23847, 0x1080E0, 1),
    (0x2884CC, 0x2484B8, '01ab59204811b97d85fc7d181c287ed428611569ae6c748701694518db32744c', 24520, 24673, 0x108104, 0x136C2680),
    (0x2885D0, 0x248344, '56e47b38cd225cf6efe008c75d1235c8a87a913a120aff3d61b86a9db771f8af', 25877, 26033, 0x10828C, 0x136D3FC0),
    (0x28874C, 0x256A18, '4d165efa4a986efdda9a4be129240ca3d8ad2346b9b272b7b5fc263c185b4a7e', 26647, 27172, 0x1082AC, 0xA985F),
    (0x2884CC, 0x2484B8, '01ab59204811b97d85fc7d181c287ed428611569ae6c748701694518db32744c', 27845, 27998, 0x1082D0, 0x136C2680),
    (0x2885D0, 0x248344, 'f066d71af7ae0f06d8be954dbd955b65d166664ef4f84a25189b2525f08c6d21', 29114, 29270, 0x108454, 0x136D3FC0),
    (0x28874C, 0x256A18, '38eea81128b98ef8616867a3b290f82f7cdef15052673ac8f5d5b4ba99313084', 29884, 30409, 0x108474, 0xA985F),
    (0x2884CC, 0x2484B8, '01ab59204811b97d85fc7d181c287ed428611569ae6c748701694518db32744c', 31082, 31235, 0x108498, 0x136C2680),
    (0x2885D0, 0x248344, 'acce50922458a2ccc8d8166e9911920a65ae875283f6555f045f36db8ef304f1', 32447, 32603, 0x108624, 0x136D3FC0),
    (0x28874C, 0x256A18, '38eea81128b98ef8616867a3b290f82f7cdef15052673ac8f5d5b4ba99313084', 33217, 33760, 0x108644, 0xA985F),
    (0x2884CC, 0x2484B8, '01ab59204811b97d85fc7d181c287ed428611569ae6c748701694518db32744c', 34433, 34586, 0x108668, 0x136C2680),
    (0x2885D0, 0x248344, '41e3c423bfac7ca84712ef2c81038065c157fdea8e41fc0f092d8a781212fc12', 35648, 35804, 0x1087EC, 0x136D3FC0),
    (0x28874C, 0x256A18, '38eea81128b98ef8616867a3b290f82f7cdef15052673ac8f5d5b4ba99313084', 36418, 36943, 0x10880C, 0xA985F),
    (0x2884CC, 0x2484B8, '01ab59204811b97d85fc7d181c287ed428611569ae6c748701694518db32744c', 37616, 37769, 0x108830, 0x136C2680),
    (0x2884D8, 0x347F60, '9d2b117bbc52476996fda990e3b8104dca4cc9b05320a556eea5f6abe0dda740', 38612, 38619, 0x10885C, 0x7004D058),
    (0x2885D0, 0x248344, '80a79022c20433eb065bb63195570f5dd62f25a47f50a79a05ed8af7147a0bc2', 39681, 39837, 0x1089D8, 0x136D3FC0),
    (0x28874C, 0x256A18, '38eea81128b98ef8616867a3b290f82f7cdef15052673ac8f5d5b4ba99313084', 40451, 41578, 0x1089F8, 0),
    (0x2884CC, 0x2484B8, '01ab59204811b97d85fc7d181c287ed428611569ae6c748701694518db32744c', 42258, 42411, 0x108A1C, 0x136C2680),
    (0x2885D0, 0x248344, 'dd1daa012b87c57976d5283d4c09f2c312a9a0c0c630f78e647ad57a94fabc04', 43473, 43629, 0x108B98, 0x136D3FC0),
    (0x28874C, 0x256A18, 'e328fb2871f0f1241aea1c9d3c6769955eae5f5160f144e8d2a1bec569f30d77', 44243, 45352, 0x108BB8, 0),
)
WRAPPERS = {
    0x2886B0: 'fe0f1ff8092040a920013fd6fe0741f8c0035fd6',
    0x2884EC: 'fe4fbfa9f30300aa080040a900013fd6601200b9fe4fc1a8c0035fd6',
    0x2884B8: '088440a9020c40f9030040f9e00308aa60001fd6',
    0x2886FC: 'fe4fbfa9f30300aa080040a900013fd6600a00f9fe4fc1a8c0035fd6',
    0x288718: 'fe4fbfa9f30300aa080040a9610a41a9631242a9651a40f900013fd6603a00b9fe4fc1a8c0035fd6',
    0x28854C: '012040a9e00308aa20001fd6',
    0x2884D8: '088440a9020c40f9030040f9e00308aa60001fd6',
    0x2885D0: '088440a9020040f9e00308aa40001fd6',
    0x28874C: 'fe4fbfa9f30300aa080040a9610a40f900013fd6601a00b9fe4fc1a8c0035fd6',
    0x2884CC: '012040a9e00308aa20001fd6',
}
TARGET_RETURNS = {0x2886B0: 0x2886BC, 0x2884EC: 0x2884FC, 0x2886FC: 0x28870C,
                  0x288718: 0x288734, 0x28874C: 0x288760}
OUTPUT_STORES = {0x2884EC: (16, 4), 0x2886FC: (16, 8),
                 0x288718: (56, 4), 0x28874C: (24, 4)}
EVENTS_SHA256 = '19825454a97c5ed3a8bec48ee838661c86ac474bc60c9b48be20c4a978feea2b'
ALLOCATION_SIZES = [4, 24, 8, 48, 4, 33, 33, 33, 33, 33, 33, 33]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def raw_hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def prior_evidence() -> dict:
    data = json.loads(previous.EVIDENCE.read_text(encoding='utf-8'))
    previous.validate(data)
    return data


def source_fingerprints() -> dict:
    return dict(configuration_verifier_sha256=sha256(Path(__file__)),
                inherited_source_fingerprints=previous.source_fingerprints())


def provenance(parent: dict) -> dict:
    return dict(inherited_scope_cycles_evidence_sha256=sha256(previous.EVIDENCE),
        Metasec_sha256=parent['input_provenance']['Metasec_sha256'],
        Bionic_sha256=parent['input_provenance']['Bionic_sha256'])


def arguments_for(wrapper: int, words: list[int], descriptor: int) -> dict:
    args = {0: words[1]}
    if wrapper == 0x2886B0:
        args = {0: descriptor, 8: words[1]}
    elif wrapper in (0x2884B8, 0x2884D8):
        args.update({1: words[2], 2: words[3]})
    elif wrapper in (0x2885D0, 0x28874C):
        args[1] = words[2]
    elif wrapper == 0x288718:
        args.update({i: words[i+1] for i in range(1, 6)})
    return {f'x{n}': hex(v) for n, v in args.items()}


def expected_descriptor_after(wrapper: int, before: bytes, returned: int) -> bytes:
    result = bytearray(before)
    if wrapper in OUTPUT_STORES:
        offset, width = OUTPUT_STORES[wrapper]
        result[offset:offset+width] = (returned & ((1 << (width*8))-1)).to_bytes(width, 'little')
    return bytes(result)


def providers() -> dict:
    return dict(memory_imports='inherited explicit memcpy/memmove provider; no native Bionic memcpy-body claim',
        java_dispatch='inherited explicit NULL-result provider; no ART/JVM execution',
        OS_JNI='inherited synthetic services, unchanged provider implementation',
        allocations='matching Bionic with inherited allocator observation',
        maximum_instruction_observations=MAX_OBSERVATIONS)


class ConfigurationScenario(previous.ScopeCyclesScenario):
    def __init__(self, control):
        super().__init__(control)
        self._config_active = False
        self._config_done = False
        self._config_count = 0
        self._config_trace = hashlib.sha256()
        self._config_code = {}
        self._config_first = []
        self._config_tail = []
        self._config_calls = []
        self._config_call = None
        self._config_parent = None
        self._config_events_before = None
        self._config_state = None
        self._config_descriptor = None
        self._config_words = None
        self._config_sp = None
        self._config_regs = None
        self._copy_source_before = None

    def _observe_config_pc(self, cpu, pc):
        offset = pc-self.image
        self._config_count += 1
        assert self._config_count < MAX_OBSERVATIONS
        raw = bytes(cpu.mem_read(pc, 4))
        self._config_trace.update(offset.to_bytes(8, 'little', signed=True)+raw)
        self._config_code[hex(offset)] = raw.hex()
        if len(self._config_first) < 16:
            self._config_first.append(hex(offset))
        self._config_tail = (self._config_tail+[hex(offset)])[-16:]

    def _return_cycle_call(self, cpu):
        super()._return_cycle_call(cpu)
        if not self._cycles_done:
            return
        old = prior_evidence()['case_result']
        assert self._cycles_calls == old['callbacks']
        assert self._cycles_count == old['instruction_observations']
        assert self._cycles_trace.hexdigest() == old['instruction_trace_sha256']
        assert previous.previous.digest(self._cycles_code) == old['observed_code_sha256']
        assert self._cycles_first == old['first_pc_offsets']
        assert self._cycles_tail == old['tail_pc_offsets']
        assert not self._cycles_scope_open and self._cycles_pairs == 7
        assert bytes(cpu.mem_read(self._cycles_table_address, previous.TABLE_SIZE)) == self._cycles_table_before
        events = self._config_state['allocator_events_ref']
        assert events == self._cycles_allocator_before
        assert previous.previous.digest(events) == old['allocator_events_sha256']
        assert self.late_jni_calls == old['late_jni_calls_after']
        assert self.java_dispatch_calls == old['java_dispatch_after']
        self._config_parent = dict(callbacks_verified=16,
            instruction_observations=self._cycles_count,
            instruction_trace_sha256=self._cycles_trace.hexdigest(),
            observed_code_sha256=previous.previous.digest(self._cycles_code),
            allocator_events_sha256=previous.previous.digest(events), observed_scope_closed=True)
        self._config_events_before = deepcopy(events)
        self._config_active = True
        self._cycles_done = False
        self._observe_config_pc(cpu, cpu.reg_read(arm.UC_ARM64_REG_PC))

    def _start_config_call(self, cpu, pc):
        assert self._config_call is None and len(self._config_calls) < len(SPECS)
        wrapper, target, expected_hash, start, _, cursor, _ = SPECS[len(self._config_calls)]
        assert self._config_count == start
        assert bytes(cpu.mem_read(pc, 4)).hex() == '00013fd6'
        assert self._reg(cpu, 8) == self.image+wrapper
        self._config_descriptor = self._reg(cpu, 0)
        size = 64 if wrapper == 0x288718 else 32
        assert any(a <= self._config_descriptor and self._config_descriptor+size <= b
                   for a, b, _ in cpu.mem_regions())
        raw = bytes(cpu.mem_read(self._config_descriptor, size))
        self._config_words = [int.from_bytes(raw[i:i+8], 'little') for i in range(0, size, 8)]
        assert self._config_words[0] == self.image+target
        assert raw_hash(raw[:32]) == expected_hash
        assert self._u(cpu, self._reg(cpu, 19)) == self.image+cursor
        self._config_sp = cpu.reg_read(arm.UC_ARM64_REG_SP)
        self._config_regs = [self._reg(cpu, n) for n in range(19, 30)]
        self._config_call = dict(ordinal=len(self._config_calls),
            callsite_offset=hex(CALLSITE), call_instruction_bytes='00013fd6',
            wrapper_offset=hex(wrapper), target_offset=hex(target),
            VM_cursor_offset=hex(cursor), call_observation_index=start,
            descriptor_address=hex(self._config_descriptor), descriptor_observed_size=size,
            descriptor_before_hex=raw.hex(), descriptor_first32_sha256=raw_hash(raw[:32]),
            descriptor_words=[hex(w) for w in self._config_words], wrapper_path=[],
            wrapper_code_verified=False, target_entered=False, target_observations=0,
            target_execution_kind='inherited_memcpy_provider' if target == 0x347F60 else 'native_instructions')
        if target == 0x347F60:
            destination, source, length = self._config_words[1:4]
            assert length in (16, 48, 192)
            self._copy_source_before = bytes(cpu.mem_read(source, length))
            self._config_call['copy'] = dict(destination=hex(destination), source=hex(source), length=length,
                source_before_sha256=raw_hash(self._copy_source_before),
                destination_before_sha256=raw_hash(bytes(cpu.mem_read(destination, length))))

    def _enter_config_target(self, cpu):
        call = self._config_call
        wrapper = int(call['wrapper_offset'], 16)
        expected = arguments_for(wrapper, self._config_words, self._config_descriptor)
        for reg, value in expected.items():
            assert self._reg(cpu, int(reg[1:])) == int(value, 16), (reg, value)
        target_return = TARGET_RETURNS.get(wrapper, VM_RESUME)
        assert self._reg(cpu, 30) == self.image+target_return
        call.update(target_entered=True, target_arguments=expected,
                    argument_binding_verified=True, target_return_offset=hex(target_return))

    def _return_config_call(self, cpu):
        call = self._config_call
        wrapper, target, _, _, end, _, returned = SPECS[len(self._config_calls)]
        assert call['target_entered'] and call['argument_binding_verified']
        assert self._config_count == end and self._reg(cpu, 0) == returned
        assert cpu.reg_read(arm.UC_ARM64_REG_SP) == self._config_sp
        assert [self._reg(cpu, n) for n in range(19, 30)] == self._config_regs
        assert call['wrapper_path'] == [hex(a) for a in range(wrapper, wrapper+len(bytes.fromhex(WRAPPERS[wrapper])), 4)]
        before = bytes.fromhex(call['descriptor_before_hex'])
        after = bytes(cpu.mem_read(self._config_descriptor, len(before)))
        assert after == expected_descriptor_after(wrapper, before, returned)
        assert self._u(cpu, self._receiver+0x88, 4) == 0
        if target == 0x347F60:
            copy = call['copy']
            source_after = bytes(cpu.mem_read(int(copy['source'],16), copy['length']))
            destination_after = bytes(cpu.mem_read(int(copy['destination'],16), copy['length']))
            assert destination_after == source_after == self._copy_source_before
            copy.update(source_after_sha256=raw_hash(source_after),
                destination_after_sha256=raw_hash(destination_after),
                copied_bytes_match=True, source_bytes_preserved=True)
        call.update(return_observation_index=end, returned_x0=hex(returned), reader_count=0,
            descriptor_after_hex=after.hex(), descriptor_after_sha256=raw_hash(after),
            descriptor_output_and_padding_verified=True, return_offset=hex(VM_RESUME),
            stack_pointer_restored=True, callee_saved_registers_restored=True, callback_returned=True)
        self._config_calls.append(call)
        self._config_call = None
        self._config_done = len(self._config_calls) == len(SPECS)

    def observe(self, cpu, pc, state):
        self._config_state = state
        if not self._config_active:
            return super().observe(cpu, pc, state)
        offset = pc-self.image
        self._observe_config_pc(cpu, pc)
        if offset == CALLSITE:
            self._start_config_call(cpu, pc)
        call = self._config_call
        if call is not None:
            wrapper = int(call['wrapper_offset'],16)
            if offset == wrapper:
                assert bytes(cpu.mem_read(pc,len(bytes.fromhex(WRAPPERS[wrapper])))).hex() == WRAPPERS[wrapper]
                call['wrapper_code_verified'] = True
            if wrapper <= offset < wrapper+len(bytes.fromhex(WRAPPERS[wrapper])):
                call['wrapper_path'].append(hex(offset))
            if offset == int(call['target_offset'],16) and not call['target_entered']:
                self._enter_config_target(cpu)
            if call['target_entered']:
                call['target_observations'] += 1
                if offset == VM_RESUME:
                    self._return_config_call(cpu)
        self._base_observe(cpu, pc, state)
        if self._config_done:
            cpu.emu_stop()
            cpu.reg_write(arm.UC_ARM64_REG_PC, bootstrap.module_prefix().digest.context.outer.oracle.STOP)

    def finish(self, result, state, proof):
        assert self._config_done and self._config_call is None
        old = prior_evidence()['case_result']
        prefix = self._config_events_before
        events = result['allocator_events']
        assert events[:len(prefix)] == prefix
        added = events[len(prefix):]
        assert previous.previous.digest(added) == EVENTS_SHA256
        return dict(control=old['control'], retained_prefix=self._config_parent,
            instruction_observations=self._config_count,
            instruction_trace_sha256=self._config_trace.hexdigest(),
            observed_code_sha256=previous.previous.digest(self._config_code),
            first_pc_offsets=self._config_first, tail_pc_offsets=self._config_tail,
            callbacks=self._config_calls,
            allocator_counts_before=old['allocator_counts_after'], allocator_counts_after=result['actual_allocator_counts'],
            allocator_delta=previous.previous.previous._delta(old['allocator_counts_after'],result['actual_allocator_counts']),
            new_allocator_events=added, new_allocator_events_sha256=previous.previous.digest(added),
            service_counts_before=old['service_counts_after'], service_counts_after=result['explicit_service_counts'],
            service_delta=previous.previous.previous._delta(old['service_counts_after'],result['explicit_service_counts']),
            jni_calls_before=old['jni_calls_after'], jni_calls_after=proof['JNI_calls'],
            libc_svc_before=old['libc_svc_after'], libc_svc_after=proof['libc_SVC_boundaries'],
            main_svc_before=old['main_svc_after'], main_svc_after=proof['main_image_SVC_boundaries'],
            late_jni_calls_before=old['late_jni_calls_after'], late_jni_calls_after=self.late_jni_calls,
            java_dispatch_before=old['java_dispatch_after'], java_dispatch_after=self.java_dispatch_calls,
            stop_boundary=dict(kind='thirty_second_configuration_callback_return_before_vm_resume',
                stop_before=hex(VM_RESUME), next_vm_instruction_executed=False))


def claims_for() -> dict:
    return dict(evidence_label='Sample verified', returned_callbacks=32,
        wrapper_descriptors_arguments_and_output_padding_verified=True,
        callback_SP_and_saved_registers_restored=True, copied_byte_ranges_verified=5,
        all_callback_targets_executed_as_native_code=False,
        native_Bionic_memcpy_body_verified=False, real_JVM_execution_verified=False,
        java_dispatch_uses_existing_NULL_result_provider=True,
        allocator_malloc_delta=12, allocator_free_delta=7, destructor_registration_delta=1,
        JNI_and_SVC_ledgers_unchanged=True, next_vm_instruction_executed=False,
        current_native_suffix_return_verified=False, complete_standalone_signer_verified=False,
        ordinary_Cronet_six_headers_verified=False, online_acceptance_verified=False,
        Android_execution=False, native_memory_used_as_python_model_input=False,
        physical_PAC_authentication_verified=False)


def run(path: Path, libc: Path) -> dict:
    parent = prior_evidence()
    p = bootstrap.module_prefix()
    p.digest.verify_images(path,libc)
    assert sha256(path) == parent['input_provenance']['Metasec_sha256']
    assert sha256(libc) == parent['input_provenance']['Bionic_sha256']
    def create(control):
        s=ConfigurationScenario(control);s.path=path;s.continue_to_svc=True;return s
    rows=p.digest.context.replay(path,libc,case_controls=[p.CONTROL],_extension_factory=create,
        _request_profile=p.digest.previous.previous.name.previous.previous.PROFILE['name'],
        _handler_read_profile=p.digest.context.NULL_PAYLOAD_READ_PROFILE['name'])
    assert len(rows)==1
    return dict(schema=SCHEMA, claims=claims_for(), providers=providers(),
        input_provenance=provenance(parent), source_fingerprints=source_fingerprints(), case_result=rows[0])


def validate(data: dict) -> None:
    parent=prior_evidence();old=parent['case_result']
    assert data['schema']==SCHEMA and data['claims']==claims_for()
    assert data['providers']==providers() and data['input_provenance']==provenance(parent)
    assert data['source_fingerprints']==source_fingerprints()
    row=data['case_result']
    assert row['control']==old['control']
    assert row['retained_prefix']==dict(callbacks_verified=16,
        instruction_observations=old['instruction_observations'], instruction_trace_sha256=old['instruction_trace_sha256'],
        observed_code_sha256=old['observed_code_sha256'], allocator_events_sha256=old['allocator_events_sha256'],
        observed_scope_closed=True)
    assert row['instruction_observations']==45352 < MAX_OBSERVATIONS
    assert row['first_pc_offsets'][0]==row['tail_pc_offsets'][-1]==hex(VM_RESUME)
    for key in ('instruction_trace_sha256','observed_code_sha256'):
        assert len(row[key])==64 and len(bytes.fromhex(row[key]))==32
    assert len(row['callbacks'])==len(SPECS)
    copies=[]
    for i,(call,spec) in enumerate(zip(row['callbacks'],SPECS)):
        wrapper,target,descriptor_hash,start,end,cursor,returned=spec
        assert call['ordinal']==i and call['callsite_offset']==hex(CALLSITE)
        assert call['call_instruction_bytes']=='00013fd6'
        assert call['wrapper_offset']==hex(wrapper) and call['target_offset']==hex(target)
        assert call['VM_cursor_offset']==hex(cursor)
        assert call['call_observation_index']==start and call['return_observation_index']==end
        raw=bytes.fromhex(call['descriptor_before_hex']);after=bytes.fromhex(call['descriptor_after_hex'])
        assert len(raw)==len(after)==call['descriptor_observed_size']==(64 if wrapper==0x288718 else 32)
        assert raw_hash(raw[:32])==call['descriptor_first32_sha256']==descriptor_hash
        assert after==expected_descriptor_after(wrapper,raw,returned) and raw_hash(after)==call['descriptor_after_sha256']
        words=[int.from_bytes(raw[j:j+8],'little') for j in range(0,len(raw),8)]
        assert call['descriptor_words']==[hex(w) for w in words] and words[0]==old['control']['base']+target
        assert call['target_arguments']==arguments_for(wrapper,words,int(call['descriptor_address'],16))
        assert call['target_return_offset']==hex(TARGET_RETURNS.get(wrapper,VM_RESUME))
        assert call['target_execution_kind']==('inherited_memcpy_provider' if target==0x347F60 else 'native_instructions')
        assert call['wrapper_path']==[hex(a) for a in range(wrapper,wrapper+len(bytes.fromhex(WRAPPERS[wrapper])),4)]
        assert call['returned_x0']==hex(returned) and call['reader_count']==0 and call['return_offset']==hex(VM_RESUME)
        assert type(call['target_observations']) is int and call['target_observations']>0
        for key in ('wrapper_code_verified','target_entered','argument_binding_verified',
            'descriptor_output_and_padding_verified','stack_pointer_restored','callee_saved_registers_restored','callback_returned'):
            assert call[key] is True,(i,key)
        if target==0x347F60:
            copy=call['copy'];copies.append(copy)
            assert copy['destination']==hex(words[1]) and copy['source']==hex(words[2]) and copy['length']==words[3]
            assert copy['copied_bytes_match'] is True and copy['source_bytes_preserved'] is True
            assert copy['source_before_sha256']==copy['source_after_sha256']==copy['destination_after_sha256']
            for key in ('source_before_sha256','destination_before_sha256'):
                assert len(copy[key])==64 and len(bytes.fromhex(copy[key]))==32
    assert [c['length'] for c in copies]==[16,16,16,48,192]
    assert row['allocator_counts_before']==old['allocator_counts_after']
    expected=dict(row['allocator_counts_before']);expected['malloc']+=12;expected['free']+=7
    assert row['allocator_counts_after']==expected and row['allocator_delta']==dict(flush=0,free=7,gc=0,malloc=12)
    added=row['new_allocator_events']
    assert row['allocator_counts_before']==old['allocator_counts_after']
    allocator_expected=dict(row['allocator_counts_before'])
    allocator_expected['malloc']+=12
    allocator_expected['free']+=7
    assert row['allocator_counts_after']==allocator_expected
    assert row['allocator_delta']==previous.previous.previous._delta(
        row['allocator_counts_before'],row['allocator_counts_after'])
    assert row['new_allocator_events_sha256']==previous.previous.digest(added)==EVENTS_SHA256
    assert [e[1] for e in added if e[0]=='alloc']==ALLOCATION_SIZES
    assert sum(e[0]=='free' for e in added)==7
    assert row['service_counts_before']==old['service_counts_after']
    expected=dict(row['service_counts_before']);expected['destructor_registration']+=1
    assert row['service_counts_after']==expected
    service_delta=previous.previous.previous._delta(row['service_counts_before'],row['service_counts_after'])
    assert row['service_delta']==service_delta
    assert all(value==int(key=='destructor_registration') for key,value in service_delta.items())
    for stem in ('jni_calls','libc_svc','main_svc','late_jni_calls'):
        assert row[stem+'_before']==old[stem+'_after']==row[stem+'_after'],stem
    assert row['java_dispatch_before']==old['java_dispatch_after']==[]
    assert row['service_delta']=={key:int(key=='destructor_registration') for key in sorted(expected)}
    for stem in ('jni_calls','libc_svc','main_svc','late_jni_calls'):
        assert row[stem+'_before']==old[stem+'_after']==row[stem+'_after']
    assert row['java_dispatch_before']==old['java_dispatch_after']==[]
    dispatch=row['java_dispatch_after']
    assert len(dispatch)==1 and dispatch[0]['arguments']==['0x1000011','0x0','0x0','0x0','0x0']
    assert dispatch[0]['caller']=='0x1cf6c8' and dispatch[0]['entry_sp']=='0x7004b850'
    assert row['stop_boundary']==dict(kind='thirty_second_configuration_callback_return_before_vm_resume',
        stop_before=hex(VM_RESUME),next_vm_instruction_executed=False)


def damaged_evidence_rejected(data: dict) -> int:
    changes=[(('claims','complete_standalone_signer_verified'),True),
        (('claims','all_callback_targets_executed_as_native_code'),True),
        (('claims','real_JVM_execution_verified'),True),
        (('providers','memory_imports'),'native Bionic memcpy'),
        (('input_provenance','Metasec_sha256'),'0'*64),
        (('source_fingerprints','configuration_verifier_sha256'),'0'*64),
        (('case_result','retained_prefix','callbacks_verified'),15),
        (('case_result','instruction_observations'),0),
        (('case_result','new_allocator_events'),[]),
        (('case_result','allocator_counts_after','malloc'),560),
        (('case_result','service_counts_after','destructor_registration'),5),
        (('case_result','allocator_delta','malloc'),0),
        (('case_result','allocator_delta','free'),0),
        (('case_result','service_delta','destructor_registration'),0),
        (('case_result','jni_calls_after'),[]),(('case_result','libc_svc_after'),[]),
        (('case_result','main_svc_after'),[]),(('case_result','late_jni_calls_after'),[]),
        (('case_result','java_dispatch_after'),[]),
        (('case_result','stop_boundary','next_vm_instruction_executed'),True)]
    for i,spec in enumerate(SPECS):
        for key,value in (('target_offset','0x0'),('descriptor_first32_sha256','0'*64),
            ('wrapper_path',[]),('target_arguments',{}),('VM_cursor_offset','0x0'),
            ('return_observation_index',0),('returned_x0','0xdeadbeef'),
            ('reader_count',1),('stack_pointer_restored',False),('callback_returned',False)):
            changes.append((('case_result','callbacks',i,key),value))
        if spec[1]==0x347F60:
            changes.append((('case_result','callbacks',i,'copy','copied_bytes_match'),False))
            changes.append((('case_result','callbacks',i,'copy','destination_after_sha256'),'0'*64))
    for path,value in changes:
        bad=deepcopy(data);obj=bad
        for key in path[:-1]:obj=obj[key]
        obj[path[-1]]=value
        try:validate(bad)
        except (AssertionError,KeyError,TypeError,ValueError):continue
        raise AssertionError(f'damaged configuration continuation evidence accepted: {path}')
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
        if EVIDENCE.exists():parser.error('refusing to overwrite frozen configuration continuation evidence')
        data=run(args.elf,args.libc);validate(data);rejected=damaged_evidence_rejected(data)
        with EVIDENCE.open('x',encoding='utf-8',newline='\n') as f:
            f.write(json.dumps(data,ensure_ascii=False,indent=2)+'\n')
    else:
        data=json.loads(EVIDENCE.read_text(encoding='utf-8'));validate(data);rejected=damaged_evidence_rejected(data)
        if args.replay:assert run(args.elf,args.libc)==data,'fresh configuration continuation replay differs'
    row=data['case_result']
    print(json.dumps(dict(schema=SCHEMA,damaged_evidence_rejected=rejected,
        returned_callbacks=len(row['callbacks']),instruction_observations=row['instruction_observations'],
        allocator_delta=row['allocator_delta'],destructor_registration_delta=row['service_delta']['destructor_registration'],
        synthetic_java_dispatch_count=len(row['java_dispatch_after']),verified_copy_ranges=5,
        current_native_suffix_return_verified=False,complete_standalone_signer_verified=False)))


if __name__=='__main__':
    main()
