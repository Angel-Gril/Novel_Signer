"""Continue the retained request through post-CRC scope release.

Reuses the existing scope model and independent controls. Native execution
starts from the established ELF/Bionic replay, never from this evidence JSON.
Stops before the following VM callback; this is not a standalone signer.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as arm

import verify_vm9_native_171_post_crc_md5_delete_return_dynamic_20261123 as previous
import verify_vm9_native_171_post_diagnostic_scope_leave_return_dynamic_20261123 as scope_controls

EVIDENCE = previous.EVIDENCE.with_name(
    'vm9_native_171_post_crc_scope_leave_return_dynamic_20261123.json')
SCHEMA = 'vm9-native-171-post-crc-scope-leave-return-dynamic-20261123-v1'
VM_CALL, VM_RESUME = previous.VM_CALL, previous.VM_RESUME
WRAPPER, TARGET = 0x288540, 0x26C9D0
LIBC_BASE, UNLOCK = scope_controls.LIBC_BASE, scope_controls.UNLOCK
MAX_OBSERVATIONS = 100000
sha256, raw_hash, digest = previous.sha256, previous.raw_hash, previous.digest
CODE_RANGES = {
    'main': ((VM_CALL, 32), (WRAPPER, 12), (TARGET, 56), (0x347F10, 16)),
    'libc': ((UNLOCK, 376),),
}
CODE_SHA256 = {domain + ':' + hex(off): scope_controls.CODE_SHA256[domain + ':' + hex(off)]
               for domain, ranges in CODE_RANGES.items() for off, size in ranges}


def parent_evidence():
    data = json.loads(previous.EVIDENCE.read_text(encoding='utf-8'))
    previous.validate(data)
    return data


def sources():
    return dict(verifier_sha256=sha256(Path(__file__)),
                parent_sha256=sha256(Path(previous.__file__)),
                parent_chain_sha256=digest(previous.source_fingerprints()),
                scope_controls_sha256=sha256(Path(scope_controls.__file__)),
                scope_control_chain_sha256=digest(scope_controls.source_fingerprints()))


def claims():
    return dict(evidence_label='Sample verified', full_parent_case_result_equal=True,
                original_wrapper_and_scope_leave_returned=True,
                matching_Bionic_unlock_executed=True,
                owner_clear_then_recursive_mutex_postcrc_leave_observed=True,
                scope_fields_omitted_after_return=True,
                released_header_reprotected=True,
                no_new_allocator_or_service_effects=True,
                existing_Python_scope_model_reused=True,
                new_providers_added=False, native_snapshot_used_as_python_model_input=False,
                next_VM_call_executed=False, physical_return_X0_ABI_compared=False,
                standalone_Python_VM_continuation_verified=False,
                complete_VM_suffix_return_verified=False,
                complete_standalone_signer_verified=False,
                real_ART_JVM_execution=False, Android_execution=False,
                physical_PAC_authentication_verified=False, online_acceptance_verified=False)


def providers():
    return dict(inherited_evidence_sha256=sha256(previous.EVIDENCE),
                new_providers=[], new_import_bindings=[],
                unlock='original matching Bionic pthread_mutex_unlock',
                components='existing independent scope fixtures and Python owner; no new model',
                returned_X0='void callback: incidental physical X0 omitted',
                output='code, locations, defined mutex fields, hashes and relations only',
                maximum_instruction_observations=MAX_OBSERVATIONS)


def read_static(path, libc):
    rows = {}
    for domain, image in (('main', path), ('libc', libc)):
        with image.open('rb') as stream:
            elf = ELFFile(stream)
            for off, size in CODE_RANGES[domain]:
                raw = scope_controls.previous.previous.previous.elf_bytes(elf, stream, off, size)
                rows[domain + ':' + hex(off)] = dict(size=size, hex=raw.hex(), sha256=raw_hash(raw))
    assert {key: row['sha256'] for key, row in rows.items()} == CODE_SHA256
    return rows


def next_call(cpu, scenario, index):
    descriptor = scenario._reg(cpu, 0)
    raw = bytes(cpu.mem_read(descriptor, 48))
    wrapper = scenario._reg(cpu, 8)
    code = bytearray()
    for instruction in Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN).disasm(
            bytes(cpu.mem_read(wrapper, 64)), wrapper):
        code.extend(instruction.bytes)
        if instruction.mnemonic in ('br', 'ret'):
            break
    else:
        raise AssertionError('unbounded next wrapper')
    return dict(index=index, callsite_offset=hex(VM_CALL),
                VM_cursor_offset=hex(scenario._u(cpu, scenario._postalloc_vmstate) - scenario.image),
                descriptor_address=hex(descriptor), descriptor_width=48,
                descriptor_sha256=raw_hash(raw), wrapper_offset=hex(wrapper - scenario.image),
                target_offset=hex(int.from_bytes(raw[:8], 'little') - scenario.image),
                wrapper_code_hex=code.hex(), wrapper_code_sha256=raw_hash(code),
                VM_call_executed=False, wrapper_executed=False, target_executed=False)


class PostCRCScopeLeaveScenario(previous.PostCRCDeletingMD5Scenario):
    def __init__(self, control):
        super().__init__(control)
        self._postcrc_leave_active = False
        self._postcrc_leave_returned = False
        self._postcrc_leave_done = False
        self._postcrc_leave_sites, self._postcrc_leave_code = [], {}
        self._postcrc_leave_rows, self._postcrc_leave_writes, self._postcrc_leave_services = [], [], []
        self._postcrc_leave_pending = False
        self._postcrc_leave_header_samples = 0

    def _postcrc_leave_track(self, cpu, pc):
        assert len(self._postcrc_leave_sites) < MAX_OBSERVATIONS
        key = self._fmt_site(pc)
        self._postcrc_leave_sites.append(key)
        self._postcrc_leave_code[key] = bytes(cpu.mem_read(pc, 4)).hex()

    def _postcrc_leave_snapshot(self, cpu, pc, kind):
        storage = bytes(cpu.mem_read(self._cs_scope, 24))
        self._postcrc_leave_rows.append(dict(
            kind=kind, index=len(self._postcrc_leave_sites), pc=self._fmt_site(pc),
            SP=hex(cpu.reg_read(arm.UC_ARM64_REG_SP)),
            callee_saved_sha256=self._idctor_saved_hash(cpu), registers={},
            VM_state_address=hex(self._postalloc_vmstate),
            VM_cursor=hex(self._u(cpu, self._postalloc_vmstate) - self.image),
            descriptor_address=hex(self._postcrc_leave_descriptor), descriptor_width=48,
            descriptor_sha256=raw_hash(bytes(cpu.mem_read(self._postcrc_leave_descriptor, 48))),
            scope_storage_address=hex(self._cs_scope), scope_storage_width=24,
            scope_storage_sha256=raw_hash(storage), scope_padding_4_sha256=raw_hash(storage[12:16]),
            scope_lifetime_ended=self._postcrc_leave_returned,
            scope_fields={} if self._postcrc_leave_returned else self._fr_scope(cpu),
            diagnostic=self._cs_diagnostic(cpu),
            cleared_pair_storage_sha256=raw_hash(bytes(cpu.mem_read(self._dl_pointer_slot, 16))),
            protected_regions_sha256=self._postcrc_leave_protected_hash(cpu)))

    def _postcrc_leave_protected_hash(self, cpu):
        return digest([dict(label=label, address=hex(address), size=size,
                            sha256=raw_hash(bytes(cpu.mem_read(address, size))))
                       for label, address, size in self._postcrc_leave_fixed])

    def _postcrc_leave_start(self, cpu, pc, state):
        # Complete the parent's real serializer at exactly its frozen stop.
        self._dl_track(cpu, pc)
        self._dl_snapshot(cpu, pc, 'before_next_VM_call')
        self._dl_next = next_call(cpu, self, len(self._dl_trace))
        self._dl_next['descriptor_word_8_matches_active_scope'] = (
            self._u(cpu, self._reg(cpu, 0) + 8) == self._cs_scope)
        self._postcrc_leave_old = self._postcrc_parent['case_result']
        assert self._dl_next == self._postcrc_leave_old['next_VM_call']
        self._dl_done, self._dl_active = True, False
        self._postcrc_leave_descriptor = self._reg(cpu, 0)
        self._postcrc_leave_descriptor_bytes = bytes(cpu.mem_read(self._postcrc_leave_descriptor, 48))
        self._postcrc_leave_entry = self._u(cpu, self._cs_slot)
        assert self._reg(cpu, 8) == self.image + WRAPPER
        assert self._u(cpu, self._postcrc_leave_descriptor) == self.image + TARGET
        assert self._u(cpu, self._postcrc_leave_descriptor + 8) == self._cs_scope
        self._postcrc_leave_sp = cpu.reg_read(arm.UC_ARM64_REG_SP)
        self._postcrc_leave_saved = self._idctor_saved_hash(cpu)
        self._postcrc_leave_events = deepcopy(state['allocator_events_ref'])
        self._postcrc_leave_fixed = previous.previous.previous.subtract_ranges(
            self._dl_ranges, [(self._cs_scope, 24), (self._postcrc_leave_entry + 8, 8)])
        self._postcrc_leave_ranges = deepcopy(self._postcrc_leave_fixed)
        self._postcrc_leave_active = True
        print('Reached retained post-CRC scope-leave call', flush=True)
        self._postcrc_leave_track(cpu, pc)
        self._postcrc_leave_snapshot(cpu, pc, 'scope_leave_VM_call')

    def native_runner(self, *args, **kwargs):
        old_write = kwargs['memory_write_observer']

        def write(cpu, address, size):
            if self._postcrc_leave_active:
                pc = cpu.reg_read(arm.UC_ARM64_REG_PC)
                self._postcrc_leave_writes.append(dict(index=len(self._postcrc_leave_sites),
                    PC=self._fmt_site(pc), address=hex(address), size=size))
                assert not any(address < start + width and start < address + size
                               for label, start, width in self._postcrc_leave_ranges), 'protected state write'
                if not self._postcrc_leave_returned:
                    assert not (address < self._postcrc_leave_descriptor + 48
                                and self._postcrc_leave_descriptor < address + size), 'packed descriptor write'
                    if address < self._postcrc_leave_entry + 16 and self._postcrc_leave_entry + 8 < address + size:
                        expected = {LIBC_BASE + 0x68E48: (self._postcrc_leave_entry + 12, 4),
                                    LIBC_BASE + 0x68E54: (self._postcrc_leave_entry + 8, 2)}
                        assert pc in expected and (address, size) == expected[pc]
                        self._postcrc_leave_pending = True
            if old_write:
                old_write(cpu, address, size)

        kwargs['memory_write_observer'] = write
        return super().native_runner(*args, **kwargs)

    def observe(self, cpu, pc, state):
        if not self._postcrc_leave_active:
            if self._dl_active and self._dl_returned and pc == self.image + VM_CALL:
                self._postcrc_leave_start(cpu, pc, state)
                self._base_observe(cpu, pc, state)
                return
            return super().observe(cpu, pc, state)
        self._postcrc_leave_track(cpu, pc)
        off = pc - self.image
        if self._postcrc_leave_pending:
            self._postcrc_leave_header_samples += 1
            self._postcrc_leave_snapshot(cpu, pc, 'after_header_write_' + str(self._postcrc_leave_header_samples))
            self._postcrc_leave_pending = False
        if not self._postcrc_leave_returned:
            names = {WRAPPER: 'wrapper_entry', TARGET: 'scope_leave_entry',
                     0x26C9E0: 'scope_vtable_store_completed', 0x26CA04: 'before_tail_unlock'}
            if off in names:
                if off == TARGET:
                    assert self._reg(cpu, 0) == self._cs_scope
                    assert self._reg(cpu, 30) == self.image + VM_RESUME
                self._postcrc_leave_snapshot(cpu, pc, names[off])
            if off == 0x347F10 or pc == LIBC_BASE + UNLOCK:
                assert self._reg(cpu, 0) == self._postcrc_leave_entry + 8
                self._postcrc_leave_services.append(dict(index=len(self._postcrc_leave_sites),
                    PC=self._fmt_site(pc), argument_address=hex(self._reg(cpu, 0)),
                    kind='unlock_PLT' if off == 0x347F10 else 'matching_Bionic_unlock_entry'))
                if pc == LIBC_BASE + UNLOCK:
                    self._postcrc_leave_snapshot(cpu, pc, 'Bionic_unlock_entry')
            if off == VM_RESUME:
                assert cpu.reg_read(arm.UC_ARM64_REG_SP) == self._postcrc_leave_sp
                assert self._idctor_saved_hash(cpu) == self._postcrc_leave_saved
                assert bytes(cpu.mem_read(self._postcrc_leave_descriptor, 48)) == self._postcrc_leave_descriptor_bytes
                self._postcrc_leave_returned = True
                self._postcrc_leave_snapshot(cpu, pc, 'scope_leave_callback_return')
                self._postcrc_leave_ranges.append(('released_entry_header', self._postcrc_leave_entry + 8, 8))
        elif off == VM_CALL:
            self._postcrc_leave_snapshot(cpu, pc, 'before_next_VM_call')
            self._postcrc_leave_next = next_call(cpu, self, len(self._postcrc_leave_sites))
            self._postcrc_leave_done = True
            cpu.emu_stop()
            cpu.reg_write(arm.UC_ARM64_REG_PC, previous.controls.oracle.STOP)
            return
        self._base_observe(cpu, pc, state)

    def finish(self, result, state, proof):
        assert self._postcrc_leave_done and self._postcrc_leave_returned and not self._postcrc_leave_pending
        assert result['allocator_events'] == self._postcrc_leave_events
        old = super().finish(result, state, proof)
        assert old == self._postcrc_leave_old, 'full parent result changed'
        trace = hashlib.sha256()
        for key in self._postcrc_leave_sites:
            trace.update(key.encode() + bytes.fromhex(self._postcrc_leave_code[key]))
        return dict(parent_case_result_sha256=digest(old), parent_verified_fields=sorted(old),
                    instruction_observations=len(self._postcrc_leave_sites),
                    instruction_trace_sha256=trace.hexdigest(),
                    observed_code_sha256=digest(self._postcrc_leave_code),
                    observation_sites=self._postcrc_leave_sites, observed_code=self._postcrc_leave_code,
                    snapshots=self._postcrc_leave_rows, native_writes=self._postcrc_leave_writes,
                    services=self._postcrc_leave_services, next_VM_call=self._postcrc_leave_next,
                    protected_ranges=[dict(label=label, address=hex(address), size=size)
                                      for label, address, size in self._postcrc_leave_ranges],
                    new_allocator_events=[], ledgers={key: old[key] for key in previous.EXPECTED['ledgers']})


def run(path, libc):
    parent = parent_evidence()
    prefix = previous.previous.previous.previous.bootstrap_prefix()
    prefix.digest.verify_images(path, libc)
    code = read_static(path, libc)
    print('Validated parent evidence; executing original ELF/Bionic prefix', flush=True)

    def create(control):
        scenario = PostCRCScopeLeaveScenario(control)
        scenario.path, scenario.continue_to_svc = path, True
        scenario._postcrc_parent = parent
        return scenario

    rows = prefix.digest.context.replay(path, libc, case_controls=[prefix.CONTROL],
        _extension_factory=create,
        _request_profile=prefix.digest.previous.previous.name.previous.previous.PROFILE['name'],
        _handler_read_profile=prefix.digest.context.NULL_PAYLOAD_READ_PROFILE['name'])
    assert len(rows) == 1
    print('Original scope leave returned; checking existing independent controls', flush=True)
    identity, cases, guards = scope_controls.independent_controls(path, libc)
    return dict(schema=SCHEMA, claims=claims(), providers=providers(), source_fingerprints=sources(),
                parent_evidence_sha256=sha256(previous.EVIDENCE),
                parent_case_result_sha256=digest(parent['case_result']), static_code=code,
                wrapper_identity=identity, native_controls=cases, component_rollback_checks=guards,
                case_result=rows[0], case_result_sha256=digest(rows[0]))


def _validate(data, parent):
    old = parent['case_result']
    assert set(data) == {'schema', 'claims', 'providers', 'source_fingerprints',
        'parent_evidence_sha256', 'parent_case_result_sha256', 'static_code',
        'wrapper_identity', 'native_controls', 'component_rollback_checks',
        'case_result', 'case_result_sha256'}
    assert data['schema'] == SCHEMA and data['claims'] == claims() and data['providers'] == providers()
    assert data['source_fingerprints'] == sources()
    assert data['parent_evidence_sha256'] == sha256(previous.EVIDENCE)
    assert data['parent_case_result_sha256'] == digest(old)
    assert data['wrapper_identity'] == scope_controls.WRAPPER_IDENTITY
    assert data['native_controls'] == scope_controls.CONTROL_SPECS
    assert data['component_rollback_checks'] == scope_controls.ROLLBACK_SPECS
    assert set(data['static_code']) == set(CODE_SHA256)
    for domain, ranges in CODE_RANGES.items():
        for off, size in ranges:
            key = domain + ':' + hex(off)
            entry = data['static_code'][key]
            raw = bytes.fromhex(entry['hex'])
            assert set(entry) == {'hex', 'size', 'sha256'}
            assert len(raw) == entry['size'] == size
            assert raw_hash(raw) == entry['sha256'] == CODE_SHA256[key]
    row = data['case_result']
    assert set(row) == {'parent_case_result_sha256', 'parent_verified_fields',
        'instruction_observations', 'instruction_trace_sha256', 'observed_code_sha256',
        'observation_sites', 'observed_code', 'snapshots', 'native_writes', 'services',
        'next_VM_call', 'protected_ranges', 'new_allocator_events', 'ledgers'}
    assert data['case_result_sha256'] == digest(row)
    assert row['parent_case_result_sha256'] == digest(old) and row['parent_verified_fields'] == sorted(old)
    sites, code = row['observation_sites'], row['observed_code']
    assert 55 < len(sites) == row['instruction_observations'] < MAX_OBSERVATIONS
    assert set(sites) == set(code) and row['observed_code_sha256'] == digest(code)
    trace = hashlib.sha256()
    for key in sites:
        raw = bytes.fromhex(code[key])
        assert len(raw) == 4
        trace.update(key.encode() + raw)
    assert trace.hexdigest() == row['instruction_trace_sha256']
    assert sites[:5] == ['main:' + hex(off) for off in (VM_CALL, WRAPPER, WRAPPER+4, WRAPPER+8, TARGET)]
    assert sites[-1] == 'main:' + hex(VM_CALL) and sites.count(sites[-1]) == 2
    assert sites.count('main:' + hex(VM_RESUME)) == sites.count('libc:' + hex(UNLOCK)) == 1
    for domain, ranges in CODE_RANGES.items():
        for off, size in ranges:
            raw = bytes.fromhex(data['static_code'][domain + ':' + hex(off)]['hex'])
            for address in range(off, off + size, 4):
                if domain + ':' + hex(address) in code:
                    assert code[domain + ':' + hex(address)] == raw[address-off:address-off+4].hex()
    snapshots = row['snapshots']
    assert len(snapshots) == 10
    assert len({x['kind'] for x in snapshots}) == len(snapshots)
    by_kind = {x['kind']: x for x in snapshots}
    first, last = snapshots[0], snapshots[-1]
    returned = by_kind['scope_leave_callback_return']
    assert first['kind'] == 'scope_leave_VM_call' and first['index'] == 1
    assert last['kind'] == 'before_next_VM_call' and last['index'] == len(sites)
    assert all(a['index'] < b['index'] for a, b in zip(snapshots, snapshots[1:]))
    assert first['scope_fields'] == old['snapshots'][-1]['active_scope']
    assert first['diagnostic'] == old['snapshots'][-1]['diagnostic']
    assert first['VM_cursor'] == returned['VM_cursor'] == '0x10a41c'
    assert first['descriptor_address'] == old['next_VM_call']['descriptor_address']
    assert first['descriptor_sha256'] == old['next_VM_call']['descriptor_sha256']
    assert first['diagnostic']['mutex_state_u16'] == 0x4001 and first['diagnostic']['owner_u32'] == 137
    assert returned['diagnostic']['mutex_state_u16'] == 0x4000 and returned['diagnostic']['owner_u32'] == 0
    assert first['SP'] == returned['SP'] and first['callee_saved_sha256'] == returned['callee_saved_sha256']
    for snap in snapshots:
        assert set(snap) == set(first) and snap['registers'] == {}
        assert sites[snap['index']-1] == snap['pc']
        assert snap['VM_state_address'] == first['VM_state_address']
        assert snap['scope_storage_address'] == first['scope_storage_address']
        assert snap['scope_storage_width'] == 24 and snap['descriptor_width'] == 48
        assert snap['protected_regions_sha256'] == first['protected_regions_sha256']
        assert snap['cleared_pair_storage_sha256'] == raw_hash(bytes(16))
        ended = snap['index'] >= returned['index']
        assert snap['scope_lifetime_ended'] is ended
        if ended:
            assert snap['scope_fields'] == {}
        else:
            assert snap['scope_fields']['address'] == first['scope_fields']['address']
            assert snap['scope_fields']['input_word_sha256'] == first['scope_fields']['input_word_sha256']
        if snap['index'] <= returned['index']:
            assert snap['descriptor_sha256'] == first['descriptor_sha256']
        for key in first['diagnostic']:
            if key not in ('entry_sha256', 'mutex_state_u16', 'owner_u32'):
                assert snap['diagnostic'][key] == first['diagnostic'][key]
    one, two = by_kind['after_header_write_1'], by_kind['after_header_write_2']
    assert one['pc'] == 'libc:0x68e4c' and two['pc'] == 'libc:0x68e58'
    assert one['diagnostic']['owner_u32'] == two['diagnostic']['owner_u32'] == 0
    assert one['diagnostic']['mutex_state_u16'] == 0x4001 and two['diagnostic']['mutex_state_u16'] == 0x4000
    assert first['index'] < one['index'] < two['index'] < returned['index']
    entry_address = int(first['diagnostic']['entry_address'], 16)
    header_writes = []
    fixed = row['protected_ranges'][:-1]
    assert row['protected_ranges'][-1] == dict(label='released_entry_header', address=hex(entry_address+8), size=8)
    assert fixed == [dict(label=label, address=hex(address), size=size)
                     for label, address, size in previous.previous.previous.subtract_ranges(
                         [(r['label'], int(r['address'], 16), r['size']) for r in old['protected_ranges']],
                         [(int(first['scope_storage_address'], 16), 24), (entry_address+8, 8)])]
    for write in row['native_writes']:
        assert set(write) == {'index', 'PC', 'address', 'size'} and write['size'] > 0
        assert sites[write['index']-1] == write['PC']
        ranges = row['protected_ranges'] if write['index'] >= returned['index'] else fixed
        assert not any(previous.overlaps(write['address'], write['size'], region) for region in ranges)
        if write['index'] < returned['index']:
            assert not previous.overlaps(write['address'], write['size'], dict(address=first['descriptor_address'], size=48))
        if previous.overlaps(write['address'], write['size'], dict(address=hex(entry_address+8), size=8)):
            header_writes.append(write)
    assert header_writes == [
        dict(index=one['index']-1, PC='libc:0x68e48', address=hex(entry_address+12), size=4),
        dict(index=two['index']-1, PC='libc:0x68e54', address=hex(entry_address+8), size=2)]
    assert [s['kind'] for s in row['services']] == ['unlock_PLT', 'matching_Bionic_unlock_entry']
    assert [s['PC'] for s in row['services']] == ['main:0x347f10', 'libc:' + hex(UNLOCK)]
    for service in row['services']:
        assert sites[service['index']-1] == service['PC'] and service['argument_address'] == hex(entry_address+8)
        assert first['index'] < service['index'] < one['index']
    assert row['new_allocator_events'] == []
    assert row['ledgers'] == {key: old[key] for key in previous.EXPECTED['ledgers']}
    call = row['next_VM_call']
    assert set(call) == {'index', 'callsite_offset', 'VM_cursor_offset', 'descriptor_address',
        'descriptor_width', 'descriptor_sha256', 'wrapper_offset', 'target_offset',
        'wrapper_code_hex', 'wrapper_code_sha256', 'VM_call_executed', 'wrapper_executed', 'target_executed'}
    assert call['index'] == len(sites) and call['callsite_offset'] == hex(VM_CALL)
    assert call['VM_cursor_offset'] == last['VM_cursor'] and call['descriptor_width'] == 48
    wrapper = bytes.fromhex(call['wrapper_code_hex'])
    assert len(wrapper) in range(4, 65, 4) and raw_hash(wrapper) == call['wrapper_code_sha256']
    assert all(call[key] is False for key in ('VM_call_executed', 'wrapper_executed', 'target_executed'))


def validate(data):
    _validate(data, parent_evidence())


def damaged_evidence_rejected(data):
    parent = parent_evidence()
    changes = [
        (('claims', 'complete_standalone_signer_verified'), True),
        (('claims', 'scope_fields_omitted_after_return'), False),
        (('providers', 'new_providers'), ['hidden']),
        (('source_fingerprints', 'parent_sha256'), '0'*64),
        (('parent_evidence_sha256',), '0'*64),
        (('case_result', 'parent_verified_fields'), []),
        (('case_result', 'instruction_trace_sha256'), '0'*64),
        (('case_result', 'snapshots', -2, 'scope_fields'), {'stale': True}),
        (('case_result', 'snapshots', -2, 'scope_lifetime_ended'), False),
        (('case_result', 'snapshots', -2, 'diagnostic', 'owner_u32'), 137),
        (('case_result', 'snapshots', -2, 'diagnostic', 'mutex_state_u16'), 0x4001),
        (('case_result', 'snapshots', -1, 'registers'), {'x0': '0x1'}),
        (('case_result', 'new_allocator_events'), [['free', 0]]),
        (('case_result', 'ledgers'), {}),
        (('case_result', 'native_writes', 0, 'size'), 0),
        (('case_result', 'protected_ranges'), []),
        (('case_result', 'next_VM_call', 'VM_call_executed'), True),
        (('case_result', 'next_VM_call', 'descriptor_hex'), 'omitted'),
        (('case_result', 'raw_identifier'), 'omitted'),
        (('native_controls', 0, 'native_snapshot_input'), True),
        (('component_rollback_checks', 0, 'all_pages_unchanged'), False),
        (('static_code', 'main:' + hex(TARGET), 'sha256'), '0'*64),
    ]
    for path, value in changes:
        bad = deepcopy(data)
        target = bad
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
        if path[0] == 'case_result':
            bad['case_result_sha256'] = digest(bad['case_result'])
        try:
            _validate(bad, parent)
        except (AssertionError, KeyError, IndexError, ValueError, TypeError):
            continue
        raise AssertionError(f'damaged scope-release evidence accepted: {path}')
    return len(changes)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf', type=Path)
    parser.add_argument('--libc', type=Path)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--capture', action='store_true')
    modes.add_argument('--replay', action='store_true')
    args = parser.parse_args()
    if (args.capture or args.replay) and (args.elf is None or args.libc is None):
        parser.error('--capture and --replay require --elf and --libc')
    if args.capture:
        if EVIDENCE.exists():
            raise FileExistsError('frozen evidence exists; refusing overwrite')
        data = run(args.elf, args.libc)
        validate(data)
        rejected = damaged_evidence_rejected(data)
        with EVIDENCE.open('x', encoding='utf-8', newline='\n') as out:
            out.write(json.dumps(data, indent=2) + '\n')
    else:
        data = json.loads(EVIDENCE.read_text(encoding='utf-8'))
        validate(data)
        rejected = damaged_evidence_rejected(data)
        if args.replay:
            assert run(args.elf, args.libc) == data, 'fresh scope-release replay differs'
    print(json.dumps(dict(schema=SCHEMA, native_controls=len(data['native_controls']),
        component_rollback_checks=len(data['component_rollback_checks']), damaged_evidence_rejected=rejected,
        instruction_observations=data['case_result']['instruction_observations'],
        scope_leave_returned=True, next_VM_call_executed=False, complete_standalone_signer_verified=False)))


if __name__ == '__main__':
    main()
