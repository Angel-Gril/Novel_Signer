"""Verify cleanup of the constructed temporary string before the next JSON callback."""
from __future__ import annotations
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as arm
from vm9_allocator import _read_span, _write_span
import vm9_objects as objects
import verify_vm9_second_delete_fresh_20261015 as fixture
import verify_vm9_native_171_post_crc_scope_leave_return_dynamic_20261123 as previous

EVIDENCE = previous.EVIDENCE.with_name('vm9_native_171_post_crc_base_string_destructor_return_dynamic_20261123.json')
CONSTRUCTION = previous.EVIDENCE.with_name('vm9_native_171_post_formatter_pair_return_dynamic_20261123.json')
SCHEMA = 'vm9-native-171-post-crc-base-string-destructor-return-dynamic-20261123-v1'
VM_CALL, VM_RESUME = previous.VM_CALL, previous.VM_RESUME
WRAPPER, TARGET, FREE = 0x2884CC, 0x2484B8, previous.previous.FREE
LIBC_BASE = previous.LIBC_BASE
raw_hash, digest, sha256 = previous.raw_hash, previous.digest, previous.sha256
subtract_ranges = previous.previous.previous.previous.subtract_ranges
MAX_OBSERVATIONS = 100000
CODE_RANGES = {'main': ((1485384, 32), (2655436, 12), (2393272, 68), (3440544, 16), (451080, 8), (2656316, 24), (2495492, 96)), 'libc': ((113344, 64),)}
CODE_SHA256 = {'main:0x16aa48': 'c53f89ea694ed64ca8b5270d014ecf3bbd4777260ee7edee83a2e8e70b25178f', 'main:0x2884cc': '82295168e4332fdd8ee754ea9b86ffc5a592a6e6c42c0e1592ea18f55c95c565', 'main:0x2484b8': 'b667b3873efcc43d4ffb0f6edb76176e2e84ec53c43007ca9bdbe82067646854', 'main:0x347fa0': 'b8de5b842297b810afe3ee06e098e06f714ec5bd7127865940c8336123008b7c', 'main:0x6e208': '68ca0fde67a507138a72ec1daa71d0ae4c0f814addfe7b6c0b71089096ac127f', 'main:0x28883c': '7493ca0b49b64cda49658a4353306ed42ed1f5936c30c94c2d250860f82e74f4', 'main:0x261404': '841bb01103243acd141063f0f2f27fe7ef1668aa0af0c3607220024e955ae0e0', 'libc:0x1bac0': 'cf64708e3eff950990ab65665d58ecc030fe9598b5094d45998f1726010386ab'}

class PostCRCBaseStringDestructorScenario(previous.PostCRCScopeLeaveScenario):
    def __init__(self, control):
        super().__init__(control)
        self._pcb_active = self._pcb_returned = self._pcb_payload_retired = False
        self._pcb_done = self._pcb_recognized = False
        self._pcb_sites, self._pcb_code, self._pcb_rows = [], {}, []
        self._pcb_writes, self._pcb_frees, self._pcb_aux, self._pcb_svc = [], [], [], []

    def _pcb_track(self, cpu, pc):
        assert len(self._pcb_sites) < MAX_OBSERVATIONS
        key = self._fmt_site(pc)
        self._pcb_sites.append(key)
        self._pcb_code[key] = bytes(cpu.mem_read(pc, 4)).hex()

    def _pcb_snapshot(self, cpu, pc, kind):
        fields = {}
        if not self._pcb_returned:
            storage = bytes(cpu.mem_read(self._pcb_object, 24))
            fields = dict(vtable_offset=hex(int.from_bytes(storage[:8], 'little') - self.image),
                capacity_u32=int.from_bytes(storage[8:12], 'little'),
                length_storage_i32=int.from_bytes(storage[12:16], 'little', signed=True),
                payload_pointer_is_NULL=int.from_bytes(storage[16:24], 'little') == 0,
                payload_pointer_matches_initial=int.from_bytes(storage[16:24], 'little') == self._pcb_payload)
        self._pcb_rows.append(dict(kind=kind, index=len(self._pcb_sites), pc=self._fmt_site(pc),
            SP=hex(cpu.reg_read(arm.UC_ARM64_REG_SP)), callee_saved_sha256=self._idctor_saved_hash(cpu),
            registers={}, VM_state_address=hex(self._postalloc_vmstate),
            VM_cursor=hex(self._u(cpu, self._postalloc_vmstate) - self.image),
            descriptor_address=hex(self._pcb_descriptor), descriptor_width=48,
            descriptor_sha256=raw_hash(bytes(cpu.mem_read(self._pcb_descriptor, 48))),
            object_storage_address=hex(self._pcb_object), object_storage_width=24,
            object_lifetime_ended=self._pcb_returned, object_fields=fields,
            object_storage_sha256=raw_hash(bytes(cpu.mem_read(self._pcb_object, 24))),
            payload_address=hex(self._pcb_payload), payload_capacity=self._pcb_capacity,
            payload_deallocation_started=self._pcb_payload_retired, payload_fields={},
            diagnostic=self._cs_diagnostic(cpu),
            protected_regions_sha256=digest([dict(label=label, address=hex(address), size=size,
                sha256=raw_hash(bytes(cpu.mem_read(address, size)))) for label, address, size in self._pcb_fixed])))

    def _pcb_start(self, cpu, pc, state):
        self._postcrc_leave_track(cpu, pc)
        self._postcrc_leave_snapshot(cpu, pc, 'before_next_VM_call')
        self._postcrc_leave_next = previous.next_call(cpu, self, len(self._postcrc_leave_sites))
        assert self._postcrc_leave_next == self._pcb_parent['case_result']['next_VM_call']
        self._postcrc_leave_done, self._postcrc_leave_active = True, False
        self._pcb_events = deepcopy(state['allocator_events_ref'])
        self._pcb_descriptor = self._reg(cpu, 0)
        self._pcb_before = bytes(cpu.mem_read(self._pcb_descriptor, 48))
        assert self._reg(cpu, 8) == self.image + WRAPPER
        assert self._u(cpu, self._pcb_descriptor) == self.image + TARGET
        self._pcb_object = self._u(cpu, self._pcb_descriptor + 8)
        matches = [(label, address, size) for label, address, size in self._postcrc_leave_ranges
                   if address == self._pcb_object and size == 24
                   and ('object' in label or label.startswith('prior_'))]
        self._pcb_arguments = dict(object_address=hex(self._pcb_object),
            retained_live_object_regions=[label for label, address, size in matches],
            argument_matches_pair_destination=self._pcb_object == self._pair_destination,
            pair_destination_constructed=self._pair_constructed,
            prior_pair_destination_address=hex(self._pair_destination),
            object_operator_delete_selected=False, void_return_X0_compared=False)
        if not matches:
            self._pcb_done = True
            cpu.emu_stop()
            cpu.reg_write(arm.UC_ARM64_REG_PC, previous.previous.controls.oracle.STOP)
            return
        storage = bytes(cpu.mem_read(self._pcb_object, 24))
        assert int.from_bytes(storage[:8], 'little') == self.image + 0x34F5F8
        self._pcb_capacity = int.from_bytes(storage[8:12], 'little')
        self._pcb_length = int.from_bytes(storage[12:16], 'little', signed=True)
        self._pcb_payload = int.from_bytes(storage[16:24], 'little')
        assert 0 <= self._pcb_length < self._pcb_capacity <= 0x100000 and self._pcb_payload
        assert any(address == self._pcb_payload and size == self._pcb_capacity
                   for label, address, size in self._postcrc_leave_ranges)
        self._pcb_arguments.update(payload_address=hex(self._pcb_payload),
            payload_capacity=self._pcb_capacity, initial_length=self._pcb_length)
        self._pcb_fixed = subtract_ranges(self._postcrc_leave_ranges,
            [(self._pcb_object, 24), (self._pcb_payload, self._pcb_capacity)])
        self._pcb_sp = cpu.reg_read(arm.UC_ARM64_REG_SP)
        self._pcb_saved = self._idctor_saved_hash(cpu)
        self._pcb_active = self._pcb_recognized = True
        print('Recognized retained live object; executing existing base destructor', flush=True)
        self._pcb_track(cpu, pc)
        self._pcb_snapshot(cpu, pc, 'base_destructor_VM_call')

    def native_runner(self, *args, **kwargs):
        assert kwargs.get('real_malloc') is True and not kwargs.get('malloc_handler')
        old_write = kwargs['memory_write_observer']

        def write(cpu, address, size):
            if self._pcb_active:
                pc = cpu.reg_read(arm.UC_ARM64_REG_PC)
                self._pcb_writes.append(dict(index=len(self._pcb_sites), PC=self._fmt_site(pc),
                                             address=hex(address), size=size))
                assert not any(address < start + width and start < address + size
                               for label, start, width in self._pcb_fixed), 'protected retained state write'
                if not self._pcb_returned:
                    assert not (address < self._pcb_descriptor + 48 and self._pcb_descriptor < address + size)
                    if address < self._pcb_object + 24 and self._pcb_object < address + size:
                        stores = {self.image + 0x2484D4: (self._pcb_object, 8),
                                  self.image + 0x2484E0: (self._pcb_object + 16, 8),
                                  self.image + 0x2484EC: (self._pcb_object + 8, 8)}
                        assert pc in stores and (address, size) == stores[pc]
                if address < self._pcb_payload + self._pcb_capacity and self._pcb_payload < address + size:
                    assert self._pcb_payload_retired and not self._pcb_returned
            if old_write:
                old_write(cpu, address, size)

        kwargs['memory_write_observer'] = write
        return super().native_runner(*args, **kwargs)

    def observe(self, cpu, pc, state):
        if not self._pcb_active:
            if self._postcrc_leave_active and self._postcrc_leave_returned and pc == self.image + VM_CALL:
                self._pcb_start(cpu, pc, state)
                if self._pcb_recognized:
                    self._base_observe(cpu, pc, state)
                return
            return super().observe(cpu, pc, state)
        self._pcb_track(cpu, pc)
        off, index = pc - self.image, len(self._pcb_sites)
        if pc in (LIBC_BASE + 0x9833C, LIBC_BASE + 0x97F40):
            self._pcb_aux.append(dict(index=index, PC=self._fmt_site(pc),
                                      kind='gc' if pc == LIBC_BASE + 0x9833C else 'flush'))
        if bytes(cpu.mem_read(pc, 4)) == bytes.fromhex('010000d4'):
            self._pcb_svc.append(dict(index=index, PC=self._fmt_site(pc), number=self._reg(cpu, 8)))
        if not self._pcb_returned:
            assert off not in (0x2484FC, 0x32A264), 'base destructor entered object deletion'
            if off == TARGET:
                assert self._reg(cpu, 0) == self._pcb_object and self._reg(cpu, 30) == self.image + VM_RESUME
            if off == 0x347FA0:
                assert self._reg(cpu, 0) == self._pcb_payload and not self._pcb_frees
                self._pcb_frees.append(dict(argument_address=hex(self._pcb_payload), free_PLT_index=index))
            if pc == LIBC_BASE + FREE:
                assert self._reg(cpu, 0) == self._pcb_payload and len(self._pcb_frees) == 1
                self._pcb_frees[0]['Bionic_free_entry_index'] = index
                self._pcb_payload_retired = True
                self._pcb_snapshot(cpu, pc, 'payload_Bionic_free_entry')
            if off == 0x2484E0:
                assert self._pcb_payload_retired
                self._pcb_frees[0].update(return_index=index, return_PC=self._fmt_site(pc))
                self._pcb_snapshot(cpu, pc, 'payload_free_return')
            if off in (WRAPPER, TARGET, 0x2484E4, 0x2484F0):
                self._pcb_snapshot(cpu, pc, {WRAPPER: 'wrapper_entry', TARGET: 'base_destructor_entry',
                    0x2484E4: 'payload_pointer_clear_complete', 0x2484F0: 'scalar_reset_complete'}[off])
            if off == VM_RESUME:
                assert cpu.reg_read(arm.UC_ARM64_REG_SP) == self._pcb_sp
                assert self._idctor_saved_hash(cpu) == self._pcb_saved
                assert bytes(cpu.mem_read(self._pcb_descriptor, 48)) == self._pcb_before
                assert self._pcb_payload_retired and len(self._pcb_frees) == 1
                self._pcb_returned = True
                self._pcb_snapshot(cpu, pc, 'base_destructor_callback_return')
        elif off == VM_CALL:
            self._pcb_snapshot(cpu, pc, 'before_next_VM_call')
            self._pcb_next = previous.next_call(cpu, self, index)
            self._pcb_done = True
            cpu.emu_stop()
            cpu.reg_write(arm.UC_ARM64_REG_PC, previous.previous.controls.oracle.STOP)
            return
        self._base_observe(cpu, pc, state)

    def finish(self, result, state, proof):
        assert self._pcb_done
        delta = result['allocator_events'][len(self._pcb_events):]
        prefix, counts, services = dict(result), deepcopy(result['actual_allocator_counts']), deepcopy(result['explicit_service_counts'])
        for event in delta:
            assert event[0] == 'free'
            counts['free'] -= 1
        for event in self._pcb_aux:
            counts[event['kind']] -= 1
        for event in self._pcb_svc:
            services['syscall_' + str(event['number'])] -= 1
        prefix.update(allocator_events=self._pcb_events, actual_allocator_counts=counts, explicit_service_counts=services)
        prefix_proof = dict(proof)
        for proof_key, ledger_key in (('libc_SVC_boundaries', 'inherited_libc_SVC'), ('main_image_SVC_boundaries', 'inherited_main_SVC')):
            prefix_proof[proof_key] = proof[proof_key][:len(self._pcb_parent['case_result']['ledgers'][ledger_key])]
        old = super().finish(prefix, state, prefix_proof)
        assert old == self._pcb_parent['case_result'], 'full scope-leave parent differs'
        trace = hashlib.sha256()
        for key in self._pcb_sites:
            trace.update(key.encode() + bytes.fromhex(self._pcb_code[key]))
        return dict(recognized_live_argument=self._pcb_recognized, arguments=self._pcb_arguments,
            parent_case_result_sha256=digest(old), parent_verified_fields=sorted(old),
            instruction_observations=len(self._pcb_sites), instruction_trace_sha256=trace.hexdigest(),
            observed_code_sha256=digest(self._pcb_code), observation_sites=self._pcb_sites, observed_code=self._pcb_code,
            snapshots=self._pcb_rows, native_writes=self._pcb_writes, free_events=self._pcb_frees,
            new_allocator_events=delta, allocator_aux_events=self._pcb_aux, new_SVC_events=self._pcb_svc,
            actual_allocator_counts=result['actual_allocator_counts'], explicit_service_counts=result['explicit_service_counts'],
            protected_ranges=[dict(label=label, address=hex(address), size=size) for label, address, size in getattr(self, '_pcb_fixed', [])],
            next_VM_call=getattr(self, '_pcb_next', {}), base_destructor_returned=self._pcb_returned,
            final_libc_SVC=proof['libc_SVC_boundaries'], final_main_SVC=proof['main_image_SVC_boundaries'])


def parent_evidence():
    data = json.loads(previous.EVIDENCE.read_text(encoding='utf-8'))
    previous.validate(data)
    return data


def sources():
    return dict(verifier_sha256=sha256(Path(__file__)),
        parent_sha256=sha256(Path(previous.__file__)), parent_chain_sha256=digest(previous.sources()),
        component_fixture_sha256=sha256(Path(fixture.__file__)),
        component_oracle_sha256=sha256(Path(fixture.oracle.__file__)),
        string_model_sha256=sha256(Path(objects.__file__)))


def claims():
    return dict(evidence_label='Sample verified', full_parent_case_result_equal=True,
        argument_matches_constructed_pair_destination=True, original_base_destructor_returned=True,
        matching_Bionic_payload_free_returned=True, stack_object_storage_not_freed=True,
        payload_pointer_clear_and_scalar_reset_observed=True, destroyed_object_fields_omitted=True,
        payload_contents_never_exported=True, existing_string_model_reused=True,
        caller_SP_and_callee_saved_restored=True, packed_descriptor_preserved_through_return=True,
        physical_return_X0_ABI_compared=False, new_providers_added=False,
        native_snapshot_used_as_python_model_input=False, actual_next_VM_call_executed=False,
        standalone_Python_VM_continuation_verified=False, complete_VM_suffix_return_verified=False,
        complete_standalone_signer_verified=False, real_ART_JVM_execution=False,
        Android_execution=False, physical_PAC_authentication_verified=False, online_acceptance_verified=False)


def providers():
    return dict(inherited_evidence_sha256=sha256(previous.EVIDENCE), new_providers=[], new_import_bindings=[],
        main_free='original matching Bionic free; no object operator delete',
        component_free='explicit synthetic free effects; no independent owning-allocator parity claim',
        object_lifetime='defined fields omitted from callback return; later storage hash is untyped',
        payload_lifetime='no payload bytes or payload-content hashes exported at any point',
        rollback='existing model transaction; external free effects are outside guest-page rollback',
        maximum_instruction_observations=MAX_OBSERVATIONS)


def read_static(path, libc):
    result = {}
    for domain, image in (('main', path), ('libc', libc)):
        with image.open('rb') as stream:
            elf = ELFFile(stream)
            for off, size in CODE_RANGES[domain]:
                raw = previous.scope_controls.previous.previous.previous.elf_bytes(elf, stream, off, size)
                result[domain+':'+hex(off)] = dict(size=size, hex=raw.hex(), sha256=raw_hash(raw))
    assert {key: row['sha256'] for key, row in result.items()} == CODE_SHA256
    return result


def component_case(path, base, label):
    pages, packed, obj, pointer = fixture.fresh(path, base, label)
    _write_span(pages, packed, (base+TARGET).to_bytes(8, 'little'))
    expected, actual, seen = [], [], set()
    watched = {(page << 12, 4096): None for page in pages
               if not fixture.G+0xD000 <= page << 12 < fixture.G+0xF000}
    def native_free(cpu):
        value = cpu.reg_read(arm.UC_ARM64_REG_X0)
        fixture.effect(label, obj, value, expected, lambda a,n: bytes(cpu.mem_read(a,n)), cpu.mem_write)
        return 0xBADC0DE
    _, _, allocations, services = fixture.oracle.native(path, base, WRAPPER, [packed], pages,
        host_imports={0x347FA0: native_free}, observed_memory=watched,
        instruction_observer=lambda cpu,pc: seen.add(pc-base))
    def model_free(tx, value):
        fixture.effect(label, obj, value, actual, lambda a,n: _read_span(tx,a,n), lambda a,b: _write_span(tx,a,b))
        return 0x1234
    result = objects.destroy_string_object(pages, object_address=obj, image_base=base, free=model_free, delete_object=False)
    assert result is None and not allocations and not services
    assert expected == actual and [row[0] for row in actual] == ([pointer] if pointer else [])
    assert all(_read_span(pages,a,n) == raw for (a,n),raw in watched.items())
    assert {WRAPPER,TARGET} <= seen and not {0x2484FC,0x32A264} & seen
    print('PASS base destructor component', hex(base), label, flush=True)
    return dict(image_base=hex(base), case=label, all_declared_pages_equal=True,
        ordered_payload_free_effects_equal=True, object_operator_delete_executed=False,
        native_snapshot_input=False, component_free_provider_explicit=True, physical_return_X0_compared=False)


def run(path, libc):
    parent = parent_evidence()
    grandparent = previous.parent_evidence()
    prefix = previous.previous.previous.previous.previous.bootstrap_prefix()
    prefix.digest.verify_images(path, libc)
    code = read_static(path, libc)
    def create(control):
        scenario = PostCRCBaseStringDestructorScenario(control)
        scenario.path, scenario.continue_to_svc = path, True
        scenario._postcrc_parent, scenario._pcb_parent = grandparent, parent
        return scenario
    print('Replaying original ELF/Bionic request prefix', flush=True)
    rows = prefix.digest.context.replay(path, libc, case_controls=[prefix.CONTROL], _extension_factory=create,
        _request_profile=prefix.digest.previous.previous.name.previous.previous.PROFILE['name'],
        _handler_read_profile=prefix.digest.context.NULL_PAYLOAD_READ_PROFILE['name'])
    assert len(rows) == 1 and rows[0]['recognized_live_argument'] and rows[0]['base_destructor_returned']
    controls = [component_case(path, base, label) for base in fixture.BASES for label in fixture.PROFILES]
    return dict(schema=SCHEMA, claims=claims(), providers=providers(), source_fingerprints=sources(),
        parent_evidence_sha256=sha256(previous.EVIDENCE),
        construction_evidence_sha256=sha256(CONSTRUCTION), static_code=code, native_controls=controls,
        case_result=rows[0], case_result_sha256=digest(rows[0]))


def _validate(data, parent):
    old = parent['case_result']
    construction = json.loads(CONSTRUCTION.read_text(encoding='utf-8'))['case_result']
    destination = construction['snapshots'][-1]['destination_object']
    assert set(data) == {'schema','claims','providers','source_fingerprints','parent_evidence_sha256',
        'construction_evidence_sha256','static_code','native_controls','case_result','case_result_sha256'}
    assert data['schema'] == SCHEMA and data['claims'] == claims() and data['providers'] == providers()
    assert data['source_fingerprints'] == sources()
    assert data['parent_evidence_sha256'] == sha256(previous.EVIDENCE)
    assert data['construction_evidence_sha256'] == sha256(CONSTRUCTION)
    assert set(data['static_code']) == set(CODE_SHA256)
    for domain, ranges in CODE_RANGES.items():
        for off, size in ranges:
            key = domain+':'+hex(off); entry = data['static_code'][key]; raw = bytes.fromhex(entry['hex'])
            assert set(entry) == {'size','hex','sha256'} and len(raw) == entry['size'] == size
            assert raw_hash(raw) == entry['sha256'] == CODE_SHA256[key]
    controls = data['native_controls']
    assert [(row['image_base'],row['case']) for row in controls] == [(hex(base),label) for base in fixture.BASES for label in fixture.PROFILES]
    for row in controls:
        assert row == dict(image_base=row['image_base'],case=row['case'],all_declared_pages_equal=True,
            ordered_payload_free_effects_equal=True,object_operator_delete_executed=False,native_snapshot_input=False,
            component_free_provider_explicit=True,physical_return_X0_compared=False)
    row = data['case_result']; assert data['case_result_sha256'] == digest(row)
    assert set(row) == {'recognized_live_argument','arguments','parent_case_result_sha256','parent_verified_fields',
        'instruction_observations','instruction_trace_sha256','observed_code_sha256','observation_sites','observed_code',
        'snapshots','native_writes','free_events','new_allocator_events','allocator_aux_events','new_SVC_events',
        'actual_allocator_counts','explicit_service_counts','protected_ranges','next_VM_call','base_destructor_returned',
        'final_libc_SVC','final_main_SVC'}
    assert row['recognized_live_argument'] is row['base_destructor_returned'] is True
    assert row['parent_case_result_sha256'] == digest(old) and row['parent_verified_fields'] == sorted(old)
    args = row['arguments']
    assert args == dict(object_address=destination['address'],retained_live_object_regions=['pair_destination_object'],
        argument_matches_pair_destination=True,pair_destination_constructed=True,prior_pair_destination_address=destination['address'],
        object_operator_delete_selected=False,void_return_X0_compared=False,payload_address=destination['payload_address'],
        payload_capacity=destination['capacity_u32'],initial_length=destination['length_u32'])
    assert args['initial_length'] == 42 and args['payload_capacity'] == 64
    sites, code = row['observation_sites'], row['observed_code']; h = hashlib.sha256()
    assert len(sites) == row['instruction_observations'] == 888 < MAX_OBSERVATIONS and set(sites) == set(code)
    assert digest(code) == row['observed_code_sha256']
    for key in sites:
        raw = bytes.fromhex(code[key]); assert len(raw) == 4; h.update(key.encode()+raw)
    assert h.hexdigest() == row['instruction_trace_sha256']
    assert sites[:5] == ['main:'+hex(off) for off in (VM_CALL,WRAPPER,WRAPPER+4,WRAPPER+8,TARGET)]
    assert sites[-1] == 'main:'+hex(VM_CALL) and sites.count(sites[-1]) == 2
    assert sites.count('libc:'+hex(FREE)) == sites.count('main:'+hex(VM_RESUME)) == 1
    assert not {'main:0x2484fc','main:0x32a264'} & set(sites)
    for domain, ranges in CODE_RANGES.items():
        for off, size in ranges:
            raw = bytes.fromhex(data['static_code'][domain+':'+hex(off)]['hex'])
            for pc in range(off,off+size,4):
                if domain+':'+hex(pc) in code: assert code[domain+':'+hex(pc)] == raw[pc-off:pc-off+4].hex()
    snapshots = row['snapshots']; assert len(snapshots) == 9
    by_kind = {snap['kind']:snap for snap in snapshots}; assert len(by_kind) == 9
    first, last = snapshots[0], snapshots[-1]; returned = by_kind['base_destructor_callback_return']
    assert first['kind'] == 'base_destructor_VM_call' and first['index'] == 1
    assert last['kind'] == 'before_next_VM_call' and last['index'] == len(sites)
    assert all(a['index'] < b['index'] for a,b in zip(snapshots,snapshots[1:]))
    assert first['VM_cursor'] == returned['VM_cursor'] == '0x10a43c' and last['VM_cursor'] == '0x10a464'
    assert first['descriptor_address'] == old['next_VM_call']['descriptor_address']
    assert first['descriptor_sha256'] == old['next_VM_call']['descriptor_sha256']
    assert first['SP'] == returned['SP'] and first['callee_saved_sha256'] == returned['callee_saved_sha256']
    assert returned['index'] == 154
    for snap in snapshots:
        assert set(snap) == set(first) and snap['registers'] == {} and snap['payload_fields'] == {}
        assert sites[snap['index']-1] == snap['pc']
        assert snap['object_storage_address'] == args['object_address'] and snap['object_storage_width'] == 24
        assert snap['payload_address'] == args['payload_address'] and snap['payload_capacity'] == args['payload_capacity']
        assert snap['diagnostic'] == first['diagnostic'] == old['snapshots'][-1]['diagnostic']
        assert snap['protected_regions_sha256'] == first['protected_regions_sha256']
        assert snap['VM_state_address'] == first['VM_state_address'] and snap['descriptor_width'] == 48
        assert snap['object_lifetime_ended'] is (snap['index'] >= returned['index'])
        assert snap['payload_deallocation_started'] is (snap['index'] >= 16)
        if snap['index'] >= returned['index']: assert snap['object_fields'] == {}
        else: assert set(snap['object_fields']) == set(first['object_fields'])
        if snap['index'] <= returned['index']: assert snap['descriptor_sha256'] == first['descriptor_sha256']
    assert first['object_fields'] == dict(vtable_offset='0x34f5f8',capacity_u32=64,length_storage_i32=42,
        payload_pointer_is_NULL=False,payload_pointer_matches_initial=True)
    cleared, reset = by_kind['payload_pointer_clear_complete'], by_kind['scalar_reset_complete']
    assert cleared['index'] == 148 and cleared['object_fields']['payload_pointer_is_NULL'] is True
    assert reset['index'] == 151 and reset['object_fields']['payload_pointer_is_NULL'] is True
    assert reset['object_fields']['capacity_u32'] == 0 and reset['object_fields']['length_storage_i32'] == -221
    assert row['free_events'] == [dict(argument_address=args['payload_address'],free_PLT_index=15,
        Bionic_free_entry_index=16,return_index=147,return_PC='main:0x2484e0')]
    assert sites[14] == 'main:0x347fa0' and sites[15] == 'libc:'+hex(FREE) and sites[146] == 'main:0x2484e0'
    assert row['new_allocator_events'] == [['free',int(args['payload_address'],16)]]
    assert row['allocator_aux_events'] == row['new_SVC_events'] == []
    counts = deepcopy(old['ledgers']['allocator_counts']); counts['free'] += 1
    assert row['actual_allocator_counts'] == counts
    assert row['explicit_service_counts'] == old['ledgers']['inherited_service_counts']
    assert row['final_libc_SVC'] == old['ledgers']['inherited_libc_SVC']
    assert row['final_main_SVC'] == old['ledgers']['inherited_main_SVC']
    regions = subtract_ranges([(r['label'],int(r['address'],16),r['size']) for r in old['protected_ranges']],
        [(int(args['object_address'],16),24),(int(args['payload_address'],16),args['payload_capacity'])])
    assert row['protected_ranges'] == [dict(label=l,address=hex(a),size=n) for l,a,n in regions]
    object_writes = []
    for write in row['native_writes']:
        assert set(write) == {'index','PC','address','size'} and write['size'] > 0
        assert sites[write['index']-1] == write['PC']
        assert not any(previous.previous.overlaps(write['address'],write['size'],r) for r in row['protected_ranges'])
        if write['index'] < returned['index']:
            assert not previous.previous.overlaps(write['address'],write['size'],dict(address=first['descriptor_address'],size=48))
            if previous.previous.overlaps(write['address'],write['size'],dict(address=args['object_address'],size=24)): object_writes.append(write)
        if previous.previous.overlaps(write['address'],write['size'],dict(address=args['payload_address'],size=64)):
            assert 16 <= write['index'] < returned['index']
    obj = int(args['object_address'],16)
    assert object_writes == [dict(index=12,PC='main:0x2484d4',address=hex(obj),size=8),
        dict(index=147,PC='main:0x2484e0',address=hex(obj+16),size=8),
        dict(index=150,PC='main:0x2484ec',address=hex(obj+8),size=8)]
    call = row['next_VM_call']
    assert set(call) == {'index','callsite_offset','VM_cursor_offset','descriptor_address','descriptor_width','descriptor_sha256',
        'wrapper_offset','target_offset','wrapper_code_hex','wrapper_code_sha256','VM_call_executed','wrapper_executed','target_executed'}
    assert call['index'] == 888 and call['callsite_offset'] == hex(VM_CALL) and call['VM_cursor_offset'] == last['VM_cursor']
    assert call['descriptor_width'] == 48 and call['wrapper_offset'] == '0x28883c' and call['target_offset'] == '0x261404'
    assert call['wrapper_code_hex'] == data['static_code']['main:0x28883c']['hex']
    assert raw_hash(bytes.fromhex(call['wrapper_code_hex'])) == call['wrapper_code_sha256']
    assert all(call[key] is False for key in ('VM_call_executed','wrapper_executed','target_executed'))


def validate(data):
    _validate(data, parent_evidence())


def damaged_evidence_rejected(data):
    parent = parent_evidence()
    changes = [
        (('claims','stack_object_storage_not_freed'),False),
        (('claims','complete_standalone_signer_verified'),True),
        (('providers','new_providers'),['hidden']),
        (('source_fingerprints','string_model_sha256'),'0'*64),
        (('construction_evidence_sha256',),'0'*64),
        (('case_result','arguments','argument_matches_pair_destination'),False),
        (('case_result','free_events',0,'argument_address'),data['case_result']['arguments']['object_address']),
        (('case_result','snapshots',-2,'object_fields'),{'stale':True}),
        (('case_result','snapshots',-2,'object_lifetime_ended'),False),
        (('case_result','snapshots',-1,'payload_fields'),{'bytes':'omitted'}),
        (('case_result','snapshots',-1,'registers'),{'x0':'0x1'}),
        (('case_result','new_allocator_events'),[]),
        (('case_result','next_VM_call','target_offset'),'0x2484fc'),
        (('case_result','next_VM_call','VM_call_executed'),True),
        (('case_result','raw_CRC'),'omitted'),
    ]
    for path, value in changes:
        bad = deepcopy(data); target = bad
        for key in path[:-1]: target = target[key]
        target[path[-1]] = value
        if path[0] == 'case_result': bad['case_result_sha256'] = digest(bad['case_result'])
        try: _validate(bad,parent)
        except (AssertionError,KeyError,ValueError,TypeError,IndexError): continue
        raise AssertionError(f'damaged base-destructor evidence accepted: {path}')
    return len(changes)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf',type=Path); parser.add_argument('--libc',type=Path)
    parser.add_argument('--compare-case',type=Path,help='optional independent case JSON, used only while capturing')
    modes = parser.add_mutually_exclusive_group(); modes.add_argument('--capture',action='store_true'); modes.add_argument('--replay',action='store_true')
    args = parser.parse_args()
    if (args.capture or args.replay) and (args.elf is None or args.libc is None): parser.error('--capture and --replay require --elf and --libc')
    if args.compare_case is not None and not args.capture: parser.error('--compare-case requires --capture')
    if args.capture:
        if EVIDENCE.exists(): raise FileExistsError('frozen evidence exists; refusing overwrite')
        data = run(args.elf,args.libc)
        if args.compare_case is not None:
            reference = json.loads(args.compare_case.read_text(encoding='utf-8'))
            if isinstance(reference,list): assert len(reference)==1; reference=reference[0]
            assert data['case_result'] == reference,'independent prototype and canonical case differ'
        validate(data); rejected = damaged_evidence_rejected(data)
        with EVIDENCE.open('x',encoding='utf-8',newline='\n') as stream: stream.write(json.dumps(data,indent=2)+'\n')
    else:
        data = json.loads(EVIDENCE.read_text(encoding='utf-8')); validate(data); rejected = damaged_evidence_rejected(data)
        if args.replay: assert run(args.elf,args.libc)==data,'fresh replay differs'
    print(json.dumps(dict(schema=SCHEMA,native_controls=len(data['native_controls']),damaged_evidence_rejected=rejected,
        instruction_observations=data['case_result']['instruction_observations'],base_destructor_returned=True,
        actual_next_VM_call_executed=False,complete_standalone_signer_verified=False)))


if __name__ == '__main__':
    main()
