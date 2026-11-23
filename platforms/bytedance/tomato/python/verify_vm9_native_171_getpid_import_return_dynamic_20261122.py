"""Bind the evidenced getpid ABS64 import and return through its native wrapper."""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as arm

import verify_vm9_native_171_post_configuration_callback_boundary_dynamic_20261122 as previous

EVIDENCE = previous.EVIDENCE.with_name('vm9_native_171_getpid_import_return_dynamic_20261122.json')
SCHEMA = 'vm9-native-171-getpid-import-return-dynamic-20261122-v1'
LIBC_BASE, IMPORT_SLOT, GETPID, PID_SVC = 0x51000000, 0x3833B0, 0x1FE6C, 0x6B030
VM_CALL, VM_RESUME, WRAPPER, INDIRECT = previous.CALLSITE, previous.VM_RESUME, previous.NULL_WRAPPER, previous.NULL_CALL
PID_RESULT = 919
GETPID_CODE = '40d03bd5010440f9201440b940000034c0035fd66b2c0114'
SYSCALL_CODE = '881580d2010000d41f0440b1009480daa87bdc54c0035fd6'
MAX_OBSERVATIONS = 2000
ORIGIN = ((0x16F974, 0x109628, 8, 9), (0x171268, 0x10962C, 8, 15))
ORIGIN_CODE = {0x16F96C: '89696df8', 0x16F974: '897b2ef8',
               0x171240: '8f7b6ef8', 0x171268: '2f6a30f8'}
sha256, digest, raw_hash = previous.sha256, previous.digest, previous.raw_hash


def prior_evidence():
    data = json.loads(previous.EVIDENCE.read_text(encoding='utf-8'))
    previous.validate(data)
    return data


def source_fingerprints():
    return dict(getpid_import_verifier_sha256=sha256(Path(__file__)),
                inherited_source_fingerprints=previous.source_fingerprints())


def provenance(parent):
    return dict(inherited_callback_boundary_evidence_sha256=sha256(previous.EVIDENCE),
                Metasec_sha256=parent['input_provenance']['Metasec_sha256'],
                Bionic_sha256=parent['input_provenance']['Bionic_sha256'])


def file_read(elf, address, size):
    segment = next(s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD'
                   and s['p_vaddr'] <= address and address+size <= s['p_vaddr']+s['p_filesz'])
    return segment.data()[address-segment['p_vaddr']:address-segment['p_vaddr']+size]


def static_binding(path, libc):
    with path.open('rb') as stream:
        elf = ELFFile(stream)
        rows = []
        for section in elf.iter_sections():
            if section['sh_type'] != 'SHT_RELA':
                continue
            symbols = elf.get_section(section['sh_link'])
            for relocation in section.iter_relocations():
                if relocation['r_offset'] != IMPORT_SLOT:
                    continue
                symbol = symbols.get_symbol(relocation['r_info_sym'])
                assert symbol.name == 'getpid' and symbol['st_shndx'] == 'SHN_UNDEF'
                assert relocation['r_info_type'] == 257 and relocation['r_addend'] == 0
                rows.append(dict(section=section.name, symbol=symbol.name,
                    symbol_index=relocation['r_info_sym'], type=257, addend=0,
                    import_slot_offset=hex(IMPORT_SLOT), undefined=True))
        assert len(rows) == 1 and file_read(elf, IMPORT_SLOT, 8) == bytes(8)
        assert file_read(elf, WRAPPER, 28).hex() == previous.NULL_CODE
        for pc, code in ORIGIN_CODE.items():
            assert file_read(elf, pc, 4).hex() == code
    with libc.open('rb') as stream:
        elf = ELFFile(stream)
        exports = [s for s in elf.get_section_by_name('.dynsym').iter_symbols()
                   if s.name == 'getpid' and s['st_shndx'] != 'SHN_UNDEF']
        assert len(exports) == 1 and exports[0]['st_value'] == GETPID
        assert file_read(elf, GETPID, 24).hex() == GETPID_CODE
        assert file_read(elf, PID_SVC-4, 24).hex() == SYSCALL_CODE
    return dict(relocation=rows[0], unresolved_file_word='0x0', libc_export_offset=hex(GETPID),
                resolved_target=hex(LIBC_BASE+GETPID), libc_getpid_code_hex=GETPID_CODE,
                libc_syscall_code_hex=SYSCALL_CODE, wrapper_code_hex=previous.NULL_CODE,
                origin_instruction_bytes={hex(pc): code for pc,code in ORIGIN_CODE.items()})


def providers():
    return dict(inherited=previous.providers(),
        binding='only the getpid ABS64 slot, after the 26 returned callbacks; metadata-derived matching-libc export',
        syscall_172=dict(result=PID_RESULT, kind='explicit synthetic getpid result; no host PID read'),
        inherited_service_and_SVC_ledgers='kept separate from the added syscall-172 ledger',
        maximum_instruction_observations=MAX_OBSERVATIONS)


def claims_for():
    return dict(evidence_label='Sample verified',
        actual_VM_import_read_and_descriptor_store_verified=True,
        only_one_ABS64_import_slot_bound=True, public_ELF_loader_changed=False,
        inherited_instruction_trace_and_26_returned_callbacks_preserved=True,
        matching_Bionic_getpid_and_syscall_172_executed=True,
        explicit_syscall_172_result=PID_RESULT, host_PID_read=False,
        wrapper_W0_store_and_padding_verified=True, callback_returned=True,
        SP_and_X19_X29_restored=True, zero_PID_cache_preserved=True,
        inherited_allocator_service_JNI_and_SVC_ledgers_unchanged=True,
        next_VM_instruction_executed=False, getppid_executed=False,
        complete_dynamic_linker_verified=False, current_native_suffix_return_verified=False,
        complete_standalone_signer_verified=False, ordinary_Cronet_six_headers_verified=False,
        Android_execution=False, online_acceptance_verified=False,
        physical_PAC_authentication_verified=False, native_memory_used_as_python_model_input=False)


class GetpidScenario(previous.CallbackBoundaryScenario):
    def __init__(self, control):
        super().__init__(control)
        self._pid_bound = False
        self._pid_active = False
        self._pid_done = False
        self._pid_count = 0
        self._pid_trace = hashlib.sha256()
        self._pid_code = {}
        self._pid_pcs = []
        self._pid_reads, self._pid_writes, self._pid_syscalls = [], [], []
        self._pid_old = prior_evidence()['case_result']
        self._pid_prefix = None

    def native_runner(self, *args, **kwargs):
        old_read, old_write, old_syscall = (kwargs['memory_read_observer'], kwargs['memory_write_observer'], kwargs['syscall_handler'])
        def read(cpu,address,size):
            pc=cpu.reg_read(arm.UC_ARM64_REG_PC)-self.image
            if self._pid_bound and not self._pid_active:
                if address==self.image+IMPORT_SLOT:
                    assert pc==0x16F96C and size==8 and self._tail_count==28214
                    assert self._reg(cpu,12)==self.image+0x383230 and self._reg(cpu,13)==0x180
                    assert self._reg(cpu,14)==1
                    self._pid_vreg=self._reg(cpu,28)+8
                    assert self._u(cpu,address)==LIBC_BASE+GETPID
                    self._pid_reads.append(dict(kind='ABS64_import_read',native_pc=hex(pc),
                        bytecode='0x109628',parent_index=self._tail_count,address=hex(address),
                        size=size,value=hex(self._u(cpu,address)),virtual_register=1,
                        observed_cursor=hex(self._u(cpu,self._reg(cpu,19))-self.image)))
                elif pc==0x171240:
                    assert address==self._pid_vreg and size==8 and self._tail_count==28299
                    assert self._reg(cpu,14)==1 and self._u(cpu,address)==LIBC_BASE+GETPID
                    self._pid_reads.append(dict(kind='virtual_register_read',native_pc=hex(pc),
                        bytecode='0x10962c',parent_index=self._tail_count,address=hex(address),
                        size=size,value=hex(self._u(cpu,address)),virtual_register=1,
                        observed_cursor=hex(self._u(cpu,self._reg(cpu,19))-self.image)))
            if old_read:old_read(cpu,address,size)
        def write(cpu,address,size):
            pc=cpu.reg_read(arm.UC_ARM64_REG_PC)-self.image
            if self._pid_bound and not self._pid_active:
                for expected_pc,cursor,width,reg in ORIGIN:
                    if pc==expected_pc and self._u(cpu,self._reg(cpu,19))==self.image+cursor+(4 if pc==0x171268 else 0):
                        assert size==width and self._reg(cpu,reg)==LIBC_BASE+GETPID
                        expected_address=self._pid_vreg if pc==0x16F974 else int(self._pid_old['pending_callback']['descriptor_address'],16)
                        assert address==expected_address
                        self._pid_writes.append(dict(native_pc=hex(pc),bytecode=hex(cursor),
                            parent_index=self._tail_count,address=hex(address),size=size,
                            source_register='x'+str(reg),value=hex(self._reg(cpu,reg)),
                            observed_cursor=hex(self._u(cpu,self._reg(cpu,19))-self.image)))
            if old_write:old_write(cpu,address,size)
        def syscall(cpu,number):
            if number!=172:return old_syscall(cpu,number)
            assert self._pid_active and not self._pid_syscalls and self._pid_svc_seen
            assert cpu.reg_read(arm.UC_ARM64_REG_PC)==LIBC_BASE+PID_SVC+4 and self._reg(cpu,8)==172
            self._pid_syscalls.append(dict(libc_svc_offset=hex(PID_SVC),number=172,
                provider='explicit synthetic result',result=PID_RESULT))
            return PID_RESULT
        kwargs.update(memory_read_observer=read,memory_write_observer=write,syscall_handler=syscall)
        return super().native_runner(*args,**kwargs)

    def _return_tail_call(self, cpu):
        super()._return_tail_call(cpu)
        if len(self._tail_calls) != 26:
            return
        assert self._tail_count == 28077 and self._tail_calls == self._pid_old['callbacks']
        assert not self._pid_bound and self._u(cpu, self.image+IMPORT_SLOT) == 0
        adjacent=bytes(cpu.mem_read(self.image+IMPORT_SLOT+8,8))
        assert adjacent==bytes(8)
        cpu.mem_write(self.image+IMPORT_SLOT, (LIBC_BASE+GETPID).to_bytes(8, 'little'))
        assert bytes(cpu.mem_read(self.image+IMPORT_SLOT+8,8))==adjacent
        self._pid_bound = True
        self._pid_binding = dict(at_parent_observation_index=28077, symbol='getpid',
            slot_offset=hex(IMPORT_SLOT), before='0x0', after=hex(LIBC_BASE+GETPID),
            relocation_type=257, addend=0, descriptor_not_written_by_binding=True,
            adjacent_getppid_slot_preserved=True)

    def _start_tail_call(self, cpu, pc):
        if len(self._tail_calls)!=26:return super()._start_tail_call(cpu,pc)
        old=self._pid_old['pending_callback']
        assert self._pid_bound and self._tail_call is None and self._pending is None
        assert self._tail_count==28557 and self._reg(cpu,8)==self.image+WRAPPER
        self._descriptor=self._reg(cpu,0)
        assert hex(self._descriptor)==old['descriptor_address']
        raw=bytes(cpu.mem_read(self._descriptor,32))
        assert int.from_bytes(raw[:8],'little')==LIBC_BASE+GETPID
        assert (bytes(8)+raw[8:]).hex()==old['descriptor_before_hex']
        assert self._u(cpu,self._reg(cpu,19))==self.image+0x10963C
        assert len(self._pid_reads)==len(self._pid_writes)==2,(self._pid_reads,self._pid_writes)
        assert self._pid_writes[-1]['address']==hex(self._descriptor)
        self._pid_descriptor_before=raw
        self._sp=cpu.reg_read(arm.UC_ARM64_REG_SP)
        self._saved=[self._reg(cpu,n) for n in range(19,30)]
        self._pending=dict(wrapper_path=[])

    def _observe_pending(self, cpu, pc):
        off=pc-self.image
        if off==WRAPPER:assert bytes(cpu.mem_read(pc,28)).hex()==previous.NULL_CODE
        if WRAPPER<=off<=INDIRECT:self._pending['wrapper_path'].append(hex(off))
        if off!=INDIRECT:return
        old=self._pid_old
        assert self._tail_count==28561 and self._tail_trace.hexdigest()==old['instruction_trace_sha256']
        assert digest(self._tail_code)==old['observed_code_sha256']
        assert self._tail_first==old['first_pc_offsets'] and self._tail_pcs==old['tail_pc_offsets']
        assert self._pending['wrapper_path']==[hex(a) for a in range(WRAPPER,INDIRECT+4,4)]
        assert self._reg(cpu,0)==self._reg(cpu,19)==self._descriptor
        assert self._reg(cpu,8)==self._u(cpu,self._descriptor)==LIBC_BASE+GETPID
        assert self._reg(cpu,30)==self.image+VM_RESUME
        assert cpu.reg_read(arm.UC_ARM64_REG_SP)==self._sp-16
        assert self._u(cpu,self._sp-16)==self.image+VM_RESUME and self._u(cpu,self._sp-8)==self._saved[0]
        assert bytes(cpu.mem_read(self._descriptor,32))==self._pid_descriptor_before
        self._pid_prefix=dict(returned_callbacks_verified=26,
            returned_callbacks_sha256=digest(self._tail_calls),instruction_observations=self._tail_count,
            instruction_trace_sha256=self._tail_trace.hexdigest(),observed_code_sha256=digest(self._tail_code),
            pending_descriptor_differs_only_in_resolved_target=True,
            original_wrapper_frame_preserved=True)
        self._pid_active=True
        self._pid_observe_pc(cpu,pc)

    def _pid_observe_pc(self, cpu, pc):
        self._pid_count += 1
        assert self._pid_count < MAX_OBSERVATIONS
        domain, offset = ('libc', pc-LIBC_BASE) if LIBC_BASE <= pc < LIBC_BASE+0x100000 else ('main', pc-self.image)
        raw = bytes(cpu.mem_read(pc,4))
        self._pid_trace.update(domain.encode()+offset.to_bytes(8,'little')+raw)
        self._pid_code[domain+':'+hex(offset)] = raw.hex()
        self._pid_pcs.append([domain, hex(offset)])

    def _base_observe(self, cpu, pc, state):
        if self._pid_active and pc == self.image+INDIRECT:
            # This precise previously-unresolved BLR is now constrained to getpid.
            previous.previous.bootstrap.module_prefix().digest.Scenario.observe(self,cpu,pc,state)
            return
        return super()._base_observe(cpu,pc,state)

    def pre_observe(self, cpu, pc, state):
        if self._pid_active and pc == LIBC_BASE+PID_SVC:
            assert not getattr(self,'_pid_svc_seen',False) and self._reg(cpu,8) == 172
            assert bytes(cpu.mem_read(pc,4)).hex() == '010000d4'
            self._pid_svc_seen = True
            self._pid_observe_pc(cpu,pc)
            # The inherited context rejects 172; this stage records it separately.
            return True
        return super().pre_observe(cpu,pc,state)

    def observe(self, cpu, pc, state):
        if not self._pid_active:
            return super().observe(cpu,pc,state)
        self._pid_observe_pc(cpu,pc)
        if pc == LIBC_BASE+GETPID:
            assert self._reg(cpu,0) == self._reg(cpu,19) == self._descriptor
            assert self._reg(cpu,30) == self.image+0x28864C
            self._pid_tp = cpu.reg_read(arm.UC_ARM64_REG_TPIDR_EL0)
            self._pid_pthread = self._u(cpu,self._pid_tp+8)
            self._pid_tls = bytes(cpu.mem_read(self._pid_tp,48))
            self._pid_cache = bytes(cpu.mem_read(self._pid_pthread+0x14,4))
            assert self._pid_cache == bytes(4)
            assert bytes(cpu.mem_read(pc,24)).hex() == GETPID_CODE
        if pc == self.image+0x28864C:
            assert len(self._pid_syscalls) == 1 and self._reg(cpu,0) == PID_RESULT
            assert bytes(cpu.mem_read(self._descriptor,32)) == self._pid_descriptor_before
        if pc == self.image+VM_RESUME:
            assert self._reg(cpu,0) == PID_RESULT
            assert cpu.reg_read(arm.UC_ARM64_REG_SP) == self._sp
            assert [self._reg(cpu,n) for n in range(19,30)] == self._saved
            expected = bytearray(self._pid_descriptor_before)
            expected[8:12] = PID_RESULT.to_bytes(4,'little')
            after = bytes(cpu.mem_read(self._descriptor,32))
            assert after == expected
            assert bytes(cpu.mem_read(self._pid_tp,48)) == self._pid_tls
            assert bytes(cpu.mem_read(self._pid_pthread+0x14,4)) == self._pid_cache
            self._pid_return = dict(return_offset=hex(VM_RESUME),returned_x0=hex(PID_RESULT),
                descriptor_address=hex(self._descriptor), descriptor_before_hex=self._pid_descriptor_before.hex(),
                descriptor_after_hex=after.hex(), output_width=4, descriptor_padding_preserved=True,
                stack_pointer_restored=True, callee_saved_registers_restored=True,
                thread_pointer=hex(self._pid_tp), pthread_pointer=hex(self._pid_pthread),
                zero_cached_PID_preserved=True, observed_TLS_bytes_preserved=True,
                callback_returned=True, next_VM_instruction_executed=False)
            self._pid_done = True
        self._base_observe(cpu,pc,state)
        if self._pid_done:
            cpu.emu_stop()
            cpu.reg_write(arm.UC_ARM64_REG_PC,previous.previous.bootstrap.module_prefix().digest.context.outer.oracle.STOP)

    def finish(self, result, state, proof):
        old = self._pid_old
        assert self._pid_done and self._pid_prefix is not None
        assert self._tail_calls == old['callbacks'] and self._tail_count == old['instruction_observations']
        assert self._tail_trace.hexdigest() == old['instruction_trace_sha256']
        assert digest(self._tail_code) == old['observed_code_sha256']
        added = result['allocator_events'][len(self._tail_events_before):]
        assert added == old['new_allocator_events']
        assert result['actual_allocator_counts'] == old['allocator_counts_after']
        assert result['explicit_service_counts'] == old['service_counts_after']
        for key,value in (('JNI_calls','jni_calls_after'),('libc_SVC_boundaries','libc_svc_after'),
                          ('main_image_SVC_boundaries','main_svc_after')):
            assert proof[key] == old[value]
        assert self.late_jni_calls == old['late_jni_calls_after'] and self.java_dispatch_calls == old['java_dispatch_after']
        return dict(control=old['control'], retained_prefix=self._pid_prefix, binding=self._pid_binding,
            import_reads=self._pid_reads, descriptor_stores=self._pid_writes,
            instruction_observations=self._pid_count, instruction_trace_sha256=self._pid_trace.hexdigest(),
            observed_code_sha256=digest(self._pid_code), pc_path=self._pid_pcs,
            syscall_172=self._pid_syscalls, callback_return=self._pid_return,
            allocator_counts=result['actual_allocator_counts'],service_counts=result['explicit_service_counts'],
            inherited_JNI_calls=proof['JNI_calls'],inherited_libc_SVC=proof['libc_SVC_boundaries'],
            inherited_main_SVC=proof['main_image_SVC_boundaries'],late_jni=self.late_jni_calls,
            java_dispatch=self.java_dispatch_calls,new_allocator_events=[])


def run(path,libc):
    parent = prior_evidence()
    p = previous.previous.bootstrap.module_prefix()
    p.digest.verify_images(path,libc)
    static = static_binding(path,libc)
    def create(control):
        scenario=GetpidScenario(control);scenario.path=path;scenario.continue_to_svc=True;return scenario
    rows=p.digest.context.replay(path,libc,case_controls=[p.CONTROL],_extension_factory=create,
        _request_profile=p.digest.previous.previous.name.previous.previous.PROFILE['name'],
        _handler_read_profile=p.digest.context.NULL_PAYLOAD_READ_PROFILE['name'])
    assert len(rows)==1
    return dict(schema=SCHEMA,claims=claims_for(),providers=providers(),input_provenance=provenance(parent),
        source_fingerprints=source_fingerprints(),static_binding=static,
        case_result=rows[0],case_result_sha256=digest(rows[0]))


def validate(data):
    parent=prior_evidence();old=parent['case_result']
    assert data['schema']==SCHEMA and data['claims']==claims_for() and data['providers']==providers()
    assert data['source_fingerprints']==source_fingerprints() and data['input_provenance']==provenance(parent)
    static=data['static_binding'];rel=static['relocation']
    assert rel['symbol']=='getpid' and rel['type']==257 and rel['addend']==0 and rel['undefined'] is True
    assert rel['section']=='.rela.dyn' and type(rel['symbol_index']) is int and rel['symbol_index']==20
    assert rel['import_slot_offset']==hex(IMPORT_SLOT) and static['unresolved_file_word']=='0x0'
    assert static['libc_export_offset']==hex(GETPID) and static['resolved_target']==hex(LIBC_BASE+GETPID)
    assert static['libc_getpid_code_hex']==GETPID_CODE and static['libc_syscall_code_hex']==SYSCALL_CODE
    assert static['wrapper_code_hex']==previous.NULL_CODE
    assert static['origin_instruction_bytes']=={hex(pc):code for pc,code in ORIGIN_CODE.items()}
    row=data['case_result'];assert data['case_result_sha256']==digest(row)
    assert row['control']==old['control']
    assert row['retained_prefix']==dict(returned_callbacks_verified=26,returned_callbacks_sha256=digest(old['callbacks']),
        instruction_observations=old['instruction_observations'],instruction_trace_sha256=old['instruction_trace_sha256'],
        observed_code_sha256=old['observed_code_sha256'],pending_descriptor_differs_only_in_resolved_target=True,
        original_wrapper_frame_preserved=True)
    assert row['binding']==dict(at_parent_observation_index=28077,symbol='getpid',slot_offset=hex(IMPORT_SLOT),
        before='0x0',after=hex(LIBC_BASE+GETPID),relocation_type=257,addend=0,descriptor_not_written_by_binding=True,adjacent_getppid_slot_preserved=True)
    assert len(row['import_reads'])==len(row['descriptor_stores'])==2
    source,vreg=row['import_reads'];vstore,dstore=row['descriptor_stores']
    assert vreg['address']==vstore['address']=='0x7004d370'
    expected_target=hex(LIBC_BASE+GETPID)
    assert source==dict(kind='ABS64_import_read',native_pc='0x16f96c',bytecode='0x109628',parent_index=28214,
        address=hex(old['control']['base']+IMPORT_SLOT),size=8,value=expected_target,virtual_register=1,observed_cursor='0x109628')
    assert vreg==dict(kind='virtual_register_read',native_pc='0x171240',bytecode='0x10962c',parent_index=28299,
        address=vstore['address'],size=8,value=expected_target,virtual_register=1,observed_cursor='0x109630')
    assert vstore==dict(native_pc='0x16f974',bytecode='0x109628',parent_index=28216,
        address=vreg['address'],size=8,source_register='x9',value=expected_target,observed_cursor='0x109628')
    assert dstore==dict(native_pc='0x171268',bytecode='0x10962c',parent_index=28309,
        address=old['pending_callback']['descriptor_address'],size=8,source_register='x15',value=expected_target,observed_cursor='0x109630')
    assert row['instruction_observations']==len(row['pc_path'])==16<MAX_OBSERVATIONS
    expected_path=[['main',hex(INDIRECT)]]+[['libc',hex(x)] for x in (0x1FE6C,0x1FE70,0x1FE74,0x1FE78,0x1FE80,
        0x6B02C,0x6B030,0x6B034,0x6B038,0x6B03C,0x6B040)]+[['main',hex(x)] for x in (0x28864C,0x288650,0x288654,VM_RESUME)]
    assert row['pc_path']==expected_path
    code={('libc',GETPID+j):GETPID_CODE[j*2:j*2+8] for j in range(0,24,4)}
    code.update({('libc',PID_SVC-4+j):SYSCALL_CODE[j*2:j*2+8] for j in range(0,24,4)})
    code.update({('main',WRAPPER+j):previous.NULL_CODE[j*2:j*2+8] for j in range(0,28,4)})
    code['main',VM_RESUME]='a50777a9'
    trace=hashlib.sha256();observed={}
    for domain,offset in expected_path:
        off=int(offset,16);raw=bytes.fromhex(code[domain,off])
        trace.update(domain.encode()+off.to_bytes(8,'little')+raw);observed[domain+':'+offset]=raw.hex()
    assert row['instruction_trace_sha256']==trace.hexdigest() and row['observed_code_sha256']==digest(observed)
    assert row['syscall_172']==[dict(libc_svc_offset=hex(PID_SVC),number=172,provider='explicit synthetic result',result=PID_RESULT)]
    returned=row['callback_return'];before=bytes.fromhex(returned['descriptor_before_hex'])
    assert len(before)==32 and int.from_bytes(before[:8],'little')==LIBC_BASE+GETPID
    assert (bytes(8)+before[8:]).hex()==old['pending_callback']['descriptor_before_hex']
    after=bytearray(before);after[8:12]=PID_RESULT.to_bytes(4,'little')
    assert returned['descriptor_after_hex']==after.hex() and returned['descriptor_address']==dstore['address']
    assert returned['return_offset']==hex(VM_RESUME) and returned['returned_x0']==hex(PID_RESULT)
    assert returned['output_width']==4 and returned['next_VM_instruction_executed'] is False
    assert returned['thread_pointer']=='0x7000a000' and returned['pthread_pointer']=='0x7000a200'
    for key in ('descriptor_padding_preserved','stack_pointer_restored','callee_saved_registers_restored',
                'zero_cached_PID_preserved','observed_TLS_bytes_preserved','callback_returned'):
        assert returned[key] is True
    for key,old_key in (('allocator_counts','allocator_counts_after'),('service_counts','service_counts_after'),
        ('inherited_JNI_calls','jni_calls_after'),('inherited_libc_SVC','libc_svc_after'),('inherited_main_SVC','main_svc_after'),
        ('late_jni','late_jni_calls_after'),('java_dispatch','java_dispatch_after')):
        assert row[key]==old[old_key]
    assert row['new_allocator_events']==[]


def damaged_evidence_rejected(data):
    changes=[(('claims','complete_standalone_signer_verified'),True),
             (('claims','host_PID_read'),True),(('claims','getppid_executed'),True),
             (('case_result','binding','after'),'0x0'),
             (('case_result','syscall_172',0,'result'),0),
             (('case_result','callback_return','callback_returned'),False),
             (('case_result','callback_return','stack_pointer_restored'),False),
             (('case_result','callback_return','descriptor_padding_preserved'),False)]
    changes += [
        (('static_binding','relocation','symbol'),'getppid'),
        (('static_binding','relocation','type'),1027),
        (('static_binding','relocation','addend'),8),
        (('static_binding','relocation','symbol_index'),21),
        (('static_binding','resolved_target'),'0x0'),
        (('static_binding','libc_getpid_code_hex'),'00'*24),
        (('case_result','binding','adjacent_getppid_slot_preserved'),False),
        (('case_result','pc_path'),[]),
        (('case_result','instruction_trace_sha256'),'0'*64),
        (('case_result','observed_code_sha256'),'0'*64),
        (('case_result','retained_prefix','pending_descriptor_differs_only_in_resolved_target'),False),
        (('case_result','callback_return','descriptor_after_hex'),'00'*32),
        (('case_result','callback_return','output_width'),8),
        (('case_result','callback_return','zero_cached_PID_preserved'),False),
        (('case_result','callback_return','next_VM_instruction_executed'),True)]
    for group in ('import_reads','descriptor_stores'):
        for i in range(2):
            for key,value in (('native_pc','0x0'),('bytecode','0x0'),('parent_index',0),
                              ('address','0x0'),('size',4),('value','0x0')):
                changes.append((('case_result',group,i,key),value))
    for key in ('inherited_JNI_calls','inherited_libc_SVC','inherited_main_SVC','late_jni','java_dispatch'):
        changes.append((('case_result',key),[]))
    for path,value in changes:
        bad=deepcopy(data);obj=bad
        for key in path[:-1]:obj=obj[key]
        obj[path[-1]]=value
        if path[0]=='case_result':bad['case_result_sha256']=digest(bad['case_result'])
        try:validate(bad)
        except (AssertionError,ValueError,TypeError,KeyError):continue
        raise AssertionError(f'damaged getpid evidence accepted: {path}')
    return len(changes)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf',type=Path);parser.add_argument('--libc',type=Path)
    mode=parser.add_mutually_exclusive_group()
    mode.add_argument('--capture',action='store_true');mode.add_argument('--replay',action='store_true')
    args=parser.parse_args()
    if (args.capture or args.replay) and (not args.elf or not args.libc):
        parser.error('--capture and --replay require --elf and --libc')
    if args.capture:
        if EVIDENCE.exists():raise FileExistsError('frozen evidence already exists; refusing overwrite')
        data=run(args.elf,args.libc);validate(data);rejected=damaged_evidence_rejected(data)
        with EVIDENCE.open('x',encoding='utf-8',newline='\n') as output:output.write(json.dumps(data,indent=2)+'\n')
    else:
        data=json.loads(EVIDENCE.read_text(encoding='utf-8'));validate(data);rejected=damaged_evidence_rejected(data)
        if args.replay:assert run(args.elf,args.libc)==data,'fresh getpid replay differs'
    print(json.dumps(dict(schema=SCHEMA,damaged_evidence_rejected=rejected,
        import_slot=hex(IMPORT_SLOT),native_getpid_return=PID_RESULT,
        instruction_observations=data['case_result']['instruction_observations'],
        stop_before=hex(VM_RESUME),complete_standalone_signer_verified=False)))


if __name__=='__main__':main()
