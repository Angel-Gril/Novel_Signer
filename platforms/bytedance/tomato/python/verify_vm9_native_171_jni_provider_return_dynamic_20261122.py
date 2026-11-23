"""Verify the original JNI tail wrapper with the inherited acquisition provider.

The provider replaces +0x26edc4; its native body and a real JVM do not execute.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as arm

import verify_vm9_native_171_thread_pointer_before_jni_dynamic_20261122 as previous
import verify_vm9_native_171_resolve_next_vm_callback_dynamic_20261121 as bootstrap
import verify_vm9_signer_objects as oracle

EVIDENCE = previous.EVIDENCE.with_name('vm9_native_171_jni_provider_return_dynamic_20261122.json')
SCHEMA = 'vm9-native-171-jni-provider-return-dynamic-20261122-v1'
VM_CALL, VM_RESUME = previous.VM_CALL, previous.VM_RESUME
WRAPPER, TARGET, NEXT_WRAPPER, NEXT_TARGET = 0x288788, 0x26EDC4, 0x288794, 0x282B84
ENV = 0x70007800
CODE_RANGES = ((WRAPPER,12),(TARGET,32),(NEXT_WRAPPER,28))
CODE_SHA256 = {
    '0x288788':'82295168e4332fdd8ee754ea9b86ffc5a592a6e6c42c0e1592ea18f55c95c565',
    '0x26edc4':'cc7fc601defb3c2faee594477be61f2b3269b986704a0074a9d46b4a7d4f04b5',
    '0x288794':'89dff6609a3af925ec6fb49b533294966a3036bec5a610457b9660cc73af8375'}
sha256, raw_hash, digest = previous.sha256, previous.raw_hash, previous.digest
PARENT_FIELDS = (
    'instruction_observations','instruction_trace_sha256','observed_code_sha256',
    'first_pc_offsets','tail_pc_offsets','retained_getppid','thread_callback',
    'cache_stores','helper_returns','MRS_TPIDR_EL0_executed','next_JNI_call')
LEDGERS = ('allocator_counts','inherited_service_counts','inherited_JNI_calls',
    'inherited_libc_SVC','inherited_main_SVC','inherited_syscall_172',
    'inherited_syscall_173','late_jni','java_dispatch')
MAX_OBSERVATIONS = 15000
NEXT_DESCRIPTOR_SHA256 = '4a8f978b15e45b5a4d21078d0d025028f9cfeb46f9a0e33b8aef6744c08d4992'


def prior_evidence():
    data=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'))
    previous.validate(data)
    return data


def source_fingerprints():
    return dict(jni_provider_return_verifier_sha256=sha256(Path(__file__)),
        thread_pointer_verifier_sha256=sha256(Path(previous.__file__)),
        acquisition_provider_source_sha256=sha256(Path(oracle.__file__)),
        inherited=previous.source_fingerprints())


def provenance(parent):
    return dict(parent_evidence_sha256=sha256(previous.EVIDENCE),
        parent_case_sha256=digest(parent['case_result']),
        library_sha256=oracle.LIBRARY_SHA256,
        inherited_input_provenance=parent['input_provenance'],
        native_snapshot_used_as_python_model_input=False)


def static_code(path):
    rows={}
    with path.open('rb') as stream:
        elf=ELFFile(stream)
        for off,size in CODE_RANGES:
            segment=next(s for s in elf.iter_segments() if s['p_type']=='PT_LOAD'
                and s['p_vaddr']<=off and off+size<=s['p_vaddr']+s['p_filesz'])
            stream.seek(segment['p_offset']+off-segment['p_vaddr']);raw=stream.read(size)
            assert len(raw)==size and raw_hash(raw)==CODE_SHA256[hex(off)]
            rows[hex(off)]=dict(size=size,hex=raw.hex(),sha256=raw_hash(raw))
    return rows


def providers():
    return dict(inherited=previous.providers(),new_providers=[],new_import_bindings=[],
        acquisition=dict(owner='verify_vm9_signer_objects.native',offset=hex(TARGET),
            real_jni_acquisition=False,environment=hex(ENV),write_width=8,
            output_pair_width=16,result_x0=0,return_to='X30',
            behavior='inherited host provider writes only output_pair[0:8]; native acquisition body is bypassed'),
        trace_scope='pre-instruction observations include the replaced target entry and final unexecuted VM BLR',
        maximum_instruction_observations=MAX_OBSERVATIONS)


def claims_for():
    return dict(evidence_label='Sample verified',thread_pointer_prefix_verified=True,
        original_VM_call_executed=True,original_tail_wrapper_executed=True,
        dynamic_target_argument_verified=True,inherited_acquisition_provider_returned=True,
        provider_output_width_and_preserved_tail_verified=True,
        original_acquisition_body_executed=False,real_ART_JVM_execution=False,
        next_VM_call_executed=False,new_providers_added=False,
        native_snapshot_used_as_python_model_input=False,complete_standalone_signer_verified=False,
        complete_VM_suffix_return_verified=False,ordinary_Cronet_six_headers_verified=False,
        Android_execution=False,physical_PAC_authentication_verified=False,online_acceptance_verified=False)


def control_specs():
    rows=[]
    for base in (0x122C0000,0x775C205000):
        for cross_page in (False,True):
            for env in (0,ENV):
                rows.append(dict(image_base=hex(base),cross_page=cross_page,
                    environment=hex(env),pair_address=hex(oracle.GUEST+(0x1FF8 if cross_page else 0x1800)),
                    pair_before_hex='a5'*16,pair_after_hex=env.to_bytes(8,'little').hex()+'a5'*8,
                    observed_pc_offsets=[hex(a) for a in (WRAPPER,WRAPPER+4,WRAPPER+8,TARGET)],
                    returned_x0=0,full_payload_memory_verified=True,descriptor_preserved=True,
                    stack_pointer_unchanged_at_provider=True,callee_saved_unchanged_at_provider=True,
                    acquisition_native_body_executed=False,provider_write_width=8))
    return rows


def independent_controls(path,libc):
    rows=[]
    for expected in control_specs():
        base=int(expected['image_base'],16);env=int(expected['environment'],16)
        pair=int(expected['pair_address'],16);descriptor=oracle.GUEST+0x1000
        pages=oracle.fresh_pages()
        raw=(base+TARGET).to_bytes(8,'little')+pair.to_bytes(8,'little')+bytes.fromhex('c3'*16)
        oracle._write_span(pages,descriptor,raw)
        before=oracle.flatten(pages);offset=pair-oracle.GUEST
        saved={getattr(arm,f'UC_ARM64_REG_X{n}'):0x120000+n for n in range(19,30)}
        observed=[]
        def observe(cpu,pc):
            observed.append(hex(pc-base))
            assert cpu.reg_read(arm.UC_ARM64_REG_SP)==oracle.GUEST+0xEF00
            assert all(cpu.reg_read(reg)==value for reg,value in saved.items())
            if pc==base+TARGET:
                assert cpu.reg_read(arm.UC_ARM64_REG_X0)==pair
                assert cpu.reg_read(arm.UC_ARM64_REG_X30)==oracle.STOP
        value,memory,allocations,ledger=oracle.native(path,base,WRAPPER,[descriptor],pages,
            env=env,libc=libc,extra_registers=saved,instruction_observer=observe,
            real_jni_acquisition=False,instruction_limit=16)
        target=bytearray(before[:0xA000]);target[offset:offset+8]=env.to_bytes(8,'little')
        assert memory==target and value==0 and allocations==ledger==[]
        assert observed==expected['observed_pc_offsets']
        rows.append(expected)
    return rows


class JniProviderScenario(previous.ThreadPointerScenario):
    def __init__(self,control):
        super().__init__(control)
        self._jni_active=False;self._jni_done=False;self._jni_returned=False
        self._jni_count=0;self._jni_trace=hashlib.sha256();self._jni_code={}
        self._jni_first=[];self._jni_tail=[];self._jni_offsets=[]
        self._jni_path=[];self._jni_reads=[];self._jni_old=prior_evidence()['case_result']

    def _track_jni(self,cpu,pc):
        assert self.image<=pc<self.image+0x400000
        self._jni_count+=1;assert self._jni_count<MAX_OBSERVATIONS
        off=pc-self.image;raw=bytes(cpu.mem_read(pc,4))
        self._jni_offsets.append(hex(off));self._jni_code[hex(off)]=raw.hex()
        self._jni_trace.update(off.to_bytes(8,'little')+raw)
        if len(self._jni_first)<16:self._jni_first.append(hex(off))
        self._jni_tail=(self._jni_tail+[hex(off)])[-16:]

    def _next_JNI_call(self,cpu,pc,state):
        super()._next_JNI_call(cpu,pc,state)
        values=(self._thread_count,self._thread_trace.hexdigest(),digest(self._thread_code),
            self._thread_first,self._thread_tail,self._thread_parent,self._thread_call,
            self._thread_stores,self._thread_helpers,self._thread_mrs,self._thread_next)
        for value,key in zip(values,PARENT_FIELDS):assert value==self._jni_old[key],key
        self._jni_parent=dict(case_result_sha256=digest(self._jni_old),verified_fields=list(PARENT_FIELDS),
            instruction_observations=self._thread_count,
            instruction_trace_sha256=self._thread_trace.hexdigest(),
            observed_code_sha256=digest(self._thread_code))
        self._jni_events_before=deepcopy(state['allocator_events_ref'])
        self._jni_descriptor=self._reg(cpu,0);self._jni_pair=self._u(cpu,self._jni_descriptor+8)
        self._jni_sp=cpu.reg_read(arm.UC_ARM64_REG_SP)
        self._jni_saved=[self._reg(cpu,n) for n in range(19,30)]
        self._jni_cache=bytes(cpu.mem_read(self.image+previous.CACHE,16))
        self._jni_call=deepcopy(self._thread_next)
        self._jni_call.update(call_index=1,wrapper_path=[],VM_call_executed=True)
        self._thread_done=False;self._thread_active=False;self._jni_active=True
        self._track_jni(cpu,pc)

    def native_runner(self,*args,**kwargs):
        assert kwargs['env']==ENV and not kwargs.get('real_jni_acquisition',False)
        old_read=kwargs['memory_read_observer']
        def read(cpu,address,size):
            if self._jni_active and cpu.reg_read(arm.UC_ARM64_REG_PC)==self.image+WRAPPER:
                assert size==8 and address in (self._jni_descriptor,self._jni_descriptor+8)
                self._jni_reads.append(dict(index=self._jni_count,pc_offset=hex(WRAPPER),
                    address=hex(address),width=size,value=hex(self._u(cpu,address))))
            if old_read:old_read(cpu,address,size)
        kwargs['memory_read_observer']=read
        return super().native_runner(*args,**kwargs)

    def _jni_return(self,cpu):
        assert self._jni_count==6 and self._jni_path==[hex(a) for a in range(WRAPPER,WRAPPER+12,4)]
        call=self._jni_call;assert call['JNI_provider_entered'] and self._reg(cpu,0)==0
        assert self._reg(cpu,30)==self.image+VM_RESUME
        assert cpu.reg_read(arm.UC_ARM64_REG_SP)==self._jni_sp
        assert [self._reg(cpu,n) for n in range(19,30)]==self._jni_saved
        before=bytes.fromhex(call['output_pair_before_hex'])
        after=bytes(cpu.mem_read(self._jni_pair,16))
        assert after==ENV.to_bytes(8,'little')+before[8:]
        assert bytes(cpu.mem_read(self._jni_descriptor,32)).hex()==call['descriptor_hex']
        assert len(self._jni_reads)==2
        call.update(return_index=6,return_offset=hex(VM_RESUME),returned_x0=0,
            wrapper_executed=True,wrapper_path=self._jni_path,
            dynamic_target_arguments={'x0':hex(self._jni_pair)},
            target_entry_observed=True,target_entry_index=5,
            target_executed=False,original_acquisition_body_executed=False,
            output_pair_after_hex=after.hex(),provider_write_width=8,
            output_pair_tail_preserved=True,descriptor_unchanged_at_return=True,
            stack_pointer_restored=True,callee_saved_registers_restored=True)
        self._jni_provider=dict(kind='inherited synthetic acquisition provider',offset=hex(TARGET),
            entry_index=5,return_index=6,output_pair_address=hex(self._jni_pair),
            environment=hex(ENV),write_width=8,pair_before_hex=before.hex(),pair_after_hex=after.hex(),
            result_x0=0,return_offset=hex(VM_RESUME),native_body_executed=False,real_ART_JVM_execution=False)
        self._jni_returned=True

    def _jni_next(self,cpu,pc):
        assert self._jni_returned and self._jni_count==1887 and self._reg(cpu,8)==self.image+NEXT_WRAPPER
        assert bytes(cpu.mem_read(pc,4)).hex()=='00013fd6'
        d=self._reg(cpu,0);raw=bytes(cpu.mem_read(d,32))
        assert raw_hash(raw)==NEXT_DESCRIPTOR_SHA256
        assert int.from_bytes(raw[:8],'little')==self.image+NEXT_TARGET
        cursor=self._u(cpu,self._reg(cpu,19))-self.image
        assert cursor==0x109C44
        self._jni_next_call=dict(index=self._jni_count,callsite_offset=hex(VM_CALL),
            call_instruction_bytes='00013fd6',wrapper_offset=hex(NEXT_WRAPPER),
            target_offset=hex(NEXT_TARGET),VM_cursor_offset=hex(cursor),descriptor_address=hex(d),
            descriptor_hex=raw.hex(),descriptor_sha256=raw_hash(raw),
            wrapper_code_hex=bytes(cpu.mem_read(self.image+NEXT_WRAPPER,28)).hex(),
            static_expected_target_arguments={'x0':hex(int.from_bytes(raw[8:16],'little'))},
            VM_call_executed=False,wrapper_executed=False,target_executed=False)
        assert bytes(cpu.mem_read(self.image+previous.CACHE,16))==self._jni_cache
        assert bytes(cpu.mem_read(self._jni_pair,16)).hex()==self._jni_call['output_pair_after_hex']
        self._jni_done=True

    def observe(self,cpu,pc,state):
        if not self._jni_active:return super().observe(cpu,pc,state)
        self._track_jni(cpu,pc);off=pc-self.image
        if WRAPPER<=off<WRAPPER+12:
            assert self._jni_count in (2,3,4)
            self._jni_path.append(hex(off))
            assert cpu.reg_read(arm.UC_ARM64_REG_SP)==self._jni_sp
            if off==WRAPPER:
                assert self._reg(cpu,0)==self._jni_descriptor
                assert bytes(cpu.mem_read(pc,12)).hex()==previous.CODE_HEX_JNI_WRAPPER
            if off==WRAPPER+4:
                assert self._reg(cpu,1)==self.image+TARGET and self._reg(cpu,8)==self._jni_pair
            if off==WRAPPER+8:assert self._reg(cpu,0)==self._jni_pair
        if off==TARGET:
            assert self._jni_count==5 and self._reg(cpu,0)==self._jni_pair
            assert self._reg(cpu,30)==self.image+VM_RESUME
            assert cpu.reg_read(arm.UC_ARM64_REG_SP)==self._jni_sp
            assert bytes(cpu.mem_read(self._jni_pair,16)).hex()==self._jni_call['output_pair_before_hex']
            self._jni_call['JNI_provider_entered']=True
        if off==VM_RESUME and not self._jni_returned:self._jni_return(cpu)
        if off==VM_CALL:self._jni_next(cpu,pc)
        self._base_observe(cpu,pc,state)
        if self._jni_done:
            cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,oracle.STOP)

    def finish(self,result,state,proof):
        assert self._jni_done and self._jni_returned
        assert result['allocator_events']==self._jni_events_before
        ledgers=dict(allocator_counts=result['actual_allocator_counts'],
            inherited_service_counts=result['explicit_service_counts'],inherited_JNI_calls=proof['JNI_calls'],
            inherited_libc_SVC=proof['libc_SVC_boundaries'],inherited_main_SVC=proof['main_image_SVC_boundaries'],
            inherited_syscall_172=self._pid_syscalls,inherited_syscall_173=self._pp_syscalls,
            late_jni=self.late_jni_calls,java_dispatch=self.java_dispatch_calls)
        for key in LEDGERS:assert ledgers[key]==self._jni_old[key],key
        return dict(control=self._jni_old['control'],retained_thread_pointer=self._jni_parent,
            instruction_observations=self._jni_count,instruction_trace_sha256=self._jni_trace.hexdigest(),
            observed_code_sha256=digest(self._jni_code),observed_code=self._jni_code,
            observation_pc_offsets=self._jni_offsets,
            first_pc_offsets=self._jni_first,tail_pc_offsets=self._jni_tail,
            JNI_callback=self._jni_call,wrapper_descriptor_reads=self._jni_reads,
            acquisition_provider=self._jni_provider,next_VM_call=self._jni_next_call,
            thread_cache_preserved=True,new_allocator_events=[],**ledgers,
            stop_boundary=dict(kind='before_next_VM_call',stop_before=hex(VM_CALL),
                next_VM_call_executed=False,original_acquisition_body_executed=False))


def run(path,libc):
    parent=prior_evidence();p=bootstrap.module_prefix();p.digest.verify_images(path,libc)
    code=static_code(path)
    def create(control):
        s=JniProviderScenario(control);s.path=path;s.continue_to_svc=True;return s
    rows=p.digest.context.replay(path,libc,case_controls=[p.CONTROL],_extension_factory=create,
        _request_profile=p.digest.previous.previous.name.previous.previous.PROFILE['name'],
        _handler_read_profile=p.digest.context.NULL_PAYLOAD_READ_PROFILE['name'])
    assert len(rows)==1
    return dict(schema=SCHEMA,claims=claims_for(),providers=providers(),source_fingerprints=source_fingerprints(),
        input_provenance=provenance(parent),static_code=code,native_provider_controls=independent_controls(path,libc),
        case_result=rows[0],case_result_sha256=digest(rows[0]))


def validate(data):
    parent=prior_evidence();old=parent['case_result']
    assert data['schema']==SCHEMA and data['claims']==claims_for() and data['providers']==providers()
    assert data['source_fingerprints']==source_fingerprints() and data['input_provenance']==provenance(parent)
    assert data['native_provider_controls']==control_specs()
    assert set(data['static_code'])==set(CODE_SHA256)
    for off,size in CODE_RANGES:
        code=data['static_code'][hex(off)];raw=bytes.fromhex(code['hex'])
        assert len(raw)==code['size']==size and raw_hash(raw)==code['sha256']==CODE_SHA256[hex(off)]
    row=data['case_result'];assert data['case_result_sha256']==digest(row)
    assert row['control']==old['control']
    assert row['retained_thread_pointer']==dict(case_result_sha256=digest(old),verified_fields=list(PARENT_FIELDS),
        instruction_observations=old['instruction_observations'],
        instruction_trace_sha256=old['instruction_trace_sha256'],observed_code_sha256=old['observed_code_sha256'])
    offsets=row['observation_pc_offsets'];code=row['observed_code']
    assert len(offsets)==row['instruction_observations']==1887<MAX_OBSERVATIONS
    assert offsets[:6]==[hex(a) for a in (VM_CALL,WRAPPER,WRAPPER+4,WRAPPER+8,TARGET,VM_RESUME)]
    assert offsets.count(hex(TARGET))==1 and offsets.count(hex(VM_CALL))==2
    assert offsets.count(hex(VM_RESUME))==1
    assert not any(TARGET<int(off,16)<TARGET+0x128 for off in offsets)
    assert offsets[-1]==hex(VM_CALL) and row['first_pc_offsets']==offsets[:16] and row['tail_pc_offsets']==offsets[-16:]
    assert set(code)==set(offsets)
    trace=hashlib.sha256()
    for off in offsets:
        raw=bytes.fromhex(code[off]);assert len(raw)==4
        trace.update(int(off,16).to_bytes(8,'little')+raw)
        assert int(off,16)==TARGET or not TARGET<=int(off,16)<TARGET+0x128
    assert row['instruction_trace_sha256']==trace.hexdigest() and row['observed_code_sha256']==digest(code)
    for off in range(WRAPPER,WRAPPER+12,4):
        assert code[hex(off)]==data['static_code'][hex(WRAPPER)]['hex'][(off-WRAPPER)*2:(off-WRAPPER+4)*2]
    assert code[hex(TARGET)]==data['static_code'][hex(TARGET)]['hex'][:8]
    assert code[hex(VM_CALL)]=='00013fd6' and hex(NEXT_WRAPPER) not in code
    call=row['JNI_callback'];before=bytes.fromhex(old['next_JNI_call']['output_pair_before_hex'])
    after=ENV.to_bytes(8,'little')+before[8:]
    expected=deepcopy(old['next_JNI_call'])
    expected.update(call_index=1,VM_call_executed=True,return_index=6,return_offset=hex(VM_RESUME),returned_x0=0,
        wrapper_executed=True,wrapper_path=[hex(a) for a in range(WRAPPER,WRAPPER+12,4)],
        dynamic_target_arguments={'x0':old['next_JNI_call']['output_pair_address']},
        target_entry_observed=True,target_entry_index=5,JNI_provider_entered=True,
        target_executed=False,original_acquisition_body_executed=False,
        output_pair_after_hex=after.hex(),provider_write_width=8,output_pair_tail_preserved=True,
        descriptor_unchanged_at_return=True,stack_pointer_restored=True,callee_saved_registers_restored=True)
    assert call==expected
    d=int(call['descriptor_address'],16);pair=call['output_pair_address']
    assert row['wrapper_descriptor_reads']==[
        dict(index=2,pc_offset=hex(WRAPPER),address=hex(d),width=8,value=hex(row['control']['base']+TARGET)),
        dict(index=2,pc_offset=hex(WRAPPER),address=hex(d+8),width=8,value=pair)]
    assert row['acquisition_provider']==dict(kind='inherited synthetic acquisition provider',offset=hex(TARGET),
        entry_index=5,return_index=6,output_pair_address=pair,environment=hex(ENV),write_width=8,
        pair_before_hex=before.hex(),pair_after_hex=after.hex(),result_x0=0,return_offset=hex(VM_RESUME),
        native_body_executed=False,real_ART_JVM_execution=False)
    next_call=row['next_VM_call'];raw=bytes.fromhex(next_call['descriptor_hex'])
    assert len(raw)==32 and raw_hash(raw)==next_call['descriptor_sha256']
    assert int.from_bytes(raw[:8],'little')==row['control']['base']+NEXT_TARGET
    assert raw_hash(raw)==next_call['descriptor_sha256']==NEXT_DESCRIPTOR_SHA256
    assert next_call['descriptor_address']=='0x7004caf8'
    assert next_call['static_expected_target_arguments']=={'x0':'0x136f3000'}
    assert next_call['index']==row['instruction_observations']
    assert next_call['callsite_offset']==hex(VM_CALL) and next_call['call_instruction_bytes']=='00013fd6'
    assert next_call['wrapper_offset']==hex(NEXT_WRAPPER) and next_call['target_offset']==hex(NEXT_TARGET)
    assert next_call['VM_cursor_offset']=='0x109c44'
    assert next_call['wrapper_code_hex']==data['static_code'][hex(NEXT_WRAPPER)]['hex']
    for key in ('VM_call_executed','wrapper_executed','target_executed'):assert next_call[key] is False
    assert row['thread_cache_preserved'] is True and row['new_allocator_events']==[]
    for key in LEDGERS:assert row[key]==old[key],key
    assert row['stop_boundary']==dict(kind='before_next_VM_call',stop_before=hex(VM_CALL),
        next_VM_call_executed=False,original_acquisition_body_executed=False)


def damaged_evidence_rejected(data):
    changes=[(('claims','original_acquisition_body_executed'),True),
        (('claims','real_ART_JVM_execution'),True),(('claims','next_VM_call_executed'),True),
        (('claims','complete_standalone_signer_verified'),True),
        (('providers','acquisition','write_width'),16),(('providers','new_providers'),['hidden']),
        (('source_fingerprints','acquisition_provider_source_sha256'),'0'*64),
        (('case_result','retained_thread_pointer','case_result_sha256'),'0'*64),
        (('case_result','instruction_observations'),6),
        (('case_result','instruction_trace_sha256'),'0'*64),(('case_result','observed_code_sha256'),'0'*64),
        (('case_result','observation_pc_offsets',4),hex(TARGET+4)),
        (('case_result','observed_code',hex(WRAPPER)),'00000000'),
        (('case_result','JNI_callback','target_executed'),True),
        (('case_result','JNI_callback','wrapper_path'),[]),
        (('case_result','JNI_callback','dynamic_target_arguments','x0'),'0x0'),
        (('case_result','JNI_callback','output_pair_after_hex'),'0'*32),
        (('case_result','JNI_callback','provider_write_width'),16),
        (('case_result','JNI_callback','return_index'),5),
        (('case_result','JNI_callback','callee_saved_registers_restored'),False),
        (('case_result','wrapper_descriptor_reads',0,'address'),'0x0'),
        (('case_result','wrapper_descriptor_reads',1,'width'),16),
        (('case_result','acquisition_provider','native_body_executed'),True),
        (('case_result','acquisition_provider','write_width'),16),
        (('case_result','acquisition_provider','pair_after_hex'),'0'*32),
        (('case_result','next_VM_call','VM_call_executed'),True),
        (('case_result','next_VM_call','target_offset'),'0x0'),
        (('case_result','next_VM_call','wrapper_code_hex'),'00'*28),
        (('case_result','next_VM_call','VM_cursor_offset'),'0x0'),
        (('case_result','next_VM_call','descriptor_sha256'),'0'*64),
        (('case_result','next_VM_call','static_expected_target_arguments','x0'),'0x0'),
        (('case_result','thread_cache_preserved'),False),
        (('case_result','stop_boundary','original_acquisition_body_executed'),True),
        (('native_provider_controls',0,'provider_write_width'),16),
        (('native_provider_controls',3,'pair_after_hex'),'0'*32)]
    for key in LEDGERS:changes.append((('case_result',key),[]))
    for off in CODE_SHA256:changes.append((('static_code',off,'sha256'),'0'*64))
    changes.append((('case_result','new_allocator_events'),[['hidden']]))
    for path,value in changes:
        bad=deepcopy(data);obj=bad
        for key in path[:-1]:obj=obj[key]
        obj[path[-1]]=value
        if path[0]=='case_result':bad['case_result_sha256']=digest(bad['case_result'])
        try:validate(bad)
        except (AssertionError,KeyError,ValueError,TypeError):continue
        raise AssertionError(f'damaged JNI-provider evidence accepted: {path}')
    return len(changes)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf',type=Path);parser.add_argument('--libc',type=Path)
    mode=parser.add_mutually_exclusive_group();mode.add_argument('--capture',action='store_true');mode.add_argument('--replay',action='store_true')
    args=parser.parse_args()
    if (args.capture or args.replay) and (not args.elf or not args.libc):parser.error('--capture and --replay require --elf and --libc')
    if args.capture:
        if EVIDENCE.exists():raise FileExistsError('frozen evidence already exists; refusing overwrite')
        data=run(args.elf,args.libc);validate(data);rejected=damaged_evidence_rejected(data)
        with EVIDENCE.open('x',encoding='utf-8',newline='\n') as output:output.write(json.dumps(data,indent=2)+'\n')
    else:
        data=json.loads(EVIDENCE.read_text(encoding='utf-8'));validate(data);rejected=damaged_evidence_rejected(data)
        if args.replay:assert run(args.elf,args.libc)==data,'fresh JNI-provider replay differs'
    print(json.dumps(dict(schema=SCHEMA,damaged_evidence_rejected=rejected,
        instruction_observations=data['case_result']['instruction_observations'],native_provider_controls=len(data['native_provider_controls']),
        JNI_tail_wrapper_returned=True,original_acquisition_body_executed=False,next_VM_call_executed=False,
        complete_standalone_signer_verified=False)))


if __name__=='__main__':main()
