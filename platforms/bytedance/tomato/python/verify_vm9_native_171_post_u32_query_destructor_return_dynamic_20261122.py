"""Verify query destruction after the u32 lookup and retain all three defaults."""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as arm

import verify_vm9_native_171_post_defaults_u32_lookup_return_dynamic_20261122 as previous
import verify_vm9_native_171_resolve_next_vm_callback_dynamic_20261121 as bootstrap
import verify_vm9_signer_objects as oracle
import verify_vm9_outer_signer_native as allocator_owner
import verify_vm9_native_171_string_destructor_return_dynamic_20261122 as destructor_owner

EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_post_u32_query_destructor_return_dynamic_20261122.json')
SCHEMA='vm9-native-171-post-u32-query-destructor-return-dynamic-20261122-v1'
VM_CALL,VM_RESUME=previous.VM_CALL,previous.VM_RESUME
WRAPPER,TARGET,EMPTY=0x2884CC,0x2484B8,0x6E208
NEXT_WRAPPER,NEXT_TARGET=0x2886b0,0x25bd8c
LIBC_BASE,FREE=0x51000000,0x1BAC0
MAX_OBSERVATIONS=40000
sha256,raw_hash,digest=previous.sha256,previous.raw_hash,previous.digest
PARENT_FIELDS=('instruction_observations','instruction_trace_sha256','observation_sites','observed_code','observed_code_sha256',
    'retained_source_constructor','tree_callback','native_reads','native_writes','mutex_calls','libc_body_entries',
    'observed_PLT_entries','prior_objects_retention','next_VM_call')
LEDGERS=previous.LEDGERS
EXPECTED={'instruction_observations': 734, 'instruction_trace_sha256': '8af7ba99647066c4feb05393c67bc11a2911b6b6a6fb7f2f6d1f6b37cdfda8af', 'observed_code_sha256': '5ec1c81948cc5ed2767ef426f81e5eb0a0137ff3ff4691e8f6630bdda676b5fb', 'next_descriptor_sha256': 'd8c2fdaace9a906583559c7b77b1d9df541de6b4b4a1b23c56a2ed1af6a22239', 'empty_descriptor_sha256': '68ca0fde67a507138a72ec1daa71d0ae4c0f814addfe7b6c0b71089096ac127f', 'return_index': 154, 'Bionic_free_entry_index': 16, 'free_return_index': 147, 'raw_returned_x0': '0x136c2680', 'next_cursor': '0x10a1e0', 'next_descriptor_address': '0x7004cbe8', 'next_static_arguments': {'x0': '0x7004cbe8', 'x8': '0x7004d178'}, 'native_reads': [{'index': 10, 'native_pc': '0x2484cc', 'address': '0x7004d1e8', 'size': 8, 'value_hex': '20406d1300000000'}, {'index': 149, 'native_pc': '0x2484e8', 'address': '0x1232e208', 'size': 8, 'value_hex': '0000000023ffffff'}], 'native_stores': [{'index': 12, 'native_pc': '0x2484d4', 'address': '0x7004d1d8', 'size': 8, 'value_hex': 'f8f5601200000000', 'source_register': 'x8'}, {'index': 147, 'native_pc': '0x2484e0', 'address': '0x7004d1e8', 'size': 8, 'value_hex': '0000000000000000', 'source_register': 'xzr'}, {'index': 150, 'native_pc': '0x2484ec', 'address': '0x7004d1e0', 'size': 8, 'value_hex': '0000000023ffffff', 'source_register': 'd0'}], 'free_calls': [{'index': 15, 'PLT_offset': '0x347fa0', 'pointer': '0x136d4020'}]}
CODE_RANGES={'main':((WRAPPER,12),(TARGET,68),(NEXT_WRAPPER,20),(NEXT_TARGET,16)),'libc':((FREE,32),)}
CODE_SHA256={'main:0x2884cc': '82295168e4332fdd8ee754ea9b86ffc5a592a6e6c42c0e1592ea18f55c95c565', 'main:0x2484b8': 'b667b3873efcc43d4ffb0f6edb76176e2e84ec53c43007ca9bdbe82067646854', 'main:0x2886b0': 'bc822015cae5b5a161f53c7dd351ab72b3ed33a9a97517d65b3d9cd69f0ab29b', 'main:0x25bd8c': '07b3bf2cf9022edb40b1d476707ce983648275d678bcc8d967861fbc19fe2bd1', 'libc:0x1bac0': '16b3ff4926bdad4ccbe4fd2f766af2a8151c0cf212da9677bc6abd4bf00245f4'}


def prior_evidence():
    data=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(data);return data


def source_fingerprints():
    return dict(post_u32_query_destructor_verifier_sha256=sha256(Path(__file__)),parent_verifier_sha256=sha256(Path(previous.__file__)),
        oracle_sha256=sha256(Path(oracle.__file__)),allocator_import_owner_sha256=sha256(Path(allocator_owner.__file__)),
        destructor_control_owner_sha256=sha256(Path(destructor_owner.__file__)),
        component_fixture_sha256=sha256(Path(destructor_owner.controls.__file__)),inherited=previous.source_fingerprints())


def provenance(parent):
    return dict(parent_evidence_sha256=sha256(previous.EVIDENCE),parent_case_sha256=digest(parent['case_result']),
        inherited_input_provenance=parent['input_provenance'],native_snapshot_used_as_python_model_input=False)


def elf_bytes(elf,stream,off,size):
    segment=next(s for s in elf.iter_segments() if s['p_type']=='PT_LOAD' and s['p_vaddr']<=off
        and off+size<=s['p_vaddr']+s['p_filesz'])
    stream.seek(segment['p_offset']+off-segment['p_vaddr']);raw=stream.read(size);assert len(raw)==size
    return raw


def read_static(path,libc):
    code={};empty=None
    for domain,filename in (('main',path),('libc',libc)):
        with filename.open('rb') as stream:
            elf=ELFFile(stream)
            if domain=='libc':
                exports=[(s['st_value'],s['st_size']) for s in elf.get_section_by_name('.dynsym').iter_symbols() if s.name=='free']
                assert exports==[(FREE,32)]
            else:
                raw=elf_bytes(elf,stream,EMPTY,8);empty=dict(offset=hex(EMPTY),hex=raw.hex(),sha256=raw_hash(raw))
            for off,size in CODE_RANGES[domain]:
                raw=elf_bytes(elf,stream,off,size);code[domain+':'+hex(off)]=dict(size=size,hex=raw.hex(),sha256=raw_hash(raw))
    return code,empty


def providers():
    return dict(inherited=previous.providers(),new_providers=[],new_import_bindings=[],
        free='inherited native import routing to the original matching Bionic free entry and body',
        component_free='explicit synthetic free observer only in independent component controls',
        returned_X0='observed incidental register value on a void destructor; no success-status meaning',
        next_static_arguments='unexecuted wrapper keeps the descriptor in X0 and loads descriptor+8 into X8',
        maximum_instruction_observations=MAX_OBSERVATIONS)


def claims_for():
    return dict(evidence_label='Sample verified',u32_lookup_prefix_revalidated=True,three_prior_default_strings_write_protected=True,
        original_VM_tail_wrapper_and_destructor_returned=True,matching_Bionic_free_entry_observed=True,
        one_payload_free_and_pointer_clear_verified=True,ELF_empty_descriptor_bits_restored=True,
        object_neighbors_and_descriptor_preserved=True,SP_and_callee_saved_restored=True,
        next_VM_call_executed=False,new_providers_added=False,native_snapshot_used_as_python_model_input=False,
        original_JNI_acquisition_body_executed=False,real_ART_JVM_execution=False,
        complete_VM_suffix_return_verified=False,complete_standalone_signer_verified=False,
        ordinary_Cronet_six_headers_verified=False,Android_execution=False,
        physical_PAC_authentication_verified=False,online_acceptance_verified=False)


def control_specs():
    return destructor_owner.control_specs()


def independent_controls(path):
    return destructor_owner.independent_controls(path)


class PostU32QueryDestructorScenario(previous.PostDefaultsU32LookupScenario):
    def __init__(self,control):
        super().__init__(control)
        self._postdtor_active=False;self._postdtor_done=False;self._postdtor_returned=False;self._postdtor_state=None
        self._postdtor_count=0;self._postdtor_trace=[];self._postdtor_code={};self._postdtor_path=[]
        self._postdtor_reads=[];self._postdtor_stores=[];self._postdtor_free_calls=[];self._postdtor_old=prior_evidence()['case_result']

    def _postdtor_track(self,cpu,pc):
        self._postdtor_count+=1;assert self._postdtor_count<MAX_OBSERVATIONS
        if LIBC_BASE<=pc<LIBC_BASE+0x200000:domain,off='libc',pc-LIBC_BASE
        else:
            assert self.image<=pc<self.image+0x400000
            domain,off='main',pc-self.image
        key=domain+':'+hex(off);self._postdtor_trace.append(key);self._postdtor_code[key]=bytes(cpu.mem_read(pc,4)).hex()

    def _postdtor_retained(self,cpu):
        rows=[]
        for expected in self._postdtor_prior:
            actual=dict(object_address=expected['object_address'],payload_address=expected['payload_address'],
                object_hex=bytes(cpu.mem_read(int(expected['object_address'],16),24)).hex(),
                payload_hex=bytes(cpu.mem_read(int(expected['payload_address'],16),8)).hex())
            assert actual==expected;rows.append(actual)
        return rows

    def _u32_next(self,cpu,pc):
        super()._u32_next(cpu,pc)
        h=hashlib.sha256()
        for key in self._u32_trace:h.update(key.encode()+bytes.fromhex(self._u32_code[key]))
        retained=deepcopy(self._u32_retention);retained['protected_write_events']=deepcopy(self._u32_protected_writes)
        values=(self._u32_count,h.hexdigest(),self._u32_trace,self._u32_code,digest(self._u32_code),
            self._u32_parent,self._u32_call,self._u32_reads,self._u32_writes,self._u32_mutex_calls,self._u32_libc_entries,
            self._u32_imports,retained,self._u32_next_call)
        for value,key in zip(values,PARENT_FIELDS):assert value==self._postdtor_old[key],key
        self._postdtor_prior=deepcopy(self._postdtor_old['prior_objects_retention']['at_next'])
        self._postdtor_ranges=[(int(row[key],16),width) for row in self._postdtor_prior for key,width in (('object_address',24),('payload_address',8))]
        self._postdtor_protected=[]
        self._postdtor_retention=dict(object_width=24,payload_width=8,before=self._postdtor_retained(cpu))
        self._postdtor_lookup_descriptor=int(self._postdtor_old['tree_callback']['descriptor_address'],16)
        self._postdtor_lookup_before=bytes(cpu.mem_read(self._postdtor_lookup_descriptor,48))
        assert self._postdtor_lookup_before.hex()==self._postdtor_old['tree_callback']['descriptor_after_hex']
        self._postdtor_parent=dict(case_result_sha256=digest(self._postdtor_old),verified_fields=list(PARENT_FIELDS))
        self._postdtor_events_before=deepcopy(self._postdtor_state['allocator_events_ref'])
        assert self._postdtor_events_before==self._u32_events_before
        self._postdtor_descriptor=self._reg(cpu,0);self._postdtor_descriptor_before=bytes(cpu.mem_read(self._postdtor_descriptor,48))
        self._postdtor_object=self._u(cpu,self._postdtor_descriptor+8);self._postdtor_object_before=bytes(cpu.mem_read(self._postdtor_object,32))
        assert self._postdtor_object_before.hex()==self._postdtor_old['tree_callback']['query_after_hex']
        self._postdtor_pointer=self._u(cpu,self._postdtor_object+16);width=self._u(cpu,self._postdtor_object+12,4)+1
        assert self._postdtor_pointer and width==33
        payload_hash=raw_hash(bytes(cpu.mem_read(self._postdtor_pointer,width)))
        assert payload_hash==self._postdtor_old['tree_callback']['query_payload_after_sha256']
        self._postdtor_empty=bytes(cpu.mem_read(self.image+EMPTY,8))
        self._postdtor_sp=cpu.reg_read(arm.UC_ARM64_REG_SP);self._postdtor_saved=[self._reg(cpu,n) for n in range(19,30)]
        self._postdtor_call=dict(call_index=1,callsite_offset=hex(VM_CALL),VM_cursor_offset='0x10a1c0',
            wrapper_offset=hex(WRAPPER),target_offset=hex(TARGET),descriptor_address=hex(self._postdtor_descriptor),
            descriptor_before_hex=self._postdtor_descriptor_before.hex(),object_address=hex(self._postdtor_object),
            object_before_hex=self._postdtor_object_before.hex(),payload_pointer=hex(self._postdtor_pointer),
            payload_width=width,payload_before_sha256=payload_hash,empty_descriptor_hex=self._postdtor_empty.hex())
        self._u32_active=False;self._u32_done=False;self._postdtor_active=True;self._postdtor_track(cpu,pc)

    def native_runner(self,*args,**kwargs):
        old_read,old_write=kwargs['memory_read_observer'],kwargs['memory_write_observer']
        def read(cpu,address,size):
            if self._postdtor_active and not self._postdtor_returned:
                off=cpu.reg_read(arm.UC_ARM64_REG_PC)-self.image
                if off in (0x2484CC,0x2484E8):
                    assert size==8 and address==(self._postdtor_object+16 if off==0x2484CC else self.image+EMPTY)
                    self._postdtor_reads.append(dict(index=self._postdtor_count,native_pc=hex(off),address=hex(address),
                        size=8,value_hex=bytes(cpu.mem_read(address,size)).hex()))
            if old_read:old_read(cpu,address,size)
        def write(cpu,address,size):
            if self._postdtor_active and any(address<start+width and start<address+size for start,width in self._postdtor_ranges):
                self._postdtor_protected.append(dict(index=self._postdtor_count,address=hex(address),size=size))
                raise AssertionError('query destruction wrote a prior default string')
            if self._postdtor_active and not self._postdtor_returned:
                if address<self._postdtor_lookup_descriptor+48 and self._postdtor_lookup_descriptor<address+size:
                    raise AssertionError('query destructor wrote the u32 result descriptor')
                off=cpu.reg_read(arm.UC_ARM64_REG_PC)-self.image
                if self._postdtor_object<=address<self._postdtor_object+32:
                    assert size==8 and (off,address) in ((0x2484D4,self._postdtor_object),
                        (0x2484E0,self._postdtor_object+16),(0x2484EC,self._postdtor_object+8))
                    value=self._reg(cpu,8) if off==0x2484D4 else 0 if off==0x2484E0 else cpu.reg_read(arm.UC_ARM64_REG_D0)
                    self._postdtor_stores.append(dict(index=self._postdtor_count,native_pc=hex(off),address=hex(address),size=8,
                        value_hex=value.to_bytes(8,'little').hex(),source_register='x8' if off==0x2484D4 else 'xzr' if off==0x2484E0 else 'd0'))
                if self._postdtor_descriptor<=address<self._postdtor_descriptor+48:raise AssertionError('destructor tail wrapper wrote descriptor')
            if old_write:old_write(cpu,address,size)
        kwargs.update(memory_read_observer=read,memory_write_observer=write)
        return super().native_runner(*args,**kwargs)

    def _postdtor_observe_call(self,cpu,pc):
        off=pc-self.image
        if WRAPPER<=off<WRAPPER+12:self._postdtor_path.append(hex(off))
        if off==TARGET:
            assert self._reg(cpu,0)==self._postdtor_object and self._reg(cpu,30)==self.image+VM_RESUME
            assert cpu.reg_read(arm.UC_ARM64_REG_SP)==self._postdtor_sp
            self._postdtor_call.update(target_entry_index=self._postdtor_count,dynamic_target_arguments={'x0':hex(self._postdtor_object)})
        if off==0x347FA0:
            assert self._reg(cpu,0)==self._postdtor_pointer
            assert self._reg(cpu,30)==self.image+0x2484E0 and cpu.reg_read(arm.UC_ARM64_REG_SP)==self._postdtor_sp-32
            self._postdtor_free_calls.append(dict(index=self._postdtor_count,PLT_offset='0x347fa0',pointer=hex(self._postdtor_pointer)))
        if pc==LIBC_BASE+FREE:
            assert self._reg(cpu,0)==self._postdtor_pointer
            assert self._reg(cpu,30)==self.image+0x2484E0 and cpu.reg_read(arm.UC_ARM64_REG_SP)==self._postdtor_sp-32
            self._postdtor_call['Bionic_free_entry']=dict(index=self._postdtor_count,libc_offset=hex(FREE),pointer=hex(self._postdtor_pointer))
        if off==0x2484E0:
            assert self._reg(cpu,19)==self._postdtor_object and cpu.reg_read(arm.UC_ARM64_REG_SP)==self._postdtor_sp-32
            self._postdtor_call['free_return']=dict(index=self._postdtor_count,raw_x0=hex(self._reg(cpu,0)))

    def _postdtor_return(self,cpu):
        assert cpu.reg_read(arm.UC_ARM64_REG_SP)==self._postdtor_sp
        assert [self._reg(cpu,n) for n in range(19,30)]==self._postdtor_saved
        raw=bytes(cpu.mem_read(self._postdtor_object,32))
        assert raw==(self.image+0x34F5F8).to_bytes(8,'little')+self._postdtor_empty+bytes(8)+self._postdtor_object_before[24:]
        assert bytes(cpu.mem_read(self._postdtor_descriptor,48))==self._postdtor_descriptor_before
        assert self._postdtor_path==list(map(hex,range(WRAPPER,WRAPPER+12,4)))
        assert len(self._postdtor_free_calls)==1 and len(self._postdtor_reads)==2 and len(self._postdtor_stores)==3
        self._postdtor_call.update(return_index=self._postdtor_count,return_offset=hex(VM_RESUME),raw_returned_x0=hex(self._reg(cpu,0)),
            descriptor_after_hex=bytes(cpu.mem_read(self._postdtor_descriptor,48)).hex(),
            object_after_hex=raw.hex(),wrapper_path=self._postdtor_path,payload_pointer_cleared=True,
            ELF_descriptor_restored=True,object_neighbors_preserved=True,descriptor_unchanged=True,SP_restored=True,callee_saved_restored=True)
        assert bytes(cpu.mem_read(self._postdtor_lookup_descriptor,48))==self._postdtor_lookup_before
        self._postdtor_retention['at_return']=self._postdtor_retained(cpu)
        self._postdtor_returned=True

    def _postdtor_next(self,cpu,pc):
        d=self._reg(cpu,0);raw=bytes(cpu.mem_read(d,48));wrapper=self._reg(cpu,8)
        assert self._postdtor_count==EXPECTED['instruction_observations'] and hex(self._u(cpu,self._reg(cpu,19))-self.image)==EXPECTED['next_cursor']
        assert wrapper==self.image+NEXT_WRAPPER and int.from_bytes(raw[:8],'little')==self.image+NEXT_TARGET
        assert raw_hash(raw)==EXPECTED['next_descriptor_sha256'] and bytes(cpu.mem_read(pc,4)).hex()=='00013fd6'
        self._postdtor_next_call=dict(index=self._postdtor_count,callsite_offset=hex(VM_CALL),wrapper_offset=hex(wrapper-self.image),
            target_offset=hex(int.from_bytes(raw[:8],'little')-self.image),VM_cursor_offset=hex(self._u(cpu,self._reg(cpu,19))-self.image),
            descriptor_address=hex(d),descriptor_hex=raw.hex(),descriptor_sha256=raw_hash(raw),
            wrapper_code_hex=bytes(cpu.mem_read(wrapper,20)).hex(),
            static_expected_target_arguments={'x0':hex(d),'x8':hex(int.from_bytes(raw[8:16],'little'))},
            VM_call_executed=False,wrapper_executed=False,target_executed=False)
        self._postdtor_retention.update(at_next=self._postdtor_retained(cpu),stop_index=self._postdtor_count,protected_write_events=self._postdtor_protected)
        self._postdtor_done=True

    def observe(self,cpu,pc,state):
        self._postdtor_state=state
        if not self._postdtor_active:return super().observe(cpu,pc,state)
        self._postdtor_track(cpu,pc);off=pc-self.image
        if not self._postdtor_returned:
            self._postdtor_observe_call(cpu,pc)
            if off==VM_RESUME:self._postdtor_return(cpu)
        elif off==VM_CALL:self._postdtor_next(cpu,pc)
        self._base_observe(cpu,pc,state)
        if self._postdtor_done:
            cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,oracle.STOP)

    def finish(self,result,state,proof):
        assert self._postdtor_done and self._postdtor_returned
        events=result['allocator_events'];assert events[:len(self._postdtor_events_before)]==self._postdtor_events_before
        assert events[len(self._postdtor_events_before):]==[['free',self._postdtor_pointer]]
        ledgers=dict(allocator_counts=result['actual_allocator_counts'],inherited_service_counts=result['explicit_service_counts'],
            inherited_JNI_calls=proof['JNI_calls'],inherited_libc_SVC=proof['libc_SVC_boundaries'],inherited_main_SVC=proof['main_image_SVC_boundaries'],
            inherited_syscall_172=self._pid_syscalls,inherited_syscall_173=self._pp_syscalls,late_jni=self.late_jni_calls,java_dispatch=self.java_dispatch_calls)
        for key,value in ledgers.items():
            if key!='allocator_counts':assert value==self._postdtor_old[key],key
        h=hashlib.sha256()
        for key in self._postdtor_trace:h.update(key.encode()+bytes.fromhex(self._postdtor_code[key]))
        return dict(control=self._postdtor_old['control'],retained_u32_lookup=self._postdtor_parent,
            instruction_observations=self._postdtor_count,instruction_trace_sha256=h.hexdigest(),observation_sites=self._postdtor_trace,
            observed_code=self._postdtor_code,observed_code_sha256=digest(self._postdtor_code),destructor_callback=self._postdtor_call,
            native_reads=self._postdtor_reads,native_stores=self._postdtor_stores,free_calls=self._postdtor_free_calls,
            prior_objects_retention=self._postdtor_retention,
            lookup_descriptor_integrity=dict(address=hex(self._postdtor_lookup_descriptor),before_hex=self._postdtor_lookup_before.hex(),after_hex=self._postdtor_lookup_before.hex(),verified_through='destructor_return'),
            observed_PLT_entries=[dict(index=i+1,PLT_offset=key[5:]) for i,key in enumerate(self._postdtor_trace) if key.startswith('main:0x347')],
            next_VM_call=self._postdtor_next_call,new_allocator_events=events[len(self._postdtor_events_before):],**ledgers,
            stop_boundary=dict(stop_before=hex(VM_CALL),kind='before_next_VM_call_after_query_destruction',VM_call_executed=False))


def run(path,libc):
    parent=prior_evidence();p=bootstrap.module_prefix();p.digest.verify_images(path,libc)
    code,empty=read_static(path,libc);assert {k:v['sha256'] for k,v in code.items()}==CODE_SHA256
    def create(control):
        s=PostU32QueryDestructorScenario(control);s.path=path;s.continue_to_svc=True;return s
    rows=p.digest.context.replay(path,libc,case_controls=[p.CONTROL],_extension_factory=create,
        _request_profile=p.digest.previous.previous.name.previous.previous.PROFILE['name'],
        _handler_read_profile=p.digest.context.NULL_PAYLOAD_READ_PROFILE['name'])
    assert len(rows)==1
    return dict(schema=SCHEMA,claims=claims_for(),providers=providers(),source_fingerprints=source_fingerprints(),
        input_provenance=provenance(parent),static_code=code,static_empty_descriptor=empty,native_controls=independent_controls(path),
        case_result=rows[0],case_result_sha256=digest(rows[0]))


def validate(data):
    parent=prior_evidence();old=parent['case_result']
    assert data['schema']==SCHEMA and data['claims']==claims_for() and data['providers']==providers()
    assert data['source_fingerprints']==source_fingerprints() and data['input_provenance']==provenance(parent)
    assert data['native_controls']==control_specs() and set(data['static_code'])==set(CODE_SHA256)
    for domain,ranges in CODE_RANGES.items():
        for off,size in ranges:
            key=domain+':'+hex(off);entry=data['static_code'][key];raw=bytes.fromhex(entry['hex'])
            assert len(raw)==entry['size']==size and raw_hash(raw)==entry['sha256']==CODE_SHA256[key]
    empty=data['static_empty_descriptor']
    assert empty==dict(offset=hex(EMPTY),hex='0000000023ffffff',sha256=EXPECTED['empty_descriptor_sha256'])
    assert raw_hash(bytes.fromhex(empty['hex']))==empty['sha256']
    row=data['case_result'];assert data['case_result_sha256']==digest(row) and row['control']==old['control']
    assert row['retained_u32_lookup']==dict(case_result_sha256=digest(old),verified_fields=list(PARENT_FIELDS))
    sites=row['observation_sites'];code=row['observed_code'];h=hashlib.sha256()
    assert len(sites)==row['instruction_observations']==EXPECTED['instruction_observations']<MAX_OBSERVATIONS
    assert set(sites)==set(code) and sites[:5]==['main:'+hex(x) for x in (VM_CALL,WRAPPER,WRAPPER+4,WRAPPER+8,TARGET)]
    assert sites[EXPECTED['return_index']-1]=='main:'+hex(VM_RESUME) and sites[-1]=='main:'+hex(VM_CALL)
    assert sites.count('main:'+hex(VM_CALL))==2 and sites.count('main:'+hex(WRAPPER))==1
    assert sites.count('main:'+hex(NEXT_TARGET))==int(NEXT_TARGET==TARGET)
    assert sites[EXPECTED['Bionic_free_entry_index']-1]=='libc:'+hex(FREE) and sites.count('libc:'+hex(FREE))==1
    for key in sites:
        raw=bytes.fromhex(code[key]);assert len(raw)==4 and raw!=bytes.fromhex('010000d4')
        h.update(key.encode()+raw)
    assert h.hexdigest()==row['instruction_trace_sha256']==EXPECTED['instruction_trace_sha256']
    assert digest(code)==row['observed_code_sha256']==EXPECTED['observed_code_sha256']
    for domain,ranges in CODE_RANGES.items():
        for off,size in ranges:
            raw=data['static_code'][domain+':'+hex(off)]['hex']
            for pc in range(off,off+size,4):
                key=domain+':'+hex(pc)
                if key in code:assert code[key]==raw[(pc-off)*2:(pc-off+4)*2]
    call=row['destructor_callback'];base=row['control']['base']
    assert call['call_index']==1 and call['callsite_offset']==hex(VM_CALL) and call['VM_cursor_offset']=='0x10a1c0'
    assert call['wrapper_offset']==hex(WRAPPER) and call['target_offset']==hex(TARGET)
    assert call['target_entry_index']==5 and call['return_index']==EXPECTED['return_index'] and call['return_offset']==hex(VM_RESUME)
    assert call['dynamic_target_arguments']=={'x0':'0x7004d1d8'} and call['object_address']=='0x7004d1d8'
    assert call['descriptor_address']==old['next_VM_call']['descriptor_address']=='0x7004cdf8'
    assert call['descriptor_before_hex']==call['descriptor_after_hex']==old['next_VM_call']['descriptor_hex']
    assert call['object_before_hex']==old['tree_callback']['query_after_hex']
    assert call['payload_pointer']=='0x136d4020' and call['payload_width']==33
    assert call['payload_before_sha256']==old['tree_callback']['query_payload_after_sha256']
    assert call['empty_descriptor_hex']==empty['hex']
    before=bytes.fromhex(call['object_before_hex']);after=bytes.fromhex(call['object_after_hex'])
    assert len(before)==len(after)==32
    assert after==(base+0x34F5F8).to_bytes(8,'little')+bytes.fromhex(empty['hex'])+bytes(8)+before[24:]
    assert call['Bionic_free_entry']==dict(index=EXPECTED['Bionic_free_entry_index'],libc_offset=hex(FREE),pointer='0x136d4020')
    assert call['free_return']==dict(index=EXPECTED['free_return_index'],raw_x0=EXPECTED['raw_returned_x0']) and call['raw_returned_x0']==EXPECTED['raw_returned_x0']
    assert call['wrapper_path']==[hex(x) for x in range(WRAPPER,WRAPPER+12,4)]
    for key in ('payload_pointer_cleared','ELF_descriptor_restored','object_neighbors_preserved','descriptor_unchanged','SP_restored','callee_saved_restored'):
        assert call[key] is True
    assert row['free_calls']==EXPECTED['free_calls']
    assert row['observed_PLT_entries']==[dict(index=x['index'],PLT_offset=x['PLT_offset']) for x in EXPECTED['free_calls']]
    assert row['observed_PLT_entries']==[dict(index=i+1,PLT_offset=key[5:]) for i,key in enumerate(sites) if key.startswith('main:0x347')]
    assert row['native_reads']==EXPECTED['native_reads'] and row['native_stores']==EXPECTED['native_stores']
    retained=old['prior_objects_retention']['at_next']
    assert row['prior_objects_retention']==dict(object_width=24,payload_width=8,before=retained,at_return=retained,at_next=retained,
        stop_index=EXPECTED['instruction_observations'],protected_write_events=[])
    assert row['lookup_descriptor_integrity']==dict(address=old['tree_callback']['descriptor_address'],
        before_hex=old['tree_callback']['descriptor_after_hex'],after_hex=old['tree_callback']['descriptor_after_hex'],verified_through='destructor_return')
    next_call=row['next_VM_call'];raw=bytes.fromhex(next_call['descriptor_hex'])
    assert len(raw)==48 and raw_hash(raw)==next_call['descriptor_sha256']==EXPECTED['next_descriptor_sha256']
    assert next_call['index']==EXPECTED['instruction_observations'] and next_call['callsite_offset']==hex(VM_CALL)
    assert next_call['wrapper_offset']==hex(NEXT_WRAPPER) and next_call['target_offset']==hex(NEXT_TARGET)
    assert next_call['VM_cursor_offset']==EXPECTED['next_cursor'] and next_call['descriptor_address']==EXPECTED['next_descriptor_address']
    assert next_call['wrapper_code_hex']==data['static_code']['main:'+hex(NEXT_WRAPPER)]['hex']
    assert next_call['static_expected_target_arguments']==EXPECTED['next_static_arguments']
    for key in ('VM_call_executed','wrapper_executed','target_executed'):assert next_call[key] is False
    assert row['new_allocator_events']==[['free',0x136D4020]]
    counts=deepcopy(old['allocator_counts']);counts['free']+=1;assert row['allocator_counts']==counts
    for key in LEDGERS:
        if key!='allocator_counts':assert row[key]==old[key],key
    assert row['stop_boundary']==dict(stop_before=hex(VM_CALL),kind='before_next_VM_call_after_query_destruction',VM_call_executed=False)


def damaged_evidence_rejected(data):
    changes=[(('claims','complete_standalone_signer_verified'),True),(('claims','next_VM_call_executed'),True),
        (('claims','matching_Bionic_free_entry_observed'),False),(('claims','original_JNI_acquisition_body_executed'),True),
        (('claims','real_ART_JVM_execution'),True),(('providers','new_providers'),['hidden']),
        (('source_fingerprints','allocator_import_owner_sha256'),'0'*64),
        (('static_empty_descriptor','hex'),'00'*8),
        (('case_result','retained_u32_lookup','case_result_sha256'),'0'*64),
        (('case_result','instruction_observations'),154),(('case_result','instruction_trace_sha256'),'0'*64),
        (('case_result','observed_code_sha256'),'0'*64),(('case_result','observation_sites',15),'libc:0x0'),
        (('case_result','destructor_callback','payload_pointer'),'0x0'),
        (('case_result','destructor_callback','payload_before_sha256'),'0'*64),
        (('case_result','destructor_callback','object_after_hex'),'00'*32),
        (('case_result','destructor_callback','descriptor_after_hex'),'00'*48),
        (('case_result','destructor_callback','empty_descriptor_hex'),'00'*8),
        (('case_result','destructor_callback','Bionic_free_entry','libc_offset'),'0x0'),
        (('case_result','destructor_callback','free_return','index'),0),
        (('case_result','destructor_callback','raw_returned_x0'),'0x0'),
        (('case_result','destructor_callback','payload_pointer_cleared'),False),
        (('case_result','destructor_callback','SP_restored'),False),
        (('case_result','destructor_callback','callee_saved_restored'),False),
        (('case_result','free_calls',0,'pointer'),'0x0'),
        (('case_result','native_reads',1,'value_hex'),'00'*8),
        (('case_result','native_stores',1,'value_hex'),'20406d1300000000'),
        (('case_result','native_stores',2,'source_register'),'x0'),
        (('case_result','new_allocator_events'),[]),(('case_result','allocator_counts','free'),267),
        (('case_result','next_VM_call','VM_call_executed'),True),
        (('case_result','next_VM_call','VM_cursor_offset'),'0x109e30'),
        (('case_result','next_VM_call','descriptor_sha256'),'0'*64),
        (('case_result','next_VM_call','static_expected_target_arguments','x0'),'0x0'),
        (('case_result','next_VM_call','static_expected_target_arguments','x8'),'0x0'),
        (('case_result','stop_boundary','VM_call_executed'),True),
        (('native_controls',0,'free_calls'),0),(('native_controls',4,'expected_empty_descriptor_hex'),'00'*8)]
    changes.extend([
        (('case_result','observed_PLT_entries'),[]),
        (('case_result','prior_objects_retention','at_return',0,'object_hex'),'00'*24),
        (('case_result','prior_objects_retention','at_next',2,'payload_hex'),'ff'*8),
        (('case_result','prior_objects_retention','protected_write_events'),['hidden']),
        (('case_result','lookup_descriptor_integrity','after_hex'),'00'*48)])
    for key in LEDGERS:
        if key!='allocator_counts':changes.append((('case_result',key),[]))
    for key in CODE_SHA256:changes.append((('static_code',key,'sha256'),'0'*64))
    for path,value in changes:
        bad=deepcopy(data);obj=bad
        for key in path[:-1]:obj=obj[key]
        obj[path[-1]]=value
        if path[0]=='case_result':bad['case_result_sha256']=digest(bad['case_result'])
        try:validate(bad)
        except (AssertionError,KeyError,ValueError,TypeError):continue
        raise AssertionError(f'damaged post-u32 query-destructor evidence accepted: {path}')
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
        if args.replay:assert run(args.elf,args.libc)==data,'fresh post-u32 query-destructor replay differs'
    print(json.dumps(dict(schema=SCHEMA,damaged_evidence_rejected=rejected,
        instruction_observations=data['case_result']['instruction_observations'],native_controls=len(data['native_controls']),
        original_string_destructor_returned=True,next_VM_call_executed=False,complete_standalone_signer_verified=False)))


if __name__=='__main__':main()
