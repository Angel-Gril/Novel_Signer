"""Verify source-string construction after the three preserved default strings."""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as arm

import verify_vm9_native_171_third_default_string_constructor_return_dynamic_20261122 as previous
import verify_vm9_native_171_string_constructor_return_dynamic_20261122 as constructor_owner

oracle,bootstrap=previous.oracle,previous.bootstrap
controls=constructor_owner.controls
sha256,raw_hash,digest=previous.sha256,previous.raw_hash,previous.digest
EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_post_defaults_string_constructor_return_dynamic_20261122.json')
SCHEMA='vm9-native-171-post-defaults-string-constructor-return-dynamic-20261122-v1'
VM_CALL,VM_RESUME=previous.VM_CALL,previous.VM_RESUME
WRAPPER,TARGET=0x2885D0,0x248344
LIBC_BASE,MALLOC=constructor_owner.LIBC_BASE,constructor_owner.MALLOC
MAX_OBSERVATIONS=constructor_owner.MAX_OBSERVATIONS
PARENT_FIELDS=('instruction_observations','instruction_trace_sha256','observation_sites','observed_code',
    'observed_code_sha256','retained_second_default_constructor','constructor_callback','native_reads','native_stores',
    'malloc_calls','next_VM_call','prior_objects_retention')
LEDGERS=previous.LEDGERS
EXPECTED={'instruction_observations': 783, 'instruction_trace_sha256': '8ff5e4641146333d74ac42ad6cf180f2876f23ada62563cbc841ff52833eba4b', 'observed_code_sha256': 'd8bfae451b80aea55cbbb401d672dd641321deffbe17e668e43d56099c8edcf2', 'return_index': 157, 'malloc_PLT_index': 24, 'malloc_entry_index': 25, 'allocation_return_index': 148, 'allocation_pointer': '0x136d4020', 'payload_before_copy_sha256': 'f27f570301f2b1b7c25a5233100c1611bfb5975ab0064b5dcfeab2cd99d47fe4', 'object_before_sha256': 'e23e72aba95fd049c783b4d16df301ae6d30fbb1f2d2f7b5c60799cfc249b5fd', 'source_length': 32, 'source_including_NUL_sha256': 'cee53c558c5851657d5d9852a595081ce73f674ecd1f42cac82a93e0c712ded5', 'store_indices': [13, 21, 21, 148], 'strlen_index': 18, 'memcpy_index': 156, 'next_cursor': '0x10a198', 'next_descriptor_address': '0x7004cb30', 'next_descriptor_sha256': '462edda3a146797d6e7a965f10c87de769c96fd8ee051c24473875eb46acf72b', 'next_static_arguments': {'x0': '0x136e0000', 'x1': '0x7004d1d8'}}
NEXT_WRAPPER,NEXT_TARGET=0x28874C,0x256A18
CODE_RANGES={'main':((WRAPPER,16),(TARGET,156),(NEXT_WRAPPER,32),(NEXT_TARGET,152)),'libc':((MALLOC,32),)}
CODE_SHA256={'main:0x2885d0': '14d9ed527789cfea4669cc452adab89d302cd67f24dc06b1de12d4ca1b71a7af', 'main:0x248344': 'f73af655d3e97f1da0d870dfaaea43bae7a33fc3403a4a26cfab43eb0e0559fd', 'main:0x28874c': 'c6d21d8e081469237fd33062bd032d24234b47fb0c9280f3485d8b5db1048e80', 'main:0x256a18': '5d158251a60991f9fc3b19f095d6071fc8d9449fa953b9ac6bbe687a820b1691', 'libc:0x1bb08': '5f183f5bc3ff80cac083022481d5449cfdceaa89cc15ff71781be915fc836b36'}


def prior_evidence():
    data=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(data);return data


def source_fingerprints():
    return dict(post_defaults_string_constructor_verifier_sha256=sha256(Path(__file__)),
        parent_verifier_sha256=sha256(Path(previous.__file__)),constructor_observer_owner_sha256=sha256(Path(constructor_owner.__file__)),
        oracle_sha256=sha256(Path(oracle.__file__)),component_fixture_sha256=sha256(Path(controls.__file__)),
        inherited=previous.source_fingerprints())


def provenance(parent):
    return dict(parent_evidence_sha256=sha256(previous.EVIDENCE),parent_case_sha256=digest(parent['case_result']),
        inherited_input_provenance=parent['input_provenance'],native_snapshot_used_as_python_model_input=False)


def read_static(path,libc):
    rows={}
    for domain,filename in (('main',path),('libc',libc)):
        with filename.open('rb') as stream:
            elf=ELFFile(stream)
            if domain=='libc':
                exports=[(s['st_value'],s['st_size']) for s in elf.get_section_by_name('.dynsym').iter_symbols() if s.name=='malloc']
                assert exports==[(MALLOC,32)]
            for off,size in CODE_RANGES[domain]:
                raw=previous.constructor_owner.previous.elf_bytes(elf,stream,off,size)
                rows[domain+':'+hex(off)]=dict(size=size,hex=raw.hex(),sha256=raw_hash(raw))
    return rows


def providers():
    return dict(inherited=previous.providers(),new_providers=[],new_import_bindings=[],
        observation_owner='frozen source-constructor read/store/return and explicit copy-provider observers reactivated',
        allocation='inherited original matching-Bionic malloc route',
        strlen='inherited host strlen provider; original Bionic strlen body does not execute',
        memcpy='inherited host memcpy provider including NUL; observer runs after its host write',
        control_allocator='explicit fresh synthetic malloc success/failure only in component controls',
        component_memory_scope='declared 0xa000-byte guest payload span; native stack and synthetic thread pointer excluded',
        maximum_instruction_observations=MAX_OBSERVATIONS)


def claims_for():
    return dict(evidence_label='Sample verified',third_default_constructor_prefix_revalidated=True,
        original_source_string_constructor_returned=True,actual_Bionic_malloc_entry_observed=True,
        inherited_strlen_and_memcpy_providers_used=True,source_including_NUL_copied=True,
        three_prior_objects_and_payloads_retained=True,object_neighbors_and_source_preserved=True,
        full_48_byte_descriptor_preserved=True,SP_and_callee_saved_restored=True,
        next_VM_call_executed=False,new_providers_added=False,native_snapshot_used_as_python_model_input=False,
        original_Bionic_strlen_and_memcpy_bodies_executed=False,original_JNI_acquisition_body_executed=False,
        real_ART_JVM_execution=False,complete_VM_suffix_return_verified=False,complete_standalone_signer_verified=False,
        ordinary_Cronet_six_headers_verified=False,Android_execution=False,
        physical_PAC_authentication_verified=False,online_acceptance_verified=False)


def retention_specs():
    return [dict(image_base=hex(base),case=label,previous_objects_retained=3,previous_payloads_retained=3,
        source_length=len(b'helper-string'),allocation_requested=len(b'helper-string\0'),
        allocation_succeeded=label=='three_prior_objects',declared_guest_payload_compared=True,SP_and_callee_saved_restored=True,
        allocator='explicit synthetic component provider',strlen_memcpy='inherited host providers')
        for base in controls.BASES for label in ('three_prior_objects','three_prior_objects_allocation_failure')]


def control_specs():return constructor_owner.control_specs()+retention_specs()


def independent_controls(path):
    rows=constructor_owner.independent_controls(path)
    for expected in retention_specs():
        base=int(expected['image_base'],16);pages,inputs,obj=controls.fixture(path,base,'construct','normal')
        block=inputs['argument_block_address'];protected=[]
        for offset,ptr,payload in ((72,oracle.GUEST+0x4800,b'first\0PQ'),(48,oracle.GUEST+0x4900,b'second\0R'),(24,oracle.GUEST+0x4A00,b'third\0ST')):
            raw=(base+0x34F5F8).to_bytes(8,'little')+bytes.fromhex('0800000000000000')+ptr.to_bytes(8,'little')
            controls._write_span(pages,obj-offset,raw);controls._write_span(pages,ptr,payload)
            protected.append((obj-offset,raw,ptr,payload))
        before=controls._read_span(pages,oracle.GUEST,0xA000)
        pointer=oracle.GUEST+0x4000 if expected['allocation_succeeded'] else 0
        requests=[];returned=[];saved={getattr(arm,f'UC_ARM64_REG_X{n}'):0x120000+n for n in range(19,30)}
        def retained(cpu):
            for address,raw,ptr,payload in protected:
                assert bytes(cpu.mem_read(address,24))==raw and bytes(cpu.mem_read(ptr,8))==payload
        def allocate(cpu,size):retained(cpu);requests.append(size);return pointer
        def observe(cpu,pc):
            if pc-base in (0x347F60,0x2483DC):
                retained(cpu);assert cpu.reg_read(arm.UC_ARM64_REG_SP)==oracle.GUEST+0xEF00
                assert all(cpu.reg_read(r)==v for r,v in saved.items());returned.append(True)
        result,memory,allocations,ledger=oracle.native(path,base,WRAPPER,[block],pages,malloc_handler=allocate,
            extra_registers=saved,instruction_observer=observe,instruction_limit=1000)
        target=bytearray(before);off=obj-oracle.GUEST;width=expected['allocation_requested']
        target[off:off+24]=(base+0x34F5F8).to_bytes(8,'little')+width.to_bytes(4,'little')+expected['source_length'].to_bytes(4,'little')+pointer.to_bytes(8,'little')
        if pointer:target[pointer-oracle.GUEST:pointer-oracle.GUEST+width]=b'helper-string\0'
        assert memory==target and result==pointer and requests==[width] and returned==[True] and allocations==ledger==[]
        rows.append(expected)
    return rows


class PostDefaultsStringConstructorScenario(previous.ThirdDefaultStringConstructorScenario):
    def __init__(self,control):
        super().__init__(control)
        self._srcctor_active=False;self._srcctor_old=prior_evidence()['case_result'];self._srcctor_state=None
        self._srcctor_protected_writes=[];self._srcctor_descriptor_writes=[]

    def native_runner(self,*args,**kwargs):
        old_write=kwargs['memory_write_observer']
        def write(cpu,address,size):
            if self._srcctor_active:
                entry=dict(index=self._strctor_count,address=hex(address),size=size,native_pc=hex(cpu.reg_read(arm.UC_ARM64_REG_PC)-self.image))
                if any(address<start+width and start<address+size for start,width in self._srcctor_ranges):
                    self._srcctor_protected_writes.append(entry)
                    raise AssertionError('source constructor continuation wrote a protected prior object or payload')
                if not self._strctor_returned and address<self._strctor_descriptor+48 and self._strctor_descriptor<address+size:
                    self._srcctor_descriptor_writes.append(entry)
                    raise AssertionError('source constructor wrote its full descriptor')
            if old_write:old_write(cpu,address,size)
        kwargs['memory_write_observer']=write
        return super().native_runner(*args,**kwargs)

    def _srcctor_retained(self,cpu):
        rows=[]
        for expected in self._srcctor_prior:
            obj=int(expected['object_address'],16);ptr=int(expected['payload_address'],16)
            actual=dict(object_address=hex(obj),payload_address=hex(ptr),object_hex=bytes(cpu.mem_read(obj,24)).hex(),
                payload_hex=bytes(cpu.mem_read(ptr,8)).hex())
            assert actual==expected;rows.append(actual)
        return rows

    def _defctor_next(self,cpu,pc):
        if not self._third_active:return super()._defctor_next(cpu,pc)
        super()._defctor_next(cpu,pc)
        retained=deepcopy(self._third_retention);retained['protected_write_events']=deepcopy(self._third_protected_writes)
        h=hashlib.sha256()
        for key in self._defctor_trace:h.update(key.encode()+bytes.fromhex(self._defctor_code[key]))
        values=(self._defctor_count,h.hexdigest(),self._defctor_trace,self._defctor_code,digest(self._defctor_code),
            self._defctor_parent,self._defctor_call,self._defctor_reads,self._defctor_stores,self._defctor_malloc_calls,self._defctor_next_call,retained)
        for value,key in zip(values,PARENT_FIELDS):assert value==self._srcctor_old[key],key
        events=self._srcctor_state['allocator_events_ref']
        assert events[len(self._defctor_events_before):]==self._srcctor_old['new_allocator_events']
        current=self._srcctor_old['constructor_callback']
        self._srcctor_prior=deepcopy(self._srcctor_old['prior_objects_retention']['at_next'])+[dict(
            object_address=current['object_address'],payload_address=current['allocation_return']['pointer'],
            object_hex=current['object_after_hex'][:48],payload_hex=current['payload_after_hex'])]
        self._srcctor_ranges=[(int(row[key],16),width) for row in self._srcctor_prior for key,width in (('object_address',24),('payload_address',8))]
        self._srcctor_retention=dict(object_width=24,payload_width=8,before=self._srcctor_retained(cpu))
        self._srcctor_parent=dict(case_result_sha256=digest(self._srcctor_old),verified_fields=list(PARENT_FIELDS))
        self._strctor_events_before=deepcopy(events)
        self._strctor_descriptor=self._reg(cpu,0);self._srcctor_descriptor_before=bytes(cpu.mem_read(self._strctor_descriptor,48))
        self._strctor_descriptor_before=self._srcctor_descriptor_before[:40]
        self._strctor_object=self._u(cpu,self._strctor_descriptor+8);self._strctor_source=self._u(cpu,self._strctor_descriptor+16)
        assert self._strctor_source
        source=bytearray()
        while len(source)<4096:
            value=bytes(cpu.mem_read(self._strctor_source+len(source),1));source.extend(value)
            if value==b'\0':break
        assert source[-1]==0;self._strctor_source_bytes=bytes(source)
        self._strctor_object_before=bytes(cpu.mem_read(self._strctor_object,32))
        self._strctor_sp=cpu.reg_read(arm.UC_ARM64_REG_SP);self._strctor_saved=[self._reg(cpu,n) for n in range(19,30)]
        self._strctor_call=dict(call_index=1,callsite_offset=hex(VM_CALL),VM_cursor_offset='0x10a178',
            wrapper_offset=hex(WRAPPER),target_offset=hex(TARGET),descriptor_address=hex(self._strctor_descriptor),
            descriptor_before_hex=self._strctor_descriptor_before.hex(),object_address=hex(self._strctor_object),
            object_before_hex=self._strctor_object_before.hex(),source_address=hex(self._strctor_source),
            source_length=len(source)-1,source_including_NUL_sha256=raw_hash(bytes(source)))
        self._strctor_count=0;self._strctor_trace=[];self._strctor_code={};self._strctor_path=[]
        self._strctor_stores=[];self._strctor_services=[];self._strctor_copy_effects=[];self._strctor_pointer=0
        self._strctor_done=False;self._strctor_returned=False
        self._defctor_active=False;self._defctor_done=False;self._third_active=False
        self._strctor_active=True;self._srcctor_active=True;self._strctor_track(cpu,pc)

    def _strctor_observe_call(self,cpu,pc):
        super()._strctor_observe_call(cpu,pc)
        if self._srcctor_active and pc==self.image+0x248388:
            self._strctor_call['allocation_return']['payload_before_copy_sha256']=raw_hash(
                bytes(cpu.mem_read(self._strctor_pointer,len(self._strctor_source_bytes))))

    def _strctor_return(self,cpu):
        super()._strctor_return(cpu)
        if self._srcctor_active:
            raw=bytes(cpu.mem_read(self._strctor_descriptor,48));assert raw==self._srcctor_descriptor_before
            self._srcctor_descriptor_integrity=dict(address=hex(self._strctor_descriptor),width=48,
                before_hex=self._srcctor_descriptor_before.hex(),at_return_hex=raw.hex(),body_write_events=self._srcctor_descriptor_writes)
            self._srcctor_retention['at_return']=self._srcctor_retained(cpu)

    def _strctor_next(self,cpu,pc):
        if not self._srcctor_active:return super()._strctor_next(cpu,pc)
        d=self._reg(cpu,0);raw=bytes(cpu.mem_read(d,48));wrapper=self._reg(cpu,8)
        assert self._strctor_count==EXPECTED['instruction_observations'] and hex(d)==EXPECTED['next_descriptor_address']
        assert hex(self._u(cpu,self._reg(cpu,19))-self.image)==EXPECTED['next_cursor']
        assert wrapper==self.image+NEXT_WRAPPER and int.from_bytes(raw[:8],'little')==self.image+NEXT_TARGET
        assert raw_hash(raw)==EXPECTED['next_descriptor_sha256'] and bytes(cpu.mem_read(pc,4)).hex()=='00013fd6'
        self._strctor_next_call=dict(index=self._strctor_count,callsite_offset=hex(VM_CALL),wrapper_offset=hex(wrapper-self.image),
            target_offset=hex(int.from_bytes(raw[:8],'little')-self.image),VM_cursor_offset=hex(self._u(cpu,self._reg(cpu,19))-self.image),
            descriptor_address=hex(d),descriptor_hex=raw.hex(),descriptor_sha256=raw_hash(raw),
            wrapper_code_hex=bytes(cpu.mem_read(wrapper,32)).hex(),
            static_expected_target_arguments={'x0':hex(int.from_bytes(raw[8:16],'little')),'x1':hex(int.from_bytes(raw[16:24],'little'))},
            VM_call_executed=False,wrapper_executed=False,target_executed=False)
        self._srcctor_retention['at_next']=self._srcctor_retained(cpu)
        self._srcctor_retention['stop_index']=self._strctor_count
        self._strctor_done=True

    def observe(self,cpu,pc,state):
        self._srcctor_state=state
        return super().observe(cpu,pc,state)

    def finish(self,result,state,proof):
        assert self._srcctor_active and self._strctor_done and self._strctor_returned
        events=result['allocator_events'];assert events[:len(self._strctor_events_before)]==self._strctor_events_before
        assert events[len(self._strctor_events_before):]==[['alloc',len(self._strctor_source_bytes),self._strctor_pointer,'0x248388']]
        ledgers=dict(allocator_counts=result['actual_allocator_counts'],inherited_service_counts=result['explicit_service_counts'],
            inherited_JNI_calls=proof['JNI_calls'],inherited_libc_SVC=proof['libc_SVC_boundaries'],inherited_main_SVC=proof['main_image_SVC_boundaries'],
            inherited_syscall_172=self._pid_syscalls,inherited_syscall_173=self._pp_syscalls,late_jni=self.late_jni_calls,java_dispatch=self.java_dispatch_calls)
        for key,value in ledgers.items():
            if key!='allocator_counts':assert value==self._srcctor_old[key],key
        h=hashlib.sha256()
        for key in self._strctor_trace:h.update(key.encode()+bytes.fromhex(self._strctor_code[key]))
        self._srcctor_retention['protected_write_events']=self._srcctor_protected_writes
        return dict(control=self._srcctor_old['control'],retained_third_default_constructor=self._srcctor_parent,
            instruction_observations=self._strctor_count,instruction_trace_sha256=h.hexdigest(),observation_sites=self._strctor_trace,
            observed_code=self._strctor_code,observed_code_sha256=digest(self._strctor_code),constructor_callback=self._strctor_call,
            native_object_stores=self._strctor_stores,services=self._strctor_services,copy_provider_effects=self._strctor_copy_effects,
            descriptor_integrity=self._srcctor_descriptor_integrity,prior_objects_retention=self._srcctor_retention,
            next_VM_call=self._strctor_next_call,new_allocator_events=events[len(self._strctor_events_before):],**ledgers,
            stop_boundary=dict(stop_before=hex(VM_CALL),kind='before_next_VM_call_after_source_constructor',VM_call_executed=False))


def run(path,libc):
    assert EXPECTED and CODE_SHA256
    parent=prior_evidence();p=bootstrap.module_prefix();p.digest.verify_images(path,libc)
    code=read_static(path,libc);assert {k:v['sha256'] for k,v in code.items()}==CODE_SHA256
    def create(control):
        s=PostDefaultsStringConstructorScenario(control);s.path=path;s.continue_to_svc=True;return s
    rows=p.digest.context.replay(path,libc,case_controls=[p.CONTROL],_extension_factory=create,
        _request_profile=p.digest.previous.previous.name.previous.previous.PROFILE['name'],
        _handler_read_profile=p.digest.context.NULL_PAYLOAD_READ_PROFILE['name'])
    assert len(rows)==1
    return dict(schema=SCHEMA,claims=claims_for(),providers=providers(),source_fingerprints=source_fingerprints(),
        input_provenance=provenance(parent),static_code=code,native_controls=independent_controls(path),
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
    row=data['case_result'];assert data['case_result_sha256']==digest(row) and row['control']==old['control']
    assert row['retained_third_default_constructor']==dict(case_result_sha256=digest(old),verified_fields=list(PARENT_FIELDS))
    sites=row['observation_sites'];code=row['observed_code'];h=hashlib.sha256()
    assert len(sites)==row['instruction_observations']==EXPECTED['instruction_observations']<MAX_OBSERVATIONS
    assert set(sites)==set(code) and sites[:6]==['main:'+hex(x) for x in (VM_CALL,WRAPPER,WRAPPER+4,WRAPPER+8,WRAPPER+12,TARGET)]
    assert sites[EXPECTED['return_index']-1]=='main:'+hex(VM_RESUME) and sites[-1]=='main:'+hex(VM_CALL)
    assert sites.count('main:'+hex(VM_CALL))==2 and sites.count('main:'+hex(WRAPPER))==1 and sites.count('main:'+hex(TARGET))==1
    if NEXT_WRAPPER!=WRAPPER:assert 'main:'+hex(NEXT_WRAPPER) not in sites
    if NEXT_TARGET!=TARGET:assert 'main:'+hex(NEXT_TARGET) not in sites
    assert sites[EXPECTED['malloc_entry_index']-1]=='libc:'+hex(MALLOC) and sites.count('libc:'+hex(MALLOC))==1
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
    call=row['constructor_callback'];base=row['control']['base'];length=EXPECTED['source_length'];width=length+1
    pointer=int(EXPECTED['allocation_pointer'],16);source_hash=EXPECTED['source_including_NUL_sha256']
    assert call['call_index']==1 and call['callsite_offset']==hex(VM_CALL) and call['VM_cursor_offset']=='0x10a178'
    assert call['wrapper_offset']==hex(WRAPPER) and call['target_offset']==hex(TARGET)
    assert call['target_entry_index']==6 and call['return_index']==EXPECTED['return_index'] and call['return_offset']==hex(VM_RESUME)
    assert call['returned_x0']==hex(pointer) and call['object_address']=='0x7004d1d8' and call['source_address']=='0x126a1330'
    assert call['descriptor_address']==old['next_VM_call']['descriptor_address']=='0x7004ccc0'
    assert call['descriptor_before_hex']==old['next_VM_call']['descriptor_hex'][:80]
    assert call['source_length']==length and call['source_including_NUL_sha256']==call['payload_including_NUL_sha256']==source_hash
    assert call['dynamic_target_arguments']=={'x0':'0x7004d1d8','x1':'0x126a1330'}
    assert call['Bionic_malloc_entry']==dict(index=EXPECTED['malloc_entry_index'],libc_offset=hex(MALLOC),request=width)
    assert call['allocation_return']==dict(index=EXPECTED['allocation_return_index'],pointer=hex(pointer),
        payload_before_copy_sha256=EXPECTED['payload_before_copy_sha256'])
    before=bytes.fromhex(call['object_before_hex']);after=bytes.fromhex(call['object_after_hex'])
    assert len(before)==len(after)==32 and raw_hash(before)==EXPECTED['object_before_sha256']
    assert after==(base+0x34F5F8).to_bytes(8,'little')+width.to_bytes(4,'little')+length.to_bytes(4,'little')+pointer.to_bytes(8,'little')+before[24:]
    assert call['wrapper_path']==[hex(x) for x in range(WRAPPER,WRAPPER+16,4)]
    for key in ('object_neighbor_bytes_preserved','descriptor_unchanged','source_unchanged','SP_restored','callee_saved_restored'):assert call[key] is True
    indices=EXPECTED['store_indices']
    assert row['native_object_stores']==[
        dict(index=indices[0],native_pc='0x248360',address='0x7004d1d8',size=8,value=hex(base+0x34F5F8),source_register='x8'),
        dict(index=indices[1],native_pc='0x24837c',address='0x7004d1e0',size=4,value=hex(width),source_register='w8'),
        dict(index=indices[2],native_pc='0x24837c',address='0x7004d1e4',size=4,value=hex(length),source_register='w0'),
        dict(index=indices[3],native_pc='0x248388',address='0x7004d1e8',size=8,value=hex(pointer),source_register='x0')]
    assert row['services']==[
        dict(kind='inherited_strlen',index=EXPECTED['strlen_index'],PC_offset='0x347f40',source='0x126a1330',result=length),
        dict(kind='actual_Bionic_malloc_route',index=EXPECTED['malloc_PLT_index'],PC_offset='0x347fd0',request=width),
        dict(kind='inherited_memcpy',index=EXPECTED['memcpy_index'],PC_offset='0x347f60',target=hex(pointer),source='0x126a1330',width=width,
            payload_including_NUL_sha256=source_hash,original_Bionic_body_executed=False)]
    assert row['copy_provider_effects']==[dict(index=EXPECTED['memcpy_index'],PC_offset='0x347f60',target=hex(pointer),width=width,
        payload_including_NUL_sha256=source_hash,observer_timing='after inherited host write',native_Bionic_memcpy_executed=False)]
    full=old['next_VM_call']['descriptor_hex']
    assert row['descriptor_integrity']==dict(address='0x7004ccc0',width=48,before_hex=full,at_return_hex=full,body_write_events=[])
    retained=deepcopy(old['prior_objects_retention']['at_next']);current=old['constructor_callback']
    retained.append(dict(object_address=current['object_address'],payload_address=current['allocation_return']['pointer'],
        object_hex=current['object_after_hex'][:48],payload_hex=current['payload_after_hex']))
    assert row['prior_objects_retention']==dict(object_width=24,payload_width=8,before=retained,at_return=retained,
        at_next=retained,stop_index=EXPECTED['instruction_observations'],protected_write_events=[])
    next_call=row['next_VM_call'];raw=bytes.fromhex(next_call['descriptor_hex'])
    assert len(raw)==48 and raw_hash(raw)==next_call['descriptor_sha256']==EXPECTED['next_descriptor_sha256']
    assert next_call['index']==EXPECTED['instruction_observations'] and next_call['callsite_offset']==hex(VM_CALL)
    assert next_call['wrapper_offset']==hex(NEXT_WRAPPER) and next_call['target_offset']==hex(NEXT_TARGET)
    assert next_call['VM_cursor_offset']==EXPECTED['next_cursor'] and next_call['descriptor_address']==EXPECTED['next_descriptor_address']
    assert next_call['wrapper_code_hex']==data['static_code']['main:'+hex(NEXT_WRAPPER)]['hex']
    assert next_call['static_expected_target_arguments']==EXPECTED['next_static_arguments']
    for key in ('VM_call_executed','wrapper_executed','target_executed'):assert next_call[key] is False
    assert row['new_allocator_events']==[['alloc',width,pointer,'0x248388']]
    counts=deepcopy(old['allocator_counts']);counts['malloc']+=1;assert row['allocator_counts']==counts
    for key in LEDGERS:
        if key!='allocator_counts':assert row[key]==old[key],key
    assert row['stop_boundary']==dict(stop_before=hex(VM_CALL),kind='before_next_VM_call_after_source_constructor',VM_call_executed=False)


def damaged_evidence_rejected(data):
    changes=[(('claims','complete_standalone_signer_verified'),True),(('claims','next_VM_call_executed'),True),
        (('claims','original_Bionic_strlen_and_memcpy_bodies_executed'),True),
        (('claims','original_JNI_acquisition_body_executed'),True),(('claims','real_ART_JVM_execution'),True),
        (('claims','three_prior_objects_and_payloads_retained'),False),(('claims','full_48_byte_descriptor_preserved'),False),
        (('providers','new_providers'),['hidden']),(('providers','new_import_bindings'),['hidden']),
        (('source_fingerprints','constructor_observer_owner_sha256'),'0'*64),
        (('case_result','retained_third_default_constructor','case_result_sha256'),'0'*64),
        (('case_result','instruction_observations'),1),(('case_result','instruction_trace_sha256'),'0'*64),
        (('case_result','observed_code_sha256'),'0'*64),(('case_result','observation_sites',5),'main:0x0'),
        (('case_result','constructor_callback','returned_x0'),'0x0'),
        (('case_result','constructor_callback','source_length'),0),
        (('case_result','constructor_callback','source_including_NUL_sha256'),'0'*64),
        (('case_result','constructor_callback','payload_including_NUL_sha256'),'0'*64),
        (('case_result','constructor_callback','object_before_hex'),'00'*32),
        (('case_result','constructor_callback','object_after_hex'),'00'*32),
        (('case_result','constructor_callback','object_neighbor_bytes_preserved'),False),
        (('case_result','constructor_callback','descriptor_unchanged'),False),
        (('case_result','constructor_callback','SP_restored'),False),
        (('case_result','constructor_callback','callee_saved_restored'),False),
        (('case_result','constructor_callback','Bionic_malloc_entry','libc_offset'),'0x0'),
        (('case_result','constructor_callback','allocation_return','pointer'),'0x0'),
        (('case_result','constructor_callback','allocation_return','payload_before_copy_sha256'),'0'*64),
        (('case_result','constructor_callback','wrapper_path'),[]),
        (('case_result','native_object_stores',1,'value'),'0x0'),
        (('case_result','native_object_stores',2,'size'),8),
        (('case_result','services',0,'result'),0),(('case_result','services',1,'request'),0),
        (('case_result','services',2,'width'),0),(('case_result','services',2,'original_Bionic_body_executed'),True),
        (('case_result','copy_provider_effects',0,'width'),0),
        (('case_result','copy_provider_effects',0,'native_Bionic_memcpy_executed'),True),
        (('case_result','descriptor_integrity','width'),40),(('case_result','descriptor_integrity','at_return_hex'),'00'*48),
        (('case_result','descriptor_integrity','body_write_events'),['hidden']),
        (('case_result','prior_objects_retention','before',0,'object_hex'),'00'*24),
        (('case_result','prior_objects_retention','at_return',1,'payload_hex'),'ff'*8),
        (('case_result','prior_objects_retention','at_next',2,'object_hex'),'00'*24),
        (('case_result','prior_objects_retention','protected_write_events'),['hidden']),
        (('case_result','new_allocator_events'),[]),(('case_result','allocator_counts','malloc'),582),
        (('case_result','next_VM_call','VM_call_executed'),True),
        (('case_result','next_VM_call','VM_cursor_offset'),'0x10a178'),
        (('case_result','next_VM_call','descriptor_sha256'),'0'*64),
        (('case_result','next_VM_call','static_expected_target_arguments','x0'),'0x0'),
        (('case_result','stop_boundary','VM_call_executed'),True),
        (('native_controls',0,'allocation_requested'),0),(('native_controls',2,'capacity'),0),
        (('native_controls',12,'previous_objects_retained'),2),(('native_controls',13,'allocation_succeeded'),True)]
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
        raise AssertionError(f'damaged post-defaults source-constructor evidence accepted: {path}')
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
        if args.replay:assert run(args.elf,args.libc)==data,'fresh post-defaults source-constructor replay differs'
    print(json.dumps(dict(schema=SCHEMA,damaged_evidence_rejected=rejected,
        instruction_observations=data['case_result']['instruction_observations'],native_controls=len(data['native_controls']),
        source_string_constructor_returned=True,next_VM_call_executed=False,complete_standalone_signer_verified=False)))


if __name__=='__main__':main()
