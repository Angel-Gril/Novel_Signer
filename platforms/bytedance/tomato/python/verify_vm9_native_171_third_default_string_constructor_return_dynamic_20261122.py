"""Verify third default StringObject construction while retaining both prior objects."""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as arm

import verify_vm9_native_171_second_default_string_constructor_return_dynamic_20261122 as previous

constructor_owner=previous.previous
oracle,controls,bootstrap=previous.oracle,previous.controls,previous.bootstrap
sha256,raw_hash,digest=previous.sha256,previous.raw_hash,previous.digest
EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_third_default_string_constructor_return_dynamic_20261122.json')
SCHEMA='vm9-native-171-third-default-string-constructor-return-dynamic-20261122-v1'
VM_CALL,VM_RESUME,WRAPPER,TARGET=previous.VM_CALL,previous.VM_RESUME,previous.WRAPPER,previous.TARGET
LIBC_BASE,MALLOC,EMPTY=previous.LIBC_BASE,previous.MALLOC,previous.EMPTY
MAX_OBSERVATIONS=previous.MAX_OBSERVATIONS
PARENT_FIELDS=('instruction_observations','instruction_trace_sha256','observation_sites','observed_code',
    'observed_code_sha256','retained_first_default_constructor','constructor_callback','native_reads','native_stores',
    'malloc_calls','next_VM_call','first_object_retention')
LEDGERS=previous.LEDGERS
EXPECTED={'instruction_observations': 3232, 'instruction_trace_sha256': '060c19ffb7351a4ba025422e79a3f4d6afe2c2a6fa03b6eccd36305c467b3423', 'observed_code_sha256': '2208c47f5dce0b4582600b5dfe1c13eb7d2056d988d22f67264233a2c23209a8', 'return_index': 148, 'malloc_PLT_index': 17, 'malloc_entry_index': 18, 'allocation_return_index': 141, 'allocation_pointer': '0x136d82d8', 'object_before_sha256': 'e5aa7b9f016a55c27a55eb2a8b34b14b42b1f33248db59ba0bf0c231c7bcb7f4', 'payload_before_hex': '0000000000000000', 'store_indices': [13, 14, 141, 143], 'initial_descriptor_sha256': '6cc16abd70eefb90dc0ba0d14fb088630873b2c6ad943f7442356735984c35a3', 'next_cursor': '0x10a178', 'next_descriptor_address': '0x7004ccc0', 'next_descriptor_sha256': '315f283d47f82d053f6eec0149668c8a6a14330e44f1cd0701e77a52f59ebcbf', 'next_static_arguments': {'x0': '0x7004d1d8', 'x1': '0x126a1330'}}
NEXT_WRAPPER,NEXT_TARGET=0x2885D0,0x248344
CODE_RANGES={'main':previous.CODE_RANGES['main']+((NEXT_WRAPPER,16),(NEXT_TARGET,156)),'libc':previous.CODE_RANGES['libc']}
CODE_SHA256={'main:0x2884cc': '82295168e4332fdd8ee754ea9b86ffc5a592a6e6c42c0e1592ea18f55c95c565', 'main:0x2481ac': '67059ef8f1b623858ffe0c627379fefe2d9bdc4d04f44cfdbdc053cb8a9751fb', 'libc:0x1bb08': '5f183f5bc3ff80cac083022481d5449cfdceaa89cc15ff71781be915fc836b36', 'main:0x2885d0': '14d9ed527789cfea4669cc452adab89d302cd67f24dc06b1de12d4ca1b71a7af', 'main:0x248344': 'f73af655d3e97f1da0d870dfaaea43bae7a33fc3403a4a26cfab43eb0e0559fd'}


def prior_evidence():
    data=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(data);return data


def source_fingerprints():
    return dict(third_default_string_constructor_verifier_sha256=sha256(Path(__file__)),
        parent_verifier_sha256=sha256(Path(previous.__file__)),inherited=previous.source_fingerprints())


def provenance(parent):
    return dict(parent_evidence_sha256=sha256(previous.EVIDENCE),parent_case_sha256=digest(parent['case_result']),
        inherited_input_provenance=parent['input_provenance'],native_snapshot_used_as_python_model_input=False)


def read_static(path,libc):
    code,empty=previous.read_static(path,libc)
    with path.open('rb') as stream:
        elf=ELFFile(stream)
        for off,size in CODE_RANGES['main']:
            raw=constructor_owner.previous.elf_bytes(elf,stream,off,size)
            code['main:'+hex(off)]=dict(size=size,hex=raw.hex(),sha256=raw_hash(raw))
    return code,empty


def providers():
    return dict(inherited=previous.providers(),new_providers=[],new_import_bindings=[],
        observation_owner='frozen constructor owner read/store/return and original-malloc observers reused for third invocation',
        retention_controls='fresh two adjacent prior objects and payloads; explicit synthetic malloc success/failure',
        component_memory_scope='declared 0xa000-byte guest payload span; native stack and synthetic thread pointer excluded')


def claims_for():
    return dict(evidence_label='Sample verified',second_default_constructor_prefix_revalidated=True,
        third_original_default_constructor_returned=True,matching_Bionic_malloc_entry_observed=True,
        eight_byte_allocation_and_one_byte_NUL_store_verified=True,first_two_objects_and_payloads_retained=True,
        object_neighbors_and_descriptor_preserved=True,SP_and_callee_saved_restored=True,
        next_VM_call_executed=False,new_providers_added=False,native_snapshot_used_as_python_model_input=False,
        original_JNI_acquisition_body_executed=False,real_ART_JVM_execution=False,
        complete_VM_suffix_return_verified=False,complete_standalone_signer_verified=False,
        ordinary_Cronet_six_headers_verified=False,Android_execution=False,
        physical_PAC_authentication_verified=False,online_acceptance_verified=False)


def retention_specs():
    return [dict(image_base=hex(base),case=label,allocation_requested=8,
        allocation_succeeded=label=='two_adjacent_objects',previous_objects_retained=2,previous_payloads_retained=2,
        declared_guest_payload_compared=True,SP_and_callee_saved_restored=True,
        allocator='explicit synthetic component provider')
        for base in controls.BASES for label in ('two_adjacent_objects','two_adjacent_objects_allocation_failure')]


def control_specs():return previous.control_specs()+retention_specs()


def independent_controls(path):
    rows=previous.independent_controls(path)
    for expected in retention_specs():
        base=int(expected['image_base'],16);pages,inputs,_=controls.fixture(path,base,'default','normal')
        block=inputs['argument_block_address'];obj=int.from_bytes(controls._read_span(pages,block+8,8),'little')
        protected=[]
        for offset,ptr,payload in ((48,oracle.GUEST+0x4800,b'first\0PQ'),(24,oracle.GUEST+0x4900,b'second\0R')):
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
            if pc==base+0x2481F8:
                retained(cpu);assert cpu.reg_read(arm.UC_ARM64_REG_SP)==oracle.GUEST+0xEF00
                assert all(cpu.reg_read(r)==v for r,v in saved.items());returned.append(True)
        result,memory,allocations,ledger=oracle.native(path,base,WRAPPER,[block],pages,malloc_handler=allocate,
            extra_registers=saved,instruction_observer=observe,instruction_limit=1000)
        target=bytearray(before);off=obj-oracle.GUEST
        target[off:off+24]=(base+0x34F5F8).to_bytes(8,'little')+bytes.fromhex('0800000000000000')+pointer.to_bytes(8,'little')
        if pointer:target[pointer-oracle.GUEST]=0
        else:target[off+8:off+12]=bytes(4)
        assert memory==target and result==pointer and requests==[8] and returned==[True] and allocations==ledger==[]
        rows.append(expected)
    return rows


class ThirdDefaultStringConstructorScenario(previous.SecondDefaultStringConstructorScenario):
    def __init__(self,control):
        super().__init__(control)
        self._third_active=False;self._third_old=prior_evidence()['case_result'];self._third_protected_writes=[]

    def native_runner(self,*args,**kwargs):
        old_write=kwargs['memory_write_observer']
        def write(cpu,address,size):
            if self._third_active and any(address<start+width and start<address+size for start,width in self._third_ranges):
                self._third_protected_writes.append(dict(index=self._defctor_count,address=hex(address),size=size,
                    native_pc=hex(cpu.reg_read(arm.UC_ARM64_REG_PC)-self.image)))
                raise AssertionError('third constructor continuation wrote a protected prior object or payload')
            if old_write:old_write(cpu,address,size)
        kwargs['memory_write_observer']=write
        return super().native_runner(*args,**kwargs)

    def _third_retained(self,cpu):
        rows=[]
        for expected in self._third_prior:
            obj=int(expected['object_address'],16);ptr=int(expected['payload_address'],16)
            actual=dict(object_address=hex(obj),payload_address=hex(ptr),object_hex=bytes(cpu.mem_read(obj,24)).hex(),
                payload_hex=bytes(cpu.mem_read(ptr,8)).hex())
            assert actual==expected;rows.append(actual)
        return rows

    def _activate_third(self,cpu,pc):
        super()._defctor_next(cpu,pc)
        retained=deepcopy(self._second_retention);retained['protected_write_events']=deepcopy(self._second_protected_writes)
        h=hashlib.sha256()
        for key in self._defctor_trace:h.update(key.encode()+bytes.fromhex(self._defctor_code[key]))
        values=(self._defctor_count,h.hexdigest(),self._defctor_trace,self._defctor_code,digest(self._defctor_code),
            self._defctor_parent,self._defctor_call,self._defctor_reads,self._defctor_stores,self._defctor_malloc_calls,self._defctor_next_call,retained)
        for value,key in zip(values,PARENT_FIELDS):assert value==self._third_old[key],key
        events=self._defctor_state['allocator_events_ref']
        assert events[len(self._defctor_events_before):]==self._third_old['new_allocator_events']
        first=self._third_old['first_object_retention'];second=self._third_old['constructor_callback']
        self._third_prior=[dict(object_address=first['object_address'],payload_address=first['payload_address'],**first['at_next']),
            dict(object_address=second['object_address'],payload_address=second['allocation_return']['pointer'],
                object_hex=second['object_after_hex'][:48],payload_hex=second['payload_after_hex'])]
        self._third_ranges=[(int(row[key],16),width) for row in self._third_prior for key,width in (('object_address',24),('payload_address',8))]
        self._third_retention=dict(object_width=24,payload_width=8,before=self._third_retained(cpu))
        self._defctor_parent=dict(case_result_sha256=digest(self._third_old),verified_fields=list(PARENT_FIELDS))
        self._defctor_old=self._third_old;self._defctor_events_before=deepcopy(events)
        self._defctor_done=False;self._defctor_returned=False;self._defctor_count=0
        self._defctor_trace=[];self._defctor_code={};self._defctor_path=[];self._defctor_reads=[]
        self._defctor_stores=[];self._defctor_malloc_calls=[];self._defctor_pointer=0
        self._defctor_descriptor=self._reg(cpu,0);self._defctor_descriptor_before=bytes(cpu.mem_read(self._defctor_descriptor,48))
        self._defctor_object=self._u(cpu,self._defctor_descriptor+8);self._defctor_object_before=bytes(cpu.mem_read(self._defctor_object,32))
        self._defctor_empty=bytes(cpu.mem_read(self.image+EMPTY,8))
        self._defctor_sp=cpu.reg_read(arm.UC_ARM64_REG_SP);self._defctor_saved=[self._reg(cpu,n) for n in range(19,30)]
        self._defctor_call=dict(call_index=1,callsite_offset=hex(VM_CALL),VM_cursor_offset='0x109ef0',
            wrapper_offset=hex(WRAPPER),target_offset=hex(TARGET),descriptor_address=hex(self._defctor_descriptor),
            descriptor_before_hex=self._defctor_descriptor_before.hex(),object_address=hex(self._defctor_object),
            object_before_hex=self._defctor_object_before.hex(),initial_descriptor_hex=self._defctor_empty.hex())
        self._second_active=False;self._third_active=True;self._defctor_track(cpu,pc)

    def _defctor_return(self,cpu):
        super()._defctor_return(cpu)
        if self._third_active:self._third_retention['at_return']=self._third_retained(cpu)

    def _defctor_next(self,cpu,pc):
        if not self._third_active:
            if not self._second_active:return super()._defctor_next(cpu,pc)
            return self._activate_third(cpu,pc)
        d=self._reg(cpu,0);raw=bytes(cpu.mem_read(d,48));wrapper=self._reg(cpu,8)
        assert self._defctor_count==EXPECTED['instruction_observations']
        assert hex(self._u(cpu,self._reg(cpu,19))-self.image)==EXPECTED['next_cursor']
        assert hex(d)==EXPECTED['next_descriptor_address']
        assert wrapper==self.image+NEXT_WRAPPER and int.from_bytes(raw[:8],'little')==self.image+NEXT_TARGET
        assert raw_hash(raw)==EXPECTED['next_descriptor_sha256'] and bytes(cpu.mem_read(pc,4)).hex()=='00013fd6'
        self._defctor_next_call=dict(index=self._defctor_count,callsite_offset=hex(VM_CALL),wrapper_offset=hex(wrapper-self.image),
            target_offset=hex(int.from_bytes(raw[:8],'little')-self.image),VM_cursor_offset=hex(self._u(cpu,self._reg(cpu,19))-self.image),
            descriptor_address=hex(d),descriptor_hex=raw.hex(),descriptor_sha256=raw_hash(raw),
            wrapper_code_hex=bytes(cpu.mem_read(wrapper,16)).hex(),
            static_expected_target_arguments={'x0':hex(int.from_bytes(raw[8:16],'little')),'x1':hex(int.from_bytes(raw[16:24],'little'))},
            VM_call_executed=False,wrapper_executed=False,target_executed=False)
        self._third_retention['at_next']=self._third_retained(cpu)
        self._third_retention['stop_index']=self._defctor_count
        self._defctor_done=True

    def finish(self,result,state,proof):
        assert self._third_active and not self._second_active
        row=constructor_owner.DefaultStringConstructorScenario.finish(self,result,state,proof)
        row['retained_second_default_constructor']=row.pop('retained_string_destructor')
        self._third_retention['protected_write_events']=self._third_protected_writes
        row['prior_objects_retention']=self._third_retention
        row['stop_boundary']=dict(stop_before=hex(VM_CALL),kind='before_next_VM_call_after_third_default_constructor',VM_call_executed=False)
        return row


def run(path,libc):
    assert EXPECTED and CODE_SHA256
    parent=prior_evidence();p=bootstrap.module_prefix();p.digest.verify_images(path,libc)
    code,empty=read_static(path,libc);assert {k:v['sha256'] for k,v in code.items()}==CODE_SHA256
    def create(control):
        s=ThirdDefaultStringConstructorScenario(control);s.path=path;s.continue_to_svc=True;return s
    rows=p.digest.context.replay(path,libc,case_controls=[p.CONTROL],_extension_factory=create,
        _request_profile=p.digest.previous.previous.name.previous.previous.PROFILE['name'],
        _handler_read_profile=p.digest.context.NULL_PAYLOAD_READ_PROFILE['name'])
    assert len(rows)==1
    return dict(schema=SCHEMA,claims=claims_for(),providers=providers(),source_fingerprints=source_fingerprints(),
        input_provenance=provenance(parent),static_code=code,static_initial_descriptor=empty,native_controls=independent_controls(path),
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
    empty=data['static_initial_descriptor']
    assert empty==dict(offset=hex(EMPTY),hex='0800000000000000',sha256=EXPECTED['initial_descriptor_sha256'])
    assert raw_hash(bytes.fromhex(empty['hex']))==empty['sha256']
    row=data['case_result'];assert data['case_result_sha256']==digest(row) and row['control']==old['control']
    assert row['retained_second_default_constructor']==dict(case_result_sha256=digest(old),verified_fields=list(PARENT_FIELDS))
    sites=row['observation_sites'];code=row['observed_code'];h=hashlib.sha256()
    assert len(sites)==row['instruction_observations']==EXPECTED['instruction_observations']<MAX_OBSERVATIONS
    assert set(sites)==set(code) and sites[:5]==['main:'+hex(x) for x in (VM_CALL,WRAPPER,WRAPPER+4,WRAPPER+8,TARGET)]
    assert sites[EXPECTED['return_index']-1]=='main:'+hex(VM_RESUME) and sites[-1]=='main:'+hex(VM_CALL)
    assert sites.count('main:'+hex(VM_CALL))==2 and sites.count('main:'+hex(WRAPPER))==1
    assert sites.count('main:'+hex(TARGET))==1
    assert 'main:'+hex(NEXT_WRAPPER) not in sites and 'main:'+hex(NEXT_TARGET) not in sites
    assert sites[EXPECTED['malloc_entry_index']-1]=='libc:'+hex(MALLOC) and sites.count('libc:'+hex(MALLOC))==1
    assert 'main:0x2481ec' not in sites
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
    call=row['constructor_callback'];base=row['control']['base'];pointer=int(EXPECTED['allocation_pointer'],16)
    assert call['call_index']==1 and call['callsite_offset']==hex(VM_CALL) and call['VM_cursor_offset']=='0x109ef0'
    assert call['wrapper_offset']==hex(WRAPPER) and call['target_offset']==hex(TARGET)
    assert call['target_entry_index']==5 and call['return_index']==EXPECTED['return_index'] and call['return_offset']==hex(VM_RESUME)
    assert call['dynamic_target_arguments']=={'x0':'0x7004d148'} and call['object_address']=='0x7004d148'
    assert call['descriptor_address']==old['next_VM_call']['descriptor_address']=='0x7004cdf8'
    assert call['descriptor_before_hex']==call['descriptor_after_hex']==old['next_VM_call']['descriptor_hex']
    assert call['initial_descriptor_hex']==empty['hex']
    before=bytes.fromhex(call['object_before_hex']);after=bytes.fromhex(call['object_after_hex'])
    assert len(before)==len(after)==32 and raw_hash(before)==EXPECTED['object_before_sha256']
    assert after==(base+0x34F5F8).to_bytes(8,'little')+bytes.fromhex(empty['hex'])+pointer.to_bytes(8,'little')+before[24:]
    assert call['Bionic_malloc_entry']==dict(index=EXPECTED['malloc_entry_index'],libc_offset=hex(MALLOC),requested_size=8)
    assert call['allocation_return']==dict(index=EXPECTED['allocation_return_index'],pointer=hex(pointer),
        payload_before_hex=EXPECTED['payload_before_hex'])
    initial_payload=bytes.fromhex(EXPECTED['payload_before_hex']);assert len(initial_payload)==8
    assert call['payload_after_hex']==(b'\0'+initial_payload[1:]).hex() and call['raw_returned_x0']==hex(pointer)
    assert call['wrapper_path']==[hex(x) for x in range(WRAPPER,WRAPPER+12,4)]
    for key in ('one_byte_NUL_written','remaining_allocation_bytes_preserved','object_neighbors_preserved',
                'descriptor_unchanged','SP_restored','callee_saved_restored'):assert call[key] is True
    assert row['malloc_calls']==[dict(index=EXPECTED['malloc_PLT_index'],requested_size=8,PLT_offset='0x347fd0')]
    assert row['native_reads']==[dict(index=12,native_pc='0x2481c8',address=hex(base+EMPTY),size=8,value_hex=empty['hex'])]
    indices=EXPECTED['store_indices']
    assert row['native_stores']==[
        dict(index=indices[0],native_pc='0x2481cc',address='0x7004d148',size=8,value_hex=(base+0x34F5F8).to_bytes(8,'little').hex(),source_register='x9'),
        dict(index=indices[1],native_pc='0x2481d0',address='0x7004d150',size=8,value_hex=empty['hex'],source_register='d0'),
        dict(index=indices[2],native_pc='0x2481dc',address='0x7004d158',size=8,value_hex=pointer.to_bytes(8,'little').hex(),source_register='x0'),
        dict(index=indices[3],native_pc='0x2481e4',address=hex(pointer),size=1,value_hex='00',source_register='wzr')]
    next_call=row['next_VM_call'];raw=bytes.fromhex(next_call['descriptor_hex'])
    assert len(raw)==48 and raw_hash(raw)==next_call['descriptor_sha256']==EXPECTED['next_descriptor_sha256']
    assert next_call['index']==EXPECTED['instruction_observations'] and next_call['callsite_offset']==hex(VM_CALL)
    assert next_call['wrapper_offset']==hex(NEXT_WRAPPER) and next_call['target_offset']==hex(NEXT_TARGET)
    assert next_call['VM_cursor_offset']==EXPECTED['next_cursor'] and next_call['descriptor_address']==EXPECTED['next_descriptor_address']
    assert next_call['wrapper_code_hex']==data['static_code']['main:'+hex(NEXT_WRAPPER)]['hex']
    assert next_call['static_expected_target_arguments']==EXPECTED['next_static_arguments']
    for key in ('VM_call_executed','wrapper_executed','target_executed'):assert next_call[key] is False
    assert row['new_allocator_events']==[['alloc',8,pointer,'0x2481dc']]
    counts=deepcopy(old['allocator_counts']);counts['malloc']+=1;assert row['allocator_counts']==counts
    for key in LEDGERS:
        if key!='allocator_counts':assert row[key]==old[key],key
    assert row['stop_boundary']==dict(stop_before=hex(VM_CALL),kind='before_next_VM_call_after_third_default_constructor',VM_call_executed=False)

    first=old['first_object_retention'];second=old['constructor_callback']
    retained=[dict(object_address=first['object_address'],payload_address=first['payload_address'],**first['at_next']),
        dict(object_address=second['object_address'],payload_address=second['allocation_return']['pointer'],
            object_hex=second['object_after_hex'][:48],payload_hex=second['payload_after_hex'])]
    assert row['prior_objects_retention']==dict(object_width=24,payload_width=8,before=retained,at_return=retained,
        at_next=retained,stop_index=EXPECTED['instruction_observations'],protected_write_events=[])


def damaged_evidence_rejected(data):
    changes=[(('claims','complete_standalone_signer_verified'),True),(('claims','next_VM_call_executed'),True),
        (('claims','matching_Bionic_malloc_entry_observed'),False),(('claims','original_JNI_acquisition_body_executed'),True),
        (('claims','real_ART_JVM_execution'),True),(('claims','native_snapshot_used_as_python_model_input'),True),
        (('providers','new_providers'),['hidden']),(('providers','new_import_bindings'),['hidden']),
        (('source_fingerprints','inherited','inherited','allocator_import_owner_sha256'),'0'*64),
        (('static_initial_descriptor','hex'),'00'*8),
        (('case_result','retained_second_default_constructor','case_result_sha256'),'0'*64),
        (('case_result','instruction_observations'),1),(('case_result','instruction_trace_sha256'),'0'*64),
        (('case_result','observed_code_sha256'),'0'*64),(('case_result','observation_sites',4),'main:0x0'),
        (('case_result','constructor_callback','descriptor_before_hex'),'00'*48),
        (('case_result','constructor_callback','object_before_hex'),'00'*32),
        (('case_result','constructor_callback','object_after_hex'),'00'*32),
        (('case_result','constructor_callback','initial_descriptor_hex'),'00'*8),
        (('case_result','constructor_callback','Bionic_malloc_entry','libc_offset'),'0x0'),
        (('case_result','constructor_callback','Bionic_malloc_entry','requested_size'),7),
        (('case_result','constructor_callback','allocation_return','pointer'),'0x0'),
        (('case_result','constructor_callback','allocation_return','index'),1),
        (('case_result','constructor_callback','allocation_return','payload_before_hex'),'ff'*8),
        (('case_result','constructor_callback','payload_after_hex'),'ff'*8),
        (('case_result','constructor_callback','raw_returned_x0'),'0x0'),
        (('case_result','constructor_callback','remaining_allocation_bytes_preserved'),False),
        (('case_result','constructor_callback','SP_restored'),False),
        (('case_result','constructor_callback','callee_saved_restored'),False),
        (('case_result','malloc_calls',0,'requested_size'),33),
        (('case_result','native_reads',0,'value_hex'),'00'*8),
        (('case_result','native_stores',1,'source_register'),'x0'),
        (('case_result','native_stores',3,'size'),8),(('case_result','native_stores',3,'value_hex'),'00'*8),
        (('case_result','new_allocator_events'),[]),(('case_result','allocator_counts','malloc'),581),
        (('case_result','next_VM_call','VM_call_executed'),True),
        (('case_result','next_VM_call','VM_cursor_offset'),'0x109ef0'),
        (('case_result','next_VM_call','descriptor_sha256'),'0'*64),
        (('case_result','next_VM_call','static_expected_target_arguments','x0'),'0x0'),
        (('case_result','stop_boundary','VM_call_executed'),True),
        (('native_controls',0,'allocation_requested'),7),(('native_controls',1,'allocation_succeeded'),True),
        (('native_controls',3,'descriptor_preserved'),True),
        (('native_controls',5,'expected_initial_descriptor_hex'),'00'*8)]
    changes.extend([
        (('claims','first_two_objects_and_payloads_retained'),False),
        (('case_result','prior_objects_retention','object_width'),32),
        (('case_result','prior_objects_retention','before',0,'object_hex'),'00'*24),
        (('case_result','prior_objects_retention','at_return',0,'payload_hex'),'ff'*8),
        (('case_result','prior_objects_retention','at_next',1,'object_hex'),'00'*24),
        (('case_result','prior_objects_retention','stop_index'),1),
        (('case_result','prior_objects_retention','protected_write_events'),['hidden']),
        (('native_controls',18,'first_payload_8_bytes_retained'),False),
        (('native_controls',19,'allocation_succeeded'),True)])
    changes.extend([
        (('case_result','prior_objects_retention','at_return',1,'payload_hex'),'ff'*8),
        (('case_result','prior_objects_retention','before',1,'object_hex'),'00'*24),
        (('native_controls',22,'previous_objects_retained'),1),
        (('native_controls',23,'allocation_succeeded'),True)])
    changes.extend([
        (('case_result','next_VM_call','static_expected_target_arguments','x1'),'0x0'),
        (('case_result','next_VM_call','descriptor_address'),'0x7004cdf8')])
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
        raise AssertionError(f'damaged third-default-constructor evidence accepted: {path}')
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
        if args.replay:assert run(args.elf,args.libc)==data,'fresh third-default-constructor replay differs'
    print(json.dumps(dict(schema=SCHEMA,damaged_evidence_rejected=rejected,
        instruction_observations=data['case_result']['instruction_observations'],native_controls=len(data['native_controls']),
        third_default_string_constructor_returned=True,next_VM_call_executed=False,complete_standalone_signer_verified=False)))


if __name__=='__main__':main()
