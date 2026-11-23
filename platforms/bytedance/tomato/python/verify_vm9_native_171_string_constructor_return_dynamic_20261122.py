"""Verify the original StringObject constructor after the locked getter."""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as arm

import verify_vm9_native_171_locked_pointer_return_dynamic_20261122 as previous
import verify_vm9_native_171_resolve_next_vm_callback_dynamic_20261121 as bootstrap
import verify_vm9_signer_objects as oracle
import verify_vm9_request_environment_strings_fresh_20261014 as controls

EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_string_constructor_return_dynamic_20261122.json')
SCHEMA='vm9-native-171-string-constructor-return-dynamic-20261122-v1'
VM_CALL,VM_RESUME=previous.VM_CALL,previous.VM_RESUME
WRAPPER,TARGET=0x2885D0,0x248344
NEXT_WRAPPER,NEXT_TARGET=0x2887B0,0x256B84
LIBC_BASE,MALLOC=0x51000000,0x1BB08
MAX_OBSERVATIONS=30000
sha256,raw_hash,digest=previous.sha256,previous.raw_hash,previous.digest
PARENT_FIELDS=('instruction_observations','instruction_trace_sha256','observation_sites','observed_code',
    'observed_code_sha256','retained_JNI_provider','locked_callback','mutex_calls','libc_body_entries',
    'native_reads','descriptor_stores','mutex_stores','next_VM_call')
LEDGERS=previous.LEDGERS
CODE_RANGES={'main':((WRAPPER,16),(TARGET,156),(NEXT_WRAPPER,32)),'libc':((MALLOC,32),)}
CODE_SHA256={'main:0x2885d0': '14d9ed527789cfea4669cc452adab89d302cd67f24dc06b1de12d4ca1b71a7af', 'main:0x248344': 'f73af655d3e97f1da0d870dfaaea43bae7a33fc3403a4a26cfab43eb0e0559fd', 'main:0x2887b0': '6ce506c18ac9a690dd2162ee9be389bdd9e9d193bcb0db655a1b8c95c2ff5280', 'libc:0x1bb08': '5f183f5bc3ff80cac083022481d5449cfdceaa89cc15ff71781be915fc836b36'}
EXPECTED={'instruction_observations': 771, 'return_index': 157, 'instruction_trace_sha256': '236277f76227ccdbdc1a14840724d327fc6dfb05991d94a79ad17ceb7e1b5dc6', 'observed_code_sha256': 'd8bfae451b80aea55cbbb401d672dd641321deffbe17e668e43d56099c8edcf2', 'source_length': 32, 'source_including_NUL_sha256': 'f27f570301f2b1b7c25a5233100c1611bfb5975ab0064b5dcfeab2cd99d47fe4', 'next_descriptor_sha256': '059d4688636cfafca5fe52ec5056b57f8c0733c7a9923c67f1b6a439bac078f9'}


def prior_evidence():
    data=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(data);return data


def source_fingerprints():
    return dict(string_constructor_verifier_sha256=sha256(Path(__file__)),
        parent_verifier_sha256=sha256(Path(previous.__file__)),oracle_sha256=sha256(Path(oracle.__file__)),
        component_fixture_sha256=sha256(Path(controls.__file__)),inherited=previous.source_fingerprints())


def provenance(parent):
    return dict(parent_evidence_sha256=sha256(previous.EVIDENCE),parent_case_sha256=digest(parent['case_result']),
        inherited_input_provenance=parent['input_provenance'],native_snapshot_used_as_python_model_input=False)


def read_static(path,libc):
    rows={}
    for domain,filename in (('main',path),('libc',libc)):
        with filename.open('rb') as stream:
            elf=ELFFile(stream)
            if domain=='libc':
                export=[(s['st_value'],s['st_size']) for s in elf.get_section_by_name('.dynsym').iter_symbols() if s.name=='malloc']
                assert export==[(MALLOC,32)]
            for off,size in CODE_RANGES[domain]:
                segment=next(s for s in elf.iter_segments() if s['p_type']=='PT_LOAD' and s['p_vaddr']<=off
                    and off+size<=s['p_vaddr']+s['p_filesz'])
                stream.seek(segment['p_offset']+off-segment['p_vaddr']);raw=stream.read(size)
                key=domain+':'+hex(off);assert len(raw)==size
                rows[key]=dict(size=size,hex=raw.hex(),sha256=raw_hash(raw))
    return rows


def providers():
    return dict(inherited=previous.providers(),new_providers=[],new_import_bindings=[],
        allocation='inherited routing to original matching Bionic malloc; actual allocation event recorded',
        strlen='inherited host strlen provider; original Bionic strlen body does not execute',
        memcpy='inherited host memcpy provider includes trailing NUL; original Bionic memcpy body does not execute',
        control_allocator='explicit fresh synthetic malloc success/failure only in independent component controls',
        maximum_instruction_observations=MAX_OBSERVATIONS)


def claims_for():
    return dict(evidence_label='Sample verified',locked_getter_prefix_revalidated=True,
        original_VM_call_and_tail_wrapper_executed=True,original_constructor_returned=True,
        actual_Bionic_malloc_entry_observed=True,inherited_strlen_and_memcpy_providers_used=True,
        source_including_NUL_copied=True,object_header_and_neighbor_bytes_verified=True,
        descriptor_preserved=True,SP_and_callee_saved_restored=True,next_VM_call_executed=False,
        native_snapshot_used_as_python_model_input=False,new_providers_added=False,
        original_Bionic_strlen_and_memcpy_bodies_executed=False,original_JNI_acquisition_body_executed=False,
        real_ART_JVM_execution=False,complete_VM_suffix_return_verified=False,
        complete_standalone_signer_verified=False,ordinary_Cronet_six_headers_verified=False,
        Android_execution=False,physical_PAC_authentication_verified=False,online_acceptance_verified=False)


def control_specs():
    rows=[]
    for base in controls.BASES:
        for label in ('normal','empty','NULL_source','allocation_failure','cross_page_object','embedded_NUL'):
            length=0 if label in ('empty','NULL_source') else 2 if label=='embedded_NUL' else len(b'helper-string')
            capacity=8 if label=='NULL_source' else length+1
            rows.append(dict(image_base=hex(base),case=label,length=length,capacity=capacity,
                allocation_requested=capacity,allocation_succeeded=label!='allocation_failure',
                original_tail_wrapper_and_constructor_returned=True,full_payload_and_padding_verified=True,
                descriptor_preserved=True,SP_and_callee_saved_restored=True,
                allocator='explicit synthetic component provider',strlen_memcpy='inherited host providers'))
    return rows


def independent_controls(path):
    rows=[]
    for expected in control_specs():
        base=int(expected['image_base'],16);label=expected['case']
        pages,inputs,obj=controls.fixture(path,base,'construct',label)
        block=inputs['argument_block_address'];before=controls._read_span(pages,oracle.GUEST,0xA000)
        source=int.from_bytes(controls._read_span(pages,block+16,8),'little')
        pointer=0 if label=='allocation_failure' else oracle.GUEST+0x4000
        payload=b'\0' if label in ('NULL_source','empty') else b'ab\0' if label=='embedded_NUL' else b'helper-string\0'
        requests=[];observed=[];copies=[];returned=[]
        saved={getattr(arm,f'UC_ARM64_REG_X{n}'):0x120000+n for n in range(19,30)}
        def allocate(cpu,size):requests.append(size);return pointer
        def observe(cpu,pc):
            off=pc-base;observed.append(off)
            if off==0x347F60:
                assert [cpu.reg_read(getattr(arm,f'UC_ARM64_REG_X{n}')) for n in range(3)]==[pointer,source,expected['capacity']]
                copies.append(True)
            if off in (0x347F60,0x2483DC):
                assert cpu.reg_read(arm.UC_ARM64_REG_SP)==oracle.GUEST+0xEF00
                assert all(cpu.reg_read(r)==v for r,v in saved.items());returned.append(True)
        result,memory,allocations,ledger=oracle.native(path,base,WRAPPER,[block],pages,malloc_handler=allocate,
            extra_registers=saved,instruction_observer=observe,instruction_limit=1000)
        target=bytearray(before);off=obj-oracle.GUEST
        target[off:off+24]=(base+0x34F5F8).to_bytes(8,'little')+expected['capacity'].to_bytes(4,'little')+expected['length'].to_bytes(4,'little')+pointer.to_bytes(8,'little')
        if pointer:target[pointer-oracle.GUEST:pointer-oracle.GUEST+len(payload)]=payload
        assert memory==target and requests==[expected['allocation_requested']] and result==pointer
        assert allocations==ledger==[] and observed[:4]==list(range(WRAPPER,WRAPPER+16,4))
        assert len(returned)==1 and len(copies)==(1 if pointer and source else 0)
        rows.append(expected)
    return rows


class StringConstructorScenario(previous.LockedPointerScenario):
    def __init__(self,control):
        super().__init__(control)
        self._strctor_active=False;self._strctor_done=False;self._strctor_returned=False
        self._strctor_count=0;self._strctor_trace=[];self._strctor_code={};self._strctor_state=None
        self._strctor_path=[];self._strctor_stores=[];self._strctor_services=[];self._strctor_copy_effects=[]
        self._strctor_old=prior_evidence()['case_result']

    def _strctor_track(self,cpu,pc):
        self._strctor_count+=1;assert self._strctor_count<MAX_OBSERVATIONS
        if LIBC_BASE<=pc<LIBC_BASE+0x200000:domain,off='libc',pc-LIBC_BASE
        else:
            assert self.image<=pc<self.image+0x400000
            domain,off='main',pc-self.image
        key=domain+':'+hex(off);self._strctor_trace.append(key);self._strctor_code[key]=bytes(cpu.mem_read(pc,4)).hex()

    def _locked_next(self,cpu,pc):
        super()._locked_next(cpu,pc)
        trace=hashlib.sha256()
        for key in self._locked_trace:trace.update(key.encode()+bytes.fromhex(self._locked_code[key]))
        values=(self._locked_count,trace.hexdigest(),self._locked_trace,self._locked_code,digest(self._locked_code),
            self._locked_parent,self._locked_call,self._locked_mutex_events,self._locked_body_entries,
            self._locked_reads,self._locked_stores,self._locked_mutex_stores,self._locked_next_call)
        for value,key in zip(values,PARENT_FIELDS):assert value==self._strctor_old[key],key
        self._strctor_parent=dict(case_result_sha256=digest(self._strctor_old),verified_fields=list(PARENT_FIELDS))
        self._strctor_events_before=deepcopy(self._strctor_state['allocator_events_ref'])
        self._strctor_descriptor=self._reg(cpu,0);self._strctor_descriptor_before=bytes(cpu.mem_read(self._strctor_descriptor,40))
        self._strctor_object=self._u(cpu,self._strctor_descriptor+8);self._strctor_source=self._u(cpu,self._strctor_descriptor+16)
        source=bytearray()
        while len(source)<4096:
            b=bytes(cpu.mem_read(self._strctor_source+len(source),1));source.extend(b)
            if b==b'\0':break
        assert source[-1]==0;self._strctor_source_bytes=bytes(source)
        self._strctor_object_before=bytes(cpu.mem_read(self._strctor_object,32))
        self._strctor_sp=cpu.reg_read(arm.UC_ARM64_REG_SP);self._strctor_saved=[self._reg(cpu,n) for n in range(19,30)]
        self._strctor_call=dict(call_index=1,callsite_offset=hex(VM_CALL),VM_cursor_offset='0x109de8',
            wrapper_offset=hex(WRAPPER),target_offset=hex(TARGET),descriptor_address=hex(self._strctor_descriptor),
            descriptor_before_hex=self._strctor_descriptor_before.hex(),object_address=hex(self._strctor_object),
            object_before_hex=self._strctor_object_before.hex(),source_address=hex(self._strctor_source),
            source_length=len(source)-1,source_including_NUL_sha256=raw_hash(bytes(source)))
        self._locked_active=False;self._locked_done=False;self._strctor_active=True
        self._strctor_track(cpu,pc)

    def native_runner(self,*args,**kwargs):
        assert kwargs.get('real_malloc') is True and not kwargs.get('malloc_handler')
        old=kwargs['memory_write_observer']
        def write(cpu,address,size):
            if self._strctor_active and not self._strctor_returned:
                pc=cpu.reg_read(arm.UC_ARM64_REG_PC)-self.image
                if pc==0x347F60:
                    assert address==self._strctor_pointer and size==len(self._strctor_source_bytes)
                    raw=bytes(cpu.mem_read(address,size));assert raw==self._strctor_source_bytes
                    self._strctor_copy_effects.append(dict(index=self._strctor_count,PC_offset='0x347f60',
                        target=hex(address),width=size,payload_including_NUL_sha256=raw_hash(raw),
                        observer_timing='after inherited host write',native_Bionic_memcpy_executed=False))
                if self._strctor_object<=address<self._strctor_object+24:
                    reg={0x248360:8,0x24837C:8,0x248388:0}[pc]
                    assert (pc,address,size) in ((0x248360,self._strctor_object,8),(0x24837C,self._strctor_object+8,4),
                        (0x24837C,self._strctor_object+12,4),(0x248388,self._strctor_object+16,8))
                    if address==self._strctor_object+12:reg=0
                    self._strctor_stores.append(dict(index=self._strctor_count,native_pc=hex(pc),address=hex(address),
                        size=size,value=hex(self._reg(cpu,reg)&((1<<(size*8))-1)),source_register=('w' if size==4 else 'x')+str(reg)))
                if self._strctor_descriptor<=address<self._strctor_descriptor+40:raise AssertionError('tail wrapper wrote descriptor')
            if old:old(cpu,address,size)
        kwargs['memory_write_observer']=write
        return super().native_runner(*args,**kwargs)

    def _strctor_observe_call(self,cpu,pc):
        off=pc-self.image
        if WRAPPER<=off<WRAPPER+16:self._strctor_path.append(hex(off))
        if off==TARGET:
            assert self._reg(cpu,0)==self._strctor_object and self._reg(cpu,1)==self._strctor_source
            assert self._reg(cpu,30)==self.image+VM_RESUME and cpu.reg_read(arm.UC_ARM64_REG_SP)==self._strctor_sp
            self._strctor_call.update(target_entry_index=self._strctor_count,
                dynamic_target_arguments={'x0':hex(self._strctor_object),'x1':hex(self._strctor_source)})
        if off==0x347F40:
            assert self._reg(cpu,0)==self._strctor_source
            self._strctor_services.append(dict(kind='inherited_strlen',index=self._strctor_count,
                PC_offset=hex(off),source=hex(self._strctor_source),result=len(self._strctor_source_bytes)-1))
        if off==0x347FD0:
            assert self._reg(cpu,0)==len(self._strctor_source_bytes)
            self._strctor_services.append(dict(kind='actual_Bionic_malloc_route',index=self._strctor_count,
                PC_offset=hex(off),request=self._reg(cpu,0)))
        if pc==LIBC_BASE+MALLOC:
            self._strctor_call['Bionic_malloc_entry']=dict(index=self._strctor_count,libc_offset=hex(MALLOC),request=self._reg(cpu,0))
        if off==0x248388:
            self._strctor_pointer=self._reg(cpu,0);assert self._strctor_pointer
            self._strctor_call['allocation_return']=dict(index=self._strctor_count,pointer=hex(self._strctor_pointer))
        if off==0x347F60:
            args=[self._reg(cpu,n) for n in range(3)]
            assert args==[self._strctor_pointer,self._strctor_source,len(self._strctor_source_bytes)]
            self._strctor_services.append(dict(kind='inherited_memcpy',index=self._strctor_count,PC_offset=hex(off),
                target=hex(args[0]),source=hex(args[1]),width=args[2],payload_including_NUL_sha256=raw_hash(self._strctor_source_bytes),
                original_Bionic_body_executed=False))

    def _strctor_return(self,cpu):
        assert self._reg(cpu,0)==self._strctor_pointer and cpu.reg_read(arm.UC_ARM64_REG_SP)==self._strctor_sp
        assert [self._reg(cpu,n) for n in range(19,30)]==self._strctor_saved
        assert self._strctor_path==[hex(a) for a in range(WRAPPER,WRAPPER+16,4)]
        raw=bytes(cpu.mem_read(self._strctor_object,32));length=len(self._strctor_source_bytes)-1
        expected=(self.image+0x34F5F8).to_bytes(8,'little')+(length+1).to_bytes(4,'little')+length.to_bytes(4,'little')+self._strctor_pointer.to_bytes(8,'little')+self._strctor_object_before[24:]
        assert raw==expected and bytes(cpu.mem_read(self._strctor_pointer,length+1))==self._strctor_source_bytes
        assert bytes(cpu.mem_read(self._strctor_source,length+1))==self._strctor_source_bytes
        assert bytes(cpu.mem_read(self._strctor_descriptor,40))==self._strctor_descriptor_before
        assert len(self._strctor_stores)==4 and len(self._strctor_services)==3 and len(self._strctor_copy_effects)==1
        self._strctor_call.update(return_index=self._strctor_count,return_offset=hex(VM_RESUME),returned_x0=hex(self._strctor_pointer),
            object_after_hex=raw.hex(),object_neighbor_bytes_preserved=True,descriptor_unchanged=True,source_unchanged=True,
            payload_including_NUL_sha256=raw_hash(bytes(cpu.mem_read(self._strctor_pointer,length+1))),
            wrapper_path=self._strctor_path,SP_restored=True,callee_saved_restored=True)
        self._strctor_returned=True

    def _strctor_next(self,cpu,pc):
        d=self._reg(cpu,0);raw=bytes(cpu.mem_read(d,48));wrapper=self._reg(cpu,8)
        assert self._strctor_count==771 and self._u(cpu,self._reg(cpu,19))==self.image+0x109E08
        assert wrapper==self.image+NEXT_WRAPPER and int.from_bytes(raw[:8],'little')==self.image+NEXT_TARGET
        assert raw_hash(raw)==EXPECTED['next_descriptor_sha256'] and bytes(cpu.mem_read(pc,4)).hex()=='00013fd6'
        self._strctor_next_call=dict(index=self._strctor_count,callsite_offset=hex(VM_CALL),
            wrapper_offset=hex(wrapper-self.image),target_offset=hex(int.from_bytes(raw[:8],'little')-self.image),
            VM_cursor_offset=hex(self._u(cpu,self._reg(cpu,19))-self.image),descriptor_address=hex(d),
            wrapper_code_hex=bytes(cpu.mem_read(wrapper,32)).hex(),
            static_expected_target_arguments={'x0':hex(int.from_bytes(raw[8:16],'little')),'x1':hex(int.from_bytes(raw[16:24],'little'))},
            descriptor_hex=raw.hex(),descriptor_sha256=raw_hash(raw),VM_call_executed=False,wrapper_executed=False,target_executed=False)
        self._strctor_done=True

    def observe(self,cpu,pc,state):
        self._strctor_state=state
        if not self._strctor_active:return super().observe(cpu,pc,state)
        self._strctor_track(cpu,pc);off=pc-self.image
        if not self._strctor_returned:
            self._strctor_observe_call(cpu,pc)
            if off==VM_RESUME:self._strctor_return(cpu)
        elif off==VM_CALL:self._strctor_next(cpu,pc)
        self._base_observe(cpu,pc,state)
        if self._strctor_done:
            cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,oracle.STOP)

    def finish(self,result,state,proof):
        assert self._strctor_done and self._strctor_returned
        events=result['allocator_events'];assert events[:len(self._strctor_events_before)]==self._strctor_events_before
        assert events[len(self._strctor_events_before):]==[['alloc',33,self._strctor_pointer,'0x248388']]
        for value,key in ((result['explicit_service_counts'],'inherited_service_counts'),(proof['JNI_calls'],'inherited_JNI_calls'),
                (proof['libc_SVC_boundaries'],'inherited_libc_SVC'),(proof['main_image_SVC_boundaries'],'inherited_main_SVC'),
                (self._pid_syscalls,'inherited_syscall_172'),(self._pp_syscalls,'inherited_syscall_173'),
                (self.late_jni_calls,'late_jni'),(self.java_dispatch_calls,'java_dispatch')):
            assert value==self._strctor_old[key],key
        trace=hashlib.sha256()
        for key in self._strctor_trace:trace.update(key.encode()+bytes.fromhex(self._strctor_code[key]))
        return dict(control=self._strctor_old['control'],retained_locked_getter=self._strctor_parent,
            instruction_observations=self._strctor_count,instruction_trace_sha256=trace.hexdigest(),
            observation_sites=self._strctor_trace,observed_code=self._strctor_code,observed_code_sha256=digest(self._strctor_code),
            constructor_callback=self._strctor_call,native_object_stores=self._strctor_stores,services=self._strctor_services,
            copy_provider_effects=self._strctor_copy_effects,
            next_VM_call=self._strctor_next_call,new_allocator_events=result['allocator_events'][len(self._strctor_events_before):],
            allocator_counts=result['actual_allocator_counts'],inherited_service_counts=result['explicit_service_counts'],
            inherited_JNI_calls=proof['JNI_calls'],inherited_libc_SVC=proof['libc_SVC_boundaries'],inherited_main_SVC=proof['main_image_SVC_boundaries'],
            inherited_syscall_172=self._pid_syscalls,inherited_syscall_173=self._pp_syscalls,
            late_jni=self.late_jni_calls,java_dispatch=self.java_dispatch_calls,
            stop_boundary=dict(stop_before=hex(VM_CALL),kind='before_tree_pointer_VM_call',VM_call_executed=False))


def run(path,libc):
    parent=prior_evidence();p=bootstrap.module_prefix();p.digest.verify_images(path,libc)
    code=read_static(path,libc)
    assert {key:row['sha256'] for key,row in code.items()}==CODE_SHA256
    def create(control):
        s=StringConstructorScenario(control);s.path=path;s.continue_to_svc=True;return s
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
    assert row['retained_locked_getter']==dict(case_result_sha256=digest(old),verified_fields=list(PARENT_FIELDS))
    sites=row['observation_sites'];code=row['observed_code'];trace=hashlib.sha256()
    assert len(sites)==row['instruction_observations']==EXPECTED['instruction_observations']==771<MAX_OBSERVATIONS
    assert set(sites)==set(code) and sites[:6]==['main:'+hex(x) for x in (VM_CALL,WRAPPER,WRAPPER+4,WRAPPER+8,WRAPPER+12,TARGET)]
    assert sites[156]=='main:'+hex(VM_RESUME) and sites[-1]=='main:'+hex(VM_CALL)
    assert sites.count('main:'+hex(VM_CALL))==2 and 'main:'+hex(NEXT_WRAPPER) not in sites
    assert sites[24]=='libc:'+hex(MALLOC) and sites.count('libc:'+hex(MALLOC))==1
    for key in sites:
        raw=bytes.fromhex(code[key]);assert len(raw)==4 and raw!=bytes.fromhex('010000d4')
        trace.update(key.encode()+raw)
    assert trace.hexdigest()==row['instruction_trace_sha256']==EXPECTED['instruction_trace_sha256']
    assert digest(code)==row['observed_code_sha256']==EXPECTED['observed_code_sha256']
    for domain,ranges in CODE_RANGES.items():
        for off,size in ranges:
            raw=data['static_code'][domain+':'+hex(off)]['hex']
            for pc in range(off,off+size,4):
                key=domain+':'+hex(pc)
                if key in code:assert code[key]==raw[(pc-off)*2:(pc-off+4)*2]
    call=row['constructor_callback'];base=row['control']['base'];source_hash=EXPECTED['source_including_NUL_sha256']
    assert call['call_index']==1 and call['callsite_offset']==hex(VM_CALL) and call['VM_cursor_offset']=='0x109de8'
    assert call['wrapper_offset']==hex(WRAPPER) and call['target_offset']==hex(TARGET)
    assert call['target_entry_index']==6 and call['return_index']==EXPECTED['return_index']==157
    assert call['return_offset']==hex(VM_RESUME) and call['returned_x0']=='0x136d4020'
    assert call['descriptor_address']==old['next_VM_call']['descriptor_address']=='0x7004ccc0'
    assert call['descriptor_before_hex']==old['next_VM_call']['descriptor_hex']
    assert call['object_address']=='0x7004d1d8' and call['source_address']=='0x126a12f0'
    assert call['source_length']==EXPECTED['source_length']==32
    assert call['source_including_NUL_sha256']==call['payload_including_NUL_sha256']==source_hash
    assert call['dynamic_target_arguments']=={'x0':'0x7004d1d8','x1':'0x126a12f0'}
    assert call['Bionic_malloc_entry']==dict(index=25,libc_offset=hex(MALLOC),request=33)
    assert call['allocation_return']==dict(index=148,pointer='0x136d4020')
    before=bytes.fromhex(call['object_before_hex']);after=bytes.fromhex(call['object_after_hex'])
    assert len(before)==len(after)==32
    assert after==(base+0x34F5F8).to_bytes(8,'little')+(33).to_bytes(4,'little')+(32).to_bytes(4,'little')+(0x136D4020).to_bytes(8,'little')+before[24:]
    assert call['wrapper_path']==[hex(x) for x in range(WRAPPER,WRAPPER+16,4)]
    for key in ('object_neighbor_bytes_preserved','descriptor_unchanged','source_unchanged','SP_restored','callee_saved_restored'):
        assert call[key] is True
    assert row['native_object_stores']==[
        dict(index=13,native_pc='0x248360',address='0x7004d1d8',size=8,value=hex(base+0x34F5F8),source_register='x8'),
        dict(index=21,native_pc='0x24837c',address='0x7004d1e0',size=4,value='0x21',source_register='w8'),
        dict(index=21,native_pc='0x24837c',address='0x7004d1e4',size=4,value='0x20',source_register='w0'),
        dict(index=148,native_pc='0x248388',address='0x7004d1e8',size=8,value='0x136d4020',source_register='x0')]
    assert row['services']==[
        dict(kind='inherited_strlen',index=18,PC_offset='0x347f40',source='0x126a12f0',result=32),
        dict(kind='actual_Bionic_malloc_route',index=24,PC_offset='0x347fd0',request=33),
        dict(kind='inherited_memcpy',index=156,PC_offset='0x347f60',target='0x136d4020',source='0x126a12f0',width=33,
            payload_including_NUL_sha256=source_hash,original_Bionic_body_executed=False)]
    assert row['copy_provider_effects']==[dict(index=156,PC_offset='0x347f60',target='0x136d4020',width=33,
        payload_including_NUL_sha256=source_hash,observer_timing='after inherited host write',native_Bionic_memcpy_executed=False)]
    next_call=row['next_VM_call'];raw=bytes.fromhex(next_call['descriptor_hex'])
    assert len(raw)==48 and raw_hash(raw)==next_call['descriptor_sha256']==EXPECTED['next_descriptor_sha256']
    assert next_call['index']==771 and next_call['callsite_offset']==hex(VM_CALL)
    assert next_call['wrapper_offset']==hex(NEXT_WRAPPER) and next_call['target_offset']==hex(NEXT_TARGET)
    assert next_call['VM_cursor_offset']=='0x109e08' and next_call['descriptor_address']=='0x7004cad8'
    assert next_call['wrapper_code_hex']==data['static_code']['main:'+hex(NEXT_WRAPPER)]['hex']
    assert next_call['static_expected_target_arguments']=={'x0':'0x136e0000','x1':'0x7004d1d8'}
    for key in ('VM_call_executed','wrapper_executed','target_executed'):assert next_call[key] is False
    assert row['new_allocator_events']==[['alloc',33,0x136D4020,'0x248388']]
    counts=deepcopy(old['allocator_counts']);counts['malloc']+=1;assert row['allocator_counts']==counts
    for key in LEDGERS:
        if key!='allocator_counts':assert row[key]==old[key],key
    assert row['stop_boundary']==dict(stop_before=hex(VM_CALL),kind='before_tree_pointer_VM_call',VM_call_executed=False)


def damaged_evidence_rejected(data):
    changes=[(('claims','complete_standalone_signer_verified'),True),(('claims','next_VM_call_executed'),True),
        (('claims','original_Bionic_strlen_and_memcpy_bodies_executed'),True),
        (('claims','original_JNI_acquisition_body_executed'),True),(('claims','real_ART_JVM_execution'),True),
        (('providers','new_providers'),['hidden']),(('source_fingerprints','oracle_sha256'),'0'*64),
        (('case_result','retained_locked_getter','case_result_sha256'),'0'*64),
        (('case_result','instruction_observations'),157),(('case_result','instruction_trace_sha256'),'0'*64),
        (('case_result','observed_code_sha256'),'0'*64),(('case_result','observation_sites',24),'libc:0x0'),
        (('case_result','constructor_callback','returned_x0'),'0x0'),
        (('case_result','constructor_callback','source_length'),31),
        (('case_result','constructor_callback','source_including_NUL_sha256'),'0'*64),
        (('case_result','constructor_callback','payload_including_NUL_sha256'),'0'*64),
        (('case_result','constructor_callback','object_after_hex'),'00'*32),
        (('case_result','constructor_callback','object_neighbor_bytes_preserved'),False),
        (('case_result','constructor_callback','descriptor_unchanged'),False),
        (('case_result','constructor_callback','SP_restored'),False),
        (('case_result','constructor_callback','callee_saved_restored'),False),
        (('case_result','constructor_callback','Bionic_malloc_entry','libc_offset'),'0x0'),
        (('case_result','constructor_callback','allocation_return','pointer'),'0x0'),
        (('case_result','constructor_callback','wrapper_path'),[]),
        (('case_result','native_object_stores',1,'value'),'0x20'),
        (('case_result','native_object_stores',2,'size'),8),
        (('case_result','services',0,'result'),31),(('case_result','services',1,'request'),32),
        (('case_result','services',2,'width'),32),(('case_result','services',2,'original_Bionic_body_executed'),True),
        (('case_result','copy_provider_effects',0,'width'),32),
        (('case_result','copy_provider_effects',0,'native_Bionic_memcpy_executed'),True),
        (('case_result','new_allocator_events'),[]),(('case_result','allocator_counts','malloc'),578),
        (('case_result','next_VM_call','VM_call_executed'),True),
        (('case_result','next_VM_call','VM_cursor_offset'),'0x109de8'),
        (('case_result','next_VM_call','descriptor_sha256'),'0'*64),
        (('case_result','next_VM_call','static_expected_target_arguments','x1'),'0x0'),
        (('case_result','stop_boundary','VM_call_executed'),True),
        (('native_controls',0,'capacity'),32),(('native_controls',2,'allocation_requested'),1)]
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
        raise AssertionError(f'damaged string-constructor evidence accepted: {path}')
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
        if args.replay:assert run(args.elf,args.libc)==data,'fresh string-constructor replay differs'
    print(json.dumps(dict(schema=SCHEMA,damaged_evidence_rejected=rejected,
        instruction_observations=data['case_result']['instruction_observations'],native_controls=len(data['native_controls']),
        original_string_constructor_returned=True,next_VM_call_executed=False,complete_standalone_signer_verified=False)))


if __name__=='__main__':main()
