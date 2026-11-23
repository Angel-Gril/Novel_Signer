"""Verify the native locked X64 getter and stop before the next VM callback."""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as arm

import verify_vm9_native_171_jni_provider_return_dynamic_20261122 as previous
import verify_vm9_second_locked_pointer_fresh_20261015 as controls

EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_locked_pointer_return_dynamic_20261122.json')
SCHEMA='vm9-native-171-locked-pointer-return-dynamic-20261122-v1'
VM_CALL,VM_RESUME=previous.VM_CALL,previous.VM_RESUME
WRAPPER,TARGET,DESTRUCTOR=0x288794,0x282B84,0x15F778
NEXT_WRAPPER,NEXT_TARGET=0x2885D0,0x248344
LIBC_BASE,LOCK,UNLOCK=0x51000000,0x68CF8,0x68D5C
MAX_OBSERVATIONS=20000
EXPECTED_TRACE_SHA256='4e08e3f059b732fc8f7c1dea539fba54bdce658590b0ee3aa1cae5916b1f7b1c'
EXPECTED_CODE_SHA256='e86ae9641ff04bc9e76ad4b6ef565fbd625fcd854ab478a53cc1f32886f6d835'
NEXT_DESCRIPTOR_SHA256='c064ae714f9fbb5bfd7e2e5681d23993b2af0cbdf8ad1230ec7e60e55333a94d'
CODE_RANGES={'main':((WRAPPER,28),(TARGET,112),(DESTRUCTOR,36),(NEXT_WRAPPER,16)),
    'libc':((LOCK,100),(UNLOCK,376))}
CODE_SHA256={
    'main:0x288794':'89dff6609a3af925ec6fb49b533294966a3036bec5a610457b9660cc73af8375',
    'main:0x282b84':'a494cc6decc029d451f5a3bc566ab48b34e1149dec7b8a83d1102c95094747e6',
    'main:0x15f778':'d00d9eae8e4f112a1c8f711d181d5304b84a5bcdeef5f657269b9d55085e01dd',
    'main:0x2885d0':'14d9ed527789cfea4669cc452adab89d302cd67f24dc06b1de12d4ca1b71a7af',
    'libc:0x68cf8':'fde4d9dc345cd38b5adc29801f17bf9d852c3410b631f47aac4e0c16a45b2c35',
    'libc:0x68d5c':'4db5f25d0e8e07c60fecf044c555fc0620d8dca1a5689a035d40197deb69bd68'}
PARENT_FIELDS=('instruction_observations','instruction_trace_sha256','observed_code_sha256',
    'observation_pc_offsets','observed_code','first_pc_offsets','tail_pc_offsets','retained_thread_pointer',
    'JNI_callback','wrapper_descriptor_reads','acquisition_provider','next_VM_call')
LEDGERS=previous.LEDGERS
sha256,raw_hash,digest=previous.sha256,previous.raw_hash,previous.digest


def prior_evidence():
    data=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(data);return data


def source_fingerprints():
    return dict(locked_pointer_verifier_sha256=sha256(Path(__file__)),
        parent_verifier_sha256=sha256(Path(previous.__file__)),
        original_fixture_owner_sha256=sha256(Path(controls.__file__)),inherited=previous.source_fingerprints())


def provenance(parent):
    return dict(parent_evidence_sha256=sha256(previous.EVIDENCE),parent_case_sha256=digest(parent['case_result']),
        inherited_input_provenance=parent['input_provenance'],native_snapshot_used_as_python_model_input=False)


def static_code(path,libc):
    rows={}
    for domain,filename in (('main',path),('libc',libc)):
        with filename.open('rb') as stream:
            elf=ELFFile(stream)
            if domain=='libc':
                actual={s.name:(s['st_value'],s['st_size']) for s in elf.get_section_by_name('.dynsym').iter_symbols()
                    if s.name in ('pthread_mutex_lock','pthread_mutex_unlock')}
                assert actual=={'pthread_mutex_lock':(LOCK,100),'pthread_mutex_unlock':(UNLOCK,376)}
            for off,size in CODE_RANGES[domain]:
                segment=next(s for s in elf.iter_segments() if s['p_type']=='PT_LOAD' and s['p_vaddr']<=off
                    and off+size<=s['p_vaddr']+s['p_filesz'])
                stream.seek(segment['p_offset']+off-segment['p_vaddr']);raw=stream.read(size);key=domain+':'+hex(off)
                assert len(raw)==size and raw_hash(raw)==CODE_SHA256[key],key
                rows[key]=dict(size=size,hex=raw.hex(),sha256=raw_hash(raw))
    return rows


def providers():
    return dict(inherited=previous.providers(),new_providers=[],new_import_bindings=[],
        mutex_routing='inherited PLT routing to original matching Bionic pthread_mutex_lock/unlock bodies',
        JNI='inherited synthetic acquisition/provider prefix; no new JNI call',
        maximum_instruction_observations=MAX_OBSERVATIONS)


def claims_for():
    return dict(evidence_label='Sample verified',JNI_provider_prefix_revalidated=True,
        original_locked_getter_returned=True,matching_Bionic_normal_mutex_bodies_executed=True,
        full_X64_loaded_while_mutex_held=True,retained_scope_owner_used_for_unlock=True,
        X64_descriptor_store_and_padding_verified=True,SP_and_callee_saved_restored=True,
        next_VM_call_executed=False,new_providers_added=False,native_snapshot_used_as_python_model_input=False,
        original_JNI_acquisition_body_executed=False,real_ART_JVM_execution=False,
        complete_VM_suffix_return_verified=False,complete_standalone_signer_verified=False,
        ordinary_Cronet_six_headers_verified=False,Android_execution=False,
        physical_PAC_authentication_verified=False,online_acceptance_verified=False)


def control_specs():
    return [dict(image_base=hex(base),case=label,expected_value=hex(value),
        field_read_while_held=True,retained_owner_used_to_unlock=True,
        descriptor_output_and_padding_verified=True,SP_and_callee_saved_restored=True,
        original_getter_destructor_and_Bionic_mutexes_returned=True,native_snapshot_input=False)
        for base in controls.BASES for label,value in (
            ('normal',0x66554433),('high_pointer',0xFEDCBA9876543210),
            ('field_alias_mutex',0x8877665500000001),('retained_mutex_owner',0x66554433))]


def independent_controls(path,libc):
    rows=[]
    for expected in control_specs():
        base=int(expected['image_base'],16);label=expected['case'];value=int(expected['expected_value'],16)
        pages,kw,receiver,owner=controls.fixture(path,base,label);block=kw['argument_block_address']
        before=controls._read_span(pages,block,32);mutex_before=controls._read_span(pages,owner+8,16)
        watched={(block,32):None,(owner+8,16):None};events=[];body=[];read_value=[];read_owner=[];returned=[]
        saved={getattr(arm,f'UC_ARM64_REG_X{n}'):0x120000+n for n in range(19,30)}
        def observe(cpu,pc):
            if pc in (base+0x347F00,base+0x347F10):events.append((pc-base,cpu.reg_read(arm.UC_ARM64_REG_X0)))
            if pc in (LIBC_BASE+LOCK,LIBC_BASE+UNLOCK):body.append(pc-LIBC_BASE)
            if pc==base+0x2887AC:
                assert cpu.reg_read(arm.UC_ARM64_REG_SP)==controls.SP
                assert all(cpu.reg_read(reg)==x for reg,x in saved.items())
                assert cpu.reg_read(arm.UC_ARM64_REG_X0)==value
                returned.append(True)
        def read(cpu,address,width):
            pc=cpu.reg_read(arm.UC_ARM64_REG_PC)
            if pc==base+0x282BC4:
                assert address==receiver+0x40 and width==8
                assert int.from_bytes(cpu.mem_read(owner+8,2),'little')&3==1
                assert int.from_bytes(cpu.mem_read(address,8),'little')==value
                read_value.append(True)
            if pc==base+0x15F790:
                assert address==controls.SP-0x48 and width==8
                assert int.from_bytes(cpu.mem_read(address,8),'little')==owner
                if label=='retained_mutex_owner':
                    assert int.from_bytes(cpu.mem_read(receiver+0x98,8),'little')==owner+1
                read_owner.append(True)
        actual,_,allocations,ledger=previous.oracle.native(path,base,WRAPPER,[block],pages,libc=libc,
            real_mutexes=True,instruction_observer=observe,memory_read_observer=read,observed_memory=watched,
            extra_registers={**saved,arm.UC_ARM64_REG_SP:controls.SP,arm.UC_ARM64_REG_TPIDR_EL0:controls.TP},instruction_limit=1000)
        result=bytearray(before);result[16:24]=value.to_bytes(8,'little')
        assert actual==value and watched[block,32]==result and watched[owner+8,16]==mutex_before
        assert events==[(0x347F00,owner+8),(0x347F10,owner+8)] and body==[LOCK,UNLOCK]
        assert allocations==[] and ledger==[['pthread_mutex_lock',owner+8],['pthread_mutex_unlock',owner+8]]
        assert read_value==read_owner==returned==[True]
        rows.append(expected)
    return rows


class LockedPointerScenario(previous.JniProviderScenario):
    def __init__(self,control):
        super().__init__(control)
        self._locked_active=False;self._locked_returned=False;self._locked_done=False
        self._locked_count=0;self._locked_trace=[];self._locked_code={};self._locked_state=None
        self._locked_path=[];self._locked_mutex_events=[];self._locked_reads=[];self._locked_stores=[];self._locked_mutex_stores=[]
        self._locked_body_entries=[];self._locked_old=prior_evidence()['case_result']

    def _locked_track(self,cpu,pc):
        self._locked_count+=1;assert self._locked_count<MAX_OBSERVATIONS
        if LIBC_BASE<=pc<LIBC_BASE+0x200000:domain,off='libc',pc-LIBC_BASE
        else:
            assert self.image<=pc<self.image+0x400000
            domain,off='main',pc-self.image
        key=domain+':'+hex(off);self._locked_trace.append(key)
        self._locked_code[key]=bytes(cpu.mem_read(pc,4)).hex()

    def _jni_next(self,cpu,pc):
        super()._jni_next(cpu,pc)
        values=(self._jni_count,self._jni_trace.hexdigest(),digest(self._jni_code),self._jni_offsets,self._jni_code,
            self._jni_first,self._jni_tail,self._jni_parent,self._jni_call,self._jni_reads,self._jni_provider,self._jni_next_call)
        for value,key in zip(values,PARENT_FIELDS):assert value==self._locked_old[key],key
        self._locked_parent=dict(case_result_sha256=digest(self._locked_old),verified_fields=list(PARENT_FIELDS))
        self._locked_events_before=deepcopy(self._locked_state['allocator_events_ref'])
        self._locked_descriptor=self._reg(cpu,0);raw=bytes(cpu.mem_read(self._locked_descriptor,32))
        self._locked_receiver=int.from_bytes(raw[8:16],'little')
        self._locked_owner=self._u(cpu,self._locked_receiver+0x98);self._locked_mutex=self._locked_owner+8
        self._locked_value=self._u(cpu,self._locked_receiver+0x40)
        self._locked_mutex_before=bytes(cpu.mem_read(self._locked_mutex,16))
        assert self._locked_mutex_before[:2]==bytes(2)
        self._locked_sp=cpu.reg_read(arm.UC_ARM64_REG_SP)
        self._locked_saved=[self._reg(cpu,n) for n in range(19,30)]
        self._locked_scope=self._locked_sp-0x50
        self._locked_scope_before=bytes(cpu.mem_read(self._locked_scope,24))
        self._locked_call=dict(callsite_offset=hex(VM_CALL),call_index=1,VM_cursor_offset='0x109c44',
            wrapper_offset=hex(WRAPPER),target_offset=hex(TARGET),descriptor_address=hex(self._locked_descriptor),
            descriptor_before_hex=raw.hex(),descriptor_before_sha256=raw_hash(raw),
            receiver_address=hex(self._locked_receiver),owner_address=hex(self._locked_owner),
            mutex_address=hex(self._locked_mutex),scope_address=hex(self._locked_scope),value=hex(self._locked_value),
            mutex_before_hex=self._locked_mutex_before.hex(),scope_before_hex=self._locked_scope_before.hex())
        self._jni_active=False;self._jni_done=False;self._locked_active=True
        self._locked_track(cpu,pc)

    def native_runner(self,*args,**kwargs):
        old_read,old_write=kwargs['memory_read_observer'],kwargs['memory_write_observer']
        def read(cpu,address,size):
            if self._locked_active and cpu.reg_read(arm.UC_ARM64_REG_PC)==self.image+0x282BC4:
                assert address==self._locked_receiver+0x40 and size==8
                assert self._u(cpu,self._locked_mutex,2)==1 and self._u(cpu,address)==self._locked_value
                self._locked_reads.append(dict(kind='held_X64_value_read',index=self._locked_count,
                    native_pc='0x282bc4',address=hex(address),size=size,value=hex(self._u(cpu,address)),mutex_state=1))
            if self._locked_active and cpu.reg_read(arm.UC_ARM64_REG_PC)==self.image+0x15F790:
                assert address==self._locked_scope+8 and size==8 and self._u(cpu,address)==self._locked_owner
                assert self._u(cpu,self._locked_mutex,2)==1
                self._locked_reads.append(dict(kind='retained_scope_owner_read',index=self._locked_count,
                    native_pc='0x15f790',address=hex(address),size=size,value=hex(self._u(cpu,address)),mutex_state=1))
            if self._locked_active and cpu.reg_read(arm.UC_ARM64_REG_PC)==self.image+0x282BAC:
                assert address==self._locked_receiver+0x98 and size==8 and self._u(cpu,address)==self._locked_owner
                self._locked_reads.append(dict(kind='receiver_owner_read',index=self._locked_count,
                    native_pc='0x282bac',address=hex(address),size=size,value=hex(self._u(cpu,address)),mutex_state=0))
            if old_read:old_read(cpu,address,size)
        def write(cpu,address,size):
            if self._locked_active and self._locked_mutex<=address<self._locked_mutex+16:
                pc=cpu.reg_read(arm.UC_ARM64_REG_PC)-LIBC_BASE
                assert pc in (0x68D3C,0x68DC0) and address==self._locked_mutex and size==2
                reg=8 if pc==0x68D3C else 6;value=self._reg(cpu,reg)&0xFFFF
                assert value==(1 if pc==0x68D3C else 0)
                self._locked_mutex_stores.append(dict(index=self._locked_count,libc_pc=hex(pc),address=hex(address),
                    size=2,before=self._u(cpu,address,2),value=value,source_register='w'+str(reg)))
            if self._locked_active and not self._locked_returned and self._locked_descriptor<=address<self._locked_descriptor+32:
                assert cpu.reg_read(arm.UC_ARM64_REG_PC)==self.image+0x2887A4
                assert address==self._locked_descriptor+16 and size==8 and self._reg(cpu,0)==self._locked_value
                self._locked_stores.append(dict(index=self._locked_count,native_pc='0x2887a4',
                    address=hex(address),size=size,value=hex(self._reg(cpu,0)),source_register='x0'))
            if old_write:old_write(cpu,address,size)
        kwargs.update(memory_read_observer=read,memory_write_observer=write)
        return super().native_runner(*args,**kwargs)

    def _locked_observe_body(self,cpu,pc):
        off=pc-self.image
        if off==TARGET:
            assert self._reg(cpu,0)==self._locked_receiver and self._reg(cpu,30)==self.image+0x2887A4
            assert cpu.reg_read(arm.UC_ARM64_REG_SP)==self._locked_sp-16
            self._locked_call.update(target_entry_index=self._locked_count,
                dynamic_target_arguments={'x0':hex(self._locked_receiver)})
        if off in (0x347F00,0x347F10):
            name='pthread_mutex_lock' if off==0x347F00 else 'pthread_mutex_unlock'
            assert self._reg(cpu,0)==self._locked_mutex
            self._locked_mutex_events.append(dict(name=name,index=self._locked_count,PLT_offset=hex(off),
                address=hex(self._locked_mutex),state_before=self._u(cpu,self._locked_mutex,2)))
        if pc in (LIBC_BASE+LOCK,LIBC_BASE+UNLOCK):
            self._locked_body_entries.append(dict(name='pthread_mutex_lock' if pc==LIBC_BASE+LOCK else 'pthread_mutex_unlock',
                index=self._locked_count,libc_offset=hex(pc-LIBC_BASE),address=hex(self._reg(cpu,0))))
        if off==0x282BBC:
            assert self._reg(cpu,0)==0 and self._u(cpu,self._locked_mutex,2)==1
            self._locked_call['lock_return_verified']=True
        if off==DESTRUCTOR:
            assert self._reg(cpu,0)==self._locked_scope
            assert self._u(cpu,self._locked_scope+8)==self._locked_owner and self._u(cpu,self._locked_scope+16,4)==0
            assert self._u(cpu,self._locked_mutex,2)==1
            self._locked_call['scope_before_destructor_hex']=bytes(cpu.mem_read(self._locked_scope,24)).hex()
        if off==0x282BCC:
            assert self._u(cpu,self._locked_mutex,2)==0 and self._reg(cpu,19)==self._locked_value
            self._locked_call['unlock_return_verified']=True

    def _locked_return(self,cpu):
        assert self._reg(cpu,0)==self._locked_value and cpu.reg_read(arm.UC_ARM64_REG_SP)==self._locked_sp
        assert [self._reg(cpu,n) for n in range(19,30)]==self._locked_saved
        assert self._locked_path==[hex(a) for a in range(WRAPPER,WRAPPER+28,4)]
        raw=bytes(cpu.mem_read(self._locked_descriptor,32));expected=bytearray.fromhex(self._locked_call['descriptor_before_hex'])
        expected[16:24]=self._locked_value.to_bytes(8,'little');assert raw==expected
        assert bytes(cpu.mem_read(self._locked_mutex,16))==self._locked_mutex_before
        assert self._u(cpu,self._locked_receiver+0x98)==self._locked_owner
        assert len(self._locked_reads)==3 and len(self._locked_stores)==1
        assert len(self._locked_mutex_events)==len(self._locked_body_entries)==2
        assert len(self._locked_mutex_stores)==2
        scope=bytes(cpu.mem_read(self._locked_scope,24))
        assert scope[:8]==(self.image+0x34C778).to_bytes(8,'little')
        assert scope[8:16]==self._locked_owner.to_bytes(8,'little') and scope[16:20]==bytes(4)
        assert scope[20:24]==self._locked_scope_before[20:24]
        self._locked_call.update(return_index=self._locked_count,return_offset=hex(VM_RESUME),
            returned_x0=hex(self._locked_value),wrapper_path=self._locked_path,
            descriptor_after_hex=raw.hex(),descriptor_after_sha256=raw_hash(raw),output_width=8,
            output_and_padding_verified=True,SP_restored=True,callee_saved_restored=True,
            mutex_after_hex=bytes(cpu.mem_read(self._locked_mutex,16)).hex(),caller_SP=hex(self._locked_sp),
            scope_after_destructor_hex=bytes(cpu.mem_read(self._locked_scope,24)).hex())
        self._locked_returned=True

    def _locked_next(self,cpu,pc):
        assert self._locked_count==1804 and self._u(cpu,self._reg(cpu,19))==self.image+0x109DE8
        assert bytes(cpu.mem_read(pc,4)).hex()=='00013fd6'
        assert self._reg(cpu,8)==self.image+NEXT_WRAPPER
        d=self._reg(cpu,0);raw=bytes(cpu.mem_read(d,40))
        assert raw_hash(raw)==NEXT_DESCRIPTOR_SHA256
        assert int.from_bytes(raw[:8],'little')==self.image+NEXT_TARGET
        cursor=self._u(cpu,self._reg(cpu,19))-self.image
        self._locked_next_call=dict(index=self._locked_count,callsite_offset=hex(VM_CALL),
            wrapper_offset=hex(NEXT_WRAPPER),target_offset=hex(NEXT_TARGET),VM_cursor_offset=hex(cursor),
            wrapper_code_hex=bytes(cpu.mem_read(self.image+NEXT_WRAPPER,16)).hex(),
            descriptor_address=hex(d),descriptor_hex=raw.hex(),descriptor_sha256=raw_hash(raw),
            static_expected_target_arguments={'x0':hex(int.from_bytes(raw[8:16],'little')),'x1':hex(int.from_bytes(raw[16:24],'little'))},
            VM_call_executed=False,wrapper_executed=False,target_executed=False)
        self._locked_done=True

    def observe(self,cpu,pc,state):
        self._locked_state=state
        if not self._locked_active:return super().observe(cpu,pc,state)
        self._locked_track(cpu,pc);off=pc-self.image
        if not self._locked_returned:
            if WRAPPER<=off<WRAPPER+28:self._locked_path.append(hex(off))
            self._locked_observe_body(cpu,pc)
            if off==VM_RESUME:self._locked_return(cpu)
        elif off==VM_CALL:self._locked_next(cpu,pc)
        self._base_observe(cpu,pc,state)
        if self._locked_done:
            cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,previous.oracle.STOP)

    def finish(self,result,state,proof):
        assert self._locked_done and self._locked_returned
        assert result['allocator_events']==self._locked_events_before
        ledgers=dict(allocator_counts=result['actual_allocator_counts'],inherited_service_counts=result['explicit_service_counts'],
            inherited_JNI_calls=proof['JNI_calls'],inherited_libc_SVC=proof['libc_SVC_boundaries'],
            inherited_main_SVC=proof['main_image_SVC_boundaries'],inherited_syscall_172=self._pid_syscalls,
            inherited_syscall_173=self._pp_syscalls,late_jni=self.late_jni_calls,java_dispatch=self.java_dispatch_calls)
        for key,value in ledgers.items():assert value==self._locked_old[key],key
        trace=hashlib.sha256()
        for key in self._locked_trace:trace.update(key.encode()+bytes.fromhex(self._locked_code[key]))
        return dict(control=self._locked_old['control'],retained_JNI_provider=self._locked_parent,
            instruction_observations=self._locked_count,instruction_trace_sha256=trace.hexdigest(),
            observation_sites=self._locked_trace,observed_code=self._locked_code,observed_code_sha256=digest(self._locked_code),
            locked_callback=self._locked_call,mutex_calls=self._locked_mutex_events,libc_body_entries=self._locked_body_entries,
            native_reads=self._locked_reads,descriptor_stores=self._locked_stores,next_VM_call=self._locked_next_call,
            mutex_stores=self._locked_mutex_stores,
            new_allocator_events=[],**ledgers,stop_boundary=dict(stop_before=hex(VM_CALL),
                kind='before_string_constructor_VM_call',VM_call_executed=False))


def run(path,libc):
    parent=prior_evidence();p=previous.bootstrap.module_prefix();p.digest.verify_images(path,libc)
    code=static_code(path,libc)
    def create(control):
        s=LockedPointerScenario(control);s.path=path;s.continue_to_svc=True;return s
    rows=p.digest.context.replay(path,libc,case_controls=[p.CONTROL],_extension_factory=create,
        _request_profile=p.digest.previous.previous.name.previous.previous.PROFILE['name'],
        _handler_read_profile=p.digest.context.NULL_PAYLOAD_READ_PROFILE['name'])
    assert len(rows)==1
    return dict(schema=SCHEMA,claims=claims_for(),providers=providers(),source_fingerprints=source_fingerprints(),
        input_provenance=provenance(parent),static_code=code,native_controls=independent_controls(path,libc),
        case_result=rows[0],case_result_sha256=digest(rows[0]))


def validate(data):
    parent=prior_evidence();old=parent['case_result']
    assert data['schema']==SCHEMA and data['claims']==claims_for() and data['providers']==providers()
    assert data['source_fingerprints']==source_fingerprints() and data['input_provenance']==provenance(parent)
    assert data['native_controls']==control_specs() and set(data['static_code'])==set(CODE_SHA256)
    for domain,ranges in CODE_RANGES.items():
        for off,size in ranges:
            key=domain+':'+hex(off);code=data['static_code'][key];raw=bytes.fromhex(code['hex'])
            assert len(raw)==code['size']==size and raw_hash(raw)==code['sha256']==CODE_SHA256[key]
    row=data['case_result'];assert data['case_result_sha256']==digest(row) and row['control']==old['control']
    assert row['retained_JNI_provider']==dict(case_result_sha256=digest(old),verified_fields=list(PARENT_FIELDS))
    sites=row['observation_sites'];code=row['observed_code']
    assert row['instruction_observations']==len(sites)==1804<MAX_OBSERVATIONS and set(sites)==set(code)
    assert sites[:6]==['main:'+hex(x) for x in (VM_CALL,WRAPPER,WRAPPER+4,WRAPPER+8,WRAPPER+12,TARGET)]
    assert sites[87]=='main:'+hex(VM_RESUME) and sites[-1]=='main:'+hex(VM_CALL)
    assert sites.count('main:'+hex(VM_CALL))==2 and 'main:'+hex(NEXT_WRAPPER) not in sites
    trace=hashlib.sha256()
    for key in sites:
        raw=bytes.fromhex(code[key]);assert len(raw)==4 and raw!=bytes.fromhex('010000d4')
        trace.update(key.encode()+raw)
    assert trace.hexdigest()==row['instruction_trace_sha256']==EXPECTED_TRACE_SHA256
    assert digest(code)==row['observed_code_sha256']==EXPECTED_CODE_SHA256
    for domain,ranges in CODE_RANGES.items():
        for off,size in ranges:
            raw=data['static_code'][domain+':'+hex(off)]['hex']
            for pc in range(off,off+size,4):
                key=domain+':'+hex(pc)
                if key in code:assert code[key]==raw[(pc-off)*2:(pc-off+4)*2]
    assert sites.count('libc:'+hex(LOCK))==sites.count('libc:'+hex(UNLOCK))==1
    call=row['locked_callback'];descriptor=old['next_VM_call'];base=row['control']['base']
    assert call['callsite_offset']==hex(VM_CALL) and call['call_index']==1 and call['return_index']==88
    assert call['VM_cursor_offset']=='0x109c44' and call['return_offset']==hex(VM_RESUME)
    assert call['wrapper_offset']==hex(WRAPPER) and call['target_offset']==hex(TARGET)
    assert call['target_entry_index']==6 and call['dynamic_target_arguments']=={'x0':'0x136f3000'}
    assert call['descriptor_address']==descriptor['descriptor_address']=='0x7004caf8'
    assert call['descriptor_before_hex']==descriptor['descriptor_hex']
    before=bytes.fromhex(call['descriptor_before_hex']);after=bytes.fromhex(call['descriptor_after_hex'])
    assert raw_hash(before)==call['descriptor_before_sha256']==descriptor['descriptor_sha256']
    expected=bytearray(before);expected[16:24]=bytes(8)
    assert after==expected and raw_hash(after)==call['descriptor_after_sha256']
    assert call['receiver_address']=='0x136f3000' and call['owner_address']=='0x136d38d0'
    assert call['mutex_address']=='0x136d38d8' and call['scope_address']=='0x7004b8e0' and call['caller_SP']=='0x7004b930'
    assert call['value']==call['returned_x0']=='0x0' and call['output_width']==8
    assert call['mutex_before_hex']==call['mutex_after_hex']=='00'*16
    assert call['wrapper_path']==[hex(a) for a in range(WRAPPER,WRAPPER+28,4)]
    for key in ('lock_return_verified','unlock_return_verified','output_and_padding_verified','SP_restored','callee_saved_restored'):
        assert call[key] is True
    scope=bytes.fromhex(call['scope_after_destructor_hex']);scope_before=bytes.fromhex(call['scope_before_hex'])
    assert len(scope)==len(scope_before)==24 and scope[:8]==(base+0x34C778).to_bytes(8,'little')
    assert scope[8:16]==int(call['owner_address'],16).to_bytes(8,'little') and scope[16:20]==bytes(4)
    assert scope[20:24]==scope_before[20:24] and call['scope_before_destructor_hex']==scope.hex()
    assert row['mutex_calls']==[
        dict(name='pthread_mutex_lock',index=20,PLT_offset='0x347f00',address='0x136d38d8',state_before=0),
        dict(name='pthread_mutex_unlock',index=52,PLT_offset='0x347f10',address='0x136d38d8',state_before=1)]
    assert row['libc_body_entries']==[
        dict(name='pthread_mutex_lock',index=21,libc_offset=hex(LOCK),address='0x136d38d8'),
        dict(name='pthread_mutex_unlock',index=53,libc_offset=hex(UNLOCK),address='0x136d38d8')]
    assert row['native_reads']==[
        dict(kind='receiver_owner_read',index=16,native_pc='0x282bac',address='0x136f3098',size=8,value='0x136d38d0',mutex_state=0),
        dict(kind='held_X64_value_read',index=42,native_pc='0x282bc4',address='0x136f3040',size=8,value='0x0',mutex_state=1),
        dict(kind='retained_scope_owner_read',index=49,native_pc='0x15f790',address='0x7004b8e8',size=8,value='0x136d38d0',mutex_state=1)]
    assert row['descriptor_stores']==[dict(index=85,native_pc='0x2887a4',address='0x7004cb08',size=8,value='0x0',source_register='x0')]
    assert row['mutex_stores']==[
        dict(index=34,libc_pc='0x68d3c',address='0x136d38d8',size=2,before=0,value=1,source_register='w8'),
        dict(index=65,libc_pc='0x68dc0',address='0x136d38d8',size=2,before=1,value=0,source_register='w6')]
    next_call=row['next_VM_call'];raw=bytes.fromhex(next_call['descriptor_hex'])
    assert len(raw)==40 and raw_hash(raw)==next_call['descriptor_sha256']==NEXT_DESCRIPTOR_SHA256
    assert int.from_bytes(raw[:8],'little')==base+NEXT_TARGET
    assert next_call['index']==1804 and next_call['callsite_offset']==hex(VM_CALL)
    assert next_call['wrapper_offset']==hex(NEXT_WRAPPER) and next_call['target_offset']==hex(NEXT_TARGET)
    assert next_call['VM_cursor_offset']=='0x109de8' and next_call['descriptor_address']=='0x7004ccc0'
    assert next_call['static_expected_target_arguments']=={'x0':'0x7004d1d8','x1':'0x126a12f0'}
    assert next_call['wrapper_code_hex']==data['static_code']['main:'+hex(NEXT_WRAPPER)]['hex']
    for key in ('VM_call_executed','wrapper_executed','target_executed'):assert next_call[key] is False
    for key in LEDGERS:assert row[key]==old[key],key
    assert row['new_allocator_events']==[]
    assert row['stop_boundary']==dict(stop_before=hex(VM_CALL),kind='before_string_constructor_VM_call',VM_call_executed=False)


def damaged_evidence_rejected(data):
    changes=[(('claims','original_locked_getter_returned'),False),
        (('claims','matching_Bionic_normal_mutex_bodies_executed'),False),
        (('claims','original_JNI_acquisition_body_executed'),True),(('claims','real_ART_JVM_execution'),True),
        (('claims','next_VM_call_executed'),True),(('claims','complete_standalone_signer_verified'),True),
        (('providers','new_providers'),['hidden']),(('source_fingerprints','parent_verifier_sha256'),'0'*64),
        (('case_result','retained_JNI_provider','case_result_sha256'),'0'*64),
        (('case_result','instruction_observations'),88),(('case_result','instruction_trace_sha256'),'0'*64),
        (('case_result','observed_code_sha256'),'0'*64),(('case_result','observation_sites',87),'main:0x0'),
        (('case_result','locked_callback','returned_x0'),'0x1'),(('case_result','locked_callback','output_width'),4),
        (('case_result','locked_callback','descriptor_after_hex'),'00'*32),
        (('case_result','locked_callback','scope_after_destructor_hex'),'00'*24),
        (('case_result','locked_callback','wrapper_path'),[]),(('case_result','locked_callback','return_index'),87),
        (('case_result','locked_callback','target_entry_index'),5),(('case_result','locked_callback','SP_restored'),False),
        (('case_result','locked_callback','callee_saved_restored'),False),
        (('case_result','mutex_calls',0,'address'),'0x0'),(('case_result','mutex_calls',1,'state_before'),0),
        (('case_result','libc_body_entries',0,'libc_offset'),'0x0'),
        (('case_result','native_reads',1,'mutex_state'),0),(('case_result','native_reads',1,'size'),4),
        (('case_result','native_reads',2,'value'),'0x0'),(('case_result','descriptor_stores',0,'size'),4),
        (('case_result','mutex_stores',0,'value'),0),(('case_result','mutex_stores',1,'source_register'),'w0'),
        (('case_result','next_VM_call','VM_call_executed'),True),
        (('case_result','next_VM_call','VM_cursor_offset'),'0x109c44'),
        (('case_result','next_VM_call','descriptor_sha256'),'0'*64),
        (('case_result','next_VM_call','static_expected_target_arguments','x1'),'0x0'),
        (('case_result','stop_boundary','VM_call_executed'),True),(('case_result','new_allocator_events'),[['hidden']]),
        (('native_controls',0,'field_read_while_held'),False),(('native_controls',2,'expected_value'),'0x8877665500000000')]
    for key in LEDGERS:changes.append((('case_result',key),[]))
    for key in CODE_SHA256:changes.append((('static_code',key,'sha256'),'0'*64))
    for path,value in changes:
        bad=deepcopy(data);obj=bad
        for key in path[:-1]:obj=obj[key]
        obj[path[-1]]=value
        if path[0]=='case_result':bad['case_result_sha256']=digest(bad['case_result'])
        try:validate(bad)
        except (AssertionError,KeyError,ValueError,TypeError):continue
        raise AssertionError(f'damaged locked-pointer evidence accepted: {path}')
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
        if args.replay:assert run(args.elf,args.libc)==data,'fresh locked-pointer replay differs'
    print(json.dumps(dict(schema=SCHEMA,damaged_evidence_rejected=rejected,
        instruction_observations=data['case_result']['instruction_observations'],native_controls=len(data['native_controls']),
        original_locked_getter_returned=True,next_VM_call_executed=False,complete_standalone_signer_verified=False)))


if __name__=='__main__':main()
