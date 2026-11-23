"""Verify original default StringObject construction after payload destruction."""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as arm

import verify_vm9_native_171_string_destructor_return_dynamic_20261122 as previous
import verify_vm9_native_171_resolve_next_vm_callback_dynamic_20261121 as bootstrap
import verify_vm9_signer_objects as oracle
import verify_vm9_outer_signer_native as allocator_owner
import verify_vm9_request_287474_consumers_fresh_20261013 as controls

EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_default_string_constructor_return_dynamic_20261122.json')
SCHEMA='vm9-native-171-default-string-constructor-return-dynamic-20261122-v1'
VM_CALL,VM_RESUME=previous.VM_CALL,previous.VM_RESUME
WRAPPER,TARGET,EMPTY=0x2884CC,0x2481AC,0x6E168
LIBC_BASE,MALLOC=0x51000000,0x1BB08
MAX_OBSERVATIONS=40000
sha256,raw_hash,digest=previous.sha256,previous.raw_hash,previous.digest
PARENT_FIELDS=('instruction_observations','instruction_trace_sha256','observation_sites','observed_code',
    'observed_code_sha256','retained_tree_lookup','destructor_callback','native_reads','native_stores','free_calls','next_VM_call')
LEDGERS=previous.LEDGERS
EXPECTED={'instruction_observations': 804, 'instruction_trace_sha256': 'dfdadbd9b82b6325a06bb1dd2958d43e8ff72f8bb5840d50ea1c94842fde321d', 'observed_code_sha256': '011f75c2e38e8d633cec41b779d3a0ad7e4029c799f2bfc98886eea75d3164e0', 'return_index': 148, 'malloc_PLT_index': 17, 'malloc_entry_index': 18, 'allocation_return_index': 141, 'allocation_pointer': '0x136d82c0', 'object_before_sha256': 'ff2a20f5911c352afb705c447311a2d9e04e139e10fda5fa312cf0737e03ffc2', 'payload_before_hex': '0000000006060000', 'store_indices': [13, 14, 141, 143], 'initial_descriptor_sha256': '6cc16abd70eefb90dc0ba0d14fb088630873b2c6ad943f7442356735984c35a3', 'next_cursor': '0x109ecc', 'next_descriptor_sha256': 'af83952e7d053239614c55a6c41dc7cb0f3b75dd44dd8f86aeaed332dc2bfedd', 'next_static_arguments': {'x0': '0x7004d130'}}
NEXT_WRAPPER,NEXT_TARGET=WRAPPER,TARGET
CODE_RANGES={'main':((WRAPPER,12),(TARGET,80)),'libc':((MALLOC,32),)}
CODE_SHA256={'main:0x2884cc': '82295168e4332fdd8ee754ea9b86ffc5a592a6e6c42c0e1592ea18f55c95c565', 'main:0x2481ac': '67059ef8f1b623858ffe0c627379fefe2d9bdc4d04f44cfdbdc053cb8a9751fb', 'libc:0x1bb08': '5f183f5bc3ff80cac083022481d5449cfdceaa89cc15ff71781be915fc836b36'}


def prior_evidence():
    data=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(data);return data


def source_fingerprints():
    return dict(default_string_constructor_verifier_sha256=sha256(Path(__file__)),
        parent_verifier_sha256=sha256(Path(previous.__file__)),oracle_sha256=sha256(Path(oracle.__file__)),
        allocator_import_owner_sha256=sha256(Path(allocator_owner.__file__)),component_fixture_sha256=sha256(Path(controls.__file__)),
        inherited=previous.source_fingerprints())


def provenance(parent):
    return dict(parent_evidence_sha256=sha256(previous.EVIDENCE),parent_case_sha256=digest(parent['case_result']),
        inherited_input_provenance=parent['input_provenance'],native_snapshot_used_as_python_model_input=False)


def read_static(path,libc):
    code={};empty=None
    for domain,filename in (('main',path),('libc',libc)):
        with filename.open('rb') as stream:
            elf=ELFFile(stream)
            if domain=='libc':
                exports=[(s['st_value'],s['st_size']) for s in elf.get_section_by_name('.dynsym').iter_symbols() if s.name=='malloc']
                assert exports==[(MALLOC,32)]
            else:
                raw=previous.elf_bytes(elf,stream,EMPTY,8);empty=dict(offset=hex(EMPTY),hex=raw.hex(),sha256=raw_hash(raw))
            for off,size in CODE_RANGES[domain]:
                raw=previous.elf_bytes(elf,stream,off,size);code[domain+':'+hex(off)]=dict(size=size,hex=raw.hex(),sha256=raw_hash(raw))
    return code,empty


def providers():
    return dict(inherited=previous.providers(),new_providers=[],new_import_bindings=[],
        allocation='inherited native import routing to original matching Bionic malloc entry and body',
        component_allocator='explicit synthetic malloc success/failure only in independent controls',
        returned_X0='observed allocation result retained in X0; no independent success-status interpretation',
        maximum_instruction_observations=MAX_OBSERVATIONS)


def claims_for():
    return dict(evidence_label='Sample verified',string_destructor_prefix_revalidated=True,
        original_VM_tail_wrapper_and_default_constructor_returned=True,matching_Bionic_malloc_entry_observed=True,
        eight_byte_allocation_and_one_byte_NUL_store_verified=True,ELF_initial_descriptor_bits_loaded=True,
        object_neighbors_and_descriptor_preserved=True,SP_and_callee_saved_restored=True,
        next_VM_call_executed=False,new_providers_added=False,native_snapshot_used_as_python_model_input=False,
        original_JNI_acquisition_body_executed=False,real_ART_JVM_execution=False,
        complete_VM_suffix_return_verified=False,complete_standalone_signer_verified=False,
        ordinary_Cronet_six_headers_verified=False,Android_execution=False,
        physical_PAC_authentication_verified=False,online_acceptance_verified=False)


def control_specs():
    return [dict(image_base=hex(base),case=label,allocation_requested=8,
        allocation_succeeded=label not in ('allocation_failure','custom_descriptor_failure'),
        descriptor_preserved=label not in ('object_packed_alias','payload_packed_alias'),
        expected_initial_descriptor_hex=((23).to_bytes(4,'little')+(7).to_bytes(4,'little')).hex()
            if label in ('custom_initial_descriptor','custom_descriptor_failure') else '0800000000000000',
        original_wrapper_and_constructor_returned=True,full_guest_memory_and_store_widths_verified=True,
        SP_and_callee_saved_restored=True,allocator='explicit synthetic component provider')
        for base in controls.BASES for label in ('normal','allocation_failure','cross_page_object','object_packed_alias',
            'custom_initial_descriptor','custom_descriptor_failure','payload_object_alias','payload_packed_alias','cross_page_payload')]


def independent_controls(path):
    rows=[]
    for expected in control_specs():
        base=int(expected['image_base'],16);label=expected['case']
        pages,inputs,_=controls.fixture(path,base,'default',label);block=inputs['argument_block_address']
        obj=int.from_bytes(controls._read_span(pages,block+8,8),'little')
        empty=bytes.fromhex(expected['expected_initial_descriptor_hex']);controls._write_span(pages,base+EMPTY,empty)
        before=controls._read_span(pages,oracle.GUEST,0xA000)
        pointer=0 if not expected['allocation_succeeded'] else obj if label=='payload_object_alias' else block if label=='payload_packed_alias' else oracle.GUEST+0x4FFF if label=='cross_page_payload' else oracle.GUEST+0x4000
        requests=[];returned=[];observed=[];writes=[]
        saved={getattr(arm,f'UC_ARM64_REG_X{n}'):0x120000+n for n in range(19,30)}
        def allocate(cpu,size):
            assert bytes(cpu.mem_read(obj,16))==(base+0x34F5F8).to_bytes(8,'little')+empty
            requests.append(size);return pointer
        def observe(cpu,pc):
            off=pc-base;observed.append(off)
            if off==0x2481F8:
                assert cpu.reg_read(arm.UC_ARM64_REG_SP)==oracle.GUEST+0xEF00
                assert all(cpu.reg_read(r)==v for r,v in saved.items());returned.append(True)
        def write(cpu,address,size):
            off=cpu.reg_read(arm.UC_ARM64_REG_PC)-base
            if off in (0x2481CC,0x2481D0,0x2481DC,0x2481E4,0x2481EC):writes.append((off,address,size))
        result,memory,allocations,ledger=oracle.native(path,base,WRAPPER,[block],pages,malloc_handler=allocate,
            extra_registers=saved,instruction_observer=observe,memory_write_observer=write,instruction_limit=1000)
        target=bytearray(before);off=obj-oracle.GUEST
        target[off:off+24]=(base+0x34F5F8).to_bytes(8,'little')+empty+pointer.to_bytes(8,'little')
        if pointer:target[pointer-oracle.GUEST]=0
        else:target[off+8:off+12]=bytes(4)
        assert memory==target and requests==[8] and result==pointer and allocations==ledger==[]
        assert returned==[True] and observed[:4]==[WRAPPER,WRAPPER+4,WRAPPER+8,TARGET]
        assert writes==[(0x2481CC,obj,8),(0x2481D0,obj+8,8),(0x2481DC,obj+16,8),
            (0x2481E4,pointer,1) if pointer else (0x2481EC,obj+8,4)]
        assert (0x2481EC in observed)==(not pointer)
        block_off=block-oracle.GUEST
        assert (memory[block_off:block_off+32]==before[block_off:block_off+32])==expected['descriptor_preserved']
        rows.append(expected)
    return rows


class DefaultStringConstructorScenario(previous.StringDestructorScenario):
    def __init__(self,control):
        super().__init__(control)
        self._defctor_active=False;self._defctor_done=False;self._defctor_returned=False;self._defctor_state=None
        self._defctor_count=0;self._defctor_trace=[];self._defctor_code={};self._defctor_path=[]
        self._defctor_reads=[];self._defctor_stores=[];self._defctor_malloc_calls=[]
        self._defctor_old=prior_evidence()['case_result'];self._defctor_pointer=0

    def _defctor_track(self,cpu,pc):
        self._defctor_count+=1;assert self._defctor_count<MAX_OBSERVATIONS
        if LIBC_BASE<=pc<LIBC_BASE+0x200000:domain,off='libc',pc-LIBC_BASE
        else:
            assert self.image<=pc<self.image+0x400000
            domain,off='main',pc-self.image
        key=domain+':'+hex(off);self._defctor_trace.append(key);self._defctor_code[key]=bytes(cpu.mem_read(pc,4)).hex()

    def _strdtor_next(self,cpu,pc):
        super()._strdtor_next(cpu,pc)
        h=hashlib.sha256()
        for key in self._strdtor_trace:h.update(key.encode()+bytes.fromhex(self._strdtor_code[key]))
        values=(self._strdtor_count,h.hexdigest(),self._strdtor_trace,self._strdtor_code,digest(self._strdtor_code),
            self._strdtor_parent,self._strdtor_call,self._strdtor_reads,self._strdtor_stores,self._strdtor_free_calls,self._strdtor_next_call)
        for value,key in zip(values,PARENT_FIELDS):assert value==self._defctor_old[key],key
        self._defctor_parent=dict(case_result_sha256=digest(self._defctor_old),verified_fields=list(PARENT_FIELDS))
        self._defctor_events_before=deepcopy(self._defctor_state['allocator_events_ref'])
        self._defctor_descriptor=self._reg(cpu,0);self._defctor_descriptor_before=bytes(cpu.mem_read(self._defctor_descriptor,48))
        self._defctor_object=self._u(cpu,self._defctor_descriptor+8)
        self._defctor_object_before=bytes(cpu.mem_read(self._defctor_object,32))
        self._defctor_empty=bytes(cpu.mem_read(self.image+EMPTY,8))
        self._defctor_sp=cpu.reg_read(arm.UC_ARM64_REG_SP);self._defctor_saved=[self._reg(cpu,n) for n in range(19,30)]
        self._defctor_call=dict(call_index=1,callsite_offset=hex(VM_CALL),VM_cursor_offset='0x109ea8',
            wrapper_offset=hex(WRAPPER),target_offset=hex(TARGET),descriptor_address=hex(self._defctor_descriptor),
            descriptor_before_hex=self._defctor_descriptor_before.hex(),object_address=hex(self._defctor_object),
            object_before_hex=self._defctor_object_before.hex(),initial_descriptor_hex=self._defctor_empty.hex())
        self._strdtor_active=False;self._strdtor_done=False;self._defctor_active=True;self._defctor_track(cpu,pc)

    def native_runner(self,*args,**kwargs):
        old_read,old_write=kwargs['memory_read_observer'],kwargs['memory_write_observer']
        def read(cpu,address,size):
            if self._defctor_active and not self._defctor_returned and cpu.reg_read(arm.UC_ARM64_REG_PC)==self.image+0x2481C8:
                assert size==8 and address==self.image+EMPTY
                self._defctor_reads.append(dict(index=self._defctor_count,native_pc='0x2481c8',address=hex(address),
                    size=8,value_hex=bytes(cpu.mem_read(address,size)).hex()))
            if old_read:old_read(cpu,address,size)
        def write(cpu,address,size):
            if self._defctor_active and not self._defctor_returned:
                off=cpu.reg_read(arm.UC_ARM64_REG_PC)-self.image
                if self._defctor_object<=address<self._defctor_object+32 or self._defctor_pointer and self._defctor_pointer<=address<self._defctor_pointer+8:
                    spec={0x2481CC:(self._defctor_object,8,'x9',self._reg(cpu,9)),
                        0x2481D0:(self._defctor_object+8,8,'d0',cpu.reg_read(arm.UC_ARM64_REG_D0)),
                        0x2481DC:(self._defctor_object+16,8,'x0',self._reg(cpu,0)),
                        0x2481E4:(self._defctor_pointer,1,'wzr',0)}
                    assert off in spec and (address,size)==spec[off][:2]
                    _,_,register,value=spec[off]
                    self._defctor_stores.append(dict(index=self._defctor_count,native_pc=hex(off),address=hex(address),size=size,
                        value_hex=value.to_bytes(size,'little').hex(),source_register=register))
                if self._defctor_descriptor<=address<self._defctor_descriptor+48:raise AssertionError('default constructor tail wrapper wrote descriptor')
            if old_write:old_write(cpu,address,size)
        kwargs.update(memory_read_observer=read,memory_write_observer=write)
        return super().native_runner(*args,**kwargs)

    def _defctor_observe_call(self,cpu,pc):
        off=pc-self.image
        if WRAPPER<=off<WRAPPER+12:self._defctor_path.append(hex(off))
        if off==TARGET:
            assert self._reg(cpu,0)==self._defctor_object and self._reg(cpu,30)==self.image+VM_RESUME
            assert cpu.reg_read(arm.UC_ARM64_REG_SP)==self._defctor_sp
            self._defctor_call.update(target_entry_index=self._defctor_count,dynamic_target_arguments={'x0':hex(self._defctor_object)})
        if off==0x347FD0 or pc==LIBC_BASE+MALLOC:
            assert self._reg(cpu,0)==8 and self._reg(cpu,30)==self.image+0x2481DC
            assert cpu.reg_read(arm.UC_ARM64_REG_SP)==self._defctor_sp-32
            entry=dict(index=self._defctor_count,requested_size=8)
            if off==0x347FD0:self._defctor_malloc_calls.append(dict(**entry,PLT_offset='0x347fd0'))
            else:self._defctor_call['Bionic_malloc_entry']=dict(**entry,libc_offset=hex(MALLOC))
        if off==0x2481DC:
            self._defctor_pointer=self._reg(cpu,0);assert self._defctor_pointer
            assert self._reg(cpu,19)==self._defctor_object and cpu.reg_read(arm.UC_ARM64_REG_SP)==self._defctor_sp-32
            self._defctor_payload_before=bytes(cpu.mem_read(self._defctor_pointer,8))
            self._defctor_call['allocation_return']=dict(index=self._defctor_count,pointer=hex(self._defctor_pointer),
                payload_before_hex=self._defctor_payload_before.hex())

    def _defctor_return(self,cpu):
        assert cpu.reg_read(arm.UC_ARM64_REG_SP)==self._defctor_sp
        assert [self._reg(cpu,n) for n in range(19,30)]==self._defctor_saved
        raw=bytes(cpu.mem_read(self._defctor_object,32));payload=bytes(cpu.mem_read(self._defctor_pointer,8))
        assert raw==(self.image+0x34F5F8).to_bytes(8,'little')+self._defctor_empty+self._defctor_pointer.to_bytes(8,'little')+self._defctor_object_before[24:]
        assert payload==b'\0'+self._defctor_payload_before[1:] and self._reg(cpu,0)==self._defctor_pointer
        assert bytes(cpu.mem_read(self._defctor_descriptor,48))==self._defctor_descriptor_before
        assert self._defctor_path==list(map(hex,range(WRAPPER,WRAPPER+12,4)))
        assert len(self._defctor_malloc_calls)==1 and len(self._defctor_reads)==1 and len(self._defctor_stores)==4
        self._defctor_call.update(return_index=self._defctor_count,return_offset=hex(VM_RESUME),raw_returned_x0=hex(self._reg(cpu,0)),
            descriptor_after_hex=bytes(cpu.mem_read(self._defctor_descriptor,48)).hex(),object_after_hex=raw.hex(),payload_after_hex=payload.hex(),
            wrapper_path=self._defctor_path,one_byte_NUL_written=True,remaining_allocation_bytes_preserved=True,
            object_neighbors_preserved=True,descriptor_unchanged=True,SP_restored=True,callee_saved_restored=True)
        self._defctor_returned=True

    def _defctor_next(self,cpu,pc):
        d=self._reg(cpu,0);raw=bytes(cpu.mem_read(d,48));wrapper=self._reg(cpu,8)
        assert self._defctor_count==EXPECTED['instruction_observations']
        assert hex(self._u(cpu,self._reg(cpu,19))-self.image)==EXPECTED['next_cursor']
        assert wrapper==self.image+NEXT_WRAPPER and int.from_bytes(raw[:8],'little')==self.image+NEXT_TARGET
        assert raw_hash(raw)==EXPECTED['next_descriptor_sha256'] and bytes(cpu.mem_read(pc,4)).hex()=='00013fd6'
        self._defctor_next_call=dict(index=self._defctor_count,callsite_offset=hex(VM_CALL),wrapper_offset=hex(wrapper-self.image),
            target_offset=hex(int.from_bytes(raw[:8],'little')-self.image),VM_cursor_offset=hex(self._u(cpu,self._reg(cpu,19))-self.image),
            descriptor_address=hex(d),descriptor_hex=raw.hex(),descriptor_sha256=raw_hash(raw),
            wrapper_code_hex=bytes(cpu.mem_read(wrapper,12)).hex(),
            static_expected_target_arguments={'x0':hex(int.from_bytes(raw[8:16],'little'))},
            VM_call_executed=False,wrapper_executed=False,target_executed=False)
        self._defctor_done=True

    def observe(self,cpu,pc,state):
        self._defctor_state=state
        if not self._defctor_active:return super().observe(cpu,pc,state)
        self._defctor_track(cpu,pc);off=pc-self.image
        if not self._defctor_returned:
            self._defctor_observe_call(cpu,pc)
            if off==VM_RESUME:self._defctor_return(cpu)
        elif off==VM_CALL:self._defctor_next(cpu,pc)
        self._base_observe(cpu,pc,state)
        if self._defctor_done:
            cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,oracle.STOP)

    def finish(self,result,state,proof):
        assert self._defctor_done and self._defctor_returned
        events=result['allocator_events'];assert events[:len(self._defctor_events_before)]==self._defctor_events_before
        assert events[len(self._defctor_events_before):]==[['alloc',8,self._defctor_pointer,'0x2481dc']]
        ledgers=dict(allocator_counts=result['actual_allocator_counts'],inherited_service_counts=result['explicit_service_counts'],
            inherited_JNI_calls=proof['JNI_calls'],inherited_libc_SVC=proof['libc_SVC_boundaries'],inherited_main_SVC=proof['main_image_SVC_boundaries'],
            inherited_syscall_172=self._pid_syscalls,inherited_syscall_173=self._pp_syscalls,late_jni=self.late_jni_calls,java_dispatch=self.java_dispatch_calls)
        for key,value in ledgers.items():
            if key!='allocator_counts':assert value==self._defctor_old[key],key
        h=hashlib.sha256()
        for key in self._defctor_trace:h.update(key.encode()+bytes.fromhex(self._defctor_code[key]))
        return dict(control=self._defctor_old['control'],retained_string_destructor=self._defctor_parent,
            instruction_observations=self._defctor_count,instruction_trace_sha256=h.hexdigest(),observation_sites=self._defctor_trace,
            observed_code=self._defctor_code,observed_code_sha256=digest(self._defctor_code),constructor_callback=self._defctor_call,
            native_reads=self._defctor_reads,native_stores=self._defctor_stores,malloc_calls=self._defctor_malloc_calls,
            next_VM_call=self._defctor_next_call,new_allocator_events=events[len(self._defctor_events_before):],**ledgers,
            stop_boundary=dict(stop_before=hex(VM_CALL),kind='before_second_default_string_constructor_VM_call',VM_call_executed=False))


def run(path,libc):
    assert EXPECTED and CODE_SHA256
    parent=prior_evidence();p=bootstrap.module_prefix();p.digest.verify_images(path,libc)
    code,empty=read_static(path,libc);assert {k:v['sha256'] for k,v in code.items()}==CODE_SHA256
    def create(control):
        s=DefaultStringConstructorScenario(control);s.path=path;s.continue_to_svc=True;return s
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
    assert row['retained_string_destructor']==dict(case_result_sha256=digest(old),verified_fields=list(PARENT_FIELDS))
    sites=row['observation_sites'];code=row['observed_code'];h=hashlib.sha256()
    assert len(sites)==row['instruction_observations']==EXPECTED['instruction_observations']<MAX_OBSERVATIONS
    assert set(sites)==set(code) and sites[:5]==['main:'+hex(x) for x in (VM_CALL,WRAPPER,WRAPPER+4,WRAPPER+8,TARGET)]
    assert sites[EXPECTED['return_index']-1]=='main:'+hex(VM_RESUME) and sites[-1]=='main:'+hex(VM_CALL)
    assert sites.count('main:'+hex(VM_CALL))==2 and sites.count('main:'+hex(WRAPPER))==1
    assert sites.count('main:'+hex(TARGET))==1
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
    assert call['call_index']==1 and call['callsite_offset']==hex(VM_CALL) and call['VM_cursor_offset']=='0x109ea8'
    assert call['wrapper_offset']==hex(WRAPPER) and call['target_offset']==hex(TARGET)
    assert call['target_entry_index']==5 and call['return_index']==EXPECTED['return_index'] and call['return_offset']==hex(VM_RESUME)
    assert call['dynamic_target_arguments']=={'x0':'0x7004d118'} and call['object_address']=='0x7004d118'
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
        dict(index=indices[0],native_pc='0x2481cc',address='0x7004d118',size=8,value_hex=(base+0x34F5F8).to_bytes(8,'little').hex(),source_register='x9'),
        dict(index=indices[1],native_pc='0x2481d0',address='0x7004d120',size=8,value_hex=empty['hex'],source_register='d0'),
        dict(index=indices[2],native_pc='0x2481dc',address='0x7004d128',size=8,value_hex=pointer.to_bytes(8,'little').hex(),source_register='x0'),
        dict(index=indices[3],native_pc='0x2481e4',address=hex(pointer),size=1,value_hex='00',source_register='wzr')]
    next_call=row['next_VM_call'];raw=bytes.fromhex(next_call['descriptor_hex'])
    assert len(raw)==48 and raw_hash(raw)==next_call['descriptor_sha256']==EXPECTED['next_descriptor_sha256']
    assert next_call['index']==EXPECTED['instruction_observations'] and next_call['callsite_offset']==hex(VM_CALL)
    assert next_call['wrapper_offset']==hex(NEXT_WRAPPER) and next_call['target_offset']==hex(NEXT_TARGET)
    assert next_call['VM_cursor_offset']==EXPECTED['next_cursor'] and next_call['descriptor_address']=='0x7004cdf8'
    assert next_call['wrapper_code_hex']==data['static_code']['main:'+hex(NEXT_WRAPPER)]['hex']
    assert next_call['static_expected_target_arguments']==EXPECTED['next_static_arguments']
    for key in ('VM_call_executed','wrapper_executed','target_executed'):assert next_call[key] is False
    assert row['new_allocator_events']==[['alloc',8,pointer,'0x2481dc']]
    counts=deepcopy(old['allocator_counts']);counts['malloc']+=1;assert row['allocator_counts']==counts
    for key in LEDGERS:
        if key!='allocator_counts':assert row[key]==old[key],key
    assert row['stop_boundary']==dict(stop_before=hex(VM_CALL),kind='before_second_default_string_constructor_VM_call',VM_call_executed=False)


def damaged_evidence_rejected(data):
    changes=[(('claims','complete_standalone_signer_verified'),True),(('claims','next_VM_call_executed'),True),
        (('claims','matching_Bionic_malloc_entry_observed'),False),(('claims','original_JNI_acquisition_body_executed'),True),
        (('claims','real_ART_JVM_execution'),True),(('claims','native_snapshot_used_as_python_model_input'),True),
        (('providers','new_providers'),['hidden']),(('providers','new_import_bindings'),['hidden']),
        (('source_fingerprints','allocator_import_owner_sha256'),'0'*64),
        (('static_initial_descriptor','hex'),'00'*8),
        (('case_result','retained_string_destructor','case_result_sha256'),'0'*64),
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
        (('case_result','new_allocator_events'),[]),(('case_result','allocator_counts','malloc'),579),
        (('case_result','next_VM_call','VM_call_executed'),True),
        (('case_result','next_VM_call','VM_cursor_offset'),'0x109ea8'),
        (('case_result','next_VM_call','descriptor_sha256'),'0'*64),
        (('case_result','next_VM_call','static_expected_target_arguments','x0'),'0x0'),
        (('case_result','stop_boundary','VM_call_executed'),True),
        (('native_controls',0,'allocation_requested'),7),(('native_controls',1,'allocation_succeeded'),True),
        (('native_controls',3,'descriptor_preserved'),True),
        (('native_controls',5,'expected_initial_descriptor_hex'),'00'*8)]
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
        raise AssertionError(f'damaged default-string-constructor evidence accepted: {path}')
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
        if args.replay:assert run(args.elf,args.libc)==data,'fresh default-string-constructor replay differs'
    print(json.dumps(dict(schema=SCHEMA,damaged_evidence_rejected=rejected,
        instruction_observations=data['case_result']['instruction_observations'],native_controls=len(data['native_controls']),
        original_default_string_constructor_returned=True,next_VM_call_executed=False,complete_standalone_signer_verified=False)))


if __name__=='__main__':main()
