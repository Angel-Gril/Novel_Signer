"""Verify u32 tree lookup after the preserved source-string constructor."""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as arm

import verify_vm9_native_171_post_defaults_string_constructor_return_dynamic_20261122 as previous
import verify_vm9_request_child_registry_read_fresh_20261015 as controls
import verify_vm9_native_171_tree_pointer_return_dynamic_20261122 as reader_owner

EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_post_defaults_u32_lookup_return_dynamic_20261122.json')
SCHEMA='vm9-native-171-post-defaults-u32-lookup-return-dynamic-20261122-v1'
VM_CALL,VM_RESUME=previous.VM_CALL,previous.VM_RESUME
WRAPPER,TARGET,LOOKUP=0x28874C,0x256A18,0x25C168
NEXT_WRAPPER,NEXT_TARGET=0x2884CC,0x2484B8
LIBC_BASE,LOCK,UNLOCK=0x51000000,0x68CF8,0x68D5C
MAX_OBSERVATIONS=30000
sha256,raw_hash,digest=previous.sha256,previous.raw_hash,previous.digest
PARENT_FIELDS=('instruction_observations','instruction_trace_sha256','observation_sites','observed_code','observed_code_sha256',
    'retained_third_default_constructor','constructor_callback','native_object_stores','services','copy_provider_effects',
    'descriptor_integrity','prior_objects_retention','next_VM_call')
LEDGERS=previous.LEDGERS
EXPECTED={'instruction_observations': 1190, 'instruction_trace_sha256': '6aee5675a5d40adf52ef80fdcb80b1c806227f2abd72958408abf990cdaa7fa4', 'observed_code_sha256': 'c68d07524fd492816357138027cc67e592d895d85b69279199f64a80e81567ba', 'return_index': 526, 'lookup_entry_index': 130, 'lookup_return_index': 407, 'lookup_pointer': '0x0', 'value': '0xa985f', 'release_return_index': 513, 'scope_address': '0x7004b8d0', 'scope_before_hex': '58c760120000000080006e13000000000000000000000000', 'reader_sha256': 'e2ccda0d49b7564351ddea954f1676b78127fa54c725e95cffbaa4283c5dfba4', 'tree_header_sha256': '7d908c43fb44802af8a53092aacc7c6efa937ede4a9d5a20f4f8cb1146cfd3a6', 'native_reads': [{'kind': 'retained_reader_scope', 'index': 419, 'native_pc': '0x1654d0', 'address': '0x7004b8d8', 'size': 8, 'value': '0x136e0080', 'reader_count': 1}], 'native_writes': [{'kind': 'reader_scope', 'index': 20, 'native_pc': '0x256a4c', 'address': '0x7004b8d0', 'size': 8, 'value': '0x1260c758', 'source_register': 'x9'}, {'kind': 'reader_scope', 'index': 20, 'native_pc': '0x256a4c', 'address': '0x7004b8d8', 'size': 8, 'value': '0x136e0080', 'source_register': 'x0'}, {'kind': 'Bionic_mutex', 'index': 60, 'libc_pc': '0x68d3c', 'address': '0x136e0088', 'size': 2, 'before': 0, 'value': 1, 'source_register': 'w8'}, {'kind': 'reader_count', 'index': 75, 'native_pc': '0x32a4c4', 'address': '0x136e0110', 'size': 4, 'before': 0, 'value': 1, 'source_register': 'w8'}, {'kind': 'Bionic_mutex', 'index': 95, 'libc_pc': '0x68dc0', 'address': '0x136e0088', 'size': 2, 'before': 1, 'value': 0, 'source_register': 'w6'}, {'kind': 'reader_flag', 'index': 121, 'native_pc': '0x165500', 'address': '0x136e0114', 'size': 1, 'before': 1, 'value': 1, 'source_register': 'w8'}, {'kind': 'reader_scope', 'index': 126, 'native_pc': '0x256a58', 'address': '0x7004b8e0', 'size': 4, 'value': '0x0', 'source_register': 'w0'}, {'kind': 'reader_scope', 'index': 417, 'native_pc': '0x1654c8', 'address': '0x7004b8d0', 'size': 8, 'value': '0x1260c758', 'source_register': 'x9'}, {'kind': 'Bionic_mutex', 'index': 451, 'libc_pc': '0x68d3c', 'address': '0x136e0088', 'size': 2, 'before': 0, 'value': 1, 'source_register': 'w8'}, {'kind': 'reader_count', 'index': 466, 'native_pc': '0x32a528', 'address': '0x136e0110', 'size': 4, 'before': 1, 'value': 0, 'source_register': 'w9'}, {'kind': 'Bionic_mutex', 'index': 493, 'libc_pc': '0x68dc0', 'address': '0x136e0088', 'size': 2, 'before': 1, 'value': 0, 'source_register': 'w6'}, {'kind': 'descriptor_W32', 'index': 523, 'native_pc': '0x288760', 'address': '0x7004cb48', 'size': 4, 'value': '0xa985f', 'reader_count': 0, 'source_register': 'w0'}], 'mutex_calls': [{'index': 46, 'PLT_offset': '0x347f00', 'address': '0x136e0088', 'operation': 'lock', 'reader_count': 0}, {'index': 82, 'PLT_offset': '0x347f10', 'address': '0x136e0088', 'operation': 'unlock', 'reader_count': 1}, {'index': 437, 'PLT_offset': '0x347f00', 'address': '0x136e0088', 'operation': 'lock', 'reader_count': 1}, {'index': 480, 'PLT_offset': '0x347f10', 'address': '0x136e0088', 'operation': 'unlock', 'reader_count': 0}], 'libc_body_entries': [{'index': 47, 'libc_offset': '0x68cf8', 'address': '0x136e0088'}, {'index': 83, 'libc_offset': '0x68d5c', 'address': '0x136e0088'}, {'index': 438, 'libc_offset': '0x68cf8', 'address': '0x136e0088'}, {'index': 481, 'libc_offset': '0x68d5c', 'address': '0x136e0088'}], 'observed_PLT_entries': [{'index': 46, 'PLT_offset': '0x347f00'}, {'index': 82, 'PLT_offset': '0x347f10'}, {'index': 437, 'PLT_offset': '0x347f00'}, {'index': 480, 'PLT_offset': '0x347f10'}], 'next_cursor': '0x10a1c0', 'next_descriptor_address': '0x7004cdf8', 'next_descriptor_sha256': 'efde9d9115160468693753021f5f62478045d8b47c5e32cee52db04b636cba77', 'next_static_arguments': {'x0': '0x7004d1d8'}}
CODE_RANGES={'main':((WRAPPER,32),(TARGET,152),(LOOKUP,24),(0x24B960,192),
    (0x1654E0,48),(0x1654B4,44),(0x165534,44),(0x32A444,184),(0x32A4FC,104)),
    'libc':((LOCK,100),(UNLOCK,376))}
CODE_RANGES['main']+=((NEXT_WRAPPER,12),(NEXT_TARGET,68))
CODE_SHA256={'main:0x28874c': 'c6d21d8e081469237fd33062bd032d24234b47fb0c9280f3485d8b5db1048e80', 'main:0x256a18': '5d158251a60991f9fc3b19f095d6071fc8d9449fa953b9ac6bbe687a820b1691', 'main:0x25c168': 'cfc39cf02f5f6e6cd9e224b624aea078ef12fe1fa91a023319193e3c72eea2fa', 'main:0x24b960': '9efcdcc2a5b9234277640e3d0a9f11d9f4869a94bcb60fadcfd1b0704fda3769', 'main:0x1654e0': '34f94085a29d38dec0e07caf93d56a1d1f47623208ef12b8e67b014174a649b9', 'main:0x1654b4': 'cd59062eb3b1f31a0f9f4e848d597d8519740509799d06dc9b612ff228c59790', 'main:0x165534': 'cab7113d04751fd956708cc7eee65d0c9206fa6f03a7193299f23121ad50656c', 'main:0x32a444': 'b5413e7e5ba4f47de3223e0010672e33772e1ce4b7bdda097b661ab999abe551', 'main:0x32a4fc': '79feae6c5ad83c7af7cc97416ec389c2a5f549582f42ddae4670c86a70b104ab', 'main:0x2884cc': '82295168e4332fdd8ee754ea9b86ffc5a592a6e6c42c0e1592ea18f55c95c565', 'main:0x2484b8': 'b667b3873efcc43d4ffb0f6edb76176e2e84ec53c43007ca9bdbe82067646854', 'libc:0x68cf8': 'fde4d9dc345cd38b5adc29801f17bf9d852c3410b631f47aac4e0c16a45b2c35', 'libc:0x68d5c': '4db5f25d0e8e07c60fecf044c555fc0620d8dca1a5689a035d40197deb69bd68'}


def prior_evidence():
    data=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(data);return data


def source_fingerprints():
    return dict(u32_lookup_verifier_sha256=sha256(Path(__file__)),
        parent_verifier_sha256=sha256(Path(previous.__file__)),reader_observer_owner_sha256=sha256(Path(reader_owner.__file__)),
        component_fixture_sha256=sha256(Path(controls.__file__)),fixture_tree_owner_sha256=sha256(Path(controls.tree_fixture.__file__)),
        fixture_registry_owner_sha256=sha256(Path(controls.registry.__file__)),
        oracle_sha256=sha256(Path(previous.oracle.__file__)),inherited=previous.source_fingerprints())


def provenance(parent):
    return dict(parent_evidence_sha256=sha256(previous.EVIDENCE),parent_case_sha256=digest(parent['case_result']),
        inherited_input_provenance=parent['input_provenance'],native_snapshot_used_as_python_model_input=False)


def read_static(path,libc):
    rows={}
    for domain,filename in (('main',path),('libc',libc)):
        with filename.open('rb') as stream:
            elf=ELFFile(stream)
            if domain=='libc':
                exports={s.name:(s['st_value'],s['st_size']) for s in elf.get_section_by_name('.dynsym').iter_symbols()
                    if s.name in ('pthread_mutex_lock','pthread_mutex_unlock')}
                assert exports=={'pthread_mutex_lock':(LOCK,100),'pthread_mutex_unlock':(UNLOCK,376)}
            for off,size in CODE_RANGES[domain]:
                segment=next(s for s in elf.iter_segments() if s['p_type']=='PT_LOAD' and s['p_vaddr']<=off
                    and off+size<=s['p_vaddr']+s['p_filesz'])
                stream.seek(segment['p_offset']+off-segment['p_vaddr']);raw=stream.read(size);key=domain+':'+hex(off)
                assert len(raw)==size;rows[key]=dict(size=size,hex=raw.hex(),sha256=raw_hash(raw))
    return rows


def providers():
    return dict(inherited=previous.providers(),new_providers=[],new_import_bindings=[],
        mutex='inherited native routing to original matching Bionic normal mutex bodies',
        component_input='fresh established tree fixtures; no native snapshots supplied as Python model input',
        observed_imports='inherited pthread_mutex_lock/unlock routes only; both original matching Bionic bodies execute',
        component_memory_scope='declared 0xa000-byte guest payload span and explicit 24-byte scope; native stack otherwise excluded',
        maximum_instruction_observations=MAX_OBSERVATIONS)


def claims_for():
    return dict(evidence_label='Sample verified',source_constructor_prefix_revalidated=True,
        original_VM_wrapper_u32_lookup_and_reader_release_returned=True,
        shared_reader_count_and_flag_stores_verified=True,four_original_Bionic_mutex_calls_verified=True,
        descriptor_W32_store_after_reader_release_verified=True,descriptor_upper_W32_and_padding_preserved=True,
        query_and_tree_header_preserved=True,all_four_live_strings_retained=True,
        current_lookup_returned_NULL=EXPECTED.get('lookup_pointer','0x0')=='0x0',
        current_found_W32_load_executed=EXPECTED.get('lookup_pointer','0x0')!='0x0',
        SP_and_callee_saved_restored=True,next_VM_call_executed=False,
        native_snapshot_used_as_python_model_input=False,new_providers_added=False,
        original_JNI_acquisition_body_executed=False,real_ART_JVM_execution=False,
        complete_VM_suffix_return_verified=False,complete_standalone_signer_verified=False,
        ordinary_Cronet_six_headers_verified=False,Android_execution=False,
        physical_PAC_authentication_verified=False,online_acceptance_verified=False)


def control_specs():
    rows=[]
    values={'empty':0xA985F,'found_zero':0,'found_max':0xFFFFFFFF,'found_high_bit':0x80000000,
        'absent_left':0xA985F,'NULL_value':0xA985F,'readers7':0x1234ABCD,'reader_count_value_alias':8,
        'guard_status_value_alias':0,'guard_padding_value_alias':0x1234ABCD,'cross_page_value':0x1234ABCD,
        'packed_value_alias':0xA5A5A5A5}
    for base in controls.tree_fixture.BASES:
        for label,value in values.items():
            found=label not in ('empty','absent_left','NULL_value')
            rows.append(dict(image_base=hex(base),case=label,lookup_pointer_nonzero=found,expected_value=hex(value),
                held_W32_value_read=found,shared_reader_restored_before_output=True,
                output_W32_and_upper_padding_verified=True,four_actual_Bionic_mutex_calls=True,
                declared_guest_payload_and_scope_verified=True,SP_and_callee_saved_restored=True,native_snapshot_input=False))
    return rows


def independent_controls(path,libc):
    rows=[]
    for expected in control_specs():
        base=int(expected['image_base'],16);label=expected['case'];value=int(expected['expected_value'],16)
        pages,kw,readers=controls.fixture(path,base,label);block=kw['argument_block_address'];scope=controls.SP-0x60
        before=controls._read_span(pages,controls.G,0xA000);scope_before=controls._read_span(pages,scope,24)
        watch={(scope,24):None};calls=[];bodies=[];lookups=[];loads=[];releases=[];stores=[];restored=[]
        count=lambda cpu:int.from_bytes(cpu.mem_read(controls.REGISTRY+0x110,4),'little')
        saved={getattr(arm,f'UC_ARM64_REG_X{n}'):0x120000+n for n in range(19,30)}
        def observe(cpu,pc):
            off=pc-base
            if off in (0x347F00,0x347F10):calls.append((off,cpu.reg_read(arm.UC_ARM64_REG_X0)))
            if pc in (LIBC_BASE+LOCK,LIBC_BASE+UNLOCK):bodies.append(pc-LIBC_BASE)
            if off==0x256A68:
                assert count(cpu)==readers+1
                assert bool(cpu.reg_read(arm.UC_ARM64_REG_X0)) is expected['lookup_pointer_nonzero'];lookups.append(True)
            if off==0x256A84:assert count(cpu)==readers;releases.append(True)
            if off==0x288768:
                assert cpu.reg_read(arm.UC_ARM64_REG_SP)==controls.SP
                assert all(cpu.reg_read(r)==v for r,v in saved.items());restored.append(True)
        def read(cpu,address,size):
            if cpu.reg_read(arm.UC_ARM64_REG_PC)==base+0x256A6C:
                assert size==4 and count(cpu)==readers+1
                assert int.from_bytes(cpu.mem_read(address,size),'little')==value;loads.append(True)
        def write(cpu,address,size):
            if cpu.reg_read(arm.UC_ARM64_REG_PC)==base+0x288760:
                assert address==block+24 and size==4 and count(cpu)==readers
                assert cpu.reg_read(arm.UC_ARM64_REG_X0)==value;stores.append(True)
        result,memory,allocations,ledger=previous.oracle.native(path,base,WRAPPER,[block],pages,libc=libc,
            real_singletons=True,real_mutexes=True,thread_id=137,instruction_observer=observe,
            memory_read_observer=read,memory_write_observer=write,observed_memory=watch,
            extra_registers={**saved,arm.UC_ARM64_REG_SP:controls.SP},instruction_limit=50000)
        target=bytearray(before);target[block-controls.G+24:block-controls.G+28]=value.to_bytes(4,'little')
        target[controls.REGISTRY-controls.G+0x114]=1
        assert result==value and memory==target
        assert watch[scope,24]==(base+0x34C758).to_bytes(8,'little')+(controls.REGISTRY+0x80).to_bytes(8,'little')+bytes(4)+scope_before[20:24]
        assert calls==[(off,controls.REGISTRY+0x88) for off in (0x347F00,0x347F10)*2]
        assert bodies==[LOCK,UNLOCK]*2 and ledger==[[name,controls.REGISTRY+0x88] for name in ('pthread_mutex_lock','pthread_mutex_unlock')*2]
        assert allocations==[] and lookups==releases==stores==restored==[True] and len(loads)==int(expected['held_W32_value_read'])
        rows.append(expected)
    return rows


class PostDefaultsU32LookupScenario(previous.PostDefaultsStringConstructorScenario):
    def __init__(self,control):
        super().__init__(control)
        self._u32_active=False;self._u32_done=False;self._u32_returned=False;self._u32_state=None
        self._u32_count=0;self._u32_trace=[];self._u32_code={};self._u32_path=[]
        self._u32_writes=[];self._u32_reads=[];self._u32_mutex_calls=[];self._u32_libc_entries=[]
        self._u32_old=prior_evidence()['case_result'];self._u32_protected_writes=[];self._u32_imports=[]

    def _u32_track(self,cpu,pc):
        self._u32_count+=1;assert self._u32_count<MAX_OBSERVATIONS
        if LIBC_BASE<=pc<LIBC_BASE+0x200000:domain,off='libc',pc-LIBC_BASE
        else:
            assert self.image<=pc<self.image+0x400000
            domain,off='main',pc-self.image
        key=domain+':'+hex(off);self._u32_trace.append(key);self._u32_code[key]=bytes(cpu.mem_read(pc,4)).hex()

    def _u32_retained(self,cpu):
        rows=[]
        for expected in self._u32_prior:
            actual=dict(object_address=expected['object_address'],payload_address=expected['payload_address'],
                object_hex=bytes(cpu.mem_read(int(expected['object_address'],16),24)).hex(),
                payload_hex=bytes(cpu.mem_read(int(expected['payload_address'],16),8)).hex())
            assert actual==expected;rows.append(actual)
        return rows

    def _strctor_next(self,cpu,pc):
        if not self._srcctor_active:return super()._strctor_next(cpu,pc)
        super()._strctor_next(cpu,pc)
        retained=deepcopy(self._srcctor_retention);retained['protected_write_events']=deepcopy(self._srcctor_protected_writes)
        h=hashlib.sha256()
        for key in self._strctor_trace:h.update(key.encode()+bytes.fromhex(self._strctor_code[key]))
        values=(self._strctor_count,h.hexdigest(),self._strctor_trace,self._strctor_code,digest(self._strctor_code),
            self._srcctor_parent,self._strctor_call,self._strctor_stores,self._strctor_services,self._strctor_copy_effects,
            self._srcctor_descriptor_integrity,retained,self._strctor_next_call)
        for value,key in zip(values,PARENT_FIELDS):assert value==self._u32_old[key],key
        self._u32_parent=dict(case_result_sha256=digest(self._u32_old),verified_fields=list(PARENT_FIELDS))
        self._u32_events_before=deepcopy(self._u32_state['allocator_events_ref'])
        assert self._u32_events_before[len(self._strctor_events_before):]==self._u32_old['new_allocator_events']
        self._u32_descriptor=self._reg(cpu,0);self._u32_descriptor_before=bytes(cpu.mem_read(self._u32_descriptor,48))
        self._u32_receiver=self._u(cpu,self._u32_descriptor+8);self._u32_query=self._u(cpu,self._u32_descriptor+16)
        self._u32_query_before=bytes(cpu.mem_read(self._u32_query,32))
        assert self._u32_query_before.hex()==self._u32_old['constructor_callback']['object_after_hex']
        self._u32_query_width=self._u(cpu,self._u32_query+12,4)+1;self._u32_payload=self._u(cpu,self._u32_query+16)
        self._u32_payload_before=bytes(cpu.mem_read(self._u32_payload,self._u32_query_width))
        assert raw_hash(self._u32_payload_before)==self._u32_old['constructor_callback']['payload_including_NUL_sha256']
        self._u32_reader=self._u32_receiver+0x80;self._u32_mutex=self._u32_receiver+0x88
        self._u32_reader_before=bytes(cpu.mem_read(self._u32_reader,0x98));self._u32_readers=self._u(cpu,self._u32_receiver+0x110,4)
        self._u32_header_before=bytes(cpu.mem_read(self._u32_receiver+8,40))
        self._u32_sp=cpu.reg_read(arm.UC_ARM64_REG_SP);self._u32_saved=[self._reg(cpu,n) for n in range(19,30)]
        self._u32_scope=self._u32_sp-0x60;self._u32_scope_before=bytes(cpu.mem_read(self._u32_scope,24))
        self._u32_prior=deepcopy(self._u32_old['prior_objects_retention']['at_next'])
        self._u32_protected_ranges=[(int(row[key],16),width) for row in self._u32_prior for key,width in (('object_address',24),('payload_address',8))]
        self._u32_protected_ranges.extend(((self._u32_query,24),(self._u32_payload,self._u32_query_width)))
        self._u32_retention=dict(object_width=24,payload_width=8,before=self._u32_retained(cpu))
        self._u32_call=dict(call_index=1,callsite_offset=hex(VM_CALL),VM_cursor_offset='0x10a198',
            wrapper_offset=hex(WRAPPER),target_offset=hex(TARGET),descriptor_address=hex(self._u32_descriptor),
            descriptor_before_hex=self._u32_descriptor_before.hex(),receiver_address=hex(self._u32_receiver),
            query_address=hex(self._u32_query),query_before_hex=self._u32_query_before.hex(),query_payload_width=self._u32_query_width,
            query_payload_including_NUL_sha256=raw_hash(self._u32_payload_before),
            tree_header_before_hex=self._u32_header_before.hex(),reader_before_hex=self._u32_reader_before.hex(),
            scope_address=hex(self._u32_scope),scope_before_hex=self._u32_scope_before.hex(),initial_readers=self._u32_readers)
        self._strctor_active=False;self._strctor_done=False;self._srcctor_active=False;self._u32_active=True;self._u32_track(cpu,pc)

    def native_runner(self,*args,**kwargs):
        old_read,old_write=kwargs['memory_read_observer'],kwargs['memory_write_observer']
        def read(cpu,address,size):
            if self._u32_active and not self._u32_returned:
                pc=cpu.reg_read(arm.UC_ARM64_REG_PC)-self.image
                if pc==0x256A6C:
                    assert address==self._u32_lookup_pointer and size==4 and self._u(cpu,self._u32_receiver+0x110,4)==self._u32_readers+1
                    self._u32_reads.append(dict(kind='held_W32_value',index=self._u32_count,native_pc=hex(pc),
                        address=hex(address),size=size,value=hex(self._u(cpu,address)),reader_count=self._u32_readers+1))
                if pc==0x1654D0:
                    assert address==self._u32_scope+8 and size==8 and self._u(cpu,address)==self._u32_reader
                    self._u32_reads.append(dict(kind='retained_reader_scope',index=self._u32_count,native_pc=hex(pc),
                        address=hex(address),size=size,value=hex(self._u(cpu,address)),reader_count=self._u(cpu,self._u32_receiver+0x110,4)))
            if old_read:old_read(cpu,address,size)
        def write(cpu,address,size):
            if self._u32_active:
                if any(address<start+width and start<address+size for start,width in self._u32_protected_ranges):
                    self._u32_protected_writes.append(dict(index=self._u32_count,address=hex(address),size=size,native_pc=hex(cpu.reg_read(arm.UC_ARM64_REG_PC)-self.image)))
                    raise AssertionError('u32 continuation wrote a protected string or payload')
                if not self._u32_returned and address<self._u32_receiver+48 and self._u32_receiver+8<address+size:
                    raise AssertionError('u32 lookup wrote its tree header')
            if self._u32_active and not self._u32_returned:
                pc=cpu.reg_read(arm.UC_ARM64_REG_PC);off=pc-self.image
                if self._u32_scope<=address<self._u32_scope+24:
                    specs={(0x256A4C,self._u32_scope):(8,9),(0x256A4C,self._u32_scope+8):(8,0),
                        (0x256A58,self._u32_scope+16):(4,0),(0x1654C8,self._u32_scope):(8,9)}
                    assert (off,address) in specs and size==specs[off,address][0]
                    reg=specs[off,address][1]
                    self._u32_writes.append(dict(kind='reader_scope',index=self._u32_count,native_pc=hex(off),
                        address=hex(address),size=size,value=hex(self._reg(cpu,reg)&((1<<(size*8))-1)),
                        source_register=('w' if size==4 else 'x')+str(reg)))
                if address==self._u32_receiver+0x110:
                    assert size==4 and off in (0x32A4C4,0x32A528)
                    reg=8 if off==0x32A4C4 else 9
                    self._u32_writes.append(dict(kind='reader_count',index=self._u32_count,native_pc=hex(off),address=hex(address),
                        size=size,before=self._u(cpu,address,4),value=self._reg(cpu,reg)&0xFFFFFFFF,source_register='w'+str(reg)))
                if address==self._u32_receiver+0x114:
                    assert size==1 and off==0x165500 and self._reg(cpu,8)==1
                    self._u32_writes.append(dict(kind='reader_flag',index=self._u32_count,native_pc=hex(off),address=hex(address),
                        size=1,before=self._u(cpu,address,1),value=1,source_register='w8'))
                if address==self._u32_mutex:
                    local=pc-LIBC_BASE;assert size==2 and local in (0x68D3C,0x68DC0)
                    reg=8 if local==0x68D3C else 6
                    self._u32_writes.append(dict(kind='Bionic_mutex',index=self._u32_count,libc_pc=hex(local),address=hex(address),
                        size=2,before=self._u(cpu,address,2),value=self._reg(cpu,reg)&0xFFFF,source_register='w'+str(reg)))
                if self._u32_descriptor<=address<self._u32_descriptor+48:
                    assert off==0x288760 and address==self._u32_descriptor+24 and size==4
                    assert self._reg(cpu,0)==self._u32_value and self._u(cpu,self._u32_receiver+0x110,4)==self._u32_readers
                    self._u32_writes.append(dict(kind='descriptor_W32',index=self._u32_count,native_pc=hex(off),address=hex(address),
                        size=4,value=hex(self._reg(cpu,0)),reader_count=self._u32_readers,source_register='w0'))
            if old_write:old_write(cpu,address,size)
        kwargs.update(memory_read_observer=read,memory_write_observer=write)
        return super().native_runner(*args,**kwargs)

    def _u32_observe_call(self,cpu,pc):
        off=pc-self.image
        if 0x347000<=off<0x348000:self._u32_imports.append(dict(index=self._u32_count,PLT_offset=hex(off)))
        if WRAPPER<=off<WRAPPER+32:self._u32_path.append(hex(off))
        if off==TARGET:
            assert self._reg(cpu,0)==self._u32_receiver and self._reg(cpu,1)==self._u32_query
            assert self._reg(cpu,30)==self.image+0x288760 and cpu.reg_read(arm.UC_ARM64_REG_SP)==self._u32_sp-16
            self._u32_call.update(target_entry_index=self._u32_count,dynamic_target_arguments={'x0':hex(self._u32_receiver),'x1':hex(self._u32_query)})
        if off in (0x347F00,0x347F10):
            assert self._reg(cpu,0)==self._u32_mutex
            self._u32_mutex_calls.append(dict(index=self._u32_count,PLT_offset=hex(off),address=hex(self._u32_mutex),
                operation='lock' if off==0x347F00 else 'unlock',reader_count=self._u(cpu,self._u32_receiver+0x110,4)))
        if pc in (LIBC_BASE+LOCK,LIBC_BASE+UNLOCK):
            self._u32_libc_entries.append(dict(index=self._u32_count,libc_offset=hex(pc-LIBC_BASE),address=hex(self._reg(cpu,0))))
        if off==LOOKUP:
            assert self._reg(cpu,0)==self._u32_receiver+8 and self._reg(cpu,1)==self._u32_query
            assert self._u(cpu,self._u32_receiver+0x110,4)==self._u32_readers+1
            self._u32_call['lookup_entry_index']=self._u32_count
        if off==0x256A68:
            self._u32_lookup_pointer=self._reg(cpu,0)
            self._u32_value=self._u(cpu,self._u32_lookup_pointer,4) if self._u32_lookup_pointer else 0xA985F
            assert self._u(cpu,self._u32_receiver+0x110,4)==self._u32_readers+1
            self._u32_call.update(lookup_return_index=self._u32_count,lookup_pointer=hex(self._u32_lookup_pointer),
                value=hex(self._u32_value),reader_count_at_lookup_return=self._u32_readers+1)
        if off==0x256A84:
            assert self._u(cpu,self._u32_receiver+0x110,4)==self._u32_readers and self._reg(cpu,19)==self._u32_value
            self._u32_call['reader_release_return_index']=self._u32_count

    def _u32_return(self,cpu):
        assert self._reg(cpu,0)==self._u32_value and cpu.reg_read(arm.UC_ARM64_REG_SP)==self._u32_sp
        assert [self._reg(cpu,n) for n in range(19,30)]==self._u32_saved
        assert self._u32_path==[hex(x) for x in range(WRAPPER,WRAPPER+32,4)]
        raw=bytes(cpu.mem_read(self._u32_descriptor,48));expected=bytearray(self._u32_descriptor_before)
        expected[24:28]=self._u32_value.to_bytes(4,'little');assert raw==expected
        reader=bytes(cpu.mem_read(self._u32_reader,0x98));expected_reader=bytearray(self._u32_reader_before);expected_reader[0x94]=1
        assert reader==expected_reader
        assert bytes(cpu.mem_read(self._u32_query,32))==self._u32_query_before
        assert bytes(cpu.mem_read(self._u32_payload,self._u32_query_width))==self._u32_payload_before
        assert bytes(cpu.mem_read(self._u32_receiver+8,40))==self._u32_header_before
        scope=bytes(cpu.mem_read(self._u32_scope,24))
        assert scope==(self.image+0x34C758).to_bytes(8,'little')+self._u32_reader.to_bytes(8,'little')+bytes(4)+self._u32_scope_before[20:24]
        assert len(self._u32_mutex_calls)==len(self._u32_libc_entries)==4
        self._u32_call.update(return_index=self._u32_count,return_offset=hex(VM_RESUME),returned_x0=hex(self._u32_value),
            descriptor_after_hex=raw.hex(),reader_after_hex=reader.hex(),scope_after_hex=scope.hex(),
            query_after_hex=bytes(cpu.mem_read(self._u32_query,32)).hex(),
            tree_header_after_hex=bytes(cpu.mem_read(self._u32_receiver+8,40)).hex(),
            query_payload_after_sha256=raw_hash(bytes(cpu.mem_read(self._u32_payload,self._u32_query_width))),
            wrapper_path=self._u32_path,descriptor_output_and_padding_verified=True,reader_state_and_neighbors_verified=True,
            query_and_tree_header_unchanged=True,scope_padding_preserved=True,SP_restored=True,callee_saved_restored=True)
        self._u32_retention['at_return']=self._u32_retained(cpu)
        self._u32_returned=True

    def _u32_next(self,cpu,pc):
        d=self._reg(cpu,0);raw=bytes(cpu.mem_read(d,48));wrapper=self._reg(cpu,8)
        assert self._u32_count==EXPECTED['instruction_observations'] and hex(d)==EXPECTED['next_descriptor_address']
        assert hex(self._u(cpu,self._reg(cpu,19))-self.image)==EXPECTED['next_cursor']
        assert wrapper==self.image+NEXT_WRAPPER and int.from_bytes(raw[:8],'little')==self.image+NEXT_TARGET
        assert raw_hash(raw)==EXPECTED['next_descriptor_sha256'] and bytes(cpu.mem_read(pc,4)).hex()=='00013fd6'
        self._u32_next_call=dict(index=self._u32_count,callsite_offset=hex(VM_CALL),wrapper_offset=hex(wrapper-self.image),
            target_offset=hex(int.from_bytes(raw[:8],'little')-self.image),VM_cursor_offset=hex(self._u(cpu,self._reg(cpu,19))-self.image),
            descriptor_address=hex(d),descriptor_hex=raw.hex(),descriptor_sha256=raw_hash(raw),
            wrapper_code_hex=bytes(cpu.mem_read(wrapper,12)).hex(),
            static_expected_target_arguments={'x0':hex(int.from_bytes(raw[8:16],'little'))},
            VM_call_executed=False,wrapper_executed=False,target_executed=False)
        assert bytes(cpu.mem_read(self._u32_query,24))==self._u32_query_before[:24]
        assert bytes(cpu.mem_read(self._u32_payload,self._u32_query_width))==self._u32_payload_before
        self._u32_retention.update(at_next=self._u32_retained(cpu),stop_index=self._u32_count,
            query_address=hex(self._u32_query),query_body_width=24,query_body_at_stop_hex=bytes(cpu.mem_read(self._u32_query,24)).hex(),
            query_payload_address=hex(self._u32_payload),query_payload_width=self._u32_query_width,
            query_payload_at_stop_sha256=raw_hash(bytes(cpu.mem_read(self._u32_payload,self._u32_query_width))))
        self._u32_done=True

    def observe(self,cpu,pc,state):
        self._u32_state=state
        if not self._u32_active:return super().observe(cpu,pc,state)
        self._u32_track(cpu,pc);off=pc-self.image
        if not self._u32_returned:
            self._u32_observe_call(cpu,pc)
            if off==VM_RESUME:self._u32_return(cpu)
        elif off==VM_CALL:self._u32_next(cpu,pc)
        self._base_observe(cpu,pc,state)
        if self._u32_done:
            cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,previous.oracle.STOP)

    def finish(self,result,state,proof):
        assert self._u32_done and self._u32_returned and result['allocator_events']==self._u32_events_before
        ledgers=dict(allocator_counts=result['actual_allocator_counts'],inherited_service_counts=result['explicit_service_counts'],
            inherited_JNI_calls=proof['JNI_calls'],inherited_libc_SVC=proof['libc_SVC_boundaries'],inherited_main_SVC=proof['main_image_SVC_boundaries'],
            inherited_syscall_172=self._pid_syscalls,inherited_syscall_173=self._pp_syscalls,late_jni=self.late_jni_calls,java_dispatch=self.java_dispatch_calls)
        for key,value in ledgers.items():assert value==self._u32_old[key],key
        trace=hashlib.sha256()
        for key in self._u32_trace:trace.update(key.encode()+bytes.fromhex(self._u32_code[key]))
        self._u32_retention['protected_write_events']=self._u32_protected_writes
        return dict(control=self._u32_old['control'],retained_source_constructor=self._u32_parent,
            instruction_observations=self._u32_count,instruction_trace_sha256=trace.hexdigest(),observation_sites=self._u32_trace,
            observed_code=self._u32_code,observed_code_sha256=digest(self._u32_code),tree_callback=self._u32_call,
            native_reads=self._u32_reads,native_writes=self._u32_writes,mutex_calls=self._u32_mutex_calls,
            libc_body_entries=self._u32_libc_entries,observed_PLT_entries=self._u32_imports,prior_objects_retention=self._u32_retention,next_VM_call=self._u32_next_call,new_allocator_events=[],**ledgers,
            stop_boundary=dict(stop_before=hex(VM_CALL),kind='before_next_VM_call_after_u32_lookup',VM_call_executed=False))


def run(path,libc):
    parent=prior_evidence();p=previous.bootstrap.module_prefix();p.digest.verify_images(path,libc)
    code=read_static(path,libc);assert {k:v['sha256'] for k,v in code.items()}==CODE_SHA256
    def create(control):
        s=PostDefaultsU32LookupScenario(control);s.path=path;s.continue_to_svc=True;return s
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
            entry=data['static_code'][domain+':'+hex(off)];raw=bytes.fromhex(entry['hex'])
            assert len(raw)==entry['size']==size and raw_hash(raw)==entry['sha256']==CODE_SHA256[domain+':'+hex(off)]
    row=data['case_result'];assert data['case_result_sha256']==digest(row) and row['control']==old['control']
    assert row['retained_source_constructor']==dict(case_result_sha256=digest(old),verified_fields=list(PARENT_FIELDS))
    sites=row['observation_sites'];code=row['observed_code'];h=hashlib.sha256()
    assert len(sites)==row['instruction_observations']==EXPECTED['instruction_observations']<MAX_OBSERVATIONS
    assert set(sites)==set(code) and sites[:7]==['main:'+hex(x) for x in (VM_CALL,WRAPPER,WRAPPER+4,WRAPPER+8,WRAPPER+12,WRAPPER+16,TARGET)]
    assert sites[EXPECTED['return_index']-1]=='main:'+hex(VM_RESUME) and sites[-1]=='main:'+hex(VM_CALL)
    assert sites.count('main:'+hex(VM_CALL))==2 and sites.count('main:'+hex(WRAPPER))==1 and sites.count('main:'+hex(TARGET))==1
    assert 'main:'+hex(NEXT_WRAPPER) not in sites and 'main:'+hex(NEXT_TARGET) not in sites
    assert 'main:0x256a6c' not in sites and sites.count('main:'+hex(LOOKUP))==1
    for key in sites:
        raw=bytes.fromhex(code[key]);assert len(raw)==4 and raw!=bytes.fromhex('010000d4')
        h.update(key.encode()+raw)
    assert h.hexdigest()==row['instruction_trace_sha256']==EXPECTED['instruction_trace_sha256']
    assert digest(code)==row['observed_code_sha256']==EXPECTED['observed_code_sha256']
    for domain,ranges in CODE_RANGES.items():
        for off,size in ranges:
            raw=data['static_code'][domain+':'+hex(off)]['hex']
            for pc in range(off,off+size,4):
                if domain+':'+hex(pc) in code:assert code[domain+':'+hex(pc)]==raw[(pc-off)*2:(pc-off+4)*2]
    call=row['tree_callback'];base=row['control']['base'];value=int(EXPECTED['value'],16)
    assert call['call_index']==1 and call['callsite_offset']==hex(VM_CALL) and call['VM_cursor_offset']=='0x10a198'
    assert call['wrapper_offset']==hex(WRAPPER) and call['target_offset']==hex(TARGET) and call['target_entry_index']==7
    assert call['dynamic_target_arguments']=={'x0':'0x136e0000','x1':'0x7004d1d8'}
    assert call['descriptor_address']==old['next_VM_call']['descriptor_address']=='0x7004cb30'
    assert call['descriptor_before_hex']==old['next_VM_call']['descriptor_hex']
    before=bytes.fromhex(call['descriptor_before_hex']);after=bytearray(before);after[24:28]=value.to_bytes(4,'little')
    assert len(before)==48 and call['descriptor_after_hex']==after.hex() and after[28:32]==before[28:32]
    assert call['receiver_address']=='0x136e0000' and call['query_address']=='0x7004d1d8'
    assert call['query_before_hex']==call['query_after_hex']==old['constructor_callback']['object_after_hex']
    assert call['query_payload_width']==old['constructor_callback']['source_length']+1==33
    assert call['query_payload_including_NUL_sha256']==call['query_payload_after_sha256']==old['constructor_callback']['payload_including_NUL_sha256']
    header=bytes.fromhex(call['tree_header_before_hex']);reader=bytes.fromhex(call['reader_before_hex'])
    assert len(header)==40 and raw_hash(header)==EXPECTED['tree_header_sha256'] and call['tree_header_after_hex']==header.hex()
    assert len(reader)==0x98 and raw_hash(reader)==EXPECTED['reader_sha256'] and call['reader_after_hex']==reader.hex()
    assert call['initial_readers']==int.from_bytes(reader[0x90:0x94],'little')==0 and reader[0x94]==1
    assert call['lookup_entry_index']==EXPECTED['lookup_entry_index'] and call['lookup_return_index']==EXPECTED['lookup_return_index']
    assert call['lookup_pointer']==EXPECTED['lookup_pointer']=='0x0' and call['value']==EXPECTED['value']=='0xa985f'
    assert call['reader_count_at_lookup_return']==1 and call['reader_release_return_index']==EXPECTED['release_return_index']
    assert call['return_index']==EXPECTED['return_index'] and call['return_offset']==hex(VM_RESUME) and call['returned_x0']==hex(value)
    scope=bytes.fromhex(call['scope_before_hex']);assert len(scope)==24 and call['scope_address']==EXPECTED['scope_address']
    assert call['scope_before_hex']==EXPECTED['scope_before_hex']
    assert call['scope_after_hex']==((base+0x34C758).to_bytes(8,'little')+int('136e0080',16).to_bytes(8,'little')+bytes(4)+scope[20:24]).hex()
    assert call['wrapper_path']==[hex(x) for x in range(WRAPPER,WRAPPER+32,4)]
    for key in ('descriptor_output_and_padding_verified','reader_state_and_neighbors_verified','query_and_tree_header_unchanged',
                'scope_padding_preserved','SP_restored','callee_saved_restored'):assert call[key] is True
    assert row['native_reads']==EXPECTED['native_reads'] and row['native_writes']==EXPECTED['native_writes']
    assert row['mutex_calls']==EXPECTED['mutex_calls'] and row['libc_body_entries']==EXPECTED['libc_body_entries']
    assert row['observed_PLT_entries']==EXPECTED['observed_PLT_entries']
    assert row['observed_PLT_entries']==[dict(index=i+1,PLT_offset=key[5:]) for i,key in enumerate(sites) if key.startswith('main:0x347')]
    assert [entry['operation'] for entry in row['mutex_calls']]==['lock','unlock']*2
    assert [entry['libc_offset'] for entry in row['libc_body_entries']]==[hex(LOCK),hex(UNLOCK)]*2
    stores=[x for x in row['native_writes'] if x['kind']=='descriptor_W32'];assert len(stores)==1
    assert stores[0]['address']=='0x7004cb48' and stores[0]['size']==4 and stores[0]['value']==hex(value) and stores[0]['reader_count']==0
    assert call['lookup_entry_index']<call['lookup_return_index']<call['reader_release_return_index']<stores[0]['index']<call['return_index']
    retained=old['prior_objects_retention']['at_next']
    assert row['prior_objects_retention']==dict(object_width=24,payload_width=8,before=retained,at_return=retained,at_next=retained,
        stop_index=EXPECTED['instruction_observations'],query_address='0x7004d1d8',query_body_width=24,
        query_body_at_stop_hex=old['constructor_callback']['object_after_hex'][:48],
        query_payload_address=old['constructor_callback']['allocation_return']['pointer'],query_payload_width=33,
        query_payload_at_stop_sha256=old['constructor_callback']['payload_including_NUL_sha256'],protected_write_events=[])
    next_call=row['next_VM_call'];raw=bytes.fromhex(next_call['descriptor_hex'])
    assert len(raw)==48 and raw_hash(raw)==next_call['descriptor_sha256']==EXPECTED['next_descriptor_sha256']
    assert next_call['index']==EXPECTED['instruction_observations'] and next_call['callsite_offset']==hex(VM_CALL)
    assert next_call['VM_cursor_offset']==EXPECTED['next_cursor'] and next_call['descriptor_address']==EXPECTED['next_descriptor_address']
    assert next_call['wrapper_offset']==hex(NEXT_WRAPPER) and next_call['target_offset']==hex(NEXT_TARGET)
    assert next_call['wrapper_code_hex']==data['static_code']['main:'+hex(NEXT_WRAPPER)]['hex']
    assert next_call['static_expected_target_arguments']==EXPECTED['next_static_arguments']
    for key in ('VM_call_executed','wrapper_executed','target_executed'):assert next_call[key] is False
    assert row['new_allocator_events']==[]
    for key in LEDGERS:assert row[key]==old[key],key
    assert row['stop_boundary']==dict(stop_before=hex(VM_CALL),kind='before_next_VM_call_after_u32_lookup',VM_call_executed=False)


def damaged_evidence_rejected(data):
    changes=[(('claims','complete_standalone_signer_verified'),True),(('claims','next_VM_call_executed'),True),
        (('claims','current_lookup_returned_NULL'),False),(('claims','current_found_W32_load_executed'),True),
        (('claims','descriptor_W32_store_after_reader_release_verified'),False),
        (('claims','original_JNI_acquisition_body_executed'),True),(('claims','real_ART_JVM_execution'),True),
        (('providers','new_providers'),['hidden']),(('providers','new_import_bindings'),['hidden']),
        (('source_fingerprints','reader_observer_owner_sha256'),'0'*64),
        (('case_result','retained_source_constructor','case_result_sha256'),'0'*64),
        (('case_result','instruction_observations'),526),(('case_result','instruction_trace_sha256'),'0'*64),
        (('case_result','observed_code_sha256'),'0'*64),(('case_result','observation_sites',6),'main:0x0'),
        (('case_result','tree_callback','lookup_pointer'),'0x1'),(('case_result','tree_callback','value'),'0x0'),
        (('case_result','tree_callback','reader_count_at_lookup_return'),0),
        (('case_result','tree_callback','reader_release_return_index'),524),
        (('case_result','tree_callback','returned_x0'),'0x0'),
        (('case_result','tree_callback','descriptor_after_hex'),'00'*48),
        (('case_result','tree_callback','query_payload_width'),32),
        (('case_result','tree_callback','query_after_hex'),'00'*32),
        (('case_result','tree_callback','query_payload_after_sha256'),'0'*64),
        (('case_result','tree_callback','tree_header_after_hex'),'00'*40),
        (('case_result','tree_callback','reader_after_hex'),'00'*0x98),
        (('case_result','tree_callback','scope_after_hex'),'00'*24),
        (('case_result','tree_callback','SP_restored'),False),(('case_result','tree_callback','callee_saved_restored'),False),
        (('case_result','native_reads',0,'size'),4),(('case_result','native_reads',0,'reader_count'),0),
        (('case_result','native_writes',6,'value'),'0x1'),
        (('case_result','native_writes',11,'size'),8),(('case_result','native_writes',11,'source_register'),'x0'),
        (('case_result','mutex_calls',0,'reader_count'),1),
        (('case_result','libc_body_entries',0,'libc_offset'),'0x0'),
        (('case_result','observed_PLT_entries'),[]),
        (('case_result','prior_objects_retention','at_return',0,'object_hex'),'00'*24),
        (('case_result','prior_objects_retention','at_next',2,'payload_hex'),'ff'*8),
        (('case_result','prior_objects_retention','query_body_width'),32),
        (('case_result','prior_objects_retention','query_payload_width'),32),
        (('case_result','prior_objects_retention','query_payload_at_stop_sha256'),'0'*64),
        (('case_result','prior_objects_retention','protected_write_events'),['hidden']),
        (('case_result','next_VM_call','VM_call_executed'),True),
        (('case_result','next_VM_call','VM_cursor_offset'),'0x10a198'),
        (('case_result','next_VM_call','static_expected_target_arguments','x0'),'0x0'),
        (('case_result','next_VM_call','descriptor_sha256'),'0'*64),
        (('case_result','new_allocator_events'),[['alloc',1,0,'0x0']]),
        (('case_result','stop_boundary','VM_call_executed'),True),
        (('native_controls',0,'expected_value'),'0x0'),(('native_controls',1,'held_W32_value_read'),False),
        (('native_controls',2,'output_W32_and_upper_padding_verified'),False)]
    for key in LEDGERS:changes.append((('case_result',key),[]))
    for key in CODE_SHA256:changes.append((('static_code',key,'sha256'),'0'*64))
    for path,value in changes:
        bad=deepcopy(data);obj=bad
        for key in path[:-1]:obj=obj[key]
        obj[path[-1]]=value
        if path[0]=='case_result':bad['case_result_sha256']=digest(bad['case_result'])
        try:validate(bad)
        except (AssertionError,KeyError,ValueError,TypeError):continue
        raise AssertionError(f'damaged post-defaults u32 evidence accepted: {path}')
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
        if args.replay:assert run(args.elf,args.libc)==data,'fresh post-defaults u32 lookup replay differs'
    print(json.dumps(dict(schema=SCHEMA,damaged_evidence_rejected=rejected,
        instruction_observations=data['case_result']['instruction_observations'],native_controls=len(data['native_controls']),
        original_u32_lookup_callback_returned=True,next_VM_call_executed=False,complete_standalone_signer_verified=False)))


if __name__=='__main__':main()
