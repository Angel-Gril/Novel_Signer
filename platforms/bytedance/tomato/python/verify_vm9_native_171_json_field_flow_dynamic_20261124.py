"""Verify two native unsigned-word to JSON-number paths without exporting scalar data."""
from __future__ import annotations
import argparse
import importlib
import os
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import struct

import verify_vm9_native_171_json_suffix_window_dynamic_20261124 as previous
from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as arm

VM_CALL,VM_RESUME,LIBC_BASE=previous.VM_CALL,previous.VM_RESUME,previous.LIBC_BASE
MAX_NEW_CALLS,MAX_NEW_INSTRUCTIONS=2,80000
digest,raw_hash,sha256=previous.digest,previous.raw_hash,previous.sha256
import verify_vm9_u32_double_fresh_20261016 as float_fixture
import verify_vm9_second_global_u32_b_fresh_20261016 as word_fixture
EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_json_field_flow_dynamic_20261124.json')
SCHEMA='vm9-native-171-json-field-flow-dynamic-20261124-v1'
FLOAT_PROFILES=('zero','signbit','u32max','high_mixed')


class JsonFieldFlowScenario(previous.JsonSuffixWindow):
    def __init__(self,control):
        super().__init__(control)
        self._jff_active=self._jff_done=False
        self._jff_flows=[]
        self._jff_pending=None
        self._jff_sites,self._jff_code,self._jff_writes=[],{},[]
        self._jff_calls,self._jff_aux=[],[]
        self._jff_stop_reason=None

    def _jff_live(self,state):
        live={}
        for event in state['allocator_events_ref'][len(self._jwx_events):]:
            if event[0]=='alloc':live[event[2]]=event[1]
            elif event[0]=='free':live.pop(event[1],None)
        return live

    def _jff_flow(self,cpu,label,word,source_offset):
        assert self._jff_pending is None or self._jff_pending['public']['node_verified']
        assert len(word)==4
        row=dict(label=label,source_offset=hex(source_offset),source_width=4,
            unsigned_getter_return_verified=True,conversion={},argument={},node={},node_verified=False,
            scalar_values_exported=False,scalar_content_hashes_exported=False)
        self._jff_flows.append(row)
        self._jff_pending=dict(public=row,word=bytes(word),bits=struct.pack('<d',float(int.from_bytes(word,'little'))))

    def _jff_index(self):
        return dict(window='suffix' if self._jff_active else 'parent',
            index=len(self._jff_sites) if self._jff_active else len(self._jwx_sites)+1)

    def _jff_track(self,cpu,pc):
        key=self._fmt_site(pc)
        self._jff_sites.append(key);self._jff_code[key]=bytes(cpu.mem_read(pc,4)).hex()

    def _jff_stop(self,cpu,reason):
        self._jff_done=True;self._jff_stop_reason=reason
        cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,previous.bootstrap().digest.context.outer.oracle.STOP)

    def _jff_call(self,cpu):
        descriptor=self._reg(cpu,0)
        return dict(index=len(self._jff_sites),descriptor_address=hex(descriptor),descriptor_width=48,
            VM_cursor_offset=hex(self._u(cpu,self._postalloc_vmstate)-self.image),
            wrapper_offset=hex(self._reg(cpu,8)-self.image),target_offset=hex(self._u(cpu,descriptor)-self.image),
            SP=hex(cpu.reg_read(arm.UC_ARM64_REG_SP)),callee_saved_sha256=self._idctor_saved_hash(cpu),
            VM_call_executed=False,wrapper_entered=False,target_entered=False,returned=False)

    def _jwx_stop(self,cpu,reason):
        if reason!='uncovered_shared_wrapper_callback_before_BLR':
            return super()._jwx_stop(cpu,reason)
        assert not self._jff_active and len(self._jwx_sites)==4027
        assert cpu.reg_read(arm.UC_ARM64_REG_PC)==self.image+0x288648
        call=self._jwx_current
        assert call['wrapper_offset']=='0x28863c' and call['target_offset']=='0x1c3024'
        assert not call['target_entered'] and not call['returned']
        assert self._jff_flows[0]['node_verified']
        self._jwx_done=True;self._jwx_stop_reason=reason;self._jwx_active=False
        self._jff_events=deepcopy(self._jff_state['allocator_events_ref'])
        self._jff_active=True;self._jff_track(cpu,self.image+0x288648)
        resumed=deepcopy(call);resumed['index']=1;resumed['entry_is_existing_wrapper_BLR']=True
        self._jff_calls.append(resumed);self._jff_current=resumed
        descriptor=int(call['descriptor_address'],16)
        self._jff_getter_before=bytes(cpu.mem_read(descriptor,48))
        self._jff_getter_word=bytes(cpu.mem_read(self.image+0x37A790,4))
        self._jff_getter_events=len(self._jff_state['allocator_events_ref'])
        assert self._reg(cpu,8)==self._u(cpu,descriptor)==self.image+0x1C3024
        previous.bootstrap().digest.Scenario.observe(self,cpu,self.image+0x288648,self._jff_state)
        print('Retained complete parent boundary; admitting original second u32 getter',flush=True)

    def _base_observe(self,cpu,pc,state):
        if self._jff_active and pc==self.image+0x288648:
            assert self._jff_current['target_offset']=='0x1c3024'
            descriptor=int(self._jff_current['descriptor_address'],16)
            assert self._reg(cpu,0)==self._reg(cpu,19)==descriptor
            assert self._reg(cpu,8)==self._u(cpu,descriptor)==self.image+0x1C3024
            previous.bootstrap().digest.Scenario.observe(self,cpu,pc,state)
            return
        return super()._base_observe(cpu,pc,state)

    def native_runner(self,*args,**kwargs):
        old_write=kwargs['memory_write_observer']
        def write(cpu,address,size):
            if self._jff_active:
                self._jff_writes.append(dict(index=len(self._jff_sites),PC=self._fmt_site(cpu.reg_read(arm.UC_ARM64_REG_PC)),
                    address=hex(address),size=size))
            if old_write:old_write(cpu,address,size)
        kwargs['memory_write_observer']=write
        return super().native_runner(*args,**kwargs)

    def _jff_relations(self,cpu,pc,state):
        flow=self._jff_pending
        if flow is None or flow['public']['node_verified']:return
        row=flow['public'];off=pc-self.image
        d0=lambda:cpu.reg_read(arm.UC_ARM64_REG_D0).to_bytes(8,'little')
        if off==0x17079C:
            assert row['conversion']=={}
            source=self._reg(cpu,9)
            assert bytes(cpu.mem_read(source,4))==flow['word']
            row['conversion'].update(source_address=hex(source),load_site=hex(off),
                source_low_u32_equals_getter=True,**self._jff_index())
        elif off==0x1707AC:
            assert row['conversion']['source_low_u32_equals_getter']
            assert d0()==flow['word']+bytes(4)
            row['conversion'].update(convert_site=hex(off),zero_extended_unsigned_operand_verified=True)
        elif off==0x1707B0:
            assert d0()==flow['bits']
            row['conversion']['binary64_equals_exact_unsigned_conversion']=True
        elif off==0x1707F8:
            assert row['conversion']['binary64_equals_exact_unsigned_conversion']
            assert d0()==flow['bits']
            flow['destination']=self._reg(cpu,9)
        elif off==0x1707FC:
            assert bytes(cpu.mem_read(flow['destination'],8))==flow['bits']
            row['conversion'].update(destination_address=hex(flow['destination']),store_site='0x1707f8',
                stored_binary64_equal=True)
        call=self._jff_current if self._jff_active else self._jwx_current
        if pc==self.image+VM_CALL and call['target_offset']=='0x261350':
            # During parent observation the new descriptor has not yet been
            # installed as _jwx_current. Decode the actual incoming block.
            self._jff_number_arguments(cpu,state)
        elif pc==self.image+0x261350:
            assert self._reg(cpu,0)==flow['wrapper'] and self._reg(cpu,1)==flow['key']
            assert d0()==flow['bits']
            row['argument']['actual_X0_X1_D0_equal']=True
        elif pc==self.image+VM_RESUME and call['target_offset']=='0x261350':
            self._jff_number_return(cpu,state)

    def _jff_number_arguments(self,cpu,state):
        flow=self._jff_pending;row=flow['public']
        assert row['conversion']['stored_binary64_equal']
        descriptor=self._reg(cpu,0)
        raw=bytes(cpu.mem_read(descriptor,48))
        assert self._reg(cpu,8)==self.image+0x288854 and self._u(cpu,descriptor)==self.image+0x261350
        wrapper,key=self._u(cpu,descriptor+8),self._u(cpu,descriptor+16)
        assert wrapper==int(self._jwx_typed_output['wrapper_address'],16)
        assert raw[24:32]==flow['bits']
        root=self._u(cpu,wrapper+8);live=self._jff_live(state)
        assert live.get(wrapper,0)>=16 and live.get(root,0)>=64
        assert root==int(self._jwx_typed_output['root_address'],16)
        assert self._u(cpu,root+24,4)==64
        head=self._u(cpu,root+16)
        tail=self._u(cpu,head+8) if head else 0
        if head:assert live.get(head,0)>=64 and tail==head
        flow.update(descriptor=descriptor,before=raw,wrapper=wrapper,key=key,root=root,
            key_bytes=self._bounded_cstring(cpu,key,limit=4096),head=head,tail=tail,
            allocation_index=len(state['allocator_events_ref']),
            prior_node_bytes=bytes(cpu.mem_read(head,64)) if head else None)
        row['argument'].update(descriptor_address=hex(descriptor),wrapper_is_initial_JSON=True,
            binary64_equals_conversion_store=True,key_contents_exported=False,key_content_hash_exported=False,
            **self._jff_index())

    def _jff_number_return(self,cpu,state):
        flow=self._jff_pending;row=flow['public'];root=flow['root']
        expected=bytearray(flow['before']);expected[32]=1
        assert bytes(cpu.mem_read(flow['descriptor'],48))==expected
        assert self._u(cpu,flow['wrapper']+8)==root
        head=self._u(cpu,root+16);live=self._jff_live(state)
        node=self._u(cpu,head+8)
        fresh={event[2]:event[1] for event in state['allocator_events_ref'][flow['allocation_index']:]
            if event[0]=='alloc'}
        assert fresh.get(node,0)>=64
        assert live.get(node,0)>=64 and self._u(cpu,node+24,4)==8
        assert bytes(cpu.mem_read(node+48,8))==flow['bits']
        integer=int.from_bytes(cpu.mem_read(node+40,4),'little',signed=True)
        assert integer==min(int.from_bytes(flow['word'],'little'),0x7FFFFFFF)
        owned_key=self._u(cpu,node+56)
        assert fresh.get(owned_key,0)>=len(flow['key_bytes'])+1
        assert live.get(owned_key,0)>=len(flow['key_bytes'])+1
        assert self._bounded_cstring(cpu,owned_key,limit=4096)==flow['key_bytes']
        assert self._u(cpu,node)==0
        if flow['head']:
            assert head==flow['head'] and self._u(cpu,flow['tail'])==node
            assert self._u(cpu,node+8)==flow['tail']
            prior=bytearray(flow['prior_node_bytes']);prior[:8]=node.to_bytes(8,'little');prior[8:16]=node.to_bytes(8,'little')
            assert bytes(cpu.mem_read(head,64))==prior
        else:
            assert head==node and self._u(cpu,node+8)==node
        row['node'].update(address=hex(node),root_address=hex(root),type_u32=8,
            new_live_node_allocation=True,new_live_key_allocation=True,key_copy_equal=True,
            binary64_equals_getter_conversion=True,signed_int32_saturation_equal=True,
            exact_one_byte_success_store_and_other_descriptor_bytes_preserved=True,
            prior_child_preserved_except_append_links=True,**self._jff_index())
        row['node_verified']=True
        print('Verified complete scalar-to-JSON-node relation:',row['label'],flush=True)

    def _jff_guard(self,cpu,pc):
        word=int.from_bytes(cpu.mem_read(pc,4),'little')
        if word==0xD4000001:
            self._jff_stop(cpu,'new_SVC_before_execution');return True
        if self.image+self._jwx_plt[0]<=pc<self.image+self._jwx_plt[1] and pc-self.image not in previous.ALLOWED_PLT:
            raise previous.UnsafeBoundary('uncovered new-phase PLT entry before host provider')
        target=None
        if word&0x7C000000==0x14000000:
            immediate=word&0x03FFFFFF
            if immediate&(1<<25):immediate-=1<<26
            target=pc+(immediate<<2)
        elif word&0xFFFFFC1F in (0xD61F0000,0xD63F0000,0xD65F0000):
            register=(word>>5)&31;target=0 if register==31 else self._reg(cpu,register)
        if target is not None:
            if not self._jwx_executable(target):
                self._jff_stop(cpu,'uncovered_new_branch_target');return True
            if self.image+self._jwx_plt[0]<=target<self.image+self._jwx_plt[1] and target-self.image not in previous.ALLOWED_PLT:
                self._jff_stop(cpu,'uncovered_new_PLT_before_branch');return True
        return False

    def observe(self,cpu,pc,state):
        if not self._jff_active:
            if self._jwx_active:
                self._jff_state=state
                # Decode the incoming numerical descriptor before the parent
                # changes its current-call record at VM_CALL.
                if pc==self.image+VM_CALL and self._u(cpu,self._reg(cpu,0))==self.image+0x261350:
                    self._jff_number_arguments(cpu,state)
                self._jff_relations(cpu,pc,state)
                getter_return=(pc==self.image+VM_RESUME and self._jwx_current['target_offset']=='0x1c3018')
                result=super().observe(cpu,pc,state)
                if getter_return:self._jff_flow(cpu,'first',self._jwx_global_word,0x37A794)
                return result
            return super().observe(cpu,pc,state)
        self._jff_state=state;self._jff_track(cpu,pc)
        if len(self._jff_sites)>=MAX_NEW_INSTRUCTIONS:self._jff_stop(cpu,'new_instruction_budget');return
        if pc in (LIBC_BASE+0x9833C,LIBC_BASE+0x97F40):
            self._jff_aux.append(dict(index=len(self._jff_sites),kind='gc' if pc==LIBC_BASE+0x9833C else 'flush'))
        call=self._jff_current
        if pc==self.image+VM_CALL:
            assert call['returned'],'nested new VM callback is outside this bounded stage'
            call=self._jff_call(cpu);self._jff_calls.append(call)
            if len(self._jff_calls)>MAX_NEW_CALLS:
                self._jff_stop(cpu,'new_callback_budget_before_next_call');return
            if (call['wrapper_offset'],call['target_offset'])!=('0x288854','0x261350'):
                self._jff_stop(cpu,'uncovered_new_VM_callback');return
            self._jff_current=call
        if self._jff_guard(cpu,pc):return
        if pc==self.image+int(call['wrapper_offset'],16):call.update(VM_call_executed=True,wrapper_entered=True)
        if pc==self.image+int(call['target_offset'],16):call['target_entered']=True
        self._jff_relations(cpu,pc,state)
        if pc==self.image+VM_RESUME:
            assert cpu.reg_read(arm.UC_ARM64_REG_SP)==int(call['SP'],16)
            assert self._idctor_saved_hash(cpu)==call['callee_saved_sha256']
            call.update(returned=True,return_index=len(self._jff_sites),caller_SP_and_callee_saved_restored=True)
            if call['target_offset']=='0x1c3024':
                descriptor=int(call['descriptor_address'],16)
                expected=bytearray(self._jff_getter_before);expected[8:12]=self._jff_getter_word
                assert bytes(cpu.mem_read(descriptor,48))==expected
                assert self._reg(cpu,0)==int.from_bytes(self._jff_getter_word,'little')
                assert bytes(cpu.mem_read(self.image+0x37A790,4))==self._jff_getter_word
                assert len(state['allocator_events_ref'])==self._jff_getter_events
                self._jff_flow(cpu,'second',self._jff_getter_word,0x37A790)
        self._base_observe(cpu,pc,state)
        assert self.late_jni_calls==self._jwx_initial_late and self.java_dispatch_calls==self._jwx_initial_java

    def finish(self,result,state,proof):
        assert self._jff_done and all(row['node_verified'] for row in self._jff_flows)
        delta=result['allocator_events'][len(self._jff_events):]
        prefix,counts=dict(result),deepcopy(result['actual_allocator_counts'])
        for event in delta:counts['malloc' if event[0]=='alloc' else 'free']-=1
        for event in self._jff_aux:counts[event['kind']]-=1
        prefix.update(allocator_events=self._jff_events,actual_allocator_counts=counts)
        old=previous.public_case(super().finish(prefix,state,proof))
        assert old==self._jff_parent['case_result'],'full retained JSON window differs'
        trace=hashlib.sha256()
        for key in self._jff_sites:trace.update(key.encode()+bytes.fromhex(self._jff_code[key]))
        return dict(full_parent_case_equal=True,parent_case_sha256=digest(old),flows=self._jff_flows,
            suffix_instruction_observations=len(self._jff_sites),suffix_trace_sha256=trace.hexdigest(),
            suffix_code_sha256=digest(self._jff_code),suffix_callbacks=self._jff_calls,
            completed_suffix_callbacks=sum(call['returned'] for call in self._jff_calls),
            suffix_stop_reason=self._jff_stop_reason,new_allocator_events=delta,allocator_aux_events=self._jff_aux,
            native_write_observations=len(self._jff_writes),actual_allocator_counts=result['actual_allocator_counts'],
            explicit_service_counts=result['explicit_service_counts'],current_native_values_used_only_for_relations=True,
            native_snapshot_used_as_VM_model_input=False,complete_standalone_signer_verified=False,online_acceptance_verified=False)


def claims():
    return dict(evidence_label='Sample verified',complete_parent_case_equal=True,
        two_unsigned_getter_to_JSON_number_relations=True,
        zero_extension_and_exact_binary64_conversion_observed=True,
        actual_packed_and_FP_argument_and_node_number_equal=True,
        signed_int32_saturation_and_owned_key_and_append_links_verified=True,
        current_native_values_used_only_for_relations=True,
        runtime_values_used_to_initialize_independent_VM=False,
        scalar_values_or_scalar_hashes_exported=False,key_contents_or_key_hashes_exported=False,
        complete_VM_suffix_return_verified=False,complete_standalone_signer_verified=False,
        real_ART_JVM_execution=False,Android_execution=False,online_acceptance_verified=False)


def providers():
    return dict(parent_evidence_sha256=sha256(previous.EVIDENCE),new_providers=[],new_import_bindings=[],
        maximum_new_callbacks=MAX_NEW_CALLS,maximum_new_instructions=MAX_NEW_INSTRUCTIONS,
        suffix_SVC_policy='stop before every new SVC',
        second_getter_target='0x1c3024',second_getter_source='0x37a790',
        unknown_callback_policy='stop before VM call',
        inherited_parent_component_controls_reused=True,
        arithmetic_relations='in-memory assertions against observed unsigned input; no independent VM seeded with native state',
        fresh_component_inputs='declared synthetic profiles only')


def sources():
    return dict(verifier_sha256=sha256(Path(__file__)),
        parent_verifier_sha256=sha256(Path(previous.__file__)),parent_chain_sha256=digest(previous.sources()),
        float_fixture_sha256=sha256(Path(float_fixture.__file__)),
        float_VM_model_sha256=sha256(Path(float_fixture.__file__).with_name('vm_full.py')),
        second_getter_fixture_sha256=sha256(Path(word_fixture.__file__)),
        component_oracle_sha256=sha256(Path(word_fixture.oracle.__file__)))


def component_controls(path):
    old_value=os.environ.get('TOMATO_LIBMETASEC')
    os.environ['TOMATO_LIBMETASEC']=str(path.resolve())
    try:model=importlib.import_module('vm_full')
    finally:
        if old_value is None:os.environ.pop('TOMATO_LIBMETASEC',None)
        else:os.environ['TOMATO_LIBMETASEC']=old_value
    assert Path(model.__file__).resolve()==Path(float_fixture.__file__).with_name('vm_full.py').resolve()
    assert raw_hash(model.SO)==word_fixture.oracle.LIBRARY_SHA256
    values=dict(float_fixture.PROFILES)
    return dict(unsigned_conversion=[float_fixture.compare(path,model,base,label,values[label],backed)
        for base in float_fixture.BASES for label in FLOAT_PROFILES for backed in (False,True)],
        getter_B=[word_fixture.compare(path,base,label) for base in word_fixture.BASES for label in word_fixture.PROFILES],
        unsigned_conversion_guards=float_fixture.guards(path,model),getter_B_guards=word_fixture.guards(path))


def run(library,libc):
    parent=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(parent)
    base_parent=json.loads(previous.previous.EVIDENCE.read_text(encoding='utf-8'))
    scope_parent=previous.previous.parent_evidence();md5_parent=previous.previous.previous.parent_evidence()
    prefix=previous.bootstrap();prefix.digest.verify_images(library,libc)
    executable=[]
    for path,base in ((library,prefix.CONTROL['base']),(libc,LIBC_BASE)):
        with path.open('rb') as stream:
            elf=ELFFile(stream)
            executable.extend((base+s['p_vaddr'],base+s['p_vaddr']+s['p_memsz'])
                for s in elf.iter_segments() if s['p_type']=='PT_LOAD' and s['p_flags']&1)
            if path==library:
                section=elf.get_section_by_name('.plt');plt=(section['sh_addr'],section['sh_addr']+section['sh_size'])
            else:
                symbol=next(s for s in elf.get_section_by_name('.dynsym').iter_symbols()
                    if s.name=='strncmp' and s['st_shndx']!='SHN_UNDEF')
                strncmp=LIBC_BASE+symbol['st_value']
    def create(control):
        scenario=JsonFieldFlowScenario(control)
        scenario.path,scenario.continue_to_svc=library,True
        scenario._postcrc_parent,scenario._pcb_parent,scenario._jwx_parent=md5_parent,scope_parent,base_parent
        scenario._jff_parent=parent
        scenario._jwx_exec,scenario._jwx_plt,scenario._jwx_strncmp=executable,plt,strncmp
        return scenario
    print('Replaying original ELF/Bionic path and both scalar-to-JSON field relations',flush=True)
    rows=prefix.digest.context.replay(library,libc,case_controls=[prefix.CONTROL],_extension_factory=create,
        _request_profile=prefix.digest.previous.previous.name.previous.previous.PROFILE['name'],
        _handler_read_profile=prefix.digest.context.NULL_PAYLOAD_READ_PROFILE['name'])
    assert len(rows)==1
    controls=component_controls(library)
    return dict(schema=SCHEMA,claims=claims(),providers=providers(),source_fingerprints=sources(),
        parent_evidence_sha256=sha256(previous.EVIDENCE),component_controls=controls,
        case_result=rows[0],case_result_sha256=digest(rows[0]))


# Fingerprint of the independent redacted result; never a VM input.
EXPECTED_CASE_SHA256='aeae79caf79a1ed31ad00e8816de38134d3ecf16b0c875877a134b2e2357bfc2'


def _validate(data,parent):
    assert set(data)=={'schema','claims','providers','source_fingerprints','parent_evidence_sha256',
        'component_controls','case_result','case_result_sha256'}
    assert data['schema']==SCHEMA and data['claims']==claims() and data['providers']==providers()
    assert data['source_fingerprints']==sources()
    assert data['parent_evidence_sha256']==sha256(previous.EVIDENCE)
    row=data['case_result']
    assert data['case_result_sha256']==digest(row)==EXPECTED_CASE_SHA256
    assert row['full_parent_case_equal'] is True and row['parent_case_sha256']==digest(parent['case_result'])
    assert row['current_native_values_used_only_for_relations'] is True
    assert row['native_snapshot_used_as_VM_model_input'] is False
    assert row['complete_standalone_signer_verified'] is row['online_acceptance_verified'] is False
    assert 0<row['suffix_instruction_observations']<=MAX_NEW_INSTRUCTIONS
    assert row['suffix_instruction_observations']==1725
    flows=row['flows'];assert len(flows)==2
    assert [(flow['label'],flow['source_offset'],flow['source_width']) for flow in flows]==[
        ('first','0x37a794',4),('second','0x37a790',4)]
    first_node=None
    for i,flow in enumerate(flows):
        assert set(flow)=={'label','source_offset','source_width','unsigned_getter_return_verified',
            'conversion','argument','node','node_verified','scalar_values_exported','scalar_content_hashes_exported'}
        assert flow['unsigned_getter_return_verified'] is flow['node_verified'] is True
        assert flow['scalar_values_exported'] is flow['scalar_content_hashes_exported'] is False
        cvt,arg,node=flow['conversion'],flow['argument'],flow['node']
        assert set(cvt)=={'source_address','load_site','source_low_u32_equals_getter','window','index',
            'convert_site','zero_extended_unsigned_operand_verified','binary64_equals_exact_unsigned_conversion',
            'destination_address','store_site','stored_binary64_equal'}
        assert cvt['load_site']=='0x17079c' and cvt['convert_site']=='0x1707ac' and cvt['store_site']=='0x1707f8'
        assert all(cvt[key] is True for key in ('source_low_u32_equals_getter','zero_extended_unsigned_operand_verified',
            'binary64_equals_exact_unsigned_conversion','stored_binary64_equal'))
        assert set(arg)=={'descriptor_address','wrapper_is_initial_JSON','binary64_equals_conversion_store',
            'key_contents_exported','key_content_hash_exported','window','index','actual_X0_X1_D0_equal'}
        assert all(arg[key] is True for key in ('wrapper_is_initial_JSON','binary64_equals_conversion_store','actual_X0_X1_D0_equal'))
        assert arg['key_contents_exported'] is arg['key_content_hash_exported'] is False
        assert set(node)=={'address','root_address','type_u32','new_live_node_allocation','new_live_key_allocation',
            'key_copy_equal','binary64_equals_getter_conversion','signed_int32_saturation_equal',
            'exact_one_byte_success_store_and_other_descriptor_bytes_preserved',
            'prior_child_preserved_except_append_links','window','index'}
        assert node['type_u32']==8
        assert all(value is True for key,value in node.items() if type(value) is bool)
        window='parent' if i==0 else 'suffix'
        assert cvt['window']==arg['window']==node['window']==window
        assert cvt['index']<arg['index']<node['index']
        assert node['root_address']==parent['case_result']['typed_JSON_output_at_first_return']['root_address']
        if first_node is not None:assert first_node!=node['address']
        first_node=node['address']
    assert flows[0]['conversion']['index']==2825
    assert flows[0]['argument']['index']==3198 and flows[0]['node']['index']==3588
    assert flows[1]['conversion']['index']==578
    assert flows[1]['argument']['index']==897 and flows[1]['node']['index']==1290
    calls=row['suffix_callbacks'];assert len(calls)==3 and row['completed_suffix_callbacks']==2
    assert calls[0]['index']==1 and calls[0]['entry_is_existing_wrapper_BLR'] is True
    assert calls[0]['wrapper_offset']=='0x28863c' and calls[0]['target_offset']=='0x1c3024'
    assert calls[1]['wrapper_offset']=='0x288854' and calls[1]['target_offset']=='0x261350'
    assert [call.get('return_index') for call in calls]==[8,1290,None]
    assert calls[-1]['index']==1725 and calls[-1]['VM_cursor_offset']=='0x10a528'
    assert calls[-1]['wrapper_offset']=='0x28863c' and calls[-1]['target_offset']=='0x204e50'
    for call in calls[:2]:
        assert all(call[key] is True for key in ('VM_call_executed','wrapper_entered','target_entered',
            'returned','caller_SP_and_callee_saved_restored'))
        assert call['index']<call['return_index']<=row['suffix_instruction_observations']
    assert all(calls[-1][key] is False for key in ('VM_call_executed','wrapper_entered','target_entered','returned'))
    assert row['suffix_stop_reason']=='new_callback_budget_before_next_call'
    assert row['allocator_aux_events']==[]
    assert [(event[0],event[1],event[3]) for event in row['new_allocator_events']]==[
        ('alloc',64,'0x2493fc'),('alloc',5,'0x249198')]
    assert row['new_allocator_events'][0][2]==int(flows[1]['node']['address'],16)
    counts=dict(parent['case_result']['actual_allocator_counts'])
    for event in row['new_allocator_events']:counts['malloc' if event[0]=='alloc' else 'free']+=1
    assert row['actual_allocator_counts']==counts
    assert row['explicit_service_counts']==parent['case_result']['explicit_service_counts']
    assert not {'word','bits','key_bytes','registers','native_writes','observation_sites','observed_code'}&set(row)
    controls=data['component_controls']
    assert set(controls)=={'unsigned_conversion','getter_B','unsigned_conversion_guards','getter_B_guards'}
    floats=controls['unsigned_conversion']
    assert [(control['image_base'],control['case'],control['guest_backing']) for control in floats]==[
        (hex(base),label,backed) for base in float_fixture.BASES for label in FLOAT_PROFILES for backed in (False,True)]
    words=controls['getter_B']
    assert [(control['image_base'],control['case']) for control in words]==[
        (hex(base),label) for base in word_fixture.BASES for label in word_fixture.PROFILES]
    for control in floats+words:
        for key,value in control.items():
            if type(value) is bool and key!='guest_backing':
                assert value is (key not in {'native_snapshot_input','complete_float_family_verified','physical_spills_and_PAC_compared'})
    assert [control['operation'] for control in controls['unsigned_conversion_guards']]==list(float_fixture.GUARDS)
    assert all(control['rejected'] is control['registers_PC_and_all_pages_unchanged'] is True
        for control in controls['unsigned_conversion_guards'])
    assert [control['case'] for control in controls['getter_B_guards']]==list(word_fixture.GUARDS)
    assert all(control['rejected'] is control['all_pages_unchanged'] is True for control in controls['getter_B_guards'])


def validate(data):
    parent=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(parent)
    _validate(data,parent)


def damaged_evidence_rejected(data):
    parent=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(parent)
    changes=[(('claims','complete_standalone_signer_verified'),True),
        (('providers','new_providers'),['guessed']),
        (('source_fingerprints','float_VM_model_sha256'),'0'*64),
        (('case_result','full_parent_case_equal'),False),
        (('case_result','flows',0,'conversion','zero_extended_unsigned_operand_verified'),False),
        (('case_result','flows',0,'argument','actual_X0_X1_D0_equal'),False),
        (('case_result','flows',0,'node','binary64_equals_getter_conversion'),False),
        (('case_result','flows',1,'node','new_live_node_allocation'),False),
        (('case_result','flows',1,'node','prior_child_preserved_except_append_links'),False),
        (('case_result','flows',0,'scalar_values_exported'),True),
        (('case_result','flows',1,'argument','key_content_hash_exported'),True),
        (('case_result','completed_suffix_callbacks'),3),
        (('case_result','suffix_callbacks',-1,'target_entered'),True),
        (('case_result','bits'),'forbidden'),
        (('component_controls','unsigned_conversion_guards',0,'rejected'),False),
        (('component_controls','getter_B',0,'adjacent_global_distinguished'),False)]
    for path,value in changes:
        bad=deepcopy(data);target=bad
        for key in path[:-1]:target=target[key]
        target[path[-1]]=value
        if path[0]=='case_result':bad['case_result_sha256']=digest(bad['case_result'])
        try:_validate(bad,parent)
        except (AssertionError,KeyError,ValueError,TypeError,IndexError):continue
        raise AssertionError('damaged field-flow evidence accepted: '+repr(path))
    return len(changes)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf',type=Path);parser.add_argument('--libc',type=Path)
    parser.add_argument('--compare-case',type=Path,help='independent case JSON, capture only')
    modes=parser.add_mutually_exclusive_group()
    modes.add_argument('--capture',action='store_true');modes.add_argument('--replay',action='store_true')
    args=parser.parse_args()
    if (args.capture or args.replay) and (args.elf is None or args.libc is None):
        parser.error('--capture and --replay require --elf and --libc')
    if args.compare_case is not None and not args.capture:parser.error('--compare-case requires --capture')
    if args.capture:
        if EVIDENCE.exists():raise FileExistsError('frozen evidence exists; refusing overwrite')
        data=run(args.elf,args.libc)
        if args.compare_case is not None:
            reference=json.loads(args.compare_case.read_text(encoding='utf-8'))
            assert data['case_result']==reference,'independent and public field-flow cases differ'
        validate(data);rejected=damaged_evidence_rejected(data)
        with EVIDENCE.open('x',encoding='utf-8',newline='\n') as stream:stream.write(json.dumps(data,indent=2)+'\n')
    else:
        data=json.loads(EVIDENCE.read_text(encoding='utf-8'));validate(data)
        rejected=damaged_evidence_rejected(data)
        if args.replay:assert run(args.elf,args.libc)==data,'fresh field-flow replay differs'
    print(json.dumps(dict(schema=SCHEMA,verified_field_relations=len(data['case_result']['flows']),
        completed_suffix_callbacks=data['case_result']['completed_suffix_callbacks'],
        damaged_evidence_rejected=rejected,complete_standalone_signer_verified=False)))


if __name__=='__main__':
    main()
