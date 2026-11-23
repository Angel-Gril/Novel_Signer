"""Bounded original helper entry with nested callback frames and strict host guards."""
from __future__ import annotations
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import verify_vm9_native_171_json_field_flow_dynamic_20261124 as previous
from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as arm
bootstrap=previous.previous.bootstrap
VM_CALL,VM_RESUME,LIBC_BASE=previous.VM_CALL,previous.VM_RESUME,previous.LIBC_BASE
digest,raw_hash,sha256=previous.digest,previous.raw_hash,previous.sha256
import verify_vm9_request_environment_vm_fresh_20261013 as frame_fixture
import verify_vm9_second_environment_helper_fresh_20261016 as return_fixture
import vm9_request_environment_vm as environment
from vm9_allocator import _read_span, _write_span, RefillUnsupported
EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_environment_entry_dynamic_20261124.json')
SCHEMA='vm9-native-171-environment-entry-dynamic-20261124-v1'
FRAME_PROFILES=('normal','patterned_stack','relocated_stack','TLS_spill_alias')
RETURN_PROFILES=('zero','max_W','patterned_stack','cross_page_packed','TLS_frame_alias','result_alias_wrapper_x19')
MAX_INSTRUCTIONS,MAX_NESTED=120000,16
ALLOWED={(0x28863C,0x204E50),(0x205044,0x167E54),(0x2050F0,0x167E54),
    (0x205058,0x26EDC4),(0x205064,0x248344),(0x205094,0x2484B8),(0x205074,0x26E9E0)}


class EnvironmentEntryScenario(previous.JsonFieldFlowScenario):
    def __init__(self,control):
        super().__init__(control)
        self._jev_active=self._jev_done=False
        self._jev_sites,self._jev_code,self._jev_writes=[],{},[]
        self._jev_calls,self._jev_stack,self._jev_aux=[],[],[]
        self._jev_entries=[];self._jev_stop_reason=None
        self._jev_root_returned=False
        self._jev_acquisition_events=[]
        self._jev_provider_pending=None

    def _jev_track(self,cpu,pc):
        key=self._fmt_site(pc);self._jev_sites.append(key)
        self._jev_code[key]=bytes(cpu.mem_read(pc,4)).hex()

    def _jev_stop(self,cpu,reason):
        assert all(bytes(cpu.mem_read(address,len(data)))==data for _,address,data in self._jev_retained)
        self._jev_retained_verified=True
        self._jev_done=True;self._jev_stop_reason=reason
        cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,bootstrap().digest.context.outer.oracle.STOP)

    def _jev_call(self,cpu):
        descriptor=self._reg(cpu,0);vmstate=self._reg(cpu,19)
        wrapper,target=self._reg(cpu,8),self._u(cpu,descriptor)
        return dict(index=len(self._jev_sites),depth=len(self._jev_stack),descriptor_address=hex(descriptor),
            wrapper_offset=hex(wrapper-self.image),target_offset=hex(target-self.image),
            VM_state_address=hex(vmstate),VM_cursor_offset=hex(self._u(cpu,vmstate)-self.image),
            SP=hex(cpu.reg_read(arm.UC_ARM64_REG_SP)),callee_saved_sha256=self._idctor_saved_hash(cpu),
            VM_call_executed=False,wrapper_entered=False,target_entered=False,returned=False)

    def _jff_stop(self,cpu,reason):
        if reason!='new_callback_budget_before_next_call':return super()._jff_stop(cpu,reason)
        assert not self._jev_active and len(self._jff_sites)==1725
        assert cpu.reg_read(arm.UC_ARM64_REG_PC)==self.image+VM_CALL
        old=self._jff_calls[-1]
        assert (old['wrapper_offset'],old['target_offset'])==('0x28863c','0x204e50')
        self._jff_done=True;self._jff_stop_reason=reason;self._jff_active=False
        self._jev_events=deepcopy(self._jff_state['allocator_events_ref'])
        self._jev_initial_late=deepcopy(self.late_jni_calls)
        self._jev_initial_java=deepcopy(self.java_dispatch_calls)
        self._jev_active=True;self._jev_track(cpu,self.image+VM_CALL)
        call=self._jev_call(cpu);self._jev_calls.append(call);self._jev_stack.append(call)
        assert call['descriptor_address']==old['descriptor_address'] and call['SP']==old['SP']
        self._jev_descriptor=int(call['descriptor_address'],16)
        self._jev_descriptor_before=bytes(cpu.mem_read(self._jev_descriptor,48))
        initial=self._jwx_typed_output
        ranges=[('JSON_wrapper',int(initial['wrapper_address'],16),16),
            ('JSON_counter',int(initial['counter_address'],16),4),
            ('JSON_root',int(initial['root_address'],16),64)]
        ranges.extend(('JSON_node_'+str(i),int(row['node']['address'],16),64) for i,row in enumerate(self._jff_flows))
        for i,event in enumerate(self._jev_events[len(self._jwx_events):]):
            if event[0]=='alloc' and event[1] in (4,5):
                # Protect only currently-owned JSON keys, not allocator metadata.
                if event[2] in (self._u(cpu,int(row['node']['address'],16)+56) for row in self._jff_flows):
                    ranges.append(('JSON_key_'+str(i),event[2],event[1]))
        self._jev_retained=[(label,address,bytes(cpu.mem_read(address,size))) for label,address,size in ranges]
        self._base_observe(cpu,self.image+VM_CALL,self._jff_state)
        print('Entering original environment helper with retained JSON objects protected',flush=True)

    def _base_observe(self,cpu,pc,state):
        if self._jev_active and pc==self.image+0x288648:
            call=self._jev_stack[-1];descriptor=int(call['descriptor_address'],16)
            assert (call['wrapper_offset'],call['target_offset'])==('0x28863c','0x204e50')
            assert self._reg(cpu,0)==self._reg(cpu,19)==descriptor
            assert self._reg(cpu,8)==self._u(cpu,descriptor)==self.image+0x204E50
            bootstrap().digest.Scenario.observe(self,cpu,pc,state);return
        return super()._base_observe(cpu,pc,state)

    def native_runner(self,*args,**kwargs):
        # Keep the already-frozen controlled JNI provider; never relabel it
        # as execution of the original +26edc4 acquisition body.
        assert not kwargs.get('real_jni_acquisition',False)
        assert not kwargs.get('real_jni_dispatch',False)
        self._jev_provider_env=kwargs['env']
        assert self._jev_provider_env
        old_write=kwargs['memory_write_observer']
        def write(cpu,address,size):
            if self._jev_active:
                assert not any(address<base+len(data) and base<address+size for _,base,data in self._jev_retained)
                self._jev_writes.append(dict(index=len(self._jev_sites),PC=self._fmt_site(cpu.reg_read(arm.UC_ARM64_REG_PC)),
                    address=hex(address),size=size))
            if old_write:old_write(cpu,address,size)
        kwargs['memory_write_observer']=write
        return super().native_runner(*args,**kwargs)

    def _jev_guard(self,cpu,pc):
        if pc==self.image+0x26E70C:
            raise previous.previous.UnsafeBoundary('unadmitted JNI dispatcher entry; provider not executed')
        word=int.from_bytes(cpu.mem_read(pc,4),'little')
        if word==0xD4000001:
            self._jev_stop(cpu,'new_SVC_before_execution');return True
        if self.image+self._jwx_plt[0]<=pc<self.image+self._jwx_plt[1] and pc-self.image not in previous.previous.ALLOWED_PLT:
            raise previous.previous.UnsafeBoundary('uncovered environment PLT entry before host provider')
        target=None
        if word&0x7C000000==0x14000000:
            immediate=word&0x03FFFFFF
            if immediate&(1<<25):immediate-=1<<26
            target=pc+(immediate<<2)
        elif word&0xFFFFFC1F in (0xD61F0000,0xD63F0000,0xD65F0000):
            register=(word>>5)&31;target=0 if register==31 else self._reg(cpu,register)
        if target is not None:
            if target==self.image+0x26E70C:
                self._jev_boundary=dict(index=len(self._jev_sites),PC=self._fmt_site(pc),
                    target_offset='0x26e70c',branch_executed=False,provider_executed=False)
                self._jev_stop(cpu,'JNI_dispatch_before_branch');return True
            if not self._jwx_executable(target):
                self._jev_boundary=dict(index=len(self._jev_sites),PC=self._fmt_site(pc),
                    branch_instruction=hex(word),target_is_executable_in_declared_images=False,
                    target_contents_exported=False,branch_executed=False)
                self._jev_stop(cpu,'external_or_unmapped_branch_before_execution');return True
            if self.image+self._jwx_plt[0]<=target<self.image+self._jwx_plt[1] and target-self.image not in previous.previous.ALLOWED_PLT:
                self._jev_boundary=dict(index=len(self._jev_sites),PC=self._fmt_site(pc),
                    main_PLT_target_offset=hex(target-self.image),branch_executed=False)
                self._jev_stop(cpu,'uncovered_environment_PLT_before_branch');return True
        return False

    def _jev_entry(self,cpu,pc):
        root=self._jev_calls[0];off=pc-self.image
        if off==0x204E50:
            assert self._reg(cpu,0)==self._jev_descriptor
            assert self._reg(cpu,30)==self.image+0x28864C
            self._jev_helper_entry_sp=cpu.reg_read(arm.UC_ARM64_REG_SP)
            assert self._jev_helper_entry_sp==int(root['SP'],16)-16
            self._jev_local=self._jev_helper_entry_sp-0x500
            self._jev_tp=cpu.reg_read(arm.UC_ARM64_REG_TPIDR_EL0)
            self._jev_entries.append(dict(kind='helper_entry',index=len(self._jev_sites),
                PC=hex(off),SP=hex(self._jev_helper_entry_sp),original_wrapper_frame_verified=True))
        if off==0x204EA8:
            local=self._jev_local
            expected=(self.image+0x8A040,local+8,self.image+0x34F170,self.image+0x34F210,local+0x10)
            assert tuple(self._reg(cpu,i) for i in range(5))==expected
            assert cpu.reg_read(arm.UC_ARM64_REG_SP)==local
            assert tuple(self._u(cpu,local+0x10+i*8) for i in range(3))==(self.image+0x2050E4,local+0x4D0,self.image+0x28864C)
            assert bytes(cpu.mem_read(self._jev_helper_entry_sp-0x28,8))==bytes(cpu.mem_read(self._jev_tp+0x28,8))
            self._jev_entries.append(dict(kind='before_nested_VM_entry',index=len(self._jev_sites),PC=hex(off),
                local_SP=hex(local),bytecode_offset='0x8a040',callback_sentinel_offset='0x2050e4',
                original_X0_X4_and_three_defined_descriptor_words_equal=True,TLS_canary_copy_equal=True,
                undefined_result_word_compared=False))
        if off==0x1684F0 and not any(row['kind']=='nested_VM_defined_registers' for row in self._jev_entries):
            local=self._jev_local;top=local+0x4D0;backing=top-0x118
            assert self._reg(cpu,19)==top-0x120 and self._reg(cpu,28)==backing
            assert self._u(cpu,top-0x120)==self.image+0x8A040
            expected={0:0,4:local+8,5:self.image+0x34F170,6:self.image+0x34F210,
                7:self.image+0x2050E4,29:(top-0x130)&~15,31:self.image+0x28864C}
            assert all(self._u(cpu,backing+slot*8)==value for slot,value in expected.items())
            self._jev_entries.append(dict(kind='nested_VM_defined_registers',index=len(self._jev_sites),PC=hex(off),
                VM_state_address=hex(top-0x120),register_backing_address=hex(backing),
                initialized_virtual_slots=sorted(expected),defined_slot_relations_verified=True,
                other_virtual_register_values_exported=False))
        if off==0x204EAC:
            self._jev_result_word=bytes(cpu.mem_read(self._jev_local+8,4))
            self._jev_entries.append(dict(kind='nested_VM_returned_to_helper',index=len(self._jev_sites),PC=hex(off),
                result_value_exported=False,result_hash_exported=False))
        if off==0x26EDC4:
            call=self._jev_stack[-1]
            assert (call['wrapper_offset'],call['target_offset'])==('0x205058','0x26edc4')
            descriptor=int(call['descriptor_address'],16);output=self._reg(cpu,0)
            assert output==self._u(cpu,descriptor+8) and self._jev_provider_pending is None
            assert not any(output<base+len(data) and base<output+8 for _,base,data in self._jev_retained)
            self._jev_provider_pending=dict(output=output,before=bytes(cpu.mem_read(output,16)),
                descriptor=descriptor,descriptor_before=bytes(cpu.mem_read(descriptor,32)),entry_index=len(self._jev_sites))
            call.update(implementation='inherited controlled JNI acquisition provider',native_acquisition_body_executed=False)

    def observe(self,cpu,pc,state):
        if not self._jev_active:return super().observe(cpu,pc,state)
        self._jev_track(cpu,pc)
        if len(self._jev_sites)>=MAX_INSTRUCTIONS:self._jev_stop(cpu,'instruction_budget');return
        if pc in (LIBC_BASE+0x9833C,LIBC_BASE+0x97F40):
            self._jev_aux.append(dict(index=len(self._jev_sites),kind='gc' if pc==LIBC_BASE+0x9833C else 'flush'))
        if pc==self.image+VM_CALL:
            call=self._jev_call(cpu);self._jev_calls.append(call)
            if self._jev_root_returned:
                self._jev_stop(cpu,'next_outer_VM_call_before_execution');return
            if len(self._jev_calls)>MAX_NESTED:
                self._jev_stop(cpu,'nested_callback_budget_before_execution');return
            if (int(call['wrapper_offset'],16),int(call['target_offset'],16)) not in ALLOWED:
                self._jev_stop(cpu,'uncovered_nested_VM_callback_before_execution');return
            self._jev_stack.append(call)
        if self._jev_guard(cpu,pc):return
        self._jev_entry(cpu,pc)
        call=self._jev_stack[-1] if self._jev_stack else None
        if call is not None:
            if pc==self.image+int(call['wrapper_offset'],16):call.update(VM_call_executed=True,wrapper_entered=True)
            if pc==self.image+int(call['target_offset'],16):call['target_entered']=True
            if pc==self.image+VM_RESUME:
                assert cpu.reg_read(arm.UC_ARM64_REG_SP)==int(call['SP'],16)
                assert self._idctor_saved_hash(cpu)==call['callee_saved_sha256']
                call.update(returned=True,return_index=len(self._jev_sites),caller_SP_and_callee_saved_restored=True)
                self._jev_stack.pop()
                if call['target_offset']=='0x26edc4':
                    pending=self._jev_provider_pending;assert pending is not None
                    assert bytes(cpu.mem_read(pending['output'],16))==self._jev_provider_env.to_bytes(8,'little')+pending['before'][8:]
                    assert self._reg(cpu,0)==0
                    assert bytes(cpu.mem_read(pending['descriptor'],32))==pending['descriptor_before']
                    self._jev_acquisition_events.append(dict(kind='inherited controlled JNI acquisition provider',
                        entry_index=pending['entry_index'],return_index=len(self._jev_sites),write_width=8,
                        output_pair_address=hex(pending['output']),output_pair_tail_preserved=True,
                        environment_matches_declared_control=True,declared_status_x0=0,
                        descriptor_preserved=True,native_acquisition_body_executed=False,real_ART_JVM_execution=False))
                    self._jev_provider_pending=None
                if call is self._jev_calls[0]:
                    expected=bytearray(self._jev_descriptor_before);expected[8:12]=self._jev_result_word
                    assert bytes(cpu.mem_read(self._jev_descriptor,48))==expected
                    assert self._reg(cpu,0)==int.from_bytes(self._jev_result_word,'little')
                    self._jev_root_returned=True
                    call.update(unsigned_X0_equals_nested_VM_result=True,exact_four_byte_result_store_and_padding_preserved=True)
        self._base_observe(cpu,pc,state)
        assert self.late_jni_calls==self._jev_initial_late and self.java_dispatch_calls==self._jev_initial_java

    def finish(self,result,state,proof):
        assert self._jev_done
        delta=result['allocator_events'][len(self._jev_events):]
        prefix,counts=dict(result),deepcopy(result['actual_allocator_counts'])
        for event in delta:counts['malloc' if event[0]=='alloc' else 'free']-=1
        for event in self._jev_aux:counts[event['kind']]-=1
        prefix.update(allocator_events=self._jev_events,actual_allocator_counts=counts)
        old=super().finish(prefix,state,proof)
        assert old==self._jev_parent['case_result'],'complete scalar-field parent differs'
        assert self._jev_retained_verified
        trace=hashlib.sha256()
        for key in self._jev_sites:trace.update(key.encode()+bytes.fromhex(self._jev_code[key]))
        return dict(parent_case_equal=True,parent_case_sha256=digest(old),instruction_observations=len(self._jev_sites),
            instruction_trace_sha256=trace.hexdigest(),observed_code_sha256=digest(self._jev_code),
            entries=self._jev_entries,callbacks=self._jev_calls,completed_callbacks=sum(c['returned'] for c in self._jev_calls),
            helper_returned=self._jev_root_returned,stop_reason=self._jev_stop_reason,boundary=getattr(self,'_jev_boundary',{}),
            protected_JSON_write_observations=0,new_allocator_events=delta,allocator_aux_events=self._jev_aux,
            native_write_observations=len(self._jev_writes),actual_allocator_counts=result['actual_allocator_counts'],
            explicit_service_counts=result['explicit_service_counts'],new_SVCs=[],
            controlled_JNI_effects=self._jev_acquisition_events,new_providers=[],
            decoded_contents_and_hashes_exported=False,native_snapshot_used_as_VM_model_input=False,
            complete_standalone_signer_verified=False,online_acceptance_verified=False)


def frame_control(path,base,label):
    pages,inputs=frame_fixture.fixture(path,base,label)
    frame_fixture.packed(pages,inputs)
    initial={key:bytearray(value) for key,value in pages.items()}
    frame=environment.prepare_request_environment_wrapper_caller(pages,
        argument_block_address=frame_fixture.G+0x1000,wrapper_offset=0x28863C,**inputs)
    watched={(frame.native_stack_address,inputs['entry_stack_address']-frame.native_stack_address):None}
    observed=[]
    def watch(cpu,pc):
        if pc==base+0x168324:observed.append(tuple(cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(5)))
    _,memory,allocations,services=frame_fixture.oracle.native(path,base,0x28863C,[frame_fixture.G+0x1000],initial,
        stop_offset=0x1684F0,observed_memory=watched,instruction_observer=watch,instruction_limit=100000,
        extra_registers={arm.UC_ARM64_REG_SP:inputs['entry_stack_address'],arm.UC_ARM64_REG_X30:inputs['return_address'],
            arm.UC_ARM64_REG_TPIDR_EL0:inputs['thread_pointer'],arm.UC_ARM64_REG_X29:inputs['saved_frame_pointer'],
            arm.UC_ARM64_REG_X28:inputs['saved_x28'],arm.UC_ARM64_REG_X19:inputs['saved_x19']})
    assert not allocations and not services and observed==[frame.vm_call_registers]
    assert _read_span(pages,frame_fixture.G,0xA000)==memory
    assert all(_read_span(pages,address,size)==data for (address,size),data in watched.items())
    print('PASS actual +28863c environment entry',hex(base),label,flush=True)
    return dict(image_base=hex(base),case=label,actual_wrapper_and_helper_entry_executed=True,
        five_VM_arguments_equal=True,complete_caller_frame_and_32_virtual_words_equal=True,
        guest_payload_equal=True,undefined_result_and_padding_preserved=True,
        native_snapshot_input=False,complete_helper_VM_verified=False)


def wrapper_guards(path):
    rows=[]
    for label in ('wrong_target','missing_packed','tagged_return'):
        pages,inputs=frame_fixture.fixture(path,frame_fixture.BASES[0],'normal')
        frame_fixture.packed(pages,inputs)
        if label=='wrong_target':_write_span(pages,frame_fixture.G+0x1000,(inputs['image_base']+1).to_bytes(8,'little'))
        elif label=='missing_packed':del pages[(frame_fixture.G+0x1000)>>12]
        else:inputs['return_address']|=1<<56
        before={key:bytes(value) for key,value in pages.items()}
        try:environment.prepare_request_environment_wrapper_caller(pages,
            argument_block_address=frame_fixture.G+0x1000,wrapper_offset=0x28863C,**inputs)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError('invalid environment entry accepted: '+label)
        assert before=={key:bytes(value) for key,value in pages.items()}
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True))
    return rows


def sources():
    return dict(verifier_sha256=sha256(Path(__file__)),
        parent_verifier_sha256=sha256(Path(previous.__file__)),parent_chain_sha256=digest(previous.sources()),
        frame_fixture_sha256=sha256(Path(frame_fixture.__file__)),
        return_fixture_sha256=sha256(Path(return_fixture.__file__)),
        environment_model_sha256=sha256(Path(environment.__file__)),
        caller_model_sha256=sha256(Path(frame_fixture.caller.__file__)),
        native_oracle_sha256=sha256(Path(frame_fixture.oracle.__file__)))


def providers():
    return dict(parent_evidence_sha256=sha256(previous.EVIDENCE),new_providers=[],new_import_bindings=[],
        acquisition='inherited controlled provider: output[0:8]=declared env, tail preserved, X0=0; native body bypassed',
        real_jni_acquisition=False,real_jni_dispatch=False,
        JNI_dispatch='stop before a branch to +26e70c; reject unexpected provider entry',
        SVC_policy='stop before new SVC execution',unknown_branch_policy='stop before executable-domain escape',
        maximum_observations=MAX_INSTRUCTIONS,maximum_nested_calls=MAX_NESTED,
        original_ART_or_JVM_execution_verified=False)


def claims():
    return dict(evidence_label='Sample verified',complete_parent_case_equal=True,
        original_helper_entry_and_nested_VM_defined_frame_observed=True,
        original_helper_and_wrapper_return_observed_under_declared_services=True,
        actual_unsigned_W_result_and_exact_four_byte_writeback_verified=True,
        initialized_virtual_slots_compared=[0,4,5,6,7,29,31],
        retained_live_JSON_bytes_preserved=True,
        controlled_acquisition_is_not_original_JNI_body=True,
        decoded_contents_or_content_hashes_exported=False,
        native_snapshot_used_to_initialize_Python_VM=False,
        complete_standalone_signer_verified=False,real_ART_JVM_execution=False,
        Android_execution=False,complete_physical_ABI_verified=False,online_acceptance_verified=False)


def run(library,libc):
    parent=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(parent)
    jff_parent=json.loads(previous.previous.EVIDENCE.read_text(encoding='utf-8'))
    base_parent=json.loads(previous.previous.previous.EVIDENCE.read_text(encoding='utf-8'))
    scope_parent=previous.previous.previous.parent_evidence()
    md5_parent=previous.previous.previous.previous.parent_evidence()
    prefix=bootstrap();prefix.digest.verify_images(library,libc)
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
        scenario=EnvironmentEntryScenario(control)
        scenario.path,scenario.continue_to_svc=library,True
        scenario._postcrc_parent,scenario._pcb_parent,scenario._jwx_parent=md5_parent,scope_parent,base_parent
        scenario._jff_parent,scenario._jev_parent=jff_parent,parent
        scenario._jwx_exec,scenario._jwx_plt,scenario._jwx_strncmp=executable,plt,strncmp
        return scenario
    print('Replaying original helper entry and guarded nested VM',flush=True)
    rows=prefix.digest.context.replay(library,libc,case_controls=[prefix.CONTROL],_extension_factory=create,
        _request_profile=prefix.digest.previous.previous.name.previous.previous.PROFILE['name'],
        _handler_read_profile=prefix.digest.context.NULL_PAYLOAD_READ_PROFILE['name'])
    assert len(rows)==1
    controls=dict(frames=[frame_control(library,base,label) for base in frame_fixture.BASES for label in FRAME_PROFILES],
        returns=[return_fixture.compare(library,base,label) for base in return_fixture.BASES for label in RETURN_PROFILES],
        caller_guards=frame_fixture.guards(library),wrapper_guards=wrapper_guards(library),
        return_guards=return_fixture.guards(library))
    return dict(schema=SCHEMA,claims=claims(),providers=providers(),source_fingerprints=sources(),
        parent_evidence_sha256=sha256(previous.EVIDENCE),case_result=rows[0],case_result_sha256=digest(rows[0]),
        component_controls=controls)


# Regression fingerprint of the independent redacted case, never a VM input.
EXPECTED_CASE_SHA256='9c7344fa6f272f53f8f6bde100445b42c33db9fca77f654fe2ae9f71bc9542d7'


def _validate(data,parent):
    assert set(data)=={'schema','claims','providers','source_fingerprints','parent_evidence_sha256',
        'case_result','case_result_sha256','component_controls'}
    assert data['schema']==SCHEMA and data['claims']==claims() and data['providers']==providers()
    assert data['source_fingerprints']==sources()
    assert data['parent_evidence_sha256']==sha256(previous.EVIDENCE)
    row=data['case_result'];assert data['case_result_sha256']==digest(row)==EXPECTED_CASE_SHA256
    assert row['parent_case_equal'] is True and row['parent_case_sha256']==digest(parent['case_result'])
    assert row['instruction_observations']==15291<MAX_INSTRUCTIONS
    assert row['completed_callbacks']==5 and row['helper_returned'] is True
    assert row['stop_reason']=='next_outer_VM_call_before_execution' and row['boundary']=={}
    assert row['protected_JSON_write_observations']==0
    assert row['decoded_contents_and_hashes_exported'] is row['native_snapshot_used_as_VM_model_input'] is False
    assert row['complete_standalone_signer_verified'] is row['online_acceptance_verified'] is False
    entries=row['entries']
    assert [(entry['kind'],entry['index'],entry['PC']) for entry in entries]==[
        ('helper_entry',6,'0x204e50'),('before_nested_VM_entry',28,'0x204ea8'),
        ('nested_VM_defined_registers',144,'0x1684f0'),('nested_VM_returned_to_helper',14390,'0x204eac')]
    entry,call,frame,returned=entries
    assert entry['original_wrapper_frame_verified'] is True
    assert call['bytecode_offset']=='0x8a040' and call['callback_sentinel_offset']=='0x2050e4'
    assert call['original_X0_X4_and_three_defined_descriptor_words_equal'] is call['TLS_canary_copy_equal'] is True
    assert call['undefined_result_word_compared'] is False
    assert frame['initialized_virtual_slots']==[0,4,5,6,7,29,31]
    assert frame['defined_slot_relations_verified'] is True and frame['other_virtual_register_values_exported'] is False
    assert returned['result_value_exported'] is returned['result_hash_exported'] is False
    local=int(call['local_SP'],16)
    assert local==int(entry['SP'],16)-0x500
    assert int(frame['VM_state_address'],16)==local+0x4D0-0x120
    assert int(frame['register_backing_address'],16)==local+0x4D0-0x118
    callbacks=row['callbacks'];assert len(callbacks)==6
    assert [(c['wrapper_offset'],c['target_offset']) for c in callbacks]==[
        ('0x28863c','0x204e50'),('0x205058','0x26edc4'),('0x205064','0x248344'),
        ('0x205074','0x26e9e0'),('0x205094','0x2484b8'),('0x288854','0x261350')]
    assert [c['index'] for c in callbacks]==[1,6462,9276,10315,12551,15291]
    assert [c.get('return_index') for c in callbacks]==[14402,6467,9432,11810,12704,None]
    assert [c['depth'] for c in callbacks]==[0,1,1,1,1,0]
    old=parent['case_result']['suffix_callbacks'][-1]
    for key in ('descriptor_address','VM_cursor_offset','SP','callee_saved_sha256'):
        assert callbacks[0][key]==old[key]
    assert int(callbacks[0]['SP'],16)==int(entry['SP'],16)+16
    for c in callbacks[:-1]:
        assert all(c[key] is True for key in ('VM_call_executed','wrapper_entered','target_entered',
            'returned','caller_SP_and_callee_saved_restored'))
        assert c['index']<c['return_index']<callbacks[-1]['index']
    for c in callbacks[1:5]:
        assert c['VM_state_address']==frame['VM_state_address']
        assert int(c['SP'],16)==local-0x180
    assert callbacks[0]['unsigned_X0_equals_nested_VM_result'] is callbacks[0]['exact_four_byte_result_store_and_padding_preserved'] is True
    assert callbacks[1]['native_acquisition_body_executed'] is False
    assert callbacks[1]['implementation']=='inherited controlled JNI acquisition provider'
    assert callbacks[-1]['VM_cursor_offset']=='0x10a558'
    assert all(callbacks[-1][key] is False for key in ('VM_call_executed','wrapper_entered','target_entered','returned'))
    acquisition=row['controlled_JNI_effects'];assert len(acquisition)==1
    assert acquisition[0]==dict(kind='inherited controlled JNI acquisition provider',entry_index=6466,return_index=6467,
        write_width=8,output_pair_address='0x7004b748',output_pair_tail_preserved=True,
        environment_matches_declared_control=True,declared_status_x0=0,descriptor_preserved=True,
        native_acquisition_body_executed=False,real_ART_JVM_execution=False)
    events=row['new_allocator_events'];assert len(events)==2
    assert events[0][:2]==['alloc',8] and events[0][3]=='0x248388' and events[1]==['free',events[0][2]]
    assert row['allocator_aux_events']==row['new_SVCs']==row['new_providers']==[]
    counts=dict(parent['case_result']['actual_allocator_counts']);counts['malloc']+=1;counts['free']+=1
    assert row['actual_allocator_counts']==counts
    assert row['explicit_service_counts']==parent['case_result']['explicit_service_counts']
    assert not {'registers','decoded_contents','decoded_content_hash','observation_sites','native_writes'}&set(row)
    controls=data['component_controls']
    assert set(controls)=={'frames','returns','caller_guards','wrapper_guards','return_guards'}
    assert [(c['image_base'],c['case']) for c in controls['frames']]==[
        (hex(base),label) for base in frame_fixture.BASES for label in FRAME_PROFILES]
    assert [(c['image_base'],c['case']) for c in controls['returns']]==[
        (hex(base),label) for base in return_fixture.BASES for label in RETURN_PROFILES]
    for c in controls['frames']+controls['returns']:
        for key,value in c.items():
            if type(value) is bool:assert value is (key not in {'native_snapshot_input','complete_helper_VM_verified'})
    assert [c['case'] for c in controls['caller_guards']]==[
        'unaligned_stack','underflow_stack','tagged_return','wide_saved_word','unknown_helper','missing_TLS','missing_frame','missing_bytecode']
    assert [c['case'] for c in controls['wrapper_guards']]==['wrong_target','missing_packed','tagged_return']
    assert [c['case'] for c in controls['return_guards']]==[
        'unknown_wrapper','bool_wrapper','wrong_helper','unaligned_stack','missing_frame','missing_TLS','canary_mismatch',
        'old_helper_LR','tagged_wrapper_LR','missing_result','wrong_exit_pc','wrong_exit_word','old_exit_target','unknown_exit_wrapper']
    assert all(c['rejected'] is c['all_pages_unchanged'] is True
        for name in ('caller_guards','wrapper_guards','return_guards') for c in controls[name])


def validate(data):
    parent=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(parent)
    _validate(data,parent)


def damaged_evidence_rejected(data):
    parent=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(parent)
    changes=[(('claims','real_ART_JVM_execution'),True),
        (('providers','real_jni_acquisition'),True),
        (('source_fingerprints','native_oracle_sha256'),'0'*64),
        (('case_result','parent_case_equal'),False),
        (('case_result','helper_returned'),False),
        (('case_result','entries',1,'undefined_result_word_compared'),True),
        (('case_result','entries',2,'initialized_virtual_slots'),list(range(32))),
        (('case_result','callbacks',1,'native_acquisition_body_executed'),True),
        (('case_result','controlled_JNI_effects',0,'write_width'),16),
        (('case_result','controlled_JNI_effects',0,'output_pair_tail_preserved'),False),
        (('case_result','protected_JSON_write_observations'),1),
        (('case_result','callbacks',-1,'target_entered'),True),
        (('case_result','new_providers'),['guessed']),
        (('case_result','decoded_contents_and_hashes_exported'),True),
        (('case_result','registers'),{'raw':'forbidden'}),
        (('component_controls','frames',0,'five_VM_arguments_equal'),False),
        (('component_controls','returns',0,'native_snapshot_input'),True),
        (('component_controls','return_guards',0,'rejected'),False)]
    for path,value in changes:
        bad=deepcopy(data);target=bad
        for key in path[:-1]:target=target[key]
        target[path[-1]]=value
        if path[0]=='case_result':bad['case_result_sha256']=digest(bad['case_result'])
        try:_validate(bad,parent)
        except (AssertionError,KeyError,ValueError,TypeError,IndexError):continue
        raise AssertionError('damaged helper-entry evidence accepted: '+repr(path))
    return len(changes)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf',type=Path);parser.add_argument('--libc',type=Path)
    parser.add_argument('--compare-case',type=Path,help='independent redacted case, capture only')
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
            assert data['case_result']==reference,'independent and public helper cases differ'
        validate(data);rejected=damaged_evidence_rejected(data)
        with EVIDENCE.open('x',encoding='utf-8',newline='\n') as stream:stream.write(json.dumps(data,indent=2)+'\n')
    else:
        data=json.loads(EVIDENCE.read_text(encoding='utf-8'));validate(data)
        rejected=damaged_evidence_rejected(data)
        if args.replay:assert run(args.elf,args.libc)==data,'fresh helper-entry replay differs'
    print(json.dumps(dict(schema=SCHEMA,helper_returned=data['case_result']['helper_returned'],
        completed_callbacks=data['case_result']['completed_callbacks'],
        damaged_evidence_rejected=rejected,complete_standalone_signer_verified=False)))


if __name__=='__main__':
    main()
