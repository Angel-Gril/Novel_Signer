"""Verify three native JSON-building callbacks after retained string cleanup.

This is a native oracle, not a Python signer. It admits at most four completed
VM callbacks, guards new host boundaries, and never supplies a guessed return.
"""
from __future__ import annotations
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import verify_vm9_native_171_post_crc_base_string_destructor_return_dynamic_20261123 as previous
from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as arm

VM_CALL, VM_RESUME = previous.VM_CALL, previous.VM_RESUME
LIBC_BASE = previous.LIBC_BASE
WRAPPER, TARGET = 0x28883C, 0x261404
MAX_CALLBACKS, MAX_INSTRUCTIONS = 4, 180000
ALLOWED_PLT = {0x347FD0,0x347FA0,0x347F20,0x347F60,0x348410,
               0x347F00,0x347F10,0x347EC0,0x347ED0,0x347EE0,0x347EF0,0x347F40,0x348310}
ALLOWED_SVC = {98,113,169,172,173,178,214,215,222,226}
raw_hash, digest = previous.raw_hash, previous.digest
sha256 = previous.sha256
EVIDENCE = previous.EVIDENCE.with_name('vm9_native_171_json_suffix_window_dynamic_20261124.json')
SCHEMA = 'vm9-native-171-json-suffix-window-dynamic-20261124-v1'
import verify_vm9_second_json_empty_fresh_20261016 as json_fixture
import verify_vm9_second_global_u32_fresh_20261016 as word_fixture
import verify_vm9_second_json_number_fresh_20261016 as number_fixture
import vm9_configuration_init as configuration
NUMBER_PROFILES = ('zero','large_uint','single_child','cross_allocation','node_failure','key_failure')


def bootstrap():
    module = previous
    for _ in range(100):
        if hasattr(module, 'bootstrap_prefix'):
            return module.bootstrap_prefix()
        module = module.previous
    raise AssertionError('unbounded predecessor module chain')


class UnsafeBoundary(RuntimeError):
    pass


class JsonSuffixWindow(previous.PostCRCBaseStringDestructorScenario):
    def __init__(self, control):
        super().__init__(control)
        self._jwx_active = self._jwx_done = False
        self._jwx_sites, self._jwx_code, self._jwx_writes = [], {}, []
        self._jwx_calls, self._jwx_aux, self._jwx_svc, self._jwx_bindings = [], [], [], []
        self._jwx_current = None
        self._jwx_stop_reason = None
        self._jwx_typed_output = None
        self._jwx_legacy_bypasses = []
        self._jwx_global_relation = None

    def _base_observe(self, cpu, pc, state):
        if self._jwx_active and pc == self.image + 0x288648:
            call = self._jwx_current
            assert call is not None and call['wrapper_entered'] and not call['returned']
            descriptor = int(call['descriptor_address'], 16)
            assert self._reg(cpu, 0) == self._reg(cpu, 19) == descriptor
            assert self._reg(cpu, 8) == self._u(cpu, descriptor)
            assert self._reg(cpu, 8) == self.image + int(call['target_offset'], 16)
            assert call['wrapper_offset'] == '0x28863c'
            if call['target_offset'] != '0x1c3018':
                self._jwx_stop(cpu, 'uncovered_shared_wrapper_callback_before_BLR')
                return
            assert bytes(cpu.mem_read(pc, 4)).hex() == '00013fd6'
            self._jwx_legacy_bypasses.append(dict(index=len(self._jwx_sites),
                PC=self._fmt_site(pc), target_offset=call['target_offset'],
                descriptor_and_actual_X8_equal=True, guessed_return_supplied=False))
            # Keep the historical gettimeofday observer's shared-PC stop and
            # its saved continuation fields out of this admitted new callback.
            bootstrap().digest.Scenario.observe(self, cpu, pc, state)
            return
        return super()._base_observe(cpu, pc, state)

    def _jwx_track(self, cpu, pc):
        key = self._fmt_site(pc)
        self._jwx_sites.append(key)
        self._jwx_code[key] = bytes(cpu.mem_read(pc,4)).hex()

    def _jwx_stop(self, cpu, reason):
        self._jwx_done = True
        self._jwx_stop_reason = reason
        cpu.emu_stop()
        cpu.reg_write(arm.UC_ARM64_REG_PC, previous.previous.previous.controls.oracle.STOP)

    def _jwx_executable(self, address):
        return address % 4 == 0 and any(a <= address < b for a,b in self._jwx_exec)

    def _jwx_descriptor(self, cpu, pc):
        address = self._reg(cpu,0); raw = bytes(cpu.mem_read(address,48))
        wrapper, target = self._reg(cpu,8), int.from_bytes(raw[:8],'little')
        known={'destroyed_string_storage':self._pcb_object,'retired_string_payload_storage':self._pcb_payload}
        if self._jwx_typed_output:
            for key in ('output_reference_address','wrapper_address','counter_address','root_address'):
                if key in self._jwx_typed_output:known['initial_JSON_'+key]=int(self._jwx_typed_output[key],16)
        relations={str(i):[name for name,value in known.items() if value and value==int.from_bytes(raw[i*8:i*8+8],'little')]
                   for i in range(1,6)}
        return dict(index=len(self._jwx_sites), VM_cursor_offset=hex(self._u(cpu,self._postalloc_vmstate)-self.image),
            descriptor_address=hex(address),descriptor_width=48,descriptor_sha256=raw_hash(raw),
            wrapper_offset=hex(wrapper-self.image),target_offset=hex(target-self.image),
            wrapper_admitted=self._jwx_executable(wrapper),target_admitted=self._jwx_executable(target),
            defined_operand_relations={key:value for key,value in relations.items() if value},
            SP=hex(cpu.reg_read(arm.UC_ARM64_REG_SP)),callee_saved_sha256=self._idctor_saved_hash(cpu),
            VM_call_executed=False,wrapper_entered=False,target_entered=False,returned=False)

    def _jwx_source(self, cpu, address):
        if address == 0:
            return dict(address='0x0',kind='NULL',bounded=True,length=None,empty_json_model_covers_source=True)
        data=bytearray()
        try:
            for i in range(4097):
                value=bytes(cpu.mem_read(address+i,1))[0]
                if value==0: break
                data.append(value)
            else:
                return dict(address=hex(address),kind='unterminated_or_over_bound',bounded=False,length=None,empty_json_model_covers_source=False)
        except Exception:
            return dict(address=hex(address),kind='unmapped',bounded=False,length=None,empty_json_model_covers_source=False)
        offset=3 if len(data)>=5 and data[:3]==b'\xef\xbb\xbf' else 0
        while offset<len(data) and 0<data[offset]<=32:offset+=1
        empty=False
        if offset<len(data) and data[offset]==123:
            offset+=1
            while offset<len(data) and 0<data[offset]<=32:offset+=1
            empty=offset<len(data) and data[offset]==125
        return dict(address=hex(address),kind='empty_object_prefix' if empty else 'other_bounded_source',
                    bounded=True,length=len(data),empty_json_model_covers_source=empty)

    def _jwx_start(self, cpu, pc, state):
        self._pcb_track(cpu,pc);self._pcb_snapshot(cpu,pc,'before_next_VM_call')
        self._pcb_next=previous.previous.next_call(cpu,self,len(self._pcb_sites))
        assert self._pcb_next==self._jwx_parent['case_result']['next_VM_call']
        self._pcb_done,self._pcb_active=True,False
        self._jwx_events=deepcopy(state['allocator_events_ref'])
        self._jwx_initial_late=deepcopy(self.late_jni_calls)
        self._jwx_initial_java=deepcopy(self.java_dispatch_calls)
        self._jwx_retained=deepcopy(self._pcb_fixed)
        self._jwx_active=True
        self._jwx_track(cpu,pc)
        call=self._jwx_descriptor(cpu,pc);self._jwx_calls.append(call);self._jwx_current=call
        assert call['wrapper_offset']==hex(WRAPPER) and call['target_offset']==hex(TARGET)
        descriptor=self._reg(cpu,0);out=self._u(cpu,descriptor+8);source=self._u(cpu,descriptor+16)
        overlaps=[label for label,a,n in self._jwx_retained if out<a+n and a<out+16]
        released_labels={'cleared_object_pointer_slot','post_store_reference_counter_pointer_slot'}
        overlap_admitted=not overlaps or set(overlaps)<=released_labels
        self._jwx_arguments=dict(output_reference_address=hex(out),output_reference_width=16,
            hidden_X8_descriptor_word_offset=8,source_descriptor_word_offset=16,source=self._jwx_source(cpu,source),
            output_overlap_labels=overlaps,output_overlap_admitted=overlap_admitted,
            malloc_hook_is_default=self._u(cpu,self.image+0x381AA0)==self.image+0x347FD0,
            free_hook_is_default=self._u(cpu,self.image+0x381AA8)==self.image+0x347FA0,
            source_contents_exported=False,source_content_hash_exported=False)
        if not self._jwx_arguments['source']['bounded'] or not overlap_admitted:
            self._jwx_stop(cpu,'uncovered_source_or_output_alias_before_JSON_call');return
        if not self._jwx_arguments['malloc_hook_is_default'] or not self._jwx_arguments['free_hook_is_default']:
            self._jwx_stop(cpu,'custom_JSON_allocation_hooks_before_call');return
        if overlaps:assert bytes(cpu.mem_read(out,16))==bytes(16)
        print('JSON source classified:',self._jwx_arguments['source']['kind'],flush=True)

    def native_runner(self,*args,**kwargs):
        old_write=kwargs['memory_write_observer']
        def write(cpu,address,size):
            if self._jwx_active:
                pc=cpu.reg_read(arm.UC_ARM64_REG_PC)
                hits=[label for label,a,n in self._jwx_retained if address<a+n and a<address+size]
                self._jwx_writes.append(dict(index=len(self._jwx_sites),PC=self._fmt_site(pc),address=hex(address),size=size,retained_regions=hits))
            if old_write:old_write(cpu,address,size)
        kwargs['memory_write_observer']=write
        return super().native_runner(*args,**kwargs)

    def _jwx_output(self,cpu,state):
        live={}
        for event in state['allocator_events_ref'][len(self._jwx_events):]:
            if event[0]=='alloc':live[event[2]]=event[1]
            elif event[0]=='free':live.pop(event[1],None)
        out=int(self._jwx_arguments['output_reference_address'],16)
        wrapper,counter=self._u(cpu,out),self._u(cpu,out+8)
        row=dict(output_reference_address=hex(out),wrapper_address=hex(wrapper),counter_address=hex(counter),
            wrapper_is_new_live_allocation=live.get(wrapper,0)>=16,counter_is_new_live_allocation=live.get(counter,0)>=4)
        if row['wrapper_is_new_live_allocation'] and row['counter_is_new_live_allocation']:
            root=self._u(cpu,wrapper+8)
            row.update(wrapper_vtable_offset=hex(self._u(cpu,wrapper)-self.image),counter_count_u32=self._u(cpu,counter,4),
                root_address=hex(root),root_is_new_live_allocation=live.get(root,0)>=64)
            if row['root_is_new_live_allocation']:
                row.update(root_type_u32=self._u(cpu,root+24,4),root_child_is_NULL=self._u(cpu,root+16)==0,
                           root_storage_sha256=raw_hash(bytes(cpu.mem_read(root,64))))
        return row

    def _jwx_guard(self,cpu,pc):
        word=int.from_bytes(bytes(cpu.mem_read(pc,4)),'little')
        if word==0xD4000001:
            number=self._reg(cpu,8)
            if number not in ALLOWED_SVC:
                self._jwx_stop(cpu,'uncovered_SVC_'+str(number));return True
            self._jwx_svc.append(dict(index=len(self._jwx_sites),PC=self._fmt_site(pc),number=number))
        if pc==self.image+0x348400:
            raise UnsafeBoundary('unexpected indirect strncmp import route; provider not executed')
        if self.image+self._jwx_plt[0]<=pc<self.image+self._jwx_plt[1] and pc-self.image not in ALLOWED_PLT:
            raise UnsafeBoundary('uncovered PLT entry before oracle provider: '+hex(pc-self.image))
        if word&0x7C000000==0x14000000:
            immediate=word&0x03FFFFFF
            if immediate&(1<<25):immediate-=1<<26
            target=pc+(immediate<<2)
            if target==self.image+0x348400:
                if word&0x80000000:cpu.reg_write(arm.UC_ARM64_REG_X30,pc+4)
                self._jwx_bindings.append(dict(index=len(self._jwx_sites),callsite=self._fmt_site(pc),
                    symbol='strncmp',matching_libc_offset=hex(self._jwx_strncmp-LIBC_BASE),python_return_supplied=False))
                cpu.reg_write(arm.UC_ARM64_REG_PC,self._jwx_strncmp);return True
            if self.image+self._jwx_plt[0]<=target<self.image+self._jwx_plt[1] and target-self.image not in ALLOWED_PLT:
                self._jwx_stop(cpu,'uncovered_PLT_before_branch_'+hex(target-self.image));return True
            if not self._jwx_executable(target):
                self._jwx_stop(cpu,'uncovered_direct_branch_target');return True
        elif word&0xFFFFFC1F in (0xD61F0000,0xD63F0000,0xD65F0000):
            register=(word>>5)&31
            target=0 if register==31 else self._reg(cpu,register)
            if not self._jwx_executable(target):
                self._jwx_stop(cpu,'uncovered_indirect_branch_target');return True
        return False

    def observe(self,cpu,pc,state):
        if not self._jwx_active:
            if self._pcb_active and self._pcb_returned and pc==self.image+VM_CALL:
                self._jwx_start(cpu,pc,state)
                if not self._jwx_done:self._base_observe(cpu,pc,state)
                return
            return super().observe(cpu,pc,state)
        self._jwx_track(cpu,pc)
        if len(self._jwx_sites)>=MAX_INSTRUCTIONS:self._jwx_stop(cpu,'instruction_budget');return
        if pc==LIBC_BASE+0x9833C:self._jwx_aux.append(dict(kind='gc',index=len(self._jwx_sites)))
        if pc==LIBC_BASE+0x97F40:self._jwx_aux.append(dict(kind='flush',index=len(self._jwx_sites)))
        call=self._jwx_current
        if pc==self.image+VM_CALL:
            if call is not None and not call['returned']:
                self._jwx_stop(cpu,'nested_VM_call_before_parent_return');return
            call=self._jwx_descriptor(cpu,pc);self._jwx_calls.append(call)
            if len(self._jwx_calls)>MAX_CALLBACKS:
                self._jwx_stop(cpu,'callback_budget_before_next_call');return
            if not call['wrapper_admitted'] or not call['target_admitted']:
                self._jwx_stop(cpu,'uncovered_VM_target');return
            self._jwx_current=call
            if call['wrapper_offset']=='0x28863c' and call['target_offset']=='0x1c3018':
                descriptor=int(call['descriptor_address'],16)
                self._jwx_global_before=bytes(cpu.mem_read(descriptor,48))
                self._jwx_global_word=bytes(cpu.mem_read(self.image+0x37A794,4))
                self._jwx_global_events=len(state['allocator_events_ref'])
                self._jwx_global_svcs=len(self._jwx_svc)
        if self._jwx_guard(cpu,pc):return
        if call is not None:
            if pc==self.image+int(call['wrapper_offset'],16):call.update(VM_call_executed=True,wrapper_entered=True)
            if pc==self.image+int(call['target_offset'],16):
                call['target_entered']=True
                if call is self._jwx_calls[0]:
                    assert self._reg(cpu,0)==int(self._jwx_arguments['source']['address'],16)
                    assert self._reg(cpu,8)==int(self._jwx_arguments['output_reference_address'],16)
                    assert cpu.reg_read(arm.UC_ARM64_REG_SP)==int(call['SP'],16)-16
                    self._jwx_arguments['actual_hidden_X8_and_source_entry_equal']=True
            if pc==self.image+VM_RESUME:
                assert cpu.reg_read(arm.UC_ARM64_REG_SP)==int(call['SP'],16)
                assert self._idctor_saved_hash(cpu)==call['callee_saved_sha256']
                call.update(returned=True,return_index=len(self._jwx_sites),caller_SP_and_callee_saved_restored=True)
                if call is self._jwx_calls[0]:
                    self._jwx_typed_output=self._jwx_output(cpu,state)
                    print('JSON constructor returned with guarded output snapshot',flush=True)
                elif call['wrapper_offset']=='0x28863c' and call['target_offset']=='0x1c3018':
                    descriptor=int(call['descriptor_address'],16)
                    expected=bytearray(self._jwx_global_before)
                    expected[8:12]=self._jwx_global_word
                    assert bytes(cpu.mem_read(descriptor,48))==expected
                    assert bytes(cpu.mem_read(self.image+0x37A794,4))==self._jwx_global_word
                    assert self._reg(cpu,0)==int.from_bytes(self._jwx_global_word,'little')
                    assert len(state['allocator_events_ref'])==self._jwx_global_events
                    assert len(self._jwx_svc)==self._jwx_global_svcs
                    self._jwx_global_relation=dict(source_offset='0x37a794',output_descriptor_offset=8,
                        output_width=4,unsigned_X0_equals_entry_global=True,global_preserved=True,
                        other_descriptor_bytes_preserved=True,no_allocation_or_free_or_SVC=True,
                        source_value_exported=False,source_value_hash_exported=False)
                    print('Global u32 callback returned; exact four-byte relation verified',flush=True)
        self._base_observe(cpu,pc,state)
        if self.late_jni_calls!=self._jwx_initial_late or self.java_dispatch_calls!=self._jwx_initial_java:
            self._jwx_stop(cpu,'inherited_controlled_JNI_boundary_reached')

    def finish(self,result,state,proof):
        assert self._jwx_done
        delta=result['allocator_events'][len(self._jwx_events):]
        prefix,counts,services=dict(result),deepcopy(result['actual_allocator_counts']),deepcopy(result['explicit_service_counts'])
        for event in delta:counts['malloc' if event[0]=='alloc' else 'free']-=1
        for event in self._jwx_aux:counts[event['kind']]-=1
        for event in self._jwx_svc:services['syscall_'+str(event['number'])]-=1
        prefix.update(allocator_events=self._jwx_events,actual_allocator_counts=counts,explicit_service_counts=services)
        prefix_proof=dict(proof)
        prefix_proof['libc_SVC_boundaries']=proof['libc_SVC_boundaries'][:len(self._jwx_parent['case_result']['final_libc_SVC'])]
        prefix_proof['main_image_SVC_boundaries']=proof['main_image_SVC_boundaries'][:len(self._jwx_parent['case_result']['final_main_SVC'])]
        old=super().finish(prefix,state,prefix_proof)
        assert old==self._jwx_parent['case_result'],'full base-destructor prefix differs'
        h=hashlib.sha256()
        for key in self._jwx_sites:h.update(key.encode()+bytes.fromhex(self._jwx_code[key]))
        return dict(parent_case_result_equal=True,parent_case_result_sha256=digest(old),arguments=self._jwx_arguments,
            instruction_observations=len(self._jwx_sites),instruction_trace_sha256=h.hexdigest(),
            callbacks=self._jwx_calls,stop_reason=self._jwx_stop_reason,typed_JSON_output_at_first_return=self._jwx_typed_output,
            new_allocator_events=delta,new_SVC_events=self._jwx_svc,allocator_aux_events=self._jwx_aux,
            matching_native_import_bindings=self._jwx_bindings,native_writes=self._jwx_writes,
            admitted_legacy_stop_bypasses=self._jwx_legacy_bypasses,global_u32_relation=self._jwx_global_relation,
            observation_sites=self._jwx_sites,observed_code=self._jwx_code,
            actual_allocator_counts=result['actual_allocator_counts'],explicit_service_counts=result['explicit_service_counts'],
            complete_standalone_signer_verified=False,online_acceptance_verified=False)


def public_case(row):
    """Publish typed relations and compact ledgers, omitting the private trace."""
    result = {key: deepcopy(row[key]) for key in (
        'parent_case_result_equal', 'parent_case_result_sha256', 'arguments',
        'instruction_observations', 'instruction_trace_sha256', 'callbacks',
        'stop_reason', 'typed_JSON_output_at_first_return', 'new_allocator_events',
        'new_SVC_events', 'allocator_aux_events', 'matching_native_import_bindings',
        'admitted_legacy_stop_bypasses', 'global_u32_relation',
        'actual_allocator_counts', 'explicit_service_counts',
        'complete_standalone_signer_verified', 'online_acceptance_verified')}
    result['typed_JSON_output_at_first_return'].pop('root_storage_sha256', None)
    result['observed_code_sha256'] = digest(row['observed_code'])
    result['native_write_summary'] = dict(observations=len(row['native_writes']),
        touched_retained_labels=sorted({label for event in row['native_writes'] for label in event['retained_regions']}),
        values_exported=False)
    result['completed_callbacks'] = sum(call['returned'] for call in row['callbacks'])
    return result


def claims():
    return dict(evidence_label='Sample verified', full_parent_case_result_equal=True,
        original_empty_JSON_reference_returned=True, original_global_u32_callback_returned=True,
        original_JSON_number_callback_returned=True,
        existing_component_models_reused=True, native_snapshot_used_as_model_input=False,
        raw_source_or_source_hash_exported=False, raw_global_word_or_hash_exported=False,
        raw_descriptor_or_register_dump_exported=False, allocation_contents_exported=False,
        complete_JSON_parser_verified=False, standalone_Python_VM_continuation_verified=False,
        complete_VM_suffix_return_verified=False, complete_standalone_signer_verified=False,
        real_ART_JVM_execution=False, Android_execution=False, online_acceptance_verified=False)


def providers():
    return dict(inherited_evidence_sha256=sha256(previous.EVIDENCE),
        allowed_main_PLT_offsets=sorted(hex(value) for value in ALLOWED_PLT),
        allowed_SVC_numbers=sorted(ALLOWED_SVC), maximum_callbacks=MAX_CALLBACKS,
        maximum_new_phase_instructions=MAX_INSTRUCTIONS,
        main_allocations='matching original Bionic allocator',
        component_allocations='explicit synthetic effects from existing fixtures',
        mutex_init='existing original matching Bionic provider',
        strlen='existing bounded host provider',
        strncmp='matching Bionic export, bound only when an observed direct branch requires it',
        legacy_stop_bypass='only active +28863c -> +1c3018 with actual X8 and descriptor equality',
        original_code_execution_is_not_independent_Python_VM=True)


def sources():
    return dict(verifier_sha256=sha256(Path(__file__)),
        parent_sha256=sha256(Path(previous.__file__)), parent_chain_sha256=digest(previous.sources()),
        empty_JSON_fixture_sha256=sha256(Path(json_fixture.__file__)),
        global_u32_fixture_sha256=sha256(Path(word_fixture.__file__)),
        JSON_number_fixture_sha256=sha256(Path(number_fixture.__file__)),
        component_oracle_sha256=sha256(Path(json_fixture.oracle.__file__)),
        configuration_model_sha256=sha256(Path(configuration.__file__)),
        request_VM_model_sha256=sha256(Path(word_fixture.model.__file__)))


def run(path, libc):
    parent=json.loads(previous.EVIDENCE.read_text(encoding='utf-8')); previous.validate(parent)
    scope_parent=previous.parent_evidence(); md5_parent=previous.previous.parent_evidence()
    prefix=bootstrap(); prefix.digest.verify_images(path,libc)
    executable=[]
    for image_path,base in ((path,prefix.CONTROL['base']),(libc,LIBC_BASE)):
        with image_path.open('rb') as stream:
            elf=ELFFile(stream)
            executable.extend((base+s['p_vaddr'],base+s['p_vaddr']+s['p_memsz'])
                for s in elf.iter_segments() if s['p_type']=='PT_LOAD' and s['p_flags']&1)
            if image_path==path:
                section=elf.get_section_by_name('.plt'); plt=(section['sh_addr'],section['sh_addr']+section['sh_size'])
            else:
                symbol=next(s for s in elf.get_section_by_name('.dynsym').iter_symbols()
                    if s.name=='strncmp' and s['st_shndx']!='SHN_UNDEF')
                strncmp=LIBC_BASE+symbol['st_value']
    def create(control):
        scenario=JsonSuffixWindow(control)
        scenario.path,scenario.continue_to_svc=path,True
        scenario._postcrc_parent,scenario._pcb_parent,scenario._jwx_parent=md5_parent,scope_parent,parent
        scenario._jwx_exec,scenario._jwx_plt,scenario._jwx_strncmp=executable,plt,strncmp
        return scenario
    print('Replaying original ELF/Bionic prefix and bounded JSON suffix',flush=True)
    rows=prefix.digest.context.replay(path,libc,case_controls=[prefix.CONTROL],_extension_factory=create,
        _request_profile=prefix.digest.previous.previous.name.previous.previous.PROFILE['name'],
        _handler_read_profile=prefix.digest.context.NULL_PAYLOAD_READ_PROFILE['name'])
    assert len(rows)==1
    case=public_case(rows[0])
    controls=dict(empty_JSON=[json_fixture.compare(path,libc,base,label)
        for base in json_fixture.BASES for label in json_fixture.PROFILES],
        global_u32=[word_fixture.compare(path,base,label)
        for base in word_fixture.BASES for label in word_fixture.PROFILES],
        JSON_number=[number_fixture.compare(path,base,label)
        for base in number_fixture.BASES for label in NUMBER_PROFILES],
        empty_JSON_guards=json_fixture.guards(path), global_u32_guards=word_fixture.guards(path),
        JSON_number_guards=number_fixture.guards(path))
    return dict(schema=SCHEMA,claims=claims(),providers=providers(),source_fingerprints=sources(),
        parent_evidence_sha256=sha256(previous.EVIDENCE),component_controls=controls,
        case_result=case,case_result_sha256=digest(case))


# Regression fingerprint of the independently captured, redacted case only.
# It is never used as native state or a semantic-model input.
EXPECTED_CASE_SHA256 = 'fc85952262a4736666ecaa2ff9199501e1f4411923dbaa9908271ab4c2c17e0c'


def _validate(data, parent):
    assert set(data)=={'schema','claims','providers','source_fingerprints',
        'parent_evidence_sha256','component_controls','case_result','case_result_sha256'}
    assert data['schema']==SCHEMA and data['claims']==claims() and data['providers']==providers()
    assert data['source_fingerprints']==sources()
    assert data['parent_evidence_sha256']==sha256(previous.EVIDENCE)
    row=data['case_result']
    assert data['case_result_sha256']==digest(row)==EXPECTED_CASE_SHA256
    assert row['parent_case_result_equal'] is True
    assert row['parent_case_result_sha256']==digest(parent['case_result'])
    assert row['complete_standalone_signer_verified'] is row['online_acceptance_verified'] is False
    assert 0<row['instruction_observations']<=MAX_INSTRUCTIONS
    calls=row['callbacks']
    assert row['instruction_observations']==4027
    assert row['completed_callbacks']==3
    assert row['completed_callbacks']==sum(call['returned'] for call in calls)
    assert len(calls)<=MAX_CALLBACKS+1
    assert [(call['wrapper_offset'],call['target_offset']) for call in calls]==[
        ('0x28883c','0x261404'),('0x28863c','0x1c3018'),
        ('0x288854','0x261350'),('0x28863c','0x1c3024')]
    assert [call.get('return_index') for call in calls]==[1605,2180,3588,None]
    assert calls[2]['defined_operand_relations']=={'1':['initial_JSON_wrapper_address']}
    assert calls[-1]['wrapper_entered'] is calls[-1]['VM_call_executed'] is True
    assert calls[-1]['target_entered'] is calls[-1]['returned'] is False
    assert calls[-1]['VM_cursor_offset']=='0x10a4dc'
    assert row['stop_reason']=='uncovered_shared_wrapper_callback_before_BLR'
    assert calls[0]['index']==1
    prior=parent['case_result']['next_VM_call']
    for key in ('VM_cursor_offset','descriptor_address','descriptor_width','descriptor_sha256',
                'wrapper_offset','target_offset'):
        assert calls[0][key]==prior[key]
    assert calls[0]['wrapper_offset']==hex(WRAPPER) and calls[0]['target_offset']==hex(TARGET)
    for call in calls:
        assert call['descriptor_width']==48 and call['index']<=row['instruction_observations']
        if call['returned']:
            assert all(call[key] is True for key in ('VM_call_executed','wrapper_entered',
                'target_entered','caller_SP_and_callee_saved_restored','wrapper_admitted','target_admitted'))
            assert call['index']<call['return_index']<=row['instruction_observations']
    assert all(a['index']<b['index'] for a,b in zip(calls,calls[1:]))
    args=row['arguments']; source=args['source']; output=row['typed_JSON_output_at_first_return']
    assert source==dict(address='0x126a1360',kind='empty_object_prefix',bounded=True,
        length=2,empty_json_model_covers_source=True)
    assert args['hidden_X8_descriptor_word_offset']==8 and args['source_descriptor_word_offset']==16
    assert args['output_reference_width']==16 and args['output_overlap_labels']==[]
    assert args['output_overlap_admitted'] is args['actual_hidden_X8_and_source_entry_equal'] is True
    assert args['malloc_hook_is_default'] is args['free_hook_is_default'] is True
    assert args['source_contents_exported'] is args['source_content_hash_exported'] is False
    assert output['output_reference_address']==args['output_reference_address']
    assert output['wrapper_vtable_offset']=='0x35ba58' and output['counter_count_u32']==1
    assert output['root_type_u32']==64 and output['root_child_is_NULL'] is True
    assert all(output[key] is True for key in ('wrapper_is_new_live_allocation',
        'counter_is_new_live_allocation','root_is_new_live_allocation'))
    assert 'root_storage_sha256' not in output
    assert output['root_address']==parent['case_result']['arguments']['payload_address']
    assert row['global_u32_relation']==dict(source_offset='0x37a794',output_descriptor_offset=8,
        output_width=4,unsigned_X0_equals_entry_global=True,global_preserved=True,
        other_descriptor_bytes_preserved=True,no_allocation_or_free_or_SVC=True,
        source_value_exported=False,source_value_hash_exported=False)
    assert len(row['admitted_legacy_stop_bypasses'])==1
    assert row['admitted_legacy_stop_bypasses'][0]['target_offset']=='0x1c3018'
    assert row['admitted_legacy_stop_bypasses'][0]['guessed_return_supplied'] is False
    assert row['native_write_summary']['values_exported'] is False
    assert row['new_SVC_events']==row['allocator_aux_events']==row['matching_native_import_bindings']==[]
    counts=dict(parent['case_result']['actual_allocator_counts']); counts['malloc']+=7; counts['free']+=1
    assert row['actual_allocator_counts']==counts
    assert row['explicit_service_counts']==parent['case_result']['explicit_service_counts']
    assert not {'native_writes','observation_sites','observed_code','registers','raw_source',
        'source_content_hash','global_word','global_word_hash','allocation_contents'} & set(row)
    controls=data['component_controls']
    assert set(controls)=={'empty_JSON','global_u32','JSON_number',
        'empty_JSON_guards','global_u32_guards','JSON_number_guards'}
    for name,fixture,profiles in (('empty_JSON',json_fixture,json_fixture.PROFILES),
        ('global_u32',word_fixture,word_fixture.PROFILES),('JSON_number',number_fixture,NUMBER_PROFILES)):
        assert [(control['image_base'],control['case']) for control in controls[name]]==[
            (hex(base),label) for base in fixture.BASES for label in profiles]
        assert all(control['native_snapshot_input'] is False for control in controls[name])
        allowed_false={'native_snapshot_input','complete_physical_ABI_verified',
            'physical_spills_and_PAC_compared','native_physical_X0_compared'}
        for control in controls[name]:
            assert all(value is (key not in allowed_false) for key,value in control.items() if type(value) is bool)
        negatives=controls[name+'_guards']
        assert [control['case'] for control in negatives]==list(fixture.GUARDS)
        assert all(control['rejected'] is control['all_pages_unchanged'] is True for control in negatives)


def validate(data):
    parent=json.loads(previous.EVIDENCE.read_text(encoding='utf-8')); previous.validate(parent)
    _validate(data,parent)


def damaged_evidence_rejected(data):
    parent=json.loads(previous.EVIDENCE.read_text(encoding='utf-8')); previous.validate(parent)
    changes=[(('claims','complete_standalone_signer_verified'),True),
        (('providers','legacy_stop_bypass'),'all callbacks'),
        (('source_fingerprints','parent_sha256'),'0'*64),
        (('case_result','parent_case_result_equal'),False),
        (('case_result','arguments','source_content_hash_exported'),True),
        (('case_result','typed_JSON_output_at_first_return','wrapper_is_new_live_allocation'),False),
        (('case_result','typed_JSON_output_at_first_return','root_storage_sha256'),'forbidden'),
        (('case_result','global_u32_relation','output_width'),8),
        (('case_result','global_u32_relation','source_value_exported'),True),
        (('case_result','admitted_legacy_stop_bypasses',0,'guessed_return_supplied'),True),
        (('case_result','callbacks',0,'returned'),False),
        (('case_result','completed_callbacks'),MAX_CALLBACKS+1),
        (('case_result','registers'),{'raw':'forbidden'}),
        (('component_controls','global_u32_guards',0,'rejected'),False)]
    for path,value in changes:
        bad=deepcopy(data); target=bad
        for key in path[:-1]: target=target[key]
        target[path[-1]]=value
        if path[0]=='case_result': bad['case_result_sha256']=digest(bad['case_result'])
        try: _validate(bad,parent)
        except (AssertionError,KeyError,ValueError,TypeError,IndexError): continue
        raise AssertionError('damaged JSON window evidence accepted: '+repr(path))
    return len(changes)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf',type=Path); parser.add_argument('--libc',type=Path)
    parser.add_argument('--compare-case',type=Path,help='independent private case, capture only')
    modes=parser.add_mutually_exclusive_group()
    modes.add_argument('--capture',action='store_true'); modes.add_argument('--replay',action='store_true')
    args=parser.parse_args()
    if (args.capture or args.replay) and (args.elf is None or args.libc is None):
        parser.error('--capture and --replay require --elf and --libc')
    if args.compare_case is not None and not args.capture: parser.error('--compare-case requires --capture')
    if args.capture:
        if EVIDENCE.exists(): raise FileExistsError('frozen evidence exists; refusing overwrite')
        data=run(args.elf,args.libc)
        if args.compare_case is not None:
            reference=json.loads(args.compare_case.read_text(encoding='utf-8'))
            if isinstance(reference,list): assert len(reference)==1; reference=reference[0]
            if 'observation_sites' in reference: reference=public_case(reference)
            assert data['case_result']==reference,'independent probe and public case differ'
        validate(data); rejected=damaged_evidence_rejected(data)
        with EVIDENCE.open('x',encoding='utf-8',newline='\n') as stream:
            stream.write(json.dumps(data,indent=2)+'\n')
    else:
        data=json.loads(EVIDENCE.read_text(encoding='utf-8')); validate(data)
        rejected=damaged_evidence_rejected(data)
        if args.replay: assert run(args.elf,args.libc)==data,'fresh replay differs'
    print(json.dumps(dict(schema=SCHEMA,completed_callbacks=data['case_result']['completed_callbacks'],
        instruction_observations=data['case_result']['instruction_observations'],
        damaged_evidence_rejected=rejected,complete_standalone_signer_verified=False)))


if __name__=='__main__':
    main()
