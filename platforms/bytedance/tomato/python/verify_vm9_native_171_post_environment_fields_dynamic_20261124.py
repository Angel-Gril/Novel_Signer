"""Native relational checks for two numeric fields after the environment helper."""
from __future__ import annotations
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import struct
import verify_vm9_native_171_environment_entry_dynamic_20261124 as previous
from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as arm
bootstrap=previous.bootstrap
VM_CALL,VM_RESUME,LIBC_BASE=previous.VM_CALL,previous.VM_RESUME,previous.LIBC_BASE
ALLOWED_PLT=previous.previous.previous.ALLOWED_PLT
UnsafeBoundary=previous.previous.previous.UnsafeBoundary
digest,raw_hash,sha256=previous.digest,previous.raw_hash,previous.sha256
import verify_vm9_second_global_u32_c_fresh_20261016 as word_fixture
import verify_vm9_second_json_number_fresh_20261016 as number_fixture
from vm9_allocator import _read_span, _write_span
EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_post_environment_fields_dynamic_20261124.json')
SCHEMA='vm9-native-171-post-environment-fields-dynamic-20261124-v1'
LIST_COUNTS=(2,3)
NUMBER_VALUES=('zero','u32max')
MAX_CALLS,MAX_INSTRUCTIONS=3,100000


class PostEnvironmentFields(previous.EnvironmentEntryScenario):
    def __init__(self,control):
        super().__init__(control)
        self._jst_active=self._jst_done=False
        self._jst_flows=[];self._jst_pending=None
        self._jst_sites,self._jst_code,self._jst_writes=[],{},[]
        self._jst_calls,self._jst_aux=[],[]
        self._jst_stop_reason=None

    def _jst_index(self):
        return dict(window='suffix' if self._jst_active else 'environment_prefix',
            index=len(self._jst_sites) if self._jst_active else len(self._jev_sites)+1)

    def _jst_begin(self,label,word,source):
        assert self._jst_pending is None or self._jst_pending['public']['node_verified']
        row=dict(label=label,source=source,conversion={},argument={},node={},node_verified=False,
            scalar_values_exported=False,scalar_hashes_exported=False)
        self._jst_flows.append(row)
        self._jst_pending=dict(public=row,word=bytes(word),bits=struct.pack('<d',float(int.from_bytes(word,'little'))))

    def _jst_track(self,cpu,pc):
        key=self._fmt_site(pc);self._jst_sites.append(key);self._jst_code[key]=bytes(cpu.mem_read(pc,4)).hex()

    def _jst_stop(self,cpu,reason):
        self._jst_done=True;self._jst_stop_reason=reason
        cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,bootstrap().digest.context.outer.oracle.STOP)

    def _jst_call(self,cpu):
        descriptor=self._reg(cpu,0);vmstate=self._reg(cpu,19)
        return dict(index=len(self._jst_sites),descriptor_address=hex(descriptor),descriptor_width=48,
            wrapper_offset=hex(self._reg(cpu,8)-self.image),target_offset=hex(self._u(cpu,descriptor)-self.image),
            VM_cursor_offset=hex(self._u(cpu,vmstate)-self.image),SP=hex(cpu.reg_read(arm.UC_ARM64_REG_SP)),
            callee_saved_sha256=self._idctor_saved_hash(cpu),VM_call_executed=False,wrapper_entered=False,
            target_entered=False,returned=False)

    def _jev_stop(self,cpu,reason):
        if reason!='next_outer_VM_call_before_execution':return super()._jev_stop(cpu,reason)
        assert not self._jst_active and len(self._jev_sites)==15291
        assert self._jev_root_returned and cpu.reg_read(arm.UC_ARM64_REG_PC)==self.image+VM_CALL
        assert all(bytes(cpu.mem_read(a,len(data)))==data for _,a,data in self._jev_retained)
        self._jev_retained_verified=True;self._jev_done=True;self._jev_stop_reason=reason;self._jev_active=False
        assert self._jst_pending['public']['source']['ABI_result_copy_verified']
        assert self._jst_pending['public']['conversion']['stored_binary64_equal']
        self._jst_events=deepcopy(self._jst_state['allocator_events_ref'])
        self._jst_active=True;self._jst_track(cpu,self.image+VM_CALL)
        call=self._jst_call(cpu);self._jst_calls.append(call);self._jst_current=call
        assert (call['wrapper_offset'],call['target_offset'])==('0x288854','0x261350')
        self._jst_number_arguments(cpu,self._jst_state)
        self._base_observe(cpu,self.image+VM_CALL,self._jst_state)
        print('Retained environment helper checkpoint; executing next numeric field',flush=True)

    def _base_observe(self,cpu,pc,state):
        if self._jst_active and pc==self.image+0x288648:
            call=self._jst_current;descriptor=int(call['descriptor_address'],16)
            assert (call['wrapper_offset'],call['target_offset'])==('0x28863c','0x1e53d0')
            assert self._reg(cpu,0)==self._reg(cpu,19)==descriptor
            assert self._reg(cpu,8)==self._u(cpu,descriptor)==self.image+0x1E53D0
            bootstrap().digest.Scenario.observe(self,cpu,pc,state);return
        return super()._base_observe(cpu,pc,state)

    def native_runner(self,*args,**kwargs):
        old_write=kwargs['memory_write_observer']
        def write(cpu,address,size):
            if self._jst_active:
                self._jst_writes.append(dict(index=len(self._jst_sites),PC=self._fmt_site(cpu.reg_read(arm.UC_ARM64_REG_PC)),
                    address=hex(address),size=size))
            if old_write:old_write(cpu,address,size)
        kwargs['memory_write_observer']=write
        return super().native_runner(*args,**kwargs)

    def _jst_conversion(self,cpu,pc):
        flow=self._jst_pending
        if flow is None or flow['public']['node_verified']:return
        row=flow['public'];off=pc-self.image
        bits=lambda:cpu.reg_read(arm.UC_ARM64_REG_D0).to_bytes(8,'little')
        if off==0x17079C:
            assert row['conversion']=={}
            source=self._reg(cpu,9);assert bytes(cpu.mem_read(source,4))==flow['word']
            row['conversion'].update(source_address=hex(source),load_site=hex(off),source_low_u32_equal=True,**self._jst_index())
        elif off==0x1707AC:
            assert row['conversion']['source_low_u32_equal'] and bits()==flow['word']+bytes(4)
            row['conversion'].update(convert_site=hex(off),unsigned_zero_extension_equal=True)
        elif off==0x1707B0:
            assert bits()==flow['bits'];row['conversion']['exact_binary64_equal']=True
        elif off==0x1707F8:
            assert row['conversion']['exact_binary64_equal'] and bits()==flow['bits']
            flow['destination']=self._reg(cpu,9)
        elif off==0x1707FC:
            assert bytes(cpu.mem_read(flow['destination'],8))==flow['bits']
            row['conversion'].update(destination_address=hex(flow['destination']),store_site='0x1707f8',stored_binary64_equal=True)

    def _jst_number_arguments(self,cpu,state):
        flow=self._jst_pending;row=flow['public'];assert row['conversion']['stored_binary64_equal']
        descriptor=self._reg(cpu,0);before=bytes(cpu.mem_read(descriptor,48))
        assert self._reg(cpu,8)==self.image+0x288854 and self._u(cpu,descriptor)==self.image+0x261350
        wrapper,key=self._u(cpu,descriptor+8),self._u(cpu,descriptor+16)
        assert wrapper==int(self._jwx_typed_output['wrapper_address'],16) and before[24:32]==flow['bits']
        root=self._u(cpu,wrapper+8);counter=int(self._jwx_typed_output['counter_address'],16)
        live=self._jff_live(state)
        assert live.get(wrapper,0)>=16 and live.get(root,0)>=64 and live.get(counter,0)>=4
        assert root==int(self._jwx_typed_output['root_address'],16) and self._u(cpu,root+24,4)==64
        assert self._u(cpu,counter,4)==1
        nodes=[];node=self._u(cpu,root+16);seen=set()
        while node:
            assert node not in seen and len(nodes)<32 and live.get(node,0)>=64
            seen.add(node);raw=bytes(cpu.mem_read(node,64));assert self._u(cpu,node+24,4)==8
            owned=self._u(cpu,node+56);payload=self._bounded_cstring(cpu,owned,limit=4096)+b'\0'
            assert live.get(owned,0)>=len(payload)
            nodes.append((node,raw,owned,payload));node=self._u(cpu,node)
        assert nodes and self._u(cpu,nodes[0][0]+8)==nodes[-1][0]
        assert all(self._u(cpu,nodes[i][0]+8)==nodes[i-1][0] for i in range(1,len(nodes)))
        flow.update(descriptor=descriptor,before=before,wrapper=wrapper,key=key,root=root,counter=counter,
            wrapper_before=bytes(cpu.mem_read(wrapper,16)),root_before=bytes(cpu.mem_read(root,64)),
            counter_before=bytes(cpu.mem_read(counter,4)),old_nodes=nodes,
            key_bytes=self._bounded_cstring(cpu,key,limit=4096),allocation_index=len(state['allocator_events_ref']))
        row['argument'].update(descriptor_address=hex(descriptor),prior_child_count=len(nodes),
            initial_JSON_wrapper_verified=True,binary64_equals_conversion=True,key_contents_or_hashes_exported=False,
            **self._jst_index())

    def _jst_number_return(self,cpu,state):
        flow=self._jst_pending;row=flow['public'];live=self._jff_live(state)
        expected=bytearray(flow['before']);expected[32]=1
        assert bytes(cpu.mem_read(flow['descriptor'],48))==expected
        assert bytes(cpu.mem_read(flow['wrapper'],16))==flow['wrapper_before']
        assert bytes(cpu.mem_read(flow['root'],64))==flow['root_before']
        assert bytes(cpu.mem_read(flow['counter'],4))==flow['counter_before']
        old=flow['old_nodes'];head,tail=old[0][0],old[-1][0]
        node=self._u(cpu,head+8)
        fresh={e[2]:e[1] for e in state['allocator_events_ref'][flow['allocation_index']:] if e[0]=='alloc'}
        assert node not in {a for a,_,_,_ in old} and fresh.get(node,0)>=64 and live.get(node,0)>=64
        assert self._u(cpu,node,8)==0 and self._u(cpu,node+8)==tail and self._u(cpu,node+24,4)==8
        assert bytes(cpu.mem_read(node+48,8))==flow['bits']
        assert int.from_bytes(cpu.mem_read(node+40,4),'little',signed=True)==min(int.from_bytes(flow['word'],'little'),0x7FFFFFFF)
        owned=self._u(cpu,node+56)
        assert fresh.get(owned,0)>=len(flow['key_bytes'])+1 and live.get(owned,0)>=len(flow['key_bytes'])+1
        assert self._bounded_cstring(cpu,owned,limit=4096)==flow['key_bytes']
        for address,raw,key,payload in old:
            expected=bytearray(raw)
            if address==head:expected[8:16]=node.to_bytes(8,'little')
            if address==tail:expected[:8]=node.to_bytes(8,'little')
            assert bytes(cpu.mem_read(address,64))==expected
            assert bytes(cpu.mem_read(key,len(payload)))==payload
        row['node'].update(address=hex(node),root_address=hex(flow['root']),prior_child_count=len(old),
            new_live_node_and_key_allocations=True,binary64_equals_source_conversion=True,int32_saturation_equal=True,
            copied_key_equal=True,old_nodes_and_owned_keys_preserved_except_append_links=True,
            root_wrapper_and_counter_preserved=True,one_byte_success_store_and_other_descriptor_bytes_preserved=True,
            **self._jst_index())
        row['node_verified']=True
        print('Verified appended numeric field:',row['label'],'prior children',len(old),flush=True)

    def _jst_guard(self,cpu,pc):
        if pc==self.image+0x26E70C:raise UnsafeBoundary('unadmitted JNI dispatcher entry')
        word=int.from_bytes(cpu.mem_read(pc,4),'little')
        if word==0xD4000001:self._jst_stop(cpu,'new_SVC_before_execution');return True
        if self.image+self._jwx_plt[0]<=pc<self.image+self._jwx_plt[1] and pc-self.image not in ALLOWED_PLT:
            raise UnsafeBoundary('unadmitted post-environment PLT entry')
        target=None
        if word&0x7C000000==0x14000000:
            n=word&0x3FFFFFF
            if n&(1<<25):n-=1<<26
            target=pc+(n<<2)
        elif word&0xFFFFFC1F in (0xD61F0000,0xD63F0000,0xD65F0000):
            register=(word>>5)&31;target=0 if register==31 else self._reg(cpu,register)
        if target is not None:
            if target==self.image+0x26E70C:self._jst_stop(cpu,'JNI_dispatch_before_branch');return True
            if not self._jwx_executable(target):self._jst_stop(cpu,'external_branch_before_execution');return True
            if self.image+self._jwx_plt[0]<=target<self.image+self._jwx_plt[1] and target-self.image not in ALLOWED_PLT:
                self._jst_stop(cpu,'uncovered_PLT_before_branch');return True
        return False

    def observe(self,cpu,pc,state):
        if not self._jst_active:
            if self._jev_active:
                self._jst_state=state
                self._jst_conversion(cpu,pc)
                result=super().observe(cpu,pc,state)
                if pc==self.image+0x204EAC:
                    self._jst_begin('environment_result',self._jev_result_word,
                        dict(kind='helper_result',capture_site='0x204eac',capture_index=len(self._jev_sites),
                            captured_while_frame_live=True,ABI_result_copy_verified=False))
                if pc==self.image+VM_RESUME and self._jev_root_returned and self._jst_pending is not None:
                    self._jst_pending['public']['source']['ABI_result_copy_verified']=True
                return result
            return super().observe(cpu,pc,state)
        self._jst_state=state;self._jst_track(cpu,pc)
        if len(self._jst_sites)>=MAX_INSTRUCTIONS:self._jst_stop(cpu,'instruction_budget');return
        if pc in (LIBC_BASE+0x9833C,LIBC_BASE+0x97F40):
            self._jst_aux.append(dict(index=len(self._jst_sites),kind='gc' if pc==LIBC_BASE+0x9833C else 'flush'))
        call=self._jst_current
        if pc==self.image+VM_CALL:
            assert call['returned'],'nested callback outside this bounded numeric stage'
            call=self._jst_call(cpu);self._jst_calls.append(call)
            if len(self._jst_calls)>MAX_CALLS:self._jst_stop(cpu,'callback_budget_before_next_call');return
            pair=call['wrapper_offset'],call['target_offset']
            if pair not in (('0x288854','0x261350'),('0x28863c','0x1e53d0')):
                self._jst_stop(cpu,'uncovered_VM_callback_before_execution');return
            self._jst_current=call
            if pair==('0x288854','0x261350'):self._jst_number_arguments(cpu,state)
            else:
                descriptor=int(call['descriptor_address'],16)
                self._jst_global_before=bytes(cpu.mem_read(descriptor,48))
                self._jst_global_word=bytes(cpu.mem_read(self.image+0x3D60D4,4))
                self._jst_global_events=len(state['allocator_events_ref'])
        if self._jst_guard(cpu,pc):return
        self._jst_conversion(cpu,pc)
        if pc==self.image+int(call['wrapper_offset'],16):call.update(VM_call_executed=True,wrapper_entered=True)
        if pc==self.image+int(call['target_offset'],16):
            call['target_entered']=True
            if call['target_offset']=='0x261350':
                flow=self._jst_pending
                assert self._reg(cpu,0)==flow['wrapper'] and self._reg(cpu,1)==flow['key']
                assert cpu.reg_read(arm.UC_ARM64_REG_D0).to_bytes(8,'little')==flow['bits']
                flow['public']['argument']['actual_X0_X1_D0_equal']=True
        if pc==self.image+VM_RESUME:
            assert cpu.reg_read(arm.UC_ARM64_REG_SP)==int(call['SP'],16)
            assert self._idctor_saved_hash(cpu)==call['callee_saved_sha256']
            call.update(returned=True,return_index=len(self._jst_sites),caller_SP_and_callee_saved_restored=True)
            if call['target_offset']=='0x261350':self._jst_number_return(cpu,state)
            else:
                descriptor=int(call['descriptor_address'],16)
                expected=bytearray(self._jst_global_before);expected[8:12]=self._jst_global_word
                assert bytes(cpu.mem_read(descriptor,48))==expected
                assert bytes(cpu.mem_read(self.image+0x3D60D4,4))==self._jst_global_word
                assert self._reg(cpu,0)==int.from_bytes(self._jst_global_word,'little')
                assert len(state['allocator_events_ref'])==self._jst_global_events
                self._jst_begin('third_global',self._jst_global_word,
                    dict(kind='global_u32',source_offset='0x3d60d4',source_width=4,
                        original_getter_return_verified=True,exact_four_byte_write_and_padding_preserved=True,
                        global_preserved=True,no_allocation_effects=True))
        self._base_observe(cpu,pc,state)
        assert self.late_jni_calls==self._jev_initial_late and self.java_dispatch_calls==self._jev_initial_java

    def finish(self,result,state,proof):
        assert self._jst_done and len(self._jst_flows)==2 and all(r['node_verified'] for r in self._jst_flows)
        delta=result['allocator_events'][len(self._jst_events):]
        prefix,counts=dict(result),deepcopy(result['actual_allocator_counts'])
        for event in delta:counts['malloc' if event[0]=='alloc' else 'free']-=1
        for event in self._jst_aux:counts[event['kind']]-=1
        prefix.update(allocator_events=self._jst_events,actual_allocator_counts=counts)
        old=super().finish(prefix,state,proof)
        assert old==self._jst_parent['case_result'],'complete environment helper parent differs'
        trace=hashlib.sha256()
        for key in self._jst_sites:trace.update(key.encode()+bytes.fromhex(self._jst_code[key]))
        return dict(parent_case_equal=True,parent_case_sha256=digest(old),field_relations=self._jst_flows,
            instruction_observations=len(self._jst_sites),instruction_trace_sha256=trace.hexdigest(),
            observed_code_sha256=digest(self._jst_code),callbacks=self._jst_calls,
            completed_callbacks=sum(call['returned'] for call in self._jst_calls),stop_reason=self._jst_stop_reason,
            new_allocator_events=delta,allocator_aux_events=self._jst_aux,native_write_observations=len(self._jst_writes),
            actual_allocator_counts=result['actual_allocator_counts'],explicit_service_counts=result['explicit_service_counts'],
            new_providers=[],new_SVCs=[],new_JNI_effects=[],scalar_values_or_hashes_exported=False,
            key_contents_or_hashes_exported=False,native_snapshot_used_as_VM_model_input=False,
            complete_standalone_signer_verified=False,online_acceptance_verified=False)


def list_control(path,base,count,label):
    pages,packed,failures=number_fixture.fresh(path,base,'two_children')
    g=number_fixture.G;root=g+0x2000
    nodes=[g+0x3100+i*0x100 for i in range(count)]
    for i,node in enumerate(nodes):
        key=g+0x7000+i*0x20
        _write_span(pages,node,bytes(64));_write_span(pages,key,('prior-'+str(i)).encode()+b'\0')
        for offset,value in ((0,nodes[i+1] if i+1<count else 0),
            (8,nodes[i-1] if i else nodes[-1]),(56,key)):
            number_fixture.w(pages,node+offset,value)
        number_fixture.w(pages,node+24,8,4);number_fixture.w(pages,node+40,i+1,4)
        _write_span(pages,node+48,struct.pack('<d',float(i+1)))
    number_fixture.w(pages,root+16,nodes[0])
    number_fixture.w(pages,packed+24,int.from_bytes(struct.pack('<d',0.0 if label=='zero' else float(0xFFFFFFFF)),'little'))
    before=_read_span(pages,packed,40)
    expected=number_fixture.services('two_children',failures)
    actual=number_fixture.services('two_children',failures)
    memory,watched,steps=number_fixture.original(path,base,pages,packed,expected)
    result=number_fixture.second.apply_request_287474_json_number_callback(pages,
        argument_block_address=packed,entry_stack_address=number_fixture.SP,image_base=base,
        allocate=actual.malloc,free=actual.free)
    assert result is True and _read_span(pages,g,0xA000)==memory
    assert all(_read_span(pages,a,n)==raw for (a,n),raw in watched.items())
    assert actual.events==expected.events and actual.freed==expected.freed
    assert actual.effects.calls==expected.effects.calls and actual.effects.blocks==expected.effects.blocks
    assert _read_span(pages,packed,32)==before[:32] and _read_span(pages,packed+33,7)==before[33:]
    print('PASS multi-child numeric append',hex(base),count,label,flush=True)
    return dict(image_base=hex(base),prior_children=count,value_profile=label,steps=steps,
        original_wrapper_and_numeric_append_returned=True,guest_image_and_all_declared_payload_bytes_equal=True,
        ordered_allocation_free_effects_equal=True,one_byte_result_and_padding_equal=True,
        native_snapshot_input=False,complete_physical_ABI_verified=False)


def sources():
    return dict(verifier_sha256=sha256(Path(__file__)),parent_verifier_sha256=sha256(Path(previous.__file__)),
        parent_chain_sha256=digest(previous.sources()),third_getter_fixture_sha256=sha256(Path(word_fixture.__file__)),
        numeric_fixture_sha256=sha256(Path(number_fixture.__file__)),native_oracle_sha256=sha256(Path(number_fixture.oracle.__file__)),
        request_VM_model_sha256=sha256(Path(number_fixture.second.__file__)))


def claims():
    return dict(evidence_label='Sample verified',complete_environment_parent_case_equal=True,
        helper_result_to_third_numeric_node_verified=True,third_global_to_fourth_numeric_node_verified=True,
        helper_result_captured_while_frame_live=True,helper_local_not_reread_after_return=True,
        new_node_and_owned_key_allocations_are_live=True,prior_nodes_and_keys_preserved_except_append_links=True,
        current_native_values_used_only_for_native_relations=True,native_snapshot_used_to_initialize_VM_model=False,
        scalar_values_or_hashes_exported=False,key_contents_or_hashes_exported=False,
        real_ART_JVM_execution=False,Android_execution=False,complete_physical_ABI_verified=False,
        complete_standalone_signer_verified=False,online_acceptance_verified=False)


def providers():
    return dict(parent_evidence_sha256=sha256(previous.EVIDENCE),new_providers=[],new_import_bindings=[],
        maximum_callbacks=MAX_CALLS,maximum_observations=MAX_INSTRUCTIONS,
        admitted_new_callbacks=[['0x288854','0x261350'],['0x28863c','0x1e53d0']],
        third_global_source='0x3d60d4',new_SVC_and_JNI_dispatch_policy='stop before execution',
        inherited_original_JNI_acquisition_body_executed=False,
        inherited_JNI_provider='controlled eight-byte env write; original body bypassed',
        existing_integer_conversion_and_numeric_models_reused=True,
        component_allocations='existing explicit synthetic services; no native snapshots as model input')


def run(library,libc):
    parent=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(parent)
    env_parent=json.loads(previous.previous.EVIDENCE.read_text(encoding='utf-8'))
    jff_parent=json.loads(previous.previous.previous.EVIDENCE.read_text(encoding='utf-8'))
    base_parent=json.loads(previous.previous.previous.previous.EVIDENCE.read_text(encoding='utf-8'))
    scope_parent=previous.previous.previous.previous.parent_evidence()
    md5_parent=previous.previous.previous.previous.previous.parent_evidence()
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
        s=PostEnvironmentFields(control)
        s.path,s.continue_to_svc=library,True
        s._postcrc_parent,s._pcb_parent,s._jwx_parent=md5_parent,scope_parent,base_parent
        s._jff_parent,s._jev_parent,s._jst_parent=jff_parent,env_parent,parent
        s._jwx_exec,s._jwx_plt,s._jwx_strncmp=executable,plt,strncmp
        return s
    print('Replaying original helper-result and third-global numeric fields',flush=True)
    rows=prefix.digest.context.replay(library,libc,case_controls=[prefix.CONTROL],_extension_factory=create,
        _request_profile=prefix.digest.previous.previous.name.previous.previous.PROFILE['name'],
        _handler_read_profile=prefix.digest.context.NULL_PAYLOAD_READ_PROFILE['name'])
    assert len(rows)==1
    controls=dict(multi_child_append=[list_control(library,base,count,label)
        for base in number_fixture.BASES for count in LIST_COUNTS for label in NUMBER_VALUES],
        third_global=[word_fixture.compare(library,base,label) for base in word_fixture.BASES for label in word_fixture.PROFILES],
        numeric_guards=number_fixture.guards(library),global_guards=word_fixture.guards(library))
    return dict(schema=SCHEMA,claims=claims(),providers=providers(),source_fingerprints=sources(),
        parent_evidence_sha256=sha256(previous.EVIDENCE),case_result=rows[0],case_result_sha256=digest(rows[0]),
        component_controls=controls)


# Independent redacted regression case, never used as guest or model state.
EXPECTED_CASE_SHA256='0b231975f84470db501fdd198f687f3fbdb945c12605dfa13cc1c4908621f093'


def _validate(data,parent):
    assert set(data)=={'schema','claims','providers','source_fingerprints','parent_evidence_sha256',
        'case_result','case_result_sha256','component_controls'}
    assert data['schema']==SCHEMA and data['claims']==claims() and data['providers']==providers()
    assert data['source_fingerprints']==sources() and data['parent_evidence_sha256']==sha256(previous.EVIDENCE)
    row=data['case_result'];assert data['case_result_sha256']==digest(row)==EXPECTED_CASE_SHA256
    assert row['parent_case_equal'] is True and row['parent_case_sha256']==digest(parent['case_result'])
    assert row['completed_callbacks']==3 and 0<row['instruction_observations']<=MAX_INSTRUCTIONS
    assert row['instruction_observations']==4205
    assert row['stop_reason']=='callback_budget_before_next_call'
    assert row['new_providers']==row['new_SVCs']==row['new_JNI_effects']==row['allocator_aux_events']==[]
    assert row['scalar_values_or_hashes_exported'] is row['key_contents_or_hashes_exported'] is False
    assert row['native_snapshot_used_as_VM_model_input'] is row['complete_standalone_signer_verified'] is row['online_acceptance_verified'] is False
    fields=row['field_relations'];assert len(fields)==2
    assert [field['label'] for field in fields]==['environment_result','third_global']
    source=fields[0]['source']
    assert source==dict(kind='helper_result',capture_site='0x204eac',capture_index=14390,
        captured_while_frame_live=True,ABI_result_copy_verified=True)
    assert fields[1]['source']==dict(kind='global_u32',source_offset='0x3d60d4',source_width=4,
        original_getter_return_verified=True,exact_four_byte_write_and_padding_preserved=True,
        global_preserved=True,no_allocation_effects=True)
    for i,field in enumerate(fields):
        assert set(field)=={'label','source','conversion','argument','node','node_verified',
            'scalar_values_exported','scalar_hashes_exported'}
        assert field['node_verified'] is True and field['scalar_values_exported'] is field['scalar_hashes_exported'] is False
        cvt,arg,node=field['conversion'],field['argument'],field['node']
        assert set(cvt)=={'source_address','load_site','source_low_u32_equal','window','index','convert_site',
            'unsigned_zero_extension_equal','exact_binary64_equal','destination_address','store_site','stored_binary64_equal'}
        assert cvt['load_site']=='0x17079c' and cvt['convert_site']=='0x1707ac' and cvt['store_site']=='0x1707f8'
        assert all(cvt[key] is True for key in ('source_low_u32_equal','unsigned_zero_extension_equal','exact_binary64_equal','stored_binary64_equal'))
        assert set(arg)=={'descriptor_address','prior_child_count','initial_JSON_wrapper_verified','binary64_equals_conversion',
            'key_contents_or_hashes_exported','window','index','actual_X0_X1_D0_equal'}
        assert arg['initial_JSON_wrapper_verified'] is arg['binary64_equals_conversion'] is arg['actual_X0_X1_D0_equal'] is True
        assert arg['key_contents_or_hashes_exported'] is False
        assert arg['prior_child_count']==node['prior_child_count']==i+2
        assert set(node)=={'address','root_address','prior_child_count','new_live_node_and_key_allocations',
            'binary64_equals_source_conversion','int32_saturation_equal','copied_key_equal',
            'old_nodes_and_owned_keys_preserved_except_append_links','root_wrapper_and_counter_preserved',
            'one_byte_success_store_and_other_descriptor_bytes_preserved','window','index'}
        assert all(value is True for key,value in node.items() if type(value) is bool)
        assert arg['window']==node['window']=='suffix' and arg['index']<node['index']
    assert fields[0]['conversion']['window']=='environment_prefix'
    assert 14402<fields[0]['conversion']['index']<15291
    assert fields[0]['conversion']['index']==14972
    assert fields[0]['argument']['index']==1
    assert fields[1]['conversion']['window']=='suffix'
    assert fields[1]['conversion']['index']<fields[1]['argument']['index']
    assert fields[1]['conversion']['index']==1410
    assert fields[0]['node']['root_address']==fields[1]['node']['root_address']
    assert fields[0]['node']['address']!=fields[1]['node']['address']
    calls=row['callbacks'];assert len(calls)==4
    assert [(c['wrapper_offset'],c['target_offset']) for c in calls[:3]]==[
        ('0x288854','0x261350'),('0x28863c','0x1e53d0'),('0x288854','0x261350')]
    old=parent['case_result']['callbacks'][-1]
    for key in ('descriptor_address','VM_cursor_offset','SP','callee_saved_sha256'):assert calls[0][key]==old[key]
    assert all(a['index']<b['index'] for a,b in zip(calls,calls[1:]))
    assert [c['index'] for c in calls]==[1,829,1729,4205]
    assert [c.get('return_index') for c in calls]==[394,840,2509,None]
    assert calls[-1]['VM_cursor_offset']=='0x10a760'
    assert (calls[-1]['wrapper_offset'],calls[-1]['target_offset'])==('0x28887c','0x256f58')
    for c in calls[:3]:
        assert all(c[key] is True for key in ('VM_call_executed','wrapper_entered','target_entered','returned','caller_SP_and_callee_saved_restored'))
        assert c['index']<c['return_index']<=row['instruction_observations']
    assert all(calls[-1][key] is False for key in ('VM_call_executed','wrapper_entered','target_entered','returned'))
    assert fields[0]['node']['index']==calls[0]['return_index']
    assert calls[1]['return_index']<fields[1]['conversion']['index']
    assert fields[1]['argument']['index']==calls[2]['index'] and fields[1]['node']['index']==calls[2]['return_index']
    counts=dict(parent['case_result']['actual_allocator_counts'])
    assert [(event[0],event[1],event[3]) for event in row['new_allocator_events']]==[
        ('alloc',64,'0x2493fc'),('alloc',5,'0x249198'),('alloc',64,'0x2493fc'),('alloc',4,'0x249198')]
    assert row['new_allocator_events'][1][2]==parent['case_result']['new_allocator_events'][-1][1]
    for event in row['new_allocator_events']:counts['malloc' if event[0]=='alloc' else 'free']+=1
    assert row['actual_allocator_counts']==counts and row['explicit_service_counts']==parent['case_result']['explicit_service_counts']
    assert not {'word','bits','registers','key_bytes','native_writes','observation_sites'}&set(row)
    controls=data['component_controls']
    assert set(controls)=={'multi_child_append','third_global','numeric_guards','global_guards'}
    assert [(c['image_base'],c['prior_children'],c['value_profile']) for c in controls['multi_child_append']]==[
        (hex(base),count,label) for base in number_fixture.BASES for count in LIST_COUNTS for label in NUMBER_VALUES]
    assert [(c['image_base'],c['case']) for c in controls['third_global']]==[
        (hex(base),label) for base in word_fixture.BASES for label in word_fixture.PROFILES]
    for c in controls['multi_child_append']+controls['third_global']:
        for key,value in c.items():
            if type(value) is bool:assert value is (key not in {'native_snapshot_input','complete_physical_ABI_verified','physical_spills_and_PAC_compared'})
    for name,fixture in (('numeric_guards',number_fixture),('global_guards',word_fixture)):
        assert [c['case'] for c in controls[name]]==list(fixture.GUARDS)
        assert all(c['rejected'] is c['all_pages_unchanged'] is True for c in controls[name])


def validate(data):
    parent=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(parent)
    _validate(data,parent)


def damaged_evidence_rejected(data):
    parent=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(parent)
    changes=[(('claims','real_ART_JVM_execution'),True),
        (('providers','inherited_original_JNI_acquisition_body_executed'),True),
        (('source_fingerprints','request_VM_model_sha256'),'0'*64),
        (('case_result','parent_case_equal'),False),
        (('case_result','field_relations',0,'source','captured_while_frame_live'),False),
        (('case_result','field_relations',0,'source','ABI_result_copy_verified'),False),
        (('case_result','field_relations',0,'conversion','unsigned_zero_extension_equal'),False),
        (('case_result','field_relations',0,'argument','actual_X0_X1_D0_equal'),False),
        (('case_result','field_relations',0,'node','old_nodes_and_owned_keys_preserved_except_append_links'),False),
        (('case_result','field_relations',1,'source','source_offset'),'0x37a794'),
        (('case_result','field_relations',1,'node','prior_child_count'),1),
        (('case_result','field_relations',1,'node','new_live_node_and_key_allocations'),False),
        (('case_result','callbacks',-1,'target_entered'),True),
        (('case_result','scalar_values_or_hashes_exported'),True),
        (('case_result','bits'),'forbidden'),
        (('component_controls','multi_child_append',0,'ordered_allocation_free_effects_equal'),False),
        (('component_controls','third_global',0,'both_prior_globals_distinguished'),False),
        (('component_controls','global_guards',0,'rejected'),False)]
    for path,value in changes:
        bad=deepcopy(data);target=bad
        for key in path[:-1]:target=target[key]
        target[path[-1]]=value
        if path[0]=='case_result':bad['case_result_sha256']=digest(bad['case_result'])
        try:_validate(bad,parent)
        except (AssertionError,KeyError,ValueError,TypeError,IndexError):continue
        raise AssertionError('damaged post-environment field evidence accepted: '+repr(path))
    return len(changes)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf',type=Path);parser.add_argument('--libc',type=Path)
    parser.add_argument('--compare-case',type=Path,help='independent case, capture only')
    modes=parser.add_mutually_exclusive_group()
    modes.add_argument('--capture',action='store_true');modes.add_argument('--replay',action='store_true')
    args=parser.parse_args()
    if (args.capture or args.replay) and (args.elf is None or args.libc is None):parser.error('--capture and --replay require --elf and --libc')
    if args.compare_case is not None and not args.capture:parser.error('--compare-case requires --capture')
    if args.capture:
        if EVIDENCE.exists():raise FileExistsError('frozen evidence exists; refusing overwrite')
        data=run(args.elf,args.libc)
        if args.compare_case is not None:
            reference=json.loads(args.compare_case.read_text(encoding='utf-8'))
            assert data['case_result']==reference,'independent and public numeric cases differ'
        validate(data);rejected=damaged_evidence_rejected(data)
        with EVIDENCE.open('x',encoding='utf-8',newline='\n') as stream:stream.write(json.dumps(data,indent=2)+'\n')
    else:
        data=json.loads(EVIDENCE.read_text(encoding='utf-8'));validate(data)
        rejected=damaged_evidence_rejected(data)
        if args.replay:assert run(args.elf,args.libc)==data,'fresh post-environment replay differs'
    print(json.dumps(dict(schema=SCHEMA,verified_numeric_fields=len(data['case_result']['field_relations']),
        completed_callbacks=data['case_result']['completed_callbacks'],damaged_evidence_rejected=rejected,
        complete_standalone_signer_verified=False)))


if __name__=='__main__':
    main()
