"""Original ninth JSON string node from the live five-word formatted payload."""
from __future__ import annotations
from copy import deepcopy
import argparse,hashlib,json,struct
from pathlib import Path
import verify_vm9_native_171_post_crc_format5_dynamic_20261125 as previous
import verify_vm9_second_json_string_fresh_20261016 as string_fixture
from unicorn import arm64_const as arm
VM_CALL,VM_RESUME,LIBC_BASE=previous.VM_CALL,previous.VM_RESUME,previous.LIBC_BASE
bootstrap,digest,sha256=previous.bootstrap,previous.digest,previous.sha256
MAX_NEW_INSTRUCTIONS=100000
EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_post_crc_json_string_dynamic_20261125.json')
SCHEMA='vm9-native-171-post-crc-json-string-dynamic-20261125-v1'


class PostCrcJsonString(previous.PostCrcFormat5):
    def __init__(self,control):
        super().__init__(control)
        self._j9_active=self._j9_done=False;self._j9_sites=[];self._j9_code={};self._j9_writes=[]
        self._j9_calls=[];self._j9_seen=set();self._j9_links=[];self._j9_result=[];self._j9_aux=[]
        self._j9_node=None;self._j9_parent=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'))

    def _j9_track(self,cpu,pc):
        site=self._fmt_site(pc);self._j9_sites.append(site);self._j9_code[site]=bytes(cpu.mem_read(pc,4)).hex()

    def _j9_call(self,cpu):
        d=self._reg(cpu,0)
        return dict(index=len(self._j9_sites),descriptor_address=hex(d),descriptor_prefix_width=40,
            wrapper_offset=hex(self._reg(cpu,8)-self.image),target_offset=hex(self._u(cpu,d)-self.image),
            VM_cursor_offset=hex(self._u(cpu,self._reg(cpu,19))-self.image),
            SP=hex(cpu.reg_read(arm.UC_ARM64_REG_SP)),callee_saved_sha256=self._idctor_saved_hash(cpu),
            VM_call_executed=False,wrapper_entered=False,target_entered=False,returned=False)

    def _f5_stop(self,cpu,reason):
        if self._j9_active:return self._j9_stop(cpu,reason)
        if reason!='next_VM_callback_before_execution':return super()._f5_stop(cpu,reason)
        assert not self._j9_active and len(self._f5_sites)==13875 and self._f5_calls[0]['returned']
        assert all(bytes(cpu.mem_read(a,len(b)))==b for _,a,b in self._f5_protected)
        self._f5_done=True;self._f5_reason=reason;self._f5_active=False
        self._j9_state=self._f5_state;self._j9_events=deepcopy(self._j9_state['allocator_events_ref'])
        self._j9_active=True;self._j9_track(cpu,self.image+VM_CALL)
        call=self._j9_call(cpu);self._j9_calls.append(call)
        assert (call['wrapper_offset'],call['target_offset'],call['VM_cursor_offset'])==('0x2888d0','0x2613e4','0x10aa98')
        self._j9_descriptor=int(call['descriptor_address'],16)
        self._j9_before=bytes(cpu.mem_read(self._j9_descriptor,40))
        self._j9_wrapper,self._j9_key,self._j9_value=[self._u(cpu,self._j9_descriptor+i) for i in (8,16,24)]
        initial=self._jwx_typed_output
        assert self._j9_wrapper==int(initial['wrapper_address'],16)
        self._j9_root=self._u(cpu,self._j9_wrapper+8);self._j9_counter=int(initial['counter_address'],16)
        assert self._j9_root==int(initial['root_address'],16) and self._u(cpu,self._j9_root+24,4)==64
        assert self._u(cpu,self._j9_counter,4)==1
        assert self._u(cpu,self.image+0x381AA0)==self.image+0x347FD0 and self._u(cpu,self.image+0x381AA8)==self.image+0x347FA0
        self._j9_value_bytes=self._bounded_cstring(cpu,self._j9_value,4096)
        self._j9_key_bytes=self._bounded_cstring(cpu,self._j9_key,4096)
        assert self._j9_value==int(self._f5_string['payload_address'],16)
        assert self._j9_value_bytes==self._f5_expected and len(self._j9_value_bytes)==self._f5_string['length']==51
        live=self._jff_live(self._j9_state)
        assert live.get(self._j9_value,0)>=self._f5_string['capacity']
        self._j9_old=[];p=self._u(cpu,self._j9_root+16);seen=set()
        while p:
            assert p not in seen and len(seen)<9 and live.get(p,0)>=64;seen.add(p)
            raw=bytes(cpu.mem_read(p,64));assert self._u(cpu,p+24,4)==8
            key=self._u(cpu,p+56);payload=self._bounded_cstring(cpu,key,4096)+b'\0'
            assert live.get(key,0)>=len(payload)
            self._j9_old.append((p,raw,key,payload));p=self._u(cpu,p)
        assert len(self._j9_old)==8
        self._j9_head,self._j9_tail=self._j9_old[0][0],self._j9_old[-1][0]
        assert self._u(cpu,self._j9_head+8)==self._j9_tail
        assert all(self._u(cpu,self._j9_old[i][0]+8)==self._j9_old[i-1][0] for i in range(1,8))
        self._j9_protected=[]
        for label,a,raw in self._f5_protected:
            if label=='JSON_node' and a==self._j9_head:
                assert len(raw)==64
                self._j9_protected.extend([(label+'_head_prefix',a,raw[:8]),(label+'_head_tail',a+16,raw[16:])])
            elif label=='JSON_node' and a==self._j9_tail:
                assert len(raw)==64;self._j9_protected.append((label+'_tail_body',a+8,raw[8:]))
            else:self._j9_protected.append((label,a,raw))
        assert any(a==self._j9_head and len(raw)==8 for _,a,raw in self._j9_protected)
        self._j9_protected.append(('current_key_input',self._j9_key,self._j9_key_bytes+b'\0'))
        self._j9_protected.append(('JSON_allocator_hooks',self.image+0x381AA0,bytes(cpu.mem_read(self.image+0x381AA0,16))))
        self._base_observe(cpu,self.image+VM_CALL,self._j9_state)
        print('Retained formatter checkpoint; original string append with eight prior numeric nodes',flush=True)

    def native_runner(self,*args,**kwargs):
        old_write=kwargs['memory_write_observer']
        def write(cpu,a,n):
            if self._j9_active:
                pc=cpu.reg_read(arm.UC_ARM64_REG_PC);off=pc-self.image
                assert not any(a<b+len(raw) and b<a+n for _,b,raw in self._j9_protected),'string append wrote retained storage'
                self._j9_writes.append((len(self._j9_sites),self._fmt_site(pc),a,n))
                for address,site,label in ((self._j9_tail,0x24A1EC,'old_tail_next'),(self._j9_head+8,0x24A1F4,'head_tail_cache')):
                    if a<address+8 and address<a+n:
                        assert (a,n,off)==(address,8,site) and self._j9_node is not None and self._reg(cpu,1)==self._j9_node
                        self._j9_links.append(dict(index=len(self._j9_sites),PC=hex(off),destination=label,width=8,new_node_pointer_verified=True))
                d=self._j9_descriptor
                if not self._j9_calls[0]['returned'] and a<d+40 and d<a+n:
                    assert (a,n,off)==(d+32,1,0x2888E8) and self._reg(cpu,8)==1
                    assert not self._j9_result
                    self._j9_result.append(dict(index=len(self._j9_sites),PC=hex(off),packed_offset=32,width=1,success=True))
            if old_write:old_write(cpu,a,n)
        kwargs['memory_write_observer']=write;return super().native_runner(*args,**kwargs)

    def _j9_stop(self,cpu,reason):
        assert all(bytes(cpu.mem_read(a,len(b)))==b for _,a,b in self._j9_protected)
        self._j9_done=True;self._j9_reason=reason
        cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,bootstrap().digest.context.outer.oracle.STOP)

    def _jst_stop(self,cpu,reason):
        if self._j9_active:return self._j9_stop(cpu,reason)
        return super()._jst_stop(cpu,reason)

    def observe(self,cpu,pc,state):
        if not self._j9_active:return super().observe(cpu,pc,state)
        self._j9_track(cpu,pc);off=pc-self.image;call=self._j9_calls[0]
        if len(self._j9_sites)>=MAX_NEW_INSTRUCTIONS:self._j9_stop(cpu,'instruction_budget');return
        if off==VM_CALL:
            assert call['returned'];self._j9_calls.append(self._j9_call(cpu));self._j9_stop(cpu,'next_VM_callback_before_execution');return
        if self._f5_guard(cpu,pc):return
        if off in (0x2888D0,0x2613E4,0x24A424,0x24A480,0x249168,0x24A214,0x24A1B0,0x347FD0):self._j9_seen.add(('main',off))
        if pc==LIBC_BASE+0x1BB08:self._j9_seen.add(('libc',0x1BB08))
        if pc in (LIBC_BASE+0x9833C,LIBC_BASE+0x97F40):self._j9_aux.append(dict(index=len(self._j9_sites),kind='gc' if pc==LIBC_BASE+0x9833C else 'flush'))
        if off==0x2888D0:
            assert self._reg(cpu,0)==self._j9_descriptor;call.update(VM_call_executed=True,wrapper_entered=True)
        if off==0x2613E4:
            assert [self._reg(cpu,i) for i in range(3)]==[self._j9_wrapper,self._j9_key,self._j9_value]
            call['target_entered']=True
        if off==0x24A424:assert [self._reg(cpu,i) for i in range(3)]==[self._j9_root,self._j9_key,self._j9_value]
        if off==0x24A49C:
            self._j9_node=self._reg(cpu,0);assert self._j9_node not in {a for a,_,_,_ in self._j9_old} and self._j9_node
        if off==0x24A1D4:assert self._reg(cpu,8)==self._j9_tail
        if off==0x24A1F0:
            assert self._reg(cpu,1)==self._j9_node and self._reg(cpu,8)==self._j9_tail
        if off==VM_RESUME:
            assert self._reg(cpu,0)==1 and len(self._j9_result)==1 and len(self._j9_links)==2
            assert cpu.reg_read(arm.UC_ARM64_REG_SP)==int(call['SP'],16) and self._idctor_saved_hash(cpu)==call['callee_saved_sha256']
            expected=bytearray(self._j9_before);expected[32]=1
            assert bytes(cpu.mem_read(self._j9_descriptor,40))==expected
            live=self._jff_live(state);node=self._j9_node
            events=state['allocator_events_ref'][len(self._j9_events):]
            assert [e[0] for e in events]==['alloc']*3
            assert [e[1] for e in events]==[64,len(self._j9_value_bytes)+1,len(self._j9_key_bytes)+1]
            assert [e[2] for e in events][0]==node
            payload,owned=self._u(cpu,node+32),self._u(cpu,node+56)
            assert [e[2] for e in events][1:]==[payload,owned] and len({node,payload,owned})==3
            assert live.get(node,0)>=64 and live.get(payload,0)>=len(self._j9_value_bytes)+1 and live.get(owned,0)>=len(self._j9_key_bytes)+1
            expected=bytearray(64);expected[8:16]=self._j9_tail.to_bytes(8,'little');expected[24:28]=(0x10).to_bytes(4,'little')
            expected[32:40]=payload.to_bytes(8,'little');expected[56:64]=owned.to_bytes(8,'little')
            assert bytes(cpu.mem_read(node,64))==expected
            assert payload!=self._j9_value and owned!=self._j9_key
            assert bytes(cpu.mem_read(payload,len(self._j9_value_bytes)+1))==self._j9_value_bytes+b'\0'
            assert bytes(cpu.mem_read(owned,len(self._j9_key_bytes)+1))==self._j9_key_bytes+b'\0'
            for a,raw,key,copy in self._j9_old:
                b=bytearray(raw)
                if a==self._j9_head:b[8:16]=node.to_bytes(8,'little')
                if a==self._j9_tail:b[:8]=node.to_bytes(8,'little')
                assert bytes(cpu.mem_read(a,64))==b and bytes(cpu.mem_read(key,len(copy)))==copy
            self._j9_node_proof=dict(address=hex(node),value_address=hex(payload),key_address=hex(owned),type=16,
                prior_children=8,children_after=9,value_length=len(self._j9_value_bytes),
                new_live_node_value_and_key_allocations=True,formatted_payload_used_as_actual_cstring_source=True,
                value_and_key_separately_owned_and_copied=True,all_node_fields_and_NULs_verified=True,
                old_nodes_and_keys_preserved_except_two_append_links=True,root_wrapper_and_counter_preserved=True,
                one_byte_success_and_other_39_packed_bytes_preserved=True)
            self._j9_protected.extend([('new_node',node,bytes(expected)),('new_value',payload,self._j9_value_bytes+b'\0'),
                ('new_key',owned,self._j9_key_bytes+b'\0'),('old_head_tail_link',self._j9_head+8,node.to_bytes(8,'little')),
                ('old_tail_next_link',self._j9_tail,node.to_bytes(8,'little'))])
            call.update(returned=True,return_index=len(self._j9_sites),caller_SP_and_callee_saved_restored=True)
            print('Original ninth string node appended; distinct live value/key copies and exact two links verified',flush=True)
        self._base_observe(cpu,pc,state)
        assert self.late_jni_calls==self._jev_initial_late and self.java_dispatch_calls==self._jev_initial_java

    def finish(self,result,state,proof):
        assert self._j9_done and self._j9_reason=='next_VM_callback_before_execution' and self._j9_calls[0]['returned']
        assert {('main',x) for x in (0x2888D0,0x2613E4,0x24A424,0x24A480,0x249168,0x24A214,0x24A1B0,0x347FD0)}|{('libc',0x1BB08)}<=self._j9_seen
        events=result['allocator_events'][len(self._j9_events):];counts=deepcopy(result['actual_allocator_counts'])
        for e in events:counts['malloc' if e[0]=='alloc' else 'free']-=1
        for e in self._j9_aux:counts[e['kind']]-=1
        old=super().finish(dict(result,allocator_events=self._j9_events,actual_allocator_counts=counts),state,proof)
        assert old==self._j9_parent['case_result'],'complete formatter checkpoint differs'
        trace=hashlib.sha256()
        for site in self._j9_sites:trace.update(site.encode()+bytes.fromhex(self._j9_code[site]))
        return dict(complete_formatter_parent_case_equal=True,parent_case_sha256=digest(old),instruction_observations=len(self._j9_sites),
            instruction_trace_sha256=trace.hexdigest(),observed_code_sha256=digest(self._j9_code),callbacks=self._j9_calls,
            source_formatted_object=hex(self._f5_output),source_formatted_payload=hex(self._j9_value),appended_string_node=self._j9_node_proof,
            append_link_writes=self._j9_links,packed_success_write=self._j9_result,
            new_allocator_events=events,allocator_aux_events=self._j9_aux,native_write_observations=len(self._j9_writes),
            actual_allocator_counts=result['actual_allocator_counts'],explicit_service_counts=result['explicit_service_counts'],
            retained_JSON_CRC_TLS_formatted_source_and_inputs_preserved=True,new_providers=[],new_SVCs=[],new_JNI_effects=[],stop_reason=self._j9_reason,
            source_values_or_hashes_exported=False,key_contents_or_hashes_exported=False,allocation_contents_exported=False,
            native_snapshot_used_as_VM_model_input=False,complete_standalone_signer_verified=False,online_acceptance_verified=False)


def run(library,libc):
    previous.validate(json.loads(previous.EVIDENCE.read_text(encoding='utf-8')))
    original=previous.PostCrcFormat5;previous.PostCrcFormat5=PostCrcJsonString
    try:return previous.run(library,libc)
    finally:previous.PostCrcFormat5=original


def compare_eight(library,image,label):
    f=string_fixture;p,packed,failures=f.fresh(library,image,'short_value')
    source=f.u(p,packed+24);size={'eight_numeric_value51':51,'eight_numeric_value300':300}[label]
    f._write_span(p,source,b'x'*size+b'\0')
    nodes=[f.G+0x6000+i*64 for i in range(8)]
    f.w(p,f.G+0x2010,nodes[0])
    for i,a in enumerate(nodes):
        f._write_span(p,a,bytes(64));f.w(p,a,nodes[i+1] if i<7 else 0)
        f.w(p,a+8,nodes[i-1] if i else nodes[-1]);f.w(p,a+24,8,4)
        f.w(p,a+40,i+3,4);f._write_span(p,a+48,struct.pack('<d',float(i+3)))
        key=f.G+0x7000+i*16;f.w(p,a+56,key);f._write_span(p,key,b'prior'+str(i).encode()+b'\0')
    expected=f.services(label,failures);actual=f.services(label,failures)
    memory,watch,steps=f.original(library,image,p,packed,expected)
    result=f.second.apply_request_287474_json_string_callback(p,argument_block_address=packed,
        entry_stack_address=f.SP,image_base=image,allocate=actual.malloc,free=actual.free)
    assert result is True and f._read_span(p,f.G,0xA000)==memory
    assert all(f._read_span(p,a,n)==raw for (a,n),raw in watch.items())
    assert actual.events==expected.events and actual.freed==expected.freed
    assert actual.effects.calls==expected.effects.calls and actual.effects.blocks==expected.effects.blocks
    node=f.u(p,nodes[-1]);assert node not in nodes and f.u(p,nodes[0]+8)==node
    assert f.u(p,node+24,4)==16 and f.u(p,node+8)==nodes[-1] and f.u(p,node)==0
    assert f._read_span(p,f.u(p,node+32),size+1)==b'x'*size+b'\0'
    print('PASS eight numeric children then JSON string',hex(image),label,flush=True)
    return dict(image_base=hex(image),case=label,steps=steps,prior_numeric_children=8,final_children=9,
        declared_value_length=size,original_wrapper_string_append_returned=True,all_guest_and_image_bytes_equal=True,
        ordered_allocation_free_and_prefree_bytes_equal=True,separate_string_node_and_copies_verified=True,
        synthetic_allocator_services=True,native_snapshot_input=False,complete_physical_ABI_verified=False)

EXPECTED_CASE_SHA256='b46fc8284685941e8d5c7a9f034dafbce735a8cd6caa07847f3d62f5d002b2f4'
EXPECTED_COMPONENTS_SHA256='e373747ad1bb23f9b644ee9469067f04ff63d28ea61b399a76b4cd905a8d721d'
EXPECTED_CASE_KEYS=['actual_allocator_counts', 'allocation_contents_exported', 'allocator_aux_events', 'append_link_writes', 'appended_string_node', 'callbacks', 'complete_formatter_parent_case_equal', 'complete_standalone_signer_verified', 'explicit_service_counts', 'instruction_observations', 'instruction_trace_sha256', 'key_contents_or_hashes_exported', 'native_snapshot_used_as_VM_model_input', 'native_write_observations', 'new_JNI_effects', 'new_SVCs', 'new_allocator_events', 'new_providers', 'observed_code_sha256', 'online_acceptance_verified', 'packed_success_write', 'parent_case_sha256', 'retained_JSON_CRC_TLS_formatted_source_and_inputs_preserved', 'source_formatted_object', 'source_formatted_payload', 'source_values_or_hashes_exported', 'stop_reason']

def sources():
    return dict(verifier_sha256=sha256(Path(__file__)),parent_verifier_sha256=sha256(Path(previous.__file__)),
        parent_chain_sha256=digest(previous.sources()),string_fixture_sha256=sha256(Path(string_fixture.__file__)),
        JSON_model_sha256=sha256(Path(__file__).with_name('vm9_configuration_init.py')),
        callback_model_sha256=sha256(Path(string_fixture.second.__file__)),
        allocator_services_sha256=sha256(Path(__file__).with_name('verify_vm9_reference_scopes_fresh_20261011.py')),
        allocator_effects_sha256=sha256(Path(__file__).with_name('verify_vm9_strings.py')),
        native_oracle_sha256=sha256(Path(string_fixture.oracle.__file__)))


def claims():
    return dict(evidence_label='Sample verified',complete_formatter_parent_case_equal=True,
        original_wrapper_JSON_string_and_append_functions_executed=True,original_matching_Bionic_malloc_executed=True,
        actual_live_formatted_payload_used_as_cstring_source=True,new_live_node_value_and_key_are_distinct_owned_allocations=True,
        all_string_node_fields_and_copied_NULs_verified=True,eight_numeric_nodes_preserved_except_two_append_links=True,
        root_wrapper_counter_CRC_TLS_and_formatted_source_preserved=True,exact_two_link_writes_and_one_byte_success_verified=True,
        source_values_or_hashes_exported=False,key_contents_or_hashes_exported=False,allocation_contents_exported=False,
        native_snapshot_used_as_VM_model_input=False,original_JNI_acquisition_body_executed=False,
        real_ART_JVM_execution=False,Android_execution=False,complete_physical_ABI_verified=False,concurrency_verified=False,
        complete_standalone_signer_verified=False,online_acceptance_verified=False)


def providers():
    return dict(parent_evidence_sha256=sha256(previous.EVIDENCE),admitted_callback=['0x2888d0','0x2613e4'],
        maximum_new_observations=MAX_NEW_INSTRUCTIONS,new_import_bindings=[],new_providers=[],
        allocation='existing JSON hooks to original matching Bionic malloc body',
        preserved_old_node_write_exceptions=['tail.next:8 bytes at +0x24a1ec','head.prev:8 bytes at +0x24a1f4'],
        unknown_callback_policy='stop before VM call',new_SVC_and_JNI_policy='stop before execution',
        inherited_JNI_provider='controlled eight-byte env write; original body bypassed',
        relevant_existing_JSON_string_native_controls_rerun=52,new_eight_numeric_composition_controls=4,
        relevant_existing_string_guards_rerun=24,other_inherited_component_controls_rerun=False,
        component_allocators='declared synthetic services only; no native output used as model input')


def capture(library,libc):
    case=run(library,libc);parent=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'))
    controls=dict(existing_JSON_string=[string_fixture.compare(library,b,l) for b in string_fixture.BASES for l in string_fixture.PROFILES],
        eight_numeric_then_string=[compare_eight(library,b,l) for b in string_fixture.BASES for l in ('eight_numeric_value51','eight_numeric_value300')],
        string_guards=string_fixture.guards(library))
    return dict(schema=SCHEMA,claims=claims(),providers=providers(),source_fingerprints=sources(),
        parent_evidence_sha256=sha256(previous.EVIDENCE),case_result=case,case_result_sha256=digest(case),
        component_controls=controls,inherited_controls_sha256=digest(parent['component_controls']))


def _validate(data,parent):
    assert set(data)=={'schema','claims','providers','source_fingerprints','parent_evidence_sha256','case_result',
        'case_result_sha256','component_controls','inherited_controls_sha256'}
    assert data['schema']==SCHEMA and data['claims']==claims() and data['providers']==providers()
    assert data['source_fingerprints']==sources() and data['parent_evidence_sha256']==sha256(previous.EVIDENCE)
    assert data['inherited_controls_sha256']==digest(parent['component_controls'])
    r=data['case_result'];assert data['case_result_sha256']==digest(r)==EXPECTED_CASE_SHA256 and set(r)==set(EXPECTED_CASE_KEYS)
    assert r['complete_formatter_parent_case_equal'] is True and r['parent_case_sha256']==digest(parent['case_result'])
    assert r['stop_reason']=='next_VM_callback_before_execution' and 0<r['instruction_observations']<MAX_NEW_INSTRUCTIONS
    assert r['new_providers']==r['new_SVCs']==r['new_JNI_effects']==[]
    assert r['retained_JSON_CRC_TLS_formatted_source_and_inputs_preserved'] is True
    assert all(r[k] is False for k in ('source_values_or_hashes_exported','key_contents_or_hashes_exported',
        'allocation_contents_exported','native_snapshot_used_as_VM_model_input','complete_standalone_signer_verified','online_acceptance_verified'))
    assert r['explicit_service_counts']==parent['case_result']['explicit_service_counts']
    assert r['source_formatted_object']==parent['case_result']['formatted_string']['object_address']
    assert r['source_formatted_payload']==parent['case_result']['formatted_string']['payload_address']
    calls=r['callbacks'];assert len(calls)==2 and calls[0]['index']==1 and calls[-1]['index']==r['instruction_observations']
    assert (calls[0]['wrapper_offset'],calls[0]['target_offset'])==('0x2888d0','0x2613e4')
    assert all(calls[0][k] is True for k in ('VM_call_executed','wrapper_entered','target_entered','returned','caller_SP_and_callee_saved_restored'))
    assert all(calls[-1][k] is False for k in ('VM_call_executed','wrapper_entered','target_entered','returned'))
    for k in ('descriptor_address','VM_cursor_offset','SP','callee_saved_sha256','wrapper_offset','target_offset'):
        assert calls[0][k]==parent['case_result']['callbacks'][-1][k]
    node=r['appended_string_node'];assert node['type']==16 and node['prior_children']==8 and node['children_after']==9
    assert node['value_length']==parent['case_result']['formatted_string']['length']==51
    assert len({node[k] for k in ('address','value_address','key_address')})==3 and node['value_address']!=r['source_formatted_payload']
    assert all(node[k] is True for k in ('new_live_node_value_and_key_allocations','formatted_payload_used_as_actual_cstring_source',
        'value_and_key_separately_owned_and_copied','all_node_fields_and_NULs_verified','old_nodes_and_keys_preserved_except_two_append_links',
        'root_wrapper_and_counter_preserved','one_byte_success_and_other_39_packed_bytes_preserved'))
    links=r['append_link_writes'];assert [(v['destination'],v['PC'],v['width']) for v in links]==[('old_tail_next','0x24a1ec',8),('head_tail_cache','0x24a1f4',8)]
    assert all(v['new_node_pointer_verified'] is True for v in links)
    assert len(r['packed_success_write'])==1 and r['packed_success_write'][0]['packed_offset']==32 and r['packed_success_write'][0]['width']==1 and r['packed_success_write'][0]['success'] is True
    assert [e[0] for e in r['new_allocator_events']]==['alloc']*3 and r['new_allocator_events'][0][1]==64 and r['new_allocator_events'][1][1]==52
    c=data['component_controls'];assert set(c)=={'existing_JSON_string','eight_numeric_then_string','string_guards'} and digest(c)==EXPECTED_COMPONENTS_SHA256
    assert [(v['image_base'],v['case']) for v in c['existing_JSON_string']]==[(hex(b),l) for b in string_fixture.BASES for l in string_fixture.PROFILES]
    for v in c['existing_JSON_string']:
        assert all(v[k] is True for k in ('original_wrapper_string_append_returned','all_guest_and_image_bytes_equal',
            'ordered_allocation_free_and_prefree_bytes_equal','result_is_one_byte_and_padding_preserved','synthetic_allocator_services'))
        assert v['native_snapshot_input'] is v['complete_physical_ABI_verified'] is False
    assert [(v['image_base'],v['case']) for v in c['eight_numeric_then_string']]==[(hex(b),l) for b in string_fixture.BASES for l in ('eight_numeric_value51','eight_numeric_value300')]
    for v in c['eight_numeric_then_string']:
        assert v['prior_numeric_children']==8 and v['final_children']==9
        assert all(v[k] is True for k in ('original_wrapper_string_append_returned','all_guest_and_image_bytes_equal',
            'ordered_allocation_free_and_prefree_bytes_equal','separate_string_node_and_copies_verified','synthetic_allocator_services'))
        assert v['native_snapshot_input'] is v['complete_physical_ABI_verified'] is False
    assert len(c['string_guards'])==24 and [v['case'] for v in c['string_guards']]==list(string_fixture.GUARDS)
    assert all(v['rejected'] is v['all_pages_unchanged'] is True and v['external_provider_effects_rolled_back'] is False for v in c['string_guards'])


def validate(data):
    parent=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(parent);_validate(data,parent)


def damaged_evidence_rejected(data):
    parent=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(parent)
    changes=[(('claims','real_ART_JVM_execution'),True),(('claims','original_JNI_acquisition_body_executed'),True),
        (('providers','new_providers'),['guessed_JSON']), (('source_fingerprints','JSON_model_sha256'),'0'*64),
        (('inherited_controls_sha256',),'0'*64),(('case_result','complete_formatter_parent_case_equal'),False),
        (('case_result','source_formatted_payload'),'0x0'),(('case_result','appended_string_node','type'),8),
        (('case_result','appended_string_node','children_after'),8),(('case_result','appended_string_node','new_live_node_value_and_key_allocations'),False),
        (('case_result','appended_string_node','value_and_key_separately_owned_and_copied'),False),
        (('case_result','appended_string_node','all_node_fields_and_NULs_verified'),False),
        (('case_result','appended_string_node','old_nodes_and_keys_preserved_except_two_append_links'),False),
        (('case_result','appended_string_node','root_wrapper_and_counter_preserved'),False),
        (('case_result','append_link_writes',0,'width'),4),(('case_result','append_link_writes',1,'new_node_pointer_verified'),False),
        (('case_result','packed_success_write',0,'width'),8),(('case_result','retained_JSON_CRC_TLS_formatted_source_and_inputs_preserved'),False),
        (('case_result','callbacks',-1,'target_entered'),True),(('case_result','key_contents_or_hashes_exported'),True),
        (('case_result','allocation_contents_exported'),True),(('case_result','registers'),[]),
        (('component_controls','eight_numeric_then_string',0,'native_snapshot_input'),True),(('component_controls','string_guards',0,'rejected'),False)]
    for path,value in changes:
        bad=deepcopy(data);target=bad
        for key in path[:-1]:target=target[key]
        target[path[-1]]=value
        if path[0]=='case_result':bad['case_result_sha256']=digest(bad['case_result'])
        try:_validate(bad,parent)
        except (AssertionError,KeyError,ValueError,TypeError,IndexError):continue
        raise AssertionError('damaged JSON string evidence accepted: '+repr(path))
    return len(changes)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--elf',type=Path);p.add_argument('--libc',type=Path);p.add_argument('--compare-case',type=Path)
    m=p.add_mutually_exclusive_group();m.add_argument('--capture',action='store_true');m.add_argument('--replay',action='store_true');args=p.parse_args()
    if (args.capture or args.replay) and (args.elf is None or args.libc is None):p.error('--capture and --replay require --elf and --libc')
    if args.compare_case is not None and not args.capture:p.error('--compare-case requires --capture')
    if args.capture:
        if EVIDENCE.exists():raise FileExistsError('frozen evidence exists; refusing overwrite')
        data=capture(args.elf,args.libc)
        if args.compare_case is not None:assert data['case_result']==json.loads(args.compare_case.read_text(encoding='utf-8'))
        validate(data);rejected=damaged_evidence_rejected(data)
        with EVIDENCE.open('x',encoding='utf-8',newline='\n') as stream:stream.write(json.dumps(data,indent=2)+'\n')
    else:
        data=json.loads(EVIDENCE.read_text(encoding='utf-8'));validate(data);rejected=damaged_evidence_rejected(data)
        if args.replay:assert capture(args.elf,args.libc)==data
    print(json.dumps(dict(schema=SCHEMA,JSON_children=9,damaged_evidence_rejected=rejected,complete_standalone_signer_verified=False)))


if __name__=='__main__':main()
