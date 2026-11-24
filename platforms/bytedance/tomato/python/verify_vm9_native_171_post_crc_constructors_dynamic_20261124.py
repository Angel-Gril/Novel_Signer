"""Original default StringObject constructors preserving eight JSON nodes."""
from __future__ import annotations
import argparse,hashlib,json,traceback
from copy import deepcopy
from pathlib import Path
import verify_vm9_native_171_crc_eighth_numeric_dynamic_20261124 as previous
import verify_vm9_request_287474_consumers_fresh_20261013 as consumer_fixture
from unicorn import arm64_const as arm
from vm9_allocator import _read_span,_write_span,RefillUnsupported
VM_CALL,VM_RESUME,LIBC_BASE=previous.VM_CALL,previous.VM_RESUME,previous.LIBC_BASE
bootstrap,digest,sha256=previous.bootstrap,previous.digest,previous.sha256
MAX_NEW_CALLBACKS,MAX_NEW_INSTRUCTIONS=4,80000
LABELS=('normal','allocation_failure','cross_page_object','object_packed_alias','custom_initial_descriptor',
    'custom_descriptor_failure','payload_object_alias','payload_packed_alias','cross_page_payload')
GUARDS=('wrong_target','wrong_wrapper','missing_packed','missing_object','missing_empty_descriptor',
    'allocator_late_failure','unmapped_allocation','invalid_allocation')
EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_post_crc_constructors_dynamic_20261124.json')
SCHEMA='vm9-native-171-post-crc-constructors-dynamic-20261124-v1'


class PostCrcConstructors(previous.CrcEighth):
    def __init__(self,control):
        super().__init__(control)
        self._sw_active=self._sw_done=False
        self._sw_sites,self._sw_code,self._sw_writes=[],{},[]
        self._sw_calls,self._sw_aux,self._sw_objects=[],[],[]
        self._sw_reason=None
        self._sw_parent=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'))

    def _sw_track(self,cpu,pc):
        site=self._fmt_site(pc);self._sw_sites.append(site);self._sw_code[site]=bytes(cpu.mem_read(pc,4)).hex()

    def _sw_call(self,cpu):
        descriptor=self._reg(cpu,0);vmstate=self._reg(cpu,19)
        return dict(index=len(self._sw_sites),descriptor_address=hex(descriptor),descriptor_width=48,
            wrapper_offset=hex(self._reg(cpu,8)-self.image),target_offset=hex(self._u(cpu,descriptor)-self.image),
            VM_cursor_offset=hex(self._u(cpu,vmstate)-self.image),SP=hex(cpu.reg_read(arm.UC_ARM64_REG_SP)),
            callee_saved_sha256=self._idctor_saved_hash(cpu),VM_call_executed=False,wrapper_entered=False,target_entered=False,returned=False)

    def _sw_retained(self,cpu):
        initial=self._jwx_typed_output
        wrapper,root,counter=(int(initial[k],16) for k in ('wrapper_address','root_address','counter_address'))
        ranges=[('JSON_wrapper',wrapper,16),('JSON_root',root,64),('JSON_counter',counter,4),
            ('CRC_source_object',self._c8_receiver,24),('CRC_source_payload',self._c8_pointer,max(0,self._c8_length)),
            ('CRC_table',self.image+0x96144,1024)]
        node=self._u(cpu,root+16);seen=set()
        while node:
            assert node not in seen and len(seen)<9;seen.add(node);ranges.append(('JSON_node',node,64))
            key=self._u(cpu,node+56);ranges.append(('JSON_key',key,len(self._bounded_cstring(cpu,key,limit=4096))+1))
            node=self._u(cpu,node)
        assert len(seen)==8
        return [(label,address,bytes(cpu.mem_read(address,width))) for label,address,width in ranges if width]

    def _c8_stop(self,cpu,reason):
        if reason!='callback_budget_before_next_call':return super()._c8_stop(cpu,reason)
        assert not self._sw_active and len(self._c8_sites)==3016 and len(self._c8_calls)==3
        assert self._c8_flow['public']['node_verified'] and cpu.reg_read(arm.UC_ARM64_REG_PC)==self.image+VM_CALL
        self._c8_done=True;self._c8_reason=reason;self._c8_active=False
        self._sw_events=deepcopy(self._sw_state['allocator_events_ref'])
        self._sw_protected=self._sw_retained(cpu)
        self._sw_active=True;self._sw_track(cpu,self.image+VM_CALL)
        call=self._sw_call(cpu);self._sw_calls.append(call);self._sw_current=call
        assert (call['wrapper_offset'],call['target_offset'],call['VM_cursor_offset'])==('0x2884cc','0x2481ac','0x10a9e0')
        self._sw_begin(cpu,self._sw_state)
        self._base_observe(cpu,self.image+VM_CALL,self._sw_state)
        print('Retained complete CRC/eighth checkpoint; executing default string constructor window',flush=True)

    def _sw_begin(self,cpu,state):
        call=self._sw_current;descriptor=int(call['descriptor_address'],16)
        receiver=self._u(cpu,descriptor+8)
        assert not any(receiver<a+len(raw) and a<receiver+32 for _,a,raw in self._sw_protected)
        initial=bytes(cpu.mem_read(self.image+0x6E168,8));assert initial==b'\x08'+bytes(7)
        row=dict(object_address=hex(receiver),descriptor_address=hex(descriptor),
            initial_descriptor_from_ELF_verified=True,known_pointer_relations=[k for k,v in vars(self).items()
                if not k.startswith('_sw_') and type(v) is int and v==receiver],
            initialized=False,source_values_or_hashes_exported=False)
        self._sw_pending=dict(public=row,receiver=receiver,descriptor=descriptor,
            descriptor_before=bytes(cpu.mem_read(descriptor,48)),object_before=bytes(cpu.mem_read(receiver,32)),
            initial=initial,allocation_index=len(state['allocator_events_ref']),body_writes=[],malloc_PLT_entered=False,malloc_body_entered=False)
        self._sw_objects.append(row)

    def native_runner(self,*args,**kwargs):
        old_write=kwargs['memory_write_observer']
        def write(cpu,address,size):
            if self._sw_active:
                pc=cpu.reg_read(arm.UC_ARM64_REG_PC);self._sw_writes.append((len(self._sw_sites),self._fmt_site(pc),address,size))
                assert not any(address<a+len(raw) and a<address+size for _,a,raw in self._sw_protected),'constructor window wrote retained live storage'
                off=pc-self.image
                if off in (0x2481CC,0x2481D0,0x2481DC,0x2481E4,0x2481EC):
                    self._sw_pending['body_writes'].append((off,address,size))
            if old_write:old_write(cpu,address,size)
        kwargs['memory_write_observer']=write
        return super().native_runner(*args,**kwargs)

    def _sw_return(self,cpu,state):
        flow=self._sw_pending;row=flow['public'];receiver=flow['receiver']
        pointer=flow['allocation_pointer'];assert pointer!=0
        events=state['allocator_events_ref'][flow['allocation_index']:]
        assert events==[['alloc',8,pointer,'0x2481dc']],events
        assert flow['malloc_PLT_entered'] and flow['malloc_body_entered']
        expected=(self.image+0x34F5F8).to_bytes(8,'little')+flow['initial']+pointer.to_bytes(8,'little')+flow['object_before'][24:]
        assert bytes(cpu.mem_read(receiver,32))==expected
        assert bytes(cpu.mem_read(flow['descriptor'],48))==flow['descriptor_before']
        assert bytes(cpu.mem_read(pointer,8))==b'\0'+flow['allocation_before'][1:]
        assert self._reg(cpu,0)==pointer
        assert flow['body_writes']==[(0x2481CC,receiver,8),(0x2481D0,receiver+8,8),
            (0x2481DC,receiver+16,8),(0x2481E4,pointer,1)]
        assert all(bytes(cpu.mem_read(a,len(raw)))==raw for _,a,raw in self._sw_protected)
        row.update(initialized=True,initial_capacity=8,initial_length=0,payload_address=hex(pointer),allocation_size=8,
            original_malloc_PLT_and_body_entered=True,new_allocation_in_current_call=True,returned_X0_equals_payload=True,
            exact_header_pointer_and_one_byte_NUL_writes_verified=True,payload_remaining_seven_bytes_preserved=True,
            object_neighbor_eight_bytes_preserved=True,descriptor_all_48_bytes_preserved=True,
            prior_JSON_CRC_and_constructed_strings_preserved=True,return_index=len(self._sw_sites))
        self._sw_protected.extend([('constructed_string',receiver,expected[:24]),
            ('constructed_payload',pointer,bytes(cpu.mem_read(pointer,8)))])
        print('Verified original default string constructor:',len(self._sw_objects),'with live eight-byte payload',flush=True)

    def _sw_stop(self,cpu,reason):
        assert all(bytes(cpu.mem_read(a,len(raw)))==raw for _,a,raw in self._sw_protected)
        self._sw_done=True;self._sw_reason=reason
        cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,bootstrap().digest.context.outer.oracle.STOP)

    def _jst_stop(self,cpu,reason):
        if self._sw_active:return self._sw_stop(cpu,reason)
        return super()._jst_stop(cpu,reason)

    def observe(self,cpu,pc,state):
        self._sw_state=state
        if not self._sw_active:return super().observe(cpu,pc,state)
        self._sw_track(cpu,pc)
        if len(self._sw_sites)>=MAX_NEW_INSTRUCTIONS:self._sw_stop(cpu,'instruction_budget');return
        if pc in (LIBC_BASE+0x9833C,LIBC_BASE+0x97F40):self._sw_aux.append(dict(index=len(self._sw_sites),kind='gc' if pc==LIBC_BASE+0x9833C else 'flush'))
        call=self._sw_current;off=pc-self.image
        if off==VM_CALL:
            assert call['returned'],'unexpected nested VM callback in constructor window'
            call=self._sw_call(cpu);self._sw_calls.append(call)
            if len(self._sw_calls)>MAX_NEW_CALLBACKS:self._sw_stop(cpu,'callback_budget_before_next_call');return
            if (call['wrapper_offset'],call['target_offset'])!=('0x2884cc','0x2481ac'):
                self._sw_stop(cpu,'uncovered_VM_callback_before_execution');return
            self._sw_current=call;self._sw_begin(cpu,state)
        if self._jst_guard(cpu,pc):return
        flow=self._sw_pending
        if off==int(call['wrapper_offset'],16):call.update(VM_call_executed=True,wrapper_entered=True)
        if off==0x2481AC:
            call['target_entered']=True
            assert self._reg(cpu,0)==flow['receiver'] and self._reg(cpu,30)==self.image+VM_RESUME
            flow['public']['actual_X0_and_tail_wrapper_LR_equal']=True
        if off==0x347FD0:
            assert self._reg(cpu,0)==8;flow['malloc_PLT_entered']=True
        if pc==LIBC_BASE+0x1BB08:
            assert self._reg(cpu,0)==8;flow['malloc_body_entered']=True
        if off==0x2481DC:
            pointer=self._reg(cpu,0);assert pointer!=0
            flow['allocation_pointer']=pointer;flow['allocation_before']=bytes(cpu.mem_read(pointer,8))
        if off==VM_RESUME:
            assert cpu.reg_read(arm.UC_ARM64_REG_SP)==int(call['SP'],16) and self._idctor_saved_hash(cpu)==call['callee_saved_sha256']
            call.update(returned=True,return_index=len(self._sw_sites),caller_SP_and_callee_saved_restored=True)
            self._sw_return(cpu,state)
        self._base_observe(cpu,pc,state)
        assert self.late_jni_calls==self._jev_initial_late and self.java_dispatch_calls==self._jev_initial_java

    def finish(self,result,state,proof):
        assert self._sw_done and self._sw_reason in ('uncovered_VM_callback_before_execution','callback_budget_before_next_call')
        assert self._sw_objects and all(row['initialized'] for row in self._sw_objects)
        delta=result['allocator_events'][len(self._sw_events):];counts=deepcopy(result['actual_allocator_counts'])
        for event in delta:counts['malloc' if event[0]=='alloc' else 'free']-=1
        for event in self._sw_aux:counts[event['kind']]-=1
        old=super().finish(dict(result,allocator_events=self._sw_events,actual_allocator_counts=counts),state,proof)
        assert old==self._sw_parent['case_result'],'complete CRC/eighth checkpoint differs'
        trace=hashlib.sha256()
        for site in self._sw_sites:trace.update(site.encode()+bytes.fromhex(self._sw_code[site]))
        return dict(complete_CRC_eighth_parent_case_equal=True,parent_case_sha256=digest(old),constructed_strings=self._sw_objects,
            instruction_observations=len(self._sw_sites),instruction_trace_sha256=trace.hexdigest(),observed_code_sha256=digest(self._sw_code),
            callbacks=self._sw_calls,completed_callbacks=sum(c['returned'] for c in self._sw_calls),stop_reason=self._sw_reason,
            new_allocator_events=delta,allocator_aux_events=self._sw_aux,native_write_observations=len(self._sw_writes),
            actual_allocator_counts=result['actual_allocator_counts'],explicit_service_counts=result['explicit_service_counts'],
            new_providers=[],new_SVCs=[],new_JNI_effects=[],source_values_or_hashes_exported=False,
            allocation_contents_exported=False,key_contents_or_hashes_exported=False,native_snapshot_used_as_VM_model_input=False,
            complete_standalone_signer_verified=False,online_acceptance_verified=False)


def run(library,libc):
    previous.validate(json.loads(previous.EVIDENCE.read_text(encoding='utf-8')))
    original=previous.CrcEighth;previous.CrcEighth=PostCrcConstructors
    print('Replaying original post-CRC default-string constructor window',flush=True)
    try:return previous.run(library,libc)
    finally:previous.CrcEighth=original


def compare(path,base,label):
    pages,inputs,_=consumer_fixture.fixture(path,base,'default',label)
    block=inputs['argument_block_address'];obj=int.from_bytes(_read_span(pages,block+8,8),'little')
    empty=(23).to_bytes(4,'little')+(7).to_bytes(4,'little') if label.startswith('custom_') else b'\x08'+bytes(7)
    _write_span(pages,base+0x6E168,empty)
    failure=label in ('allocation_failure','custom_descriptor_failure')
    pointer=0 if failure else obj if label=='payload_object_alias' else block if label=='payload_packed_alias' else consumer_fixture.G+0x4FFF if label=='cross_page_payload' else consumer_fixture.G+0x4000
    native_pages={k:bytearray(v) for k,v in pages.items()}
    before=_read_span(pages,consumer_fixture.G,0xA000);events=[];model_events=[];writes=[];returns=[]
    saved={getattr(arm,'UC_ARM64_REG_X'+str(i)):0x120000+i for i in range(19,30)}
    def allocate(cpu,size):
        assert bytes(cpu.mem_read(obj,16))==(base+0x34F5F8).to_bytes(8,'little')+empty
        events.append(['allocate',size,pointer]);return pointer
    def model_allocate(p,size):model_events.append(['allocate',size,pointer]);return pointer
    def no_free(*args):raise AssertionError('unexpected default-constructor free')
    def observe(cpu,pc):
        if pc==base+0x2481F8:
            assert cpu.reg_read(arm.UC_ARM64_REG_SP)==consumer_fixture.G+0xEF00
            assert all(cpu.reg_read(r)==value for r,value in saved.items());returns.append(True)
    def write(cpu,address,size):
        off=cpu.reg_read(arm.UC_ARM64_REG_PC)-base
        if off in (0x2481CC,0x2481D0,0x2481DC,0x2481E4,0x2481EC):writes.append((off,address,size))
    result,memory,allocations,ledger=consumer_fixture.oracle.native(path,base,0x2884CC,[block],native_pages,
        malloc_handler=allocate,extra_registers=saved,instruction_observer=observe,memory_write_observer=write,instruction_limit=1000)
    value=consumer_fixture.model.apply_request_287474_consumer(pages,**inputs,allocate=model_allocate,free=no_free)
    assert value==result==pointer and events==model_events==[['allocate',8,pointer]]
    assert _read_span(pages,consumer_fixture.G,0xA000)==memory and allocations==ledger==[] and returns==[True]
    assert writes==[(0x2481CC,obj,8),(0x2481D0,obj+8,8),(0x2481DC,obj+16,8),
        (0x2481EC,obj+8,4) if failure else (0x2481E4,pointer,1)]
    print('PASS post-CRC default constructor',hex(base),label,flush=True)
    return dict(image_base=hex(base),case=label,allocation_succeeded=not failure,original_tail_wrapper_and_constructor_returned=True,
        full_declared_guest_bytes_and_padding_equal=True,allocation_request_and_return_equal=True,
        exact_store_addresses_and_widths_verified=True,SP_and_callee_saved_restored=True,
        synthetic_component_allocator=True,native_snapshot_input=False,complete_physical_ABI_verified=False)


def guards(path):
    rows=[]
    for label in GUARDS:
        base=consumer_fixture.BASES[0];pages,inputs,_=consumer_fixture.fixture(path,base,'default','normal')
        block=inputs['argument_block_address'];obj=int.from_bytes(_read_span(pages,block+8,8),'little')
        if label=='wrong_target':_write_span(pages,block,(base+1).to_bytes(8,'little'))
        elif label=='wrong_wrapper':inputs['wrapper_offset']=1
        elif label=='missing_packed':del pages[block>>12]
        elif label=='missing_object':_write_span(pages,block+8,(0x66000000).to_bytes(8,'little'))
        elif label=='missing_empty_descriptor':del pages[(base+0x6E168)>>12]
        before={k:bytes(v) for k,v in pages.items()}
        def allocate(p,size):
            _write_span(p,consumer_fixture.G+0x4000,b'synthetic allocation side effect')
            if label=='allocator_late_failure':raise RefillUnsupported('declared allocator rejection')
            if label=='unmapped_allocation':return 0x66000000
            if label=='invalid_allocation':return -1
            return consumer_fixture.G+0x4000
        try:consumer_fixture.model.apply_request_287474_consumer(pages,**inputs,allocate=allocate,free=lambda *args:None)
        except (RefillUnsupported,ValueError,OverflowError):pass
        else:raise AssertionError('default constructor guard accepted '+label)
        assert before=={k:bytes(v) for k,v in pages.items()}
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True))
    return rows

EXPECTED_CASE_SHA256='fc59939efe85687e80ff1ab70f9dc82127cd59567bbc0f4d3d6ea86599070cca'
EXPECTED={'instruction_observations': 1151, 'callbacks': [{'index': 1, 'descriptor_address': '0x7004cdf8', 'descriptor_width': 48, 'wrapper_offset': '0x2884cc', 'target_offset': '0x2481ac', 'VM_cursor_offset': '0x10a9e0', 'SP': '0x7004b930', 'callee_saved_sha256': '1dfcf39e697485c9789eaf1f5667782d682043ac2a66bc54fafb8587c49e2af9', 'VM_call_executed': True, 'wrapper_entered': True, 'target_entered': True, 'returned': True, 'return_index': 583, 'caller_SP_and_callee_saved_restored': True}, {'index': 1151, 'descriptor_address': '0x7004c9f0', 'descriptor_width': 48, 'wrapper_offset': '0x288898', 'target_offset': '0x2850a8', 'VM_cursor_offset': '0x10aa00', 'SP': '0x7004b930', 'callee_saved_sha256': '1dfcf39e697485c9789eaf1f5667782d682043ac2a66bc54fafb8587c49e2af9', 'VM_call_executed': False, 'wrapper_entered': False, 'target_entered': False, 'returned': False}], 'new_allocator_events': [['alloc', 8, 325944128, '0x2481dc']], 'actual_allocator_counts': {'malloc': 625, 'free': 278, 'gc': 3, 'flush': 4}, 'native_write_observations': 119}


def sources():
    return dict(verifier_sha256=sha256(Path(__file__)),parent_verifier_sha256=sha256(Path(previous.__file__)),
        parent_chain_sha256=digest(previous.sources()),consumer_fixture_sha256=sha256(Path(consumer_fixture.__file__)),
        callback_model_sha256=sha256(Path(consumer_fixture.model.__file__)),
        object_model_sha256=sha256(Path(consumer_fixture.__file__).with_name('vm9_objects.py')),
        native_oracle_sha256=sha256(Path(consumer_fixture.oracle.__file__)))


def claims():
    return dict(evidence_label='Sample verified',complete_CRC_eighth_parent_case_equal=True,
        original_tail_wrappers_default_constructors_and_malloc_executed=True,exact_header_pointer_and_single_NUL_writes_verified=True,
        object_neighbors_descriptor_and_payload_tail_preserved=True,new_eight_byte_allocations_live=True,
        eight_JSON_nodes_keys_CRC_storage_and_prior_constructed_strings_preserved=True,
        source_values_or_hashes_exported=False,allocation_contents_exported=False,key_contents_or_hashes_exported=False,
        native_snapshot_used_as_VM_model_input=False,real_ART_JVM_execution=False,Android_execution=False,
        complete_physical_ABI_verified=False,complete_standalone_signer_verified=False,online_acceptance_verified=False)


def providers():
    return dict(parent_evidence_sha256=sha256(previous.EVIDENCE),maximum_new_callbacks=MAX_NEW_CALLBACKS,
        maximum_new_observations=MAX_NEW_INSTRUCTIONS,admitted_callback=['0x2884cc','0x2481ac'],new_providers=[],new_import_bindings=[],
        allocation='inherited import routing to original matching Bionic malloc body',
        new_SVC_and_JNI_policy='stop before execution',unknown_callback_policy='stop before VM call',
        inherited_original_JNI_acquisition_body_executed=False,
        inherited_JNI_provider='controlled eight-byte env write; original body bypassed',
        component_allocators='declared synthetic success/failure services only; native snapshots never used as model input',
        inherited_component_controls_rerun=False)


def capture(library,libc):
    case=run(library,libc);parent=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'))
    controls=dict(default_constructor=[compare(library,base,label) for base in consumer_fixture.BASES for label in LABELS],
        constructor_guards=guards(library))
    return dict(schema=SCHEMA,claims=claims(),providers=providers(),source_fingerprints=sources(),
        parent_evidence_sha256=sha256(previous.EVIDENCE),case_result=case,case_result_sha256=digest(case),
        component_controls=controls,inherited_controls_sha256=digest(parent['component_controls']))


def _validate(data,parent):
    assert set(data)=={'schema','claims','providers','source_fingerprints','parent_evidence_sha256','case_result',
        'case_result_sha256','component_controls','inherited_controls_sha256'}
    assert data['schema']==SCHEMA and data['claims']==claims() and data['providers']==providers()
    assert data['source_fingerprints']==sources() and data['parent_evidence_sha256']==sha256(previous.EVIDENCE)
    assert data['inherited_controls_sha256']==digest(parent['component_controls'])
    row=data['case_result'];assert data['case_result_sha256']==digest(row)==EXPECTED_CASE_SHA256
    assert set(row)=={'complete_CRC_eighth_parent_case_equal','parent_case_sha256','constructed_strings','instruction_observations',
        'instruction_trace_sha256','observed_code_sha256','callbacks','completed_callbacks','stop_reason','new_allocator_events',
        'allocator_aux_events','native_write_observations','actual_allocator_counts','explicit_service_counts','new_providers',
        'new_SVCs','new_JNI_effects','source_values_or_hashes_exported','allocation_contents_exported','key_contents_or_hashes_exported',
        'native_snapshot_used_as_VM_model_input','complete_standalone_signer_verified','online_acceptance_verified'}
    assert row['complete_CRC_eighth_parent_case_equal'] is True and row['parent_case_sha256']==digest(parent['case_result'])
    assert 0<row['completed_callbacks']<=MAX_NEW_CALLBACKS and 0<row['instruction_observations']<MAX_NEW_INSTRUCTIONS
    assert row['stop_reason'] in ('uncovered_VM_callback_before_execution','callback_budget_before_next_call')
    for key,value in EXPECTED.items():assert row[key]==value
    assert row['new_providers']==row['new_SVCs']==row['new_JNI_effects']==row['allocator_aux_events']==[]
    assert all(row[k] is False for k in ('source_values_or_hashes_exported','allocation_contents_exported','key_contents_or_hashes_exported',
        'native_snapshot_used_as_VM_model_input','complete_standalone_signer_verified','online_acceptance_verified'))
    assert row['explicit_service_counts']==parent['case_result']['explicit_service_counts']
    objects=row['constructed_strings'];calls=row['callbacks']
    assert len(objects)==row['completed_callbacks'] and len(calls)==len(objects)+1
    assert len({o['object_address'] for o in objects})==len({o['payload_address'] for o in objects})==len(objects)
    for obj,call in zip(objects,calls):
        assert obj['initial_capacity']==obj['allocation_size']==8 and obj['initial_length']==0
        assert obj['source_values_or_hashes_exported'] is False
        assert all(obj[k] is True for k in ('initial_descriptor_from_ELF_verified','initialized','actual_X0_and_tail_wrapper_LR_equal',
            'original_malloc_PLT_and_body_entered','new_allocation_in_current_call','returned_X0_equals_payload',
            'exact_header_pointer_and_one_byte_NUL_writes_verified','payload_remaining_seven_bytes_preserved',
            'object_neighbor_eight_bytes_preserved','descriptor_all_48_bytes_preserved','prior_JSON_CRC_and_constructed_strings_preserved'))
        assert (call['wrapper_offset'],call['target_offset'])==('0x2884cc','0x2481ac')
        assert call['descriptor_address']==obj['descriptor_address'] and call['index']<call['return_index']==obj['return_index']
        assert all(call[k] is True for k in ('VM_call_executed','wrapper_entered','target_entered','returned','caller_SP_and_callee_saved_restored'))
    old=parent['case_result']['callbacks'][-1]
    for key in ('descriptor_address','VM_cursor_offset','SP','callee_saved_sha256','wrapper_offset','target_offset'):assert calls[0][key]==old[key]
    assert calls[0]['index']==1 and calls[-1]['index']==row['instruction_observations']
    assert all(calls[-1][k] is False for k in ('VM_call_executed','wrapper_entered','target_entered','returned'))
    assert [(e[0],e[1],e[3]) for e in row['new_allocator_events']]==[('alloc',8,'0x2481dc')]*len(objects)
    controls=data['component_controls'];assert set(controls)=={'default_constructor','constructor_guards'}
    assert [(c['image_base'],c['case']) for c in controls['default_constructor']]==[(hex(base),label) for base in consumer_fixture.BASES for label in LABELS]
    for c in controls['default_constructor']:
        assert c['allocation_succeeded'] is (c['case'] not in ('allocation_failure','custom_descriptor_failure'))
        assert all(c[k] is True for k in ('original_tail_wrapper_and_constructor_returned','full_declared_guest_bytes_and_padding_equal',
            'allocation_request_and_return_equal','exact_store_addresses_and_widths_verified','SP_and_callee_saved_restored','synthetic_component_allocator'))
        assert c['native_snapshot_input'] is c['complete_physical_ABI_verified'] is False
    assert [c['case'] for c in controls['constructor_guards']]==list(GUARDS)
    assert all(c['rejected'] is c['all_pages_unchanged'] is True for c in controls['constructor_guards'])


def validate(data):
    parent=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(parent);_validate(data,parent)


def damaged_evidence_rejected(data):
    parent=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(parent)
    changes=[(('claims','real_ART_JVM_execution'),True),(('providers','inherited_original_JNI_acquisition_body_executed'),True),
        (('source_fingerprints','object_model_sha256'),'0'*64),(('inherited_controls_sha256',),'0'*64),
        (('case_result','complete_CRC_eighth_parent_case_equal'),False),(('case_result','parent_case_sha256'),'0'*64),
        (('case_result','constructed_strings',0,'initial_capacity'),0),(('case_result','constructed_strings',0,'initial_length'),1),
        (('case_result','constructed_strings',0,'original_malloc_PLT_and_body_entered'),False),
        (('case_result','constructed_strings',0,'new_allocation_in_current_call'),False),
        (('case_result','constructed_strings',0,'returned_X0_equals_payload'),False),
        (('case_result','constructed_strings',0,'exact_header_pointer_and_one_byte_NUL_writes_verified'),False),
        (('case_result','constructed_strings',0,'payload_remaining_seven_bytes_preserved'),False),
        (('case_result','constructed_strings',0,'object_neighbor_eight_bytes_preserved'),False),
        (('case_result','constructed_strings',0,'descriptor_all_48_bytes_preserved'),False),
        (('case_result','constructed_strings',0,'prior_JSON_CRC_and_constructed_strings_preserved'),False),
        (('case_result','callbacks',-1,'target_entered'),True),(('case_result','allocation_contents_exported'),True),
        (('case_result','registers'),[]),(('component_controls','default_constructor',0,'exact_store_addresses_and_widths_verified'),False),
        (('component_controls','default_constructor',0,'native_snapshot_input'),True),(('component_controls','constructor_guards',0,'rejected'),False)]
    for path,value in changes:
        bad=deepcopy(data);target=bad
        for key in path[:-1]:target=target[key]
        target[path[-1]]=value
        if path[0]=='case_result':bad['case_result_sha256']=digest(bad['case_result'])
        try:_validate(bad,parent)
        except (AssertionError,KeyError,ValueError,TypeError,IndexError):continue
        raise AssertionError('damaged post-CRC constructor evidence accepted: '+repr(path))
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
    print(json.dumps(dict(schema=SCHEMA,constructed_strings=data['case_result']['completed_callbacks'],
        damaged_evidence_rejected=rejected,complete_standalone_signer_verified=False)))


if __name__=='__main__':main()
