"""Native relational check for a serial atomic uint32 source and fifth JSON node."""
from __future__ import annotations
import argparse,hashlib,importlib,json,os,struct
from pathlib import Path
from copy import deepcopy
import verify_vm9_native_171_post_environment_fields_dynamic_20261124 as previous
import verify_vm9_second_atomic_u32_fresh_20261016 as atomic_fixture
import verify_vm9_u32_double_fresh_20261016 as unsigned_fixture
from unicorn import arm64_const as arm
from elftools.elf.elffile import ELFFile
from vm9_allocator import _read_span,_write_span
VM_CALL,VM_RESUME,LIBC_BASE=previous.VM_CALL,previous.VM_RESUME,previous.LIBC_BASE
bootstrap,digest,raw_hash,sha256=previous.bootstrap,previous.digest,previous.raw_hash,previous.sha256
MAX_CALLS,MAX_INSTRUCTIONS=2,60000
number_fixture=previous.number_fixture
UNSIGNED_VALUES=(('zero',0),('one',1),('signbit',0x80000000),('u32max',0xFFFFFFFF))
UNSIGNED_PROFILES=('zero','signbit','u32max','high_mixed')
EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_atomic_numeric_field_dynamic_20261124.json')
SCHEMA='vm9-native-171-atomic-numeric-field-dynamic-20261124-v1'


class AtomicNumericField(previous.PostEnvironmentFields):
    def __init__(self,control):
        super().__init__(control)
        self._jan_active=self._jan_done=False
        self._jan_sites,self._jan_code,self._jan_writes=[],{},[]
        self._jan_calls,self._jan_aux=[],[]
        self._jan_flow=None;self._jan_origin=None;self._jan_stop_reason=None

    def _jan_index(self):return dict(window='atomic_suffix',index=len(self._jan_sites))

    def _jst_index(self):
        if self._jan_active:return self._jan_index()
        return super()._jst_index()

    def _jan_track(self,cpu,pc):
        key=self._fmt_site(pc);self._jan_sites.append(key);self._jan_code[key]=bytes(cpu.mem_read(pc,4)).hex()

    def _jan_stop(self,cpu,reason):
        self._jan_done=True;self._jan_stop_reason=reason
        cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,bootstrap().digest.context.outer.oracle.STOP)

    def _jan_call(self,cpu):
        descriptor=self._reg(cpu,0);vmstate=self._reg(cpu,19)
        return dict(index=len(self._jan_sites),descriptor_address=hex(descriptor),descriptor_width=48,
            wrapper_offset=hex(self._reg(cpu,8)-self.image),target_offset=hex(self._u(cpu,descriptor)-self.image),
            VM_cursor_offset=hex(self._u(cpu,vmstate)-self.image),SP=hex(cpu.reg_read(arm.UC_ARM64_REG_SP)),
            callee_saved_sha256=self._idctor_saved_hash(cpu),VM_call_executed=False,wrapper_entered=False,
            target_entered=False,returned=False)

    def _jan_retained(self,cpu):
        out=[];initial=self._jwx_typed_output
        for name,width in (('wrapper_address',16),('counter_address',4),('root_address',64)):
            address=int(initial[name],16);out.append((address,bytes(cpu.mem_read(address,width))))
        for row in self._jff_flows+self._jst_flows:
            node=int(row['node']['address'],16);out.append((node,bytes(cpu.mem_read(node,64))))
            key=self._u(cpu,node+56);out.append((key,self._bounded_cstring(cpu,key,limit=4096)+b'\0'))
        return out

    def _jst_stop(self,cpu,reason):
        if self._jan_active:return self._jan_stop(cpu,reason)
        if reason!='callback_budget_before_next_call':return super()._jst_stop(cpu,reason)
        assert not self._jan_active and len(self._jst_sites)==4205
        assert cpu.reg_read(arm.UC_ARM64_REG_PC)==self.image+VM_CALL
        assert all(row['node_verified'] for row in self._jst_flows)
        self._jst_done=True;self._jst_stop_reason=reason;self._jst_active=False
        self._jan_events=deepcopy(self._jst_state['allocator_events_ref'])
        self._jan_active=True;self._jan_track(cpu,self.image+VM_CALL)
        call=self._jan_call(cpu);self._jan_calls.append(call);self._jan_current=call
        assert (call['wrapper_offset'],call['target_offset'])==('0x28887c','0x256f58')
        self._jan_descriptor=int(call['descriptor_address'],16)
        self._jan_before=bytes(cpu.mem_read(self._jan_descriptor,48))
        self._jan_receiver=self._u(cpu,self._jan_descriptor+8)
        assert self._jan_receiver<=(1<<64)-0x13C and (self._jan_receiver+0x138)&3==0
        self._jan_receiver_before=bytes(cpu.mem_read(self._jan_receiver,0x13C))
        self._jan_word=bytes(cpu.mem_read(self._jan_receiver+0x138,4))
        self._jan_protected=self._jan_retained(cpu)
        matches=[name for name,value in vars(self).items()
            if name!='_jan_receiver' and type(value) is int and value==self._jan_receiver]
        live={}
        for event in self._jan_events:
            if event[0]=='alloc':live[event[2]]=event[1]
            elif event[0]=='free':live.pop(event[1],None)
        containing=[(address,size) for address,size in live.items()
            if address<=self._jan_receiver and self._jan_receiver+0x13C<=address+size]
        self._jan_origin=dict(receiver_address=hex(self._jan_receiver),known_pointer_relations=matches,
            containing_live_allocations=[dict(address=hex(a),size=n,receiver_offset=self._jan_receiver-a) for a,n in containing],
            receiver_equals_JSON_root=self._jan_receiver==int(self._jwx_typed_output['root_address'],16),
            source_offset='0x138',source_width=4,source_value_or_hash_exported=False)
        assert matches or containing,'receiver provenance is unresolved'
        print('Reached serial atomic getter with retained receiver provenance',flush=True)
        print(json.dumps(self._jan_origin),flush=True)
        self._base_observe(cpu,self.image+VM_CALL,self._jst_state)

    def native_runner(self,*args,**kwargs):
        old_write=kwargs['memory_write_observer']
        def write(cpu,address,size):
            if self._jan_active:
                self._jan_writes.append(dict(index=len(self._jan_sites),PC=self._fmt_site(cpu.reg_read(arm.UC_ARM64_REG_PC)),
                    address=hex(address),size=size))
            if old_write:old_write(cpu,address,size)
        kwargs['memory_write_observer']=write
        return super().native_runner(*args,**kwargs)

    def _jan_conversion(self,cpu,pc):
        old=self._jst_pending;self._jst_pending=self._jan_flow
        try:super()._jst_conversion(cpu,pc)
        finally:self._jst_pending=old

    def _jan_number_arguments(self,cpu,state):
        old=self._jst_pending;self._jst_pending=self._jan_flow
        try:super()._jst_number_arguments(cpu,state)
        finally:self._jst_pending=old
        assert self._jan_flow['public']['argument']['prior_child_count']==4

    def _jan_number_return(self,cpu,state):
        old=self._jst_pending;self._jst_pending=self._jan_flow
        try:super()._jst_number_return(cpu,state)
        finally:self._jst_pending=old

    def observe(self,cpu,pc,state):
        if not self._jan_active:return super().observe(cpu,pc,state)
        self._jan_state=state;self._jan_track(cpu,pc)
        if len(self._jan_sites)>=MAX_INSTRUCTIONS:self._jan_stop(cpu,'instruction_budget');return
        if pc in (LIBC_BASE+0x9833C,LIBC_BASE+0x97F40):
            self._jan_aux.append(dict(index=len(self._jan_sites),kind='gc' if pc==LIBC_BASE+0x9833C else 'flush'))
        call=self._jan_current
        if pc==self.image+VM_CALL:
            assert call['returned'],'unexpected nested callback in atomic numeric stage'
            call=self._jan_call(cpu);self._jan_calls.append(call)
            if len(self._jan_calls)>MAX_CALLS:self._jan_stop(cpu,'callback_budget_before_next_call');return
            if (call['wrapper_offset'],call['target_offset'])!=('0x288854','0x261350'):
                self._jan_stop(cpu,'uncovered_VM_callback_before_execution');return
            self._jan_current=call;self._jan_number_arguments(cpu,state)
        if self._jst_guard(cpu,pc):return
        self._jan_conversion(cpu,pc)
        if pc==self.image+int(call['wrapper_offset'],16):call.update(VM_call_executed=True,wrapper_entered=True)
        if pc==self.image+int(call['target_offset'],16):
            call['target_entered']=True
            if call['target_offset']=='0x256f58':
                assert self._reg(cpu,0)==self._jan_receiver and self._reg(cpu,30)==self.image+0x28888C
                self._jan_origin['actual_X0_receiver_and_wrapper_return_equal']=True
            else:
                flow=self._jan_flow
                assert self._reg(cpu,0)==flow['wrapper'] and self._reg(cpu,1)==flow['key']
                assert cpu.reg_read(arm.UC_ARM64_REG_D0).to_bytes(8,'little')==flow['bits']
                flow['public']['argument']['actual_X0_X1_D0_equal']=True
        if pc==self.image+0x256F5C:
            assert self._reg(cpu,8)==self._jan_receiver+0x138
            assert bytes(cpu.mem_read(self._reg(cpu,8),4))==self._jan_word
            self._jan_origin['actual_LDAR_address_equal']=True
        if pc==self.image+VM_RESUME:
            assert cpu.reg_read(arm.UC_ARM64_REG_SP)==int(call['SP'],16)
            assert self._idctor_saved_hash(cpu)==call['callee_saved_sha256']
            call.update(returned=True,return_index=len(self._jan_sites),caller_SP_and_callee_saved_restored=True)
            if call['target_offset']=='0x256f58':
                expected=bytearray(self._jan_before);expected[16:20]=self._jan_word
                assert bytes(cpu.mem_read(self._jan_descriptor,48))==expected
                assert bytes(cpu.mem_read(self._jan_receiver,0x13C))==self._jan_receiver_before
                assert self._reg(cpu,0)==int.from_bytes(self._jan_word,'little')
                assert state['allocator_events_ref']==self._jan_events
                assert all(bytes(cpu.mem_read(a,len(raw)))==raw for a,raw in self._jan_protected)
                self._jan_origin.update(unsigned_X0_and_exact_four_byte_store_equal=True,
                    descriptor_padding_and_receiver_bytes_preserved=True,retained_JSON_objects_and_keys_preserved=True,
                    no_allocation_or_free_effects=True,serial_observation_only=True,
                    concurrent_acquire_release_semantics_verified=False)
                row=dict(label='serial_atomic_u32',source=self._jan_origin,conversion={},argument={},node={},
                    node_verified=False,scalar_values_exported=False,scalar_hashes_exported=False)
                self._jan_flow=dict(public=row,word=self._jan_word,
                    bits=struct.pack('<d',float(int.from_bytes(self._jan_word,'little'))))
                print('Original atomic getter returned with packed padding and retained JSON bytes preserved',flush=True)
            else:self._jan_number_return(cpu,state)
        self._base_observe(cpu,pc,state)
        assert self.late_jni_calls==self._jev_initial_late and self.java_dispatch_calls==self._jev_initial_java

    def finish(self,result,state,proof):
        assert self._jan_done and self._jan_flow is not None and self._jan_flow['public']['node_verified']
        delta=result['allocator_events'][len(self._jan_events):]
        prefix,counts=dict(result),deepcopy(result['actual_allocator_counts'])
        for event in delta:counts['malloc' if event[0]=='alloc' else 'free']-=1
        for event in self._jan_aux:counts[event['kind']]-=1
        prefix.update(allocator_events=self._jan_events,actual_allocator_counts=counts)
        old=super().finish(prefix,state,proof)
        assert old==self._jan_parent['case_result'],'complete post-environment parent differs'
        trace=hashlib.sha256()
        for key in self._jan_sites:trace.update(key.encode()+bytes.fromhex(self._jan_code[key]))
        return dict(parent_case_equal=True,parent_case_sha256=digest(old),field_relation=self._jan_flow['public'],
            instruction_observations=len(self._jan_sites),instruction_trace_sha256=trace.hexdigest(),
            observed_code_sha256=digest(self._jan_code),callbacks=self._jan_calls,
            completed_callbacks=sum(call['returned'] for call in self._jan_calls),stop_reason=self._jan_stop_reason,
            new_allocator_events=delta,allocator_aux_events=self._jan_aux,native_write_observations=len(self._jan_writes),
            actual_allocator_counts=result['actual_allocator_counts'],explicit_service_counts=result['explicit_service_counts'],
            new_providers=[],new_SVCs=[],new_JNI_effects=[],scalar_values_or_hashes_exported=False,
            key_contents_or_hashes_exported=False,native_snapshot_used_as_VM_model_input=False,
            complete_standalone_signer_verified=False,online_acceptance_verified=False)


def unsigned_append_control(path,base,label,value):
    pages,packed,failures=number_fixture.fresh(path,base,'two_children');g=number_fixture.G;root=g+0x2000
    nodes=[g+0x3100+i*0x100 for i in range(4)]
    for i,node in enumerate(nodes):
        key=g+0x7000+i*0x20
        _write_span(pages,node,bytes(64));_write_span(pages,key,('prior-'+str(i)).encode()+b'\0')
        for offset,word in ((0,nodes[i+1] if i+1<4 else 0),(8,nodes[i-1] if i else nodes[-1]),(56,key)):
            number_fixture.w(pages,node+offset,word)
        number_fixture.w(pages,node+24,8,4);number_fixture.w(pages,node+40,i+1,4)
        _write_span(pages,node+48,struct.pack('<d',float(i+1)))
    number_fixture.w(pages,root+16,nodes[0]);_write_span(pages,packed+24,struct.pack('<d',float(value)))
    before=_read_span(pages,packed,40);expected=number_fixture.services('two_children',failures);actual=number_fixture.services('two_children',failures)
    memory,watched,steps=number_fixture.original(path,base,pages,packed,expected)
    result=number_fixture.second.apply_request_287474_json_number_callback(pages,argument_block_address=packed,
        entry_stack_address=number_fixture.SP,image_base=base,allocate=actual.malloc,free=actual.free)
    assert result is True and _read_span(pages,g,0xA000)==memory
    assert all(_read_span(pages,a,n)==raw for (a,n),raw in watched.items())
    assert actual.events==expected.events and actual.freed==expected.freed
    assert actual.effects.calls==expected.effects.calls and actual.effects.blocks==expected.effects.blocks
    assert _read_span(pages,packed,32)==before[:32] and _read_span(pages,packed+33,7)==before[33:]
    print('PASS fifth unsigned numeric append',hex(base),label,flush=True)
    return dict(image_base=hex(base),prior_children=4,value_profile=label,steps=steps,
        original_wrapper_and_numeric_append_returned=True,guest_image_and_all_declared_payload_bytes_equal=True,
        ordered_allocation_free_effects_equal=True,one_byte_result_and_padding_equal=True,
        native_snapshot_input=False,complete_physical_ABI_verified=False)



def sources():
    return dict(verifier_sha256=sha256(Path(__file__)),parent_verifier_sha256=sha256(Path(previous.__file__)),
        parent_chain_sha256=digest(previous.sources()),atomic_fixture_sha256=sha256(Path(atomic_fixture.__file__)),
        unsigned_fixture_sha256=sha256(Path(unsigned_fixture.__file__)),numeric_fixture_sha256=sha256(Path(number_fixture.__file__)),
        unsigned_VM_model_sha256=sha256(Path(unsigned_fixture.__file__).with_name('vm_full.py')),
        callback_model_sha256=sha256(Path(atomic_fixture.model.__file__)),
        native_oracle_sha256=sha256(Path(number_fixture.oracle.__file__)))


def claims():
    return dict(evidence_label='Sample verified',complete_post_environment_parent_case_equal=True,
        receiver_provenance_relations_observed=True,actual_LDAR_address_and_u32_return_verified=True,
        unsigned_zero_extension_and_exact_binary64_observed=True,fifth_JSON_numeric_node_verified=True,
        old_nodes_and_owned_keys_preserved_except_append_links=True,new_node_and_key_allocations_live=True,
        current_native_values_used_only_for_relations=True,native_snapshot_used_to_initialize_VM_model=False,
        scalar_values_or_hashes_exported=False,key_contents_or_hashes_exported=False,
        concurrent_acquire_release_semantics_verified=False,real_ART_JVM_execution=False,Android_execution=False,
        complete_physical_ABI_verified=False,complete_standalone_signer_verified=False,online_acceptance_verified=False)


def providers():
    return dict(parent_evidence_sha256=sha256(previous.EVIDENCE),new_providers=[],new_import_bindings=[],
        maximum_callbacks=MAX_CALLS,maximum_observations=MAX_INSTRUCTIONS,
        admitted_new_callbacks=[['0x28887c','0x256f58'],['0x288854','0x261350']],
        atomic_source_offset='0x138',receiver_observed_prefix_width=0x13C,atomic_memory_contract='serial observation only',
        new_SVC_and_JNI_dispatch_policy='stop before execution',unknown_callback_policy='stop before VM call',
        inherited_original_JNI_acquisition_body_executed=False,
        inherited_JNI_provider='controlled eight-byte env write; original body bypassed',
        existing_serial_getter_unsigned_conversion_and_numeric_models_reused=True,
        component_allocations='existing explicit synthetic services; no native snapshots as model input')


def component_controls(path):
    saved=os.environ.get('TOMATO_LIBMETASEC');os.environ['TOMATO_LIBMETASEC']=str(path.resolve())
    try:model=importlib.import_module('vm_full')
    finally:
        if saved is None:os.environ.pop('TOMATO_LIBMETASEC',None)
        else:os.environ['TOMATO_LIBMETASEC']=saved
    assert Path(model.__file__).resolve()==Path(unsigned_fixture.__file__).with_name('vm_full.py').resolve()
    assert raw_hash(model.SO)==atomic_fixture.oracle.LIBRARY_SHA256
    return dict(atomic_getter=[atomic_fixture.compare(path,base,label)
            for base in atomic_fixture.BASES for label in atomic_fixture.PROFILES],
        unsigned_conversion=[unsigned_fixture.compare(path,model,base,label,value,backed)
            for base in unsigned_fixture.BASES for label,value in unsigned_fixture.PROFILES if label in UNSIGNED_PROFILES for backed in (False,True)],
        fifth_node_append=[unsigned_append_control(path,base,label,value)
            for base in number_fixture.BASES for label,value in UNSIGNED_VALUES],
        atomic_guards=atomic_fixture.guards(path),unsigned_conversion_guards=unsigned_fixture.guards(path,model))


def run(library,libc):
    parent=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(parent)
    st_parent=json.loads(previous.previous.EVIDENCE.read_text(encoding='utf-8'))
    env_parent=json.loads(previous.previous.previous.EVIDENCE.read_text(encoding='utf-8'))
    jff_parent=json.loads(previous.previous.previous.previous.EVIDENCE.read_text(encoding='utf-8'))
    base_parent=json.loads(previous.previous.previous.previous.previous.EVIDENCE.read_text(encoding='utf-8'))
    scope_parent=previous.previous.previous.previous.previous.parent_evidence()
    md5_parent=previous.previous.previous.previous.previous.previous.parent_evidence()
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
                symbol=next(s for s in elf.get_section_by_name('.dynsym').iter_symbols() if s.name=='strncmp' and s['st_shndx']!='SHN_UNDEF')
                strncmp=LIBC_BASE+symbol['st_value']
    def create(control):
        s=AtomicNumericField(control);s.path,s.continue_to_svc=library,True
        s._postcrc_parent,s._pcb_parent,s._jwx_parent=md5_parent,scope_parent,base_parent
        s._jff_parent,s._jev_parent,s._jst_parent,s._jan_parent=jff_parent,env_parent,st_parent,parent
        s._jwx_exec,s._jwx_plt,s._jwx_strncmp=executable,plt,strncmp
        return s
    print('Replaying original serial atomic getter and unsigned numeric append',flush=True)
    rows=prefix.digest.context.replay(library,libc,case_controls=[prefix.CONTROL],_extension_factory=create,
        _request_profile=prefix.digest.previous.previous.name.previous.previous.PROFILE['name'],
        _handler_read_profile=prefix.digest.context.NULL_PAYLOAD_READ_PROFILE['name'])
    assert len(rows)==1
    return dict(schema=SCHEMA,claims=claims(),providers=providers(),source_fingerprints=sources(),
        parent_evidence_sha256=sha256(previous.EVIDENCE),case_result=rows[0],case_result_sha256=digest(rows[0]),
        component_controls=component_controls(library))


EXPECTED_CASE_SHA256='f92378a21c557e143f8faeab460f0d98ed669d11f88a59a2a5f0f555ae8e6711'
EXPECTED={'observations': 2845, 'calls': [1, 1030, 2845], 'returns': [12, 1858, None], 'next_pair': ['0x288854', '0x261350'], 'next_cursor': '0x10a7d0', 'source': {'receiver_address': '0x136e0000', 'known_pointer_relations': ['hash_registry_root', '_tree_receiver', '_u32_receiver'], 'containing_live_allocations': [{'address': '0x136e0000', 'size': 320, 'receiver_offset': 0}], 'receiver_equals_JSON_root': False, 'source_offset': '0x138', 'source_width': 4, 'source_value_or_hash_exported': False, 'actual_X0_receiver_and_wrapper_return_equal': True, 'actual_LDAR_address_equal': True, 'unsigned_X0_and_exact_four_byte_store_equal': True, 'descriptor_padding_and_receiver_bytes_preserved': True, 'retained_JSON_objects_and_keys_preserved': True, 'no_allocation_or_free_effects': True, 'serial_observation_only': True, 'concurrent_acquire_release_semantics_verified': False}, 'allocator_events': [['alloc', 64, 325972800, '0x2493fc'], ['alloc', 4, 325944096, '0x249198']], 'actual_allocator_counts': {'malloc': 618, 'free': 278, 'gc': 3, 'flush': 4}}


def _validate(data,parent):
    assert set(data)=={'schema','claims','providers','source_fingerprints','parent_evidence_sha256',
        'case_result','case_result_sha256','component_controls'}
    assert data['schema']==SCHEMA and data['claims']==claims() and data['providers']==providers()
    assert data['source_fingerprints']==sources() and data['parent_evidence_sha256']==sha256(previous.EVIDENCE)
    row=data['case_result'];assert data['case_result_sha256']==digest(row)==EXPECTED_CASE_SHA256
    assert row['parent_case_equal'] is True and row['parent_case_sha256']==digest(parent['case_result'])
    assert row['completed_callbacks']==2 and row['instruction_observations']==EXPECTED['observations']<MAX_INSTRUCTIONS
    assert row['stop_reason']=='callback_budget_before_next_call'
    assert row['new_providers']==row['new_SVCs']==row['new_JNI_effects']==row['allocator_aux_events']==[]
    assert row['scalar_values_or_hashes_exported'] is row['key_contents_or_hashes_exported'] is False
    assert row['native_snapshot_used_as_VM_model_input'] is row['complete_standalone_signer_verified'] is row['online_acceptance_verified'] is False
    assert not {'word','bits','registers','key_bytes','native_writes','observation_sites'}&set(row)
    field=row['field_relation']
    assert set(field)=={'label','source','conversion','argument','node','node_verified','scalar_values_exported','scalar_hashes_exported'}
    assert field['label']=='serial_atomic_u32' and field['node_verified'] is True
    assert field['scalar_values_exported'] is field['scalar_hashes_exported'] is False
    source=field['source'];assert source==EXPECTED['source']
    assert source['source_offset']=='0x138' and source['source_width']==4
    assert source['known_pointer_relations'] or source['containing_live_allocations']
    assert source['receiver_equals_JSON_root'] is source['source_value_or_hash_exported'] is False
    for key in ('actual_X0_receiver_and_wrapper_return_equal','actual_LDAR_address_equal',
            'unsigned_X0_and_exact_four_byte_store_equal','descriptor_padding_and_receiver_bytes_preserved',
            'retained_JSON_objects_and_keys_preserved','no_allocation_or_free_effects','serial_observation_only'):
        assert source[key] is True
    assert source['concurrent_acquire_release_semantics_verified'] is False
    cvt,arg,node=field['conversion'],field['argument'],field['node']
    assert (cvt['load_site'],cvt['convert_site'],cvt['store_site'])==('0x17079c','0x1707ac','0x1707f8')
    assert cvt['window']==arg['window']==node['window']=='atomic_suffix'
    assert cvt['index']<arg['index']<node['index']
    for key in ('source_low_u32_equal','unsigned_zero_extension_equal','exact_binary64_equal','stored_binary64_equal'):
        assert cvt[key] is True
    assert arg['prior_child_count']==node['prior_child_count']==4
    assert arg['key_contents_or_hashes_exported'] is False
    assert all(arg[key] is True for key in ('initial_JSON_wrapper_verified','binary64_equals_conversion','actual_X0_X1_D0_equal'))
    assert all(node[key] is True for key in ('new_live_node_and_key_allocations','binary64_equals_source_conversion',
        'int32_saturation_equal','copied_key_equal','old_nodes_and_owned_keys_preserved_except_append_links',
        'root_wrapper_and_counter_preserved','one_byte_success_store_and_other_descriptor_bytes_preserved'))
    calls=row['callbacks'];assert len(calls)==3
    assert [(c['wrapper_offset'],c['target_offset']) for c in calls[:2]]==[('0x28887c','0x256f58'),('0x288854','0x261350')]
    assert [c['index'] for c in calls]==EXPECTED['calls'] and [c.get('return_index') for c in calls]==EXPECTED['returns']
    old=parent['case_result']['callbacks'][-1]
    for key in ('descriptor_address','VM_cursor_offset','SP','callee_saved_sha256'):assert calls[0][key]==old[key]
    for call in calls[:2]:
        assert all(call[key] is True for key in ('VM_call_executed','wrapper_entered','target_entered','returned','caller_SP_and_callee_saved_restored'))
        assert call['index']<call['return_index']<=row['instruction_observations']
    assert all(calls[-1][key] is False for key in ('VM_call_executed','wrapper_entered','target_entered','returned'))
    assert [calls[-1]['wrapper_offset'],calls[-1]['target_offset']]==EXPECTED['next_pair']
    assert calls[-1]['VM_cursor_offset']==EXPECTED['next_cursor']
    assert calls[0]['return_index']<cvt['index'] and arg['index']==calls[1]['index'] and node['index']==calls[1]['return_index']
    assert row['new_allocator_events']==EXPECTED['allocator_events'] and row['actual_allocator_counts']==EXPECTED['actual_allocator_counts']
    assert row['explicit_service_counts']==parent['case_result']['explicit_service_counts']
    controls=data['component_controls']
    assert set(controls)=={'atomic_getter','unsigned_conversion','fifth_node_append','atomic_guards','unsigned_conversion_guards'}
    assert [(c['image_base'],c['case']) for c in controls['atomic_getter']]==[(hex(base),label) for base in atomic_fixture.BASES for label in atomic_fixture.PROFILES]
    assert [(c['image_base'],c['case'],c['guest_backing']) for c in controls['unsigned_conversion']]==[
        (hex(base),label,backed) for base in unsigned_fixture.BASES for label,_ in unsigned_fixture.PROFILES if label in UNSIGNED_PROFILES for backed in (False,True)]
    assert [(c['image_base'],c['prior_children'],c['value_profile']) for c in controls['fifth_node_append']]==[
        (hex(base),4,label) for base in number_fixture.BASES for label,_ in UNSIGNED_VALUES]
    for name in ('atomic_getter','unsigned_conversion','fifth_node_append'):
        for c in controls[name]:
            for key,value in c.items():
                if type(value) is bool and key!='guest_backing':
                    assert value is (key not in {'native_snapshot_input','complete_physical_ABI_verified',
                        'physical_spills_and_PAC_compared','concurrent_acquire_release_semantics_verified','complete_float_family_verified'})
    assert [c['case'] for c in controls['atomic_guards']]==list(atomic_fixture.GUARDS)
    assert all(c['rejected'] is c['all_pages_unchanged'] is True for c in controls['atomic_guards'])
    assert [c['operation'] for c in controls['unsigned_conversion_guards']]==list(unsigned_fixture.GUARDS)
    assert all(c['rejected'] is c['registers_PC_and_all_pages_unchanged'] is True for c in controls['unsigned_conversion_guards'])


def validate(data):
    parent=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(parent)
    _validate(data,parent)


def damaged_evidence_rejected(data):
    parent=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(parent)
    changes=[(('claims','concurrent_acquire_release_semantics_verified'),True),
        (('providers','inherited_original_JNI_acquisition_body_executed'),True),
        (('source_fingerprints','unsigned_VM_model_sha256'),'0'*64),
        (('case_result','parent_case_equal'),False),
        (('case_result','field_relation','source','receiver_address'),'0x0'),
        (('case_result','field_relation','source','actual_LDAR_address_equal'),False),
        (('case_result','field_relation','source','descriptor_padding_and_receiver_bytes_preserved'),False),
        (('case_result','field_relation','conversion','unsigned_zero_extension_equal'),False),
        (('case_result','field_relation','conversion','exact_binary64_equal'),False),
        (('case_result','field_relation','argument','actual_X0_X1_D0_equal'),False),
        (('case_result','field_relation','node','int32_saturation_equal'),False),
        (('case_result','field_relation','node','old_nodes_and_owned_keys_preserved_except_append_links'),False),
        (('case_result','field_relation','node','prior_child_count'),3),
        (('case_result','field_relation','node','new_live_node_and_key_allocations'),False),
        (('case_result','callbacks',-1,'target_entered'),True),
        (('case_result','scalar_values_or_hashes_exported'),True),
        (('case_result','bits'),'forbidden'),
        (('component_controls','atomic_getter',0,'concurrent_acquire_release_semantics_verified'),True),
        (('component_controls','unsigned_conversion',0,'high_source_bits_ignored'),False),
        (('component_controls','fifth_node_append',0,'ordered_allocation_free_effects_equal'),False),
        (('component_controls','atomic_guards',0,'rejected'),False),
        (('component_controls','unsigned_conversion_guards',0,'rejected'),False)]
    for path,value in changes:
        bad=deepcopy(data);target=bad
        for key in path[:-1]:target=target[key]
        target[path[-1]]=value
        if path[0]=='case_result':bad['case_result_sha256']=digest(bad['case_result'])
        try:_validate(bad,parent)
        except (AssertionError,KeyError,ValueError,TypeError,IndexError):continue
        raise AssertionError('damaged atomic numeric evidence accepted: '+repr(path))
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
            assert data['case_result']==json.loads(args.compare_case.read_text(encoding='utf-8')),'independent and public atomic cases differ'
        validate(data);rejected=damaged_evidence_rejected(data)
        with EVIDENCE.open('x',encoding='utf-8',newline='\n') as stream:stream.write(json.dumps(data,indent=2)+'\n')
    else:
        data=json.loads(EVIDENCE.read_text(encoding='utf-8'));validate(data);rejected=damaged_evidence_rejected(data)
        if args.replay:assert run(args.elf,args.libc)==data,'fresh atomic numeric replay differs'
    print(json.dumps(dict(schema=SCHEMA,verified_numeric_fields=1,completed_callbacks=data['case_result']['completed_callbacks'],
        damaged_evidence_rejected=rejected,complete_standalone_signer_verified=False)))


if __name__=='__main__':main()
