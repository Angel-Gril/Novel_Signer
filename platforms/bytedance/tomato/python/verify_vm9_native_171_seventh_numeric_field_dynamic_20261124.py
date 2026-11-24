"""Native seventh-number append preserving the entire sixth-field evidence case."""
from __future__ import annotations
import argparse,hashlib,json,struct,traceback
from copy import deepcopy
from pathlib import Path
import verify_vm9_native_171_sixth_numeric_field_dynamic_20261124 as previous
from unicorn import arm64_const as arm
from elftools.elf.elffile import ELFFile
from vm9_allocator import _read_span,_write_span
VM_CALL,VM_RESUME,LIBC_BASE=previous.VM_CALL,previous.VM_RESUME,previous.LIBC_BASE
bootstrap,digest,sha256=previous.bootstrap,previous.digest,previous.sha256
MAX_NEW_CALLBACKS,MAX_NEW_INSTRUCTIONS=1,30000
EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_seventh_numeric_field_dynamic_20261124.json')
SCHEMA='vm9-native-171-seventh-numeric-field-dynamic-20261124-v1'
number_fixture=previous.number_fixture
VALUES=(('zero',0),('one',1),('signbit',0x80000000),('u32max',0xFFFFFFFF))


class SeventhPreserved(previous.SixthNumericField):
    def __init__(self,control):
        super().__init__(control)
        self._j7_active=self._j7_done=False
        self._j7_sites,self._j7_code,self._j7_writes=[],{},[]
        self._j7_calls,self._j7_aux=[],[]
        self._j7_flow=None;self._j7_reason=None

    def _j7_index(self):
        return dict(window='seventh_suffix' if self._j7_active else 'sixth_prefix',
            index=len(self._j7_sites) if self._j7_active else len(self._jan_sites))

    def _jst_index(self):
        if self._j7_active:return self._j7_index()
        return super()._jst_index()

    def _jan_conversion(self,cpu,pc):
        if (self._jan_active and self._jan_next_active and self._jan_flow is not None
                and self._jan_flow['public']['node_verified']
                and self._jan_flow['public']['argument']['prior_child_count']==5):
            self._j7_conversion(cpu,pc)
        return super()._jan_conversion(cpu,pc)

    def _j7_conversion(self,cpu,pc):
        off=pc-self.image;flow=self._j7_flow
        if flow is not None and flow['public']['node_verified']:return
        if off==0x17079C:
            assert flow is None,'second conversion source before seventh node'
            source=self._reg(cpu,9);word=bytes(cpu.mem_read(source,4))
            row=dict(label='seventh_numeric',source=dict(kind='VM_scalar_at_conversion',source_width=4,
                upstream_business_source_verified=False,scalar_values_or_hashes_exported=False),
                conversion=dict(source_address=hex(source),load_site=hex(off),**self._j7_index()),
                argument={},node={},node_verified=False)
            self._j7_flow=dict(public=row,word=word,bits=struct.pack('<d',float(int.from_bytes(word,'little'))))
        elif flow is not None and off==0x1707AC:
            assert cpu.reg_read(arm.UC_ARM64_REG_D0).to_bytes(8,'little')==flow['word']+bytes(4)
            flow['public']['conversion'].update(convert_site=hex(off),unsigned_zero_extension_equal=True)
        elif flow is not None and off==0x1707B0:
            assert cpu.reg_read(arm.UC_ARM64_REG_D0).to_bytes(8,'little')==flow['bits']
            flow['public']['conversion']['exact_binary64_equal']=True
        elif flow is not None and off==0x1707F8:
            assert flow['public']['conversion']['exact_binary64_equal']
            assert cpu.reg_read(arm.UC_ARM64_REG_D0).to_bytes(8,'little')==flow['bits']
            flow['destination']=self._reg(cpu,9)
        elif flow is not None and off==0x1707FC:
            assert bytes(cpu.mem_read(flow['destination'],8))==flow['bits']
            flow['public']['conversion'].update(destination_address=hex(flow['destination']),
                store_site='0x1707f8',stored_binary64_equal=True)

    def _j7_call(self,cpu):
        descriptor=self._reg(cpu,0);vmstate=self._reg(cpu,19)
        return dict(index=len(self._j7_sites),descriptor_address=hex(descriptor),descriptor_width=48,
            wrapper_offset=hex(self._reg(cpu,8)-self.image),target_offset=hex(self._u(cpu,descriptor)-self.image),
            VM_cursor_offset=hex(self._u(cpu,vmstate)-self.image),SP=hex(cpu.reg_read(arm.UC_ARM64_REG_SP)),
            callee_saved_sha256=self._idctor_saved_hash(cpu),VM_call_executed=False,wrapper_entered=False,
            target_entered=False,returned=False)

    def _j7_track(self,cpu,pc):
        key=self._fmt_site(pc);self._j7_sites.append(key);self._j7_code[key]=bytes(cpu.mem_read(pc,4)).hex()

    def _jan_stop(self,cpu,reason):
        if reason!='callback_budget_before_next_call':return super()._jan_stop(cpu,reason)
        assert not self._j7_active and len(self._jan_sites)==4225 and len(self._jan_calls)==4
        assert cpu.reg_read(arm.UC_ARM64_REG_PC)==self.image+VM_CALL
        assert self._jan_flow['public']['node_verified'] and self._jan_flow['public']['argument']['prior_child_count']==5
        assert self._j7_flow is not None and self._j7_flow['public']['conversion']['stored_binary64_equal']
        self._jan_done=True;self._jan_stop_reason=reason;self._jan_active=False
        self._j7_events=deepcopy(self._jan_state['allocator_events_ref'])
        self._j7_active=True;self._j7_track(cpu,self.image+VM_CALL)
        call=self._j7_call(cpu);self._j7_calls.append(call);self._j7_current=call
        assert (call['wrapper_offset'],call['target_offset'])==('0x288854','0x261350')
        assert call['VM_cursor_offset']=='0x10a808'
        self._j7_number_arguments(cpu,self._jan_state)
        self._base_observe(cpu,self.image+VM_CALL,self._jan_state)
        print('Retained complete sixth-field boundary; executing seventh numeric append',flush=True)

    def _j7_number_arguments(self,cpu,state):
        old=self._jst_pending;self._jst_pending=self._j7_flow
        try:super()._jst_number_arguments(cpu,state)
        finally:self._jst_pending=old
        assert self._j7_flow['public']['argument']['prior_child_count']==6

    def _j7_number_return(self,cpu,state):
        old=self._jst_pending;self._jst_pending=self._j7_flow
        try:super()._jst_number_return(cpu,state)
        finally:self._jst_pending=old

    def _j7_stop(self,cpu,reason):
        self._j7_done=True;self._j7_reason=reason
        cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,bootstrap().digest.context.outer.oracle.STOP)

    def _jst_stop(self,cpu,reason):
        if self._j7_active:return self._j7_stop(cpu,reason)
        return super()._jst_stop(cpu,reason)

    def native_runner(self,*args,**kwargs):
        old_write=kwargs['memory_write_observer']
        def write(cpu,address,size):
            if self._j7_active:self._j7_writes.append((len(self._j7_sites),pc_site(cpu),address,size))
            if old_write:old_write(cpu,address,size)
        def pc_site(cpu):return self._fmt_site(cpu.reg_read(arm.UC_ARM64_REG_PC))
        kwargs['memory_write_observer']=write
        return super().native_runner(*args,**kwargs)

    def observe(self,cpu,pc,state):
        if not self._j7_active:return super().observe(cpu,pc,state)
        self._j7_track(cpu,pc)
        if len(self._j7_sites)>=MAX_NEW_INSTRUCTIONS:self._j7_stop(cpu,'instruction_budget');return
        if pc in (LIBC_BASE+0x9833C,LIBC_BASE+0x97F40):
            self._j7_aux.append(dict(index=len(self._j7_sites),kind='gc' if pc==LIBC_BASE+0x9833C else 'flush'))
        call=self._j7_current
        if pc==self.image+VM_CALL:
            assert call['returned'],'unexpected nested callback'
            call=self._j7_call(cpu);self._j7_calls.append(call)
            self._j7_stop(cpu,'callback_budget_before_next_call');return
        if self._jst_guard(cpu,pc):return
        if pc==self.image+int(call['wrapper_offset'],16):call.update(VM_call_executed=True,wrapper_entered=True)
        if pc==self.image+int(call['target_offset'],16):
            flow=self._j7_flow;call['target_entered']=True
            assert self._reg(cpu,0)==flow['wrapper'] and self._reg(cpu,1)==flow['key']
            assert cpu.reg_read(arm.UC_ARM64_REG_D0).to_bytes(8,'little')==flow['bits']
            flow['public']['argument']['actual_X0_X1_D0_equal']=True
        if pc==self.image+VM_RESUME:
            assert cpu.reg_read(arm.UC_ARM64_REG_SP)==int(call['SP'],16)
            assert self._idctor_saved_hash(cpu)==call['callee_saved_sha256']
            call.update(returned=True,return_index=len(self._j7_sites),caller_SP_and_callee_saved_restored=True)
            self._j7_number_return(cpu,state)
        self._base_observe(cpu,pc,state)
        assert self.late_jni_calls==self._jev_initial_late and self.java_dispatch_calls==self._jev_initial_java

    def finish(self,result,state,proof):
        assert self._j7_done and self._j7_reason=='callback_budget_before_next_call'
        assert self._j7_flow['public']['node_verified'] and len(self._j7_calls)==2
        delta=result['allocator_events'][len(self._j7_events):]
        counts=deepcopy(result['actual_allocator_counts'])
        for event in delta:counts['malloc' if event[0]=='alloc' else 'free']-=1
        for event in self._j7_aux:counts[event['kind']]-=1
        prefix=dict(result,allocator_events=self._j7_events,actual_allocator_counts=counts)
        old=super().finish(prefix,state,proof)
        assert old==self._j7_parent['case_result'],'complete sixth-field checkpoint differs'
        trace=hashlib.sha256()
        for site in self._j7_sites:trace.update(site.encode()+bytes.fromhex(self._j7_code[site]))
        return dict(complete_sixth_parent_case_equal=True,parent_case_sha256=digest(old),field_relation=self._j7_flow['public'],
            instruction_observations=len(self._j7_sites),instruction_trace_sha256=trace.hexdigest(),observed_code_sha256=digest(self._j7_code),
            callbacks=self._j7_calls,completed_callbacks=sum(c['returned'] for c in self._j7_calls),stop_reason=self._j7_reason,
            new_allocator_events=delta,allocator_aux_events=self._j7_aux,native_write_observations=len(self._j7_writes),
            actual_allocator_counts=result['actual_allocator_counts'],explicit_service_counts=result['explicit_service_counts'],
            new_providers=[],new_SVCs=[],new_JNI_effects=[],scalar_values_or_hashes_exported=False,key_contents_or_hashes_exported=False,
            native_snapshot_used_as_VM_model_input=False,complete_standalone_signer_verified=False,online_acceptance_verified=False)


def run(library,libc):
    parent=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(parent)
    modules=[];module=previous.previous
    for _ in range(7):modules.append(module);module=module.previous
    atomic,postenv,environment,fieldflow,jsonsuffix,base_string,scope=modules
    controls=[json.loads(m.EVIDENCE.read_text(encoding='utf-8')) for m in (postenv,environment,fieldflow,jsonsuffix)]
    md5_parent=scope.parent_evidence();scope_parent=base_string.parent_evidence()
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
    scenarios=[]
    def create(control):
        s=SeventhPreserved(control);s.path,s.continue_to_svc=library,True
        s._postcrc_parent,s._pcb_parent,s._jwx_parent=md5_parent,scope_parent,json.loads(base_string.EVIDENCE.read_text(encoding='utf-8'))
        s._jff_parent,s._jev_parent,s._jst_parent=controls[3],controls[2],controls[1]
        s._jan_parent=controls[0];s._j7_parent=parent
        s._jwx_exec,s._jwx_plt,s._jwx_strncmp=executable,plt,strncmp
        scenarios.append(s);return s
    print('Replaying native seventh append with full sixth-field checkpoint retained',flush=True)
    old_budget=atomic.MAX_CALLS;atomic.MAX_CALLS=3
    try:
        rows=prefix.digest.context.replay(library,libc,case_controls=[prefix.CONTROL],_extension_factory=create,
            _request_profile=prefix.digest.previous.previous.name.previous.previous.PROFILE['name'],
            _handler_read_profile=prefix.digest.context.NULL_PAYLOAD_READ_PROFILE['name'])
        assert len(rows)==1;return rows[0]
    except Exception:
        report=dict(traceback=traceback.format_exc())
        if scenarios:
            s=scenarios[0];report.update(flow=s._j7_flow['public'] if s._j7_flow else None,
                calls=s._j7_calls,last_sites=s._j7_sites[-20:],stop_reason=s._j7_reason)
        raise
    finally:atomic.MAX_CALLS=old_budget


def append_control(path,base,label,value):
    pages,packed,failures=number_fixture.fresh(path,base,'two_children');g=number_fixture.G;root=g+0x2000
    nodes=[g+0x3100+i*0x100 for i in range(6)]
    for i,node in enumerate(nodes):
        key=g+0x7000+i*0x20
        _write_span(pages,node,bytes(64));_write_span(pages,key,('prior-'+str(i)).encode()+b'\0')
        for offset,word in ((0,nodes[i+1] if i+1<6 else 0),(8,nodes[i-1] if i else nodes[-1]),(56,key)):
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
    print('PASS seventh unsigned numeric append',hex(base),label,flush=True)
    return dict(image_base=hex(base),prior_children=6,value_profile=label,steps=steps,
        original_wrapper_and_numeric_append_returned=True,guest_image_and_all_declared_payload_bytes_equal=True,
        ordered_allocation_free_effects_equal=True,one_byte_result_and_padding_equal=True,
        native_snapshot_input=False,complete_physical_ABI_verified=False)

EXPECTED_CASE_SHA256='8e22891e6d608783d0f85daeb8479888af3150732edfa9ebfbf59abefd01cd1c'
EXPECTED={'instruction_observations': 958, 'callbacks': [{'index': 1, 'descriptor_address': '0x7004ca20', 'descriptor_width': 48, 'wrapper_offset': '0x288854', 'target_offset': '0x261350', 'VM_cursor_offset': '0x10a808', 'SP': '0x7004b930', 'callee_saved_sha256': '1dfcf39e697485c9789eaf1f5667782d682043ac2a66bc54fafb8587c49e2af9', 'VM_call_executed': True, 'wrapper_entered': True, 'target_entered': True, 'returned': True, 'return_index': 390, 'caller_SP_and_callee_saved_restored': True}, {'index': 958, 'descriptor_address': '0x7004ca60', 'descriptor_width': 48, 'wrapper_offset': '0x288820', 'target_offset': '0x258bac', 'VM_cursor_offset': '0x10a828', 'SP': '0x7004b930', 'callee_saved_sha256': '1dfcf39e697485c9789eaf1f5667782d682043ac2a66bc54fafb8587c49e2af9', 'VM_call_executed': False, 'wrapper_entered': False, 'target_entered': False, 'returned': False}], 'new_allocator_events': [['alloc', 64, 325972928, '0x2493fc'], ['alloc', 4, 325944112, '0x249198']], 'actual_allocator_counts': {'malloc': 622, 'free': 278, 'gc': 3, 'flush': 4}, 'native_write_observations': 126}


def sources():
    return dict(verifier_sha256=sha256(Path(__file__)),parent_verifier_sha256=sha256(Path(previous.__file__)),
        parent_chain_sha256=digest(previous.sources()),numeric_fixture_sha256=sha256(Path(number_fixture.__file__)),
        callback_model_sha256=sha256(Path(number_fixture.second.__file__)),
        native_oracle_sha256=sha256(Path(number_fixture.oracle.__file__)))


def claims():
    return dict(evidence_label='Sample verified',complete_sixth_parent_case_equal=True,
        captured_VM_word_unsigned_conversion_and_seventh_node_equal=True,actual_X0_X1_D0_arguments_equal=True,
        six_old_nodes_and_keys_preserved_except_append_links=True,new_node_and_key_allocations_live=True,
        source_upstream_business_meaning_verified=False,scalar_values_or_hashes_exported=False,key_contents_or_hashes_exported=False,
        native_snapshot_used_as_VM_model_input=False,real_ART_JVM_execution=False,Android_execution=False,
        concurrent_acquire_release_semantics_verified=False,complete_physical_ABI_verified=False,
        complete_standalone_signer_verified=False,online_acceptance_verified=False)


def providers():
    return dict(parent_evidence_sha256=sha256(previous.EVIDENCE),maximum_new_callbacks=MAX_NEW_CALLBACKS,
        maximum_new_observations=MAX_NEW_INSTRUCTIONS,admitted_callback=['0x288854','0x261350'],
        new_providers=[],new_import_bindings=[],new_SVC_and_JNI_policy='stop before execution',
        next_VM_callback_policy='stop before execution',
        inherited_original_JNI_acquisition_body_executed=False,
        inherited_JNI_provider='controlled eight-byte env write; original body bypassed',
        model_inputs='declared synthetic profiles only; native values used for in-memory relations',
        inherited_component_controls_rerun=False)


def capture(library,libc):
    case=run(library,libc)
    parent=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'))
    controls=[append_control(library,base,label,value) for base in number_fixture.BASES for label,value in VALUES]
    return dict(schema=SCHEMA,claims=claims(),providers=providers(),source_fingerprints=sources(),
        parent_evidence_sha256=sha256(previous.EVIDENCE),case_result=case,case_result_sha256=digest(case),
        component_controls=dict(seventh_node_append=controls,
            inherited_controls_sha256=digest(parent['component_controls']),inherited_controls_rerun=False))


def _validate(data,parent):
    assert set(data)=={'schema','claims','providers','source_fingerprints','parent_evidence_sha256','case_result','case_result_sha256','component_controls'}
    assert data['schema']==SCHEMA and data['claims']==claims() and data['providers']==providers()
    assert data['source_fingerprints']==sources() and data['parent_evidence_sha256']==sha256(previous.EVIDENCE)
    row=data['case_result'];assert data['case_result_sha256']==digest(row)==EXPECTED_CASE_SHA256
    assert set(row)=={'complete_sixth_parent_case_equal','parent_case_sha256','field_relation','instruction_observations',
        'instruction_trace_sha256','observed_code_sha256','callbacks','completed_callbacks','stop_reason','new_allocator_events',
        'allocator_aux_events','native_write_observations','actual_allocator_counts','explicit_service_counts','new_providers',
        'new_SVCs','new_JNI_effects','scalar_values_or_hashes_exported','key_contents_or_hashes_exported',
        'native_snapshot_used_as_VM_model_input','complete_standalone_signer_verified','online_acceptance_verified'}
    assert row['complete_sixth_parent_case_equal'] is True and row['parent_case_sha256']==digest(parent['case_result'])
    assert row['completed_callbacks']==1 and row['stop_reason']=='callback_budget_before_next_call'
    assert 0<row['instruction_observations']<MAX_NEW_INSTRUCTIONS
    for key,value in EXPECTED.items():assert row[key]==value
    assert row['new_providers']==row['new_SVCs']==row['new_JNI_effects']==row['allocator_aux_events']==[]
    assert all(row[k] is False for k in ('scalar_values_or_hashes_exported','key_contents_or_hashes_exported',
        'native_snapshot_used_as_VM_model_input','complete_standalone_signer_verified','online_acceptance_verified'))
    assert row['explicit_service_counts']==parent['case_result']['explicit_service_counts']
    field=row['field_relation'];assert set(field)=={'label','source','conversion','argument','node','node_verified'}
    assert field['label']=='seventh_numeric' and field['node_verified'] is True
    assert field['source']==dict(kind='VM_scalar_at_conversion',source_width=4,
        upstream_business_source_verified=False,scalar_values_or_hashes_exported=False)
    cvt,arg,node=field['conversion'],field['argument'],field['node']
    assert (cvt['load_site'],cvt['convert_site'],cvt['store_site'])==('0x17079c','0x1707ac','0x1707f8')
    assert cvt['window']=='sixth_prefix' and 3238<cvt['index']<4225
    assert cvt['unsigned_zero_extension_equal'] is cvt['exact_binary64_equal'] is cvt['stored_binary64_equal'] is True
    assert arg['window']==node['window']=='seventh_suffix' and arg['prior_child_count']==node['prior_child_count']==6
    assert arg['key_contents_or_hashes_exported'] is False
    assert all(arg[k] is True for k in ('initial_JSON_wrapper_verified','binary64_equals_conversion','actual_X0_X1_D0_equal'))
    assert all(node[k] is True for k in ('new_live_node_and_key_allocations','binary64_equals_source_conversion','int32_saturation_equal',
        'copied_key_equal','old_nodes_and_owned_keys_preserved_except_append_links','root_wrapper_and_counter_preserved',
        'one_byte_success_store_and_other_descriptor_bytes_preserved'))
    calls=row['callbacks'];assert len(calls)==2
    assert calls[0]['index']==arg['index']==1 and calls[0]['return_index']==node['index']<calls[1]['index']
    old=parent['case_result']['callbacks'][-1]
    for key in ('descriptor_address','VM_cursor_offset','SP','callee_saved_sha256','wrapper_offset','target_offset'):
        assert calls[0][key]==old[key]
    assert all(calls[0][k] is True for k in ('VM_call_executed','wrapper_entered','target_entered','returned','caller_SP_and_callee_saved_restored'))
    assert all(calls[-1][k] is False for k in ('VM_call_executed','wrapper_entered','target_entered','returned'))
    controls=data['component_controls'];assert set(controls)=={'seventh_node_append','inherited_controls_sha256','inherited_controls_rerun'}
    assert controls['inherited_controls_sha256']==digest(parent['component_controls']) and controls['inherited_controls_rerun'] is False
    assert [(c['image_base'],c['prior_children'],c['value_profile']) for c in controls['seventh_node_append']]==[
        (hex(base),6,label) for base in number_fixture.BASES for label,_ in VALUES]
    expected_keys={'image_base','prior_children','value_profile','steps','original_wrapper_and_numeric_append_returned',
        'guest_image_and_all_declared_payload_bytes_equal','ordered_allocation_free_effects_equal','one_byte_result_and_padding_equal',
        'native_snapshot_input','complete_physical_ABI_verified'}
    for c in controls['seventh_node_append']:
        assert set(c)==expected_keys and type(c['steps']) is int and c['steps']>0
        assert all(c[k] is True for k in ('original_wrapper_and_numeric_append_returned','guest_image_and_all_declared_payload_bytes_equal',
            'ordered_allocation_free_effects_equal','one_byte_result_and_padding_equal'))
        assert c['native_snapshot_input'] is c['complete_physical_ABI_verified'] is False


def validate(data):
    parent=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(parent);_validate(data,parent)


def damaged_evidence_rejected(data):
    parent=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(parent)
    changes=[(('claims','real_ART_JVM_execution'),True),(('providers','inherited_original_JNI_acquisition_body_executed'),True),
        (('source_fingerprints','callback_model_sha256'),'0'*64),(('case_result','complete_sixth_parent_case_equal'),False),
        (('case_result','parent_case_sha256'),'0'*64),(('case_result','field_relation','source','upstream_business_source_verified'),True),
        (('case_result','field_relation','conversion','unsigned_zero_extension_equal'),False),
        (('case_result','field_relation','conversion','stored_binary64_equal'),False),
        (('case_result','field_relation','argument','actual_X0_X1_D0_equal'),False),
        (('case_result','field_relation','node','prior_child_count'),5),
        (('case_result','field_relation','node','old_nodes_and_owned_keys_preserved_except_append_links'),False),
        (('case_result','field_relation','node','new_live_node_and_key_allocations'),False),
        (('case_result','callbacks',-1,'target_entered'),True),(('case_result','scalar_values_or_hashes_exported'),True),
        (('case_result','registers'),[]),(('component_controls','inherited_controls_sha256'),'0'*64),
        (('component_controls','inherited_controls_rerun'),True),
        (('component_controls','seventh_node_append',0,'prior_children'),5),
        (('component_controls','seventh_node_append',0,'ordered_allocation_free_effects_equal'),False),
        (('component_controls','seventh_node_append',0,'native_snapshot_input'),True)]
    for path,value in changes:
        bad=deepcopy(data);target=bad
        for key in path[:-1]:target=target[key]
        target[path[-1]]=value
        if path[0]=='case_result':bad['case_result_sha256']=digest(bad['case_result'])
        try:_validate(bad,parent)
        except (AssertionError,KeyError,ValueError,TypeError,IndexError):continue
        raise AssertionError('damaged seventh numeric evidence accepted: '+repr(path))
    return len(changes)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--elf',type=Path);p.add_argument('--libc',type=Path)
    p.add_argument('--compare-case',type=Path);m=p.add_mutually_exclusive_group()
    m.add_argument('--capture',action='store_true');m.add_argument('--replay',action='store_true');args=p.parse_args()
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
    print(json.dumps(dict(schema=SCHEMA,verified_numeric_fields=1,completed_callbacks=data['case_result']['completed_callbacks'],
        damaged_evidence_rejected=rejected,complete_standalone_signer_verified=False)))


if __name__=='__main__':main()
