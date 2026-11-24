"""Native relational checks for the sixth live JSON numeric node."""
from __future__ import annotations
import argparse,hashlib,importlib,json,struct,sys
from copy import deepcopy
from pathlib import Path
from unicorn import arm64_const as arm
from vm9_allocator import _read_span,_write_span
import verify_vm9_native_171_atomic_numeric_field_dynamic_20261124 as previous
import verify_vm9_second_atomic_u32_fresh_20261016 as atomic_fixture
import verify_vm9_u32_double_fresh_20261016 as unsigned_fixture
import verify_vm9_second_json_number_fresh_20261016 as number_fixture
VM_CALL,VM_RESUME,LIBC_BASE=previous.VM_CALL,previous.VM_RESUME,previous.LIBC_BASE
bootstrap,digest,raw_hash,sha256=previous.bootstrap,previous.digest,previous.raw_hash,previous.sha256
EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_sixth_numeric_field_dynamic_20261124.json')
SCHEMA='vm9-native-171-sixth-numeric-field-dynamic-20261124-v1'
MAX_CALLS,MAX_INSTRUCTIONS=3,60000
UNSIGNED_VALUES=(('zero',0),('one',1),('signbit',0x80000000),('u32max',0xFFFFFFFF))
class SixthNumericField(previous.AtomicNumericField):
    def __init__(self,control):
        super().__init__(control)
        self._jan_next_active=False
        self._jan_next_trace=[]

    def _jan_conversion(self,cpu,pc):
        if not self._jan_next_active:
            return super()._jan_conversion(cpu,pc)
        off=pc-self.image
        flow=self._jan_flow
        if flow is not None and flow['public']['node_verified']:
            return
        if off==0x17079c and (flow is None or not flow['public']['node_verified']):
            source=self._reg(cpu,9);word=bytes(cpu.mem_read(source,4))
            row=dict(label='sixth_numeric',source=dict(kind='carried_vm_scalar',capture_site='0x17079c',
                source_address=hex(source),source_width=4,source_value_or_hash_exported=False),
                conversion={},argument={},node={},node_verified=False,
                scalar_values_exported=False,scalar_hashes_exported=False)
            self._jan_flow=dict(public=row,word=word,
                bits=struct.pack('<d',float(int.from_bytes(word,'little'))))
            flow=self._jan_flow
            row['conversion'].update(source_address=hex(source),load_site=hex(off),
                source_low_u32_equal=True,window='sixth_suffix',index=len(self._jan_sites))
        elif flow is not None and off==0x1707ac:
            assert cpu.reg_read(arm.UC_ARM64_REG_D0).to_bytes(8,'little')==flow['word']+bytes(4)
            flow['public']['conversion'].update(convert_site=hex(off),unsigned_zero_extension_equal=True)
        elif flow is not None and off==0x1707b0:
            assert cpu.reg_read(arm.UC_ARM64_REG_D0).to_bytes(8,'little')==flow['bits']
            flow['public']['conversion']['exact_binary64_equal']=True
        elif flow is not None and off==0x1707f8:
            assert cpu.reg_read(arm.UC_ARM64_REG_D0).to_bytes(8,'little')==flow['bits']
            flow['destination']=self._reg(cpu,9)
        elif flow is not None and off==0x1707fc:
            assert bytes(cpu.mem_read(flow['destination'],8))==flow['bits']
            flow['public']['conversion'].update(destination_address=hex(flow['destination']),
                store_site='0x1707f8',stored_binary64_equal=True)

    def _jan_number_arguments(self,cpu,state):
        old=self._jst_pending;self._jst_pending=self._jan_flow
        try:previous.previous.PostEnvironmentFields._jst_number_arguments(self,cpu,state)
        finally:self._jst_pending=old

    def _jan_number_return(self,cpu,state):
        old=self._jst_pending;self._jst_pending=self._jan_flow
        try:previous.previous.PostEnvironmentFields._jst_number_return(self,cpu,state)
        finally:self._jst_pending=old

    def observe(self,cpu,pc,state):
        result=super().observe(cpu,pc,state)
        if (not self._jan_next_active and len(self._jan_calls)>=2 and
                self._jan_calls[-1]['returned'] and self._jan_flow is not None and
                self._jan_flow['public']['node_verified']):
            self._jan_next_active=True
            self._jan_next_trace=[]
            self._jan_flow=None
        if self._jan_next_active and self._jan_sites and 0x170780<=pc-self.image<=0x170824:
            self._jan_next_trace.append(dict(offset=hex(pc-self.image),
                d0=hex(cpu.reg_read(arm.UC_ARM64_REG_D0)),x9=hex(self._reg(cpu,9))))
        return result

    def finish(self,result,state,proof):
        if (self._jan_flow is None or not self._jan_flow['public']['node_verified']) and self._jst_flows:
            candidate=self._jst_flows[-1]
            if candidate.get('label')=='sixth_numeric' and candidate.get('node_verified'):
                self._jan_flow={'public':candidate}
        if self._jan_flow is not None and self._jan_flow['public']['node_verified']:
            self._jan_done=True
            if self._jan_stop_reason is None:
                self._jan_stop_reason='natural_boundary_after_sixth_node'
        row=super().finish(result,state,proof)
        return row



def fifth_node_control(path,base,label,value):
    pages,packed,failures=number_fixture.fresh(path,base,'two_children');g=number_fixture.G;root=g+0x2000
    nodes=[g+0x3100+i*0x100 for i in range(5)]
    for i,node in enumerate(nodes):
        key=g+0x7000+i*0x20;_write_span(pages,node,bytes(64));_write_span(pages,key,('prior-'+str(i)).encode()+b'\0')
        for offset,word in ((0,nodes[i+1] if i+1<5 else 0),(8,nodes[i-1] if i else nodes[-1]),(56,key)):number_fixture.w(pages,node+offset,word)
        number_fixture.w(pages,node+24,8,4);number_fixture.w(pages,node+40,i+1,4);_write_span(pages,node+48,struct.pack('<d',float(i+1)))
    number_fixture.w(pages,root+16,nodes[0]);_write_span(pages,packed+24,struct.pack('<d',float(value)))
    before=_read_span(pages,packed,40);expected=number_fixture.services('two_children',failures);actual=number_fixture.services('two_children',failures)
    memory,watched,steps=number_fixture.original(path,base,pages,packed,expected)
    result=number_fixture.second.apply_request_287474_json_number_callback(pages,argument_block_address=packed,entry_stack_address=number_fixture.SP,image_base=base,allocate=actual.malloc,free=actual.free)
    assert result is True and _read_span(pages,g,0xA000)==memory
    assert all(_read_span(pages,a,n)==raw for (a,n),raw in watched.items())
    assert actual.events==expected.events and actual.freed==expected.freed and actual.effects.calls==expected.effects.calls and actual.effects.blocks==expected.effects.blocks
    assert _read_span(pages,packed,32)==before[:32] and _read_span(pages,packed+33,7)==before[33:]
    return dict(image_base=hex(base),prior_children=5,value_profile=label,steps=steps,original_wrapper_and_numeric_append_returned=True,
        guest_image_and_all_declared_payload_bytes_equal=True,ordered_allocation_free_effects_equal=True,one_byte_result_and_padding_equal=True,
        native_snapshot_input=False,complete_physical_ABI_verified=False)


def claims():
    return dict(evidence_label='Sample verified',complete_post_environment_parent_case_equal=True,
        carried_scalar_to_sixth_numeric_node_verified=True,source_conversion_and_binary64_store_verified=True,
        prior_five_nodes_and_owned_keys_preserved_except_append_links=True,new_sixth_node_and_key_allocations_live=True,
        current_native_values_used_only_for_relations=True,native_snapshot_used_to_initialize_VM_model=False,
        scalar_values_or_hashes_exported=False,key_contents_or_hashes_exported=False,
        concurrent_acquire_release_semantics_verified=False,real_ART_JVM_execution=False,Android_execution=False,
        complete_physical_ABI_verified=False,complete_standalone_signer_verified=False,online_acceptance_verified=False)


def providers():
    return dict(parent_evidence_sha256=sha256(previous.EVIDENCE),new_providers=[],new_import_bindings=[],maximum_callbacks=3,maximum_observations=60000,
        admitted_new_callbacks=[['0x288854','0x261350']],next_unexecuted_callback=['0x288854','0x261350'],atomic_memory_contract='serial observation only',
        new_SVC_and_JNI_dispatch_policy='stop before execution',unknown_callback_policy='stop before VM call',
        inherited_original_JNI_acquisition_body_executed=False,inherited_JNI_provider='controlled eight-byte env write; original body bypassed',
        existing_unsigned_conversion_and_numeric_models_reused=True,component_allocations='existing explicit synthetic services; no native snapshots as model input')


def sources():
    return dict(verifier_sha256=sha256(Path(__file__)),parent_verifier_sha256=sha256(Path(previous.__file__)),parent_chain_sha256=digest(previous.sources()),
        atomic_fixture_sha256=sha256(Path(atomic_fixture.__file__)),unsigned_fixture_sha256=sha256(Path(unsigned_fixture.__file__)),numeric_fixture_sha256=sha256(Path(number_fixture.__file__)),
        unsigned_VM_model_sha256=sha256(Path(unsigned_fixture.__file__).with_name('vm_full.py')),callback_model_sha256=sha256(Path(atomic_fixture.model.__file__)),native_oracle_sha256=sha256(Path(number_fixture.oracle.__file__)))


def run(library,libc):
    old_cls,old_max=previous.AtomicNumericField,previous.MAX_CALLS;previous.AtomicNumericField=SixthNumericField;previous.MAX_CALLS=3
    try:data=previous.run(library,libc)
    finally:previous.AtomicNumericField,previous.MAX_CALLS=old_cls,old_max
    controls=dict(previous=data['component_controls'],sixth_node_append=[fifth_node_control(library,base,label,value) for base in number_fixture.BASES for label,value in UNSIGNED_VALUES])
    case=data['case_result'];case.pop('next_conversion_trace',None)
    return dict(schema=SCHEMA,claims=claims(),providers=providers(),source_fingerprints=sources(),parent_evidence_sha256=sha256(previous.EVIDENCE),
        case_result=case,case_result_sha256=digest(case),component_controls=controls)


def _validate(data,parent):
    assert set(data)=={'schema','claims','providers','source_fingerprints','parent_evidence_sha256','case_result','case_result_sha256','component_controls'}
    assert data['schema']==SCHEMA and data['claims']==claims() and data['providers']==providers() and data['source_fingerprints']==sources()
    assert data['parent_evidence_sha256']==sha256(previous.EVIDENCE)
    row=data['case_result'];assert data['case_result_sha256']==digest(row)
    assert row['parent_case_equal'] is True and row['parent_case_sha256']==digest(parent['case_result'])
    assert row['completed_callbacks']==3 and row['instruction_observations']==4225 and row['stop_reason']=='callback_budget_before_next_call'
    assert row['new_providers']==row['new_SVCs']==row['new_JNI_effects']==row['allocator_aux_events']==[]
    assert row['scalar_values_or_hashes_exported'] is row['key_contents_or_hashes_exported'] is False
    field=row['field_relation'];assert field['label']=='sixth_numeric' and field['node_verified'] is True
    assert field['source']['kind']=='carried_vm_scalar' and field['source']['source_width']==4 and field['source']['source_value_or_hash_exported'] is False
    cvt,arg,node=field['conversion'],field['argument'],field['node']
    assert cvt['window']=='sixth_suffix' and (cvt['load_site'],cvt['convert_site'],cvt['store_site'])==('0x17079c','0x1707ac','0x1707f8')
    assert all(cvt[k] is True for k in ('source_low_u32_equal','unsigned_zero_extension_equal','exact_binary64_equal','stored_binary64_equal'))
    assert arg['prior_child_count']==node['prior_child_count']==5 and arg['window']==node['window']=='atomic_suffix'
    assert arg['key_contents_or_hashes_exported'] is False and all(arg[k] is True for k in ('initial_JSON_wrapper_verified','binary64_equals_conversion','actual_X0_X1_D0_equal'))
    assert all(node[k] is True for k in ('new_live_node_and_key_allocations','binary64_equals_source_conversion','int32_saturation_equal','copied_key_equal','old_nodes_and_owned_keys_preserved_except_append_links','root_wrapper_and_counter_preserved','one_byte_success_store_and_other_descriptor_bytes_preserved'))
    calls=row['callbacks'];assert len(calls)==4 and [c['index'] for c in calls]==[1,1030,2845,4225]
    assert [c.get('return_index') for c in calls]==[12,1858,3238,None]
    assert [(c['wrapper_offset'],c['target_offset']) for c in calls]==[('0x28887c','0x256f58'),('0x288854','0x261350'),('0x288854','0x261350'),('0x288854','0x261350')]
    assert all(calls[-1][k] is False for k in ('VM_call_executed','wrapper_entered','target_entered','returned'))
    assert row['new_allocator_events']==[['alloc',64,325972800,'0x2493fc'],['alloc',4,325944096,'0x249198'],['alloc',64,325972864,'0x2493fc'],['alloc',3,325944104,'0x249198']]
    assert row['actual_allocator_counts']=={'malloc':620,'free':278,'gc':3,'flush':4}
    controls=data['component_controls'];assert set(controls)=={'previous','sixth_node_append'} and len(controls['sixth_node_append'])==8
    assert all(x['prior_children']==5 and x['value_profile'] in {'zero','one','signbit','u32max'} for x in controls['sixth_node_append'])
    for control in controls['sixth_node_append']:
        assert all(control[key] is True for key in ('original_wrapper_and_numeric_append_returned','guest_image_and_all_declared_payload_bytes_equal','ordered_allocation_free_effects_equal','one_byte_result_and_padding_equal'))


def validate(data):
    parent=json.loads(previous.previous.EVIDENCE.read_text(encoding='utf-8'));previous.previous.validate(parent);_validate(data,parent)


def damaged_evidence_rejected(data):
    parent=json.loads(previous.previous.EVIDENCE.read_text(encoding='utf-8'));previous.previous.validate(parent)
    changes=[(('claims','concurrent_acquire_release_semantics_verified'),True),(('providers','inherited_original_JNI_acquisition_body_executed'),True),
        (('case_result','parent_case_equal'),False),(('case_result','field_relation','source','source_width'),8),
        (('case_result','field_relation','conversion','unsigned_zero_extension_equal'),False),(('case_result','field_relation','conversion','exact_binary64_equal'),False),
        (('case_result','field_relation','argument','prior_child_count'),4),(('case_result','field_relation','node','new_live_node_and_key_allocations'),False),
        (('case_result','field_relation','node','old_nodes_and_owned_keys_preserved_except_append_links'),False),(('case_result','field_relation','node','prior_child_count'),4),
        (('case_result','callbacks',-1,'target_entered'),True),(('case_result','scalar_values_or_hashes_exported'),True),
        (('component_controls','sixth_node_append',0,'prior_children'),4),(('component_controls','sixth_node_append',0,'ordered_allocation_free_effects_equal'),False)]
    for path,value in changes:
        bad=deepcopy(data);target=bad
        for key in path[:-1]:target=target[key]
        target[path[-1]]=value
        if path[0]=='case_result':bad['case_result_sha256']=digest(bad['case_result'])
        try:_validate(bad,parent)
        except (AssertionError,KeyError,ValueError,TypeError,IndexError):continue
        raise AssertionError('damaged sixth numeric evidence accepted: '+repr(path))
    return len(changes)


def main():
    p=argparse.ArgumentParser();p.add_argument('--elf',type=Path);p.add_argument('--libc',type=Path);p.add_argument('--compare-case',type=Path);m=p.add_mutually_exclusive_group();m.add_argument('--capture',action='store_true');m.add_argument('--replay',action='store_true');a=p.parse_args()
    if (a.capture or a.replay) and (a.elf is None or a.libc is None):p.error('--capture and --replay require --elf and --libc')
    if a.compare_case is not None and not a.capture:p.error('--compare-case requires --capture')
    if a.capture:
        if EVIDENCE.exists():raise FileExistsError('frozen evidence exists; refusing overwrite')
        data=run(a.elf,a.libc)
        if a.compare_case is not None:assert data['case_result']==json.loads(a.compare_case.read_text(encoding='utf-8'))
        validate(data);rejected=damaged_evidence_rejected(data);EVIDENCE.write_text(json.dumps(data,indent=2)+'\n',encoding='utf-8',newline='\n')
    else:
        data=json.loads(EVIDENCE.read_text(encoding='utf-8'));validate(data);rejected=damaged_evidence_rejected(data)
        if a.replay:assert run(a.elf,a.libc)==data
    print(json.dumps(dict(schema=SCHEMA,verified_numeric_fields=1,completed_callbacks=data['case_result']['completed_callbacks'],damaged_evidence_rejected=rejected,complete_standalone_signer_verified=False)))


if __name__=='__main__':main()
