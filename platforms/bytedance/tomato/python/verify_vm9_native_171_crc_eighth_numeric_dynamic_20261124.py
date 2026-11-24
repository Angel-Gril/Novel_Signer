"""Native CRC input/read/write relation and signed eighth JSON numeric node."""
from __future__ import annotations
import argparse,binascii,hashlib,importlib,json,os,struct,traceback
from copy import deepcopy
from pathlib import Path
import verify_vm9_native_171_seventh_numeric_field_dynamic_20261124 as previous
import verify_vm9_second_crc_fresh_20261015 as crc_fixture
import verify_vm9_i32_double_fresh_20261016 as signed_fixture
from unicorn import arm64_const as arm
from vm9_allocator import _read_span,_write_span
VM_CALL,VM_RESUME,LIBC_BASE=previous.VM_CALL,previous.VM_RESUME,previous.LIBC_BASE
bootstrap,digest,sha256=previous.bootstrap,previous.digest,previous.sha256
MAX_NEW_CALLBACKS,MAX_NEW_INSTRUCTIONS=2,60000
number_fixture=previous.number_fixture
SIGNED_PROFILES=('zero','i32max','i32min','minus_one','high_mixed')
APPEND_VALUES=(('zero',0),('minus_one',-1),('i32min',-0x80000000),('i32max',0x7FFFFFFF))
EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_crc_eighth_numeric_dynamic_20261124.json')
SCHEMA='vm9-native-171-crc-eighth-numeric-dynamic-20261124-v1'


def standard_table():
    words=[]
    for byte in range(256):
        value=byte
        for _ in range(8):value=(value>>1)^(0xEDB88320 if value&1 else 0)
        words.append(value.to_bytes(4,'little'))
    return b''.join(words)


class CrcEighth(previous.SeventhPreserved):
    def __init__(self,control):
        super().__init__(control)
        self._c8_active=self._c8_done=False
        self._c8_sites,self._c8_code,self._c8_writes=[],{},[]
        self._c8_calls,self._c8_aux=[],[]
        self._c8_flow=None;self._c8_reason=None;self._c8_crc_returned=False
        self._c8_core_entered=False;self._c8_core_returned=False;self._c8_stored=False
        self._c8_read_offsets=[]
        self._c8_parent=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'))

    def _c8_index(self):return dict(window='crc_eighth_suffix',index=len(self._c8_sites))

    def _jst_index(self):
        if self._c8_active:return self._c8_index()
        return super()._jst_index()

    def _c8_track(self,cpu,pc):
        site=self._fmt_site(pc);self._c8_sites.append(site);self._c8_code[site]=bytes(cpu.mem_read(pc,4)).hex()

    def _c8_call(self,cpu):
        descriptor=self._reg(cpu,0);vmstate=self._reg(cpu,19)
        return dict(index=len(self._c8_sites),descriptor_address=hex(descriptor),descriptor_width=48,
            wrapper_offset=hex(self._reg(cpu,8)-self.image),target_offset=hex(self._u(cpu,descriptor)-self.image),
            VM_cursor_offset=hex(self._u(cpu,vmstate)-self.image),SP=hex(cpu.reg_read(arm.UC_ARM64_REG_SP)),
            callee_saved_sha256=self._idctor_saved_hash(cpu),VM_call_executed=False,wrapper_entered=False,target_entered=False,returned=False)

    def _c8_json_ranges(self,cpu):
        initial=self._jwx_typed_output
        wrapper,root,counter=(int(initial[name],16) for name in ('wrapper_address','root_address','counter_address'))
        ranges=[('JSON_wrapper',wrapper,16),('JSON_root',root,64),('JSON_counter',counter,4)]
        node=self._u(cpu,root+16);seen=set()
        while node:
            assert node not in seen and len(seen)<8
            seen.add(node);ranges.append(('JSON_node',node,64))
            key=self._u(cpu,node+56);ranges.append(('JSON_key',key,len(self._bounded_cstring(cpu,key,limit=4096))+1))
            node=self._u(cpu,node)
        assert len(seen)==7
        return ranges

    def _j7_stop(self,cpu,reason):
        if reason!='callback_budget_before_next_call':return super()._j7_stop(cpu,reason)
        assert not self._c8_active and len(self._j7_sites)==958 and len(self._j7_calls)==2
        assert self._j7_flow['public']['node_verified'] and cpu.reg_read(arm.UC_ARM64_REG_PC)==self.image+VM_CALL
        self._j7_done=True;self._j7_reason=reason;self._j7_active=False
        self._c8_events=deepcopy(self._jan_state['allocator_events_ref'])
        self._c8_active=True;self._c8_track(cpu,self.image+VM_CALL)
        call=self._c8_call(cpu);self._c8_calls.append(call);self._c8_current=call
        assert (call['wrapper_offset'],call['target_offset'],call['VM_cursor_offset'])==('0x288820','0x258bac','0x10a828')
        self._c8_descriptor=int(call['descriptor_address'],16)
        self._c8_descriptor_before=bytes(cpu.mem_read(self._c8_descriptor,48))
        self._c8_receiver=self._u(cpu,self._c8_descriptor+8)
        self._c8_object_before=bytes(cpu.mem_read(self._c8_receiver,24))
        assert self._u(cpu,self._c8_receiver)==self.image+0x34F5F8
        self._c8_length=int.from_bytes(self._c8_object_before[12:16],'little',signed=True)
        self._c8_pointer=int.from_bytes(self._c8_object_before[16:24],'little')
        assert self._c8_length<=0x100000
        capacity=int.from_bytes(self._c8_object_before[8:12],'little')
        assert self._c8_length<=0 or (self._c8_pointer and capacity>self._c8_length)
        self._c8_payload=bytes(cpu.mem_read(self._c8_pointer,max(0,self._c8_length))) if self._c8_length>0 else b''
        table=bytes(cpu.mem_read(self.image+0x96144,1024));assert table==standard_table()
        value=0xFFFFFFFF
        for byte in self._c8_payload:value=int.from_bytes(table[((value^byte)&255)*4:((value^byte)&255)*4+4],'little')^(value>>8)
        self._c8_expected=value^0xFFFFFFFF
        assert self._c8_expected==binascii.crc32(self._c8_payload)
        live={}
        for event in self._c8_events:
            if event[0]=='alloc':live[event[2]]=event[1]
            elif event[0]=='free':live.pop(event[1],None)
        owners=[dict(address=hex(a),size=n,payload_offset=self._c8_pointer-a) for a,n in live.items()
            if self._c8_length>0 and a<=self._c8_pointer and self._c8_pointer+self._c8_length<=a+n]
        matches=[k for k,v in vars(self).items() if not k.startswith('_c8_') and type(v) is int and v==self._c8_receiver]
        self._c8_source=dict(object_address=hex(self._c8_receiver),payload_address=hex(self._c8_pointer),
            signed_length=self._c8_length,consumed_length=len(self._c8_payload),known_pointer_relations=matches,
            live_payload_allocations=owners,string_object_header_checked=True,guest_table_is_standard=True,
            guest_table_and_binascii_expected_equal=True,source_bytes_or_hashes_exported=False,CRC_value_or_hash_exported=False)
        ranges=self._c8_json_ranges(cpu)+[('CRC_source_object',self._c8_receiver,24),('CRC_table',self.image+0x96144,1024)]
        if self._c8_length>0:ranges.append(('CRC_consumed_payload',self._c8_pointer,self._c8_length))
        self._c8_protected=[(label,address,bytes(cpu.mem_read(address,size))) for label,address,size in ranges]
        self._base_observe(cpu,self.image+VM_CALL,self._jan_state)
        print('Retained complete seventh checkpoint; executing original CRC',flush=True)
        print(json.dumps(self._c8_source),flush=True)

    def native_runner(self,*args,**kwargs):
        old_read=kwargs.get('memory_read_observer');old_write=kwargs['memory_write_observer']
        def read(cpu,address,size):
            if self._c8_active and not self._c8_crc_returned and cpu.reg_read(arm.UC_ARM64_REG_PC)==self.image+0x24B2B0:
                assert size==1 and address==self._c8_pointer+len(self._c8_read_offsets)
                self._c8_read_offsets.append(address-self._c8_pointer)
            if old_read:old_read(cpu,address,size)
        def write(cpu,address,size):
            if self._c8_active:
                pc=cpu.reg_read(arm.UC_ARM64_REG_PC);self._c8_writes.append((len(self._c8_sites),self._fmt_site(pc),address,size))
                if not self._c8_crc_returned:
                    assert not any(address<a+len(raw) and a<address+size for _,a,raw in self._c8_protected),'CRC wrote retained input/JSON storage'
                    if address<self._c8_descriptor+48 and self._c8_descriptor<address+size:
                        assert (pc-self.image,address,size)==(0x288830,self._c8_descriptor+16,4)
                        assert self._reg(cpu,0)==self._c8_expected;self._c8_stored=True
            if old_write:old_write(cpu,address,size)
        kwargs.update(memory_read_observer=read,memory_write_observer=write)
        return super().native_runner(*args,**kwargs)

    def _c8_conversion(self,cpu,pc):
        flow=self._c8_flow
        if flow is None or flow['public']['node_verified']:return
        row=flow['public'];off=pc-self.image
        bits=lambda:cpu.reg_read(arm.UC_ARM64_REG_D0).to_bytes(8,'little')
        if off==0x17079C:raise AssertionError('unexpected unsigned conversion before CRC numeric node')
        if off==0x1707D8:
            assert row['conversion']=={}
            source=self._reg(cpu,9);assert bytes(cpu.mem_read(source,4))==flow['word']
            row['conversion'].update(source_address=hex(source),load_site=hex(off),source_low_i32_equal=True,**self._c8_index())
        elif off==0x1707DC:
            assert row['conversion']['source_low_i32_equal'] and bits()==flow['word']+bytes(4)
            row['conversion']['load_zeroes_upper_lane']=True
        elif off==0x1707E0:
            signed=int.from_bytes(flow['word'],'little',signed=True)
            assert bits()==(signed&((1<<64)-1)).to_bytes(8,'little')
            row['conversion'].update(convert_site=hex(off),signed_extension_equal=True)
        elif off==0x1707E4:
            assert bits()==flow['bits'];row['conversion']['exact_binary64_equal']=True
        elif off==0x1707F8:
            assert row['conversion']['exact_binary64_equal'] and bits()==flow['bits'];flow['destination']=self._reg(cpu,9)
        elif off==0x1707FC:
            assert bytes(cpu.mem_read(flow['destination'],8))==flow['bits']
            row['conversion'].update(destination_address=hex(flow['destination']),store_site='0x1707f8',stored_binary64_equal=True)

    def _c8_number_arguments(self,cpu,state):
        old=self._jst_pending;self._jst_pending=self._c8_flow
        try:super()._jst_number_arguments(cpu,state)
        finally:self._jst_pending=old
        assert self._c8_flow['public']['argument']['prior_child_count']==7

    def _c8_number_return(self,cpu,state):
        flow=self._c8_flow;row=flow['public'];expected=bytearray(flow['before']);expected[32]=1
        assert bytes(cpu.mem_read(flow['descriptor'],48))==expected
        assert bytes(cpu.mem_read(flow['wrapper'],16))==flow['wrapper_before']
        assert bytes(cpu.mem_read(flow['root'],64))==flow['root_before']
        assert bytes(cpu.mem_read(flow['counter'],4))==flow['counter_before']
        live=self._jff_live(state);old=flow['old_nodes'];head,tail=old[0][0],old[-1][0];node=self._u(cpu,head+8)
        fresh={e[2]:e[1] for e in state['allocator_events_ref'][flow['allocation_index']:] if e[0]=='alloc'}
        assert node not in {a for a,_,_,_ in old} and fresh.get(node,0)>=64 and live.get(node,0)>=64
        assert self._u(cpu,node)==0 and self._u(cpu,node+8)==tail and self._u(cpu,node+24,4)==8
        assert bytes(cpu.mem_read(node+48,8))==flow['bits']
        assert int.from_bytes(cpu.mem_read(node+40,4),'little',signed=True)==int.from_bytes(flow['word'],'little',signed=True)
        owned=self._u(cpu,node+56)
        assert fresh.get(owned,0)>=len(flow['key_bytes'])+1 and live.get(owned,0)>=len(flow['key_bytes'])+1
        assert self._bounded_cstring(cpu,owned,limit=4096)==flow['key_bytes']
        for address,raw,key,payload in old:
            expected=bytearray(raw)
            if address==head:expected[8:16]=node.to_bytes(8,'little')
            if address==tail:expected[:8]=node.to_bytes(8,'little')
            assert bytes(cpu.mem_read(address,64))==expected and bytes(cpu.mem_read(key,len(payload)))==payload
        row['node'].update(address=hex(node),root_address=hex(flow['root']),prior_child_count=len(old),new_live_node_and_key_allocations=True,
            binary64_equals_signed_source_conversion=True,int32_field_equal=True,copied_key_equal=True,
            old_nodes_and_owned_keys_preserved_except_append_links=True,root_wrapper_and_counter_preserved=True,
            one_byte_success_store_and_other_descriptor_bytes_preserved=True,**self._c8_index())
        row['node_verified']=True
        print('Verified eighth numeric node from original CRC and signed conversion',flush=True)

    def _c8_stop(self,cpu,reason):
        self._c8_done=True;self._c8_reason=reason
        cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,bootstrap().digest.context.outer.oracle.STOP)

    def _jst_stop(self,cpu,reason):
        if self._c8_active:return self._c8_stop(cpu,reason)
        return super()._jst_stop(cpu,reason)

    def observe(self,cpu,pc,state):
        if not self._c8_active:return super().observe(cpu,pc,state)
        self._c8_track(cpu,pc)
        if len(self._c8_sites)>=MAX_NEW_INSTRUCTIONS:self._c8_stop(cpu,'instruction_budget');return
        if pc in (LIBC_BASE+0x9833C,LIBC_BASE+0x97F40):self._c8_aux.append(dict(index=len(self._c8_sites),kind='gc' if pc==LIBC_BASE+0x9833C else 'flush'))
        call=self._c8_current;off=pc-self.image
        if off==VM_CALL:
            assert call['returned'],'unexpected nested callback in CRC/eighth window'
            call=self._c8_call(cpu);self._c8_calls.append(call)
            if len(self._c8_calls)>MAX_NEW_CALLBACKS:self._c8_stop(cpu,'callback_budget_before_next_call');return
            if (call['wrapper_offset'],call['target_offset'])!=('0x288854','0x261350'):
                self._c8_stop(cpu,'uncovered_VM_callback_before_execution');return
            self._c8_current=call;self._c8_number_arguments(cpu,state)
        if self._jst_guard(cpu,pc):return
        self._c8_conversion(cpu,pc)
        if off==int(call['wrapper_offset'],16):call.update(VM_call_executed=True,wrapper_entered=True)
        if off==int(call['target_offset'],16):
            call['target_entered']=True
            if off==0x258BAC:
                assert self._reg(cpu,0)==self._c8_receiver and self._reg(cpu,30)==self.image+0x288830
                self._c8_source['actual_X0_receiver_and_return_equal']=True
            else:
                flow=self._c8_flow;assert self._reg(cpu,0)==flow['wrapper'] and self._reg(cpu,1)==flow['key']
                assert cpu.reg_read(arm.UC_ARM64_REG_D0).to_bytes(8,'little')==flow['bits']
                flow['public']['argument']['actual_X0_X1_D0_equal']=True
        if off==0x24B298:
            assert not self._c8_core_entered and self._reg(cpu,0)==self._c8_pointer
            assert self._reg(cpu,1)==(self._c8_length&0xFFFFFFFF)
            self._c8_core_entered=True;self._c8_source['actual_core_pointer_and_length_equal']=True
        if off==0x258BC4:
            assert self._c8_core_entered and self._reg(cpu,0)==self._c8_expected
            self._c8_core_returned=True;self._c8_source['native_guest_table_and_binascii_equal']=True
        if off==VM_RESUME:
            assert cpu.reg_read(arm.UC_ARM64_REG_SP)==int(call['SP'],16) and self._idctor_saved_hash(cpu)==call['callee_saved_sha256']
            call.update(returned=True,return_index=len(self._c8_sites),caller_SP_and_callee_saved_restored=True)
            if call['target_offset']=='0x258bac':
                expected=bytearray(self._c8_descriptor_before);expected[16:20]=self._c8_expected.to_bytes(4,'little')
                assert self._c8_core_returned and self._c8_stored and self._reg(cpu,0)==self._c8_expected
                assert bytes(cpu.mem_read(self._c8_descriptor,48))==expected
                assert all(bytes(cpu.mem_read(a,len(raw)))==raw for _,a,raw in self._c8_protected)
                assert state['allocator_events_ref']==self._c8_events
                assert self._c8_read_offsets==list(range(max(0,self._c8_length)))
                self._c8_crc_returned=True
                self._c8_source.update(source_table_and_seven_JSON_nodes_preserved=True,no_allocation_or_free_effects=True,
                    exact_sequential_consumed_byte_reads=True,unsigned_X0_and_exact_four_byte_store_equal=True,descriptor_padding_preserved=True)
                word=bytes(cpu.mem_read(self._c8_descriptor+16,4))
                row=dict(label='CRC_signed_eighth',source=self._c8_source,conversion={},argument={},node={},node_verified=False)
                self._c8_flow=dict(public=row,word=word,bits=struct.pack('<d',float(int.from_bytes(word,'little',signed=True))))
                print('Original CRC returned; source bytes, guest table and seven JSON nodes preserved',flush=True)
            else:self._c8_number_return(cpu,state)
        self._base_observe(cpu,pc,state)
        assert self.late_jni_calls==self._jev_initial_late and self.java_dispatch_calls==self._jev_initial_java

    def finish(self,result,state,proof):
        assert self._c8_done and self._c8_reason=='callback_budget_before_next_call'
        assert self._c8_flow['public']['node_verified'] and len(self._c8_calls)==3
        delta=result['allocator_events'][len(self._c8_events):];counts=deepcopy(result['actual_allocator_counts'])
        for event in delta:counts['malloc' if event[0]=='alloc' else 'free']-=1
        for event in self._c8_aux:counts[event['kind']]-=1
        old=super().finish(dict(result,allocator_events=self._c8_events,actual_allocator_counts=counts),state,proof)
        assert old==self._c8_parent['case_result'],'complete seventh-field checkpoint differs'
        trace=hashlib.sha256()
        for site in self._c8_sites:trace.update(site.encode()+bytes.fromhex(self._c8_code[site]))
        return dict(complete_seventh_parent_case_equal=True,parent_case_sha256=digest(old),field_relation=self._c8_flow['public'],
            instruction_observations=len(self._c8_sites),instruction_trace_sha256=trace.hexdigest(),observed_code_sha256=digest(self._c8_code),
            callbacks=self._c8_calls,completed_callbacks=sum(c['returned'] for c in self._c8_calls),stop_reason=self._c8_reason,
            new_allocator_events=delta,allocator_aux_events=self._c8_aux,native_write_observations=len(self._c8_writes),
            actual_allocator_counts=result['actual_allocator_counts'],explicit_service_counts=result['explicit_service_counts'],
            new_providers=[],new_SVCs=[],new_JNI_effects=[],source_bytes_or_hashes_exported=False,CRC_value_or_hash_exported=False,
            key_contents_or_hashes_exported=False,native_snapshot_used_as_VM_model_input=False,complete_standalone_signer_verified=False,online_acceptance_verified=False)


def run(library,libc):
    previous.validate(json.loads(previous.EVIDENCE.read_text(encoding='utf-8')))
    original=previous.SeventhPreserved;previous.SeventhPreserved=CrcEighth
    print('Replaying original CRC and signed eighth numeric field',flush=True)
    try:return previous.run(library,libc)
    finally:previous.SeventhPreserved=original


def append_control(path,base,label,value):
    pages,packed,failures=number_fixture.fresh(path,base,'two_children');g=number_fixture.G;root=g+0x2000
    nodes=[g+0x3100+i*0x100 for i in range(7)]
    for i,node in enumerate(nodes):
        key=g+0x7000+i*0x20
        _write_span(pages,node,bytes(64));_write_span(pages,key,('prior-'+str(i)).encode()+b'\0')
        for offset,word in ((0,nodes[i+1] if i+1<7 else 0),(8,nodes[i-1] if i else nodes[-1]),(56,key)):
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
    print('PASS eighth signed numeric append',hex(base),label,flush=True)
    return dict(image_base=hex(base),prior_children=7,value_profile=label,steps=steps,
        original_wrapper_and_numeric_append_returned=True,guest_image_and_all_declared_payload_bytes_equal=True,
        ordered_allocation_free_effects_equal=True,one_byte_result_and_padding_equal=True,
        native_snapshot_input=False,complete_physical_ABI_verified=False)

EXPECTED_CASE_SHA256='55e3fd7509ab2895eb74542febe1b03bf9f3173921a90ffb72c8c0367e6762f7'
EXPECTED={'instruction_observations': 3016, 'callbacks': [{'index': 1, 'descriptor_address': '0x7004ca60', 'descriptor_width': 48, 'wrapper_offset': '0x288820', 'target_offset': '0x258bac', 'VM_cursor_offset': '0x10a828', 'SP': '0x7004b930', 'callee_saved_sha256': '1dfcf39e697485c9789eaf1f5667782d682043ac2a66bc54fafb8587c49e2af9', 'VM_call_executed': True, 'wrapper_entered': True, 'target_entered': True, 'returned': True, 'return_index': 277, 'caller_SP_and_callee_saved_restored': True}, {'index': 1220, 'descriptor_address': '0x7004ca20', 'descriptor_width': 48, 'wrapper_offset': '0x288854', 'target_offset': '0x261350', 'VM_cursor_offset': '0x10a85c', 'SP': '0x7004b930', 'callee_saved_sha256': '1dfcf39e697485c9789eaf1f5667782d682043ac2a66bc54fafb8587c49e2af9', 'VM_call_executed': True, 'wrapper_entered': True, 'target_entered': True, 'returned': True, 'return_index': 2000, 'caller_SP_and_callee_saved_restored': True}, {'index': 3016, 'descriptor_address': '0x7004cdf8', 'descriptor_width': 48, 'wrapper_offset': '0x2884cc', 'target_offset': '0x2481ac', 'VM_cursor_offset': '0x10a9e0', 'SP': '0x7004b930', 'callee_saved_sha256': '1dfcf39e697485c9789eaf1f5667782d682043ac2a66bc54fafb8587c49e2af9', 'VM_call_executed': False, 'wrapper_entered': False, 'target_entered': False, 'returned': False}], 'new_allocator_events': [['alloc', 64, 325972992, '0x2493fc'], ['alloc', 3, 325944120, '0x249198']], 'actual_allocator_counts': {'malloc': 624, 'free': 278, 'gc': 3, 'flush': 4}, 'native_write_observations': 281}


def sources():
    return dict(verifier_sha256=sha256(Path(__file__)),parent_verifier_sha256=sha256(Path(previous.__file__)),
        parent_chain_sha256=digest(previous.sources()),CRC_fixture_sha256=sha256(Path(crc_fixture.__file__)),
        signed_fixture_sha256=sha256(Path(signed_fixture.__file__)),numeric_fixture_sha256=sha256(Path(number_fixture.__file__)),
        signed_VM_model_sha256=sha256(Path(signed_fixture.__file__).with_name('vm_full.py')),
        CRC_model_sha256=sha256(Path(crc_fixture.__file__).with_name('vm9_jni_followup.py')),
        callback_model_sha256=sha256(Path(crc_fixture.second.__file__)),native_oracle_sha256=sha256(Path(crc_fixture.oracle.__file__)))


def claims():
    return dict(evidence_label='Sample verified',complete_seventh_parent_case_equal=True,
        original_CRC_object_and_buffer_body_returned=True,guest_table_native_and_binascii_relation_equal=True,
        sequential_consumed_bytes_observed=True,source_object_payload_table_and_seven_JSON_nodes_preserved=True,
        unsigned_W0_exact_four_byte_store_and_padding_verified=True,CRC_low_word_to_signed_binary64_conversion_equal=True,
        actual_X0_X1_D0_and_eighth_node_equal=True,new_node_and_key_allocations_live=True,
        seven_old_nodes_and_keys_preserved_except_append_links=True,
        source_business_meaning_beyond_pointer_relations_verified=False,
        source_bytes_or_hashes_exported=False,CRC_value_or_hash_exported=False,key_contents_or_hashes_exported=False,
        native_snapshot_used_as_VM_model_input=False,real_ART_JVM_execution=False,Android_execution=False,
        concurrent_acquire_release_semantics_verified=False,complete_physical_ABI_verified=False,
        complete_standalone_signer_verified=False,online_acceptance_verified=False)


def providers():
    return dict(parent_evidence_sha256=sha256(previous.EVIDENCE),maximum_new_callbacks=MAX_NEW_CALLBACKS,
        maximum_new_observations=MAX_NEW_INSTRUCTIONS,admitted_callbacks=[['0x288820','0x258bac'],['0x288854','0x261350']],
        new_providers=[],new_import_bindings=[],new_SVC_and_JNI_policy='stop before execution',
        next_VM_callback_policy='stop before execution',inherited_original_JNI_acquisition_body_executed=False,
        inherited_JNI_provider='controlled eight-byte env write; original body bypassed',
        model_inputs='declared synthetic profiles only; current native bytes used for in-memory relations',
        inherited_component_controls_rerun=False)


def component_controls(path):
    saved=os.environ.get('TOMATO_LIBMETASEC');os.environ['TOMATO_LIBMETASEC']=str(path.resolve())
    try:model=importlib.import_module('vm_full')
    finally:
        if saved is None:os.environ.pop('TOMATO_LIBMETASEC',None)
        else:os.environ['TOMATO_LIBMETASEC']=saved
    assert Path(model.__file__).resolve()==Path(signed_fixture.__file__).with_name('vm_full.py').resolve()
    assert hashlib.sha256(model.SO).hexdigest()==crc_fixture.oracle.LIBRARY_SHA256
    crc_fixture.equivalent_wrappers(path)
    return dict(CRC=[crc_fixture.compare(path,base,label) for base in crc_fixture.BASES for label in crc_fixture.PROFILES],
        signed_conversion=[signed_fixture.compare(path,model,base,label,value,backed)
            for base in signed_fixture.BASES for label,value in signed_fixture.PROFILES if label in SIGNED_PROFILES for backed in (False,True)],
        eighth_node_append=[append_control(path,base,label,value) for base in number_fixture.BASES for label,value in APPEND_VALUES],
        CRC_guards=crc_fixture.guards(path),signed_conversion_guards=signed_fixture.guards(path,model))


def capture(library,libc):
    case=run(library,libc);parent=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'))
    return dict(schema=SCHEMA,claims=claims(),providers=providers(),source_fingerprints=sources(),
        parent_evidence_sha256=sha256(previous.EVIDENCE),case_result=case,case_result_sha256=digest(case),
        component_controls=component_controls(library),inherited_controls_sha256=digest(parent['component_controls']))


def _validate(data,parent):
    assert set(data)=={'schema','claims','providers','source_fingerprints','parent_evidence_sha256','case_result',
        'case_result_sha256','component_controls','inherited_controls_sha256'}
    assert data['schema']==SCHEMA and data['claims']==claims() and data['providers']==providers()
    assert data['source_fingerprints']==sources() and data['parent_evidence_sha256']==sha256(previous.EVIDENCE)
    assert data['inherited_controls_sha256']==digest(parent['component_controls'])
    row=data['case_result'];assert data['case_result_sha256']==digest(row)==EXPECTED_CASE_SHA256
    assert set(row)=={'complete_seventh_parent_case_equal','parent_case_sha256','field_relation','instruction_observations',
        'instruction_trace_sha256','observed_code_sha256','callbacks','completed_callbacks','stop_reason','new_allocator_events',
        'allocator_aux_events','native_write_observations','actual_allocator_counts','explicit_service_counts','new_providers',
        'new_SVCs','new_JNI_effects','source_bytes_or_hashes_exported','CRC_value_or_hash_exported','key_contents_or_hashes_exported',
        'native_snapshot_used_as_VM_model_input','complete_standalone_signer_verified','online_acceptance_verified'}
    assert row['complete_seventh_parent_case_equal'] is True and row['parent_case_sha256']==digest(parent['case_result'])
    assert row['completed_callbacks']==2 and row['stop_reason']=='callback_budget_before_next_call'
    assert 0<row['instruction_observations']<MAX_NEW_INSTRUCTIONS
    for key,value in EXPECTED.items():assert row[key]==value
    assert row['new_providers']==row['new_SVCs']==row['new_JNI_effects']==row['allocator_aux_events']==[]
    assert all(row[k] is False for k in ('source_bytes_or_hashes_exported','CRC_value_or_hash_exported','key_contents_or_hashes_exported',
        'native_snapshot_used_as_VM_model_input','complete_standalone_signer_verified','online_acceptance_verified'))
    assert row['explicit_service_counts']==parent['case_result']['explicit_service_counts']
    field=row['field_relation'];assert set(field)=={'label','source','conversion','argument','node','node_verified'}
    assert field['label']=='CRC_signed_eighth' and field['node_verified'] is True
    source=field['source']
    assert source['consumed_length']==max(0,source['signed_length'])<=0x100000
    assert source['source_bytes_or_hashes_exported'] is source['CRC_value_or_hash_exported'] is False
    assert all(source[k] is True for k in ('string_object_header_checked','guest_table_is_standard','guest_table_and_binascii_expected_equal',
        'actual_X0_receiver_and_return_equal','actual_core_pointer_and_length_equal','native_guest_table_and_binascii_equal',
        'source_table_and_seven_JSON_nodes_preserved','no_allocation_or_free_effects','exact_sequential_consumed_byte_reads',
        'unsigned_X0_and_exact_four_byte_store_equal','descriptor_padding_preserved'))
    cvt,arg,node=field['conversion'],field['argument'],field['node']
    assert (cvt['load_site'],cvt['convert_site'],cvt['store_site'])==('0x1707d8','0x1707e0','0x1707f8')
    assert cvt['window']==arg['window']==node['window']=='crc_eighth_suffix'
    assert all(cvt[k] is True for k in ('source_low_i32_equal','load_zeroes_upper_lane','signed_extension_equal','exact_binary64_equal','stored_binary64_equal'))
    assert arg['prior_child_count']==node['prior_child_count']==7 and arg['key_contents_or_hashes_exported'] is False
    assert all(arg[k] is True for k in ('initial_JSON_wrapper_verified','binary64_equals_conversion','actual_X0_X1_D0_equal'))
    assert all(node[k] is True for k in ('new_live_node_and_key_allocations','binary64_equals_signed_source_conversion','int32_field_equal','copied_key_equal',
        'old_nodes_and_owned_keys_preserved_except_append_links','root_wrapper_and_counter_preserved','one_byte_success_store_and_other_descriptor_bytes_preserved'))
    calls=row['callbacks'];assert len(calls)==3
    assert calls[0]['index']==1 and calls[0]['return_index']<cvt['index']<arg['index']==calls[1]['index']
    assert node['index']==calls[1]['return_index']<calls[-1]['index']
    old=parent['case_result']['callbacks'][-1]
    for key in ('descriptor_address','VM_cursor_offset','SP','callee_saved_sha256','wrapper_offset','target_offset'):assert calls[0][key]==old[key]
    for call in calls[:2]:
        assert all(call[k] is True for k in ('VM_call_executed','wrapper_entered','target_entered','returned','caller_SP_and_callee_saved_restored'))
    assert all(calls[-1][k] is False for k in ('VM_call_executed','wrapper_entered','target_entered','returned'))
    controls=data['component_controls'];assert set(controls)=={'CRC','signed_conversion','eighth_node_append','CRC_guards','signed_conversion_guards'}
    assert [(c['image_base'],c['case']) for c in controls['CRC']]==[(hex(base),label) for base in crc_fixture.BASES for label in crc_fixture.PROFILES]
    assert [(c['image_base'],c['case'],c['guest_backing']) for c in controls['signed_conversion']]==[
        (hex(base),label,backed) for base in signed_fixture.BASES for label,_ in signed_fixture.PROFILES if label in SIGNED_PROFILES for backed in (False,True)]
    assert [(c['image_base'],c['prior_children'],c['value_profile']) for c in controls['eighth_node_append']]==[
        (hex(base),7,label) for base in number_fixture.BASES for label,_ in APPEND_VALUES]
    for group in ('CRC','signed_conversion','eighth_node_append'):
        for c in controls[group]:
            for key,value in c.items():
                if type(value) is bool and key!='guest_backing':assert value is (key not in {
                    'native_snapshot_input','physical_saved_registers_and_PAC_compared','complete_float_family_verified','complete_physical_ABI_verified'})
    assert [(c['image_base'],c['case']) for c in controls['CRC_guards']]==[(hex(base),label) for base in crc_fixture.BASES for label in crc_fixture.GUARDS]
    assert all(c['rejected'] is c['all_pages_unchanged'] is True for c in controls['CRC_guards'])
    assert [c['operation'] for c in controls['signed_conversion_guards']]==list(signed_fixture.GUARDS)
    assert all(c['rejected'] is c['registers_PC_and_all_pages_unchanged'] is True for c in controls['signed_conversion_guards'])


def validate(data):
    parent=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(parent);_validate(data,parent)


def damaged_evidence_rejected(data):
    parent=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(parent)
    changes=[(('claims','real_ART_JVM_execution'),True),(('providers','inherited_original_JNI_acquisition_body_executed'),True),
        (('source_fingerprints','CRC_model_sha256'),'0'*64),(('inherited_controls_sha256',),'0'*64),
        (('case_result','complete_seventh_parent_case_equal'),False),(('case_result','parent_case_sha256'),'0'*64),
        (('case_result','field_relation','source','native_guest_table_and_binascii_equal'),False),
        (('case_result','field_relation','source','exact_sequential_consumed_byte_reads'),False),
        (('case_result','field_relation','source','descriptor_padding_preserved'),False),
        (('case_result','field_relation','source','source_table_and_seven_JSON_nodes_preserved'),False),
        (('case_result','field_relation','source','CRC_value_or_hash_exported'),True),
        (('case_result','field_relation','conversion','signed_extension_equal'),False),
        (('case_result','field_relation','conversion','source_low_i32_equal'),False),
        (('case_result','field_relation','conversion','stored_binary64_equal'),False),
        (('case_result','field_relation','argument','actual_X0_X1_D0_equal'),False),
        (('case_result','field_relation','node','prior_child_count'),6),(('case_result','field_relation','node','int32_field_equal'),False),
        (('case_result','field_relation','node','new_live_node_and_key_allocations'),False),
        (('case_result','field_relation','node','old_nodes_and_owned_keys_preserved_except_append_links'),False),
        (('case_result','callbacks',-1,'target_entered'),True),(('case_result','registers'),[]),
        (('component_controls','CRC',0,'W0_and_all_guest_and_image_bytes_equal'),False),
        (('component_controls','signed_conversion',0,'exact_int32_to_double_bits_equal'),False),
        (('component_controls','eighth_node_append',0,'ordered_allocation_free_effects_equal'),False),
        (('component_controls','CRC_guards',0,'rejected'),False),(('component_controls','signed_conversion_guards',0,'rejected'),False)]
    for path,value in changes:
        bad=deepcopy(data);target=bad
        for key in path[:-1]:target=target[key]
        target[path[-1]]=value
        if path[0]=='case_result':bad['case_result_sha256']=digest(bad['case_result'])
        try:_validate(bad,parent)
        except (AssertionError,KeyError,ValueError,TypeError,IndexError):continue
        raise AssertionError('damaged CRC/eighth evidence accepted: '+repr(path))
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
    print(json.dumps(dict(schema=SCHEMA,verified_numeric_fields=1,completed_callbacks=data['case_result']['completed_callbacks'],
        damaged_evidence_rejected=rejected,complete_standalone_signer_verified=False)))


if __name__=='__main__':main()
