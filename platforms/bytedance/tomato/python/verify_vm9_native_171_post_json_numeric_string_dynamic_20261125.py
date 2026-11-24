"""Original libc++ numeric string: nine unsigned globals, warm TLS and reserve/shrink."""
from __future__ import annotations
from copy import deepcopy
import argparse,hashlib,json
from pathlib import Path
import verify_vm9_native_171_post_crc_json_string_dynamic_20261125 as previous
import verify_vm9_second_numeric_string_fresh_20261016 as numeric_fixture
from unicorn import arm64_const as arm
VM_CALL,VM_RESUME,LIBC_BASE=previous.VM_CALL,previous.VM_RESUME,previous.LIBC_BASE
bootstrap,digest,sha256=previous.bootstrap,previous.digest,previous.sha256
MAX_NEW_INSTRUCTIONS=150000
EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_post_json_numeric_string_dynamic_20261125.json')
SCHEMA='vm9-native-171-post-json-numeric-string-dynamic-20261125-v1'


class PostJsonNumericString(previous.PostCrcJsonString):
    def __init__(self,control):
        super().__init__(control)
        self._ns_active=self._ns_done=False;self._ns_sites=[];self._ns_code={};self._ns_writes=[]
        self._ns_calls=[];self._ns_globals=[];self._ns_values=[];self._ns_decimals=[];self._ns_append=[]
        self._ns_cleanup=[];self._ns_aux=[];self._ns_seen=set();self._ns_TLS_read=False
        self._ns_parent=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'))

    def _ns_string(self,cpu,address):
        raw=bytes(cpu.mem_read(address,24));tag=raw[0]
        long=bool(tag&1);length=int.from_bytes(raw[8:16],'little') if long else tag>>1
        storage=(int.from_bytes(raw[:8],'little')&~1) if long else 23
        pointer=int.from_bytes(raw[16:24],'little') if long else address+1
        assert 0<=length<storage<=1048576 and (long or length<=22)
        data=bytes(cpu.mem_read(pointer,length+1));assert data[-1:]==b'\0'
        return dict(representation='long' if long else 'short',length=length,storage_bytes=storage,
            usable_capacity=storage-1,payload_address=hex(pointer)),data[:-1]

    def _ns_track(self,cpu,pc):
        site=self._fmt_site(pc);self._ns_sites.append(site);self._ns_code[site]=bytes(cpu.mem_read(pc,4)).hex()

    def _ns_call(self,cpu):
        d=self._reg(cpu,0)
        return dict(index=len(self._ns_sites),descriptor_address=hex(d),descriptor_prefix_width=24,
            wrapper_offset=hex(self._reg(cpu,8)-self.image),target_offset=hex(self._u(cpu,d)-self.image),
            VM_cursor_offset=hex(self._u(cpu,self._reg(cpu,19))-self.image),
            SP=hex(cpu.reg_read(arm.UC_ARM64_REG_SP)),callee_saved_sha256=self._idctor_saved_hash(cpu),
            VM_call_executed=False,wrapper_entered=False,target_entered=False,returned=False)

    def _j9_stop(self,cpu,reason):
        if self._ns_active:return self._ns_stop(cpu,reason)
        if reason!='next_VM_callback_before_execution':return super()._j9_stop(cpu,reason)
        assert len(self._j9_sites)==1218 and self._j9_calls[0]['returned']
        assert all(bytes(cpu.mem_read(a,len(b)))==b for _,a,b in self._j9_protected)
        self._j9_done=True;self._j9_reason=reason;self._j9_active=False
        self._ns_state=self._j9_state;self._ns_events=deepcopy(self._ns_state['allocator_events_ref'])
        self._ns_protected=list(self._j9_protected)
        self._ns_active=True;self._ns_track(cpu,self.image+VM_CALL)
        call=self._ns_call(cpu);self._ns_calls.append(call)
        assert (call['wrapper_offset'],call['target_offset'],call['VM_cursor_offset'])==('0x2888f4','0x28794c','0x10aabc')
        self._ns_descriptor=int(call['descriptor_address'],16)
        self._ns_packed=bytes(cpu.mem_read(self._ns_descriptor,24))
        self._ns_output=self._u(cpu,self._ns_descriptor+8);self._ns_receiver=self._u(cpu,self._ns_descriptor+16)
        assert not any(self._ns_output<a+len(b) and a<self._ns_output+24 for _,a,b in self._ns_protected),'numeric output aliases retained storage'
        assert not (self._ns_output<self._ns_descriptor+24 and self._ns_descriptor<self._ns_output+24)
        self._ns_neighbor=bytes(cpu.mem_read(self._ns_output+24,8))
        self._ns_protected.append(('numeric_u32_globals',self.image+0x3D1988,bytes(cpu.mem_read(self.image+0x3D1988,36))))
        self._ns_TLS_pointer=self.tls_pointer
        assert self._u(cpu,self.tls_array+16+4*8)==self._ns_TLS_pointer
        assert self._u(cpu,self.image+0x382930)==5
        self._base_observe(cpu,self.image+VM_CALL,self._ns_state)
        print('Retained nine-node JSON checkpoint; original libc++ numeric string construction admitted',flush=True)

    def native_runner(self,*args,**kwargs):
        old_write,old_read=kwargs['memory_write_observer'],kwargs['memory_read_observer']
        def read(cpu,a,n):
            if self._ns_active:
                pc=cpu.reg_read(arm.UC_ARM64_REG_PC)-self.image
                if pc==0x2879A0:
                    offset=a-(self.image+0x3D1988)
                    assert offset==len(self._ns_globals)*4 and n==4 and 0<=offset<36
                    value=self._u(cpu,a,4);self._ns_values.append(value)
                    self._ns_globals.append(dict(index=len(self._ns_sites),PC=hex(pc),global_offset=hex(0x3D1988+offset),width=4))
                if pc==0x2850BC:
                    assert a==self._ns_TLS_pointer and n==4 and not self._ns_TLS_read
                    self._ns_TLS_read=True;self._ns_TLS_value=self._u(cpu,a,4)
            if old_read:old_read(cpu,a,n)
        def write(cpu,a,n):
            if self._ns_active:
                pc=cpu.reg_read(arm.UC_ARM64_REG_PC)
                assert not any(a<b+len(raw) and b<a+n for _,b,raw in self._ns_protected),'numeric string wrote retained storage'
                if not self._ns_calls[0]['returned']:
                    assert not (a<self._ns_descriptor+24 and self._ns_descriptor<a+n),'numeric string wrote packed input'
                    assert not (a<self._ns_output+32 and self._ns_output+24<a+n),'numeric string wrote output neighbor'
                self._ns_writes.append((len(self._ns_sites),self._fmt_site(pc),a,n))
            if old_write:old_write(cpu,a,n)
        kwargs['memory_write_observer'],kwargs['memory_read_observer']=write,read
        return super().native_runner(*args,**kwargs)

    def _ns_stop(self,cpu,reason):
        assert all(bytes(cpu.mem_read(a,len(b)))==b for _,a,b in self._ns_protected)
        self._ns_done=True;self._ns_reason=reason
        cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,bootstrap().digest.context.outer.oracle.STOP)

    def _f5_stop(self,cpu,reason):
        if self._ns_active:return self._ns_stop(cpu,reason)
        return super()._f5_stop(cpu,reason)

    def _jst_stop(self,cpu,reason):
        if self._ns_active:return self._ns_stop(cpu,reason)
        return super()._jst_stop(cpu,reason)

    def observe(self,cpu,pc,state):
        if not self._ns_active:return super().observe(cpu,pc,state)
        self._ns_track(cpu,pc);off=pc-self.image;call=self._ns_calls[0]
        if len(self._ns_sites)>=MAX_NEW_INSTRUCTIONS:self._ns_stop(cpu,'instruction_budget');return
        if off==VM_CALL:
            assert call['returned'];self._ns_calls.append(self._ns_call(cpu));self._ns_stop(cpu,'next_VM_callback_before_execution');return
        if self._f5_guard(cpu,pc):return
        if off in (0x2888F4,0x28794C,0x32BF14,0x287A38,0x32B16C,0x2254F0,0x32AA70,0x2850A8,0x34377C,0x3485D0,0x287A70,0x32AD4C,0x347FD0,0x347FA0):self._ns_seen.add(('main',off))
        if pc in (LIBC_BASE+0x68760,LIBC_BASE+0x1BB08,LIBC_BASE+0x1BAC0):self._ns_seen.add(('libc',pc-LIBC_BASE))
        if pc in (LIBC_BASE+0x9833C,LIBC_BASE+0x97F40):self._ns_aux.append(dict(index=len(self._ns_sites),kind='gc' if pc==LIBC_BASE+0x9833C else 'flush'))
        if off==0x2888F4:
            assert self._reg(cpu,0)==self._ns_descriptor;call.update(VM_call_executed=True,wrapper_entered=True)
        if off==0x28794C:
            assert self._reg(cpu,8)==self._ns_output and self._reg(cpu,0)==self._ns_receiver
            assert self._reg(cpu,30)==self.image+0x288904;call['target_entered']=True
        if off==0x32AD4C and self._reg(cpu,30)-self.image in (0x28798C,0x287A0C):
            assert self._reg(cpu,0)==self._ns_output
            assert self._reg(cpu,1)==(128 if self._reg(cpu,30)-self.image==0x28798C else 0)
        if off==0x28798C:
            info,data=self._ns_string(cpu,self._ns_output)
            assert info['representation']=='long' and info['storage_bytes']==144 and info['length']==0 and not data
            self._ns_initial_buffer=int(info['payload_address'],16)
            events=state['allocator_events_ref'][len(self._ns_events):]
            assert len(events)==1 and events[0][:3]==['alloc',144,self._ns_initial_buffer]
            self._ns_reserved=dict(index=len(self._ns_sites),requested=128,allocation_bytes=144,usable_capacity=143,
                empty_long_descriptor_and_NUL_verified=True)
        if off==0x32BAA4:
            number=len(self._ns_decimals)
            assert number<10 and (len(self._ns_values)==number+1 if number<9 else self._ns_TLS_read)
            value=self._ns_values[number] if number<9 else self._ns_TLS_value
            assert self._reg(cpu,0)==value
            self._ns_decimal_target=self._reg(cpu,8);self._ns_decimal_value=str(value).encode('ascii')
            self._ns_decimals.append(dict(argument_index=number,source='global' if number<9 else 'TLS',input_width=4,
                actual_unsigned_X0_and_hidden_output_verified=True,decimal_and_NUL_equal=False))
        if off in (0x2879AC,0x2879F0):
            info,data=self._ns_string(cpu,self._ns_decimal_target)
            assert data==self._ns_decimal_value and info['representation']=='short'
            self._ns_decimals[-1].update(decimal_and_NUL_equal=True,short_decimal_length=info['length'])
        if off==0x287A38:
            assert self._reg(cpu,0)==self._ns_decimal_target and self._reg(cpu,1)==124
            self._ns_moved_target=self._reg(cpu,8)
        if off==0x2879BC:
            info,data=self._ns_string(cpu,self._ns_moved_target)
            assert data==self._ns_decimal_value+b'|' and info['representation']=='short'
            assert bytes(cpu.mem_read(self._ns_decimal_target,24))==bytes(24)
        if off in (0x2879C8,0x2879FC):
            expected=b''.join(str(v).encode('ascii')+b'|' for v in self._ns_values)
            if off==0x2879FC:expected+=str(self._ns_TLS_value).encode('ascii')
            info,data=self._ns_string(cpu,self._ns_output)
            assert data==expected and info['representation']=='long' and info['storage_bytes']==144
            self._ns_append.append(dict(index=len(self._ns_sites),global_parts=len(self._ns_values),
                TLS_part=off==0x2879FC,entire_prefix_and_NUL_equal=True))
        if off==0x32AA70 and self._reg(cpu,30)-self.image in (0x2879D0,0x2879D8,0x287A04):
            self._ns_cleanup.append(dict(index=len(self._ns_sites),return_PC=hex(self._reg(cpu,30)-self.image)))
        if off==0x2850A8:assert self._reg(cpu,0)==self._ns_receiver
        if off==0x34377C:assert self._reg(cpu,0)==self.image+0x382920
        if off==0x2850BC:assert self._reg(cpu,0)==self._ns_TLS_pointer
        if off==0x287A08:
            assert len(self._ns_values)==9 and self._ns_TLS_read and len(self._ns_decimals)==10
            self._ns_expected=b'|'.join(str(v).encode('ascii') for v in [*self._ns_values,self._ns_TLS_value])
            info,data=self._ns_string(cpu,self._ns_output);assert data==self._ns_expected
            assert info['representation']=='long' and info['storage_bytes']==144 and 19<=len(data)<=109
            self._ns_pre_shrink=dict(index=len(self._ns_sites),length=len(data),storage_bytes=144,
                independent_unsigned_join_equal=True)
        if off==VM_RESUME:
            assert len(self._ns_globals)==9 and len(self._ns_decimals)==10 and len(self._ns_append)==10 and len(self._ns_cleanup)==19
            assert all(d['decimal_and_NUL_equal'] for d in self._ns_decimals)
            assert cpu.reg_read(arm.UC_ARM64_REG_SP)==int(call['SP'],16) and self._idctor_saved_hash(cpu)==call['callee_saved_sha256']
            assert bytes(cpu.mem_read(self._ns_descriptor,24))==self._ns_packed and bytes(cpu.mem_read(self._ns_output+24,8))==self._ns_neighbor
            info,data=self._ns_string(cpu,self._ns_output);assert data==self._ns_expected
            events=state['allocator_events_ref'][len(self._ns_events):];length=len(data)
            if length<=22:
                assert info['representation']=='short' and events==[['alloc',144,self._ns_initial_buffer,events[0][3]],['free',self._ns_initial_buffer]]
            else:
                size=(length+16)&~15;pointer=int(info['payload_address'],16)
                assert info['representation']=='long' and info['storage_bytes']==size and pointer!=self._ns_initial_buffer
                assert [e[0] for e in events]==['alloc','alloc','free'] and [e[1] for e in events[:2]]==[144,size]
                assert events[1][2]==pointer and events[-1]==['free',self._ns_initial_buffer]
                assert self._jff_live(state).get(pointer,0)>=size
                self._ns_protected.append(('numeric_long_payload',pointer,bytes(cpu.mem_read(pointer,size))))
            self._ns_final=dict(info,object_address=hex(self._ns_output),independent_unsigned_join_and_NUL_equal=True,
                shrink_representation_and_original_buffer_free_verified=True,packed24_and_neighbor8_preserved=True,
                hidden_X8_output_verified=True,CPU_X0_return_interpreted=False)
            self._ns_protected.append(('numeric_cpp_string',self._ns_output,bytes(cpu.mem_read(self._ns_output,24))))
            call.update(returned=True,return_index=len(self._ns_sites),caller_SP_and_callee_saved_restored=True)
            print('Original libc++ numeric string returned; nine globals, warm TLS, decimal/move/append/shrink verified',flush=True)
        self._base_observe(cpu,pc,state)
        assert self.late_jni_calls==self._jev_initial_late and self.java_dispatch_calls==self._jev_initial_java

    def finish(self,result,state,proof):
        assert self._ns_done and self._ns_reason=='next_VM_callback_before_execution' and self._ns_calls[0]['returned']
        assert {('main',x) for x in (0x2888F4,0x28794C,0x32BF14,0x287A38,0x32B16C,0x2254F0,0x32AA70,0x2850A8,0x34377C,0x3485D0,0x287A70,0x32AD4C,0x347FD0,0x347FA0)}|{('libc',x) for x in (0x68760,0x1BB08,0x1BAC0)}<=self._ns_seen
        events=result['allocator_events'][len(self._ns_events):];counts=deepcopy(result['actual_allocator_counts'])
        for e in events:counts['malloc' if e[0]=='alloc' else 'free']-=1
        for e in self._ns_aux:counts[e['kind']]-=1
        old=super().finish(dict(result,allocator_events=self._ns_events,actual_allocator_counts=counts),state,proof)
        assert old==self._ns_parent['case_result'],'complete ninth-node JSON checkpoint differs'
        trace=hashlib.sha256()
        for site in self._ns_sites:trace.update(site.encode()+bytes.fromhex(self._ns_code[site]))
        return dict(complete_JSON_string_parent_case_equal=True,parent_case_sha256=digest(old),instruction_observations=len(self._ns_sites),
            instruction_trace_sha256=trace.hexdigest(),observed_code_sha256=digest(self._ns_code),callbacks=self._ns_calls,
            global_reads=self._ns_globals,decimal_conversions=self._ns_decimals,append_prefixes=self._ns_append,
            direct_temporary_cleanup_calls=self._ns_cleanup,initial_reserve=self._ns_reserved,pre_shrink=self._ns_pre_shrink,
            final_cpp_string=self._ns_final,TLS_source=dict(control_offset='0x382920',payload_address=hex(self._ns_TLS_pointer),
                warm_index=5,original_getter_emutls_and_matching_libc_executed=True),
            retained_nine_JSON_nodes_keys_values_CRC_TLS_and_formatted_source_preserved=True,
            native_write_observations=len(self._ns_writes),new_allocator_events=events,allocator_aux_events=self._ns_aux,
            actual_allocator_counts=result['actual_allocator_counts'],explicit_service_counts=result['explicit_service_counts'],
            new_providers=[],new_SVCs=[],new_JNI_effects=[],stop_reason=self._ns_reason,
            source_values_or_hashes_exported=False,allocation_contents_exported=False,native_snapshot_used_as_VM_model_input=False,
            complete_standalone_signer_verified=False,online_acceptance_verified=False)


def run(library,libc):
    previous.validate(json.loads(previous.EVIDENCE.read_text(encoding='utf-8')))
    original=previous.PostCrcJsonString;previous.PostCrcJsonString=PostJsonNumericString
    try:return previous.run(library,libc)
    finally:previous.PostCrcJsonString=original

EXPECTED_CASE_SHA256='add292a36c17b995b90d760ba6a53633989f784655d443ff62f6ec20dea1f24a'
EXPECTED_COMPONENTS_SHA256='4167f699158bb23a310ee6095587ace3d782c5cd284d3399bbb57fb9cc1ff37d'
EXPECTED_CASE_KEYS=['TLS_source', 'actual_allocator_counts', 'allocation_contents_exported', 'allocator_aux_events', 'append_prefixes', 'callbacks', 'complete_JSON_string_parent_case_equal', 'complete_standalone_signer_verified', 'decimal_conversions', 'direct_temporary_cleanup_calls', 'explicit_service_counts', 'final_cpp_string', 'global_reads', 'initial_reserve', 'instruction_observations', 'instruction_trace_sha256', 'native_snapshot_used_as_VM_model_input', 'native_write_observations', 'new_JNI_effects', 'new_SVCs', 'new_allocator_events', 'new_providers', 'observed_code_sha256', 'online_acceptance_verified', 'parent_case_sha256', 'pre_shrink', 'retained_nine_JSON_nodes_keys_values_CRC_TLS_and_formatted_source_preserved', 'source_values_or_hashes_exported', 'stop_reason']

def sources():
    return dict(verifier_sha256=sha256(Path(__file__)),parent_verifier_sha256=sha256(Path(previous.__file__)),
        parent_chain_sha256=digest(previous.sources()),numeric_fixture_sha256=sha256(Path(numeric_fixture.__file__)),
        callback_model_sha256=sha256(Path(numeric_fixture.second.__file__)),
        allocator_services_sha256=sha256(Path(__file__).with_name('verify_vm9_reference_scopes_fresh_20261011.py')),
        allocator_effects_sha256=sha256(Path(__file__).with_name('verify_vm9_strings.py')),
        native_oracle_sha256=sha256(Path(numeric_fixture.oracle.__file__)))


def claims():
    return dict(evidence_label='Sample verified',complete_JSON_string_parent_case_equal=True,
        original_numeric_wrapper_decimal_pipe_move_append_cleanup_and_shrink_executed=True,
        nine_ordered_u32_global_reads_and_original_warm_TLS_getter_verified=True,
        matching_libc_malloc_free_and_pthread_getspecific_executed=True,
        ten_unsigned_decimal_temporaries_and_ten_entire_append_prefixes_verified=True,
        reserve128_and_final_reserve0_representation_and_buffer_lifetime_verified=True,
        final_libcxx_string_equals_independent_unsigned_join=True,packed24_neighbor8_SP_and_callee_saved_preserved=True,
        retained_nine_JSON_nodes_keys_values_CRC_TLS_and_formatted_source_preserved=True,
        source_values_or_hashes_exported=False,allocation_contents_exported=False,native_snapshot_used_as_VM_model_input=False,
        original_JNI_acquisition_body_executed=False,real_ART_JVM_execution=False,Android_execution=False,
        complete_physical_ABI_verified=False,concurrency_verified=False,complete_standalone_signer_verified=False,online_acceptance_verified=False)


def providers():
    return dict(parent_evidence_sha256=sha256(previous.EVIDENCE),admitted_callback=['0x2888f4','0x28794c'],
        maximum_new_observations=MAX_NEW_INSTRUCTIONS,new_import_bindings=[],new_providers=[],
        output_type='24-byte libc++ string; hidden X8 output; CPU X0 not interpreted as object metadata',
        expected_output='independent unsigned-decimal join from observed nine u32 reads then original TLS u32',
        allocation_and_TLS='inherited original matching Bionic allocation and warm emutls/libc routing',
        unknown_callback_policy='stop before VM call',new_SVC_and_JNI_policy='stop before execution',
        inherited_JNI_provider='controlled eight-byte env write; original body bypassed',
        relevant_existing_numeric_string_native_controls_rerun=30,relevant_existing_numeric_guards_rerun=34,
        other_inherited_component_controls_rerun=False,component_services='declared synthetic allocator and TLS boundaries; fresh ELF inputs')


def capture(library,libc):
    case=run(library,libc);parent=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'))
    controls=dict(numeric_string=[numeric_fixture.compare(library,b,l) for b in numeric_fixture.BASES for l in numeric_fixture.PROFILES],
        numeric_guards=numeric_fixture.guards(library))
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
    assert r['complete_JSON_string_parent_case_equal'] is True and r['parent_case_sha256']==digest(parent['case_result'])
    assert r['stop_reason']=='next_VM_callback_before_execution' and 0<r['instruction_observations']<MAX_NEW_INSTRUCTIONS
    assert r['new_providers']==r['new_SVCs']==r['new_JNI_effects']==[]
    assert r['retained_nine_JSON_nodes_keys_values_CRC_TLS_and_formatted_source_preserved'] is True
    assert all(r[k] is False for k in ('source_values_or_hashes_exported','allocation_contents_exported',
        'native_snapshot_used_as_VM_model_input','complete_standalone_signer_verified','online_acceptance_verified'))
    assert r['explicit_service_counts']==parent['case_result']['explicit_service_counts']
    calls=r['callbacks'];assert len(calls)==2 and calls[0]['index']==1 and calls[-1]['index']==r['instruction_observations']
    assert (calls[0]['wrapper_offset'],calls[0]['target_offset'])==('0x2888f4','0x28794c') and calls[0]['descriptor_prefix_width']==24
    assert all(calls[0][k] is True for k in ('VM_call_executed','wrapper_entered','target_entered','returned','caller_SP_and_callee_saved_restored'))
    assert all(calls[-1][k] is False for k in ('VM_call_executed','wrapper_entered','target_entered','returned'))
    for k in ('descriptor_address','VM_cursor_offset','SP','callee_saved_sha256','wrapper_offset','target_offset'):
        assert calls[0][k]==parent['case_result']['callbacks'][-1][k]
    assert [(v['PC'],v['global_offset'],v['width']) for v in r['global_reads']]==[('0x2879a0',hex(0x3D1988+i*4),4) for i in range(9)]
    assert len(r['decimal_conversions'])==10
    for i,v in enumerate(r['decimal_conversions']):
        assert v['argument_index']==i and v['source']==('global' if i<9 else 'TLS') and v['input_width']==4
        assert v['actual_unsigned_X0_and_hidden_output_verified'] is v['decimal_and_NUL_equal'] is True
        assert 1<=v['short_decimal_length']<=10
    assert [(v['global_parts'],v['TLS_part']) for v in r['append_prefixes']]==[(i,False) for i in range(1,10)]+[(9,True)]
    assert all(v['entire_prefix_and_NUL_equal'] is True for v in r['append_prefixes'])
    assert len(r['direct_temporary_cleanup_calls'])==19
    initial=r['initial_reserve'];assert (initial['requested'],initial['allocation_bytes'],initial['usable_capacity'])==(128,144,143)
    assert initial['empty_long_descriptor_and_NUL_verified'] is True
    final=r['final_cpp_string'];assert 19<=final['length']<=109
    assert final['length']==r['pre_shrink']['length'] and r['pre_shrink']['independent_unsigned_join_equal'] is True
    assert all(final[k] is True for k in ('independent_unsigned_join_and_NUL_equal','shrink_representation_and_original_buffer_free_verified',
        'packed24_and_neighbor8_preserved','hidden_X8_output_verified')) and final['CPU_X0_return_interpreted'] is False
    if final['representation']=='short':assert final['length']<=22 and final['storage_bytes']==23 and final['usable_capacity']==22
    else:assert final['representation']=='long' and final['length']>=23 and final['storage_bytes']==((final['length']+16)&~15) and final['usable_capacity']==final['storage_bytes']-1
    assert r['TLS_source']['control_offset']=='0x382920' and r['TLS_source']['warm_index']==5 and r['TLS_source']['original_getter_emutls_and_matching_libc_executed'] is True
    c=data['component_controls'];assert set(c)=={'numeric_string','numeric_guards'} and digest(c)==EXPECTED_COMPONENTS_SHA256
    assert [(v['image_base'],v['case']) for v in c['numeric_string']]==[(hex(b),l) for b in numeric_fixture.BASES for l in numeric_fixture.PROFILES]
    for v in c['numeric_string']:
        assert all(v[k] is True for k in ('original_numeric_wrapper_reserve_decimal_append_move_cleanup_shrink_returned',
            'all_guest_and_image_bytes_equal','ordered_TLS_allocation_free_and_prefree_bytes_equal','packed_bytes_preserved',
            'receiver_unmapped','synthetic_allocator_and_TLS_services'))
        assert v['native_snapshot_input'] is v['complete_physical_ABI_verified'] is False
    assert len(c['numeric_guards'])==34 and [v['case'] for v in c['numeric_guards']]==list(numeric_fixture.GUARDS)
    assert all(v['rejected'] is v['all_model_pages_unchanged'] is True and v['external_provider_effect_rollback_verified'] is False for v in c['numeric_guards'])


def validate(data):
    parent=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(parent);_validate(data,parent)


def damaged_evidence_rejected(data):
    parent=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(parent)
    changes=[(('claims','real_ART_JVM_execution'),True),(('claims','original_JNI_acquisition_body_executed'),True),
        (('providers','new_providers'),['guessed_TLS']), (('source_fingerprints','callback_model_sha256'),'0'*64),
        (('inherited_controls_sha256',),'0'*64),(('case_result','complete_JSON_string_parent_case_equal'),False),
        (('case_result','global_reads',0,'width'),8),(('case_result','global_reads',0,'global_offset'),'0x0'),
        (('case_result','decimal_conversions',0,'decimal_and_NUL_equal'),False),(('case_result','decimal_conversions',9,'source'),'global'),
        (('case_result','append_prefixes',0,'entire_prefix_and_NUL_equal'),False),(('case_result','direct_temporary_cleanup_calls'),[]),
        (('case_result','initial_reserve','allocation_bytes'),128),(('case_result','pre_shrink','independent_unsigned_join_equal'),False),
        (('case_result','final_cpp_string','shrink_representation_and_original_buffer_free_verified'),False),
        (('case_result','final_cpp_string','CPU_X0_return_interpreted'),True),
        (('case_result','TLS_source','original_getter_emutls_and_matching_libc_executed'),False),
        (('case_result','retained_nine_JSON_nodes_keys_values_CRC_TLS_and_formatted_source_preserved'),False),
        (('case_result','callbacks',-1,'target_entered'),True),(('case_result','source_values_or_hashes_exported'),True),
        (('case_result','allocation_contents_exported'),True),(('case_result','registers'),[]),
        (('component_controls','numeric_string',0,'native_snapshot_input'),True),(('component_controls','numeric_guards',0,'rejected'),False)]
    for path,value in changes:
        bad=deepcopy(data);target=bad
        for key in path[:-1]:target=target[key]
        target[path[-1]]=value
        if path[0]=='case_result':bad['case_result_sha256']=digest(bad['case_result'])
        try:_validate(bad,parent)
        except (AssertionError,KeyError,ValueError,TypeError,IndexError):continue
        raise AssertionError('damaged numeric string evidence accepted: '+repr(path))
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
    print(json.dumps(dict(schema=SCHEMA,numeric_strings=1,damaged_evidence_rejected=rejected,complete_standalone_signer_verified=False)))


if __name__=='__main__':main()
