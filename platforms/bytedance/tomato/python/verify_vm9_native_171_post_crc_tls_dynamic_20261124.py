"""Original warm TLS getter preserving the complete post-CRC constructor checkpoint."""
from __future__ import annotations
from copy import deepcopy
import argparse,hashlib,json
from pathlib import Path
import verify_vm9_native_171_post_crc_constructors_dynamic_20261124 as previous
import verify_vm9_native_171_post_environment_fields_dynamic_20261124 as guard_owner
import verify_vm9_second_TLS_u32_fresh_20261016 as tls_fixture
from unicorn import arm64_const as arm
VM_CALL,VM_RESUME,LIBC_BASE=previous.VM_CALL,previous.VM_RESUME,previous.LIBC_BASE
bootstrap,digest,sha256=previous.bootstrap,previous.digest,previous.sha256
MAX_NEW_INSTRUCTIONS=20000
ALLOWED_PLT=guard_owner.ALLOWED_PLT|{0x3485D0}
EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_post_crc_tls_dynamic_20261124.json')
SCHEMA='vm9-native-171-post-crc-tls-dynamic-20261124-v1'


class PostCrcTls(previous.PostCrcConstructors):
    def __init__(self,control):
        super().__init__(control)
        self._tu_active=self._tu_done=False
        self._tu_sites,self._tu_code,self._tu_writes,self._tu_reads=[],{},[],[]
        self._tu_calls=[];self._tu_seen=set();self._tu_reason=None
        self._tu_parent=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'))

    def _tu_track(self,cpu,pc):
        site=self._fmt_site(pc);self._tu_sites.append(site);self._tu_code[site]=bytes(cpu.mem_read(pc,4)).hex()

    def _tu_call(self,cpu):
        descriptor=self._reg(cpu,0)
        return dict(index=len(self._tu_sites),descriptor_address=hex(descriptor),descriptor_width=48,
            wrapper_offset=hex(self._reg(cpu,8)-self.image),target_offset=hex(self._u(cpu,descriptor)-self.image),
            VM_cursor_offset=hex(self._u(cpu,self._reg(cpu,19))-self.image),
            SP=hex(cpu.reg_read(arm.UC_ARM64_REG_SP)),callee_saved_sha256=self._idctor_saved_hash(cpu),
            VM_call_executed=False,wrapper_entered=False,target_entered=False,returned=False)

    def _sw_stop(self,cpu,reason):
        if reason!='uncovered_VM_callback_before_execution':return super()._sw_stop(cpu,reason)
        assert not self._tu_active and len(self._sw_sites)==1151
        assert all(bytes(cpu.mem_read(a,len(b)))==b for _,a,b in self._sw_protected)
        assert cpu.reg_read(arm.UC_ARM64_REG_PC)==self.image+VM_CALL
        self._sw_done=True;self._sw_reason=reason;self._sw_active=False
        self._tu_state=self._sw_state;self._tu_events=deepcopy(self._tu_state['allocator_events_ref'])
        self._tu_protected=list(self._sw_protected)
        self._tu_active=True;self._tu_track(cpu,self.image+VM_CALL)
        call=self._tu_call(cpu);self._tu_calls.append(call)
        assert (call['wrapper_offset'],call['target_offset'],call['VM_cursor_offset'])==('0x288898','0x2850a8','0x10aa00')
        self._tu_descriptor=int(call['descriptor_address'],16)
        self._tu_packed_before=bytes(cpu.mem_read(self._tu_descriptor,48))
        self._tu_index=self._u(cpu,self.image+0x382930)
        assert self._tu_index==5
        assert self._u(cpu,self.image+0x382920)==self._u(cpu,self.image+0x382928)==4
        self._tu_array=self.tls_array;self._tu_pointer=self.tls_pointer
        self._tu_slot=self._tu_array+16+(self._tu_index-1)*8
        assert self._u(cpu,self._tu_slot)==self._tu_pointer==self.tls_block+8
        assert self._u(cpu,self._tu_array+8)>=self._tu_index
        assert self._u(cpu,self._tu_array+8)==14
        events=self._tu_events;start=len(self.tls_allocations)
        assert events[start]==['alloc',19,self.tls_block,'0x3438e0']
        assert all(not ((e[0]=='free' and e[1]==self.tls_block) or
            (e[0]=='alloc' and e[2]==self.tls_block)) for e in events[start+1:])
        live={}
        for e in events:
            if e[0]=='alloc':live[e[2]]=e[1]
            elif e[0]=='free':live.pop(e[1],None)
        assert live[self.tls_block]==19 and live[self._tu_array]>=128
        self._tu_pthread_body=False
        self._tu_value=self._u(cpu,self._tu_pointer,4)
        for label,a,n in [('TLS_control',self.image+0x382920,32),
            ('TLS_key_once_counter',self.image+0x3E31F4,20),('TLS_array',self._tu_array,128),
            ('TLS_allocation',self.tls_block,19)]:
            self._tu_protected.append((label,a,bytes(cpu.mem_read(a,n))))
        self._base_observe(cpu,self.image+VM_CALL,self._tu_state)
        print('Retained constructor checkpoint; entering original warm TLS getter',flush=True)

    def native_runner(self,*args,**kwargs):
        old_write,old_read=kwargs['memory_write_observer'],kwargs['memory_read_observer']
        def write(cpu,address,size):
            if self._tu_active:
                pc=cpu.reg_read(arm.UC_ARM64_REG_PC)
                assert not any(address<a+len(b) and a<address+size for _,a,b in self._tu_protected),'TLS window wrote retained storage'
                self._tu_writes.append((len(self._tu_sites),self._fmt_site(pc),address,size))
                d=self._tu_descriptor
                if address<d+48 and d<address+size:
                    assert (pc-self.image,address,size)==(0x2888A8,d+16,4)
                    assert self._reg(cpu,0)==self._tu_value
                    assert not self._tu_result_writes
                    self._tu_result_writes.append(dict(index=len(self._tu_sites),native_PC='0x2888a8',packed_offset=16,size=4,equals_TLS_u32=True))
            if old_write:old_write(cpu,address,size)
        def read(cpu,address,size):
            if self._tu_active and self._tu_calls[0]['returned'] and address<self._tu_descriptor+20 and self._tu_descriptor+16<address+size:
                assert address==self._tu_descriptor+16 and size==4
                assert self._u(cpu,address,4)==self._tu_value
                self._tu_reads.append(dict(index=len(self._tu_sites),native_PC=self._fmt_site(cpu.reg_read(arm.UC_ARM64_REG_PC)),
                    VM_cursor_offset=hex(self._u(cpu,self._tu_state['PC_slot'])-self.image),packed_offset=16,size=4,equals_TLS_u32=True))
            if old_read:old_read(cpu,address,size)
        kwargs['memory_write_observer'],kwargs['memory_read_observer']=write,read
        self._tu_result_writes=[]
        return super().native_runner(*args,**kwargs)

    def _tu_stop(self,cpu,reason):
        assert all(bytes(cpu.mem_read(a,len(b)))==b for _,a,b in self._tu_protected)
        self._tu_done=True;self._tu_reason=reason
        cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,bootstrap().digest.context.outer.oracle.STOP)

    def _jst_stop(self,cpu,reason):
        if self._tu_active:return self._tu_stop(cpu,reason)
        return super()._jst_stop(cpu,reason)

    def _tu_guard(self,cpu,pc):
        word=int.from_bytes(cpu.mem_read(pc,4),'little')
        if word==0xD4000001:self._tu_stop(cpu,'new_SVC_before_execution');return True
        if pc==self.image+0x26E70C:self._tu_stop(cpu,'JNI_dispatch_before_execution');return True
        if self.image+self._jwx_plt[0]<=pc<self.image+self._jwx_plt[1] and pc-self.image not in ALLOWED_PLT:
            self._tu_stop(cpu,'uncovered_PLT_before_execution');return True
        target=None
        if word&0x7C000000==0x14000000:
            n=word&0x3FFFFFF
            if n&(1<<25):n-=1<<26
            target=pc+(n<<2)
        elif word&0xFFFFFC1F in (0xD61F0000,0xD63F0000,0xD65F0000):
            register=(word>>5)&31;target=0 if register==31 else self._reg(cpu,register)
        if target is not None:
            if target==self.image+0x26E70C:self._tu_stop(cpu,'JNI_dispatch_before_branch');return True
            if not self._jwx_executable(target):self._tu_stop(cpu,'external_branch_before_execution');return True
            if self.image+self._jwx_plt[0]<=target<self.image+self._jwx_plt[1] and target-self.image not in ALLOWED_PLT:
                self._tu_stop(cpu,'uncovered_PLT_before_branch');return True
        return False

    def observe(self,cpu,pc,state):
        if not self._tu_active:return super().observe(cpu,pc,state)
        self._tu_track(cpu,pc);off=pc-self.image;call=self._tu_calls[0]
        if len(self._tu_sites)>=MAX_NEW_INSTRUCTIONS:self._tu_stop(cpu,'instruction_budget');return
        if off==VM_CALL:
            assert call['returned']
            self._tu_calls.append(self._tu_call(cpu));self._tu_stop(cpu,'next_VM_callback_before_execution');return
        if self._tu_guard(cpu,pc):return
        if pc==LIBC_BASE+0x68760:self._tu_pthread_body=True
        if off in (0x288898,0x2850A8,0x34377C,0x34379C,0x3485D0,0x3437B0,0x3438B0,0x2850BC,0x2888A8):
            self._tu_seen.add(off)
        if off==0x288898:
            assert self._reg(cpu,0)==self._tu_descriptor
            call.update(VM_call_executed=True,wrapper_entered=True)
        if off==0x2850A8:
            assert self._reg(cpu,0)==self._u(cpu,self._tu_descriptor+8)
            call['target_entered']=True
        if off==0x34377C:assert self._reg(cpu,0)==self.image+0x382920
        if off==0x34379C:assert self._reg(cpu,22)==self._tu_index
        if off==0x3485D0:assert self._reg(cpu,0)==self._u(cpu,self.image+0x3E31F4,4)
        if off==0x3437B0:assert self._reg(cpu,0)==self._tu_array
        if off==0x3438B0:assert self._reg(cpu,22)==self._tu_slot and self._reg(cpu,20)==self._tu_pointer
        if off==0x2850BC:assert self._reg(cpu,0)==self._tu_pointer and self._u(cpu,self._tu_pointer,4)==self._tu_value
        if off==0x2888A8:assert self._reg(cpu,0)==self._tu_value
        if off==VM_RESUME:
            assert cpu.reg_read(arm.UC_ARM64_REG_SP)==int(call['SP'],16) and self._idctor_saved_hash(cpu)==call['callee_saved_sha256']
            assert self._reg(cpu,0)==self._tu_value and len(self._tu_result_writes)==1
            expected=bytearray(self._tu_packed_before);expected[16:20]=self._tu_value.to_bytes(4,'little')
            assert bytes(cpu.mem_read(self._tu_descriptor,48))==expected
            self._tu_protected.append(('completed_TLS_descriptor',self._tu_descriptor,bytes(expected)))
            call.update(returned=True,return_index=len(self._tu_sites),caller_SP_and_callee_saved_restored=True)
            print('Original warm TLS read returned; exactly one four-byte result store verified',flush=True)
        self._base_observe(cpu,pc,state)
        assert self.late_jni_calls==self._jev_initial_late and self.java_dispatch_calls==self._jev_initial_java

    def finish(self,result,state,proof):
        assert self._tu_done and self._tu_reason=='next_VM_callback_before_execution'
        assert self._tu_calls[0]['returned'] and len(self._tu_calls)==2
        assert self._tu_seen=={0x288898,0x2850A8,0x34377C,0x34379C,0x3485D0,0x3437B0,0x3438B0,0x2850BC,0x2888A8}
        assert result['allocator_events']==self._tu_events
        assert self._tu_pthread_body,'matching libc pthread_getspecific body not entered'
        old=super().finish(result,state,proof)
        assert old==self._tu_parent['case_result'],'complete constructor checkpoint differs'
        assert self._tu_reads
        trace=hashlib.sha256()
        for site in self._tu_sites:trace.update(site.encode()+bytes.fromhex(self._tu_code[site]))
        return dict(complete_constructor_parent_case_equal=True,parent_case_sha256=digest(old),
            instruction_observations=len(self._tu_sites),instruction_trace_sha256=trace.hexdigest(),observed_code_sha256=digest(self._tu_code),
            callbacks=self._tu_calls,result_writes=self._tu_result_writes,VM_result_reads=self._tu_reads,
            TLS_control_offset='0x382920',TLS_index=self._tu_index,TLS_array_address=hex(self._tu_array),
            TLS_payload_address=hex(self._tu_pointer),TLS_slot_address=hex(self._tu_slot),
            earlier_configuration_TLS_payload_reused=True,original_getter_and_emutls_executed=True,
            original_pthread_getspecific_PLT_entered=True,warm_index_and_array_slot_verified=True,
            TLS_storage_preserved=True,packed_other_44_bytes_preserved=True,retained_JSON_CRC_and_empty_string_preserved=True,
            native_write_observations=len(self._tu_writes),actual_allocator_counts=result['actual_allocator_counts'],
            explicit_service_counts=result['explicit_service_counts'],new_allocator_events=[],new_providers=[],new_SVCs=[],new_JNI_effects=[],
            stop_reason=self._tu_reason,source_values_or_hashes_exported=False,native_snapshot_used_as_VM_model_input=False,
            complete_standalone_signer_verified=False,online_acceptance_verified=False)


def run(library,libc):
    previous.validate(json.loads(previous.EVIDENCE.read_text(encoding='utf-8')))
    original=previous.PostCrcConstructors;previous.PostCrcConstructors=PostCrcTls
    try:return previous.run(library,libc)
    finally:previous.PostCrcConstructors=original

EXPECTED_CASE_SHA256='4411cc7e6e97b38a0892e00bbe2dd24edfadb01620d6e50d281c25b61649aee7'
EXPECTED_COMPONENTS_SHA256='ddc3dd041bf3b9d927e4b64e53da86c87e0db891b94dcc736e4a0bb9ba73ef3e'
EXPECTED_CASE_KEYS=['TLS_array_address', 'TLS_control_offset', 'TLS_index', 'TLS_payload_address', 'TLS_slot_address', 'TLS_storage_preserved', 'VM_result_reads', 'actual_allocator_counts', 'callbacks', 'complete_constructor_parent_case_equal', 'complete_standalone_signer_verified', 'earlier_configuration_TLS_payload_reused', 'explicit_service_counts', 'instruction_observations', 'instruction_trace_sha256', 'native_snapshot_used_as_VM_model_input', 'native_write_observations', 'new_JNI_effects', 'new_SVCs', 'new_allocator_events', 'new_providers', 'observed_code_sha256', 'online_acceptance_verified', 'original_getter_and_emutls_executed', 'original_pthread_getspecific_PLT_entered', 'packed_other_44_bytes_preserved', 'parent_case_sha256', 'result_writes', 'retained_JSON_CRC_and_empty_string_preserved', 'source_values_or_hashes_exported', 'stop_reason', 'warm_index_and_array_slot_verified']

def sources():
    return dict(verifier_sha256=sha256(Path(__file__)),parent_verifier_sha256=sha256(Path(previous.__file__)),
        parent_chain_sha256=digest(previous.sources()),guard_owner_sha256=sha256(Path(guard_owner.__file__)),
        TLS_fixture_sha256=sha256(Path(tls_fixture.__file__)),TLS_services_fixture_sha256=sha256(Path(tls_fixture.dependency.__file__)),
        callback_model_sha256=sha256(Path(__file__).with_name('vm9_request_287474_vm.py')),
        TLS_model_sha256=sha256(Path(__file__).with_name('vm9_objects.py')),
        native_oracle_sha256=sha256(Path(tls_fixture.oracle.__file__)))


def claims():
    return dict(evidence_label='Sample verified',complete_constructor_parent_case_equal=True,
        original_TLS_getter_and_emutls_executed=True,earlier_configuration_TLS_payload_reused=True,
        four_byte_packed_store_and_VM_read_verified=True,TLS_storage_and_other_44_packed_bytes_preserved=True,
        eight_JSON_nodes_CRC_and_empty_string_preserved=True,no_new_allocations_or_OS_JNI_providers=True,
        source_values_or_hashes_exported=False,native_snapshot_used_as_VM_model_input=False,
        original_JNI_acquisition_body_executed=False,real_ART_JVM_execution=False,Android_execution=False,
        complete_physical_ABI_verified=False,concurrency_verified=False,complete_standalone_signer_verified=False,online_acceptance_verified=False)


def providers():
    return dict(parent_evidence_sha256=sha256(previous.EVIDENCE),admitted_callback=['0x288898','0x2850a8'],
        maximum_new_observations=MAX_NEW_INSTRUCTIONS,additionally_admitted_existing_PLT=['0x3485d0'],
        new_import_bindings=[],new_providers=[],TLS_service='inherited existing matching libc routing, original emutls body',
        unknown_callback_policy='stop before VM call',new_SVC_and_JNI_policy='stop before execution',
        inherited_JNI_provider='controlled eight-byte env write; original body bypassed',
        relevant_existing_TLS_native_controls_rerun=14,relevant_existing_TLS_guards_rerun=15,
        other_inherited_component_controls_rerun=False,
        component_allocation_and_futex_services='declared fresh synthetic services; original TLS and matching libc bodies execute')


def capture(library,libc):
    case=run(library,libc);parent=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'))
    controls=dict(TLS_u32=[tls_fixture.compare(library,libc,base,label)
        for base in tls_fixture.dependency.BASES for label in tls_fixture.profiles()],
        TLS_guards=tls_fixture.guards(library,libc))
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
    assert set(row)==set(EXPECTED_CASE_KEYS)
    assert row['parent_case_sha256']==digest(parent['case_result']) and row['complete_constructor_parent_case_equal'] is True
    assert row['stop_reason']=='next_VM_callback_before_execution' and 0<row['instruction_observations']<MAX_NEW_INSTRUCTIONS
    assert all(row[k] is True for k in ('earlier_configuration_TLS_payload_reused','original_getter_and_emutls_executed',
        'original_pthread_getspecific_PLT_entered','warm_index_and_array_slot_verified','TLS_storage_preserved',
        'packed_other_44_bytes_preserved','retained_JSON_CRC_and_empty_string_preserved'))
    assert all(row[k] is False for k in ('source_values_or_hashes_exported','native_snapshot_used_as_VM_model_input',
        'complete_standalone_signer_verified','online_acceptance_verified'))
    assert row['new_allocator_events']==row['new_providers']==row['new_SVCs']==row['new_JNI_effects']==[]
    assert row['actual_allocator_counts']==parent['case_result']['actual_allocator_counts']
    assert row['explicit_service_counts']==parent['case_result']['explicit_service_counts']
    calls=row['callbacks'];assert len(calls)==2 and calls[0]['index']==1 and calls[-1]['index']==row['instruction_observations']
    assert (calls[0]['wrapper_offset'],calls[0]['target_offset'])==('0x288898','0x2850a8')
    assert all(calls[0][k] is True for k in ('VM_call_executed','wrapper_entered','target_entered','returned','caller_SP_and_callee_saved_restored'))
    assert all(calls[-1][k] is False for k in ('VM_call_executed','wrapper_entered','target_entered','returned'))
    for k in ('descriptor_address','VM_cursor_offset','SP','callee_saved_sha256','wrapper_offset','target_offset'):
        assert calls[0][k]==parent['case_result']['callbacks'][-1][k]
    assert len(row['result_writes'])==1 and row['VM_result_reads']
    for r in row['result_writes']+row['VM_result_reads']:
        assert r['packed_offset']==16 and r['size']==4 and r['equals_TLS_u32'] is True
    c=data['component_controls'];assert set(c)=={'TLS_u32','TLS_guards'} and digest(c)==EXPECTED_COMPONENTS_SHA256
    assert [(r['image_base'],r['case']) for r in c['TLS_u32']]==[(hex(b),l) for b in tls_fixture.dependency.BASES for l in tls_fixture.profiles()]
    for r in c['TLS_u32']:
        assert all(r[k] is True for k in ('original_second_wrapper_and_TLS_getter_returned',
            'uint32_result_guest_ELF_TLS_and_packed_padding_match','allocation_and_wake_order_match',
            'original_TLS_and_matching_libc_executed','ignored_receiver_unmapped'))
        assert r['native_snapshot_input'] is False
    assert len(c['TLS_guards'])==15
    assert all(r['rejected'] is r['all_model_pages_unchanged'] is True and r['external_provider_effect_rollback_verified'] is False for r in c['TLS_guards'])


def validate(data):
    parent=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(parent);_validate(data,parent)


def damaged_evidence_rejected(data):
    parent=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(parent)
    changes=[(('claims','real_ART_JVM_execution'),True),(('claims','original_JNI_acquisition_body_executed'),True),
        (('providers','new_providers'),['guessed_TLS']), (('source_fingerprints','TLS_model_sha256'),'0'*64),
        (('inherited_controls_sha256',),'0'*64),(('case_result','complete_constructor_parent_case_equal'),False),
        (('case_result','earlier_configuration_TLS_payload_reused'),False),(('case_result','TLS_index'),0),
        (('case_result','TLS_payload_address'),'0x0'),(('case_result','TLS_storage_preserved'),False),
        (('case_result','packed_other_44_bytes_preserved'),False),(('case_result','retained_JSON_CRC_and_empty_string_preserved'),False),
        (('case_result','result_writes',0,'size'),8),(('case_result','result_writes',0,'packed_offset'),20),
        (('case_result','VM_result_reads',0,'equals_TLS_u32'),False),(('case_result','VM_result_reads'),[]),
        (('case_result','callbacks',0,'caller_SP_and_callee_saved_restored'),False),(('case_result','callbacks',-1,'target_entered'),True),
        (('case_result','source_values_or_hashes_exported'),True),(('case_result','registers'),[]),
        (('component_controls','TLS_u32',0,'native_snapshot_input'),True),(('component_controls','TLS_guards',0,'rejected'),False)]
    for path,value in changes:
        bad=deepcopy(data);target=bad
        for key in path[:-1]:target=target[key]
        target[path[-1]]=value
        if path[0]=='case_result':bad['case_result_sha256']=digest(bad['case_result'])
        try:_validate(bad,parent)
        except (AssertionError,KeyError,ValueError,TypeError,IndexError):continue
        raise AssertionError('damaged post-CRC TLS evidence accepted: '+repr(path))
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
    print(json.dumps(dict(schema=SCHEMA,TLS_callbacks=1,damaged_evidence_rejected=rejected,complete_standalone_signer_verified=False)))


if __name__=='__main__':main()
