"""Original request releases the configuration owner's retained reference.

R17/R18 are checked against owner+160/+168. Fresh Python pages exercise the
observed count2 branch using existing VM/reference/diagnostic owners. No native
snapshot, deleting-branch or physical-stack equivalence is claimed.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
from unicorn import arm64_const as arm
import verify_vm9_native_171_configuration_cleanup_20261119 as previous

context,graph,name,diagnostics=previous.context,previous.graph,previous.name,previous.diagnostics
references=previous.references
EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_configuration_owner_cleanup_20261119.json')
ENTRY,ENTER,CALL,STOP=0xFD390,0xFD3AC,0xFD424,0x16AA4C
GOT_BASE=previous.previous.GOT_BASE
WORDS=[(ENTRY,0x934A380F),(0xFD394,0x890E0218),(0xFD398,0x8B70391A),
    (0xFD39C,0x8368391A),(0xFD3A0,0x8B40391A),(0xFD3A4,0x05804B11),
    (0xFD3A8,0x05C19B11),(ENTER,0x067E0C91),(0xFD3B0,0x8094002D),
    (0xFD3B4,0x80022001),(0xFD3B8,0x7FE2F8FB),(0xFD3BC,0x88040016),
    (0xFD3C0,0x000080AB),(0xFD404,0x8B5A0C18),(0xFD408,0x08400018),
    (0xFD40C,0xA37F0C18),(0xFD410,0xA378311A),(0xFD414,0x8B50311A),
    (0xFD418,0x934A340F),(0xFD41C,0x07804B11),(0xFD420,0x05C19B11),(CALL,0x067E0C91)]
EXPECTED=previous.EXPECTED
LOADS=[(0xFD394,456,1,'ELF GOT base'),(0xFD404,1872,1,'frame'),
    (0xFD408,0,1,'ELF GOT slot'),(0xFD40C,2032,20,'frame')]
STORES=[(0xFD39C,4336),(0xFD3A0,4328),(0xFD3A4,4320),(0xFD414,4312),(0xFD418,4304)]
CLAIMS=dict(retained_configuration_cleanup_instruction_code_allocation_prefix_verified=True,
    completed_cleanup_observer_retired_after_full_prefix_check=True,original_diagnostic_bodies_executed=True,
    R17_R18_match_configuration_owner_fields160_168=True,
    fresh_Python_VM_selected_arguments_count_and_branches_match=True,
    fresh_Python_scoped_reference_release_selected_semantics_match=True,
    original_owner_u32_count2_to1_and_adjacent12_preserved=True,
    previously_released_clone_source_counter_remains_one=True,warm_scope_lock_and_unlock_verified=True,
    configuration_owner_pair_source_and_clone_preserved=True,allocation_service_JNI_and_SVC_ledgers_unchanged=True,
    native_memory_used_as_model_input=False,new_OS_JNI_or_internal_helper_providers=False,
    deleting_cleanup_branch_verified=False,full_VM_or_physical_stack_equivalence_verified=False,
    owner_cleanup_exit_return_consumed=False,complete_configuration_value_provenance_verified=False,
    saved_NULL_business_branch_verified=False,KMSV_value_generated=False,client_key_value_generated=False,
    real_business_cache_restored=False,real_JVM_identity_verified=False,ordinary_Cronet_six_headers_verified=False,
    whole_request_equivalence_verified=False,callback_or_ordinary_wrapper_returned=False,
    complete_standalone_signer_verified=False,Android_execution=False,online_acceptance_verified=False)


def selected_projection():
    return dict(source_owner_offset=160,counter_owner_offset=168,source_register=17,counter_register=18,
        scope_frame_offset=4920,scope_pointer_source_frame_offset=2032,exit_slot_pointer_frame_offset=1872,
        enter=dict(bytecode=hex(ENTER),wrapper='0x2858d0',target='0x26c858',packed_frame_offset=4320),
        exit=dict(bytecode=hex(CALL),wrapper='0x2858e0',target='0x26c9d0',packed_frame_offset=4304),
        reference_pair_preserved=True,count_before_u32=2,count_after_u32=1,adjacent12_preserved=True,
        prior_clone_source_counter_remains_one=True,NULL_counter_branch_taken=False,
        positive_count_branch_taken=True,positive_branch_target='0xfd404',
        selected_mutex_locked_state_u32=0x4001,selected_mutex_locked_owner_u32=137,
        selected_mutex_final_state_u32=0x4000,selected_mutex_final_owner_u32=0,
        selected_mutex_other32_bytes_zero=True,lock_result_u32=0,actual_exit_X0_u64=0,
        owner_source_table_and_clone_preserved=True,allocation_or_free_calls=0,
        events=['pthread_mutex_lock','pthread_mutex_unlock'])


def fresh(image):
    pages,frame,source,counter,table,entry,tls,put,read,w=previous.fresh(image)
    owner=0x67000000;sibling_source=0x61000400;sibling_counter=0x62000400
    put(owner,b'\xa5'*264);w(owner+160,source);w(owner+168,counter)
    w(frame+1872,image+0x382DC0)
    w(frame+2088,sibling_source);w(frame+2096,sibling_counter)
    put(sibling_counter,b'\xa5'*16);w(sibling_counter,1,4)
    return pages,frame,source,counter,table,entry,tls,put,read,w,owner,sibling_counter


def preservation(read,frame,source,counter,table,entry,owner,sibling):
    return {a:read(a,n) for a,n in ((owner,264),(source,24),(counter,16),(sibling,16),
        (frame+2088,16),(table,2048),(entry,48),(frame+5016,24),(0x66000100,11))}


def check_preservation(read,counter,before):
    assert int.from_bytes(read(counter,4),'little')==1 and read(counter+4,12)==before[counter][4:]
    for a,b in before.items():
        if a!=counter:assert read(a,len(b))==b


def model_projection():
    image=graph.BASES[0];pages,frame,source,counter,table,entry,tls,put,read,w,owner,sibling=fresh(image)
    before=preservation(read,frame,source,counter,table,entry,owner,sibling);events=[]
    def no_service(*args):raise AssertionError('warm count2 owner cleanup must neither allocate nor free')
    helper_scope=frame+0x1800
    references.release_scoped_string_reference(pages,reference_address=owner+160,
        entry_stack_address=helper_scope+0x40,image_base=image,thread_pointer=tls,thread_id=137,
        allocate=no_service,free=no_service,diagnostic_observer=lambda kind,*args:events.append(kind))
    check_preservation(read,counter,before)
    assert int.from_bytes(read(helper_scope+8,4),'little')==0 and events==selected_projection()['events']
    return selected_projection()


def interpreter_projection(path):
    saved=os.environ.get('TOMATO_LIBMETASEC')
    try:
        os.environ['TOMATO_LIBMETASEC']=str(path.resolve());import vm_full as vm_module
    finally:
        if saved is None:os.environ.pop('TOMATO_LIBMETASEC',None)
        else:os.environ['TOMATO_LIBMETASEC']=saved
    assert hashlib.sha256(vm_module.SO).hexdigest()==graph.inputs.SHA256
    class Boundary(Exception):pass
    saved_base=vm_module.B;rows=[]
    try:
        for image in graph.BASES:
            vm_module.B=image;pages,frame,source,counter,table,entry,tls,put,read,w,owner,sibling=fresh(image)
            class Memory:
                def u32(self,a):return int.from_bytes(read(a,4),'little')
                def u64(self,a):return int.from_bytes(read(a,8),'little')
                def rb(self,a):return read(a,1)[0]
                def w64(self,a,v):w(a,v)
                def w32(self,a,v):w(a,v,4)
            m=Memory();steps=[];events=[];writes=[]
            preserved=preservation(read,frame,source,counter,table,entry,owner,sibling)
            before_frame=read(frame,0x2000)
            for a,value in WORDS:put(image+a,value.to_bytes(4,'little'))
            vm=vm_module.VM(m,ENTRY,0,0,0,0,0,maxsteps=32)
            vm.R=[0xA5A5000000000000+i for i in range(32)]
            vm.R[0]=0;vm.R[2]=sibling;vm.R[16]=frame+4920
            vm.R[17]=m.u64(owner+160);vm.R[18]=m.u64(owner+168);vm.R[20]=image+GOT_BASE
            vm.R[22]=image+0x2858D0;vm.R[23]=image+0x28587C;vm.R[29]=frame;vm.R[30]=image+0x2858E0
            vm.cb=image+0x28587C;before=list(vm.R)
            def no_service(*args):raise AssertionError('unexpected fresh owner VM allocation/free')
            def native(vm,wrapper,packed):
                assert vm.pc==image+ENTER and wrapper==image+0x2858D0 and packed==frame+4320
                assert [m.u64(packed+i*8) for i in range(3)]==[image+0x26C858,frame+4920,source]
                scope=diagnostics.enter_diagnostic_scope(pages,object_address=frame+4920,input_word=source,
                    image_base=image,thread_pointer=tls,thread_id=137,allocate=no_service,
                    observer=lambda kind,*args:events.append(kind))
                assert scope.lock_result==0 and scope.allocation_sizes==()
                assert m.u32(entry+8)==0x4001 and m.u32(entry+12)==137
            def step(vm,dw,op,sub):
                if vm.pc==image+CALL:raise Boundary()
                assert (vm.pc-image,dw)==WORDS[len(steps)];steps.append(hex(vm.pc-image))
            vm.native_hook=native;vm.step_hook=step
            original_write=m.w32
            def count_write(a,v):
                assert a==counter and v==1;writes.append([hex(vm.pc-image),4,2,1]);original_write(a,v)
            m.w32=count_write
            try:vm.run()
            except Boundary:pass
            else:raise AssertionError('fresh owner VM failed to stop before exit CALL')
            assert steps==[hex(a) for a,_ in WORDS[:-1]] and writes==[['0xfd3bc',4,2,1]]
            assert [m.u64(frame+4304+i*8) for i in range(2)]==[image+0x26C9D0,frame+4920]
            assert vm.R[31]==image+ENTER+4 and vm.R[1]==image+0x26C9D0
            assert vm.R[4]==image+0x2858E0 and vm.R[5]==frame+4304 and vm.R[20]==frame+4920
            assert vm.R[25]==image+0x28587C
            assert all(vm.R[i]==before[i] for i in range(32) if i not in (1,4,5,20,25,31))
            result=diagnostics.leave_diagnostic_scope(pages,object_address=frame+4920,image_base=image,
                thread_pointer=tls,observer=lambda kind,*args:events.append(kind))
            assert result==0 and m.u32(entry+8)==0x4000 and m.u32(entry+12)==0 and read(entry+16,32)==bytes(32)
            check_preservation(read,counter,preserved);assert events==selected_projection()['events']
            after=read(frame,0x2000)
            assert all(a==b for i,(a,b) in enumerate(zip(before_frame,after))
                if not (4304<=i<4344 or 4920<=i<4932 or 4936<=i<4944))
            rows.append(dict(image_base=hex(image),executed_bytecodes=steps,projection=selected_projection()))
    finally:vm_module.B=saved_base
    return rows


def providers():
    return dict(inherited_cleanup=previous.providers(),maximum_handler_reads=2,maximum_main_SVCs=4,
        independent_model_owners=['vm_full.py:VM.run','vm9_reference_scopes.py:release_scoped_string_reference',
            'vm9_diagnostics.py:enter_diagnostic_scope','vm9_diagnostics.py:leave_diagnostic_scope'],
        independent_model_input='fresh owner fields160/168, count2, sibling count1, frame, warm table and recursive mutex',
        allocation_deltas={},service_count_deltas={},new_OS_JNI_or_internal_helper_providers=[],
        retired_completed_observation_windows=['cleanup_active'],original_scope_kept=True,
        stop_before=hex(STOP),outer_bytecode=hex(CALL))


class Scenario(previous.Scenario):
    def __init__(self,c):
        super().__init__(c);self.owner_cleanup_active=False;self.owner_cleanup_done=False
        self.owner_cleanup_steps=[];self.owner_cleanup_loads=[];self.owner_cleanup_stores=[]
        self.owner_cleanup_counter_writes=[];self.owner_cleanup_compares=[];self.owner_cleanup_calls=[];self.owner_cleanup_events=[]

    def native_runner(self,*args,**kwargs):
        original=kwargs['memory_write_observer']
        def write(cpu,address,size):
            if self.owner_cleanup_active:
                reg=lambda n:cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(n)))
                off=cpu.reg_read(arm.UC_ARM64_REG_PC)-self.image
                bc=int.from_bytes(cpu.mem_read(self.scope_state['PC_slot'],8),'little')-self.image
                if self.exit_counter<=address<self.exit_counter+16:
                    assert (off,bc,address,size,reg(11),reg(12),reg(10))==(0x17208C,0xFD3BC,self.exit_counter,4,1,self.exit_counter,0)
                    assert int.from_bytes(cpu.mem_read(address,4),'little')==2
                    self.owner_cleanup_counter_writes.append(dict(native_pc=hex(off),bytecode=hex(bc),size=4,before_u32=2,after_u32=1))
                if self.scope_frame+4304<=address<self.scope_frame+4344:
                    expected={0xFD39C:(4336,self.owner_cleanup_source),0xFD3A0:(4328,self.scope_frame+4920),
                        0xFD3A4:(4320,self.image+0x26C858),0xFD414:(4312,self.scope_frame+4920),0xFD418:(4304,self.image+0x26C9D0)}
                    offset,value=expected[bc]
                    assert (off,address,size,reg(15))==(0x171268,self.scope_frame+offset,8,value)
                    self.owner_cleanup_stores.append(dict(cursor_bytecode=hex(bc),frame_offset=offset,size=8))
            original(cpu,address,size)
        kwargs['memory_write_observer']=write
        return super().native_runner(*args,**kwargs)

    def cleanup_boundary(self,cpu,state):
        prefix=state['configuration_cleanup_prefix']
        old=next(r for r in json.loads(previous.EVIDENCE.read_text(encoding='utf-8'))['case_results'] if r['control']==self.control)
        for k in ('instruction_observations','trace_sha256','code_sha256'):assert prefix[k]==old['continuation_'+k]
        assert self.cleanup_done and self.cleanup_active and self.original_scope
        assert graph.digest(state['allocator_events_ref'])==old['allocation_ledger_sha256']
        u=lambda a,n=8:int.from_bytes(cpu.mem_read(a,n),'little')
        self.owner_cleanup_source=u(state['backing']+17*8)
        assert self.owner_cleanup_source==u(self.scope_owner+160)==self.scope_input
        assert u(state['backing']+18*8)==u(self.scope_owner+168)==self.exit_counter
        assert self.exit_counter!=self.source_counter and self.owner_cleanup_source!=self.source_pointer
        assert u(self.exit_counter,4)==2 and u(self.source_counter,4)==1
        assert u(self.scope_frame+1872)==self.image+0x382DC0 and u(self.image+0x382DC0)==self.image+0x26C9D0
        self.owner_cleanup_before={a:bytes(cpu.mem_read(a,n)) for a,n in (
            (self.scope_owner,264),(self.owner_cleanup_source,24),(self.exit_counter,16),(self.source_counter,16),
            (self.copy_table,2048),(self.clone_destination,24),(self.clone_new_payload,11))}
        self.owner_cleanup_entry=u(self.copy_table+((self.owner_cleanup_source>>4)&255)*8)
        self.owner_cleanup_entry_before=bytes(cpu.mem_read(self.owner_cleanup_entry,48))
        assert u(self.owner_cleanup_entry+8,4)==0x4000 and u(self.owner_cleanup_entry+12,4)==0
        self.owner_cleanup_allocations=deepcopy(state['allocator_events_ref'])
        # Only the completed previous cleanup's observer retires. Guest scope
        # execution stays enabled; no register, instruction or page is patched.
        self.cleanup_active=False;self.owner_cleanup_active=True

    def observe(self,cpu,pc,state):
        self.scope_state=state
        if not self.owner_cleanup_active:
            super().observe(cpu,pc,state)
            if not self.owner_cleanup_active:return
        off=pc-self.image
        reg=lambda n:cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(n)))
        raw=lambda a,n:bytes(cpu.mem_read(a,n))
        u=lambda a,n=8:int.from_bytes(raw(a,n),'little')
        bc=u(state['PC_slot'])-self.image
        if off in (0x27E6AC,0x27ED6C):raise AssertionError('unexpected ordinary callback/wrapper RET')
        if bc!=previous.CALL and (not self.owner_cleanup_steps or self.owner_cleanup_steps[-1]!=hex(bc)):
            assert bc==WORDS[len(self.owner_cleanup_steps)][0];self.owner_cleanup_steps.append(hex(bc))
        if off==context.LOAD:
            a,offset,destination,source=LOADS[len(self.owner_cleanup_loads)]
            base={'frame':self.scope_frame,'ELF GOT base':self.image+GOT_BASE,'ELF GOT slot':self.image+0x382DC0}[source]
            assert (bc,reg(12),reg(13),reg(14))==(a,base,offset,destination)
            expected={0xFD394:self.image+0x26C858,0xFD404:self.image+0x382DC0,
                0xFD408:self.image+0x26C9D0,0xFD40C:self.scope_frame+4920}[bc]
            assert u(base+offset)==expected
            self.owner_cleanup_loads.append(dict(bytecode=hex(bc),offset=offset,destination=destination,source=source))
        if (off,bc)==(0x16EDE8,0xFD3B0):
            assert reg(9)==self.exit_counter and reg(11)==0
            self.owner_cleanup_compares.append(dict(bytecode=hex(bc),native_pc=hex(off),kind='nonNULL counter',taken=False))
        if (off,bc)==(0x16EC64,0xFD3C0):
            assert reg(9)==1 and u(self.exit_counter,4)==1
            self.owner_cleanup_compares.append(dict(bytecode=hex(bc),native_pc=hex(off),kind='positive count',taken=True,target='0xfd404'))
        if off==0x16AA48 and bc in (ENTER,CALL):
            packed=reg(0);enter=bc==ENTER;wrapper=0x2858D0 if enter else 0x2858E0;target=0x26C858 if enter else 0x26C9D0
            assert reg(8)==self.image+wrapper and packed==self.scope_frame+(4320 if enter else 4304)
            assert u(packed)==self.image+target and u(packed+8)==self.scope_frame+4920
            if enter:assert u(packed+16)==self.owner_cleanup_source
            self.owner_cleanup_calls.append(dict(bytecode=hex(bc),wrapper=hex(wrapper),target=hex(target),packed_frame_offset=packed-self.scope_frame))
        if off==0x26C858 and bc==ENTER:
            assert (reg(0),reg(1))==(self.scope_frame+4920,self.owner_cleanup_source) and u(self.exit_counter,4)==2
            self.owner_cleanup_enter_seen=True
        if off==0x347F00 and bc==ENTER:
            assert self.owner_cleanup_enter_seen and reg(0)==self.owner_cleanup_entry+8
            self.owner_cleanup_events.append('pthread_mutex_lock')
        if off==STOP and bc==ENTER:
            scope=self.scope_frame+4920;entry=self.owner_cleanup_entry
            assert u(scope)==self.image+0x35D410 and u(scope+8,4)==0 and u(scope+16)==self.owner_cleanup_source
            assert u(entry+8,4)==0x4001 and u(entry+12,4)==137 and reg(0)==0
            self.owner_cleanup_enter_done=True
        if off==0x26C9D0 and bc==CALL:
            assert self.owner_cleanup_enter_done and reg(0)==self.scope_frame+4920 and u(self.exit_counter,4)==1
            self.owner_cleanup_exit_seen=True
        if off==0x347F10 and bc==CALL:
            assert self.owner_cleanup_exit_seen and reg(0)==self.owner_cleanup_entry+8
            self.owner_cleanup_events.append('pthread_mutex_unlock')
        if off==STOP and bc==CALL:
            assert self.owner_cleanup_events==selected_projection()['events'] and reg(0)==0 and u(self.exit_counter,4)==1
            assert raw(self.exit_counter+4,12)==self.owner_cleanup_before[self.exit_counter][4:]
            for a,b in self.owner_cleanup_before.items():
                if a!=self.exit_counter:assert raw(a,len(b))==b
            assert raw(self.owner_cleanup_entry,48)==self.owner_cleanup_entry_before
            assert u(self.owner_cleanup_entry+8,4)==0x4000 and u(self.owner_cleanup_entry+12,4)==0
            assert raw(self.owner_cleanup_entry+16,32)==bytes(32) and u(self.source_counter,4)==1
            assert raw(state['context'],128)==state['handler_bytes'] and u(self.scope_frame+1536)==u(self.scope_frame+1552)==0
            assert state['allocator_events_ref']==self.owner_cleanup_allocations and self.original_scope
            self.owner_cleanup_done=True;self.owner_cleanup_boundary(cpu,state)

    def owner_cleanup_boundary(self,cpu,state):
        cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,context.outer.oracle.STOP)

    def finish(self,result,state,proof):
        data=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(data)
        old=next(r for r in data['case_results'] if r['control']==self.control);prefix=proof['configuration_cleanup_prefix']
        assert self.owner_cleanup_done and result['allocator_events']==self.owner_cleanup_allocations
        assert graph.digest(result['allocator_events'])==old['allocation_ledger_sha256']
        assert result['actual_allocator_counts']==old['allocator_counts'] and result['explicit_service_counts']==old['service_counts']
        for k in ('JNI_calls','libc_SVC_boundaries','main_image_SVC_boundaries'):assert proof[k]==prefix[k]==old[k]
        return dict(control=self.control,retained_configuration_cleanup_prefix_verified=True,
            retained_prefix_instruction_observations=prefix['instruction_observations'],retained_prefix_trace_sha256=prefix['trace_sha256'],
            retained_prefix_code_sha256=prefix['code_sha256'],retired_completed_observers=['cleanup_active'],original_scope_kept=True,
            R17_R18_match_owner_fields160_168=True,source_and_counter_distinct_from_clone_source_reference=True,
            executed_bytecodes=self.owner_cleanup_steps,native_loads=self.owner_cleanup_loads,native_packed_stores=self.owner_cleanup_stores,
            native_counter_writes=self.owner_cleanup_counter_writes,native_compares=self.owner_cleanup_compares,native_calls=self.owner_cleanup_calls,
            selected_cleanup_projection=selected_projection(),original_enter_and_exit_bodies_seen=True,
            allocation_ledger_sha256=old['allocation_ledger_sha256'],allocator_counts=old['allocator_counts'],service_counts=old['service_counts'],
            JNI_calls=proof['JNI_calls'],libc_SVC_boundaries=proof['libc_SVC_boundaries'],main_image_SVC_boundaries=proof['main_image_SVC_boundaries'],
            continuation_instruction_observations=proof['instruction_observations'],continuation_trace_sha256=proof['trace_sha256'],
            continuation_code_sha256=proof['code_sha256'],observation_stop_before=hex(STOP),outer_bytecode=hex(CALL),callback_or_ordinary_RET_seen=False)


def replay(path,libc,*,on_case=None,case_controls=None):
    return context.replay(path,libc,on_case=on_case,case_controls=case_controls,_extension_factory=Scenario,
        _request_profile=name.previous.previous.PROFILE['name'],_handler_read_profile=context.NULL_PAYLOAD_READ_PROFILE['name'])


def verify_images(data,path,libc):
    previous.verify_images({},path,libc);_,_,read=graph.inputs.load_elf(path)
    for a,w in WORDS:assert int.from_bytes(read(a,4),'little')==w,hex(a)
    assert interpreter_projection(path)==expected_VM_projection() and model_projection()==selected_projection()
    return dict(instruction_bindings=len(EXPECTED),bytecode_words=len(WORDS),GOT_relative_relocations=2,
        independent_Python_VM_cases=2,independent_scoped_owner_reference_release_verified=True)


def expected_VM_projection():
    return [dict(image_base=hex(b),executed_bytecodes=[hex(a) for a,_ in WORDS[:-1]],projection=selected_projection()) for b in graph.BASES]


def validate(data):
    assert data['schema']=='vm9-native-171-configuration-owner-cleanup-20261119-v1' and data['claims']==CLAIMS and data['providers']==providers()
    assert data['instructions']==[dict(offset=hex(a),mnemonic=m,operands=s) for a,m,s in EXPECTED]
    assert data['bytecode_words']==[dict(offset=hex(a),word=hex(w)) for a,w in WORDS]
    assert data['independent_Python_projection']==model_projection() and data['independent_Python_VM_projection']==expected_VM_projection()
    old_data=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(old_data)
    assert data['provenance']==old_data['provenance'] and len(data['case_results'])==len(context.controls())
    for row,old in zip(data['case_results'],old_data['case_results']):
        assert row['control']==old['control'] and row['retained_configuration_cleanup_prefix_verified'] is True
        for k in ('instruction_observations','trace_sha256','code_sha256'):assert row['retained_prefix_'+k]==old['continuation_'+k]
        assert row['retired_completed_observers']==['cleanup_active'] and row['original_scope_kept'] is True
        assert row['R17_R18_match_owner_fields160_168'] is True and row['source_and_counter_distinct_from_clone_source_reference'] is True
        assert row['executed_bytecodes']==[hex(a) for a,_ in WORDS]
        assert row['native_loads']==[dict(bytecode=hex(a),offset=o,destination=d,source=s) for a,o,d,s in LOADS]
        assert row['native_packed_stores']==[dict(cursor_bytecode=hex(a),frame_offset=o,size=8) for a,o in STORES]
        assert row['native_counter_writes']==[dict(native_pc='0x17208c',bytecode='0xfd3bc',size=4,before_u32=2,after_u32=1)]
        assert row['native_compares']==[dict(bytecode='0xfd3b0',native_pc='0x16ede8',kind='nonNULL counter',taken=False),
            dict(bytecode='0xfd3c0',native_pc='0x16ec64',kind='positive count',taken=True,target='0xfd404')]
        assert row['native_calls']==[dict(bytecode=hex(b),wrapper=hex(w),target=hex(t),packed_frame_offset=f)
            for b,w,t,f in ((ENTER,0x2858D0,0x26C858,4320),(CALL,0x2858E0,0x26C9D0,4304))]
        assert row['selected_cleanup_projection']==selected_projection() and row['original_enter_and_exit_bodies_seen'] is True
        for k in ('allocation_ledger_sha256','allocator_counts','service_counts','JNI_calls','libc_SVC_boundaries','main_image_SVC_boundaries'):assert row[k]==old[k]
        assert row['continuation_instruction_observations']>old['continuation_instruction_observations']
        for k in ('continuation_trace_sha256','continuation_code_sha256'):assert graph.inputs.is_digest(row[k])
        assert row['observation_stop_before']==hex(STOP) and row['outer_bytecode']==hex(CALL) and row['callback_or_ordinary_RET_seen'] is False


def negatives(data):
    count=0
    def reject(path,value):
        nonlocal count
        bad=deepcopy(data);target=bad
        for k in path[:-1]:target=target[k]
        target[path[-1]]=value
        try:validate(bad)
        except AssertionError:count+=1
        else:raise AssertionError('damaged configuration owner cleanup evidence accepted: '+str(path))
    for k,v in CLAIMS.items():reject(('claims',k),not v)
    reject(('providers','maximum_handler_reads'),3);reject(('providers','maximum_main_SVCs'),5)
    reject(('providers','original_scope_kept'),False);reject(('instructions',0,'mnemonic'),'nop')
    reject(('bytecode_words',0,'word'),'0x0');reject(('independent_Python_projection','count_after_u32'),0)
    reject(('independent_Python_VM_projection',0,'executed_bytecodes'),[])
    for i in range(len(data['case_results'])):
        changes=[(('retained_configuration_cleanup_prefix_verified',),False),(('retained_prefix_trace_sha256',),'0'*64),
            (('retired_completed_observers',),[]),(('original_scope_kept',),False),
            (('R17_R18_match_owner_fields160_168',),False),(('source_and_counter_distinct_from_clone_source_reference',),False),
            (('executed_bytecodes',),[]),(('native_loads',),[]),(('native_packed_stores',),[]),
            (('native_counter_writes',0,'size'),8),(('native_counter_writes',0,'after_u32'),0),
            (('native_compares',),[]),(('native_calls',),[]),(('original_enter_and_exit_bodies_seen',),False),
            (('allocation_ledger_sha256',),'0'*64),(('allocator_counts','malloc'),0),(('service_counts','syscall_226'),0),
            (('JNI_calls',),[]),(('libc_SVC_boundaries',),[]),(('main_image_SVC_boundaries',),[]),
            (('continuation_instruction_observations',),0),(('continuation_trace_sha256',),'bad'),
            (('continuation_code_sha256',),'bad'),(('observation_stop_before',),'0x0'),
            (('outer_bytecode',),hex(ENTER)),(('callback_or_ordinary_RET_seen',),True)]
        for k,v in selected_projection().items():changes.append((('selected_cleanup_projection',k),not v if isinstance(v,bool) else 'bad'))
        for path,value in changes:reject(('case_results',i)+path,value)
    return count


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--elf',type=Path);ap.add_argument('--libc',type=Path);ap.add_argument('--replay',action='store_true')
    args=ap.parse_args()
    if args.replay and (not args.elf or not args.libc):ap.error('--replay requires --elf and --libc')
    data=json.loads(EVIDENCE.read_text(encoding='utf-8'));validate(data)
    result=dict(retained_configuration_owner_cleanup_cases=len(data['case_results']),damaged_evidence_rejected=negatives(data),
        KMSV_value_generated=False,ordinary_Cronet_six_headers_verified=False,complete_standalone_signer_verified=False)
    if args.elf:result['image_bindings']=verify_images(data,args.elf,args.libc)
    elif args.libc:graph.inputs.libc_image(args.libc)
    if args.replay:
        assert replay(args.elf,args.libc)==data['case_results'],'frozen configuration owner cleanup replay differs'
        result['original_code_cases_replayed']=len(data['case_results'])
    print(json.dumps(result))


if __name__=='__main__':main()
