"""Original warm registry branch hashes its preserved configuration clone.

The current request's native rounds are observed without seeding a model.
Separate fresh declared payload/table controls compare Python and original
numeric results. Different inputs are never claimed to have equal hashes.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
from unicorn import arm64_const as arm
import verify_vm9_native_171_configuration_owner_cleanup_20261119 as previous
import verify_vm9_request_hash64_fresh_20261012 as fresh_hash
import vm9_objects as objects

context,graph,name=previous.context,previous.graph,previous.name
EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_configuration_hash64_20261119.json')
ENTRY,CALL,STOP=0xFD428,0xFD5B8,0x16AA4C
GOT_BASE=previous.GOT_BASE
TARGET,WRAPPER,TABLE=0x258BE0,0x285E38,0x96548
TABLE_SHA256='e0d21fc6200880c2170d9145ecdf89f5f5dc60ffd0921f72e4dcffe26b9e2a8b'
DECLARED_PAYLOAD=b'clone\0test'
# Deliberately synthetic; no native table bytes or named CRC variant seed it.
DECLARED_TABLE=b''.join((((i*0x9E3779B97F4A7C15)^(i<<41))&((1<<64)-1)).to_bytes(8,'little') for i in range(256))
WORDS=[(ENTRY,0x8340C91A),(0xFD42C,0x8348C91A),(0xFD430,0x9B750C18),
    (0xFD434,0x88C0003D),(0xFD438,0x00000351),(0xFD43C,0x00411035),
    (0xFD440,0xAA3B0056),(0xFD444,0x40401014),(0xFD588,0x8B590C18),
    (0xFD58C,0x08400018),(0xFD590,0x08400018),(0xFD594,0x18690418),
    (0xFD598,0xB3601018),(0xFD59C,0x89840418),(0xFD5A0,0x935E0C18),
    (0xFD5A4,0x9348C09A),(0xFD5A8,0x8B40C09A),(0xFD5AC,0x8B4AC00F),
    (0xFD5B0,0xA34C0418),(0xFD5B4,0x05C19B11),(CALL,0x067E0C91)]
EXPECTED=[(context.LOAD,'ldr','x9, [x12, x13]'),(0x171268,'str','x15, [x17, x16]'),
    (0x17208C,'str','w11, [x12, x10]'),(0x170068,'ldrsb','x11, [x11, x12]'),
    (0x16F050,'cmp','x9, x10'),(0x16F058,'csel','x9, xzr, x12, eq'),
    (0x258BE8,'ldr','x8, [x0, #0x10]'),(0x258BEC,'ldr','w1, [x0, #0xc]'),
    (0x258BF4,'bl','#0x24b2d4'),(0x258BFC,'ret',''),
    (0x24B2D4,'cmp','w1, #0'),(0x24B2E0,'mov','x0, xzr'),
    (0x24B2E4,'csel','w9, w1, wzr, gt'),(0x24B2EC,'cbz','x9, #0x24b30c'),
    (0x24B2F0,'ldrb','w11, [x8], #1'),(0x24B2F4,'and','x12, x0, #0xff'),
    (0x24B2F8,'sub','x9, x9, #1'),(0x24B2FC,'eor','x11, x12, x11'),
    (0x24B300,'ldr','x11, [x10, x11, lsl #3]'),(0x24B304,'eor','x0, x11, x0, lsr #8'),
    (0x24B308,'cbnz','x9, #0x24b2f0'),(0x24B30C,'ret',''),
    (WRAPPER,'stp','x30, x19, [sp, #-0x10]!'),(0x285E3C,'mov','x19, x0'),
    (0x285E40,'ldp','x8, x0, [x0]'),(0x285E44,'blr','x8'),
    (0x285E48,'str','x0, [x19, #0x10]'),(0x285E4C,'ldp','x30, x19, [sp], #0x10'),
    (0x285E50,'ret',''),(STOP,'ldp','x5, x1, [x29, #-0x90]')]
LOADS=[(0xFD430,1712,19,'frame'),(0xFD588,1840,1,'frame'),
    (0xFD58C,0,1,'registry global slot'),(0xFD590,0,1,'registry wrapper'),
    (0xFD594,304,19,'registry root'),(0xFD598,2048,22,'frame'),
    (0xFD59C,144,1,'ELF GOT'),(0xFD5A0,2000,2,'frame'),(0xFD5B0,400,4,'frame')]
STORES=[(0xFD42C,4896),(0xFD430,4904),(0xFD5A8,2824),(0xFD5AC,2816)]
CLAIMS=dict(retained_owner_cleanup_instruction_code_allocation_prefix_verified=True,
    completed_owner_cleanup_observer_retired_after_full_prefix_check=True,original_scope_execution_kept=True,
    original_warm_guard_bit0_branch_and_registry_reads_verified=True,
    fresh_Python_VM_selected_path_arguments_and_writes_match=True,
    original_clone_hash64_ten_round_contract_verified=True,original_uint64_return_and_packed_store_match=True,
    two_fresh_declared_native_hash_controls_match_Python=True,clone_table_and_reference_counts_preserved=True,
    allocation_service_JNI_and_SVC_ledgers_unchanged=True,native_memory_used_as_model_input=False,
    native_and_declared_model_inputs_equal=False,current_request_numeric_hash_compared_to_Python=False,
    new_OS_JNI_or_internal_helper_providers=False,cold_registry_initialization_branch_verified=False,
    full_VM_or_physical_stack_equivalence_verified=False,hash_return_consumed=False,
    complete_configuration_value_provenance_verified=False,real_business_cache_restored=False,
    real_JVM_identity_verified=False,KMSV_value_generated=False,client_key_value_generated=False,
    ordinary_Cronet_six_headers_verified=False,whole_request_equivalence_verified=False,
    callback_or_ordinary_wrapper_returned=False,complete_standalone_signer_verified=False,
    Android_execution=False,online_acceptance_verified=False)


def selected_projection():
    return dict(cleared_reference_frame_offsets=[4896,4904],guard_frame_offset=1712,guard_offset='0x3d1558',
        guard_u8=1,selected_bit0=1,warm_branch='0xfd444',warm_branch_target='0xfd588',cold_path_skipped=True,
        saved_word_frame_offset=1568,saved_word_size=4,saved_word_u32=0,
        registry_global_slot_offset='0x3d1550',registry_member_offset=304,
        GOT_frame_offset=2048,GOT_slot_offset='0x382d10',clone_pointer_frame_offset=2000,clone_frame_offset=5016,
        wrapper_frame_offset=400,wrapper_offset=hex(WRAPPER),target_offset=hex(TARGET),packed_frame_offset=2816,
        result_frame_offset=2832,result_size=8,length_u32=10,rounds=10,table_offset=hex(TABLE),
        uint64_X0_equals_packed_result=True,clone_header_payload_and_table_preserved=True,
        both_reference_counts_one=True,allocation_or_service_calls=0)


def fresh(image):
    pages,frame,source,counter,table,entry,tls,put,read,w,owner,sibling=previous.fresh(image)
    w(counter,1,4);clone=frame+5016;payload=0x66000100
    w(clone,image+0x34F5F8);w(clone+8,11,4);w(clone+12,10,4);w(clone+16,payload)
    put(payload,DECLARED_PAYLOAD+b'\0');put(image+TABLE,DECLARED_TABLE)
    wrapper=0x68000000;root=0x69000000;member=0x69001000
    put(image+0x3D1558,bytes([1])+bytes(7));w(image+0x3D1550,wrapper)
    w(wrapper,root);put(root,b'\xa5'*312);w(root+304,member)
    for offset,value in ((1712,image+0x3D1558),(1840,image+0x3D1550),(2048,image+GOT_BASE),
        (2000,clone),(400,image+WRAPPER)):w(frame+offset,value)
    w(image+0x382D10,image+TARGET)
    return pages,frame,clone,payload,counter,sibling,wrapper,root,member,put,read,w


def model_projection():
    image=graph.BASES[0];pages,frame,clone,payload,counter,sibling,wrapper,root,member,put,read,w=fresh(image)
    before={k:bytes(v) for k,v in pages.items()}
    value=objects.hash_string_object64(pages,object_address=clone,image_base=image)
    assert before=={k:bytes(v) for k,v in pages.items()}
    assert 0<=value<1<<64
    return dict(declared_payload_hex=DECLARED_PAYLOAD.hex(),declared_table_sha256=hashlib.sha256(DECLARED_TABLE).hexdigest(),
        hash_hex=hex(value),model_pages_preserved=True,current_native_input_bytes_used=False)


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
            vm_module.B=image;pages,frame,clone,payload,counter,sibling,wrapper,root,member,put,read,w=fresh(image)
            class Memory:
                def u32(self,a):return int.from_bytes(read(a,4),'little')
                def u64(self,a):return int.from_bytes(read(a,8),'little')
                def rb(self,a):return read(a,1)[0]
                def w64(self,a,v):w(a,v)
                def w32(self,a,v):w(a,v,4)
            m=Memory();before={k:bytes(v) for k,v in pages.items()};steps=[];calls=[]
            for a,value in WORDS:put(image+a,value.to_bytes(4,'little'))
            put(image+CALL+4,bytes(4));before_frame=read(frame,0x2000)
            vm=vm_module.VM(m,ENTRY,0,0,0,0,0,maxsteps=24)
            vm.R=[0xA5A5000000000000+i for i in range(32)]
            vm.R[0]=vm.R[21]=0;vm.R[23]=image+0x28587C;vm.R[29]=frame
            vm.cb=image+0x28587C;initial=list(vm.R)
            def native(vm,function,packed):
                assert vm.pc==image+CALL and function==image+WRAPPER and packed==frame+2816
                assert [m.u64(packed+i*8) for i in range(2)]==[image+TARGET,clone]
                value=objects.hash_string_object64(pages,object_address=clone,image_base=image)
                assert hex(value)==model_projection()['hash_hex'];w(packed+16,value);calls.append(hex(vm.pc-image))
            def step(vm,dw,op,sub):
                if vm.pc==image+CALL+4:raise Boundary()
                assert (vm.pc-image,dw)==WORDS[len(steps)];steps.append(hex(vm.pc-image))
            vm.native_hook=native;vm.step_hook=step
            try:vm.run()
            except Boundary:pass
            else:raise AssertionError('fresh hash VM did not stop after CALL')
            assert calls==[hex(CALL)] and steps==[hex(a) for a,_ in WORDS]
            assert [vm.R[i] for i in (1,2,4,5,19,22,25,31)]==[
                image+TARGET,clone,image+WRAPPER,frame+2816,member,image+GOT_BASE,image+0x28587C,image+CALL+4]
            assert all(vm.R[i]==initial[i] for i in range(32) if i not in (1,2,4,5,19,22,25,31))
            assert m.u64(frame+4896)==m.u64(frame+4904)==0 and m.u32(frame+1568)==0
            assert hex(m.u64(frame+2832))==model_projection()['hash_hex']
            after=read(frame,0x2000)
            assert all(a==b for i,(a,b) in enumerate(zip(before_frame,after))
                if not (1568<=i<1572 or 2816<=i<2840 or 4896<=i<4912))
            for page,value in before.items():
                if not frame>>12<=page<(frame+0x2000)>>12:assert bytes(pages[page])==value
            assert m.u32(counter)==m.u32(sibling)==1
            rows.append(dict(image_base=hex(image),executed_bytecodes=steps,projection=selected_projection(),
                declared_model_hash_hex=model_projection()['hash_hex']))
    finally:vm_module.B=saved_base
    return rows


def expected_VM_projection():
    return [dict(image_base=hex(b),executed_bytecodes=[hex(a) for a,_ in WORDS],projection=selected_projection(),
        declared_model_hash_hex=model_projection()['hash_hex']) for b in graph.BASES]


def expected_native_hash_projection():
    return [dict(image_base=hex(b),declared_input_and_table=True,hash_hex=model_projection()['hash_hex'],
        uint64_return_packed_result_and_guest_bytes_match=True,no_allocator_or_service_effects=True) for b in graph.BASES]


def independent_native_hash_controls(path):
    rows=[]
    for image in graph.BASES:
        pages,obj=fresh_hash.fresh(path,image,'embedded_NUL_tail')
        fresh_hash._write_span(pages,obj+12,(10).to_bytes(4,'little'))
        fresh_hash._write_span(pages,fresh_hash.DATA,DECLARED_PAYLOAD+b'\0')
        fresh_hash._write_span(pages,image+TABLE,DECLARED_TABLE)
        observed={(image+0x96000,4096):None}
        value,memory,allocations,services=fresh_hash.oracle.native(path,image,WRAPPER,[fresh_hash.PACKED],pages,
            observed_memory=observed,instruction_limit=20000)
        expected=fresh_hash.apply(pages,obj,image)
        assert value==expected==int(model_projection()['hash_hex'],16)
        assert fresh_hash._read_span(pages,fresh_hash.G,0xA000)==memory
        assert all(fresh_hash._read_span(pages,a,n)==data for (a,n),data in observed.items())
        assert not allocations and not services
        rows.append(dict(image_base=hex(image),declared_input_and_table=True,hash_hex=hex(value),
            uint64_return_packed_result_and_guest_bytes_match=True,no_allocator_or_service_effects=True))
    assert rows==expected_native_hash_projection();return rows


def providers():
    return dict(inherited_owner_cleanup=previous.providers(),maximum_handler_reads=2,maximum_main_SVCs=4,
        independent_model_owners=['vm_full.py:VM.run','vm9_objects.py:hash_string_object64'],
        independent_model_input='fresh declared registry graph/guard1/clone bytes and synthetic uint64 table; no native snapshot',
        current_native_table='matching immutable ELF table at +0x96548; observed native rounds only',
        current_request_numeric_hash_compared_to_Python=False,allocation_deltas={},service_count_deltas={},
        new_OS_JNI_or_internal_helper_providers=[],retired_completed_observation_windows=['owner_cleanup_active'],
        original_scope_kept=True,stop_before=hex(STOP),outer_bytecode=hex(CALL))


def round_projection():
    return [dict(iteration=i,remaining=9-i,payload_pointer_advanced=True,
        low_byte_table_index_verified=True,uint64_recurrence_verified=True) for i in range(10)]


class Scenario(previous.Scenario):
    def __init__(self,c):
        super().__init__(c);self.hash_active=False;self.hash_done=False
        self.hash_steps=[];self.hash_loads=[];self.hash_stores=[];self.hash_saved_writes=[]
        self.hash_result_writes=[];self.hash_rounds=[];self.hash_accumulator=0

    def native_runner(self,*args,**kwargs):
        original=kwargs['memory_write_observer']
        def write(cpu,address,size):
            if self.hash_active:
                reg=lambda n:cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(n)))
                off=cpu.reg_read(arm.UC_ARM64_REG_PC)-self.image
                bc=int.from_bytes(cpu.mem_read(self.scope_state['PC_slot'],8),'little')-self.image
                if address in (self.scope_frame+4896,self.scope_frame+4904,self.scope_frame+2824,self.scope_frame+2816):
                    expected={0xFD42C:(4896,0),0xFD430:(4904,0),
                        0xFD5A8:(2824,self.clone_destination),0xFD5AC:(2816,self.image+TARGET)}
                    offset,value=expected[bc]
                    assert (off,address,size,reg(15))==(0x171268,self.scope_frame+offset,8,value)
                    self.hash_stores.append(dict(cursor_bytecode=hex(bc),frame_offset=offset,size=8))
                if self.scope_frame+1568<=address<self.scope_frame+1576:
                    assert (off,bc,address,size,reg(11))==(0x17208C,0xFD440,self.scope_frame+1568,4,0)
                    assert reg(12)+reg(10)==address
                    self.hash_saved_writes.append(dict(native_pc=hex(off),bytecode=hex(bc),frame_offset=1568,size=4,value_u32=0))
                if address==self.scope_frame+2832:
                    assert (off,bc,size,reg(0))==(0x285E48,CALL,8,self.hash_accumulator)
                    self.hash_result_writes.append(dict(native_pc=hex(off),bytecode=hex(bc),frame_offset=2832,size=8,X0_matches=True))
            original(cpu,address,size)
        kwargs['memory_write_observer']=write
        return super().native_runner(*args,**kwargs)

    def owner_cleanup_boundary(self,cpu,state):
        prefix=state['configuration_owner_cleanup_prefix']
        old=next(r for r in json.loads(previous.EVIDENCE.read_text(encoding='utf-8'))['case_results'] if r['control']==self.control)
        for k in ('instruction_observations','trace_sha256','code_sha256'):assert prefix[k]==old['continuation_'+k]
        assert self.owner_cleanup_done and self.owner_cleanup_active and self.original_scope
        assert graph.digest(state['allocator_events_ref'])==old['allocation_ledger_sha256']
        raw=lambda a,n:bytes(cpu.mem_read(a,n))
        u=lambda a,n=8:int.from_bytes(raw(a,n),'little')
        self.hash_guard=u(self.scope_frame+1712);assert self.hash_guard==self.image+0x3D1558 and u(self.hash_guard,1)==1
        self.hash_slot=u(self.scope_frame+1840);assert self.hash_slot==self.image+0x3D1550
        self.hash_registry_wrapper=u(self.hash_slot);self.hash_registry_root=u(self.hash_registry_wrapper)
        self.hash_registry_member=u(self.hash_registry_root+304)
        assert u(self.clone_destination+12,4)==10 and u(self.clone_destination+16)==self.clone_new_payload
        self.hash_payload_before=raw(self.clone_new_payload,11)
        self.hash_preserved={a:raw(a,n) for a,n in ((self.scope_owner,264),(self.exit_counter,16),
            (self.source_counter,16),(self.clone_destination,24),(self.clone_new_payload,11),
            (self.copy_table,2048),(self.owner_cleanup_entry,48),(self.hash_guard,8),
            (self.hash_slot,8),(self.hash_registry_wrapper,8),(self.hash_registry_root,312),(self.image+TABLE,2048))}
        assert hashlib.sha256(self.hash_preserved[self.image+TABLE]).hexdigest()==TABLE_SHA256
        assert u(self.exit_counter,4)==u(self.source_counter,4)==1
        self.hash_saved_adjacent=raw(self.scope_frame+1572,4)
        self.hash_initial_R=[u(state['backing']+i*8) for i in range(32)]
        assert self.hash_initial_R[0]==self.hash_initial_R[21]==0
        self.hash_allocations=deepcopy(state['allocator_events_ref'])
        # The accepted owner cleanup is complete. Retire its observer only;
        # all original guest code and diagnostic scope execution remain live.
        self.owner_cleanup_active=False;self.hash_active=True

    def observe(self,cpu,pc,state):
        self.scope_state=state
        if not self.hash_active:
            super().observe(cpu,pc,state)
            if not self.hash_active:return
        off=pc-self.image
        reg=lambda n:cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(n)))
        raw=lambda a,n:bytes(cpu.mem_read(a,n))
        u=lambda a,n=8:int.from_bytes(raw(a,n),'little')
        bc=u(state['PC_slot'])-self.image
        if off in (0x27E6AC,0x27ED6C):raise AssertionError('unexpected ordinary callback/wrapper RET')
        if bc!=previous.CALL and (not self.hash_steps or self.hash_steps[-1]!=hex(bc)):
            assert bc==WORDS[len(self.hash_steps)][0];self.hash_steps.append(hex(bc))
        if off==context.LOAD:
            a,offset,destination,source=LOADS[len(self.hash_loads)]
            base={'frame':self.scope_frame,'registry global slot':self.hash_slot,
                'registry wrapper':self.hash_registry_wrapper,'registry root':self.hash_registry_root,'ELF GOT':self.image+GOT_BASE}[source]
            expected={0xFD430:self.hash_guard,0xFD588:self.hash_slot,0xFD58C:self.hash_registry_wrapper,
                0xFD590:self.hash_registry_root,0xFD594:self.hash_registry_member,0xFD598:self.image+GOT_BASE,
                0xFD59C:self.image+TARGET,0xFD5A0:self.clone_destination,0xFD5B0:self.image+WRAPPER}[bc]
            assert (bc,reg(12),reg(13),reg(14),u(base+offset))==(a,base,offset,destination,expected)
            self.hash_loads.append(dict(bytecode=hex(bc),offset=offset,destination=destination,source=source))
        if off==0x170068 and bc==0xFD434:
            assert reg(11)+reg(12)==self.hash_guard and u(self.hash_guard,1)==1;self.hash_flag_read=True
        if off==0x16F050 and bc==0xFD444:
            assert self.hash_flag_read and reg(9)==1 and reg(10)==0;self.hash_warm_branch=True
        if off==0x16AA48:
            assert self.hash_warm_branch and bc==CALL and reg(8)==self.image+WRAPPER and reg(0)==self.scope_frame+2816
            assert [u(reg(0)+i*8) for i in range(2)]==[self.image+TARGET,self.clone_destination]
            assert u(self.scope_frame+4896)==u(self.scope_frame+4904)==u(self.scope_frame+1568,4)==0
            assert raw(self.scope_frame+1572,4)==self.hash_saved_adjacent
            selected=(1,2,4,5,19,22,25,31)
            assert [u(state['backing']+i*8) for i in selected]==[self.image+TARGET,self.clone_destination,
                self.image+WRAPPER,self.scope_frame+2816,self.hash_registry_member,self.image+GOT_BASE,
                self.image+0x28587C,self.image+CALL+4]
            assert all(u(state['backing']+i*8)==self.hash_initial_R[i] for i in range(32) if i not in selected)
            self.hash_call_seen=True
        if off==TARGET:
            assert self.hash_call_seen and reg(0)==self.clone_destination;self.hash_object_entered=True
        if off==0x24B2D4:
            assert self.hash_object_entered and reg(0)==self.clone_new_payload and reg(1)==10;self.hash_raw_entered=True
        if off==0x24B2F0:
            i=len(self.hash_rounds)
            assert self.hash_raw_entered and i<10 and (reg(0),reg(8),reg(9))==(self.hash_accumulator,self.clone_new_payload+i,10-i)
            self.hash_observed_byte=u(reg(8),1)
            assert self.hash_observed_byte==self.hash_payload_before[i]
        if off==0x24B300:
            assert reg(10)==self.image+TABLE and reg(11)==((self.hash_accumulator^self.hash_observed_byte)&255)
            self.hash_observed_entry=u(reg(10)+reg(11)*8)
        if off==0x24B304:
            assert reg(11)==self.hash_observed_entry and reg(0)==self.hash_accumulator
            self.hash_expected_next=self.hash_observed_entry^(self.hash_accumulator>>8)
        if off==0x24B308:
            i=len(self.hash_rounds)
            assert reg(0)==self.hash_expected_next and reg(8)==self.clone_new_payload+i+1 and reg(9)==9-i
            self.hash_accumulator=reg(0);self.hash_rounds.append(round_projection()[i])
        if off==0x24B30C:
            assert len(self.hash_rounds)==10 and reg(0)==self.hash_accumulator;self.hash_raw_returned=True
        if off==0x285E48:
            assert self.hash_raw_returned and reg(19)==self.scope_frame+2816 and reg(0)==self.hash_accumulator
        if off==0x285E4C:
            assert self.hash_result_writes and u(self.scope_frame+2832)==self.hash_accumulator;self.hash_packed_verified=True
        if off==STOP and bc==CALL:
            assert self.hash_packed_verified and reg(0)==u(self.scope_frame+2832)==self.hash_accumulator
            assert self.hash_rounds==round_projection()
            for a,b in self.hash_preserved.items():assert raw(a,len(b))==b
            assert raw(self.scope_frame+1572,4)==self.hash_saved_adjacent
            assert raw(state['context'],128)==state['handler_bytes'] and u(self.scope_frame+1536)==u(self.scope_frame+1552)==0
            assert state['allocator_events_ref']==self.hash_allocations and self.original_scope
            self.hash_done=True;self.hash_boundary(cpu,state)

    def hash_boundary(self,cpu,state):
        cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,context.outer.oracle.STOP)

    def finish(self,result,state,proof):
        data=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(data)
        old=next(r for r in data['case_results'] if r['control']==self.control);prefix=proof['configuration_owner_cleanup_prefix']
        assert self.hash_done and result['allocator_events']==self.hash_allocations
        assert graph.digest(result['allocator_events'])==old['allocation_ledger_sha256']
        assert result['actual_allocator_counts']==old['allocator_counts'] and result['explicit_service_counts']==old['service_counts']
        for k in ('JNI_calls','libc_SVC_boundaries','main_image_SVC_boundaries'):assert proof[k]==prefix[k]==old[k]
        return dict(control=self.control,retained_owner_cleanup_prefix_verified=True,
            retained_prefix_instruction_observations=prefix['instruction_observations'],retained_prefix_trace_sha256=prefix['trace_sha256'],
            retained_prefix_code_sha256=prefix['code_sha256'],retired_completed_observers=['owner_cleanup_active'],original_scope_kept=True,
            executed_bytecodes=self.hash_steps,native_loads=self.hash_loads,native_packed_stores=self.hash_stores,
            native_saved_word_writes=self.hash_saved_writes,native_hash_result_writes=self.hash_result_writes,
            native_round_contract=self.hash_rounds,selected_hash_projection=selected_projection(),
            original_object_and_raw_hash_bodies_seen=True,original_table_sha256=TABLE_SHA256,
            current_request_numeric_hash_compared_to_Python=False,
            allocation_ledger_sha256=old['allocation_ledger_sha256'],allocator_counts=old['allocator_counts'],service_counts=old['service_counts'],
            JNI_calls=proof['JNI_calls'],libc_SVC_boundaries=proof['libc_SVC_boundaries'],main_image_SVC_boundaries=proof['main_image_SVC_boundaries'],
            continuation_instruction_observations=proof['instruction_observations'],continuation_trace_sha256=proof['trace_sha256'],
            continuation_code_sha256=proof['code_sha256'],observation_stop_before=hex(STOP),outer_bytecode=hex(CALL),callback_or_ordinary_RET_seen=False)


def replay(path,libc,*,on_case=None,case_controls=None):
    return context.replay(path,libc,on_case=on_case,case_controls=case_controls,_extension_factory=Scenario,
        _request_profile=name.previous.previous.PROFILE['name'],_handler_read_profile=context.NULL_PAYLOAD_READ_PROFILE['name'])


def verify_images(data,path,libc):
    from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
    previous.verify_images({},path,libc);elf,_,read=graph.inputs.load_elf(path);decoder=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
    for a,m,s in EXPECTED:
        ins,=decoder.disasm(read(a,4),a);assert (ins.mnemonic,ins.op_str)==(m,s),hex(a)
    for a,w in WORDS:assert int.from_bytes(read(a,4),'little')==w,hex(a)
    assert hashlib.sha256(read(TABLE,2048)).hexdigest()==TABLE_SHA256
    rel=[r for s in elf.iter_sections() if s['sh_type']=='SHT_RELA' for r in s.iter_relocations() if r['r_offset']==0x382D10]
    assert len(rel)==1 and rel[0]['r_info_type']==1027 and rel[0]['r_addend']==TARGET
    assert interpreter_projection(path)==expected_VM_projection()
    return dict(instruction_bindings=len(EXPECTED),bytecode_words=len(WORDS),GOT_relative_relocation_verified=True,
        immutable_ELF_hash_table_verified=True,independent_Python_VM_cases=2)


def validate(data):
    assert data['schema']=='vm9-native-171-configuration-hash64-20261119-v1' and data['claims']==CLAIMS and data['providers']==providers()
    assert data['instructions']==[dict(offset=hex(a),mnemonic=m,operands=s) for a,m,s in EXPECTED]
    assert data['bytecode_words']==[dict(offset=hex(a),word=hex(w)) for a,w in WORDS]
    assert data['original_table_sha256']==TABLE_SHA256 and data['independent_Python_projection']==model_projection()
    assert data['independent_Python_VM_projection']==expected_VM_projection()
    assert data['independent_native_hash_projection']==expected_native_hash_projection()
    old_data=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(old_data)
    assert data['provenance']==old_data['provenance'] and len(data['case_results'])==len(context.controls())
    for row,old in zip(data['case_results'],old_data['case_results']):
        assert row['control']==old['control'] and row['retained_owner_cleanup_prefix_verified'] is True
        for k in ('instruction_observations','trace_sha256','code_sha256'):assert row['retained_prefix_'+k]==old['continuation_'+k]
        assert row['retired_completed_observers']==['owner_cleanup_active'] and row['original_scope_kept'] is True
        assert row['executed_bytecodes']==[hex(a) for a,_ in WORDS]
        assert row['native_loads']==[dict(bytecode=hex(a),offset=o,destination=d,source=s) for a,o,d,s in LOADS]
        assert row['native_packed_stores']==[dict(cursor_bytecode=hex(a),frame_offset=o,size=8) for a,o in STORES]
        assert row['native_saved_word_writes']==[dict(native_pc='0x17208c',bytecode='0xfd440',frame_offset=1568,size=4,value_u32=0)]
        assert row['native_hash_result_writes']==[dict(native_pc='0x285e48',bytecode=hex(CALL),frame_offset=2832,size=8,X0_matches=True)]
        assert row['native_round_contract']==round_projection() and row['selected_hash_projection']==selected_projection()
        assert row['original_object_and_raw_hash_bodies_seen'] is True and row['original_table_sha256']==TABLE_SHA256
        assert row['current_request_numeric_hash_compared_to_Python'] is False
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
        else:raise AssertionError('damaged configuration hash64 evidence accepted: '+str(path))
    for k,v in CLAIMS.items():reject(('claims',k),not v)
    reject(('providers','maximum_handler_reads'),3);reject(('providers','maximum_main_SVCs'),5)
    reject(('providers','original_scope_kept'),False);reject(('instructions',0,'mnemonic'),'nop')
    reject(('bytecode_words',0,'word'),'0x0');reject(('original_table_sha256',),'0'*64)
    reject(('independent_Python_projection','hash_hex'),'0x0')
    reject(('independent_Python_VM_projection',0,'executed_bytecodes'),[])
    reject(('independent_native_hash_projection',0,'hash_hex'),'0x0')
    for i in range(len(data['case_results'])):
        changes=[(('retained_owner_cleanup_prefix_verified',),False),(('retained_prefix_trace_sha256',),'0'*64),
            (('retired_completed_observers',),[]),(('original_scope_kept',),False),(('executed_bytecodes',),[]),
            (('native_loads',),[]),(('native_packed_stores',),[]),(('native_saved_word_writes',0,'size'),8),
            (('native_hash_result_writes',0,'size'),4),(('native_hash_result_writes',0,'X0_matches'),False),
            (('native_round_contract',),[]),(('native_round_contract',0,'remaining'),0),
            (('original_object_and_raw_hash_bodies_seen',),False),(('original_table_sha256',),'0'*64),
            (('current_request_numeric_hash_compared_to_Python',),True),(('allocation_ledger_sha256',),'0'*64),
            (('allocator_counts','malloc'),0),(('service_counts','syscall_226'),0),(('JNI_calls',),[]),
            (('libc_SVC_boundaries',),[]),(('main_image_SVC_boundaries',),[]),
            (('continuation_instruction_observations',),0),(('continuation_trace_sha256',),'bad'),
            (('continuation_code_sha256',),'bad'),(('observation_stop_before',),'0x0'),
            (('outer_bytecode',),hex(ENTRY)),(('callback_or_ordinary_RET_seen',),True)]
        for k,v in selected_projection().items():changes.append((('selected_hash_projection',k),not v if isinstance(v,bool) else 'bad'))
        for path,value in changes:reject(('case_results',i)+path,value)
    return count


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--elf',type=Path);ap.add_argument('--libc',type=Path);ap.add_argument('--replay',action='store_true')
    args=ap.parse_args()
    if args.replay and (not args.elf or not args.libc):ap.error('--replay requires --elf and --libc')
    data=json.loads(EVIDENCE.read_text(encoding='utf-8'));validate(data)
    result=dict(retained_configuration_hash64_cases=len(data['case_results']),damaged_evidence_rejected=negatives(data),
        current_request_numeric_hash_compared_to_Python=False,KMSV_value_generated=False,
        ordinary_Cronet_six_headers_verified=False,complete_standalone_signer_verified=False)
    if args.elf:result['image_bindings']=verify_images(data,args.elf,args.libc)
    elif args.libc:graph.inputs.libc_image(args.libc)
    if args.replay:
        assert independent_native_hash_controls(args.elf)==data['independent_native_hash_projection']
        assert replay(args.elf,args.libc)==data['case_results'],'frozen configuration hash64 replay differs'
        result['original_code_cases_replayed']=len(data['case_results']);result['fresh_declared_native_hash_controls_replayed']=2
    print(json.dumps(result))


if __name__=='__main__':main()
