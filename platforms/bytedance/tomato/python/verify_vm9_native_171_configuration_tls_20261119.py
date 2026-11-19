"""Original configuration flags and a cold TLS variable in a warm thread array.

The current request's original getter executes without helper substitution.
Fresh declared VM pages use the actual request callback source and existing
TLS model; separate original TLS controls compare those declared semantics.
Different current and declared hashes/indices are not claimed to be equal.
"""
from __future__ import annotations

import argparse
import ast
from copy import deepcopy
import hashlib
import inspect
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unicorn import arm64_const as arm
import verify_vm9_native_171_configuration_hash64_20261119 as previous
import verify_vm9_request_TLS_word_fresh_20261012 as tls_fixture
import vm9_objects as objects
import vm9_request_vm as owner

context,graph,name=previous.context,previous.graph,previous.name
EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_configuration_tls_20261119.json')
ENTRY,CALL,STOP=0xFD5BC,0xFD5E8,0x16AA4C
WRAPPER,TARGET,CONTROL=0x285E54,0x2850A8,0x382920
GOT_BASE=previous.GOT_BASE
WORDS=[(ENTRY,0x8B4ABA0F),(0xFD5C0,0x88C00218),(0xFD5C4,0x08400230),
    (0xFD5C8,0x83772618),(0xFD5CC,0x8B781418),(0xFD5D0,0x88C8001A),
    (0xFD5D4,0x89900418),(0xFD5D8,0x9B70B89A),(0xFD5DC,0x8B48B89A),
    (0xFD5E0,0xA3460A18),(0xFD5E4,0x05C19B11),(CALL,0x067E0C91)]
LOADS=[(0xFD5C0,8,1,'member'),(0xFD5C8,4856,16,'frame'),
    (0xFD5CC,2832,17,'frame'),(0xFD5D4,528,1,'ELF GOT'),(0xFD5E0,1224,4,'frame')]
STORES=[(0xFD5D4,'member',8),(0xFD5DC,'frame',2800),(0xFD5E0,'frame',2792)]
EXPECTED=[(context.LOAD,'ldr','x9, [x12, x13]'),(0x171268,'str','x15, [x17, x16]'),
    (TARGET,'stp','x29, x30, [sp, #-0x10]!'),(0x2850B0,'adrp','x0, #0x382000'),
    (0x2850B4,'add','x0, x0, #0x920'),(0x2850B8,'bl','#0x34377c'),
    (0x2850BC,'ldr','w0, [x0]'),(0x2850C4,'ret',''),
    (0x343798,'ldar','x22, [x8]'),(0x34379C,'cbz','x22, #0x343800'),
    (0x343828,'adrp','x8, #0x3e3000'),(0x343830,'add','x22, x9, #1'),
    (0x343838,'str','x22, [x8, #0x200]'),(0x34383C,'stlr','x22, [x9]'),
    (0x343854,'bl','#0x3485d0'),(0x343858,'cbnz','x0, #0x3437b0'),
    (0x3438AC,'ldr','x20, [x22, #0x10]!'),(0x3438B0,'cbnz','x20, #0x34391c'),
    (0x3438D8,'add','x0, x23, x21'),(0x3438DC,'bl','#0x347fd0'),
    (0x3438F0,'stur','x0, [x20, #-8]'),(0x343914,'bl','#0x347f20'),
    (0x343918,'str','x20, [x22]'),(0x343934,'ret',''),
    (WRAPPER,'stp','x30, x19, [sp, #-0x10]!'),(0x285E58,'mov','x19, x0'),
    (0x285E5C,'ldp','x8, x0, [x0]'),(0x285E60,'blr','x8'),
    (0x285E64,'str','w0, [x19, #0x10]'),(0x285E68,'ldp','x30, x19, [sp], #0x10'),
    (0x285E6C,'ret',''),(STOP,'ldp','x5, x1, [x29, #-0x90]')]
CLAIMS=dict(retained_hash64_instruction_code_and_allocation_prefix_verified=True,
    completed_hash_observer_retired_after_full_prefix=True,original_scope_kept=True,
    original_flags_or256_and_selected_arguments_verified=True,
    original_TLS_getter_and_emutls_bodies_executed=True,
    cold_descriptor_in_warm_array_index_and_slot_verified=True,
    exactly_one_19_byte_allocation_verified=True,original_four_byte_return_and_padding_verified=True,
    fresh_declared_VM_executes_actual_request_callback_source=True,
    fresh_declared_TLS_model_and_two_original_controls_match=True,
    previous_hash_clone_table_and_count1_references_preserved=True,
    service_JNI_and_SVC_ledgers_unchanged=True,native_memory_used_as_Python_model_input=False,
    current_request_hash_numeric_Python_equality_verified=False,
    current_and_declared_TLS_indices_equal=False,new_OS_JNI_or_internal_helper_providers=False,
    current_whole_TLS_heap_or_physical_stack_equivalence_verified=False,TLS_return_consumed=False,
    complete_configuration_provenance_verified=False,real_business_state_or_JVM_identity_verified=False,
    KMSV_value_generated=False,client_key_value_generated=False,ordinary_Cronet_six_headers_verified=False,
    whole_request_equivalence_verified=False,callback_or_ordinary_wrapper_returned=False,
    complete_standalone_signer_verified=False,Android_execution=False,online_acceptance_verified=False)


def selected_projection():
    return dict(member_flags_offset=8,member_flags_before=16,member_flags_after=272,flag_store_size=8,
        R16_source_frame_offset=4856,R17_source_frame_offset=2832,R17_preserves_actual_hash=True,
        GOT_slot_offset='0x382e90',wrapper_frame_offset=1224,wrapper_offset=hex(WRAPPER),target_offset=hex(TARGET),
        packed_frame_offset=2792,result_frame_offset=2808,result_size=4,result_u32=0,adjacent12_preserved=True,
        TLS_control_offset=hex(CONTROL),TLS_size=4,TLS_alignment=4,TLS_template_NULL=True,
        native_index_before=0,native_counter_before=4,native_index_after=5,native_counter_after=5,
        warm_once_state=2,existing_array_capacity=14,new_slot_was_NULL=True,
        allocation_sizes=[19],allocation_callsite='0x3438e0',TLS_pointer_is_block_plus8=True,
        new_TLS_variable_zero_initialized=True,existing_array_other_bytes_preserved=True,
        both_reference_counts_one=True,previous_hash_and_clone_and_table_preserved=True)


def _callback(image,get_tls,diagnostic,ledger):
    # Isolate the current owning callback source, as existing request verifiers do.
    tree=ast.parse(inspect.getsource(owner._execute_request_vm_impl))
    node=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=='callback')
    ns=dict(vars(owner));ns.update(image=image,get_tls=get_tls,diagnostic_scope=diagnostic,ledger=ledger,allocate=None)
    exec(compile(ast.Module(body=[node],type_ignores=[]),owner.__file__,'exec'),ns)
    return ns['callback']


def fresh(image):
    pages,frame,clone,payload,counter,sibling,wrapper,root,member,put,read,w=previous.fresh(image)
    put(member,b'\xa5'*32);w(member+8,16)
    w(frame+4856,0x6C000000);w(frame+2832,int(previous.model_projection()['hash_hex'],16))
    w(frame+1224,image+WRAPPER);w(image+0x382E90,image+TARGET)
    put(image+CONTROL,(4).to_bytes(8,'little')+(4).to_bytes(8,'little')+bytes(16))
    w(image+0x3E31F4,3,4);w(image+0x3E31F8,2,4);w(image+0x3E3200,7)
    put(image+0x3E3208,bytes(40))
    array,block=0x6A001000,0x6A002000
    put(array,bytes(128));w(array,1);w(array+8,14);w(array+16,0x6C001000)
    put(block,b'\xa5'*4096);allocations=[]
    def reject(*args):raise AssertionError('unexpected declared warm-TLS service')
    def allocate(p,n):
        assert p is not pages and n==19 and not allocations
        allocations.append(n);return block
    def get_specific(p,key):assert key==3;return array
    def get_tls(p,control):
        assert control==image+CONTROL
        return objects.get_emulated_tls_address(p,control_address=control,image_base=image,
            allocate=allocate,reallocate=reject,get_specific=get_specific,set_specific=reject,
            create_key=reject,once_wake=reject)
    return pages,frame,clone,payload,counter,sibling,member,array,block,put,read,w,get_tls,allocations


def declared_projection():
    return dict(TLS_index_before=0,TLS_counter_before=7,TLS_index_after=8,TLS_counter_after=8,
        result_u32=0,allocation_sizes=[19],TLS_pointer_is_block_plus8=True,
        actual_request_callback_executed=True,adjacent12_preserved=True,existing_array_other_bytes_preserved=True,
        declared_hash_hex=previous.model_projection()['hash_hex'],native_snapshot_input=False)


def model_projection():
    image=graph.BASES[0]
    pages,frame,clone,payload,counter,sibling,member,array,block,put,read,w,get_tls,allocations=fresh(image)
    packed=frame+2792;before_array=read(array,128)
    w(packed,image+TARGET);w(packed+8,member);padding=read(packed+20,12)
    memory=SimpleNamespace(pages=pages,u64=lambda a:int.from_bytes(read(a,8),'little'))
    diagnostic={};ledger=[]
    _callback(image,get_tls,diagnostic,ledger)(SimpleNamespace(m=memory),image+WRAPPER,packed)
    assert len(ledger)==1 and diagnostic=={'request_TLS_words':[0]} and allocations==[19]
    assert int.from_bytes(read(packed+16,4),'little')==0 and read(packed+20,12)==padding
    assert int.from_bytes(read(image+CONTROL+16,8),'little')==8
    assert int.from_bytes(read(image+0x3E3200,8),'little')==8
    slot=array+16+7*8;assert int.from_bytes(read(slot,8),'little')==block+8
    assert int.from_bytes(read(block,8),'little')==block and read(block+8,4)==bytes(4)
    assert read(block+12,7)==b'\xa5'*7
    assert all(a==b for i,(a,b) in enumerate(zip(before_array,read(array,128))) if not 72<=i<80)
    return declared_projection()


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
            vm_module.B=image
            pages,frame,clone,payload,counter,sibling,member,array,block,put,read,w,get_tls,allocations=fresh(image)
            class Memory:
                def __init__(self):self.pages=pages
                def u32(self,a):return int.from_bytes(read(a,4),'little')
                def u64(self,a):return int.from_bytes(read(a,8),'little')
                def rb(self,a):return read(a,1)[0]
                def w64(self,a,v):w(a,v)
                def w32(self,a,v):w(a,v,4)
            m=Memory();steps=[];ledger=[];diagnostic={}
            for a,value in WORDS:put(image+a,value.to_bytes(4,'little'))
            put(image+CALL+4,bytes(4));before_frame=read(frame,0x2000)
            preserved={a:read(a,n) for a,n in ((clone,24),(payload,11),(counter,16),(sibling,16),(image+previous.TABLE,2048))}
            vm=vm_module.VM(m,ENTRY,0,0,0,0,0,maxsteps=15)
            vm.R=[0xA5A5000000000000+i for i in range(32)]
            vm.R[0]=vm.R[21]=0;vm.R[19]=member;vm.R[22]=image+GOT_BASE
            vm.R[23]=image+0x28587C;vm.R[29]=frame;vm.cb=image+0x28587C;initial=list(vm.R)
            callback=_callback(image,get_tls,diagnostic,ledger)
            def native(vm,function,packed):
                assert vm.pc==image+CALL and function==image+WRAPPER and packed==frame+2792
                assert [m.u64(packed+i*8) for i in range(2)]==[image+TARGET,member]
                callback(vm,function,packed)
            def step(vm,dw,op,sub):
                if vm.pc==image+CALL+4:raise Boundary()
                assert (vm.pc-image,dw)==WORDS[len(steps)];steps.append(hex(vm.pc-image))
            vm.native_hook=native;vm.step_hook=step
            try:vm.run()
            except Boundary:pass
            else:raise AssertionError('declared TLS VM did not stop after CALL')
            assert steps==[hex(a) for a,_ in WORDS] and len(ledger)==1 and diagnostic=={'request_TLS_words':[0]}
            selected=(1,4,5,16,17,25,31)
            assert [vm.R[i] for i in selected]==[image+TARGET,image+WRAPPER,frame+2792,0x6C000000,
                int(previous.model_projection()['hash_hex'],16),image+0x28587C,image+CALL+4]
            assert all(vm.R[i]==initial[i] for i in range(32) if i not in selected)
            assert m.u64(member+8)==272 and m.u32(frame+2808)==0 and allocations==[19]
            after=read(frame,0x2000)
            assert all(a==b for i,(a,b) in enumerate(zip(before_frame,after)) if not 2792<=i<2812)
            for a,b in preserved.items():assert read(a,len(b))==b
            assert m.u32(counter)==m.u32(sibling)==1 and m.u64(array+72)==block+8
            assert m.u64(image+CONTROL+16)==m.u64(image+0x3E3200)==8
            rows.append(dict(image_base=hex(image),executed_bytecodes=steps,declared_projection=declared_projection(),
                member_flags_after=272,selected_registers_and_frame_writes_verified=True))
    finally:vm_module.B=saved_base
    return rows


def expected_VM_projection():
    return [dict(image_base=hex(b),executed_bytecodes=[hex(a) for a,_ in WORDS],declared_projection=declared_projection(),
        member_flags_after=272,selected_registers_and_frame_writes_verified=True) for b in graph.BASES]


def expected_native_TLS_projection():
    return [dict(image_base=hex(b),cold_descriptor_in_declared_warm_array=True,index_before=0,counter_before=7,
        index_after=8,counter_after=8,one_allocation_size=19,result_u32=0,
        guest_image_TLS_padding_and_effects_match=True,native_snapshot_input=False) for b in graph.BASES]


def independent_native_TLS_controls(path,libc):
    rows=[]
    for image in graph.BASES:
        pages,model=tls_fixture.fresh(path,libc,image,'warm_zero')
        tls_fixture._write_span(pages,image+CONTROL+16,bytes(8))
        tls_fixture._write_span(pages,image+0x3E3200,(7).to_bytes(8,'little'))
        returned,memory,observed,allocations,wakes=tls_fixture.native(path,libc,image,pages,model)
        n=len(model.allocator.calls);w=len(model.wakes)
        value=tls_fixture.apply(pages,image,model.get_tls)
        assert returned==value==0 and tls_fixture._read_span(pages,tls_fixture.G,0xA000)==memory
        assert all(tls_fixture._read_span(pages,a,n)==data for (a,n),data in observed.items())
        assert model.allocator.calls[n:]==allocations and len(allocations)==1 and allocations[0][0]==19
        assert model.wakes[w:]==wakes==[]
        assert int.from_bytes(tls_fixture._read_span(pages,image+CONTROL+16,8),'little')==8
        assert int.from_bytes(tls_fixture._read_span(pages,image+0x3E3200,8),'little')==8
        assert tls_fixture._read_span(pages,tls_fixture.PACKED+20,12)==b'\xa5'*12
        rows.append(expected_native_TLS_projection()[len(rows)])
    return rows


def providers():
    return dict(inherited_hash64=previous.providers(),maximum_handler_reads=2,maximum_main_SVCs=4,
        retired_completed_observation_windows=['hash_active'],original_scope_kept=True,
        independent_model_owners=['vm_full.py:VM.run','vm9_request_vm.py:_execute_request_vm_impl.callback',
            'vm9_objects.py:get_emulated_tls_address'],
        current_and_declared_hashes_or_TLS_indices_compared=False,new_OS_JNI_or_internal_helper_providers=[],
        current_request_allocation_delta=dict(malloc=1,bytes=19),service_count_deltas={},
        stop_before=hex(STOP),outer_bytecode=hex(CALL))


class Scenario(previous.Scenario):
    def __init__(self,c):
        super().__init__(c);self.tls_active=False;self.tls_done=False
        self.tls_steps=[];self.tls_loads=[];self.tls_stores=[];self.tls_result_writes=[]

    def native_runner(self,*args,**kwargs):
        original=kwargs['memory_write_observer']
        def write(cpu,address,size):
            if self.tls_active:
                reg=lambda n:cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(n)))
                off=cpu.reg_read(arm.UC_ARM64_REG_PC)-self.image
                bc=int.from_bytes(cpu.mem_read(self.scope_state['PC_slot'],8),'little')-self.image
                if address in (self.hash_registry_member+8,self.scope_frame+2800,self.scope_frame+2792):
                    site,kind,offset=STORES[len(self.tls_stores)]
                    base=self.hash_registry_member if kind=='member' else self.scope_frame
                    value={0xFD5D4:272,0xFD5DC:self.hash_registry_member,0xFD5E0:self.image+TARGET}[bc]
                    assert (bc,off,address,size,reg(15))==(site,0x171268,base+offset,8,value)
                    self.tls_stores.append(dict(cursor_bytecode=hex(bc),destination=kind,offset=offset,size=8))
                if address==self.scope_frame+2808:
                    assert (off,bc,size,reg(0))==(0x285E64,CALL,4,0)
                    self.tls_result_writes.append(dict(native_pc=hex(off),bytecode=hex(bc),frame_offset=2808,size=4,value_u32=0))
            original(cpu,address,size)
        kwargs['memory_write_observer']=write
        return super().native_runner(*args,**kwargs)

    def hash_boundary(self,cpu,state):
        old=next(r for r in json.loads(previous.EVIDENCE.read_text())['case_results'] if r['control']==self.control)
        prefix=state['configuration_hash64_prefix']
        for k in ('instruction_observations','trace_sha256','code_sha256'):assert prefix[k]==old['continuation_'+k]
        assert self.hash_done and self.hash_active and self.original_scope
        assert graph.digest(state['allocator_events_ref'])==old['allocation_ledger_sha256']
        raw=lambda a,n:bytes(cpu.mem_read(a,n));u=lambda a,n=8:int.from_bytes(raw(a,n),'little')
        assert u(self.hash_registry_member+8)==16 and u(self.image+0x3E3200)==4
        assert raw(self.image+CONTROL,32)==(4).to_bytes(8,'little')+(4).to_bytes(8,'little')+bytes(16)
        assert u(self.image+0x3E31F8,4)==2
        self.tls_once_key_before=raw(self.image+0x3E31F4,8)
        self.tls_initial_R=[u(state['backing']+i*8) for i in range(32)]
        self.tls_opaque_R16=u(self.scope_frame+4856);self.tls_old_hash=u(self.scope_frame+2832)
        self.tls_preserved={a:raw(a,n) for a,n in ((self.scope_owner,264),(self.exit_counter,16),
            (self.source_counter,16),(self.clone_destination,24),(self.clone_new_payload,11),
            (self.copy_table,2048),(self.image+previous.TABLE,2048),(self.scope_frame+2832,8))}
        self.tls_allocations=deepcopy(state['allocator_events_ref'])
        self.hash_active=False;self.tls_active=True

    def observe(self,cpu,pc,state):
        self.scope_state=state
        if not self.tls_active:
            super().observe(cpu,pc,state)
            if not self.tls_active:return
        off=pc-self.image
        reg=lambda n:cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(n)))
        raw=lambda a,n:bytes(cpu.mem_read(a,n));u=lambda a,n=8:int.from_bytes(raw(a,n),'little')
        bc=u(state['PC_slot'])-self.image
        if off in (0x27E6AC,0x27ED6C):raise AssertionError('unexpected ordinary callback/wrapper RET')
        if bc!=previous.CALL and (not self.tls_steps or self.tls_steps[-1]!=hex(bc)):
            assert bc==WORDS[len(self.tls_steps)][0];self.tls_steps.append(hex(bc))
        if off==context.LOAD:
            a,offset,destination,source=LOADS[len(self.tls_loads)]
            base={'frame':self.scope_frame,'member':self.hash_registry_member,'ELF GOT':self.image+GOT_BASE}[source]
            expected={0xFD5C0:16,0xFD5C8:self.tls_opaque_R16,0xFD5CC:self.tls_old_hash,
                0xFD5D4:self.image+TARGET,0xFD5E0:self.image+WRAPPER}[bc]
            assert (bc,reg(12),reg(13),reg(14),u(base+offset))==(a,base,offset,destination,expected)
            self.tls_loads.append(dict(bytecode=hex(bc),offset=offset,destination=destination,source=source))
        if off==0x16AA48:
            assert bc==CALL and reg(8)==self.image+WRAPPER and reg(0)==self.scope_frame+2792
            assert [u(reg(0)+i*8) for i in range(2)]==[self.image+TARGET,self.hash_registry_member]
            selected=(1,4,5,16,17,25,31)
            assert [u(state['backing']+i*8) for i in selected]==[self.image+TARGET,self.image+WRAPPER,
                self.scope_frame+2792,self.tls_opaque_R16,self.tls_old_hash,self.image+0x28587C,self.image+CALL+4]
            assert all(u(state['backing']+i*8)==self.tls_initial_R[i] for i in range(32) if i not in selected)
            assert u(self.hash_registry_member+8)==272
            self.tls_padding_before=raw(reg(0)+20,12);self.tls_call_seen=True
        if off==TARGET:
            assert self.tls_call_seen and reg(0)==self.hash_registry_member;self.tls_getter_entered=True
        if off==0x34377C:
            assert self.tls_getter_entered and reg(0)==self.image+CONTROL;self.tls_emutls_entered=True
        if off==0x34379C:
            assert self.tls_emutls_entered and reg(22)==0;self.tls_cold_seen=True
        if off==0x343830:
            assert self.tls_cold_seen and reg(9)==4
        if off==0x343840:
            assert reg(22)==5 and u(self.image+CONTROL+16)==u(self.image+0x3E3200)==5
            self.tls_index_verified=True
        if off==0x3437B0:
            assert self.tls_index_verified and reg(0)!=0
            self.tls_array=reg(0);assert u(self.tls_array)==1 and u(self.tls_array+8)==14
            self.tls_array_before=raw(self.tls_array,128);self.tls_slot=self.tls_array+48
            assert u(self.tls_slot)==0
        if off==0x3438B0:
            assert reg(22)==self.tls_slot and reg(20)==0;self.tls_slot_was_NULL=True
        if off==0x3438DC:
            assert self.tls_slot_was_NULL and reg(0)==19;self.tls_malloc_seen=True
        if off==0x3438E0:
            assert self.tls_malloc_seen and reg(0)!=0;self.tls_block=reg(0)
        if off==0x343918:
            assert reg(22)==self.tls_slot and reg(20)==self.tls_block+8
            assert u(reg(20)-8)==self.tls_block and u(reg(20),4)==0
        if off==0x2850BC:
            assert reg(0)==self.tls_block+8 and u(reg(0),4)==0;self.tls_pointer=reg(0)
        if off==0x285E68:
            assert self.tls_result_writes and u(self.scope_frame+2808,4)==0
            assert raw(self.scope_frame+2812,12)==self.tls_padding_before;self.tls_packed_verified=True
        if off==STOP and bc==CALL:
            assert self.tls_packed_verified and reg(0)==0 and u(self.tls_slot)==self.tls_pointer
            assert raw(self.image+0x3E31F4,8)==self.tls_once_key_before
            assert raw(self.image+CONTROL,32)==(4).to_bytes(8,'little')+(4).to_bytes(8,'little')+(5).to_bytes(8,'little')+bytes(8)
            assert all(a==b for i,(a,b) in enumerate(zip(self.tls_array_before,raw(self.tls_array,128))) if not 48<=i<56)
            for a,b in self.tls_preserved.items():assert raw(a,len(b))==b
            assert u(self.source_counter,4)==u(self.exit_counter,4)==1
            assert raw(state['context'],128)==state['handler_bytes'] and self.original_scope
            assert state['allocator_events_ref']==self.tls_allocations+[['alloc',19,self.tls_block,'0x3438e0']]
            self.tls_done=True;self.tls_boundary(cpu,state)

    def tls_boundary(self,cpu,state):
        cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,context.outer.oracle.STOP)

    def finish(self,result,state,proof):
        data=json.loads(previous.EVIDENCE.read_text());previous.validate(data)
        old=next(r for r in data['case_results'] if r['control']==self.control);prefix=proof['configuration_hash64_prefix']
        assert self.tls_done and result['allocator_events']==self.tls_allocations+[['alloc',19,self.tls_block,'0x3438e0']]
        counts=dict(old['allocator_counts']);counts['malloc']+=1
        assert result['actual_allocator_counts']==counts and result['explicit_service_counts']==old['service_counts']
        for k in ('JNI_calls','libc_SVC_boundaries','main_image_SVC_boundaries'):assert proof[k]==prefix[k]==old[k]
        return dict(control=self.control,retained_hash64_prefix_verified=True,
            retained_prefix_instruction_observations=prefix['instruction_observations'],retained_prefix_trace_sha256=prefix['trace_sha256'],
            retained_prefix_code_sha256=prefix['code_sha256'],retired_completed_observers=['hash_active'],original_scope_kept=True,
            executed_bytecodes=self.tls_steps,native_loads=self.tls_loads,native_stores=self.tls_stores,
            native_result_writes=self.tls_result_writes,selected_TLS_projection=selected_projection(),
            allocation_prefix_sha256=old['allocation_ledger_sha256'],allocation_ledger_sha256=graph.digest(result['allocator_events']),
            allocation_event_projection=[dict(action='alloc',size=19,callsite='0x3438e0',pointer_owns_TLS_variable=True)],
            allocator_counts=counts,service_counts=old['service_counts'],JNI_calls=proof['JNI_calls'],
            libc_SVC_boundaries=proof['libc_SVC_boundaries'],main_image_SVC_boundaries=proof['main_image_SVC_boundaries'],
            continuation_instruction_observations=proof['instruction_observations'],continuation_trace_sha256=proof['trace_sha256'],
            continuation_code_sha256=proof['code_sha256'],observation_stop_before=hex(STOP),outer_bytecode=hex(CALL),
            callback_or_ordinary_RET_seen=False)


def replay(path,libc,*,on_case=None,case_controls=None):
    return context.replay(path,libc,on_case=on_case,case_controls=case_controls,_extension_factory=Scenario,
        _request_profile=name.previous.previous.PROFILE['name'],_handler_read_profile=context.NULL_PAYLOAD_READ_PROFILE['name'])


def verify_images(data,path,libc):
    from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
    previous.verify_images({},path,libc);elf,_,read=graph.inputs.load_elf(path);decoder=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
    for a,m,s in EXPECTED:
        ins,=decoder.disasm(read(a,4),a);assert (ins.mnemonic,ins.op_str)==(m,s),hex(a)
    for a,w in WORDS:assert int.from_bytes(read(a,4),'little')==w,hex(a)
    rel=[r for s in elf.iter_sections() if s['sh_type']=='SHT_RELA' for r in s.iter_relocations() if r['r_offset']==0x382E90]
    assert len(rel)==1 and rel[0]['r_info_type']==1027 and rel[0]['r_addend']==TARGET
    assert interpreter_projection(path)==expected_VM_projection()
    return dict(instruction_bindings=len(EXPECTED),bytecode_words=len(WORDS),GOT_relative_relocation_verified=True,
        independent_Python_VM_cases=2,actual_request_callback_source_executed=True)


def validate(data):
    assert data['schema']=='vm9-native-171-configuration-tls-20261119-v1' and data['claims']==CLAIMS and data['providers']==providers()
    assert data['instructions']==[dict(offset=hex(a),mnemonic=m,operands=s) for a,m,s in EXPECTED]
    assert data['bytecode_words']==[dict(offset=hex(a),word=hex(w)) for a,w in WORDS]
    assert data['independent_model_projection']==model_projection()
    assert data['independent_Python_VM_projection']==expected_VM_projection()
    assert data['independent_native_TLS_projection']==expected_native_TLS_projection()
    assert data['request_callback_source_sha256']==hashlib.sha256(Path(owner.__file__).read_bytes()).hexdigest()
    old_data=json.loads(previous.EVIDENCE.read_text());previous.validate(old_data)
    assert data['provenance']==old_data['provenance'] and len(data['case_results'])==len(context.controls())
    for row,old in zip(data['case_results'],old_data['case_results']):
        assert row['control']==old['control'] and row['retained_hash64_prefix_verified'] is True
        for k in ('instruction_observations','trace_sha256','code_sha256'):assert row['retained_prefix_'+k]==old['continuation_'+k]
        assert row['retired_completed_observers']==['hash_active'] and row['original_scope_kept'] is True
        assert row['executed_bytecodes']==[hex(a) for a,_ in WORDS]
        assert row['native_loads']==[dict(bytecode=hex(a),offset=o,destination=d,source=s) for a,o,d,s in LOADS]
        assert row['native_stores']==[dict(cursor_bytecode=hex(a),destination=k,offset=o,size=8) for a,k,o in STORES]
        assert row['native_result_writes']==[dict(native_pc='0x285e64',bytecode=hex(CALL),frame_offset=2808,size=4,value_u32=0)]
        assert row['selected_TLS_projection']==selected_projection() and row['allocation_prefix_sha256']==old['allocation_ledger_sha256']
        assert graph.inputs.is_digest(row['allocation_ledger_sha256']) and row['allocation_ledger_sha256']!=row['allocation_prefix_sha256']
        assert row['allocation_event_projection']==[dict(action='alloc',size=19,callsite='0x3438e0',pointer_owns_TLS_variable=True)]
        counts=dict(old['allocator_counts']);counts['malloc']+=1
        assert row['allocator_counts']==counts
        for k in ('service_counts','JNI_calls','libc_SVC_boundaries','main_image_SVC_boundaries'):assert row[k]==old[k]
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
        else:raise AssertionError('damaged configuration TLS evidence accepted: '+str(path))
    for k,v in CLAIMS.items():reject(('claims',k),not v)
    reject(('providers','maximum_handler_reads'),3);reject(('providers','maximum_main_SVCs'),5)
    reject(('providers','current_request_allocation_delta','bytes'),4)
    reject(('instructions',0,'mnemonic'),'nop');reject(('bytecode_words',0,'word'),'0x0')
    reject(('request_callback_source_sha256',),'0'*64)
    reject(('independent_model_projection','TLS_index_after'),5)
    reject(('independent_Python_VM_projection',0,'executed_bytecodes'),[])
    reject(('independent_native_TLS_projection',0,'one_allocation_size'),4)
    for i in range(len(data['case_results'])):
        changes=[(('retained_hash64_prefix_verified',),False),(('retained_prefix_trace_sha256',),'0'*64),
            (('retired_completed_observers',),[]),(('original_scope_kept',),False),(('executed_bytecodes',),[]),
            (('native_loads',),[]),(('native_stores',),[]),(('native_result_writes',0,'size'),8),
            (('allocation_prefix_sha256',),'0'*64),(('allocation_ledger_sha256',),'bad'),
            (('allocation_event_projection',0,'size'),4),(('allocator_counts','malloc'),0),
            (('service_counts','syscall_226'),0),(('JNI_calls',),[]),(('libc_SVC_boundaries',),[]),
            (('main_image_SVC_boundaries',),[]),(('continuation_instruction_observations',),0),
            (('continuation_trace_sha256',),'bad'),(('continuation_code_sha256',),'bad'),
            (('observation_stop_before',),'0x0'),(('outer_bytecode',),hex(ENTRY)),(('callback_or_ordinary_RET_seen',),True)]
        for k,v in selected_projection().items():changes.append((('selected_TLS_projection',k),not v if isinstance(v,bool) else 'bad'))
        for path,value in changes:reject(('case_results',i)+path,value)
    return count


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--elf',type=Path);ap.add_argument('--libc',type=Path);ap.add_argument('--replay',action='store_true')
    args=ap.parse_args()
    if args.replay and (not args.elf or not args.libc):ap.error('--replay requires --elf and --libc')
    data=json.loads(EVIDENCE.read_text());validate(data)
    result=dict(retained_configuration_TLS_cases=len(data['case_results']),damaged_evidence_rejected=negatives(data),
        current_request_hash_numeric_Python_equality_verified=False,ordinary_Cronet_six_headers_verified=False,
        complete_standalone_signer_verified=False)
    if args.elf:result['image_bindings']=verify_images(data,args.elf,args.libc)
    elif args.libc:graph.inputs.libc_image(args.libc)
    if args.replay:
        assert independent_native_TLS_controls(args.elf,args.libc)==data['independent_native_TLS_projection']
        assert replay(args.elf,args.libc)==data['case_results'],'frozen configuration TLS replay differs'
        result['original_code_cases_replayed']=len(data['case_results']);result['fresh_declared_native_TLS_controls_replayed']=2
    print(json.dumps(result))


if __name__=='__main__':main()
