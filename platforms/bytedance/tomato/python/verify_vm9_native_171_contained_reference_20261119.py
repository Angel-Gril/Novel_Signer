"""Continue the original request through its configuration reference getter.

Compare selected reference/lock semantics with fresh declared Python pages.
Stop before the interpreter consumes the getter return; no business identity
or complete configuration construction provenance is inferred from the pair.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
from unicorn import arm64_const as arm
import verify_vm9_native_171_kmsv_scope_exit_20261119 as previous
import vm9_reference_scopes as references

context,graph,name,diagnostics=previous.context,previous.graph,previous.name,previous.diagnostics
EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_contained_reference_20261119.json')
ENTRY,CALL,STOP=0xFD294,0xFD2B4,0x16AA4C
TARGET,WRAPPER,GOT_SLOT=0x2633A4,0x285E14,0x382CF8
WORDS=[(ENTRY,0x89030618),(0xFD298,0x8B4ACA0F),(0xFD29C,0x8B78C89A),
    (0xFD2A0,0x935E0E18),(0xFD2A4,0x9350C89A),(0xFD2A8,0x8B48C89A),
    (0xFD2AC,0xA34B0018),(0xFD2B0,0x05C19B11),(CALL,0x067E0C91)]
EXPECTED=[(context.LOAD,'ldr','x9, [x12, x13]'),(0x171268,'str','x15, [x17, x16]'),
    (WRAPPER,'str','x30, [sp, #-0x10]!'),(0x285E18,'ldp','x9, x8, [x0]'),
    (0x285E1C,'ldr','x0, [x0, #0x10]'),(0x285E20,'blr','x9'),
    (0x285E24,'ldr','x30, [sp], #0x10'),(0x285E28,'ret',''),
    (TARGET,'add','x1, x0, #0x18'),(0x2633A8,'mov','x0, x8'),(0x2633AC,'b','#0x15f580'),
    (0x15F580,'sub','sp, sp, #0x50'),(0x15F5A8,'stp','xzr, xzr, [x0]'),
    (0x15F5B0,'ldr','x1, [x1]'),(0x15F5B4,'bl','#0x26c858'),
    (0x15F5B8,'ldr','x8, [x19]'),(0x15F5BC,'str','x8, [x20]'),
    (0x15F5C0,'ldr','x8, [x19, #8]'),(0x15F5C4,'str','x8, [x20, #8]'),
    (0x15F5C8,'cbz','x8, #0x15f5d8'),(0x15F5CC,'ldr','w9, [x8]'),
    (0x15F5D0,'add','w9, w9, #1'),(0x15F5D4,'str','w9, [x8]'),
    (0x15F5DC,'bl','#0x26c9d0'),(STOP,'ldp','x5, x1, [x29, #-0x90]')]
LOADS={ENTRY:(120,1,'ELF GOT'),0xFD2A0:(2008,2,'frame'),0xFD2AC:(352,4,'frame')}
CHANGED=(1,2,4,5,25)
CLAIMS=dict(retained_scope_exit_instruction_code_and_allocation_prefix_verified=True,
    original_eight_argument_bytecodes_match_independent_fresh_VM=True,
    original_configuration_member24_reference_getter_executed=True,
    original_destination_pair_cleared_then_copied=True,original_source_counter_u32_retained_from1_to2=True,
    warm_table_missing_selected_entry_allocates48=True,selected_recursive_lock_released=True,
    fresh_independent_Python_scoped_reference_copy_matches=True,
    retained_service_JNI_and_SVC_ledgers_unchanged=True,native_memory_used_as_model_input=False,
    new_OS_JNI_or_internal_helper_providers=False,complete_source_pair_construction_provenance_verified=False,
    full_VM_or_physical_stack_equivalence_verified=False,getter_return_consumed=False,
    saved_NULL_business_branch_verified=False,KMSV_value_generated=False,client_key_value_generated=False,
    real_business_cache_restored=False,real_JVM_identity_verified=False,ordinary_Cronet_six_headers_verified=False,
    whole_request_equivalence_verified=False,callback_or_ordinary_wrapper_returned=False,
    complete_standalone_signer_verified=False,Android_execution=False,online_acceptance_verified=False)


def argument_projection():
    return dict(executed_bytecodes=[hex(a) for a,_ in WORDS[:-1]],receiver='configuration+0xa0 pointee',
        receiver_member_offset=24,source_pair_width=16,destination_frame_offset=2088,
        destination_pointer_source_frame_offset=2008,wrapper_source_frame_offset=352,
        GOT_slot_offset=hex(GOT_SLOT),target_offset=hex(TARGET),wrapper_offset=hex(WRAPPER),
        packed_frame_offset=2856,packed_words=['image+0x2633a4','frame+2088','receiver'],
        selected_registers=dict(R1='image+0x2633a4',R2='frame+2088',R4='image+0x285e14',
            R5='frame+2856',R25='image+0x28587c'),
        unselected_registers_and_adjacent_frame_bytes_preserved=True,stop_before_bytecode=hex(CALL))


def interpreter_projection(path):
    saved=os.environ.get('TOMATO_LIBMETASEC')
    try:
        os.environ['TOMATO_LIBMETASEC']=str(path.resolve());import vm_full as vm_module
    finally:
        if saved is None:os.environ.pop('TOMATO_LIBMETASEC',None)
        else:os.environ['TOMATO_LIBMETASEC']=saved
    assert hashlib.sha256(vm_module.SO).hexdigest()==graph.inputs.SHA256
    class Memory:
        def __init__(self):self.pages={}
        def u32(self,a):return int.from_bytes(name._read_span(self.pages,a,4),'little')
        def u64(self,a):return int.from_bytes(name._read_span(self.pages,a,8),'little')
        def rb(self,a):return name._read_span(self.pages,a,1)[0]
        def put(self,a,b):name.put(self.pages,a,b)
        def w64(self,a,v):self.put(a,int(v).to_bytes(8,'little'))
    class Boundary(Exception):pass
    saved_base=vm_module.B;rows=[]
    try:
        for image in graph.BASES:
            vm_module.B=image;m=Memory();frame=0x60000000;receiver=0x61000000
            m.put(frame,b'\xa5'*0x2000);m.w64(frame+2008,frame+2088)
            m.w64(frame+352,image+WRAPPER);m.w64(image+GOT_SLOT,image+TARGET)
            for a,w in WORDS:m.put(image+a,w.to_bytes(4,'little'))
            before_frame=name._read_span(m.pages,frame,0x2000)
            vm=vm_module.VM(m,ENTRY,0,0,0,0,0,maxsteps=9)
            vm.R=[0xA5A5000000000000+i for i in range(32)]
            vm.R[0]=0;vm.R[17]=receiver;vm.R[20]=image+previous.previous.GOT_BASE;vm.R[23]=image+0x28587C
            vm.R[29]=frame;vm.R[31]=image+ENTRY
            before=list(vm.R);steps=[]
            def step(vm,dw,op,sub):
                if vm.pc==image+CALL:raise Boundary()
                assert (vm.pc-image,dw)==WORDS[len(steps)];steps.append(hex(vm.pc-image))
            vm.step_hook=step
            try:vm.run()
            except Boundary:pass
            else:raise AssertionError('reference arguments did not stop before CALL')
            assert steps==argument_projection()['executed_bytecodes']
            assert [vm.R[i] for i in CHANGED]==[image+TARGET,frame+2088,image+WRAPPER,frame+2856,image+0x28587C]
            assert all(vm.R[i]==before[i] for i in range(32) if i not in CHANGED)
            assert [m.u64(frame+2856+i*8) for i in range(3)]==[image+TARGET,frame+2088,receiver]
            after=name._read_span(m.pages,frame,0x2000)
            assert all(a==b for i,(a,b) in enumerate(zip(before_frame,after)) if not 2856<=i<2880)
            rows.append(dict(image_base=hex(image),projection=argument_projection()))
    finally:vm_module.B=saved_base
    return rows


def copy_projection():
    return dict(source_pair16_and_receiver88_preserved=True,destination_pair_equals_source=True,
        destination_adjacent16_bytes_preserved=True,source_object_header24_bytes_preserved=True,
        source_counter_before_u32=1,source_counter_after_u32=2,source_counter_store_width=4,
        source_counter_adjacent12_bytes_preserved=True,selected_slot_initially_NULL=True,
        warm_table_other255_slots_preserved=True,selected_entry_size=48,selected_entry_vtable_offset='0x34c738',
        selected_recursive_mutex_state_u32=0x4000,selected_recursive_mutex_owner_u32=0,
        selected_recursive_mutex_other32_bytes_zero=True,guard_and_global_mutex_preserved=True,
        normalized_events=[['lock','global'],['unlock','global'],['lock','selected'],['unlock','selected']],
        added_allocation_sizes=[48])


def model_projection():
    image=0x10000000;root=0x60000000;receiver=0x61000000;pointer=0x62000220;counter=0x63000000
    frame=root+0x100;scope=root+0x200;tls=root+0x300;pthread=root+0x400;stack=root+0x600
    pages={p:bytearray(4096) for p in range(root>>12,(root+0x5000)>>12)}
    def read(a,n):return name._read_span(pages,a,n)
    def put(a,b):name.put(pages,a,b)
    def w(a,v,n=8):put(a,int(v).to_bytes(n,'little'))
    put(image+diagnostics.GUARD,bytes(8));put(image+diagnostics.GUARD_MUTEX,bytes(40))
    put(image+diagnostics.GLOBAL_LOCK,bytes(24));w(tls+8,pthread);w(pthread+16,137,4)
    put(scope,b'\xa5'*24);allocations=[];addresses=[root+0x1000,root+0x2000,root+0x3000,root+0x4000]
    def allocate(p,size):
        assert size==[48,2048,48,48][len(allocations)];a=addresses[len(allocations)]
        put(a,bytes(size));allocations.append((size,a));return a
    diagnostics.enter_diagnostic_scope(pages,object_address=scope,input_word=0x64000000,image_base=image,
        thread_pointer=tls,thread_id=137,allocate=allocate)
    diagnostics.leave_diagnostic_scope(pages,object_address=scope,image_base=image,thread_pointer=tls)
    put(receiver,b'\xa5'*88);w(receiver+24,pointer);w(receiver+32,counter)
    put(pointer,b'\xa5'*24);put(counter,b'\xa5'*16);w(counter,1,4);put(frame-8,b'\xa5'*32)
    receiver_before=read(receiver,88);header=read(pointer,24);count_before=read(counter,16)
    adjacent=read(frame-8,32);table_before=read(addresses[1],2048);events=[]
    references.copy_scoped_string_reference(pages,destination_address=frame,source_address=receiver+24,
        entry_stack_address=stack,image_base=image,thread_pointer=tls,thread_id=137,allocate=allocate,
        diagnostic_observer=lambda *e:events.append(e))
    entry=addresses[3];index=(pointer>>4)&255
    assert read(receiver,88)==receiver_before and read(frame,16)==read(receiver+24,16)
    assert read(frame-8,8)+read(frame+16,8)==adjacent[:8]+adjacent[24:]
    assert read(pointer,24)==header and int.from_bytes(read(counter,4),'little')==2 and read(counter+4,12)==count_before[4:]
    expected=bytearray(table_before);expected[index*8:index*8+8]=entry.to_bytes(8,'little')
    assert read(addresses[1],2048)==expected
    assert read(entry,48)==(image+0x34C738).to_bytes(8,'little')+bytes.fromhex('0040000000000000')+bytes(32)
    assert events==[('pthread_mutex_lock',addresses[0]+8),('pthread_mutex_unlock',addresses[0]+8),
        ('pthread_mutex_lock',entry+8),('pthread_mutex_unlock',entry+8)]
    assert read(image+diagnostics.GUARD,8)==bytes.fromhex('0101000089000000')
    assert read(addresses[0]+8,40)==bytes(40) and read(image+diagnostics.GUARD_MUTEX,40)==bytes(40)
    return copy_projection()


def providers():
    return dict(inherited_scope_exit=previous.providers(),maximum_handler_reads=2,maximum_main_SVCs=4,
        independent_model_owners=['vm_full.py:VM.run','vm9_reference_scopes.py:copy_scoped_string_reference'],
        independent_model_input='fresh declared receiver pair/count1, destination and warm table with missing selected slot',
        allocation_deltas=dict(malloc=1,sizes=[48],callsite='0x32a210'),service_count_deltas={},
        new_OS_JNI_or_internal_helper_providers=[],stop_before=hex(STOP),outer_bytecode=hex(CALL))


class Scenario(previous.Scenario):
    def __init__(self,c):
        super().__init__(c);self.copy_active=False;self.copy_entered=False;self.copy_done=False
        self.copy_loads=[];self.copy_stores=[];self.copy_writes=[];self.copy_events=[];self.count_writes=[]

    def native_runner(self,*args,**kwargs):
        original=kwargs['memory_write_observer']
        def write(cpu,address,size):
            if self.copy_active:
                def reg(n):return cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(n)))
                off=cpu.reg_read(arm.UC_ARM64_REG_PC)-self.image
                bc=int.from_bytes(cpu.mem_read(self.scope_state['PC_slot'],8),'little')-self.image
                if self.scope_frame+2856<=address<self.scope_frame+2880:
                    expected={0xFD2A0:(2872,self.scope_input),0xFD2A8:(2864,self.scope_frame+2088),0xFD2AC:(2856,self.image+TARGET)}
                    offset,value=expected[bc]
                    assert (off,address,size,reg(15))==(0x171268,self.scope_frame+offset,8,value)
                    self.copy_stores.append(dict(cursor_bytecode=hex(bc),frame_offset=offset,size=8))
                if self.copy_entered and self.copy_destination<=address<self.copy_destination+16:
                    assert bc==CALL and (off,address-self.copy_destination,size) in (
                        (0x15F5A8,0,8),(0x15F5A8,8,8),(0x15F5BC,0,8),(0x15F5C4,8,8))
                    self.copy_writes.append(dict(native_pc=hex(off),offset=address-self.copy_destination,size=size))
                if self.copy_entered and address==self.source_counter:
                    assert (off,bc,size,reg(9))==(0x15F5D4,CALL,4,2)
                    assert int.from_bytes(cpu.mem_read(address,4),'little')==1
                    self.count_writes.append(dict(native_pc=hex(off),size=4,before_u32=1,after_u32=2))
            original(cpu,address,size)
        kwargs['memory_write_observer']=write
        return super().native_runner(*args,**kwargs)

    def exit_boundary(self,cpu,state):
        assert self.exit_done and not self.copy_active
        self.copy_active=True;self.copy_allocations=deepcopy(state['allocator_events_ref'])

    def observe(self,cpu,pc,state):
        self.scope_state=state
        if not self.copy_active:
            super().observe(cpu,pc,state)
            if not self.copy_active:return
        off=pc-self.image
        def reg(n):return cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(n)))
        def raw(a,n):return bytes(cpu.mem_read(a,n))
        def u(a,n=8):return int.from_bytes(raw(a,n),'little')
        bc=u(state['PC_slot'])-self.image
        if off in (0x27E6AC,0x27ED6C):raise AssertionError('unexpected ordinary callback/wrapper RET')
        if off==context.LOAD and bc==ENTRY:
            self.copy_initial_R=[u(state['backing']+i*8) for i in range(32)]
            self.copy_packed_before=raw(self.scope_frame+2848,40)
            assert self.copy_initial_R[17]==self.scope_input
        if off==context.LOAD and bc in LOADS:
            offset,destination,role=LOADS[bc];base=self.image+previous.previous.GOT_BASE if role=='ELF GOT' else self.scope_frame
            value={ENTRY:self.image+TARGET,0xFD2A0:self.scope_frame+2088,0xFD2AC:self.image+WRAPPER}[bc]
            assert (reg(12),reg(13),reg(14),u(reg(12)+reg(13)))==(base,offset,destination,value)
            self.copy_loads.append(dict(bytecode=hex(bc),offset=offset,destination=destination,source=role))
        if off==0x16A5E8 and bc==CALL:
            assert len(self.copy_loads)==3 and len(self.copy_stores)==3
            assert [u(state['backing']+i*8) for i in CHANGED]==[
                self.image+TARGET,self.scope_frame+2088,self.image+WRAPPER,self.scope_frame+2856,self.image+0x28587C]
            assert all(u(state['backing']+i*8)==self.copy_initial_R[i] for i in range(32) if i not in CHANGED)
            after=raw(self.scope_frame+2848,40);assert after[:8]+after[32:]==self.copy_packed_before[:8]+self.copy_packed_before[32:]
        if off==WRAPPER and bc==CALL:
            assert reg(0)==self.scope_frame+2856 and [u(reg(0)+i*8) for i in range(3)]==[
                self.image+TARGET,self.scope_frame+2088,self.scope_input]
            assert u(state['backing']+31*8)==self.image+CALL+4
            self.copy_wrapper_seen=True
        if off==TARGET:
            assert bc==CALL and self.copy_wrapper_seen and reg(0)==self.scope_input and reg(8)==self.scope_frame+2088
            self.copy_destination=reg(8);self.source_pointer=u(reg(0)+24);self.source_counter=u(reg(0)+32)
            assert self.source_pointer and self.source_counter and u(self.source_counter,4)==1
            history=[e for e in self.copy_allocations if (e[0]=='alloc' and e[2]==self.source_counter) or (e[0]=='free' and e[1]==self.source_counter)]
            assert history and history[-1][:2]==['alloc',4]
            self.receiver_before=raw(self.scope_input,88);self.header_before=raw(self.source_pointer,24)
            self.source_count_before=raw(self.source_counter,16);self.destination_before=raw(self.copy_destination-8,32)
            self.copy_table=u(self.image+diagnostics.TABLE);self.copy_table_before=raw(self.copy_table,2048)
            self.copy_index=(self.source_pointer>>4)&255;assert u(self.copy_table+self.copy_index*8)==0
            self.copy_guard_before=raw(self.image+diagnostics.GUARD,8);self.copy_global=u(self.image+diagnostics.GLOBAL_LOCK)
            self.copy_global_before=raw(self.copy_global,48);self.copy_entered=True
        if off==0x15F580 and bc==CALL:
            assert self.copy_entered and reg(0)==self.copy_destination and reg(1)==self.scope_input+24
            self.copy_body_seen=True
        if self.copy_entered and bc==CALL and off in (0x347F00,0x347F10):
            self.copy_events.append(('lock' if off==0x347F00 else 'unlock',reg(0)))
        if off==STOP and bc==CALL:
            assert self.copy_body_seen and reg(0)==0
            assert raw(self.scope_input,88)==self.receiver_before and raw(self.copy_destination,16)==raw(self.scope_input+24,16)
            assert raw(self.copy_destination-8,8)+raw(self.copy_destination+16,8)==self.destination_before[:8]+self.destination_before[24:]
            assert raw(self.source_pointer,24)==self.header_before
            assert u(self.source_counter,4)==2 and raw(self.source_counter+4,12)==self.source_count_before[4:]
            delta=state['allocator_events_ref'][len(self.copy_allocations):]
            assert len(delta)==1 and delta[0][:2]==['alloc',48] and delta[0][3]=='0x32a210'
            entry=delta[0][2];table=bytearray(self.copy_table_before);table[self.copy_index*8:self.copy_index*8+8]=entry.to_bytes(8,'little')
            assert raw(self.copy_table,2048)==table
            assert raw(entry,48)==(self.image+0x34C738).to_bytes(8,'little')+bytes.fromhex('0040000000000000')+bytes(32)
            assert self.copy_events==[('lock',self.copy_global+8),('unlock',self.copy_global+8),('lock',entry+8),('unlock',entry+8)]
            assert raw(self.image+diagnostics.GUARD,8)==self.copy_guard_before and raw(self.copy_global,48)==self.copy_global_before
            assert raw(self.image+diagnostics.GUARD_MUTEX,40)==bytes(40)
            assert raw(self.scope_owner,264)==self.exit_owner_before and u(self.exit_counter,4)==2
            assert raw(self.exit_counter+4,12)==self.exit_counter_before[4:] and raw(self.scope_object,24)==self.exit_object_before
            assert u(self.scope_frame+1536)==u(self.scope_frame+1552)==0
            assert raw(state['context'],128)==state['handler_bytes'] and u(self.state_owner+0x18)==self.node
            assert raw(self.node,64)==name.previous.previous.empty_bytes()
            assert previous.previous.previous.lookup.tree_projection(raw,self.image,self.container)==self.tree
            assert name.previous.previous.previous.output._cstring(cpu,self.prefix.source)==self.prefix.raw
            assert u(self.image+0x3D1558,1)==1 and u(context.outer.root_fixture.TLS+0x100,4)==2
            self.copy_done=True;self.copy_boundary(cpu,state)

    def copy_boundary(self,cpu,state):
        cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,context.outer.oracle.STOP)

    def finish(self,result,state,proof):
        data=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(data)
        old=next(r for r in data['case_results'] if r['control']==self.control);prefix=proof['kmsv_scope_exit_prefix']
        for k,field in [('instruction_observations','continuation_instruction_observations'),('trace_sha256','continuation_trace_sha256'),
            ('code_sha256','continuation_code_sha256')]:assert prefix[k]==old[field]
        assert self.copy_done and graph.digest(self.copy_allocations)==old['allocation_ledger_sha256']
        assert result['allocator_events'][:len(self.copy_allocations)]==self.copy_allocations
        expected=deepcopy(old['allocator_counts']);expected['malloc']+=1
        assert result['actual_allocator_counts']==expected and result['explicit_service_counts']==old['service_counts']
        for k in ('JNI_calls','libc_SVC_boundaries','main_image_SVC_boundaries'):assert proof[k]==prefix[k]==old[k]
        return dict(control=self.control,retained_scope_exit_prefix_verified=True,
            retained_prefix_instruction_observations=prefix['instruction_observations'],retained_prefix_trace_sha256=prefix['trace_sha256'],
            retained_prefix_code_sha256=prefix['code_sha256'],argument_projection=argument_projection(),native_loads=self.copy_loads,
            native_packed_stores=self.copy_stores,destination_writes=self.copy_writes,source_counter_writes=self.count_writes,
            source_counter_live_allocation_size=4,selected_copy_projection=copy_projection(),original_getter_body_seen=True,
            actual_X0_u64=0,native_CALL_link_register_offset=hex(CALL+4),
            allocation_ledger_sha256=graph.digest(result['allocator_events']),allocation_delta_sizes=[48],allocator_counts=expected,
            service_counts=result['explicit_service_counts'],JNI_calls=proof['JNI_calls'],libc_SVC_boundaries=proof['libc_SVC_boundaries'],
            main_image_SVC_boundaries=proof['main_image_SVC_boundaries'],
            handler_empty_state_tree_directory_configuration_previous_scope_and_saved_NULLs_unchanged=True,
            registry_guard_at_stop=1,errno_at_stop=2,continuation_instruction_observations=proof['instruction_observations'],
            continuation_trace_sha256=proof['trace_sha256'],continuation_code_sha256=proof['code_sha256'],
            observation_stop_before=hex(STOP),outer_bytecode=hex(CALL),callback_or_ordinary_RET_seen=False)


def replay(path,libc,*,on_case=None,case_controls=None):
    return context.replay(path,libc,on_case=on_case,case_controls=case_controls,_extension_factory=Scenario,
        _request_profile=name.previous.previous.PROFILE['name'],_handler_read_profile=context.NULL_PAYLOAD_READ_PROFILE['name'])


def verify_images(data,path,libc):
    from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
    previous.verify_images({},path,libc);elf,_,read=graph.inputs.load_elf(path);decoder=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
    for a,m,s in EXPECTED:
        ins,=decoder.disasm(read(a,4),a);assert (ins.mnemonic,ins.op_str)==(m,s),hex(a)
    for a,w in WORDS:assert int.from_bytes(read(a,4),'little')==w,hex(a)
    rel=[r for s in elf.iter_sections() if s['sh_type']=='SHT_RELA' for r in s.iter_relocations() if r['r_offset']==GOT_SLOT]
    assert len(rel)==1 and rel[0]['r_info_type']==1027 and rel[0]['r_addend']==TARGET
    assert interpreter_projection(path)==[dict(image_base=hex(b),projection=argument_projection()) for b in graph.BASES]
    assert model_projection()==copy_projection()
    return dict(instruction_bindings=len(EXPECTED),bytecode_words=len(WORDS),GOT_relative_relocation_verified=True,
        independent_Python_VM_cases=2,independent_Python_reference_copy_verified=True)


def validate(data):
    assert data['schema']=='vm9-native-171-contained-reference-20261119-v1' and data['claims']==CLAIMS and data['providers']==providers()
    assert data['instructions']==[dict(offset=hex(a),mnemonic=m,operands=s) for a,m,s in EXPECTED]
    assert data['bytecode_words']==[dict(offset=hex(a),word=hex(w)) for a,w in WORDS]
    assert data['independent_Python_projection']==model_projection()
    assert data['independent_Python_VM_projection']==[dict(image_base=hex(b),projection=argument_projection()) for b in graph.BASES]
    old_data=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(old_data)
    assert data['provenance']==old_data['provenance'] and len(data['case_results'])==len(context.controls())
    for row,old in zip(data['case_results'],old_data['case_results']):
        assert row['control']==old['control'] and row['retained_scope_exit_prefix_verified'] is True
        for k,field in [('retained_prefix_instruction_observations','continuation_instruction_observations'),
            ('retained_prefix_trace_sha256','continuation_trace_sha256'),('retained_prefix_code_sha256','continuation_code_sha256')]:assert row[k]==old[field]
        assert row['argument_projection']==argument_projection()
        assert row['native_loads']==[dict(bytecode=hex(a),offset=o,destination=d,source=s) for a,(o,d,s) in LOADS.items()]
        assert row['native_packed_stores']==[dict(cursor_bytecode=hex(a),frame_offset=o,size=8) for a,o in ((0xFD2A0,2872),(0xFD2A8,2864),(0xFD2AC,2856))]
        assert row['destination_writes']==[dict(native_pc=hex(a),offset=o,size=8) for a,o in ((0x15F5A8,0),(0x15F5A8,8),(0x15F5BC,0),(0x15F5C4,8))]
        assert row['source_counter_writes']==[dict(native_pc='0x15f5d4',size=4,before_u32=1,after_u32=2)]
        assert row['source_counter_live_allocation_size']==4 and row['selected_copy_projection']==copy_projection()
        assert row['original_getter_body_seen'] is True and row['actual_X0_u64']==0 and row['native_CALL_link_register_offset']==hex(CALL+4)
        assert row['handler_empty_state_tree_directory_configuration_previous_scope_and_saved_NULLs_unchanged'] is True
        assert graph.inputs.is_digest(row['allocation_ledger_sha256']) and row['allocation_delta_sizes']==[48]
        counts=deepcopy(old['allocator_counts']);counts['malloc']+=1;assert row['allocator_counts']==counts
        for k in ('service_counts','JNI_calls','libc_SVC_boundaries','main_image_SVC_boundaries'):assert row[k]==old[k]
        assert row['registry_guard_at_stop']==1 and row['errno_at_stop']==2 and row['callback_or_ordinary_RET_seen'] is False
        assert row['observation_stop_before']==hex(STOP) and row['outer_bytecode']==hex(CALL)
        assert row['continuation_instruction_observations']>old['continuation_instruction_observations']
        for k in ('continuation_trace_sha256','continuation_code_sha256'):assert graph.inputs.is_digest(row[k])


def negatives(data):
    count=0
    def reject(path,value):
        nonlocal count
        bad=deepcopy(data);target=bad
        for k in path[:-1]:target=target[k]
        target[path[-1]]=value
        try:validate(bad)
        except AssertionError:count+=1
        else:raise AssertionError('damaged contained-reference evidence accepted: '+str(path))
    for k,v in CLAIMS.items():reject(('claims',k),not v)
    reject(('providers','maximum_handler_reads'),3);reject(('providers','maximum_main_SVCs'),5)
    reject(('instructions',0,'mnemonic'),'nop');reject(('bytecode_words',0,'word'),'0x0')
    for i in range(len(data['case_results'])):
        changes=[(('retained_scope_exit_prefix_verified',),False),(('retained_prefix_trace_sha256',),'0'*64),
            (('argument_projection','receiver_member_offset'),32),(('argument_projection','destination_frame_offset'),2096),
            (('native_loads',),[]),(('native_packed_stores',),[]),(('destination_writes',),[]),
            (('source_counter_writes',0,'after_u32'),1),(('source_counter_live_allocation_size',),8),
            (('original_getter_body_seen',),False),(('actual_X0_u64',),1),(('native_CALL_link_register_offset',),hex(CALL)),
            (('allocation_ledger_sha256',),'bad'),(('allocation_delta_sizes',),[]),(('allocator_counts','malloc'),0),
            (('service_counts','syscall_226'),0),(('JNI_calls',),[]),(('libc_SVC_boundaries',),[]),(('main_image_SVC_boundaries',),[]),
            (('handler_empty_state_tree_directory_configuration_previous_scope_and_saved_NULLs_unchanged',),False),
            (('registry_guard_at_stop',),0),(('errno_at_stop',),17),(('callback_or_ordinary_RET_seen',),True),
            (('observation_stop_before',),'0x0'),(('outer_bytecode',),'0xfd290'),(('continuation_instruction_observations',),0)]
        for k,v in copy_projection().items():
            changes.append((('selected_copy_projection',k),not v if isinstance(v,bool) else ([] if isinstance(v,list) else 'bad')))
        for path,value in changes:reject(('case_results',i)+path,value)
    return count


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--elf',type=Path);ap.add_argument('--libc',type=Path);ap.add_argument('--replay',action='store_true')
    args=ap.parse_args()
    if args.replay and (not args.elf or not args.libc):ap.error('--replay requires --elf and --libc')
    data=json.loads(EVIDENCE.read_text(encoding='utf-8'));validate(data)
    result=dict(retained_reference_copy_cases=len(data['case_results']),damaged_evidence_rejected=negatives(data),
        KMSV_value_generated=False,ordinary_Cronet_six_headers_verified=False,complete_standalone_signer_verified=False)
    if args.elf:result['image_bindings']=verify_images(data,args.elf,args.libc)
    elif args.libc:graph.inputs.libc_image(args.libc)
    if args.replay:
        assert replay(args.elf,args.libc)==data['case_results'],'frozen reference copy replay differs'
        result['original_code_cases_replayed']=len(data['case_results'])
    print(json.dumps(result))


if __name__=='__main__':main()
