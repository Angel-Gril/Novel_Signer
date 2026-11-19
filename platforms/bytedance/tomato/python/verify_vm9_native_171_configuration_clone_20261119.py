"""Original request copies the configuration reference's string by its length.

The Python VM and string owner use fresh declared pages, never native bytes.
Only selected copy semantics are compared; configuration value provenance,
physical stack equivalence and a complete signer are outside this boundary.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
from unicorn import arm64_const as arm
import verify_vm9_native_171_contained_reference_20261119 as previous
import vm9_objects as objects

context,graph,name,diagnostics=previous.context,previous.graph,previous.name,previous.diagnostics
EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_configuration_clone_20261119.json')
ENTRY,CALL,STOP=0xFD2B8,0xFD2DC,0x16AA4C
TARGET,WRAPPER,GOT_SLOT=0x2483E0,0x285B44,0x382D00
GOT_BASE=previous.previous.previous.GOT_BASE
DECLARED_PAYLOAD=b'clone\0test'
WORDS=[(ENTRY,0x8F4A8A0F),(0xFD2BC,0x89040018),(0xFD2C0,0x93411218),
    (0xFD2C4,0x935888DA),(0xFD2C8,0x935E0C18),(0xFD2CC,0x935088DA),
    (0xFD2D0,0x8B4888DA),(0xFD2D4,0xA35E0818),(0xFD2D8,0x05C19B11),(CALL,0x067E0C91)]
EXPECTED=[(context.LOAD,'ldr','x9, [x12, x13]'),(0x171268,'str','x15, [x17, x16]'),
    (WRAPPER,'ldp','x8, x1, [x0, #8]'),(0x285B48,'ldr','x2, [x0]'),
    (0x285B4C,'mov','x0, x8'),(0x285B50,'br','x2'),
    (TARGET,'stp','x29, x30, [sp, #-0x30]!'),(0x2483F0,'ldr','w19, [x1, #0xc]'),
    (0x248400,'add','w0, w19, #1'),(0x248404,'str','x8, [x21]'),
    (0x248408,'str','xzr, [x21, #0x10]'),(0x24840C,'stp','w0, w19, [x21, #8]'),
    (0x248410,'tbnz','w19, #0x1f, #0x248438'),(0x248418,'bl','#0x347fd0'),
    (0x24841C,'str','x0, [x21, #0x10]'),(0x248420,'cbz','x0, #0x248438'),
    (0x248424,'ldr','x1, [x20, #0x10]'),(0x248428,'mov','x2, x19'),
    (0x248430,'bl','#0x347f60'),(0x248434,'strb','wzr, [x22, x19]'),
    (0x248444,'ret',''),(STOP,'ldp','x5, x1, [x29, #-0x90]')]
LOADS={0xFD2BC:(128,1,'ELF GOT'),0xFD2C0:(2088,2,'frame'),
    0xFD2C8:(2000,2,'frame'),0xFD2D4:(1984,4,'frame')}
CHANGED=(1,2,4,5,25)
CLAIMS=dict(retained_reference_instruction_code_and_allocation_prefix_verified=True,
    original_nine_argument_bytecodes_match_independent_fresh_VM=True,
    original_clone_source_is_copied_configuration_reference_pointer=True,
    original_clone_reads_declared_u32_length_and_appends_zero=True,
    original_clone_allocates11_and_preserves_source_and_neighbors=True,
    original_allocation_return_PC_not_BL_recorded=True,
    fresh_independent_Python_clone_selected_semantics_match=True,
    retained_service_JNI_and_SVC_ledgers_unchanged=True,native_memory_used_as_model_input=False,
    native_and_independent_model_payload_bytes_equal=False,
    new_OS_JNI_or_internal_helper_providers=False,complete_configuration_value_provenance_verified=False,
    full_VM_or_physical_stack_equivalence_verified=False,clone_return_consumed=False,
    saved_NULL_business_branch_verified=False,KMSV_value_generated=False,client_key_value_generated=False,
    real_business_cache_restored=False,real_JVM_identity_verified=False,ordinary_Cronet_six_headers_verified=False,
    whole_request_equivalence_verified=False,callback_or_ordinary_wrapper_returned=False,
    complete_standalone_signer_verified=False,Android_execution=False,online_acceptance_verified=False)


def argument_projection():
    return dict(executed_bytecodes=[hex(a) for a,_ in WORDS[:-1]],
        source='pointer in copied reference at frame+2088',source_pointer_frame_offset=2088,
        destination_frame_offset=5016,destination_pointer_source_frame_offset=2000,
        wrapper_source_frame_offset=1984,GOT_slot_offset=hex(GOT_SLOT),target_offset=hex(TARGET),
        wrapper_offset=hex(WRAPPER),packed_frame_offset=3624,
        packed_words=['image+0x2483e0','frame+5016','copied source object pointer'],
        selected_registers=dict(R1='image+0x2483e0',R2='frame+5016',R4='image+0x285b44',
            R5='frame+3624',R25='image+0x28587c'),
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
            vm_module.B=image;m=Memory();frame=0x60000000;source=0x61000000
            m.put(frame,b'\xa5'*0x2000);m.w64(frame+2088,source);m.w64(frame+2000,frame+5016)
            m.w64(frame+1984,image+WRAPPER);m.w64(image+GOT_SLOT,image+TARGET)
            for a,w in WORDS:m.put(image+a,w.to_bytes(4,'little'))
            before_frame=name._read_span(m.pages,frame,0x2000)
            vm=vm_module.VM(m,ENTRY,0,0,0,0,0,maxsteps=10)
            vm.R=[0xA5A5000000000000+i for i in range(32)]
            vm.R[0]=0;vm.R[20]=image+GOT_BASE;vm.R[23]=image+0x28587C
            vm.R[29]=frame;vm.R[31]=image+ENTRY
            before=list(vm.R);steps=[]
            def step(vm,dw,op,sub):
                if vm.pc==image+CALL:raise Boundary()
                assert (vm.pc-image,dw)==WORDS[len(steps)];steps.append(hex(vm.pc-image))
            vm.step_hook=step
            try:vm.run()
            except Boundary:pass
            else:raise AssertionError('clone arguments did not stop before CALL')
            assert steps==argument_projection()['executed_bytecodes']
            assert [vm.R[i] for i in CHANGED]==[image+TARGET,frame+5016,image+WRAPPER,frame+3624,image+0x28587C]
            assert all(vm.R[i]==before[i] for i in range(32) if i not in CHANGED)
            assert [m.u64(frame+3624+i*8) for i in range(3)]==[image+TARGET,frame+5016,source]
            after=name._read_span(m.pages,frame,0x2000)
            assert all(a==b for i,(a,b) in enumerate(zip(before_frame,after)) if not 3624<=i<3648)
            rows.append(dict(image_base=hex(image),projection=argument_projection()))
    finally:vm_module.B=saved_base
    return rows


def clone_projection():
    return dict(length_u32=10,capacity_u32=11,vtable_offset='0x34f5f8',
        copied_exact_declared_length=True,zero_appended_at_declared_length=True,
        payload_distinct_from_source=True,source_header24_and_payload_preserved=True,
        destination_adjacent16_bytes_preserved=True,source_reference_count_preserved=True,
        actual_X0_equals_new_payload=True,added_allocation_sizes=[11])


def model_projection():
    image=0x10000000;destination=0x60000100;source=0x61000100;payload=0x62000100;allocated=0x63000100
    reference=0x64000100;counter=0x65000100
    pages={};put=lambda a,b:name.put(pages,a,b)
    read=lambda a,n:name._read_span(pages,a,n)
    def w(a,v,n=8):put(a,int(v).to_bytes(n,'little'))
    put(source,b'\xa5'*24);w(source,image+0x34F5F8);w(source+8,11,4);w(source+12,10,4);w(source+16,payload)
    put(payload,DECLARED_PAYLOAD+b'\0');put(destination-8,b'\xa5'*40);put(allocated,b'\xa5'*16)
    w(reference,source);w(reference+8,counter);put(counter,b'\xa5'*16);w(counter,2,4)
    reference_before=read(reference,16);counter_before=read(counter,16)
    source_before=read(source,24);payload_before=read(payload,11);adjacent=read(destination-8,40)
    allocations=[]
    def allocate(p,size):
        assert size==11 and not allocations;allocations.append(size);return allocated
    result=objects.clone_string_object(pages,object_address=destination,source_object_address=source,allocate=allocate,image_base=image)
    assert result==allocated and read(destination,24)==(image+0x34F5F8).to_bytes(8,'little')+(11).to_bytes(4,'little')+(10).to_bytes(4,'little')+allocated.to_bytes(8,'little')
    assert read(allocated,11)==DECLARED_PAYLOAD+b'\0' and read(allocated+11,5)==b'\xa5'*5
    assert allocated!=payload and read(source,24)==source_before and read(payload,11)==payload_before
    assert read(reference,16)==reference_before and read(counter,16)==counter_before
    assert read(destination-8,8)+read(destination+24,8)==adjacent[:8]+adjacent[32:]
    assert allocations==[11]
    return clone_projection()


def providers():
    return dict(inherited_reference=previous.providers(),maximum_handler_reads=2,maximum_main_SVCs=4,
        independent_model_owners=['vm_full.py:VM.run','vm9_objects.py:clone_string_object'],
        independent_model_input='fresh declared frame and length10 string containing an embedded zero; independent payload bytes',
        compared_scope='selected length, copy, terminator, allocation and preservation semantics; not equal source bytes',
        allocation_deltas=dict(malloc=1,sizes=[11],BL_offset='0x248418',ledger_return_PC='0x24841c'),
        service_count_deltas={},new_OS_JNI_or_internal_helper_providers=[],stop_before=hex(STOP),outer_bytecode=hex(CALL))


class Scenario(previous.Scenario):
    def __init__(self,c):
        super().__init__(c);self.clone_active=False;self.clone_entered=False;self.clone_done=False
        self.clone_loads=[];self.clone_stores=[];self.clone_writes=[];self.clone_entry_seen=False

    def native_runner(self,*args,**kwargs):
        original=kwargs['memory_write_observer']
        def write(cpu,address,size):
            if self.clone_active:
                def reg(n):return cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(n)))
                off=cpu.reg_read(arm.UC_ARM64_REG_PC)-self.image
                bc=int.from_bytes(cpu.mem_read(self.scope_state['PC_slot'],8),'little')-self.image
                if self.scope_frame+3624<=address<self.scope_frame+3648:
                    expected={0xFD2C8:(3640,self.source_pointer),0xFD2D0:(3632,self.scope_frame+5016),0xFD2D4:(3624,self.image+TARGET)}
                    offset,value=expected[bc]
                    assert (off,address,size,reg(15))==(0x171268,self.scope_frame+offset,8,value)
                    self.clone_stores.append(dict(cursor_bytecode=hex(bc),frame_offset=offset,size=8))
                if self.clone_entered and self.clone_destination<=address<self.clone_destination+24:
                    assert bc==CALL and (off,address-self.clone_destination,size) in (
                        (0x248404,0,8),(0x248408,16,8),(0x24840C,8,4),(0x24840C,12,4),(0x24841C,16,8))
                    self.clone_writes.append(dict(native_pc=hex(off),offset=address-self.clone_destination,size=size))
            original(cpu,address,size)
        kwargs['memory_write_observer']=write
        return super().native_runner(*args,**kwargs)

    def copy_boundary(self,cpu,state):
        assert self.copy_done and not self.clone_active
        self.clone_active=True;self.clone_allocations=deepcopy(state['allocator_events_ref'])
        raw=lambda a,n:bytes(cpu.mem_read(a,n))
        self.clone_table_before=raw(self.copy_table,2048);self.clone_entry_before=raw(int.from_bytes(raw(self.copy_table+self.copy_index*8,8),'little'),48)
        self.clone_receiver_before=raw(self.scope_input,88);self.clone_reference_before=raw(self.copy_destination,16)
        self.clone_count_before=raw(self.source_counter,16)

    def observe(self,cpu,pc,state):
        self.scope_state=state
        if not self.clone_active:
            super().observe(cpu,pc,state)
            if not self.clone_active:return
        off=pc-self.image
        def reg(n):return cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(n)))
        def raw(a,n):return bytes(cpu.mem_read(a,n))
        def u(a,n=8):return int.from_bytes(raw(a,n),'little')
        bc=u(state['PC_slot'])-self.image
        if off in (0x27E6AC,0x27ED6C):raise AssertionError('unexpected ordinary callback/wrapper RET')
        if off==context.LOAD and bc==0xFD2BC:
            self.clone_initial_R=[u(state['backing']+i*8) for i in range(32)]
            self.clone_packed_before=raw(self.scope_frame+3616,40)
        if off==context.LOAD and bc in LOADS:
            offset,destination,role=LOADS[bc];base=self.image+GOT_BASE if role=='ELF GOT' else self.scope_frame
            value={0xFD2BC:self.image+TARGET,0xFD2C0:self.source_pointer,0xFD2C8:self.scope_frame+5016,0xFD2D4:self.image+WRAPPER}[bc]
            assert (reg(12),reg(13),reg(14),u(reg(12)+reg(13)))==(base,offset,destination,value)
            self.clone_loads.append(dict(bytecode=hex(bc),offset=offset,destination=destination,source=role))
        if off==0x16A5E8 and bc==CALL:
            assert len(self.clone_loads)==4 and len(self.clone_stores)==3
            assert [u(state['backing']+i*8) for i in CHANGED]==[
                self.image+TARGET,self.scope_frame+5016,self.image+WRAPPER,self.scope_frame+3624,self.image+0x28587C]
            assert all(u(state['backing']+i*8)==self.clone_initial_R[i] for i in range(32) if i not in CHANGED)
            after=raw(self.scope_frame+3616,40);assert after[:8]+after[32:]==self.clone_packed_before[:8]+self.clone_packed_before[32:]
        if off==WRAPPER and bc==CALL:
            assert reg(0)==self.scope_frame+3624 and [u(reg(0)+i*8) for i in range(3)]==[
                self.image+TARGET,self.scope_frame+5016,self.source_pointer]
            assert u(state['backing']+31*8)==self.image+CALL+4;self.clone_entry_seen=True
        if off==TARGET and bc==CALL:
            assert self.clone_entry_seen and reg(0)==self.scope_frame+5016 and reg(1)==self.source_pointer and reg(30)==self.image+STOP
            self.clone_destination=reg(0);self.clone_source=reg(1);self.clone_entered=True
            self.clone_header_before=raw(reg(1),24);self.clone_length=u(reg(1)+12,4);assert self.clone_length==10
            self.clone_source_payload=u(reg(1)+16);self.clone_payload_before=raw(self.clone_source_payload,11)
            self.clone_destination_before=raw(reg(0)-8,40)
        if self.clone_entered and off==0x347FD0:
            assert bc==CALL and reg(30)==self.image+0x24841C and reg(0)==11;self.clone_malloc_seen=True
        if self.clone_entered and off==0x347F60:
            assert bc==CALL and reg(30)==self.image+0x248434 and reg(1)==self.clone_source_payload and reg(2)==10
            self.clone_new_payload=reg(0);self.clone_memcpy_seen=True
        if self.clone_entered and off==0x248434:
            assert self.clone_memcpy_seen and reg(22)==self.clone_new_payload and reg(19)==10
            assert raw(self.clone_new_payload,10)==self.clone_payload_before[:10];self.clone_terminator_seen=True
        if off==STOP and bc==CALL:
            assert self.clone_entered and self.clone_malloc_seen and self.clone_terminator_seen
            a=self.clone_destination;new=self.clone_new_payload
            assert u(a)==self.image+0x34F5F8 and u(a+8,4)==11 and u(a+12,4)==10 and u(a+16)==new
            assert new!=self.clone_source_payload and reg(0)==new and raw(new,11)==self.clone_payload_before[:10]+b'\0'
            assert raw(self.clone_source,24)==self.clone_header_before and raw(self.clone_source_payload,11)==self.clone_payload_before
            assert raw(a-8,8)+raw(a+24,8)==self.clone_destination_before[:8]+self.clone_destination_before[32:]
            assert state['allocator_events_ref'][len(self.clone_allocations):]==[['alloc',11,new,'0x24841c']]
            assert raw(self.scope_input,88)==self.clone_receiver_before and raw(self.copy_destination,16)==self.clone_reference_before
            assert raw(self.source_counter,16)==self.clone_count_before and u(self.source_counter,4)==2
            assert raw(self.copy_table,2048)==self.clone_table_before and raw(u(self.copy_table+self.copy_index*8),48)==self.clone_entry_before
            assert raw(self.image+diagnostics.GUARD,8)==self.copy_guard_before and raw(self.copy_global,48)==self.copy_global_before
            assert raw(self.image+diagnostics.GUARD_MUTEX,40)==bytes(40)
            assert raw(self.scope_owner,264)==self.exit_owner_before and u(self.exit_counter,4)==2
            assert raw(self.exit_counter+4,12)==self.exit_counter_before[4:] and raw(self.scope_object,24)==self.exit_object_before
            assert u(self.scope_frame+1536)==u(self.scope_frame+1552)==0
            assert raw(state['context'],128)==state['handler_bytes'] and u(self.state_owner+0x18)==self.node
            assert raw(self.node,64)==name.previous.previous.empty_bytes()
            assert previous.previous.previous.previous.lookup.tree_projection(raw,self.image,self.container)==self.tree
            assert name.previous.previous.previous.output._cstring(cpu,self.prefix.source)==self.prefix.raw
            assert u(self.image+0x3D1558,1)==1 and u(context.outer.root_fixture.TLS+0x100,4)==2
            self.clone_done=True;self.clone_boundary(cpu,state)

    def clone_boundary(self,cpu,state):
        cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,context.outer.oracle.STOP)

    def finish(self,result,state,proof):
        data=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(data)
        old=next(r for r in data['case_results'] if r['control']==self.control);prefix=proof['contained_reference_prefix']
        for k,field in [('instruction_observations','continuation_instruction_observations'),('trace_sha256','continuation_trace_sha256'),
            ('code_sha256','continuation_code_sha256')]:assert prefix[k]==old[field]
        assert self.clone_done and graph.digest(self.clone_allocations)==old['allocation_ledger_sha256']
        assert result['allocator_events'][:len(self.clone_allocations)]==self.clone_allocations
        assert result['allocator_events'][len(self.clone_allocations):]==[['alloc',11,self.clone_new_payload,'0x24841c']]
        expected=deepcopy(old['allocator_counts']);expected['malloc']+=1
        assert result['actual_allocator_counts']==expected and result['explicit_service_counts']==old['service_counts']
        for k in ('JNI_calls','libc_SVC_boundaries','main_image_SVC_boundaries'):assert proof[k]==prefix[k]==old[k]
        return dict(control=self.control,retained_reference_prefix_verified=True,
            retained_prefix_instruction_observations=prefix['instruction_observations'],retained_prefix_trace_sha256=prefix['trace_sha256'],
            retained_prefix_code_sha256=prefix['code_sha256'],argument_projection=argument_projection(),native_loads=self.clone_loads,
            native_packed_stores=self.clone_stores,destination_writes=self.clone_writes,selected_clone_projection=clone_projection(),
            original_clone_body_seen=True,source_payload_length=10,source_payload_sha256=hashlib.sha256(self.clone_payload_before[:10]).hexdigest(),
            actual_X0_is_new_payload=True,native_CALL_link_register_offset=hex(CALL+4),
            allocation_ledger_sha256=graph.digest(result['allocator_events']),allocation_delta_sizes=[11],allocation_ledger_return_PC='0x24841c',
            allocator_counts=expected,service_counts=result['explicit_service_counts'],JNI_calls=proof['JNI_calls'],
            libc_SVC_boundaries=proof['libc_SVC_boundaries'],main_image_SVC_boundaries=proof['main_image_SVC_boundaries'],
            handler_empty_state_tree_directory_configuration_reference_locks_and_saved_NULLs_unchanged=True,
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
    assert model_projection()==clone_projection()
    return dict(instruction_bindings=len(EXPECTED),bytecode_words=len(WORDS),GOT_relative_relocation_verified=True,
        independent_Python_VM_cases=2,independent_Python_clone_selected_semantics_verified=True)


def validate(data):
    assert data['schema']=='vm9-native-171-configuration-clone-20261119-v1' and data['claims']==CLAIMS and data['providers']==providers()
    assert data['instructions']==[dict(offset=hex(a),mnemonic=m,operands=s) for a,m,s in EXPECTED]
    assert data['bytecode_words']==[dict(offset=hex(a),word=hex(w)) for a,w in WORDS]
    assert data['independent_Python_projection']==model_projection()
    assert data['independent_Python_VM_projection']==[dict(image_base=hex(b),projection=argument_projection()) for b in graph.BASES]
    old_data=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(old_data)
    assert data['provenance']==old_data['provenance'] and len(data['case_results'])==len(context.controls())
    for row,old in zip(data['case_results'],old_data['case_results']):
        assert row['control']==old['control'] and row['retained_reference_prefix_verified'] is True
        for k,field in [('retained_prefix_instruction_observations','continuation_instruction_observations'),
            ('retained_prefix_trace_sha256','continuation_trace_sha256'),('retained_prefix_code_sha256','continuation_code_sha256')]:assert row[k]==old[field]
        assert row['argument_projection']==argument_projection()
        assert row['native_loads']==[dict(bytecode=hex(a),offset=o,destination=d,source=s) for a,(o,d,s) in LOADS.items()]
        assert row['native_packed_stores']==[dict(cursor_bytecode=hex(a),frame_offset=o,size=8) for a,o in ((0xFD2C8,3640),(0xFD2D0,3632),(0xFD2D4,3624))]
        assert row['destination_writes']==[dict(native_pc=hex(a),offset=o,size=s) for a,o,s in (
            (0x248404,0,8),(0x248408,16,8),(0x24840C,8,4),(0x24840C,12,4),(0x24841C,16,8))]
        assert row['selected_clone_projection']==clone_projection() and row['original_clone_body_seen'] is True
        assert row['source_payload_length']==10 and graph.inputs.is_digest(row['source_payload_sha256'])
        assert row['actual_X0_is_new_payload'] is True and row['native_CALL_link_register_offset']==hex(CALL+4)
        assert row['handler_empty_state_tree_directory_configuration_reference_locks_and_saved_NULLs_unchanged'] is True
        assert graph.inputs.is_digest(row['allocation_ledger_sha256']) and row['allocation_delta_sizes']==[11]
        assert row['allocation_ledger_return_PC']=='0x24841c'
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
        else:raise AssertionError('damaged configuration clone evidence accepted: '+str(path))
    for k,v in CLAIMS.items():reject(('claims',k),not v)
    reject(('providers','maximum_handler_reads'),3);reject(('providers','maximum_main_SVCs'),5)
    reject(('instructions',0,'mnemonic'),'nop');reject(('bytecode_words',0,'word'),'0x0')
    for i in range(len(data['case_results'])):
        changes=[(('retained_reference_prefix_verified',),False),(('retained_prefix_trace_sha256',),'0'*64),
            (('argument_projection','source_pointer_frame_offset'),2096),(('argument_projection','destination_frame_offset'),5024),
            (('native_loads',),[]),(('native_packed_stores',),[]),(('destination_writes',),[]),
            (('original_clone_body_seen',),False),(('source_payload_length',),11),(('source_payload_sha256',),'bad'),
            (('actual_X0_is_new_payload',),False),(('native_CALL_link_register_offset',),hex(CALL)),
            (('allocation_ledger_sha256',),'bad'),(('allocation_delta_sizes',),[]),(('allocation_ledger_return_PC',),'0x248418'),
            (('allocator_counts','malloc'),0),(('service_counts','syscall_226'),0),(('JNI_calls',),[]),
            (('libc_SVC_boundaries',),[]),(('main_image_SVC_boundaries',),[]),
            (('handler_empty_state_tree_directory_configuration_reference_locks_and_saved_NULLs_unchanged',),False),
            (('registry_guard_at_stop',),0),(('errno_at_stop',),17),(('callback_or_ordinary_RET_seen',),True),
            (('observation_stop_before',),'0x0'),(('outer_bytecode',),'0xfd2b4'),(('continuation_instruction_observations',),0)]
        for k,v in clone_projection().items():
            changes.append((('selected_clone_projection',k),not v if isinstance(v,bool) else ([] if isinstance(v,list) else 'bad')))
        for path,value in changes:reject(('case_results',i)+path,value)
    return count


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--elf',type=Path);ap.add_argument('--libc',type=Path);ap.add_argument('--replay',action='store_true')
    args=ap.parse_args()
    if args.replay and (not args.elf or not args.libc):ap.error('--replay requires --elf and --libc')
    data=json.loads(EVIDENCE.read_text(encoding='utf-8'));validate(data)
    result=dict(retained_configuration_clone_cases=len(data['case_results']),damaged_evidence_rejected=negatives(data),
        KMSV_value_generated=False,ordinary_Cronet_six_headers_verified=False,complete_standalone_signer_verified=False)
    if args.elf:result['image_bindings']=verify_images(data,args.elf,args.libc)
    elif args.libc:graph.inputs.libc_image(args.libc)
    if args.replay:
        assert replay(args.elf,args.libc)==data['case_results'],'frozen configuration clone replay differs'
        result['original_code_cases_replayed']=len(data['case_results'])
    print(json.dumps(result))


if __name__=='__main__':main()
