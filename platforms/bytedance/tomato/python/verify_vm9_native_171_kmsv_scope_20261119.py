"""Original KMSV NULL spill, configured scope input and cold diagnostic lock.

Preserve the accepted KMSV prefix. Enable the existing original diagnostic
oracle option only at this scope's entry. Independent models use declared
fresh pages, never native memory. Stop before consuming the scope return.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path

from unicorn import arm64_const as arm
import verify_vm9_native_171_kmsv_lookup_20261119 as previous
import vm9_diagnostics as diagnostics

context=previous.context
graph=previous.graph
name=previous.name
EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_kmsv_scope_20261119.json')
ENTRY,CALL,STOP=0xFD22C,0xFD258,0x16AA4C
TARGET,WRAPPER,GOT_BASE,GOT_SLOT=0x26C858,0x2858D0,0x382C80,0x382E48
WORDS=[(0xFD22C,0x8B4D1C18),(0xFD230,0x8B40805A),(0xFD234,0x934A380F),
    (0xFD238,0x890E0218),(0xFD23C,0x83760C18),(0xFD240,0x90050018),
    (0xFD244,0x9350391A),(0xFD248,0x8B68391A),(0xFD24C,0x8B40391A),
    (0xFD250,0x05804B11),(0xFD254,0x05C19B11),(CALL,0x067E0C91)]
EXPECTED=[(0x16F96C,'ldr','x9, [x12, x13]'),(0x16F974,'str','x9, [x28, x14, lsl #3]'),
    (0x171268,'str','x15, [x17, x16]'),(0x16A5E8,'eor','x11, x11, x4'),
    (0x2858D0,'ldp','x8, x1, [x0, #8]'),
    (0x2858D4,'ldr','x2, [x0]'),(0x2858D8,'mov','x0, x8'),(0x2858DC,'br','x2'),
    (TARGET,'sub','sp, sp, #0x60'),(0x26C85C,'stp','x29, x30, [sp, #0x20]'),
    (0x26C89C,'str','x9, [x0]'),(0x26C8A0,'str','w10, [x0, #8]'),
    (0x26C8A4,'str','x1, [x0, #0x10]'),(0x26C8AC,'tbz','w8, #0, #0x26c990'),
    (0x26C90C,'ubfx','x24, x8, #4, #8'),(0x26C94C,'str','x20, [x23, x24, lsl #3]'),
    (0x26C964,'str','w0, [x19, #8]'),(0x26C98C,'ret',''),
    (0x26C998,'bl','#0x32d3a0'),(0x26C9C4,'bl','#0x32d4f8'),
    (STOP,'ldp','x5, x1, [x29, #-0x90]')]
LOADS={0xFD22C:(3504,1,'frame'),0xFD238:(456,1,'ELF GOT'),
    0xFD23C:(1744,16,'frame'),0xFD240:(160,2,'configuration')}
STORES={0xFD230:(1536,'NULL'),0xFD244:(4336,'input'),0xFD248:(4328,'scope'),0xFD24C:(4320,'target')}
CHANGED=(1,2,4,5,16,25)
CLAIMS=dict(
    retained_KMSV_instruction_code_and_allocation_prefix_verified=True,
    original_KMSV_NULL_extracted_and_saved_to_frame=True,
    scope_input_loaded_from_configuration_member_A0=True,
    original_eleven_argument_bytecodes_match_independent_fresh_VM=True,
    original_diagnostic_body_and_matching_Bionic_mutexes_executed=True,
    existing_diagnostic_oracle_flag_enabled_only_at_selected_entry=True,
    cold_guard_table_entry_and_locked_scope_match_fresh_Python_owner=True,
    exact_three_native_allocation_tail_and_unchanged_services_verified=True,
    native_memory_used_as_model_input=False,new_OS_JNI_or_internal_helper_providers=False,
    entire_retained_KMSV_row_reproduced=False,full_VM_or_physical_stack_equivalence_verified=False,
    original_scope_exit_executed=False,scope_return_consumed=False,
    complete_configuration_member_construction_provenance_verified=False,
    saved_NULL_business_branch_verified=False,KMSV_value_generated=False,client_key_value_generated=False,
    real_business_cache_restored=False,real_JVM_identity_verified=False,
    ordinary_Cronet_six_headers_verified=False,whole_request_equivalence_verified=False,
    callback_or_ordinary_wrapper_returned=False,complete_standalone_signer_verified=False,
    Android_execution=False,online_acceptance_verified=False)


def argument_projection():
    return dict(executed_bytecodes=[hex(a) for a,_ in WORDS[:-1]],NULL_source_frame_offset=3504,
        NULL_source_equals_lookup_packed_plus24=True,NULL_spill_frame_offset=1536,NULL_value=0,
        GOT_slot_offset=hex(GOT_SLOT),target_offset=hex(TARGET),configuration_frame_offset=1744,
        configuration_vtable_offset='0x35b688',configuration_member_offset=160,
        input_is_configuration_member=True,input_is_KMSV_NULL=False,
        scope_frame_offset=4920,packed_frame_offset=4320,
        packed_words=['image+0x26c858','frame+4920','configuration+0xa0 pointee'],
        selected_registers=dict(R1='image+0x26c858',R2='configuration+0xa0 pointee',R4='image+0x2858d0',
            R5='frame+4320',R16='configuration',R25='image+0x28587c'),
        unselected_virtual_registers_preserved_before_CALL=True,selected_adjacent_frame_bytes_preserved=True,
        stop_before_bytecode=hex(CALL))


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
        def put(self,a,raw):name.put(self.pages,a,raw)
        def w64(self,a,v):self.put(a,int(v).to_bytes(8,'little'))
    class Boundary(Exception):pass
    saved_base=vm_module.B;rows=[]
    try:
        for image in graph.BASES:
            vm_module.B=image;m=Memory();frame=0x60000000;owner=0x61000000;value=0x62000000
            m.put(frame,b'\xa5'*0x2000);m.put(owner,bytes(264));m.put(value,bytes(88))
            m.w64(owner,image+0x35B688);m.w64(owner+160,value)
            m.w64(frame+3504,0);m.w64(frame+1744,owner);m.w64(image+GOT_SLOT,image+TARGET)
            for a,w in WORDS:m.put(image+a,w.to_bytes(4,'little'))
            before_frame=name._read_span(m.pages,frame,0x2000)
            vm=vm_module.VM(m,ENTRY,0,0,0,image+0x28587C,0,maxsteps=12)
            vm.R=[0xA5A5000000000000+i for i in range(32)]
            vm.R[0]=0;vm.R[17]=frame+4920;vm.R[20]=image+GOT_BASE
            vm.R[22]=image+WRAPPER;vm.R[23]=image+0x28587C;vm.R[29]=frame;vm.R[31]=image+ENTRY
            before=list(vm.R);steps=[]
            def step(vm,dw,op,sub):
                if vm.pc==image+CALL:raise Boundary()
                assert (vm.pc-image,dw)==WORDS[len(steps)];steps.append(hex(vm.pc-image))
            vm.step_hook=step
            try:vm.run()
            except Boundary:pass
            else:raise AssertionError('argument projection did not stop before CALL')
            assert steps==argument_projection()['executed_bytecodes']
            assert [vm.R[i] for i in CHANGED]==[image+TARGET,value,image+WRAPPER,frame+4320,owner,image+0x28587C]
            assert all(vm.R[i]==before[i] for i in range(32) if i not in CHANGED)
            assert m.u64(frame+1536)==0 and [m.u64(frame+4320+i*8) for i in range(3)]==[image+TARGET,frame+4920,value]
            after=name._read_span(m.pages,frame,0x2000)
            selected=set(range(1536,1544))|set(range(4320,4344))
            assert all(a==b for i,(a,b) in enumerate(zip(before_frame,after)) if i not in selected)
            rows.append(dict(image_base=hex(image),projection=argument_projection()))
    finally:vm_module.B=saved_base
    return rows


def scope_projection(read,image,obj,input_word,initial_padding,allocations,events):
    def u(a,n=8):return int.from_bytes(read(a,n),'little')
    global_lock=u(image+diagnostics.GLOBAL_LOCK);table=u(image+diagnostics.TABLE)
    index=(input_word>>4)&255;entry=u(table+index*8)
    assert global_lock and table and entry and [size for size,_ in allocations]==[48,2048,48]
    assert [a for _,a in allocations]==[global_lock,table,entry]
    assert u(obj)==image+0x35D410 and u(obj+16)==input_word and read(obj+12,4)==initial_padding
    assert u(global_lock)==u(entry)==image+0x34C738
    assert read(global_lock+8,40)==bytes(40) and read(image+diagnostics.GUARD_MUTEX,40)==bytes(40)
    assert all(u(table+i*8)==(entry if i==index else 0) for i in range(256))
    assert u(entry+8,4)==0x4001 and u(entry+12,4)==137 and read(entry+16,32)==bytes(32)
    roles={image+diagnostics.GUARD_MUTEX:'guard mutex',global_lock+8:'global mutex',entry+8:'entry mutex'}
    normalized=[[kind,137 if kind=='gettid' else roles[address]] for kind,address in events]
    return dict(scope_vtable_offset='0x35d410',saved_lock_result_u32=u(obj+8,4),
        scope_input_preserved=True,scope_padding_preserved=True,
        guard=name.blob(read(image+diagnostics.GUARD,8)),global_mutex_zero=True,guard_mutex_zero=True,
        allocation_sizes=[size for size,_ in allocations],table_slots=256,selected_table_index=index,
        only_selected_table_slot_populated=True,lock_vtable_offset='0x34c738',
        recursive_mutex_state_u32=u(entry+8,4),recursive_mutex_owner_u32=u(entry+12,4),
        recursive_mutex_other32_bytes_zero=True,normalized_mutex_gettid_events=normalized,
        scope_exit_executed=False,selected_entry_lock_held=True)


def model_projection():
    image=0x10000000;root=0x60000000;obj=root+0x100;input_word=0x62000000;tls=root+0x500;pthread=root+0x600
    pages={p:bytearray(4096) for p in range(root>>12,(root+0x5000)>>12)}
    def put(a,raw):name.put(pages,a,raw)
    def w(a,v,n=8):put(a,int(v).to_bytes(n,'little'))
    put(obj,b'\xa5'*24);put(image+diagnostics.GUARD,bytes(8));put(image+diagnostics.GLOBAL_LOCK,bytes(24))
    put(image+diagnostics.GUARD_MUTEX,bytes(40));w(tls+8,pthread);w(pthread+16,137,4)
    allocations=[];events=[];addresses=[root+0x1000,root+0x2000,root+0x3000]
    def allocate(p,size):
        assert size==[48,2048,48][len(allocations)];address=addresses[len(allocations)]
        put(address,bytes(size));allocations.append((size,address));return address
    scope=diagnostics.enter_diagnostic_scope(pages,object_address=obj,input_word=input_word,image_base=image,
        thread_pointer=tls,thread_id=137,allocate=allocate,observer=lambda *e:events.append(e))
    assert scope.allocation_sizes==(48,2048,48) and scope.lock_result==0 and scope.table_index==0
    return scope_projection(lambda a,n:name._read_span(pages,a,n),image,obj,input_word,b'\xa5'*4,allocations,events)


def providers():
    return dict(inherited_KMSV=previous.providers(),maximum_handler_reads=2,maximum_main_SVCs=4,
        independent_model_owners=['vm_full.py:VM.run','vm9_diagnostics.py:enter_diagnostic_scope'],
        independent_model_input='fresh declared frame, configuration member pointer and zero cold diagnostic pages',
        diagnostic_execution='existing real_diagnostics option deferred until +0x26c858 at outer+0xfd258',
        previous_diagnostic_scopes_original_body_executed=False,thread_id=137,
        allocation_deltas=dict(malloc=3,sizes=[48,2048,48],callsite='0x32a210'),service_count_deltas={},
        new_OS_JNI_or_internal_helper_providers=[],stop_before=hex(STOP),outer_bytecode=hex(CALL))


class Scenario(previous.Scenario):
    def __init__(self,c):
        super().__init__(c);self.scope_active=False;self.original_scope=False;self.scope_body_seen=False
        self.scope_loads=[];self.scope_stores=[];self.scope_mutex_events=[];self.scope_state=None;self.source_writes=[]

    def native_runner(self,*args,**kwargs):
        assert not kwargs.get('real_diagnostics')
        assert kwargs['real_singletons'] and kwargs['real_mutexes'] and kwargs['real_recursive_mutexes'] and kwargs['libc']
        owner=self
        class DiagnosticWindow:
            def __bool__(self):return owner.original_scope
        kwargs['real_diagnostics']=DiagnosticWindow()
        original=kwargs['memory_write_observer']
        def write(cpu,address,size):
            state=self.scope_state
            if state and 'backing' in state:
                def u(a):return int.from_bytes(cpu.mem_read(a,8),'little')
                frame=u(state['backing']+29*8);off=cpu.reg_read(arm.UC_ARM64_REG_PC)-self.image
                if address==frame+1744 and size==8:
                    assert off==0x171268;self.source_writes.append((u(state['PC_slot'])-self.image,cpu.reg_read(arm.UC_ARM64_REG_X15)))
                if self.scope_active and not self.original_scope:
                    if any(address<frame+a+n and frame+a<address+size for a,n in ((1536,8),(4320,24))):
                        bc=u(state['PC_slot'])-self.image-4;offset,role=STORES[bc]
                        values={'NULL':0,'scope':frame+4920,'input':self.scope_input,'target':self.image+TARGET}
                        assert off==0x171268 and size==8 and address==frame+offset
                        assert cpu.reg_read(arm.UC_ARM64_REG_X15)==values[role]
                        self.scope_stores.append(dict(bytecode=hex(bc),cursor_bytecode=hex(bc+4),frame_offset=offset,size=8))
            original(cpu,address,size)
        kwargs['memory_write_observer']=write
        return super().native_runner(*args,**kwargs)

    def kmsv_boundary(self,cpu,state):
        assert self.kmsv_done and not self.scope_active
        def u(a):return int.from_bytes(cpu.mem_read(a,8),'little')
        self.scope_active=True;self.scope_allocations_before=deepcopy(state['allocator_events_ref'])
        self.scope_frame=u(state['backing']+29*8);self.scope_initial_R=[u(state['backing']+i*8) for i in range(32)]
        self.scope_owner=u(self.scope_frame+1744);self.scope_input=u(self.scope_owner+160)
        assert self.scope_frame+3504==self.kmsv_lookup+24 and u(self.scope_frame+3504)==0
        assert u(self.scope_owner)==self.image+0x35B688 and self.scope_input and self.scope_input&4095==0
        assert len(self.source_writes)==2 and self.source_writes[-1]==(0xF8D68,self.scope_owner)
        assert self.scope_initial_R[17]==self.scope_frame+4920 and self.scope_initial_R[20]==self.image+GOT_BASE
        assert self.scope_initial_R[22]==self.image+WRAPPER and self.scope_initial_R[23]==self.image+0x28587C
        self.scope_null_before=bytes(cpu.mem_read(self.scope_frame+1528,24))
        self.scope_packed_before=bytes(cpu.mem_read(self.scope_frame+4312,40))
        for size,address in ((264,self.scope_owner),(88,self.scope_input)):
            assert len([e for e in state['allocator_events_ref'] if e[0]=='alloc' and e[1:3]==[size,address]])==1

    def observe(self,cpu,pc,state):
        self.scope_state=state
        if not self.scope_active:
            super().observe(cpu,pc,state)
            if not self.scope_active:return
        off=pc-self.image
        def reg(n):return cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(n)))
        def raw(a,n):return bytes(cpu.mem_read(a,n))
        def u(a,n=8):return int.from_bytes(raw(a,n),'little')
        bc=u(state['PC_slot'])-self.image
        if off in (0x27E6AC,0x27ED6C):raise AssertionError('unexpected ordinary callback/wrapper RET')
        if off==context.LOAD and bc in LOADS:
            offset,destination,role=LOADS[bc]
            bases={'frame':self.scope_frame,'ELF GOT':self.image+GOT_BASE,'configuration':self.scope_owner}
            values={0xFD22C:0,0xFD238:self.image+TARGET,0xFD23C:self.scope_owner,0xFD240:self.scope_input}
            assert (reg(12),reg(13),reg(14),u(reg(12)+reg(13)))==(bases[role],offset,destination,values[bc])
            self.scope_loads.append(dict(bytecode=hex(bc),offset=offset,destination=destination,source=role))
        if off==0x16A5E8 and bc==CALL:
            assert not self.original_scope and len(self.scope_loads)==4 and len(self.scope_stores)==4
            expected=[self.image+TARGET,self.scope_input,self.image+WRAPPER,self.scope_frame+4320,self.scope_owner,self.image+0x28587C]
            assert [u(state['backing']+i*8) for i in CHANGED]==expected
            assert all(u(state['backing']+i*8)==self.scope_initial_R[i] for i in range(32) if i not in CHANGED)
            self.scope_registers_verified=True
        if off==0x2858D0 and bc==CALL:
            assert self.scope_registers_verified and not self.original_scope
            assert u(state['backing']+31*8)==self.image+CALL+4
            assert all(u(state['backing']+i*8)==self.scope_initial_R[i] for i in range(32) if i not in (*CHANGED,31))
            assert reg(0)==self.scope_frame+4320 and [u(reg(0)+i*8) for i in range(3)]==[self.image+TARGET,self.scope_frame+4920,self.scope_input]
            after_null=raw(self.scope_frame+1528,24);after_packed=raw(self.scope_frame+4312,40)
            assert u(self.scope_frame+1536)==0 and self.scope_null_before[:8]+self.scope_null_before[16:]==after_null[:8]+after_null[16:]
            assert self.scope_packed_before[:8]+self.scope_packed_before[32:]==after_packed[:8]+after_packed[32:]
            self.scope_arguments_seen=True
        if off==TARGET and bc==CALL:
            assert self.scope_arguments_seen and not self.original_scope
            assert reg(0)==self.scope_frame+4920 and reg(1)==self.scope_input and reg(30)==self.image+STOP
            assert raw(self.image+diagnostics.GUARD,8)==bytes(8) and u(self.image+diagnostics.GLOBAL_LOCK)==u(self.image+diagnostics.TABLE)==0
            assert raw(self.image+diagnostics.GUARD_MUTEX,40)==bytes(40)
            self.scope_object=reg(0);self.scope_padding=raw(reg(0)+12,4);self.original_scope=True
        if off==0x26C85C and bc==CALL:
            assert self.original_scope and reg(0)==self.scope_object;self.scope_body_seen=True
        if self.original_scope and bc==CALL:
            if off in (0x347F00,0x347F10):self.scope_mutex_events.append(('pthread_mutex_lock' if off==0x347F00 else 'pthread_mutex_unlock',reg(0)))
            if off==0x348310:
                assert reg(0)==0xB2;self.scope_mutex_events.append(('gettid',137))
        if off==STOP and bc==CALL:
            assert self.scope_body_seen and self.original_scope and reg(0)==0
            tail=state['allocator_events_ref'][len(self.scope_allocations_before):]
            assert len(tail)==3 and [e[0:2] for e in tail]==[['alloc',s] for s in (48,2048,48)]
            assert all(e[3]=='0x32a210' for e in tail)
            self.scope_model_observed=scope_projection(raw,self.image,self.scope_object,self.scope_input,self.scope_padding,
                [(e[1],e[2]) for e in tail],self.scope_mutex_events)
            assert self.scope_model_observed==model_projection()
            assert raw(state['context'],128)==state['handler_bytes'] and u(self.state_owner+0x18)==self.node
            assert raw(self.node,64)==name.previous.previous.empty_bytes()
            assert previous.lookup.tree_projection(raw,self.image,self.container)==self.tree
            assert name.previous.previous.previous.output._cstring(cpu,self.prefix.source)==self.prefix.raw
            assert u(self.scope_frame+1536)==0 and u(self.scope_frame+1744)==self.scope_owner and u(self.scope_owner+160)==self.scope_input
            assert u(self.image+0x3D1558,1)==1 and u(context.outer.root_fixture.TLS+0x100,4)==2
            self.scope_done=True;cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,context.outer.oracle.STOP)

    def finish(self,result,state,proof):
        old_data=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(old_data)
        old=next(r for r in old_data['case_results'] if r['control']==self.control);prefix=proof['kmsv_lookup_prefix']
        for key,field in [('instruction_observations','continuation_instruction_observations'),('trace_sha256','continuation_trace_sha256'),
            ('code_sha256','continuation_code_sha256')]:assert prefix[key]==old[field]
        assert self.scope_done and graph.digest(self.scope_allocations_before)==old['allocation_ledger_sha256']
        assert result['allocator_events'][:len(self.scope_allocations_before)]==self.scope_allocations_before
        tail=result['allocator_events'][len(self.scope_allocations_before):]
        assert len(tail)==3 and [e[1] for e in tail]==[48,2048,48] and all(e[0]=='alloc' and e[3]=='0x32a210' for e in tail)
        counts=dict(old['allocator_counts']);counts['malloc']+=3;assert result['actual_allocator_counts']==counts
        assert result['explicit_service_counts']==old['service_counts']
        for key in ('JNI_calls','libc_SVC_boundaries','main_image_SVC_boundaries'):assert proof[key]==prefix[key]==old[key]
        return dict(control=self.control,retained_KMSV_prefix_verified=True,
            retained_prefix_instruction_observations=prefix['instruction_observations'],retained_prefix_trace_sha256=prefix['trace_sha256'],
            retained_prefix_code_sha256=prefix['code_sha256'],retained_prefix_allocation_sha256=graph.digest(self.scope_allocations_before),
            argument_projection=argument_projection(),native_loads=self.scope_loads,native_stores=self.scope_stores,
            configuration_owner_allocation_size=264,input_allocation_size=88,input_page_aligned=True,
            configuration_frame_source_write=dict(bytecode='0xf8d68',native_pc='0x171268',frame_offset=1744,value_is_configuration=True),
            selected_scope_projection=self.scope_model_observed,original_scope_body_seen=True,actual_X0_u64=0,
            native_CALL_link_register_offset=hex(CALL+4),
            allocation_ledger_sha256=graph.digest(result['allocator_events']),allocator_counts=counts,service_counts=result['explicit_service_counts'],
            JNI_calls=proof['JNI_calls'],libc_SVC_boundaries=proof['libc_SVC_boundaries'],main_image_SVC_boundaries=proof['main_image_SVC_boundaries'],
            handler_empty_state_tree_directory_configuration_member_unchanged=True,registry_guard_at_stop=1,errno_at_stop=2,
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
    relocations=[r for s in elf.iter_sections() if s['sh_type']=='SHT_RELA' for r in s.iter_relocations() if r['r_offset']==GOT_SLOT]
    assert len(relocations)==1 and relocations[0]['r_info_type']==1027 and relocations[0]['r_addend']==TARGET
    assert interpreter_projection(path)==[dict(image_base=hex(b),projection=argument_projection()) for b in graph.BASES]
    return dict(instruction_bindings=len(EXPECTED),bytecode_words=len(WORDS),GOT_relative_relocation_verified=True,
        independent_Python_VM_cases=2,independent_cold_diagnostic_model_verified=True)


def validate(data):
    assert data['schema']=='vm9-native-171-kmsv-scope-20261119-v1' and data['claims']==CLAIMS and data['providers']==providers()
    assert data['instructions']==[dict(offset=hex(a),mnemonic=m,operands=s) for a,m,s in EXPECTED]
    assert data['bytecode_words']==[dict(offset=hex(a),word=hex(w)) for a,w in WORDS]
    assert data['independent_Python_projection']==model_projection()
    assert data['independent_Python_VM_projection']==[dict(image_base=hex(b),projection=argument_projection()) for b in graph.BASES]
    old_data=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(old_data)
    assert data['provenance']==old_data['provenance'] and len(data['case_results'])==len(context.controls())
    for row,old in zip(data['case_results'],old_data['case_results']):
        assert row['control']==old['control'] and row['retained_KMSV_prefix_verified'] is True
        for k,field in [('retained_prefix_instruction_observations','continuation_instruction_observations'),
            ('retained_prefix_trace_sha256','continuation_trace_sha256'),('retained_prefix_code_sha256','continuation_code_sha256'),
            ('retained_prefix_allocation_sha256','allocation_ledger_sha256')]:assert row[k]==old[field]
        assert row['argument_projection']==argument_projection()
        assert row['native_loads']==[dict(bytecode=hex(a),offset=o,destination=d,source=s) for a,(o,d,s) in LOADS.items()]
        assert row['native_stores']==[dict(bytecode=hex(a),cursor_bytecode=hex(a+4),frame_offset=o,size=8) for a,(o,_) in STORES.items()]
        assert row['configuration_owner_allocation_size']==264 and row['input_allocation_size']==88 and row['input_page_aligned'] is True
        assert row['configuration_frame_source_write']==dict(bytecode='0xf8d68',native_pc='0x171268',frame_offset=1744,value_is_configuration=True)
        assert row['selected_scope_projection']==data['independent_Python_projection'] and row['original_scope_body_seen'] is True
        assert row['actual_X0_u64']==0 and row['native_CALL_link_register_offset']==hex(CALL+4)
        assert row['handler_empty_state_tree_directory_configuration_member_unchanged'] is True
        counts=dict(old['allocator_counts']);counts['malloc']+=3;assert row['allocator_counts']==counts
        for key in ('service_counts','JNI_calls','libc_SVC_boundaries','main_image_SVC_boundaries'):assert row[key]==old[key]
        assert row['registry_guard_at_stop']==1 and row['errno_at_stop']==2 and row['callback_or_ordinary_RET_seen'] is False
        assert row['observation_stop_before']==hex(STOP) and row['outer_bytecode']==hex(CALL)
        assert row['continuation_instruction_observations']>old['continuation_instruction_observations']
        for key in ('allocation_ledger_sha256','continuation_trace_sha256','continuation_code_sha256'):assert graph.inputs.is_digest(row[key])


def negatives(data):
    count=0
    def reject(path,value):
        nonlocal count
        bad=deepcopy(data);target=bad
        for key in path[:-1]:target=target[key]
        target[path[-1]]=value
        try:validate(bad)
        except AssertionError:count+=1
        else:raise AssertionError('damaged scope evidence accepted: '+str(path))
    for key,value in CLAIMS.items():reject(('claims',key),not value)
    reject(('providers','maximum_handler_reads'),3);reject(('providers','maximum_main_SVCs'),5)
    reject(('instructions',0,'mnemonic'),'nop');reject(('bytecode_words',0,'word'),'0x0')
    for i in range(len(data['case_results'])):
        for path,value in [(('retained_KMSV_prefix_verified',),False),(('retained_prefix_trace_sha256',),'0'*64),
            (('retained_prefix_allocation_sha256',),'0'*64),(('native_loads',),[]),(('native_stores',),[]),
            (('argument_projection','input_is_KMSV_NULL'),True),(('argument_projection','NULL_spill_frame_offset'),1552),
            (('configuration_owner_allocation_size',),88),(('input_allocation_size',),264),(('input_page_aligned',),False),
            (('configuration_frame_source_write','bytecode'),'0xf7dd8'),(('selected_scope_projection','saved_lock_result_u32'),1),
            (('selected_scope_projection','recursive_mutex_owner_u32'),0),(('selected_scope_projection','allocation_sizes'),[]),
            (('selected_scope_projection','selected_entry_lock_held'),False),(('original_scope_body_seen',),False),(('actual_X0_u64',),1),
            (('native_CALL_link_register_offset',),'0xfd258'),(('allocator_counts','malloc'),0),(('service_counts','syscall_226'),0),(('JNI_calls',),[]),
            (('libc_SVC_boundaries',),[]),(('main_image_SVC_boundaries',),[]),
            (('handler_empty_state_tree_directory_configuration_member_unchanged',),False),(('registry_guard_at_stop',),0),
            (('errno_at_stop',),17),(('callback_or_ordinary_RET_seen',),True),(('observation_stop_before',),'0x0'),
            (('outer_bytecode',),'0xfd228'),(('continuation_instruction_observations',),0)]:reject(('case_results',i)+path,value)
    return count


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--elf',type=Path);ap.add_argument('--libc',type=Path);ap.add_argument('--replay',action='store_true')
    args=ap.parse_args()
    if args.replay and (not args.elf or not args.libc):ap.error('--replay requires --elf and --libc')
    data=json.loads(EVIDENCE.read_text(encoding='utf-8'));validate(data)
    result=dict(retained_scope_cases=len(data['case_results']),damaged_evidence_rejected=negatives(data),
        KMSV_value_generated=False,ordinary_Cronet_six_headers_verified=False,complete_standalone_signer_verified=False)
    if args.elf:result['image_bindings']=verify_images(data,args.elf,args.libc)
    elif args.libc:graph.inputs.libc_image(args.libc)
    if args.replay:
        assert replay(args.elf,args.libc)==data['case_results'],'frozen diagnostic scope replay differs'
        result['original_code_cases_replayed']=len(data['case_results'])
    print(json.dumps(result))


if __name__=='__main__':main()
