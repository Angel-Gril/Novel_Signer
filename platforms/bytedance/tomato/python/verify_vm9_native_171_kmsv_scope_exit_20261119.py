"""Original configuration counter retain and matching diagnostic scope exit.

The counter and configuration inputs are declared independently for Python.
Preserve the cold scope prefix and stop before consuming the exit return.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
from unicorn import arm64_const as arm
import verify_vm9_native_171_kmsv_scope_20261119 as previous

context=previous.context
graph=previous.graph
name=previous.name
diagnostics=previous.diagnostics
EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_kmsv_scope_exit_20261119.json')
ENTRY,CALL,STOP=0xFD25C,0xFD290,0x16AA4C
TARGET,WRAPPER,GOT_SLOT=0x26C9D0,0x2858E0,0x382DC0
WORDS=[(0xFD25C,0x90250218),(0xFD260,0x88250018),(0xFD264,0x8083002D),
    (0xFD268,0x80022001),(0xFD26C,0x002200BB),(0xFD270,0x88040016),
    (0xFD274,0x890A0018),(0xFD278,0x837F0C18),(0xFD27C,0x8378311A),
    (0xFD280,0x8B50311A),(0xFD284,0x934A340F),(0xFD288,0x07804B11),
    (0xFD28C,0x05C19B11),(CALL,0x067E0C91)]
EXPECTED=[(context.LOAD,'ldr','x9, [x12, x13]'),(0x16F974,'str','x9, [x28, x14, lsl #3]'),
    (0x16EDE8,'cmp','x9, x11'),(0x170308,'ldrsw','x9, [x10, x11]'),
    (0x17030C,'str','x9, [x28, x14, lsl #3]'),(0x16DB74,'str','x10, [x28, x15, lsl #3]'),
    (0x17208C,'str','w11, [x12, x10]'),(0x171268,'str','x15, [x17, x16]'),
    (0x16A5E8,'eor','x11, x11, x4'),(0x2858E0,'ldp','x1, x8, [x0]'),
    (0x2858E4,'mov','x0, x8'),(0x2858E8,'br','x1'),
    (TARGET,'adrp','x9, #0x35d000'),(0x26C9D4,'ldr','w8, [x0, #8]'),
    (0x26C9DC,'str','x9, [x0]'),(0x26C9E0,'cbz','w8, #0x26c9e8'),
    (0x26C9E8,'ldr','x8, [x0, #0x10]'),(0x26C9F0,'ubfx','x8, x8, #4, #8'),
    (0x26C9F8,'ldr','x8, [x9, x8, lsl #3]'),(0x26C9FC,'cbz','x8, #0x26c9e4'),
    (0x26CA00,'add','x0, x8, #8'),(0x26CA04,'b','#0x347f10'),
    (STOP,'ldp','x5, x1, [x29, #-0x90]')]
LOADS={0xFD25C:(168,18,'configuration'),0xFD260:(160,17,'configuration'),
    0xFD274:(320,1,'ELF GOT'),0xFD278:(2032,16,'frame')}
CHANGED=(1,4,5,16,17,18,25)
CLAIMS=dict(retained_scope_instruction_code_and_allocation_prefix_verified=True,
    original_configuration_counter_pointer_compared_with_zero=True,
    branch_does_not_consume_saved_KMSV_NULL=True,original_counter_u32_retained_from1_to2=True,
    original_thirteen_argument_bytecodes_match_independent_fresh_VM=True,
    original_scope_exit_and_matching_Bionic_unlock_executed=True,
    selected_scope_object_and_table_preserved=True,selected_recursive_lock_released=True,
    fresh_independent_Python_enter_and_leave_scope_match=True,
    complete_retained_allocation_service_JNI_SVC_ledgers_unchanged=True,
    native_memory_used_as_model_input=False,new_OS_JNI_or_internal_helper_providers=False,
    complete_configuration_counter_construction_provenance_verified=False,
    full_VM_or_physical_stack_equivalence_verified=False,scope_exit_return_consumed=False,
    saved_NULL_business_branch_verified=False,KMSV_value_generated=False,client_key_value_generated=False,
    real_business_cache_restored=False,real_JVM_identity_verified=False,
    ordinary_Cronet_six_headers_verified=False,whole_request_equivalence_verified=False,
    callback_or_ordinary_wrapper_returned=False,complete_standalone_signer_verified=False,
    Android_execution=False,online_acceptance_verified=False)


def argument_projection():
    return dict(executed_bytecodes=[hex(a) for a,_ in WORDS[:-1]],
        configuration_counter_member_offset=168,configuration_input_member_offset=160,
        branch=dict(bytecode='0xfd264',left='configuration+0xa8 pointee',right=0,
            comparison='equal',taken=False,fallthrough='0xfd268',consumes_saved_KMSV_NULL=False),
        counter_before_u32=1,counter_after_u32=2,counter_store_width=4,
        scope_frame_offset=4920,scope_source_frame_offset=2032,packed_frame_offset=4304,
        GOT_slot_offset=hex(GOT_SLOT),target_offset=hex(TARGET),wrapper_offset=hex(WRAPPER),
        packed_words=['image+0x26c9d0','frame+4920'],
        selected_registers=dict(R1='image+0x26c9d0',R4='image+0x2858e0',R5='frame+4304',
            R16='frame+4920',R17='configuration+0xa0 pointee',R18='configuration+0xa8 pointee',R25='image+0x28587c'),
        unselected_registers_frame_bytes_and_counter_adjacent_preserved=True,stop_before_bytecode=hex(CALL))


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
        def w32(self,a,v):self.put(a,int(v).to_bytes(4,'little'))
    class Boundary(Exception):pass
    saved_base=vm_module.B;rows=[]
    try:
        for image in graph.BASES:
            vm_module.B=image;m=Memory();frame=0x60000000;owner=0x61000000;value=0x62000000;counter=0x63000000
            m.put(frame,b'\xa5'*0x2000);m.put(owner,bytes(264));m.put(value,bytes(88));m.put(counter,b'\xa5'*16)
            m.w64(owner+160,value);m.w64(owner+168,counter);m.w32(counter,1)
            m.w64(frame+2032,frame+4920);m.w64(image+GOT_SLOT,image+TARGET)
            for a,w in WORDS:m.put(image+a,w.to_bytes(4,'little'))
            before_frame=name._read_span(m.pages,frame,0x2000);before_counter=name._read_span(m.pages,counter,16)
            vm=vm_module.VM(m,ENTRY,0,0,0,image+0x28587C,0,maxsteps=14)
            vm.R=[0xA5A5000000000000+i for i in range(32)]
            vm.R[0]=0;vm.R[16]=owner;vm.R[20]=image+previous.GOT_BASE
            vm.R[23]=image+0x28587C;vm.R[29]=frame;vm.R[30]=image+WRAPPER;vm.R[31]=image+ENTRY
            before=list(vm.R);steps=[]
            def step(vm,dw,op,sub):
                if vm.pc==image+CALL:raise Boundary()
                assert (vm.pc-image,dw)==WORDS[len(steps)];steps.append(hex(vm.pc-image))
            vm.step_hook=step
            try:vm.run()
            except Boundary:pass
            else:raise AssertionError('retain projection did not stop before CALL')
            assert steps==argument_projection()['executed_bytecodes']
            assert [vm.R[i] for i in CHANGED]==[image+TARGET,image+WRAPPER,frame+4304,frame+4920,value,counter,image+0x28587C]
            assert all(vm.R[i]==before[i] for i in range(32) if i not in CHANGED)
            assert m.u32(counter)==2 and name._read_span(m.pages,counter+4,12)==before_counter[4:]
            assert [m.u64(frame+4304+i*8) for i in range(2)]==[image+TARGET,frame+4920]
            after=name._read_span(m.pages,frame,0x2000)
            assert all(a==b for i,(a,b) in enumerate(zip(before_frame,after)) if not 4304<=i<4320)
            rows.append(dict(image_base=hex(image),projection=argument_projection()))
    finally:vm_module.B=saved_base
    return rows


def exit_projection(read,image,obj,scope_before,table_before,entry,events):
    def u(a,n=8):return int.from_bytes(read(a,n),'little')
    assert read(obj,24)==scope_before and u(obj)==image+0x35D410 and u(obj+8,4)==0
    assert read(u(image+diagnostics.TABLE),2048)==table_before
    assert u(entry)==image+0x34C738 and u(entry+8,4)==0x4000 and u(entry+12,4)==0
    assert read(entry+16,32)==bytes(32)
    assert read(image+diagnostics.GUARD,8)==bytes.fromhex('0101000089000000')
    assert read(image+diagnostics.GUARD_MUTEX,40)==bytes(40)
    assert read(u(image+diagnostics.GLOBAL_LOCK)+8,40)==bytes(40)
    assert events==[('pthread_mutex_unlock',entry+8)]
    return dict(scope_object24_bytes_preserved=True,table2048_bytes_preserved=True,
        recursive_mutex_state_u32=0x4000,recursive_mutex_owner_u32=0,other32_mutex_bytes_zero=True,
        guard=name.blob(read(image+diagnostics.GUARD,8)),global_and_guard_mutexes_zero=True,
        normalized_events=[['pthread_mutex_unlock','selected entry mutex']],scope_exit_executed=True,
        selected_entry_lock_held=False,scope_exit_return_u32=0)


def model_projection():
    image=0x10000000;root=0x60000000;obj=root+0x100;input_word=0x62000000;tls=root+0x500;pthread=root+0x600
    pages={p:bytearray(4096) for p in range(root>>12,(root+0x5000)>>12)}
    def read(a,n):return name._read_span(pages,a,n)
    def put(a,b):name.put(pages,a,b)
    def w(a,v,n=8):put(a,int(v).to_bytes(n,'little'))
    put(obj,b'\xa5'*24);put(image+diagnostics.GUARD,bytes(8));put(image+diagnostics.GLOBAL_LOCK,bytes(24))
    put(image+diagnostics.GUARD_MUTEX,bytes(40));w(tls+8,pthread);w(pthread+16,137,4)
    allocations=[];addresses=[root+0x1000,root+0x2000,root+0x3000]
    def allocate(p,size):
        assert size==[48,2048,48][len(allocations)];address=addresses[len(allocations)]
        put(address,bytes(size));allocations.append((size,address));return address
    scope=diagnostics.enter_diagnostic_scope(pages,object_address=obj,input_word=input_word,image_base=image,
        thread_pointer=tls,thread_id=137,allocate=allocate)
    before=read(obj,24);table_before=read(addresses[1],2048);events=[]
    assert scope.lock_result==0 and scope.entry_address==addresses[2] and scope.table_index==0
    result=diagnostics.leave_diagnostic_scope(pages,object_address=obj,image_base=image,thread_pointer=tls,
        observer=lambda *e:events.append(e))
    assert result==0 and [s for s,_ in allocations]==[48,2048,48]
    return exit_projection(read,image,obj,before,table_before,scope.entry_address,events)


def providers():
    return dict(inherited_scope=previous.providers(),maximum_handler_reads=2,maximum_main_SVCs=4,
        independent_model_owners=['vm_full.py:VM.run','vm9_diagnostics.py:enter_diagnostic_scope',
            'vm9_diagnostics.py:leave_diagnostic_scope'],
        independent_model_input='fresh declared configuration pointers, counter1, frame and independently constructed locked scope',
        allocation_deltas={},service_count_deltas={},new_OS_JNI_or_internal_helper_providers=[],
        stop_before=hex(STOP),outer_bytecode=hex(CALL))


class Scenario(previous.Scenario):
    def __init__(self,c):
        super().__init__(c);self.exit_active=False;self.exit_done=False;self.exit_body=False
        self.exit_loads=[];self.exit_stores=[];self.counter_writes=[];self.exit_events=[]

    def native_runner(self,*args,**kwargs):
        original=kwargs['memory_write_observer']
        def write(cpu,address,size):
            if self.exit_active:
                def reg(n):return cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(n)))
                def u(a):return int.from_bytes(cpu.mem_read(a,8),'little')
                bc=u(self.scope_state['PC_slot'])-self.image;off=cpu.reg_read(arm.UC_ARM64_REG_PC)-self.image
                if address==self.exit_counter:
                    assert (off,bc,size,reg(11),reg(12),reg(10))==(0x17208C,0xFD270,4,2,self.exit_counter,0)
                    assert u(address)&0xFFFFFFFF==1
                    self.counter_writes.append(dict(native_pc=hex(off),bytecode=hex(bc),size=4,before_u32=1,after_u32=2))
                if self.scope_frame+4304<=address<self.scope_frame+4320:
                    assert off==0x171268 and size==8
                    expected={0xFD280:(4312,self.scope_object),0xFD284:(4304,self.image+TARGET)}
                    offset,value=expected[bc];assert address==self.scope_frame+offset and reg(15)==value
                    self.exit_stores.append(dict(bytecode=hex(bc-4),cursor_bytecode=hex(bc),frame_offset=offset,size=8))
            original(cpu,address,size)
        kwargs['memory_write_observer']=write
        return super().native_runner(*args,**kwargs)

    def scope_boundary(self,cpu,state):
        assert self.scope_done and not self.exit_active
        def raw(a,n):return bytes(cpu.mem_read(a,n))
        def u(a,n=8):return int.from_bytes(raw(a,n),'little')
        self.exit_active=True;self.exit_allocations=deepcopy(state['allocator_events_ref'])
        self.exit_initial_R=[u(state['backing']+i*8) for i in range(32)]
        self.exit_counter=u(self.scope_owner+168);assert self.exit_counter and u(self.exit_counter,4)==1
        history=[e for e in self.exit_allocations if
            (e[0]=='alloc' and e[2]==self.exit_counter) or (e[0]=='free' and e[1]==self.exit_counter)]
        assert history and history[-1][0:2]==['alloc',4]
        self.exit_counter_before=raw(self.exit_counter,16);self.exit_owner_before=raw(self.scope_owner,264)
        self.exit_object_before=raw(self.scope_object,24);self.exit_table=u(self.image+diagnostics.TABLE)
        self.exit_table_before=raw(self.exit_table,2048);self.exit_entry=u(self.exit_table+((self.scope_input>>4)&255)*8)
        self.exit_packed_before=raw(self.scope_frame+4296,32)
        assert u(self.scope_frame+2032)==self.scope_object==self.scope_frame+4920
        assert self.exit_initial_R[30]==self.image+WRAPPER

    def observe(self,cpu,pc,state):
        self.scope_state=state
        if not self.exit_active:
            super().observe(cpu,pc,state)
            if not self.exit_active:return
        off=pc-self.image
        def reg(n):return cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(n)))
        def raw(a,n):return bytes(cpu.mem_read(a,n))
        def u(a,n=8):return int.from_bytes(raw(a,n),'little')
        bc=u(state['PC_slot'])-self.image
        if off in (0x27E6AC,0x27ED6C):raise AssertionError('unexpected ordinary callback/wrapper RET')
        if off==context.LOAD and bc in LOADS:
            offset,destination,role=LOADS[bc]
            bases={'configuration':self.scope_owner,'ELF GOT':self.image+previous.GOT_BASE,'frame':self.scope_frame}
            values={0xFD25C:self.exit_counter,0xFD260:self.scope_input,0xFD274:self.image+TARGET,0xFD278:self.scope_object}
            assert (reg(12),reg(13),reg(14),u(reg(12)+reg(13)))==(bases[role],offset,destination,values[bc])
            self.exit_loads.append(dict(bytecode=hex(bc),offset=offset,destination=destination,source=role))
        if off==0x16EDE8 and bc==0xFD264:
            assert reg(9)==self.exit_counter and reg(11)==0;self.exit_branch_seen=True
        if off==0x170308 and bc==0xFD268:
            assert self.exit_branch_seen and (reg(10),reg(11),reg(14),u(reg(10),4))==(self.exit_counter,0,1,1)
            self.exit_counter_load_seen=True
        if off==0x16DB74 and bc==0xFD26C:
            assert self.exit_counter_load_seen and reg(10)==2 and reg(15)==1;self.exit_increment_seen=True
        expected=[self.image+TARGET,self.image+WRAPPER,self.scope_frame+4304,self.scope_object,
            self.scope_input,self.exit_counter,self.image+0x28587C]
        if off==0x16A5E8 and bc==CALL:
            assert self.exit_increment_seen and len(self.exit_loads)==4 and len(self.exit_stores)==2 and len(self.counter_writes)==1
            assert [u(state['backing']+i*8) for i in CHANGED]==expected
            assert all(u(state['backing']+i*8)==self.exit_initial_R[i] for i in range(32) if i not in CHANGED)
            self.exit_registers_seen=True
        if off==WRAPPER and bc==CALL:
            assert self.exit_registers_seen and reg(0)==self.scope_frame+4304
            assert [u(reg(0)+i*8) for i in range(2)]==[self.image+TARGET,self.scope_object]
            assert u(state['backing']+31*8)==self.image+CALL+4
            assert all(u(state['backing']+i*8)==self.exit_initial_R[i] for i in range(32) if i not in (*CHANGED,31))
            after=raw(self.scope_frame+4296,32);assert after[:8]+after[24:]==self.exit_packed_before[:8]+self.exit_packed_before[24:]
            self.exit_wrapper_seen=True
        if off==TARGET and bc==CALL:
            assert self.exit_wrapper_seen and reg(0)==self.scope_object and reg(30)==self.image+STOP
            self.exit_entered=True
        if off==0x26C9D4 and bc==CALL:
            assert self.exit_entered;self.exit_body=True
        if self.exit_body and bc==CALL and off in (0x347F00,0x347F10):
            self.exit_events.append(('pthread_mutex_lock' if off==0x347F00 else 'pthread_mutex_unlock',reg(0)))
        if off==STOP and bc==CALL:
            assert self.exit_body and reg(0)==0
            self.exit_observed=exit_projection(raw,self.image,self.scope_object,self.exit_object_before,
                self.exit_table_before,self.exit_entry,self.exit_events)
            assert self.exit_observed==model_projection()
            assert u(self.exit_counter,4)==2 and raw(self.exit_counter+4,12)==self.exit_counter_before[4:]
            assert raw(self.scope_owner,264)==self.exit_owner_before and u(self.scope_frame+1536)==0
            assert raw(state['context'],128)==state['handler_bytes'] and u(self.state_owner+0x18)==self.node
            assert raw(self.node,64)==name.previous.previous.empty_bytes()
            assert previous.previous.lookup.tree_projection(raw,self.image,self.container)==self.tree
            assert name.previous.previous.previous.output._cstring(cpu,self.prefix.source)==self.prefix.raw
            assert u(self.image+0x3D1558,1)==1 and u(context.outer.root_fixture.TLS+0x100,4)==2
            self.exit_done=True;self.exit_boundary(cpu,state)

    def exit_boundary(self,cpu,state):
        cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,context.outer.oracle.STOP)

    def finish(self,result,state,proof):
        data=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(data)
        old=next(r for r in data['case_results'] if r['control']==self.control);prefix=proof['kmsv_scope_prefix']
        for k,field in [('instruction_observations','continuation_instruction_observations'),('trace_sha256','continuation_trace_sha256'),
            ('code_sha256','continuation_code_sha256')]:assert prefix[k]==old[field]
        assert self.exit_done and graph.digest(self.exit_allocations)==old['allocation_ledger_sha256']
        assert result['allocator_events']==self.exit_allocations and result['actual_allocator_counts']==old['allocator_counts']
        assert result['explicit_service_counts']==old['service_counts']
        for k in ('JNI_calls','libc_SVC_boundaries','main_image_SVC_boundaries'):assert proof[k]==prefix[k]==old[k]
        return dict(control=self.control,retained_scope_prefix_verified=True,
            retained_prefix_instruction_observations=prefix['instruction_observations'],retained_prefix_trace_sha256=prefix['trace_sha256'],
            retained_prefix_code_sha256=prefix['code_sha256'],argument_projection=argument_projection(),native_loads=self.exit_loads,
            native_stores=self.exit_stores,counter_writes=self.counter_writes,counter_live_allocation_size=4,
            counter_adjacent12_bytes_preserved=True,selected_exit_projection=self.exit_observed,original_scope_exit_body_seen=True,
            actual_X0_u64=0,native_CALL_link_register_offset=hex(CALL+4),
            allocation_ledger_sha256=graph.digest(result['allocator_events']),allocator_counts=result['actual_allocator_counts'],
            service_counts=result['explicit_service_counts'],JNI_calls=proof['JNI_calls'],libc_SVC_boundaries=proof['libc_SVC_boundaries'],
            main_image_SVC_boundaries=proof['main_image_SVC_boundaries'],
            handler_empty_state_tree_directory_configuration_and_saved_NULL_unchanged=True,registry_guard_at_stop=1,errno_at_stop=2,
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
    rel=[r for s in elf.iter_sections() if s['sh_type']=='SHT_RELA' for r in s.iter_relocations() if r['r_offset']==GOT_SLOT]
    assert len(rel)==1 and rel[0]['r_info_type']==1027 and rel[0]['r_addend']==TARGET
    assert interpreter_projection(path)==[dict(image_base=hex(b),projection=argument_projection()) for b in graph.BASES]
    return dict(instruction_bindings=len(EXPECTED),bytecode_words=len(WORDS),GOT_relative_relocation_verified=True,
        independent_Python_VM_cases=2,independent_Python_scope_exit_verified=True)


def validate(data):
    assert data['schema']=='vm9-native-171-kmsv-scope-exit-20261119-v1' and data['claims']==CLAIMS and data['providers']==providers()
    assert data['instructions']==[dict(offset=hex(a),mnemonic=m,operands=s) for a,m,s in EXPECTED]
    assert data['bytecode_words']==[dict(offset=hex(a),word=hex(w)) for a,w in WORDS]
    assert data['independent_Python_projection']==model_projection()
    assert data['independent_Python_VM_projection']==[dict(image_base=hex(b),projection=argument_projection()) for b in graph.BASES]
    old_data=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(old_data)
    assert data['provenance']==old_data['provenance'] and len(data['case_results'])==len(context.controls())
    for row,old in zip(data['case_results'],old_data['case_results']):
        assert row['control']==old['control'] and row['retained_scope_prefix_verified'] is True
        for k,field in [('retained_prefix_instruction_observations','continuation_instruction_observations'),
            ('retained_prefix_trace_sha256','continuation_trace_sha256'),('retained_prefix_code_sha256','continuation_code_sha256')]:assert row[k]==old[field]
        assert row['argument_projection']==argument_projection()
        assert row['native_loads']==[dict(bytecode=hex(a),offset=o,destination=d,source=s) for a,(o,d,s) in LOADS.items()]
        assert row['native_stores']==[dict(bytecode=hex(a),cursor_bytecode=hex(a+4),frame_offset=o,size=8) for a,o in ((0xFD27C,4312),(0xFD280,4304))]
        assert row['counter_writes']==[dict(native_pc='0x17208c',bytecode='0xfd270',size=4,before_u32=1,after_u32=2)]
        assert row['counter_live_allocation_size']==4 and row['counter_adjacent12_bytes_preserved'] is True
        assert row['selected_exit_projection']==data['independent_Python_projection'] and row['original_scope_exit_body_seen'] is True
        assert row['actual_X0_u64']==0 and row['native_CALL_link_register_offset']==hex(CALL+4)
        assert row['handler_empty_state_tree_directory_configuration_and_saved_NULL_unchanged'] is True
        for k in ('allocation_ledger_sha256','allocator_counts','service_counts','JNI_calls','libc_SVC_boundaries','main_image_SVC_boundaries'):assert row[k]==old[k]
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
        else:raise AssertionError('damaged scope-exit evidence accepted: '+str(path))
    for k,v in CLAIMS.items():reject(('claims',k),not v)
    reject(('providers','maximum_handler_reads'),3);reject(('providers','maximum_main_SVCs'),5)
    reject(('instructions',0,'mnemonic'),'nop');reject(('bytecode_words',0,'word'),'0x0')
    for i in range(len(data['case_results'])):
        for path,value in [(('retained_scope_prefix_verified',),False),(('retained_prefix_trace_sha256',),'0'*64),
            (('argument_projection','branch','consumes_saved_KMSV_NULL'),True),(('argument_projection','branch','taken'),True),
            (('native_loads',),[]),(('native_stores',),[]),(('counter_writes',0,'after_u32'),1),
            (('counter_live_allocation_size',),8),(('counter_adjacent12_bytes_preserved',),False),
            (('selected_exit_projection','selected_entry_lock_held'),True),(('selected_exit_projection','recursive_mutex_owner_u32'),137),
            (('original_scope_exit_body_seen',),False),(('actual_X0_u64',),1),(('native_CALL_link_register_offset',),'0xfd290'),
            (('allocation_ledger_sha256',),'0'*64),(('allocator_counts','malloc'),0),(('service_counts','syscall_226'),0),
            (('JNI_calls',),[]),(('libc_SVC_boundaries',),[]),(('main_image_SVC_boundaries',),[]),
            (('handler_empty_state_tree_directory_configuration_and_saved_NULL_unchanged',),False),
            (('registry_guard_at_stop',),0),(('errno_at_stop',),17),(('callback_or_ordinary_RET_seen',),True),
            (('observation_stop_before',),'0x0'),(('outer_bytecode',),'0xfd258'),(('continuation_instruction_observations',),0)]:
            reject(('case_results',i)+path,value)
    return count


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--elf',type=Path);ap.add_argument('--libc',type=Path);ap.add_argument('--replay',action='store_true')
    args=ap.parse_args()
    if args.replay and (not args.elf or not args.libc):ap.error('--replay requires --elf and --libc')
    data=json.loads(EVIDENCE.read_text(encoding='utf-8'));validate(data)
    result=dict(retained_scope_exit_cases=len(data['case_results']),damaged_evidence_rejected=negatives(data),
        KMSV_value_generated=False,ordinary_Cronet_six_headers_verified=False,complete_standalone_signer_verified=False)
    if args.elf:result['image_bindings']=verify_images(data,args.elf,args.libc)
    elif args.libc:graph.inputs.libc_image(args.libc)
    if args.replay:
        assert replay(args.elf,args.libc)==data['case_results'],'frozen scope exit replay differs'
        result['original_code_cases_replayed']=len(data['case_results'])
    print(json.dumps(result))


if __name__=='__main__':main()
