"""Original post-getter arithmetic and warm TLS setter, before return consumption.

Current native observations establish instruction contracts. Fresh declared
VM pages and original setter controls use separate inputs and the actual
request callback source. No native snapshot seeds a Python model.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unicorn import arm64_const as arm
import verify_vm9_native_171_configuration_tls_20261119 as previous
import verify_vm9_request_TLS_store_fresh_20261012 as fixture

context,graph,name=previous.context,previous.graph,previous.name
EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_configuration_tls_store_20261119.json')
ENTRY,CALL,STOP=0xFD5EC,0xFD628,0x16AA4C
WRAPPER,TARGET,CONTROL=0x285E70,0x27ED70,previous.CONTROL
GOT_BASE=previous.GOT_BASE
M64=(1<<64)-1
WORDS=[(ENTRY,0x8B4AB40F),(0xFD5F0,0x937B0818),(0xFD5F4,0x08251751),
    (0xFD5F8,0x91920618),(0xFD5FC,0x9B78785A),(0xFD600,0x9B78B09A),
    (0xFD604,0x9350B09A),(0xFD608,0x08201751),(0xFD60C,0x0843C991),
    (0xFD610,0x080200D1),(0xFD614,0x8B04D5C1),(0xFD618,0x08022751),
    (0xFD61C,0x8AFA0096),(0xFD620,0xA34C0618),(0xFD624,0x05C19B11),(CALL,0x067E0C91)]
LOADS=[(0xFD5F0,1888,18,'frame'),(0xFD5F8,600,2,'ELF GOT'),(0xFD620,408,4,'frame')]
STORES=[(0xFD600,1528,8),(0xFD604,2776,8),(0xFD608,2768,8),(0xFD61C,2784,4)]
ARITHMETIC=[(0xFD5F4,'R18 equals frame scalar'),(0xFD5F8,'R1 equals R18 xor R17'),
    (0xFD60C,'R1 equals prior xor R16'),(0xFD610,'R1 equals ror64(prior,60)'),
    (0xFD614,'R1 equals sign-extended low32'),(0xFD618,'R2 equals signed getter word'),
    (0xFD61C,'R1 equals prior xor signed getter word')]
EXPECTED=[(context.LOAD,'ldr','x9, [x12, x13]'),(0x171268,'str','x15, [x17, x16]'),
    (0x17208C,'str','w11, [x12, x10]'),(TARGET,'stp','x29, x30, [sp, #-0x20]!'),
    (0x27ED74,'str','x19, [sp, #0x10]'),(0x27ED78,'mov','x29, sp'),
    (0x27ED7C,'adrp','x0, #0x382000'),(0x27ED80,'mov','w19, w1'),
    (0x27ED84,'add','x0, x0, #0x920'),(0x27ED88,'bl','#0x34377c'),
    (0x27ED8C,'str','w19, [x0]'),(0x27ED98,'ret',''),
    (WRAPPER,'ldp','x2, x8, [x0]'),(0x285E74,'ldr','w1, [x0, #0x10]'),
    (0x285E78,'mov','x0, x8'),(0x285E7C,'br','x2'),
    (STOP,'ldp','x5, x1, [x29, #-0x90]')]
CLAIMS=dict(retained_TLS_getter_instruction_code_and_allocation_prefix_verified=True,
    completed_getter_observer_retired_after_full_prefix=True,original_scope_kept=True,
    original_post_getter_arithmetic_and_signed_word_load_verified=True,
    original_setter_and_warm_emutls_executed=True,original_four_byte_TLS_write_and_adjacent12_verified=True,
    original_return_is_existing_TLS_pointer=True,no_new_allocation_or_service_JNI_SVC=True,
    actual_request_callback_source_executed_on_fresh_declared_pages=True,
    six_independent_VM_and_original_setter_controls_match=True,
    native_memory_used_as_Python_model_input=False,current_request_numeric_Python_equality_verified=False,
    current_and_declared_TLS_indices_equal=False,current_whole_TLS_heap_or_physical_stack_equivalence_verified=False,
    TLS_setter_return_consumed=False,complete_configuration_provenance_verified=False,
    real_business_state_or_JVM_identity_verified=False,KMSV_value_generated=False,client_key_value_generated=False,
    ordinary_Cronet_six_headers_verified=False,whole_request_equivalence_verified=False,
    callback_or_ordinary_wrapper_returned=False,complete_standalone_signer_verified=False,
    new_OS_JNI_or_internal_helper_providers=False,Android_execution=False,online_acceptance_verified=False)
CASES=[('zero',0x123456789ABCDEF0,0),('negative',0xFEDCBA9876543210,0xFFFFFFFF),('highbit',0,0x80000000)]


def sx32(v):
    v&=0xFFFFFFFF
    return (v-(1<<32) if v&(1<<31) else v)&M64


def rotated(h,scalar,opaque):
    v=(h^scalar^opaque)&M64
    return ((v>>60)|(v<<4))&M64


def declared_value(scalar,word):
    return (rotated(int(previous.previous.model_projection()['hash_hex'],16),scalar,0x6C000000)^word)&0xFFFFFFFF


def arithmetic_projection():return [dict(bytecode=hex(a),relation=s,observed_operands_match=True) for a,s in ARITHMETIC]


def selected_projection():
    return dict(scalar_source_frame_offset=1888,opaque_R16_source_frame_offset=4856,
        hash_R17_source_frame_offset=2832,getter_word_frame_offset=2808,getter_word_load_signed=True,
        rotate_right_bits=60,result_store_width=4,packed_frame_offset=2768,value_frame_offset=2784,
        receiver_saved_frame_offset=1528,GOT_slot_offset='0x382ed8',wrapper_frame_offset=408,
        wrapper=hex(WRAPPER),target=hex(TARGET),native_TLS_index=5,TLS_control_preserved=True,
        existing_TLS_pointer_returned=True,TLS_write_size=4,adjacent12_preserved=True,
        old_getter_word_and_hash_and_clone_tables_preserved=True,both_reference_counts_one=True)


def expected_VM_projection():
    return [dict(image_base=hex(b),case=label,scalar_u64=hex(scalar),getter_word_u32=hex(word),
        derived_value_u32=hex(declared_value(scalar,word)),TLS_index=8,
        executed_bytecodes=[hex(a) for a,_ in WORDS],actual_callback_source_executed=True,
        selected_registers_frame_TLS_and_padding_verified=True,native_snapshot_input=False)
        for b in graph.BASES for label,scalar,word in CASES]


def interpreter_projection(path):
    saved=os.environ.get('TOMATO_LIBMETASEC')
    try:
        os.environ['TOMATO_LIBMETASEC']=str(path.resolve());import vm_full as module
    finally:
        if saved is None:os.environ.pop('TOMATO_LIBMETASEC',None)
        else:os.environ['TOMATO_LIBMETASEC']=saved
    assert hashlib.sha256(module.SO).hexdigest()==graph.inputs.SHA256
    class Boundary(Exception):pass
    old_base=module.B;rows=[]
    try:
        for image in graph.BASES:
            module.B=image
            for label,scalar,word in CASES:
                pages,frame,clone,payload,counter,sibling,member,array,block,put,read,w,get_tls,allocs=previous.fresh(image)
                pointer=get_tls(pages,image+CONTROL);assert pointer==block+8 and allocs==[19]
                w(pointer,word,4);w(frame+2808,word,4);w(frame+1888,scalar)
                w(frame+408,image+WRAPPER);w(image+0x382ED8,image+TARGET);w(member+8,272)
                before_frame=read(frame,0x2000);before_tls=read(pointer,16)
                preserved={a:read(a,n) for a,n in ((clone,24),(payload,11),(counter,16),(sibling,16),
                    (image+previous.previous.TABLE,2048),(image+CONTROL,32),(array,128),(member,32))}
                for a,value in WORDS:put(image+a,value.to_bytes(4,'little'))
                put(image+CALL+4,bytes(4))
                class Memory:
                    def __init__(self):self.pages=pages
                    def u32(self,a):return int.from_bytes(read(a,4),'little')
                    def u64(self,a):return int.from_bytes(read(a,8),'little')
                    def rb(self,a):return read(a,1)[0]
                    def w64(self,a,v):w(a,v)
                    def w32(self,a,v):w(a,v,4)
                m=Memory();vm=module.VM(m,ENTRY,0,0,0,0,0,maxsteps=20)
                vm.R=[0xA5A5000000000000+i for i in range(32)]
                vm.R[0]=vm.R[21]=0;vm.R[16]=0x6C000000
                vm.R[17]=int(previous.previous.model_projection()['hash_hex'],16)
                vm.R[19]=member;vm.R[22]=image+GOT_BASE;vm.R[23]=image+0x28587C;vm.R[29]=frame
                vm.cb=image+0x28587C;initial=list(vm.R);steps=[];diagnostic={};ledger=[]
                callback=previous._callback(image,get_tls,diagnostic,ledger)
                def native(vm,function,packed):
                    assert vm.pc==image+CALL and function==image+WRAPPER and packed==frame+2768
                    assert (m.u64(packed),m.u64(packed+8),m.u32(packed+16))==(image+TARGET,member,declared_value(scalar,word))
                    callback(vm,function,packed)
                def step(vm,dw,op,sub):
                    if vm.pc==image+CALL+4:raise Boundary()
                    assert (vm.pc-image,dw)==WORDS[len(steps)];steps.append(hex(vm.pc-image))
                vm.native_hook=native;vm.step_hook=step
                try:vm.run()
                except Boundary:pass
                else:raise AssertionError('declared setter VM did not stop after call')
                value=declared_value(scalar,word);selected=(1,2,4,5,18,25,31)
                assert [vm.R[i] for i in selected]==[sx32(value),sx32(word),image+WRAPPER,frame+2768,scalar,
                    image+0x28587C,image+CALL+4]
                assert all(vm.R[i]==initial[i] for i in range(32) if i not in selected)
                assert m.u64(frame+1528)==member and m.u64(frame+2768)==image+TARGET and m.u64(frame+2776)==member
                assert m.u32(frame+2784)==m.u32(pointer)==value and read(pointer+4,12)==before_tls[4:]
                assert all(a==b for i,(a,b) in enumerate(zip(before_frame,read(frame,0x2000)))
                    if not (1528<=i<1536 or 2768<=i<2788))
                for a,data in preserved.items():assert read(a,len(data))==data
                assert allocs==[19] and len(ledger)==1 and diagnostic=={'request_TLS_stores':[value]}
                rows.append(expected_VM_projection()[len(rows)])
    finally:module.B=old_base
    return rows


def expected_native_projection():
    return [dict(image_base=r['image_base'],case=r['case'],derived_value_u32=r['derived_value_u32'],
        original_setter_and_matching_libc_executed=True,actual_request_callback_source_executed=True,
        guest_image_TLS_and_padding_match=True,no_allocation_or_wake=True,native_snapshot_input=False)
        for r in expected_VM_projection()]


def independent_native_controls(path,libc):
    rows=[];f=fixture.dependency
    for image in graph.BASES:
        for label,scalar,word in CASES:
            value=declared_value(scalar,word);pages,services=fixture.fresh(path,libc,image,True,value)
            returned,memory,observed,allocations,wakes=fixture.native(path,libc,image,pages,services)
            n=len(services.allocator.calls);k=len(services.wakes)
            diagnostic={};ledger=[];read=lambda a,n:f._read_span(pages,a,n)
            callback=previous._callback(image,services.get_tls,diagnostic,ledger)
            callback(SimpleNamespace(m=SimpleNamespace(pages=pages,u64=lambda a:int.from_bytes(read(a,8),'little'))),
                image+WRAPPER,f.PACKED)
            pointer=services.get_tls(pages,image+CONTROL)
            assert returned==pointer and read(pointer,4)==value.to_bytes(4,'little')
            assert read(f.G,0xA000)==memory and all(read(a,n)==data for (a,n),data in observed.items())
            assert services.allocator.calls[n:]==allocations==[] and services.wakes[k:]==wakes==[]
            assert read(f.PACKED+20,12)==b'\xa5'*12
            assert len(ledger)==1 and diagnostic=={'request_TLS_stores':[value]}
            rows.append(expected_native_projection()[len(rows)])
    return rows


def providers():
    return dict(inherited_TLS_getter=previous.providers(),maximum_handler_reads=2,maximum_main_SVCs=4,
        retired_completed_observation_windows=['tls_active'],original_scope_kept=True,
        independent_model_owners=['vm_full.py:VM.run','vm9_request_vm.py:_execute_request_vm_impl.callback',
            'vm9_objects.py:get_emulated_tls_address'],current_and_declared_numeric_values_compared=False,
        new_OS_JNI_or_internal_helper_providers=[],allocation_and_service_count_deltas={},
        stop_before=hex(STOP),outer_bytecode=hex(CALL))


class Scenario(previous.Scenario):
    def __init__(self,c):
        super().__init__(c);self.store_active=False;self.store_done=False
        self.store_steps=[];self.store_loads=[];self.store_writes=[];self.store_arithmetic=[];self.TLS_writes=[]

    def native_runner(self,*args,**kwargs):
        original=kwargs['memory_write_observer']
        def write(cpu,address,size):
            if self.store_active:
                reg=lambda n:cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(n)))
                off=cpu.reg_read(arm.UC_ARM64_REG_PC)-self.image
                bc=int.from_bytes(cpu.mem_read(self.scope_state['PC_slot'],8),'little')-self.image
                if address in (self.scope_frame+1528,self.scope_frame+2776,self.scope_frame+2768,self.scope_frame+2784):
                    a,offset,width=STORES[len(self.store_writes)]
                    expected={1528:self.hash_registry_member,2776:self.hash_registry_member,
                        2768:self.image+TARGET,2784:self.store_value}
                    assert (bc,address,size)==(a,self.scope_frame+offset,width)
                    if size==8:assert off==0x171268 and reg(15)==expected[offset]
                    else:assert off==0x17208C and (reg(11)&0xFFFFFFFF)==expected[offset]
                    self.store_writes.append(dict(cursor_bytecode=hex(a),frame_offset=offset,size=width))
                if address==self.tls_pointer:
                    assert off==0x27ED8C and size==4 and (reg(19)&0xFFFFFFFF)==self.store_value
                    self.TLS_writes.append(dict(native_pc=hex(off),size=4,value_matches_native_arithmetic=True))
            original(cpu,address,size)
        kwargs['memory_write_observer']=write
        return super().native_runner(*args,**kwargs)

    def tls_boundary(self,cpu,state):
        old=next(r for r in json.loads(previous.EVIDENCE.read_text())['case_results'] if r['control']==self.control)
        prefix=state['configuration_tls_prefix']
        for k in ('instruction_observations','trace_sha256','code_sha256'):assert prefix[k]==old['continuation_'+k]
        assert self.tls_done and self.tls_active and self.original_scope
        assert graph.digest(state['allocator_events_ref'])==old['allocation_ledger_sha256']
        raw=lambda a,n:bytes(cpu.mem_read(a,n));u=lambda a,n=8:int.from_bytes(raw(a,n),'little')
        self.store_initial_R=[u(state['backing']+i*8) for i in range(32)]
        self.store_scalar=u(self.scope_frame+1888);self.store_hash=u(self.scope_frame+2832)
        self.store_opaque=u(self.scope_frame+4856);self.store_word=u(self.scope_frame+2808,4)
        assert self.store_initial_R[16:18]==[self.store_opaque,self.store_hash] and self.store_word==0
        self.store_rotated=rotated(self.store_hash,self.store_scalar,self.store_opaque)
        self.store_value=(self.store_rotated^self.store_word)&0xFFFFFFFF
        self.store_before=raw(self.tls_pointer,16);self.store_padding=raw(self.scope_frame+2788,12)
        self.store_preserved={a:raw(a,n) for a,n in ((self.scope_owner,264),(self.exit_counter,16),
            (self.source_counter,16),(self.clone_destination,24),(self.clone_new_payload,11),(self.copy_table,2048),
            (self.image+previous.previous.TABLE,2048),(self.scope_frame+2832,8),(self.scope_frame+1888,8),
            (self.scope_frame+2808,4),(self.image+CONTROL,32),(self.tls_array,128),(self.hash_registry_member,32))}
        self.store_allocations=deepcopy(state['allocator_events_ref'])
        self.tls_active=False;self.store_active=True

    def observe(self,cpu,pc,state):
        self.scope_state=state
        if not self.store_active:
            super().observe(cpu,pc,state)
            if not self.store_active:return
        off=pc-self.image
        reg=lambda n:cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(n)))
        raw=lambda a,n:bytes(cpu.mem_read(a,n));u=lambda a,n=8:int.from_bytes(raw(a,n),'little')
        bc=u(state['PC_slot'])-self.image
        if off in (0x27E6AC,0x27ED6C):raise AssertionError('unexpected ordinary callback/wrapper RET')
        if bc!=previous.CALL and (not self.store_steps or self.store_steps[-1]!=hex(bc)):
            assert bc==WORDS[len(self.store_steps)][0];self.store_steps.append(hex(bc))
            R=lambda i:u(state['backing']+i*8)
            expectations={0xFD5F4:(18,self.store_scalar),0xFD5F8:(1,self.store_scalar^self.store_hash),
                0xFD60C:(1,self.store_scalar^self.store_hash^self.store_opaque),0xFD610:(1,self.store_rotated),
                0xFD614:(1,sx32(self.store_rotated)),0xFD618:(2,sx32(self.store_word)),
                0xFD61C:(1,sx32(self.store_rotated)^sx32(self.store_word))}
            if bc in expectations:
                i,value=expectations[bc];assert R(i)==value
                self.store_arithmetic.append(arithmetic_projection()[len(self.store_arithmetic)])
        if off==context.LOAD:
            a,offset,destination,source=LOADS[len(self.store_loads)]
            base=self.scope_frame if source=='frame' else self.image+GOT_BASE
            expected={0xFD5F0:self.store_scalar,0xFD5F8:self.image+TARGET,0xFD620:self.image+WRAPPER}[bc]
            assert (bc,reg(12),reg(13),reg(14),u(base+offset))==(a,base,offset,destination,expected)
            self.store_loads.append(dict(bytecode=hex(a),offset=offset,destination=destination,source=source))
        if off==0x16AA48:
            assert bc==CALL and reg(8)==self.image+WRAPPER and reg(0)==self.scope_frame+2768
            assert (u(reg(0)),u(reg(0)+8),u(reg(0)+16,4))==(self.image+TARGET,self.hash_registry_member,self.store_value)
            selected=(1,2,4,5,18,25,31)
            assert [u(state['backing']+i*8) for i in selected]==[sx32(self.store_value),sx32(self.store_word),
                self.image+WRAPPER,self.scope_frame+2768,self.store_scalar,self.image+0x28587C,self.image+CALL+4]
            assert all(u(state['backing']+i*8)==self.store_initial_R[i] for i in range(32) if i not in selected)
            assert raw(self.scope_frame+2788,12)==self.store_padding;self.store_call_seen=True
        if off==TARGET:
            assert self.store_call_seen and (reg(0),reg(1))==(self.hash_registry_member,self.store_value)
            self.store_target_seen=True
        if off==0x34377C:
            assert self.store_target_seen and reg(0)==self.image+CONTROL;self.store_emutls_seen=True
        if off==0x27ED8C:
            assert self.store_emutls_seen and (reg(0),reg(19))==(self.tls_pointer,self.store_value)
        if off==STOP and bc==CALL:
            assert self.TLS_writes and reg(0)==self.tls_pointer and u(self.tls_pointer,4)==self.store_value
            assert raw(self.tls_pointer+4,12)==self.store_before[4:] and raw(self.scope_frame+2788,12)==self.store_padding
            for a,b in self.store_preserved.items():assert raw(a,len(b))==b
            assert u(self.source_counter,4)==u(self.exit_counter,4)==1
            assert raw(state['context'],128)==state['handler_bytes'] and self.original_scope
            assert state['allocator_events_ref']==self.store_allocations
            self.store_done=True;self.store_boundary(cpu,state)

    def store_boundary(self,cpu,state):
        cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,context.outer.oracle.STOP)

    def finish(self,result,state,proof):
        data=json.loads(previous.EVIDENCE.read_text());previous.validate(data)
        old=next(r for r in data['case_results'] if r['control']==self.control);prefix=proof['configuration_tls_prefix']
        assert self.store_done and result['allocator_events']==self.store_allocations
        assert result['actual_allocator_counts']==old['allocator_counts'] and result['explicit_service_counts']==old['service_counts']
        for k in ('JNI_calls','libc_SVC_boundaries','main_image_SVC_boundaries'):assert proof[k]==prefix[k]==old[k]
        return dict(control=self.control,retained_TLS_prefix_verified=True,
            retained_prefix_instruction_observations=prefix['instruction_observations'],retained_prefix_trace_sha256=prefix['trace_sha256'],
            retained_prefix_code_sha256=prefix['code_sha256'],retired_completed_observers=['tls_active'],original_scope_kept=True,
            executed_bytecodes=self.store_steps,native_loads=self.store_loads,native_stores=self.store_writes,
            native_arithmetic=self.store_arithmetic,native_TLS_writes=self.TLS_writes,selected_store_projection=selected_projection(),
            allocation_ledger_sha256=graph.digest(result['allocator_events']),allocator_counts=old['allocator_counts'],
            service_counts=old['service_counts'],JNI_calls=proof['JNI_calls'],libc_SVC_boundaries=proof['libc_SVC_boundaries'],
            main_image_SVC_boundaries=proof['main_image_SVC_boundaries'],continuation_instruction_observations=proof['instruction_observations'],
            continuation_trace_sha256=proof['trace_sha256'],continuation_code_sha256=proof['code_sha256'],
            observation_stop_before=hex(STOP),outer_bytecode=hex(CALL),callback_or_ordinary_RET_seen=False)


def replay(path,libc,*,on_case=None,case_controls=None):
    return context.replay(path,libc,on_case=on_case,case_controls=case_controls,_extension_factory=Scenario,
        _request_profile=name.previous.previous.PROFILE['name'],_handler_read_profile=context.NULL_PAYLOAD_READ_PROFILE['name'])


def verify_images(data,path,libc):
    from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
    previous.verify_images({},path,libc);elf,_,read=graph.inputs.load_elf(path);decoder=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
    for a,m,s in EXPECTED:
        ins,=decoder.disasm(read(a,4),a);assert (ins.mnemonic,ins.op_str)==(m,s),(hex(a),ins.mnemonic,ins.op_str)
    for a,w in WORDS:assert int.from_bytes(read(a,4),'little')==w,hex(a)
    rel=[r for s in elf.iter_sections() if s['sh_type']=='SHT_RELA' for r in s.iter_relocations() if r['r_offset']==0x382ED8]
    assert len(rel)==1 and rel[0]['r_info_type']==1027 and rel[0]['r_addend']==TARGET
    assert interpreter_projection(path)==expected_VM_projection()
    return dict(instruction_bindings=len(EXPECTED),bytecode_words=len(WORDS),GOT_relative_relocation_verified=True,
        fresh_declared_VM_cases=6,actual_request_callback_source_executed=True)


def validate(data):
    assert data['schema']=='vm9-native-171-configuration-tls-store-20261119-v1' and data['claims']==CLAIMS and data['providers']==providers()
    assert data['instructions']==[dict(offset=hex(a),mnemonic=m,operands=s) for a,m,s in EXPECTED]
    assert data['bytecode_words']==[dict(offset=hex(a),word=hex(w)) for a,w in WORDS]
    assert data['independent_Python_VM_projection']==expected_VM_projection()
    assert data['independent_native_setter_projection']==expected_native_projection()
    assert data['request_callback_source_sha256']==hashlib.sha256(Path(previous.owner.__file__).read_bytes()).hexdigest()
    old_data=json.loads(previous.EVIDENCE.read_text());previous.validate(old_data)
    assert data['provenance']==old_data['provenance'] and len(data['case_results'])==len(context.controls())
    for row,old in zip(data['case_results'],old_data['case_results']):
        assert row['control']==old['control'] and row['retained_TLS_prefix_verified'] is True
        for k in ('instruction_observations','trace_sha256','code_sha256'):assert row['retained_prefix_'+k]==old['continuation_'+k]
        assert row['retired_completed_observers']==['tls_active'] and row['original_scope_kept'] is True
        assert row['executed_bytecodes']==[hex(a) for a,_ in WORDS]
        assert row['native_loads']==[dict(bytecode=hex(a),offset=o,destination=d,source=s) for a,o,d,s in LOADS]
        assert row['native_stores']==[dict(cursor_bytecode=hex(a),frame_offset=o,size=n) for a,o,n in STORES]
        assert row['native_arithmetic']==arithmetic_projection() and row['selected_store_projection']==selected_projection()
        assert row['native_TLS_writes']==[dict(native_pc='0x27ed8c',size=4,value_matches_native_arithmetic=True)]
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
        else:raise AssertionError('damaged TLS store evidence accepted: '+str(path))
    for k,v in CLAIMS.items():reject(('claims',k),not v)
    for k,v in [('maximum_handler_reads',3),('maximum_main_SVCs',5)]:reject(('providers',k),v)
    reject(('instructions',0,'mnemonic'),'nop');reject(('bytecode_words',0,'word'),'0x0')
    reject(('request_callback_source_sha256',),'0'*64)
    reject(('independent_Python_VM_projection',0,'derived_value_u32'),'0x0')
    reject(('independent_native_setter_projection',0,'no_allocation_or_wake'),False)
    for i in range(len(data['case_results'])):
        changes=[(('retained_TLS_prefix_verified',),False),(('retained_prefix_trace_sha256',),'0'*64),
            (('retired_completed_observers',),[]),(('original_scope_kept',),False),(('executed_bytecodes',),[]),
            (('native_loads',),[]),(('native_stores',),[]),(('native_arithmetic',),[]),(('native_TLS_writes',0,'size'),8),
            (('allocation_ledger_sha256',),'0'*64),(('allocator_counts','malloc'),0),(('service_counts','syscall_226'),0),
            (('JNI_calls',),[]),(('libc_SVC_boundaries',),[]),(('main_image_SVC_boundaries',),[]),
            (('continuation_instruction_observations',),0),(('continuation_trace_sha256',),'bad'),
            (('continuation_code_sha256',),'bad'),(('observation_stop_before',),'0x0'),(('outer_bytecode',),hex(ENTRY)),
            (('callback_or_ordinary_RET_seen',),True)]
        for k,v in selected_projection().items():changes.append((('selected_store_projection',k),not v if isinstance(v,bool) else 'bad'))
        for path,value in changes:reject(('case_results',i)+path,value)
    return count


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--elf',type=Path);ap.add_argument('--libc',type=Path);ap.add_argument('--replay',action='store_true')
    args=ap.parse_args()
    if args.replay and (not args.elf or not args.libc):ap.error('--replay requires --elf and --libc')
    data=json.loads(EVIDENCE.read_text());validate(data)
    result=dict(retained_configuration_TLS_store_cases=len(data['case_results']),damaged_evidence_rejected=negatives(data),
        current_request_numeric_Python_equality_verified=False,ordinary_Cronet_six_headers_verified=False,
        complete_standalone_signer_verified=False)
    if args.elf:result['image_bindings']=verify_images(data,args.elf,args.libc)
    elif args.libc:graph.inputs.libc_image(args.libc)
    if args.replay:
        assert independent_native_controls(args.elf,args.libc)==data['independent_native_setter_projection']
        assert replay(args.elf,args.libc)==data['case_results'],'frozen configuration TLS store replay differs'
        result['original_code_cases_replayed']=len(data['case_results']);result['fresh_declared_native_setter_controls_replayed']=6
    print(json.dumps(result))


if __name__=='__main__':main()
