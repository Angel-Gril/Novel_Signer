"""Original configuration header preparation and 56-byte copy, before consumption.

Native observations check instruction contracts only. Independent declared VM
pages execute the existing request callback; no native snapshot seeds Python.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
from unicorn import arm64_const as arm
import verify_vm9_native_171_configuration_tls_store_20261119 as previous

context,graph,name=previous.context,previous.graph,previous.name
EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_configuration_copy56_20261120.json')
ENTRY,CALL,STOP=0xFD62C,0xFD694,0x16AA4C
FRAME_SIZE=0x1400
WRAPPER,TARGET=0x2858A8,0x347F60
RAW_WORDS=[0x9346C80F,0x9348CA0F,0x934A420F,0x00020E0F,0x9344C10F,0xB3512418,
    0xB340985A,0xAB7B4116,0xA358985A,0xA340D91A,0x9B58B85A,0x9B58D11A,
    0x9350D11A,0x935C0A18,0x9348D11A,0x935B0E18,0x9340D11A,0x9378C91A,
    0x91810418,0x8B40491A,0xA378411A,0x837E0E18,0x8370411A,0x9348411A,
    0xA35F0A18,0x05C19B11,0x067E0C91]
WORDS=[(ENTRY+i*4,w) for i,w in enumerate(RAW_WORDS)]
LOADS=[(0xFD640,4656,6,'frame'),(0xFD660,1928,2,'frame'),(0xFD668,1912,2,'frame'),
    (0xFD674,48,2,'ELF GOT'),(0xFD680,2008,16,'frame'),(0xFD68C,2024,4,'frame')]
# Native STORE64 advances the cursor before its write; STORE32 advances after.
STORES=[(0xFD648,1632,8),(0xFD648,4968,4),(0xFD650,1656,8),(0xFD654,4960,8),
    (0xFD658,1784,8),(0xFD65C,4952,8),(0xFD660,4944,8),(0xFD668,4936,8),
    (0xFD670,4928,8),(0xFD674,4920,8),(0xFD67C,4384,8),(0xFD680,4376,8),
    (0xFD688,4368,8),(0xFD68C,4360,8)]
WINDOWS=[(1632,1640),(1656,1664),(1784,1792),(2088,2144),(4360,4392),(4920,4972)]
EXPECTED=[(context.LOAD,'ldr','x9, [x12, x13]'),(0x171268,'str','x15, [x17, x16]'),
    (0x17208C,'str','w11, [x12, x10]'),(WRAPPER,'ldp','x8, x1, [x0, #8]'),
    (0x2858AC,'ldr','x2, [x0, #0x18]'),(0x2858B0,'ldr','x3, [x0]'),
    (0x2858B4,'mov','x0, x8'),(0x2858B8,'br','x3'),(TARGET,'adrp','x16, #0x375000'),
    (0x347F64,'ldr','x17, [x16, #0x240]'),(0x347F68,'add','x16, x16, #0x240'),
    (0x347F6C,'br','x17'),(STOP,'ldp','x5, x1, [x29, #-0x90]')]
CASES=[('small',0x12345678,0x66001000),('wide',0xFEDCBA9876543210,0x66002000)]
CLAIMS=dict(retained_TLS_store_instruction_code_and_allocation_prefix_verified=True,
    completed_store_observer_retired_after_full_prefix=True,original_scope_kept=True,
    original_header_pointer_preparation_and_copy_executed=True,source_final_four_padding_bytes_preserved=True,
    copy_destination_matches_pre_call_source=True,copy_source_and_adjacent_destination_bytes_preserved=True,
    returned_X0_is_destination=True,old_TLS_hash_clone_tables_and_count1_references_preserved=True,
    no_new_allocation_or_service_JNI_SVC=True,actual_request_callback_source_executed_on_fresh_declared_pages=True,
    four_independent_declared_VM_cases_verified=True,native_memory_used_as_Python_model_input=False,
    current_request_numeric_Python_equality_verified=False,copy_return_consumed=False,
    configuration_suffix_return_verified=False,complete_configuration_provenance_verified=False,
    real_business_state_or_JVM_identity_verified=False,KMSV_value_generated=False,client_key_value_generated=False,
    ordinary_Cronet_six_headers_verified=False,whole_request_equivalence_verified=False,
    callback_or_ordinary_wrapper_returned=False,complete_standalone_signer_verified=False,
    new_OS_JNI_or_internal_helper_providers=False,Android_execution=False,online_acceptance_verified=False)


def selected_projection():
    return dict(virtual_frame_size=FRAME_SIZE,frame_allocation_bytecode='0xf7720',frame_allocation_word='0xef7b000f',
        native_cursor_offset_above_frame=16,native_backing_offset_above_frame=24,
        surrounding_window_preserved_except_checked_cursor_and_register_backing=True,
        scalar_source='R18',first_string_source_frame_offset=1912,second_string_source_frame_offset=1928,
        seed_frame_offset=4868,output_slots_frame_offsets=[4896,4904],mode_u32=0,source_frame_offset=4920,
        destination_frame_offset=2088,packed_frame_offset=4360,size=56,source_padding_bytes=4,
        saved_pointer_frame_offsets=[1632,1656,1784],wrapper=hex(WRAPPER),target=hex(TARGET),
        GOT_slot_offset=hex(previous.GOT_BASE+48),PLT_symbol='memcpy',X0_equals_destination=True,
        source_preserved=True,destination_adjacent8_before_and_after_preserved=True,
        selected_registers_and_all_frame_write_ranges_verified=True)


def expected_VM_projection():
    return [dict(image_base=hex(b),case=label,declared_scalar_u64=hex(scalar),
        executed_bytecodes=[hex(a) for a,_ in WORDS],frame_header_and_pointer_slots_verified=True,
        copy56_source_destination_and_padding_verified=True,actual_request_callback_source_executed=True,
        selected_registers_and_all_frame_write_ranges_verified=True,no_TLS_or_allocator_service=True,
        native_snapshot_input=False) for b in graph.BASES for label,scalar,_ in CASES]


def interpreter_projection(path):
    saved=os.environ.get('TOMATO_LIBMETASEC')
    try:
        os.environ['TOMATO_LIBMETASEC']=str(path.resolve());import vm_full as module
    finally:
        if saved is None:os.environ.pop('TOMATO_LIBMETASEC',None)
        else:os.environ['TOMATO_LIBMETASEC']=saved
    assert hashlib.sha256(module.SO).hexdigest()==previous.graph.inputs.SHA256
    class Boundary(Exception):pass
    rows=[];old_base=module.B
    try:
        for image in previous.graph.BASES:
            module.B=image
            for label,scalar,pointer in CASES:
                pages,frame,clone,payload,counter,sibling,member,array,block,put,read,w,get_tls,allocs=previous.previous.fresh(image)
                source,destination=frame+4920,frame+2088
                put(source,b'\xa5'*56);put(destination-8,b'\x5a'*72)
                for offset,value in [(4656,pointer),(1928,0x66003000),(1912,0x66004000),
                    (2008,destination),(2024,image+0x2858A8)]:w(frame+offset,value)
                w(image+previous.GOT_BASE+48,image+0x347F60)
                before=read(frame,0x2000)
                expected=b''.join(x.to_bytes(8,'little') for x in (scalar,0x66004000,0x66003000,
                    frame+4868,frame+4896,frame+4904))+bytes(4)+b'\xa5'*4
                for i,word in enumerate(RAW_WORDS):put(image+ENTRY+i*4,word.to_bytes(4,'little'))
                put(image+CALL+4,bytes(4))
                class Memory:
                    def __init__(self):self.pages=pages
                    def u32(self,a):return int.from_bytes(read(a,4),'little')
                    def u64(self,a):return int.from_bytes(read(a,8),'little')
                    def rb(self,a):return read(a,1)[0]
                    def w32(self,a,v):w(a,v,4)
                    def w64(self,a,v):w(a,v)
                m=Memory();vm=module.VM(m,ENTRY,0,0,0,0,0,maxsteps=30)
                vm.R=[0xA5A5000000000000+i for i in range(32)]
                vm.R[0]=vm.R[21]=0;vm.R[18]=scalar;vm.R[20]=source
                vm.R[22]=image+previous.GOT_BASE;vm.R[23]=image+0x28587C;vm.R[29]=frame
                initial=list(vm.R);vm.cb=image+0x28587C;ledger=[];diagnostic={};steps=[]
                def reject(*args):raise AssertionError('copy VM unexpectedly requested TLS')
                callback=previous.previous._callback(image,reject,diagnostic,ledger)
                def native(vm,function,packed):
                    assert (vm.pc,function,packed)==(image+CALL,image+0x2858A8,frame+4360)
                    assert [m.u64(packed+i*8) for i in range(4)]==[image+0x347F60,destination,source,56]
                    assert read(source,56)==expected
                    callback(vm,function,packed)
                    assert read(source,56)==read(destination,56)==expected
                def step(vm,word,op,sub):
                    if vm.pc==image+CALL+4:raise Boundary()
                    assert (vm.pc-image,word)==(ENTRY+len(steps)*4,RAW_WORDS[len(steps)])
                    steps.append(hex(vm.pc-image))
                vm.native_hook=native;vm.step_hook=step
                try:vm.run()
                except Boundary:pass
                else:raise AssertionError('copy VM did not stop after call')
                selected=(1,2,3,4,5,6,16,25,31)
                assert [vm.R[i] for i in selected]==[56,image+0x347F60,frame+4896,image+0x2858A8,
                    frame+4360,pointer,destination,image+0x28587C,image+CALL+4]
                assert all(vm.R[i]==initial[i] for i in range(32) if i not in selected)
                windows=[(1632,1640),(1656,1664),(1784,1792),(2088,2144),(4360,4392),(4920,4972)]
                assert all(a==b for i,(a,b) in enumerate(zip(before,read(frame,0x2000)))
                    if not any(start<=i<end for start,end in windows))
                assert read(destination-8,8)==read(destination+56,8)==b'\x5a'*8
                assert len(ledger)==1 and diagnostic=={} and allocs==[]
                assert m.u64(frame+1632)==pointer and m.u64(frame+1656)==frame+4904 and m.u64(frame+1784)==frame+4896
                rows.append(dict(image_base=hex(image),case=label,declared_scalar_u64=hex(scalar),
                    executed_bytecodes=steps,frame_header_and_pointer_slots_verified=True,
                    copy56_source_destination_and_padding_verified=True,actual_request_callback_source_executed=True,
                    selected_registers_and_all_frame_write_ranges_verified=True,no_TLS_or_allocator_service=True,
                    native_snapshot_input=False))
    finally:module.B=old_base
    return rows


def providers():
    return dict(inherited_TLS_store=previous.providers(),maximum_handler_reads=2,maximum_main_SVCs=4,
        retired_completed_observation_windows=['store_active'],original_scope_kept=True,
        independent_model_owners=['vm_full.py:VM.run','vm9_request_vm.py:_execute_request_vm_impl.callback'],
        current_and_declared_numeric_values_compared=False,new_OS_JNI_or_internal_helper_providers=[],
        allocation_and_service_count_deltas={},stop_before=hex(STOP),outer_bytecode=hex(CALL))


class Scenario(previous.Scenario):
    def __init__(self,c):
        super().__init__(c);self.copy56_active=False;self.copy56_done=False
        self.copy56_steps=[];self.copy56_loads=[];self.copy56_writes=[]

    def native_runner(self,*args,**kwargs):
        original=kwargs['memory_write_observer']
        def write(cpu,address,size):
            if self.copy56_active:
                offset=address-self.scope_frame
                if any(start<=offset<end for start,end in WINDOWS) and not 2088<=offset<2144:
                    bc=int.from_bytes(cpu.mem_read(self.scope_state['PC_slot'],8),'little')-self.image
                    a,o,n=STORES[len(self.copy56_writes)]
                    assert (bc,offset,size)==(a,o,n),(hex(bc),offset,size,hex(a),o,n,self.copy56_writes)
                    pc=cpu.reg_read(arm.UC_ARM64_REG_PC)-self.image
                    r=15 if n==8 else 11
                    value=cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(r)))&((1<<(n*8))-1)
                    assert pc==(0x171268 if n==8 else 0x17208C) and value==self.copy56_values[o],(hex(pc),o,n)
                    self.copy56_writes.append(dict(cursor_bytecode=hex(a),frame_offset=o,size=n))
            original(cpu,address,size)
        kwargs['memory_write_observer']=write
        return super().native_runner(*args,**kwargs)

    def store_boundary(self,cpu,state):
        data=json.loads(previous.EVIDENCE.read_text());previous.validate(data)
        old=next(r for r in data['case_results'] if r['control']==self.control)
        prefix=state['configuration_tls_store_prefix']
        for k in ('instruction_observations','trace_sha256','code_sha256'):assert prefix[k]==old['continuation_'+k]
        for k in ('JNI_calls','libc_SVC_boundaries','main_image_SVC_boundaries'):assert prefix[k]==old[k]
        assert self.store_done and self.store_active and self.original_scope
        assert graph.digest(state['allocator_events_ref'])==old['allocation_ledger_sha256']
        raw=lambda a,n:bytes(cpu.mem_read(a,n));u=lambda a,n=8:int.from_bytes(raw(a,n),'little')
        f=self.scope_frame;self.copy56_initial_R=[u(state['backing']+i*8) for i in range(32)]
        assert state['PC_slot']==f+FRAME_SIZE+16 and state['backing']==f+FRAME_SIZE+24
        self.copy56_scalar=self.copy56_initial_R[18];self.copy56_pointer=u(f+4656)
        assert self.copy56_initial_R[20]==f+4920 and self.copy56_scalar==self.store_scalar
        assert u(f+2008)==f+2088 and u(f+2024)==self.image+WRAPPER
        self.copy56_values={1632:self.copy56_pointer,4968:0,1656:f+4904,4960:f+4904,
            1784:f+4896,4952:f+4896,4944:f+4868,4936:u(f+1928),4928:u(f+1912),
            4920:self.copy56_scalar,4384:56,4376:f+4920,4368:f+2088,4360:self.image+TARGET}
        self.copy56_before=raw(f,0x2000)
        self.copy56_expected=b''.join(self.copy56_values[o].to_bytes(8,'little') for o in range(4920,4968,8))+bytes(4)+raw(f+4972,4)
        self.copy56_preserved={a:raw(a,n) for a,n in ((self.scope_owner,264),(self.exit_counter,16),
            (self.source_counter,16),(self.clone_destination,24),(self.clone_new_payload,11),(self.copy_table,2048),
            (self.image+previous.previous.previous.TABLE,2048),(self.tls_pointer,16),
            (self.image+previous.CONTROL,32),(self.tls_array,128),(self.hash_registry_member,32))}
        self.copy56_allocations=deepcopy(state['allocator_events_ref'])
        self.store_active=False;self.copy56_active=True

    def observe(self,cpu,pc,state):
        self.scope_state=state
        if not self.copy56_active:
            super().observe(cpu,pc,state)
            if not self.copy56_active:return
        off=pc-self.image
        reg=lambda n:cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(n)))
        raw=lambda a,n:bytes(cpu.mem_read(a,n));u=lambda a,n=8:int.from_bytes(raw(a,n),'little')
        bc=u(state['PC_slot'])-self.image;f=self.scope_frame
        if off in (0x27E6AC,0x27ED6C):raise AssertionError('unexpected ordinary callback/wrapper RET')
        if bc!=previous.CALL and (not self.copy56_steps or self.copy56_steps[-1]!=hex(bc)):
            assert bc==WORDS[len(self.copy56_steps)][0],(hex(off),hex(bc),self.copy56_steps)
            self.copy56_steps.append(hex(bc))
        if off==context.LOAD:
            a,o,d,s=LOADS[len(self.copy56_loads)];base=f if s=='frame' else self.image+previous.GOT_BASE
            expected={4656:self.copy56_pointer,1928:self.copy56_values[4936],1912:self.copy56_values[4928],
                48:self.image+TARGET,2008:f+2088,2024:self.image+WRAPPER}[o]
            assert (bc,reg(12),reg(13),reg(14),u(base+o))==(a,base,o,d,expected)
            self.copy56_loads.append(dict(bytecode=hex(a),offset=o,destination=d,source=s))
        if off==0x16AA48:
            assert (bc,reg(8),reg(0))==(CALL,self.image+WRAPPER,f+4360)
            assert [u(f+4360+i*8) for i in range(4)]==[self.image+TARGET,f+2088,f+4920,56]
            assert raw(f+4920,56)==self.copy56_expected
            selected=(1,2,3,4,5,6,16,25,31)
            assert [u(state['backing']+i*8) for i in selected]==[56,self.image+TARGET,f+4896,
                self.image+WRAPPER,f+4360,self.copy56_pointer,f+2088,self.image+0x28587C,self.image+CALL+4]
            assert all(u(state['backing']+i*8)==self.copy56_initial_R[i] for i in range(32) if i not in selected)
            self.copy56_call_R=[u(state['backing']+i*8) for i in range(32)]
            self.copy56_call_seen=True
        if off==TARGET:
            assert self.copy56_call_seen and (reg(0),reg(1),reg(2))==(f+2088,f+4920,56)
            self.copy56_target_seen=True
        if off==STOP and bc==CALL:
            assert self.copy56_target_seen and reg(0)==f+2088
            assert raw(f+2088,56)==raw(f+4920,56)==self.copy56_expected
            runtime=[(FRAME_SIZE+16,FRAME_SIZE+24),(FRAME_SIZE+24,FRAME_SIZE+24+256)]
            changed=[i for i,(a,b) in enumerate(zip(self.copy56_before,raw(f,0x2000)))
                if a!=b and not any(start<=i<end for start,end in WINDOWS+runtime)]
            assert not changed,('unexpected frame writes',changed)
            assert [u(state['backing']+i*8) for i in range(32)]==self.copy56_call_R
            for o,v in self.copy56_values.items():assert u(f+o,4 if o==4968 else 8)==v
            for a,b in self.copy56_preserved.items():assert raw(a,len(b))==b
            assert u(self.source_counter,4)==u(self.exit_counter,4)==1
            assert raw(state['context'],128)==state['handler_bytes'] and self.original_scope
            assert state['allocator_events_ref']==self.copy56_allocations
            self.copy56_done=True;cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,context.outer.oracle.STOP)

    def finish(self,result,state,proof):
        old=next(r for r in json.loads(previous.EVIDENCE.read_text())['case_results'] if r['control']==self.control)
        prefix=proof['configuration_tls_store_prefix']
        assert self.copy56_done and result['allocator_events']==self.copy56_allocations
        assert result['actual_allocator_counts']==old['allocator_counts'] and result['explicit_service_counts']==old['service_counts']
        for k in ('JNI_calls','libc_SVC_boundaries','main_image_SVC_boundaries'):assert proof[k]==prefix[k]==old[k]
        return dict(control=self.control,retained_TLS_store_prefix_verified=True,
            retained_prefix_instruction_observations=prefix['instruction_observations'],retained_prefix_trace_sha256=prefix['trace_sha256'],
            retained_prefix_code_sha256=prefix['code_sha256'],retired_completed_observers=['store_active'],original_scope_kept=True,
            executed_bytecodes=self.copy56_steps,native_loads=self.copy56_loads,native_stores=self.copy56_writes,
            selected_copy_projection=selected_projection(),allocation_ledger_sha256=graph.digest(result['allocator_events']),
            allocator_counts=old['allocator_counts'],service_counts=old['service_counts'],JNI_calls=proof['JNI_calls'],
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
        ins,=decoder.disasm(read(a,4),a);assert (ins.mnemonic,ins.op_str)==(m,s),(hex(a),ins.mnemonic,ins.op_str)
    for a,w in WORDS:assert int.from_bytes(read(a,4),'little')==w,hex(a)
    assert int.from_bytes(read(0xF7720,4),'little')==0xEF7B000F  # R29 -= 5120
    for offset,kind in ((previous.GOT_BASE+48,257),(0x375240,1026)):
        rows=[(s,r) for s in elf.iter_sections() if s['sh_type']=='SHT_RELA' for r in s.iter_relocations() if r['r_offset']==offset]
        (section,rel),=rows
        assert rel['r_info_type']==kind and rel['r_addend']==0
        assert elf.get_section(section['sh_link']).get_symbol(rel['r_info_sym']).name=='memcpy'
    assert interpreter_projection(path)==expected_VM_projection()
    return dict(instruction_bindings=len(EXPECTED),bytecode_words=len(WORDS),memcpy_symbol_relocations=2,
        frame_allocation_words=1,fresh_declared_VM_cases=4,actual_request_callback_source_executed=True)


def validate(data):
    assert data['schema']=='vm9-native-171-configuration-copy56-20261120-v1' and data['claims']==CLAIMS and data['providers']==providers()
    assert data['instructions']==[dict(offset=hex(a),mnemonic=m,operands=s) for a,m,s in EXPECTED]
    assert data['bytecode_words']==[dict(offset=hex(a),word=hex(w)) for a,w in WORDS]
    assert data['independent_Python_VM_projection']==expected_VM_projection()
    assert data['request_callback_source_sha256']==hashlib.sha256(Path(previous.previous.owner.__file__).read_bytes()).hexdigest()
    old_data=json.loads(previous.EVIDENCE.read_text());previous.validate(old_data)
    assert data['provenance']==old_data['provenance'] and len(data['case_results'])==len(context.controls())
    for row,old in zip(data['case_results'],old_data['case_results']):
        assert row['control']==old['control'] and row['retained_TLS_store_prefix_verified'] is True
        for k in ('instruction_observations','trace_sha256','code_sha256'):assert row['retained_prefix_'+k]==old['continuation_'+k]
        assert row['retired_completed_observers']==['store_active'] and row['original_scope_kept'] is True
        assert row['executed_bytecodes']==[hex(a) for a,_ in WORDS]
        assert row['native_loads']==[dict(bytecode=hex(a),offset=o,destination=d,source=s) for a,o,d,s in LOADS]
        assert row['native_stores']==[dict(cursor_bytecode=hex(a),frame_offset=o,size=n) for a,o,n in STORES]
        assert row['selected_copy_projection']==selected_projection()
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
        else:raise AssertionError('damaged copy evidence accepted: '+str(path))
    for k,v in CLAIMS.items():reject(('claims',k),not v)
    for k,v in [('maximum_handler_reads',3),('maximum_main_SVCs',5)]:reject(('providers',k),v)
    reject(('instructions',0,'mnemonic'),'nop');reject(('bytecode_words',0,'word'),'0x0')
    reject(('request_callback_source_sha256',),'0'*64)
    reject(('independent_Python_VM_projection',0,'declared_scalar_u64'),'0x0')
    for i in range(len(data['case_results'])):
        changes=[(('retained_TLS_store_prefix_verified',),False),(('retained_prefix_trace_sha256',),'0'*64),
            (('retired_completed_observers',),[]),(('original_scope_kept',),False),(('executed_bytecodes',),[]),
            (('native_loads',),[]),(('native_stores',),[]),(('allocation_ledger_sha256',),'0'*64),
            (('allocator_counts','malloc'),0),(('service_counts','syscall_226'),0),(('JNI_calls',),[]),
            (('libc_SVC_boundaries',),[]),(('main_image_SVC_boundaries',),[]),
            (('continuation_instruction_observations',),0),(('continuation_trace_sha256',),'bad'),
            (('continuation_code_sha256',),'bad'),(('observation_stop_before',),'0x0'),(('outer_bytecode',),hex(ENTRY)),
            (('callback_or_ordinary_RET_seen',),True)]
        for k,v in selected_projection().items():changes.append((('selected_copy_projection',k),not v if isinstance(v,bool) else 'bad'))
        for path,value in changes:reject(('case_results',i)+path,value)
    return count


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--elf',type=Path);ap.add_argument('--libc',type=Path);ap.add_argument('--replay',action='store_true')
    args=ap.parse_args()
    if args.replay and (not args.elf or not args.libc):ap.error('--replay requires --elf and --libc')
    data=json.loads(EVIDENCE.read_text());validate(data)
    result=dict(retained_configuration_copy56_cases=len(data['case_results']),damaged_evidence_rejected=negatives(data),
        current_request_numeric_Python_equality_verified=False,ordinary_Cronet_six_headers_verified=False,
        complete_standalone_signer_verified=False)
    if args.elf:result['image_bindings']=verify_images(data,args.elf,args.libc)
    elif args.libc:graph.inputs.libc_image(args.libc)
    if args.replay:
        assert replay(args.elf,args.libc)==data['case_results'],'frozen configuration copy replay differs'
        result['original_code_cases_replayed']=len(data['case_results'])
    print(json.dumps(result))


if __name__=='__main__':main()
