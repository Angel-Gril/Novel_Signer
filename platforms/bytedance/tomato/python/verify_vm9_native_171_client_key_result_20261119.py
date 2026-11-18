"""Original NULL lookup spill and the following cold static-guard precheck.

The next branch consumes another guard's low bit, rather than the saved NULL
lookup result. Reproduce fifteen bytecodes on independent fresh Python VM
pages, and stop before dispatching the next guard-acquisition callback.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path

from unicorn import arm64_const as arm
import verify_vm9_native_171_client_key_lookup_20261119 as previous

context=previous.context
graph=previous.graph
EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_client_key_result_20261119.json')
ENTRY,BRANCH,TARGET,STOP_BC,STOP=0xFD144,0xFD160,0xFD164,0xFD180,0x16A5E8
GUARD,OBJECT,GOT,ACQUIRE,WRAPPER,TRAMPOLINE=0x3E0CD0,0x3E0CB8,0x382CB8,0x32D3A0,0x285944,0x28587C
WORDS=[
    (0xFD144,0x8B4D1C18),(0xFD148,0x8B50805A),(0xFD14C,0x88C0003D),
    (0xFD150,0x00000351),(0xFD154,0x00411035),(0xFD158,0x8B7F0C18),
    (0xFD15C,0x83610C18),(0xFD160,0x24201014),(0xFD164,0x8B590818),
    (0xFD168,0x08400018),(0xFD16C,0x9B68191A),(0xFD170,0x8B40191A),
    (0xFD174,0x934A180F),(0xFD178,0xA3590A18),(0xFD17C,0x05C19B11),
    (0xFD180,0x067E0C91),
]
EXPECTED=[
    (0x16F96C,'ldr','x9, [x12, x13]'),(0x16F974,'str','x9, [x28, x14, lsl #3]'),
    (0x171184,'ldr','x10, [x19]'),(0x171188,'ldr','w11, [x10]'),
    (0x17118C,'ldr','w9, [x10, #4]!'),(0x171190,'str','x10, [x19]'),
    (0x171238,'ldr','x17, [x28, x13, lsl #3]'),(0x171240,'ldr','x15, [x28, x14, lsl #3]'),
    (0x171268,'str','x15, [x17, x16]'),
    (0x170068,'ldrsb','x11, [x11, x12]'),(0x17009C,'str','x11, [x28, x16, lsl #3]'),
    (0x16F044,'ldr','x9, [x28, w9, sxtw #3]'),(0x16F04C,'ldr','x10, [x28, w10, sxtw #3]'),
    (0x16F050,'cmp','x9, x10'),(0x16F058,'csel','x9, xzr, x12, eq'),
    (0x16F068,'add','x8, x8, x9, lsl #2'),(0x16F09C,'str','x8, [x19]'),
    (STOP,'eor','x11, x11, x4'),
]
LOADS={0xFD144:(3504,1,'NULL lookup result'),0xFD158:(2032,17,'frame local address'),
    0xFD15C:(1072,16,'next static object'),0xFD164:(1824,1,'ELF GOT slot'),
    0xFD168:(0,1,'ELF relocated guard function'),0xFD178:(1832,4,'guard wrapper')}
STORES={0xFD148:(1552,0),0xFD16C:(4200,'guard'),0xFD170:(4192,'acquire')}
CHANGED=(1,4,5,16,17,25)
CLAIMS=dict(
    entire_retained_lookup_evidence_row_reproduced=True,
    original_NULL_result_loaded_and_saved_to_frame_local=True,
    following_BNE_consumes_new_guard_low_bit_instead_of_saved_NULL=True,
    original_cold_guard_branch_falls_through_to_callback_preparation=True,
    original_next_callback_arguments_prepared_from_bound_ELF_pointers=True,
    selected_fifteen_bytecodes_match_independent_fresh_Python_VM=True,
    native_memory_used_as_model_input=False,new_OS_JNI_or_internal_helper_providers=False,
    next_guard_acquisition_callback_executed=False,saved_NULL_later_branch_verified=False,
    full_VM_or_physical_stack_equivalence_verified=False,header_value_generated=False,
    real_business_cache_restored=False,real_JVM_identity_verified=False,
    ordinary_Cronet_six_headers_verified=False,whole_request_equivalence_verified=False,
    callback_or_ordinary_wrapper_returned=False,complete_standalone_signer_verified=False,
    Android_execution=False,online_acceptance_verified=False,
)


def projection():
    return dict(executed_bytecodes=[hex(a) for a,_ in WORDS[:-1]],
        NULL_source=dict(bytecode=hex(ENTRY),frame_offset=3504,equals_lookup_packed_plus24=True,value_u64=0),
        NULL_spill=dict(bytecode='0xfd148',cursor_at_data_store='0xfd14c',frame_offset=1552,size=8,value_u64=0),
        next_guard_offset=hex(GUARD),next_object_offset=hex(OBJECT),guard_eight_bytes_unchanged_zero=True,
        branch=dict(bytecode=hex(BRANCH),registers=[1,0],values_u64=[0,0],
            R1_source='signed first byte of next static guard, then AND1',
            signed_displacement_words=41,taken=False,next_bytecode=hex(TARGET)),
        declared_frame_inputs=[dict(offset=3504,value='NULL lookup result'),dict(offset=2032,value='frame+4920'),
            dict(offset=1072,value='image+0x3e0cb8'),dict(offset=1824,value='image+0x382cb8'),
            dict(offset=1832,value='image+0x285944')],
        next_packed=dict(frame_offset=4192,function_offset=hex(ACQUIRE),argument_offset=hex(GUARD)),
        virtual_register_outputs=dict(R1='image+0x32d3a0',R4='image+0x285944',R5='frame+4192',
            R16='image+0x3e0cb8',R17='frame+4920',R25='image+0x28587c'),
        unselected_virtual_registers_preserved=True,link_register_unchanged=True,
        bytes_outside_selected_frame_stores_preserved=True,stop_bytecode=hex(STOP_BC),callback_executed=False)


def interpreter_projection(path):
    """Execute only declared bytecodes, pages, frame inputs and ELF relocation."""
    saved=os.environ.get('TOMATO_LIBMETASEC')
    try:
        os.environ['TOMATO_LIBMETASEC']=str(path.resolve())
        import vm_full as vm_module
    finally:
        if saved is None:os.environ.pop('TOMATO_LIBMETASEC',None)
        else:os.environ['TOMATO_LIBMETASEC']=saved
    assert hashlib.sha256(vm_module.SO).hexdigest()==graph.inputs.SHA256
    class Memory:
        def __init__(self):self.pages={}
        def u32(self,a):return int.from_bytes(previous.previous._read_span(self.pages,a,4),'little')
        def u64(self,a):return int.from_bytes(previous.previous._read_span(self.pages,a,8),'little')
        def rb(self,a):return previous.previous._read_span(self.pages,a,1)[0]
        def put(self,a,raw):previous.previous.put(self.pages,a,raw)
        def w64(self,a,v):self.put(a,int(v).to_bytes(8,'little'))
    class Boundary(Exception):pass
    original_base=vm_module.B;rows=[]
    try:
        for image in graph.BASES:
            vm_module.B=image;m=Memory();frame=0x60000000
            m.put(frame,b'\xa5'*0x2000);m.put(image+GUARD,bytes(8));m.w64(image+GOT,image+ACQUIRE)
            for offset,value in ((3504,0),(2032,frame+4920),(1072,image+OBJECT),(1824,image+GOT),(1832,image+WRAPPER)):
                m.w64(frame+offset,value)
            for address,word in WORDS:m.put(image+address,word.to_bytes(4,'little'))
            before_null=previous.previous._read_span(m.pages,frame+1544,24)
            before_packed=previous.previous._read_span(m.pages,frame+4184,32)
            vm=vm_module.VM(m,ENTRY,0,0,0,image+TRAMPOLINE,0,maxsteps=16)
            vm.R=[0xA5A5000000000000+i for i in range(32)]
            vm.R[0]=0;vm.R[19]=image+GUARD;vm.R[23]=image+TRAMPOLINE;vm.R[29]=frame
            vm.R[31]=image+ENTRY;before=list(vm.R);steps=[]
            def step(vm,dw,op,sub):
                if vm.pc==image+STOP_BC:raise Boundary()
                expected=WORDS[len(steps)];assert vm.pc==image+expected[0] and dw==expected[1]
                if vm.pc==image+BRANCH:assert vm.R[1]==vm.R[0]==0
                steps.append(hex(vm.pc-image))
            vm.step_hook=step
            try:vm.run()
            except Boundary:pass
            else:raise AssertionError('fifteen-instruction projection did not stop before CALL')
            assert steps==projection()['executed_bytecodes'] and vm.pc==image+STOP_BC
            assert [vm.R[i] for i in CHANGED]==[image+ACQUIRE,image+WRAPPER,frame+4192,image+OBJECT,frame+4920,image+TRAMPOLINE]
            assert all(vm.R[i]==before[i] for i in range(32) if i not in CHANGED)
            assert m.u64(frame+1552)==0 and m.u64(frame+4192)==image+ACQUIRE and m.u64(frame+4200)==image+GUARD
            after_null=previous.previous._read_span(m.pages,frame+1544,24)
            after_packed=previous.previous._read_span(m.pages,frame+4184,32)
            assert before_null[:8]+before_null[16:]==after_null[:8]+after_null[16:]
            assert before_packed[:8]+before_packed[24:]==after_packed[:8]+after_packed[24:]
            assert previous.previous._read_span(m.pages,image+GUARD,8)==bytes(8)
            rows.append(dict(image_base=hex(image),projection=projection()))
    finally:vm_module.B=original_base
    return rows


def providers():
    return dict(inherited_lookup=previous.providers(),maximum_handler_reads=2,maximum_main_SVCs=4,
        independent_model_owner='vm_full.py:VM.run',
        independent_model_input='fresh declared frame/guard/registers and sixteen bound ELF words; CALL not executed',
        pointer_origin=dict(GOT_offset=hex(GOT),relocation_type=1027,addend=hex(ACQUIRE),guard_section='SHT_NOBITS'),
        new_OS_JNI_or_internal_helper_providers=[],stop_before=hex(STOP),outer_bytecode=hex(STOP_BC))


class Scenario(previous.Scenario):
    def __init__(self,control):
        super().__init__(control);self.result_active=False;self.result_loads=[];self.result_stores=[];self.guard_byte_seen=False

    def lookup_boundary(self,cpu,state):
        assert self.lookup_done and not self.result_active
        def u(a):return int.from_bytes(cpu.mem_read(a,8),'little')
        self.result_active=True;self.frame=u(state['backing']+29*8);self.result_PC_slot=state['PC_slot']
        assert self.frame+3504==self.lookup_packed+24 and u(self.frame+3504)==0
        self.result_initial_R=[u(state['backing']+i*8) for i in range(32)]
        assert self.result_initial_R[0]==0 and self.result_initial_R[19]==self.image+GUARD
        assert self.result_initial_R[23]==self.image+TRAMPOLINE and self.result_initial_R[31]==self.image+ENTRY
        assert bytes(cpu.mem_read(self.image+GUARD,8))==bytes(8)
        for offset,value in ((2032,self.frame+4920),(1072,self.image+OBJECT),
            (1824,self.image+GOT),(1832,self.image+WRAPPER)):assert u(self.frame+offset)==value
        assert u(self.image+GOT)==self.image+ACQUIRE
        self.result_null_before=bytes(cpu.mem_read(self.frame+1544,24))
        self.result_packed_before=bytes(cpu.mem_read(self.frame+4184,32))

    def native_runner(self,*args,**kwargs):
        original=kwargs['memory_write_observer']
        def write(cpu,address,size):
            if self.result_active:
                ranges=((self.frame+1552,8),(self.frame+4192,16))
                if any(address<a+n and a<address+size for a,n in ranges):
                    def reg(n):return cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(n)))
                    cursor=int.from_bytes(cpu.mem_read(self.result_PC_slot,8),'little')-self.image
                    # +0x17118c/+0x171190 advance the cursor before this store.
                    bc=cursor-4
                    offset,value=STORES[bc]
                    if value=='guard':value=self.image+GUARD
                    elif value=='acquire':value=self.image+ACQUIRE
                    assert cpu.reg_read(arm.UC_ARM64_REG_PC)==self.image+0x171268 and size==8
                    assert address==self.frame+offset and reg(17)==self.frame and reg(16)==offset and reg(15)==value
                    self.result_stores.append(dict(bytecode=hex(bc),cursor_bytecode=hex(cursor),
                        native_pc='0x171268',frame_offset=offset,size=8))
            original(cpu,address,size)
        kwargs['memory_write_observer']=write
        return super().native_runner(*args,**kwargs)

    def observe(self,cpu,pc,state):
        if not self.result_active:
            super().observe(cpu,pc,state)
            if not self.result_active:return
        off=pc-self.image
        def reg(n):return cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(n)))
        def raw(a,n):return bytes(cpu.mem_read(a,n))
        def u(a,n=8):return int.from_bytes(raw(a,n),'little')
        bc=u(state['PC_slot'])-self.image
        if off in (0x27E6AC,0x27ED6C,0x16AA48):raise AssertionError('unexpected next callback or ordinary RET')
        if off==context.LOAD:
            offset,destination,label=LOADS[bc]
            base=self.image+GOT if bc==0xFD168 else self.frame
            values={0xFD144:0,0xFD158:self.frame+4920,0xFD15C:self.image+OBJECT,
                0xFD164:self.image+GOT,0xFD168:self.image+ACQUIRE,0xFD178:self.image+WRAPPER}
            assert (reg(12),reg(13),reg(14),u(base+offset))==(base,offset,destination,values[bc])
            self.result_loads.append(dict(bytecode=hex(bc),native_pc=hex(context.LOAD),offset=offset,
                virtual_register=destination,source=label))
        if off==0x170068 and bc==0xFD14C:
            assert (reg(11),reg(12),reg(16))==(self.image+GUARD,0,1)
            assert raw(self.image+GUARD,8)==bytes(8);self.guard_byte_seen=True
        if off==0x17009C and bc==0xFD14C:
            assert self.guard_byte_seen and reg(11)==0 and reg(16)==1
        if off==0x16F050 and bc==BRANCH:
            assert self.guard_byte_seen and reg(9)==reg(10)==0 and reg(12)==41
            assert u(self.frame+1552)==0;self.result_branch_seen=True
        if off==0x16F09C and bc==BRANCH:
            assert self.result_branch_seen and reg(8)==self.image+TARGET;self.result_branch_stored=True
        if off==STOP and bc==STOP_BC:
            assert self.result_branch_stored and len(self.result_loads)==6 and len(self.result_stores)==3
            assert [int(row['bytecode'],16) for row in self.result_stores]==list(STORES)
            expected=[self.image+ACQUIRE,self.image+WRAPPER,self.frame+4192,
                self.image+OBJECT,self.frame+4920,self.image+TRAMPOLINE]
            assert [u(state['backing']+i*8) for i in CHANGED]==expected
            assert all(u(state['backing']+i*8)==self.result_initial_R[i] for i in range(32) if i not in CHANGED)
            assert u(self.frame+1552)==0 and (u(self.frame+4192),u(self.frame+4200))==(self.image+ACQUIRE,self.image+GUARD)
            after_null=raw(self.frame+1544,24);after_packed=raw(self.frame+4184,32)
            assert self.result_null_before[:8]+self.result_null_before[16:]==after_null[:8]+after_null[16:]
            assert self.result_packed_before[:8]+self.result_packed_before[24:]==after_packed[:8]+after_packed[24:]
            assert raw(self.image+GUARD,8)==bytes(8)
            assert raw(state['context'],128)==state['handler_bytes'] and u(self.state_owner+0x18)==self.node
            assert raw(self.node,64)==previous.previous.previous.previous.empty_bytes()
            assert previous.previous.previous.previous.previous.output._cstring(cpu,self.prefix.source)==self.prefix.raw
            assert previous.tree_projection(raw,self.image,self.container)==self.tree
            assert u(self.image+0x3D1558,1)==1 and u(context.outer.root_fixture.TLS+0x100,4)==2
            self.result_done=True;cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,context.outer.oracle.STOP)

    def finish(self,result,state,proof):
        retained=super().finish(result,state,proof['client_key_lookup_prefix'])
        frozen=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(frozen)
        old=next(row for row in frozen['case_results'] if row['control']==self.control)
        assert retained==old,'entire retained lookup row differs'
        assert self.result_done and self.result_branch_seen and self.result_branch_stored
        return dict(control=self.control,entire_retained_lookup_row_reproduced=True,retained_lookup_row_sha256=graph.digest(retained),
            selected_projection=projection(),native_loads=self.result_loads,native_stores=self.result_stores,
            allocation_ledger_sha256=graph.digest(result['allocator_events']),allocator_counts=result['actual_allocator_counts'],
            service_counts=result['explicit_service_counts'],JNI_calls=proof['JNI_calls'],
            libc_SVC_boundaries=proof['libc_SVC_boundaries'],main_image_SVC_boundaries=proof['main_image_SVC_boundaries'],
            handler_empty_state_request_tree_and_source_directory_unchanged=True,registry_guard_at_stop=1,errno_at_stop=2,
            continuation_instruction_observations=proof['instruction_observations'],
            continuation_trace_sha256=proof['trace_sha256'],continuation_code_sha256=proof['code_sha256'],
            observation_stop_before=hex(STOP),outer_bytecode=hex(STOP_BC),callback_or_ordinary_RET_seen=False)


def replay(path,libc,*,on_case=None,case_controls=None):
    return context.replay(path,libc,on_case=on_case,case_controls=case_controls,_extension_factory=Scenario,
        _request_profile=previous.previous.previous.previous.PROFILE['name'],
        _handler_read_profile=context.NULL_PAYLOAD_READ_PROFILE['name'])


def verify_images(data,path,libc):
    from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
    old=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(old);previous.verify_images(old,path,libc)
    elf,_,read=graph.inputs.load_elf(path);decoder=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
    for a,m,s in EXPECTED:
        ins,=decoder.disasm(read(a,4),a);assert (ins.mnemonic,ins.op_str)==(m,s),hex(a)
    for a,w in WORDS:assert int.from_bytes(read(a,4),'little')==w,hex(a)
    relocations=[r for section in elf.iter_sections() if section['sh_type']=='SHT_RELA'
        for r in section.iter_relocations() if r['r_offset']==GOT]
    assert len(relocations)==1 and relocations[0]['r_info_type']==1027 and relocations[0]['r_addend']==ACQUIRE
    assert any(section['sh_type']=='SHT_NOBITS' and section['sh_addr']<=GUARD
        and GUARD+8<=section['sh_addr']+section['sh_size'] for section in elf.iter_sections())
    modeled=interpreter_projection(path)
    assert modeled==[dict(image_base=hex(base),projection=projection()) for base in graph.BASES]
    return dict(additional_instruction_bindings=len(EXPECTED),bytecode_words=len(WORDS),
        independent_Python_VM_cases=len(modeled),GOT_relative_relocation_and_guard_NOBITS_verified=True)


def validate(data):
    assert data['schema']=='vm9-native-171-client-key-result-20261119-v1'
    assert data['claims']==CLAIMS and data['providers']==providers()
    assert data['provenance']==previous.previous.previous.previous.previous.previous.previous.provenance()
    assert data['instructions']==[dict(offset=hex(a),mnemonic=m,operands=s) for a,m,s in EXPECTED]
    assert data['bytecode_words']==[dict(offset=hex(a),word=hex(w)) for a,w in WORDS]
    assert data['independent_Python_projection']==[dict(image_base=hex(base),projection=projection()) for base in graph.BASES]
    frozen=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(frozen)
    assert len(data['case_results'])==len(context.controls())
    for row,old in zip(data['case_results'],frozen['case_results']):
        assert row['control']==old['control'] and row['entire_retained_lookup_row_reproduced'] is True
        assert row['retained_lookup_row_sha256']==graph.digest(old) and row['selected_projection']==projection()
        assert row['native_loads']==[dict(bytecode=hex(a),native_pc=hex(context.LOAD),offset=o,virtual_register=r,source=s)
            for a,(o,r,s) in LOADS.items()]
        assert row['native_stores']==[dict(bytecode=hex(a),cursor_bytecode=hex(a+4),
            native_pc='0x171268',frame_offset=o,size=8) for a,(o,_) in STORES.items()]
        for key in ('allocation_ledger_sha256','allocator_counts','service_counts','JNI_calls',
            'libc_SVC_boundaries','main_image_SVC_boundaries'):assert row[key]==old[key]
        assert row['handler_empty_state_request_tree_and_source_directory_unchanged'] is True
        assert row['registry_guard_at_stop']==1 and row['errno_at_stop']==2
        assert row['observation_stop_before']==hex(STOP) and row['outer_bytecode']==hex(STOP_BC)
        assert row['callback_or_ordinary_RET_seen'] is False
        assert row['continuation_instruction_observations']>old['continuation_instruction_observations']
        for key in ('continuation_trace_sha256','continuation_code_sha256'):assert graph.inputs.is_digest(row[key])


def negatives(data):
    rejected=0
    def reject(path,value):
        nonlocal rejected
        bad=deepcopy(data);target=bad
        for key in path[:-1]:target=target[key]
        target[path[-1]]=value
        try:validate(bad)
        except AssertionError:rejected+=1
        else:raise AssertionError('damaged result evidence accepted: '+str(path))
    for key,value in CLAIMS.items():reject(('claims',key),not value)
    reject(('providers','maximum_handler_reads'),3);reject(('providers','maximum_main_SVCs'),5)
    reject(('instructions',0,'mnemonic'),'nop');reject(('bytecode_words',0,'word'),'0x0')
    for i in range(len(data['case_results'])):
        for path,value in ((('retained_lookup_row_sha256',),'0'*64),(('entire_retained_lookup_row_reproduced',),False),
            (('selected_projection','NULL_spill','value_u64'),1),(('selected_projection','branch','taken'),True),
            (('selected_projection','branch','R1_source'),'NULL lookup result'),(('native_loads',),[]),(('native_stores',),[]),
            (('native_stores',0,'cursor_bytecode'),'0xfd148'),
            (('allocation_ledger_sha256',),'0'*64),(('allocator_counts','malloc'),0),(('service_counts','syscall_226'),0),
            (('JNI_calls',),[]),(('main_image_SVC_boundaries',),[]),(('libc_SVC_boundaries',),[]),
            (('handler_empty_state_request_tree_and_source_directory_unchanged',),False),(('registry_guard_at_stop',),0),
            (('errno_at_stop',),17),(('observation_stop_before',),'0x0'),(('outer_bytecode',),'0xfd160'),
            (('callback_or_ordinary_RET_seen',),True),(('continuation_instruction_observations',),0)):
            reject(('case_results',i)+path,value)
    return rejected


def build(path,libc,*,on_case=None):
    modeled=interpreter_projection(path)
    data=dict(schema='vm9-native-171-client-key-result-20261119-v1',claims=CLAIMS,providers=providers(),
        provenance=previous.previous.previous.previous.previous.previous.previous.provenance(),
        independent_Python_projection=modeled,instructions=[dict(offset=hex(a),mnemonic=m,operands=s) for a,m,s in EXPECTED],
        bytecode_words=[dict(offset=hex(a),word=hex(w)) for a,w in WORDS],case_results=[])
    verify_images(data,path,libc);data['case_results']=replay(path,libc,on_case=on_case);validate(data);return data


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--elf',type=Path);ap.add_argument('--libc',type=Path);ap.add_argument('--replay',action='store_true')
    args=ap.parse_args()
    if args.replay and (not args.elf or not args.libc):ap.error('--replay requires --elf and --libc')
    data=json.loads(EVIDENCE.read_text(encoding='utf-8'));validate(data)
    result=dict(retained_result_cases=len(data['case_results']),damaged_evidence_rejected=negatives(data),
        header_value_generated=False,ordinary_Cronet_six_headers_verified=False,complete_standalone_signer_verified=False)
    if args.elf:result['image_bindings']=verify_images(data,args.elf,args.libc)
    elif args.libc:graph.inputs.libc_image(args.libc)
    if args.replay:
        assert replay(args.elf,args.libc)==data['case_results'],'frozen client-key-result replay differs'
        result['original_code_cases_replayed']=len(data['case_results'])
    print(json.dumps(result))


if __name__=='__main__':main()
