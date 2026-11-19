"""Original suffix call preparation plus independent complete suffix controls.

The current native request stops before entering the suffix wrapper. Separate
declared pages exercise the actual callback and original helper independently;
they do not establish current-request numeric or whole-request equivalence.
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
import verify_vm9_native_171_configuration_copy56_20261120 as previous
import verify_vm9_request_suffix_fresh_20261013 as fixture

context,graph,name=previous.context,previous.graph,previous.name
owner=previous.previous.previous.owner
EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_configuration_suffix_call_20261120.json')
ENTRY,CALL,STOP=0xFD698,0xFD6B0,0x16AA48
WRAPPER,TARGET=0x285E80,0x2869F0
WORDS=[(ENTRY,0x8B4AB00F),(0xFD69C,0x8368B09A),(0xFD6A0,0x8B410E18),
    (0xFD6A4,0x8B40B09A),(0xFD6A8,0xA34D0018),(0xFD6AC,0x05C19B11),(CALL,0x067E0C91)]
LOADS=[(0xFD6A0,1080,1),(0xFD6A8,416,4)]
STORES=[(0xFD6A0,2760,8),(0xFD6A8,2752,8)]
EXPECTED=[(context.LOAD,'ldr','x9, [x12, x13]'),(0x171268,'str','x15, [x17, x16]'),
    (STOP,'blr','x8'),(WRAPPER,'ldp','x1, x8, [x0]'),(0x285E84,'mov','x0, x8'),
    (0x285E88,'br','x1'),(TARGET,'stp','x29, x30, [sp, #-0x60]!')]
CASES=[('small','length_7',0x12345678,0x1234),('wide','timestamp_high_bits',0xFEDCBA9876543210,0xFFFF)]
CLAIMS=dict(retained_copy_instruction_code_and_allocation_prefix_verified=True,
    completed_copy_observer_retired_after_full_prefix=True,original_scope_kept=True,
    original_seven_suffix_argument_words_executed=True,original_suffix_target_and_receiver_prepared=True,
    native_packed_padding_and_selected_registers_verified=True,old_frame_TLS_heap_and_count1_preserved=True,
    no_new_current_allocation_or_service_JNI_SVC=True,four_declared_VM_actual_callback_suffix_returns_verified=True,
    four_independent_original_helper_controls_match_actual_callback=True,
    independent_semantic_guest_image_outputs_and_ownership_effects_equal=True,
    native_memory_used_as_Python_model_input=False,current_native_suffix_wrapper_entered=False,
    current_native_suffix_return_verified=False,current_request_numeric_Python_equality_verified=False,
    full_native_physical_stack_or_whole_request_equality_verified=False,
    complete_configuration_provenance_verified=False,real_business_state_or_JVM_identity_verified=False,
    KMSV_value_generated=False,client_key_value_generated=False,ordinary_Cronet_six_headers_verified=False,
    callback_or_ordinary_wrapper_returned=False,complete_standalone_signer_verified=False,
    new_OS_JNI_or_internal_helper_providers=False,Android_execution=False,online_acceptance_verified=False)


def selected_projection():
    return dict(receiver_source='R16',receiver_frame_offset=2088,packed_frame_offset=2752,
        target_frame_offset=1080,wrapper_frame_offset=416,wrapper=hex(WRAPPER),target=hex(TARGET),
        packed_written_size=16,packed_adjacent_padding_preserved=True,virtual_frame_size=previous.FRAME_SIZE,
        current_header_and_source_preserved=True,current_TLS_and_heap_preserved=True,
        current_wrapper_not_entered=True)


def expected_VM_projection():
    return [dict(image_base=hex(b),case=label,declared_scalar_u64=hex(scalar),declared_seed_u16=hex(seed),
        executed_bytecodes=[hex(a) for a,_ in WORDS],actual_request_callback_source_executed=True,
        complete_suffix_returned=True,nonNULL_outputs_verified=True,input_header_and_packed_padding_preserved=True,
        selected_and_unselected_registers_and_frame_writes_verified=True,native_snapshot_input=False)
        for b in graph.BASES for label,_,scalar,seed in CASES]


def expected_native_projection():
    return [dict(image_base=r['image_base'],case=r['case'],original_suffix_helper_returned=True,
        actual_request_callback_source_executed=True,semantic_guest_image_outputs_and_effects_match=True,
        pre_free_payloads_and_live_blocks_match=True,physical_stack_and_void_X0_excluded=True,
        native_snapshot_input=False) for r in expected_VM_projection()]


def callback(image,service,diagnostic,ledger):
    tree=ast.parse(inspect.getsource(owner._execute_request_vm_impl))
    node=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=='callback')
    def singleton(p,stack):
        assert stack==fixture.dependency.SP-0x3F0
        service.events.append(['singleton136']);return fixture.fixture_owner.WRAPPER
    ns=dict(vars(owner));ns.update(image=image,ledger=ledger,diagnostic_scope=diagnostic,
        allocate=service.malloc,reallocate=service.effects.realloc,free=service.free,
        get_singleton=singleton,parse_decimal=lambda p,a:0,
        inputs={'thread_pointer':fixture.dependency.TP},
        frame=SimpleNamespace(native_stack_address=fixture.dependency.SP+0x180))
    exec(compile(ast.Module(body=[node],type_ignores=[]),owner.__file__,'exec'),ns)
    return ns['callback']


def declared_controls(path,libc=None):
    graph.inputs.load_elf(path)
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
            for label,profile,scalar,seed in CASES:
                p=fixture.fresh(path,image,profile);f=fixture.G+0xA000;packed=f+2752
                read=lambda a,n:fixture._read_span(p,a,n)
                u=lambda a,n=8:int.from_bytes(read(a,n),'little')
                w=lambda a,v,n=8:fixture.dependency.w(p,a,v,n)
                fixture._write_span(p,f,b'\xa5'*previous.FRAME_SIZE)
                w(fixture.OBJ,scalar);w(fixture.SEED,seed,2)
                w(f+1080,image+TARGET);w(f+416,image+WRAPPER)
                before=read(f,previous.FRAME_SIZE);header=read(fixture.OBJ,64)
                expected=fixture.native(path,libc,image,p) if libc else None
                service=fixture.dependency.Services();ledger=[]
                diagnostic={'thread_id':137,'events':service.events}
                class Memory:
                    def __init__(self):self.pages=p
                    def u32(self,a):return u(a,4)
                    def u64(self,a):return u(a)
                    def rb(self,a):return read(a,1)[0]
                    def w32(self,a,v):w(a,v,4)
                    def w64(self,a,v):w(a,v)
                m=Memory();vm=module.VM(m,ENTRY,0,0,0,0,0,maxsteps=10)
                vm.R=[0xA5A5000000000000+i for i in range(32)]
                vm.R[0]=0;vm.R[16]=fixture.OBJ;vm.R[23]=image+0x28587C;vm.R[29]=f
                initial=list(vm.R);vm.cb=image+0x28587C;steps=[]
                invoke=callback(image,service,diagnostic,ledger)
                def native(vm,function,argument):
                    assert (vm.pc,function,argument)==(image+CALL,image+WRAPPER,packed)
                    assert (u(packed),u(packed+8))==(image+TARGET,fixture.OBJ)
                    invoke(vm,function,argument)
                def step(vm,dw,op,sub):
                    if vm.pc==image+CALL+4:raise Boundary()
                    assert (vm.pc-image,dw)==WORDS[len(steps)];steps.append(hex(vm.pc-image))
                vm.native_hook=native;vm.step_hook=step
                try:vm.run()
                except Boundary:pass
                else:raise AssertionError('declared suffix VM did not stop after call')
                selected=(1,4,5,25,31)
                assert [vm.R[i] for i in selected]==[image+TARGET,image+WRAPPER,packed,image+0x28587C,image+CALL+4]
                assert all(vm.R[i]==initial[i] for i in range(32) if i not in selected)
                assert all(a==b for i,(a,b) in enumerate(zip(before,read(f,previous.FRAME_SIZE)))
                    if not 2752<=i<2768)
                assert (u(packed),u(packed+8))==(image+TARGET,fixture.OBJ) and read(fixture.OBJ,64)==header
                outputs=[u(fixture.OUT1),u(fixture.OUT2)]
                assert all(outputs) and len(ledger)==1
                assert diagnostic['request_suffixes']==[dict(object_address=fixture.OBJ,
                    output_pointer_addresses=outputs,outer_suffix_returned=True)]
                if expected:
                    memory,observed,other=expected
                    assert read(fixture.G,0xA000)==memory
                    for (a,n),data in observed.items():assert read(a,n)==data
                    assert service.events==other.events and service.effects.calls==other.effects.calls
                    assert service.effects.blocks==other.effects.blocks and service.freed==other.freed
                    rows.append(expected_native_projection()[len(rows)])
                else:rows.append(expected_VM_projection()[len(rows)])
    finally:module.B=old_base
    return rows


def interpreter_projection(path):return declared_controls(path)
def independent_native_controls(path,libc):return declared_controls(path,libc)


def providers():
    return dict(inherited_copy56=previous.providers(),maximum_handler_reads=2,maximum_main_SVCs=4,
        public_trace_limit=400000,retired_completed_observation_windows=['copy56_active'],original_scope_kept=True,
        independent_model_owners=['vm_full.py:VM.run','vm9_request_vm.py:_execute_request_vm_impl.callback',
            'vm9_request_transform.py:construct_request_suffix'],
        independent_fixture_owner='verify_vm9_request_suffix_fresh_20261013.py',
        independent_allocator_and_SDK_inputs_explicit=True,independent_decimal_result=0,
        independent_physical_stack_and_void_X0_compared=False,current_and_declared_numeric_values_compared=False,
        new_OS_JNI_or_internal_helper_providers=[],current_allocation_and_service_count_deltas={},
        stop_before=hex(STOP),outer_bytecode=hex(CALL))


class Scenario(previous.Scenario):
    def __init__(self,c):
        super().__init__(c);self.suffix_call_active=False;self.suffix_call_done=False
        self.suffix_call_steps=[];self.suffix_call_loads=[];self.suffix_call_writes=[]

    def native_runner(self,*args,**kwargs):
        original=kwargs['memory_write_observer']
        def write(cpu,address,size):
            if self.suffix_call_active and self.scope_frame+2752<=address<self.scope_frame+2768:
                u=lambda a:int.from_bytes(cpu.mem_read(a,8),'little')
                a,o,n=STORES[len(self.suffix_call_writes)]
                assert (u(self.scope_state['PC_slot'])-self.image,address-self.scope_frame,size)==(a,o,n)
                assert cpu.reg_read(arm.UC_ARM64_REG_PC)-self.image==0x171268
                value=self.image+TARGET if o==2752 else self.scope_frame+2088
                assert cpu.reg_read(arm.UC_ARM64_REG_X15)==value
                self.suffix_call_writes.append(dict(cursor_bytecode=hex(a),frame_offset=o,size=n))
            original(cpu,address,size)
        kwargs['memory_write_observer']=write
        return super().native_runner(*args,**kwargs)

    def copy56_boundary(self,cpu,state):
        data=json.loads(previous.EVIDENCE.read_text());previous.validate(data)
        old=next(r for r in data['case_results'] if r['control']==self.control)
        prefix=state['configuration_copy56_prefix']
        for k in ('instruction_observations','trace_sha256','code_sha256'):assert prefix[k]==old['continuation_'+k]
        for k in ('JNI_calls','libc_SVC_boundaries','main_image_SVC_boundaries'):assert prefix[k]==old[k]
        assert self.copy56_done and self.copy56_active and self.original_scope
        assert graph.digest(state['allocator_events_ref'])==old['allocation_ledger_sha256']
        u=lambda a:int.from_bytes(cpu.mem_read(a,8),'little');f=self.scope_frame
        self.suffix_call_initial_R=[u(state['backing']+i*8) for i in range(32)]
        assert self.suffix_call_initial_R[16]==f+2088
        assert u(f+1080)==self.image+TARGET and u(f+416)==self.image+WRAPPER
        self.suffix_call_before=bytes(cpu.mem_read(f,0x2000))
        self.suffix_call_preserved={a:bytes(cpu.mem_read(a,len(b))) for a,b in self.copy56_preserved.items()}
        self.suffix_call_allocations=deepcopy(state['allocator_events_ref'])
        self.copy56_active=False;self.suffix_call_active=True

    def observe(self,cpu,pc,state):
        self.scope_state=state
        if not self.suffix_call_active:
            super().observe(cpu,pc,state)
            if not self.suffix_call_active:return
        off=pc-self.image;f=self.scope_frame
        u=lambda a:int.from_bytes(cpu.mem_read(a,8),'little')
        reg=lambda i:cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i)))
        bc=u(state['PC_slot'])-self.image
        if off in (WRAPPER,TARGET,0x27E6AC,0x27ED6C):raise AssertionError('suffix/wrapper entered before observation stop')
        if bc!=previous.CALL and (not self.suffix_call_steps or self.suffix_call_steps[-1]!=hex(bc)):
            assert bc==WORDS[len(self.suffix_call_steps)][0],(hex(off),hex(bc),self.suffix_call_steps)
            self.suffix_call_steps.append(hex(bc))
        if off==context.LOAD:
            a,o,d=LOADS[len(self.suffix_call_loads)]
            assert (bc,reg(12),reg(13),reg(14))==(a,f,o,d)
            assert u(f+o)==self.image+(TARGET if d==1 else WRAPPER)
            self.suffix_call_loads.append(dict(bytecode=hex(a),frame_offset=o,destination=d))
        if off==STOP:
            assert (bc,reg(8),reg(0))==(CALL,self.image+WRAPPER,f+2752)
            assert (u(f+2752),u(f+2760))==(self.image+TARGET,f+2088)
            selected=(1,4,5,25,31)
            assert [u(state['backing']+i*8) for i in selected]==[self.image+TARGET,self.image+WRAPPER,
                f+2752,self.image+0x28587C,self.image+CALL+4]
            assert all(u(state['backing']+i*8)==self.suffix_call_initial_R[i] for i in range(32) if i not in selected)
            runtime=[(previous.FRAME_SIZE+16,previous.FRAME_SIZE+24+256)]
            assert all(a==b for i,(a,b) in enumerate(zip(self.suffix_call_before,bytes(cpu.mem_read(f,0x2000))))
                if not any(start<=i<end for start,end in [(2752,2768)]+runtime))
            for a,b in self.suffix_call_preserved.items():assert bytes(cpu.mem_read(a,len(b)))==b
            assert state['allocator_events_ref']==self.suffix_call_allocations and self.original_scope
            self.suffix_call_done=True;cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,context.outer.oracle.STOP)

    def finish(self,result,state,proof):
        old=next(r for r in json.loads(previous.EVIDENCE.read_text())['case_results'] if r['control']==self.control)
        prefix=proof['configuration_copy56_prefix']
        assert self.suffix_call_done and result['allocator_events']==self.suffix_call_allocations
        assert result['actual_allocator_counts']==old['allocator_counts'] and result['explicit_service_counts']==old['service_counts']
        for k in ('JNI_calls','libc_SVC_boundaries','main_image_SVC_boundaries'):assert proof[k]==prefix[k]==old[k]
        return dict(control=self.control,retained_copy56_prefix_verified=True,
            retained_prefix_instruction_observations=prefix['instruction_observations'],retained_prefix_trace_sha256=prefix['trace_sha256'],
            retained_prefix_code_sha256=prefix['code_sha256'],retired_completed_observers=['copy56_active'],original_scope_kept=True,
            executed_bytecodes=self.suffix_call_steps,native_loads=self.suffix_call_loads,native_stores=self.suffix_call_writes,
            selected_suffix_call_projection=selected_projection(),allocation_ledger_sha256=graph.digest(result['allocator_events']),
            allocator_counts=old['allocator_counts'],service_counts=old['service_counts'],JNI_calls=proof['JNI_calls'],
            libc_SVC_boundaries=proof['libc_SVC_boundaries'],main_image_SVC_boundaries=proof['main_image_SVC_boundaries'],
            continuation_instruction_observations=proof['instruction_observations'],continuation_trace_sha256=proof['trace_sha256'],
            continuation_code_sha256=proof['code_sha256'],observation_stop_before=hex(STOP),outer_bytecode=hex(CALL),
            current_suffix_wrapper_entered=False,callback_or_ordinary_RET_seen=False)


def replay(path,libc,*,on_case=None,case_controls=None):
    return context.replay(path,libc,on_case=on_case,case_controls=case_controls,_extension_factory=Scenario,
        _request_profile=name.previous.previous.PROFILE['name'],_handler_read_profile=context.NULL_PAYLOAD_READ_PROFILE['name'])


def verify_images(data,path,libc):
    from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
    previous.verify_images({},path,libc);_,_,read=graph.inputs.load_elf(path);decoder=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
    for a,m,s in EXPECTED:
        ins,=decoder.disasm(read(a,4),a);assert (ins.mnemonic,ins.op_str)==(m,s)
    for a,w in WORDS:assert int.from_bytes(read(a,4),'little')==w
    assert interpreter_projection(path)==expected_VM_projection()
    return dict(instruction_bindings=len(EXPECTED),bytecode_words=len(WORDS),fresh_declared_VM_cases=4,
        actual_request_callback_source_executed=True,current_request_suffix_body_executed=False)


def validate(data):
    assert data['schema']=='vm9-native-171-configuration-suffix-call-20261120-v1' and data['claims']==CLAIMS and data['providers']==providers()
    assert data['instructions']==[dict(offset=hex(a),mnemonic=m,operands=s) for a,m,s in EXPECTED]
    assert data['bytecode_words']==[dict(offset=hex(a),word=hex(w)) for a,w in WORDS]
    assert data['independent_Python_VM_projection']==expected_VM_projection()
    assert data['independent_native_suffix_projection']==expected_native_projection()
    assert data['request_callback_source_sha256']==hashlib.sha256(Path(owner.__file__).read_bytes()).hexdigest()
    old_data=json.loads(previous.EVIDENCE.read_text());previous.validate(old_data)
    assert data['provenance']==old_data['provenance'] and len(data['case_results'])==len(context.controls())
    for row,old in zip(data['case_results'],old_data['case_results']):
        assert row['control']==old['control'] and row['retained_copy56_prefix_verified'] is True
        for k in ('instruction_observations','trace_sha256','code_sha256'):assert row['retained_prefix_'+k]==old['continuation_'+k]
        assert row['retired_completed_observers']==['copy56_active'] and row['original_scope_kept'] is True
        assert row['executed_bytecodes']==[hex(a) for a,_ in WORDS]
        assert row['native_loads']==[dict(bytecode=hex(a),frame_offset=o,destination=d) for a,o,d in LOADS]
        assert row['native_stores']==[dict(cursor_bytecode=hex(a),frame_offset=o,size=n) for a,o,n in STORES]
        assert row['selected_suffix_call_projection']==selected_projection()
        for k in ('allocation_ledger_sha256','allocator_counts','service_counts','JNI_calls','libc_SVC_boundaries','main_image_SVC_boundaries'):assert row[k]==old[k]
        assert old['continuation_instruction_observations']<row['continuation_instruction_observations']<400000
        for k in ('continuation_trace_sha256','continuation_code_sha256'):assert graph.inputs.is_digest(row[k])
        assert row['observation_stop_before']==hex(STOP) and row['outer_bytecode']==hex(CALL)
        assert row['current_suffix_wrapper_entered'] is False and row['callback_or_ordinary_RET_seen'] is False


def negatives(data):
    count=0
    def reject(path,value):
        nonlocal count
        bad=deepcopy(data);target=bad
        for k in path[:-1]:target=target[k]
        target[path[-1]]=value
        try:validate(bad)
        except AssertionError:count+=1
        else:raise AssertionError('damaged suffix call evidence accepted: '+str(path))
    for k,v in CLAIMS.items():reject(('claims',k),not v)
    for k,v in [('maximum_handler_reads',3),('maximum_main_SVCs',5),('public_trace_limit',750000)]:reject(('providers',k),v)
    reject(('instructions',0,'mnemonic'),'nop');reject(('bytecode_words',0,'word'),'0x0')
    reject(('request_callback_source_sha256',),'0'*64)
    reject(('independent_Python_VM_projection',0,'complete_suffix_returned'),False)
    reject(('independent_native_suffix_projection',0,'physical_stack_and_void_X0_excluded'),False)
    for i in range(len(data['case_results'])):
        changes=[(('retained_copy56_prefix_verified',),False),(('retained_prefix_trace_sha256',),'0'*64),
            (('retired_completed_observers',),[]),(('original_scope_kept',),False),(('executed_bytecodes',),[]),
            (('native_loads',),[]),(('native_stores',),[]),(('allocation_ledger_sha256',),'0'*64),
            (('allocator_counts','malloc'),0),(('service_counts','syscall_226'),0),(('JNI_calls',),[]),
            (('libc_SVC_boundaries',),[]),(('main_image_SVC_boundaries',),[]),
            (('continuation_instruction_observations',),400000),(('continuation_trace_sha256',),'bad'),
            (('continuation_code_sha256',),'bad'),(('observation_stop_before',),'0x0'),(('outer_bytecode',),hex(ENTRY)),
            (('current_suffix_wrapper_entered',),True),(('callback_or_ordinary_RET_seen',),True)]
        for k,v in selected_projection().items():changes.append((('selected_suffix_call_projection',k),not v if isinstance(v,bool) else 'bad'))
        for path,value in changes:reject(('case_results',i)+path,value)
    return count


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--elf',type=Path);ap.add_argument('--libc',type=Path);ap.add_argument('--replay',action='store_true')
    args=ap.parse_args()
    if args.replay and (not args.elf or not args.libc):ap.error('--replay requires --elf and --libc')
    data=json.loads(EVIDENCE.read_text());validate(data)
    result=dict(retained_configuration_suffix_call_cases=len(data['case_results']),damaged_evidence_rejected=negatives(data),
        current_native_suffix_return_verified=False,ordinary_Cronet_six_headers_verified=False,complete_standalone_signer_verified=False)
    if args.elf:result['image_bindings']=verify_images(data,args.elf,args.libc)
    elif args.libc:graph.inputs.libc_image(args.libc)
    if args.replay:
        assert independent_native_controls(args.elf,args.libc)==data['independent_native_suffix_projection']
        assert replay(args.elf,args.libc)==data['case_results'],'frozen suffix call replay differs'
        result['original_code_cases_replayed']=len(data['case_results']);result['fresh_declared_native_suffix_controls_replayed']=4
    print(json.dumps(result))


if __name__=='__main__':main()
