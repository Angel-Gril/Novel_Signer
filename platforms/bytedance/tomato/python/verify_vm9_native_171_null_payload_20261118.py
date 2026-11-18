"""Original constructed NULL payload load and its consuming equality branch.

One explicit read profile permits only handler+8 at the bound bytecode/site.
The existing Python VM executes two instructions on declared fresh inputs.
Stop after the branch cursor store, before the next bytecode handler executes.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import json
import os
from pathlib import Path

from unicorn import arm64_const as arm
import verify_vm9_native_171_file_check_20261118 as previous

context=previous.context
graph=previous.graph
EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_null_payload_20261118.json')
STOP=0x16EE38
BRANCH=0xFCD08
TARGET=0xFD064
WORDS=[(previous.CURSOR,0x10400218),(BRANCH,0x1896002D),(TARGET,0x8B600E18)]
EXPECTED=[
    (0x15DE4C,'mov','x19, x1'),(0x15DE64,'str','x19, [x20]'),
    (0x16F970,'str','w14, [x23]'),(0x16F974,'str','x9, [x28, x14, lsl #3]'),
    (0x16F978,'ldr','w9, [x8, #4]!'),(0x16EDDC,'ldr','x9, [x28, w9, sxtw #3]'),
    (0x16EDE4,'ldr','x11, [x28, w11, sxtw #3]'),(0x16EDE8,'cmp','x9, x11'),
    (0x16EDF0,'csel','x9, x10, xzr, eq'),(0x16EE00,'add','x8, x8, x9, lsl #2'),
    (0x16EE30,'ldr','w11, [x8, #4]!'),(0x16EE34,'str','x8, [x19]'),
    (STOP,'add','x8, x9, x10'),
]
CLAIMS=dict(
    inherited_absent_file_and_empty_state_row_reproduced=True,
    original_constructor_wrote_NULL_payload_to_handler_member_8=True,
    second_handler_load_and_R2_store_executed=True,
    original_R2_equals_R0_branch_and_cursor_store_executed=True,
    selected_two_instruction_projection_matches_existing_Python_VM=True,
    next_bytecode_handler_executed=False,
    new_OS_JNI_or_internal_helper_providers=False,native_memory_used_as_model_input=False,
    full_request_VM_or_physical_stack_equivalence_verified=False,
    real_filesystem_or_business_cache_restored=False,real_JVM_identity_verified=False,
    ordinary_Cronet_six_headers_verified=False,whole_request_equivalence_verified=False,
    callback_or_ordinary_wrapper_returned=False,complete_standalone_signer_verified=False,
    Android_execution=False,online_acceptance_verified=False,
)


def projection():
    return dict(load_bytecode=hex(previous.CURSOR),member_offset='0x8',virtual_register=2,
        constructor_payload_u64=0,loaded_value_u64=0,branch_bytecode=hex(BRANCH),
        branch_registers=[2,0],branch_values_u64=[0,0],equal=True,
        signed_displacement_words=214,target_bytecode=hex(TARGET),
        executed_bytecodes=[hex(previous.CURSOR),hex(BRANCH)],
        virtual_registers_other_than_R2_preserved=True)


def second_read():
    return dict(native_pc=hex(context.LOAD),bytecode=hex(previous.CURSOR),member_offset='0x8',
        size=8,virtual_register=2,value_u64=0,base_is_constructed_handler=True,
        value_is_constructor_member_payload=True)


def writer():
    return dict(native_pc='0x15de64',instruction_hex='930200f9',member_offset='0x8',
        size=8,value_u64=0,matches_constructor_member=True)


def providers():
    return dict(inherited_file_check=previous.providers(),
        handler_read_profile=context.NULL_PAYLOAD_READ_PROFILE,
        handler_reads=[dict(native_pc=hex(context.LOAD),bytecode=hex(context.CURSOR),member_offset='0x50'),
            second_read()],maximum_handler_reads=2,
        independent_model_owner='vm_full.py:VM.run',
        independent_model_input='declared bytecode words and fresh synthetic handler/registers',
        new_OS_JNI_or_internal_helper_providers=[],stop_before=hex(STOP),next_bytecode=hex(TARGET))


def interpreter_projection(path):
    """Use the existing VM, never a native memory/register snapshot."""
    saved=os.environ.get('TOMATO_LIBMETASEC')
    try:
        os.environ['TOMATO_LIBMETASEC']=str(path.resolve())
        import vm_full as vm_module
    finally:
        if saved is None:os.environ.pop('TOMATO_LIBMETASEC',None)
        else:os.environ['TOMATO_LIBMETASEC']=saved
    assert previous.previous.digest(vm_module.SO)==graph.inputs.SHA256
    from vm9_allocator import _read_span, _write_span
    class Memory:
        def __init__(self):self.pages={}
        def u32(self,a):return int.from_bytes(_read_span(self.pages,a,4),'little')
        def u64(self,a):return int.from_bytes(_read_span(self.pages,a,8),'little')
        def put(self,a,raw):
            for page in range(a>>12,((a+len(raw)-1)>>12)+1):self.pages.setdefault(page,bytearray(4096))
            _write_span(self.pages,a,raw)
    class Boundary(Exception):pass
    original_base=vm_module.B;rows=[]
    try:
        for image in graph.BASES:
            vm_module.B=image;m=Memory();handler=0x60000000
            m.put(handler,bytes(128))
            for address,word in WORDS:m.put(image+address,word.to_bytes(4,'little'))
            vm=vm_module.VM(m,previous.CURSOR,0,0,0,0,0,maxsteps=3)
            vm.R=[0xA5A5000000000000+i for i in range(32)]
            vm.R[0]=0;vm.R[1]=handler;before=list(vm.R);steps=[]
            def step(vm,dw,op,sub):
                if vm.pc==image+TARGET:raise Boundary()
                expected=WORDS[len(steps)]
                assert vm.pc==image+expected[0] and dw==expected[1]
                if vm.pc==image+BRANCH:assert vm.R[2]==0
                steps.append(hex(vm.pc-image))
            vm.step_hook=step
            try:vm.run()
            except Boundary:pass
            else:raise AssertionError('two-instruction model did not stop at its target')
            assert vm.pc==image+TARGET and steps==projection()['executed_bytecodes'] and vm.R[2]==0
            assert all(vm.R[i]==before[i] for i in range(32) if i!=2)
            assert _read_span(m.pages,handler,128)==bytes(128)
            rows.append(dict(image_base=hex(image),projection=projection()))
    finally:vm_module.B=original_base
    return rows


class Scenario(previous.Scenario):
    def __init__(self,control):
        super().__init__(control);self.active=False;self.null_flow=[];self.payload_writers=[]

    def native_runner(self,*args,**kwargs):
        original=kwargs['memory_write_observer']
        def write(cpu,address,size):
            if cpu.reg_read(arm.UC_ARM64_REG_PC)==self.image+0x15DE64:
                assert size==8 and address==cpu.reg_read(arm.UC_ARM64_REG_X20)
                self.payload_writers.append((address,cpu.reg_read(arm.UC_ARM64_REG_X19)))
                assert len(self.payload_writers)<128
            original(cpu,address,size)
        kwargs['memory_write_observer']=write
        return super().native_runner(*args,**kwargs)

    def handler_read_boundary(self,cpu,state):
        assert not self.active
        member=state['context']+8
        assert [v for a,v in self.payload_writers if a==member]==[0]
        self.active=True
        self.registers_before=bytes(cpu.mem_read(state['backing'],256))

    def observe(self,cpu,pc,state):
        if not self.active:
            super().observe(cpu,pc,state)
            if not self.active:return
        off=pc-self.image
        def reg(n):return cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(n)))
        def u(a,n=8):return int.from_bytes(cpu.mem_read(a,n),'little')
        bc=u(state['PC_slot'])-self.image
        if off in (0x27E6AC,0x27ED6C):raise AssertionError('unexpected callback or ordinary RET')
        if off in (context.LOAD,0x16F970,context.STORE,context.STOP):
            assert bc==previous.CURSOR and reg(12)==state['context'] and reg(13)==8 and reg(14)==2
            if off==context.LOAD:assert u(reg(12)+8)==0
            else:assert reg(9)==0
            if off==context.STOP:
                after=bytes(cpu.mem_read(state['backing'],256))
                assert after[16:24]==bytes(8)
                assert self.registers_before[:16]+self.registers_before[24:]==after[:16]+after[24:]
            self.null_flow.append(hex(off))
        if off==0x16EDE8:
            assert bc==BRANCH and reg(9)==reg(11)==u(state['backing']+16)==u(state['backing'])==0
            assert reg(10)==214
            self.null_flow.append(hex(off))
        if off==0x16EDF0:
            assert bc==BRANCH and (cpu.reg_read(arm.UC_ARM64_REG_NZCV)>>30)&1==1
            self.null_flow.append(hex(off))
        if off==0x16EDF4:
            assert bc==BRANCH and reg(9)==214
            self.null_flow.append(hex(off))
        if off==0x16EE34:
            assert bc==BRANCH and reg(8)==self.image+TARGET
            self.null_flow.append(hex(off))
        if off==STOP:
            assert bc==TARGET and len(self.null_flow)==8
            after=bytes(cpu.mem_read(state['backing'],256))
            assert after==self.registers_before[:16]+bytes(8)+self.registers_before[24:]
            assert bytes(cpu.mem_read(state['context'],128))==state['handler_bytes']
            assert u(self.state_owner+0x18)==self.node and bytes(cpu.mem_read(self.node,64))==previous.empty_bytes()
            assert u(self.image+0x3D1558,1)==1 and u(context.outer.root_fixture.TLS+0x100,4)==2
            assert previous.previous.output._cstring(cpu,self.prefix.source)==self.prefix.raw
            self.null_flow.append(hex(off));self.branch_stopped=True
            self.branch_boundary(cpu,state)

    def branch_boundary(self,cpu,state):
        cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,context.outer.oracle.STOP)

    def finish(self,result,state,proof):
        old_row=super().finish(result,state,proof['second_handler_read_prefix'])
        frozen=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(frozen)
        old=next(row for row in frozen['case_results'] if row['control']==self.control)
        assert old_row==old,'entire inherited file-check row differs'
        assert self.branch_stopped and proof['context_reads'][1:]==[second_read()]
        assert proof['JNI_calls']==old['JNI_calls'] and proof['libc_SVC_boundaries']==old['libc_SVC_boundaries']
        assert proof['main_image_SVC_boundaries']==old['main_image_SVC_boundaries']
        return dict(control=self.control,inherited_file_check_row_sha256=graph.digest(old_row),
            constructor_payload_writer=writer(),second_handler_read=proof['context_reads'][1],
            native_flow=self.null_flow,selected_projection=projection(),
            handler_bytes_unchanged=True,empty_state_root_and_payload_unchanged=True,
            source_directory_string_unchanged=True,registry_guard_at_stop=1,errno_at_stop=2,
            main_image_SVC_boundaries=proof['main_image_SVC_boundaries'],JNI_calls=proof['JNI_calls'],
            libc_SVC_boundaries=proof['libc_SVC_boundaries'],service_counts=result['explicit_service_counts'],
            allocator_counts=result['actual_allocator_counts'],allocation_ledger_sha256=graph.digest(result['allocator_events']),
            continuation_instruction_observations=proof['instruction_observations'],
            continuation_trace_sha256=proof['trace_sha256'],continuation_code_sha256=proof['code_sha256'],
            original_outer_postconditions_passed=True,observation_stop_before=hex(STOP),
            next_bytecode_cursor=hex(TARGET),next_bytecode_handler_executed=False,
            callback_or_ordinary_RET_seen=False)


def replay(path,libc,*,on_case=None,case_controls=None):
    return context.replay(path,libc,on_case=on_case,case_controls=case_controls,
        _extension_factory=Scenario,_request_profile=previous.PROFILE['name'],
        _handler_read_profile=context.NULL_PAYLOAD_READ_PROFILE['name'])


def verify_elf(data,path):
    from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
    old=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(old)
    upstream=previous.verify_elf(old,path)
    _,_,read=graph.inputs.load_elf(path);decoder=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
    for a,m,s in EXPECTED:
        ins,=decoder.disasm(read(a,4),a);assert (ins.mnemonic,ins.op_str)==(m,s),hex(a)
    for a,word in WORDS:assert int.from_bytes(read(a,4),'little')==word
    rows=interpreter_projection(path)
    return dict(upstream=upstream,additional_instructions=len(EXPECTED),additional_bytecode_words=len(WORDS),
        independent_existing_Python_VM_cases=len(rows))


def validate(data):
    assert data['schema']=='vm9-native-171-null-payload-20261118-v1'
    assert data['provenance']==previous.previous.previous.previous.provenance()
    assert data['claims']==CLAIMS and data['providers']==providers()
    assert data['instructions']==[dict(offset=hex(a),mnemonic=m,operands=s) for a,m,s in EXPECTED]
    assert data['bytecode_words']==[dict(offset=hex(a),word=hex(w)) for a,w in WORDS]
    assert data['independent_projection']==projection()
    frozen=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(frozen)
    assert len(data['case_results'])==len(context.controls())
    for row,old in zip(data['case_results'],frozen['case_results']):
        assert row['control']==old['control'] and row['inherited_file_check_row_sha256']==graph.digest(old)
        assert row['constructor_payload_writer']==writer() and row['second_handler_read']==second_read()
        assert row['selected_projection']==projection()
        assert row['native_flow']==[hex(a) for a in (
            context.LOAD,0x16F970,context.STORE,context.STOP,0x16EDE8,0x16EDF0,0x16EDF4,0x16EE34,STOP)]
        for key in ('handler_bytes_unchanged','empty_state_root_and_payload_unchanged',
            'source_directory_string_unchanged','original_outer_postconditions_passed'):assert row[key] is True
        assert row['registry_guard_at_stop']==1 and row['errno_at_stop']==2
        assert row['next_bytecode_cursor']==hex(TARGET) and row['observation_stop_before']==hex(STOP)
        assert row['next_bytecode_handler_executed'] is row['callback_or_ordinary_RET_seen'] is False
        for key in ('main_image_SVC_boundaries','JNI_calls','libc_SVC_boundaries','service_counts',
            'allocator_counts','allocation_ledger_sha256'):assert row[key]==old[key]
        assert row['continuation_instruction_observations']==old['continuation_instruction_observations']+96
        for key in ('continuation_trace_sha256','continuation_code_sha256'):assert graph.inputs.is_digest(row[key])


def build(path,libc,*,on_case=None):
    data=dict(schema='vm9-native-171-null-payload-20261118-v1',provenance=previous.previous.previous.previous.provenance(),
        claims=CLAIMS,providers=providers(),independent_projection=projection(),
        instructions=[dict(offset=hex(a),mnemonic=m,operands=s) for a,m,s in EXPECTED],
        bytecode_words=[dict(offset=hex(a),word=hex(w)) for a,w in WORDS],case_results=[])
    verify_elf(data,path);data['case_results']=replay(path,libc,on_case=on_case);validate(data)
    return data


def negatives(data):
    count=0
    def reject(path,value):
        nonlocal count
        bad=deepcopy(data);target=bad
        for key in path[:-1]:target=target[key]
        target[path[-1]]=value
        try:validate(bad)
        except AssertionError:count+=1
        else:raise AssertionError('damaged NULL payload evidence accepted: '+str(path))
    for key,value in CLAIMS.items():reject(('claims',key),not value)
    for key,value in (('maximum_handler_reads',3),('next_bytecode','0xfcd0c')):reject(('providers',key),value)
    reject(('instructions',0,'mnemonic'),'nop');reject(('bytecode_words',1,'word'),'0x0')
    reject(('independent_projection','target_bytecode'),'0xfcd0c')
    for i in range(len(data['case_results'])):
        p=('case_results',i)
        for path,value in ((('inherited_file_check_row_sha256',),'0'*64),
            (('constructor_payload_writer','value_u64'),1),(('constructor_payload_writer','native_pc'),'0x0'),
            (('second_handler_read','bytecode'),'0xfae4c'),(('second_handler_read','member_offset'),'0x50'),
            (('second_handler_read','virtual_register'),1),(('second_handler_read','value_u64'),1),
            (('selected_projection','equal'),False),(('native_flow',),[]),(('handler_bytes_unchanged',),False),
            (('empty_state_root_and_payload_unchanged',),False),(('registry_guard_at_stop',),0),
            (('errno_at_stop',),17),(('source_directory_string_unchanged',),False),
            (('next_bytecode_cursor',),'0xfcd0c'),(('next_bytecode_handler_executed',),True),
            (('callback_or_ordinary_RET_seen',),True),(('JNI_calls',),[]),
            (('service_counts','syscall_48'),5),(('libc_SVC_boundaries',),[]),
            (('main_image_SVC_boundaries',),[]),(('continuation_instruction_observations',),0)):
            reject(p+path,value)
    return count


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--elf',type=Path);ap.add_argument('--libc',type=Path);ap.add_argument('--replay',action='store_true')
    args=ap.parse_args()
    if args.replay and (not args.elf or not args.libc):ap.error('--replay requires --elf and --libc')
    data=json.loads(EVIDENCE.read_text(encoding='utf-8'));validate(data)
    result=dict(retained_NULL_payload_cases=len(data['case_results']),damaged_evidence_rejected=negatives(data),
        ordinary_Cronet_six_headers_verified=False,complete_standalone_signer_verified=False)
    if args.elf:result['Metasec_bindings']=verify_elf(data,args.elf)
    if args.libc:graph.inputs.libc_image(args.libc);result['matching_Bionic_digest_verified']=True
    if args.replay:
        assert replay(args.elf,args.libc)==data['case_results'],'frozen NULL payload replay differs'
        result['original_code_cases_replayed']=len(data['case_results'])
    print(json.dumps(result))


if __name__=='__main__':main()
