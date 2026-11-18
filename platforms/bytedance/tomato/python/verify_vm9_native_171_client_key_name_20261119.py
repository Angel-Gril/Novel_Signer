"""Original static guard and StringObject for the X-BD-CLIENT-KEY name.

Reuse the two-read/four-SVC profile. Independently decode the ELF constant,
acquire a fresh serial guard and construct a fresh string through existing
Python owners. Stop after the native constructor returns to the interpreter.
This verifies the header name only, without a header value or signing claim.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path

from unicorn import arm64_const as arm
import verify_vm9_native_171_null_payload_20261118 as previous
import vm9_objects as objects
import vm9_startup as startup
from vm9_allocator import _read_span, _write_span

context=previous.context
graph=previous.graph
EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_client_key_name_20261119.json')
NAME=b'X-BD-CLIENT-KEY'
SOURCE,MASK,TEXT=0xF2724,0xF27C0,0x3E0F14
GUARD,OBJECT,MUTEX=0x3E0CB0,0x3E0C98,0x3E2F40
GUARD_BC,STRING_BC,STOP=0xFD098,0xFD0D4,0x16AA4C
WORDS=[(0xFD064,0x8B600E18),(GUARD_BC,0x067E0C91),(0xFD0A0,0x005F002D),(STRING_BC,0x067E0C91)]
EXPECTED=[
    (0x167E54,'mov','w9, wzr'),(0x167E70,'strb','w10, [x1, x8]'),
    (0x285944,'stp','x30, x19, [sp, #-0x10]!'),(0x28594C,'ldp','x8, x0, [x0]'),
    (0x285950,'blr','x8'),(0x285954,'str','w0, [x19, #0x10]'),
    (0x285958,'ldp','x30, x19, [sp], #0x10'),(0x28595C,'ret',''),
    (0x32D3A0,'paciasp',''),(0x32D3B8,'ldarb','w8, [x0]'),
    (0x2859A8,'ldp','x8, x1, [x0, #8]'),(0x2859AC,'ldr','x2, [x0]'),
    (0x2859B0,'mov','x0, x8'),(0x2859B4,'br','x2'),
    (0x248360,'str','x8, [x0]'),(0x24837C,'stp','w8, w0, [x19, #8]'),
    (0x248384,'bl','#0x347fd0'),(0x248388,'str','x0, [x19, #0x10]'),
    (0x2483A4,'b','#0x347f60'),(STOP,'ldp','x5, x1, [x29, #-0x90]'),
]
CLAIMS=dict(
    retained_NULL_branch_trace_and_allocation_prefix_verified=True,
    original_ELF_masked_constant_to_header_name_joined=True,
    original_serial_guard_acquisition_and_packed_u32_store_executed=True,
    original_header_name_StringObject_construction_and_return_executed=True,
    selected_guard_mutex_and_string_projections_match_existing_Python_owners=True,
    native_memory_used_as_model_input=False,new_OS_JNI_or_internal_helper_providers=False,
    static_guard_released=False,header_value_generated=False,
    full_VM_or_physical_stack_equivalence_verified=False,real_JVM_identity_verified=False,
    real_business_cache_restored=False,ordinary_Cronet_six_headers_verified=False,
    whole_request_equivalence_verified=False,callback_or_ordinary_wrapper_returned=False,
    complete_standalone_signer_verified=False,Android_execution=False,online_acceptance_verified=False,
)


def blob(raw):return dict(length=len(raw),sha256=previous.previous.previous.digest(raw),hex=raw.hex())


def put(p,a,raw):
    for page in range(a>>12,((a+len(raw)-1)>>12)+1):p.setdefault(page,bytearray(4096))
    _write_span(p,a,raw)


def model_projection():
    image=0x10000000;guard=0x60000000;obj=guard+0x100;source=guard+0x200;payload=guard+0x300;packed=guard+0x400
    p={};put(p,guard,bytes(8));put(p,image+MUTEX,bytes(40));put(p,obj,bytes(24));put(p,source,NAME+b'\0')
    put(p,packed,b'\xa5'*24);before=_read_span(p,packed,24)
    acquired=startup.acquire_serial_guard(p,guard_address=guard,image_base=image,thread_id=137)
    _write_span(p,packed+16,int(acquired).to_bytes(4,'little'));after=_read_span(p,packed,24)
    allocations=[]
    def allocate(p,size):
        assert allocations==[] and size==len(NAME)+1;allocations.append(size);put(p,payload,bytes(size));return payload
    returned=objects.construct_string_object(p,object_address=obj,source_address=source,allocate=allocate,
        vtable_address=image+0x34F5F8)
    assert returned==payload and acquired is True
    return dict(header_name=blob(NAME),guard_before=blob(bytes(8)),guard_after=blob(_read_span(p,guard,8)),
        global_mutex_before=blob(bytes(40)),global_mutex_after=blob(_read_span(p,image+MUTEX,40)),
        acquired_u32=int(acquired),packed_bytes_outside_u32_preserved=before[:16]+before[20:]==after[:16]+after[20:],
        packed_result_u32=int.from_bytes(after[16:20],'little'),object_was_zero=True,
        string_vtable_offset='0x34f5f8',capacity=int.from_bytes(_read_span(p,obj+8,4),'little'),
        length=int.from_bytes(_read_span(p,obj+12,4),'little'),terminated_payload=blob(_read_span(p,payload,len(NAME)+1)),
        requested_allocations=allocations,returned_X0_is_payload=True,static_guard_first_byte_at_stop=0)


def source_binding():
    return dict(decoder='0x167e54',byte_writer='0x167e70',source=hex(SOURCE),mask=hex(MASK),destination=hex(TEXT),
        original_byte_stores=len(NAME),destination_initially_zero=True,terminator_not_written=True)


def providers():
    return dict(inherited_NULL_payload=previous.providers(),maximum_handler_reads=2,maximum_main_SVCs=4,
        independent_model_owners=['vm9_objects.py:decode_masked_bytes','vm9_startup.py:acquire_serial_guard',
            'vm9_objects.py:construct_string_object'],independent_model_input='fresh pages and declared ELF constant/zero guard/mutex/object',
        decoder=source_binding(),guard_offset=hex(GUARD),string_object_offset=hex(OBJECT),mutex_offset=hex(MUTEX),
        thread_id=137,new_OS_JNI_or_internal_helper_providers=[],stop_before=hex(STOP),outer_bytecode=hex(STRING_BC))


class Scenario(previous.Scenario):
    def __init__(self,control):
        super().__init__(control);self.following=False;self.decode_stores=[];self.events=[];self.return_pc=None

    def native_runner(self,*args,**kwargs):
        original=kwargs['memory_write_observer']
        def write(cpu,address,size):
            if address<self.image+TEXT+len(NAME)+1 and self.image+TEXT<address+size:
                def reg(n):return cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(n)))
                assert cpu.reg_read(arm.UC_ARM64_REG_PC)==self.image+0x167E70 and size==1
                index=address-self.image-TEXT;assert index==len(self.decode_stores)<len(NAME)
                assert (reg(0),reg(1),reg(2))==(self.image+SOURCE,self.image+TEXT,self.image+MASK)
                assert reg(8)==index and reg(10)&255==NAME[index]
                if not self.decode_stores:assert bytes(cpu.mem_read(self.image+TEXT,len(NAME)+1))==bytes(len(NAME)+1)
                self.decode_stores.append(index)
            original(cpu,address,size)
        kwargs['memory_write_observer']=write
        return super().native_runner(*args,**kwargs)

    def branch_boundary(self,cpu,state):
        assert not self.following and self.decode_stores==list(range(len(NAME)))
        self.following=True;self.prefix_allocations=deepcopy(state['allocator_events_ref'])

    def observe(self,cpu,pc,state):
        if not self.following:
            super().observe(cpu,pc,state)
            if not self.following:return
        off=pc-self.image
        def reg(n):return cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(n)))
        def raw(a,n):return bytes(cpu.mem_read(a,n))
        def u(a,n=8):return int.from_bytes(raw(a,n),'little')
        bc=u(state['PC_slot'])-self.image
        if off in (0x27E6AC,0x27ED6C):raise AssertionError('unexpected callback or ordinary RET')
        if off==context.LOAD and bc==0xFD064:
            frame=u(state['backing']+29*8)
            assert reg(12)==frame and reg(13)==1048 and reg(14)==17 and u(frame+1048)==self.image+GUARD
            self.frame_load_seen=True
        if off==context.STOP and bc==0xFD064:
            assert self.frame_load_seen and u(state['backing']+17*8)==self.image+GUARD
        if off==0x285944 and bc==GUARD_BC:
            assert not hasattr(self,'guard_packed');self.guard_packed=reg(0);self.guard_before=raw(reg(0),24)
            assert u(reg(0))==self.image+0x32D3A0 and u(reg(0)+8)==self.image+GUARD and reg(30)==self.image+STOP
            assert raw(self.image+GUARD,8)==bytes(8) and raw(self.image+MUTEX,40)==bytes(40)
            self.events.append('guard entry')
        if off==0x285954 and bc==GUARD_BC:
            assert reg(0)==1 and reg(19)==self.guard_packed;self.guard_store_seen=True
        if off==0x285958 and bc==GUARD_BC:
            assert self.guard_store_seen;after=raw(self.guard_packed,24)
            assert u(self.guard_packed+16,4)==1 and self.guard_before[:16]+self.guard_before[20:]==after[:16]+after[20:]
            assert blob(raw(self.image+GUARD,8))==model_projection()['guard_after'] and raw(self.image+MUTEX,40)==bytes(40)
            self.events.append('guard result stored')
        if off==0x16EDE8 and bc==0xFD0A0:
            assert reg(9)==1 and reg(11)==0;self.events.append('acquired result differs from zero')
        if off==0x2859A8 and bc==STRING_BC:
            assert self.events==['guard entry','guard result stored','acquired result differs from zero']
            packed=reg(0)
            assert (u(packed),u(packed+8),u(packed+16))==(self.image+0x248344,self.image+OBJECT,self.image+TEXT)
            assert reg(30)==self.image+STOP and raw(self.image+OBJECT,24)==bytes(24)
            assert raw(self.image+TEXT,len(NAME)+1)==NAME+b'\0'
            self.return_pc=reg(30);self.events.append('string entry')
        if off==0x248344 and bc==STRING_BC:
            assert self.return_pc and reg(0)==self.image+OBJECT and reg(1)==self.image+TEXT
            self.events.append('native constructor entry')
        if pc==self.return_pc:
            assert bc==STRING_BC and len(self.events)==5
            assert u(self.image+OBJECT)==self.image+0x34F5F8
            assert u(self.image+OBJECT+8,4)==16 and u(self.image+OBJECT+12,4)==15
            self.payload=u(self.image+OBJECT+16)
            assert reg(0)==self.payload and raw(self.payload,16)==NAME+b'\0'
            assert raw(self.image+TEXT,16)==NAME+b'\0' and raw(self.image+MUTEX,40)==bytes(40)
            assert blob(raw(self.image+GUARD,8))==model_projection()['guard_after']
            assert raw(state['context'],128)==state['handler_bytes'] and u(self.image+0x3D1558,1)==1
            assert u(context.outer.root_fixture.TLS+0x100,4)==2
            assert u(self.state_owner+0x18)==self.node and raw(self.node,64)==previous.previous.empty_bytes()
            assert previous.previous.previous.output._cstring(cpu,self.prefix.source)==self.prefix.raw
            self.events.append('native constructor returned');self.finished=True
            self.name_boundary(cpu,state)

    def name_boundary(self,cpu,state):
        cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,context.outer.oracle.STOP)

    def finish(self,result,state,proof):
        frozen=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(frozen)
        old=next(row for row in frozen['case_results'] if row['control']==self.control)
        prefix=proof['null_branch_prefix']
        for key,old_key in (('instruction_observations','continuation_instruction_observations'),
            ('trace_sha256','continuation_trace_sha256'),('code_sha256','continuation_code_sha256')):assert prefix[key]==old[old_key]
        assert graph.digest(self.prefix_allocations)==old['allocation_ledger_sha256']
        assert self.branch_stopped and self.finished and len(self.null_flow)==9
        tail=result['allocator_events'][len(self.prefix_allocations):]
        assert result['allocator_events'][:len(self.prefix_allocations)]==self.prefix_allocations
        assert tail==[['alloc',16,self.payload,'0x248388']]
        counts=dict(old['allocator_counts']);counts['malloc']+=1
        assert result['actual_allocator_counts']==counts
        assert result['explicit_service_counts']==old['service_counts']
        for key in ('JNI_calls','libc_SVC_boundaries','main_image_SVC_boundaries'):assert proof[key]==prefix[key]==old[key]
        return dict(control=self.control,retained_checkpoint_trace_and_allocation_prefix_verified=True,
            retained_prefix_instruction_observations=prefix['instruction_observations'],
            retained_prefix_trace_sha256=prefix['trace_sha256'],retained_prefix_code_sha256=prefix['code_sha256'],
            retained_prefix_allocation_ledger_sha256=graph.digest(self.prefix_allocations),
            source_binding=source_binding(),native_events=self.events,selected_projection=model_projection(),
            allocation_tail=[dict(kind='alloc',size=16,callsite='0x248388',pointer_is_returned_payload=True)],
            handler_bytes_unchanged=True,empty_state_root_and_payload_unchanged=True,source_directory_string_unchanged=True,
            registry_guard_at_stop=1,errno_at_stop=2,original_outer_postconditions_passed=True,
            service_counts=result['explicit_service_counts'],allocator_counts=result['actual_allocator_counts'],
            JNI_calls=proof['JNI_calls'],libc_SVC_boundaries=proof['libc_SVC_boundaries'],main_image_SVC_boundaries=proof['main_image_SVC_boundaries'],
            continuation_instruction_observations=proof['instruction_observations'],continuation_trace_sha256=proof['trace_sha256'],
            continuation_code_sha256=proof['code_sha256'],allocation_ledger_sha256=graph.digest(result['allocator_events']),
            observation_stop_before=hex(STOP),outer_bytecode=hex(STRING_BC),callback_or_ordinary_RET_seen=False)


def replay(path,libc,*,on_case=None,case_controls=None):
    return context.replay(path,libc,on_case=on_case,case_controls=case_controls,_extension_factory=Scenario,
        _request_profile=previous.previous.PROFILE['name'],_handler_read_profile=context.NULL_PAYLOAD_READ_PROFILE['name'])


def verify_elf(data,path):
    from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
    old=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(old)
    upstream=previous.verify_elf(old,path);_,_,read=graph.inputs.load_elf(path);decoder=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
    for a,m,s in EXPECTED:
        ins,=decoder.disasm(read(a,4),a);assert (ins.mnemonic,ins.op_str)==(m,s),hex(a)
    for a,word in WORDS:assert int.from_bytes(read(a,4),'little')==word
    p={};put(p,SOURCE,read(SOURCE,16));put(p,MASK,read(MASK,16));put(p,TEXT,bytes(16))
    assert objects.decode_masked_bytes(p,source_address=SOURCE,mask_address=MASK,destination_address=TEXT,max_bytes=15)==15
    assert _read_span(p,TEXT,16)==NAME+b'\0'
    return dict(upstream=upstream,additional_instructions=len(EXPECTED),additional_bytecode_words=len(WORDS),
        independent_ELF_masked_decode_verified=True)


def validate(data):
    assert data['schema']=='vm9-native-171-client-key-name-20261119-v1'
    assert data['provenance']==previous.previous.previous.previous.previous.provenance()
    assert data['claims']==CLAIMS and data['providers']==providers()
    assert data['instructions']==[dict(offset=hex(a),mnemonic=m,operands=s) for a,m,s in EXPECTED]
    assert data['bytecode_words']==[dict(offset=hex(a),word=hex(w)) for a,w in WORDS]
    assert data['independent_Python_projection']==model_projection()
    frozen=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(frozen)
    assert len(data['case_results'])==len(context.controls())
    for row,old in zip(data['case_results'],frozen['case_results']):
        assert row['control']==old['control'] and row['retained_checkpoint_trace_and_allocation_prefix_verified'] is True
        for key,old_key in (('retained_prefix_instruction_observations','continuation_instruction_observations'),
            ('retained_prefix_trace_sha256','continuation_trace_sha256'),('retained_prefix_code_sha256','continuation_code_sha256'),
            ('retained_prefix_allocation_ledger_sha256','allocation_ledger_sha256')):assert row[key]==old[old_key]
        assert row['source_binding']==source_binding() and row['selected_projection']==model_projection()
        assert row['native_events']==['guard entry','guard result stored','acquired result differs from zero',
            'string entry','native constructor entry','native constructor returned']
        assert row['allocation_tail']==[dict(kind='alloc',size=16,callsite='0x248388',pointer_is_returned_payload=True)]
        for key in ('handler_bytes_unchanged','empty_state_root_and_payload_unchanged',
            'source_directory_string_unchanged','original_outer_postconditions_passed'):assert row[key] is True
        assert row['registry_guard_at_stop']==1 and row['errno_at_stop']==2
        assert row['observation_stop_before']==hex(STOP) and row['outer_bytecode']==hex(STRING_BC)
        assert row['callback_or_ordinary_RET_seen'] is False
        for key in ('service_counts','JNI_calls','libc_SVC_boundaries','main_image_SVC_boundaries'):assert row[key]==old[key]
        counts=dict(old['allocator_counts']);counts['malloc']+=1;assert row['allocator_counts']==counts
        assert row['continuation_instruction_observations']==old['continuation_instruction_observations']+2277
        for key in ('continuation_trace_sha256','continuation_code_sha256','allocation_ledger_sha256'):assert graph.inputs.is_digest(row[key])


def build(path,libc,*,on_case=None):
    data=dict(schema='vm9-native-171-client-key-name-20261119-v1',provenance=previous.previous.previous.previous.previous.provenance(),
        claims=CLAIMS,providers=providers(),independent_Python_projection=model_projection(),
        instructions=[dict(offset=hex(a),mnemonic=m,operands=s) for a,m,s in EXPECTED],
        bytecode_words=[dict(offset=hex(a),word=hex(w)) for a,w in WORDS],case_results=[])
    verify_elf(data,path);data['case_results']=replay(path,libc,on_case=on_case);validate(data);return data


def negatives(data):
    count=0
    def reject(path,value):
        nonlocal count
        bad=deepcopy(data);target=bad
        for key in path[:-1]:target=target[key]
        target[path[-1]]=value
        try:validate(bad)
        except AssertionError:count+=1
        else:raise AssertionError('damaged client-key-name evidence accepted: '+str(path))
    for key,value in CLAIMS.items():reject(('claims',key),not value)
    reject(('providers','maximum_handler_reads'),3);reject(('providers','maximum_main_SVCs'),5)
    reject(('instructions',0,'mnemonic'),'nop');reject(('bytecode_words',1,'word'),'0x0')
    reject(('independent_Python_projection','length'),0)
    for i in range(len(data['case_results'])):
        p=('case_results',i)
        for path,value in ((('retained_checkpoint_trace_and_allocation_prefix_verified',),False),
            (('retained_prefix_trace_sha256',),'0'*64),(('retained_prefix_allocation_ledger_sha256',),'0'*64),
            (('source_binding','source'),'0x0'),(('source_binding','original_byte_stores'),16),
            (('selected_projection','acquired_u32'),0),(('selected_projection','guard_after','hex'),'00'*8),
            (('selected_projection','length'),0),(('selected_projection','terminated_payload','sha256'),'0'*64),
            (('allocation_tail',0,'size'),8),(('allocation_tail',0,'callsite'),'0x0'),
            (('native_events',),[]),(('handler_bytes_unchanged',),False),
            (('empty_state_root_and_payload_unchanged',),False),(('source_directory_string_unchanged',),False),
            (('registry_guard_at_stop',),0),(('errno_at_stop',),17),(('observation_stop_before',),'0x0'),
            (('outer_bytecode',),'0xfd098'),(('callback_or_ordinary_RET_seen',),True),(('JNI_calls',),[]),
            (('libc_SVC_boundaries',),[]),(('main_image_SVC_boundaries',),[]),
            (('service_counts','syscall_48'),5),(('allocator_counts','malloc'),0),
            (('continuation_instruction_observations',),0)):
            reject(p+path,value)
    return count


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--elf',type=Path);ap.add_argument('--libc',type=Path);ap.add_argument('--replay',action='store_true')
    args=ap.parse_args()
    if args.replay and (not args.elf or not args.libc):ap.error('--replay requires --elf and --libc')
    data=json.loads(EVIDENCE.read_text(encoding='utf-8'));validate(data)
    result=dict(retained_client_key_name_cases=len(data['case_results']),damaged_evidence_rejected=negatives(data),
        header_value_generated=False,ordinary_Cronet_six_headers_verified=False,complete_standalone_signer_verified=False)
    if args.elf:result['Metasec_bindings']=verify_elf(data,args.elf)
    if args.libc:graph.inputs.libc_image(args.libc);result['matching_Bionic_digest_verified']=True
    if args.replay:
        assert replay(args.elf,args.libc)==data['case_results'],'frozen client-key-name replay differs'
        result['original_code_cases_replayed']=len(data['case_results'])
    print(json.dumps(result))


if __name__=='__main__':main()
