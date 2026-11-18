"""Original X-BD-KMSV name initialization, publication and missing-key lookup.

Continue the accepted client-key-result prefix. Existing Python owners use
fresh declared pages; native memory is never model input. This checkpoint
proves the name and NULL lookup, without generating a KMSV value.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path

from unicorn import arm64_const as arm
import verify_vm9_native_171_client_key_result_20261119 as previous

context=previous.context
graph=previous.graph
lookup=previous.previous
name=lookup.previous
EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_kmsv_lookup_20261119.json')
NAME=b'X-BD-KMSV'
SOURCE,MASK,TEXT=0xF2734,0xF27B4,0x3E0F28
GUARD,OBJECT,MUTEX=0x3E0CD0,0x3E0CB8,name.MUTEX
GUARD_BC,STRING_BC,ATE_BC,RELEASE_BC,LOOKUP_BC=0xFD180,0xFD1BC,0xFD1E8,0xFD204,0xFD228
STOP=name.STOP
WORDS=[(GUARD_BC,0x067E0C91),(0xFD188,0x005F002D),
    (STRING_BC,0x067E0C91),(ATE_BC,0x067E0C91),(RELEASE_BC,0x067E0C91),(LOOKUP_BC,0x067E0C91)]
EXPECTED=name.EXPECTED+lookup.EXPECTED
EVENTS=['guard entry','guard u32 stored','acquired result differs from zero','string entry',
    'string returned','matching Bionic registration entry','registration u32 stored',
    'guard release entry','published name lookup entry','NULL lookup returned']
CLAIMS=dict(
    retained_result_instruction_code_and_allocation_prefix_verified=True,
    original_ELF_masked_constant_to_KMSV_name_joined=True,
    original_KMSV_guard_acquisition_and_u32_store_executed=True,
    original_KMSV_name_StringObject_constructed_and_returned=True,
    matching_Bionic_destructor_registration_record_observed=True,
    original_KMSV_guard_release_and_missing_name_lookup_executed=True,
    selected_projections_match_existing_fresh_Python_owners=True,
    native_memory_used_as_model_input=False,new_OS_JNI_or_internal_helper_providers=False,
    entire_retained_result_row_reproduced=False,full_VM_or_Bionic_state_equivalence_verified=False,
    KMSV_value_generated=False,client_key_value_generated=False,saved_client_key_NULL_later_branch_verified=False,
    real_business_cache_restored=False,real_JVM_identity_verified=False,
    ordinary_Cronet_six_headers_verified=False,whole_request_equivalence_verified=False,
    callback_or_ordinary_wrapper_returned=False,complete_standalone_signer_verified=False,
    Android_execution=False,online_acceptance_verified=False,
)


def source_binding():
    return dict(decoder='0x167e54',byte_writer='0x167e70',source=hex(SOURCE),mask=hex(MASK),destination=hex(TEXT),
        original_byte_stores=len(NAME),destination_initially_zero=True,terminator_not_written=True)


def model_projection():
    image=0x10000000;root=0x60000000
    pages={page:bytearray(4096) for page in range(root>>12,(root+0x4000)>>12)};next_pointer=root+0x1000
    def put(a,raw):name.put(pages,a,raw)
    def read(a,n):return name._read_span(pages,a,n)
    def word(a,n=8):return int.from_bytes(read(a,n),'little')
    def allocate(p,size):
        nonlocal next_pointer
        address=next_pointer;next_pointer+=0x100;assert next_pointer<root+0x4000
        put(address,bytes(size));return address
    def unexpected(*args):raise AssertionError('unexpected fresh model provider')
    guard=image+GUARD;obj=image+OBJECT;source=image+TEXT
    put(guard,bytes(8));put(image+MUTEX,bytes(40));put(obj,bytes(24));put(source,NAME+b'\0')
    acquired=lookup.startup.acquire_serial_guard(pages,guard_address=guard,image_base=image,thread_id=137)
    assert acquired is True;guard_acquired=read(guard,8);assert read(image+MUTEX,40)==bytes(40)
    payload=name.objects.construct_string_object(pages,object_address=obj,source_address=source,
        allocate=allocate,vtable_address=image+0x34F5F8)
    assert payload==word(obj+16)
    registrations=[]
    def register(p,destructor,object_address,dso):
        registrations.append([hex(destructor-image),hex(object_address-image),hex(dso-image)]);return 0
    registered=lookup.callbacks.register_process_destructor(pages,destructor_address=image+0x2484B8,
        object_address=obj,dso_address=image+0x34C700,register_exit=register)
    lookup.startup.release_serial_guard(pages,guard_address=guard,image_base=image)
    descriptor=root+0x80;container=root+0x100;key=root+0x200;value=root+0x300
    put(container,bytes(40))
    for i,offset in enumerate((0x182D6C,0x182D6C,0x188A94)):put(descriptor+i*8,(image+offset).to_bytes(8,'little'))
    lookup.registry.construct_configuration_tree(pages,container_address=container,descriptor_address=descriptor,
        image_base=image,allocate=allocate)
    for target,text in ((key,lookup.KEY),(value,lookup.VALUE)):
        put(target,bytes(24));put(target+0x40,text+b'\0')
        name.objects.construct_string_object(pages,object_address=target,source_address=target+0x40,
            allocate=allocate,vtable_address=image+0x34F5F8)
    lookup.registry.insert_configuration_pair(pages,container_address=container,key_address=key,value_address=value,
        image_base=image,allocate=allocate,free=unexpected)
    tree=lookup.tree_projection(read,image,container);before={a:bytes(raw) for a,raw in pages.items()}
    found=lookup.registry.lookup_configuration_value(pages,container_address=container,key_address=obj,image_base=image)
    assert found==0 and before=={a:bytes(raw) for a,raw in pages.items()}
    return dict(name=name.blob(NAME),guard_after_acquire=name.blob(guard_acquired),
        guard_after_release=name.blob(read(guard,8)),mutex_after=name.blob(read(image+MUTEX,40)),
        guard_acquired_u32=int(acquired),string_vtable_offset='0x34f5f8',capacity=word(obj+8,4),length=word(obj+12,4),
        terminated_payload=name.blob(read(payload,len(NAME)+1)),constructor_X0_is_payload=True,
        registration_arguments=registrations,registration_status_u32=registered,
        tree=tree,lookup_result_NULL=True,model_lookup_pages_unchanged=True,
        packed_bytes_outside_acquire_u32_preserved=True,packed_bytes_outside_registration_u32_preserved=True,
        packed_bytes_outside_lookup_u64_preserved=True)


def providers():
    return dict(inherited_result=previous.providers(),maximum_handler_reads=2,maximum_main_SVCs=4,
        independent_model_owners=['vm9_objects.py:decode_masked_bytes','vm9_objects.py:construct_string_object',
            'vm9_startup.py:acquire_serial_guard','vm9_startup.py:release_serial_guard',
            'vm9_callbacks.py:register_process_destructor','vm9_registry.py:lookup_configuration_value'],
        independent_model_input='fresh declared zero guard/mutex/object and singleton X-TEST/value tree',
        decoder=source_binding(),guard_offset=hex(GUARD),object_offset=hex(OBJECT),thread_id=137,
        matching_Bionic_export=hex(lookup.LIBC_EXPORT),additional_libc_SVCs=[dict(libc_pc='0x6a550',number=226)]*2,
        allocation_delta=dict(malloc=1,size=10,callsite='0x248388'),service_count_deltas=dict(syscall_226=2),
        new_OS_JNI_or_internal_helper_providers=[],stop_before=hex(STOP),outer_bytecode=hex(LOOKUP_BC))


class Scenario(previous.Scenario):
    def __init__(self,control):
        super().__init__(control);self.kmsv_active=False;self.kmsv_decoded=[];self.kmsv_events=[]
        self.kmsv_protections=[];self.kmsv_model=model_projection();self.kmsv_return=None

    def native_runner(self,*args,**kwargs):
        original=kwargs['memory_write_observer']
        def write(cpu,address,size):
            if address<self.image+TEXT+len(NAME)+1 and self.image+TEXT<address+size:
                def reg(n):return cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(n)))
                index=address-self.image-TEXT
                assert cpu.reg_read(arm.UC_ARM64_REG_PC)==self.image+0x167E70 and size==1
                assert index==len(self.kmsv_decoded)<len(NAME)
                assert (reg(0),reg(1),reg(2))==(self.image+SOURCE,self.image+TEXT,self.image+MASK)
                assert reg(8)==index and reg(10)&255==NAME[index]
                if not self.kmsv_decoded:assert bytes(cpu.mem_read(self.image+TEXT,len(NAME)+1))==bytes(len(NAME)+1)
                self.kmsv_decoded.append(index)
            original(cpu,address,size)
        kwargs['memory_write_observer']=write
        return super().native_runner(*args,**kwargs)

    def result_boundary(self,cpu,state):
        assert self.result_done and not self.kmsv_active and self.kmsv_decoded==list(range(len(NAME)))
        self.kmsv_active=True;self.kmsv_prefix_allocations=deepcopy(state['allocator_events_ref'])

    def observe(self,cpu,pc,state):
        if not self.kmsv_active:
            super().observe(cpu,pc,state)
            if not self.kmsv_active:return
        off=pc-self.image
        def reg(n):return cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(n)))
        def raw(a,n):return bytes(cpu.mem_read(a,n))
        def u(a,n=8):return int.from_bytes(raw(a,n),'little')
        bc=u(state['PC_slot'])-self.image
        if off in (0x27E6AC,0x27ED6C):raise AssertionError('unexpected ordinary callback/wrapper RET')
        if off==0x285944 and bc==GUARD_BC:
            self.kmsv_guard_packed=reg(0);self.kmsv_guard_before=raw(reg(0),24)
            assert (u(reg(0)),u(reg(0)+8))==(self.image+0x32D3A0,self.image+GUARD)
            assert reg(30)==self.image+STOP and raw(self.image+GUARD,8)==bytes(8) and raw(self.image+MUTEX,40)==bytes(40)
            self.kmsv_events.append('guard entry')
        if off==0x285954 and bc==GUARD_BC:
            assert reg(0)==1 and reg(19)==self.kmsv_guard_packed;self.kmsv_guard_store=True
        if off==0x285958 and bc==GUARD_BC:
            assert self.kmsv_guard_store;after=raw(self.kmsv_guard_packed,24)
            assert u(self.kmsv_guard_packed+16,4)==1
            assert self.kmsv_guard_before[:16]+self.kmsv_guard_before[20:]==after[:16]+after[20:]
            assert name.blob(raw(self.image+GUARD,8))==self.kmsv_model['guard_after_acquire']
            assert raw(self.image+MUTEX,40)==bytes(40);self.kmsv_events.append('guard u32 stored')
        if off==0x16EDE8 and bc==0xFD188:
            assert reg(9)==1 and reg(11)==0;self.kmsv_events.append('acquired result differs from zero')
        if off==0x2859A8 and bc==STRING_BC:
            packed=reg(0)
            assert tuple(u(packed+i*8) for i in range(3))==(self.image+0x248344,self.image+OBJECT,self.image+TEXT)
            assert reg(30)==self.image+STOP and raw(self.image+OBJECT,24)==bytes(24)
            assert raw(self.image+TEXT,len(NAME)+1)==NAME+b'\0';self.kmsv_events.append('string entry')
        if off==STOP and bc==STRING_BC:
            assert u(self.image+OBJECT)==self.image+0x34F5F8
            assert (u(self.image+OBJECT+8,4),u(self.image+OBJECT+12,4))==(10,9)
            self.kmsv_payload=u(self.image+OBJECT+16)
            assert reg(0)==self.kmsv_payload and raw(self.kmsv_payload,10)==NAME+b'\0'
            self.kmsv_events.append('string returned')
        if off==0x285B7C and bc==ATE_BC:
            self.kmsv_atexit=reg(0);self.kmsv_atexit_before=raw(reg(0),40)
            assert tuple(u(reg(0)+i*8) for i in range(4))==(graph.inputs.LIBC_BASE+lookup.LIBC_EXPORT,
                self.image+0x2484B8,self.image+OBJECT,self.image+0x34C700)
            self.kmsv_events.append('matching Bionic registration entry')
        if pc==graph.inputs.LIBC_BASE+0x6A550 and bc==ATE_BC:
            assert reg(8)==226 and reg(1)==4096 and reg(0)&4095==0
            expected=(3,1)[len(self.kmsv_protections)];assert reg(2)==expected
            needle=b''.join((self.image+i).to_bytes(8,'little') for i in (0x2484B8,OBJECT,0x34C700))
            data=raw(reg(0),4096)
            if not self.kmsv_protections:
                assert needle not in data;self.kmsv_registration_page=reg(0)
            else:
                assert reg(0)==self.kmsv_registration_page and data.count(needle)==1
                self.kmsv_registration_offset=data.index(needle)
            self.kmsv_protections.append(expected)
        if off==0x285B90 and bc==ATE_BC:
            assert reg(0)==0 and reg(19)==self.kmsv_atexit;self.kmsv_registration_store=True
        if off==0x28596C and bc==RELEASE_BC:
            assert self.kmsv_registration_store and self.kmsv_protections==[3,1]
            after=raw(self.kmsv_atexit,40);assert u(self.kmsv_atexit+32,4)==0
            assert self.kmsv_atexit_before[:32]+self.kmsv_atexit_before[36:]==after[:32]+after[36:]
            self.kmsv_events.append('registration u32 stored')
            assert (u(reg(0)),u(reg(0)+8))==(self.image+0x32D4F8,self.image+GUARD)
            assert name.blob(raw(self.image+GUARD,8))==self.kmsv_model['guard_after_acquire']
            self.kmsv_events.append('guard release entry')
        if off==0x285BB0 and bc==LOOKUP_BC:
            assert (u(reg(0)),u(reg(0)+16))==(self.image+0x25C168,self.image+OBJECT)
            assert name.blob(raw(self.image+GUARD,8))==self.kmsv_model['guard_after_release']
            assert raw(self.image+MUTEX,40)==bytes(40)
            self.kmsv_container=u(reg(0)+8);self.kmsv_tree=lookup.tree_projection(raw,self.image,self.kmsv_container)
            assert self.kmsv_tree==self.kmsv_model['tree'] and self.kmsv_container==self.container
            self.kmsv_lookup=reg(0);self.kmsv_lookup_before=raw(reg(0),32);self.kmsv_return=reg(30)
            assert self.kmsv_return==self.image+STOP;self.kmsv_events.append('published name lookup entry')
        if self.kmsv_return is not None and pc==self.kmsv_return:
            assert bc==LOOKUP_BC and reg(0)==0 and u(self.kmsv_lookup+24)==0
            assert raw(self.kmsv_lookup,24)==self.kmsv_lookup_before[:24]
            assert lookup.tree_projection(raw,self.image,self.kmsv_container)==self.kmsv_tree==self.tree
            assert raw(state['context'],128)==state['handler_bytes']
            assert u(self.state_owner+0x18)==self.node and raw(self.node,64)==name.previous.previous.empty_bytes()
            assert name.previous.previous.previous.output._cstring(cpu,self.prefix.source)==self.prefix.raw
            assert u(self.image+0x3D1558,1)==1 and u(context.outer.root_fixture.TLS+0x100,4)==2
            assert name.blob(raw(self.image+GUARD,8))==self.kmsv_model['guard_after_release']
            assert raw(self.image+MUTEX,40)==bytes(40) and raw(self.image+TEXT,10)==raw(self.kmsv_payload,10)==NAME+b'\0'
            self.kmsv_events.append('NULL lookup returned');assert self.kmsv_events==EVENTS
            self.kmsv_done=True;self.kmsv_boundary(cpu,state)

    def kmsv_boundary(self,cpu,state):
        cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,context.outer.oracle.STOP)

    def finish(self,result,state,proof):
        frozen=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(frozen)
        old=next(row for row in frozen['case_results'] if row['control']==self.control)
        prefix=proof['client_key_result_prefix']
        for key,field in [('instruction_observations','continuation_instruction_observations'),
            ('trace_sha256','continuation_trace_sha256'),('code_sha256','continuation_code_sha256')]:assert prefix[key]==old[field]
        assert self.result_done and self.kmsv_done and graph.digest(self.kmsv_prefix_allocations)==old['allocation_ledger_sha256']
        assert result['allocator_events'][:len(self.kmsv_prefix_allocations)]==self.kmsv_prefix_allocations
        assert result['allocator_events'][len(self.kmsv_prefix_allocations):]==[['alloc',10,self.kmsv_payload,'0x248388']]
        counts=dict(old['allocator_counts']);counts['malloc']+=1;assert result['actual_allocator_counts']==counts
        services=dict(old['service_counts']);services['syscall_226']+=2;assert result['explicit_service_counts']==services
        for key in ('JNI_calls','main_image_SVC_boundaries'):assert proof[key]==prefix[key]==old[key]
        assert prefix['libc_SVC_boundaries']==old['libc_SVC_boundaries']
        assert proof['libc_SVC_boundaries']==old['libc_SVC_boundaries']+providers()['additional_libc_SVCs']
        return dict(control=self.control,retained_result_prefix_verified=True,
            retained_prefix_instruction_observations=prefix['instruction_observations'],retained_prefix_trace_sha256=prefix['trace_sha256'],
            retained_prefix_code_sha256=prefix['code_sha256'],retained_prefix_allocation_sha256=graph.digest(self.kmsv_prefix_allocations),
            source_binding=source_binding(),native_events=self.kmsv_events,selected_projection=self.kmsv_model,
            protected_page_protection_sequence=self.kmsv_protections,registration_record_byte_offset=self.kmsv_registration_offset,
            registered_words_found_exactly_once=True,allocation_tail=[dict(kind='alloc',size=10,callsite='0x248388',pointer_is_payload=True)],
            allocation_ledger_sha256=graph.digest(result['allocator_events']),allocator_counts=counts,service_counts=services,
            JNI_calls=proof['JNI_calls'],libc_SVC_boundaries=proof['libc_SVC_boundaries'],main_image_SVC_boundaries=proof['main_image_SVC_boundaries'],
            handler_empty_state_request_tree_and_source_directory_unchanged=True,registry_guard_at_stop=1,errno_at_stop=2,
            continuation_instruction_observations=proof['instruction_observations'],continuation_trace_sha256=proof['trace_sha256'],
            continuation_code_sha256=proof['code_sha256'],observation_stop_before=hex(STOP),outer_bytecode=hex(LOOKUP_BC),
            callback_or_ordinary_RET_seen=False)


def replay(path,libc,*,on_case=None,case_controls=None):
    return context.replay(path,libc,on_case=on_case,case_controls=case_controls,_extension_factory=Scenario,
        _request_profile=name.previous.previous.PROFILE['name'],_handler_read_profile=context.NULL_PAYLOAD_READ_PROFILE['name'])


def verify_images(data,path,libc):
    from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
    previous.verify_images({},path,libc);_,_,read=graph.inputs.load_elf(path);decoder=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
    for a,m,s in EXPECTED:
        ins,=decoder.disasm(read(a,4),a);assert (ins.mnemonic,ins.op_str)==(m,s),hex(a)
    for a,w in WORDS:assert int.from_bytes(read(a,4),'little')==w,hex(a)
    pages={};name.put(pages,SOURCE,read(SOURCE,10));name.put(pages,MASK,read(MASK,10));name.put(pages,TEXT,bytes(10))
    assert name.objects.decode_masked_bytes(pages,source_address=SOURCE,mask_address=MASK,
        destination_address=TEXT,max_bytes=len(NAME))==len(NAME)
    assert name._read_span(pages,TEXT,10)==NAME+b'\0'
    return dict(instruction_bindings=len(EXPECTED),bytecode_words=len(WORDS),independent_ELF_masked_decode_verified=True,
        matching_Bionic_export_verified=libc is not None)


def validate(data):
    assert data['schema']=='vm9-native-171-kmsv-lookup-20261119-v1' and data['claims']==CLAIMS and data['providers']==providers()
    assert data['provenance']==previous.previous.previous.previous.previous.previous.previous.previous.provenance()
    assert data['instructions']==[dict(offset=hex(a),mnemonic=m,operands=s) for a,m,s in EXPECTED]
    assert data['bytecode_words']==[dict(offset=hex(a),word=hex(w)) for a,w in WORDS]
    assert data['independent_Python_projection']==model_projection()
    frozen=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(frozen)
    assert len(data['case_results'])==len(context.controls())
    for row,old in zip(data['case_results'],frozen['case_results']):
        assert row['control']==old['control'] and row['retained_result_prefix_verified'] is True
        for key,field in [('retained_prefix_instruction_observations','continuation_instruction_observations'),
            ('retained_prefix_trace_sha256','continuation_trace_sha256'),('retained_prefix_code_sha256','continuation_code_sha256'),
            ('retained_prefix_allocation_sha256','allocation_ledger_sha256')]:assert row[key]==old[field]
        assert row['source_binding']==source_binding() and row['native_events']==EVENTS
        assert row['selected_projection']==data['independent_Python_projection']
        assert row['protected_page_protection_sequence']==[3,1] and row['registered_words_found_exactly_once'] is True
        assert 0<=row['registration_record_byte_offset']<=4096-24
        assert row['allocation_tail']==[dict(kind='alloc',size=10,callsite='0x248388',pointer_is_payload=True)]
        counts=dict(old['allocator_counts']);counts['malloc']+=1;assert row['allocator_counts']==counts
        services=dict(old['service_counts']);services['syscall_226']+=2;assert row['service_counts']==services
        for key in ('JNI_calls','main_image_SVC_boundaries'):assert row[key]==old[key]
        assert row['libc_SVC_boundaries']==old['libc_SVC_boundaries']+providers()['additional_libc_SVCs']
        assert row['handler_empty_state_request_tree_and_source_directory_unchanged'] is True
        assert row['registry_guard_at_stop']==1 and row['errno_at_stop']==2 and row['callback_or_ordinary_RET_seen'] is False
        assert row['observation_stop_before']==hex(STOP) and row['outer_bytecode']==hex(LOOKUP_BC)
        assert row['continuation_instruction_observations']>old['continuation_instruction_observations']
        for key in ('allocation_ledger_sha256','continuation_trace_sha256','continuation_code_sha256'):assert graph.inputs.is_digest(row[key])


def negatives(data):
    rejected=0
    def reject(path,value):
        nonlocal rejected
        bad=deepcopy(data);target=bad
        for key in path[:-1]:target=target[key]
        target[path[-1]]=value
        try:validate(bad)
        except AssertionError:rejected+=1
        else:raise AssertionError('damaged KMSV evidence accepted: '+str(path))
    for key,value in CLAIMS.items():reject(('claims',key),not value)
    reject(('providers','maximum_handler_reads'),3);reject(('providers','maximum_main_SVCs'),5)
    reject(('instructions',0,'mnemonic'),'nop');reject(('bytecode_words',0,'word'),'0x0')
    for i in range(len(data['case_results'])):
        for path,value in [(('retained_result_prefix_verified',),False),(('retained_prefix_trace_sha256',),'0'*64),
            (('retained_prefix_allocation_sha256',),'0'*64),(('source_binding','source'),'0x0'),(('native_events',),[]),
            (('selected_projection','lookup_result_NULL'),False),(('selected_projection','name','hex'),'00'),
            (('protected_page_protection_sequence',),[1,3]),(('registered_words_found_exactly_once',),False),
            (('registration_record_byte_offset',),4096),(('allocation_tail',0,'size'),16),(('allocator_counts','malloc'),0),
            (('service_counts','syscall_226'),0),(('JNI_calls',),[]),(('main_image_SVC_boundaries',),[]),(('libc_SVC_boundaries',),[]),
            (('handler_empty_state_request_tree_and_source_directory_unchanged',),False),(('registry_guard_at_stop',),0),
            (('errno_at_stop',),17),(('callback_or_ordinary_RET_seen',),True),(('observation_stop_before',),'0x0'),
            (('outer_bytecode',),'0xfd258'),(('continuation_instruction_observations',),0)]:reject(('case_results',i)+path,value)
    return rejected


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--elf',type=Path);ap.add_argument('--libc',type=Path);ap.add_argument('--replay',action='store_true')
    args=ap.parse_args()
    if args.replay and (not args.elf or not args.libc):ap.error('--replay requires --elf and --libc')
    data=json.loads(EVIDENCE.read_text(encoding='utf-8'));validate(data)
    result=dict(retained_KMSV_lookup_cases=len(data['case_results']),damaged_evidence_rejected=negatives(data),
        KMSV_value_generated=False,ordinary_Cronet_six_headers_verified=False,complete_standalone_signer_verified=False)
    if args.elf:result['image_bindings']=verify_images(data,args.elf,args.libc)
    elif args.libc:graph.inputs.libc_image(args.libc)
    if args.replay:
        assert replay(args.elf,args.libc)==data['case_results'],'frozen KMSV lookup replay differs'
        result['original_code_cases_replayed']=len(data['case_results'])
    print(json.dumps(result))


if __name__=='__main__':main()
