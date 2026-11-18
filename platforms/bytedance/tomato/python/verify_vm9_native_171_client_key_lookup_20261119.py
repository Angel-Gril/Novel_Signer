"""Original destructor registration, static publication and missing name lookup.

Continue the accepted name constructor on the same CPU. Keep the two-handler-
read/four-main-SVC contract. Independent Python owners use fresh declared
pages and the one synthetic test header. This does not generate a key value.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path

from unicorn import arm64_const as arm
import verify_vm9_native_171_client_key_name_20261119 as previous
import vm9_callbacks as callbacks
import vm9_registry as registry
import vm9_startup as startup

context=previous.context
graph=previous.graph
EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_client_key_lookup_20261119.json')
ATE_BC,RELEASE_BC,LOOKUP_BC=0xFD100,0xFD11C,0xFD140
KEY,VALUE=b'X-TEST',b'value'
LIBC_EXPORT=0x75254
EXPECTED=[
    (0x285B84,'ldp','x8, x0, [x0]'),(0x285B88,'ldp','x1, x2, [x19, #0x10]'),
    (0x285B8C,'blr','x8'),(0x285B90,'str','w0, [x19, #0x20]'),
    (0x28596C,'ldp','x1, x8, [x0]'),(0x285970,'mov','x0, x8'),(0x285974,'br','x1'),
    (0x32D514,'stlrb','w21, [x0]'),(0x32D528,'ldrb','w20, [x19, #1]'),
    (0x32D52C,'strb','w21, [x19, #1]'),
    (0x285BB8,'ldp','x8, x0, [x0]'),(0x285BBC,'ldr','x1, [x19, #0x10]'),
    (0x285BC0,'blr','x8'),(0x285BC4,'str','x0, [x19, #0x18]'),
    (0x25C170,'add','x0, x0, #0x20'),(0x25C174,'bl','#0x24b960'),
]
CLAIMS=dict(
    retained_name_trace_and_allocation_prefix_verified=True,
    matching_Bionic_destructor_registration_and_u32_result_executed=True,
    registered_destructor_object_and_DSO_found_in_protected_native_page=True,
    static_guard_release_and_name_publication_executed=True,
    original_name_keyed_configuration_lookup_returned_NULL=True,
    selected_registration_guard_and_lookup_match_fresh_Python_owners=True,
    native_memory_used_as_model_input=False,new_OS_JNI_or_internal_helper_providers=False,
    full_VM_or_Bionic_state_equivalence_verified=False,header_value_generated=False,
    real_business_cache_restored=False,real_JVM_identity_verified=False,
    ordinary_Cronet_six_headers_verified=False,whole_request_equivalence_verified=False,
    callback_or_ordinary_wrapper_returned=False,complete_standalone_signer_verified=False,
    Android_execution=False,online_acceptance_verified=False,
)


def tree_projection(read,image,container):
    def u(a,n=8):return int.from_bytes(read(a,n),'little')
    controller=u(container+32);sentinel=u(controller);node=u(sentinel+8)
    assert u(controller+8)==1 and node
    assert (u(sentinel+16),u(sentinel+24))==(node,node)
    assert u(node,4)==1 and (u(node+8),u(node+16),u(node+24))==(sentinel,0,0)
    pair=u(node+32);key=u(pair);value=u(pair+8)
    def string(obj):
        assert u(obj)==image+0x34F5F8
        length=u(obj+12,4);assert length<256
        return read(u(obj+16),length+1)
    assert string(key)==KEY+b'\0' and string(value)==VALUE+b'\0'
    return dict(container_vtable=hex(u(container)-image),
        cleanup_offsets=[hex(u(container+i)-image) for i in (8,16)],
        comparator_offset=hex(u(container+24)-image),
        controller_comparator_offset=hex(u(controller+16)-image),
        controller_hook_offset=hex(u(controller+24)-image),node_count=1,
        singleton_sentinel_links_verified=True,node_color=1,node_parent_is_sentinel=True,
        child_pointers_NULL=True,key=previous.blob(KEY),value=previous.blob(VALUE))


def model_projection():
    image=0x10000000;root=0x60000000
    p={page:bytearray(4096) for page in range(root>>12,(root+0x4000)>>12)};next_pointer=root+0x1000
    def put(a,raw):previous.put(p,a,raw)
    def w(a,v,n=8):put(a,int(v).to_bytes(n,'little'))
    def allocate(pages,size):
        nonlocal next_pointer
        pointer=next_pointer;next_pointer+=0x100;previous.put(pages,pointer,bytes(size));return pointer
    def unexpected(*args):raise AssertionError('unexpected independent model provider')
    def string(obj,text):
        put(obj,bytes(24));source=obj+0x40;put(source,text+b'\0')
        previous.objects.construct_string_object(p,object_address=obj,source_address=source,
            allocate=allocate,vtable_address=image+0x34F5F8)
    descriptor=root+0x80;container=root+0x100;key=root+0x200;value=root+0x300;query=root+0x400
    put(container,bytes(40))
    for i,offset in enumerate((0x182D6C,0x182D6C,0x188A94)):w(descriptor+8*i,image+offset)
    registry.construct_configuration_tree(p,container_address=container,descriptor_address=descriptor,
        image_base=image,allocate=allocate)
    for obj,text in ((key,KEY),(value,VALUE),(query,previous.NAME)):string(obj,text)
    registry.insert_configuration_pair(p,container_address=container,key_address=key,value_address=value,
        image_base=image,allocate=allocate,free=unexpected)
    tree=tree_projection(lambda a,n:previous._read_span(p,a,n),image,container)
    before={page:bytes(raw) for page,raw in p.items()}
    result=registry.lookup_configuration_value(p,container_address=container,key_address=query,image_base=image)
    assert result==0 and before=={page:bytes(raw) for page,raw in p.items()}
    guard=root+0x500;put(guard,bytes.fromhex('0002000089000000'));put(image+previous.MUTEX,bytes(40))
    startup.release_serial_guard(p,guard_address=guard,image_base=image)
    registrations=[]
    def register(pages,destructor,obj,dso):
        registrations.append([hex(destructor-image),hex(obj-image),hex(dso-image)]);return 0
    status=callbacks.register_process_destructor(p,destructor_address=image+0x2484B8,
        object_address=image+previous.OBJECT,dso_address=image+0x34C700,register_exit=register)
    return dict(tree=tree,query=previous.blob(previous.NAME),lookup_result_NULL=result==0,
        model_lookup_pages_unchanged=True,guard_after=previous.blob(previous._read_span(p,guard,8)),
        global_mutex_after=previous.blob(previous._read_span(p,image+previous.MUTEX,40)),
        registration_arguments=registrations,registration_status_u32=status)


def providers():
    return dict(inherited_name=previous.providers(),maximum_handler_reads=2,maximum_main_SVCs=4,
        independent_model_owners=['vm9_callbacks.py:register_process_destructor',
            'vm9_startup.py:release_serial_guard','vm9_registry.py:lookup_configuration_value'],
        independent_model_input='fresh pages, declared initialized guard and one synthetic X-TEST/value tree',
        actual_destructor_target='matching Bionic .dynsym __cxa_atexit, not a main-image PLT alias',
        additional_libc_SVCs=[dict(libc_pc='0x6a550',number=226)]*2,
        service_count_deltas=dict(syscall_226=2),new_OS_JNI_or_internal_helper_providers=[],
        stop_before=hex(previous.STOP),outer_bytecode=hex(LOOKUP_BC))


class Scenario(previous.Scenario):
    def __init__(self,control):
        super().__init__(control);self.next_part=False;self.lookup_flow=[];self.protections=[];self.lookup_return=None

    def name_boundary(self,cpu,state):
        assert not self.next_part and self.finished
        self.next_part=True;self.name_allocations=deepcopy(state['allocator_events_ref'])

    def observe(self,cpu,pc,state):
        if not self.next_part:
            super().observe(cpu,pc,state)
            if not self.next_part:return
        off=pc-self.image
        def reg(n):return cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(n)))
        def raw(a,n):return bytes(cpu.mem_read(a,n))
        def u(a,n=8):return int.from_bytes(raw(a,n),'little')
        bc=u(state['PC_slot'])-self.image
        if off in (0x27E6AC,0x27ED6C):raise AssertionError('unexpected callback or ordinary RET')
        if pc==graph.inputs.LIBC_BASE+0x6A550 and bc==ATE_BC:
            assert reg(8)==226 and reg(1)==4096 and reg(0)&4095==0
            expected=(3,1)[len(self.protections)];assert reg(2)==expected
            page=reg(0);needle=b''.join((self.image+i).to_bytes(8,'little') for i in (0x2484B8,previous.OBJECT,0x34C700))
            data=raw(page,4096)
            if not self.protections:
                assert needle not in data;self.registration_page=page
            else:
                assert page==self.registration_page and data.count(needle)==1
                self.registration_record_offset=data.index(needle)
            self.protections.append(expected)
        if off==0x285B7C and bc==ATE_BC:
            packed=reg(0);self.atexit_packed=packed;self.atexit_before=raw(packed,40)
            assert tuple(u(packed+i*8) for i in range(4))==(graph.inputs.LIBC_BASE+LIBC_EXPORT,
                self.image+0x2484B8,self.image+previous.OBJECT,self.image+0x34C700)
            self.lookup_flow.append('matching Bionic registration entry')
        if off==0x28596C and bc==RELEASE_BC:
            packed=reg(0);assert (u(packed),u(packed+8))==(self.image+0x32D4F8,self.image+previous.GUARD)
            after=raw(self.atexit_packed,40)
            assert u(self.atexit_packed+32,4)==0 and self.protections==[3,1]
            assert self.atexit_before[:32]+self.atexit_before[36:]==after[:32]+after[36:]
            assert raw(self.image+previous.GUARD,8)==bytes.fromhex('0002000089000000')
            self.lookup_flow.append('registration u32 zero and other packed bytes preserved')
        if off==0x285BB0 and bc==LOOKUP_BC:
            packed=reg(0);assert (u(packed),u(packed+16))==(self.image+0x25C168,self.image+previous.OBJECT)
            assert raw(self.image+previous.GUARD,8)==bytes.fromhex('0101000089000000')
            assert raw(self.image+previous.MUTEX,40)==bytes(40)
            self.container=u(packed+8);self.tree=tree_projection(raw,self.image,self.container)
            assert self.tree==model_projection()['tree']
            self.lookup_packed=packed;self.lookup_before=raw(packed,32);self.lookup_return=reg(30)
            assert self.lookup_return==self.image+previous.STOP
            self.lookup_flow.append('guard published and synthetic request tree bound')
        if self.lookup_return is not None and pc==self.lookup_return:
            assert bc==LOOKUP_BC and self.lookup_flow==[
                'matching Bionic registration entry','registration u32 zero and other packed bytes preserved',
                'guard published and synthetic request tree bound']
            assert reg(0)==0 and u(self.lookup_packed+24)==0
            assert raw(self.lookup_packed,24)==self.lookup_before[:24]
            assert tree_projection(raw,self.image,self.container)==self.tree
            assert raw(state['context'],128)==state['handler_bytes']
            assert u(self.state_owner+0x18)==self.node and raw(self.node,64)==previous.previous.previous.empty_bytes()
            assert previous.previous.previous.previous.output._cstring(cpu,self.prefix.source)==self.prefix.raw
            assert u(self.image+0x3D1558,1)==1 and u(context.outer.root_fixture.TLS+0x100,4)==2
            self.lookup_flow.append('NULL lookup returned and other packed bytes preserved');self.lookup_done=True
            self.lookup_boundary(cpu,state)

    def lookup_boundary(self,cpu,state):
        cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,context.outer.oracle.STOP)

    def finish(self,result,state,proof):
        assert self.lookup_done and self.finished and self.protections==[3,1]
        old_data=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(old_data)
        old=next(row for row in old_data['case_results'] if row['control']==self.control)
        prefix=proof['client_key_name_prefix']
        for key,old_key in (('instruction_observations','continuation_instruction_observations'),
            ('trace_sha256','continuation_trace_sha256'),('code_sha256','continuation_code_sha256')):assert prefix[key]==old[old_key]
        assert graph.digest(self.name_allocations)==old['allocation_ledger_sha256']
        assert result['allocator_events']==self.name_allocations and result['actual_allocator_counts']==old['allocator_counts']
        services=dict(old['service_counts']);services['syscall_226']+=2;assert result['explicit_service_counts']==services
        for key in ('JNI_calls','main_image_SVC_boundaries'):assert proof[key]==prefix[key]==old[key]
        assert prefix['libc_SVC_boundaries']==old['libc_SVC_boundaries']
        assert proof['libc_SVC_boundaries']==old['libc_SVC_boundaries']+providers()['additional_libc_SVCs']
        return dict(control=self.control,retained_name_trace_and_allocation_prefix_verified=True,
            retained_prefix_instruction_observations=prefix['instruction_observations'],
            retained_prefix_trace_sha256=prefix['trace_sha256'],retained_prefix_code_sha256=prefix['code_sha256'],
            selected_projection=model_projection(),native_flow=self.lookup_flow,
            protected_page_protection_sequence=self.protections,registered_words_found_exactly_once=True,
            registration_record_byte_offset=self.registration_record_offset,
            allocation_ledger_sha256=graph.digest(result['allocator_events']),allocator_counts=result['actual_allocator_counts'],
            service_counts=result['explicit_service_counts'],JNI_calls=proof['JNI_calls'],
            libc_SVC_boundaries=proof['libc_SVC_boundaries'],main_image_SVC_boundaries=proof['main_image_SVC_boundaries'],
            handler_and_empty_state_and_source_directory_unchanged=True,registry_guard_at_stop=1,errno_at_stop=2,
            continuation_instruction_observations=proof['instruction_observations'],
            continuation_trace_sha256=proof['trace_sha256'],continuation_code_sha256=proof['code_sha256'],
            observation_stop_before=hex(previous.STOP),outer_bytecode=hex(LOOKUP_BC),callback_or_ordinary_RET_seen=False)


def replay(path,libc,*,on_case=None,case_controls=None):
    return context.replay(path,libc,on_case=on_case,case_controls=case_controls,_extension_factory=Scenario,
        _request_profile=previous.previous.previous.PROFILE['name'],_handler_read_profile=context.NULL_PAYLOAD_READ_PROFILE['name'])


def verify_images(data,path,libc):
    from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
    upstream=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(upstream)
    previous.verify_elf(upstream,path);_,_,read=graph.inputs.load_elf(path);decoder=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
    for a,m,s in EXPECTED:
        ins,=decoder.disasm(read(a,4),a);assert (ins.mnemonic,ins.op_str)==(m,s),hex(a)
    if libc is not None:
        elf,_=graph.inputs.libc_image(libc)
        matches=[s for s in elf.get_section_by_name('.dynsym').iter_symbols() if s.name=='__cxa_atexit']
        assert len(matches)==1 and matches[0]['st_value']==LIBC_EXPORT and matches[0]['st_info']['type']=='STT_FUNC'
    return dict(additional_instruction_bindings=len(EXPECTED),matching_Bionic_export_verified=libc is not None)


def validate(data):
    assert data['schema']=='vm9-native-171-client-key-lookup-20261119-v1'
    assert data['claims']==CLAIMS and data['providers']==providers()
    assert data['provenance']==previous.previous.previous.previous.previous.previous.provenance()
    assert data['instructions']==[dict(offset=hex(a),mnemonic=m,operands=s) for a,m,s in EXPECTED]
    assert data['independent_Python_projection']==model_projection()
    frozen=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(frozen)
    assert len(data['case_results'])==len(context.controls())
    for row,old in zip(data['case_results'],frozen['case_results']):
        assert row['control']==old['control'] and row['retained_name_trace_and_allocation_prefix_verified'] is True
        for key,old_key in (('retained_prefix_instruction_observations','continuation_instruction_observations'),
            ('retained_prefix_trace_sha256','continuation_trace_sha256'),('retained_prefix_code_sha256','continuation_code_sha256')):assert row[key]==old[old_key]
        assert row['selected_projection']==model_projection()
        assert row['native_flow']==['matching Bionic registration entry',
            'registration u32 zero and other packed bytes preserved','guard published and synthetic request tree bound',
            'NULL lookup returned and other packed bytes preserved']
        assert row['protected_page_protection_sequence']==[3,1] and row['registered_words_found_exactly_once'] is True
        assert type(row['registration_record_byte_offset']) is int and 0<=row['registration_record_byte_offset']<=4096-24
        for key in ('allocation_ledger_sha256','allocator_counts','JNI_calls','main_image_SVC_boundaries'):assert row[key]==old[key]
        services=dict(old['service_counts']);services['syscall_226']+=2;assert row['service_counts']==services
        assert row['libc_SVC_boundaries']==old['libc_SVC_boundaries']+providers()['additional_libc_SVCs']
        assert row['handler_and_empty_state_and_source_directory_unchanged'] is True
        assert row['registry_guard_at_stop']==1 and row['errno_at_stop']==2
        assert row['observation_stop_before']==hex(previous.STOP) and row['outer_bytecode']==hex(LOOKUP_BC)
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
        else:raise AssertionError('damaged lookup evidence accepted: '+str(path))
    for key,value in CLAIMS.items():reject(('claims',key),not value)
    reject(('providers','maximum_handler_reads'),3);reject(('providers','maximum_main_SVCs'),5)
    reject(('instructions',0,'mnemonic'),'nop')
    for i in range(len(data['case_results'])):
        for path,value in ((('retained_prefix_trace_sha256',),'0'*64),(('selected_projection','lookup_result_NULL'),False),
            (('selected_projection','tree','node_count'),0),(('protected_page_protection_sequence',),[3,3]),
            (('registered_words_found_exactly_once',),False),(('registration_record_byte_offset',),4096),
            (('native_flow',),[]),(('allocation_ledger_sha256',),'0'*64),(('allocator_counts','malloc'),0),
            (('service_counts','syscall_226'),0),(('JNI_calls',),[]),(('main_image_SVC_boundaries',),[]),
            (('libc_SVC_boundaries',),[]),(('handler_and_empty_state_and_source_directory_unchanged',),False),
            (('registry_guard_at_stop',),0),(('errno_at_stop',),17),(('observation_stop_before',),'0x0'),
            (('outer_bytecode',),'0xfd100'),(('callback_or_ordinary_RET_seen',),True),
            (('continuation_instruction_observations',),0)):
            reject(('case_results',i)+path,value)
    return rejected


def build(path,libc,*,on_case=None):
    data=dict(schema='vm9-native-171-client-key-lookup-20261119-v1',claims=CLAIMS,providers=providers(),
        provenance=previous.previous.previous.previous.previous.previous.provenance(),
        independent_Python_projection=model_projection(),
        instructions=[dict(offset=hex(a),mnemonic=m,operands=s) for a,m,s in EXPECTED],case_results=[])
    verify_images(data,path,libc);data['case_results']=replay(path,libc,on_case=on_case);validate(data);return data


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--elf',type=Path);ap.add_argument('--libc',type=Path);ap.add_argument('--replay',action='store_true')
    args=ap.parse_args()
    if args.replay and (not args.elf or not args.libc):ap.error('--replay requires --elf and --libc')
    data=json.loads(EVIDENCE.read_text(encoding='utf-8'));validate(data)
    result=dict(retained_lookup_cases=len(data['case_results']),damaged_evidence_rejected=negatives(data),
        header_value_generated=False,ordinary_Cronet_six_headers_verified=False,complete_standalone_signer_verified=False)
    if args.elf:result['image_bindings']=verify_images(data,args.elf,args.libc)
    elif args.libc:graph.inputs.libc_image(args.libc)
    if args.replay:
        assert replay(args.elf,args.libc)==data['case_results'],'frozen client-key lookup replay differs'
        result['original_code_cases_replayed']=len(data['case_results'])
    print(json.dumps(result))


if __name__=='__main__':main()
