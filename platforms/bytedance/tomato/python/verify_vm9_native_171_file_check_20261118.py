"""Original absent-file result, packed false and empty-state initialization.

An explicit four-call profile adds only the generated cache file's faccessat.
Inherited providers still report ENOENT. Existing Python callbacks run on
independent pages. Stop before the next handler read, without signing claims.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

from unicorn import arm64_const as arm
import verify_vm9_native_171_cache_path_20261118 as previous
import vm9_configuration_init as configuration
import vm9_state as model

context=previous.context
graph=previous.graph
PROFILE=context.AID_FILE_PROFILE
EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_file_check_20261118.json')
STOP=0x16F96C
CURSOR=0xFCD04
EXPECTED=[
    (0x26A56C,'stp','x30, x19, [sp, #-0x10]!'), (0x26A578,'blr','x8'),
    (0x26A57C,'and','w8, w0, #1'), (0x26A580,'strb','w8, [x19, #0x10]'),
    (0x26A584,'ldp','x30, x19, [sp], #0x10'), (0x26A588,'ret',''),
    (0x26A628,'stp','x30, x19, [sp, #-0x10]!'), (0x26A634,'blr','x8'),
    (0x26A638,'str','x0, [x19, #8]'), (0x26A63C,'ldp','x30, x19, [sp], #0x10'),
    (0x24A4E8,'bl','#0x2493e8'), (0x24A4F0,'mov','w8, #0x40'),
    (0x24A4F4,'str','w8, [x0, #0x18]'), (0x2493F4,'mov','w0, #0x40'),
    (0x249404,'stp','q0, q0, [x0, #0x20]'), (0x249408,'stp','q0, q0, [x0]'),
    (0x26A498,'mov','x0, x20'), (STOP,'ldr','x9, [x12, x13]'),
]
FLOW=[dict(native_pc=hex(pc),x0_u64=x0,errno=errno) for pc,x0,errno in (
    (0x271DC0,(1<<64)-2,17),(0x271D84,(1<<64)-1,17),
    (0x271D88,(1<<64)-1,2),(0x27308C,(1<<64)-1,2),
    (0x25DE08,(1<<64)-1,2),(0x25DE0C,(1<<64)-1,2),
    (0x25DE10,0,2),(0x25DE1C,0,2),(0x26A57C,0,2),(0x26A580,0,2),(0x26A584,0,2))]
LIBC_TAIL=[dict(libc_pc=pc,number=number) for pc,number in (
    ('0x1bf1c',98),('0x1bf1c',98),('0x6a550',226),('0x6a550',226))]
SERVICE_DELTAS=dict(syscall_48=1,syscall_98=2,syscall_226=2,clock=1)
CLAIMS=dict(
    inherited_default_cache_path_selected_prefix_verified=True,
    fourth_main_faccessat_exactly_bound_to_generated_cache_path=True,
    original_ENOENT_errno_and_false_result_verified=True,
    original_packed_boolean_store_verified=True,
    original_empty_container_construction_publication_and_state_helper_return_verified=True,
    selected_projections_match_existing_Python_callbacks_on_independent_pages=True,
    next_handler_member_0x8_read_not_executed=True,
    new_OS_JNI_or_internal_helper_providers=False,native_memory_used_as_model_input=False,
    full_state_VM_or_physical_stack_equivalence_verified=False,
    real_filesystem_or_business_cache_restored=False,real_JVM_identity_verified=False,
    ordinary_Cronet_six_headers_verified=False,whole_request_equivalence_verified=False,
    callback_or_ordinary_wrapper_returned=False,complete_standalone_signer_verified=False,
    Android_execution=False,online_acceptance_verified=False,
)


def empty_bytes():return bytes(24)+(64).to_bytes(4,'little')+bytes(36)


def binding():
    return dict(native_pc='0x271dbc',bytecode='0xfca40',number=48,dirfd_u32=0xFFFFFF9C,
        flags=0,pathname_length=len(PROFILE['pathname']),pathname_sha256=previous.digest(PROFILE['pathname']),
        mode=4,return_pc='0x27308c')


def providers():
    return dict(inherited_cache_path=previous.providers(),request_profile=PROFILE['name'],
        ordered_main_image_SVCs=[*previous.previous.bindings(),binding()],maximum_main_SVCs=4,
        additional_syscall_owner='verify_vm9_outer_signer_native.py:case.syscall',kernel_result=-2,
        independent_model_owner='vm9_state.py:StateCallbacks',
        independent_model_input='fresh pages, declared file path, declared synthetic packed arguments',
        additional_inherited_libc_SVCs=LIBC_TAIL,service_count_deltas=SERVICE_DELTAS,
        new_OS_JNI_or_internal_helper_providers=[],stop_before=hex(STOP),outer_bytecode=hex(CURSOR))


def model_projection():
    image=0x10000000;obj=0x60000000;source=obj+0x100;errno=obj+0x200;packed=obj+0x300;node=obj+0x500
    pages={obj>>12:bytearray(4096),(image+0x381AA0)>>12:bytearray(4096)}
    def w(a,v,n=8):configuration._w(pages,a,v,n)
    raw=PROFILE['pathname'];w(obj+12,len(raw),4);w(obj+16,source)
    configuration._write_span(pages,source,raw+b'\0');w(errno,17,4)
    configuration._write_span(pages,packed,b'\xa5'*32);w(packed,image+0x25DDEC);w(packed+8,obj)
    before=configuration._read_span(pages,packed,32);events=[];allocations=[]
    def syscall(p,number,args):
        assert number==48 and args==(0xFFFFFF9C,source,4,0)
        path=configuration.objects._cstring(p,args[1],257)[:-1]
        events.append(dict(number=number,dirfd_u32=args[0],path=previous.blob(path),mode=args[2],flags=args[3],kernel_result=-2))
        return -2
    def unsupported(*args,**kwargs):raise AssertionError('unexpected independent-model provider')
    def allocate(p,size):
        assert size==64 and allocations==[];allocations.append(size);return node
    class Memory:
        def __init__(self):self.pages=pages
        def u64(self,a):return configuration._u(pages,a)
        def wb(self,a,v):w(a,v,1)
        def w64(self,a,v):w(a,v)
    callbacks=model.StateCallbacks(image_base=image,native_stack_address=obj+0x1000,
        allocate=allocate,reallocate=unsupported,free=unsupported,get_tls=unsupported,
        initialize_registry=unsupported,broadcast=unsupported,read_property=unsupported,
        syscall=syscall,errno_address=errno,mkdir=unsupported,register_destructor=unsupported)
    vm=SimpleNamespace(m=Memory());callbacks(vm,image+0x26A56C,packed)
    after=configuration._read_span(pages,packed,32)
    result=dict(provider_events=events,errno=configuration._u(pages,errno,4),result_byte=after[16],
        packed_bytes_outside_result_preserved=before[:16]+before[17:]==after[:16]+after[17:])
    w(image+0x381AA0,image+0x347FD0);w(packed,image+0x24A4D8)
    callbacks(vm,image+0x26A628,packed)
    payload=configuration._read_span(pages,node,64);assert configuration._u(pages,packed+8)==node
    assert payload==empty_bytes()
    result.update(empty_container=previous.blob(payload),empty_container_type=64,
        empty_container_allocations=allocations,callback_targets=callbacks.modeled)
    return result


class Scenario:
    def __init__(self,control):
        self.control=control;self.image=control['base'];self.prefix=previous.Scenario(control)
        self.resumed=False;self.flow=[];self.state_events=[];self.file_seen=False;self.stopped=False

    def native_runner(self,*args,**kwargs):return self.prefix.native_runner(*args,**kwargs)
    def member_boundary(self,*args,**kwargs):return self.prefix.member_boundary(*args,**kwargs)

    def observe(self,cpu,pc,state):
        off=pc-self.image
        def reg(n):return cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(n)))
        def u(a,n=8):return int.from_bytes(cpu.mem_read(a,n),'little')
        def raw(a,n):return bytes(cpu.mem_read(a,n))
        def string(a):return previous.output._cstring(cpu,a)
        if off in (0x27E6AC,0x27ED6C):raise AssertionError('unexpected callback or ordinary RET')
        if off==0x269988:
            assert not hasattr(self,'state_owner');self.state_owner=reg(0)
            assert u(self.state_owner+0x18)==0
        if off==0x26A56C and self.prefix.resumed:
            self.packed=reg(0);self.before=raw(self.packed,32)
            assert u(self.packed)==self.image+0x25DDEC and u(self.packed+8)==self.prefix.file_object
        if not self.resumed:
            if off!=previous.STOP or not self.prefix.file_entry:
                self.prefix.observe(cpu,pc,state)
                return
            p=self.prefix
            assert p.file_entry and p.sha_pending is p.format_pending is None
            assert reg(0)==p.file_data and previous.blob(string(reg(0)))==previous.projection()['cache_path'] and reg(1)==4
            assert u(context.outer.root_fixture.TLS+0x100,4)==17 and string(p.source)==p.raw
            p.cache_events.append(dict(native_pc=hex(off),path=previous.blob(string(reg(0))),mode=4,errno=17,
                input_is_formatted_CString=True))
            self.cache_prefix=dict(identity_events=p.identity_events,SHA1_events=p.sha_events,cache_events=p.cache_events,
                independent_formula_projection=previous.projection())
            self.resumed=True
        if off==0x271DBC:
            assert not self.file_seen and reg(8)==48 and string(reg(1))==PROFILE['pathname']
            self.file_seen=True
        if off in {int(row['native_pc'],16) for row in FLOW}:
            row=dict(native_pc=hex(off),x0_u64=reg(0),errno=u(context.outer.root_fixture.TLS+0x100,4))
            assert row==FLOW[len(self.flow)];self.flow.append(row)
        if off==0x26A580:assert reg(8)==0 and reg(19)==self.packed
        if off==0x26A584:
            after=raw(self.packed,32)
            assert after[16]==0 and self.before[:16]+self.before[17:]==after[:16]+after[17:]
            self.packed_preserved=True
        if off==0x26A628:
            assert self.flow==FLOW and not hasattr(self,'empty_packed')
            self.empty_packed=reg(0);assert u(self.empty_packed)==self.image+0x24A4D8
        if off==0x24A4D8:
            assert reg(30)==self.image+0x26A638
            self.state_events.append(dict(native_pc=hex(off),return_pc='0x26a638'))
        if off==0x26A638:
            self.node=reg(0);assert self.node and reg(19)==self.empty_packed
            assert raw(self.node,64)==empty_bytes()
            self.state_events.append(dict(native_pc=hex(off),empty_container=previous.blob(raw(self.node,64))))
        if off==0x26A63C:
            assert u(self.empty_packed+8)==self.node
            self.state_events.append(dict(native_pc=hex(off),packed_result_is_empty_container=True))
        if off==0x26A498:
            assert u(self.state_owner+0x18)==self.node
            self.state_events.append(dict(native_pc=hex(off),state_owner_root_is_empty_container=True))
        if off==STOP and reg(12)==state['context']:
            assert u(state['PC_slot'])==self.image+CURSOR and reg(13)==8 and reg(14)==2
            assert self.flow==FLOW and self.file_seen and self.packed_preserved and len(self.state_events)==4
            assert u(context.outer.root_fixture.TLS+0x100,4)==2
            assert u(self.image+0x3D1558,1)==1 and raw(state['context'],0x80)==state['handler_bytes']
            assert string(self.prefix.source)==self.prefix.raw and raw(self.node,64)==empty_bytes()
            assert u(self.state_owner+0x18)==self.node
            self.next_read=dict(native_pc=hex(off),bytecode=hex(CURSOR),member_offset='0x8',
                virtual_register=2,base_is_constructed_handler=True,load_executed=False)
            self.stopped=True;cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,context.outer.oracle.STOP)

    def finish(self,result,state,proof):
        assert self.stopped and proof['main_image_SVC_boundaries']==providers()['ordered_main_image_SVCs']
        frozen=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(frozen)
        old=next(row for row in frozen['case_results'] if row['control']==self.control)
        assert self.cache_prefix=={key:old[key] for key in self.cache_prefix}
        assert proof['JNI_calls']==old['JNI_calls']
        assert proof['libc_SVC_boundaries']==old['libc_SVC_boundaries']+LIBC_TAIL
        return dict(control=self.control,selected_cache_path_prefix=self.cache_prefix,native_flow=self.flow,
            packed_result_byte=0,packed_bytes_outside_result_preserved=True,state_events=self.state_events,
            independent_Python_projection=model_projection(),next_handler_read=self.next_read,
            state_root_is_original_empty_container=True,empty_container_payload=previous.blob(empty_bytes()),
            context_handler_bytes_unchanged=True,registry_guard_at_stop=1,source_directory_string_unchanged=True,
            main_image_SVC_boundaries=proof['main_image_SVC_boundaries'],JNI_calls=proof['JNI_calls'],
            libc_SVC_boundaries=proof['libc_SVC_boundaries'],original_outer_postconditions_passed=True,
            observation_stop_before=hex(STOP),callback_or_ordinary_RET_seen=False,
            service_counts=result['explicit_service_counts'],allocator_counts=result['actual_allocator_counts'],
            continuation_instruction_observations=proof['instruction_observations'],
            continuation_trace_sha256=proof['trace_sha256'],continuation_code_sha256=proof['code_sha256'],
            allocation_ledger_sha256=graph.digest(result['allocator_events']))


def replay(path,libc,*,on_case=None,case_controls=None):
    return context.replay(path,libc,on_case=on_case,case_controls=case_controls,
        _extension_factory=Scenario,_request_profile=PROFILE['name'])


def verify_elf(data,path):
    from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
    frozen=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(frozen)
    upstream=previous.verify_elf(frozen,path)
    _,_,read=graph.inputs.load_elf(path);decoder=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
    for a,m,s in EXPECTED:
        ins,=decoder.disasm(read(a,4),a);assert (ins.mnemonic,ins.op_str)==(m,s),hex(a)
    assert int.from_bytes(read(CURSOR,4),'little')==0x10400218
    return dict(upstream=upstream,additional_instructions=len(EXPECTED),additional_bytecode_words=1)


def validate(data):
    assert data['schema']=='vm9-native-171-file-check-20261118-v1'
    assert data['provenance']==previous.previous.previous.provenance()
    assert data['claims']==CLAIMS and data['providers']==providers()
    assert data['instructions']==[dict(offset=hex(a),mnemonic=m,operands=s) for a,m,s in EXPECTED]
    projection=model_projection();assert data['independent_Python_projection']==projection
    assert projection['result_byte']==0 and projection['errno']==2 and projection['packed_bytes_outside_result_preserved']
    frozen=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(frozen)
    assert len(data['case_results'])==len(context.controls())
    for row,old in zip(data['case_results'],frozen['case_results']):
        assert row['control']==old['control'] and row['native_flow']==FLOW
        assert row['selected_cache_path_prefix']=={key:old[key] for key in (
            'identity_events','SHA1_events','cache_events','independent_formula_projection')}
        assert row['independent_Python_projection']==projection
        assert row['state_events']==[
            dict(native_pc='0x24a4d8',return_pc='0x26a638'),
            dict(native_pc='0x26a638',empty_container=projection['empty_container']),
            dict(native_pc='0x26a63c',packed_result_is_empty_container=True),
            dict(native_pc='0x26a498',state_owner_root_is_empty_container=True)]
        assert row['next_handler_read']==dict(native_pc=hex(STOP),bytecode=hex(CURSOR),member_offset='0x8',
            virtual_register=2,base_is_constructed_handler=True,load_executed=False)
        assert row['packed_result_byte']==0 and row['empty_container_payload']==projection['empty_container']
        for key in ('packed_bytes_outside_result_preserved','state_root_is_original_empty_container',
            'context_handler_bytes_unchanged','source_directory_string_unchanged','original_outer_postconditions_passed'):
            assert row[key] is True
        assert row['registry_guard_at_stop']==1 and row['callback_or_ordinary_RET_seen'] is False
        assert row['observation_stop_before']==hex(STOP)
        assert row['main_image_SVC_boundaries']==providers()['ordered_main_image_SVCs']
        assert row['JNI_calls']==old['JNI_calls'] and row['libc_SVC_boundaries']==old['libc_SVC_boundaries']+LIBC_TAIL
        counts=dict(old['service_counts'])
        for key,value in SERVICE_DELTAS.items():counts[key]+=value
        assert row['service_counts']==counts
        assert old['continuation_instruction_observations']<row['continuation_instruction_observations']<400000
        for key in ('continuation_trace_sha256','continuation_code_sha256','allocation_ledger_sha256'):
            assert graph.inputs.is_digest(row[key])


def build(path,libc,*,on_case=None):
    data=dict(schema='vm9-native-171-file-check-20261118-v1',provenance=previous.previous.previous.provenance(),
        claims=CLAIMS,providers=providers(),independent_Python_projection=model_projection(),
        instructions=[dict(offset=hex(a),mnemonic=m,operands=s) for a,m,s in EXPECTED],case_results=[])
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
        else:raise AssertionError('damaged file-check evidence accepted: '+str(path))
    for key,value in CLAIMS.items():reject(('claims',key),not value)
    reject(('providers','maximum_main_SVCs'),5)
    reject(('instructions',0,'mnemonic'),'nop')
    reject(('independent_Python_projection','result_byte'),1)
    for i in range(len(data['case_results'])):
        p=('case_results',i)
        for path,value in ((('packed_result_byte',),1),(('packed_bytes_outside_result_preserved',),False),
            (('independent_Python_projection','errno'),17),(('next_handler_read','load_executed'),True),
            (('next_handler_read','member_offset'),'0x50'),(('state_events',3,'state_owner_root_is_empty_container'),False),
            (('empty_container_payload','sha256'),'0'*64),(('registry_guard_at_stop',),0),
            (('selected_cache_path_prefix','cache_events'),[]),(('JNI_calls',),[]),(('service_counts','syscall_48'),1),
            (('main_image_SVC_boundaries',3,'number'),79),(('main_image_SVC_boundaries',3,'pathname_sha256'),'0'*64),
            (('main_image_SVC_boundaries',3,'return_pc'),'0x0'),(('callback_or_ordinary_RET_seen',),True)):
            reject(p+path,value)
        for n in range(len(FLOW)):reject(p+('native_flow',n,'x0_u64'),123)
    return count


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--elf',type=Path);ap.add_argument('--libc',type=Path);ap.add_argument('--replay',action='store_true')
    args=ap.parse_args()
    if args.replay and (not args.elf or not args.libc):ap.error('--replay requires --elf and --libc')
    data=json.loads(EVIDENCE.read_text(encoding='utf-8'));validate(data)
    result=dict(retained_file_check_cases=len(data['case_results']),damaged_evidence_rejected=negatives(data),
        ordinary_Cronet_six_headers_verified=False,complete_standalone_signer_verified=False)
    if args.elf:result['Metasec_bindings']=verify_elf(data,args.elf)
    if args.libc:graph.inputs.libc_image(args.libc);result['matching_Bionic_digest_verified']=True
    if args.replay:
        assert replay(args.elf,args.libc)==data['case_results'],'frozen file-check replay differs'
        result['original_code_cases_replayed']=len(data['case_results'])
    print(json.dumps(result))


if __name__=='__main__':main()
