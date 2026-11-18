"""Constructed request through directory stat/mkdir failure and helper return.

Three ordered main-image SVCs use the inherited absent-file services. The
existing mkdir service returns EEXIST. Compare the two directory queries,
mkdir call and selected result/scratch projection to the existing Python
directory helper, staged independently from the declared path. Stop before
the caller's next instruction; no Android or whole-request signing claim.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from unicorn import arm64_const as arm
import verify_vm9_native_171_aid_cache_20261118 as previous
import vm9_configuration_init as model

context=previous.context
graph=previous.graph
output=previous.output
PROFILE=context.AID_DIRECTORY_PROFILE
EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_directory_20261118.json')
STOP=0x25EF7C
EXPECTED=[
    (0x25EB54,'sub','sp, sp, #0x1d0'), (0x25EB80,'tbz','w2, #0, #0x25ec4c'),
    (0x25EBA0,'add','x0, sp, #0x88'), (0x25EBAC,'bl','#0x276b9c'),
    (0x25EBB4,'strb','wzr, [x20, x21]'), (0x25EBBC,'cmp','w9, #0x2f'),
    (0x25EBC4,'strb','wzr, [x20, x8]'), (0x25EBD4,'bl','#0x272d80'),
    (0x25EBD8,'cbnz','w0, #0x25ebec'), (0x25EBEC,'orr','x20, x20, #1'),
    (0x25EC10,'strb','wzr, [x20]'), (0x25EC14,'bl','#0x272d80'),
    (0x25EC18,'cbz','w0, #0x25ec30'), (0x25EC20,'mov','w1, w19'),
    (0x25EC24,'bl','#0x3484a0'), (0x25EC28,'tbz','w0, #0x1f, #0x25ec40'),
    (0x25EC2C,'b','#0x25ec9c'), (0x25EC9C,'mov','w0, wzr'),
    (0x25ECA0,'ldr','x8, [x22, #0x28]'), (0x25ECC4,'ret',''),
    (STOP,'mov','x0, x20'), (0x272C0C,'stp','x29, x30, [sp, #-0x50]!'),
    (0x272D50,'mov','w0, #0x138'), (0x272D64,'bl','#0x271d9c'),
    (0x272D68,'ldp','x20, x19, [sp, #0x40]'), (0x272D80,'mov','x8, x0'),
    (0x272D84,'mov','x2, x1'), (0x272D88,'mov','w0, #-0x64'),
    (0x272D90,'mov','w3, wzr'), (0x271D9C,'sub','x0, x0, #0xe9'),
]
FLOW=[dict(native_pc=hex(pc),x0_u64=value,errno=err) for pc,value,err in (
    (0x25EBD8,(1<<64)-1,2),(0x25EBEC,(1<<64)-1,2),
    (0x25EC18,(1<<64)-1,2),(0x25EC1C,(1<<64)-1,2),
    (0x25EC28,0xFFFFFFFF,17),(0x25EC2C,0xFFFFFFFF,17),(0x25EC9C,0xFFFFFFFF,17),
    (0x25ECA0,0,17),(0x25ECC4,0,17),(STOP,0,17))]
CLAIMS=dict(
    inherited_aid_search_and_readability_flow_verified=True,
    three_main_SVCs_bound_by_order_site_path_and_arguments=True,
    two_original_stat_error_continuations_and_preserved_buffers_verified=True,
    existing_mkdir_EEXIST_result_consumed_by_original_code=True,
    original_directory_helper_returns_false_to_caller=True,
    provider_sequence_and_selected_result_projection_match_existing_Python_model=True,
    model_input_copied_from_native_memory=False,physical_stack_bytes_compared=False,
    observer_stops_before_callers_next_instruction=True,
    callback_or_ordinary_wrapper_returned=False,registry_guard_modified_by_observer=False,
    new_OS_JNI_or_internal_helper_providers=False,
    real_filesystem_state_or_successful_directory_creation_verified=False,
    business_state_restored=False,real_JVM_identity_verified=False,
    ordinary_Cronet_six_headers_verified=False,whole_request_native_Python_equivalence_verified=False,
    complete_standalone_signer_verified=False,Android_execution=False,online_acceptance_verified=False,
)


def digest(raw):return hashlib.sha256(raw).hexdigest()


def stat_event(path):
    return dict(kind='syscall',number=79,dirfd_u32=0xFFFFFF9C,flags=0,
        pathname_length=len(path),pathname_sha256=digest(path),kernel_result=-2)


def mkdir_event(path):
    return dict(kind='mkdir_service',pathname_length=len(path),pathname_sha256=digest(path),
        mode=0o755,result_u32=0xFFFFFFFF,errno_set=17)


def bindings():
    rows=[previous.binding()]
    for path in PROFILE['stat_paths']:
        rows.append(dict(native_pc='0x271dbc',bytecode='0xfca40',number=79,dirfd_u32=0xFFFFFF9C,
            flags=0,pathname_length=len(path),pathname_sha256=digest(path),
            stat_buffer_in_native_stack=True,stat_buffer_size=128,stat_buffer_SP_offset=0x58,return_pc='0x272d68'))
    return rows


def providers():
    return dict(inherited_context_profile=context.PROVIDERS,request_profile=PROFILE['name'],
        ordered_main_image_SVCs=bindings(),main_image_SVC_maximum_calls=3,
        mkdir_owner='verify_vm9_outer_signer_native.py:case.mkdir',mkdir_calls_after_aid_boundary=1,
        mkdir_errno=17,mkdir_result_u32=0xFFFFFFFF,new_OS_JNI_or_internal_helper_providers=[],
        Python_model_owner='vm9_configuration_init.py:ensure_environment_directory',
        Python_input='independent pages, declared static directory string and synthetic stack',
        stop_before=hex(STOP),stop_kind='observation sentinel after directory helper RET; no request RET')


def model_projection():
    obj,source,errno,entry=0x60000000,0x60000100,0x60000200,0x60011000
    pages={a>>12:bytearray(4096) for a in (obj,entry-4096)}
    raw=context.AID_CACHE_PROFILE['pathname']
    model._w(pages,obj+16,source);model._write_span(pages,source,raw+b'\0')
    before=model._read_span(pages,entry-0x1C8,128);events=[]
    def syscall(p,number,args):
        assert number==79 and args[0]==0xFFFFFF9C and args[2]==entry-0x1C8 and args[3]==0
        path=model.objects._cstring(p,args[1],257)[:-1]
        event=stat_event(path);event['number']=number;events.append(event)
        return -2
    def mkdir(p,path_address,mode):
        assert mode==0o755
        path=model.objects._cstring(p,path_address,257)[:-1]
        event=mkdir_event(path);event['mode']=mode;events.append(event)
        model._w(p,errno,17,4)
        return 0xFFFFFFFF
    result=model.ensure_environment_directory(pages,object_address=obj,entry_stack_address=entry,
        syscall=syscall,errno_address=errno,mkdir=mkdir)
    return dict(provider_events=events,result=result,errno=model._u(pages,errno,4),
        scratch_length=len(raw)+1,scratch_sha256=digest(model._read_span(pages,entry-0x148,len(raw)+1)),
        stat_buffers_preserved=model._read_span(pages,entry-0x1C8,128)==before)


class Scenario:
    def __init__(self,control):
        self.control=control;self.image=control['base'];self.prefix=previous.Scenario(control)
        self.prefix_done=False;self.flow=[];self.stat_calls=[];self.pending=None;self.events=[]
        self.stopped=False

    def native_runner(self,*args,**kwargs):return self.prefix.native_runner(*args,**kwargs)
    def member_boundary(self,cpu,state,proof):self.prefix.member_boundary(cpu,state,proof)

    def observe(self,cpu,pc,state):
        def reg(n):return cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(n)))
        def u(a,n=8):return int.from_bytes(cpu.mem_read(a,n),'little')
        off=pc-self.image;errno_address=context.outer.root_fixture.TLS+0x100
        if not self.prefix_done:
            if off!=previous.STOP:
                self.prefix.observe(cpu,pc,state)
                return
            row=dict(native_pc=hex(off),signed_x0=reg(0))
            assert self.prefix.flow==previous.FLOW[:-1] and row==previous.FLOW[-1]
            self.prefix.flow.append(row)
            assert self.prefix.errno_written and self.prefix.pending is None
            assert self.prefix.searches==previous.searches() and self.prefix.early_statuses==self.prefix.formats==[]
            assert u(self.image+0x3D1558,1)==1
            assert bytes(cpu.mem_read(state['context'],0x80))==state['handler_bytes']
            self.prefix_done=True
        assert u(state['PC_slot'])==self.image+0xFCA40
        if off==0x25EB54:
            self.entry=cpu.reg_read(arm.UC_ARM64_REG_SP)
            assert reg(1)==0o755 and reg(2)==1
            self.source=u(reg(0)+16);self.raw=output._cstring(cpu,self.source)
            assert self.raw==context.AID_CACHE_PROFILE['pathname']
            self.buffer=self.entry-0x148;self.stat_buffer=self.entry-0x1C8
        if off==0x25EBC4:
            assert reg(20)==self.buffer and reg(8)==len(self.raw)-1 and u(self.buffer+reg(8),1)==47
        if off==0x25EBC8:
            assert output._cstring(cpu,self.buffer)==PROFILE['stat_paths'][0]
            self.trailing_slash_removed=True
        if off==0x25EC14:
            assert output._cstring(cpu,self.buffer)==PROFILE['stat_paths'][1]
            self.prefix_split_verified=True
        if off==0x271DBC:
            assert reg(8)==79 and self.pending is None and len(self.stat_calls)<2
            path=output._cstring(cpu,reg(1));assert path==PROFILE['stat_paths'][len(self.stat_calls)]
            assert reg(2)==self.stat_buffer
            self.pending=dict(path=path,before=bytes(cpu.mem_read(self.stat_buffer,128)),kernel_seen=False,errno_seen=False)
        if self.pending is not None:
            if off==0x271DC0:
                assert reg(0)==(1<<64)-2
                self.pending['kernel_seen']=True
            if off==0x271D88:
                assert self.pending['kernel_seen'] and reg(0)==(1<<64)-1 and u(errno_address,4)==2
                self.pending['errno_seen']=True
            if off==0x272D68:
                assert self.pending['errno_seen'] and reg(0)==(1<<64)-1
                unchanged=bytes(cpu.mem_read(self.stat_buffer,128))==self.pending['before']
                assert unchanged
                event=stat_event(self.pending['path']);self.events.append(event)
                self.stat_calls.append(dict(event,return_u64=reg(0),errno_value=u(errno_address,4),
                    original_errno_store_completed=True,stat_buffer_unchanged=unchanged))
                self.pending=None
        if off==0x3484A0:
            assert self.pending is None and len(self.stat_calls)==2 and len(self.events)==2
            path=output._cstring(cpu,reg(0));assert path==b'/data' and reg(1)==0o755
            self.events.append(dict(kind='mkdir_service',pathname_length=len(path),pathname_sha256=digest(path),mode=reg(1)))
        if off==0x25EC28:
            assert reg(0)==0xFFFFFFFF and u(errno_address,4)==17
            self.events[-1].update(result_u32=reg(0),errno_set=u(errno_address,4))
        if off in {int(row['native_pc'],16) for row in FLOW}:
            row=dict(native_pc=hex(off),x0_u64=reg(0),errno=u(errno_address,4))
            assert row==FLOW[len(self.flow)];self.flow.append(row)
        if off==STOP:
            assert self.flow==FLOW and self.pending is None
            assert self.trailing_slash_removed and self.prefix_split_verified
            assert bytes(cpu.mem_read(state['context'],0x80))==state['handler_bytes'] and u(self.image+0x3D1558,1)==1
            assert output._cstring(cpu,self.source)==self.raw
            self.projection=dict(provider_events=self.events,result=bool(reg(0)),errno=u(errno_address,4),
                scratch_length=len(self.raw)+1,scratch_sha256=digest(bytes(cpu.mem_read(self.buffer,len(self.raw)+1))),
                stat_buffers_preserved=all(row['stat_buffer_unchanged'] for row in self.stat_calls))
            assert self.projection==model_projection()
            self.stopped=True;cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,context.outer.oracle.STOP)

    def finish(self,result,state,proof):
        assert self.stopped and proof['main_image_SVC_boundaries']==bindings()
        frozen=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(frozen)
        old=next(row for row in frozen['case_results'] if row['control']==self.control)
        assert self.prefix.prefix==old['member_prefix'] and self.prefix.flow==old['observed_native_flow']
        return dict(control=self.control,inherited_aid_gate_prefix_verified=True,
            member_prefix=self.prefix.prefix,aid_searches=self.prefix.searches,
            main_image_SVC_boundaries=proof['main_image_SVC_boundaries'],stat_calls=self.stat_calls,
            trailing_slash_removed=True,prefix_split_verified=True,source_string_unchanged=True,
            native_flow=self.flow,native_directory_projection=self.projection,
            existing_Python_directory_projection_matches=True,directory_helper_returned_false=True,
            context_handler_bytes_unchanged=True,registry_guard_at_stop=1,
            original_outer_postconditions_passed=True,observation_stop_before=hex(STOP),
            oracle_PC_is_observation_sentinel=True,callback_or_ordinary_RET_seen=False,
            JNI_calls=proof['JNI_calls'],libc_SVC_boundaries=proof['libc_SVC_boundaries'],
            continuation_instruction_observations=proof['instruction_observations'],
            continuation_trace_sha256=proof['trace_sha256'],continuation_code_sha256=proof['code_sha256'],
            allocator_counts=result['actual_allocator_counts'],service_counts=result['explicit_service_counts'],
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
    return dict(upstream=upstream,additional_instructions=len(EXPECTED))


def validate(data):
    assert data['schema']=='vm9-native-171-directory-20261118-v1'
    assert data['provenance']==previous.provenance() and data['claims']==CLAIMS and data['providers']==providers()
    assert data['instructions']==[dict(offset=hex(a),mnemonic=m,operands=s) for a,m,s in EXPECTED]
    projection=model_projection();assert data['independent_Python_directory_projection']==projection
    assert projection['result'] is False and projection['errno']==17 and projection['stat_buffers_preserved'] is True
    assert projection['provider_events']==[*(stat_event(path) for path in PROFILE['stat_paths']),mkdir_event(b'/data')]
    frozen=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(frozen)
    assert len(data['case_results'])==len(context.controls())
    for row,old in zip(data['case_results'],frozen['case_results']):
        assert row['control']==old['control'] and row['member_prefix']==old['member_prefix']
        assert row['aid_searches']==old['aid_searches'] and row['main_image_SVC_boundaries']==bindings()
        assert row['native_flow']==FLOW and row['native_directory_projection']==projection
        for key in ('inherited_aid_gate_prefix_verified','trailing_slash_removed','prefix_split_verified',
            'source_string_unchanged','existing_Python_directory_projection_matches','directory_helper_returned_false',
            'context_handler_bytes_unchanged','original_outer_postconditions_passed','oracle_PC_is_observation_sentinel'):
            assert row[key] is True
        assert row['registry_guard_at_stop']==1 and row['callback_or_ordinary_RET_seen'] is False
        assert row['observation_stop_before']==hex(STOP)
        assert row['stat_calls']==[dict(stat_event(path),return_u64=(1<<64)-1,errno_value=2,
            original_errno_store_completed=True,stat_buffer_unchanged=True) for path in PROFILE['stat_paths']]
        assert row['JNI_calls']==old['JNI_calls'] and row['libc_SVC_boundaries']==old['libc_SVC_boundaries']
        counts=dict(old['service_counts']);counts['syscall_79']+=2;counts['mkdir_exists']+=1
        assert row['service_counts']==counts
        assert row['continuation_instruction_observations']>old['continuation_instruction_observations']
        for key in ('continuation_trace_sha256','continuation_code_sha256','allocation_ledger_sha256'):
            assert graph.inputs.is_digest(row[key])


def build(path,libc,*,on_case=None):
    data=dict(schema='vm9-native-171-directory-20261118-v1',provenance=previous.provenance(),
        claims=CLAIMS,providers=providers(),instructions=[dict(offset=hex(a),mnemonic=m,operands=s) for a,m,s in EXPECTED],
        independent_Python_directory_projection=model_projection(),case_results=[])
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
        else:raise AssertionError('damaged directory evidence accepted: '+str(path))
    for key,value in CLAIMS.items():reject(('claims',key),not value)
    reject(('providers','main_image_SVC_maximum_calls'),4)
    reject(('providers','mkdir_errno'),0)
    reject(('independent_Python_directory_projection','result'),True)
    reject(('instructions',0,'mnemonic'),'nop')
    for i in range(len(data['case_results'])):
        p=('case_results',i)
        for path,value in ((('existing_Python_directory_projection_matches',),False),
            (('native_directory_projection','result'),True),(('native_directory_projection','errno'),0),
            (('native_directory_projection','scratch_sha256'),'0'*64),
            (('registry_guard_at_stop',),0),(('observation_stop_before',),'0x27ed6c'),
            (('callback_or_ordinary_RET_seen',),True),(('aid_searches',),[]),
            (('JNI_calls',),[]),(('libc_SVC_boundaries',),[]),(('service_counts','syscall_79'),0)):
            reject(p+path,value)
        for n in (1,2):
            for key,value in (('number',48),('pathname_sha256','0'*64),('stat_buffer_SP_offset',0),('return_pc','0x0')):
                reject(p+('main_image_SVC_boundaries',n,key),value)
        for n in range(2):
            for key,value in (('errno_value',17),('original_errno_store_completed',False),('stat_buffer_unchanged',False)):
                reject(p+('stat_calls',n,key),value)
        for n in range(len(FLOW)):reject(p+('native_flow',n,'x0_u64'),123)
    return count


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--elf',type=Path);ap.add_argument('--libc',type=Path);ap.add_argument('--replay',action='store_true')
    args=ap.parse_args()
    if args.replay and (not args.elf or not args.libc):ap.error('--replay requires --elf and --libc')
    data=json.loads(EVIDENCE.read_text(encoding='utf-8'));validate(data)
    result=dict(retained_directory_cases=len(data['case_results']),damaged_evidence_rejected=negatives(data),
        ordinary_Cronet_six_headers_verified=False,complete_standalone_signer_verified=False)
    if args.elf:result['Metasec_bindings']=verify_elf(data,args.elf)
    if args.libc:graph.inputs.libc_image(args.libc);result['matching_Bionic_digest_verified']=True
    if args.replay:
        assert replay(args.elf,args.libc)==data['case_results'],'frozen directory replay differs'
        result['original_code_cases_replayed']=len(data['case_results'])
    print(json.dumps(result))


if __name__=='__main__':main()
