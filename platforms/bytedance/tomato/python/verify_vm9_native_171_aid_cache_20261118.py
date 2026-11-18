"""Synthetic aid input through the original absent-cache error continuation.

Only one main-image faccessat is permitted, with an exact site, cursor, path
and argument binding. The inherited offline service returns ENOENT. Observe
the original errno store and false readability result, then stop before the
directory-creation path. This is neither Android cache state nor signing.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from unicorn import arm64_const as arm
import verify_vm9_native_171_diagnostic_gates_20261118 as previous

context=previous.upstream.context
graph=context.graph
output=previous.upstream.output
EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_aid_cache_20261118.json')
PROFILE=context.AID_CACHE_PROFILE
STOP=0x25EF6C
EXPECTED=[
    (0x271DBC,'svc','#0'), (0x271DC0,'cmn','x0, #1, lsl #12'),
    (0x271DC4,'cneg','x0, x0, hi'), (0x271DC8,'b.hi','#0x271d68'),
    (0x271D74,'mov','w19, w0'), (0x271D78,'bl','#0x3481a0'),
    (0x271D7C,'mov','x8, x0'), (0x271D80,'mov','x0, #-1'),
    (0x271D84,'str','w19, [x8]'), (0x271D88,'ldr','x19, [sp, #0x10]'),
    (0x271D90,'ret',''), (0x273088,'bl','#0x271d9c'),
    (0x2730A0,'ret',''), (0x25DE04,'bl','#0x2730a4'),
    (0x25DE08,'cmp','w0, #0'), (0x25DE0C,'cset','w0, eq'),
    (0x25DE10,'b','#0x25de18'), (0x25DE1C,'ret',''),
    (0x25EF64,'bl','#0x25ddec'), (0x25EF68,'tbnz','w0, #0, #0x25ef7c'),
    (STOP,'ldr','x0, [x19]'), (0x25EF70,'mov','w1, #0x1ed'),
    (0x25EF74,'mov','w2, #1'), (0x25EF78,'bl','#0x25eb54'),
]
FLOW=[dict(native_pc=hex(pc),signed_x0=value) for pc,value in (
    (0x271DC0,-2),(0x271DC4,-2),(0x271DC8,2),(0x271D68,2),
    (0x271D78,2),(0x271D84,-1),(0x271D88,-1),(0x271D90,-1),
    (0x27308C,-1),(0x2730A0,-1),(0x25DE08,-1),(0x25DE0C,-1),
    (0x25DE10,0),(0x25DE18,0),(0x25EF68,0),(STOP,0))]
CLAIMS=dict(
    synthetic_aid_input_reaches_nonempty_local_gate=True,
    first_minus_8_diagnostic_branch_not_taken_before_stop=True,
    narrowly_bound_original_main_image_faccessat_executed=True,
    inherited_absent_filesystem_result_consumed_by_original_code=True,
    original_errno_store_and_false_readability_return_verified=True,
    original_caller_falls_through_to_directory_path=True,
    original_outer_postconditions_passed=True,
    original_default_libc_only_SVC_policy_unchanged=True,
    observation_sentinel_before_directory_path=True,
    callback_or_ordinary_wrapper_returned=False,
    registry_guard_modified=False,new_OS_JNI_or_internal_helper_providers=False,
    real_Android_cache_state_verified=False,business_state_restored=False,
    real_JVM_identity_verified=False,ordinary_Cronet_six_headers_verified=False,
    whole_request_native_Python_equivalence_verified=False,
    complete_standalone_signer_verified=False,Android_execution=False,online_acceptance_verified=False,
)


def binding():
    return dict(native_pc=hex(PROFILE['native_pc']),bytecode=hex(PROFILE['bytecode']),
        number=PROFILE['number'],dirfd_u32=PROFILE['dirfd_u32'],mode=PROFILE['mode'],flags=PROFILE['flags'],
        pathname_length=len(PROFILE['pathname']),pathname_sha256=hashlib.sha256(PROFILE['pathname']).hexdigest())


def providers():
    return dict(inherited_context_profile=context.PROVIDERS,request_profile=PROFILE['name'],
        changed_input='fresh synthetic URL CString only',
        main_image_SVC_allowance=[binding()],main_image_SVC_maximum_calls=1,
        absent_filesystem_owner='verify_vm9_outer_signer_native.py:case.syscall',
        syscall_result=-2,errno_address_owner='existing outer __errno import and TLS+0x100',
        new_OS_JNI_or_internal_helper_providers=[],registry_guard_write=False,
        stop_before=hex(STOP),stop_kind='explicit observation sentinel; no callback return')


def searches():
    return [dict(bytecode=bc,target='0x248c54',pattern=pattern,
        source_length=5,source_sha256=hashlib.sha256(b'aid=1').hexdigest(),start_u32=0,result_u32=result)
        for bc,pattern,result in (('0xfbf2c','&aid=',0xFFFFFFFF),('0xfc130','aid=',0))]


class Scenario:
    def __init__(self,control):
        self.control=control;self.image=control['base'];self.pending=None
        self.searches=[];self.flow=[];self.svc_seen=False;self.stopped=False
        self.errno_written=False;self.early_statuses=[];self.formats=[]

    def native_runner(self,*args,**kwargs):
        return context.outer.oracle.native(*args,**kwargs)

    def member_boundary(self,cpu,state,proof):
        self.prefix=proof
        self.guard_at_member=int.from_bytes(cpu.mem_read(self.image+0x3D1558,1),'little')
        assert self.guard_at_member==1

    def observe(self,cpu,pc,state):
        def reg(n):return cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(n)))
        def u(a,n=8):return int.from_bytes(cpu.mem_read(a,n),'little')
        off=pc-self.image
        if off==0x27ED14:
            assert output._cstring(cpu,u(reg(0)))==PROFILE['URL']
            self.fresh_URL_verified=True
        if self.pending is not None and pc==self.pending['return_pc']:
            row=self.pending['row'];row['result_u32']=reg(0)&0xFFFFFFFF
            self.searches.append(row);self.pending=None
        if 'PC_slot' not in state:return
        bc=u(state['PC_slot'])-self.image
        if off==0x248C54 and bc in (0xFBF2C,0xFC130):
            _,source=output._string(cpu,reg(0),self.image)
            _,pattern=output._string(cpu,reg(1),self.image)
            assert source==b'aid=1' and self.pending is None
            self.pending=dict(return_pc=reg(30),row=dict(bytecode=hex(bc),target=hex(off),
                pattern=pattern.decode('ascii'),source_length=len(source),
                source_sha256=hashlib.sha256(source).hexdigest(),start_u32=reg(2)&0xFFFFFFFF))
        if off==0x170308 and bc==0xFC23C:
            frame=u(state['backing']+29*8)
            assert reg(10)==frame and reg(11)==4724
            assert u(frame+4712)==self.image+0x34F5F8
            self.local_length=u(reg(10)+reg(11),4)
            assert self.local_length==1
        if off==0x16EDE8 and bc==0xFC240:
            assert reg(9)==u(state['backing']+8)==1 and reg(11)==u(state['backing'])==0
            self.original_comparison_verified=True
        if off==0x16EE34 and bc==0xFC240:
            assert self.original_comparison_verified and reg(8)==self.image+0xFC244
            self.aid_branch=dict(bytecode=hex(bc),equal=False,target=hex(reg(8)-self.image))
        if off==0x16DB74 and bc in (0xFC5CC,0xFEF94):self.early_statuses.append(hex(bc))
        if off==0x248908 and state['store_verified'] and output._cstring(cpu,reg(1))==b'%d|%s':
            self.formats.append(reg(2))
        if off in (0x27E6AC,0x27ED6C):raise AssertionError('unexpected callback or ordinary RET')
        if off==PROFILE['native_pc']:
            assert not self.svc_seen and bc==PROFILE['bytecode'] and reg(8)==48
            self.svc_seen=True
            assert reg(30)==self.image+0x27308C
        if not self.svc_seen:return
        assert bc==PROFILE['bytecode']
        if off==0x271D7C:
            assert reg(0)==context.outer.root_fixture.TLS+0x100
            self.errno_address=reg(0)
        if off==0x271D84:
            assert reg(8)==self.errno_address and reg(19)&0xFFFFFFFF==2
        if off==0x271D88:
            assert u(self.errno_address,4)==2
            self.errno_written=True
        if off in {int(row['native_pc'],16) for row in FLOW}:
            value=reg(0);value-=1<<64 if value&(1<<63) else 0
            row=dict(native_pc=hex(off),signed_x0=value)
            assert row==FLOW[len(self.flow)]
            self.flow.append(row)
        if off==STOP:
            assert self.errno_written and self.flow==FLOW
            self.guard_at_stop=u(self.image+0x3D1558,1)
            assert self.guard_at_stop==1 and bytes(cpu.mem_read(state['context'],0x80))==state['handler_bytes']
            self.stopped=True
            cpu.emu_stop()
            cpu.reg_write(arm.UC_ARM64_REG_PC,context.outer.oracle.STOP)

    def finish(self,result,state,proof):
        assert self.stopped and self.fresh_URL_verified and self.pending is None
        assert self.early_statuses==self.formats==[] and self.searches==searches()
        assert proof['main_image_SVC_boundaries']==[binding()]
        assert result['virtual_descriptors_not_executed']
        return dict(control=self.control,fresh_URL_verified=True,aid_searches=self.searches,
            local_string_length=self.local_length,aid_branch=self.aid_branch,
            main_image_SVC_boundaries=proof['main_image_SVC_boundaries'],observed_native_flow=self.flow,
            errno_value=2,errno_slot_is_inherited_TLS=True,errno_store_completed=self.errno_written,
            readability_result=0,callback_or_ordinary_RET_seen=False,
            guard_at_member=self.guard_at_member,guard_at_stop=self.guard_at_stop,
            early_status_stores=self.early_statuses,diagnostic_formatters=self.formats,
            context_handler_bytes_unchanged=True,original_outer_postconditions_passed=True,
            observation_stop_before=hex(STOP),oracle_PC_is_observation_sentinel=True,
            member_prefix=self.prefix,JNI_calls=proof['JNI_calls'],libc_SVC_boundaries=proof['libc_SVC_boundaries'],
            continuation_instruction_observations=proof['instruction_observations'],
            continuation_trace_sha256=proof['trace_sha256'],continuation_code_sha256=proof['code_sha256'],
            allocator_counts=result['actual_allocator_counts'],service_counts=result['explicit_service_counts'],
            allocation_ledger_sha256=graph.digest(result['allocator_events']))


def replay(path,libc,*,on_case=None,case_controls=None):
    original=graph.inputs.URL
    rows=context.replay(path,libc,on_case=on_case,case_controls=case_controls,
        _extension_factory=Scenario,_request_profile=PROFILE['name'])
    assert graph.inputs.URL==original and b'?' not in original
    return rows


def verify_elf(data,path):
    from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
    frozen=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(frozen)
    upstream=previous.verify_elf(frozen,path)
    _,_,read=graph.inputs.load_elf(path);decoder=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
    for a,m,s in EXPECTED:
        ins,=decoder.disasm(read(a,4),a)
        assert (ins.mnemonic,ins.op_str)==(m,s),hex(a)
    assert int.from_bytes(read(PROFILE['bytecode'],4),'little')==0x067E0C91
    return dict(upstream=upstream,additional_instructions=len(EXPECTED),additional_bytecode_words=1)


def provenance():
    return dict(Metasec_sha256=graph.inputs.SHA256,Bionic_sha256=graph.inputs.LIBC_SHA256,
        default_URL_sha256=hashlib.sha256(graph.inputs.URL).hexdigest(),
        synthetic_URL_sha256=hashlib.sha256(PROFILE['URL']).hexdigest())


def validate(data):
    assert data['schema']=='vm9-native-171-aid-cache-20261118-v1'
    assert b'?' not in graph.inputs.URL and PROFILE['URL']==graph.inputs.URL+b'?aid=1'
    assert data['provenance']==provenance() and data['claims']==CLAIMS and data['providers']==providers()
    assert data['instructions']==[dict(offset=hex(a),mnemonic=m,operands=s) for a,m,s in EXPECTED]
    assert data['bytecode']==dict(offset=hex(PROFILE['bytecode']),word='0x67e0c91')
    assert len(data['case_results'])==len(context.controls())
    default=json.loads(context.EVIDENCE.read_text(encoding='utf-8'));context.validate(default)
    for row,control,old in zip(data['case_results'],context.controls(),default['case_results']):
        assert row['control']==control and row['aid_searches']==searches()
        for key in ('fresh_URL_verified','errno_slot_is_inherited_TLS','errno_store_completed',
            'context_handler_bytes_unchanged','original_outer_postconditions_passed','oracle_PC_is_observation_sentinel'):
            assert row[key] is True
        assert row['local_string_length']==1
        assert row['aid_branch']==dict(bytecode='0xfc240',equal=False,target='0xfc244')
        assert row['main_image_SVC_boundaries']==[binding()] and row['observed_native_flow']==FLOW
        assert row['errno_value']==2 and row['readability_result']==0
        assert row['callback_or_ordinary_RET_seen'] is False and row['observation_stop_before']==hex(STOP)
        assert row['guard_at_member']==row['guard_at_stop']==1
        assert row['early_status_stores']==row['diagnostic_formatters']==[]
        assert row['JNI_calls']==old['JNI_calls'] and row['libc_SVC_boundaries']==old['libc_SVC_boundaries']
        expected_counts=dict(old['service_counts'])
        expected_counts['syscall_48']+=1
        expected_counts['clock']+=2
        assert row['service_counts']==expected_counts
        assert row['continuation_instruction_observations']>old['continuation_instruction_observations']
        for key in ('continuation_trace_sha256','continuation_code_sha256','allocation_ledger_sha256'):
            assert graph.inputs.is_digest(row[key])
        assert graph.inputs.is_digest(row['member_prefix']['trace_sha256'])
        assert graph.inputs.is_digest(row['member_prefix']['code_sha256'])


def build(path,libc,*,on_case=None):
    data=dict(schema='vm9-native-171-aid-cache-20261118-v1',provenance=provenance(),
        claims=CLAIMS,providers=providers(),
        instructions=[dict(offset=hex(a),mnemonic=m,operands=s) for a,m,s in EXPECTED],
        bytecode=dict(offset=hex(PROFILE['bytecode']),word='0x67e0c91'),case_results=[])
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
        else:raise AssertionError('damaged aid/cache evidence accepted: '+str(path))
    for key,value in CLAIMS.items():reject(('claims',key),not value)
    reject(('provenance','synthetic_URL_sha256'),'0'*64)
    reject(('providers','main_image_SVC_maximum_calls'),2)
    reject(('providers','syscall_result'),0)
    reject(('instructions',0,'mnemonic'),'nop')
    reject(('bytecode','word'),'0x0')
    for i in range(len(data['case_results'])):
        p=('case_results',i)
        for path,value in ((('local_string_length',),0),(('aid_searches',1,'result_u32'),0xFFFFFFFF),
            (('aid_branch','equal'),True),(('aid_branch','target'),'0xfc5cc'),
            (('main_image_SVC_boundaries',0,'number'),79),(('main_image_SVC_boundaries',0,'native_pc'),'0x0'),
            (('main_image_SVC_boundaries',0,'bytecode'),'0x0'),(('main_image_SVC_boundaries',0,'pathname_sha256'),'0'*64),
            (('main_image_SVC_boundaries',0,'dirfd_u32'),0),(('main_image_SVC_boundaries',0,'mode'),0),
            (('errno_value',),0),(('readability_result',),1),(('errno_store_completed',),False),
            (('guard_at_stop',),0),(('callback_or_ordinary_RET_seen',),True),
            (('oracle_PC_is_observation_sentinel',),False),(('observation_stop_before',),'0x27ed6c'),
            (('early_status_stores',),['0xfc5cc']),(('JNI_calls',),[]),(('libc_SVC_boundaries',),[]),
            (('service_counts','syscall_48'),0),(('original_outer_postconditions_passed',),False)):
            reject(p+path,value)
        for j in range(len(FLOW)):reject(p+('observed_native_flow',j,'signed_x0'),123)
    return count


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--elf',type=Path);ap.add_argument('--libc',type=Path);ap.add_argument('--replay',action='store_true')
    args=ap.parse_args()
    if args.replay and (not args.elf or not args.libc):ap.error('--replay requires --elf and --libc')
    data=json.loads(EVIDENCE.read_text(encoding='utf-8'));validate(data)
    result=dict(retained_aid_cache_cases=len(data['case_results']),damaged_evidence_rejected=negatives(data),
        ordinary_Cronet_six_headers_verified=False,complete_standalone_signer_verified=False)
    if args.elf:result['Metasec_bindings']=verify_elf(data,args.elf)
    if args.libc:graph.inputs.libc_image(args.libc);result['matching_Bionic_digest_verified']=True
    if args.replay:
        assert replay(args.elf,args.libc)==data['case_results'],'frozen aid/cache replay differs'
        result['original_code_cases_replayed']=len(data['case_results'])
    print(json.dumps(result))


if __name__=='__main__':main()
