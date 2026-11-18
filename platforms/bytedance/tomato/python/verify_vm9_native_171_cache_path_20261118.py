"""Original default cache identity, SHA-1 and filename through a file-check call.

Retain the prior directory profile and providers. Join a decoded ELF constant
to its original StringObject clone, original SHA-1 output and filename format.
Stop before the file readability call; its syscall is not allowed or executed.
Only the declared default identity and selected projections are compared.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from unicorn import arm64_const as arm
import verify_vm9_native_171_directory_20261118 as previous

context=previous.context
graph=previous.graph
output=previous.output
EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_cache_path_20261118.json')
STOP=0x25DE04
IDENTITY=b'def'
FORMAT=b'%s/%s%s'
PREFIX=b'.msp_'
SOURCE=dict(source='0xa4674',mask='0xa4688',destination='0x3ded4c')
EXPECTED=[
    (0x26A3E8,'add','x0, x0, #0x674'), (0x26A3EC,'add','x1, x1, #0xd4c'),
    (0x26A3F0,'add','x2, x2, #0x688'), (0x26A3F4,'bl','#0x167e54'),
    (0x26A480,'mov','x0, x19'), (0x26A484,'bl','#0x248344'),
    (0x269930,'bl','#0x2483e0'), (0x26A51C,'mov','x0, x9'),
    (0x26A520,'blr','x10'), (0x26A524,'ldr','x30, [sp], #0x10'),
    (0x2587AC,'ldr','x8, [x0, #0x10]'), (0x2587B0,'ldr','w1, [x0, #0xc]'),
    (0x2587B8,'bl','#0x2451fc'), (0x2587C0,'tbz','w20, #0, #0x2587ec'),
    (0x2587CC,'mov','w1, #0x14'), (0x2587D0,'bl','#0x19364c'),
    (0x25EF7C,'mov','x0, x20'), (0x25EF80,'bl','#0x15e1a8'),
    (0x25EFA8,'ret',''), (0x25DDF4,'ldr','w8, [x0, #0xc]'),
    (0x25DDFC,'ldr','x0, [x0, #0x10]'), (0x25DE00,'mov','w1, #4'),
    (STOP,'bl','#0x2730a4'),
]
CLAIMS=dict(
    original_decoded_default_identity_to_StringObject_clone_joined=True,
    original_SHA1_hex_result_matches_independent_hashlib=True,
    actual_digest_output_pointer_consumed_by_original_filename_formatter=True,
    selected_filename_matches_independent_declared_input_formula=True,
    accepted_directory_failure_projection_preserved=True,
    original_environment_helper_returned_after_failed_directory_creation=True,
    file_readability_object_to_CString_argument_joined=True,
    observer_stops_before_file_readability_call=True,
    additional_main_image_SVCs_executed=False,
    new_OS_JNI_or_internal_helper_providers=False,
    native_memory_used_as_independent_formula_input=False,
    alternate_identity_or_cache_path_cases_verified=False,
    full_guest_SHA1_or_formatter_stack_equivalence_verified=False,
    file_readability_result_or_real_filesystem_state_verified=False,
    business_state_restored=False,real_JVM_identity_verified=False,
    ordinary_Cronet_six_headers_verified=False,whole_request_equivalence_verified=False,
    callback_or_ordinary_wrapper_returned=False,complete_standalone_signer_verified=False,
    Android_execution=False,online_acceptance_verified=False,
)


def digest(raw):return hashlib.sha256(raw).hexdigest()


def blob(raw):return dict(length=len(raw),sha256=digest(raw))


def projection():
    suffix=hashlib.sha1(IDENTITY).hexdigest().encode()
    directory=context.AID_CACHE_PROFILE['pathname']
    path=directory+b'/'+PREFIX+suffix
    return dict(identity=blob(IDENTITY),SHA1_hex=blob(suffix),format=blob(FORMAT),
        directory=blob(directory),prefix=blob(PREFIX),cache_path=blob(path),
        directory_trailing_slash_preserved=True,double_separator_preserved=True)


def providers():
    return dict(inherited_directory_profile=previous.providers(),
        original_default_identity_decoder=SOURCE,identity_scope='original decoded default only',
        independent_formula='declared default identity, hashlib.sha1, declared directory/prefix/format',
        stop_before=hex(STOP),new_OS_JNI_or_internal_helper_providers=[])


class Scenario(previous.Scenario):
    def __init__(self,control):
        super().__init__(control)
        self.resumed=False;self.identity_events=[];self.sha_events=[];self.cache_events=[]
        self.sha_pending=None;self.format_pending=None;self.file_entry=False

    def observe(self,cpu,pc,state):
        off=pc-self.image
        if off in (0x27E6AC,0x27ED6C):raise AssertionError('unexpected callback or ordinary RET')
        def reg(n):return cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(n)))
        def u(a,n=8):return int.from_bytes(cpu.mem_read(a,n),'little')
        def string(a):return output._cstring(cpu,a)
        def obj(a):
            assert u(a)==self.image+0x34F5F8
            raw=bytes(cpu.mem_read(u(a+16),u(a+12,4)))
            assert u(u(a+16)+len(raw),1)==0
            return raw
        if off==0x248344 and reg(1)==self.image+int(SOURCE['destination'],16):
            assert self.identity_events==[] and string(reg(1))==IDENTITY
            assert reg(30)==self.image+0x26A488
            self.identity_object=reg(0)
            self.identity_events.append(dict(native_pc=hex(off),source_image_offset=SOURCE['destination'],
                return_pc='0x26a488',identity=blob(IDENTITY)))
        if off==0x2483E0 and hasattr(self,'identity_object') and reg(1)==self.identity_object:
            assert len(self.identity_events)==1 and obj(reg(1))==IDENTITY
            assert reg(30)==self.image+0x269934
            self.clone_object=reg(0)
            self.identity_events.append(dict(native_pc=hex(off),source_is_original_identity_object=True,
                return_pc='0x269934',identity=blob(IDENTITY)))
        if off==0x258780:
            assert self.sha_pending is None and self.sha_events==[]
            assert reg(0)==self.clone_object and obj(reg(0))==IDENTITY and reg(1)==1
            assert reg(30)==self.image+0x26A524
            self.sha_pending=dict(reference=reg(8),return_pc=reg(30))
            self.sha_events.append(dict(native_pc=hex(off),source_is_original_clone=True,
                flag=reg(1),identity=blob(obj(reg(0))),return_pc='0x26a524'))
        if self.sha_pending is not None and pc==self.sha_pending['return_pc']:
            ref=self.sha_pending['reference'];self.digest_object=u(ref)
            raw=obj(self.digest_object)
            assert raw==hashlib.sha1(IDENTITY).hexdigest().encode() and u(u(ref+8),4)==1
            self.digest_source=u(self.digest_object+16)
            self.sha_events.append(dict(native_pc=hex(off),result=blob(raw),reference_count=1))
            self.sha_pending=None
        if not self.resumed:
            if off!=previous.STOP:
                super().observe(cpu,pc,state)
                return
            row=dict(native_pc=hex(off),x0_u64=reg(0),errno=u(context.outer.root_fixture.TLS+0x100,4))
            assert self.flow==previous.FLOW[:-1] and row==previous.FLOW[-1]
            self.flow.append(row)
            assert self.pending is None and self.trailing_slash_removed and self.prefix_split_verified
            self.directory_projection=dict(provider_events=self.events,result=bool(reg(0)),errno=row['errno'],
                scratch_length=len(self.raw)+1,scratch_sha256=digest(bytes(cpu.mem_read(self.buffer,len(self.raw)+1))),
                stat_buffers_preserved=all(x['stat_buffer_unchanged'] for x in self.stat_calls))
            assert self.directory_projection==previous.model_projection()
            assert string(self.source)==self.raw
            self.resumed=True
        if off==0x25EFA8:
            assert reg(30)==self.image+0x26A4F8
            self.cache_events.append(dict(native_pc=hex(off),return_pc='0x26a4f8'))
        if off==0x248908:
            assert string(reg(1))==FORMAT and self.cache_events==[dict(native_pc='0x25efa8',return_pc='0x26a4f8')]
            assert string(reg(2))==context.AID_CACHE_PROFILE['pathname']
            assert string(reg(3))==PREFIX and reg(4)==self.digest_source
            assert string(reg(4))==hashlib.sha1(IDENTITY).hexdigest().encode()
            assert reg(30)==self.image+0x16AA4C
            self.file_object=reg(0);self.format_pending=reg(30)
            self.cache_events.append(dict(native_pc=hex(off),format=blob(string(reg(1))),
                arguments=[blob(string(reg(i))) for i in (2,3,4)],
                third_argument_is_original_digest_data=True,return_pc='0x16aa4c'))
        if self.format_pending is not None and pc==self.format_pending:
            assert blob(obj(self.file_object))==projection()['cache_path']
            self.file_data=u(self.file_object+16)
            self.cache_events.append(dict(native_pc=hex(off),formatted_path=blob(obj(self.file_object))))
            self.format_pending=None
        if off==0x25DDEC:
            assert reg(0)==self.file_object and blob(obj(reg(0)))==projection()['cache_path']
            assert reg(30)==self.image+0x26A57C
            self.file_entry=True
            self.cache_events.append(dict(native_pc=hex(off),input_is_formatted_object=True,return_pc='0x26a57c'))
        if off==STOP:
            assert self.file_entry and self.sha_pending is None and self.format_pending is None
            assert reg(0)==self.file_data and blob(string(reg(0)))==projection()['cache_path'] and reg(1)==4
            assert u(context.outer.root_fixture.TLS+0x100,4)==17
            assert string(self.source)==self.raw
            assert u(self.image+0x3D1558,1)==1 and bytes(cpu.mem_read(state['context'],0x80))==state['handler_bytes']
            self.cache_events.append(dict(native_pc=hex(off),path=blob(string(reg(0))),mode=4,errno=17,
                input_is_formatted_CString=True))
            self.stopped=True;cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,context.outer.oracle.STOP)

    def finish(self,result,state,proof):
        assert self.stopped and self.resumed and len(self.identity_events)==len(self.sha_events)==2
        assert proof['main_image_SVC_boundaries']==previous.bindings()
        frozen=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(frozen)
        old=next(row for row in frozen['case_results'] if row['control']==self.control)
        assert self.flow==old['native_flow'] and self.stat_calls==old['stat_calls']
        assert self.directory_projection==old['native_directory_projection']
        assert self.prefix.prefix==old['member_prefix'] and self.prefix.searches==old['aid_searches']
        assert proof['JNI_calls']==old['JNI_calls']
        return dict(control=self.control,identity_events=self.identity_events,SHA1_events=self.sha_events,
            cache_events=self.cache_events,inherited_directory_row_projection_verified=True,
            independent_formula_projection=projection(),main_image_SVC_boundaries=proof['main_image_SVC_boundaries'],
            context_handler_bytes_unchanged=True,registry_guard_at_stop=1,source_directory_string_unchanged=True,
            observation_stop_before=hex(STOP),callback_or_ordinary_RET_seen=False,
            original_outer_postconditions_passed=True,JNI_calls=proof['JNI_calls'],
            libc_SVC_boundaries=proof['libc_SVC_boundaries'],service_counts=result['explicit_service_counts'],
            allocator_counts=result['actual_allocator_counts'],
            continuation_instruction_observations=proof['instruction_observations'],
            continuation_trace_sha256=proof['trace_sha256'],continuation_code_sha256=proof['code_sha256'],
            allocation_ledger_sha256=graph.digest(result['allocator_events']))


def replay(path,libc,*,on_case=None,case_controls=None):
    return context.replay(path,libc,on_case=on_case,case_controls=case_controls,
        _extension_factory=Scenario,_request_profile=context.AID_DIRECTORY_PROFILE['name'])


def verify_elf(data,path):
    from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
    import vm9_objects as objects
    from vm9_allocator import _read_span
    frozen=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(frozen)
    upstream=previous.verify_elf(frozen,path)
    _,_,read=graph.inputs.load_elf(path);decoder=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
    for a,m,s in EXPECTED:
        ins,=decoder.disasm(read(a,4),a);assert (ins.mnemonic,ins.op_str)==(m,s),hex(a)
    base=context.controls()[0]['base'];pages=context.outer.oracle.image_pages(path,base)
    objects.decode_masked_bytes(pages,source_address=base+int(SOURCE['source'],16),
        destination_address=base+int(SOURCE['destination'],16),mask_address=base+int(SOURCE['mask'],16))
    assert _read_span(pages,base+int(SOURCE['destination'],16),4)==IDENTITY+b'\0'
    return dict(upstream=upstream,additional_instructions=len(EXPECTED),independent_ELF_default_identity_decode=True)


def validate(data):
    assert data['schema']=='vm9-native-171-cache-path-20261118-v1'
    assert data['provenance']==previous.previous.provenance() and data['claims']==CLAIMS
    assert data['providers']==providers() and data['independent_formula_projection']==projection()
    assert data['instructions']==[dict(offset=hex(a),mnemonic=m,operands=s) for a,m,s in EXPECTED]
    frozen=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(frozen)
    assert len(data['case_results'])==len(context.controls())
    p=projection()
    for row,old in zip(data['case_results'],frozen['case_results']):
        assert row['control']==old['control']
        assert row['identity_events']==[
            dict(native_pc='0x248344',source_image_offset=SOURCE['destination'],return_pc='0x26a488',identity=p['identity']),
            dict(native_pc='0x2483e0',source_is_original_identity_object=True,return_pc='0x269934',identity=p['identity'])]
        assert row['SHA1_events']==[
            dict(native_pc='0x258780',source_is_original_clone=True,flag=1,identity=p['identity'],return_pc='0x26a524'),
            dict(native_pc='0x26a524',result=p['SHA1_hex'],reference_count=1)]
        assert row['cache_events']==[
            dict(native_pc='0x25efa8',return_pc='0x26a4f8'),
            dict(native_pc='0x248908',format=p['format'],arguments=[p['directory'],p['prefix'],p['SHA1_hex']],
                third_argument_is_original_digest_data=True,return_pc='0x16aa4c'),
            dict(native_pc='0x16aa4c',formatted_path=p['cache_path']),
            dict(native_pc='0x25ddec',input_is_formatted_object=True,return_pc='0x26a57c'),
            dict(native_pc=hex(STOP),path=p['cache_path'],mode=4,errno=17,input_is_formatted_CString=True)]
        for key in ('inherited_directory_row_projection_verified','context_handler_bytes_unchanged',
                    'source_directory_string_unchanged','original_outer_postconditions_passed'):assert row[key] is True
        assert row['registry_guard_at_stop']==1 and row['callback_or_ordinary_RET_seen'] is False
        assert row['observation_stop_before']==hex(STOP) and row['independent_formula_projection']==p
        assert row['main_image_SVC_boundaries']==old['main_image_SVC_boundaries'] and row['JNI_calls']==old['JNI_calls']
        for key in ('syscall_48','syscall_79','mkdir_exists'):assert row['service_counts'][key]==old['service_counts'][key]
        assert old['continuation_instruction_observations']<row['continuation_instruction_observations']<400000
        for key in ('continuation_trace_sha256','continuation_code_sha256','allocation_ledger_sha256'):
            assert graph.inputs.is_digest(row[key])


def build(path,libc,*,on_case=None):
    data=dict(schema='vm9-native-171-cache-path-20261118-v1',provenance=previous.previous.provenance(),
        claims=CLAIMS,providers=providers(),independent_formula_projection=projection(),
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
        else:raise AssertionError('damaged cache-path evidence accepted: '+str(path))
    for key,value in CLAIMS.items():reject(('claims',key),not value)
    reject(('providers','original_default_identity_decoder','source'),'0xa4678')
    reject(('independent_formula_projection','double_separator_preserved'),False)
    reject(('instructions',0,'mnemonic'),'nop')
    for i in range(len(data['case_results'])):
        p=('case_results',i)
        for path,value in ((('identity_events',0,'source_image_offset'),'0x0'),
            (('identity_events',1,'source_is_original_identity_object'),False),
            (('SHA1_events',0,'flag'),0),(('SHA1_events',0,'identity','sha256'),'0'*64),
            (('SHA1_events',1,'result','sha256'),'0'*64),(('SHA1_events',1,'reference_count'),0),
            (('cache_events',1,'third_argument_is_original_digest_data'),False),
            (('cache_events',2,'formatted_path','length'),75),(('cache_events',3,'input_is_formatted_object'),False),
            (('cache_events',4,'mode'),0),(('cache_events',4,'errno'),2),
            (('cache_events',4,'input_is_formatted_CString'),False),
            (('inherited_directory_row_projection_verified',),False),(('registry_guard_at_stop',),0),
            (('callback_or_ordinary_RET_seen',),True),(('observation_stop_before',),'0x271dbc'),
            (('main_image_SVC_boundaries',),[]),(('JNI_calls',),[]),(('service_counts','syscall_48'),2)):
            reject(p+path,value)
    return count


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--elf',type=Path);ap.add_argument('--libc',type=Path);ap.add_argument('--replay',action='store_true')
    args=ap.parse_args()
    if args.replay and (not args.elf or not args.libc):ap.error('--replay requires --elf and --libc')
    data=json.loads(EVIDENCE.read_text(encoding='utf-8'));validate(data)
    result=dict(retained_cache_path_cases=len(data['case_results']),damaged_evidence_rejected=negatives(data),
        ordinary_Cronet_six_headers_verified=False,complete_standalone_signer_verified=False)
    if args.elf:result['Metasec_bindings']=verify_elf(data,args.elf)
    if args.libc:graph.inputs.libc_image(args.libc);result['matching_Bionic_digest_verified']=True
    if args.replay:
        assert replay(args.elf,args.libc)==data['case_results'],'frozen cache-path replay differs'
        result['original_code_cases_replayed']=len(data['case_results'])
    print(json.dumps(result))


if __name__=='__main__':main()
