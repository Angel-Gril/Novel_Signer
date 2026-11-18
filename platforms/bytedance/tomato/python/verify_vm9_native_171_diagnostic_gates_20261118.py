"""Observe diagnostic gate inputs in the unchanged constructed 0x171 request.

The synthetic URL has no query. Both aid searches fail, a moved local string
is empty, and the existing registry guard has low bit one. These observations
do not establish all causes of missing six headers or restore business state.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from unicorn import arm64_const as arm
import verify_vm9_native_171_output_20261118 as upstream

graph=upstream.graph
EVIDENCE=upstream.EVIDENCE.with_name('vm9_native_171_diagnostic_gates_20261118.json')
WORDS={0xFBF2C:0x067E0C91,0xFC130:0x067E0C91,0xFC23C:0x9282D4C1,
    0xFC240:0x1C42002D,0xFC504:0xA81BC116,0xFC5CC:0x7F01FAFB,
    0xFC5DC:0xFB1F5054,0xFEE08:0x8980003D,0xFEE10:0x00411035,
    0xFEE14:0x44401014,0xFEF94:0x7EA0F97B}
EXPECTED=[(0x170308,'ldrsw','x9, [x10, x11]'),
    (0x17030C,'str','x9, [x28, x14, lsl #3]'),
    (0x16EDE8,'cmp','x9, x11'),(0x16EDF0,'csel','x9, x10, xzr, eq'),
    (0x16EE34,'str','x8, [x19]'),
    (0x170068,'ldrsb','x11, [x11, x12]'),(0x17009C,'str','x11, [x28, x16, lsl #3]'),
    (0x16E118,'str','x9, [x28, x12, lsl #3]'),
    (0x16F050,'cmp','x9, x10'),(0x16F058,'csel','x9, xzr, x12, eq'),
    (0x16F09C,'str','x8, [x19]'),(0x16DB64,'add','x10, x11, w10, sxtw'),
    (0x16DB74,'str','x10, [x28, x15, lsl #3]')]
CLAIMS=dict(original_aid_searches_and_empty_local_gate_observed=True,
    minus_8_origin_is_bytecode_0xfc5cc=True,original_registry_guard_gate_observed=True,
    both_status_stores_and_taken_branches_observed=True,upstream_output_row_unchanged=True,
    fixture_or_registry_guard_modified=False,new_OS_JNI_or_internal_helper_providers=False,
    complete_missing_six_headers_cause_verified=False,business_state_restored=False,
    ordinary_Cronet_six_headers_verified=False,whole_request_native_Python_equivalence_verified=False,
    complete_standalone_signer_verified=False,Android_execution=False)
PROVIDERS=dict(inherited_output_profile=upstream.PROVIDERS,
    new_OS_JNI_or_internal_helper_providers=[],observers_read_only=True,
    fixture_URL_owner='verify_vm9_native_171_inputs_20261118.py:URL',
    scope='unchanged synthetic URL and explicit NULL-JNI profiles; diagnostic gates only')
EMPTY_SHA256=hashlib.sha256(b'').hexdigest()
SEARCHES=[dict(bytecode=bc,target='0x248c54',pattern=pattern,source_length=0,
    source_sha256=EMPTY_SHA256,start_u32=0,result_u32=0xFFFFFFFF)
    for bc,pattern in (('0xfbf2c','&aid='),('0xfc130','aid='))]
STATUSES=[dict(bytecode=hex(bc),word=hex(word),source_slot=0,source_value=0,
    destination_slot=slot,signed_immediate=value,native_value=value,store_completed=True)
    for bc,word,slot,value in ((0xFC5CC,0x7F01FAFB,21,-8),(0xFEF94,0x7EA0F97B,2,-11))]
BRANCHES=[dict(bytecode=hex(bc),native_pc=hex(pc),left_slot=slot,left_value=value,
    right_slot=0,right_value=0,condition=condition,taken=True,target=hex(target))
    for bc,pc,slot,value,condition,target in (
        (0xFC240,0x16EE34,1,0,'eq',0xFC5CC),
        (0xFC5DC,0x16F09C,21,-8,'ne',0xFC258),
        (0xFEE14,0x16F09C,1,1,'ne',0xFEF5C))]
LOCAL_GATE=dict(bytecode='0xfc23c',native_pc='0x170308',frame_offset=4724,
    object_frame_offset=4712,member_offset=12,size=4,value=0,
    object_vtable_offset='0x34f5f8',object_capacity=8,object_length=0,payload_present=True)
REGISTRY_GATE=dict(bytecode='0xfee08',native_pc='0x170068',source_image_offset='0x3d1558',
    size=1,raw_byte=1,signed_result=1,mask_bytecode='0xfee10',mask=1,masked_result=1)


class Scenario(upstream.Scenario):
    def __init__(self,control):
        super().__init__(control)
        self.searches=[];self.pending_search=None
        self.branches=[];self.status_stores=[];self.comparisons=[]

    def member_boundary(self,cpu,state,proof):
        super().member_boundary(cpu,state,proof)
        self.frame=int.from_bytes(cpu.mem_read(state['backing']+29*8,8),'little')

    def observe(self,cpu,pc,state):
        def reg(name):return cpu.reg_read(getattr(arm,'UC_ARM64_REG_'+name.upper()))
        def u(address,size=8):return int.from_bytes(cpu.mem_read(address,size),'little')
        if self.pending_search is not None and pc==self.pending_search['return_pc']:
            row=self.pending_search['row'];row['result_u32']=reg('x0')&0xFFFFFFFF
            self.searches.append(row);self.pending_search=None
        super().observe(cpu,pc,state)
        if not self.active or self.callback_done or not state['store_verified']:return
        off=pc-self.image
        interesting=(0x248C54,0x170308,0x16EDE8,0x16F050,0x16EE34,0x16F09C,
                     0x170068,0x17009C,0x16E11C,0x16DB74,0x16DB78)
        if off not in interesting or reg('x28')!=state['backing']:return
        bc=u(state['PC_slot'])-self.image
        if off==0x248C54 and bc in (0xFBF2C,0xFC130):
            _,source=upstream.output._string(cpu,reg('x0'),self.image)
            _,pattern=upstream.output._string(cpu,reg('x1'),self.image)
            assert self.pending_search is None
            self.pending_search=dict(return_pc=reg('x30'),row=dict(bytecode=hex(bc),target=hex(off),
                pattern=pattern.decode('ascii'),source_length=len(source),
                source_sha256=hashlib.sha256(source).hexdigest(),start_u32=reg('x2')&0xFFFFFFFF))
        if off==0x170308 and bc==0xFC23C:
            assert reg('x10')==self.frame and reg('x11')==4724
            assert u(state['backing']+29*8)==self.frame
            obj=self.frame+4712
            assert u(obj)==self.image+0x34F5F8
            self.local_gate=dict(bytecode=hex(bc),native_pc=hex(off),frame_offset=reg('x11'),
                object_frame_offset=4712,member_offset=12,size=4,value=u(reg('x10')+reg('x11'),4),
                object_vtable_offset=hex(u(obj)-self.image),object_capacity=u(obj+8,4),
                object_length=u(obj+12,4),payload_present=bool(u(obj+16)))
        if off==0x16EDE8 and bc==0xFC240:
            assert reg('x9')==reg('x11')==u(state['backing'])==u(state['backing']+8)==0
            self.comparisons.append(hex(bc))
        if off==0x16F050 and bc in (0xFC5DC,0xFEE14):
            slot=21 if bc==0xFC5DC else 1
            value=-8 if slot==21 else 1
            assert u(state['backing'])==0 and u(state['backing']+slot*8)==value&((1<<64)-1)
            assert {reg('x9'),reg('x10')}=={0,value&((1<<64)-1)}
            self.comparisons.append(hex(bc))
        if off in (0x16EE34,0x16F09C) and bc in (0xFC240,0xFC5DC,0xFEE14):
            expected=next(row for row in BRANCHES if row['bytecode']==hex(bc))
            assert self.comparisons[-1]==hex(bc) and reg('x19')==state['PC_slot']
            row=dict(expected);row['target']=hex(reg('x8')-self.image)
            self.branches.append(row)
        if off==0x170068 and bc==0xFEE08:
            assert reg('x11')==u(state['backing']+22*8)==self.image+0x3D1558
            assert reg('x12')==0
            self.registry_gate=dict(bytecode=hex(bc),native_pc=hex(off),
                source_image_offset=hex(reg('x11')-self.image),size=1,
                raw_byte=u(reg('x11')+reg('x12'),1))
        if off==0x17009C and bc==0xFEE08:
            assert reg('x16')==1
            self.registry_gate['signed_result']=reg('x11')
        if off==0x16E11C and bc==0xFEE10:
            self.registry_gate.update(mask_bytecode=hex(bc),mask=1,masked_result=u(state['backing']+8))
        if off==0x16DB74 and bc in (0xFC5CC,0xFEF94):
            expected=next(row for row in STATUSES if row['bytecode']==hex(bc))
            assert reg('x15')==expected['destination_slot'] and u(state['backing'])==0
            assert reg('x10')==expected['native_value']&((1<<64)-1)
            self.status_stores.append(dict(expected,store_completed=False))
        if off==0x16DB78 and bc in (0xFC5CC,0xFEF94):
            row=self.status_stores[-1]
            assert row['bytecode']==hex(bc)
            assert u(state['backing']+row['destination_slot']*8)==row['native_value']&((1<<64)-1)
            row['store_completed']=True

    def finish(self,result,state,proof):
        row=super().finish(result,state,proof)
        frozen=json.loads(upstream.EVIDENCE.read_text(encoding='utf-8'))
        upstream.validate(frozen)
        previous=next(item for item in frozen['case_results'] if item['control']==self.control)
        assert row==previous,'gate observers changed the upstream output row'
        assert self.pending_search is None
        return dict(control=self.control,upstream_output_row_unchanged=True,
            upstream_output_row_sha256=graph.digest(row),aid_searches=self.searches,
            local_string_gate=self.local_gate,registry_guard_gate=self.registry_gate,
            native_comparison_bytecodes=self.comparisons,taken_branches=self.branches,
            status_stores=self.status_stores,output_keys=row['output_keys'],
            serialized_sha256=row['serialized_sha256'])


def replay(path,libc,*,on_case=None,case_controls=None):
    return upstream.context.replay(path,libc,on_case=on_case,case_controls=case_controls,_extension_factory=Scenario)


def verify_elf(data,path):
    from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
    frozen=json.loads(upstream.EVIDENCE.read_text(encoding='utf-8'));upstream.validate(frozen)
    previous=upstream.verify_elf(frozen,path)
    _,_,read=graph.inputs.load_elf(path);decoder=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
    for a,m,s in EXPECTED:
        ins,=decoder.disasm(read(a,4),a)
        assert (ins.mnemonic,ins.op_str)==(m,s),hex(a)
    for a,w in WORDS.items():assert int.from_bytes(read(a,4),'little')==w
    for row in STATUSES:
        w=WORDS[int(row['bytecode'],16)]
        immediate=((w>>21)&31)|(((w>>11)&31)<<5)|(((w>>26)&31)<<10)|(((w>>6)&1)<<15)
        immediate-=65536 if immediate&32768 else 0
        assert w&63==59 and (((w>>17)&15)|((w>>27)&16))==row['source_slot']
        assert (((w>>7)&15)|((w>>12)&16))==row['destination_slot']
        assert immediate==row['signed_immediate']
    for row in BRANCHES:
        bc=int(row['bytecode'],16);w=WORDS[bc]
        if row['condition']=='eq':
            assert w&63==45
            left=((w>>22)&15)|((w>>27)&16);right=((w>>7)&15)|((w>>17)&16)
            immediate=((w>>16)&31)|(((w>>26)&31)<<5)|(((w>>11)&31)<<10)|(((w>>6)&1)<<15)
        else:
            assert w&63==20
            left=((w>>12)&15)|((w>>27)&16);right=(w>>7)&31
            immediate=((w>>26)&31)|(((w>>21)&31)<<5)|(((w>>16)&31)<<10)|(((w>>6)&1)<<15)
        immediate-=65536 if immediate&32768 else 0
        assert (left,right)==(row['left_slot'],row['right_slot'])
        assert bc+4+4*immediate==int(row['target'],16)
    w=WORDS[0xFC23C]
    immediate=((w>>21)&31)|(((w>>6)&31)<<5)|(((w>>26)&31)<<10)|(((w>>16)&1)<<15)
    assert w&63==1 and (((w>>12)&15)|((w>>27)&16))==29
    assert (((w>>17)&15)|((w>>7)&16))==1 and immediate==LOCAL_GATE['frame_offset']
    w=WORDS[0xFEE10]
    mask=((w>>16)&31)|(((w>>26)&31)<<5)|(((w>>6)&31)<<10)|(((w>>21)&1)<<15)
    assert w&63==53 and mask==REGISTRY_GATE['mask']
    assert (((w>>12)&15)|((w>>27)&16))==(((w>>22)&15)|(((w>>11)&1)<<4))==1
    return dict(upstream=previous,additional_instructions=len(EXPECTED),additional_bytecode_words=len(WORDS),
                independently_decoded_statuses=2,independently_decoded_branches=3)


def validate(data):
    assert data['schema']=='vm9-native-171-diagnostic-gates-20261118-v1'
    assert data['provenance']==dict(Metasec_sha256=graph.inputs.SHA256,Bionic_sha256=graph.inputs.LIBC_SHA256,
        upstream='vm9_native_171_output_20261118.json',fixture_URL_sha256=hashlib.sha256(graph.inputs.URL).hexdigest())
    assert b'?' not in graph.inputs.URL
    assert data['claims']==CLAIMS and data['providers']==PROVIDERS
    assert data['instructions']==[dict(offset=hex(a),mnemonic=m,operands=s) for a,m,s in EXPECTED]
    assert data['bytecode_words']=={hex(a):hex(w) for a,w in WORDS.items()}
    frozen=json.loads(upstream.EVIDENCE.read_text(encoding='utf-8'));upstream.validate(frozen)
    assert len(data['case_results'])==len(frozen['case_results'])
    for row,previous in zip(data['case_results'],frozen['case_results']):
        assert row['control']==previous['control']
        assert row['upstream_output_row_unchanged'] is True
        assert row['upstream_output_row_sha256']==graph.digest(previous)
        assert row['aid_searches']==SEARCHES
        assert row['local_string_gate']==LOCAL_GATE and row['registry_guard_gate']==REGISTRY_GATE
        assert row['native_comparison_bytecodes']==[item['bytecode'] for item in BRANCHES]
        assert row['taken_branches']==BRANCHES and row['status_stores']==STATUSES
        assert row['output_keys']==['X-Neptune'] and row['serialized_sha256']==previous['serialized_sha256']


def build(path,libc,*,on_case=None):
    data=dict(schema='vm9-native-171-diagnostic-gates-20261118-v1',
        provenance=dict(Metasec_sha256=graph.inputs.SHA256,Bionic_sha256=graph.inputs.LIBC_SHA256,
            upstream='vm9_native_171_output_20261118.json',fixture_URL_sha256=hashlib.sha256(graph.inputs.URL).hexdigest()),
        claims=CLAIMS,providers=PROVIDERS,
        instructions=[dict(offset=hex(a),mnemonic=m,operands=s) for a,m,s in EXPECTED],
        bytecode_words={hex(a):hex(w) for a,w in WORDS.items()},case_results=[])
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
        else:raise AssertionError('damaged diagnostic gate evidence accepted: '+str(path))
    for key,value in CLAIMS.items():reject(('claims',key),not value)
    reject(('provenance','fixture_URL_sha256'),'0'*64)
    reject(('providers','observers_read_only'),False)
    reject(('instructions',0,'mnemonic'),'ldr')
    reject(('bytecode_words','0xfc5cc'),'0x0')
    for i in range(len(data['case_results'])):
        p=('case_results',i)
        for path,value in ((('upstream_output_row_unchanged',),False),(('upstream_output_row_sha256',),'0'*64),
            (('aid_searches',0,'pattern'),'aid'),(('aid_searches',1,'result_u32'),0),
            (('aid_searches',0,'source_length'),1),(('local_string_gate','frame_offset'),4720),
            (('local_string_gate','value'),1),(('registry_guard_gate','source_image_offset'),'0x3d1550'),
            (('registry_guard_gate','raw_byte'),0),(('registry_guard_gate','masked_result'),0),
            (('native_comparison_bytecodes',),[]),(('output_keys',),[]),(('serialized_sha256',),'0'*64)):
            reject(p+path,value)
        for n in range(3):
            reject(p+('taken_branches',n,'taken'),False)
            reject(p+('taken_branches',n,'target'),'0x0')
        for n in range(2):
            reject(p+('status_stores',n,'native_value'),0)
            reject(p+('status_stores',n,'store_completed'),False)
            reject(p+('status_stores',n,'destination_slot'),0)
    return count


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--elf',type=Path);ap.add_argument('--libc',type=Path);ap.add_argument('--replay',action='store_true')
    args=ap.parse_args()
    if args.replay and (not args.elf or not args.libc):ap.error('--replay requires --elf and --libc')
    data=json.loads(EVIDENCE.read_text(encoding='utf-8'));validate(data)
    result=dict(retained_gate_cases=len(data['case_results']),damaged_evidence_rejected=negatives(data),
        business_state_restored=False,ordinary_Cronet_six_headers_verified=False)
    if args.elf:result['Metasec_bindings']=verify_elf(data,args.elf)
    if args.libc:graph.inputs.libc_image(args.libc);result['matching_Bionic_digest_verified']=True
    if args.replay:
        assert replay(args.elf,args.libc)==data['case_results'],'frozen diagnostic gate replay differs'
        result['original_code_cases_replayed']=len(data['case_results'])
    print(json.dumps(result))


if __name__=='__main__':main()
