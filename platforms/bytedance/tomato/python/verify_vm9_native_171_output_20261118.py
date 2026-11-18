"""Original constructed 0x171 callback return, diagnostic output and cleanup.

The accepted NULL JNI scenarios continue naturally to the ordinary wrapper's
RET. Duplicate insertion retains the first key and replaces its value; the
second key and first value are released. This is not six-header signing.
No native return, output tree or serialized bytes initialize a Python model.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from unicorn import arm64_const as arm

import verify_vm9_native_171_context_load_20261118 as context
import verify_vm9_request_output_reference_20261026 as output

graph=context.graph
EVIDENCE=context.EVIDENCE.with_name('vm9_native_171_output_20261118.json')
WORDS={0xFAE48:0x93500E18,0xFAE4C:0x10820418,0xFAE64:0x067E0C91,
       0xFC520:0x067E0C91,0xFC5AC:0x067E0C91,0xFEF94:0x7EA0F97B,
       0xFEFBC:0x067E0C91,0xFF048:0x067E0C91}
EXPECTED=[(0x282A68,'ldrb','w0, [x0, #0x52]'),(0x282A6C,'ret',''),
          (0x285C48,'blr','x8'),(0x285C4C,'and','w8, w0, #1'),
          (0x285C50,'strb','w8, [x19, #0x10]'),
          (0x27ED34,'bl','#0x27f84c'),(0x27ED38,'mov','x21, x0'),
          (0x27ED60,'mov','x0, x21'),(0x27ED6C,'ret',''),
          (0x16DB74,'str','x10, [x28, x15, lsl #3]'),
          (0x27E6AC,'sub','x1, x29, #0x58'),
          (0x2800FC,'stp','x29, x30, [sp, #-0x60]!'),
          (0x25BF3C,'sub','sp, sp, #0x80'),
          (0x248908,'stp','x29, x30, [sp, #-0x60]!')]
RELEVANT_CALLS=[dict(bytecode=hex(bc),wrapper=hex(wrapper),target=hex(target))
    for bc,wrapper,target in ((0xFAE64,0x285C3C,0x282A68),
        (0xFC520,0x285990,0x248908),(0xFC5AC,0x2859B8,0x25BF3C),
        (0xFEFBC,0x285990,0x248908),(0xFF048,0x2859B8,0x25BF3C))]
INSERTION_SEQUENCE=[dict(key='X-Neptune',signed_int32=signed,bytecode=callsite,
    formatter_text_length=8,value_length=length,value_sha256=digest)
    for signed,callsite,length,digest in (
        (-8,'0xfc5ac',11,'a1044d84eac2246ae4d65e06f16274e75fd0d79dd10871da2cceb6416f06b5d6'),
        (-11,'0xff048',12,'1bf206240310d9ae694302bf0f50d0a9d6c49f980a6d56f665ae874d2914702b'))]
OUTPUT_ALLOCATIONS=dict(counter=4,key0_buffer=10,key0_object=24,value0_buffer=16,
    value0_object=24,pair0=16,node0=40,sentinel=40,controller=40,container=40)
DISCARDED_ALLOCATIONS=dict(key_buffer=10,key_object=24,value_buffer=16,value_object=24)
SERIALIZED_SHA256='e3f893005b89e0a6feac1b8a1b7016a3bb7be514e4121884ad53d1e34497e00f'
CLAIMS=dict(original_callback_return_and_one_node_output_verified=True,
    original_serialization_and_ordinary_RET_verified=True,
    duplicate_X_Neptune_insertion_replaces_minus_8_with_minus_11=True,
    discarded_value_and_duplicate_key_lifetimes_verified=True,
    output_tree_allocation_epochs_and_free_calls_verified=True,
    returned_CString_is_live_caller_owned_allocation=True,
    native_diagnostic_status_minus_11_observed=True,
    successful_six_header_signing_verified=False,whole_request_native_Python_differential_verified=False,
    full_handler_or_live_Java_identity_verified=False,complete_standalone_signer_verified=False,
    Android_execution=False,online_acceptance_verified=False)
PROVIDERS=dict(inherited_context_profile=context.PROVIDERS,
    inherited_stop_description_applies_to='upstream default prefix only; extension continues naturally',
    new_OS_JNI_or_internal_helper_providers=[],original_ordinary_wrapper_RET=True,
    observation_sentinel_PC_rewrite=False,
    output_observer_owner='verify_vm9_request_output_reference_20261026.py:_tree,_string,_cstring',
    scope='synthetic constructed ordinary 0x171 NULL-JNI diagnostic output')


class Scenario:
    def __init__(self,control):
        self.control=control;self.image=control['base'];self.steps=0
        self.active=False;self.callback_done=False
        self.formats=[];self.insertions=[];self.root_calls=[];self.status=[]
        self.tracked={};self.frees=[];self.flag=[];self.serializer=[]
        self.discarded={};self.discarded_frees=[]

    def member_boundary(self,cpu,state,proof):
        self.member_prefix=proof

    def native_runner(self,*args,**kwargs):
        result=context.outer.oracle.native(*args,**kwargs)
        self.native_return=result[0]
        return result

    def observe(self,cpu,pc,state):
        image=self.image;offset=pc-image;self.steps+=1
        def reg(name):return cpu.reg_read(getattr(arm,'UC_ARM64_REG_'+name.upper()))
        def u(address,size=8):return int.from_bytes(cpu.mem_read(address,size),'little')
        def cursor():return u(state['PC_slot'])-image
        if offset==graph.CALLBACK:
            self.active=True;self.output_slot=reg('x8')
        if offset==0x282A68 and self.active and not self.callback_done:
            assert reg('x0')==state['expected_payload']
            assert u(reg('x0')+0x52,1)==1
            self.flag.append(dict(pc='0x282a68',member_offset='0x52',byte=1,bytecode=hex(cursor())))
            self.flag_pending=True
        if offset==0x282A6C and self.flag:
            assert reg('x0')==1
        if offset==0x285C54 and getattr(self,'flag_pending',False):
            assert u(reg('x19')+16,1)==1
            self.packed_flag_is_one=True
            self.flag_pending=False
        if self.active and not self.callback_done and 'backing' in state and reg('x28')==state['backing']:
            if offset==0x16AA48:
                argument=reg('x0')
                self.root_calls.append(dict(bytecode=hex(cursor()),wrapper=hex(reg('x8')-image),
                                            target=hex(u(argument)-image)))
            if offset==0x16DB74 and cursor()==0xFEF94:
                assert u(state['backing'])==0
                assert reg('x10')==(1<<64)-11
                self.status.append(dict(bytecode='0xfef94',word='0x7ea0f97b',source_R0=0,
                                        signed_immediate=-11,native_value=-11))
        if state['store_verified'] and self.active and not self.callback_done and offset==0x248908:
            fmt=output._cstring(cpu,reg('x1'))
            if fmt==b'%d|%s':
                value=reg('x2')&0xFFFFFFFF
                signed=value-(1<<32) if value&(1<<31) else value
                text=output._cstring(cpu,reg('x3'))
                self.formats.append(dict(object_address=reg('x0'),signed=signed,text=text))
        if state['store_verified'] and self.active and not self.callback_done and offset==0x25BF3C:
            if u(reg('x1'))!=image+0x34F5F8 or u(reg('x2'))!=image+0x34F5F8:
                return
            key,raw_key=output._string(cpu,reg('x1'),image)
            value,raw_value=output._string(cpu,reg('x2'),image)
            self.insertions.append(dict(container=reg('x0'),key=key,value=value,
                                        raw_key=raw_key,raw_value=raw_value,bytecode=hex(cursor())))
            if raw_key==b'X-Neptune':
                # First value is replaced; duplicate key is discarded. The
                # original key and second value survive in the final tree.
                kind,record=('value',value) if not self.discarded else ('key',key)
                assert kind+'_object' not in self.discarded
                addresses={f'{kind}_{part}':int(record[field],16)
                           for part,field in (('object','object_address'),('buffer','payload_address'))}
                self._track_allocations(state,addresses,self.discarded)
        if offset==0x27E6AC:
            assert self.active and not self.callback_done
            self.callback_done=True
            self.tree,self.keys=output._tree(cpu,self.output_slot,image)
            assert self.tree['node_count']==1 and self.keys==[b'X-Neptune']
            assert len(self.discarded)==4 and all(block.get('freed') for block in self.discarded.values())
            self._track_tree(state)
        if offset==0x2800FC:
            assert self.callback_done
            self.serializer.append(dict(pc='0x2800fc',x0=reg('x0'),x1=reg('x1')))
        if offset==0x347FA0:
            address=reg('x0')
            for blocks,frees in ((self.discarded,self.discarded_frees),(self.tracked,self.frees)):
                for label,block in blocks.items():
                    if block['address']==address and not block.get('freed'):
                        block['freed']=True
                        frees.append(dict(label=label,size=block['size'],ordinal=self.steps))
        if offset==0x27ED6C:
            assert self.callback_done and len(self.serializer)==1
            self.return_pointer=reg('x0')
            self.raw_output=output._cstring(cpu,self.return_pointer)
            self.tree_objects_freed_before_RET=all(block.get('freed') for block in self.tracked.values())
            assert self.tree_objects_freed_before_RET

    def _track_tree(self,state):
        tree=self.tree
        addresses={name:int(tree[name+'_address'],16) for name in ('container','counter','controller','sentinel')}
        for index,node in enumerate(tree['nodes']):
            addresses.update({f'node{index}':int(node['node_address'],16),
                              f'pair{index}':int(node['pair_address'],16)})
            for kind in ('key','value'):
                addresses[f'{kind}{index}_object']=int(node[kind]['object_address'],16)
                addresses[f'{kind}{index}_buffer']=int(node[kind]['payload_address'],16)
        self._track_allocations(state,addresses,self.tracked)

    def _track_allocations(self,state,addresses,blocks):
        assert len(set(addresses.values()))==len(addresses)
        for label,address in addresses.items():
            events=[(index,event) for index,event in enumerate(state['allocator_events_ref'])
                    if (event[0]=='alloc' and event[2]==address) or (event[0]=='free' and event[1]==address)]
            epoch,event=events[-1]
            assert event[0]=='alloc'
            blocks[label]=dict(address=address,size=event[1],allocation_epoch=epoch)

    def finish(self,result,state,proof):
        assert self.native_return==self.return_pointer and self.return_pointer
        assert len(self.status)==1
        node=self.tree['nodes'][0]
        insertions=[item for item in self.insertions if item['container']==int(self.tree['container_address'],16)]
        assert len(insertions)==2
        sequence=[]
        for insertion,signed,callsite in zip(insertions,(-8,-11),('0xfc5ac','0xff048')):
            formats=[item for item in self.formats if item['object_address']==int(insertion['value']['object_address'],16)]
            assert len(formats)==1
            fmt=formats[0]
            expected=str(signed).encode()+b'|'+fmt['text']
            assert fmt['signed']==signed and insertion['raw_value']==expected
            assert insertion['raw_key']==b'X-Neptune' and insertion['bytecode']==callsite
            sequence.append(dict(key='X-Neptune',signed_int32=signed,bytecode=callsite,
                formatter_text_length=len(fmt['text']),value_length=len(expected),
                value_sha256=hashlib.sha256(expected).hexdigest()))
        insertion=insertions[-1]
        assert insertions[0]['key']==node['key'] and insertion['value']==node['value']
        assert insertion['key']['object_address']!=node['key']['object_address']
        assert insertion['container']==int(self.tree['container_address'],16)
        assert fmt['object_address']==int(node['value']['object_address'],16) and fmt['signed']==-11
        expected=str(fmt['signed']).encode()+b'|'+fmt['text']
        assert insertion['raw_value']==expected
        assert self.raw_output==b'X-Neptune\r\n'+expected+b'\r\n'
        assert self.packed_flag_is_one and len(self.flag)==1 and self.tree_objects_freed_before_RET
        events=result['allocator_events']
        lifetimes={}
        for group,blocks in (('discarded',self.discarded),('output',self.tracked)):
            for label,block in blocks.items():
                tail=[(index,event) for index,event in enumerate(events) if index>block['allocation_epoch']
                      and ((event[0]=='free' and event[1]==block['address']) or
                           (event[0]=='alloc' and event[2]==block['address']))]
                free_epoch,event=tail[0]
                assert event[0]=='free' and block['freed'],label
                lifetimes[group+'_'+label]=dict(size=block['size'],allocation_epoch=block['allocation_epoch'],
                                               free_epoch=free_epoch)
        assert max(item['ordinal'] for item in self.discarded_frees)<min(item['ordinal'] for item in self.frees)
        output_events=[event for event in events if (event[0]=='alloc' and event[2]==self.return_pointer)
                       or (event[0]=='free' and event[1]==self.return_pointer)]
        assert output_events[-1][0]=='alloc' and output_events[-1][1]>len(self.raw_output)
        return dict(control=self.control,ordinary_wrapper_returned=True,callback_returned=True,
            original_outer_postconditions_passed=True,observation_PC_rewritten=False,
            member_prefix=self.member_prefix,first_context_read=proof['context_reads'][0],
            JNI_calls=proof['JNI_calls'],evaluator_returns=proof['evaluator_returns'],
            flag_reads=self.flag,packed_flag_boolean=1,status_origin=self.status[0],
            insertion_sequence=sequence,final_tree_has_last_value_and_original_key=True,
            discarded_strings_freed_before_callback_return=True,
            discarded_string_allocations={label:block['size'] for label,block in self.discarded.items()},
            discarded_string_free_order=[event['label'] for event in self.discarded_frees],
            tracked_allocation_lifetimes=lifetimes,
            formatter_signed_int32=-11,formatter_text_length=len(fmt['text']),
            output_tree_node_count=1,output_counter_at_callback_return=1,
            output_keys=['X-Neptune'],output_value_length=len(expected),
            output_value_sha256=hashlib.sha256(expected).hexdigest(),
            serialized_length=len(self.raw_output),serialized_sha256=hashlib.sha256(self.raw_output).hexdigest(),
            serializer_entries=1,serialized_equals_observed_tree=True,
            wrapper_RET_matches_native_return=True,serialized_buffer_live_and_caller_owned=True,
            serialized_allocation_size=output_events[-1][1],
            tracked_output_allocations={label:block['size'] for label,block in self.tracked.items()},
            tracked_output_blocks_freed_before_RET=len(self.frees),
            output_free_order=[event['label'] for event in self.frees],
            root_native_calls=self.root_calls,libc_SVC_boundaries=proof['libc_SVC_boundaries'],
            continuation_instruction_observations=proof['instruction_observations'],
            continuation_trace_sha256=proof['trace_sha256'],continuation_code_sha256=proof['code_sha256'],
            allocation_ledger_sha256=graph.digest(events),
            publication_ledger_sha256=graph.digest(result['publication_ledger']))


def replay(path,libc,*,on_case=None,case_controls=None):
    return context.replay(path,libc,on_case=on_case,case_controls=case_controls,_extension_factory=Scenario)


def verify_elf(data,path):
    from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
    upstream=json.loads(context.EVIDENCE.read_text());context.validate(upstream)
    prior=context.verify_elf(upstream,path)
    _,_,read=graph.inputs.load_elf(path);decoder=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
    for address,mnemonic,operands in EXPECTED:
        ins,=decoder.disasm(read(address,4),address)
        assert (ins.mnemonic,ins.op_str)==(mnemonic,operands),hex(address)
    for address,word in WORDS.items():assert int.from_bytes(read(address,4),'little')==word
    return dict(upstream=prior,additional_instructions=len(EXPECTED),additional_bytecode_words=len(WORDS))


def validate(data):
    assert data['schema']=='vm9-native-171-output-20261118-v1'
    assert data['provenance']==dict(Metasec_sha256=graph.inputs.SHA256,Bionic_sha256=graph.inputs.LIBC_SHA256,
        upstream='vm9_native_171_context_load_20261118.json')
    assert data['claims']==CLAIMS and data['providers']==PROVIDERS
    assert data['instructions']==[dict(offset=hex(a),mnemonic=m,operands=s) for a,m,s in EXPECTED]
    assert data['bytecode_words']=={hex(a):hex(w) for a,w in WORDS.items()}
    assert len(data['case_results'])==len(context.controls())
    upstream=json.loads(context.EVIDENCE.read_text(encoding='utf-8'));context.validate(upstream)
    for row,control,prefix in zip(data['case_results'],context.controls(),upstream['case_results']):
        assert row['control']==control
        for key in ('ordinary_wrapper_returned','callback_returned','original_outer_postconditions_passed',
                    'serialized_equals_observed_tree','wrapper_RET_matches_native_return','serialized_buffer_live_and_caller_owned',
                    'final_tree_has_last_value_and_original_key','discarded_strings_freed_before_callback_return'):
            assert row[key] is True
        assert row['member_prefix']==dict(instruction_observations=prefix['continuation_instruction_observations'],
            trace_sha256=prefix['continuation_trace_sha256'],code_sha256=prefix['continuation_code_sha256'])
        assert row['first_context_read']==prefix['first_observed_context_read']
        assert row['JNI_calls']==prefix['JNI_calls'] and row['evaluator_returns']==prefix['evaluator_returns']
        assert row['libc_SVC_boundaries']==prefix['libc_SVC_boundaries']
        assert row['continuation_instruction_observations']>prefix['continuation_instruction_observations']
        assert row['flag_reads']==[dict(pc='0x282a68',member_offset='0x52',byte=1,bytecode='0xfae64')]
        assert [call for call in row['root_native_calls'] if call['bytecode'] in
                {item['bytecode'] for item in RELEVANT_CALLS}]==RELEVANT_CALLS
        assert row['observation_PC_rewritten'] is False
        assert row['output_keys']==['X-Neptune'] and row['output_tree_node_count']==row['output_counter_at_callback_return']==1
        assert row['status_origin']==dict(bytecode='0xfef94',word='0x7ea0f97b',source_R0=0,signed_immediate=-11,native_value=-11)
        assert row['formatter_signed_int32']==-11 and row['formatter_text_length']==8
        assert row['insertion_sequence']==INSERTION_SEQUENCE
        assert row['output_value_sha256']==INSERTION_SEQUENCE[-1]['value_sha256']
        assert row['serialized_sha256']==SERIALIZED_SHA256
        assert row['packed_flag_boolean']==1 and row['serializer_entries']==1
        assert row['serialized_length']==25 and row['output_value_length']==12
        assert row['serialized_allocation_size']>row['serialized_length']
        assert row['tracked_output_blocks_freed_before_RET']==10
        assert row['tracked_output_allocations']==OUTPUT_ALLOCATIONS
        assert row['output_free_order']==list(OUTPUT_ALLOCATIONS)
        assert row['discarded_string_allocations']==DISCARDED_ALLOCATIONS
        assert row['discarded_string_free_order']==list(DISCARDED_ALLOCATIONS)
        expected_lifetimes={group+'_'+label:size for group,blocks in (('discarded',DISCARDED_ALLOCATIONS),('output',OUTPUT_ALLOCATIONS))
                            for label,size in blocks.items()}
        lifetimes=row['tracked_allocation_lifetimes']
        assert set(lifetimes)==set(expected_lifetimes)
        assert len({item['allocation_epoch'] for item in lifetimes.values()})==14
        assert len({item['free_epoch'] for item in lifetimes.values()})==14
        for label,size in expected_lifetimes.items():
            item=lifetimes[label]
            assert set(item)=={'size','allocation_epoch','free_epoch'} and item['size']==size
            assert isinstance(item['allocation_epoch'],int) and 0<=item['allocation_epoch']<item['free_epoch']
        for group,order in (('discarded',row['discarded_string_free_order']),('output',row['output_free_order'])):
            epochs=[lifetimes[group+'_'+label]['free_epoch'] for label in order]
            assert epochs==sorted(epochs)
        assert max(lifetimes['discarded_'+label]['free_epoch'] for label in DISCARDED_ALLOCATIONS)<min(
            lifetimes['output_'+label]['free_epoch'] for label in OUTPUT_ALLOCATIONS)
        for key in ('serialized_sha256','output_value_sha256','continuation_trace_sha256',
                    'continuation_code_sha256','allocation_ledger_sha256','publication_ledger_sha256'):
            assert graph.inputs.is_digest(row[key])


def build(path,libc,*,on_case=None):
    data=dict(schema='vm9-native-171-output-20261118-v1',
        provenance=dict(Metasec_sha256=graph.inputs.SHA256,Bionic_sha256=graph.inputs.LIBC_SHA256,
            upstream='vm9_native_171_context_load_20261118.json'),claims=CLAIMS,providers=PROVIDERS,
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
        else:raise AssertionError('damaged native output evidence accepted: '+str(path))
    for key,value in CLAIMS.items():
        reject(('claims',key),not value)
    reject(('provenance','Bionic_sha256'),'0'*64)
    reject(('providers','observation_sentinel_PC_rewrite'),True)
    reject(('instructions',0,'operands'),'w0, [x0, #0x51]')
    reject(('bytecode_words','0xfef94'),'0x0')
    for i in range(len(context.controls())):
        prefix=('case_results',i)
        for key,value in (('ordinary_wrapper_returned',False),('callback_returned',False),
                          ('original_outer_postconditions_passed',False),
                          ('serialized_equals_observed_tree',False),('observation_PC_rewritten',True),
                          ('tracked_output_blocks_freed_before_RET',0),('output_keys',[]),
                          ('formatter_signed_int32',0),('output_counter_at_callback_return',0),
                          ('final_tree_has_last_value_and_original_key',False),
                          ('discarded_strings_freed_before_callback_return',False),
                          ('wrapper_RET_matches_native_return',False),('serialized_buffer_live_and_caller_owned',False),
                          ('packed_flag_boolean',0),('serializer_entries',2),('serialized_length',24),
                          ('output_value_length',11),('serialized_allocation_size',25),
                          ('serialized_sha256','0'*64),('output_value_sha256','0'*64),
                          ('JNI_calls',[]),('evaluator_returns',[]),('libc_SVC_boundaries',[]),
                          ('flag_reads',[]),('output_free_order',[]),('discarded_string_free_order',[])):
            reject(prefix+(key,),value)
        reject(prefix+('member_prefix','trace_sha256'),'0'*64)
        reject(prefix+('first_context_read','member_offset'),'0x40')
        reject(prefix+('status_origin','source_R0'),1)
        reject(prefix+('insertion_sequence',0,'signed_int32'),-11)
        reject(prefix+('insertion_sequence',1,'value_sha256'),'0'*64)
        reject(prefix+('insertion_sequence',),list(reversed(INSERTION_SEQUENCE)))
        row=data['case_results'][i]
        call_index=next(n for n,call in enumerate(row['root_native_calls']) if call['bytecode']=='0xfefbc')
        reject(prefix+('root_native_calls',call_index,'target'),'0x0')
        for label,item in row['tracked_allocation_lifetimes'].items():
            reject(prefix+('tracked_allocation_lifetimes',label,'free_epoch'),item['allocation_epoch'])
        reject(prefix+('tracked_output_allocations','value0_buffer'),15)
        reject(prefix+('discarded_string_allocations','value_buffer'),15)
    return count


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--elf',type=Path);ap.add_argument('--libc',type=Path);ap.add_argument('--replay',action='store_true')
    args=ap.parse_args()
    if args.replay and (not args.elf or not args.libc):ap.error('--replay requires --elf and --libc')
    data=json.loads(EVIDENCE.read_text());validate(data)
    result=dict(retained_output_cases=len(context.controls()),damaged_evidence_rejected=negatives(data),
                successful_six_header_signing_verified=False)
    if args.elf:result['Metasec_bindings']=verify_elf(data,args.elf)
    if args.libc:graph.inputs.libc_image(args.libc);result['matching_Bionic_digest_verified']=True
    if args.replay:
        assert replay(args.elf,args.libc)==data['case_results'],'frozen native output replay differs'
        result['original_code_cases_replayed']=len(context.controls())
    print(json.dumps(result))


if __name__=='__main__':main()
