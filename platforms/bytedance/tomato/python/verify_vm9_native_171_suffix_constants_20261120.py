"""Original current suffix entry and lazy constants, before string construction.

Fresh component pages cover every combination of the three initialization
flags. They execute the constant prefix extracted from the existing suffix
owner, never a second decoder or a model seeded by current native memory.
"""
from __future__ import annotations
import argparse
import ast
from copy import deepcopy
import hashlib
import inspect
import json
from pathlib import Path
from unicorn import arm64_const as arm
import verify_vm9_native_171_configuration_suffix_call_20261120 as previous
import vm9_request_transform as owner
from vm9_allocator import _PageTransaction, _read_span

context,graph,fixture=previous.context,previous.graph,previous.fixture
EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_suffix_constants_20261120.json')
STOP=0x286CE8
# The spans include each destination's padding and its four-byte flag.
WINDOWS=((0x3E0FF0,24,0x3E1004),(0x3E1008,8,0x3E100C),(0x3E1010,16,0x3E101C))
SOURCES_AND_MASKS=((0xFFBD0,0x100750),(0xFFBE4,0x100748),(0xFFBE8,0x10073C))
CALLS=(0x286AF0,0x286C10,0x286CD0)
FLAG_STORES=(0x286B00,0x286C24,0x286CE4)
EXPECTED=[(previous.WRAPPER,'ldp','x1, x8, [x0]'),(previous.TARGET,'stp','x29, x30, [sp, #-0x60]!'),
    (0x286AC4,'ldar','w8, [x8]'),(CALLS[0],'bl','#0x167e54'),(FLAG_STORES[0],'stlr','w9, [x8]'),
    (0x286B6C,'ldar','w8, [x8]'),(CALLS[1],'bl','#0x167e54'),(FLAG_STORES[1],'stlr','w9, [x8]'),
    (0x286C94,'ldar','w10, [x10]'),(CALLS[2],'bl','#0x167e54'),(FLAG_STORES[2],'stlr','w9, [x8]'),
    (STOP,'sub','x21, sp, #0x20'),(0x286DAC,'bl','#0x248344')]
CLAIMS=dict(retained_suffix_call_instruction_code_allocation_prefix_verified=True,
    completed_call_observer_retired=True,original_scope_kept=True,original_suffix_wrapper_and_body_entered=True,
    three_original_lazy_decoders_and_release_stores_verified=True,current_input_and_old_state_preserved=True,
    no_new_allocation_service_JNI_or_SVC=True,all_eight_declared_flag_combinations_at_two_bases_verified=True,
    existing_suffix_owner_source_prefix_executed=True,full_component_guest_and_image_bytes_equal=True,
    native_memory_used_as_Python_model_input=False,current_string_constructor_entered=False,
    current_native_suffix_return_verified=False,current_request_numeric_Python_equality_verified=False,
    complete_configuration_provenance_verified=False,ordinary_Cronet_six_headers_verified=False,
    complete_standalone_signer_verified=False,online_acceptance_verified=False,new_providers=False,Android_execution=False)


def model_prefix(pages,base):
    """Execute only the existing owner's selector/constant source statements."""
    function,=ast.parse(inspect.getsource(owner.construct_request_suffix)).body
    begin=next(i for i,n in enumerate(function.body) if isinstance(n,ast.FunctionDef) and n.name=='u')
    end=next(i for i,n in enumerate(function.body) if isinstance(n,ast.Assign)
        and isinstance(n.targets[0],ast.Name) and n.targets[0].id=='timestamp')
    nodes=function.body[begin:end]
    assert [n.name for n in nodes if isinstance(n,ast.FunctionDef)]==['u','w','selector']
    assert len([n for n in nodes if isinstance(n,ast.For)])==1 and not any(isinstance(n,ast.Call)
        and isinstance(n.func,ast.Name) and n.func.id in ('allocate','free') for n in ast.walk(ast.Module(body=nodes,type_ignores=[])))
    transaction=_PageTransaction(pages)
    namespace=dict(vars(owner),p=transaction,image_base=base,max_bytes=0x100000)
    exec(compile(ast.Module(body=nodes,type_ignores=[]),owner.__file__,'exec'),namespace)
    select=namespace['selector']
    layout=[dict(source=select(s),destination=select(d),mask=select(k),flag=select(f))
        for f,s,d,k in ((0x18,0x20,0,0x28),(0x30,0x38,8,0x40),(0x48,0x50,16,0x58))]
    assert [(r['destination']-base,r['flag']-base) for r in layout]==[(a,f) for a,n,f in WINDOWS]
    assert [(r['source']-base,r['mask']-base) for r in layout]==list(SOURCES_AND_MASKS)
    transaction.commit()
    return layout


def independent_controls(path):
    rows=[]
    for base in graph.BASES:
        for flags in range(8):
            native_pages=fixture.fresh(path,base,'length_7')
            for i,(a,n,f) in enumerate(WINDOWS):
                fixture._write_span(native_pages,base+f,((flags>>i)&1).to_bytes(4,'little'))
                if flags>>i&1:fixture._write_span(native_pages,base+a,(b'fixture\0',b'Q\0',b'marker\0')[i])
            model_pages={a:bytearray(b) for a,b in native_pages.items()}
            layout=model_prefix(model_pages,base)
            observed={(page<<12,4096):None for page in native_pages if base<=page<<12<base+0x400000}
            decoders=[]
            def watch(cpu,pc):
                if pc==base+0x167E54:
                    decoders.append([cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(3)])
            _,memory,_,_=fixture.oracle.native(path,base,previous.TARGET,[fixture.OBJ],native_pages,
                extra_registers={arm.UC_ARM64_REG_TPIDR_EL0:fixture.dependency.TP},
                observed_memory=observed,instruction_observer=watch,stop_offset=STOP,instruction_limit=5000)
            assert memory==_read_span(model_pages,fixture.G,0xA000)
            for (a,n),data in observed.items():assert _read_span(model_pages,a,n)==data
            assert decoders==[[r[k] for k in ('source','destination','mask')]
                for i,r in enumerate(layout) if not flags>>i&1]
            rows.append(dict(image_base=hex(base),declared_warm_flags=flags,original_decoders=3-flags.bit_count(),
                original_stopped_before=hex(STOP),existing_owner_prefix_executed=True,
                complete_semantic_guest_and_image_bytes_equal=True,native_snapshot_input=False))
    return rows


def providers():
    return dict(inherited_suffix_call=previous.providers(),maximum_handler_reads=2,maximum_main_SVCs=4,
        public_trace_limit=400000,new_providers=[],retired_completed_observation_windows=['suffix_call_active'],
        independent_owner='vm9_request_transform.py:construct_request_suffix constant prefix',
        independent_fixture='verify_vm9_request_suffix_fresh_20261013.py',component_instruction_limit=5000)


class Scenario(previous.Scenario):
    def __init__(self,c):
        super().__init__(c);self.constants_active=False;self.constants_done=False
        self.constants_entries=[];self.constants_decoders=[];self.constants_stores=[]

    def native_runner(self,*args,**kwargs):
        original=kwargs['memory_write_observer']
        def write(cpu,address,size):
            if self.constants_active:
                for i,(a,n,f) in enumerate(WINDOWS):
                    if address==self.image+f:
                        assert size==4 and cpu.reg_read(arm.UC_ARM64_REG_PC)==self.image+FLAG_STORES[i]
                        assert cpu.reg_read(arm.UC_ARM64_REG_X9)==1
                        self.constants_stores.append(hex(f))
            original(cpu,address,size)
        kwargs['memory_write_observer']=write
        return super().native_runner(*args,**kwargs)

    def suffix_call_boundary(self,cpu,state):
        data=json.loads(previous.EVIDENCE.read_text());previous.validate(data)
        old=next(r for r in data['case_results'] if r['control']==self.control)
        prefix=state['configuration_suffix_call_prefix']
        for k in ('instruction_observations','trace_sha256','code_sha256'):assert prefix[k]==old['continuation_'+k]
        for k in ('JNI_calls','libc_SVC_boundaries','main_image_SVC_boundaries'):assert prefix[k]==old[k]
        assert self.suffix_call_done and self.suffix_call_active and self.original_scope
        assert self.suffix_call_steps==old['executed_bytecodes'] and self.suffix_call_loads==old['native_loads']
        assert self.suffix_call_writes==old['native_stores']
        assert graph.digest(state['allocator_events_ref'])==old['allocation_ledger_sha256']
        raw=lambda a,n:bytes(cpu.mem_read(a,n))
        self.constants_before_frame=raw(self.scope_frame,0x2000)
        self.constants_before_allocations=deepcopy(state['allocator_events_ref'])
        self.constants_preserved={a:raw(a,len(b)) for a,b in self.suffix_call_preserved.items()}
        self.constants_tp=cpu.reg_read(arm.UC_ARM64_REG_TPIDR_EL0)
        self.constants_canary=raw(self.constants_tp+0x28,8)
        # Independent ELF pages establish constant-only expectations. Current
        # frame, headers, scalar, pointers and heap never become model inputs.
        pages=fixture.fresh(self.path,self.image,'length_7')
        for a,n,f in WINDOWS:assert raw(self.image+a,n)==_read_span(pages,self.image+a,n)
        assert raw(self.image+0x383540,0x80)==_read_span(pages,self.image+0x383540,0x80)
        self.constants_layout=model_prefix(pages,self.image)
        self.constants_expected={a:_read_span(pages,self.image+a,n) for a,n,f in WINDOWS}
        self.suffix_call_active=False;self.constants_active=True

    def observe(self,cpu,pc,state):
        self.scope_state=state
        if not self.constants_active:
            super().observe(cpu,pc,state)
            if not self.constants_active:return
        off=pc-self.image
        raw=lambda a,n:bytes(cpu.mem_read(a,n))
        u=lambda a:int.from_bytes(raw(a,8),'little')
        reg=lambda n:cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(n)))
        assert u(state['PC_slot'])==self.image+previous.CALL
        if off in (previous.WRAPPER,previous.TARGET):
            self.constants_entries.append(hex(off))
            assert reg(0)==self.scope_frame+(2752 if off==previous.WRAPPER else 2088)
        if off==0x167E54:
            i=len(self.constants_decoders);r=self.constants_layout[i]
            assert [reg(j) for j in range(3)]==[r[k] for k in ('source','destination','mask')]
            assert reg(30)==self.image+CALLS[i]+4
            self.constants_decoders.append(dict(call=hex(CALLS[i]),source=hex(r['source']-self.image),
                destination=hex(r['destination']-self.image),mask=hex(r['mask']-self.image)))
        if off in (0x248344,context.LOAD,0x27E6AC,0x27ED6C):raise AssertionError('unexpected post-constant execution')
        if off==STOP:
            assert self.constants_entries==[hex(previous.WRAPPER),hex(previous.TARGET)]
            assert len(self.constants_decoders)==3 and self.constants_stores==[hex(f) for a,n,f in WINDOWS]
            for a,b in self.constants_expected.items():assert raw(self.image+a,len(b))==b
            assert reg(26)==self.scope_frame+2088 and reg(1)==self.image+WINDOWS[0][0]
            fp=cpu.reg_read(arm.UC_ARM64_REG_FP)
            assert raw(fp-8,8)==self.constants_canary and u(fp-0x18)==self.constants_tp
            assert u(fp-0x20)==self.image+WINDOWS[1][0]
            assert raw(self.constants_tp+0x28,8)==self.constants_canary
            assert raw(self.scope_frame,0x2000)==self.constants_before_frame
            for a,b in self.constants_preserved.items():assert raw(a,len(b))==b
            assert state['allocator_events_ref']==self.constants_before_allocations and self.original_scope
            self.constants_done=True;self.constants_boundary(cpu,state)

    def constants_boundary(self,cpu,state):
        cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,context.outer.oracle.STOP)

    def finish(self,result,state,proof):
        old=next(r for r in json.loads(previous.EVIDENCE.read_text())['case_results'] if r['control']==self.control)
        prefix=proof['configuration_suffix_call_prefix']
        assert self.constants_done and result['allocator_events']==self.constants_before_allocations
        assert result['actual_allocator_counts']==old['allocator_counts'] and result['explicit_service_counts']==old['service_counts']
        for k in ('JNI_calls','libc_SVC_boundaries','main_image_SVC_boundaries'):assert proof[k]==old[k]
        return dict(control=self.control,retained_suffix_call_prefix_verified=True,
            retained_prefix_instruction_observations=prefix['instruction_observations'],retained_prefix_trace_sha256=prefix['trace_sha256'],
            retained_prefix_code_sha256=prefix['code_sha256'],retired_completed_observers=['suffix_call_active'],original_scope_kept=True,
            original_entries=self.constants_entries,original_decoders=self.constants_decoders,release_flag_stores=self.constants_stores,
            constants_equal_independent_existing_owner=True,input_and_old_frame_TLS_heap_preserved=True,
            allocation_ledger_sha256=old['allocation_ledger_sha256'],allocator_counts=old['allocator_counts'],service_counts=old['service_counts'],
            JNI_calls=proof['JNI_calls'],libc_SVC_boundaries=proof['libc_SVC_boundaries'],main_image_SVC_boundaries=proof['main_image_SVC_boundaries'],
            continuation_instruction_observations=proof['instruction_observations'],continuation_trace_sha256=proof['trace_sha256'],
            continuation_code_sha256=proof['code_sha256'],observation_stop_before=hex(STOP),outer_bytecode=hex(previous.CALL),
            current_string_constructor_entered=False,current_native_suffix_return_verified=False)


def replay(path,libc,*,case_controls=None):
    def create(c):
        s=Scenario(c);s.path=path;return s
    return context.replay(path,libc,case_controls=case_controls,_extension_factory=create,
        _request_profile=previous.name.previous.previous.PROFILE['name'],_handler_read_profile=context.NULL_PAYLOAD_READ_PROFILE['name'])


def verify_images(path,libc):
    from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
    previous.verify_images({},path,libc);_,_,read=graph.inputs.load_elf(path)
    decoder=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
    for a,m,s in EXPECTED:
        ins,=decoder.disasm(read(a,4),a);assert (ins.mnemonic,ins.op_str)==(m,s)
    return dict(instruction_bindings=len(EXPECTED),fresh_declared_flag_combinations=16)


def validate(data):
    assert data['schema']=='vm9-native-171-suffix-constants-20261120-v1' and data['claims']==CLAIMS and data['providers']==providers()
    assert data['instructions']==[dict(offset=hex(a),mnemonic=m,operands=s) for a,m,s in EXPECTED]
    assert data['suffix_owner_source_sha256']==hashlib.sha256(Path(owner.__file__).read_bytes()).hexdigest()
    expected=[dict(image_base=hex(b),declared_warm_flags=f,original_decoders=3-f.bit_count(),original_stopped_before=hex(STOP),
        existing_owner_prefix_executed=True,complete_semantic_guest_and_image_bytes_equal=True,native_snapshot_input=False)
        for b in graph.BASES for f in range(8)]
    assert data['independent_projection']==expected
    before=json.loads(previous.EVIDENCE.read_text());previous.validate(before)
    assert data['provenance']==before['provenance'] and len(data['case_results'])==len(before['case_results'])
    for row,old in zip(data['case_results'],before['case_results']):
        assert row['control']==old['control'] and row['retained_suffix_call_prefix_verified'] is True
        for k in ('instruction_observations','trace_sha256','code_sha256'):assert row['retained_prefix_'+k]==old['continuation_'+k]
        assert row['retired_completed_observers']==['suffix_call_active'] and row['original_scope_kept'] is True
        assert row['original_entries']==[hex(previous.WRAPPER),hex(previous.TARGET)]
        assert row['original_decoders']==[dict(call=hex(call),source=hex(s),destination=hex(a),mask=hex(k))
            for call,(a,n,f),(s,k) in zip(CALLS,WINDOWS,SOURCES_AND_MASKS)]
        assert row['release_flag_stores']==[hex(f) for a,n,f in WINDOWS]
        for k in ('constants_equal_independent_existing_owner','input_and_old_frame_TLS_heap_preserved'):assert row[k] is True
        for k in ('allocation_ledger_sha256','allocator_counts','service_counts','JNI_calls','libc_SVC_boundaries','main_image_SVC_boundaries'):assert row[k]==old[k]
        assert old['continuation_instruction_observations']<row['continuation_instruction_observations']<400000
        for k in ('continuation_trace_sha256','continuation_code_sha256'):assert graph.inputs.is_digest(row[k])
        assert row['observation_stop_before']==hex(STOP) and row['outer_bytecode']==hex(previous.CALL)
        assert row['current_string_constructor_entered'] is False and row['current_native_suffix_return_verified'] is False


def negatives(data):
    paths=[(('claims',k),not v) for k,v in CLAIMS.items()]
    paths.extend([(('providers','public_trace_limit'),750000),(('providers','maximum_handler_reads'),3),
        (('providers','maximum_main_SVCs'),5),(('suffix_owner_source_sha256',),'0'*64),
        (('instructions',0,'mnemonic'),'nop'),(('independent_projection',0,'native_snapshot_input'),True)])
    for i,row in enumerate(data['case_results']):
        for key in row:
            if key=='control':value={}
            elif isinstance(row[key],bool):value=not row[key]
            elif isinstance(row[key],list):value=[]
            elif isinstance(row[key],dict):value={}
            elif isinstance(row[key],int):value=400000
            else:value='bad'
            paths.append((('case_results',i,key),value))
    for path,value in paths:
        bad=deepcopy(data);target=bad
        for k in path[:-1]:target=target[k]
        target[path[-1]]=value
        try:validate(bad)
        except (AssertionError,KeyError,ValueError,TypeError):pass
        else:raise AssertionError('damaged suffix constants evidence accepted: '+str(path))
    return len(paths)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--elf',type=Path);ap.add_argument('--libc',type=Path);ap.add_argument('--replay',action='store_true')
    args=ap.parse_args()
    if args.replay and (not args.elf or not args.libc):ap.error('--replay requires --elf and --libc')
    data=json.loads(EVIDENCE.read_text());validate(data)
    result=dict(retained_suffix_constants_cases=len(data['case_results']),damaged_evidence_rejected=negatives(data),
        current_native_suffix_return_verified=False,ordinary_Cronet_six_headers_verified=False,complete_standalone_signer_verified=False)
    if args.elf:result['image_bindings']=verify_images(args.elf,args.libc)
    elif args.libc:graph.inputs.libc_image(args.libc)
    if args.replay:
        assert independent_controls(args.elf)==data['independent_projection']
        assert replay(args.elf,args.libc)==data['case_results']
        result.update(original_code_cases_replayed=4,fresh_declared_native_constant_controls_replayed=16)
    print(json.dumps(result))


if __name__=='__main__':main()
