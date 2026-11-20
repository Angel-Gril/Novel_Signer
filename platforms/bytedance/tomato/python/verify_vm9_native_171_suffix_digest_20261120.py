"""Current suffix constant string, raw MD5 reference, assignment and release.

Independent component inputs execute the existing suffix owner's source
prefix against the original helper. Current native bytes only check native
instruction/object relations and never initialize the Python model.
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
import verify_vm9_native_171_suffix_constants_20261120 as previous
import vm9_diagnostics as diagnostics
from vm9_allocator import _read_span

context,graph,fixture,owner=previous.context,previous.graph,previous.fixture,previous.owner
EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_suffix_digest_20261120.json')
STOP=0x286E10
PROFILES=('length_0','length_7','length_32','mode_one','mode_one_short_constant','mode_all_bits','warm_constants','NULL_MD5_source')
EXPECTED=[(previous.STOP,'sub','x21, sp, #0x20'),(0x286D88,'ldr','x8, [x26]'),
    (0x286D90,'ldr','x9, [x26, #0x20]'),(0x286D94,'ldr','w20, [x26, #0x30]'),
    (0x286D9C,'ldp','x25, x8, [x26, #0x10]'),(0x286DA4,'ldr','x8, [x26, #0x28]'),
    (0x286DAC,'bl','#0x248344'),(0x286DB0,'cmp','w20, #1'),
    (0x286DF4,'bl','#0x25874c'),(0x286E00,'bl','#0x162620'),(0x286E08,'bl','#0x15e1a8'),
    (0x286E0C,'ldr','x24, [x26, #8]'),(STOP,'mov','x9, #0x1040')]
CALLS=(0x248344,0x25874C,0x162620,0x15E1A8)
CLAIMS=dict(retained_constants_instruction_code_allocation_prefix_verified=True,
    completed_constants_observer_retired=True,original_scope_kept=True,original_scratch_and_header_reads_verified=True,
    original_constant_string_constructed=True,original_mode0_raw_MD5_reference_constructed=True,
    original_reference_assignment_and_temporary_release_verified=True,current_count_two_then_one_verified=True,
    native_MD5_bytes_checked_as_native_object_contract=True,current_header_and_non_diagnostic_old_state_preserved=True,
    one_declared_diagnostic_table_slot_created=True,original_diagnostic_lock_events_balanced=True,
    exact_five_allocation_and_zero_free_delta_verified=True,no_new_service_JNI_or_SVC=True,
    sixteen_independent_original_and_existing_source_prefix_controls_verified=True,
    full_semantic_guest_image_and_selected_scratch_bytes_equal=True,ordered_ownership_effects_equal=True,
    native_memory_used_as_Python_model_input=False,current_numeric_Python_equality_verified=False,
    current_native_suffix_return_verified=False,complete_configuration_provenance_verified=False,
    ordinary_Cronet_six_headers_verified=False,online_acceptance_verified=False,complete_standalone_signer_verified=False,
    new_providers=False,Android_execution=False)


def source_prefix():
    function,=ast.parse(inspect.getsource(owner.construct_request_suffix)).body
    end=next(i for i,n in enumerate(function.body) if isinstance(n,ast.Assign)
        and isinstance(n.targets[0],ast.Name) and n.targets[0].id=='sized')
    assert isinstance(function.body[end-1],ast.If)
    function.name='suffix_digest_prefix'
    function.body=function.body[:end]+ast.parse('p.commit()\nreturn constant,md5ref,rawref,second').body
    namespace=dict(vars(owner));exec(compile(ast.Module(body=[function],type_ignores=[]),owner.__file__,'exec'),namespace)
    return namespace[function.name]


def independent_controls(path,libc):
    prefix=source_prefix();rows=[]
    for base in graph.BASES:
        for label in PROFILES:
            p=fixture.fresh(path,base,label);expected=fixture.dependency.Services();actual=fixture.dependency.Services()
            E=fixture.dependency.SP
            observed={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
            for a,n in ((E-0x110,24),(E-0x120,16)):
                observed[a,n]=None
            mode=fixture.dependency.u(p,fixture.OBJ+48,4)
            if mode!=1:observed[E-0x130,16]=None
            def watch(cpu,pc):
                off=pc-base
                if off in (0x347F00,0x347F10):expected.diagnostic('pthread_mutex_lock' if off==0x347F00 else 'pthread_mutex_unlock',cpu.reg_read(arm.UC_ARM64_REG_X0))
                if off==0x348310:expected.diagnostic('gettid',137)
            _,memory,_,_=fixture.oracle.native(path,base,previous.previous.TARGET,[fixture.OBJ],p,libc=libc,
                real_diagnostics=True,real_singletons=True,real_mutexes=True,real_recursive_mutexes=True,thread_id=137,
                extra_registers={arm.UC_ARM64_REG_TPIDR_EL0:fixture.dependency.TP},observed_memory=observed,
                host_imports={0x347FA0:expected.native_free,0x348320:lambda c:expected.effects.native(c,'realloc',c.reg_read(arm.UC_ARM64_REG_X1),c.reg_read(arm.UC_ARM64_REG_X0))},
                malloc_handler=expected.native_malloc,instruction_observer=watch,stop_offset=STOP,instruction_limit=30000)
            constant,reference,temporary,second=prefix(p,object_address=fixture.OBJ,entry_stack_address=E,
                image_base=base,thread_pointer=fixture.dependency.TP,allocate=actual.malloc,reallocate=actual.effects.realloc,
                free=actual.free,get_singleton=lambda q:fixture.fixture_owner.WRAPPER,parse_decimal=lambda q,a:0,
                thread_id=137,diagnostic_observer=actual.diagnostic)
            assert _read_span(p,fixture.G,0xA000)==memory
            for (a,n),data in observed.items():assert _read_span(p,a,n)==data,(hex(base),label,hex(a),n)
            assert actual.events==expected.events and actual.effects.calls==expected.effects.calls
            assert actual.effects.blocks==expected.effects.blocks and actual.freed==expected.freed
            assert (constant,reference,temporary)==(E-0x110,E-0x120,E-0x130)
            assert second==(constant if mode==1 else fixture.dependency.u(p,fixture.OBJ+8))
            obj=fixture.dependency.u(p,reference);counter=fixture.dependency.u(p,reference+8)
            assert obj and counter and fixture.dependency.u(p,counter,4)==1
            rows.append(dict(image_base=hex(base),case=label,mode_is_one=mode==1,original_stopped_before=hex(STOP),
                existing_suffix_source_prefix_executed=True,complete_semantic_guest_image_and_selected_scratch_bytes_equal=True,
                ordered_effects_pre_free_payloads_and_live_blocks_equal=True,reference_count_one_verified=True,native_snapshot_input=False))
    return rows


def providers():
    return dict(inherited_constants=previous.providers(),maximum_handler_reads=2,maximum_main_SVCs=4,
        public_trace_limit=400000,retired_completed_observation_windows=['constants_active'],new_providers=[],
        independent_owner='vm9_request_transform.py:construct_request_suffix prefix through mode branch',
        independent_fixture='verify_vm9_request_suffix_fresh_20261013.py',component_instruction_limit=30000,
        current_native_input_used_only_for_native_relations=True,current_and_declared_numeric_values_compared=False)


class Scenario(previous.Scenario):
    def __init__(self,c):
        super().__init__(c);self.digest_active=False;self.digest_done=False;self.digest_calls=[]
        self.continue_to_svc=False;self.svc_boundary=None;self.digest_boundary_seen=False

    def stop_before_svc(self,cpu,pc,state):
        assert self.digest_boundary_seen and self.digest_done
        raw=lambda a,n:bytes(cpu.mem_read(a,n))
        u=lambda a,n=8:int.from_bytes(raw(a,n),'little')
        off=pc-self.image
        assert off in (0x271DBC,0x286EC8) and raw(pc,4)==bytes.fromhex('010000d4')
        regs={f'x{i}':hex(cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i)))) for i in range(12)}
        regs.update({f'x{i}':hex(cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i)))) for i in (24,25,26,29,30)})
        sp=cpu.reg_read(arm.UC_ARM64_REG_SP)
        stack=raw(sp,0x80)
        self.svc_boundary=dict(
            kind='first_unpermitted_main_image_svc' if off==0x271DBC else 'target_suffix_svc',
            pc_offset=hex(off),instruction=raw(pc,4).hex(),svc_number=cpu.reg_read(arm.UC_ARM64_REG_X8),
            svc_args=[hex(cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i)))) for i in range(4)],
            pc_slot=hex(state['PC_slot']),
            pc_slot_value=hex(u(state['PC_slot'])),registers=regs,sp=hex(sp),
            stack_window_offset='0x0',stack_window_size=len(stack),
            stack_window_sha256=hashlib.sha256(stack).hexdigest(),
            post_digest_instructions=[hex(x) for x in (0x286E10,0x286E74,0x286E84,0x286E98,0x286E9C,0x286EA4,0x286EC8)],
            native_memory_used_as_python_model_input=False)
        cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,context.outer.oracle.STOP)

    def pre_observe(self,cpu,pc,state):
        if self.continue_to_svc and self.digest_boundary_seen and pc-self.image in (0x271DBC,0x286EC8):
            self.stop_before_svc(cpu,pc,state)
            return True
        return False

    def constants_boundary(self,cpu,state):
        data=json.loads(previous.EVIDENCE.read_text());previous.validate(data)
        old=next(r for r in data['case_results'] if r['control']==self.control)
        prefix=state['suffix_constants_prefix']
        for k in ('instruction_observations','trace_sha256','code_sha256'):assert prefix[k]==old['continuation_'+k]
        for k in ('JNI_calls','libc_SVC_boundaries','main_image_SVC_boundaries'):assert prefix[k]==old[k]
        assert self.constants_done and self.constants_active and self.original_scope
        assert self.constants_entries==old['original_entries'] and self.constants_decoders==old['original_decoders']
        assert self.constants_stores==old['release_flag_stores']
        assert graph.digest(state['allocator_events_ref'])==old['allocation_ledger_sha256']
        raw=lambda a,n:bytes(cpu.mem_read(a,n));u=lambda a,n=8:int.from_bytes(raw(a,n),'little')
        self.digest_E=cpu.reg_read(arm.UC_ARM64_REG_FP)+0x60
        assert cpu.reg_read(arm.UC_ARM64_REG_SP)==self.digest_E-0xF0
        self.digest_frame_before=raw(self.scope_frame,0x2000)
        self.digest_header=self.scope_frame+2088
        self.digest_source=u(self.digest_header+16);self.digest_second=u(self.digest_header+8)
        assert u(self.digest_header+48,4)==0
        source_pointer=u(self.digest_source+16);source_length=u(self.digest_source+12,4)
        assert source_pointer and source_length<=0x100000
        # A relation inside the same native execution, never a model input.
        self.digest_expected_bytes=hashlib.md5(raw(source_pointer,source_length)).digest()
        self.digest_native_source_before=raw(self.digest_source,24),raw(source_pointer,source_length+1)
        self.digest_native_source_payload=source_pointer
        self.digest_allocations=deepcopy(state['allocator_events_ref'])
        self.digest_preserved={a:raw(a,len(b)) for a,b in self.constants_preserved.items()}
        self.digest_preserved.update({self.image+a:raw(self.image+a,n) for a,n,flag in previous.WINDOWS})
        self.digest_guard_before=raw(self.image+diagnostics.GUARD,8)
        self.digest_global_before=raw(self.copy_global,48)
        self.digest_guard_mutex_before=raw(self.image+diagnostics.GUARD_MUTEX,40)
        self.digest_lock_events=[]
        self.constants_active=False;self.digest_active=True

    def observe(self,cpu,pc,state):
        self.scope_state=state
        off=pc-self.image
        if self.continue_to_svc and self.digest_boundary_seen:
            return
        if not self.digest_active:
            super().observe(cpu,pc,state)
            if not self.digest_active:return
        off=pc-self.image;E=self.digest_E;f=self.scope_frame
        raw=lambda a,n:bytes(cpu.mem_read(a,n));u=lambda a,n=8:int.from_bytes(raw(a,n),'little')
        reg=lambda n:cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(n)))
        assert u(state['PC_slot'])==self.image+previous.previous.CALL
        if off in (0x347F00,0x347F10):self.digest_lock_events.append(('lock' if off==0x347F00 else 'unlock',reg(0)))
        if off in CALLS and reg(30) in [self.image+x for x in (0x286DB0,0x286DF8,0x286E04,0x286E0C)]:
            i=len(self.digest_calls);assert off==CALLS[i]
            args=((E-0x110,self.image+0x3E0FF0),(self.digest_source,0),
                (E-0x120,E-0x130),(E-0x130,))[i]
            assert tuple(reg(n) for n in range(len(args)))==args
            assert reg(30)==self.image+(0x286DB0,0x286DF8,0x286E04,0x286E0C)[i]
            if i==1:assert reg(8)==E-0x130
            if i==3:
                assert raw(E-0x120,16)==raw(E-0x130,16)
                assert u(u(E-0x120+8),4)==2
                self.digest_count_two_seen=True
            self.digest_calls.append(hex(off))
        if off==0x286DB0:
            constant=E-0x110;payload=u(constant+16)
            assert u(constant)==self.image+0x34F5F8 and u(constant+8,4)==17 and u(constant+12,4)==16
            assert reg(0)==payload and raw(payload,17)==raw(self.image+0x3E0FF0,17)
        if off in (0x27E6AC,0x27ED6C) or (off==0x286E74 and not self.continue_to_svc):
            raise AssertionError('unexpected post-digest execution')
        if off==STOP:
            assert self.digest_calls==list(map(hex,CALLS)) and self.digest_count_two_seen
            obj=u(E-0x120);counter=u(E-0x120+8)
            assert obj and counter and raw(E-0x120,16)==raw(E-0x130,16) and u(counter,4)==1
            assert u(obj)==self.image+0x34F5F8 and (u(obj+8,4),u(obj+12,4))==(17,16)
            assert raw(u(obj+16),17)==self.digest_expected_bytes+b'\0'
            assert reg(24)==self.digest_second and reg(26)==self.digest_header
            assert cpu.reg_read(arm.UC_ARM64_REG_SP)==E-0x260
            fp=cpu.reg_read(arm.UC_ARM64_REG_FP)
            assert u(fp-0x90)==u(self.digest_header) and u(fp-0x80)==u(self.digest_header+24)
            assert u(fp-0x68)==u(self.digest_header+32) and u(fp-0x60)==u(self.digest_header+40)
            assert raw(fp-8,8)==self.constants_canary and raw(self.constants_tp+0x28,8)==self.constants_canary
            assert raw(f,0x2000)==self.digest_frame_before
            assert raw(self.digest_source,24)==self.digest_native_source_before[0]
            assert raw(self.digest_native_source_payload,len(self.digest_native_source_before[1]))==self.digest_native_source_before[1]
            after=state['allocator_events_ref'];assert after[:len(self.digest_allocations)]==self.digest_allocations
            delta=after[len(self.digest_allocations):]
            assert [r[0] for r in delta]==['alloc']*5 and [r[1] for r in delta]==[17,24,17,48,4]
            assert [r[3] for r in delta]==['0x248388','0x32a210','0x248238','0x32a210','0x32a210']
            assert [r[2] for r in delta][1:3]==[obj,u(obj+16)] and delta[4][2]==counter
            index=(obj>>4)&255;entry=delta[3][2]
            table=bytearray(self.digest_preserved[self.copy_table])
            assert table[index*8:index*8+8]==bytes(8)
            table[index*8:index*8+8]=entry.to_bytes(8,'little')
            for a,b in self.digest_preserved.items():
                assert raw(a,len(b))==(table if a==self.copy_table else b),('unexpected old-window change',hex(a),len(b))
            assert u(self.image+diagnostics.TABLE)==self.copy_table and u(self.image+diagnostics.GLOBAL_LOCK)==self.copy_global
            assert raw(entry,48)==(self.image+0x34C738).to_bytes(8,'little')+bytes.fromhex('0040000000000000')+bytes(32)
            assert raw(self.image+diagnostics.GUARD,8)==self.digest_guard_before
            assert raw(self.copy_global,48)==self.digest_global_before
            assert raw(self.image+diagnostics.GUARD_MUTEX,40)==self.digest_guard_mutex_before
            assert self.digest_lock_events==[('lock',self.copy_global+8),('unlock',self.copy_global+8)]+[
                (operation,entry+8) for _ in range(3) for operation in ('lock','unlock')]
            assert self.original_scope
            self.digest_done=True
            if self.continue_to_svc:
                self.digest_boundary_seen=True
                state['start_new_instruction_window']=True
                self.digest_active=False
            else:
                cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,context.outer.oracle.STOP)

    def finish(self,result,state,proof):
        old=next(r for r in json.loads(previous.EVIDENCE.read_text())['case_results'] if r['control']==self.control)
        prefix=proof['suffix_constants_prefix'];assert self.digest_done
        assert result['allocator_events'][:len(self.digest_allocations)]==self.digest_allocations
        counts=dict(old['allocator_counts']);counts['malloc']+=5
        if self.continue_to_svc:
            assert proof['main_image_SVC_boundaries']==old['main_image_SVC_boundaries']
            assert proof['libc_SVC_boundaries']==old['libc_SVC_boundaries'] and proof['JNI_calls']==old['JNI_calls']
            post_digest_events=result['allocator_events'][len(self.digest_allocations):]
            post_digest_services=result['explicit_service_counts']
            service_delta={key:post_digest_services.get(key,0)-old['service_counts'].get(key,0)
                for key in set(post_digest_services)|set(old['service_counts'])}
            assert all(value>=0 for value in service_delta.values())
        else:
            assert result['actual_allocator_counts']==counts and result['explicit_service_counts']==old['service_counts']
            post_digest_events=[];post_digest_services=old['service_counts'];service_delta={}
        for k in ('JNI_calls','libc_SVC_boundaries','main_image_SVC_boundaries'):assert proof[k]==old[k]
        row=dict(control=self.control,retained_constants_prefix_verified=True,
            retained_prefix_instruction_observations=prefix['instruction_observations'],retained_prefix_trace_sha256=prefix['trace_sha256'],
            retained_prefix_code_sha256=prefix['code_sha256'],retired_completed_observers=['constants_active'],original_scope_kept=True,
            original_direct_calls=self.digest_calls,current_mode=0,constant_string_length=16,raw_MD5_length=16,
            scratch_header_and_selected_registers_verified=True,native_raw_MD5_contract_verified=True,
            reference_count_two_then_one_verified=True,header_source_old_frame_TLS_and_non_diagnostic_heap_preserved=True,
            one_diagnostic_slot_and_all_other_table_bytes_verified=True,ordered_diagnostic_lock_events_verified=True,
            new_allocation_sizes=[17,24,17,48,4],new_free_count=0,allocation_ledger_sha256=graph.digest(result['allocator_events']),
            allocator_counts=counts,service_counts=old['service_counts'],JNI_calls=proof['JNI_calls'],libc_SVC_boundaries=proof['libc_SVC_boundaries'],
            main_image_SVC_boundaries=proof['main_image_SVC_boundaries'],continuation_instruction_observations=proof['instruction_observations'],
            continuation_trace_sha256=proof['trace_sha256'],continuation_code_sha256=proof['code_sha256'],
            observation_stop_before=hex(STOP),outer_bytecode=hex(previous.previous.CALL),current_native_suffix_return_verified=False)
        if self.continue_to_svc:
            assert self.svc_boundary is not None
            row.update(svc_boundary=self.svc_boundary,observation_stop_before_svc=self.svc_boundary['pc_offset'],
                entered_svc_handler=False,handler_read_count_delta=0,main_image_svc_count_delta=0,
                instruction_observation_windows=proof['instruction_observation_windows'],
                total_continuation_instruction_observations=proof['instruction_observations'],
                post_digest_instruction_observations=proof['instruction_observation_windows'][-1],
                public_instruction_window_limit=400000,post_digest_allocator_event_count=len(post_digest_events),
                post_digest_allocator_events_sha256=graph.digest(post_digest_events),
                post_digest_allocator_counts=result['actual_allocator_counts'],
                post_digest_service_counts=post_digest_services,post_digest_service_delta=service_delta,
                main_image_svc_count_at_boundary=len(proof['main_image_SVC_boundaries']),
                required_main_image_svc_limit=4,
                target_suffix_svc_reached=self.svc_boundary['pc_offset']=='0x286ec8')
        return row


def replay(path,libc,*,case_controls=None):
    def create(c):
        s=Scenario(c);s.path=path;return s
    return context.replay(path,libc,case_controls=case_controls,_extension_factory=create,
        _request_profile=previous.previous.name.previous.previous.PROFILE['name'],_handler_read_profile=context.NULL_PAYLOAD_READ_PROFILE['name'])


def boundary_replay(path,libc,*,case_controls=None):
    def create(c):
        s=Scenario(c);s.path=path;s.continue_to_svc=True;return s
    rows=context.replay(path,libc,case_controls=case_controls,_extension_factory=create,
        _request_profile=previous.previous.name.previous.previous.PROFILE['name'],_handler_read_profile=context.NULL_PAYLOAD_READ_PROFILE['name'])
    for row in rows:
        assert row.get('svc_boundary') is not None
    return rows


def verify_images(path,libc):
    from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
    previous.verify_images(path,libc);_,_,read=graph.inputs.load_elf(path);decoder=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
    for a,m,s in EXPECTED:
        ins,=decoder.disasm(read(a,4),a);assert (ins.mnemonic,ins.op_str)==(m,s)
    return dict(instruction_bindings=len(EXPECTED),independent_prefix_cases=16)


def projection():
    return [dict(image_base=hex(b),case=p,mode_is_one=p in ('mode_one','mode_one_short_constant'),original_stopped_before=hex(STOP),
        existing_suffix_source_prefix_executed=True,complete_semantic_guest_image_and_selected_scratch_bytes_equal=True,
        ordered_effects_pre_free_payloads_and_live_blocks_equal=True,reference_count_one_verified=True,native_snapshot_input=False)
        for b in graph.BASES for p in PROFILES]


def validate(data):
    assert data['schema']=='vm9-native-171-suffix-digest-20261120-v1' and data['claims']==CLAIMS and data['providers']==providers()
    assert data['instructions']==[dict(offset=hex(a),mnemonic=m,operands=s) for a,m,s in EXPECTED]
    assert data['suffix_owner_source_sha256']==hashlib.sha256(Path(owner.__file__).read_bytes()).hexdigest()
    assert data['independent_projection']==projection()
    before=json.loads(previous.EVIDENCE.read_text());previous.validate(before)
    assert data['provenance']==before['provenance'] and len(data['case_results'])==len(before['case_results'])
    for row,old in zip(data['case_results'],before['case_results']):
        assert row['control']==old['control'] and row['retained_constants_prefix_verified'] is True
        for k in ('instruction_observations','trace_sha256','code_sha256'):assert row['retained_prefix_'+k]==old['continuation_'+k]
        assert row['retired_completed_observers']==['constants_active'] and row['original_scope_kept'] is True
        assert row['original_direct_calls']==list(map(hex,CALLS)) and row['current_mode']==0
        assert row['constant_string_length']==row['raw_MD5_length']==16
        for k in ('scratch_header_and_selected_registers_verified','native_raw_MD5_contract_verified',
            'reference_count_two_then_one_verified','header_source_old_frame_TLS_and_non_diagnostic_heap_preserved',
            'one_diagnostic_slot_and_all_other_table_bytes_verified','ordered_diagnostic_lock_events_verified'):assert row[k] is True
        assert row['new_allocation_sizes']==[17,24,17,48,4] and row['new_free_count']==0
        counts=dict(old['allocator_counts']);counts['malloc']+=5;assert row['allocator_counts']==counts
        for k in ('service_counts','JNI_calls','libc_SVC_boundaries','main_image_SVC_boundaries'):assert row[k]==old[k]
        for k in ('allocation_ledger_sha256','continuation_trace_sha256','continuation_code_sha256'):assert graph.inputs.is_digest(row[k])
        assert old['continuation_instruction_observations']<row['continuation_instruction_observations']<400000
        assert row['observation_stop_before']==hex(STOP) and row['outer_bytecode']==hex(previous.previous.CALL)
        assert row['current_native_suffix_return_verified'] is False


def negatives(data):
    paths=[(('claims',k),not v) for k,v in CLAIMS.items()]
    paths.extend([(('providers','public_trace_limit'),750000),(('providers','maximum_handler_reads'),3),
        (('providers','maximum_main_SVCs'),5),(('suffix_owner_source_sha256',),'0'*64),
        (('instructions',0,'mnemonic'),'nop'),(('independent_projection',0,'native_snapshot_input'),True)])
    for i,row in enumerate(data['case_results']):
        for key,v in row.items():
            value={} if isinstance(v,dict) else [] if isinstance(v,list) else not v if isinstance(v,bool) else 400000 if isinstance(v,int) else 'bad'
            paths.append((('case_results',i,key),value))
    for path,value in paths:
        bad=deepcopy(data);target=bad
        for k in path[:-1]:target=target[k]
        target[path[-1]]=value
        try:validate(bad)
        except (AssertionError,KeyError,ValueError,TypeError):pass
        else:raise AssertionError('damaged suffix digest evidence accepted: '+str(path))
    return len(paths)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--elf',type=Path);ap.add_argument('--libc',type=Path);ap.add_argument('--replay',action='store_true')
    ap.add_argument('--svc-boundary',action='store_true',help='run one existing control and stop before svc #0')
    args=ap.parse_args()
    if args.svc_boundary and (not args.elf or not args.libc):ap.error('--svc-boundary requires --elf and --libc')
    if args.svc_boundary and args.replay:ap.error('--svc-boundary cannot be combined with --replay')
    if args.replay and (not args.elf or not args.libc):ap.error('--replay requires --elf and --libc')
    data=json.loads(EVIDENCE.read_text());validate(data)
    result=dict(retained_suffix_digest_cases=len(data['case_results']),damaged_evidence_rejected=negatives(data),
        current_native_suffix_return_verified=False,ordinary_Cronet_six_headers_verified=False,complete_standalone_signer_verified=False)
    if args.elf:result['image_bindings']=verify_images(args.elf,args.libc)
    elif args.libc:graph.inputs.libc_image(args.libc)
    if args.replay:
        assert independent_controls(args.elf,args.libc)==data['independent_projection']
        assert replay(args.elf,args.libc)==data['case_results']
        result.update(original_code_cases_replayed=4,fresh_declared_native_digest_controls_replayed=16)
    if args.svc_boundary:
        controls=context.controls()[:1]
        rows=boundary_replay(args.elf,args.libc,case_controls=controls)
        assert len(rows)==1 and rows[0]['entered_svc_handler'] is False
        assert rows[0]['handler_read_count_delta']==0 and rows[0]['main_image_svc_count_delta']==0
        result.update(svc_boundary_control=rows[0])
    print(json.dumps(result))


if __name__=='__main__':main()
