"""Original-body differentials for warm event emission and returned callers.

Explicit allocation/free services. Matching libc executes string imports and
normal mutex bodies. No native output or singleton return seeds Python.
"""
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path
from unicorn import arm64_const as arm
import vm9_request_event as events
import vm9_request_caller as caller
import vm9_request_leaf_prefixes as leaves
import vm9_cpp_strings as cpp
from vm9_allocator import RefillUnsupported,_read_span,_write_span
from verify_vm9_signer_objects import GUEST,LIBRARY_SHA256,image_pages,fresh_pages,native
from verify_vm9_strings import Effects
from verify_vm9_request_mode_format_fresh_20261007 import imports,services,snapshot
from verify_vm9_worker_allocator import LIBC_SHA256

BASES=(0x122C0000,0x775C205000)
STACK=GUEST+0xEF00
LOGGER=GUEST+0x1000
INPUTS=tuple(GUEST+0x1200+24*i for i in range(4))


def fresh(library,image):return {**image_pages(library,image),**fresh_pages()}
def u(p,a):return int.from_bytes(_read_span(p,a,8),'little')
def w(p,a,v):_write_span(p,a,v.to_bytes(8,'little'))
def duplicate(e):
    result=Effects(blocks=e.blocks);result.next=e.next
    return result


def fixture(library,image,count,capacity,*,nonempty=True,input_lengths=(5,8,29,2)):
    p=fresh(library,image);e=Effects(blocks={})
    if capacity>=200:
        old=GUEST+0x1800;e.blocks[old]=capacity*96;e.next=GUEST+0x7000
    else:old=e.malloc(p,capacity*96) if capacity else 0
    if capacity:_write_span(p,old,bytes(capacity*96))
    _write_span(p,LOGGER,bytes(64));w(p,LOGGER+40,old);w(p,LOGGER+48,old+count*96);w(p,LOGGER+56,old+capacity*96)
    w(p,image+0x3E1B08,LOGGER)
    if nonempty and count<200:
        for record in range(count):
            for index in range(4):
                text=(b'old-'+str(record).encode()+b':'+str(index).encode())*(5 if index==2 else 1)
                source=GUEST+0x2000;_write_span(p,source,text+b'\0')
                cpp.construct_cpp_string(p,object_address=old+record*96+index*24,source_address=source,allocate=e.malloc)
    for index,(obj,length) in enumerate(zip(INPUTS,input_lengths)):
        text=bytes([65+index])*length;source=GUEST+0x1100 if capacity>=200 else GUEST+0x2100+index*0x100
        _write_span(p,source,text+b'\0');cpp.construct_cpp_string(p,object_address=obj,source_address=source,allocate=e.malloc)
    return p,e


def check_memory(model,memory,observed):
    assert _read_span(model,GUEST,0xA000)==memory,'complete payload mismatch'
    for key,value in observed.items():
        actual=_read_span(model,*key)
        assert actual==value,(key,[(hex(key[0]+i),actual[i:i+8].hex(),value[i:i+8].hex()) for i in range(0,key[1],8) if actual[i:i+8]!=value[i:i+8]])


def full_caller(library,libc,image,entries,*,wrapper=False,error=0,unsampled=False):
    p,seed=fixture(library,image,1,1,nonempty=True,input_lengths=(5,0,0,0));event=INPUTS[0]
    divisor=10;sequence=1 if unsampled else 0;values=(7,1<<63,(1<<64)-1,sequence)
    w(p,image+0x3839E8,divisor)
    expected,actual=duplicate(seed),duplicate(seed)
    observed={(LOGGER,64):None,(image+0x3D2000,4096):None,(image+0x3E1000,4096):None}
    offset=0x28DC40 if wrapper else 0x28DDD0
    args=[*values,error] if wrapper else [event,*values]
    registers={} if wrapper else {arm.UC_ARM64_REG_X5:error}
    _,memory,_,ledger=native(library,image,offset,args,p,libc=libc,real_mutexes=True,
        extra_registers=registers,host_imports=services(entries,expected),
        malloc_handler=lambda cpu,size:expected.native(cpu,'malloc',size),observed_memory=observed,instruction_limit=1500000)
    model={k:bytearray(v) for k,v in p.items()};captures=[]
    def observe(_p,**fields):captures.append(fields)
    if wrapper:
        def format_event(p,obj,*words):
            return leaves.execute_event_formatter_prefix(p,image_base=image,entry_stack_address=STACK-0xF0,
                event_object_address=obj,argument_words=words[:4],mode=words[4],allocate=actual.malloc,free=actual.free,observer=observe)
        result=events.execute_request_event(model,image_base=image,entry_stack_address=STACK,argument_words=values,
            emit_error_event=error,allocate=actual.malloc,free=actual.free,format_event=format_event)
    else:
        result=leaves.execute_event_formatter_prefix(model,image_base=image,entry_stack_address=STACK,
            event_object_address=event,argument_words=values,mode=error,allocate=actual.malloc,free=actual.free,observer=observe)
    assert expected.calls==actual.calls and expected.blocks==actual.blocks
    check_memory(model,memory,observed)
    count=(u(model,LOGGER+48)-u(model,LOGGER+40))//96
    emitted=(0 if unsampled else (2 if wrapper and error else 1))
    assert count==1+emitted
    assert len(ledger)==2*emitted
    assert sum(c['phase']=='event_formatter_completed' for c in captures)==emitted
    if not wrapper:assert result is (not unsampled)
    return dict(image_base=hex(image),native_entry_offset=hex(offset),error_mode=error,unsampled=unsampled,
        original_native_caller_returned=True,python_bounded_caller_returned=True,
        full_final_payload_and_two_global_pages_match=True,payload_padding_mask_used=False,
        ordered_allocator_cleanup_effects_match=True,event_records_appended=emitted,record_count=count,
        matching_libc_mutex_transitions_observed=len(ledger),native_input_snapshot_used=False,
        controlled_warm_singleton_input=True,complete_request_vm_verified=False)


def emission_case(library,libc,image,entries,count,capacity,lengths,nonempty=True):
    p,seed=fixture(library,image,count,capacity,nonempty=nonempty,input_lengths=lengths)
    before_inputs=[_read_span(p,a,24) for a in INPUTS]
    expected,actual=duplicate(seed),duplicate(seed)
    local=STACK-0x140
    observed={(LOGGER,64):None,(local+8,96):None,(image+0x3E1000,4096):None}
    growth=count<200 and count==capacity
    if growth:observed[local+0x68,40]=None
    _,memory,_,ledger=native(library,image,0x28FF44,list(INPUTS),p,libc=libc,real_mutexes=True,
        host_imports=services(entries,expected),malloc_handler=lambda cpu,size:expected.native(cpu,'malloc',size),
        observed_memory=observed,instruction_limit=1000000)
    model={k:bytearray(v) for k,v in p.items()}
    result=events.execute_event_emission(model,image_base=image,entry_stack_address=STACK,
        input_object_addresses=INPUTS,allocate=actual.malloc,free=actual.free)
    assert expected.calls==actual.calls and expected.blocks==actual.blocks
    check_memory(model,memory,observed)
    assert ledger==[['pthread_mutex_lock',LOGGER],['pthread_mutex_unlock',LOGGER]]
    for address,before in zip(INPUTS,before_inputs):assert _read_span(model,address,24)==bytes(2)+before[2:]
    assert result.appended==(count<200) and result.dropped==(count>=200)
    assert (u(model,LOGGER+48)-u(model,LOGGER+40))//96==count+(count<200)
    return dict(image_base=hex(image),initial_record_count=count,initial_capacity=capacity,input_lengths=list(lengths),
        nonempty_old_record_fixture=nonempty and count<200,appended=result.appended,dropped=result.dropped,
        full_payload_logger_temporary_record_scratch_and_global_page_match=True,payload_padding_mask_used=False,
        ordered_allocator_cleanup_effects_match=True,matching_libc_normal_mutex_body_executed=True,
        source_first_two_bytes_zeroed_and_remaining_bytes_retained=True,
        original_native_emission_body_returned=True,python_warm_emission_owner_verified=True,
        allocation_sizes=[c[1] for c in actual.calls if c[0]=='malloc'],
        native_input_snapshot_used=False,controlled_warm_singleton_input=True)


def move_case(library,libc,image,entries,source_length,destination_length):
    p=fresh(library,image);seed=Effects(blocks={});dest,source=GUEST+0x1200,GUEST+0x1220
    for obj,length,char in ((dest,destination_length,b'D'),(source,source_length,b'S')):
        _write_span(p,GUEST+0x2000,char*length+b'\0');cpp.construct_cpp_string(p,object_address=obj,source_address=GUEST+0x2000,allocate=seed.malloc)
    expected,actual=duplicate(seed),duplicate(seed)
    _,memory,_,ledger=native(library,image,0x17F5BC,[dest,source],p,libc=libc,
        host_imports=services(entries,expected),malloc_handler=lambda cpu,size:expected.native(cpu,'malloc',size))
    model={k:bytearray(v) for k,v in p.items()}
    cpp.move_assign_cpp_string(model,object_address=dest,source_object_address=source,free=actual.free)
    check_memory(model,memory,{})
    assert not ledger and expected.calls==actual.calls and expected.blocks==actual.blocks
    return dict(image_base=hex(image),source_length=source_length,destination_length=destination_length,
        original_native_move_assignment_executed=True,complete_payload_and_cleanup_effects_match=True,
        source_first_two_bytes_zeroed=True,native_input_snapshot_used=False)



def return_case(library,image,sentinel):
    p=fresh(library,image);word=GUEST+0x2000;packed=GUEST+0x2100;descriptor=GUEST+0x2200;top=GUEST+0xC000
    data=_read_span(p,image+0xFFB78,4);_write_span(p,word,data)
    _write_span(p,descriptor,(image+0x28587C).to_bytes(8,'little')+top.to_bytes(8,'little')+sentinel.to_bytes(8,'little'))
    selected=[];epilogue=[]
    def observe(cpu,address):
        if address==image+0x168594:selected.append(cpu.reg_read(arm.UC_ARM64_REG_X8)-image)
        if image+0x172440<=address<=image+0x17245C:epilogue.append(address-image)
    _,memory,allocations,ledger=native(library,image,0x168324,
        [word,packed,image+0x35E230,image+0x35E690,descriptor],p,
        instruction_observer=observe,instruction_limit=5000)
    assert selected==[0x16A974] and epilogue==list(range(0x172440,0x172460,4))
    assert not allocations and not ledger
    registers=[0]*32;registers[31]=sentinel
    result=caller.validate_request_vm_exit(p,image_base=image,pc=image+0xFFB78,
        registers=registers,return_address=sentinel)
    assert result['selected_slot']==31 and result['caller_sentinel_matches']
    return dict(image_base=hex(image),caller_sentinel=hex(sentinel),sample_exit_word_hex=data.hex(),
        original_native_dispatch_return_handler_epilogue_and_ret_executed=True,
        handler_offset='0x16a974',epilogue_offset='0x172440',slot31_equals_saved_sentinel=True,
        native_x0_return_abi_compared=False,native_input_snapshot_used=False,
        full_native_request_vm_executed=False)


def negatives(library):
    image=BASES[0];rows=[]
    mutations=(('cold_singleton',lambda p:w(p,image+0x3E1B08,0)),
        ('alternate_publication',lambda p:_write_span(p,image+0x3E1B20,b'\1')),
        ('contended_mutex',lambda p:_write_span(p,LOGGER,b'\1\0')),
        ('invalid_vector_end',lambda p:w(p,LOGGER+48,u(p,LOGGER+48)+1)),
        ('invalid_vector_capacity',lambda p:w(p,LOGGER+56,u(p,LOGGER+40))),
        ('vector_exceeds_bound',lambda p:w(p,LOGGER+56,u(p,LOGGER+40)+96*513)))
    for name,mutate in mutations:
        p,seed=fixture(library,image,1,1);mutate(p);before=snapshot(p);e=duplicate(seed)
        try:events.execute_event_emission(p,image_base=image,entry_stack_address=STACK,
            input_object_addresses=INPUTS,allocate=e.malloc,free=e.free)
        except RefillUnsupported:pass
        else:raise AssertionError(name+' accepted')
        assert snapshot(p)==before and not e.calls;rows.append(name+'_refused_without_page_or_allocator_changes')
    for name,addresses,stack in (('overlapping_inputs',(INPUTS[0],INPUTS[0],*INPUTS[2:]),STACK),
            ('wrong_input_count',INPUTS[:3],STACK),('unaligned_stack',INPUTS,STACK+1)):
        p,seed=fixture(library,image,1,1);before=snapshot(p);e=duplicate(seed)
        try:events.execute_event_emission(p,image_base=image,entry_stack_address=stack,
            input_object_addresses=addresses,allocate=e.malloc,free=e.free)
        except RefillUnsupported:pass
        else:raise AssertionError(name+' accepted')
        assert snapshot(p)==before and not e.calls;rows.append(name+'_refused_without_changes')
    p,seed=fixture(library,image,1,1);before=snapshot(p);e=duplicate(seed);e.failures={0}
    try:events.execute_event_emission(p,image_base=image,entry_stack_address=STACK,
        input_object_addresses=INPUTS,allocate=e.malloc,free=e.free)
    except RefillUnsupported:pass
    else:raise AssertionError('allocation failure accepted')
    assert snapshot(p)==before;rows.append('growth_allocation_failure_refused_without_page_commit')
    p,seed=fixture(library,image,1,1);before=snapshot(p);e=duplicate(seed)
    try:cpp.move_assign_cpp_string(p,object_address=INPUTS[2],source_object_address=INPUTS[2],free=e.free)
    except RefillUnsupported:pass
    else:raise AssertionError('move alias accepted')
    assert snapshot(p)==before and not e.calls;rows.append('move_self_alias_refused_without_changes')
    for name,pc,registers,mutation in (
            ('wrong_return_pc',image+0xFFB74,[0]*31+[GUEST+0xF000],None),
            ('wrong_return_target',image+0xFFB78,[0]*32,None),
            ('wrong_exit_word',image+0xFFB78,[0]*31+[GUEST+0xF000],lambda p:_write_span(p,image+0xFFB78,bytes(4)))):
        p=fresh(library,image)
        if mutation:mutation(p)
        before=snapshot(p)
        try:caller.validate_request_vm_exit(p,image_base=image,pc=pc,registers=registers,return_address=GUEST+0xF000)
        except RefillUnsupported:pass
        else:raise AssertionError(name+' accepted')
        assert snapshot(p)==before;rows.append(name+'_refused_without_page_changes')
    return rows


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--library',type=Path,required=True);ap.add_argument('--libc',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);ap.add_argument('--red',action='store_true')
    args=ap.parse_args();assert hashlib.sha256(args.library.read_bytes()).hexdigest()==LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==LIBC_SHA256
    entries=imports(args.library,args.libc)
    if args.red:
        full_caller(args.library,args.libc,BASES[0],entries);return
    emissions,callers,moves,returns=[],[],[],[]
    for image in BASES:
        for wrapper,error,unsampled in ((False,0,False),(False,0xFFFFFFFF,False),(False,7,True),
                (True,0,False),(True,7,False),(True,7,True)):
            callers.append(full_caller(args.library,args.libc,image,entries,wrapper=wrapper,error=error,unsampled=unsampled))
            print('returned event caller',hex(image),wrapper,error,unsampled,'PASS',flush=True)
        for count,capacity,lengths in ((0,0,(0,0,0,0)),(0,2,(22,23,31,0)),(1,1,(5,8,29,2)),
                (1,2,(22,23,31,0)),(3,3,(0,22,23,48)),(3,5,(48,0,22,23)),
                (199,200,(23,23,23,23)),(200,200,(23,23,23,23))):
            emissions.append(emission_case(args.library,args.libc,image,entries,count,capacity,lengths,nonempty=count<199))
            print('warm emission',hex(image),count,capacity,lengths,'PASS',flush=True)
        for sl,dl in ((0,0),(22,23),(23,22),(29,48)):
            moves.append(move_case(args.library,args.libc,image,entries,sl,dl));print('move assignment',hex(image),sl,dl,'PASS',flush=True)
        for sentinel in (GUEST+0xF000,0xDEAD0000):
            returns.append(return_case(args.library,image,sentinel));print('native VM return',hex(image),hex(sentinel),'PASS',flush=True)
    negative=negatives(args.library)
    report=dict(schema='vm9-request-event-emission-fresh-differential-v1',evidence_date='2026-10-07',
        sample_sha256=LIBRARY_SHA256,libc_sha256=LIBC_SHA256,emission_controls=len(emissions),
        returned_caller_controls=len(callers),move_assignment_controls=len(moves),vm_return_controls=len(returns),negative_controls=len(negative),
        emission_cases=emissions,returned_caller_cases=callers,move_assignment_cases=moves,vm_return_cases=returns,negative_checks=negative,
        native_input_snapshot_used=False,warm_logger_record_vector_emission_verified=True,
        original_native_emission_and_callers_returned=True,explicit_component_allocator_used=True,
        matching_libc_normal_mutex_body_executed=True,matching_libc_allocator_used=False,
        full_final_payload_comparison_uses_no_mask=True,whole_native_stack_tls_os_equivalence_claimed=False,
        cold_logger_singleton_recovered=False,alternate_publication_branch_recovered=False,
        complete_request_vm_verified=False,complete_python_medusa=False,
        fresh_signer_output_verified=False,live_server_matrix_verified=False)
    args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print('event emission controls',len(emissions)+len(callers)+len(moves)+len(returns),'negative',len(negative),'PASS',flush=True)

if __name__=='__main__':main()
