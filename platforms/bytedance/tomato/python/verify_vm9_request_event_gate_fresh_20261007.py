"""Fresh native controls for C++ strings and two request callback orchestrators.

The original outer bodies execute; evaluator/elapsed-logger/event-formatter
leaves are explicit component services. Their native bodies are not compared.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from unicorn import arm64_const as arm
import vm9_objects as objects
import vm9_cpp_strings as cpp
import vm9_request_boolean_gate as gate
import vm9_request_event as event
from vm9_allocator import RefillUnsupported, _read_span, _write_span
from verify_vm9_signer_objects import GUEST, LIBRARY_SHA256, image_pages, fresh_pages, native
from verify_vm9_strings import Effects

BASES = (0x122C0000, 0x775C205000)
STACK = GUEST + 0xEF00
DEST, SOURCE, SOURCE_OBJECT = GUEST + 0x1800, GUEST + 0x2000, GUEST + 0x2800
MASK64 = (1 << 64) - 1


def string_case(library, image, length, operation, representation='auto'):
    p = {**image_pages(library, image), **fresh_pages()}
    payload = bytes((i % 251) + 1 for i in range(length))
    _write_span(p, SOURCE, payload + b'\0')
    blocks = {}
    if operation in ('clone', 'destroy'):
        heap = representation == 'heap' or representation == 'auto' and length >= 23
        if heap:
            capacity = max(32, (length + 16) & ~15)
            _write_span(p, SOURCE_OBJECT, (capacity | 1).to_bytes(8, 'little') +
                length.to_bytes(8, 'little') + SOURCE.to_bytes(8, 'little'))
            blocks[SOURCE] = capacity
        else:
            _write_span(p, SOURCE_OBJECT, bytes([length * 2]) + payload + b'\0')
    a, n = Effects(blocks=blocks), Effects(blocks=blocks)
    model = {k: bytearray(v) for k, v in p.items()}
    def free(cpu):
        return n.native(cpu, 'free', pointer=cpu.reg_read(arm.UC_ARM64_REG_X0))
    if operation == 'construct':
        target, arguments = 0x32ABA0, [DEST, SOURCE, length]
    elif operation == 'cstring':
        target, arguments = 0x165B78, [DEST, SOURCE]
    elif operation == 'clone':
        target, arguments = 0x32A9C4, [DEST, SOURCE_OBJECT]
    else:
        target, arguments = 0x32AA70, [SOURCE_OBJECT]
    _, memory, allocations, services = native(library, image, target, arguments, p,
        malloc_handler=lambda cpu, size:n.native(cpu, 'malloc', size),
        host_imports={0x347FA0: free})
    if operation in ('construct', 'cstring'):
        cpp.construct_cpp_string(model, object_address=DEST, source_address=SOURCE,
            length=length if operation == 'construct' else None, allocate=a.malloc)
    elif operation == 'clone':
        cpp.clone_cpp_string(model, object_address=DEST, source_object_address=SOURCE_OBJECT, allocate=a.malloc)
    else:
        cpp.destroy_cpp_string(model, object_address=SOURCE_OBJECT, free=a.free)
    assert _read_span(model, GUEST, 0xA000) == memory
    assert a.calls == n.calls and a.blocks == n.blocks
    assert not services
    return dict(image_base=hex(image), operation=operation, length=length,
        input_representation=representation, full_payload_memory_match=True,
        ordered_allocator_and_free_effects_match=True, preserved_padding_verified=True,
        native_input_snapshot_used=False, explicit_component_allocator_used=True,
        native_return_abi_compared=False, helper_object_return_is_api_only=True)


def gate_case(library, image, control):
    p = {**image_pages(library, image), **fresh_pages()}
    receiver = GUEST + 0x1600
    _write_span(p, receiver, bytes([0x31, control['cached']]) + bytes([0xD3]) * 30)
    _write_span(p, image + 0x3E1620, control['counter'].to_bytes(8, 'little'))
    addresses = gate.resolve_boolean_gate_addresses(p, image_base=image)
    if control.get('warm'):
        for prefix in ('first', 'second'):
            objects.decode_masked_bytes(p, source_address=addresses[prefix + '_source'],
                destination_address=addresses[prefix + '_name'], mask_address=addresses[prefix + '_mask'])
            _write_span(p, addresses[prefix + '_flag'], (2).to_bytes(4, 'little'))
    model = {k: bytearray(v) for k, v in p.items()}
    nlog, alog, nscope, ascope = [], [], [], []
    observed = {(STACK - 0x100, 0x60): None, (image + 0x3E1000, 0x1000): None}
    def clock(cpu):
        clock_id = cpu.reg_read(arm.UC_ARM64_REG_X0)
        assert clock_id == 1
        nlog.append(['clock', clock_id, 17, 731])
        cpu.mem_write(cpu.reg_read(arm.UC_ARM64_REG_X1), (17).to_bytes(8, 'little') + (731).to_bytes(8, 'little'))
        return 0
    def evaluate(cpu):
        values = [cpu.reg_read(r) for r in (arm.UC_ARM64_REG_X0, arm.UC_ARM64_REG_X1, arm.UC_ARM64_REG_X2)]
        nlog.append(['evaluate', *values])
        return control['raw']
    def cleanup(cpu):
        address = cpu.reg_read(arm.UC_ARM64_REG_X0)
        nscope.append(bytes(cpu.mem_read(address, 16)))
        nlog.append(['cleanup', address])
        return 0
    returned, memory, allocations, services = native(library, image, 0x28BB5C, [receiver], p,
        host_imports={0x348450:clock, 0x28B05C:evaluate, 0x28C09C:cleanup},
        observed_memory=observed, instruction_limit=100000)
    def aclock(p, clock_id):
        alog.append(['clock', clock_id, 17, 731])
        return 0, 17, 731
    def aevaluate(p, descriptor, mode, name):
        alog.append(['evaluate', descriptor, mode, name])
        return control['raw']
    def acleanup(p, scope):
        ascope.append(_read_span(p, scope, 16))
        alog.append(['cleanup', scope])
    result = gate.execute_boolean_gate(model, object_address=receiver, image_base=image,
        entry_stack_address=STACK, read_clock=aclock, evaluate=aevaluate, leave_scope=acleanup)
    expected_call = control['counter'] % 74 == 0 or control['cached'] != 0
    expected = control['raw'] & 1 if expected_call else 0
    assert int(result.returned_boolean) == returned == expected
    assert result.evaluator_called == expected_call
    assert _read_span(model, GUEST, 0xA000) == memory
    for (address, width), data in observed.items():
        assert _read_span(model, address, width) == data, hex(address)
    assert nlog == alog and nscope == ascope, (nlog, alog, nscope, ascope)
    assert not allocations and not services
    return dict(image_base=hex(image), case=control['name'], counter_value=control['counter'],
        original_cached_byte=control['cached'], warm_globals=bool(control.get('warm')),
        raw_evaluator_return=hex(control['raw']), evaluator_called=result.evaluator_called,
        returned_boolean=result.returned_boolean, full_payload_and_global_page_match=True,
        local_scratch_bytes_compared=0x60, local_scope_and_parameter_slots_match=True,
        ordered_clock_evaluator_cleanup_inputs_match=True, native_input_snapshot_used=False,
        actual_evaluator_body_executed=False, actual_elapsed_logger_body_executed=False,
        actual_os_clock_executed=False)


def event_case(library, image, error_mode, warm):
    p = {**image_pages(library, image), **fresh_pages()}
    if warm:
        for source, mask, destination, flag in ((0x11F0C0,0x11F2E0,0x3E1990,0x3E19A4),
                (0x11F0E0,0x11F2C0,0x3E19B0,0x3E19C4)):
            objects.decode_masked_bytes(p, source_address=image+source, destination_address=image+destination, mask_address=image+mask)
            _write_span(p, image+flag, (2).to_bytes(4, 'little'))
    model = {k: bytearray(v) for k, v in p.items()}
    arguments = (0x1122334455667788, 0, MASK64, GUEST + 0x2200)
    observed = {(STACK-0xF0, 0x80):None, (image+0x3E1000,0x1000):None}
    nlog, alog = [], []
    def format_native(cpu):
        values=[cpu.reg_read(getattr(arm, 'UC_ARM64_REG_X'+str(i))) for i in range(6)]
        nlog.append([values, bytes(cpu.mem_read(values[0],24))])
        return 0
    _, memory, allocations, services = native(library, image,
        0x28DC38 if error_mode == 0 else 0x28DC40, [*arguments, error_mode], p,
        host_imports={0x28DDD0:format_native}, observed_memory=observed, instruction_limit=100000)
    def format_model(p, object_address, *args):
        alog.append([[object_address, *args], _read_span(p,object_address,24)])
    def forbidden(*args):
        raise AssertionError('sample event literals must remain inline strings')
    result=event.execute_request_event(model, image_base=image, entry_stack_address=STACK,
        argument_words=arguments, emit_error_event=error_mode, allocate=forbidden, free=forbidden,
        format_event=format_model)
    assert _read_span(model,GUEST,0xA000)==memory
    for (address,width), data in observed.items():
        assert _read_span(model,address,width)==data,hex(address)
    assert nlog==alog
    assert len(alog)==result.formatter_calls==1+int(bool(error_mode))
    assert not allocations and not services
    return dict(image_base=hex(image), error_event_mode=error_mode, warm_globals=warm,
        formatter_calls=result.formatter_calls, full_payload_and_global_page_match=True,
        cpp_objects_and_padding_bytes_compared=0x80, cpp_scratch_and_formatter_arguments_match=True,
        native_input_snapshot_used=False, actual_event_formatter_body_executed=False,
        native_return_abi_compared=False)


def negatives(library):
    names=[];image=BASES[0]
    def forbidden(*args):raise AssertionError('unexpected allocation/service')
    for label, length in (('string_bound',23),('string_native_abort',MASK64-15)):
        p={**image_pages(library,image),**fresh_pages()};before={k:bytes(v) for k,v in p.items()}
        try:cpp.construct_cpp_string(p,object_address=DEST,source_address=SOURCE,length=length,allocate=forbidden,max_bytes=22)
        except RefillUnsupported:pass
        else:raise AssertionError(label+' accepted')
        assert before=={k:bytes(v) for k,v in p.items()};names.append(label+'_refused_without_page_changes')
    p={**image_pages(library,image),**fresh_pages()}
    _write_span(p,SOURCE,b'x'*23+b'\0')
    before={k:bytes(v) for k,v in p.items()}
    try:cpp.construct_cpp_string(p,object_address=DEST,source_address=SOURCE,allocate=lambda *a:0)
    except RefillUnsupported:pass
    else:raise AssertionError('null operator new accepted')
    assert before=={k:bytes(v) for k,v in p.items()};names.append('null_cpp_allocation_refused_without_page_changes')
    p={**image_pages(library,image),**fresh_pages()}
    _write_span(p,image+0x383848,bytes(8))
    before={k:bytes(v) for k,v in p.items()}
    try:gate.execute_boolean_gate(p,object_address=DEST,image_base=image,entry_stack_address=STACK,
            read_clock=lambda p,i:(0,17,731),evaluate=lambda *a:1,leave_scope=lambda *a:None)
    except RefillUnsupported:pass
    else:raise AssertionError('unknown evaluator layout accepted')
    assert before=={k:bytes(v) for k,v in p.items()};names.append('unknown_indirect_target_refused_without_page_changes')
    for label, evaluate, cleanup in (('missing_evaluator',None,lambda *a:None),
            ('missing_scope_cleanup',lambda *a:1,None),('invalid_evaluator_word',lambda *a:-1,lambda *a:None)):
        p={**image_pages(library,image),**fresh_pages()};_write_span(p,DEST,bytes(2))
        before={k:bytes(v) for k,v in p.items()}
        try:gate.execute_boolean_gate(p,object_address=DEST,image_base=image,entry_stack_address=STACK,
                read_clock=lambda p,i:(0,17,731),evaluate=evaluate,leave_scope=cleanup)
        except RefillUnsupported:pass
        else:raise AssertionError(label+' accepted')
        assert before=={k:bytes(v) for k,v in p.items()};names.append(label+'_refused_without_page_changes')
    for label, words, mode in (('missing_event_formatter',(0,0,0,0),0),('invalid_event_arguments',(0,0,0),0),('invalid_event_mode',(0,0,0,0),1<<32)):
        p={**image_pages(library,image),**fresh_pages()};before={k:bytes(v) for k,v in p.items()}
        try:event.execute_request_event(p,image_base=image,entry_stack_address=STACK,argument_words=words,
                emit_error_event=mode,allocate=forbidden,free=forbidden)
        except RefillUnsupported:pass
        else:raise AssertionError(label+' accepted')
        assert before=={k:bytes(v) for k,v in p.items()};names.append(label+'_refused_without_page_changes')
    return names


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args();assert hashlib.sha256(args.library.read_bytes()).hexdigest()==LIBRARY_SHA256
    strings,gates,events=[],[],[]
    controls=[dict(name=name,counter=counter,cached=cached,raw=raw,warm=warm) for name,counter,cached,raw,warm in
        (('cold_zero',0,0,0,False),('cold_odd',0,0,3,False),('cold_even',0,0,2,False),
         ('counter_one_skip',1,0,1,False),('counter_73_skip',73,0,1,False),('counter_74_evaluate',74,0,1,False),
         ('cached_forces_evaluate',75,2,1,False),('warm_globals_nonzero_flag',1,1,MASK64,True))]
    for image in BASES:
        for length in (0,1,22,23,31,65):
            for operation in ('construct','cstring','clone','destroy'):
                strings.append(string_case(args.library,image,length,operation))
            print('C++ string',hex(image),length,'PASS',flush=True)
        for length in (0,22):
            strings.append(string_case(args.library,image,length,'clone','heap'))
        for control in controls:
            gates.append(gate_case(args.library,image,control));print('request boolean gate',hex(image),control['name'],'PASS',flush=True)
        for mode,warm in ((0,False),(1,False),(7,True),(0,True)):
            events.append(event_case(args.library,image,mode,warm));print('request event',hex(image),mode,warm,'PASS',flush=True)
    negative=negatives(args.library)
    report=dict(schema='vm9-request-event-gate-fresh-differential-v1',evidence_date='2026-10-07',sample_sha256=LIBRARY_SHA256,
        cpp_string_controls=len(strings),boolean_gate_controls=len(gates),event_wrapper_controls=len(events),negative_controls=len(negative),
        cpp_string_cases=strings,boolean_gate_cases=gates,event_wrapper_cases=events,negative_checks=negative,
        native_input_snapshot_used=False,actual_evaluator_body_executed=False,actual_event_formatter_body_executed=False,
        actual_elapsed_logger_body_executed=False,whole_handoff_native_differential_verified=False,
        complete_python_medusa=False,fresh_input_signer_output_verified=False,current_online_header_matrix_verified=False,
        limitations=['Native outer gate/event bodies execute, but evaluator, scope cleanup and event formatter leaves are explicit component services.',
            'C++ string allocator/free are explicit Effects, not matching-libc allocator proof.',
            'These compare payload, initialized local scratch and the observed global page, not full native stack/TLS/OS.',
            'Helper C++ string returns and event wrapper native return ABI are not compared.',
            'Complete request, real URL/header/JNI, fresh signature and online behavior remain unresolved.'])
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print('event/gate',len(strings),'+',len(gates),'+',len(events),'native controls;',len(negative),'negative PASS')

if __name__=='__main__':main()
