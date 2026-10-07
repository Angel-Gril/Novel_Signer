"""Fresh original-body controls stopped before unresolved JNI/format leaves.

The native JNI acquisition stub is never used by these prefix controls:
Unicorn stops before +0x26edc4. No simulated JNI return validates that body.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from unicorn import arm64_const as arm
import vm9_objects as objects
import vm9_request_leaf_prefixes as leaf
from vm9_allocator import RefillUnsupported, _read_span, _write_span
from verify_vm9_signer_objects import GUEST, LIBRARY_SHA256, image_pages, fresh_pages, native

BASES = (0x122C0000, 0x775C205000)
STACK = GUEST + 0xEF00
DESCRIPTOR, METHOD, EVENT = (GUEST + n for n in (0x1600, 0x2000, 0x2800))


def fresh(library, image):
    return {**image_pages(library, image), **fresh_pages()}


def snapshot(pages):
    return {key: bytes(value) for key, value in pages.items()}


def evaluator_case(library, image, warm_indices, count):
    p = fresh(library, image)
    for index in warm_indices:
        name, flag, source, mask = leaf.EVALUATOR_GLOBAL_OFFSETS[index]
        objects.decode_masked_bytes(p, source_address=image + source,
            destination_address=image + name, mask_address=image + mask)
        # Nonzero flags must be preserved, including values other than one.
        _write_span(p, image + flag, (7).to_bytes(4, 'little'))
        _write_span(p, image + name, b'W')
    _write_span(p, DESCRIPTOR, METHOD.to_bytes(8, 'little') * 2)
    _write_span(p, METHOD, b'method_fixture\0')
    before = snapshot(p)
    windows = {(STACK - 0xB0, 0x48): None, (STACK - 0xF0, 0x20): None,
        (image + 0x3E1000, 4096): None}
    returned, memory, allocations, services = native(library, image, 0x28B05C,
        [DESCRIPTOR, count, METHOD], p, stop_offset=0x26EDC4,
        observed_memory=windows, instruction_limit=30000)
    assert returned == STACK - 0xE0 and not allocations and not services
    staged = []
    def observe(tx, **context):
        staged.append((context, {key: _read_span(tx, *key) for key in windows},
            _read_span(tx, GUEST, 0xA000)))
    try:
        leaf.execute_stack_evaluator_prefix(p, image_base=image,
            entry_stack_address=STACK, descriptor_address=DESCRIPTOR,
            descriptor_count=count, method_name_address=METHOD, observer=observe)
    except RefillUnsupported as exc:
        assert str(exc) == 'request JNI acquisition +0x26edc4 is not recovered'
    else:
        raise AssertionError('missing real JNI acquisition was accepted')
    assert snapshot(p) == before
    assert len(staged) == 1
    context, model_windows, payload = staged[0]
    for key, expected in windows.items():
        assert model_windows[key] == expected, (key, model_windows[key].hex(), expected.hex())
    assert payload == memory
    assert len(context['globals']) == 9
    for index, entry in enumerate(context['globals']):
        assert entry['decode_performed'] == (index not in warm_indices)
        assert entry['flag_before'] == (7 if index in warm_indices else 0)
    return dict(image_base=hex(image), warm_indices=list(warm_indices), descriptor_count=count,
        stopped_before_offset='0x26edc4', nine_lazy_globals_and_flags_match=True,
        initialized_input_and_encoded_pointer_slots_match=True,
        untouched_environment_pair_and_slot_match=True, full_payload_memory_match=True,
        staged_memory_matches_native_stop=True, transaction_committed=False,
        native_jni_acquisition_stub_used=False, actual_jni_acquisition_body_executed=False,
        native_input_snapshot_used=False)


def formatter_case(library, image, divisor, sequence, mode, warm):
    p = fresh(library, image)
    _write_span(p, image + 0x3839E8, divisor.to_bytes(8, 'little'))
    if warm:
        objects.decode_masked_bytes(p, source_address=image + 0x11F1CC,
            destination_address=image + 0x3E1AD0, mask_address=image + 0x11F1D8)
        _write_span(p, image + 0x3E1ADC, (9).to_bytes(4, 'little'))
        _write_span(p, image + 0x3E1AD0, b'W')
    words = (0x123456789ABCDEF0, 0x1122334455667788, 0x9988776655443322, sequence)
    selected = (sequence % divisor if divisor else sequence) == 0
    windows = {(STACK - 0x17C, 0x24): None, (image + 0x3E1000, 4096): None}
    if selected:
        windows[STACK - 0x210, 4] = None
    result, memory, allocations, services = native(library, image, 0x28DDD0,
        [EVENT, *words], p, extra_registers={arm.UC_ARM64_REG_X5: mode},
        stop_offset=0x28F0F4 if selected else None,
        observed_memory=windows, instruction_limit=30000)
    assert not allocations and not services
    if selected:
        assert result == image + 0x3E1AD0
    model = {key: bytearray(value) for key, value in p.items()}
    before = snapshot(model)
    staged = []
    def observe(tx, **context):
        staged.append((context, {key: _read_span(tx, *key) for key in windows},
            _read_span(tx, GUEST, 0xA000)))
    if selected:
        try:
            leaf.execute_event_formatter_prefix(model, image_base=image,
                entry_stack_address=STACK, event_object_address=EVENT,
                argument_words=words, mode=mode, observer=observe)
        except RefillUnsupported as exc:
            assert str(exc) == 'request mode format builder +0x28f0f4 is not recovered'
        else:
            raise AssertionError('missing real mode builder was accepted')
        assert snapshot(model) == before
        context, model_windows, payload = staged[-1]
        assert context['phase'] == 'before_mode_format_builder'
        assert context['argument_address'] == STACK - 0x210
        assert context['format_object_address'] == STACK - 0x260
        assert context['output_object_address'] == STACK - 0x198
        assert context['globals'][0]['decode_performed'] == (not warm)
        assert model_windows == windows and payload == memory
    else:
        assert leaf.execute_event_formatter_prefix(model, image_base=image,
            entry_stack_address=STACK, event_object_address=EVENT,
            argument_words=words, mode=mode, observer=observe) is False
        assert len(staged) == 1
        assert {key: _read_span(model, *key) for key in windows} == windows
        assert _read_span(model, GUEST, 0xA000) == memory
    assert staged[0][0]['selected'] == selected
    return dict(image_base=hex(image), divisor=divisor, sequence=sequence, mode=mode,
        warm_mode_global=warm, formatting_selected=selected,
        native_stopped_before_offset='0x28f0f4' if selected else None,
        unsampled_native_return_observed=not selected,
        abi_argument_slots_match=True, sampling_decision_matches_native_branch=True,
        mode_global_and_argument_match=selected,
        observed_global_page_match=True, full_payload_memory_match=True,
        transaction_committed=not selected, native_return_x0_compared=False,
        native_input_snapshot_used=False)


def negatives(library):
    image = BASES[0]
    result = []
    for label, mutation, operation, message in (
        ('encoded_table_mismatch', lambda p: _write_span(p,image+0x383860,bytes(8)),
            'evaluator', 'encoded global table'),
        ('negative_count', lambda p: None, 'negative_count', 'uint32'),
        ('misaligned_evaluator_stack', lambda p: None, 'bad_stack', 'aligned'),
        ('mode_exceeds_uint32', lambda p: None, 'bad_mode', 'uint32'),
        ('too_few_formatter_arguments', lambda p: None, 'bad_words', 'four uint64'),
        ('formatter_word_exceeds_uint64', lambda p: None, 'bad_word', 'uint64'),
    ):
        p = fresh(library,image); mutation(p); before=snapshot(p)
        try:
            if operation in ('evaluator','negative_count','bad_stack'):
                leaf.execute_stack_evaluator_prefix(p,image_base=image,
                    entry_stack_address=STACK+(1 if operation=='bad_stack' else 0),
                    descriptor_address=DESCRIPTOR,descriptor_count=-1 if operation=='negative_count' else 2,
                    method_name_address=METHOD)
            else:
                words=(0,0,0) if operation=='bad_words' else (0,0,0,1<<64 if operation=='bad_word' else 0)
                leaf.execute_event_formatter_prefix(p,image_base=image,entry_stack_address=STACK,
                    event_object_address=EVENT,argument_words=words,mode=1<<32 if operation=='bad_mode' else 0)
        except RefillUnsupported as exc:
            assert message in str(exc)
        else: raise AssertionError(label+' accepted')
        assert snapshot(p)==before;result.append(label+'_refused_without_page_changes')
    return result


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args();assert hashlib.sha256(args.library.read_bytes()).hexdigest()==LIBRARY_SHA256
    evaluators,formatters=[],[]
    for image in BASES:
        for warm,count in (((),2),(tuple(range(9)),2),((0,2,4,6,8),2),((1,3,5,7),0),((),0xFFFFFFFF)):
            evaluators.append(evaluator_case(args.library,image,warm,count))
            print('evaluator prefix',hex(image),warm,count,'PASS',flush=True)
        for divisor,sequence,mode,warm in ((10,0,0,False),(10,1,7,False),(10,9,0,False),
                (10,10,7,False),(10,11,0,False),(10,leaf.MASK64,0,False),
                (0,0,0xFFFFFFFF,False),(0,1,0,False),(1,leaf.MASK64,7,True),
                (10,20,0,True)):
            formatters.append(formatter_case(args.library,image,divisor,sequence,mode,warm))
            print('formatter prefix',hex(image),divisor,sequence,mode,warm,'PASS',flush=True)
    negative=negatives(args.library)
    report=dict(schema='vm9-request-leaf-prefixes-fresh-differential-v1',evidence_date='2026-10-07',
        sample_sha256=LIBRARY_SHA256,evaluator_prefix_controls=len(evaluators),
        event_formatter_controls=len(formatters),negative_controls=len(negative),
        evaluator_prefix_cases=evaluators,event_formatter_cases=formatters,negative_checks=negative,
        evaluator_native_body_executed_to_acquisition_call=True,
        native_jni_acquisition_stub_used=False,actual_jni_acquisition_body_executed=False,
        event_formatter_native_body_executed_to_mode_builder_call=True,
        actual_mode_format_builder_body_executed=False,native_input_snapshot_used=False,
        complete_callback_body_verified=False,complete_python_medusa=False,
        fresh_input_signer_output_verified=False,current_online_header_matrix_verified=False,
        limitations=['Native stops before actual unresolved JNI acquisition and mode builder; no JNI result is supplied.',
            'Only unsampled event path returns; sampled/event and evaluator transactions refuse without committing.',
            'Synthetic component inputs compare initialized input/encoded-pointer slots, global page and payload, not full stack/TLS/OS.',
            'Nonzero JNI stack-trace walk, string comparisons and request URL/headers/JNI conversions are not restored.'])
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print('request leaf prefixes PASS',len(evaluators),len(formatters),len(negative),flush=True)

if __name__=='__main__':main()
