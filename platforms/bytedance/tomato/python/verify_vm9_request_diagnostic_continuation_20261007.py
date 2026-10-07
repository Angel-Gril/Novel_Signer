"""Same Python outer state -> request tree allocation with the owning session.

Only the existing outer allocator session may service this request. Snapshot
copies or a detached allocator session cannot provide its GuestOS staging chain.
This is Python composition; the tree itself has an independent native component
comparison, but this whole handoff is not a native differential.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import vm9_outer_allocator as outer_allocator
import vm9_registry as registry
import verify_vm9_outer_constructor_boundary as boundary
import verify_vm9_request_prefix_fresh_20261007 as prefix
import verify_vm9_worker_allocator as worker
import verify_vm9_root_configuration as fixture
import verify_vm9_signer_objects as oracle
from vm9_allocator import _PageTransaction, _read_span, _write_span, RefillUnsupported


def case(library, libc, image, label, property_value, vm_module):
    sessions, observation = [], []
    previous_make = outer_allocator.make_session
    def capture_session(*args, **kwargs):
        session = previous_make(*args, **kwargs)
        sessions.append(session)
        return session
    def terminal(pages, *, result, **unused):
        matching = [session for session in sessions if session.pages is pages]
        assert len(matching) == 1, 'request must use the session owning the outer pages'
        session = matching[0]
        # A plain page copy has no allocator/OS owner. It must be refused
        # before a result pointer or mapping side effect is published.
        copied = {key: bytearray(data) for key, data in pages.items()}
        before = {key: bytes(data) for key, data in copied.items()}
        mapping_before = (list(session.tx.mappings), session.tx.next_address)
        try:
            registry.construct_configuration_tree_reference(copied,
                output_reference_address=worker.TOP + 0x800,
                image_base=image, allocate=session.allocate)
        except RefillUnsupported as exc:
            assert str(exc) == 'base provider requires the owning OS staging chain'
        else:
            raise AssertionError('detached page copy accepted by owning allocator')
        assert {key: bytes(data) for key, data in copied.items()} == before
        assert (list(session.tx.mappings), session.tx.next_address) == mapping_before
        del copied, before
        staged = _PageTransaction(pages)
        memory_imports = prefix.resolve_request_memory_imports(staged, library, image)
        request = worker.TOP + 0x100
        _write_span(staged, request, bytes(0x800))
        pair = result.callback_pair_addresses[0]
        assert int.from_bytes(_read_span(staged, pair, 8), 'little') == image + 0x2830C4
        handler = int.from_bytes(_read_span(staged, pair + 8, 8), 'little')
        logger_address=int.from_bytes(_read_span(staged,image+0x3E1B08,8),'little')
        logger_begin=int.from_bytes(_read_span(staged,logger_address+40,8),'little')
        logger_end=int.from_bytes(_read_span(staged,logger_address+48,8),'little')
        assert logger_end-logger_begin==96
        old_record=_read_span(staged,logger_begin,96)
        inputs = dict(entry_stack_address=worker.TOP, return_address=0xDEAD0000,
            thread_pointer=fixture.TLS, image_base=image, argument_x0=handler,
            argument_x1=request, argument_x2=0, argument_x3=request + 0x200,
            output_x8=request + 0x400)
        allocations, frees, reallocations = [], [], []
        def allocate(pages, size):
            pointer = session.allocate(pages, size)
            allocations.append((size, pointer))
            return pointer
        def free(pages, pointer):
            frees.append(pointer)
            return session.free(pages, pointer)
        def reallocate(pages, pointer, size):
            reallocations.append((pointer, size))
            return session.reallocate(pages, pointer, size)
        import vm9_jni_environment
        diag = {'thread_id': session.thread_id}
        def acquire_environment(pages, **inputs):
            storage=int.from_bytes(_read_span(pages,image+0x374F90,8),'little')
            receipt=dict(component_entry_offset='0x26edc4',java_vm_storage_offset=hex(storage-image),
                java_vm_pointer=int.from_bytes(_read_span(pages,storage,8),'little'),
                owning_tls_allocator_provider_used=True,java_vm_service_configured=False,
                component_completed=False,parent_request_transaction_committed=False)
            diag.setdefault('jni_environment_acquisitions',[]).append(receipt)
            allocation_sequence=unused['allocation_sequence']
            before=len(allocation_sequence)
            try:
                result=vm9_jni_environment.acquire_thread_environment(pages,image_base=image,**inputs,
                    get_tls=session.get_tls,register_destructor=session.thread_destructor,invoke_javavm=None)
            except RefillUnsupported as exc:
                receipt.update(failure=str(exc),unresolved_leaf_target_offset='0x26ef7c')
                raise
            else:
                receipt.update(component_completed=True,environment=result.environment)
                return result
            finally:
                receipt['owning_tls_allocation_sizes']=[size for size,_ in allocation_sequence[before:]]
        clock_reads = []
        def read_clock(pages, clock_id):
            result = session.read_clock(pages, clock_id)
            clock_reads.append([clock_id, *result])
            return result
        try:
            state, frame, vm, ledger, decoded = prefix.execute_prefix(
                staged, inputs, vm_module, 1791023800, 500000000,
                allocate=allocate, diagnostic_scope=diag,
                reallocate=reallocate, free=free, prepare_format=session.prepare_format,
                read_clock=read_clock,acquire_environment=acquire_environment)
            continuation_error = None
        except prefix.RequestContinuationBoundary as exc:
            state, frame, vm, ledger, decoded = (exc.staged, exc.frame, exc.vm,
                exc.ledger, exc.decoded)
            continuation_error = f"{type(exc.cause).__name__}: {exc.cause}"
        print('request continuation', hex(image), vm.steps, hex(vm.pc - image), continuation_error, flush=True)
        nested = diag.get('nested_getters', [])
        assert not reallocations, 'this composition must not silently substitute real realloc'
        if image == 0x122C0000:
            assert vm.steps == 957 and vm.pc - image == 0xFFB78
            assert continuation_error is None
            assert diag['request_vm_return']['caller_sentinel_matches']
            assert diag['request_vm_return']['selected_slot']==31
            assert len(nested) == 1
            assert len(diag.get('formatted_strings', [])) == 1
            formatted = diag['formatted_strings'][0]
            assert formatted['signed_int32'] == -5 and formatted['declared_length'] == 11
            assert formatted['format_bytes_hex'] == '25647c2573'
            assert len(diag.get('configuration_insertions', [])) == 1
            assert len(diag.get('string_cleanups', [])) == 1
            assert len(frees) == 18
            assert frees[-1]==logger_begin
            assert len(diag.get('request_event_prefixes', [])) == 1
            event_prefix = diag['request_event_prefixes'][0]
            assert event_prefix['phase'] == 'before_first_formatter'
            assert event_prefix['emit_error_event'] == 0
            assert event_prefix['first_object_hex'] == event_prefix['first_copy_hex']
            assert event_prefix['first_object_hex'][:2] == '22'
            assert event_prefix['second_object_hex'][:2] == '26'
            assert not event_prefix['body_transaction_committed']
            assert len(diag.get('request_event_leaf_prefixes', [])) == 8
            sampling, mode_prefix, mode_body, event_arguments, arguments_body, emission, emission_completed, formatter_completed = diag['request_event_leaf_prefixes']
            assert sampling['phase'] == 'sampling_decision' and sampling['selected']
            assert sampling['divisor'] == 10 and sampling['sequence'] == 0
            assert sampling['argument_words'] == [0, 0, 0, 0]
            assert mode_prefix['phase'] == 'before_mode_format_builder'
            assert mode_prefix['unresolved_leaf_target_offset'] == '0x28f0f4'
            assert mode_prefix['mode'] == 0
            assert mode_prefix['format_address'] == image + 0x3E1AD0
            assert not mode_prefix['body_transaction_committed']
            assert mode_body['phase'] == 'mode_body_completed'
            assert mode_body['bounded_mode_body_completed'] and mode_body['rendered_length'] == 8
            assert not mode_body['whole_request_callback_completed']
            assert event_arguments['phase'] == 'before_event_arguments_formatter'
            assert event_arguments['call_target_offset'] == '0x28e86c'
            assert event_arguments['unresolved_leaf_target_offset'] is None
            assert event_arguments['mode_cpp_object_hex'].startswith('107b227830223a307d00')
            assert not event_arguments['body_transaction_committed']
            assert all(not row['whole_callback_transaction_committed'] for row in diag['request_event_leaf_prefixes'])
            assert arguments_body['phase'] == 'event_arguments_body_completed'
            assert arguments_body['bounded_event_arguments_body_completed'] and arguments_body['rendered_length'] == 29
            assert not arguments_body['whole_request_callback_completed']
            assert emission['phase'] == 'before_event_emission'
            assert emission['unresolved_leaf_target_offset'] == '0x28ff44'
            assert emission['mode_cpp_object_hex'].startswith('107b227830223a307d00')
            assert emission['arguments_cpp_object_hex'][:2] == '21'
            assert emission['auxiliary_cpp_object_hex'].startswith('047b7d00')
            assert not emission['body_transaction_committed']
            assert emission_completed['phase']=='event_emission_completed' and emission_completed['appended']
            assert emission_completed['record_count']==2 and not emission_completed['dropped']
            assert formatter_completed['phase']=='event_formatter_completed' and formatter_completed['body_transaction_committed']
            assert len(diag['request_event_completed'])==1
            assert diag['request_event_completed'][0]['bounded_request_event_returned']
            assert diag['request_event_completed'][0]['formatter_calls']==1
            assert [size for size, _ in allocations][-14:] == [64,128,256,8,8,64,128,256,512,1024,40,40,32,192]
            assert len(allocations)==33
            current_begin=int.from_bytes(_read_span(state,logger_address+40,8),'little')
            current_end=int.from_bytes(_read_span(state,logger_address+48,8),'little')
            assert current_end-current_begin==192
            assert _read_span(state,current_begin,96)==old_record
            emitted_record=current_begin+96
            def text(address):
                tag=_read_span(state,address,1)[0]
                length=int.from_bytes(_read_span(state,address+8,8),'little') if tag&1 else tag>>1
                pointer=int.from_bytes(_read_span(state,address+16,8),'little') if tag&1 else address+1
                return _read_span(state,pointer,length)
            assert text(emitted_record+24)==b'{"x0":0}'
            assert text(emitted_record+48)==b'{"x1":0,"x2":0,"x3":0,"x4":0}'
            assert text(emitted_record+72)==b'{}'
            assert _read_span(state,emitted_record+48,1)==b'\x21'
            assert _read_span(state,logger_address,2)==bytes(2)
            assert _read_span(state,inputs['output_x8'],16)==allocations[0][1].to_bytes(8,'little')+allocations[3][1].to_bytes(8,'little')
            staged.commit()
            assert _read_span(pages,current_begin,192)==_read_span(state,current_begin,192)
            assert len(diag.get('elapsed_clocks', [])) == 1
            assert diag['elapsed_clocks'][0]['elapsed_microseconds'] == 0
            assert clock_reads == [[1, 0, 1791023800, 500000000]] * 2
        else:
            assert image == 0x775C205000
            assert vm.steps == 965 and vm.pc - image == 0xF8FD0
            assert continuation_error == 'RefillUnsupported: JavaVM unavailable for AttachCurrentThread +0x26ef7c'
            assert not nested and not diag.get('formatted_strings')
            assert len(diag.get('string_comparisons', [])) == 1
            assert diag['string_comparisons'][0]['equal'] is False
            assert len(diag.get('guard_acquires', [])) == 1 and diag['guard_acquires'][0]['acquired']
            assert [item['length'] for item in diag.get('memory_fills', [])] == [160]
            assert all(item['value'] == 0 for item in diag['memory_fills'])
            assert len(diag.get('raw_mutex_states', [])) == 1
            assert diag['raw_mutex_states'][0]['cleared_bytes'] == 140
            assert len(diag.get('guard_releases', [])) == 1
            release = diag['guard_releases'][0]
            assert release['guard_before_hex'][:4] == '0002'
            assert release['guard_after_hex'][:4] == '0101'
            assert release['guard_before_hex'][4:] == release['guard_after_hex'][4:]
            assert not release['broadcast_executed']
            assert clock_reads == [[1, 0, 1791023800, 500000000]] * 2
            assert len(diag.get('request_boolean_prefixes', [])) == 1
            boolean_prefix = diag['request_boolean_prefixes'][0]
            assert boolean_prefix['phase'] == 'before_evaluator' and boolean_prefix['evaluator_needed']
            assert boolean_prefix['addresses']['evaluator'] == image + 0x28B05C
            assert boolean_prefix['scope_hex'][16:18] == '01'
            assert not boolean_prefix['body_transaction_committed']
            assert len(diag.get('request_evaluator_prefixes', [])) == 1
            evaluator = diag['request_evaluator_prefixes'][0]
            assert evaluator['phase'] == 'before_jni_acquisition'
            assert evaluator['unresolved_leaf_target_offset'] == '0x26edc4'
            assert len(diag.get('jni_environment_acquisitions',[]))==1
            acquisition=diag['jni_environment_acquisitions'][0]
            assert acquisition['owning_tls_allocator_provider_used'] and acquisition['java_vm_pointer']==0
            assert acquisition['java_vm_storage_offset']=='0x3deed8'
            assert acquisition['unresolved_leaf_target_offset']=='0x26ef7c'
            assert not acquisition['component_completed'] and not acquisition['parent_request_transaction_committed']
            assert len(evaluator['globals']) == 9 and evaluator['descriptor_count'] == 2
            assert evaluator['descriptor_address'] == boolean_prefix['evaluator_argument_address']
            assert evaluator['method_name_address'] == boolean_prefix['addresses']['second_name']
            assert not evaluator['body_transaction_committed']
            assert len(diag.get('shared_state_pointers', [])) == 1
            getter = diag['shared_state_pointers'][0]
            assert getter['readers_before'] == getter['readers_after'] == 0
            assert getter['object_address'] == diag['raw_mutex_states'][0]['storage_address']
            assert not getter['pointed_value_dereferenced']
        assert any(item['symbol']=='memset' and item['relocation_offset']=='0x382c80'
                   and item['target_offset']=='0x347f20' and item['relocation_kind']==257
                   for item in memory_imports)
        for getter in nested:
            assert getter['vm_steps'] == 54 and getter['vm_exit_pc'] == image + 0x99150
            assert getter['output_matches_receiver']
            assert getter['acquire_reader_count'] == getter['released_reader_count'] + 1
        if diag.get('request_vm_return'):
            next_callback=None
        else:
            inner=diag['request_evaluator_prefixes'][-1]
            next_callback=dict(wrapper_offset=hex(ledger[-1][0]),
                bounded_callback_orchestration_component_verified=True,
                supported_prefix_staged_without_transaction_commit=True,
                unresolved_leaf_target_offset=diag.get('jni_environment_acquisitions',[inner])[-1]['unresolved_leaf_target_offset'],
                target_offset=hex(ledger[-1][1]) if ledger[-1][3][0] else None,
                target_address=hex(ledger[-1][3][0]),null_target=not bool(ledger[-1][3][0]),
                packed_words=[hex(word) for word in ledger[-1][3]],
                callback_body_implemented=False,native_outer_branch_equivalence_verified=False)
        assert any(item[:2] == (0x2858D0, 0x26C858) for item in ledger)
        assert [size for size, _ in allocations][:4] == [40, 40, 40, 4]
        descriptor = [item for item in ledger if item[:2] == (0x2858BC, 0x25C324)]
        assert len(descriptor) == 1
        output = descriptor[0][3][1]
        assert int.from_bytes(_read_span(state, output, 8), 'little') == allocations[0][1]
        assert int.from_bytes(_read_span(state, output + 8, 8), 'little') == allocations[3][1]
        assert int.from_bytes(_read_span(state, allocations[3][1], 4), 'little') == 1
        for size, pointer in allocations:
            assert pointer and pointer % (8 if size == 40 else 4) == 0
            assert any(mapping.base <= pointer and pointer + size <= mapping.end
                       for mapping in session.tx.mappings)
        observation.append(dict(image_base=hex(image), property_profile=label,
            same_python_outer_output_used=True, native_input_snapshot_used=False,
            owning_allocator_session_used=True, allocator_returns_substituted=False,
            detached_page_copy_rejected_without_page_or_mapping_changes=True,
            actual_matching_libc_allocation_model_used=True,
            request_allocation_sizes=[size for size, _ in allocations], diagnostic_events=diag.get('events', []),
            diagnostic_scopes=[dict(table_index=s.table_index, entry_address=hex(s.entry_address), lock_result=s.lock_result) for s in diag.get('scopes', [])],
            nested_getters=diag.get('nested_getters', []),
            continued_after_nested_getter=bool(diag.get('nested_getters')),
            nested_getter_source_state_injected=False,
            string_comparisons=diag.get('string_comparisons', []),
            formatted_strings=diag.get('formatted_strings', []),
            continued_after_string_comparison=bool(diag.get('string_comparisons')),
            continued_after_signed_formatter=bool(diag.get('formatted_strings')),
            request_free_addresses=[hex(pointer) for pointer in frees],
            request_reallocation_requests=[[hex(pointer), size] for pointer, size in reallocations],
            matching_libc_realloc_implemented=False,
            string_cleanups=diag.get('string_cleanups', []),
            cstring_constructors=diag.get('cstring_constructors', []),
            guard_acquires=diag.get('guard_acquires', []),
            guard_releases=diag.get('guard_releases', []),
            raw_mutex_states=diag.get('raw_mutex_states', []),
            shared_state_pointers=diag.get('shared_state_pointers', []),
            request_event_prefixes=diag.get('request_event_prefixes', []),
            request_boolean_prefixes=diag.get('request_boolean_prefixes', []),
            request_event_leaf_prefixes=diag.get('request_event_leaf_prefixes', []),
            request_evaluator_prefixes=diag.get('request_evaluator_prefixes', []),
            jni_environment_acquisitions=diag.get('jni_environment_acquisitions',[]),
            native_jni_acquisition_stub_used=False,
            actual_jni_acquisition_body_executed=False,
            inner_callback_body_transaction_committed=bool(diag.get('request_event_completed')),
            clock_stores=diag.get('clock_stores', []),
            elapsed_clocks=diag.get('elapsed_clocks', []),
            request_clock_reads=clock_reads,
            owning_clock_provider_used=True,
            actual_os_clock_executed=False,
            memory_import_relocations=memory_imports,
            memory_fills=diag.get('memory_fills', []),
            configuration_insertions=diag.get('configuration_insertions', []),
            next_callback=next_callback,
            request_vm_return=diag.get('request_vm_return'),
            request_event_completed=diag.get('request_event_completed',[]),
            request_parent_transaction_committed_to_owning_session=bool(diag.get('request_vm_return')),
            complete_low_synthetic_request_vm_model_returned=bool(diag.get('request_vm_return')),
            callback_ledger=[dict(wrapper=hex(item[0]), target=hex(item[1]), argument=hex(item[2]), words=[hex(x) for x in item[3]]) for item in ledger],
            continuation_error=continuation_error,
            x8_reference_output_generated=True, reference_count_initial_value=1,
            allocated_spans_inside_owned_os_mappings=True,
            request_objects_are_synthetic=True, steps=vm.steps,
            stop_bytecode_offset=hex(vm.pc - image),
            boundary_wrapper_offset=next_callback['wrapper_offset'] if next_callback else None,
            boundary_target_offset=next_callback['target_offset'] if next_callback else None,
            initial_diagnostic_wrapper_offset='0x2858d0',
            initial_diagnostic_target_offset='0x26c858',
            actual_jvm_used=False, actual_os_threads_created=False,
            whole_handoff_native_differential_verified=False,
            request_diagnostic_transaction_committed=bool(diag.get('scopes')),
            continued_after_diagnostic=True))
    outer_allocator.make_session = capture_session
    try:
        result = boundary.case(library, libc, image, label, property_value, vm_module,
            apply_logger_model=True, apply_handoff_model=True, apply_publication=True,
            terminal_observer=terminal)
    finally:
        outer_allocator.make_session = previous_make
    assert result['python_constructor_returned'] and result['publication_applied']
    assert len(observation) == 1
    return observation[0]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--library', type=Path, default=boundary.LIBRARY)
    parser.add_argument('--libc', type=Path, default=boundary.LIBC)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest() == worker.LIBC_SHA256
    os.environ['TOMATO_LIBMETASEC'] = str(args.library.resolve())
    import vm_full
    rows = [case(args.library, args.libc, image, 'absent', None, vm_full)
            for image in (0x122C0000, 0x775C205000)]
    report = dict(schema='vm9-request-diagnostic-continuation-probe-v1', evidence_date='2026-10-07',
        sample_sha256=oracle.LIBRARY_SHA256, libc_sha256=worker.LIBC_SHA256, controls=len(rows), cases=rows,
        synthetic_request_nested_getter_composition_verified=any(row['continued_after_nested_getter'] for row in rows),
        nested_getter_composition_controls=sum(row['continued_after_nested_getter'] for row in rows),
        high_image_outer_getter_continuation_verified=any(row['image_base']=='0x775c205000' and row['continued_after_nested_getter'] for row in rows),
        signed_format_composition_controls=sum(row['continued_after_signed_formatter'] for row in rows),
        equality_composition_controls=sum(row['continued_after_string_comparison'] for row in rows),
        matching_libc_realloc_implemented=False,
        elapsed_clock_composition_controls=sum(bool(row['elapsed_clocks']) for row in rows),
        raw_mutex_state_composition_controls=sum(bool(row['raw_mutex_states']) for row in rows),
        serial_guard_release_composition_controls=sum(bool(row['guard_releases']) for row in rows),
        shared_state_pointer_composition_controls=sum(bool(row['shared_state_pointers']) for row in rows),
        actual_os_clock_executed=False,
        request_event_prefix_composition_controls=sum(bool(row['request_event_prefixes']) for row in rows),
        request_boolean_prefix_composition_controls=sum(bool(row['request_boolean_prefixes']) for row in rows),
        request_event_leaf_prefix_composition_controls=sum(bool(row['request_event_leaf_prefixes']) for row in rows),
        request_mode_body_composition_controls=sum(any(item.get('bounded_mode_body_completed') for item in row['request_event_leaf_prefixes']) for row in rows),
        request_event_arguments_body_composition_controls=sum(any(item.get('bounded_event_arguments_body_completed') for item in row['request_event_leaf_prefixes']) for row in rows),
        request_evaluator_prefix_composition_controls=sum(bool(row['request_evaluator_prefixes']) for row in rows),
        native_jni_acquisition_stub_used=False,
        actual_jni_acquisition_body_executed=False,
        python_jni_acquisition_started_composition_controls=sum(bool(row['jni_environment_acquisitions']) for row in rows),
        java_vm_service_configured=False,
        inner_callback_body_transaction_committed=any(bool(row['request_event_completed']) for row in rows),
        request_event_return_composition_controls=sum(bool(row['request_event_completed']) for row in rows),
        request_vm_model_return_composition_controls=sum(bool(row['request_vm_return']) for row in rows),
        whole_handoff_native_differential_verified=False,
        real_url_headers_jni_conversion_verified=False,
        no_jvm_rust_signer_complete=False,
        complete_python_medusa=False, fresh_input_signer_output_verified=False,
        current_online_header_matrix_verified=False,
        limitations=['This is a same Python outer/request composition, not whole native handoff differential.',
            'Request URL/header/JNI conversion and later callback bodies remain unresolved.',
            'A continuation error marks the next callback boundary; it is not treated as a signature failure.',
            'Equality and signed format callbacks have component native differences; whole-native outer branch equivalence remains unverified.',
            'No JVM, server request or raw signature is used.'])
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('request diagnostic continuation probe written; next callback boundary is recorded')


if __name__ == '__main__':
    main()
