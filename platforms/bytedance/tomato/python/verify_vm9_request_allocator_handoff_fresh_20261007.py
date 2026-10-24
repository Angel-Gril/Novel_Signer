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
import vm9_registry as registry
import vm9_objects as objects
import vm9_jni_environment as environment


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
        request = worker.TOP + 0x100
        _write_span(staged, request, bytes(0x800))
        prefix.resolve_request_memory_imports(staged, library, image)
        descriptor = request + 0x100
        _write_span(staged, descriptor, b''.join((image + offset).to_bytes(8, 'little')
            for offset in (0x182D6C, 0x182D6C, 0x188A94)))
        setup_allocations = []
        def setup_allocate(pages, size):
            pointer = session.allocate(pages, size)
            setup_allocations.append((size, pointer))
            return pointer
        header = setup_allocate(staged, 40)
        registry.construct_configuration_tree(staged, container_address=header,
            descriptor_address=descriptor, image_base=image, allocate=setup_allocate)
        objects.construct_reference_wrapper(staged, object_address=request,
            referenced_address=header, allocate=setup_allocate)
        pair = result.callback_pair_addresses[0]
        assert int.from_bytes(_read_span(staged, pair, 8), 'little') == image + 0x2830C4
        handler = int.from_bytes(_read_span(staged, pair + 8, 8), 'little')
        inputs = dict(entry_stack_address=worker.TOP, return_address=0xDEAD0000,
            thread_pointer=fixture.TLS, image_base=image, argument_x0=handler,
            argument_x1=request, argument_x2=0, argument_x3=request + 0x200,
            output_x8=request + 0x400)
        allocations = []
        def allocate(pages, size):
            pointer = session.allocate(pages, size)
            allocations.append((size, pointer))
            return pointer
        def write_word(pages, address, value):
            _write_span(pages, address, value.to_bytes(8, 'little'))
        vm_pointer = setup_allocate(staged, 64)
        vm_table = setup_allocate(staged, 64)
        env_pointer = setup_allocate(staged, 8)
        jni_table = setup_allocate(staged, 0x800)
        write_word(staged, image + 0x3DEED8, vm_pointer)
        write_word(staged, vm_pointer, vm_table)
        write_word(staged, vm_table + 0x30, 0x7400F000)
        write_word(staged, env_pointer, jni_table)
        write_word(staged, jni_table + 0x30, 0x7400F130)
        write_word(staged, jni_table + 0x720, 0x7400F820)
        def invoke_javavm(pages, function, args):
            assert function == 0x7400F000 and args[0] == vm_pointer
            write_word(pages, args[1], env_pointer)
            return 0
        def acquire_environment(pages, **kwargs):
            return environment.acquire_thread_environment(pages, image_base=image, **kwargs,
                get_tls=session.get_tls, register_destructor=session.thread_destructor,
                invoke_javavm=invoke_javavm)
        def invoke_jni(pages, function, args):
            assert args[0] == env_pointer and function in (0x7400F130, 0x7400F820)
            return 0
        diagnostic_scope = {'thread_id': 137}
        state, frame, vm, ledger, decoded = prefix.execute_prefix(
            staged, inputs, vm_module, 1791023800, 500000000, allocate=allocate,
            reallocate=session.reallocate, free=session.free,
            prepare_format=session.prepare_format,
            read_clock=session.read_clock,
            acquire_environment=acquire_environment,
            invoke_jni=invoke_jni,
            get_tls=session.get_tls,
            initialize_registry=session.initialize_registry,
            broadcast=session.broadcast,
            register_exit=session.register_destructor,
            get_singleton=session.singleton,
            diagnostic_scope=diagnostic_scope)
        expected_steps = 957 if image == 0x122C0000 else 2475
        print('request owning allocator', hex(image), expected_steps,
            'steps', vm.steps, 'callbacks', len(ledger),
            'allocations', len(allocations), flush=True)
        assert vm.steps == expected_steps and vm.pc - image == 0xFFB78
        assert ledger[-1][:2] == (0x285FB4, 0x28DC38)
        if expected_steps == 957:
            assert [size for size, _ in allocations] == [40, 40, 40, 48, 2048, 48, 4, 48, 24, 8, 9, 16, 8, 32, 16, 24, 10, 16, 40, 64, 128, 256, 8, 8, 64, 128, 256, 512, 1024, 40, 40, 32, 192]
        descriptor = [item for item in ledger if item[:2] == (0x2858BC, 0x25C324)]
        assert len(descriptor) == (1 if expected_steps == 957 else 2)
        output = descriptor[0][3][1]
        if expected_steps == 957:
            assert int.from_bytes(_read_span(state, output, 8), 'little') == allocations[0][1]
        if expected_steps == 957:
            assert int.from_bytes(_read_span(state, output + 8, 8), 'little') == allocations[6][1]
            assert int.from_bytes(_read_span(state, allocations[6][1], 4), 'little') == 1
        for size, pointer in allocations:
            assert pointer and pointer % (8 if size == 40 else 4) == 0
            assert any(mapping.base <= pointer and pointer + size <= mapping.end
                       for mapping in session.tx.mappings)
        observation.append(dict(image_base=hex(image), property_profile=label,
            same_python_outer_output_used=True, native_input_snapshot_used=False,
            owning_allocator_session_used=True, allocator_returns_substituted=False,
            detached_page_copy_rejected_without_page_or_mapping_changes=True,
            actual_matching_libc_allocation_model_used=True,
            request_allocation_sizes=[size for size, _ in allocations],
            setup_allocation_sizes=[size for size, _ in setup_allocations],
            x8_reference_output_generated=True, reference_count_initial_value=1,
            allocated_spans_inside_owned_os_mappings=True,
            request_objects_are_synthetic=True, steps=vm.steps,
            callback_count=len(ledger), scoped_tree_reference_callback_count=len(descriptor),
            actual_jni_environment_acquisition=bool(diagnostic_scope.get('request_evaluator_prefixes')),
            actual_request_cleanup_completed=bool(diagnostic_scope.get('request_tree_cleanups')),
            actual_request_vm_returned=bool(diagnostic_scope.get('request_vm_return')),
            stop_bytecode_offset=hex(vm.pc - image),
            boundary_wrapper_offset='0x285fb4', boundary_target_offset='0x28dc38',
            actual_jvm_used=False, actual_os_threads_created=False,
            whole_handoff_native_differential_verified=False,
            request_diagnostic_transaction_committed=False))
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
    rows = []
    for image in (0x122C0000, 0x775C205000):
        for label, value in (('absent', None), ('sdk_30', b'30')):
            rows.append(case(args.library, args.libc, image, label, value, vm_full))
            print('request owning allocator', hex(image), label, 'PASS', flush=True)
    report = dict(schema='vm9-request-allocator-handoff-fresh-python-v2', evidence_date='2026-10-24',
        sample_sha256=oracle.LIBRARY_SHA256, libc_sha256=worker.LIBC_SHA256,
        controls=len(rows), cases=rows, fresh_input_signer_output_verified=False,
        complete_python_medusa=False, current_online_header_matrix_verified=False,
        limitations=['These are same Python-state compositions, not whole native handoff comparisons.',
            'The low image-base path and high image-base path take different recovered VM branches; both return at the caller sentinel.',
            'URL/header/JNI request conversion is not recovered; request objects and the JavaVM/JNI providers are synthetic.',
            'The complete independent signer output and later server request callbacks remain open.',
            'The disposable OS/allocator session and request page staging are not a published signer state.',
            'Explicit OS/clock/property/JNI services; no native snapshot, actual JVM or server request.'])
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('request owning allocator', len(rows), 'Python compositions PASS; fresh signature remains open')


if __name__ == '__main__':
    main()
