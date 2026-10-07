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
        request = worker.TOP + 0x100
        _write_span(staged, request, bytes(0x800))
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
        state, frame, vm, ledger, decoded = prefix.execute_prefix(
            staged, inputs, vm_module, 1791023800, 500000000, allocate=allocate)
        assert vm.steps == 611 and vm.pc - image == 0xF80A8
        assert ledger[-1][:2] == (0x2858D0, 0x26C858)
        assert [size for size, _ in allocations] == [40, 40, 40, 4]
        descriptor = [item for item in ledger if item[:2] == (0x2858BC, 0x25C324)]
        assert len(descriptor) == 1
        output = descriptor[0][3][1]
        assert int.from_bytes(_read_span(state, output, 8), 'little') == allocations[0][1]
        assert int.from_bytes(_read_span(state, output + 8, 8), 'little') == allocations[-1][1]
        assert int.from_bytes(_read_span(state, allocations[-1][1], 4), 'little') == 1
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
            x8_reference_output_generated=True, reference_count_initial_value=1,
            allocated_spans_inside_owned_os_mappings=True,
            request_objects_are_synthetic=True, steps=vm.steps,
            stop_bytecode_offset=hex(vm.pc - image),
            boundary_wrapper_offset='0x2858d0', boundary_target_offset='0x26c858',
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
    report = dict(schema='vm9-request-allocator-handoff-fresh-python-v1', evidence_date='2026-10-07',
        sample_sha256=oracle.LIBRARY_SHA256, libc_sha256=worker.LIBC_SHA256,
        controls=len(rows), cases=rows, fresh_input_signer_output_verified=False,
        complete_python_medusa=False, current_online_header_matrix_verified=False,
        limitations=['These are same Python-state compositions, not whole native handoff comparisons.',
            'URL/header/JNI request conversion is not recovered; request objects are synthetic.',
            'Stops at a diagnostic scope; later request callbacks and signature output remain open.',
            'The disposable OS/allocator session and request page staging are not a published signer state.',
            'Explicit OS/clock/property/JNI services; no native snapshot, actual JVM or server request.'])
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('request owning allocator', len(rows), 'Python compositions PASS; fresh signature remains open')


if __name__ == '__main__':
    main()
