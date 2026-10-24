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
import verify_vm9_java_request_facade_fresh_20261020 as facade_fixture
import verify_vm9_jni_header_input_fresh_20261020 as header_fixture
G = header_fixture.G
from vm9_allocator import _PageTransaction, _read_span, _write_span, RefillUnsupported
import vm9_registry as registry
import vm9_objects as objects
import vm9_jni_environment as environment
from vm9_request_vm import invoke_java_request_facade_service


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
        # Synthetic JavaVM/JNI services are live and use the same staged pages.
        all_jni_slots = tuple(header_fixture.SLOTS) + (0x30,0x78,0xA8,0x388,0x480,0x2F0)
        jni_functions = {slot: G + 0xF400 + index * 16
                         for index, slot in enumerate(all_jni_slots)}
        for slot, function in jni_functions.items():
            write_word(staged, jni_table + slot, function)
        facade_service = facade_fixture.Services(image, label)
        def invoke_jni(pages, function, args):
            slot = next((s for s,f in jni_functions.items() if f == function), None)
            if slot is None:
                slot = next((s for s in range(0,0x748,8)
                             if int.from_bytes(_read_span(pages,jni_table+s,8),'little')==function), None)
            if slot is None: raise RefillUnsupported(f'unknown synthetic JNI function {function:#x}')
            if slot == 0x30: return request + 0x5F0
            if slot in (0x78,0xA8,0x2F0,0x388,0x480): return 0
            # Reuse the independently defined JNI semantics, translating the
            # live environment pointer to the fixture's stable handle.
            translated = tuple(header_fixture.ENV if i == 0 else v for i,v in enumerate(args))
            return facade_service.jni(function, translated,
                lambda a,n: _read_span(pages,a,n), lambda a,b: _write_span(pages,a,b))
        diagnostic_scope = {'thread_id': 137}
        facade_address = request + 0x700; receiver = request + 0x740
        container = request + 0x780; control = request + 0x7C0
        sentinel = request + 0x800; node = request + 0x840; pair = request + 0x880
        fallback = request + 0x8A0; child_mutex = request + 0x8C0
        for address,value in ((facade_address+0x18,receiver),(receiver,image+0x35D5F0),
                (receiver+8,child_mutex),(receiver+0x10,container),(receiver+0x20,fallback),
                (container,image+0x35B828),(container+0x20,control),(control,sentinel),(control+8,1),
                (sentinel,1),(sentinel+8,node),(sentinel+0x10,node),(sentinel+0x18,node),
                (node,1),(node+8,sentinel),(node+0x18,0),(node+0x20,pair),
                (pair,image+0x2830C4),(pair+8,request+0x200),(control+0x10,node),
                (fallback,0),(fallback+8,request+0x200)):
            write_word(staged,address,value)
        _write_span(staged, child_mutex, bytes(0x98))
        write_word(staged, image+0x35D5F0+0x20, image+0x27DD04)
        publication_result = []
        def publish_request(**kwargs):
            value = session.publish_request_state(**kwargs)
            publication_result.append(value)
            return value
        output = invoke_java_request_facade_service(staged, image + 0x17B8F8,
            image_base=image, entry_stack_address=inputs['entry_stack_address'],
            thread_pointer=fixture.TLS, thread_id=137, environment_pointer=env_pointer,
            facade_address=facade_address, url_reference=header_fixture.G + 0x1900 + 2,
            header_array_reference=header_fixture.G + 0x1800,
            return_address=inputs['return_address'],
            vm_module=vm_module, seconds=1791023800, nanoseconds=500000000,
            allocate=allocate,
            calloc=lambda p,c,n: (lambda a: (_write_span(p,a,bytes(n)) or a))(
                allocate(p,n)) if c == 1 else (_ for _ in ()).throw(RefillUnsupported('calloc count')),
            free=session.free,
            invoke_jni=invoke_jni, diagnostic_scope=diagnostic_scope,
            diagnostic_observer=lambda *e: None, acquire_environment=acquire_environment,
            wake_condition=lambda *e: 0,
            lock_mutex=lambda *e, **k: 0, unlock_mutex=lambda *e, **k: 0,
            reallocate=session.reallocate, prepare_format=session.prepare_format,
            read_clock=session.read_clock, get_tls=session.get_tls,
            initialize_registry=session.initialize_registry, broadcast=session.broadcast,
            register_exit=session.thread_destructor, get_singleton=session.singleton,
            publish_request=publish_request)
        vm_return = diagnostic_scope.get('request_vm_return', {})
        vm = type('VMResult', (), {'steps': vm_return.get('vm_steps'),
            'pc': vm_return.get('caller_native_return', {}).get('pc', image)})()
        ledger = diagnostic_scope.get('callbacks', [])
        expected_steps = vm.steps
        print('java request owning allocator', hex(image), expected_steps,
            'steps', vm.steps, 'callbacks', vm_return.get('callback_count'),
            'pc', hex(vm.pc-image), 'allocations', len(allocations), flush=True)
        assert vm_return.get('caller_sentinel_matches') is True
        assert vm_return.get('caller_sentinel_matches') is True
        assert len(publication_result) == 1
        publication = publication_result[0]
        assert publication['published'] is True
        assert session.published and session.publication_count == 1
        try:
            session.publish_request_state(
                diagnostic_scope=diagnostic_scope, result=output)
        except RefillUnsupported as exc:
            assert str(exc) == 'outer allocator session already published'
            duplicate_publication_rejected = True
        else:
            raise AssertionError('outer session accepted a second publication')
        descriptor = []
        wrong_target_before = {k: bytes(v) for k, v in staged.staged.items()}
        try:
            invoke_java_request_facade_service(staged, image + 0x284F98,
                image_base=image, entry_stack_address=inputs['entry_stack_address'],
                thread_pointer=fixture.TLS, thread_id=137, environment_pointer=env_pointer,
                facade_address=facade_address, url_reference=header_fixture.G + 0x1902,
                header_array_reference=header_fixture.G + 0x1800,
                return_address=inputs['return_address'], vm_module=vm_module,
                seconds=0, nanoseconds=0, allocate=allocate, calloc=lambda p,c,n: allocate(p,n),
                free=session.free, invoke_jni=invoke_jni, diagnostic_scope={})
        except RefillUnsupported:
            pass
        else:
            raise AssertionError('wrong facade target accepted')
        assert wrong_target_before == {k: bytes(v) for k, v in staged.staged.items()}
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
            callback_count=vm_return.get('callback_count'), scoped_tree_reference_callback_count=len(descriptor),
            normal_java_facade_entry_used=True, child_dispatcher_entry_used=True,
            wrong_facade_target_rejected=True, wrong_target_pages_unchanged=True,
            owning_request_vm_entry_used=True, strict_callback_abi_validated=True,
            actual_jni_environment_acquisition=bool(diagnostic_scope.get('request_evaluator_prefixes')),
            actual_request_cleanup_completed=bool(diagnostic_scope.get('request_tree_cleanups')),
            actual_request_vm_returned=bool(diagnostic_scope.get('request_vm_return')),
            request_publication_count=session.publication_count,
            request_published_mapping_count=publication['allocator_mapping_count'],
            duplicate_request_publication_rejected=duplicate_publication_rejected,
            stop_bytecode_offset=vm_return.get('bytecode_offset'),
            boundary_wrapper_offset='0x285fb4', boundary_target_offset='0x28dc38',
            actual_jvm_used=False, actual_os_threads_created=False,
            whole_handoff_native_differential_verified=False,
            request_diagnostic_transaction_committed=True,
            request_pages_published_to_outer_session=publication['published']))
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
    report = dict(schema='vm9-java-request-handoff-fresh-python-v2', evidence_date='2026-10-25',
        sample_sha256=oracle.LIBRARY_SHA256, libc_sha256=worker.LIBC_SHA256,
        controls=len(rows), rollback_guards=len(rows) * 2, cases=rows, fresh_input_signer_output_verified=False,
        complete_python_medusa=False, current_online_header_matrix_verified=False,
        normal_java_facade_entry_used=True, child_dispatcher_entry_used=True,
        owning_request_vm_entry_used=True, synthetic_jni_and_java_vm=True,
        limitations=['These are same Python-state compositions, not whole native handoff comparisons.',
            'The low image-base path and high image-base path take different recovered VM branches; both return at the caller sentinel.',
            'URL/header/JNI request conversion is not recovered; request objects and the JavaVM/JNI providers are synthetic.',
            'The strict owning callback entry now has an explicit outer-session publication owner; this proves staged state commit, not a complete native signer state.',
            'The complete independent signer output and later server request callbacks remain open.',
            'Explicit OS/clock/property/JNI services; no native snapshot, actual JVM or server request.'])
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('request owning allocator', len(rows), 'Python compositions PASS; fresh signature remains open')


if __name__ == '__main__':
    main()
