"""Python controls for explicit provider-effect rollback.

The native bridge still refuses implicit mapping.  These controls exercise the
opt-in journal and CPU-page snapshot around a live Unicorn service hook; they
do not claim native/JVM or online signer equivalence.
"""
from __future__ import annotations

import argparse
import json
import inspect
from pathlib import Path

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
from unicorn import arm64_const as arm

from vm9_allocator import RefillUnsupported
from vm9_effects import EffectJournal
import vm9_native_service_bridge as bridge
import vm9_request_vm as request_vm
import vm9_request_dispatch as request_dispatch
import vm9_jni_request as jni_request
import vm9_callbacks
import vm9_state
import vm9_request_287474_vm as second_vm
import vm9_request_28048c_vm as child_vm
import vm9_request_environment_vm as environment_vm
import vm9_logger
import vm9_jni_environment
import vm9_request_caller
import vm9_configuration_init
import vm9_objects
import vm9_registry
import vm9_reference_scopes
import vm9_request_token_vm
import vm9_request_token_cipher
import vm9_request_token_tail
from vm9_allocator import _write_span


PAGE = 0x400000
TARGET = 0x401000


def _cpu():
    cpu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    cpu.mem_map(PAGE, 0x2000)
    cpu.mem_write(PAGE, bytes(range(256)) * 32)
    cpu.reg_write(arm.UC_ARM64_REG_PC, TARGET)
    cpu.reg_write(arm.UC_ARM64_REG_X0, PAGE)
    return cpu


def verify():
    rows = []

    # A provider can mutate both live CPU bytes and an external owner.  A
    # failing hook restores both when the caller explicitly opts in.
    cpu = _cpu()
    before = bytes(cpu.mem_read(PAGE, 0x2000))
    external = []
    journal = EffectJournal()

    def failing(pages, _fn, _args):
        pages[PAGE >> 12][0:8] = b"provider"
        external.append("mapping")
        journal.record_undo(lambda: external.pop())
        raise RefillUnsupported("controlled provider failure")

    imports = bridge.make_native_service_imports(
        [bridge.NativeService(TARGET, 1, failing)], image_base=0,
        effect_journal=journal, rollback_pages=True)
    try:
        imports[TARGET](cpu)
    except RefillUnsupported:
        pass
    else:
        raise AssertionError("failing provider unexpectedly returned")
    assert bytes(cpu.mem_read(PAGE, 0x2000)) == before
    assert external == [] and len(journal) == 0
    rows.append(dict(case="hook_failure", provider_effects_rolled_back=True,
        mapped_cpu_bytes_rolled_back=True, mapping_topology_unchanged=True))

    # Successful provider effects remain live until the owning caller commits
    # or explicitly rolls back its larger transaction.
    cpu = _cpu()
    before = bytes(cpu.mem_read(PAGE, 0x2000))
    external = []
    journal = EffectJournal()
    mark = journal.checkpoint()

    def successful(pages, _fn, _args):
        old = bytes(pages[PAGE >> 12][0:8])
        pages[PAGE >> 12][0:8] = b"commit!!"
        external.append("mapping")
        journal.record_undo(lambda: external.pop())
        journal.record_undo(lambda: cpu.mem_write(PAGE, old))
        return 7

    imports = bridge.make_native_service_imports(
        [bridge.NativeService(TARGET, 1, successful)], image_base=0,
        effect_journal=journal, rollback_pages=True)
    assert imports[TARGET](cpu) == 7
    assert bytes(cpu.mem_read(PAGE, 8)) == b"commit!!"
    assert external == ["mapping"] and len(journal) == 2
    journal.rollback(mark)
    assert bytes(cpu.mem_read(PAGE, 0x2000)) == before
    assert external == [] and len(journal) == 0
    rows.append(dict(case="outer_owner_rollback", successful_result=7,
        provider_effects_rolled_back=True, mapped_cpu_bytes_rolled_back=True))

    # Nested success records remain available to an outer failure.
    journal = EffectJournal()
    state = []
    try:
        with journal.transaction():
            state.append("outer")
            journal.record_undo(lambda: state.pop())
            with journal.transaction():
                state.append("inner")
                journal.record_undo(lambda: state.pop())
            raise RefillUnsupported("controlled outer rejection")
    except RefillUnsupported:
        pass
    assert state == [] and len(journal) == 0
    rows.append(dict(case="nested_outer_failure", inner_undo_preserved=True,
        reverse_order_rollback=True))

    # The owning request wrapper uses the same boundary around its VM
    # implementation.  Patch only the implementation seam so this control
    # checks the production wrapper without replaying a private ELF sample.
    original_impl = request_vm._execute_request_vm_impl
    external = []
    journal = EffectJournal()

    def failed_request(*_args, **_kwargs):
        external.append("request")
        journal.record_undo(lambda: external.pop())
        raise RefillUnsupported("controlled request failure")

    request_vm._execute_request_vm_impl = failed_request
    try:
        try:
            request_vm.execute_request_vm({}, {}, object(), 0, 0,
                effect_journal=journal)
        except RefillUnsupported:
            pass
        else:
            raise AssertionError("failed request unexpectedly returned")
    finally:
        request_vm._execute_request_vm_impl = original_impl
    assert external == [] and len(journal) == 0
    rows.append(dict(case="owning_request_failure", request_effects_rolled_back=True))

    external = []
    journal = EffectJournal()
    original_impl = request_vm._execute_request_vm_impl

    def successful_request(*_args, **_kwargs):
        external.append("request")
        journal.record_undo(lambda: external.pop())
        return "complete"

    request_vm._execute_request_vm_impl = successful_request
    try:
        try:
            with journal.transaction():
                assert request_vm.execute_request_vm({}, {}, object(), 0, 0,
                    effect_journal=journal) == "complete"
                assert external == ["request"] and len(journal) == 1
                raise RefillUnsupported("controlled outer rejection")
        except RefillUnsupported:
            pass
    finally:
        request_vm._execute_request_vm_impl = original_impl
    assert external == [] and len(journal) == 0
    rows.append(dict(case="nested_owning_request_success_then_outer_failure",
        outer_owner_retains_undo=True, explicit_outer_rollback=True))

    external = []
    journal = EffectJournal()
    original_child = request_dispatch._invoke_signer_child_request_impl

    def failed_child(*_args, **_kwargs):
        external.append("child")
        journal.record_undo(lambda: external.pop())
        raise RefillUnsupported("controlled child failure")

    request_dispatch._invoke_signer_child_request_impl = failed_child
    try:
        try:
            request_dispatch.invoke_signer_child_request(effect_journal=journal)
        except RefillUnsupported:
            pass
        else:
            raise AssertionError("failed child unexpectedly returned")
    finally:
        request_dispatch._invoke_signer_child_request_impl = original_child
    assert external == [] and len(journal) == 0
    rows.append(dict(case="child_dispatch_failure", child_provider_effects_rolled_back=True))

    # The Java facade must pass the same owner journal through both the child
    # dispatcher and its nested owning request VM callback.  A child-only
    # journal would leave nested provider effects outside the outer boundary.
    original_dispatch = request_dispatch.invoke_signer_child_request
    original_callback = request_vm.invoke_request_vm_callback
    captured = {}

    def fake_dispatch(*_args, **kwargs):
        captured["child_journal"] = kwargs.get("effect_journal")
        callback = kwargs["invoke_callback"]
        captured["result"] = callback(
            {}, 0x27DD04,
            url_reference_address=1, header_reference_address=2, mode=3,
            context_address=4, output_reference_address=5,
            entry_stack_address=0x1000,
        )
        return captured["result"]

    def fake_callback(*_args, **kwargs):
        captured["nested_journal"] = kwargs.get("effect_journal")
        return "nested-ok"

    request_dispatch.invoke_signer_child_request = fake_dispatch
    request_vm.invoke_request_vm_callback = fake_callback
    try:
        journal = EffectJournal()
        result = request_vm.invoke_java_request_service(
            {}, 0x27DD04, image_base=0, thread_pointer=7, thread_id=8,
            return_address=9, vm_module=object(), seconds=0, nanoseconds=0,
            receiver_address=10, url_reference_address=11,
            header_reference_address=12, mode=13, output_reference_address=14,
            entry_stack_address=0x1000, allocate=lambda *_: 0,
            free=lambda *_: None, diagnostic_scope={}, effect_journal=journal,
        )
        assert result == "nested-ok"
        assert captured["child_journal"] is journal
        assert captured["nested_journal"] is journal
    finally:
        request_dispatch.invoke_signer_child_request = original_dispatch
        request_vm.invoke_request_vm_callback = original_callback
    rows.append(dict(case="java_facade_nested_journal",
        child_journal_forwarded=True, nested_journal_forwarded=True))

    # The public normal-facade entry must preserve that same journal through
    # its facade callback closure as well.  This uses the production adapter;
    # only the JNI facade body is replaced so the boundary remains isolated.
    original_facade = jni_request.invoke_java_request_facade
    captured = {}
    def fake_facade(_pages, **kwargs):
        captured["facade_callback"] = kwargs["invoke_request"]
        return kwargs["invoke_request"](_pages, 0x27DD04,
            receiver_address=10, url_reference_address=11,
            header_reference_address=12, mode=13,
            output_reference_address=14, entry_stack_address=0x1000)
    jni_request.invoke_java_request_facade = fake_facade
    original_dispatch = request_dispatch.invoke_signer_child_request
    original_callback = request_vm.invoke_request_vm_callback
    def fake_dispatch(*_args, **kwargs):
        captured["facade_child_journal"] = kwargs.get("effect_journal")
        return kwargs["invoke_callback"]({}, 0x2830C4,
            url_reference_address=1, header_reference_address=2, mode=3,
            context_address=4, output_reference_address=5,
            entry_stack_address=0x1000)
    def fake_callback(*_args, **kwargs):
        captured["facade_nested_journal"] = kwargs.get("effect_journal")
        return "facade-nested-ok"
    request_dispatch.invoke_signer_child_request = fake_dispatch
    request_vm.invoke_request_vm_callback = fake_callback
    try:
        journal = EffectJournal()
        result = request_vm.invoke_java_request_facade_service(
            {}, 0x17B8F8, image_base=0, entry_stack_address=0x1000,
            thread_pointer=7, thread_id=8, environment_pointer=0,
            facade_address=10, url_reference=11, header_array_reference=12,
            return_address=9, vm_module=object(), seconds=0, nanoseconds=0,
            allocate=lambda *_: 0, calloc=lambda *_: 0, free=lambda *_: None,
            invoke_jni=lambda *_: 0, diagnostic_scope={}, effect_journal=journal)
        assert result == "facade-nested-ok"
        assert captured["facade_child_journal"] is journal
        assert captured["facade_nested_journal"] is journal
    finally:
        jni_request.invoke_java_request_facade = original_facade
        request_dispatch.invoke_signer_child_request = original_dispatch
        request_vm.invoke_request_vm_callback = original_callback
    rows.append(dict(case="java_facade_service_nested_journal",
        facade_callback_bound=True, child_journal_forwarded=True,
        nested_journal_forwarded=True))

    # Signer-handle publication is another external JNI owner.  Its default
    # path remains unchanged, while an opted-in journal removes a partial
    # first-handle effect if the second provider call fails.
    external = []
    journal = EffectJournal()

    def failing_invoke(*_args):
        external.append("jni-handle")
        journal.record_undo(lambda: external.pop())
        raise RefillUnsupported("controlled signer handle failure")

    try:
        vm9_callbacks.publish_signer_handle(
            root_address=1, environment=2, invoke=failing_invoke,
            get_reference_type=lambda *_: 0,
            delete_reference=lambda *_: None, effect_journal=journal,
        )
    except RefillUnsupported:
        pass
    else:
        raise AssertionError("failing signer handle unexpectedly returned")
    assert external == [] and len(journal) == 0
    rows.append(dict(case="signer_handle_provider_failure",
        jni_provider_effects_rolled_back=True))

    # The request-state elapsed getter has the same opt-in boundary around its
    # realtime provider.  Its guest page transaction remains page-only by
    # default, while a provider failure removes the external clock effect.
    pages = {1: bytearray(0x1000)}
    before = bytes(pages[1])
    external = []
    journal = EffectJournal()

    def failing_clock(_pages, _clock_id):
        external.append("clock")
        journal.record_undo(lambda: external.pop())
        raise RefillUnsupported("controlled clock failure")

    try:
        vm9_state.read_request_elapsed_seconds(
            pages, object_address=0x1000, read_clock=failing_clock,
            effect_journal=journal,
        )
    except RefillUnsupported:
        pass
    else:
        raise AssertionError("failing state clock unexpectedly returned")
    assert bytes(pages[1]) == before
    assert external == [] and len(journal) == 0
    rows.append(dict(case="state_clock_provider_failure",
        state_provider_effects_rolled_back=True, state_pages_unchanged=True))

    # Both second-VM realtime wrappers use the same journal boundary.
    for offset, callback, name in (
            (0x26CC60, second_vm.apply_request_287474_realtime_milliseconds_callback,
             "second_realtime_milliseconds_provider_failure"),
            (0x26CC64, second_vm.apply_request_287474_realtime_seconds_callback,
             "second_realtime_seconds_provider_failure")):
        pages = {2: bytearray(0x1000)}
        _write_span(pages, 0x2000, offset.to_bytes(8, "little"))
        before = bytes(pages[2])
        external = []
        journal = EffectJournal()

        def failing_second_clock(_pages, _clock_id):
            external.append("clock")
            journal.record_undo(lambda: external.pop())
            raise RefillUnsupported("controlled second clock failure")

        try:
            callback(pages, argument_block_address=0x2000,
                entry_stack_address=0x3000, image_base=0,
                read_clock=failing_second_clock, effect_journal=journal)
        except RefillUnsupported:
            pass
        else:
            raise AssertionError("failing second clock unexpectedly returned")
        assert bytes(pages[2]) == before
        assert external == [] and len(journal) == 0
        rows.append(dict(case=name, second_clock_effects_rolled_back=True,
            second_pages_unchanged=True))

    # Environment acquisition has the same opt-in boundary.  The explicit
    # journal is forwarded from the second VM through its child/helper calls;
    # a failing provider must leave both staged guest bytes and its external
    # ledger unchanged.
    assert inspect.getsource(environment_vm.execute_request_environment_vm_prefix).count(
        'effect_journal=effect_journal') >= 1
    assert inspect.getsource(second_vm.execute_request_287474_vm_prefix).count(
        'effect_journal=effect_journal') >= 3
    assert inspect.getsource(child_vm.execute_request_28048c_vm_prefix).count(
        'effect_journal=effect_journal') >= 2
    pages = {2: bytearray(0x1000)}
    _write_span(pages, 0x2000, (0x26EDC4).to_bytes(8, 'little'))
    _write_span(pages, 0x2008, (0x2400).to_bytes(8, 'little'))
    before = bytes(pages[2])
    external = []
    journal = EffectJournal()

    def failing_environment(p, **_kwargs):
        _write_span(p, 0x2200, b'environment')
        external.append('environment')
        journal.record_undo(lambda: external.pop())
        raise RefillUnsupported('controlled environment acquisition failure')

    try:
        environment_vm.apply_request_environment_acquisition_callback(
            pages, argument_block_address=0x2000, image_base=0,
            entry_stack_address=0x3000, acquire_environment=failing_environment,
            effect_journal=journal)
    except RefillUnsupported:
        pass
    else:
        raise AssertionError('failing environment acquisition unexpectedly returned')
    assert bytes(pages[2]) == before
    assert external == [] and len(journal) == 0
    rows.append(dict(case='environment_acquisition_provider_failure',
        environment_effects_rolled_back=True, environment_pages_unchanged=True,
        second_child_helper_journal_forwarded=True))

    # StringObject construction uses the same boundary for an allocator
    # provider.  The nested object transaction must not publish its vtable or
    # payload when allocation fails.
    pages = {2: bytearray(0x1000)}
    _write_span(pages, 0x2000, b''.join(value.to_bytes(8, 'little') for value in
        (0x248344, 0x2200, 0x2300)))
    _write_span(pages, 0x2300, b'x\0')
    before = bytes(pages[2])
    external = []
    journal = EffectJournal()

    def failing_string_allocate(p, _size):
        _write_span(p, 0x2400, b'string')
        external.append('string-allocation')
        journal.record_undo(lambda: external.pop())
        raise RefillUnsupported('controlled StringObject allocation failure')

    try:
        environment_vm.apply_request_environment_string_callback(
            pages, wrapper_offset=0x205064, argument_block_address=0x2000,
            image_base=0, allocate=failing_string_allocate, free=lambda *_: None,
            effect_journal=journal)
    except RefillUnsupported:
        pass
    else:
        raise AssertionError('failing StringObject allocation unexpectedly returned')
    assert bytes(pages[2]) == before
    assert external == [] and len(journal) == 0
    rows.append(dict(case='environment_string_allocator_failure',
        string_provider_effects_rolled_back=True, string_pages_unchanged=True))

    # The logger wrapper also owns a provider boundary.  Patch only its
    # already-established logger seam so this control isolates transaction
    # behavior without synthesizing a logger result or native sink output.
    pages = {2: bytearray(0x1000)}
    _write_span(pages, 0x2000, (0x26E9E0).to_bytes(8, 'little') +
        (0x2200).to_bytes(8, 'little') + (0x2300).to_bytes(8, 'little'))
    before = bytes(pages[2])
    external = []
    journal = EffectJournal()
    original_logger = vm9_logger.log_literal_unavailable

    def failing_logger(p, **_kwargs):
        _write_span(p, 0x2400, b'logger')
        external.append('logger')
        journal.record_undo(lambda: external.pop())
        raise RefillUnsupported('controlled logger provider failure')

    vm9_logger.log_literal_unavailable = failing_logger
    try:
        try:
            environment_vm.apply_request_environment_logger_callback(
                pages, argument_block_address=0x2000, image_base=0,
                entry_stack_address=0x3000, read_property=lambda *_: 0,
                syscall=lambda *_: 0, errno_address=0x2500,
                effect_journal=journal)
        except RefillUnsupported:
            pass
        else:
            raise AssertionError('failing logger unexpectedly returned')
    finally:
        vm9_logger.log_literal_unavailable = original_logger
    assert bytes(pages[2]) == before
    assert external == [] and len(journal) == 0
    rows.append(dict(case='environment_logger_provider_failure',
        logger_effects_rolled_back=True, logger_pages_unchanged=True))

    # JNI availability is an owning caller boundary too.  A provider failure
    # after the wrapper has staged its frame must remove external effects while
    # leaving the supplied pages untouched.
    pages = {index: bytearray(0x1000) for index in range(16)}
    _write_span(pages, 0x2000, (0x204B80).to_bytes(8, 'little'))
    _write_span(pages, 0x2800 + 0x28, b'canary!!')
    before = {key: bytes(value) for key, value in pages.items()}
    external = []
    journal = EffectJournal()
    original_availability = vm9_jni_environment.check_cached_static_method_availability

    def failing_availability(*_args, **_kwargs):
        external.append('jni-availability')
        journal.record_undo(lambda: external.pop())
        raise RefillUnsupported('controlled JNI availability failure')

    vm9_jni_environment.check_cached_static_method_availability = failing_availability
    try:
        try:
            vm9_request_caller.execute_request_jni_availability_wrapper(
                pages, image_base=0, entry_stack_address=0x3000,
                argument_block_address=0x2000, return_address=0x4000,
                thread_pointer=0x2800, acquire_environment=lambda *_a, **_k: None,
                invoke_jni=lambda *_a: 0, effect_journal=journal)
        except RefillUnsupported:
            pass
        else:
            raise AssertionError('failing JNI availability unexpectedly returned')
    finally:
        vm9_jni_environment.check_cached_static_method_availability = original_availability
    assert before == {key: bytes(value) for key, value in pages.items()}
    assert external == [] and len(journal) == 0
    rows.append(dict(case='jni_availability_provider_failure',
        jni_effects_rolled_back=True, jni_pages_unchanged=True))

    # The second VM's operator-new wrapper is another owning allocator
    # boundary. A provider that records an allocation and then fails must be
    # removed from the outer journal while the packed guest result stays staged.
    pages = {index: bytearray(0x1000) for index in range(16)}
    allocation_block = 0x2000
    _write_span(pages, allocation_block,
        (0x32A1F0).to_bytes(8, 'little') + (24).to_bytes(8, 'little'))
    before = {key: bytes(value) for key, value in pages.items()}
    external = []
    journal = EffectJournal()

    def failing_allocate(_pages, _size):
        external.append('malloc')
        journal.record_undo(lambda: external.pop())
        raise RefillUnsupported('controlled allocation provider failure')

    try:
        second_vm.apply_request_287474_allocation_callback(
            pages, argument_block_address=allocation_block,
            entry_stack_address=0x5000, image_base=0,
            allocate=failing_allocate, effect_journal=journal)
    except RefillUnsupported:
        pass
    else:
        raise AssertionError('failing allocation unexpectedly returned')
    assert before == {key: bytes(value) for key, value in pages.items()}
    assert external == [] and len(journal) == 0
    rows.append(dict(case='second_allocation_provider_failure',
        allocation_effects_rolled_back=True, allocation_pages_unchanged=True))

    # Formatter construction owns several allocator calls. The callback must
    # keep those provider undo records inside the same second-VM checkpoint.
    pages = {index: bytearray(0x1000) for index in range(16)}
    format_block = 0x2000
    _write_span(pages, format_block,
        (0x248908).to_bytes(8, 'little') + (0x3000).to_bytes(8, 'little')
        + (0x4000).to_bytes(8, 'little') + (7).to_bytes(4, 'little'))
    before = {key: bytes(value) for key, value in pages.items()}
    external = []
    journal = EffectJournal()
    original_formatter = vm9_configuration_init.format_string_object

    def failing_formatter(*_args, **_kwargs):
        external.append('formatter-allocate')
        journal.record_undo(lambda: external.pop())
        raise RefillUnsupported('controlled formatter provider failure')

    vm9_configuration_init.format_string_object = failing_formatter
    try:
        try:
            second_vm.apply_request_287474_string_format_callback(
                pages, argument_block_address=format_block,
                entry_stack_address=0x8000, image_base=0,
                allocate=lambda *_a: 0x5000, reallocate=lambda *_a: 0x5000,
                free=lambda *_a: 0, effect_journal=journal)
        except RefillUnsupported:
            pass
        else:
            raise AssertionError('failing formatter unexpectedly returned')
    finally:
        vm9_configuration_init.format_string_object = original_formatter
    assert before == {key: bytes(value) for key, value in pages.items()}
    assert external == [] and len(journal) == 0
    rows.append(dict(case='second_formatter_provider_failure',
        formatter_effects_rolled_back=True, formatter_pages_unchanged=True))

    # The explicit second-VM free tail is also an external provider boundary.
    pages = {index: bytearray(0x1000) for index in range(16)}
    consumer_block = 0x2000
    _write_span(pages, consumer_block,
        (0x32A264).to_bytes(8, 'little') + (0x5000).to_bytes(8, 'little'))
    before = {key: bytes(value) for key, value in pages.items()}
    external = []
    journal = EffectJournal()

    def failing_free(_pages, _address):
        external.append('free')
        journal.record_undo(lambda: external.pop())
        raise RefillUnsupported('controlled consumer free failure')

    try:
        second_vm.apply_request_287474_consumer(
            pages, wrapper_offset=0x288610,
            argument_block_address=consumer_block, image_base=0,
            allocate=lambda *_a: 0x6000, free=failing_free,
            effect_journal=journal)
    except RefillUnsupported:
        pass
    else:
        raise AssertionError('failing consumer free unexpectedly returned')
    assert before == {key: bytes(value) for key, value in pages.items()}
    assert external == [] and len(journal) == 0
    rows.append(dict(case='second_consumer_free_provider_failure',
        free_effects_rolled_back=True, consumer_pages_unchanged=True))

    # String assignment can allocate/reallocate before publishing its packed
    # result. Keep that external provider work within the same callback scope.
    pages = {index: bytearray(0x1000) for index in range(16)}
    assignment_block = 0x2000
    _write_span(pages, assignment_block,
        (0x2485A4).to_bytes(8, 'little') + (0x3000).to_bytes(8, 'little')
        + (0x4000).to_bytes(8, 'little'))
    before = {key: bytes(value) for key, value in pages.items()}
    external = []
    journal = EffectJournal()
    original_assign = vm9_objects.assign_string_object

    def failing_assign(*_args, **_kwargs):
        external.append('assignment-allocate')
        journal.record_undo(lambda: external.pop())
        raise RefillUnsupported('controlled assignment provider failure')

    vm9_objects.assign_string_object = failing_assign
    try:
        try:
            second_vm.apply_request_287474_string_assignment_callback(
                pages, wrapper_offset=0x28861C,
                argument_block_address=assignment_block, image_base=0,
                allocate=lambda *_a: 0x5000, reallocate=lambda *_a: 0x5000,
                free=lambda *_a: 0, effect_journal=journal)
        except RefillUnsupported:
            pass
        else:
            raise AssertionError('failing assignment unexpectedly returned')
    finally:
        vm9_objects.assign_string_object = original_assign
    assert before == {key: bytes(value) for key, value in pages.items()}
    assert external == [] and len(journal) == 0
    rows.append(dict(case='second_string_assignment_provider_failure',
        assignment_effects_rolled_back=True, assignment_pages_unchanged=True))

    # Configuration-reference construction is an allocator/JNI owner too.
    pages = {index: bytearray(0x1000) for index in range(16)}
    reference_block = 0x2000
    _write_span(pages, reference_block,
        (0x257804).to_bytes(8, 'little') + (0x3000).to_bytes(8, 'little')
        + (0x4000).to_bytes(8, 'little'))
    before = {key: bytes(value) for key, value in pages.items()}
    external = []
    journal = EffectJournal()
    original_reference = vm9_registry.read_configuration_string_reference

    def failing_reference(*_args, **_kwargs):
        external.append('reference-allocate')
        journal.record_undo(lambda: external.pop())
        raise RefillUnsupported('controlled reference provider failure')

    vm9_registry.read_configuration_string_reference = failing_reference
    try:
        try:
            second_vm.apply_request_287474_reference_getter_callback(
                pages, argument_block_address=reference_block,
                entry_stack_address=0x8000, image_base=0,
                thread_pointer=0x7000, allocate=lambda *_a: 0x5000,
                effect_journal=journal)
        except RefillUnsupported:
            pass
        else:
            raise AssertionError('failing reference getter unexpectedly returned')
    finally:
        vm9_registry.read_configuration_string_reference = original_reference
    assert before == {key: bytes(value) for key, value in pages.items()}
    assert external == [] and len(journal) == 0
    rows.append(dict(case='second_reference_provider_failure',
        reference_effects_rolled_back=True, reference_pages_unchanged=True))

    pages = {index: bytearray(0x1000) for index in range(16)}
    pair_block = 0x2000
    _write_span(pages, pair_block,
        (0x2633A4).to_bytes(8, 'little') + (0x3000).to_bytes(8, 'little')
        + (0x4000).to_bytes(8, 'little'))
    before = {key: bytes(value) for key, value in pages.items()}
    external = []
    journal = EffectJournal()
    original_pair = vm9_reference_scopes.copy_scoped_string_reference

    def failing_pair(*_args, **_kwargs):
        external.append('pair-allocate')
        journal.record_undo(lambda: external.pop())
        raise RefillUnsupported('controlled pair provider failure')

    vm9_reference_scopes.copy_scoped_string_reference = failing_pair
    try:
        try:
            second_vm.apply_request_287474_pair_getter_callback(
                pages, argument_block_address=pair_block,
                entry_stack_address=0x8000, image_base=0,
                thread_pointer=0x7000, allocate=lambda *_a: 0x5000,
                effect_journal=journal)
        except RefillUnsupported:
            pass
        else:
            raise AssertionError('failing pair getter unexpectedly returned')
    finally:
        vm9_reference_scopes.copy_scoped_string_reference = original_pair
    assert before == {key: bytes(value) for key, value in pages.items()}
    assert external == [] and len(journal) == 0
    rows.append(dict(case='second_pair_provider_failure',
        pair_effects_rolled_back=True, pair_pages_unchanged=True))

    pages = {index: bytearray(0x1000) for index in range(16)}
    cached_block = 0x2000
    _write_span(pages, cached_block,
        (0x1CF55C).to_bytes(8, 'little') + (0x3000).to_bytes(8, 'little'))
    before = {key: bytes(value) for key, value in pages.items()}
    external = []
    journal = EffectJournal()
    original_cached = vm9_jni_environment.copy_cached_dispatch_byte_reference

    def failing_cached(*_args, **_kwargs):
        external.append('cached-jni')
        journal.record_undo(lambda: external.pop())
        raise RefillUnsupported('controlled cached JNI provider failure')

    vm9_jni_environment.copy_cached_dispatch_byte_reference = failing_cached
    try:
        try:
            second_vm.apply_request_287474_cached_reference_callback(
                pages, argument_block_address=cached_block,
                entry_stack_address=0x8000, image_base=0,
                thread_pointer=0x7000, acquire_environment=lambda *_a, **_k: None,
                invoke_jni=lambda *_a: 0, register_exit=lambda *_a: 0,
                allocate=lambda *_a: 0x5000, calloc=lambda *_a: 0x6000,
                free=lambda *_a: 0, effect_journal=journal)
        except RefillUnsupported:
            pass
        else:
            raise AssertionError('failing cached JNI unexpectedly returned')
    finally:
        vm9_jni_environment.copy_cached_dispatch_byte_reference = original_cached
    assert before == {key: bytes(value) for key, value in pages.items()}
    assert external == [] and len(journal) == 0
    rows.append(dict(case='second_cached_reference_provider_failure',
        cached_reference_effects_rolled_back=True, cached_reference_pages_unchanged=True))

    pages = {index: bytearray(0x1000) for index in range(16)}
    json_string_block = 0x2000
    _write_span(pages, json_string_block,
        (0x2613E4).to_bytes(8, 'little') + (0x3000).to_bytes(8, 'little')
        + (0x4000).to_bytes(8, 'little') + (0x5000).to_bytes(8, 'little')
        + b'\0')
    before = {key: bytes(value) for key, value in pages.items()}
    external = []
    journal = EffectJournal()
    original_json_string = vm9_configuration_init.add_json_string_to_object

    def failing_json_string(*_args, **_kwargs):
        external.append('json-string-allocate')
        journal.record_undo(lambda: external.pop())
        raise RefillUnsupported('controlled JSON string provider failure')

    vm9_configuration_init.add_json_string_to_object = failing_json_string
    try:
        try:
            second_vm.apply_request_287474_json_string_callback(
                pages, argument_block_address=json_string_block,
                entry_stack_address=0x8000, image_base=0,
                allocate=lambda *_a: 0x6000, free=lambda *_a: 0,
                effect_journal=journal)
        except RefillUnsupported:
            pass
        else:
            raise AssertionError('failing JSON string unexpectedly returned')
    finally:
        vm9_configuration_init.add_json_string_to_object = original_json_string
    assert before == {key: bytes(value) for key, value in pages.items()}
    assert external == [] and len(journal) == 0
    rows.append(dict(case='second_json_string_provider_failure',
        json_string_effects_rolled_back=True, json_string_pages_unchanged=True))

    pages = {index: bytearray(0x1000) for index in range(16)}
    string_fill_block = 0x2000
    _write_span(pages, string_fill_block,
        (0x248DD8).to_bytes(8, 'little') + (0x3000).to_bytes(8, 'little')
        + (4).to_bytes(4, 'little') + b'Z')
    before = {key: bytes(value) for key, value in pages.items()}
    external = []
    journal = EffectJournal()
    original_fill = vm9_objects.fill_string_object

    def failing_fill(*_args, **_kwargs):
        external.append('string-fill-allocate')
        journal.record_undo(lambda: external.pop())
        raise RefillUnsupported('controlled string fill provider failure')

    vm9_objects.fill_string_object = failing_fill
    try:
        try:
            second_vm.apply_request_287474_string_fill_callback(
                pages, argument_block_address=string_fill_block,
                entry_stack_address=0x8000, image_base=0,
                allocate=lambda *_a: 0x6000, reallocate=lambda *_a: 0x6000,
                free=lambda *_a: 0, effect_journal=journal)
        except RefillUnsupported:
            pass
        else:
            raise AssertionError('failing string fill unexpectedly returned')
    finally:
        vm9_objects.fill_string_object = original_fill
    assert before == {key: bytes(value) for key, value in pages.items()}
    assert external == [] and len(journal) == 0
    rows.append(dict(case='second_string_fill_provider_failure',
        string_fill_effects_rolled_back=True, string_fill_pages_unchanged=True))

    pages = {index: bytearray(0x1000) for index in range(16)}
    json_block = 0x2000
    _write_span(pages, json_block,
        (0x261404).to_bytes(8, 'little') + (0x3000).to_bytes(8, 'little')
        + (0x4000).to_bytes(8, 'little'))
    before = {key: bytes(value) for key, value in pages.items()}
    external = []
    journal = EffectJournal()
    original_json = vm9_configuration_init.construct_empty_json_reference

    def failing_json(*_args, **_kwargs):
        external.append('json-reference-allocate')
        journal.record_undo(lambda: external.pop())
        raise RefillUnsupported('controlled JSON reference provider failure')

    vm9_configuration_init.construct_empty_json_reference = failing_json
    try:
        try:
            second_vm.apply_request_287474_json_callback(
                pages, argument_block_address=json_block,
                entry_stack_address=0x8000, image_base=0,
                thread_pointer=0x7000, allocate=lambda *_a: 0x6000,
                free=lambda *_a: 0, effect_journal=journal)
        except RefillUnsupported:
            pass
        else:
            raise AssertionError('failing JSON reference unexpectedly returned')
    finally:
        vm9_configuration_init.construct_empty_json_reference = original_json
    assert before == {key: bytes(value) for key, value in pages.items()}
    assert external == [] and len(journal) == 0
    rows.append(dict(case='second_json_reference_provider_failure',
        json_reference_effects_rolled_back=True, json_reference_pages_unchanged=True))

    pages = {index: bytearray(0x1000) for index in range(16)}
    transform_block = 0x2000
    _write_span(pages, transform_block,
        (0x248780).to_bytes(8, 'little') + (0x3000).to_bytes(8, 'little')
        + (0x4000).to_bytes(8, 'little') + (0x5000).to_bytes(8, 'little'))
    before = {key: bytes(value) for key, value in pages.items()}
    external = []
    journal = EffectJournal()
    original_clone = vm9_objects.clone_string_object

    def failing_clone(*_args, **_kwargs):
        external.append('token-transform-allocate')
        journal.record_undo(lambda: external.pop())
        raise RefillUnsupported('controlled token transform provider failure')

    vm9_objects.clone_string_object = failing_clone
    try:
        try:
            vm9_request_token_vm.apply_token_string_transform_callback(
                pages, wrapper_offset=0x2887F0,
                argument_block_address=transform_block, image_base=0,
                entry_stack_address=0x8000, allocate=lambda *_a: 0x6000,
                reallocate=lambda *_a: 0x6000, free=lambda *_a: 0,
                effect_journal=journal)
        except RefillUnsupported:
            pass
        else:
            raise AssertionError('failing token transform unexpectedly returned')
    finally:
        vm9_objects.clone_string_object = original_clone
    assert before == {key: bytes(value) for key, value in pages.items()}
    assert external == [] and len(journal) == 0
    rows.append(dict(case='second_token_transform_provider_failure',
        token_transform_effects_rolled_back=True, token_transform_pages_unchanged=True))

    pages = {index: bytearray(0x1000) for index in range(16)}
    digest_block = 0x2000
    _write_span(pages, digest_block,
        (0x25874C).to_bytes(8, 'little') + (0x3000).to_bytes(8, 'little')
        + (0x4000).to_bytes(8, 'little') + b'\1')
    before = {key: bytes(value) for key, value in pages.items()}
    external = []
    journal = EffectJournal()
    original_digest = vm9_reference_scopes.construct_scoped_digest_reference

    def failing_digest(*_args, **_kwargs):
        external.append('token-digest-allocate')
        journal.record_undo(lambda: external.pop())
        raise RefillUnsupported('controlled token digest provider failure')

    vm9_reference_scopes.construct_scoped_digest_reference = failing_digest
    try:
        try:
            vm9_request_token_vm.apply_token_digest_callback(
                pages, argument_block_address=digest_block, image_base=0,
                entry_stack_address=0x8000, thread_pointer=0x7000,
                allocate=lambda *_a: 0x6000, reallocate=lambda *_a: 0x6000,
                free=lambda *_a: 0, effect_journal=journal)
        except RefillUnsupported:
            pass
        else:
            raise AssertionError('failing token digest unexpectedly returned')
    finally:
        vm9_reference_scopes.construct_scoped_digest_reference = original_digest
    assert before == {key: bytes(value) for key, value in pages.items()}
    assert external == [] and len(journal) == 0
    rows.append(dict(case='second_token_digest_provider_failure',
        token_digest_effects_rolled_back=True, token_digest_pages_unchanged=True))

    pages = {index: bytearray(0x1000) for index in range(16)}
    cipher_block = 0x2000
    _write_span(pages, cipher_block,
        (0x287580).to_bytes(8, 'little') + (0x3000).to_bytes(8, 'little')
        + (0x4000).to_bytes(8, 'little') + (0x5000).to_bytes(8, 'little'))
    before = {key: bytes(value) for key, value in pages.items()}
    external = []
    journal = EffectJournal()
    original_cipher = vm9_request_token_cipher.encrypt_token_string_object

    def failing_cipher(*_args, **_kwargs):
        external.append('token-cipher-allocate')
        journal.record_undo(lambda: external.pop())
        raise RefillUnsupported('controlled token cipher provider failure')

    vm9_request_token_cipher.encrypt_token_string_object = failing_cipher
    try:
        try:
            vm9_request_token_vm.apply_token_cipher_callback(
                pages, argument_block_address=cipher_block, image_base=0,
                entry_stack_address=0x9000, thread_pointer=0x7000,
                allocate=lambda *_a: 0x6000, reallocate=lambda *_a: 0x6000,
                free=lambda *_a: 0, effect_journal=journal)
        except RefillUnsupported:
            pass
        else:
            raise AssertionError('failing token cipher unexpectedly returned')
    finally:
        vm9_request_token_cipher.encrypt_token_string_object = original_cipher
    assert before == {key: bytes(value) for key, value in pages.items()}
    assert external == [] and len(journal) == 0
    rows.append(dict(case='second_token_cipher_provider_failure',
        token_cipher_effects_rolled_back=True, token_cipher_pages_unchanged=True))

    pages = {index: bytearray(0x1000) for index in range(16)}
    tail_block = 0x2000
    _write_span(pages, tail_block,
        (0x248684).to_bytes(8, 'little') + (0x3000).to_bytes(8, 'little')
        + (0x4000).to_bytes(8, 'little'))
    before = {key: bytes(value) for key, value in pages.items()}
    external = []
    journal = EffectJournal()
    original_append = vm9_objects.append_string_object

    def failing_append(*_args, **_kwargs):
        external.append('token-tail-allocate')
        journal.record_undo(lambda: external.pop())
        raise RefillUnsupported('controlled token tail provider failure')

    vm9_objects.append_string_object = failing_append
    try:
        try:
            vm9_request_token_tail.apply_token_tail_callback(
                pages, wrapper_offset=0x288BF0, argument_block_address=tail_block,
                image_base=0, entry_stack_address=0x9000, thread_pointer=0x7000,
                allocate=lambda *_a: 0x6000, reallocate=lambda *_a: 0x6000,
                free=lambda *_a: 0, effect_journal=journal)
        except RefillUnsupported:
            pass
        else:
            raise AssertionError('failing token tail unexpectedly returned')
    finally:
        vm9_objects.append_string_object = original_append
    assert before == {key: bytes(value) for key, value in pages.items()}
    assert external == [] and len(journal) == 0
    rows.append(dict(case='second_token_tail_provider_failure',
        token_tail_effects_rolled_back=True, token_tail_pages_unchanged=True))

    pages = {index: bytearray(0x1000) for index in range(16)}
    base64_block = 0x2000
    _write_span(pages, base64_block,
        (0x258C14).to_bytes(8, 'little') + (0x3000).to_bytes(8, 'little')
        + (0x4000).to_bytes(8, 'little'))
    before = {key: bytes(value) for key, value in pages.items()}
    external = []
    journal = EffectJournal()
    original_base64 = vm9_request_token_tail.construct_base64_string_reference

    def failing_base64(*_args, **_kwargs):
        external.append('base64-allocate')
        journal.record_undo(lambda: external.pop())
        raise RefillUnsupported('controlled Base64 provider failure')

    vm9_request_token_tail.construct_base64_string_reference = failing_base64
    try:
        try:
            vm9_request_token_tail.apply_token_tail_callback(
                pages, wrapper_offset=0x288C10, argument_block_address=base64_block,
                image_base=0, entry_stack_address=0x9000, thread_pointer=0x7000,
                allocate=lambda *_a: 0x6000, reallocate=lambda *_a: 0x6000,
                free=lambda *_a: 0, effect_journal=journal)
        except RefillUnsupported:
            pass
        else:
            raise AssertionError('failing Base64 tail unexpectedly returned')
    finally:
        vm9_request_token_tail.construct_base64_string_reference = original_base64
    assert before == {key: bytes(value) for key, value in pages.items()}
    assert external == [] and len(journal) == 0
    rows.append(dict(case='second_base64_tail_provider_failure',
        base64_effects_rolled_back=True, base64_pages_unchanged=True))

    pages = {index: bytearray(0x1000) for index in range(16)}
    printf_block = 0x2000
    _write_span(pages, printf_block,
        (0x278314).to_bytes(8, 'little') + (0x3000).to_bytes(8, 'little')
        + (0x4000).to_bytes(8, 'little') + (0x5000).to_bytes(8, 'little'))
    _write_span(pages, 0x4000, b'%s\0')
    _write_span(pages, 0x5000, b'x\0')
    _write_span(pages, 0x7000 + 0x28, b'canary!!')
    before = {key: bytes(value) for key, value in pages.items()}
    external = []
    journal = EffectJournal()
    original_printf = vm9_request_token_tail.apply_token_printf_callback

    def failing_printf(*_args, **_kwargs):
        external.append('printf-allocate')
        journal.record_undo(lambda: external.pop())
        raise RefillUnsupported('controlled token printf provider failure')

    vm9_request_token_tail.apply_token_printf_callback = failing_printf
    try:
        try:
            second_vm.apply_request_287474_allocated_printf_callback(
                pages, argument_block_address=printf_block,
                entry_stack_address=0x9000, image_base=0,
                thread_pointer=0x7000, allocate=lambda *_a: 0x6000,
                effect_journal=journal)
        except RefillUnsupported:
            pass
        else:
            raise AssertionError('failing allocated printf unexpectedly returned')
    finally:
        vm9_request_token_tail.apply_token_printf_callback = original_printf
    assert before == {key: bytes(value) for key, value in pages.items()}
    assert external == [] and len(journal) == 0
    rows.append(dict(case='second_allocated_printf_provider_failure',
        allocated_printf_effects_rolled_back=True, allocated_printf_pages_unchanged=True))

    return dict(schema="vm9-provider-effect-rollback-v1",
        evidence_label="Sample verified",
        controls=rows, python_controls=len(rows), rollback_controls=len(rows),
        native_input_snapshot_used=False, live_jvm_verified=False,
        current_medusa_verified=False,
        implicit_mapping_or_unmapping=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = verify()
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + "\n",
            encoding="utf-8", newline="\n")
    print(json.dumps({k: v for k, v in result.items() if k != "controls"}))


if __name__ == "__main__":
    main()
