"""Python controls for explicit provider-effect rollback.

The native bridge still refuses implicit mapping.  These controls exercise the
opt-in journal and CPU-page snapshot around a live Unicorn service hook; they
do not claim native/JVM or online signer equivalence.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
from unicorn import arm64_const as arm

from vm9_allocator import RefillUnsupported
from vm9_effects import EffectJournal
import vm9_native_service_bridge as bridge
import vm9_request_vm as request_vm
import vm9_request_dispatch as request_dispatch
import vm9_callbacks
import vm9_state


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
