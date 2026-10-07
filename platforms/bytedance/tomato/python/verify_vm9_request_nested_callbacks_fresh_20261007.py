"""Fresh ORi controls and full nested string-getter callback differential."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

from unicorn import arm64_const as arm

import verify_vm9_signer_objects as oracle
from verify_vm9_libc_mapping import LIBC_SHA256
from verify_vm9_request_nested_fresh_20261007 import bounded_native, write
from vm9_allocator import RefillUnsupported, _read_span, _write_span
from vm9_request_nested import NORMAL_KEY, ori_request_word
from vm9_request_nested_callbacks import (execute_nested_string_getter,
    nested_getter_inputs_from_request)

MASK64 = (1 << 64) - 1


def ori_word(src, dst, immediate):
    return (48 | ((immediate & 31) << 16) | ((immediate & 0x7FE0) << 1)
            | ((immediate & 0x8000) << 6) | (dst << 22) | (src << 27))


def ori_case(library, image, control):
    name, src, dst, immediate = control
    pages = oracle.image_pages(library, image); pages.update(oracle.fresh_pages())
    stream, wordptr = oracle.GUEST + 0xE000, oracle.GUEST + 0xE800
    backing = wordptr - dst * 8 if name == "current_word_alias_destination" else oracle.GUEST + 0xD000
    x22, x23, x29, x30 = (oracle.GUEST + n for n in (0xE100, 0xE200, 0xE500, 0xE600))
    for i in range(32):
        write(pages, backing + i * 8, (0x1122334455667788 ^ i * 0x0101010101010101) & MASK64)
    left = int.from_bytes(_read_span(pages, backing + src * 8, 8), "little")
    if name == "scratch_alias_source":
        x22 = backing + src * 8
    word = ori_word(src, dst, immediate)
    write(pages, stream, wordptr); write(pages, wordptr, word, 4)
    write(pages, wordptr + 4, 0x11600218, 4)
    write(pages, x29 - 8, 0x33DC5)
    if name != "ELF_sample":
        table = oracle.GUEST + 0xC800
        fold = (((0x00A060400A021040 | (~(image + 0x168324) & MASK64)) & 0x00A061440A061440)
                + ((image + 0x168324) & 0x0000010400040400)) & MASK64
        mask = (fold | 0x01010104) ^ NORMAL_KEY
        write(pages, image + 0x3798D8, (table - mask) & MASK64)
        for op in range(64):
            write(pages, table + op * 8, image + 0x160000 + op * 4 + 0x33DC5)
    inputs = dict(x19=stream, x20=image + 0x379000, x22=x22, x23=x23,
                  x28=backing, x29=x29, x30=x30)
    native = bounded_native(library, image, 0x16E32C, 0x16E518, pages, inputs)
    result = ori_request_word(pages, image_base=image, **inputs)
    assert result["next_handler"] == native["target"]
    assert result["writes"] == native["writes"]
    assert oracle.flatten(pages) == native["guest"]
    for name_reg, value in {**inputs, **result["register_updates"]}.items():
        assert native["regs"][name_reg] == value, (name, name_reg)
    assert result["src"] == src and result["dst"] == dst and result["immediate"] == immediate
    assert result["value"] == left | immediate
    return dict(image_base=hex(image), case=name, src=src, dst=dst, immediate=hex(immediate),
        word=hex(word), next_word=hex(result["next_word"]), next_handler_offset=hex(result["next_handler_offset"]),
        dispatch_table_kind="relocated_ELF" if name == "ELF_sample" else "explicit_synthetic",
        full_guest_bytes_compared=oracle.GUEST_SIZE, full_guest_memory_match=True,
        registers_match=True, ordered_writes_match=True, native_input_snapshot_used=False)


def caller_control(library, image, control):
    pages = oracle.image_pages(library, image)
    pages.update({a >> 12: bytearray([control["fill"]]) * 4096 for a in
                  range(oracle.GUEST, oracle.GUEST + oracle.GUEST_SIZE, 4096)})
    object_address = oracle.GUEST + control["object_offset"]
    reader, source = object_address + 0x88, object_address + 0x118
    payload = control["payload"]
    length = control.get("declared_length", len(payload))
    write(pages, reader, control["mutex_state"], 2)
    write(pages, reader + 0x88, control["readers"], 4)
    _write_span(pages, source, (image + 0x34F5F8).to_bytes(8, "little") +
        ((length + 1) & 0xFFFFFFFF).to_bytes(4, "little") + length.to_bytes(4, "little") +
        (oracle.GUEST + 0x3000).to_bytes(8, "little"))
    _write_span(pages, oracle.GUEST + 0x3000, payload + b"\0")
    inputs = dict(entry_stack_address=oracle.GUEST + 0xEF00, return_address=oracle.STOP,
        thread_pointer=oracle.GUEST + 0xD000, image_base=image, object_address=object_address,
        preserved_x8=oracle.GUEST + control["output_offset"],
        saved_frame_pointer=oracle.GUEST + 0xDE00, saved_x28=0x123456789ABCDEF0,
        saved_x19=oracle.GUEST + 0x2200)
    return pages, inputs


def getter_case(library, libc, image, control, vm_module):
    native_pages, inputs = caller_control(library, image, control)
    callbacks = []
    native_allocations = []
    native_allocator = oracle.Allocator()
    backing = inputs["entry_stack_address"] - 0x148
    stream = backing - 8
    observed = {(oracle.GUEST, oracle.GUEST_SIZE): None}

    def callback_entry(cpu, address):
        wrapper = address - image
        if wrapper not in (0x25705C, 0x257068, 0x257078):
            return
        argument = cpu.reg_read(arm.UC_ARM64_REG_X0)
        count = 3 if wrapper == 0x257068 else 2
        words = tuple(int.from_bytes(cpu.mem_read(argument + i * 8, 8), "little") for i in range(count))
        slots = tuple(int.from_bytes(cpu.mem_read(backing + i * 8, 8), "little") for i in range(32))
        pc = int.from_bytes(cpu.mem_read(stream, 8), "little")
        callbacks.append(dict(wrapper_offset=wrapper, target_offset=words[0] - image,
            argument_address=argument, words=words, registers=slots, vm_pc=pc))

    def malloc(cpu, size):
        pointer = 0 if control.get("malloc_null") else native_allocator.take(size)
        native_allocations.append((size, pointer))
        return pointer

    native_return, native_payload, _, native_services = oracle.native(library, image, 0x256ED4,
        [inputs["object_address"]], native_pages, libc=libc, real_mutexes=True,
        extra_registers={arm.UC_ARM64_REG_X8: inputs["preserved_x8"],
            arm.UC_ARM64_REG_X29: inputs["saved_frame_pointer"],
            arm.UC_ARM64_REG_X28: inputs["saved_x28"], arm.UC_ARM64_REG_X19: inputs["saved_x19"]},
        instruction_observer=callback_entry, malloc_handler=malloc,
        observed_memory=observed, instruction_limit=300000)
    model_pages, model_inputs = caller_control(library, image, control)
    model_allocator = oracle.Allocator()
    model_allocations = []

    def allocate(pages, size):
        pointer = 0 if control.get("malloc_null") else model_allocator.model(pages, size)
        model_allocations.append((size, pointer))
        return pointer

    previous_base = vm_module.B
    result = execute_nested_string_getter(model_pages, model_inputs, vm_module, allocate=allocate)
    assert vm_module.B == previous_base
    assert len(callbacks) == len(result["callbacks"]) == 3
    for native, model in zip(callbacks, result["callbacks"]):
        for key in native:
            assert native[key] == model[key], (control["name"], key)
    assert [item["kind"] for item in result["callbacks"]] == ["acquire", "clone", "release"]
    assert native_allocations == model_allocations
    assert [entry[0] for entry in native_services] == [
        "pthread_mutex_lock", "pthread_mutex_unlock", "pthread_mutex_lock", "pthread_mutex_unlock"]
    assert _read_span(model_pages, oracle.GUEST, 0xA000) == native_payload
    memory = observed[oracle.GUEST, oracle.GUEST_SIZE]
    initial_top = result["caller"].registers[29]
    ranges = ((backing, 0x100), (stream, 8), (initial_top - 0x90, 0x90))
    for address, width in ranges:
        off = address - oracle.GUEST
        assert _read_span(model_pages, address, width) == memory[off:off + width], hex(address)
    reader = inputs["object_address"] + 0x88
    assert int.from_bytes(_read_span(model_pages, reader + 0x88, 4), "little") == control["readers"]
    assert int.from_bytes(_read_span(model_pages, reader, 2), "little") == control["mutex_state"]
    assert native_return == image + 0x257050  # Native caller's retained callback-marker ABI value.
    out = inputs["preserved_x8"]
    pointer = int.from_bytes(_read_span(model_pages, out + 16, 8), "little")
    if pointer:
        assert _read_span(model_pages, pointer, len(control["payload"]) + 1) == control["payload"] + b"\0"
    return dict(image_base=hex(image), case=control["name"], object_offset=hex(control["object_offset"]),
        output_offset=hex(control["output_offset"]), fresh_fill=hex(control["fill"]),
        declared_length=hex(result["declared_length"]), fixture_payload_sha256=hashlib.sha256(control["payload"]).hexdigest(),
        malloc_null=bool(control.get("malloc_null")), allocation_sizes=[size for size, _ in model_allocations],
        semantic_vm_steps=result["vm_steps"], vm_exit_offset=hex(result["vm_exit_pc"] - image),
        callback_pairs=[[hex(c["wrapper_offset"]), hex(c["target_offset"])] for c in callbacks],
        callback_inputs_and_32_slots_match=True, final_backing_and_virtual_stack_match=True,
        stream_slot_match=True, payload_bytes_compared=0xA000, full_payload_memory_match=True,
        allocation_sequence_match=True, matching_libc_mutexes_executed=True,
        reader_count_restored=True, native_caller_returned=True, python_vm_exited=True,
        native_caller_abi_return_python_modeled=False, explicit_allocator_service_used=True,
        native_input_snapshot_used=False, real_url_headers_jni_conversion_verified=False)


def wrapper_case(library, libc, image, control, vm_module):
    # Start the real wrapper with explicit packed arguments and physical
    # request-frame values; no observed register or memory is model input.
    native_pages, source_inputs = caller_control(library, image, control)
    wrapper_sp = source_inputs["entry_stack_address"]
    request_frame = SimpleNamespace(native_stack_address=wrapper_sp + 0x180,
        register_backing_address=wrapper_sp + 0x68)
    argument = oracle.GUEST + 0xA800
    packed_input = b"".join(value.to_bytes(8, "little") for value in
        (image + 0x256ED4, source_inputs["preserved_x8"],
         source_inputs["object_address"], 0x5A5A5A5A))
    _write_span(native_pages, argument, packed_input)
    derived = nested_getter_inputs_from_request(native_pages, request_frame=request_frame,
        callback_argument_address=argument, thread_pointer=source_inputs["thread_pointer"], image_base=image)
    entries, returns = [], []
    allocated = []
    allocator = oracle.Allocator()
    def observe(cpu, address):
        if address == image + 0x256ED4:
            entries.append(dict(entry_stack_address=cpu.reg_read(arm.UC_ARM64_REG_SP),
                return_address=cpu.reg_read(arm.UC_ARM64_REG_X30),
                preserved_x8=cpu.reg_read(arm.UC_ARM64_REG_X8),
                object_address=cpu.reg_read(arm.UC_ARM64_REG_X0),
                saved_frame_pointer=cpu.reg_read(arm.UC_ARM64_REG_X29),
                saved_x28=cpu.reg_read(arm.UC_ARM64_REG_X28),
                saved_x19=cpu.reg_read(arm.UC_ARM64_REG_X19),
                thread_pointer=cpu.reg_read(arm.UC_ARM64_REG_TPIDR_EL0), image_base=image))
        if address == image + 0x28598C:
            returns.append(tuple(cpu.reg_read(reg) for reg in (arm.UC_ARM64_REG_SP,
                arm.UC_ARM64_REG_X30, arm.UC_ARM64_REG_X29,
                arm.UC_ARM64_REG_X28, arm.UC_ARM64_REG_X19)))
    def malloc(cpu, size):
        pointer = allocator.take(size)
        allocated.append((size, pointer))
        return pointer
    native_result, payload, _, _ = oracle.native(library, image, 0x285978, [argument], native_pages,
        libc=libc, real_mutexes=True, malloc_handler=malloc, instruction_observer=observe,
        extra_registers={arm.UC_ARM64_REG_X29: derived["saved_frame_pointer"],
            arm.UC_ARM64_REG_X28: derived["saved_x28"], arm.UC_ARM64_REG_X19: derived["saved_x19"]},
        instruction_limit=300000)
    assert entries == [derived], (entries, derived)
    assert returns == [(wrapper_sp, oracle.STOP, derived["saved_frame_pointer"],
                        derived["saved_x28"], derived["saved_x19"])]
    assert native_result == image + 0x257050
    model_pages, _ = caller_control(library, image, control)
    _write_span(model_pages, argument, packed_input)
    model_inputs = nested_getter_inputs_from_request(model_pages, request_frame=request_frame,
        callback_argument_address=argument, thread_pointer=source_inputs["thread_pointer"], image_base=image)
    assert model_inputs == derived
    model_allocator = oracle.Allocator()
    result = execute_nested_string_getter(model_pages, model_inputs, vm_module,
        allocate=model_allocator.model)
    assert _read_span(model_pages, oracle.GUEST, 0xA000) == payload
    assert model_allocator.calls == [list(item) for item in allocated]
    return dict(image_base=hex(image), case=control["name"], wrapper_offset="0x285978",
        derived_caller_abi_matches_native_entry=True, native_wrapper_returned=True,
        native_wrapper_restored_sp_lr_and_callee_saved_registers=True,
        model_payload_matches_native_wrapper=True, allocation_sequence_matches=True,
        model_inputs_from_native_snapshot=False, explicit_request_frame_inputs=True,
        semantic_vm_steps=result["vm_steps"], python_full_native_caller_abi_modeled=False)


def negative_cases(library, vm_module):
    image = 0x122C0000
    control = dict(name="negative", object_offset=0x1800, output_offset=0x8000,
                   fill=0xA5, payload=b"seed", readers=0, mutex_state=0)
    names = []
    for label, mutation, kwargs in (
        ("nonpositive_budget", None, {"max_vm_steps": 0}),
        ("exhausted_budget", None, {"max_vm_steps": 1}),
        ("output_unmapped", "output", {}),
        ("oversized_source", "oversized", {"max_payload_bytes": 3}),
        ("unmapped_source", "source", {}),
        ("reader_wait_required", "reader", {}),
        ("unknown_callback_target", "target", {}),
    ):
        pages, inputs = caller_control(library, image, control)
        if mutation == "output":
            inputs["preserved_x8"] = 0xDEAD0000
        elif mutation == "source":
            write(pages, inputs["object_address"] + 0x128, 0xDEAD0000)
        elif mutation == "reader":
            write(pages, inputs["object_address"] + 0x110, 0x7FFFFFFF, 4)
        elif mutation == "target":
            # +0x99058 loads the base at +0x35b658; MOVhi/ORi and ADD
            # select the dereferenced function slot at +0x381c50. The first
            # +0x35b650 qword is not this callback's target input.
            slot = image + 0x381C50
            pointer = int.from_bytes(_read_span(pages, slot, 8), "little")
            assert pointer == image + 0x32A444
            write(pages, slot, pointer + 1)
        before = {k: bytes(v) for k, v in pages.items()}
        calls = []
        old_base = vm_module.B
        def allocate(pages, size):
            calls.append(size)
            return oracle.GUEST + 0x4000
        try:
            execute_nested_string_getter(pages, inputs, vm_module, allocate=allocate, **kwargs)
        except (RefillUnsupported, ValueError) as error:
            if mutation == "target":
                assert str(error) == (f"unknown nested string callback +0x25705c -> {image + 0x32A445:#x}"), str(error)
        else:
            raise AssertionError("negative getter input accepted: " + label)
        assert {k: bytes(v) for k, v in pages.items()} == before, label
        assert calls == [], label
        assert vm_module.B == old_base, label
        names.append(label + "_refused_without_page_or_allocation_changes")
    return names


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--libc", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest() == LIBC_SHA256
    os.environ["TOMATO_LIBMETASEC"] = str(args.library.resolve())
    import vm_full
    assert hashlib.sha256(vm_full.SO).hexdigest() == oracle.LIBRARY_SHA256
    ori_rows, getter_rows, wrapper_rows = [], [], []
    profiles = [
        dict(name="empty", object_offset=0x1800, output_offset=0x8000, fill=0xA5,
             payload=b"", readers=0, mutex_state=0),
        dict(name="embedded_nul_cross_page", object_offset=0x1FF8, output_offset=0x8FF8, fill=0x5A,
             payload=b"ab\0cd", readers=7, mutex_state=0x2000),
        dict(name="utf8", object_offset=0x2800, output_offset=0x9000, fill=0x3C,
             payload="fresh-测试".encode("utf-8"), readers=1, mutex_state=0),
        dict(name="long_high_reader", object_offset=0x1800, output_offset=0x8000, fill=0,
             payload=b"x" * 65, readers=0x7FFFFFFD, mutex_state=0x2000),
        dict(name="malloc_null", object_offset=0x2900, output_offset=0x8100, fill=0xCC,
             payload=b"allocation-failure", readers=2, mutex_state=0, malloc_null=True),
        dict(name="negative_length", object_offset=0x1800, output_offset=0x8000, fill=0x11,
             payload=b"", readers=0, mutex_state=0x2000, declared_length=0xFFFFFFFF),
    ]
    for image in (0x122C0000, 0x775C205000):
        for control in (("ELF_sample", 19, 1, 0x6560), ("zero", 0, 31, 0),
                        ("max", 31, 0, 0xFFFF), ("self_alias", 31, 31, 0x8000),
                        ("scratch_alias_source", 1, 2, 0x7FFF),
                        ("current_word_alias_destination", 31, 16, 0x1234)):
            ori_rows.append(ori_case(args.library, image, control))
            print("ORi", hex(image), control[0], "PASS", flush=True)
        for control in profiles:
            getter_rows.append(getter_case(args.library, args.libc, image, control, vm_full))
            print("nested getter", hex(image), control["name"], "PASS", flush=True)
        for control in (profiles[0], profiles[1]):
            wrapper_rows.append(wrapper_case(args.library, args.libc, image, control, vm_full))
            print("request wrapper", hex(image), control["name"], "PASS", flush=True)
    negatives = negative_cases(args.library, vm_full)
    report = dict(schema="vm9-request-nested-callbacks-fresh-differential-v1", evidence_date="2026-10-07",
        sample_sha256=oracle.LIBRARY_SHA256, libc_sha256=LIBC_SHA256,
        ori_controls=len(ori_rows), ori_cases=ori_rows, getter_controls=len(getter_rows), getter_cases=getter_rows,
        wrapper_controls=len(wrapper_rows), wrapper_cases=wrapper_rows,
        request_wrapper_caller_abi_verified=True,
        negative_cases=negatives, ori_python_implementation_verified=True,
        nested_getter_callback_cycle_verified=True, native_caller_return_verified=True,
        python_semantic_vm_exit_verified=True, python_full_native_caller_abi_modeled=False,
        real_request_outer_composition_verified=False, real_url_headers_jni_conversion_verified=False,
        complete_python_medusa=False, fresh_input_signer_output_verified=False,
        current_online_header_matrix_verified=False, no_jvm_rust_signer_complete=False,
        limitations=[
            "Reader and source StringObject states are explicit fixtures, not recovered Java/URL/header inputs.",
            "Allocation is an explicit service; the native side executes actual matching-libc mutexes, not real malloc boot.",
            "Remaining VM semantics reuse vm_full with guest-backed slots. Other physical frame spills and repair paths are outside the contract.",
            "Native caller return and Python VM exit are proved; the full native caller ABI return is not modeled in Python.",
            "No JVM, captured input snapshot, online request or signature output is used.",
        ])
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("nested callbacks", len(ori_rows), "ORi +", len(getter_rows), "getter +",
          len(wrapper_rows), "wrapper +", len(negatives), "negative controls PASS")


if __name__ == "__main__":
    main()
