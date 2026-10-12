"""Fresh +0x287474 caller/prelude and the first bounded VM callback.

Original instructions are an output oracle. Synthetic stack/TLS/object bytes
are constructed independently; the complete second VM remains unverified.
"""
from pathlib import Path
import argparse, hashlib, json, os
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
import vm9_request_caller as caller
from vm9_allocator import RefillUnsupported, _read_span, _write_span

BASES = (0x122C0000, 0x775C205000)
SP = oracle.GUEST + 0xEF00
TP = oracle.GUEST + 0xD000
OWNER = 'prepare_request_287474_vm_caller'


def fixture(library, image, label):
    pages = oracle.image_pages(library, image)
    pages.update(oracle.fresh_pages())
    inputs = dict(entry_stack_address=SP, return_address=oracle.STOP,
        thread_pointer=TP, image_base=image, object_address=oracle.GUEST + 0x1800,
        saved_frame_pointer=oracle.GUEST + 0xDE00,
        saved_x28=0x123456789ABCDEF0, saved_x19=oracle.GUEST + 0x2200)
    if label == 'NULL_object': inputs['object_address'] = 0
    elif label == 'cross_page_object': inputs['object_address'] = oracle.GUEST + 0x1FF8
    elif label == 'wide_saved_words':
        inputs.update(saved_frame_pointer=0xFEDCBA9876543210,
            saved_x28=(1 << 64) - 1, saved_x19=1 << 63)
    elif label == 'relocated_stack':
        inputs['entry_stack_address'] = oracle.GUEST + 0xDF00
        inputs['thread_pointer'] = oracle.GUEST + 0xC000
    elif label == 'TLS_spill_alias':
        inputs['thread_pointer'] = SP - 0x48
    elif label == 'patterned_stack':
        start = inputs['entry_stack_address'] - 0x1A00
        _write_span(pages, start, bytes((i * 37 + 11) & 255 for i in range(0x1A00)))
    return pages, inputs


def original(library, pages, inputs, stop, watch, observer=None):
    return oracle.native(library, inputs['image_base'], 0x287474,
        [inputs['object_address']], pages, stop_offset=stop, observed_memory=watch,
        extra_registers={arm.UC_ARM64_REG_SP: inputs['entry_stack_address'],
            arm.UC_ARM64_REG_X30: inputs['return_address'],
            arm.UC_ARM64_REG_TPIDR_EL0: inputs['thread_pointer'],
            arm.UC_ARM64_REG_X29: inputs['saved_frame_pointer'],
            arm.UC_ARM64_REG_X28: inputs['saved_x28'],
            arm.UC_ARM64_REG_X19: inputs['saved_x19']},
        instruction_limit=100000, instruction_observer=observer)


def red(library):
    rows = []
    assert not hasattr(caller, OWNER), 'RED requires the pre-change owner'
    for image in BASES:
        pages, inputs = fixture(library, image, 'patterned_stack')
        local = SP - 0x1A00
        watch = {(local, 0x1A00): None}
        entries = []
        def observe(cpu, address):
            if address == image + 0x168324:
                entries.append(tuple(cpu.reg_read(getattr(arm, 'UC_ARM64_REG_X' + str(i)))
                    for i in range(5)))
        _, _, allocations, services = original(library, pages, inputs, 0x1684F0, watch, observe)
        assert not allocations and not services
        assert entries == [(image + 0x102BB0, local + 8, image + 0x35EDF0,
            image + 0x35F3D0, local + 0x10)]
        assert int.from_bytes(watch[local, 0x1A00][0x10:0x18], 'little') == image + 0x2884AC
        rows.append(dict(image_base=hex(image), original_caller_prelude_reached=True,
            prior_second_frame_owner_missing=True, fresh_stack_input=True,
            native_snapshot_input=False))
    return rows


def compare_frame(library, image, label):
    pages, inputs = fixture(library, image, label)
    initial = {k: bytearray(v) for k, v in pages.items()}
    frame = getattr(caller, OWNER)(pages, **inputs)
    watch = {(frame.native_stack_address, 0x1A00): None}
    entries, physical = [], []
    def observe(cpu, address):
        if address == image + 0x168324:
            entries.append(tuple(cpu.reg_read(getattr(arm, 'UC_ARM64_REG_X' + str(i)))
                for i in range(5)))
        if address == image + 0x1684EC:
            physical.append(tuple(cpu.reg_read(reg) for reg in
                (arm.UC_ARM64_REG_SP, arm.UC_ARM64_REG_X28, arm.UC_ARM64_REG_X19)))
    _, memory, allocations, services = original(library, initial, inputs, 0x1684F0, watch, observe)
    assert not allocations and not services and entries == [frame.vm_call_registers]
    assert _read_span(pages, oracle.GUEST, 0xA000) == memory
    assert _read_span(pages, frame.native_stack_address, 0x1A00) == watch[frame.native_stack_address, 0x1A00]
    assert physical == [(frame.native_stack_address - 0x180,
        frame.register_backing_address, frame.register_backing_address - 8)]
    print('PASS token frame', hex(image), label, flush=True)
    return dict(image_base=hex(image), case=label, original_prelude_reached=True,
        complete_caller_frame_and_all_32_backing_words_equal=True,
        five_VM_arguments_and_physical_dispatch_registers_equal=True,
        saved_registers_and_live_TLS_canary_equal=True, untouched_guest_bytes_equal=True,
        native_snapshot_input=False, vm_body_not_executed=True)


def compare_prefix(library, image, label, vm_module):
    import vm9_request_287474_vm as model
    pages, inputs = fixture(library, image, label)
    initial = {k: bytearray(v) for k, v in pages.items()}
    result = model.execute_request_287474_vm_prefix(pages, vm_module=vm_module, **inputs)
    frame = result.frame
    watch = {(frame.register_backing_address, 0x100): None,
        (result.callbacks[-1][2], 0x20): None}
    for address, length in result.decoded:
        watch[address, length] = None
    native_ledger = []
    def observe(cpu, address):
        if address - image in (0x2884B8, 0x2884CC):
            arg = cpu.reg_read(arm.UC_ARM64_REG_X0)
            words = tuple(int.from_bytes(cpu.mem_read(arg + i * 8, 8), 'little') for i in range(4))
            native_ledger.append((address - image, words[0] - image, arg, words))
    returned, _, allocations, services = original(library, initial, inputs, 0x2884CC, watch, observe)
    assert not allocations and not services
    # Unicorn's end address is not included in its code observer.
    assert native_ledger == list(result.callbacks[:-1])
    assert returned == result.callbacks[-1][2]
    native_words = tuple(int.from_bytes(watch[frame.register_backing_address, 0x100][i * 8:i * 8 + 8], 'little') for i in range(32))
    assert native_words == result.registers, [i for i in range(32) if native_words[i] != result.registers[i]]
    assert all(_read_span(result.staged, address, length) == raw
        for (address, length), raw in watch.items() if address != frame.register_backing_address)
    assert all(pages[k] == initial[k] for k in pages), 'bounded prefix must not publish pages'
    print('PASS token prefix', hex(image), label, result.steps, flush=True)
    return dict(image_base=hex(image), case=label, original_second_VM_boundary_reached=True,
        steps=result.steps, stop_bytecode_offset=hex(result.pc - image),
        boundary_wrapper_offset='0x2884cc', boundary_target_offset='0x2481ac',
        callback_ledger_and_descriptor_equal=True, all_32_virtual_registers_equal=True,
        three_decoded_constant_ranges_equal=True, supplied_pages_unchanged=True,
        native_snapshot_input=False, complete_second_vm_verified=False)


def guards(library):
    rows = []
    for label in ('unaligned_stack', 'underflow_stack', 'tagged_return', 'wide_object',
                  'negative_image', 'missing_TLS', 'missing_frame', 'missing_bytecode'):
        pages, inputs = fixture(library, BASES[0], 'patterned_stack')
        if label == 'unaligned_stack': inputs['entry_stack_address'] += 1
        elif label == 'underflow_stack': inputs['entry_stack_address'] = 0x100
        elif label == 'tagged_return': inputs['return_address'] |= 1 << 56
        elif label == 'wide_object': inputs['object_address'] = 1 << 64
        elif label == 'negative_image': inputs['image_base'] = -1
        elif label == 'missing_TLS': del pages[TP >> 12]
        elif label == 'missing_frame': del pages[(SP - 0x1A00) >> 12]
        elif label == 'missing_bytecode': del pages[(BASES[0] + 0x102BB0) >> 12]
        before = {k: bytes(v) for k, v in pages.items()}
        try: getattr(caller, OWNER)(pages, **inputs)
        except RefillUnsupported: pass
        else: raise AssertionError(label)
        assert before == {k: bytes(v) for k, v in pages.items()}
        rows.append(dict(case=label, rejected=True, all_pages_unchanged=True))
    return rows


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--library', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--group', choices=('red', 'frames', 'prefix', 'guards', 'all'), default='all')
    args = p.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == oracle.LIBRARY_SHA256
    report = dict(schema='vm9-request-287474-vm-fresh-v1', evidence_date='2026-10-13',
        sample_sha256=oracle.LIBRARY_SHA256, frame_cases=[], prefix_cases=[], negative_cases=[],
        native_snapshot_input=False, private_names_or_payloads_published=False,
        whole_request_native_differential_verified=False, actual_URL_header_JNI_conversion_verified=False,
        live_Android_JVM_verified=False, complete_python_medusa=False,
        fresh_signer_output_verified=False, live_server_matrix_verified=False,
        whole_physical_stack_bytes_compared=False, allocator_provider_mapping_rollback_verified=False,
        complete_second_vm_verified=False)
    if args.group == 'red': report['red_cases'] = red(args.library)
    if args.group in ('frames', 'all'):
        report['frame_cases'] = [compare_frame(args.library, image, label)
            for image in BASES for label in ('normal', 'NULL_object', 'cross_page_object',
                'wide_saved_words', 'relocated_stack', 'TLS_spill_alias', 'patterned_stack')]
    if args.group in ('prefix','all'):
        os.environ['TOMATO_LIBMETASEC'] = str(args.library.resolve())
        import vm_full
        assert Path(vm_full.__file__).resolve().parent == Path(__file__).resolve().parent
        report['prefix_cases'] = [compare_prefix(args.library, image, label, vm_full)
            for image in BASES for label in ('normal', 'cross_page_object', 'patterned_stack')]
    if args.group in ('guards', 'all'): report['negative_cases'] = guards(args.library)
    report['native_Python_controls'] = len(report['frame_cases']) + len(report['prefix_cases'])
    report['rollback_guards'] = len(report['negative_cases'])
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
    print('PASS token VM', args.group, report['native_Python_controls'], report['rollback_guards'])


if __name__ == '__main__': main()
