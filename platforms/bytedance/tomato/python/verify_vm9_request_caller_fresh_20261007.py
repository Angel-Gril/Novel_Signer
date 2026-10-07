"""Compare current request caller with original ELF instructions.

Pure Python runs first; native register/memory observations are expected-only.
The verification stops before request bytecode execution or JNI conversion.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from unicorn.arm64_const import (UC_ARM64_REG_SP, UC_ARM64_REG_X0,
    UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X4,
    UC_ARM64_REG_X8, UC_ARM64_REG_X19, UC_ARM64_REG_X28,
    UC_ARM64_REG_X29, UC_ARM64_REG_X30)
import verify_vm9_signer_objects as oracle
from vm9_allocator import RefillUnsupported, _read_span
from vm9_request_caller import prepare_request_caller

BASES = (0x122C0000, 0x775C205000)
CALL_REGS = (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
            UC_ARM64_REG_X3, UC_ARM64_REG_X4)


def case(library, image, top, flag):
    pages = oracle.image_pages(library, image)
    pages.update(oracle.fresh_pages())
    inputs = dict(entry_stack_address=top, return_address=oracle.STOP,
        thread_pointer=oracle.GUEST + 0xD000, image_base=image,
        argument_x0=oracle.GUEST + 0x2000, argument_x1=oracle.GUEST + 0x2100,
        argument_x2=flag, argument_x3=oracle.GUEST + 0x2200,
        output_x8=oracle.GUEST + 0x2300, saved_frame_pointer=oracle.GUEST + 0x2400,
        saved_x28=0x12345678, saved_x19=0xFEDCBA98)
    initial = {key: bytearray(value) for key, value in pages.items()}
    frame = prepare_request_caller(pages, **inputs)
    memory = {(frame.packed_arguments_address, 0x40): None,
              (top - 0x28, 0x28): None,
              (frame.register_backing_address - 8, 0x108): None}
    call = []

    def observe(cpu, address):
        if address == image + 0x168324:
            call.append(tuple(cpu.reg_read(reg) for reg in CALL_REGS))

    _, _, allocations, services = oracle.native(library, image, 0x2830C4,
        [inputs['argument_x0'], inputs['argument_x1'], flag, inputs['argument_x3']],
        initial, extra_registers={UC_ARM64_REG_SP: top,
            UC_ARM64_REG_X8: inputs['output_x8'],
            UC_ARM64_REG_X19: inputs['saved_x19'],
            UC_ARM64_REG_X28: inputs['saved_x28'],
            UC_ARM64_REG_X29: inputs['saved_frame_pointer'],
            UC_ARM64_REG_X30: inputs['return_address']},
        stop_offset=0x1684F0, instruction_limit=250, observed_memory=memory,
        instruction_observer=observe)
    assert not allocations and not services
    assert call == [frame.vm_call_registers], 'request VM call arguments differ'
    assert all(expected == _read_span(pages, address, width)
               for (address, width), expected in memory.items()), 'caller/prelude span differs'
    assert _read_span(pages, frame.native_stack_address + 0x24, 4) == b'\xA5' * 4
    return dict(image_base=hex(image), entry_stack_address=hex(top), input_x2=hex(flag),
        original_elf_instructions_executed=True, native_input_snapshot_used=False,
        caller_vm_arguments_equal=True, packed_and_saved_frame_spans_equal=True,
        all_32_backing_words_equal=True, w2_upper_word_preserved=True,
        request_bytecode_executed=False)


def negatives(library):
    pages = oracle.image_pages(library, BASES[0])
    pages.update(oracle.fresh_pages())
    before = {key: bytes(value) for key, value in pages.items()}
    inputs = dict(entry_stack_address=oracle.GUEST + 0xEF00, return_address=oracle.STOP,
        thread_pointer=oracle.GUEST + 0xD000, image_base=BASES[0],
        argument_x0=0, argument_x1=0, argument_x2=0, argument_x3=0, output_x8=0)
    controls = [('unaligned_stack', {'entry_stack_address': inputs['entry_stack_address'] + 1}),
        ('tagged_return', {'return_address': 0xA00000007000F000}),
        ('negative_word', {'argument_x2': -1}),
        ('unmapped_stack', {'entry_stack_address': 0x64000000})]
    rows = []
    for name, changed in controls:
        try:
            prepare_request_caller(pages, **(inputs | changed))
        except (RefillUnsupported, ValueError):
            pass
        else:
            raise AssertionError('unsupported request caller input accepted: ' + name)
        assert {key: bytes(value) for key, value in pages.items()} == before
        rows.append(dict(control=name, rejected=True, pages_unchanged=True))
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--library', type=Path, default=Path(r'C:\AI\6\libmetasec_ml_71332.so'))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == oracle.LIBRARY_SHA256
    rows = [case(args.library, image, top, flag)
        for image in BASES for top in (oracle.GUEST + 0xEF00, oracle.GUEST + 0xEC00)
        for flag in (0, 1, 0x12345678, 0xFFFFFFFF, 0xFEDCBA9876543210)]
    report = dict(schema='vm9-request-caller-fresh-differential-v1', evidence_date='2026-10-07',
        sample_sha256=oracle.LIBRARY_SHA256, controls=len(rows), cases=rows,
        negative_controls=negatives(args.library),
        native_caller_entry_offset='0x2830c4', request_vm_offset='0xf7720',
        original_prelude_stop_offset='0x1684f0',
        fresh_input_signer_output_verified=False, complete_python_medusa=False,
        current_online_header_matrix_verified=False,
        limitations=['Native request arguments are explicit ABI words; URL/header conversion is unresolved.',
            'Only defined caller/VM backing spans are compared, not physical prelude scratch.',
            'This does not execute request bytecode, produce headers or contact a server.'])
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('request caller', len(rows), 'native differences and 4 rejection controls PASS; signing remains open')


if __name__ == '__main__':
    main()
