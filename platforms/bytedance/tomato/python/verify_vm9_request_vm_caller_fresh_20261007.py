"""Fresh +0x256ed4 frame and generic VM prelude against original instructions."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from unicorn.arm64_const import (
    UC_ARM64_REG_X8, UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
    UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X19, UC_ARM64_REG_X28,
    UC_ARM64_REG_X29,
)
import verify_vm9_signer_objects as oracle
from vm9_allocator import RefillUnsupported, _read_span
from vm9_request_caller import prepare_request_vm_caller


def case(library, image, object_offset, preserved_x8):
    pages = oracle.image_pages(library, image)
    pages.update(oracle.fresh_pages())
    entry, obj, thread = oracle.GUEST + 0xEF00, oracle.GUEST + object_offset, oracle.GUEST + 0xD000
    inputs = dict(entry_stack_address=entry, return_address=oracle.STOP,
        thread_pointer=thread, image_base=image, object_address=obj,
        preserved_x8=preserved_x8, saved_frame_pointer=oracle.GUEST + 0xDE00,
        saved_x28=0x123456789ABCDEF0, saved_x19=oracle.GUEST + 0x2200)
    initial = {key: bytearray(data) for key, data in pages.items()}
    frame = prepare_request_vm_caller(pages, **inputs)
    observed = {(frame.native_stack_address, 0x3B0): None}
    entries = []
    dispatch = []
    def observe(cpu, address):
        if address == image + 0x1684F0:
            dispatch.append(dict(sp=hex(cpu.reg_read(31)), x0=hex(cpu.reg_read(UC_ARM64_REG_X0)), x1=hex(cpu.reg_read(UC_ARM64_REG_X1)), x2=hex(cpu.reg_read(UC_ARM64_REG_X2)), x3=hex(cpu.reg_read(UC_ARM64_REG_X3)), x4=hex(cpu.reg_read(UC_ARM64_REG_X4)), x9=hex(cpu.reg_read(UC_ARM64_REG_X9))))
        if address == image + 0x168324:
            entries.append(tuple(cpu.reg_read(reg) for reg in (
                UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
                UC_ARM64_REG_X3, UC_ARM64_REG_X4)))
    _, expected, calls, ledger = oracle.native(library, image, 0x256ED4, [obj], initial,
        extra_registers={UC_ARM64_REG_X8: preserved_x8,
            UC_ARM64_REG_X29: inputs['saved_frame_pointer'],
            UC_ARM64_REG_X28: inputs['saved_x28'], UC_ARM64_REG_X19: inputs['saved_x19']},
        stop_offset=0x1684F0, observed_memory=observed, instruction_limit=10000,
        instruction_observer=observe)
    assert oracle.flatten(pages)[:0xA000] == expected
    assert not calls and not ledger and entries == [frame.vm_call_registers]
    for (address, length), raw in observed.items():
        assert _read_span(pages, address, length) == raw
    return dict(image_base=hex(image), object_offset=hex(object_offset),
        preserved_x8=hex(preserved_x8), bytecode_offset=hex(frame.bytecode_offset),
        vm_entry_arguments_equal=True, entire_caller_frame_equal=True,
        all_32_backing_words_equal=True, saved_registers_and_tls_canary_equal=True,
        descriptor_top_delta=0x380, dispatch_registers=dispatch, native_input_snapshot_used=False,
        vm_body_not_executed=True, url_headers_jni_conversion_verified=False)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--library', type=Path, default=Path(r'C:\AI\6\libmetasec_ml_71332.so'))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == oracle.LIBRARY_SHA256
    rows = []
    for image in (0x122C0000, 0x775C205000):
        for offset, x8 in ((0x1800, 0x7004EDD8), (0x1FF8, 0x64000000),
                           (0x2800, image + 0x257050)):
            rows.append(case(args.library, image, offset, x8))
            print('request VM caller', hex(image), hex(offset), 'PASS', flush=True)
    report = dict(schema='vm9-request-vm-caller-fresh-differential-v1', evidence_date='2026-10-07',
        sample_sha256=oracle.LIBRARY_SHA256, controls=len(rows), cases=rows,
        complete_python_medusa=False, fresh_input_signer_output_verified=False,
        current_online_header_matrix_verified=False,
        limitations=['Stops at +0x1684f0 after the generic prelude, before nested VM instructions.',
            'Fresh synthetic stack/object inputs; URL/header/JNI conversion remains unresolved.',
            'No native page snapshot, actual JVM, server request or signature output is used.'])
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('request VM caller', len(rows), 'fresh controls PASS')


if __name__ == '__main__':
    main()
