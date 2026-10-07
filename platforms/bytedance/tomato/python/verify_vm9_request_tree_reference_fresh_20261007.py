"""Compare current request x8 tree-reference allocation against native code."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from unicorn.arm64_const import UC_ARM64_REG_X8
import verify_vm9_signer_objects as oracle
import vm9_registry as registry
from vm9_allocator import _read_span


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--library', type=Path, default=Path(r'C:\AI\6\libmetasec_ml_71332.so'))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == oracle.LIBRARY_SHA256
    rows = []
    for image in (0x122C0000, 0x775C205000):
        for output in (oracle.GUEST + 0x1800, oracle.GUEST + 0x1FF8,
                       oracle.GUEST + 0x2800, oracle.GUEST + 0x3FF8):
            pages = oracle.image_pages(args.library, image)
            pages.update(oracle.fresh_pages())
            initial = {key: bytearray(value) for key, value in pages.items()}
            allocation = oracle.Allocator()
            pointer = registry.construct_configuration_tree_reference(pages,
                output_reference_address=output, image_base=image, allocate=allocation.model)
            _, expected, calls, ledger = oracle.native(args.library, image, 0x25C324,
                [oracle.GUEST + 0x3000], initial,
                extra_registers={UC_ARM64_REG_X8: output}, instruction_limit=5000)
            assert oracle.flatten(pages)[:0xA000] == expected
            assert calls == allocation.calls and not ledger
            assert [size for size, _ in calls] == [40, 40, 40, 4]
            assert int.from_bytes(_read_span(pages, output, 8), 'little') == pointer
            count = int.from_bytes(_read_span(pages, output + 8, 8), 'little')
            assert int.from_bytes(_read_span(pages, count, 4), 'little') == 1
            rows.append(dict(image_base=hex(image), output_reference_address=hex(output),
                x8_output_equal=True, synthetic_x0_is_not_output=True,
                allocation_sizes=[size for size, _ in calls],
                allocation_and_memory_equal=True, count_initial_value=1,
                output_crosses_page=bool(output & 0xFF8 == 0xFF8),
                output_overlaps_allocated_container=output < pointer + 40 and pointer < output + 16,
                original_native_constructor_executed=True, native_input_snapshot_used=False))
    pages = oracle.image_pages(args.library, 0x122C0000)
    pages.update(oracle.fresh_pages())
    before = {key: bytes(value) for key, value in pages.items()}
    try:
        registry.construct_configuration_tree_reference(pages,
            output_reference_address=0x64000000, image_base=0x122C0000,
            allocate=lambda *_: (_ for _ in ()).throw(AssertionError('allocation after invalid output')))
    except ValueError as exc:
        assert 'missing checkpoint page' in str(exc)
    else:
        raise AssertionError('unmapped output accepted')
    assert {key: bytes(value) for key, value in pages.items()} == before
    report = dict(schema='vm9-request-tree-reference-fresh-differential-v1', evidence_date='2026-10-07',
        sample_sha256=oracle.LIBRARY_SHA256, controls=len(rows), cases=rows,
        negative_controls=[dict(control='unmapped_output', rejected=True, pages_unchanged=True)],
        fresh_input_signer_output_verified=False, complete_python_medusa=False,
        current_online_header_matrix_verified=False,
        limitations=['Allocator is a nonreusing explicit service in this component differential.',
            'Real allocator and full request callback composition are not verified by this report.',
            'Physical stack scratch and diagnostic scopes are excluded; no server request.'])
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('request x8 tree reference', len(rows), 'native differences and 1 rejection PASS')


if __name__ == '__main__':
    main()
