"""Fresh controls for the original B +0x3249b0 unsigned64 reader.

Only synthetic input/output words enter Python. Native stack/TLS and AST are
outside this primitive comparison; private ELF bytes are never published.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import random

import verify_vm9_signer_objects as oracle
import vm9_alternative_startup as alternative
from verify_vm9_alternative_varuint32_20261008 import encode
from vm9_allocator import RefillUnsupported, _read_span, _write_span

DATA, OUTPUT = oracle.GUEST+0x2000, oracle.GUEST+0x4000


def inputs():
    cases = []
    values = [0, 1, 127, 128, 129, (1 << 32)-1, 1 << 32, (1 << 63)-1, 1 << 63, (1 << 64)-1]
    for bit in range(14, 64, 7):
        values.extend(((1 << bit)-1, 1 << bit))
    for value in sorted(set(values)):
        data = encode(value)
        cases.append((f'canonical_{value}', data, len(data), OUTPUT))
        for size in range(len(data)):
            cases.append((f'truncated_{value}_{size}', data, size, OUTPUT))
    for width in range(1, 11):
        data = b'\x80'*(width-1)+b'\0'
        cases.append((f'redundant_zero_{width}', data, width, OUTPUT))
        cases.append((f'trailing_bytes_{width}', data+b'\xff\xff', width+2, OUTPUT))
    for prefix in (0x80, 0xFF):
        for last in range(256):
            cases.append((f'tenth_byte_{prefix}_{last}', bytes([prefix])*9+bytes([last]), 10, OUTPUT))
    cases.append(('eleventh_terminator_ignored', b'\x80'*10+b'\0', 11, OUTPUT))
    for output in (0x77000000, 0, alternative.MASK64):
        cases.append((f'overflow_unused_output_{output}', b'\x80'*9+b'\2', 10, output))
    cases.extend([('reversed_bounds', b'\0', -1, OUTPUT),
                  ('empty_unmapped_input', b'', 0, OUTPUT),
                  ('output_aliases_input', encode((1 << 64)-1), 10, DATA),
                  ('unaligned_output_alias', encode(1 << 63), 10, DATA+1)])
    rng = random.Random(0x3249B0)
    for index in range(32):
        size = rng.randrange(0, 13)
        data = bytes(rng.randrange(256) for _ in range(size))
        cases.append((f'deterministic_bytes_{index}', data, size, OUTPUT))
    return cases


def compare(library, base, label, data, extent, output):
    pages = oracle.fresh_pages()
    _write_span(pages, OUTPUT, (0x0123456789ABCDEF).to_bytes(8, 'little'))
    _write_span(pages, DATA, data)
    start = 0x77000000 if label == 'empty_unmapped_input' else DATA
    mapped_output = oracle.GUEST <= output <= oracle.GUEST+oracle.GUEST_SIZE-8
    before = _read_span(pages, output, 8) if mapped_output else None
    model = {key: bytearray(value) for key, value in pages.items()}
    observed = {(output, 8): None} if mapped_output else {}
    returned, memory, calls, ledger = oracle.native(library, base, 0x3249B0,
        [start, start+extent, output], pages, instruction_limit=400, observed_memory=observed)
    assert not calls and not ledger
    result = alternative.read_reader_varuint64(model, start_address=start,
        end_address=start+extent, output_address=output)
    assert result.bytes_consumed == returned, label
    assert _read_span(model, oracle.GUEST, 0xA000) == memory, label
    overflow = extent >= 10 and len(data) >= 10 and all(b & 128 for b in data[:9]) and 1 < data[9] < 128
    if overflow:
        assert result.value is None and not result.output_written
        if mapped_output:
            assert observed[output, 8] == before
    else:
        assert result.output_written
        assert result.value == int.from_bytes(observed[output, 8], 'little')
        if not returned:
            assert result.value == 0
    return dict(label=label, image_base_hex=hex(base), bytes_available=extent,
        bytes_consumed=result.bytes_consumed, output_written=result.output_written,
        overflow_preserves_output=overflow, native_Python_return_match=True,
        guest_input_output_region_match=True, native_input_snapshot_used=False)


def negatives():
    rejected = []
    for label, options in (
        ('negative_start', dict(start_address=-1)),
        ('overflow_end', dict(end_address=alternative.MASK64+1)),
        ('scan_wrap', dict(start_address=alternative.MASK64-8, end_address=alternative.MASK64)),
        ('null_output', dict(output_address=0)),
        ('overflow_output', dict(output_address=alternative.MASK64-6)),
        ('missing_output', dict(output_address=0x77000000)),
        ('partly_mapped_output', dict(output_address=oracle.GUEST+oracle.GUEST_SIZE-4)),
        ('missing_input', dict(start_address=0x77000000, end_address=0x77000001)),
        ('missing_continuation', dict(start_address=oracle.GUEST+oracle.GUEST_SIZE-1,
                                     end_address=oracle.GUEST+oracle.GUEST_SIZE+1)),
        ('failed_parse_missing_output', dict(start_address=DATA, end_address=DATA,
                                            output_address=0x77000000))):
        pages = oracle.fresh_pages()
        _write_span(pages, DATA, b'\x80\1')
        before = {key: bytes(value) for key, value in pages.items()}
        params = dict(start_address=DATA, end_address=DATA+2, output_address=OUTPUT)
        params.update(options)
        try:
            alternative.read_reader_varuint64(pages, **params)
        except (RefillUnsupported, ValueError):
            pass
        else:
            raise AssertionError('u64 guard accepted: '+label)
        assert {key: bytes(value) for key, value in pages.items()} == before, label
        rejected.append(dict(label=label, rejected=True, all_pages_unchanged=True,
                             native_fault_path_compared=False))
    return rejected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    sample_hash = hashlib.sha256(args.library.read_bytes()).hexdigest()
    assert sample_hash == oracle.LIBRARY_SHA256, 'unexpected native sample'
    rejected = negatives()
    specs, cases = inputs(), []
    for base in (0x122C0000, 0x775C205000):
        for index, spec in enumerate(specs, 1):
            cases.append(compare(args.library, base, *spec))
            if index % 128 == 0:
                print('B u64:', hex(base), index, '/', len(specs), 'passed', flush=True)
        print('B u64:', hex(base), len(specs), 'controls passed', flush=True)
    evidence = dict(schema='vm9-alternative-reader-varuint64-fresh-v1', evidence_date='2026-10-08',
        evidence_timezone='UTC', host_trial_label='20261008', sample_sha256=sample_hash,
        native_function_offset_hex='0x3249b0', native_Python_helper_controls=len(cases),
        rollback_negative_controls=len(rejected), guest_input_output_bytes_compared=0xA000,
        tenth_byte_all_256_values_with_two_prefixes_checked_per_base=True,
        terminating_tenth_byte_overflow_preserves_output=True, missing_termination_clears_output=True,
        native_unused_output_controls=6, native_input_snapshot_used=False,
        reader_AST_native_Python_controls=0, complete_python_reader_implemented=False,
        complete_python_bootstrap_controls=0, complete_python_medusa=False,
        fresh_signer_output_verified=False, live_server_matrix_verified=False,
        cases=cases, negative_cases=rejected)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2)+'\n', encoding='utf-8')
    print('B u64:', len(cases), 'native/Python +', len(rejected), 'rollback controls passed')


if __name__ == '__main__':
    main()
