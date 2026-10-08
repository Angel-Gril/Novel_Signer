"""Fresh-input controls for the actual B reader signed-word helper.

Original +0x324e0c executes to its natural return. Synthetic bytes and output
words are the only model inputs; no native snapshot, type vector or AST input.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import random

import verify_vm9_signer_objects as oracle
import vm9_alternative_startup as alternative
from vm9_allocator import RefillUnsupported, _read_span, _write_span

DATA = oracle.GUEST + 0x2000
OUTPUT = oracle.GUEST + 0x4000


def encode(value):
    result = bytearray()
    while True:
        byte = value & 127
        value >>= 7
        if (value == 0 and not byte & 64) or (value == -1 and byte & 64):
            result.append(byte)
            return bytes(result)
        result.append(byte | 128)


def inputs():
    cases = []
    def add(label, data, extent=None, output=OUTPUT, start=DATA):
        cases.append((label, data, len(data) if extent is None else extent, output, start))
    values = {0, 1, -1, -(1 << 31), (1 << 31) - 1}
    for boundary in [6, 13, 20, 27]:
        for sign in [-1, 1]:
            for delta in [-1, 0, 1]:
                values.add(sign * (1 << boundary) + delta)
    for value in sorted(values):
        data = encode(value)
        add(f'canonical_{value}', data)
        for extent in range(len(data)):
            add(f'truncated_{value}_{extent}', data, extent)
    for byte in range(128):
        add(f'single_terminator_{byte}', bytes([byte]))
    for byte in range(256):
        add(f'fifth_byte_{byte}', b'\xff' * 4 + bytes([byte]))
    for width in range(1, 6):
        for byte, label in [(0, 'zero'), (127, 'minus_one')]:
            data = bytes([byte | 128]) * (width - 1) + bytes([byte])
            add(f'overlong_{label}_{width}', data)
            add(f'following_bytes_{label}_{width}', data + b'\x80\xff')
    add('sixth_terminator_ignored', b'\x80' * 5 + b'\0')
    add('reversed_bounds', b'\0', -1)
    for failure, data, extent in [('empty', b'', 0), ('truncated', b'\x80', 1),
                                   ('fifth_positive_overflow', b'\x80' * 4 + b'\x08', 5),
                                   ('fifth_negative_overflow', b'\xff' * 4 + b'\x77', 5),
                                   ('five_continuations', b'\x80' * 5, 5)]:
        for output, label in [(0, 'null'), (0x77000000, 'unmapped'),
                              (alternative.MASK64, 'overflow_word')]:
            add(f'{failure}_unused_output_{label}', data, extent, output)
    for displacement in [-1, 0, 1]:
        add(f'output_alias_{displacement}', encode(-8193), output=DATA + displacement)
    add('input_crosses_page', encode(-(1 << 31)), start=oracle.GUEST + 0x2FFE)
    add('output_crosses_page', encode((1 << 31) - 1), output=oracle.GUEST + 0x4FFE)
    rng = random.Random(0x324E0C)
    for index in range(64):
        value = rng.randrange(-(1 << 31), 1 << 31)
        add(f'generated_value_{index}', encode(value))
    for index in range(64):
        size = rng.randrange(0, 8)
        add(f'generated_bytes_{index}', bytes(rng.randrange(256) for _ in range(size)))
    return cases


def compare(library, base, label, data, extent, output, start):
    pages = oracle.fresh_pages()
    _write_span(pages, OUTPUT, (0xA1B2C3D4).to_bytes(4, 'little'))
    _write_span(pages, start, data)
    mapped_output = oracle.GUEST <= output <= oracle.GUEST + oracle.GUEST_SIZE - 4
    initial_word = _read_span(pages, output, 4) if mapped_output else None
    model = {key: bytearray(value) for key, value in pages.items()}
    observed = {(output, 4): None} if mapped_output else {}
    returned, memory, calls, ledger = oracle.native(
        library, base, 0x324E0C, [start, start + extent, output], pages,
        instruction_limit=200, observed_memory=observed)
    assert not calls and not ledger
    result = alternative.read_reader_varint32(
        model, start_address=start, end_address=start + extent, output_address=output)
    assert result.bytes_consumed == returned, label
    assert _read_span(model, oracle.GUEST, 0xA000) == memory, label
    if returned:
        assert result.output_written and result.value is not None, label
        assert result.value == int.from_bytes(observed[output, 4], 'little', signed=True), label
    else:
        assert not result.output_written and result.value is None, label
        if mapped_output:
            assert observed[output, 4] == initial_word, label
    return dict(label=label, image_base_hex=hex(base), bytes_available=extent,
                bytes_consumed=result.bytes_consumed, output_written=result.output_written,
                failure_preserves_output=not bool(returned),
                output_mapped=mapped_output, native_Python_return_match=True,
                guest_input_output_region_match=True, native_input_snapshot_used=False)


def negatives():
    cases = []
    for label, change in [
        ('negative_start', dict(start_address=-1)),
        ('wrapping_scan', dict(start_address=alternative.MASK64 - 3)),
        ('overflow_end', dict(end_address=alternative.MASK64 + 1)),
        ('negative_output', dict(output_address=-1)),
        ('null_success_output', dict(output_address=0)),
        ('overflow_success_output', dict(output_address=alternative.MASK64 - 2)),
        ('missing_success_output', dict(output_address=0x77000000)),
        ('partly_mapped_success_output', dict(output_address=oracle.GUEST + oracle.GUEST_SIZE - 2)),
        ('missing_first_byte', dict(start_address=0x77000000, end_address=0x77000001)),
        ('missing_continuation_page', dict(start_address=oracle.GUEST + oracle.GUEST_SIZE - 1,
                                         end_address=oracle.GUEST + oracle.GUEST_SIZE + 1)),
    ]:
        pages = oracle.fresh_pages()
        _write_span(pages, DATA, b'\x80\x01')
        before = {key: bytes(value) for key, value in pages.items()}
        options = dict(start_address=DATA, end_address=DATA + 2, output_address=OUTPUT)
        options.update(change)
        try:
            alternative.read_reader_varint32(pages, **options)
        except (RefillUnsupported, ValueError):
            pass
        else:
            raise AssertionError('invalid helper input accepted: ' + label)
        assert {key: bytes(value) for key, value in pages.items()} == before, label
        cases.append(dict(label=label, rejected=True, all_pages_unchanged=True))
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    sample_hash = hashlib.sha256(args.library.read_bytes()).hexdigest()
    assert sample_hash == oracle.LIBRARY_SHA256, 'unexpected native sample'
    specs = inputs()
    cases = []
    for base in [0x122C0000, 0x775C205000]:
        for spec in specs:
            cases.append(compare(args.library, base, *spec))
        print('B reader i32 helper:', hex(base), len(specs), 'controls passed', flush=True)
    rejected = negatives()
    evidence = dict(
        schema='vm9-alternative-reader-varint32-fresh-v1',
        evidence_date='2026-10-08', evidence_timezone='UTC', host_trial_label='20261008',
        sample_sha256=sample_hash, native_function_offset_hex='0x324e0c',
        native_Python_helper_controls=len(cases), rollback_negative_controls=len(rejected),
        cases=cases, negative_cases=rejected, native_input_snapshot_used=False,
        synthetic_input_bytes_used=True, natural_native_return_verified=True,
        guest_input_output_bytes_compared=0xA000,
        native_unused_output_controls=sum(not c['output_mapped'] for c in cases),
        fifth_byte_all_256_values_checked_per_base=True,
        fifth_terminator_allowed_ranges_hex=['0x00..0x07', '0x78..0x7f'],
        failure_preserves_output=True, overlong_encodings_accepted=True,
        section_1_type_vectors_implemented=False, reader_AST_native_Python_controls=0,
        complete_python_reader_implemented=False, independent_Python_factory_implemented=False,
        complete_python_bootstrap_controls=0, complete_python_medusa=False,
        fresh_signer_output_verified=False, live_server_matrix_verified=False)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2) + '\n', encoding='utf-8')
    print('B reader i32 helper:', len(cases), 'native/Python +', len(rejected),
          'rollback controls passed', flush=True)


if __name__ == '__main__':
    main()
