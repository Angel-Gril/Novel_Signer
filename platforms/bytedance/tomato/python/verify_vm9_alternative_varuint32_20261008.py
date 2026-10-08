"""Fresh-input differential controls for B reader's +0x324870 u32 helper.

Synthetic bytes and explicit output words are the only model inputs. The
native original runs to its natural return; no reader, AST or factory output
is supplied to Python. Raw private ELF data is not exported.
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
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def inputs():
    cases = []
    values = [0, 1, 127, 128, 129, 16383, 16384, (1 << 21) - 1,
              1 << 21, (1 << 28) - 1, 1 << 28, (1 << 32) - 1]
    for value in values:
        data = encode(value)
        cases.append((f'canonical_{value}', data, len(data), OUTPUT))
        for size in range(len(data)):
            cases.append((f'truncated_{value}_{size}', data, size, OUTPUT))
    for width in range(1, 6):
        data = b'\x80' * (width - 1) + b'\0'
        cases.append((f'overlong_zero_{width}', data, width, OUTPUT))
        cases.append((f'following_bytes_{width}', data + b'\xff\xff', width + 2, OUTPUT))
    for last in [15, 16, 31, 127, 128, 255]:
        data = b'\xff' * 4 + bytes([last])
        cases.append((f'fifth_byte_{last}', data, 5, OUTPUT))
    cases.append(('sixth_terminator_ignored', b'\x80' * 5 + b'\0', 6, OUTPUT))
    cases.append(('fifth_overflow_unused_output', b'\x80' * 4 + b'\x10', 5, 0x77000000))
    cases.append(('reversed_bounds', b'\0', -1, OUTPUT))
    cases.append(('output_aliases_input', b'\x80\x01', 2, DATA))
    rng = random.Random(324870)
    for index in range(64):
        size = rng.randrange(0, 8)
        data = bytes(rng.randrange(256) for _ in range(size))
        cases.append((f'deterministic_bytes_{index}', data, size, OUTPUT))
    return cases


def compare(library, base, label, data, extent, output):
    pages = oracle.fresh_pages()
    _write_span(pages, OUTPUT, (0xA1B2C3D4).to_bytes(4, 'little'))
    _write_span(pages, DATA, data)
    mapped_output = oracle.GUEST <= output < oracle.GUEST + oracle.GUEST_SIZE - 3
    initial_word = int.from_bytes(_read_span(pages, output, 4), 'little') if mapped_output else None
    model = {key: bytearray(value) for key, value in pages.items()}
    observed = {(output, 4): None} if mapped_output else {}
    returned, memory, calls, ledger = oracle.native(
        library, base, 0x324870, [DATA, DATA + extent, output], pages,
        instruction_limit=200, observed_memory=observed)
    assert not calls and not ledger
    result = alternative.read_reader_varuint32(
        model, start_address=DATA, end_address=DATA + extent,
        output_address=output)
    assert result.bytes_consumed == returned, label
    assert _read_span(model, oracle.GUEST, 0xA000) == memory, label
    overflow = (extent >= 5 and len(data) >= 5 and
                all(value & 128 for value in data[:4]) and 15 < data[4] < 128)
    if overflow:
        assert not result.output_written and result.value is None
        if mapped_output:
            assert int.from_bytes(observed[output, 4], 'little') == initial_word
    else:
        assert result.output_written
        assert result.value == int.from_bytes(observed[output, 4], 'little'), label
    return dict(label=label, image_base_hex=hex(base), bytes_available=extent,
                bytes_consumed=result.bytes_consumed, output_written=result.output_written,
                overflow_preserves_output=overflow, native_Python_return_match=True,
                whole_guest_memory_match=True, native_input_snapshot_used=False)


def negatives():
    cases = []
    for label, change in [
        ('negative_start', dict(start_address=-1)),
        ('overflow_end', dict(end_address=alternative.MASK64 + 1)),
        ('overflow_output', dict(output_address=alternative.MASK64 - 2)),
        ('missing_output_page', dict(output_address=0x77000000)),
        ('partly_mapped_output', dict(output_address=oracle.GUEST + oracle.GUEST_SIZE - 2)),
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
            alternative.read_reader_varuint32(pages, **options)
        except (RefillUnsupported, ValueError):
            pass
        else:
            raise AssertionError('invalid helper input accepted: ' + label)
        assert {key: bytes(value) for key, value in pages.items()} == before
        cases.append(dict(label=label, rejected=True, all_pages_unchanged=True))
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    sample_hash = hashlib.sha256(args.library.read_bytes()).hexdigest()
    assert sample_hash == oracle.LIBRARY_SHA256, 'unexpected native sample'
    cases = []
    for base in [0x122C0000, 0x775C205000]:
        for spec in inputs():
            cases.append(compare(args.library, base, *spec))
        print('B reader u32 helper:', hex(base), len(inputs()), 'controls passed', flush=True)
    rejected = negatives()
    evidence = dict(
        schema='vm9-alternative-reader-varuint32-fresh-v1',
        evidence_date='2026-10-08', evidence_timezone='UTC', host_trial_label='20261008',
        sample_sha256=sample_hash, native_function_offset_hex='0x324870',
        native_Python_helper_controls=len(cases), rollback_negative_controls=len(rejected),
        cases=cases, negative_cases=rejected, native_input_snapshot_used=False,
        synthetic_input_bytes_used=True, natural_native_return_verified=True,
        native_unmapped_unused_output_controls=2,
        overlong_encodings_accepted=True, fifth_byte_overflow_preserves_output=True,
        missing_terminator_clears_output=True,
        reader_324188_implemented=False, reader_AST_native_Python_controls=0,
        complete_python_bootstrap_controls=0, complete_python_medusa=False,
        fresh_signer_output_verified=False, live_server_matrix_verified=False)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2) + '\n', encoding='utf-8')
    print('B reader u32 helper:', len(cases), 'native/Python +', len(rejected),
          'rollback controls passed', flush=True)


if __name__ == '__main__':
    main()
