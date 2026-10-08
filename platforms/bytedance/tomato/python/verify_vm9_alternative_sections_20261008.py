"""Actual B section dispatcher and supported handlers versus fresh Python.

The callback vtable is a synthetic status-only service. This verifies section
parsing, state writes and callback arguments, not actual node/AST construction.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import random
from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as arm

import verify_vm9_signer_objects as oracle
import vm9_alternative_startup as alternative
from vm9_allocator import RefillUnsupported, _read_span, _write_span
from verify_vm9_alternative_varuint32_20261008 import encode
from verify_vm9_alternative_blob_xor_20261008 import constructor_codec_byte

STATE = oracle.GUEST + 0x1000
DATA = oracle.GUEST + 0x2000
OBJECT = oracle.GUEST + 0x4000
VTABLE = oracle.GUEST + 0x5000
SCRATCH = oracle.GUEST + 0xB000
CALLBACK = oracle.GUEST + 0xF300
SLOTS = {0x50: 2, 0x98: 5, 0xA0: 1, 0x160: 1}
GLOBALS = (0x3E2CFC, 0x3E2D08, 0x3E2D0C, 0x3E2D14,
           0x3E2D18, 0x3E2D28, 0x3E2D2C, 0x3E2D34, 0x3E2D38, 0x3E2D70)


def put(pages, address, value, size=8):
    _write_span(pages, address, value.to_bytes(size, 'little'))


def section(number, payload):
    return bytes([number]) + encode(len(payload)) + payload


def exported(name, kind, index):
    return encode(len(name)) + name + bytes([kind]) + encode(index)


def fixtures():
    cases = []
    def add(label, sections=b'', **options):
        cases.append(dict(label=label, blob=b'\xA1' * 8 + sections, **options))
    add('no_sections')
    add('function_empty', section(3, b'\0'))
    add('function_indices', section(3, b'\x03\x01\x80\x01\xff\xff\xff\xff\x0f'))
    add('function_index_wrap', section(3, b'\x03\x01\x02\x03'), imported=0xFFFFFFFF)
    add('function_callback_failure', section(3, b'\x03\x01\x02\x03'), failure_slot=0x50, failure_call=1)
    add('function_count_too_large', section(3, b'\x04\x01'))
    add('function_index_truncated', section(3, b'\x01\x80'))
    add('function_count_truncated', section(3, b'\x80'))
    add('function_trailing_byte', section(3, b'\0\0'))
    add('export_empty', section(7, b'\0'))
    exports = b''.join(exported(bytes([65 + kind, 0, 255]), kind, 1 << (kind * 7)) for kind in range(4))
    add('export_four_kinds', section(7, b'\x04' + exports))
    add('export_callback_failure', section(7, b'\x04' + exports), failure_slot=0x98, failure_call=2)
    for kind in [4, 5, 255]:
        add(f'export_invalid_kind_{kind}', section(7, b'\x01' + exported(b'a', kind, 0)))
    add('export_name_past_section', section(7, b'\x01\x05a'))
    add('export_missing_kind', section(7, b'\x01\x01a'))
    add('export_missing_index', section(7, b'\x01\x01a\0\x80'))
    add('start_zero', section(8, b'\0'))
    add('start_max', section(8, encode(0xFFFFFFFF)))
    add('start_callback_failure', section(8, b'\x07'), failure_slot=0xA0)
    add('start_empty_payload', section(8, b''))
    add('start_fifth_overflow', section(8, b'\x80' * 4 + b'\x10'))
    add('start_trailing_byte', section(8, b'\x07\0'))
    add('data_count', section(12, b'\x03'))
    add('data_count_callback_failure', section(12, b'\x03'), failure_slot=0x160)
    add('data_count_trailing_byte', section(12, b'\x03\0'))
    add('rank_12_before_3', section(12, b'\0') + section(3, b'\0'))
    add('rank_3_before_12', section(3, b'\0') + section(12, b'\0'))
    add('duplicate_start', section(8, b'\0') + section(8, b'\0'))
    add('previous_rank_12', section(3, b'\0'), previous=12)
    add('previous_rank_7', section(3, b'\0'), previous=7)
    add('rank_warm_input', section(3, b'\0') + section(7, b'\0'), warm_rank=True)
    add('previous_rank_10_rejects_12', section(12, b'\0'), previous=10)
    add('previous_rank_12_accepts_10_envelope_error', b'\x0a\x7f', previous=12)
    add('rank_7_before_12', section(7, b'\0') + section(12, b'\0'))
    for size in [0, 1, 4, 5, 6, 7, 8, 14, 15]:
        name = bytes([97 + size]) * size
        add(f'custom_generic_{size}', section(0, encode(size) + name + b'\xff\x80payload'))
    add('repeated_custom_around_sections', section(0, b'\0garbage') + section(3, b'\0') +
        section(0, b'\x01a') + section(7, b'\0') + section(0, b'\0'))
    add('custom_flag_preserved', section(0, b'\x01a'), custom_flag=91)
    add('custom_name_out_of_bounds', section(0, b'\x03a'))
    add('custom_name_truncated', section(0, b'\x80'))
    add('unknown_section_13', section(13, b''))
    add('unknown_section_14', section(14, b''))
    add('missing_envelope_length', b'\x03')
    add('truncated_envelope_length', b'\x03\x80')
    add('overflow_envelope_length', b'\x03' + b'\x80' * 4 + b'\x10')
    add('envelope_end_past_input', b'\x03\x7f\0')
    add('empty_function_payload', section(3, b''))
    add('overlong_envelope_and_count', b'\x03\x82\x00\x80\x00')
    rng = random.Random(324188)
    for index in range(24):
        count = rng.randrange(0, 6)
        payload = encode(count) + b''.join(encode(rng.randrange(1 << 32)) for _ in range(count))
        add(f'function_generated_{index}', section(3, payload), imported=rng.randrange(1 << 32))
    for index in range(16):
        count = rng.randrange(0, 4)
        payload = encode(count) + b''.join(exported(bytes(rng.randrange(256) for _ in range(rng.randrange(0, 8))),
                                                    rng.randrange(0, 4), rng.randrange(1 << 32)) for _ in range(count))
        add(f'export_generated_{index}', section(7, payload))
    return cases


def actual_inputs(library):
    """Extract selected payloads from independent fresh-ELF Python XOR.

    Envelope extraction is fixture construction; only actual +324188 controls
    prove the supported payloads. No core node/AST or full-module claim follows.
    """
    pages = oracle.fresh_pages()
    base = 0x122C0000
    pages.update(oracle.image_pages(library, base))
    table = oracle.GUEST + 0x4000
    _write_span(pages, table + 50, bytes([constructor_codec_byte(library)]))
    alternative.decode_factory_blob_xor(pages, blob_address=base+0x387D20, blob_size=0x37FD0,
        codec_table_address=table, codec_table_count=3)
    blob = _read_span(pages, base+0x387D20, 0x37FD0)
    cursor = 8
    selected = {}
    while cursor < len(blob):
        number = blob[cursor]
        cursor += 1
        size = 0
        for index in range(5):
            byte = blob[cursor]
            cursor += 1
            size |= (byte & 127) << (index*7)
            if byte < 128:
                break
        else:
            raise AssertionError('actual fixture envelope did not terminate')
        end = cursor + size
        assert end <= len(blob)
        if number in [3, 7, 12]:
            assert number not in selected
            selected[number] = blob[cursor:end]
        cursor = end
    assert cursor == len(blob) and sorted(selected) == [3, 7, 12]
    cases = [dict(label='actual_ELF_section_'+str(number),
                  blob=b'A'*8+section(number, payload), actual_ELF_section_input=True)
             for number, payload in selected.items()]
    cases.append(dict(label='actual_ELF_sections_3_7_12',
                      blob=b'A'*8+b''.join(section(number, payload) for number, payload in selected.items()),
                      actual_ELF_section_input=True))
    return cases


def prepare(library, base, spec):
    pages = oracle.fresh_pages()
    pages.update(oracle.image_pages(library, base))
    _write_span(pages, STATE, bytes(0xB0))
    _write_span(pages, DATA, spec['blob'])
    for offset, value in [(0, len(spec['blob'])), (8, DATA), (16, len(spec['blob'])),
                          (24, 8), (32, OBJECT)]:
        put(pages, STATE + offset, value)
    put(pages, STATE + 0x88, spec.get('previous', 0xFFFFFFFF), 4)
    put(pages, STATE + 0x8C, spec.get('custom_flag', 0), 1)
    put(pages, STATE + 0x90, spec.get('imported', 0), 4)
    put(pages, STATE + 0xAC, 0xFFFFFFFF, 4)
    put(pages, OBJECT, VTABLE)
    for slot in SLOTS:
        put(pages, VTABLE + slot, CALLBACK + slot)
    if spec.get('warm_rank'):
        ranks = [0, 1, 2, 3, 4, 5, 7, 8, 9, 10, 12, 13, 11, 6]
        _write_span(pages, base + 0x3E2D38, b''.join(n.to_bytes(4, 'little') for n in ranks))
        put(pages, base + 0x3E2D70, 1, 4)
    return pages


def compare(args, base, spec):
    pages = prepare(args.library, base, spec)
    model = {key: bytearray(value) for key, value in pages.items()}
    native_events = []
    model_events = []
    def status(slot, index):
        return 0xFFFFFFFF if slot == spec.get('failure_slot') and index == spec.get('failure_call', 0) else 0
    imports = {}
    with args.libc.open('rb') as stream:
        elf = ELFFile(stream)
        cmp_entry = next(0x51000000 + symbol['st_value'] for section in elf.iter_sections()
                         if section['sh_type'] == 'SHT_DYNSYM' for symbol in section.iter_symbols()
                         if symbol.name == 'memcmp' and symbol['st_value'])
    def memcmp(cpu):
        cpu.reg_write(arm.UC_ARM64_REG_PC, cmp_entry)
        return None
    imports[0x347FE0] = memcmp
    for slot, argc in SLOTS.items():
        def service(cpu, slot=slot, argc=argc):
            values = [cpu.reg_read(getattr(arm, 'UC_ARM64_REG_X'+str(index)))
                      for index in range(argc + 1)]
            assert values[0] == OBJECT
            event = (slot, tuple(values[1:]), int.from_bytes(cpu.mem_read(STATE + 24, 8), 'little'),
                     int.from_bytes(cpu.mem_read(STATE, 8), 'little'))
            value = status(slot, len(native_events))
            native_events.append(event)
            return value
        imports[CALLBACK + slot - base] = service
    observed = {(base + offset, 64): None for offset in GLOBALS}
    returned, memory, calls, ledger = oracle.native(
        args.library, base, 0x324188, [STATE], pages, host_imports=imports,
        libc=args.libc, observed_memory=observed, instruction_limit=30000)
    assert not calls and not ledger
    def callback(event):
        value = status(event.slot_offset, len(model_events))
        model_events.append((event.slot_offset, event.arguments, event.cursor, event.section_end))
        return value
    result = alternative.run_reader_sections(
        model, state_address=STATE, image_base=base,
        varuint_scratch_address=SCRATCH, callback=callback)
    assert result.status == returned, (spec['label'], result.status, returned)
    assert model_events == native_events, (spec['label'], model_events, native_events)
    assert _read_span(model, oracle.GUEST, 0xA000) == memory, spec['label']
    for (address, width), data in observed.items():
        assert _read_span(model, address, width) == data, (spec['label'], hex(address - base))
    return dict(label=spec['label'], image_base_hex=hex(base), status=result.status,
                cursor=result.cursor, last_section=result.last_section,
                sections_entered=list(result.sections_entered), callback_count=len(native_events),
                native_Python_return_match=True, whole_guest_memory_match=True,
                rank_and_custom_decoder_memory_match=True, callback_arguments_and_state_match=True,
                actual_ELF_section_input=spec.get('actual_ELF_section_input', False),
                native_input_snapshot_used=False)


def negatives(args):
    cases = []
    specs = [dict(label='unsupported_type_handler', blob=b'A' * 8 + section(1, b'\0')),
             dict(label='unsupported_import_handler', blob=b'A' * 8 + section(2, b'\0'))]
    for marker in [b'dylink', b'dylink.0', b'linking', b'target_features', b'reloc.CODE']:
        specs.append(dict(label='unsupported_custom_' + marker.decode(),
                          blob=b'A' * 8 + section(0, encode(len(marker)) + marker)))
    for spec in specs:
        pages = prepare(args.library, 0x122C0000, spec)
        before = {key: bytes(value) for key, value in pages.items()}
        try:
            alternative.run_reader_sections(pages, state_address=STATE, image_base=0x122C0000,
                                            varuint_scratch_address=SCRATCH, callback=lambda event: 0)
        except RefillUnsupported:
            pass
        else:
            raise AssertionError('unsupported reader branch accepted: ' + spec['label'])
        assert {key: bytes(value) for key, value in pages.items()} == before
        cases.append(dict(label=spec['label'], rejected=True, all_pages_unchanged=True,
                          native_unrecovered_handler_compared=False))
    for label, options in [('missing_input_page', dict()),
                           ('scratch_overlaps_input', dict(varuint_scratch_address=DATA)),
                           ('section_limit', dict(max_sections=1)),
                           ('entry_limit', dict(max_entries=1)),
                           ('invalid_callback_status', dict(callback=lambda event: -1))]:
        spec = dict(blob=b'A' * 8 + section(3, b'\x02\x01\x02') + section(7, b'\0'))
        pages = prepare(args.library, 0x122C0000, spec)
        if label == 'missing_input_page':
            del pages[DATA >> 12]
        before = {key: bytes(value) for key, value in pages.items()}
        params = dict(state_address=STATE, image_base=0x122C0000,
                      varuint_scratch_address=SCRATCH, callback=lambda event: 0)
        params.update(options)
        try:
            alternative.run_reader_sections(pages, **params)
        except (RefillUnsupported, ValueError):
            pass
        else:
            raise AssertionError('reader guard accepted: ' + label)
        assert {key: bytes(value) for key, value in pages.items()} == before
        cases.append(dict(label=label, rejected=True, all_pages_unchanged=True,
                          native_unrecovered_handler_compared=False))
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library', required=True, type=Path)
    parser.add_argument('--libc', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    sample_hash = hashlib.sha256(args.library.read_bytes()).hexdigest()
    assert sample_hash == oracle.LIBRARY_SHA256
    libc_hash = hashlib.sha256(args.libc.read_bytes()).hexdigest()
    assert libc_hash == 'd2376df6d2ac3e0213f85e3614c4c7ad1d28c84c44926058d5c1b95c855563db'
    inputs = fixtures() + actual_inputs(args.library)
    cases = []
    for base in [0x122C0000, 0x775C205000]:
        for spec in inputs:
            try:
                cases.append(compare(args, base, spec))
            except Exception as error:
                raise AssertionError('native/Python control failed: '+spec['label']) from error
        print('B reader sections:', hex(base), len(inputs), 'controls passed', flush=True)
    rejected = negatives(args)
    evidence = dict(schema='vm9-alternative-reader-sections-fresh-v1',
                    evidence_date='2026-10-08', evidence_timezone='UTC', host_trial_label='20261008',
                    sample_sha256=sample_hash, native_function_offset_hex='0x324188',
                    matching_libc_sha256=libc_hash,
                    actual_matching_libc_memcmp_used=True,
                    native_Python_section_controls=len(cases), rollback_negative_controls=len(rejected),
                    synthetic_section_controls=sum(not c['actual_ELF_section_input'] for c in cases),
                    actual_ELF_selected_section_controls=sum(c['actual_ELF_section_input'] for c in cases),
                    cases=cases, negative_cases=rejected, native_input_snapshot_used=False,
                    supported_section_ids=[0, 3, 7, 8, 12], custom_special_handlers_implemented=False,
                    callbacks_are_explicit_status_services=True, actual_AST_callbacks_executed=False,
                    reader_AST_native_Python_controls=0, complete_python_reader_implemented=False,
                    independent_Python_factory_implemented=False, complete_python_bootstrap_controls=0,
                    complete_python_medusa=False, fresh_signer_output_verified=False,
                    live_server_matrix_verified=False)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2) + '\n', encoding='utf-8')
    print('B reader sections:', len(cases), 'native/Python +', len(rejected), 'rollback controls passed')


if __name__ == '__main__':
    main()
