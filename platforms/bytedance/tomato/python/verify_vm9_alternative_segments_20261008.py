"""Fresh B empty element vectors, data segments and expression callbacks.

Nonempty native element vectors reach abort; their model guard rolls back pages.
Callbacks are pure status services, and no AST or instruction execution is claimed.
Actual ELF payload bytes remain private.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import random

from unicorn import arm64_const as arm
import verify_vm9_alternative_import_limits_20261008 as harness
import verify_vm9_alternative_sections_20261008 as sections
import verify_vm9_signer_objects as oracle
import vm9_alternative_startup as alternative
from verify_vm9_alternative_blob_xor_20261008 import constructor_codec_byte
from verify_vm9_alternative_varint32_20261008 import encode as signed
from verify_vm9_alternative_varuint32_20261008 import encode as u32
from vm9_allocator import RefillUnsupported, _read_span, _write_span


def element(flags=0, index=0, expression=b'\x41\0\x0b', value=-16, count=0, entries=b''):
    result = u32(flags)+(u32(index) if flags & 3 == 2 else b'')
    if not flags & 1:
        result += expression
    if flags & 3:
        result += signed(value) if flags & 4 else b'\0'
    return result+u32(count)+entries


def data(flags=0, index=0, expression=b'\x41\0\x0b', payload=b'z', size=None):
    return u32(flags)+(u32(index) if flags & 2 else b'')+(
        expression if not flags & 1 else b'')+u32(len(payload) if size is None else size)+payload


def options():
    return dict(enable_element_section=True, enable_data_section=True,
                expression_scratch_address=harness.EXPRESSION_SCRATCH)


def fixtures():
    cases = []
    def add(label, number, payload, **settings):
        cases.append(dict(label=label, blob=b'A'*8+sections.section(number, payload), **settings))
    for number in (9, 11):
        for label, payload in (('empty', b'\0'), ('missing_count', b''), ('truncated_count', b'\x80'),
            ('overflow_count', b'\x80'*4+b'\x10'), ('count_past_input', b'\2\0'),
            ('empty_trailing', b'\0\0'), ('missing_flags', b'\1'), ('truncated_flags', b'\1\x80'),
            ('overflow_flags', b'\1'+b'\x80'*4+b'\x10')):
            add(f'{number}_{label}', number, payload)
        for flags in (8, 127, 128, 0xFFFFFFFF):
            add(f'{number}_invalid_flags_{flags}', number, b'\1'+u32(flags))
        for flags in range(8):
            for index in (0, 0xFFFFFFFF):
                payload = element(flags, index) if number == 9 else data(flags, index, payload=b'\0\xffz')
                add(f'{number}_flags_{flags}_index_{index}', number, b'\1'+payload,
                    counts=(0xFFFFFFFF,)*4)
        add(f'{number}_missing_index', number, b'\1\2')
        add(f'{number}_truncated_index', number, b'\1\2\x80')
        add(f'{number}_missing_expression', number, b'\1\0')
        add(f'{number}_missing_size', number, b'\1\1'+(b'\0' if number == 9 else b''))
        add(f'{number}_truncated_size', number, b'\1\1'+(b'\0' if number == 9 else b'')+b'\x80')
    for value in (-21, -17, -16, -22, -20, -18, -15, -1, 0, 1, -(1 << 31), (1 << 31)-1):
        add(f'element_reference_type_{value}', 9, b'\1'+element(5, value=value))
    for label, payload in (('missing_elemkind', b'\1\1'), ('invalid_elemkind', b'\1\1\1\0'),
        ('missing_type', b'\1\5'), ('truncated_type', b'\1\5\x80'),
        ('overflow_type', b'\1\5'+b'\x80'*4+b'\x08'),
        ('element_count_past_input', b'\1'+element(1, count=2, entries=b'\0'))):
        add(label, 9, payload)
    add('nonempty_element_callback_rejects_before_abort', 9, b'\1'+element(1, count=1, entries=b'\0'),
        failure_slot=0x128, failure_call=3)
    for size in (0, 1, 127, 128, 257):
        add(f'data_payload_size_{size}', 11, b'\1'+data(1, payload=bytes((i*73)&255 for i in range(size))))
    add('data_size_past_section', 11, b'\1'+data(1, size=2))
    add('data_size_overflow', 11, b'\1\1'+b'\x80'*4+b'\x10')
    for count in (0, 1, 2, 0xFFFFFFFF):
        add(f'data_count_expected_{count}', 11, b'\1'+data(1), data_count=count)
    add('data_empty_count_mismatch', 11, b'\0', data_count=1)

    expressions = [('end', b'\x0b'), ('kind_zero_then_end', b'\0\x0b'),
                   ('kind_zero_missing_end', b'\0'), ('multiple_kind_zero', b'\0'*4+b'\x0b')]
    for opcode, values in ((0x41, (0, -1, -(1 << 31), (1 << 31)-1)),
                           (0x42, (0, -1, -(1 << 63), (1 << 63)-1))):
        expressions.extend((f'signed_{opcode:x}_{v}', bytes([opcode])+signed(v)+b'\x0b') for v in values)
        expressions.extend((f'truncated_{opcode:x}_{len(t)}', bytes([opcode])+t) for t in (b'', b'\x80', b'\x80'*10))
    expressions += [('i32_overflow', b'\x41'+b'\x80'*4+b'\x08'),
                    ('i64_overflow', b'\x42'+b'\x80'*9+b'\1')]
    for opcode, width in ((0x43, 4), (0x44, 8)):
        for bits in (0, (1 << (width*8))-1, 1 << (width*8-1),
                     0x7FC01234 if width == 4 else 0x7FF8000012345678):
            expressions.append((f'raw_{opcode:x}_{bits:x}', bytes([opcode])+bits.to_bytes(width, 'little')+b'\x0b'))
        expressions.extend((f'raw_truncated_{opcode:x}_{size}', bytes([opcode])+b'\xff'*size)
                           for size in range(width))
    for opcode in (1, 2, 0x23, 0x40, 0x45, 0x7F, 0x80, 0xFB, 0xFF):
        expressions.append((f'unsupported_{opcode:x}', bytes([opcode])+b'\0\x0b'))
    for opcode in (0xFC, 0xFD, 0xFE):
        expressions.extend((f'prefix_{opcode:x}_{sub}', bytes([opcode])+u32(sub)+b'\x0b')
                           for sub in (0, 510, 511, 512, 0xFFFFFFFF))
        expressions.extend((f'prefix_{opcode:x}_{label}', bytes([opcode])+tail)
                           for label, tail in (('missing', b''), ('truncated', b'\x80'), ('overflow', b'\x80'*4+b'\x10')))
    expressions.append(('mixed_constants', b'\0\x41\x7f\x42\x7f\x43'+b'\xff'*4+b'\x44'+b'\xff'*8+b'\x0b'))
    for label, expression in expressions:
        # Leave no following size bytes for malformed-expression controls.
        tail = b'\0' if expression.endswith(b'\x0b') else b''
        add('expression_'+label, 11, b'\1\0'+expression+tail)
    for opcode, kind, expression in ((0, 1, b'\0'), (0, 2, b'\0\x7f\x0b'),
        (0x45, 2, b'\x45\x7f\x0b'), (0x41, 3, b'\x41\x7f\x0b'),
        (0x0B, 6, b'\x0b'), (0x41, 0, b'\x41\1\x0b')):
        add(f'relocated_table_{opcode:x}_{kind}', 11, b'\1'+data(expression=expression),
            relocated_opcode_table=True, opcode_overrides={opcode: kind})

    for number, slots in ((9, (0x100, 0x108, 0x110, 0x118, 0x120, 0x128)),
                          (11, (0x140, 0x148, 0x150, 0x158))):
        for slot in slots:
            entry = element() if number == 9 else data()
            call = {0x100: 0, 0x108: 1, 0x110: 2, 0x118: 7, 0x120: 8, 0x128: 9,
                    0x140: 0, 0x148: 1, 0x150: 6, 0x158: 7}[slot]
            add(f'{number}_callback_failure_{slot:x}', number, b'\2'+entry*2,
                failure_slot=slot, failure_call=call)
    for slot, expression, call in ((0xC0, b'\x0b', 2), (0xC8, b'\x0b', 3),
        (0xF0, b'\0\x0b', 3), (0xE0, b'\x41\x7f\x0b', 3),
        (0xE8, b'\x42\x7f\x0b', 3), (0xD0, b'\x43'+b'\xff'*4+b'\x0b', 3),
        (0xD8, b'\x44'+b'\xff'*8+b'\x0b', 3)):
        add(f'expression_callback_failure_{slot:x}', 11, b'\1'+data(expression=expression),
            failure_slot=slot, failure_call=call)
    for number in (9, 11):
        entry = element(1) if number == 9 else data(1)
        segment = sections.section(number, b'\1'+entry)
        for label, blob in (('duplicate', segment*2), ('rank_rejection', segment+sections.section(8, b'\0')),
                            ('custom_suffix', segment+sections.section(0, b'\1z'))):
            cases.append(dict(label=f'{number}_{label}', blob=b'A'*8+blob))
    for expected in (0, 1, 2):
        cases.append(dict(label=f'data_count_section_{expected}', blob=b'A'*8+
            sections.section(12, u32(expected))+sections.section(11, b'\1'+data(1))))
    cases.append(dict(label='elements_then_data', blob=b'A'*8+sections.section(9, b'\1'+element())+
                     sections.section(11, b'\1'+data())))
    rng = random.Random(0x3215F0)
    for number in (9, 11):
        for trial in range(8):
            count = rng.randrange(1, 5)
            entries = []
            for _ in range(count):
                flags = rng.randrange(8)
                expression = b'\0\x41'+signed(rng.randrange(-(1 << 31), 1 << 31))+b'\x0b'
                entries.append(element(flags, rng.getrandbits(32), expression, rng.choice((-21, -17, -16)))
                    if number == 9 else data(flags, rng.getrandbits(32), expression,
                        bytes(rng.getrandbits(8) for _ in range(rng.randrange(16)))))
            add(f'{number}_generated_{trial}', number, u32(count)+b''.join(entries))
    return cases


def actual_inputs(library):
    base, pages = 0x122C0000, oracle.fresh_pages()
    pages.update(oracle.image_pages(library, base))
    codec = oracle.GUEST+0x4000
    _write_span(pages, codec+50, bytes([constructor_codec_byte(library)]))
    alternative.decode_factory_blob_xor(pages, blob_address=base+0x387D20, blob_size=0x37FD0,
        codec_table_address=codec, codec_table_count=3)
    blob, cursor, selected = _read_span(pages, base+0x387D20, 0x37FD0), 8, {}
    while cursor < len(blob):
        number = blob[cursor]; cursor += 1; size = 0
        for i in range(5):
            byte = blob[cursor]; cursor += 1; size |= (byte & 127) << (i*7)
            if byte < 128:
                break
        else:
            raise AssertionError('fresh ELF envelope did not terminate')
        assert cursor+size <= len(blob)
        if number in (1, 2, 3, 6, 7, 9, 10, 11, 12):
            assert number not in selected
            selected[number] = blob[cursor:cursor+size]
        cursor += size
    assert cursor == len(blob) and 9 not in selected and len(selected[11]) == 4001 and selected[11][0] == 3
    result = []
    for label, numbers in (('actual_ELF_data', (11,)), ('actual_ELF_data_count_data', (12, 11)),
        ('actual_ELF_types_imports_functions_globals_exports_count_code_data', (1, 2, 3, 6, 7, 12, 10, 11))):
        result.append(dict(label=label, blob=b'A'*8+b''.join(sections.section(n, selected[n]) for n in numbers),
            actual_ELF_data_section_input=True, actual_ELF_global_section_input=6 in numbers,
            actual_ELF_code_section_input=10 in numbers, function_count=121 if 10 in numbers else 0,
            instruction_limit=12000000 if 10 in numbers else 150000))
    return result


def abort_controls(args):
    records = []
    class AbortBoundary(Exception):
        pass
    slots = {0x100: 1, 0x108: 3, 0x110: 1, 0x118: 1, 0x120: 2, 0x128: 2,
             0xC0: 1, 0xC8: 0, 0xE0: 1}
    for base in (0x122C0000, 0x775C205000):
        for flags in range(8):
            spec = dict(label=f'nonempty_element_flags_{flags}', blob=b'A'*8+
                sections.section(9, b'\1'+element(flags, count=1, entries=b'\0')))
            pages = harness.prepare(args, base, spec)
            native_events, model_events, trap = [], [], []
            host = {}
            for slot, argc in slots.items():
                sections.put(pages, sections.VTABLE+slot, sections.CALLBACK+slot)
                def callback(cpu, slot=slot, argc=argc):
                    native_events.append((slot, tuple(cpu.reg_read(getattr(arm, 'UC_ARM64_REG_X'+str(i)))
                        for i in range(1, argc+1)), int.from_bytes(cpu.mem_read(sections.STATE+24, 8), 'little')))
                    return 0
                host[sections.CALLBACK+slot-base] = callback
            def abort(cpu):
                trap.append(int.from_bytes(cpu.mem_read(sections.STATE+24, 8), 'little'))
                raise AbortBoundary()
            host[0x347F50] = abort
            try:
                oracle.native(args.library, base, 0x324188, [sections.STATE], pages,
                    libc=args.libc, host_imports=host, instruction_limit=150000)
            except AbortBoundary:
                pass
            else:
                raise AssertionError('native nonempty element did not reach abort')
            assert len(trap) == 1 and native_events[-1][0] == 0x128
            before = {key: bytes(value) for key, value in pages.items()}
            def callback(event):
                model_events.append((event.slot_offset, event.arguments, event.cursor))
                return 0
            try:
                alternative.run_reader_sections(pages, state_address=sections.STATE, image_base=base,
                    varuint_scratch_address=sections.SCRATCH, callback=callback, **options())
            except RefillUnsupported as error:
                assert 'nonempty element vector native abort' in str(error)
            else:
                raise AssertionError('model nonempty element accepted')
            assert model_events == native_events and {key: bytes(value) for key, value in pages.items()} == before
            records.append(dict(label=spec['label'], image_base_hex=hex(base),
                native_abort_boundary_observed=True, preceding_callback_arguments_and_cursor_match=True,
                native_abort_executed=False, model_rejected=True, all_model_pages_unchanged=True))
    return records


def negatives(args):
    rejected = []
    cases = [
        ('element_disabled', dict(enable_element_section=False), 9, b'\0'),
        ('data_disabled', dict(enable_data_section=False), 11, b'\0'),
        ('invalid_element_opt_in', dict(enable_element_section=1), 9, b'\0'),
        ('invalid_data_opt_in', dict(enable_data_section=1), 11, b'\0'),
        ('missing_scratch', dict(expression_scratch_address=None), 11, b'\0'),
        ('unaligned_scratch', dict(expression_scratch_address=harness.EXPRESSION_SCRATCH+1), 11, b'\0'),
        ('unmapped_scratch', dict(expression_scratch_address=0x90000000), 11, b'\0'),
        ('scratch_overflow', dict(expression_scratch_address=(1 << 64)-1), 11, b'\0'),
        ('scratch_overlaps_input', dict(expression_scratch_address=sections.DATA), 11, b'\0'),
        ('scratch_overlaps_state', dict(expression_scratch_address=sections.STATE), 11, b'\0'),
        ('scratch_overlaps_u32', dict(expression_scratch_address=sections.SCRATCH), 11, b'\0'),
        ('scratch_overlaps_imports', dict(expression_scratch_address=harness.IMPORT_SCRATCH,
            enable_table_memory_imports=True, import_scratch_address=harness.IMPORT_SCRATCH), 11, b'\0'),
        ('scratch_overlaps_globals', dict(expression_scratch_address=harness.GLOBAL_SCRATCH,
            enable_global_section=True, global_scratch_address=harness.GLOBAL_SCRATCH), 11, b'\0'),
        ('expression_budget_invalid', dict(max_expression_ops=0), 11, b'\0'),
        ('expression_budget_excessive', dict(max_expression_ops=65537), 11, b'\0'),
        ('expression_budget', dict(max_expression_ops=1), 11, b'\1'+data(expression=b'\0\x0b')),
        ('expression_count_bound', dict(max_entries=1), 11, b'\2'+data(1)*2),
        ('element_count_bound', dict(max_entries=1), 9, b'\2'+element(1)*2),
        ('element_vector_bound', dict(max_entries=1), 9, b'\1'+element(1, count=2, entries=b'\0\0')),
        ('invalid_callback_status', dict(callback=lambda e: -1), 11, b'\1'+data()),
        ('callback_exception', dict(callback=lambda e: (_ for _ in ()).throw(RuntimeError('synthetic failure'))), 11, b'\1'+data()),
    ]
    for label in ('opcode_table_null', 'opcode_table_unaligned', 'opcode_table_unmapped', 'opcode_table_overflow',
                  'opcode_table_overlaps_scratch', 'missing_expression_input_page'):
        cases.append((label, {}, 11, b'\1'+data()))
    for label, settings, number, payload in cases:
        blob = b'A'*8+sections.section(number, payload)
        pages = harness.prepare(args, 0x122C0000, dict(blob=blob))
        if label.startswith('opcode_table_'):
            pointer = {'opcode_table_null': 0, 'opcode_table_unaligned': harness.EXPRESSION_SCRATCH+1,
                'opcode_table_unmapped': 0x90000000, 'opcode_table_overflow': (1 << 64)-4,
                'opcode_table_overlaps_scratch': harness.EXPRESSION_SCRATCH}[label]
            sections.put(pages, 0x122C0000+0x3750B0, pointer)
        if label == 'missing_expression_input_page':
            start = oracle.GUEST+oracle.GUEST_SIZE-12
            _write_span(pages, start, blob[:12])
            sections.put(pages, sections.STATE+8, start)
        before = {key: bytes(value) for key, value in pages.items()}
        params = dict(state_address=sections.STATE, image_base=0x122C0000,
            varuint_scratch_address=sections.SCRATCH, callback=lambda e: 0, **options())
        params.update(settings)
        try:
            alternative.run_reader_sections(pages, **params)
        except (RefillUnsupported, ValueError, RuntimeError):
            pass
        else:
            raise AssertionError('segment guard accepted: '+label)
        assert {key: bytes(value) for key, value in pages.items()} == before, label
        rejected.append(dict(label=label, rejected=True, all_pages_unchanged=True, native_fault_path_compared=False))
    for label, blob in (
        ('segments_do_not_enable_imports', b'A'*8+sections.section(2, b'\1'+harness.imports0.function())),
        ('segments_do_not_enable_definitions', b'A'*8+sections.section(4, b'\0')),
        ('segments_do_not_enable_globals', b'A'*8+sections.section(6, b'\1\x7f\0\x0b')),
        ('segments_do_not_enable_code', b'A'*8+sections.section(10, b'\1\2\0\0')),
        ('existing_type_storage_overlaps_scratch', b'A'*8),
        ('future_type_storage_overlaps_scratch', b'A'*8+sections.section(1, b'\1\x60\1\x7f\1\x7e')),
    ):
        spec = dict(blob=blob)
        if label == 'existing_type_storage_overlaps_scratch':
            spec['params'] = (1, 2)
        pages = harness.prepare(args, 0x122C0000, spec)
        params = dict(state_address=sections.STATE, image_base=0x122C0000,
            varuint_scratch_address=sections.SCRATCH, callback=lambda e: 0, **options())
        if label == 'existing_type_storage_overlaps_scratch':
            params['expression_scratch_address'] = harness.types.OLD_PARAMS
        if label == 'future_type_storage_overlaps_scratch':
            params['vector_allocate'] = lambda size: harness.EXPRESSION_SCRATCH
        before = {key: bytes(value) for key, value in pages.items()}
        try:
            alternative.run_reader_sections(pages, **params)
        except RefillUnsupported:
            pass
        else:
            raise AssertionError('segment isolation guard accepted: '+label)
        assert {key: bytes(value) for key, value in pages.items()} == before, label
        rejected.append(dict(label=label, rejected=True, all_pages_unchanged=True, native_fault_path_compared=False))
    return rejected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library', required=True, type=Path)
    parser.add_argument('--libc', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == oracle.LIBRARY_SHA256
    libc_hash = hashlib.sha256(args.libc.read_bytes()).hexdigest()
    assert libc_hash == 'd2376df6d2ac3e0213f85e3614c4c7ad1d28c84c44926058d5c1b95c855563db'
    rejected, aborts = negatives(args), abort_controls(args)
    specs, records = fixtures()+actual_inputs(args.library), []
    for base in (0x122C0000, 0x775C205000):
        for index, spec in enumerate(specs, 1):
            settings = options()
            globals_enabled = spec.get('actual_ELF_global_section_input', False)
            if globals_enabled:
                settings.update(enable_global_section=True, global_scratch_address=harness.GLOBAL_SCRATCH)
            code_enabled = spec.get('actual_ELF_code_section_input', False)
            if code_enabled:
                settings.update(enable_code_section=True)
            record = harness.compare(args, base, spec, segment_sections=True,
                global_sections=globals_enabled, code_sections=code_enabled, model_options=settings)
            if 'callback_failure' in spec['label'] or 'callback_rejects' in spec['label']:
                assert record['status'] == 1, spec['label']
            records.append(record)
            if index % 32 == 0 or spec.get('actual_ELF_data_section_input'):
                print('B segments:', hex(base), index, '/', len(specs), 'passed', flush=True)
    evidence = dict(schema='vm9-alternative-reader-segments-fresh-v1', evidence_date='2026-10-08',
        evidence_timezone='UTC', host_trial_label='20261008', sample_sha256=oracle.LIBRARY_SHA256,
        matching_libc_sha256=libc_hash, native_element_section_offset_hex='0x323a04',
        native_data_section_offset_hex='0x323fb4', native_expression_helper_offset_hex='0x3215f0',
        native_core_function_offset_hex='0x324188', native_Python_segment_controls=len(records),
        rollback_negative_controls=len(rejected), native_abort_boundary_controls=len(aborts),
        purely_synthetic_controls=sum(not c['actual_ELF_data_section_input'] for c in records),
        actual_ELF_data_section_controls=sum(c['actual_ELF_data_section_input'] for c in records),
        actual_ELF_data_section_payload_bytes=4001, actual_ELF_data_segment_count=3,
        actual_ELF_element_section_present=False, independent_section_opt_ins_required=True,
        expression_helper_writes_result_word=False, kind_zero_callback_supported=True,
        nonempty_element_vectors_implemented=False, nonempty_element_vectors_native_abort=True,
        callbacks_are_explicit_status_services=True, actual_AST_callbacks_executed=False,
        allocator_boot_implemented=False, instruction_execution_implemented=False,
        native_input_snapshot_used=False, private_payload_bytes_published=False,
        native_stack_or_TLS_as_a_whole_compared=False, reader_AST_native_Python_controls=0,
        complete_python_reader_implemented=False, independent_Python_factory_implemented=False,
        complete_python_bootstrap_controls=0, complete_python_medusa=False,
        fresh_signer_output_verified=False, live_server_matrix_verified=False,
        cases=records, negative_cases=rejected, abort_boundary_cases=aborts)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2)+'\n', encoding='utf-8')
    print('B segments:', len(records), 'native/Python +', len(rejected), 'rollback +', len(aborts), 'abort boundaries passed')


if __name__ == '__main__':
    main()
