"""Fresh B section 4/5 definitions versus the original native dispatcher.

Reuses the import-limits differential harness. Only the transient descriptor
pointer is normalized; all 19 bytes, other arguments, counts and state match.
Actual AST callbacks and allocator boot remain explicit, unimplemented services.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import random

import verify_vm9_alternative_import_limits_20261008 as limits0
import verify_vm9_alternative_imports_20261008 as imports0
import verify_vm9_alternative_sections_20261008 as sections
import verify_vm9_alternative_types_20261008 as types
import verify_vm9_signer_objects as oracle
import vm9_alternative_startup as alternative
from verify_vm9_alternative_blob_xor_20261008 import constructor_codec_byte
from verify_vm9_alternative_varint32_20261008 import encode as i32
from verify_vm9_alternative_varuint32_20261008 import encode as u32
from vm9_allocator import RefillUnsupported, _read_span, _write_span

STATE, DATA, SCRATCH = sections.STATE, sections.DATA, sections.SCRATCH
IMPORT_SCRATCH = limits0.IMPORT_SCRATCH


def table(value=-16, flags=0, minimum=0, maximum=0):
    return i32(value)+bytes([flags])+u32(minimum)+(u32(maximum) if flags & 1 else b'')


def memory(flags=0, minimum=0, maximum=0):
    return bytes([flags])+u32(minimum)+(u32(maximum) if flags & 1 else b'')


def fixtures():
    cases = []
    def add(label, number, payload, **options):
        cases.append(dict(label=label, blob=b'A'*8+sections.section(number, payload), **options))
    for number in (4, 5):
        add(f'section_{number}_empty', number, b'\0')
        add(f'section_{number}_empty_count_callback_failure', number, b'\0',
            failure_slot=0x58 if number == 4 else 0x68)
        for label, payload in (('count_missing', b''), ('count_truncated', b'\x80'),
                               ('count_overflow', b'\x80'*4+b'\x10'),
                               ('count_past_payload', b'\2\0'), ('trailing_byte', b'\0\0')):
            add(f'section_{number}_{label}', number, payload)
    for value in (-21, -17, -16):
        for flags in (0, 1, 4, 5):
            add(f'table_type_{value}_flags_{flags}', 4, b'\1'+table(value, flags, 0xFFFFFFFF, 3))
    for value in (-22, -20, -19, -18, -15, -5, -1, 0, -(1 << 31), (1 << 31)-1):
        add(f'table_invalid_type_{value}', 4, b'\1'+table(value))
    for number in (4, 5):
        prefix = i32(-16) if number == 4 else b''
        for flags in (2, 3, 6, 7, 8, 9, 15, 127, 128, 255):
            add(f'section_{number}_invalid_flags_{flags}', number, b'\1'+prefix+bytes([flags])+b'\0\0')
        for label, tail in (('flags_missing', b''), ('minimum_missing', b'\0'),
                            ('minimum_truncated', b'\0\x80'), ('maximum_missing', b'\1\0'),
                            ('maximum_truncated', b'\1\0\x80')):
            add(f'section_{number}_{label}', number, b'\1'+prefix+tail)
        valid = table() if number == 4 else memory()
        add(f'section_{number}_count_callback_failure', number, b'\1'+valid,
            failure_slot=0x58 if number == 4 else 0x68)
        add(f'section_{number}_entry_callback_failure', number, b'\2'+valid*2,
            failure_slot=0x60 if number == 4 else 0x70, failure_call=2)
        add(f'section_{number}_imported_index_wrap', number, b'\3'+valid*3, counts=(7, 0xFFFFFFFF, 0xFFFFFFFF, 11))
        add(f'section_{number}_success_then_invalid', number, b'\2'+valid+prefix+b'\2\0')
        add(f'section_{number}_redundant_count', number, b'\x81\0'+valid)
        add(f'section_{number}_valid_trailing_byte', number, b'\1'+valid+b'\0')
    for flags in (0, 1, 4, 5):
        for minimum, maximum in ((0, 0), (1, 0), (1 << 32, (1 << 32)+3),
                                  (1 << 63, (1 << 64)-1), ((1 << 64)-1, 2)):
            add(f'memory_flags_{flags}_minimum_{minimum}', 5, b'\1'+memory(flags, minimum, maximum))
    for label, tail in (('type_missing', b''), ('type_truncated', b'\x80'),
                        ('type_fifth_overflow', b'\x80'*4+b'\x08\0\0'),
                        ('minimum_fifth_overflow', i32(-16)+b'\0'+b'\x80'*4+b'\x10'),
                        ('maximum_fifth_overflow', i32(-16)+b'\1\0'+b'\x80'*4+b'\x10')):
        add('table_'+label, 4, b'\1'+tail)
    for field in ('minimum', 'maximum'):
        prefix = b'\0' if field == 'minimum' else b'\1\0'
        for label, tail in (('overflow', b'\x80'*9+b'\2'), ('ten_continuations', b'\x80'*10),
                            ('nine_continuations', b'\x80'*9), ('eleventh_terminator', b'\x80'*10+b'\0')):
            add(f'memory_{field}_{label}', 5, b'\1'+prefix+tail)
    add('table_redundant_bounds', 4, b'\1'+i32(-21)+b'\5\x80\0\x81\0')
    add('memory_redundant_bounds', 5, b'\1\5'+b'\x80'*9+b'\0'+b'\x81'+b'\x80'*8+b'\0')
    both = sections.section(4, b'\2'+table(-21, 5, 7, 1)+table(-17, 0, 3))
    both += sections.section(5, b'\2'+memory(5, 1 << 63, 2)+memory(0, 7))
    mixed_imports = b'\4'+imports0.function(index=2)+limits0.table(-21, 5, 4, 1)+limits0.memory(5, 3, 2)+imports0.global_()
    combo = sections.section(1, b'\1'+types.function_type([-1], [-2]))
    combo += sections.section(2, mixed_imports)+sections.section(3, b'\1\0')+both
    combo += sections.section(7, b'\0')+sections.section(12, b'\0')
    cases.append(dict(label='types_four_import_kinds_functions_definitions_exports_data', blob=b'A'*8+combo))
    for label, blob in (('table_then_memory', both), ('duplicate_table', both+sections.section(4, b'\0')),
                        ('memory_then_table_rank_rejection', sections.section(5, b'\0')+sections.section(4, b'\0')),
                        ('custom_between_definitions', sections.section(4, b'\1'+table())+
                         sections.section(0, b'\1zdata')+sections.section(5, b'\1'+memory()))):
        cases.append(dict(label=label, blob=b'A'*8+blob, counts=(3, 5, 7, 9)))
    rng = random.Random(0x3231E4)
    for index in range(12):
        number, count = rng.choice((4, 5)), rng.randrange(1, 5)
        entries = []
        for _ in range(count):
            flags = rng.choice((0, 1, 4, 5))
            entries.append(table(rng.choice((-21, -17, -16)), flags, rng.randrange(1 << 32), rng.randrange(1 << 32))
                           if number == 4 else memory(flags, rng.randrange(1 << 64), rng.randrange(1 << 64)))
        add(f'definitions_generated_{index}', number, u32(count)+b''.join(entries),
            counts=tuple(rng.randrange(1 << 32) for _ in range(4)))
    return cases


def actual_inputs(library):
    pages, base = oracle.fresh_pages(), 0x122C0000
    pages.update(oracle.image_pages(library, base))
    codec = oracle.GUEST+0x4000
    _write_span(pages, codec+50, bytes([constructor_codec_byte(library)]))
    alternative.decode_factory_blob_xor(pages, blob_address=base+0x387D20, blob_size=0x37FD0,
        codec_table_address=codec, codec_table_count=3)
    blob, cursor, selected = _read_span(pages, base+0x387D20, 0x37FD0), 8, {}
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
            raise AssertionError('fresh fixture envelope did not terminate')
        end = cursor+size
        assert end <= len(blob)
        if number in (1, 2, 3, 4, 5, 7, 12):
            assert number not in selected
            selected[number] = blob[cursor:end]
        cursor = end
    assert cursor == len(blob) and sorted(selected) == [1, 2, 3, 7, 12]
    # The pinned sample has neither section 4 nor 5. These definitions are
    # explicitly synthetic additions to independently XORed function/global input.
    selected[4] = b'\2'+table(-21, 5, 7, 1)+table(-17, 0, 3)
    selected[5] = b'\2'+memory(5, 1 << 63, 2)+memory(0, 7)
    return [dict(label=label, blob=b'A'*8+b''.join(sections.section(n, selected[n]) for n in numbers),
                 fresh_ELF_function_global_plus_synthetic_definitions=True)
            for label, numbers in (
                ('fresh_ELF_imports_plus_synthetic_definitions', (2, 4, 5)),
                ('fresh_ELF_imports_functions_exports_data_plus_synthetic_definitions', (2, 3, 4, 5, 7, 12)),
                ('fresh_ELF_types_imports_functions_exports_data_plus_synthetic_definitions', (1, 2, 3, 4, 5, 7, 12)))]


def negatives(args):
    rejected = []
    blob = b'A'*8+sections.section(4, b'\1'+table())+sections.section(5, b'\1'+memory())
    for label, options, setup in (
        ('definition_opt_in_disabled', dict(enable_table_memory_sections=False), None),
        ('imports_opt_in_does_not_enable_definitions', dict(enable_table_memory_sections=False, enable_table_memory_imports=True), None),
        ('invalid_definition_opt_in', dict(enable_table_memory_sections=1), None),
        ('missing_scratch_service', dict(import_scratch_address=None), None),
        ('unaligned_scratch', dict(import_scratch_address=IMPORT_SCRATCH+1), None),
        ('null_scratch', dict(import_scratch_address=0), None),
        ('overflow_scratch', dict(import_scratch_address=alternative.MASK64-7), None),
        ('scratch_alias_state', dict(import_scratch_address=STATE), None),
        ('scratch_alias_input', dict(import_scratch_address=DATA), None),
        ('scratch_alias_u32', dict(import_scratch_address=SCRATCH), None),
        ('scratch_alias_type_storage', dict(import_scratch_address=types.OLD_PARAMS),
         lambda p: types.word_vector(p, STATE+0x28, types.OLD_PARAMS, 1, 4)),
        ('missing_scratch_page', dict(import_scratch_address=0x77000000), None),
        ('partial_scratch_page', dict(import_scratch_address=oracle.GUEST+oracle.GUEST_SIZE-16), None),
        ('entry_bound', dict(max_entries=1), None),
        ('invalid_callback_status', dict(callback=lambda e: -1 if e.slot_offset == 0x70 else 0), None),
        ('callback_exception', dict(callback=lambda e: (_ for _ in ()).throw(RuntimeError('synthetic callback failure'))), None),
    ):
        spec = dict(blob=blob)
        if label == 'entry_bound':
            spec['blob'] = b'A'*8+sections.section(4, b'\2'+table()*2)
        pages = limits0.prepare(args, 0x122C0000, spec)
        if setup:
            setup(pages)
        before = {key: bytes(value) for key, value in pages.items()}
        params = dict(state_address=STATE, image_base=0x122C0000, varuint_scratch_address=SCRATCH,
            callback=lambda e: 0, enable_table_memory_sections=True, import_scratch_address=IMPORT_SCRATCH)
        params.update(options)
        try:
            alternative.run_reader_sections(pages, **params)
        except (RefillUnsupported, ValueError, RuntimeError):
            pass
        else:
            raise AssertionError('definition guard accepted: '+label)
        assert {key: bytes(value) for key, value in pages.items()} == before, label
        rejected.append(dict(label=label, rejected=True, all_pages_unchanged=True, native_fault_path_compared=False))
    for number, descriptor in ((4, table()), (5, memory())):
        pages = limits0.prepare(args, 0x122C0000, dict(blob=b'A'*8+sections.section(number, b'\1'+descriptor)))
        result = alternative.run_reader_sections(pages, state_address=STATE, image_base=0x122C0000,
            varuint_scratch_address=SCRATCH, callback=lambda e: 0, enable_table_memory_sections=True,
            import_scratch_address=IMPORT_SCRATCH)
        assert result.status == 0 and len(result.callback_events) == 2
    pages = limits0.prepare(args, 0x122C0000, dict(blob=b'A'*8+sections.section(2, b'\1'+limits0.table())))
    before = {key: bytes(value) for key, value in pages.items()}
    try:
        alternative.run_reader_sections(pages, state_address=STATE, image_base=0x122C0000,
            varuint_scratch_address=SCRATCH, callback=lambda e: 0, enable_table_memory_sections=True,
            import_scratch_address=IMPORT_SCRATCH)
    except RefillUnsupported:
        pass
    else:
        raise AssertionError('definitions opt-in enabled imports')
    assert {key: bytes(value) for key, value in pages.items()} == before
    rejected.append(dict(label='definitions_opt_in_does_not_enable_imports', rejected=True,
                         all_pages_unchanged=True, native_fault_path_compared=False))
    blob = b'A'*8+sections.section(1, b'\1'+types.function_type([-1], [-2]))+sections.section(4, b'\1'+table())
    pages = limits0.prepare(args, 0x122C0000, dict(blob=blob))
    before = {key: bytes(value) for key, value in pages.items()}
    try:
        alternative.run_reader_sections(pages, state_address=STATE, image_base=0x122C0000,
            varuint_scratch_address=SCRATCH, callback=lambda e: 0, vector_allocate=lambda size: IMPORT_SCRATCH,
            enable_table_memory_sections=True, import_scratch_address=IMPORT_SCRATCH)
    except RefillUnsupported:
        pass
    else:
        raise AssertionError('planned type storage overlapped definition scratch')
    assert {key: bytes(value) for key, value in pages.items()} == before
    rejected.append(dict(label='planned_type_storage_aliases_definition_scratch', rejected=True,
                         all_pages_unchanged=True, native_fault_path_compared=False))
    return rejected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library', required=True, type=Path)
    parser.add_argument('--libc', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    sample_hash = hashlib.sha256(args.library.read_bytes()).hexdigest()
    assert sample_hash == oracle.LIBRARY_SHA256, 'unexpected native sample'
    libc_hash = hashlib.sha256(args.libc.read_bytes()).hexdigest()
    assert libc_hash == 'd2376df6d2ac3e0213f85e3614c4c7ad1d28c84c44926058d5c1b95c855563db', 'unexpected matching libc'
    rejected = negatives(args)
    specs, cases = fixtures()+actual_inputs(args.library), []
    for base in (0x122C0000, 0x775C205000):
        for index, spec in enumerate(specs, 1):
            try:
                cases.append(limits0.compare(args, base, spec, definition_sections=True,
                                            model_options=dict(enable_table_memory_sections=True)))
            except Exception as error:
                raise AssertionError('native/Python definition control failed: '+spec['label']) from error
            if index % 32 == 0:
                print('B table/memory sections:', hex(base), index, '/', len(specs), 'passed', flush=True)
        print('B table/memory sections:', hex(base), len(specs), 'controls passed', flush=True)
    evidence = dict(schema='vm9-alternative-reader-table-memory-sections-fresh-v1', evidence_date='2026-10-08',
        evidence_timezone='UTC', host_trial_label='20261008', sample_sha256=sample_hash,
        matching_libc_sha256=libc_hash, native_table_section_offset_hex='0x3231e4',
        native_memory_section_offset_hex='0x3232dc', native_core_function_offset_hex='0x324188',
        native_Python_table_memory_section_controls=len(cases), rollback_negative_controls=len(rejected),
        purely_synthetic_controls=sum(not c['fresh_ELF_function_global_plus_synthetic_definitions'] for c in cases),
        fresh_ELF_function_global_plus_synthetic_definitions_controls=sum(
            c['fresh_ELF_function_global_plus_synthetic_definitions'] for c in cases),
        actual_ELF_table_memory_section_controls=0,
        actual_ELF_table_memory_import_controls=0, supported_section_ids=[0, 1, 2, 3, 4, 5, 7, 8, 12],
        table_memory_sections_require_independent_explicit_opt_in_and_scratch=True,
        imports_opt_in_does_not_enable_definitions=True, definitions_opt_in_does_not_enable_imports=True,
        definitions_without_imports_opt_in_checked=True, guest_input_output_bytes_compared=0xA000,
        descriptor_bytes_compared_per_callback=19, transient_native_descriptor_pointer_normalized=True,
        native_stack_or_TLS_as_a_whole_compared=False, callbacks_are_explicit_status_services=True,
        actual_AST_callbacks_executed=False, allocator_boot_implemented=False,
        import_names_or_payloads_published=False, native_input_snapshot_used=False,
        reader_AST_native_Python_controls=0, complete_python_reader_implemented=False,
        independent_Python_factory_implemented=False, complete_python_bootstrap_controls=0,
        complete_python_medusa=False, fresh_signer_output_verified=False, live_server_matrix_verified=False,
        cases=cases, negative_cases=rejected)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2)+'\n', encoding='utf-8')
    print('B table/memory sections:', len(cases), 'native/Python +', len(rejected), 'rollback controls passed')


if __name__ == '__main__':
    main()
