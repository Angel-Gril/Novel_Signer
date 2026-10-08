"""Fresh B section 6 and initializer controls against the original dispatcher.

The native caller local starts from an explicit synthetic eight-byte ABI seed.
Only callback values/state are compared; natural stack initialization and actual
AST callbacks are not claimed. Fresh ELF global payloads remain private.
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
import verify_vm9_alternative_table_memory_sections_20261008 as definitions
import verify_vm9_alternative_types_20261008 as types
import verify_vm9_signer_objects as oracle
import vm9_alternative_startup as alternative
from verify_vm9_alternative_blob_xor_20261008 import constructor_codec_byte
from verify_vm9_alternative_varint32_20261008 import encode as signed
from verify_vm9_alternative_varuint32_20261008 import encode as u32
from vm9_allocator import RefillUnsupported, _read_span, _write_span

STATE, DATA, SCRATCH = sections.STATE, sections.DATA, sections.SCRATCH
GLOBAL_SCRATCH = limits0.GLOBAL_SCRATCH


def global_(value=-1, mutable=0, expression=b'\x41\0\x0b'):
    return signed(value)+bytes([mutable])+expression


def fixtures():
    cases = []
    def add(label, payload, **options):
        cases.append(dict(label=label, blob=b'A'*8+sections.section(6, payload), **options))
    for label, payload in (('empty', b'\0'), ('count_missing', b''), ('count_truncated', b'\x80'),
                            ('count_overflow', b'\x80'*4+b'\x10'), ('count_past_payload', b'\2\0'),
                            ('empty_trailing_byte', b'\0\0')):
        add(label, payload)
    add('empty_count_callback_failure', b'\0', failure_slot=0x78)
    for value in imports0.VALID_TYPES:
        for mutable in (0, 1, 2, 127, 255):
            add(f'type_{value}_mutable_{mutable}', b'\1'+global_(value, mutable))
    for value in (-22, -20, -18, -15, -6, 0, 1, -(1 << 31), (1 << 31)-1):
        add(f'invalid_type_{value}', b'\1'+global_(value))
    for value in (0, -1, -17, -(1 << 31), (1 << 31)-1):
        add(f'extended_type_rejected_{value}', b'\1'+signed(-21)+signed(value)+b'\0\x0b')
    for label, tail in (('type_missing', b''), ('type_truncated', b'\x80'),
                        ('type_overflow', b'\x80'*4+b'\x08'), ('extended_missing', signed(-21)),
                        ('extended_truncated', signed(-21)+b'\x80'), ('mutable_missing', b'\x7f'),
                        ('expression_missing', b'\x7f\0')):
        add(label, b'\1'+tail)
    add('redundant_count_and_type', b'\x81\0'+b'\xff'*4+b'\x7f\0'+
        b'\x41'+b'\xff'*4+b'\x7f\x0b')
    # Each end-only entry overwrites its low word with the type, retaining high.
    for seed in (0, 0x0123456789ABCDEF, 0xFFFFFFFF00000000):
        add(f'end_only_seed_{seed:x}', b'\2'+global_(-1, expression=b'\x0b')+
            global_(-17, expression=b'\x0b'), global_word_seed=seed)
    add('i64_then_end_only_high_word_retained', b'\2'+global_(expression=b'\x42'+signed(-1)+b'\x0b')+
        global_(-2, expression=b'\x0b'))
    add('index_wrap', b'\3'+global_()*3, counts=(3, 5, 7, 0xFFFFFFFF))
    for opcode, values in ((0x41, (0, -1, -(1 << 31), (1 << 31)-1, -8193)),
                           (0x42, (0, -1, -(1 << 63), (1 << 63)-1, -(1 << 32)))):
        for value in values:
            add(f'constant_{opcode:x}_{value}', b'\1'+global_(expression=bytes([opcode])+signed(value)+b'\x0b'))
        for tail in (b'', b'\x80', b'\x80'*10):
            add(f'constant_{opcode:x}_truncated_{len(tail)}', b'\1'+global_(expression=bytes([opcode])+tail))
    add('i32_fifth_overflow', b'\1'+global_(expression=b'\x41'+b'\x80'*4+b'\x08\x0b'))
    for last in (1, 63, 64, 126, 128, 255):
        add(f'i64_tenth_invalid_{last}', b'\1'+global_(expression=b'\x42'+b'\x80'*9+bytes([last])+b'\x0b'))
    for opcode, width in ((0x43, 4), (0x44, 8)):
        for bits in (0, 1, (1 << (width*8))-1, 1 << (width*8-1),
                     0x7FC01234 if width == 4 else 0x7FF8000012345678):
            add(f'raw_constant_{opcode:x}_{bits:x}', b'\1'+global_(expression=bytes([opcode])+
                bits.to_bytes(width, 'little')+b'\x0b'))
        for size in range(width):
            add(f'raw_constant_{opcode:x}_truncated_{size}', b'\1'+global_(expression=bytes([opcode])+b'\xff'*size))
    for expression, label in ((b'\x41\1', 'missing_end'), (b'\x0b\0', 'trailing_opcode'),
        (b'\x41\1\x42\x7f\x43\x34\x12\x80\xff\x44'+b'\xff'*8+b'\x0b', 'multiple_constants'),
        (b'\x41\1\x42\x80', 'success_then_truncated'), (b'\x41\1\x23\0\x0b', 'success_then_invalid')):
        add(label, b'\1'+global_(expression=expression))
    for opcode in (0, 1, 2, 0x23, 0x40, 0x45, 0x7F, 0x80, 0xFB, 0xFF):
        add(f'unsupported_opcode_{opcode:x}', b'\1'+global_(expression=bytes([opcode])+b'\0\x0b'))
    for opcode in (0xFC, 0xFD, 0xFE):
        for sub in (0, 1, 510, 511, 512, 0xFFFFFFFF):
            add(f'prefix_{opcode:x}_sub_{sub}', b'\1'+global_(expression=bytes([opcode])+u32(sub)+b'\x0b'))
        for label, data in (('missing', b''), ('truncated', b'\x80'), ('overflow', b'\x80'*4+b'\x10')):
            add(f'prefix_{opcode:x}_{label}', b'\1'+global_(expression=bytes([opcode])+data))
    expressions = {0x78: b'\x41\1\x0b', 0x80: b'\x41\1\x0b', 0x88: b'\x41\1\x0b',
        0x90: b'\x41\1\x0b', 0xC0: b'\x41\1\x0b', 0xC8: b'\x0b',
        0xD0: b'\x43'+b'\xff'*4+b'\x0b', 0xD8: b'\x44'+b'\xff'*8+b'\x0b',
        0xE0: b'\x41\x7f\x0b', 0xE8: b'\x42\x7f\x0b'}
    for slot, expression in expressions.items():
        failure_call = {0x78: 0, 0x80: 1, 0x88: 2, 0x90: 7, 0xC0: 3, 0xC8: 4}.get(slot, 4)
        add(f'callback_failure_{slot:x}', b'\2'+global_(expression=expression)*2,
            failure_slot=slot, failure_call=failure_call)
    add('second_entry_callback_failure', b'\2'+global_()*2, failure_slot=0x80, failure_call=8)
    add('relocated_opcode_table_copy', b'\1'+global_(), relocated_opcode_table=True)
    for opcode, kind, expression in ((0x45, 2, b'\x45\x7f\x0b'), (0x41, 3, b'\x41\x7f\x0b'),
                                    (0x0B, 0x12345678, b'\x0b'), (0, 1, b'\0'),
                                    (0x41, 0, b'\x41\1\x0b')):
        add(f'relocated_opcode_override_{opcode:x}_{kind:x}', b'\1'+global_(expression=expression),
            relocated_opcode_table=True, opcode_overrides={opcode: kind})
    add('globals_without_import_or_definition_opt_in', b'\1'+global_(),
        model_options=dict(enable_function_global_imports=False, enable_table_memory_imports=False,
                           enable_table_memory_sections=False))
    base = sections.section(6, b'\1'+global_())
    for label, blob in (('duplicate', base+base), ('rank_rejection', base+sections.section(5, b'\0')),
                        ('generic_custom_between', base+sections.section(0, b'\1z')+sections.section(7, b'\0'))):
        cases.append(dict(label=label, blob=b'A'*8+blob))
    mix = sections.section(1, b'\1'+types.function_type([-1], [-2]))
    mix += sections.section(2, b'\4'+imports0.function(index=2)+limits0.table()+limits0.memory()+imports0.global_())
    mix += sections.section(3, b'\1\0')+sections.section(4, b'\1'+definitions.table())
    mix += sections.section(5, b'\1'+definitions.memory())+base+sections.section(7, b'\0')+sections.section(12, b'\0')
    cases.append(dict(label='types_all_import_kinds_all_definitions_exports_data', blob=b'A'*8+mix))
    rng = random.Random(0x32365C)
    for index in range(12):
        entries = []
        count = rng.randrange(1, 5)
        for _ in range(count):
            width = rng.choice((4, 8))
            opcode = 0x43 if width == 4 else 0x44
            expression = bytes([opcode])+rng.getrandbits(width*8).to_bytes(width, 'little')+b'\x0b'
            entries.append(global_(rng.choice(imports0.VALID_TYPES), rng.randrange(2), expression))
        add(f'generated_{index}', u32(count)+b''.join(entries),
            counts=tuple(rng.randrange(1 << 32) for _ in range(4)), global_word_seed=rng.getrandbits(64))
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
            raise AssertionError('fresh ELF envelope did not terminate')
        end = cursor+size
        assert end <= len(blob)
        if number in (1, 2, 3, 6, 7, 12):
            assert number not in selected
            selected[number] = blob[cursor:end]
        cursor = end
    assert cursor == len(blob) and sorted(selected) == [1, 2, 3, 6, 7, 12]
    assert len(selected[6]) == 133 and selected[6][0] == 22
    cases = [dict(label=label, blob=b'A'*8+b''.join(sections.section(n, selected[n]) for n in numbers),
                  actual_ELF_global_section_input=True)
             for label, numbers in (('fresh_ELF_globals', (6,)), ('fresh_ELF_imports_globals', (2, 6)),
                ('fresh_ELF_imports_functions_globals_exports_data', (2, 3, 6, 7, 12)),
                ('fresh_ELF_types_imports_functions_globals_exports_data', (1, 2, 3, 6, 7, 12)))]
    selected[4], selected[5] = b'\1'+definitions.table(), b'\1'+definitions.memory()
    cases.append(dict(label='fresh_ELF_selected_plus_synthetic_table_memory_definitions',
        blob=b'A'*8+b''.join(sections.section(n, selected[n]) for n in (1, 2, 3, 4, 5, 6, 7, 12)),
        actual_ELF_global_section_input=True, fresh_ELF_function_global_plus_synthetic_definitions=True))
    return cases


def negatives(args):
    rejected = []
    blob = b'A'*8+sections.section(6, b'\1'+global_())
    def opcode_pointer(pages, value):
        sections.put(pages, 0x122C0000+0x3750B0, value)
    for label, options, setup in (
        ('global_opt_in_disabled', dict(enable_global_section=False), None),
        ('imports_definitions_do_not_enable_globals', dict(enable_global_section=False,
            enable_function_global_imports=True, enable_table_memory_sections=True), None),
        ('invalid_opt_in', dict(enable_global_section=1), None),
        ('missing_scratch', dict(global_scratch_address=None), None),
        ('null_scratch', dict(global_scratch_address=0), None),
        ('unaligned_scratch', dict(global_scratch_address=GLOBAL_SCRATCH+1), None),
        ('overflow_scratch', dict(global_scratch_address=alternative.MASK64-7), None),
        ('scratch_alias_state', dict(global_scratch_address=STATE), None),
        ('scratch_alias_input', dict(global_scratch_address=DATA), None),
        ('scratch_alias_u32', dict(global_scratch_address=SCRATCH), None),
        ('scratch_alias_import', dict(global_scratch_address=limits0.IMPORT_SCRATCH,
            enable_table_memory_imports=True), None),
        ('scratch_alias_type_storage', dict(global_scratch_address=types.OLD_PARAMS),
            lambda p: types.word_vector(p, STATE+0x28, types.OLD_PARAMS, 1, 4)),
        ('missing_scratch_page', dict(global_scratch_address=0x77000000), None),
        ('partial_scratch_page', dict(global_scratch_address=oracle.GUEST+oracle.GUEST_SIZE-8), None),
        ('entry_bound', dict(max_entries=1), None),
        ('initializer_bound', dict(max_initializer_ops=1), None),
        ('invalid_initializer_bound', dict(max_initializer_ops=0), None),
        ('invalid_callback_status', dict(callback=lambda e: -1 if e.slot_offset == 0xE0 else 0), None),
        ('callback_exception', dict(callback=lambda e: (_ for _ in ()).throw(RuntimeError('synthetic failure'))), None),
        ('null_opcode_table', {}, lambda p: opcode_pointer(p, 0)),
        ('overflow_opcode_table', {}, lambda p: opcode_pointer(p, alternative.MASK64-3)),
        ('unmapped_opcode_table', {}, lambda p: opcode_pointer(p, 0x77000000)),
        ('opcode_table_alias_scratch', {}, lambda p: opcode_pointer(p, GLOBAL_SCRATCH)),
    ):
        spec = dict(blob=blob)
        if label == 'entry_bound':
            spec['blob'] = b'A'*8+sections.section(6, b'\2'+global_()*2)
        pages = limits0.prepare(args, 0x122C0000, spec)
        if setup:
            setup(pages)
        before = {key: bytes(value) for key, value in pages.items()}
        params = dict(state_address=STATE, image_base=0x122C0000, varuint_scratch_address=SCRATCH,
            callback=lambda e: 0, enable_global_section=True, global_scratch_address=GLOBAL_SCRATCH,
            import_scratch_address=limits0.IMPORT_SCRATCH)
        params.update(options)
        try:
            alternative.run_reader_sections(pages, **params)
        except (RefillUnsupported, ValueError, RuntimeError):
            pass
        else:
            raise AssertionError('global guard accepted: '+label)
        assert {key: bytes(value) for key, value in pages.items()} == before, label
        rejected.append(dict(label=label, rejected=True, all_pages_unchanged=True, native_fault_path_compared=False))
    for number, payload in ((2, b'\1'+imports0.global_()), (4, b'\1'+definitions.table())):
        pages = limits0.prepare(args, 0x122C0000, dict(blob=b'A'*8+sections.section(number, payload)))
        before = {key: bytes(value) for key, value in pages.items()}
        try:
            alternative.run_reader_sections(pages, state_address=STATE, image_base=0x122C0000,
                varuint_scratch_address=SCRATCH, callback=lambda e: 0, enable_global_section=True,
                global_scratch_address=GLOBAL_SCRATCH)
        except RefillUnsupported:
            pass
        else:
            raise AssertionError('global opt-in enabled other handler')
        assert {key: bytes(value) for key, value in pages.items()} == before
        rejected.append(dict(label=f'globals_do_not_enable_section_{number}', rejected=True,
                             all_pages_unchanged=True, native_fault_path_compared=False))
    pages = limits0.prepare(args, 0x122C0000, dict(blob=b'A'*8+
        sections.section(1, b'\1'+types.function_type([-1], [-2]))+sections.section(6, b'\1'+global_())))
    before = {key: bytes(value) for key, value in pages.items()}
    try:
        alternative.run_reader_sections(pages, state_address=STATE, image_base=0x122C0000,
            varuint_scratch_address=SCRATCH, callback=lambda e: 0, vector_allocate=lambda size: GLOBAL_SCRATCH,
            enable_global_section=True, global_scratch_address=GLOBAL_SCRATCH)
    except RefillUnsupported:
        pass
    else:
        raise AssertionError('future type allocation overlaps global scratch')
    assert {key: bytes(value) for key, value in pages.items()} == before
    rejected.append(dict(label='planned_type_storage_aliases_global_scratch', rejected=True,
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
    assert libc_hash == 'd2376df6d2ac3e0213f85e3614c4c7ad1d28c84c44926058d5c1b95c855563db'
    rejected = negatives(args)
    specs, cases = fixtures()+actual_inputs(args.library), []
    for base in (0x122C0000, 0x775C205000):
        for index, spec in enumerate(specs, 1):
            options = dict(enable_global_section=True, global_scratch_address=GLOBAL_SCRATCH,
                           enable_table_memory_sections=True)
            options.update(spec.get('model_options', {}))
            try:
                cases.append(limits0.compare(args, base, spec, definition_sections=True,
                                             global_sections=True, model_options=options))
            except Exception as error:
                raise AssertionError('native/Python global control failed: '+spec['label']) from error
            if index % 32 == 0:
                print('B globals:', hex(base), index, '/', len(specs), 'passed', flush=True)
        print('B globals:', hex(base), len(specs), 'controls passed', flush=True)
    evidence = dict(schema='vm9-alternative-reader-globals-fresh-v1', evidence_date='2026-10-08',
        evidence_timezone='UTC', host_trial_label='20261008', sample_sha256=sample_hash,
        matching_libc_sha256=libc_hash, native_global_section_offset_hex='0x323464',
        native_initializer_offset_hex='0x32365c', opcode_table_GOT_offset_hex='0x3750b0',
        native_core_function_offset_hex='0x324188', native_Python_global_section_controls=len(cases),
        rollback_negative_controls=len(rejected), actual_ELF_global_section_controls=sum(
            c['actual_ELF_global_section_input'] for c in cases),
        purely_synthetic_controls=sum(not c['actual_ELF_global_section_input'] for c in cases),
        actual_ELF_global_section_payload_bytes=133, actual_ELF_global_section_entries=22,
        actual_ELF_table_memory_section_controls=0, supported_section_ids=[0, 1, 2, 3, 4, 5, 6, 7, 8, 12],
        global_section_requires_independent_explicit_opt_in_and_scratch=True,
        native_local_word_seed_is_explicit_synthetic_ABI_input=True, native_local_word_seed_bytes=8,
        natural_native_stack_initialization_recovered=False, native_stack_or_TLS_as_a_whole_compared=False,
        relocated_opcode_table_and_overrides_checked=True, initializer_kind_uses_uint32_bits=True,
        i32_initializer_output_zero_extended=True, end_only_retains_caller_local_high_word=True,
        definition_callbacks_do_not_increment_import_counts=True, guest_input_output_bytes_compared=0xA000,
        callbacks_are_explicit_status_services=True, actual_AST_callbacks_executed=False,
        allocator_boot_implemented=False, import_names_or_payloads_published=False, native_input_snapshot_used=False,
        reader_AST_native_Python_controls=0, complete_python_reader_implemented=False,
        independent_Python_factory_implemented=False, complete_python_bootstrap_controls=0,
        complete_python_medusa=False, fresh_signer_output_verified=False, live_server_matrix_verified=False,
        cases=cases, negative_cases=rejected)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2)+'\n', encoding='utf-8')
    print('B globals:', len(cases), 'native/Python +', len(rejected), 'rollback controls passed')


if __name__ == '__main__':
    main()
