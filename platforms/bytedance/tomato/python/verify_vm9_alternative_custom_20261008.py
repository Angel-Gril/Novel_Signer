"""Fresh native/Python B special custom metadata and section composition.

Only status callbacks and explicit allocation plans are supplied. Private ELF
names/payloads are never exported; no actual AST, bootstrap or signer is claimed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import random

import verify_vm9_alternative_import_limits_20261008 as harness
import verify_vm9_alternative_sections_20261008 as sections
import verify_vm9_alternative_types_20261008 as types
import verify_vm9_signer_objects as oracle
import vm9_alternative_startup as alternative
from verify_vm9_alternative_blob_xor_20261008 import constructor_codec_byte
from verify_vm9_alternative_varint64_20261008 import encode as i64
from verify_vm9_alternative_varuint32_20261008 import encode as u32
from vm9_allocator import RefillUnsupported, _read_span, _write_span


NO_ADDEND = 0x7F81C34C7
I64_ADDEND = 0x63CB38
MINIMAL = ((b'dylink', b'\0'*5), (b'dylink.0', b''), (b'linking', b'\2'),
           (b'target_features', b'\0'), (b'reloc.CODE', b'\0\0'))


def string(value=b'z'):
    return u32(len(value))+value


def subsection(tag, body, size=None):
    return u32(tag)+u32(len(body) if size is None else size)+body


def custom(name, body):
    return sections.section(0, string(name)+body)


def symbol(kind, flags=0):
    body = u32(kind)+u32(flags)
    if kind in (0, 2, 4, 5):
        body += u32(0xFFFFFFFF)
        if flags & 0x50 != 0x10:
            body += string(b'\0\xffs')
    elif kind == 1:
        body += string(b'\0\xffd')
        if not flags & 0x10:
            body += u32(0xFFFFFFFF)+u32(128)+u32(127)
    elif kind == 3:
        body += u32(0xFFFFFFFF)
    return body


def options():
    return dict(enable_special_custom_sections=True, custom_scratch_address=harness.CUSTOM_SCRATCH)


def fixtures():
    cases = []
    def add(label, name, body, **settings):
        cases.append(dict(label=label, blob=b'A'*8+custom(name, body), custom_flag=91, **settings))
    for name, body in MINIMAL:
        add('minimal_'+name.decode(), name, body)
        add('trailing_'+name.decode(), name, body+b'\0')
    dylink = u32(0xFFFFFFFF)+u32(31)+u32(128)+u32(127)+u32(2)+string(b'\0\xffx')+string(b'')
    features = u32(3)+b'\0'+string(b'')+b'\xff'+string(b'\0\xfft')+b'+'+string(b'x')
    dylink_bodies = {1: b'\0'*4, 2: b'\2'+string(b'')+string(b'\0\xffd'),
                     3: b'\2'+string(b'')+u32(0xFFFFFFFF)+string()+u32(128),
                     4: b'\1'+string(b'\0\xffm')+string(b'')+u32(0xFFFFFFFF)}
    linking_bodies = {5: b'\2'+string(b'')+u32(31)+u32(0xFFFFFFFF)+string()+b'\0\0',
                      6: b'\2'+u32(0xFFFFFFFF)+u32(128)+b'\0\0',
                      7: b'\2'+string(b'')+u32(0xFFFFFFFF)+b'\0'+string()+b'\0\2'+b'\0\0'*2,
                      8: b'\6'+b''.join(symbol(k) for k in range(6))}
    representatives = [(b'dylink', dylink), (b'target_features', features)]
    for name, bodies, version in ((b'dylink.0', dylink_bodies, b''), (b'linking', linking_bodies, b'\2')):
        for tag, body in bodies.items():
            label = name.decode()+'_tag_'+str(tag)
            wrapped = version+subsection(tag, body)
            add(label, name, wrapped)
            representatives.append((name, wrapped))
            add(label+'_size_too_long', name, version+subsection(tag, body, len(body)+1))
            add(label+'_size_too_short', name, version+subsection(tag, body, len(body)-1))
            add(label+'_trailing', name, version+subsection(tag, body+b'\0'))
            add(label+'_empty_body', name, version+subsection(tag, b''))
        add(name.decode()+'_all_tags', name, version+b''.join(subsection(t, b) for t, b in bodies.items()))
        for tag in (0, 9, 128, 0xFFFFFFFF):
            add(name.decode()+'_unknown_'+str(tag), name, version+subsection(tag, b'\xff\x80opaque'))
        add(name.decode()+'_unknown_then_known', name,
            version+subsection(127, b'\xff\x80opaque')+subsection(next(iter(bodies)), next(iter(bodies.values()))))
        for label, body in (('tag_truncated', b'\x80'), ('tag_overflow', b'\x80'*4+b'\x10'),
            ('size_truncated', b'\1\x80'), ('size_overflow', b'\1'+b'\x80'*4+b'\x10'),
            ('size_past_section', b'\1\x7f'), ('count_huge_truncated', subsection(next(iter(bodies)) if name == b'linking' else 2, u32(0xFFFFFFFF)))):
            add(name.decode()+'_'+label, name, version+body)
    for version in (0, 1, 3, 128, 0xFFFFFFFF):
        add('linking_version_'+str(version), b'linking', u32(version))
    for alignment in (31, 32, 127, 0xFFFFFFFF):
        add('linking_alignment_'+str(alignment), b'linking', b'\2'+subsection(5, b'\1'+string()+u32(alignment)+b'\0'))
    for kind in (0, 1, 2, 3, 4, 5, 6, 128, 0xFFFFFFFF):
        for flags in (0, 0x10, 0x40, 0x50, 0xFF, 0x100, 0xFFFFFFFF):
            add(f'linking_symbol_kind_{kind}_flags_{flags}', b'linking', b'\2'+subsection(8, b'\1'+symbol(kind, flags)))
    for kind in range(35):
        body = b'\0\1'+u32(kind)+u32(0xFFFFFFFF)+u32(128)
        if (1 << kind) & I64_ADDEND:
            body += i64(-129)
        add('reloc_kind_'+str(kind), b'reloc.CODE', body)
    for kind in (35, 127, 128, 0xFFFFFFFF):
        add('reloc_invalid_kind_'+str(kind), b'reloc.DATA', b'\0\1'+u32(kind)+b'\0\0')
    for value in (-(1 << 63), -128, -1, 0, 127, 128, (1 << 63)-1):
        add('reloc_addend_'+str(value), b'reloc.CODE', b'\0\1\3\0\0'+i64(value))
    for label, body in (('missing_addend', b'\0\1\3\0\0'), ('truncated_addend', b'\0\1\3\0\0\x80'),
        ('overflow_addend', b'\0\1\3\0\0'+b'\x80'*9+b'\x02'),
        ('count_past_bytes', b'\0\2\0'), ('count_huge', b'\0'+u32(0xFFFFFFFF)),
        ('kind_truncated', b'\0\1\x80'), ('kind_overflow', b'\0\1'+b'\x80'*4+b'\x10'),
        ('overlong_fields', b'\x80\0\x81\0\x80\0\x80\0\x80\0')):
        add('reloc_'+label, b'reloc', body)
    for name in (b'reloc', b'relocX', b'relocXX', b'relocXXX', b'reloc'+b'X'*10):
        add('reloc_name_length_'+str(len(name)), name, b'\0\0')
    for size in (0, 4, 5, 6, 7, 8, 15):
        add('generic_name_length_'+str(size), b'x'*size, b'\xff\x80opaque')
    for index, (name, body) in enumerate(representatives):
        for cut in range(len(body)):
            add(f'truncated_body_{index}_{cut}', name, body[:cut])
    for name in (b'dylink', b'target_features'):
        prefix = b'\0'*4 if name == b'dylink' else b''
        for label, body in (('count_huge', u32(0xFFFFFFFF)), ('name_past_end', b'\1'+(b'\xff' if name == b'target_features' else b'')+b'\x7f')):
            add(name.decode()+'_'+label, name, prefix+body)
    # Subsections and nested records share one budget. Each new custom resets it.
    add('record_budget_exact', b'linking', b'\2'+subsection(7, b'\1'+string()+b'\0\2'+b'\0\0'*2),
        model_settings=dict(max_custom_records=4))
    cases.append(dict(label='record_budget_resets_per_custom', custom_flag=255,
        blob=b'A'*8+custom(b'linking', b'\2'+subsection(6, b'\1\0\0'))*2,
        model_settings=dict(max_custom_records=2)))
    rng = random.Random(322700)
    for index in range(16):
        count = rng.randrange(1, 5)
        body = u32(count)+b''.join(symbol(rng.randrange(0, 9), rng.randrange(1 << 32)) for _ in range(count))
        add('linking_generated_'+str(index), b'linking', b'\2'+subsection(8, body))
    for flag in (0, 1, 91, 255):
        for label, body in (('success', b'\2'), ('failure', b'\1')):
            cases.append(dict(label=f'flag_{flag}_{label}', custom_flag=flag,
                blob=b'A'*8+custom(b'linking', body)))
    cases.append(dict(label='customs_around_ordinary_sections', custom_flag=91, blob=b'A'*8+
        custom(b'linking', b'\2')+sections.section(3, b'\1\0')+
        custom(b'reloc.CODE', b'\0\0')+sections.section(7, b'\0')+custom(b'dylink.0', b'')))
    return cases


def actual_inputs(library):
    base, pages = 0x122C0000, oracle.fresh_pages()
    pages.update(oracle.image_pages(library, base))
    codec = oracle.GUEST+0x4000
    _write_span(pages, codec+50, bytes([constructor_codec_byte(library)]))
    alternative.decode_factory_blob_xor(pages, blob_address=base+0x387D20, blob_size=0x37FD0,
        codec_table_address=codec, codec_table_count=3)
    blob = _read_span(pages, base+0x387D20, 0x37FD0)
    cursor, parts, customs, ids = 8, [], [], []
    while cursor < len(blob):
        start, number = cursor, blob[cursor]
        cursor += 1; size = 0
        for i in range(5):
            byte = blob[cursor]; cursor += 1; size |= (byte & 127) << (i*7)
            if byte < 128:
                break
        else:
            raise AssertionError('fresh ELF envelope did not terminate')
        assert cursor+size <= len(blob)
        if number == 0:
            customs.append(blob[cursor:cursor+size])
        cursor += size
        parts.append(blob[start:cursor]); ids.append(number)
    assert cursor == len(blob) and list(map(len, customs)) == [1758, 3240, 177]
    cases = [dict(label='actual_ELF_custom_'+str(i), blob=b'A'*8+sections.section(0, payload),
        custom_flag=91, actual_ELF_custom_section_input=True) for i, payload in enumerate(customs)]
    cases.append(dict(label='actual_ELF_three_custom_sections', custom_flag=91,
        blob=b'A'*8+b''.join(sections.section(0, payload) for payload in customs),
        actual_ELF_custom_section_input=True))
    cases.append(dict(label='actual_ELF_complete_section_composition', custom_flag=91,
        blob=b'A'*8+b''.join(parts), actual_ELF_custom_section_input=True,
        actual_ELF_complete_section_composition=True, actual_ELF_global_section_input=True,
        actual_ELF_code_section_input=True, actual_ELF_data_section_input=True,
        function_count=121, instruction_limit=12000000, actual_section_ids=ids))
    return cases


def compare(args, base, spec):
    full = spec.get('actual_ELF_complete_section_composition', False)
    settings = options()
    if full:
        settings.update(enable_table_memory_sections=True, enable_global_section=True,
            global_scratch_address=harness.GLOBAL_SCRATCH, enable_code_section=True,
            enable_element_section=True, enable_data_section=True,
            expression_scratch_address=harness.EXPRESSION_SCRATCH)
    settings.update(spec.get('model_settings', {}))
    record = harness.compare(args, base, spec, custom_sections=True, definition_sections=full,
        global_sections=full, code_sections=full, segment_sections=full, model_options=settings)
    if spec['label'].startswith('minimal_') or spec['label'].startswith('actual_ELF_'):
        assert record['status'] == 0, spec['label']
    if full:
        assert record['sections_entered'] == spec['actual_section_ids']
        assert record['final_import_counts'] == [18, 0, 0, 22]
        assert record['instruction_word_callback_count'] == 54533 and record['final_code_body_count'] == 121
        assert record['data_payload_lengths'] == [3632, 352, 0]
    return record


def negatives(args):
    records = []
    valid = custom(b'linking', b'\2'+subsection(7, b'\1'+string()+b'\0\2'+b'\0\0'*2))
    cases = [('disabled_'+name.decode(), dict(enable_special_custom_sections=False), custom(name, body), None)
             for name, body in MINIMAL]
    for label, settings in (
        ('invalid_opt_in', dict(enable_special_custom_sections=1)),
        ('scratch_missing', dict(custom_scratch_address=None)), ('scratch_null', dict(custom_scratch_address=0)),
        ('scratch_unaligned', dict(custom_scratch_address=harness.CUSTOM_SCRATCH+1)),
        ('scratch_overflow', dict(custom_scratch_address=(1 << 64)-1)),
        ('scratch_unmapped', dict(custom_scratch_address=0x90000000)),
        ('scratch_alias_state', dict(custom_scratch_address=sections.STATE)),
        ('scratch_alias_input', dict(custom_scratch_address=sections.DATA)),
        ('scratch_alias_u32', dict(custom_scratch_address=sections.SCRATCH)),
        ('scratch_alias_imports', dict(custom_scratch_address=harness.IMPORT_SCRATCH)),
        ('scratch_alias_globals', dict(custom_scratch_address=harness.GLOBAL_SCRATCH,
            enable_global_section=True, global_scratch_address=harness.GLOBAL_SCRATCH)),
        ('scratch_alias_expression', dict(custom_scratch_address=harness.EXPRESSION_SCRATCH,
            enable_data_section=True, expression_scratch_address=harness.EXPRESSION_SCRATCH)),
        ('scratch_alias_decoder', dict(custom_scratch_address=0x122C0000+0x3E2D08)),
        ('scratch_alias_decoder_key', dict(custom_scratch_address=0x122C0000+0x121110)),
        ('scratch_alias_opcode_pointer', dict(custom_scratch_address=0x122C0000+0x3750B0)),
        ('records_zero', dict(max_custom_records=0)), ('records_excessive', dict(max_custom_records=65537)),
        ('records_noninteger', dict(max_custom_records='4')), ('records_nested_budget', dict(max_custom_records=3)),
    ):
        cases.append((label, settings, valid, None))
    for tag in (6, 8):
        body = b'\2'+subsection(tag, b'\2'+(b'\0\0' if tag == 6 else symbol(6))*2)
        cases.append(('records_tag_'+str(tag), dict(max_custom_records=2), custom(b'linking', body), None))
    cases.append(('records_unknown_subsections', dict(max_custom_records=1),
        custom(b'dylink.0', subsection(127, b'')*2), None))
    cases.append(('scratch_alias_type_storage', dict(custom_scratch_address=types.OLD_PARAMS), valid,
        lambda p: types.word_vector(p, sections.STATE+0x28, types.OLD_PARAMS, 1, 4)))
    for label, pointer in (('scratch_alias_opcode_table', harness.CUSTOM_SCRATCH),
                           ('scratch_alias_opcode_table_tail', harness.CUSTOM_SCRATCH-504)):
        cases.append((label, dict(enable_global_section=True, global_scratch_address=harness.GLOBAL_SCRATCH),
            valid, lambda p, pointer=pointer: sections.put(p, 0x122C0000+0x3750B0, pointer)))
    cases.append(('missing_name_input_page', {}, valid, lambda p: p.pop(sections.DATA >> 12)))
    for label, settings, part, setup in cases:
        pages = harness.prepare(args, 0x122C0000, dict(blob=b'A'*8+part, custom_flag=91))
        if setup:
            setup(pages)
        before = {key: bytes(value) for key, value in pages.items()}
        params = dict(state_address=sections.STATE, image_base=0x122C0000,
            varuint_scratch_address=sections.SCRATCH, callback=lambda event: 0,
            enable_table_memory_imports=True, import_scratch_address=harness.IMPORT_SCRATCH, **options())
        params.update(settings)
        try:
            alternative.run_reader_sections(pages, **params)
        except (RefillUnsupported, ValueError):
            pass
        else:
            raise AssertionError('custom guard accepted: '+label)
        assert {key: bytes(value) for key, value in pages.items()} == before, label
        records.append(dict(label=label, rejected=True, all_pages_unchanged=True, native_fault_path_compared=False))
    # A new type allocation must also respect the retained custom work region.
    pages = harness.prepare(args, 0x122C0000, dict(blob=b'A'*8+sections.section(1, b'\1'+types.function_type([-1], [-2]))))
    before = {key: bytes(value) for key, value in pages.items()}
    try:
        alternative.run_reader_sections(pages, state_address=sections.STATE, image_base=0x122C0000,
            varuint_scratch_address=sections.SCRATCH, callback=lambda event: 0,
            vector_allocate=lambda size: harness.CUSTOM_SCRATCH, **options())
    except RefillUnsupported:
        pass
    else:
        raise AssertionError('type allocation overlapped custom scratch')
    assert {key: bytes(value) for key, value in pages.items()} == before
    records.append(dict(label='planned_type_storage_aliases_custom_scratch', rejected=True,
        all_pages_unchanged=True, native_fault_path_compared=False))
    return records


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
    rejected, specs, records = negatives(args), fixtures()+actual_inputs(args.library), []
    for base in (0x122C0000, 0x775C205000):
        for index, spec in enumerate(specs, 1):
            try:
                records.append(compare(args, base, spec))
            except Exception as error:
                raise AssertionError('native/Python custom control failed: '+spec['label']) from error
            if index % 32 == 0:
                print('B custom:', hex(base), index, '/', len(specs), 'passed', flush=True)
        print('B custom:', hex(base), len(specs), 'controls passed', flush=True)
    evidence = dict(schema='vm9-alternative-reader-custom-fresh-v1', evidence_date='2026-10-08',
        evidence_timezone='UTC', host_trial_label='20261008', sample_sha256=sample_hash,
        matching_libc_sha256=libc_hash, native_core_function_offset_hex='0x324188',
        native_custom_function_offset_hex='0x322700', native_special_handler_offsets_hex={
            'dylink': '0x321f08', 'dylink.0': '0x321b2c', 'linking': '0x322130',
            'target_features': '0x322060', 'reloc_prefix': '0x321990'},
        native_Python_custom_controls=len(records), rollback_negative_controls=len(rejected),
        purely_synthetic_controls=sum(not c['actual_ELF_custom_section_input'] for c in records),
        actual_ELF_custom_controls=sum(c['actual_ELF_custom_section_input'] for c in records),
        actual_ELF_complete_section_composition_controls=sum(c['actual_ELF_complete_section_composition'] for c in records),
        actual_ELF_custom_payload_bytes=[1758, 3240, 177], generated_fixture_seed=322700,
        native_symbol_mask_recheck_controls=sum(bool(c['native_symbol_mask_recheck_kinds']) for c in records),
        native_linking_symbol_abort_reached=False, linking_abort_globally_unreachable_proved=False,
        reloc_no_addend_mask_hex=hex(NO_ADDEND), reloc_i64_addend_mask_hex=hex(I64_ADDEND),
        custom_handlers_require_explicit_opt_in_and_scratch=True, custom_record_budget_scope='per_custom_section',
        pre_change_minimal_expected_RED_controls=5, pre_change_failure='special custom-section handler is unrecovered',
        actual_matching_libc_memcmp_used=True, callbacks_are_explicit_status_services=True,
        private_names_or_payloads_published=False, native_input_snapshot_used=False,
        native_stack_or_TLS_as_a_whole_compared=False, actual_AST_callbacks_executed=False,
        allocator_boot_implemented=False, reader_AST_native_Python_controls=0,
        complete_python_reader_implemented=False, independent_Python_factory_implemented=False,
        complete_python_bootstrap_controls=0, complete_python_medusa=False,
        fresh_signer_output_verified=False, live_server_matrix_verified=False,
        cases=records, negative_cases=rejected)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2)+'\n', encoding='utf-8')
    print('B custom:', len(records), 'native/Python +', len(rejected), 'rollback controls passed')


if __name__ == '__main__':
    main()
