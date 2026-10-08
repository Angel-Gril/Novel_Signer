"""Fresh B section 10 metadata, local groups and raw code-word controls.

Callbacks are pure status services. Raw words are read, not executed. Real ELF
code and names stay private; published evidence contains only counts and flags.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import random

import verify_vm9_alternative_globals_20261008 as globals0
import verify_vm9_alternative_import_limits_20261008 as limits0
import verify_vm9_alternative_imports_20261008 as imports0
import verify_vm9_alternative_sections_20261008 as sections
import verify_vm9_alternative_types_20261008 as types
import verify_vm9_signer_objects as oracle
import vm9_alternative_startup as alternative
from verify_vm9_alternative_blob_xor_20261008 import constructor_codec_byte
from verify_vm9_alternative_varint32_20261008 import encode as signed
from verify_vm9_alternative_varuint32_20261008 import encode as u32
from vm9_allocator import RefillUnsupported, _read_span, _write_span


def body(words=(), metadata=0, groups=(), size=None):
    data = u32(metadata)+u32(len(groups))+b''.join(u32(count)+signed(value) for count, value in groups)
    data += b''.join(word.to_bytes(4, 'little') for word in words)
    return u32(len(data) if size is None else size)+data


def fixtures():
    cases = []
    def add(label, payload, count=1, **options):
        cases.append(dict(label=label, blob=b'A'*8+sections.section(10, payload), function_count=count, **options))
    add('empty', b'\0', 0)
    add('empty_count_mismatch', b'\0', 1)
    for label, payload in (('count_missing', b''), ('count_truncated', b'\x80'),
                           ('count_overflow', b'\x80'*4+b'\x10'), ('count_past_remaining', b'\2\0')):
        add(label, payload)
    add('count_mismatch', b'\1'+body(), 0)
    add('one_empty_body', b'\1'+body())
    add('one_word', b'\1'+body([0xFEDCBA98]))
    add('multiple_words', b'\1'+body([0, 1, 0xFFFFFFFF, 0x80000000]))
    for metadata in (0, 1, 127, 128, 16384, 0xFFFFFFFF):
        add(f'metadata_{metadata}', b'\1'+body([7], metadata))
    for value in imports0.VALID_TYPES:
        for count in (0, 1, 0xFFFFFFFF):
            add(f'local_type_{value}_count_{count}', b'\1'+body([3], groups=[(count, value)]))
    for value in (-22, -20, -18, -15, -6, 0, 1, -(1 << 31), (1 << 31)-1):
        add(f'invalid_local_type_{value}', b'\1'+body(groups=[(1, value)]))
    add('local_count_overflow_before_type', b'\1'+u32(10)+b'\0\2'+u32(0xFFFFFFFF)+signed(-1)+b'\1')
    add('local_count_sum_boundary', b'\1'+body(groups=[(0xFFFFFFFE, -1), (1, -2)]))
    add('zero_local_groups', b'\1'+body(groups=[(0, -1), (0, -2)]))
    for secondary in (0, -1, -17, -(1 << 31), (1 << 31)-1):
        tail = b'\0\1\1'+signed(-21)+signed(secondary)
        add(f'extended_local_rejected_{secondary}', b'\1'+u32(len(tail))+tail)
    for label, data in (('body_size_missing', b''), ('body_size_truncated', b'\x80'),
        ('metadata_missing', b'\2'), ('metadata_truncated', b'\2\x80'),
        ('groups_missing', b'\2\0'), ('groups_truncated', b'\2\0\x80'),
        ('groups_past_remaining', b'\3\0\2\0'), ('local_count_missing', b'\3\0\1'),
        ('local_count_truncated', b'\4\0\1\x80'), ('local_type_missing', b'\3\0\1\0'),
        ('local_type_truncated', b'\4\0\1\0\x80'), ('local_type_overflow', b'\7\0\1\0'+b'\x80'*4+b'\x08'),
        ('extended_secondary_missing', b'\4\0\1\0'+signed(-21)),
        ('extended_secondary_truncated', b'\5\0\1\0'+signed(-21)+b'\x80')):
        add(label, b'\1'+data)
    for size in (0, 1, 3, 5):
        # A smaller declared body can consume header/words beyond its boundary,
        # within section input; exact body-end comparison subsequently rejects.
        add(f'body_end_overshoot_{size}', b'\1'+body([1], size=size))
    for suffix_size in range(4):
        payload = b'\1\6\0\0'+b'\xFF'*suffix_size
        # Native does not advance and repeats zero; fail at the first/third word.
        for retry in (0, 2):
            add(f'short_word_{suffix_size}_callback_rejection_after_{retry}', payload,
                failure_slot=0x168, failure_call=2+retry)
    add('word_reads_past_body_inside_section', b'\1'+body([0x12345678], size=3))
    add('remaining_body_bytes_underflow', b'\1'+body(size=1))
    add('body_trailing_section_byte', b'\1'+body()+b'\0')
    add('empty_trailing_section_byte', b'\0\0', 0)
    for slot, failure_call in ((0xB0, 0), (0xA8, 1), (0xB8, 2), (0x168, 3), (0xF8, 4)):
        add(f'callback_failure_{slot:x}', b'\1'+body([1], groups=[(2, -1)]),
            failure_slot=slot, failure_call=failure_call)
    add('second_body_callback_failure', b'\2'+body([1])*2, 2, failure_slot=0xA8, failure_call=5)
    add('imported_index_wrap', b'\3'+body([1])*3, 3, counts=(0xFFFFFFFF, 2, 3, 4))
    add('redundant_count_header_locals', b'\x81\0\x88\0\x80\0\x81\0\x80\0\xff\x7f')
    add('code_without_other_opt_ins', b'\1'+body([1]), model_options=dict(
        enable_function_global_imports=False, enable_table_memory_imports=False,
        enable_table_memory_sections=False, enable_global_section=False))
    code = sections.section(10, b'\1'+body([7]))
    for label, data in (('functions_then_code', sections.section(3, b'\1\0')+code),
        ('duplicate_code', code+code), ('code_then_function_rank_rejection', code+sections.section(3, b'\1\0')),
        ('code_then_generic_custom', code+sections.section(0, b'\1z')),
        ('data_count_then_code', sections.section(12, b'\0')+code)):
        cases.append(dict(label=label, blob=b'A'*8+data, function_count=1))
    combo = sections.section(1, b'\1'+types.function_type([-1], [-2]))
    combo += sections.section(2, b'\1'+imports0.function())+sections.section(3, b'\1\0')
    combo += sections.section(6, b'\1'+globals0.global_())+sections.section(7, b'\0')+sections.section(12, b'\0')+code
    cases.append(dict(label='types_imports_functions_globals_exports_data_count_code', blob=b'A'*8+combo,
                      synthetic_global_section_input=True))
    rng = random.Random(0x323CA8)
    for index in range(12):
        count = rng.randrange(1, 4)
        entries = [body([rng.getrandbits(32) for _ in range(rng.randrange(5))], rng.getrandbits(32),
            [(rng.randrange(16), rng.choice(imports0.VALID_TYPES)) for _ in range(rng.randrange(4))])
            for _ in range(count)]
        add(f'generated_{index}', u32(count)+b''.join(entries), count,
            counts=tuple(rng.getrandbits(32) for _ in range(4)))
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
        if number in (1, 2, 3, 6, 7, 10, 12):
            assert number not in selected
            selected[number] = blob[cursor:end]
        cursor = end
    assert cursor == len(blob) and sorted(selected) == [1, 2, 3, 6, 7, 10, 12]
    assert len(selected[10]) == 218682 and selected[10][0] == selected[3][0] == 121
    return [dict(label=label, blob=b'A'*8+b''.join(sections.section(n, selected[n]) for n in numbers),
                 function_count=121, actual_ELF_code_section_input=True, instruction_limit=6000000,
                 actual_ELF_global_section_input=6 in numbers)
            for label, numbers in (('fresh_ELF_code', (10,)), ('fresh_ELF_functions_code', (3, 10)),
                ('fresh_ELF_types_imports_functions_globals_exports_data_count_code', (1, 2, 3, 6, 7, 12, 10)))]


def negatives(args):
    rejected = []
    for label, options, payload in (
        ('code_opt_in_disabled', dict(enable_code_section=False), b'\1'+body([1])),
        ('other_opt_ins_do_not_enable_code', dict(enable_code_section=False, enable_global_section=True,
             global_scratch_address=limits0.GLOBAL_SCRATCH), b'\1'+body([1])),
        ('invalid_opt_in', dict(enable_code_section=1), b'\1'+body([1])),
        ('invalid_word_bound', dict(max_code_words=0), b'\1'+body([1])),
        ('word_bound', dict(max_code_words=1), b'\1'+body([1, 2])),
        ('nonadvancing_word_bound', dict(max_code_words=3), b'\1\6\0\0'),
        ('word_bound_across_bodies', dict(max_code_words=1), b'\2'+body([1])*2),
        ('body_count_bound', dict(max_entries=1), b'\2'+body()*2),
        ('local_group_bound', dict(max_entries=1), b'\1'+body(groups=[(0, -1), (0, -2)])),
        ('invalid_callback_status', dict(callback=lambda e: -1 if e.slot_offset == 0x168 else 0), b'\1'+body([1])),
        ('callback_exception', dict(callback=lambda e: (_ for _ in ()).throw(RuntimeError('synthetic failure'))), b'\1'+body([1])),
    ):
        pages = limits0.prepare(args, 0x122C0000, dict(blob=b'A'*8+sections.section(10, payload)))
        sections.put(pages, sections.STATE+0xA4, 2 if label in ('word_bound_across_bodies', 'body_count_bound') else 1, 4)
        before = {key: bytes(value) for key, value in pages.items()}
        params = dict(state_address=sections.STATE, image_base=0x122C0000,
            varuint_scratch_address=sections.SCRATCH, callback=lambda e: 0, enable_code_section=True)
        params.update(options)
        try:
            alternative.run_reader_sections(pages, **params)
        except (RefillUnsupported, ValueError, RuntimeError):
            pass
        else:
            raise AssertionError('code guard accepted: '+label)
        assert {key: bytes(value) for key, value in pages.items()} == before, label
        rejected.append(dict(label=label, rejected=True, all_pages_unchanged=True, native_fault_path_compared=False))
    for label, blob in (
        ('code_opt_in_does_not_enable_imports', b'A'*8+sections.section(2, b'\1'+imports0.function())),
        ('code_opt_in_does_not_enable_globals', b'A'*8+sections.section(6, b'\1'+globals0.global_())),
        ('code_opt_in_does_not_enable_definitions', b'A'*8+sections.section(4, b'\0')),
        ('missing_first_word_page', b'A'*8+sections.section(10, b'\1'+body([1]))),
    ):
        pages = limits0.prepare(args, 0x122C0000, dict(blob=blob))
        sections.put(pages, sections.STATE+0xA4, 1, 4)
        if label == 'missing_first_word_page':
            start = oracle.GUEST+oracle.GUEST_SIZE-14
            _write_span(pages, start, blob[:14])
            sections.put(pages, sections.STATE+8, start)
        before = {key: bytes(value) for key, value in pages.items()}
        try:
            alternative.run_reader_sections(pages, state_address=sections.STATE, image_base=0x122C0000,
                varuint_scratch_address=sections.SCRATCH, callback=lambda e: 0, enable_code_section=True)
        except (RefillUnsupported, ValueError):
            pass
        else:
            raise AssertionError('code isolation/page guard accepted: '+label)
        assert {key: bytes(value) for key, value in pages.items()} == before, label
        rejected.append(dict(label=label, rejected=True, all_pages_unchanged=True, native_fault_path_compared=False))
    return rejected


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
    rejected = negatives(args)
    specs, cases = fixtures()+actual_inputs(args.library), []
    for base in (0x122C0000, 0x775C205000):
        for index, spec in enumerate(specs, 1):
            includes_globals = spec.get('actual_ELF_global_section_input', False) or spec.get('synthetic_global_section_input', False)
            options = dict(enable_code_section=True)
            if includes_globals:
                options.update(enable_global_section=True, global_scratch_address=limits0.GLOBAL_SCRATCH)
            options.update(spec.get('model_options', {}))
            try:
                cases.append(limits0.compare(args, base, spec, code_sections=True, global_sections=includes_globals,
                                             model_options=options))
            except Exception as error:
                raise AssertionError('native/Python code control failed: '+spec['label']) from error
            if index % 32 == 0 or spec.get('actual_ELF_code_section_input'):
                print('B code:', hex(base), index, '/', len(specs), 'passed', flush=True)
        print('B code:', hex(base), len(specs), 'controls passed', flush=True)
    evidence = dict(schema='vm9-alternative-reader-code-fresh-v1', evidence_date='2026-10-08',
        evidence_timezone='UTC', host_trial_label='20261008', sample_sha256=sample_hash,
        matching_libc_sha256=libc_hash, native_code_section_offset_hex='0x323ca8',
        native_core_function_offset_hex='0x324188', native_Python_code_section_controls=len(cases),
        rollback_negative_controls=len(rejected), purely_synthetic_controls=sum(
            not c['actual_ELF_code_section_input'] for c in cases), actual_ELF_code_section_controls=sum(
            c['actual_ELF_code_section_input'] for c in cases), actual_ELF_code_section_payload_bytes=218682,
        actual_ELF_code_section_bodies=121, code_section_requires_independent_explicit_opt_in=True,
        raw_words_are_read_not_executed=True, instruction_execution_implemented=False,
        code_callback_budget_includes_native_nonadvancing_zero_word_retries=True,
        body_count_must_match_function_count=True, callbacks_are_explicit_status_services=True,
        actual_AST_callbacks_executed=False, allocator_boot_implemented=False,
        native_stack_or_TLS_as_a_whole_compared=False, import_names_or_code_payloads_published=False,
        native_input_snapshot_used=False, reader_AST_native_Python_controls=0,
        complete_python_reader_implemented=False, independent_Python_factory_implemented=False,
        complete_python_bootstrap_controls=0, complete_python_medusa=False,
        fresh_signer_output_verified=False, live_server_matrix_verified=False,
        cases=cases, negative_cases=rejected)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2)+'\n', encoding='utf-8')
    print('B code:', len(cases), 'native/Python +', len(rejected), 'rollback controls passed')


if __name__ == '__main__':
    main()
