"""Fresh B function/global import controls against original section/core code.

Callbacks are explicit status services, not actual AST construction. Fresh ELF
payloads are independently XORed in Python. Their names and contents stay private.
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
import verify_vm9_alternative_sections_20261008 as sections
import verify_vm9_alternative_types_20261008 as types
import vm9_alternative_startup as alternative
from verify_vm9_alternative_blob_xor_20261008 import constructor_codec_byte
from verify_vm9_alternative_varuint32_20261008 import encode as u32
from verify_vm9_alternative_varint32_20261008 import encode as i32
from vm9_allocator import RefillUnsupported, _read_span, _write_span

STATE, DATA, OBJECT = sections.STATE, sections.DATA, sections.OBJECT
VTABLE, SCRATCH, CALLBACK = sections.VTABLE, sections.SCRATCH, sections.CALLBACK
SLOTS = {**types.SLOTS, 0x28: 7, 0x40: 8}
COUNT_OFFSETS = (0x90, 0x94, 0x98, 0x9C)
VALID_TYPES = (-5, -4, -3, -2, -1, -17, -16)


def imported(module, field, kind, descriptor):
    return u32(len(module))+module+u32(len(field))+field+bytes([kind])+descriptor


def function(module=b'm', field=b'f', index=0):
    return imported(module, field, 0, u32(index))


def global_(module=b'm', field=b'g', value=-1, mutable=0):
    return imported(module, field, 3, i32(value)+bytes([mutable]))


def fixtures():
    cases = []
    def add(label, payload=b'\0', **options):
        cases.append(dict(label=label, blob=b'A'*8+sections.section(2, payload), **options))
    add('import_empty')
    add('import_empty_trailing_byte', b'\0\0')
    add('import_count_missing', b'')
    add('import_count_truncated', b'\x80')
    add('import_count_exceeds_remaining', b'\x02\0')
    add('import_count_overflow', b'\x80'*4+b'\x10')
    for index in (0, 127, 128, 16384, 0xFFFFFFFF):
        add(f'function_type_index_{index}', b'\1'+function(index=index))
    add('function_empty_names', b'\1'+function(b'', b''))
    add('function_binary_names', b'\1'+function(b'\0\xff\x80', b'\xff\0'))
    add('function_long_names', b'\1'+function(b'm'*129, b'f'*128))
    add('function_non_utf8_names', b'\1'+function(b'\xc0\xaf', b'\xed\xa0\x80'))
    add('function_redundant_lengths_and_index', b'\x81\0\x81\0m\x81\0f\0\x80\0')
    for mutable in (0, 1, 2, 127, 128, 255):
        for value in VALID_TYPES:
            add(f'global_type_{value}_mutable_{mutable}', b'\1'+global_(value=value, mutable=mutable))
    add('global_empty_binary_names', b'\1'+global_(b'', b'\0\xff', -17, 1))
    add('global_redundant_signed_type', b'\1'+imported(b'm', b'g', 3, b'\xff'*4+b'\x7f\1'))
    for value in (0, 1, -6, -15, -18, -22, -(1 << 31), (1 << 31)-1):
        add(f'global_invalid_type_{value}', b'\1'+global_(value=value))
    for value in (0, 1, -1, -17, -(1 << 31), (1 << 31)-1):
        add(f'global_extended_type_{value}', b'\1'+imported(b'm', b'g', 3, i32(-21)+i32(value)+b'\0'))
    for label, payload in (
        ('module_length_missing', b''), ('module_length_truncated', b'\x80'),
        ('module_length_overflow', b'\x80'*4+b'\x10'), ('module_past_end', b'\x03a'),
        ('field_length_missing', b'\x01m'), ('field_length_truncated', b'\x01m\x80'),
        ('field_past_end', b'\x01m\x03a'), ('kind_missing', b'\x01m\x01f'),
        ('function_index_missing', b'\x01m\x01f\0'),
        ('function_index_truncated', b'\x01m\x01f\0\x80'),
        ('function_index_overflow', b'\x01m\x01f\0'+b'\x80'*4+b'\x10'),
        ('global_type_missing', b'\x01m\x01f\3'),
        ('global_type_truncated', b'\x01m\x01f\3\x80'),
        ('global_type_overflow', b'\x01m\x01f\3'+b'\x80'*4+b'\x08\0'),
        ('global_mutable_missing', b'\x01m\x01f\3\x7f'),
        ('global_extended_missing_secondary', b'\x01m\x01f\3'+i32(-21)),
        ('global_extended_truncated_secondary', b'\x01m\x01f\3'+i32(-21)+b'\x80'),
    ):
        add(label, b'\1'+payload)
    for kind in (4, 127, 255):
        add(f'invalid_import_kind_{kind}', b'\1'+imported(b'm', b'f', kind, b''))
    mixed = b'\4'+function(index=2)+global_(value=-16, mutable=1)+function(index=0xFFFFFFFF)+global_()
    add('mixed_functions_globals', mixed)
    add('mixed_counter_wrap', mixed, counts=(0xFFFFFFFF, 19, 23, 0xFFFFFFFF))
    add('mixed_nonzero_counters', mixed, counts=(11, 19, 23, 31))
    for slot, failure_call in ((0x28, 0), (0x40, 1), (0x28, 2), (0x40, 3)):
        add(f'mixed_failure_{slot}_{failure_call}', mixed, failure_slot=slot, failure_call=failure_call)
    add('import_valid_then_bad_name', b'\2'+function()+b'\x05a')
    add('import_valid_then_bad_global', b'\2'+global_()+global_(mutable=2))
    add('import_function_trailing_byte', b'\1'+function()+b'\0')
    add('import_global_trailing_byte', b'\1'+global_()+b'\0')
    add('duplicate_import_section', b'\0')
    cases[-1]['blob'] += sections.section(2, b'\0')
    add('import_after_function_order_rejected', b'\0', previous=3)
    combo = sections.section(1, b'\1'+types.function_type([-1], [-2]))+sections.section(2, mixed)
    combo += sections.section(3, b'\2\0\1')+sections.section(7, b'\0')+sections.section(12, b'\0')
    cases.append(dict(label='types_mixed_imports_functions_exports_data', blob=b'A'*8+combo))
    rng = random.Random(0x322CF8)
    for index in range(16):
        count = rng.randrange(1, 7)
        entries = []
        for _ in range(count):
            module = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 9)))
            field = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 9)))
            entries.append(function(module, field, rng.randrange(1 << 32)) if rng.randrange(2)
                           else global_(module, field, rng.choice(VALID_TYPES), rng.randrange(2)))
        add(f'import_generated_{index}', u32(count)+b''.join(entries),
            counts=(rng.randrange(1 << 32), 19, 23, rng.randrange(1 << 32)))
    return cases


def actual_inputs(library):
    pages = oracle.fresh_pages()
    base = 0x122C0000
    pages.update(oracle.image_pages(library, base))
    table = oracle.GUEST+0x4000
    _write_span(pages, table+50, bytes([constructor_codec_byte(library)]))
    alternative.decode_factory_blob_xor(pages, blob_address=base+0x387D20, blob_size=0x37FD0,
        codec_table_address=table, codec_table_count=3)
    blob = _read_span(pages, base+0x387D20, 0x37FD0)
    cursor, selected = 8, {}
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
        if number in (1, 2, 3, 7, 12):
            assert number not in selected
            selected[number] = blob[cursor:end]
        cursor = end
    assert cursor == len(blob) and sorted(selected) == [1, 2, 3, 7, 12]
    return [dict(label=label, blob=b'A'*8+b''.join(sections.section(n, selected[n]) for n in numbers),
                 actual_ELF_section_input=True) for label, numbers in (
        ('actual_ELF_imports', (2,)), ('actual_ELF_imports_functions_exports_data', (2, 3, 7, 12)),
        ('actual_ELF_types_imports_functions_exports_data', (1, 2, 3, 7, 12)))]


def prepare(args, base, spec):
    pages = types.prepare(args, base, spec)
    for slot in SLOTS:
        sections.put(pages, VTABLE+slot, CALLBACK+slot)
    for offset, value in zip(COUNT_OFFSETS, spec.get('counts', (0, 19, 23, 0))):
        sections.put(pages, STATE+offset, value, 4)
    return pages


def snapshot(read, slot, arguments, cursor, end, vectors):
    counts = tuple(int.from_bytes(read(STATE+offset, 4), 'little') for offset in COUNT_OFFSETS)
    names = tuple(bytes(read(arguments[i], arguments[i+1])) for i in (1, 3)) if slot in (0x28, 0x40) else ()
    return slot, arguments, cursor, end, vectors, counts, names


def compare(args, base, spec):
    pages = prepare(args, base, spec)
    model = {key: bytearray(value) for key, value in pages.items()}
    native_events, model_events = [], []
    native_alloc, native_effects, observe, allocate, free = types.services()
    def status(slot, index):
        return 0xFFFFFFFF if slot == spec.get('failure_slot') and index == spec.get('failure_call', 0) else 0
    imports = {0x347FA0: free}
    with args.libc.open('rb') as stream:
        elf = ELFFile(stream)
        memcmp = next(0x51000000+s['st_value'] for sec in elf.iter_sections()
                      if sec['sh_type'] == 'SHT_DYNSYM' for s in sec.iter_symbols()
                      if s.name == 'memcmp' and s['st_value'])
    def compare_bytes(cpu):
        cpu.reg_write(arm.UC_ARM64_REG_PC, memcmp)
    imports[0x347FE0] = compare_bytes
    for slot, argc in SLOTS.items():
        def service(cpu, slot=slot, argc=argc):
            values = [cpu.reg_read(getattr(arm, 'UC_ARM64_REG_X'+str(i))) for i in range(min(argc+1, 8))]
            if argc+1 > 8:
                sp = cpu.reg_read(arm.UC_ARM64_REG_SP)
                # +0x323024 stores only one bool byte; the ABI slot's padding is unspecified.
                values.append(int.from_bytes(cpu.mem_read(sp, 1), 'little'))
            assert values[0] == OBJECT
            arguments = tuple(values[1:])
            vectors = ()
            if slot == 0x20:
                vectors = tuple(tuple(int.from_bytes(cpu.mem_read(pointer+i*8, 8), 'little') for i in range(count))
                                for count, pointer in ((arguments[1], arguments[2]), (arguments[3], arguments[4])))
            event = snapshot(cpu.mem_read, slot, arguments,
                int.from_bytes(cpu.mem_read(STATE+24, 8), 'little'),
                int.from_bytes(cpu.mem_read(STATE, 8), 'little'), vectors)
            value = status(slot, len(native_events))
            native_events.append(event)
            return value
        imports[CALLBACK+slot-base] = service
    observed = {(base+offset, 64): None for offset in sections.GLOBALS}
    returned, memory, calls, ledger = oracle.native(args.library, base, 0x324188, [STATE], pages,
        host_imports=imports, libc=args.libc, observed_memory=observed, instruction_limit=150000,
        malloc_handler=lambda cpu, size: allocate(size, cpu),
        instruction_observer=lambda cpu, addr: observe(cpu, addr, base))
    assert not calls and not ledger
    model_alloc, _, _, planned, _ = types.services()
    def callback(event):
        names = tuple(_read_span(model, event.arguments[i], event.arguments[i+1]) for i in (1, 3)) \
            if event.slot_offset in (0x28, 0x40) else ()
        value = status(event.slot_offset, len(model_events))
        model_events.append((event.slot_offset, event.arguments, event.cursor, event.section_end,
                             event.type_vectors, event.import_counts, names))
        return value
    result = alternative.run_reader_sections(model, state_address=STATE, image_base=base,
        varuint_scratch_address=SCRATCH, callback=callback, vector_allocate=planned,
        enable_function_global_imports=True)
    assert result.status == returned, (spec['label'], 'return')
    assert native_events == model_events, (spec['label'], 'callback arguments/state/counts/names/type cells')
    assert native_alloc == model_alloc, (spec['label'], 'allocation plan')
    assert native_effects == [types.effect_tuple(e) for e in result.vector_effects], (spec['label'], 'vector effects')
    assert _read_span(model, oracle.GUEST, 0xA000) == memory, (spec['label'], 'guest input/output')
    for (address, size), value in observed.items():
        assert _read_span(model, address, size) == value, (spec['label'], 'rank/custom globals')
    return dict(label=spec['label'], image_base_hex=hex(base), status=result.status, cursor=result.cursor,
        last_section=result.last_section, sections_entered=list(result.sections_entered),
        callback_count=len(native_events), function_import_callback_count=sum(e[0] == 0x28 for e in native_events),
        global_import_callback_count=sum(e[0] == 0x40 for e in native_events),
        final_import_counts=[int.from_bytes(_read_span(model, STATE+o, 4), 'little') for o in COUNT_OFFSETS],
        allocation_count=len(native_alloc), free_count=sum(e[0] == 'free' for e in native_effects),
        native_Python_return_match=True, guest_input_output_region_match=True, rank_global_memory_match=True,
        callback_arguments_state_counts_names_and_type_cells_match=True,
        global_mutable_stack_argument_compared=any(e[0] == 0x40 for e in native_events),
        allocation_free_effects_and_publication_match=True,
        actual_ELF_section_input=spec.get('actual_ELF_section_input', False), native_input_snapshot_used=False)


def negatives(args):
    valid = b'\2'+function()+global_()
    specs = [('imports_disabled', valid, dict(enable_function_global_imports=False)),
             ('invalid_opt_in', valid, dict(enable_function_global_imports=1)),
             ('entry_bound', valid, dict(max_entries=1)),
             ('invalid_callback_status', valid, dict(callback=lambda e: -1 if e.slot_offset == 0x40 else 0)),
             ('callback_exception', valid, dict(callback=lambda e: (_ for _ in ()).throw(RuntimeError('status service')))),
             ('scratch_alias', valid, dict(varuint_scratch_address=DATA)),
             ('missing_input', valid, {})]
    for kind in (1, 2):
        entry = imported(b'm', b'x', kind, b'\0\0')
        specs.extend([(f'unrecovered_kind_{kind}', b'\1'+entry, {}),
                      (f'function_then_unrecovered_kind_{kind}', b'\2'+function()+entry, {})])
    rejected = []
    for label, payload, options in specs:
        pages = prepare(args, 0x122C0000, dict(blob=b'A'*8+sections.section(2, payload)))
        if label == 'missing_input':
            pages.pop(DATA >> 12)
        before = {key: bytes(value) for key, value in pages.items()}
        params = dict(state_address=STATE, image_base=0x122C0000, varuint_scratch_address=SCRATCH,
                      callback=lambda e: 0, enable_function_global_imports=True)
        params.update(options)
        try:
            alternative.run_reader_sections(pages, **params)
        except (RefillUnsupported, ValueError, RuntimeError):
            pass
        else:
            raise AssertionError('import guard accepted: '+label)
        assert {key: bytes(value) for key, value in pages.items()} == before, label
        rejected.append(dict(label=label, rejected=True, all_pages_unchanged=True,
                             native_unrecovered_handler_compared=False))
    for label, suffix, options in (
        ('types_then_disabled_import', valid, dict(enable_function_global_imports=False)),
        ('types_then_table_import', b'\1'+imported(b'm', b'x', 1, b''), {}),
        ('types_then_memory_import', b'\1'+imported(b'm', b'x', 2, b''), {})):
        blob = b'A'*8+sections.section(1, b'\1'+types.function_type([-1], [-2]))+sections.section(2, suffix)
        pages = prepare(args, 0x122C0000, dict(blob=blob))
        before = {key: bytes(value) for key, value in pages.items()}
        _, _, _, planned, _ = types.services()
        params = dict(state_address=STATE, image_base=0x122C0000, varuint_scratch_address=SCRATCH,
                      callback=lambda e: 0, vector_allocate=planned, enable_function_global_imports=True)
        params.update(options)
        try:
            alternative.run_reader_sections(pages, **params)
        except RefillUnsupported:
            pass
        else:
            raise AssertionError('late import guard accepted: '+label)
        assert {key: bytes(value) for key, value in pages.items()} == before, label
        rejected.append(dict(label=label, rejected=True, all_pages_unchanged=True,
                             native_unrecovered_handler_compared=False))
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
    inputs = fixtures()+actual_inputs(args.library)
    cases = []
    for base in (0x122C0000, 0x775C205000):
        for spec in inputs:
            try:
                cases.append(compare(args, base, spec))
            except Exception as error:
                raise AssertionError('native/Python import control failed: '+spec['label']) from error
        print('B imports:', hex(base), len(inputs), 'controls passed', flush=True)
    rejected = negatives(args)
    evidence = dict(schema='vm9-alternative-reader-imports-fresh-v1', evidence_date='2026-10-08',
        evidence_timezone='UTC', host_trial_label='20261008', sample_sha256=sample_hash,
        matching_libc_sha256=libc_hash, native_import_function_offset_hex='0x322cf8',
        native_core_function_offset_hex='0x324188', native_Python_import_controls=len(cases),
        synthetic_import_controls=sum(not c['actual_ELF_section_input'] for c in cases),
        actual_ELF_selected_section_controls=sum(c['actual_ELF_section_input'] for c in cases),
        rollback_negative_controls=len(rejected), guest_input_output_bytes_compared=0xA000,
        supported_section_ids=[0, 1, 2, 3, 7, 8, 12], supported_import_kinds=[0, 3],
        function_global_imports_require_explicit_opt_in=True, table_memory_imports_implemented=False,
        import_names_or_payloads_published=False, global_ninth_argument_read_from_native_stack=True,
        callbacks_are_explicit_status_services=True, actual_AST_callbacks_executed=False,
        allocation_free_are_explicit_services=True, allocator_boot_implemented=False,
        native_input_snapshot_used=False, reader_AST_native_Python_controls=0,
        complete_python_reader_implemented=False, independent_Python_factory_implemented=False,
        complete_python_bootstrap_controls=0, complete_python_medusa=False,
        fresh_signer_output_verified=False, live_server_matrix_verified=False,
        cases=cases, negative_cases=rejected)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2)+'\n', encoding='utf-8')
    print('B imports:', len(cases), 'native/Python +', len(rejected), 'rollback controls passed')


if __name__ == '__main__':
    main()
