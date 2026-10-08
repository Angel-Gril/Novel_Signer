"""Fresh B table/memory imports against actual native section/core code.

The native descriptor lives on the caller stack. Only that transient pointer
is normalized to explicit model scratch; its 19 content bytes are compared.
Callbacks and vector allocations remain explicit services, not actual AST.
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
import verify_vm9_alternative_imports_20261008 as imports0
import verify_vm9_alternative_sections_20261008 as sections
import verify_vm9_alternative_types_20261008 as types
import vm9_alternative_startup as alternative
from verify_vm9_alternative_varuint32_20261008 import encode as u32
from verify_vm9_alternative_varint32_20261008 import encode as i32
from vm9_allocator import RefillUnsupported, _read_span, _write_span

STATE, DATA, OBJECT = sections.STATE, sections.DATA, sections.OBJECT
VTABLE, SCRATCH, CALLBACK = sections.VTABLE, sections.SCRATCH, sections.CALLBACK
IMPORT_SCRATCH = oracle.GUEST+0xB100
SLOTS = {**imports0.SLOTS, 0x30: 8, 0x38: 7}


def entry(kind, descriptor, module=b'm', field=b'l'):
    return imports0.imported(module, field, kind, descriptor)


def table(value=-16, flags=0, minimum=0, maximum=0):
    return entry(1, i32(value)+bytes([flags])+u32(minimum)+(u32(maximum) if flags & 1 else b''))


def memory(flags=0, minimum=0, maximum=0):
    return entry(2, bytes([flags])+u32(minimum)+(u32(maximum) if flags & 1 else b''))


def fixtures():
    cases = []
    def add(label, payload, **options):
        cases.append(dict(label=label, blob=b'A'*8+sections.section(2, payload), **options))
    for value in (-21, -17, -16):
        for flags in (0, 1, 4, 5):
            add(f'table_type_{value}_flags_{flags}', b'\1'+table(value, flags, 0xFFFFFFFF, 3))
    for value in (-22, -20, -19, -18, -15, -5, -1, 0, -(1 << 31), (1 << 31)-1):
        add(f'table_invalid_type_{value}', b'\1'+table(value))
    for kind in (1, 2):
        for flags in (2, 3, 6, 7, 8, 9, 15, 127, 128, 255):
            descriptor = (i32(-16) if kind == 1 else b'')+bytes([flags])+b'\0\0'
            add(f'kind_{kind}_invalid_flags_{flags}', b'\1'+entry(kind, descriptor))
    for flags in (0, 1, 4, 5):
        for minimum, maximum in ((0, 0), (1, 0), (1 << 32, (1 << 32)+3),
                                  (1 << 63, (1 << 64)-1), ((1 << 64)-1, 2)):
            add(f'memory_flags_{flags}_minimum_{minimum}', b'\1'+memory(flags, minimum, maximum))
    for kind in (1, 2):
        prefix = i32(-16) if kind == 1 else b''
        for label, tail in (
            ('flags_missing', b''), ('minimum_missing', b'\0'), ('minimum_truncated', b'\0\x80'),
            ('maximum_missing', b'\1\0'), ('maximum_truncated', b'\1\0\x80')):
            add(f'kind_{kind}_{label}', b'\1'+entry(kind, prefix+tail))
    add('table_type_missing', b'\1'+entry(1, b''))
    add('table_type_truncated', b'\1'+entry(1, b'\x80'))
    add('table_type_fifth_overflow', b'\1'+entry(1, b'\x80'*4+b'\x08\0\0'))
    add('table_minimum_fifth_overflow', b'\1'+entry(1, i32(-16)+b'\0'+b'\x80'*4+b'\x10'))
    add('table_maximum_fifth_overflow', b'\1'+entry(1, i32(-16)+b'\1\0'+b'\x80'*4+b'\x10'))
    for field in ('minimum', 'maximum'):
        prefix = b'\0' if field == 'minimum' else b'\1\0'
        for label, tail in (('overflow', b'\x80'*9+b'\2'), ('ten_continuations', b'\x80'*10),
                            ('nine_continuations', b'\x80'*9), ('eleventh_terminator', b'\x80'*10+b'\0')):
            add(f'memory_{field}_{label}', b'\1'+entry(2, prefix+tail))
    add('table_redundant_bounds', b'\1'+entry(1, i32(-21)+b'\5\x80\0\x81\0'))
    add('memory_redundant_bounds', b'\1'+entry(2, b'\5'+b'\x80'*9+b'\0'+b'\x81'+b'\x80'*8+b'\0'))
    add('table_binary_names', b'\1'+entry(1, i32(-17)+b'\0\0', b'\0\xff', b''))
    add('memory_binary_names', b'\1'+entry(2, b'\0\0', b'', b'\xc0\xaf'))
    mixed = b'\4'+imports0.function(index=2)+table(-21, 5, 12, 3)+memory(5, 1 << 63, 9)+imports0.global_()
    add('four_import_kinds', mixed)
    add('four_counter_wrap', mixed, counts=(0xFFFFFFFF,)*4)
    for slot, call in ((0x28, 0), (0x30, 1), (0x38, 2), (0x40, 3)):
        add(f'four_kinds_callback_failure_{slot}', mixed, failure_slot=slot, failure_call=call)
    for label, first, second in (('table_then_memory', table(), memory()),
                                 ('memory_then_table', memory(), table())):
        add(label, b'\2'+first+second)
    add('table_then_bad_memory', b'\2'+table()+entry(2, b'\2\0'))
    add('memory_then_bad_table', b'\2'+memory()+table(-1))
    add('table_trailing_byte', b'\1'+table()+b'\0')
    add('memory_trailing_byte', b'\1'+memory()+b'\0')
    combo = sections.section(1, b'\1'+types.function_type([-1], [-2]))+sections.section(2, mixed)
    combo += sections.section(3, b'\1\0')+sections.section(7, b'\0')+sections.section(12, b'\0')
    cases.append(dict(label='types_four_import_kinds_functions_exports_data', blob=b'A'*8+combo))
    rng = random.Random(0x321844)
    for index in range(12):
        entries = []
        for _ in range(rng.randrange(1, 5)):
            flags = rng.choice((0, 1, 4, 5))
            entries.append(table(rng.choice((-21, -17, -16)), flags, rng.randrange(1 << 32), rng.randrange(1 << 32))
                           if rng.randrange(2) else memory(flags, rng.randrange(1 << 64), rng.randrange(1 << 64)))
        add(f'limits_generated_{index}', u32(len(entries))+b''.join(entries),
            counts=tuple(rng.randrange(1 << 32) for _ in range(4)))
    return cases


def actual_compositions(library):
    # The fresh ELF has function/global imports only. Add two explicitly
    # synthetic imports; never describe those as real ELF table/memory inputs.
    cases = []
    for spec in imports0.actual_inputs(library):
        blob, cursor, parts = spec['blob'], 8, []
        while cursor < len(blob):
            kind = blob[cursor]
            cursor += 1
            size, shift = 0, 0
            while True:
                b = blob[cursor]
                cursor += 1
                size |= (b & 127) << shift
                if b < 128:
                    break
                shift += 7
            payload = blob[cursor:cursor+size]
            cursor += size
            if kind == 2:
                assert payload[0] == 40
                payload = u32(42)+payload[1:]+table(-21, 5, 7, 1)+memory(5, 1 << 63, 1)
            parts.append(sections.section(kind, payload))
        cases.append(dict(label=spec['label']+'_plus_synthetic_limits', blob=b'A'*8+b''.join(parts),
                          fresh_ELF_function_global_plus_synthetic_limits=True))
    return cases


def prepare(args, base, spec):
    pages = imports0.prepare(args, base, spec)
    for slot in SLOTS:
        sections.put(pages, VTABLE+slot, CALLBACK+slot)
    for offset, value in zip(imports0.COUNT_OFFSETS, spec.get('counts', (0, 0, 0, 0))):
        sections.put(pages, STATE+offset, value, 4)
    return pages


def limits_tuple(data):
    return int.from_bytes(data[:8], 'little'), int.from_bytes(data[8:16], 'little'), *data[16:19]


def compare(args, base, spec):
    pages = prepare(args, base, spec)
    model = {key: bytearray(value) for key, value in pages.items()}
    native_events, model_events, descriptors = [], [], []
    native_alloc, native_effects, observe, allocate, free = types.services()
    def status(slot, call):
        return 0xFFFFFFFF if slot == spec.get('failure_slot') and call == spec.get('failure_call', 0) else 0
    host = {0x347FA0: free}
    with args.libc.open('rb') as stream:
        elf = ELFFile(stream)
        memcmp = next(0x51000000+s['st_value'] for sec in elf.iter_sections()
                      if sec['sh_type'] == 'SHT_DYNSYM' for s in sec.iter_symbols()
                      if s.name == 'memcmp' and s['st_value'])
    def compare_bytes(cpu):
        cpu.reg_write(arm.UC_ARM64_REG_PC, memcmp)
    host[0x347FE0] = compare_bytes
    for slot, argc in SLOTS.items():
        def service(cpu, slot=slot, argc=argc):
            values = [cpu.reg_read(getattr(arm, 'UC_ARM64_REG_X'+str(i))) for i in range(min(argc+1, 8))]
            if argc+1 > 8:
                width = 1 if slot == 0x40 else 8
                values.append(int.from_bytes(cpu.mem_read(cpu.reg_read(arm.UC_ARM64_REG_SP), width), 'little'))
            assert values[0] == OBJECT
            arguments = list(values[1:])
            limits = ()
            if slot in (0x30, 0x38):
                descriptor = bytes(cpu.mem_read(arguments[-1], 19))
                descriptors.append(descriptor)
                limits = limits_tuple(descriptor)
                arguments[-1] = IMPORT_SCRATCH
            vectors = ()
            if slot == 0x20:
                vectors = tuple(tuple(int.from_bytes(cpu.mem_read(pointer+i*8, 8), 'little') for i in range(count))
                                for count,pointer in ((arguments[1], arguments[2]), (arguments[3], arguments[4])))
            event = imports0.snapshot(cpu.mem_read, slot, tuple(arguments),
                int.from_bytes(cpu.mem_read(STATE+24, 8), 'little'),
                int.from_bytes(cpu.mem_read(STATE, 8), 'little'), vectors)
            if slot in (0x30, 0x38):
                names = tuple(bytes(cpu.mem_read(arguments[i], arguments[i+1])) for i in (1, 3))
                event = (*event[:-1], names)
            value = status(slot, len(native_events))
            native_events.append((*event, limits))
            return value
        host[CALLBACK+slot-base] = service
    observed = {(base+offset, 64): None for offset in sections.GLOBALS}
    returned, guest, calls, ledger = oracle.native(args.library, base, 0x324188, [STATE], pages,
        host_imports=host, libc=args.libc, observed_memory=observed, instruction_limit=150000,
        malloc_handler=lambda cpu, size: allocate(size, cpu),
        instruction_observer=lambda cpu, address: observe(cpu, address, base))
    assert not calls and not ledger
    model_alloc, _, _, planned, _ = types.services()
    def callback(event):
        names = tuple(_read_span(model, event.arguments[i], event.arguments[i+1]) for i in (1, 3)) \
            if event.slot_offset in (0x28, 0x30, 0x38, 0x40) else ()
        value = status(event.slot_offset, len(model_events))
        model_events.append((event.slot_offset, event.arguments, event.cursor, event.section_end,
                             event.type_vectors, event.import_counts, names, event.import_limits))
        return value
    result = alternative.run_reader_sections(model, state_address=STATE, image_base=base,
        varuint_scratch_address=SCRATCH, callback=callback, vector_allocate=planned,
        enable_function_global_imports=True, enable_table_memory_imports=True,
        import_scratch_address=IMPORT_SCRATCH)
    assert result.status == returned, (spec['label'], 'return')
    assert native_events == model_events, (spec['label'], 'callback state/arguments/descriptor/counts/names')
    assert native_alloc == model_alloc, (spec['label'], 'allocation plan')
    assert native_effects == [types.effect_tuple(e) for e in result.vector_effects], (spec['label'], 'vector effects')
    assert _read_span(model, oracle.GUEST, 0xA000) == guest, (spec['label'], 'guest input/output')
    for (address, size), data in observed.items():
        assert _read_span(model, address, size) == data, (spec['label'], 'rank globals')
    limits_calls = [e for e in native_events if e[0] in (0x30, 0x38)]
    if limits_calls and result.status == 0:
        assert _read_span(model, IMPORT_SCRATCH, 19) == descriptors[-1], (spec['label'], 'final model scratch')
    return dict(label=spec['label'], image_base_hex=hex(base), status=result.status, cursor=result.cursor,
        last_section=result.last_section, sections_entered=list(result.sections_entered), callback_count=len(native_events),
        import_callback_counts=[sum(e[0] == slot for e in native_events) for slot in (0x28, 0x30, 0x38, 0x40)],
        final_import_counts=[int.from_bytes(_read_span(model, STATE+o, 4), 'little') for o in imports0.COUNT_OFFSETS],
        allocation_count=len(native_alloc), free_count=sum(e[0] == 'free' for e in native_effects),
        native_Python_return_match=True, guest_input_output_region_match=True, rank_global_memory_match=True,
        callback_state_counts_names_type_cells_and_limits_match=True,
        allocation_free_effects_and_publication_match=True, transient_descriptor_pointer_normalized=True,
        descriptor_bytes_compared_per_callback=19, native_stack_or_TLS_as_a_whole_compared=False,
        fresh_ELF_function_global_plus_synthetic_limits=spec.get('fresh_ELF_function_global_plus_synthetic_limits', False),
        actual_ELF_table_memory_import_input=False, native_input_snapshot_used=False)


def negatives(args):
    rejected = []
    valid = b'\2'+table()+memory()
    for label, options, setup in (
        ('table_memory_opt_in_disabled', dict(enable_table_memory_imports=False), None),
        ('invalid_opt_in', dict(enable_table_memory_imports=1), None),
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
        ('invalid_callback_status', dict(callback=lambda e: -1 if e.slot_offset == 0x38 else 0), None),
    ):
        pages = prepare(args, 0x122C0000, dict(blob=b'A'*8+sections.section(2, valid)))
        if setup:
            setup(pages)
        before = {key: bytes(value) for key, value in pages.items()}
        params = dict(state_address=STATE, image_base=0x122C0000, varuint_scratch_address=SCRATCH,
            callback=lambda e: 0, enable_function_global_imports=True, enable_table_memory_imports=True,
            import_scratch_address=IMPORT_SCRATCH)
        params.update(options)
        try:
            alternative.run_reader_sections(pages, **params)
        except (RefillUnsupported, ValueError):
            pass
        else:
            raise AssertionError('limits guard accepted: '+label)
        assert {key: bytes(value) for key, value in pages.items()} == before, label
        rejected.append(dict(label=label, rejected=True, all_pages_unchanged=True, native_fault_path_compared=False))
    blob = b'A'*8+sections.section(1, b'\1'+types.function_type([-1], [-2]))+sections.section(2, valid)
    pages = prepare(args, 0x122C0000, dict(blob=blob))
    before = {key: bytes(value) for key, value in pages.items()}
    try:
        alternative.run_reader_sections(pages, state_address=STATE, image_base=0x122C0000,
            varuint_scratch_address=SCRATCH, callback=lambda e: 0,
            vector_allocate=lambda size: IMPORT_SCRATCH, enable_table_memory_imports=True,
            import_scratch_address=IMPORT_SCRATCH)
    except RefillUnsupported:
        pass
    else:
        raise AssertionError('type allocation overlapped import scratch')
    assert {key: bytes(value) for key, value in pages.items()} == before
    rejected.append(dict(label='planned_type_storage_aliases_import_scratch', rejected=True,
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
    specs, cases = fixtures()+actual_compositions(args.library), []
    for base in (0x122C0000, 0x775C205000):
        for index, spec in enumerate(specs, 1):
            try:
                cases.append(compare(args, base, spec))
            except Exception as error:
                raise AssertionError('native/Python limits control failed: '+spec['label']) from error
            if index % 32 == 0:
                print('B import limits:', hex(base), index, '/', len(specs), 'passed', flush=True)
        print('B import limits:', hex(base), len(specs), 'controls passed', flush=True)
    evidence = dict(schema='vm9-alternative-reader-import-limits-fresh-v1', evidence_date='2026-10-08',
        evidence_timezone='UTC', host_trial_label='20261008', sample_sha256=sample_hash,
        matching_libc_sha256=libc_hash, native_table_helper_offset_hex='0x321844',
        native_import_function_offset_hex='0x322cf8', native_core_function_offset_hex='0x324188',
        native_Python_import_limits_controls=len(cases), rollback_negative_controls=len(rejected),
        purely_synthetic_import_controls=sum(not c['fresh_ELF_function_global_plus_synthetic_limits'] for c in cases),
        fresh_ELF_function_global_plus_synthetic_limits_controls=sum(c['fresh_ELF_function_global_plus_synthetic_limits'] for c in cases),
        actual_ELF_table_memory_import_controls=0, supported_import_kinds=[0, 1, 2, 3],
        table_memory_imports_require_explicit_opt_in_and_scratch=True, guest_input_output_bytes_compared=0xA000,
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
    print('B import limits:', len(cases), 'native/Python +', len(rejected), 'rollback controls passed')


if __name__ == '__main__':
    main()
