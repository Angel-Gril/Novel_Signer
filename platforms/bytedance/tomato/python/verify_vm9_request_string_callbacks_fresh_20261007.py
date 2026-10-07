"""Fresh request C-string equality and signed format callback differences.

Native formatting executes matching-libc vsnprintf. Allocation/reallocation
are explicit controlled effects, distinct from the same-session integration.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as arm
import vm9_configuration_init as configuration
from vm9_allocator import RefillUnsupported, _read_span, _write_span
from verify_vm9_signer_objects import GUEST, LIBRARY_SHA256, fresh_pages, image_pages, native
from verify_vm9_libc_mapping import LIBC_SHA256
from verify_vm9_shared_reference import fixture as formatter_fixture, TLS, word
from verify_vm9_strings import Effects

BASES = (0x122C0000, 0x775C205000)
OBJECT, PAYLOAD, CSTRING, FORMAT, PACKED = (GUEST + n for n in (0x1800, 0x2000, 0x3000, 0x3500, 0x3800))


def equality_case(library, image, control, wrapper):
    pages = {**image_pages(library, image), **fresh_pages()}
    payload, cstring = control['payload'], control['cstring']
    length = control.get('length', len(payload))
    pointer = 0 if control.get('null_payload') else PAYLOAD
    source = 0 if control.get('null_cstring') else CSTRING
    _write_span(pages, OBJECT, (image + 0x34F5F8).to_bytes(8, 'little') +
        (len(payload) + 1).to_bytes(4, 'little') + (length & 0xFFFFFFFF).to_bytes(4, 'little') +
        pointer.to_bytes(8, 'little'))
    _write_span(pages, PAYLOAD, payload + b'\0')
    _write_span(pages, CSTRING, cstring + b'\0')
    packed = b''.join(v.to_bytes(8, 'little') for v in (image + 0x24880C, OBJECT, source, 0xA5A5A5A5A5A5A5A5))
    _write_span(pages, PACKED, packed)
    observed = {(PACKED, 32): None}
    entry = 0x2858EC if wrapper else 0x24880C
    arguments = [PACKED] if wrapper else [OBJECT, source]
    returned, memory, allocations, services = native(library, image, entry, arguments,
        pages, observed_memory=observed)
    got = configuration.string_equals_cstring(pages, object_address=OBJECT, cstring_address=source)
    assert got == control['expected']
    if wrapper:
        _write_span(pages, PACKED + 24, bytes([int(got)]))
        assert observed[PACKED, 32] == _read_span(pages, PACKED, 32)
    else:
        assert returned == int(got)
    assert _read_span(pages, GUEST, 0xA000) == memory
    assert not allocations and not services
    return dict(image_base=hex(image), case=control['name'], wrapper_executed=wrapper,
        native_return_or_packed_boolean_matches=True, full_payload_memory_match=True,
        explicit_synthetic_inputs=True, native_input_snapshot_used=False)


def guard_case(library, libc, image, control):
    import vm9_startup
    pages = {**image_pages(library, image), **fresh_pages()}
    guard = GUEST + 0x1900
    _write_span(pages, guard, bytes([control['byte0'], control['byte1']]) + b'\x5a\xa5' + (0xA5A5A5A5).to_bytes(4, 'little'))
    _write_span(pages, image + 0x3E2F40, (control['mutex_state']).to_bytes(2, 'little'))
    _write_span(pages, PACKED, b''.join(v.to_bytes(8, 'little') for v in
        (image + 0x32D3A0, guard, 0xA5A5A5A5A5A5A5A5)))
    observed = {(guard, 8): None, (PACKED, 24): None, (image + 0x3E2F40, 40): None}
    _, payload, allocations, services = native(library, image, 0x285944, [PACKED], pages,
        libc=libc, real_mutexes=True, real_singletons=True, thread_id=137,
        observed_memory=observed, instruction_limit=10000)
    result = vm9_startup.acquire_serial_guard(pages, guard_address=guard,
        image_base=image, thread_id=137)
    assert result == control['expected']
    _write_span(pages, PACKED + 16, int(result).to_bytes(4, 'little'))
    assert _read_span(pages, GUEST, 0xA000) == payload
    for (address, width), data in observed.items():
        assert _read_span(pages, address, width) == data, hex(address)
    assert not allocations
    expected_services = [] if control['byte0'] else (
        [['pthread_mutex_lock', image + 0x3E2F40]] +
        ([['gettid', 137]] if result else []) +
        [['pthread_mutex_unlock', image + 0x3E2F40]])
    assert services == expected_services, services
    return dict(image_base=hex(image), case=control['name'], guard_wrapper_executed=True,
        matching_libc_mutex_executed=not bool(control['byte0']),
        full_payload_guard_padding_and_global_mutex_match=True,
        gettid_calls=int(result), native_input_snapshot_used=False)


def formatting_case(library, libc, image, control, exports):
    pages = formatter_fixture(library, image, libc)
    integer, string = control['integer'], control['string']
    fmt = control.get('format', b'%d|%s')
    capacity, length = control.get('capacity', 8), control.get('length', 0)
    _write_span(pages, OBJECT, (image + 0x34F5F8).to_bytes(8, 'little') +
        capacity.to_bytes(4, 'little') + length.to_bytes(4, 'little') + PAYLOAD.to_bytes(8, 'little'))
    _write_span(pages, PAYLOAD, b'z' * length + b'\0')
    _write_span(pages, CSTRING, string + b'\0')
    _write_span(pages, FORMAT, fmt + b'\0')
    _write_span(pages, PACKED, b''.join(v.to_bytes(8, 'little') for v in
        (image + 0x248908, OBJECT, FORMAT, integer, CSTRING)))
    # Each side gets the same fixture and separate allocator state.
    model_pages = {k: bytearray(v) for k, v in pages.items()}
    expected = Effects(blocks={PAYLOAD: capacity})
    actual = Effects(blocks={PAYLOAD: capacity})
    native_events, model_events, native_freed, model_freed = [], [], [], []
    observed = {(p << 12, 4096): None for p in pages if image <= p << 12 < image + 0x400000}
    for span in ((TLS, 0xB00), (0x510DE930, 16), (0x510E0200, 0x800)):
        observed[span] = None
    def malloc(cpu, size):
        native_events.append(['malloc', size])
        return expected.native(cpu, 'malloc', size)
    def free(cpu):
        pointer = cpu.reg_read(arm.UC_ARM64_REG_X0)
        native_events.append(['free', pointer])
        native_freed.append(bytes(cpu.mem_read(pointer, expected.blocks[pointer])))
        return expected.native(cpu, 'free', pointer=pointer)
    def realloc(cpu):
        pointer, size = cpu.reg_read(arm.UC_ARM64_REG_X0), cpu.reg_read(arm.UC_ARM64_REG_X1)
        native_events.append(['realloc', pointer, size])
        return expected.native(cpu, 'realloc', size, pointer)
    def vsnprintf(cpu):
        cpu.reg_write(arm.UC_ARM64_REG_PC, exports['vsnprintf'])
        return None
    def syscall(cpu, number):
        assert number == 98
        values = [cpu.reg_read(r) for r in (arm.UC_ARM64_REG_X0, arm.UC_ARM64_REG_X1, arm.UC_ARM64_REG_X2)]
        assert values[1] == 129
        native_events.append(['wake', *values])
        return 0
    returned, memory, _, _ = native(library, image, 0x285990, [PACKED], pages,
        libc=libc, malloc_handler=malloc, extra_registers={arm.UC_ARM64_REG_TPIDR_EL0: TLS},
        host_imports={0x347FA0: free, 0x348320: realloc, 0x347F70: vsnprintf},
        syscall_handler=syscall, observed_memory=observed, instruction_limit=300000)
    def amalloc(p, size):
        model_events.append(['malloc', size])
        return actual.malloc(p, size)
    def afree(p, pointer):
        model_events.append(['free', pointer])
        model_freed.append(_read_span(p, pointer, actual.blocks[pointer]))
        return actual.free(p, pointer)
    def arealloc(p, pointer, size):
        model_events.append(['realloc', pointer, size])
        return actual.realloc(p, pointer, size)
    def wake(p, address, operation, count):
        model_events.append(['wake', address, operation, count])
        return 0
    def prepare(p):
        configuration.prepare_bionic_format_locale(p, once_address=0x510DE938,
            key_address=0x510DE930, generation_table=0x510E0200, thread_pointer=TLS, wake=wake)
    result = configuration.format_string_object(model_pages, object_address=OBJECT,
        format_address=FORMAT, argument_addresses=(integer, CSTRING), image_base=image,
        allocate=amalloc, reallocate=arealloc, free=afree, prepare_format=prepare)
    # +0x248a8c calls +0x246d7c, whose successful cleanup sets W0=0.
    # The Python helper returns its destination for API use, not native X0.
    assert returned == 0 and result == OBJECT, (hex(returned), hex(result))
    got_memory = _read_span(model_pages, GUEST, 0xA000)
    assert got_memory == memory, next(((hex(i), a, b) for i, (a, b) in enumerate(zip(got_memory, memory)) if a != b), None)
    for (address, width), observed_bytes in observed.items():
        assert _read_span(model_pages, address, width) == observed_bytes, hex(address)
    assert model_events == native_events, (model_events, native_events)
    if control['name'] == 'forced_destination_realloc':
        assert sum(e[0] == 'realloc' for e in model_events) == 1
    if control['name'] == 'truncation_retry_and_growth':
        assert not any(e[0] == 'realloc' for e in model_events)
    assert actual.calls == expected.calls and actual.blocks == expected.blocks
    assert model_freed == native_freed
    final_length = int.from_bytes(_read_span(model_pages, OBJECT + 12, 4), 'little')
    final_pointer = int.from_bytes(_read_span(model_pages, OBJECT + 16, 8), 'little')
    rendered = _read_span(model_pages, final_pointer, final_length)
    assert rendered == control['expected']
    return dict(image_base=hex(image), case=control['name'], raw_integer=hex(integer),
        rendered_length=final_length, rendered_sha256=hashlib.sha256(rendered).hexdigest(),
        payload_image_and_observed_tls_generation_windows_match=True,
        payload_bytes_compared=0xA000, tls_bytes_compared=0xB00,
        generation_bytes_compared=0x800,
        ordered_allocation_free_reallocation_and_wake_match=True,
        pre_free_bytes_match=True, explicit_allocator_service_used=True,
        native_success_cleanup_status=returned, python_helper_returns_output_object=True,
        native_abi_return_and_python_helper_return_are_distinct=True,
        realloc_calls=sum(event[0] == 'realloc' for event in model_events),
        matching_libc_vsnprintf_executed=True, native_input_snapshot_used=False)


def negative_cases(library, image):
    names = []
    for label, fmt, arguments, bound in (
        ('unknown_unsigned', b'%u', (5,), 256),
        ('missing_decimal', b'%d', (), 256),
        ('incomplete', b'%', (), 256),
        ('decimal_bound', b'%d', (0x80000000,), 4),
        ('null_string', b'%d|%s', (5, 0), 256),
        ('invalid_decimal_abi_word', b'%d', (1 << 64,), 256),
    ):
        pages = {**image_pages(library, image), **fresh_pages()}
        _write_span(pages, FORMAT, fmt + b'\0')
        before = {k: bytes(v) for k, v in pages.items()}
        try:
            configuration._format_guest_strings(pages, FORMAT, arguments, bound)
        except (RefillUnsupported, ValueError):
            pass
        else:
            raise AssertionError('unsupported format accepted: ' + label)
        assert before == {k: bytes(v) for k, v in pages.items()}
        names.append(label + '_refused')
    import vm9_startup
    for label, byte1, mutex, thread_id in (
        ('recursive_guard', 2, 0, 137),
        ('waiting_guard', 6, 0, 137),
        ('missing_guard_thread', 0, 0, None),
        ('invalid_guard_thread', 0, 0, 1 << 32),
        ('contended_global_mutex', 0, 1, 137),
    ):
        pages = {**image_pages(library, image), **fresh_pages()}
        _write_span(pages, OBJECT, b'\0' + bytes([byte1]) + bytes(6))
        _write_span(pages, image + 0x3E2F40, mutex.to_bytes(2, 'little'))
        before = {k: bytes(v) for k, v in pages.items()}
        try:
            vm9_startup.acquire_serial_guard(pages, guard_address=OBJECT,
                image_base=image, thread_id=thread_id)
        except RefillUnsupported:
            pass
        else:
            raise AssertionError('unsupported guard accepted: ' + label)
        assert before == {k: bytes(v) for k, v in pages.items()}
        names.append(label + '_refused_without_page_changes')
    return names


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--library', type=Path, required=True)
    parser.add_argument('--libc', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest() == LIBC_SHA256
    with args.library.open('rb') as stream:
        elf = ELFFile(stream)
        plt, jumps = elf.get_section_by_name('.plt'), elf.get_section_by_name('.rela.plt')
        symbols = elf.get_section(jumps['sh_link'])
        import_entries = {symbols.get_symbol(r['r_info_sym']).name:
            plt['sh_addr'] + 32 + index * 16 for index, r in enumerate(jumps.iter_relocations())}
        assert import_entries['realloc'] == 0x348320 and import_entries['memcmp'] == 0x347FE0
    exports = {}
    with args.libc.open('rb') as stream:
        for section in ELFFile(stream).iter_sections():
            if section['sh_type'] == 'SHT_DYNSYM':
                exports.update({s.name: 0x51000000 + s['st_value'] for s in section.iter_symbols() if s['st_shndx'] != 'SHN_UNDEF'})
    equality, formatting, guards = [], [], []
    comparisons = [
        dict(name='empty', payload=b'', cstring=b'', expected=True),
        dict(name='equal', payload=b'seed', cstring=b'seed', expected=True),
        dict(name='prefix', payload=b'seed', cstring=b'seed-tail', expected=False),
        dict(name='early_nul', payload=b'seed-tail', cstring=b'seed', expected=False),
        dict(name='embedded_nul', payload=b'ab\0cd', cstring=b'ab\0cd', expected=False),
        dict(name='negative_length', payload=b'seed', cstring=b'seed', length=-1, expected=False),
        dict(name='null_payload', payload=b'seed', cstring=b'seed', null_payload=True, expected=False),
        dict(name='null_cstring', payload=b'seed', cstring=b'seed', null_cstring=True, expected=False),
    ]
    formats = [
        dict(name='request_minus_five', integer=0xFFFFFFFB, string=b'12345678', expected=b'-5|12345678'),
        dict(name='zero_empty', integer=0, string=b'', expected=b'0|'),
        dict(name='int32_min', integer=0x80000000, string=b'seed', expected=b'-2147483648|seed'),
        dict(name='int32_max', integer=0x7FFFFFFF, string=b'seed', expected=b'2147483647|seed'),
        dict(name='high_bits_ignored', integer=0x12345678FFFFFFFF, string=b'seed', expected=b'-1|seed'),
        dict(name='truncation_retry_and_growth', integer=0xFFFFFFFB, string=b'x'*65, capacity=8, length=7, expected=b'-5|'+b'x'*65),
        dict(name='forced_destination_realloc', integer=0xFFFFFFFB, string=b'x'*65, capacity=8, length=8, expected=b'-5|'+b'x'*65),
        dict(name='escaped_percent', integer=0xFFFFFFFF, string=b'ignored', format=b'%%:%d', expected=b'%:-1'),
    ]
    guard_controls = [
        dict(name='cold', byte0=0, byte1=0, mutex_state=0, expected=True),
        dict(name='completed_byte0', byte0=1, byte1=0, mutex_state=0, expected=False),
        dict(name='completed_byte1', byte0=0, byte1=1, mutex_state=0x2000, expected=False),
        dict(name='nonzero_byte0', byte0=2, byte1=2, mutex_state=0, expected=False),
        dict(name='cold_shared_mutex', byte0=0, byte1=0, mutex_state=0x2000, expected=True),
    ]
    for image in BASES:
        for control in comparisons:
            for wrapper in (False, True):
                equality.append(equality_case(args.library, image, control, wrapper))
                print('cstring equality', hex(image), control['name'], 'wrapper' if wrapper else 'target', 'PASS', flush=True)
        for control in formats:
            formatting.append(formatting_case(args.library, args.libc, image, control, exports))
            print('signed formatter', hex(image), control['name'], 'PASS', flush=True)
        for control in guard_controls:
            guards.append(guard_case(args.library, args.libc, image, control))
            print('serial guard', hex(image), control['name'], 'PASS', flush=True)
    negative = negative_cases(args.library, BASES[0])
    report = dict(schema='vm9-request-string-callbacks-fresh-differential-v1', evidence_date='2026-10-07',
        sample_sha256=LIBRARY_SHA256, libc_sha256=LIBC_SHA256,
        equality_controls=len(equality), equality_cases=equality,
        guard_controls=len(guards), guard_cases=guards,
        formatting_controls=len(formatting), formatting_cases=formatting, negative_cases=negative,
        callback_wrappers_native_differential_verified=True,
        signed_int32_formatting_verified=True, matching_libc_realloc_implemented=False,
        component_realloc_plt_offset='0x348320', component_realloc_import_verified_from_elf=True,
        forced_realloc_controls=sum(c['case'] == 'forced_destination_realloc' for c in formatting),
        negative_controls=len(negative),
        complete_python_medusa=False, fresh_input_signer_output_verified=False,
        current_online_header_matrix_verified=False, no_jvm_rust_signer_complete=False,
        limitations=['Synthetic component fixtures use explicit malloc/realloc/free services; matching-libc vsnprintf itself executes natively.',
            'Only %d, %s and %% are supported. Width, precision, unsigned and other conversions fail closed.',
            'Component callback agreement does not prove the whole outer request branch, JNI conversion or signer output.'])
    args.output.write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    print('request callbacks', len(equality), 'equality +', len(formatting), 'format +', len(guards), 'guard +', len(negative), 'negative PASS')


if __name__ == '__main__':
    main()
