"""Execute the formatter's saved X2/X3 path with synthetic strings and bionic.

This component oracle establishes va_list addressing and actual libc reads.
It does not identify the strings observed in the Android business callback.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as arm

import vm9_configuration_init as model
from vm9_allocator import _read_span, _write_span
from verify_vm9_libc_mapping import LIBC_SHA256
from verify_vm9_shared_reference import TLS, fixture
from verify_vm9_signer_objects import GUEST, LIBRARY_SHA256, native
from verify_vm9_strings import Effects

BASES = (0x122C0000, 0x775C205000)
OBJECT, PAYLOAD, LEFT, RIGHT, FORMAT = (GUEST + n for n in
                                      (0x1800, 0x2000, 0x3000, 0x3200, 0x3500))
CASES = (
    ('two_strings', b'%s|%s', b'alpha', b'beta', b'alpha|beta', 2),
    ('left_changed', b'%s|%s', b'gamma', b'beta', b'gamma|beta', 2),
    ('right_changed', b'%s|%s', b'alpha', b'delta', b'alpha|delta', 2),
    ('swapped', b'%s|%s', b'beta', b'alpha', b'beta|alpha', 2),
    ('growth', b'%s|%s', b'a' * 65, b'b' * 70, b'a' * 65 + b'|' + b'b' * 70, 2),
    ('empty_left', b'%s|%s', b'', b'beta', b'|beta', 2),
    ('one_argument_control', b'%s', b'alpha', b'beta', b'alpha', 1),
    ('literal_control', b'literal%%', b'alpha', b'beta', b'literal%', 0),
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def run_case(library, libc, image, control, export):
    name, fmt, left, right, rendered, consumed = control
    pages = fixture(library, image, libc)
    _write_span(pages, OBJECT, struct.pack('<QIIQ', image + 0x34F5F8, 8, 0, PAYLOAD))
    for address, value in ((PAYLOAD, b''), (LEFT, left), (RIGHT, right), (FORMAT, fmt)):
        _write_span(pages, address, value + b'\0')
    model_pages = {k: bytearray(v) for k, v in pages.items()}
    native_effects = Effects(blocks={PAYLOAD: 8})
    model_effects = Effects(blocks={PAYLOAD: 8})
    observed = {(p << 12, 4096): None for p in pages if image <= p << 12 < image + 0x400000}
    observed.update({span: None for span in ((TLS, 0xB00), (0x510DE930, 16), (0x510E0200, 0x800))})
    descriptors, reads, native_events, model_events = [], [], [], []
    active = None
    libc_end = 0x51000000 + libc.stat().st_size

    def vsnprintf(cpu):
        nonlocal active
        fp = cpu.reg_read(arm.UC_ARM64_REG_X29)
        pointer = cpu.reg_read(arm.UC_ARM64_REG_X3)
        raw = bytes(cpu.mem_read(pointer, 32))
        stack, gr_top, vr_top, gr_offs, vr_offs = struct.unpack('<QQQii', raw)
        require((stack - fp, gr_top - fp, vr_top - fp, gr_offs, vr_offs)
                == (0x60, -0x10, -0x40, -0x30, -0x80), 'va_list fields')
        require(pointer == fp - 0x110, 'copied va_list address')
        require(bytes(cpu.mem_read(fp - 0xf0, 32)) == raw, 'va_copy contents')
        require(cpu.reg_read(arm.UC_ARM64_REG_X30) == image + 0x248a28,
                'formatter return address')
        require(cpu.reg_read(arm.UC_ARM64_REG_X2) == FORMAT, 'format argument')
        slots = (gr_top + gr_offs, gr_top + gr_offs + 8)
        require(slots == (fp - 0x40, fp - 0x38), 'saved X2/X3 addresses')
        require(tuple(int.from_bytes(cpu.mem_read(a, 8), 'little') for a in slots)
                == (LEFT, RIGHT), 'original X2/X3 pointers survive to libc')
        descriptors.append({'gr_top_fp_offset': -16, 'gr_offs': -48,
                            'argument_slot_fp_offsets': [-64, -56]})
        active = {'slots': slots, 'slot_reads': set(), 'buffer_reads': set()}
        reads.append(active)
        native_events.append(('format',))
        cpu.reg_write(arm.UC_ARM64_REG_PC, export)
        return None

    def on_read(cpu, address, size):
        if active is None or not 0x51000000 <= cpu.reg_read(arm.UC_ARM64_REG_PC) < libc_end:
            return
        for index, slot in enumerate(active['slots']):
            if address < slot + 8 and slot < address + size:
                active['slot_reads'].add(index)
        for index, (start, value) in enumerate(((LEFT, left), (RIGHT, right))):
            if address < start + len(value) + 1 and start < address + size:
                active['buffer_reads'].add(index)

    def malloc(cpu, size):
        native_events.append(('malloc', size))
        return native_effects.native(cpu, 'malloc', size)

    def free(cpu):
        address = cpu.reg_read(arm.UC_ARM64_REG_X0)
        native_events.append(('free', address))
        return native_effects.native(cpu, 'free', pointer=address)

    def realloc(cpu):
        address, size = (cpu.reg_read(r) for r in (arm.UC_ARM64_REG_X0, arm.UC_ARM64_REG_X1))
        native_events.append(('realloc', address, size))
        return native_effects.native(cpu, 'realloc', size, address)

    def syscall(cpu, number):
        values = tuple(cpu.reg_read(r) for r in
                       (arm.UC_ARM64_REG_X0, arm.UC_ARM64_REG_X1, arm.UC_ARM64_REG_X2))
        require(number == 98 and values[1] == 129, 'bounded locale futex wake')
        native_events.append(('wake', *values))
        return 0

    result, memory, _, _ = native(
        library, image, 0x248908, [OBJECT, FORMAT, LEFT, RIGHT], pages, libc=libc,
        extra_registers={arm.UC_ARM64_REG_TPIDR_EL0: TLS},
        malloc_handler=malloc, host_imports={0x347FA0: free, 0x348320: realloc, 0x347F70: vsnprintf},
        syscall_handler=syscall, memory_read_observer=on_read,
        observed_memory=observed, instruction_limit=300000)

    def allocate(pages, size):
        model_events.append(('malloc', size))
        return model_effects.malloc(pages, size)

    def release(pages, address):
        model_events.append(('free', address))
        return model_effects.free(pages, address)

    def reallocate(pages, address, size):
        model_events.append(('realloc', address, size))
        return model_effects.realloc(pages, address, size)

    def wake(pages, address, operation, count):
        model_events.append(('wake', address, operation, count))
        return 0

    def prepare(pages):
        model_events.append(('format',))
        model.prepare_bionic_format_locale(pages, once_address=0x510DE938,
            key_address=0x510DE930, generation_table=0x510E0200, thread_pointer=TLS, wake=wake)

    model.format_string_object(model_pages, object_address=OBJECT, format_address=FORMAT,
        argument_addresses=(LEFT, RIGHT), image_base=image, allocate=allocate,
        reallocate=reallocate, free=release, prepare_format=prepare)
    require(result == 0, 'native cleanup status')
    require(_read_span(model_pages, GUEST, 0xA000) == memory, 'complete guest payload')
    require(all(value == _read_span(model_pages, address, width)
                for (address, width), value in observed.items()), 'image/TLS/locale memory')
    require(native_effects.calls == model_effects.calls
            and native_effects.blocks == model_effects.blocks, 'allocator state')
    require(native_events == model_events, 'ordered effects')
    length = int.from_bytes(_read_span(model_pages, OBJECT + 12, 4), 'little')
    pointer = int.from_bytes(_read_span(model_pages, OBJECT + 16, 8), 'little')
    require(_read_span(model_pages, pointer, length) == rendered, 'independent expected output')
    require(bool(reads), 'vsnprintf reached')
    require(all(row['slot_reads'] == set(range(consumed)) for row in reads),
            'libc reads exactly the consumed saved GP argument slots')
    require(set.union(*(row['buffer_reads'] for row in reads)) == set(range(consumed)),
            'libc dereferences the expected string buffers')
    require(len(reads) >= 2 if name == 'growth' else len(reads) == 1, 'retry control')
    return {'case': name, 'image_base': hex(image), 'vsnprintf_calls': len(reads),
            'saved_gp_slots_read_by_libc': sorted(set.union(*(r['slot_reads'] for r in reads))),
            'string_buffers_read_by_libc': sorted(set.union(*(r['buffer_reads'] for r in reads))),
            'va_list_layout_verified': True, 'native_python_memory_and_effects_equal': True,
            'expected_output_matches': True}


def run(library, libc):
    require(hashlib.sha256(library.read_bytes()).hexdigest() == LIBRARY_SHA256, 'library hash')
    require(hashlib.sha256(libc.read_bytes()).hexdigest() == LIBC_SHA256, 'libc hash')
    with libc.open('rb') as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name('.dynsym')
        export = next(0x51000000 + s['st_value'] for s in symbols.iter_symbols()
                      if s.name == 'vsnprintf' and s['st_shndx'] != 'SHN_UNDEF')
    cases = [run_case(library, libc, image, control, export)
             for image in BASES for control in CASES]
    return {'schema': 'vm9-jni-formatter-varargs-20261104-v1', 'evidence_date': '2026-11-04',
            'sample_sha256': LIBRARY_SHA256, 'libc_sha256': LIBC_SHA256,
            'scope': 'fresh_synthetic_component_inputs_with_explicit_allocator_services',
            'native_python_controls': len(cases), 'cases': cases,
            'saved_x2_x3_reachable_through_va_list': True,
            'synthetic_string_buffers_consumed_by_matching_libc': True,
            'android_captured_buffer_consumption_verified': False,
            'android_input_map_identity_joined': False, 'complete_signer_verified': False,
            'online_header_acceptance_verified': False}


def verify_record(path: Path) -> dict:
    report = json.loads(path.read_text(encoding='utf-8'))
    require(report['schema'] == 'vm9-jni-formatter-varargs-20261104-v1', 'evidence schema')
    require(report['native_python_controls'] == 16, 'evidence control count')
    require(report['saved_x2_x3_reachable_through_va_list'] is True,
            'evidence va_list relation')
    require(report['synthetic_string_buffers_consumed_by_matching_libc'] is True,
            'evidence libc consumption')
    require(report['android_captured_buffer_consumption_verified'] is False,
            'evidence Android scope')
    return {key: report[key] for key in (
        'schema', 'native_python_controls', 'saved_x2_x3_reachable_through_va_list',
        'synthetic_string_buffers_consumed_by_matching_libc',
        'android_captured_buffer_consumption_verified', 'complete_signer_verified')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library', type=Path)
    parser.add_argument('--libc', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--evidence', type=Path,
                        default=Path(__file__).resolve().parents[1] /
                        'evidence' / 'vm9_jni_formatter_varargs_20261104.json')
    args = parser.parse_args()
    if args.library is None and args.libc is None:
        print(json.dumps(verify_record(args.evidence), sort_keys=True))
        return
    require(args.library is not None and args.libc is not None,
            'library and libc must be supplied together')
    report = run(args.library, args.libc)
    if args.output:
        args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({key: value for key, value in report.items() if key != 'cases'}, sort_keys=True))


if __name__ == '__main__':
    main()
