"""Verify the live callback-scoped JNI string flow and its AArch64 callsites."""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
from elftools.elf.elffile import ELFFile


NAME = 'vm9_android_jni_request_string_flow_20261104'
EXPECTED_LIBRARY_SHA256 = '712384bd0e310fded0ae9b6441c2a264dd356dfaf1ef42d2ebc3c790fdd9269c'
EXPECTED_CAPTURE_SHA256 = 'bfaf7d3f08b5231f9e10d28edafdd72e742f1134eca3622501a2724992a0237e'
EXPECTED_GET_LENGTHS = Counter({
    1: 2, 5: 1, 7: 9, 9: 7, 10: 3, 11: 1, 16: 2, 20: 1, 25: 2, 31: 1,
    42: 2, 43: 2, 45: 6, 52: 1, 54: 5, 56: 1, 59: 1, 70: 2, 87: 1,
    89: 1, 95: 1,
})


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_static(library: Path) -> int:
    require(sha256(library) == EXPECTED_LIBRARY_SHA256, 'native library hash')
    with library.open('rb') as stream:
        elf = ELFFile(stream)
        require(elf['e_ident']['EI_CLASS'] == 'ELFCLASS64', 'ELF class')
        require(elf['e_machine'] == 'EM_AARCH64' and elf['e_type'] == 'ET_DYN',
                'ELF target')
        section = elf.get_section_by_name('.text')
        require(section is not None, 'missing .text')
        data = section.data()
        base = int(section['sh_addr'])
        decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

        def decode(start: int, end: int) -> dict[int, tuple[str, str]]:
            offset = start - base
            limit = end - base
            require(offset >= 0 and limit <= len(data) and offset < limit,
                    f'instruction range {start:#x}..{end:#x}')
            return {ins.address: (ins.mnemonic, ins.op_str)
                    for ins in decoder.disasm(data[offset:limit], start)}

        ins = {}
        for start, end in ((0x1a1d84, 0x1a1df8), (0x1a1e24, 0x1a1ed0), (0x1a1ef0, 0x1a1f04),
                           (0x1676dc, 0x1676fc), (0x26f6e0, 0x26f860),
                           (0x26f888, 0x26f8a0), (0x26f948, 0x26f964)):
            ins.update(decode(start, end))

        callee = decode(0x248908, 0x248ac8)
        require(len(callee) == (0x248ac8 - 0x248908) // 4, 'complete callee decode')
        ins.update(callee)
        plt = elf.get_section_by_name('.plt')
        require(plt is not None, 'missing .plt')
        offset = 0x347f70 - int(plt['sh_addr'])
        require(0 <= offset <= len(plt.data()) - 16, 'formatter PLT bounds')
        ins.update({i.address: (i.mnemonic, i.op_str)
                    for i in decoder.disasm(plt.data()[offset:offset + 16], 0x347f70)})
        relocations = elf.get_section_by_name('.rela.plt')
        require(relocations is not None, 'missing .rela.plt')
        symbols = elf.get_section(relocations['sh_link'])
        imports = [(r['r_info_type'], symbols.get_symbol(r['r_info_sym']).name)
                   for r in relocations.iter_relocations() if r['r_offset'] == 0x375248]
        require(imports == [(1026, 'vsnprintf')], 'formatter GOT relocation')

    expected = {
        0x1a1d84: ('mov', 'x0, x20'),
        0x1a1d88: ('mov', 'x1, x21'),
        0x1a1d8c: ('mov', 'x2, x27'),
        0x1a1d90: ('ldur', 'x3, [x29, #-0x50]'),
        0x1a1d94: ('ldur', 'x4, [x29, #-0x40]'),
        0x1a1d98: ('bl', '#0x26f650'),
        0x1a1da0: ('stur', 'x0, [x29, #-0x48]'),
        0x1a1dd4: ('mov', 'x0, x20'),
        0x1a1dd8: ('mov', 'x1, x21'),
        0x1a1ddc: ('mov', 'x2, x27'),
        0x1a1de0: ('ldur', 'x3, [x29, #-0x60]'),
        0x1a1de4: ('ldur', 'x4, [x29, #-0x40]'),
        0x1a1de8: ('bl', '#0x26f650'),
        0x1a1df0: ('stur', 'x0, [x29, #-0x58]'),
        0x26f728: ('ldurb', 'w8, [x27, #-1]'),
        0x26f738: ('add', 'x27, x27, #1'),
        0x26f800: ('cbz', 'x24, #0x26f788'),
        0x26f808: ('mov', 'x0, x20'),
        0x26f80c: ('mov', 'x1, x22'),
        0x26f810: ('ldr', 'x8, [x8, #0xf8]'),
        0x26f814: ('blr', 'x8'),
        0x26f838: ('ldr', 'x8, [x20]'),
        0x26f83c: ('mov', 'x0, x20'),
        0x26f840: ('mov', 'x1, x21'),
        0x26f844: ('mov', 'x2, x25'),
        0x26f848: ('mov', 'x3, x24'),
        0x26f84c: ('ldr', 'x8, [x8, #0x108]'),
        0x26f850: ('blr', 'x8'),
        0x26f888: ('ldr', 'x8, [x20]'),
        0x26f890: ('ldr', 'x8, [x8, #0x118]'),
        0x26f948: ('add', 'x3, sp, #0x10'),
        0x26f94c: ('mov', 'x0, x20'),
        0x26f950: ('mov', 'x1, x22'),
        0x26f958: ('blr', 'x8'),
        0x26f960: ('str', 'x0, [sp, #8]'),
        0x1a1e24: ('ldr', 'x8, [x8, #0x548]'),
        0x1a1e2c: ('blr', 'x8'),
        0x1a1e34: ('str', 'x0, [x22, #0x10]'),
        0x1a1e48: ('ldr', 'x8, [x8, #0x548]'),
        0x1a1e50: ('blr', 'x8'),
        0x1a1e5c: ('str', 'x0, [x23, #0x10]'),
        0x1a1eb4: ('ldr', 'x2, [x22, #0x10]'),
        0x1a1ebc: ('ldr', 'x3, [x23, #0x10]'),
        0x1a1ec4: ('bl', '#0x248908'),
        0x1a1ef4: ('bl', '#0x1676dc'),
        0x1a1efc: ('bl', '#0x1676dc'),
        0x248930: ('stp', 'x3, x4, [x29, #-0x38]'),
        0x248938: ('stur', 'x2, [x29, #-0x40]'),
        0x248990: ('sub', 'x25, sp, #0x20'),
        0x248994: ('mov', 'sp, x25'),
        0x248998: ('sub', 'x22, sp, #0x20'),
        0x2489d0: ('mov', 'x26, #-0x30'),
        0x2489d4: ('sub', 'x10, x29, #0xc0'),
        0x2489dc: ('sub', 'x8, x29, #0x40'),
        0x2489e0: ('movk', 'x26, #0xff80, lsl #32'),
        0x2489e4: ('add', 'x27, x10, #0x80'),
        0x2489e8: ('add', 'x19, x8, #0x30'),
        0x2489ec: ('add', 'x24, x29, #0x60'),
        0x248a00: ('stp', 'x27, x26, [x25, #0x10]'),
        0x248a08: ('stp', 'x24, x19, [x25]'),
        0x248a10: ('ldp', 'q1, q0, [x25]'),
        0x248a14: ('mov', 'x2, x20'),
        0x248a18: ('mov', 'x3, x22'),
        0x248a20: ('stp', 'q1, q0, [x22]'),
        0x248a24: ('bl', '#0x347f70'),
        0x347f70: ('adrp', 'x16, #0x375000'),
        0x347f74: ('ldr', 'x17, [x16, #0x248]'),
        0x347f78: ('add', 'x16, x16, #0x248'),
        0x347f7c: ('br', 'x17'),
        0x1676dc: ('ldr', 'x2, [x0, #0x10]'),
        0x1676e4: ('ldp', 'x8, x1, [x0]'),
        0x1676f0: ('ldr', 'x3, [x9, #0x550]'),
        0x1676f4: ('br', 'x3'),
    }
    for address, instruction in expected.items():
        actual = ins.get(address)
        require(actual == instruction,
                f'instruction mismatch at {address:#x}: {actual!r}')
    require(0x1a1e30 == 0x1a1e2c + 4 and 0x1a1e54 == 0x1a1e50 + 4,
            'GetStringUTFChars return PC relation')
    require(0x1a1ef8 == 0x1a1ef4 + 4 and 0x1a1f00 == 0x1a1efc + 4,
            'release-wrapper return PC relation')
    require(not any('#-0x40' in op_str or '#-0x38' in op_str
                    for mnemonic, op_str in callee.values()
                    if mnemonic in {'ldr', 'ldur', 'ldp', 'ldnp'}),
            'callee unexpectedly reloads saved JNI argument slots')
    return len(expected)


def verify_capture(path: Path) -> int:
    raw = path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == EXPECTED_CAPTURE_SHA256,
            'sanitized capture hash')
    rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
    require(len(rows) == 471, 'capture row count')
    require(rows[-1].get('event') == 'utf_summary'
            and rows[-1].get('reason') == 'host_finish', 'capture terminal summary')

    enter = next(row for row in rows if row.get('capture_sequence') == 99)
    leave = next(row for row in rows if row.get('capture_sequence') == 400)
    require(enter.get('event') == 'business_scope_enter' and enter.get('depth') == 1,
            'business callback entry')
    require(leave.get('event') == 'business_scope_leave' and leave.get('depth') == 0,
            'business callback exit')
    require(enter.get('thread_id') == leave.get('thread_id'), 'callback thread scope')
    require(enter.get('input_entry_count') == 12, 'callback Map cardinality')

    gets = [row for row in rows if row.get('event') == 'guest_jni_string_observed'
            and row.get('active_security_factor_depth') == 1
            and enter['capture_sequence'] < row.get('capture_sequence', 0)
            < leave['capture_sequence']]
    releases = [row for row in rows if row.get('event') == 'business_scoped_jni_string_api'
                and row.get('thread_id') == enter['thread_id']
                and enter['capture_sequence'] < row.get('capture_sequence', 0)
                < leave['capture_sequence']]
    require(len(gets) == 52, 'callback-scoped GetStringUTFChars observations')
    require(Counter(row.get('length') for row in gets) == EXPECTED_GET_LENGTHS,
            'callback-scoped string length distribution')
    get_pcs = Counter(candidate.get('guest_offset')
                      for row in gets for candidate in row.get('caller_candidates', [])
                      if candidate.get('field') == 'guest_x30')
    require(get_pcs == Counter({'+0x1a1e30': 26, '+0x1a1e54': 26}),
            'GetStringUTFChars return PCs')
    get_ids = Counter(row.get('jstring_id') for row in gets)
    require(None not in get_ids and len(get_ids) == 52
            and all(count == 1 for count in get_ids.values()),
            'unique temporary getter IDs')

    require(len(releases) == 192, 'callback-scoped ReleaseStringUTFChars count')
    require(all(row.get('callback_depth') == 1 for row in releases),
            'release callback depth')
    require(all(row.get('slots') == [
        {'name': 'ReleaseStringUTFChars', 'table_offset': '0x550'}
    ] for row in releases), 'release JNI table slot')
    release_pcs = Counter(candidate.get('guest_offset')
                          for row in releases
                          for candidate in row.get('guest_register_candidates', [])
                          if candidate.get('field') == 'guest_x30')
    require(release_pcs == Counter({'+0x1a1ef8': 96, '+0x1a1f00': 96}),
            'release wrapper return PCs')
    release_ids = Counter(row.get('jstring_id') for row in releases)
    require(all(release_ids[jstring_id] == 1 for jstring_id in get_ids),
            'each captured getter has one matching release ID')
    require(all(row.get('input_object_match', {}).get('role') == 'other'
                for row in gets + releases), 'recorded object comparison outcomes')
    return len(rows)


def verify(data: dict, capture: Path | None = None,
           library: Path | None = None) -> dict:
    require(data.get('schema') == 'vm9-android-jni-request-string-flow-20261104-v1',
            'schema')
    require(data.get('evidence_date') == '2026-11-04', 'date')
    require(data.get('sample_scope') == 'one_live_r4_callback_during_reader_request',
            'sample scope')
    artifacts = data['artifacts']
    require(artifacts['sanitized_capture_sha256'] == EXPECTED_CAPTURE_SHA256,
            'capture digest')
    require(artifacts['native_library_sha256'] == EXPECTED_LIBRARY_SHA256,
            'native library digest')
    require(artifacts.get('capture_runner_sha256') is None
            and artifacts.get('capture_runner_sha256_status') ==
            'unavailable_for_original_retry2_capture; the retained runner is a later self-check revision',
            'capture runner provenance')
    require(artifacts['raw_strings_and_runtime_pointers_retained'] is False,
            'privacy metadata')

    capture_meta = data['capture']
    require(capture_meta['row_count'] == 471
            and capture_meta['terminal_reason'] == 'host_finish', 'capture summary')
    scope = capture_meta['callback_scope']
    require(scope == {'enter_sequence': 99, 'leave_sequence': 400,
                      'map_entry_count': 12, 'depth': 1}, 'callback scope metadata')

    jni = data['jni_observation']
    require(jni['get_return_pc_counts'] == {'0x1a1e30': 26, '0x1a1e54': 26},
            'getter distribution')
    require(capture_meta['captured_getstringutfchars_returns_in_scope'] == 52
            and jni['get_release_temporary_id_joins'] == 52, 'getter/release joins')
    require(capture_meta['captured_release_string_utf_chars_in_scope'] == 192
            and jni['release_return_pc_counts'] == {'0x1a1ef8': 96, '0x1a1f00': 96},
            'release distribution')
    require(jni['same_object_self_check_in_capture_runner'] is False
            and jni['get_calls_same_object_comparison_positive_matches'] == 0,
            'object comparison scope')
    require(data['static_dataflow'] == {
        'jni_get_return_0x1a1e30_stored_at': '[x22,#0x10]',
        'jni_get_return_0x1a1e54_stored_at': '[x23,#0x10]',
        'jni_first_jstring_source_helper_offset': '0x26f650',
        'jni_second_jstring_source_helper_offset': '0x26f650',
        'jni_first_jstring_return_stored_at': '[x29,#-0x48]',
        'jni_second_jstring_return_stored_at': '[x29,#-0x58]',
        'jni_first_get_argument_source': '[x29,#-0x48]',
        'jni_second_get_argument_source': '[x29,#-0x58]',
        'jni_string_source_helper_semantics_verified': False,
        'jni_source_helper_object_class_table_offset': '0xf8',
        'jni_source_helper_method_id_table_offset': '0x108',
        'jni_source_helper_object_call_v_table_offset': '0x118',
        'jni_source_helper_signature_return_scan': "after ')'",
        'jni_source_helper_object_return_branch_verified': True,
        'jni_string_source_helper_java_method_invocation_verified': True,
        'callee_call_offset': '0x1a1ec4',
        'callee_target_offset': '0x248908',
        'callee_x2_source': '[x22,#0x10]',
        'callee_x3_source': '[x23,#0x10]',
        'callee_x2_saved_at': '[x29,#-0x40]',
        'callee_x3_saved_at': '[x29,#-0x38]',
        'callee_saved_jni_argument_reload_count': 0,
        'callee_va_list_pointer_register': 'x22',
        'callee_va_list_gr_top_fp_offset': -16,
        'callee_va_list_gr_offs': -48,
        'callee_va_list_vr_top_fp_offset': -64,
        'callee_va_list_vr_offs': -128,
        'callee_va_list_gp_argument_slot_fp_offsets': [-64, -56],
        'callee_va_list_materialized_at': '0x248a20',
        'callee_formatter_call_offset': '0x248a24',
        'callee_formatter_plt_offset': '0x347f70',
        'callee_formatter_got_symbol': 'vsnprintf',
        'callee_saved_jni_arguments_indirectly_reachable_via_va_list': True,
        'release_wrapper_target_offset': '0x1676dc',
        'release_helper_jni_table_byte_offset': '0x550',
    }, 'static dataflow metadata')
    require(data['conclusions'] == {
        'guest_jni_get_and_release_observed_inside_business_callback': True,
        'captured_get_release_handle_ids_joined': True,
        'jni_return_buffers_statically_passed_as_native_arguments': True,
        'callee_semantics_fully_identified': False,
        'callee_use_of_jni_return_buffers_verified': False,
        'callee_saved_jni_arguments_indirectly_reachable_via_va_list': True,
        'callee_directly_reads_saved_jni_arguments': False,
        'callback_url_or_input_map_object_identity_joined': False,
        'jni_string_source_helper_java_method_invocation_verified': True,
        'jni_string_provider_method_identity_joined': False,
        'returned_buffer_bytes_joined_to_parser_input': False,
        'complete_standalone_signer_verified': False,
        'whole_request_native_python_differential_verified': False,
        'online_header_acceptance_verified': False,
    }, 'conclusions')

    static_instructions = verify_static(library) if library is not None else None
    capture_rows = verify_capture(capture) if capture is not None else None
    return {'static_instructions_verified': static_instructions,
            'capture_rows_verified': capture_rows,
            'callback_scoped_get_release_ids_joined': True,
            'jni_buffers_passed_as_native_arguments': True,
            'callee_use_of_jni_return_buffers_verified': False,
            'callee_directly_reads_saved_jni_arguments': False,
            'callee_saved_jni_arguments_indirectly_reachable_via_va_list': True,
            'input_map_identity_joined': False,
            'jni_string_source_helper_java_method_invocation_verified': True,
            'jni_string_provider_method_identity_joined': False,
            'complete_signer_verified': False}


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path,
                        default=root / 'evidence' / f'{NAME}.json')
    parser.add_argument('--capture', type=Path)
    parser.add_argument('--library', type=Path)
    args = parser.parse_args()
    data = json.loads(args.evidence.read_text(encoding='utf-8'))
    print(json.dumps(verify(data, capture=args.capture, library=args.library),
                     sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
