"""Verify the redacted JNI string-call observations and their ELF callsites."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
from elftools.elf.elffile import ELFFile

NAME = 'vm9_framesign_jni_string_calls_20261104'
CALLS = {
    '0x1a1e30': 22,
    '0x1a1e54': 22,
    '0x28b9ec': 2,
    '0x28ba08': 2,
}
HEX_256 = re.compile(r'^[0-9a-f]{64}$')


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_elf(path: Path, expected_digest: str, rows: list[dict]) -> int:
    require(digest(path) == expected_digest, 'local native library hash')
    with path.open('rb') as stream:
        elf = ELFFile(stream)
        require(elf['e_ident']['EI_CLASS'] == 'ELFCLASS64', 'ELF class')
        require(elf['e_machine'] == 'EM_AARCH64' and elf['e_type'] == 'ET_DYN', 'ELF target')
        section = elf.get_section_by_name('.text')
        require(section is not None, 'missing .text')
        data = section.data()
        section_start = int(section['sh_addr'])
        decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        verified = 0
        for row in rows:
            load = int(row['jni_table_load_offset'], 16)
            call = int(row['indirect_call_offset'], 16)
            ret = int(row['caller_return_offset'], 16)
            require(ret == call + 4, 'caller return relation')
            require(row['jni_table_byte_offset'] == '0x548', 'JNI table offset')
            start = load - section_start
            end = call + 8 - section_start
            require(start >= 0 and end <= len(data), 'callsite outside .text')
            code = data[start:end]
            instructions = {int(ins.address): ins for ins in decoder.disasm(code, load)}
            load_insn = instructions.get(load)
            call_insn = instructions.get(call)
            require(load_insn is not None and load_insn.mnemonic == 'ldr'
                    and load_insn.op_str == 'x8, [x8, #0x548]', 'JNI table load instruction')
            require(call_insn is not None and call_insn.mnemonic == 'blr'
                    and call_insn.op_str == 'x8', 'JNI indirect call instruction')
            verified += 1
    return verified


def verify(data: dict, probe_dir: Path | None = None, library: Path | None = None) -> dict:
    require(data.get('schema') == 'vm9-framesign-jni-string-calls-20261104-v1', 'schema')
    require(data.get('evidence_date') == '2026-11-04', 'date')
    require(data.get('sample_scope') == 'single_fixed_synthetic_jni_initializer_call', 'scope')
    probe = data['probe']
    require(probe['id'] == 'configuration_initializer_copy_provider_probe19_run8', 'probe identity')
    for key in ('source_sha256', 'entry_class_sha256', 'runner_sha256', 'sanitized_log_sha256',
                'metadata_sha256', 'native_library_sha256'):
        require(bool(HEX_256.fullmatch(probe[key])), key)
    require(probe['process_exit_code'] == 0 and probe['signature_result_length'] == 10
            and probe['read_only_guest_observation'] is True, 'probe result')

    api = data['api_observation']
    require(api['api'] == 'GetStringUtfChars' and api['call_count'] == 48, 'API count')
    require(api['caller_offsets_relative_to_main_image'] == CALLS, 'caller distribution')
    require(api['raw_api_lines_retained'] is False and api['raw_arguments_retained'] is False
            and api['runtime_pointers_retained'] is False, 'redaction')

    rows = data['static_callsite_checks']
    require(len(rows) == 4, 'static callsite count')
    require({row['caller_return_offset']: row['count'] for row in rows} == CALLS,
            'static callsite counts')
    require(data['conclusions'] == {
        'verbose_api_calls_observed': True,
        'caller_offsets_match_getstring_utf_chars_table_slot': True,
        'original_initializer_object_identity_joined': False,
        'returned_buffer_bytes_joined': False,
        'original_android_provider_joined': False,
        'copy_source_joined': False,
        'complete_signer_verified': False,
        'ordinary_cronet_header_chain_verified': False,
        'online_header_acceptance_verified': False,
    }, 'conclusions')

    if probe_dir is not None:
        source = probe_dir / 'HookMain.java'
        entry = probe_dir / 'classes' / 'HookMain.class'
        runner = probe_dir / 'run_buffer_probe.py'
        run_dir = probe_dir / 'run8'
        log_path = run_dir / 'sanitized.log'
        meta_path = run_dir / 'metadata.json'
        for path, key in ((source, 'source_sha256'), (entry, 'entry_class_sha256'),
                          (runner, 'runner_sha256'), (log_path, 'sanitized_log_sha256'),
                          (meta_path, 'metadata_sha256')):
            require(digest(path) == probe[key], 'local ' + key)
        meta = json.loads(meta_path.read_text(encoding='utf-8'))
        require(meta['process_exit_code'] == 0 and meta['read_only_guest_probe'] is True
                and meta['raw_values_retained'] is False and meta['main_module_base_seen'] is True,
                'local terminal/privacy')
        require(meta['native_library_sha256'] == probe['native_library_sha256'], 'local native library')
        require(meta['jni_string_api_calls'] == {'GetStringUtfChars': 48}, 'local API count')
        local_callers = meta['jni_string_api_callers'].get('GetStringUtfChars', {})
        require({key.lstrip('+'): value for key, value in local_callers.items()} == CALLS,
                'local callsites')
        log = log_path.read_text(encoding='utf-8-sig')
        require('[HookMain] FRAME_SIGN_RESULT_LENGTH=10' in log, 'local signature result')
        require('JNIEnv->' not in log and not re.search(r'0x[0-9a-fA-F]{8,}', log),
                'sanitized log contains raw calls or pointers')

    verified_sites = verify_elf(library, probe['native_library_sha256'], rows) if library else 0
    return {'api_calls_verified': 48, 'caller_sites_verified': 4,
            'elf_instructions_verified': verified_sites,
            'provider_joined': False, 'complete_signer_verified': False,
            'online_acceptance_verified': False,
            'local_probe_verified': probe_dir is not None}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, default=Path(__file__).resolve().parents[1] /
                        'evidence' / (NAME + '.json'))
    parser.add_argument('--probe-dir', type=Path)
    parser.add_argument('--library', type=Path)
    args = parser.parse_args()
    result = verify(json.loads(args.evidence.read_text(encoding='utf-8')),
                    args.probe_dir, args.library)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
