"""Verify the redacted parser-writer correlation and unresolved copy source."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

NAME = 'vm9_framesign_copy_writer_join_20261104'
ROLES = ('md5_piece_0_4', 'md5_piece_8_4', 'sha1_preimage_offset_4')
HEX_256 = re.compile(r'^[0-9a-f]{64}$')


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def attrs(line: str, prefix: str) -> dict[str, str]:
    tail = line.split(prefix, 1)[1]
    return dict(token.split('=', 1) for token in tail.split() if '=' in token)


def rows(log: str, tag: str) -> dict[str, dict[str, str]]:
    result = {}
    prefix = '[HookMain] ' + tag + ' '
    for line in log.splitlines():
        if not line.startswith(prefix):
            continue
        row = attrs(line, prefix)
        role = row.get('role')
        require(role in ROLES and role not in result, tag + ' role set')
        result[role] = row
    require(set(result) == set(ROLES), tag + ' coverage')
    return result


def verify(data: dict, probe_dir: Path | None = None) -> dict:
    require(data.get('schema') == 'vm9-framesign-copy-writer-join-20261104-v1', 'schema')
    require(data.get('evidence_date') == '2026-11-04', 'date')
    require(data.get('sample_scope') == 'single_fixed_synthetic_jni_initializer_call', 'scope')
    probe = data['probe']
    require(probe['id'] == 'configuration_initializer_copy_provider_probe13g', 'probe identity')
    for key in ('source_sha256', 'entry_class_sha256', 'runner_sha256', 'sanitized_log_sha256',
                'native_library_sha256'):
        require(bool(HEX_256.fullmatch(probe[key])), key)
    require(probe['process_exit_code'] == 0 and probe['signature_result_length'] == 10
            and probe['read_only_guest_observation'] is True, 'probe result')

    correction = data['misclassified_counter_correction']
    require(correction == {
        'fill_callsite_offset': '0x2482cc', 'fill_return_offset': '0x2482d0',
        'fill_entry_events': 2, 'fill_lengths': {'165': 1, '263': 1},
        'actual_copy_callsite_offset': '0x248254', 'clone_copy_callsite_offset': '0x248430',
        'copy_and_clone_entry_events': 0,
    }, 'fill/copy correction')
    require(len(data['parser_reads']) == 3, 'parser role count')
    for row, role in zip(data['parser_reads'], ROLES, strict=True):
        require(row == {
            'role': role, 'parser_writer_events': 4, 'store_address_matches': 4,
            'source_operand_matches': 0, 'temporal_matches': 4, 'full_source_matches': 0,
            'contiguous_source_registers': [],
        }, 'parser writer relationship')
    require(data['provider_returns'] == 0 and data['copy_chain'] == 'none', 'provider boundary')
    require(data['raw_values_retained'] is False and data['pointers_retained'] is False
            and data['operand_digests_retained'] is False and data['plaintext_retained'] is False,
            'redaction')
    require(data['conclusions'] == {
        'parser_writer_site_identity_joined': True,
        'parser_writer_address_and_order_joined': True,
        'copy_source_pointer_joined': False,
        'jni_string_provider_joined': False,
        'complete_signer_verified': False,
        'ordinary_cronet_header_chain_verified': False,
        'online_header_acceptance_verified': False,
    }, 'conclusions')

    if probe_dir is not None:
        source = probe_dir / 'HookMain.java'
        entry = probe_dir / 'classes' / 'HookMain.class'
        runner = probe_dir / 'run_buffer_probe.py'
        log_path = probe_dir / 'run1' / 'sanitized.log'
        meta_path = probe_dir / 'run1' / 'metadata.json'
        for path, key in ((source, 'source_sha256'), (entry, 'entry_class_sha256'),
                          (runner, 'runner_sha256'), (log_path, 'sanitized_log_sha256')):
            require(digest(path) == probe[key], 'local ' + key)
        meta = json.loads(meta_path.read_text(encoding='utf-8'))
        require(meta['process_exit_code'] == 0 and meta['raw_values_retained'] is False
                and meta['read_only_guest_probe'] is True, 'local terminal/privacy')
        require(meta['native_library_sha256'] == probe['native_library_sha256'], 'local native library')
        log = log_path.read_text(encoding='utf-8-sig')
        writer_rows = rows(log, 'FRAME_BUFFER_WORDPROVIDER_READ_WRITERS')
        for role, row in writer_rows.items():
            require(row['parser_writer_events'] == '4' and row['parser_store_address_matches'] == '4'
                    and row['parser_store_source_matches'] == '0'
                    and row['parser_store_temporal_matches'] == '4'
                    and row['parser_store_full_matches'] == '0'
                    and row['contiguous_source_registers'] == 'none', 'local writer relation')
        source_rows = rows(log, 'FRAME_BUFFER_WORDPROVIDER_SOURCE')
        for row in source_rows.values():
            require(row['returned_providers'] == '0' and row['temporal_order_verified'] == 'false',
                    'local JNI provider result')
        require('[HookMain] FRAME_SIGN_RESULT_LENGTH=10' in log, 'local signature result')

    return {'parser_roles_verified': 3, 'writer_events_verified': 12,
            'copy_source_joined': False, 'jni_provider_joined': False,
            'complete_signer_verified': False, 'online_acceptance_verified': False,
            'local_probe_verified': probe_dir is not None}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, default=Path(__file__).resolve().parents[1] /
                        'evidence' / (NAME + '.json'))
    parser.add_argument('--probe-dir', type=Path)
    args = parser.parse_args()
    result = verify(json.loads(args.evidence.read_text(encoding='utf-8')), args.probe_dir)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
