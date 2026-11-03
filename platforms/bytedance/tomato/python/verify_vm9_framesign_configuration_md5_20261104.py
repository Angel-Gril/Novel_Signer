"""Verify observed-input MD5 derivation actually driving configuration decryption."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import verify_vm9_framesign_configuration_decrypt_20261104 as prior
from verify_vm9_framesign_aes_material_20261103 import owner_sha256, ledger_sha256

block = prior.block
NAME = 'vm9_framesign_configuration_md5_20261104'
SOURCE = 'configuration_md5_key_model_probe'
PARENT = prior.NAME + '.json'
OWNERS = prior.OWNERS
ARTIFACTS = (*prior.ARTIFACTS, ('host_materials.py', 'materials_bridge_sha256'))
INPUTS = ['observed_MD5_input_12_bytes_and_flag_zero', 'observed_configuration_ciphertext_272_bytes',
          'observed_empty_IV_and_mode_zero', 'observed_SHA1_preimage_12_bytes',
          'observed_twelve_reduction_leaf_bytes', 'observed_lookup_key_10_bytes',
          'fresh_relocated_ELF_tables_and_descriptors', 'explicit_fixture_allocation_and_warm_singleton_services']
COMPARISONS = ['observed_configuration_AES_key_16_bytes', 'observed_native_MD5_output_16_bytes',
               'observed_configuration_plaintext_271_bytes', 'observed_RC4_input_263_bytes',
               'observed_RC4_key_20_bytes', 'observed_decoder_prefix_4_bytes_for_counterexample_only']
CLAIMS = {
    'independent_runs': 2, 'calls': 8, 'MD5_input_length': 12, 'MD5_flag': 0,
    'configuration_AES_key_length': 16,
    'existing_Python_MD5_equals_native_output_and_AES_key': True,
    'independent_MD5_equals_existing_model': True,
    'configuration_decrypt_actually_uses_generated_MD5_key': True,
    'captured_AES_key_used_only_for_comparisons': True,
    'MD5_return_and_cipher_input_share_pointer_and_write_event_identity': True,
    'MD5_and_SHA1_inputs_differ_in_each_four_byte_piece': True,
    'MD5_of_decoder_prefix_is_actual_counterexample': True,
    'changed_input_reversed_input_hex_flag_and_SHA1_preimage_rejected': True,
    'configuration_decrypt_RC4_Protobuf_selection_and_AES_chain_preserved': True,
    'complete_prior_relation_ledger_preserved': True,
    'configuration_AES_key_generated_from_observed_MD5_input': True,
    'MD5_input_independently_generated': False, 'SHA1_preimage_independently_generated': False,
    'MD5_source_copy_lineage_closed': False,
    'reduction_leaf_bytes_independently_generated': False, 'lookup_key_independently_generated': False,
    'actual_Android_allocator_or_singleton_equivalence_verified': False,
    'general_input_equivalence_verified': False, 'android_equivalence_verified': False,
    'complete_standalone_signer_verified': False, 'online_header_acceptance_verified': False,
}
STATIC = {
    '0x263504': ('str', 'x30, [sp, #-0x10]!'),
    '0x263508': ('ldr', 'x9, [x0, #0x10]'),
    '0x26350c': ('ldp', 'x10, x8, [x0]'),
    '0x263510': ('ldrb', 'w1, [x0, #0x18]'),
    '0x263514': ('mov', 'x0, x9'), '0x263518': ('blr', 'x10'),
    '0x26351c': ('ldr', 'x30, [sp], #0x10'),
    '0x25874c': ('sub', 'sp, sp, #0x10'),
    '0x258750': ('stp', 'x9, x30, [sp]'),
    '0x258754': ('adr', 'x9, #0x258764'),
    '0x258758': ('mov', 'x30, x9'), '0x25875c': ('ret', ''),
}
EVENTS = {'KEYORIGIN_INPUT', 'KEYORIGIN_TERMINAL', 'KEYORIGIN_RETURN', 'KEYORIGIN_CIPHER_JOIN',
          'KEYDERIVE_LIFETIME', 'KEYDERIVE_INPUT_RELATION', 'KEYDERIVE_MODEL'}


def same(left, right):
    return block.canonical(left) == block.canonical(right)


def parse_new(path: Path) -> list[dict]:
    prior.parse_new(path)
    rows = []
    for line in path.read_text(encoding='utf-8-sig').splitlines():
        prefix = '[HookMain] FRAME_BUFFER_'
        if not line.startswith(prefix):
            continue
        event, _, attributes = line[len(prefix):].partition(' ')
        block.require(not event.endswith('ERROR'), 'probe observation error')
        if not event.startswith(('KEYORIGIN_', 'KEYDERIVE_')):
            continue
        block.require(event in EVENTS, 'unknown configuration digest event')
        row = {'event': event}
        for token in attributes.split():
            key, value = token.split('=', 1)
            block.require(key not in row, 'duplicate configuration digest attribute')
            row[key] = (value == 'true' if value in ('true', 'false') else
                        int(value) if value.lstrip('-').isdecimal() else value)
        rows.append(row)
    return block.ordered(rows)


def expected_new() -> list[dict]:
    rows = []
    for ordinal in range(1, 5):
        def add(event, **values):
            rows.append({'event': event, 'ordinal': ordinal, **values})
        add('KEYORIGIN_INPUT', index=1, length=12, raw_output=True, low_byte_flag=0,
            input_equals_decoder_prefix=False, input_equals_encoded_configuration=False)
        add('KEYORIGIN_TERMINAL', index=1, depth=0, length=12, source_location='outside_modules',
            writers_and_BCP_at_read=f'libc.so+0x1c148/outside_modules/{ordinal}:4,libc.so+0x1c300/outside_modules/{ordinal}:8',
            source_inside_decoder=False, decoder_offset=-1, decoder_snapshot_equal=False,
            decoder_write_events_equal=False)
        add('KEYORIGIN_RETURN', index=1, output_length=16, independent_MD5_equals_native=True)
        add('KEYORIGIN_CIPHER_JOIN', index=1, input_length=12, digest_length=16, digest_equals_AES_key=True)
        add('KEYDERIVE_LIFETIME', index=1, key_length=16, same_data_pointer=True,
            same_write_events=True, snapshot_equal=True, temporal_order_verified=True)
        add('KEYDERIVE_INPUT_RELATION', MD5_input_length=12, SHA1_input_length=12,
            MD5_equals_SHA1_input=False, same_first_four=False, same_middle_four=False,
            same_last_four=False, same_last_eight=False)
        add('KEYDERIVE_MODEL', process_exit_code=0, input_length=12, flag=0, key_length=16,
            existing_Python_MD5_equals_native_output=True, existing_Python_MD5_equals_native_AES_key=True,
            independent_MD5_equals_existing=True, configuration_decrypt_uses_generated_key=True,
            changed_input_matches=False, reversed_input_matches=False, hexadecimal_flag_matches=False,
            decoder_prefix_candidate_matches=False, SHA1_preimage_candidate_matches=False)
    return block.ordered(rows)


def prior_ledger(evidence_dir: Path, index: int, log: Path | None = None) -> dict:
    return {'decrypt': prior.parse_new(log) if log else prior.expected_new(),
            'earlier_ledger': prior.prior_ledger(evidence_dir, index, log)}


def verify(data: dict, evidence_dir: Path, probe_dir: Path | None = None,
           elf: Path | None = None, libc_jar: Path | None = None) -> dict:
    require = block.require
    require(set(data) == {'schema', 'evidence_date', 'input', 'parent_evidence', 'parent_evidence_sha256',
                         'owners', 'owner_hash_format', 'probe', 'runs', 'static_analysis', 'conclusions',
                         'raw_values_retained', 'operand_digests_retained', 'interpretation'}, 'evidence keys')
    require(data['schema'] == 'vm9-framesign-configuration-md5-20261104-v1'
            and data['evidence_date'] == '2026-11-04', 'schema/date')
    require(same(data['input'], block.EXPECTED_INPUT) and same(data['conclusions'], CLAIMS), 'input/conclusions')
    require(data['raw_values_retained'] is False and data['operand_digests_retained'] is False, 'privacy')
    require(data['parent_evidence'] == 'evidence/' + PARENT
            and data['parent_evidence_sha256'] == block.sha256(evidence_dir / PARENT), 'parent identity')
    parent = json.loads((evidence_dir / PARENT).read_text())
    prior.verify(parent, evidence_dir, elf=elf, libc_jar=libc_jar)
    require(data['owner_hash_format'] == 'sha256_bytes_CRLF_normalized_to_LF'
            and set(data['owners']) == set(OWNERS), 'owners')
    for owner, digest in data['owners'].items():
        require(digest == owner_sha256(Path(__file__).with_name(owner)), 'owner identity')
    probe = data['probe']
    identity_keys = {key for _, key in ARTIFACTS}
    fixed = {'source_relative_path': SOURCE + '/HookMain.java', 'read_only_guest_observation': True,
             'fresh_rootfs_per_run': True, 'synthetic_jni_provider_used': True, 'setup_rounds_per_run': 1,
             'restore_enabled': False, 'run_deadline_seconds': 1200,
             'python_operand_transport': 'private_in_memory_stdin_stdout_pipe', 'model_inputs': INPUTS,
             'comparison_only_inputs': COMPARISONS, 'RC4_uses_model_generated_data_and_key': True,
             'warm_singleton_and_allocator_are_explicit_fixtures': True,
             'configuration_decrypt_uses_generated_MD5_key': True}
    require(set(probe) == identity_keys | set(fixed), 'probe keys')
    require(same({k: probe[k] for k in fixed}, fixed), 'probe scope')
    for key in identity_keys:
        require(isinstance(probe[key], str) and block.HEX_256.fullmatch(probe[key]), 'probe digest')
    require(isinstance(data['runs'], list) and len(data['runs']) == 2, 'run count')
    expected = expected_new()
    for index, run in enumerate(data['runs'], 1):
        require(set(run) == {'local_run_name', 'source_sha256', 'entry_class_sha256', 'native_library_sha256',
                            'python_model_sha256', 'preblock_model_sha256', 'configuration_model_sha256',
                            'process_exit_code', 'sanitized_log_sha256', 'repeat_trials', 'observations',
                            'prior_relation_ledger_sha256', 'runner_sha256', 'run_deadline_seconds'}, 'run keys')
        require(run['local_run_name'] == SOURCE + '/run' + str(index)
                and type(run['process_exit_code']) is int and run['process_exit_code'] == 0, 'run terminal')
        require(run['runner_sha256'] == probe['runner_sha256']
                and type(run['run_deadline_seconds']) is int and run['run_deadline_seconds'] == 1200, 'run deadline')
        for key in ('source_sha256', 'entry_class_sha256'):
            require(run[key] == probe[key], 'paired build')
        for key in ('native_library_sha256', 'python_model_sha256', 'preblock_model_sha256', 'configuration_model_sha256'):
            require(run[key] == parent['runs'][index - 1][key], 'prior artifact identity')
        require(isinstance(run['sanitized_log_sha256'], str) and block.HEX_256.fullmatch(run['sanitized_log_sha256']), 'log digest')
        require(same(run['repeat_trials'], parent['runs'][index - 1]['repeat_trials']), 'changed outputs')
        require(same(run['observations'], expected), 'configuration MD5 relations')
        ledger = prior_ledger(evidence_dir, index)
        require(run['prior_relation_ledger_sha256'] == ledger_sha256(ledger), 'prior ledger identity')
        if probe_dir is not None:
            log = probe_dir / run['local_run_name'] / 'sanitized.log'
            require(block.sha256(log) == run['sanitized_log_sha256'], 'local log identity')
            require(same(parse_new(log), expected), 'local configuration MD5 relations')
            require(same(prior_ledger(evidence_dir, index, log), ledger), 'complete prior ledger')
            require(same([{'ordinal': r['ordinal'], 'fields': r['fields']} for r in block.parse_log(log)], run['repeat_trials']), 'local outputs')
            meta = json.loads(log.with_name('metadata.json').read_text())
            require(type(meta['process_exit_code']) is int and meta['process_exit_code'] == 0
                    and meta['read_only_guest_probe'] is True and meta['raw_values_retained'] is False, 'local terminal/privacy')
            for key in ('source_sha256', 'entry_class_sha256', 'native_library_sha256', 'python_model_sha256',
                        'preblock_model_sha256', 'configuration_model_sha256'):
                require(meta[key] == run[key], 'local build identity')
    if probe_dir is not None:
        for relative, key in ARTIFACTS:
            require(block.sha256(probe_dir / SOURCE / relative) == probe[key], 'local probe identity')
        runner = (probe_dir / SOURCE / 'run_buffer_probe.py').read_text()
        require(runner.count('threading.Timer(1200, proc.kill)') == 1, 'runner actual deadline')
        roots = [(probe_dir / SOURCE / ('run' + str(i)) / 'rootfs').resolve() for i in (1, 2)]
        require(roots[0] != roots[1] and all(p.is_dir() for p in roots), 'fresh rootfs directories')
    static = data['static_analysis']
    require(set(static) == {'native_library_sha256', 'instructions'}
            and static['native_library_sha256'] == block.LIBRARY_SHA256, 'static identity')
    require([r['image_offset'] for r in static['instructions']] == list(STATIC), 'static sites')
    for row in static['instructions']:
        require(set(row) == {'image_offset', 'file_offset', 'bytes_hex', 'mnemonic', 'operands'}
                and (row['mnemonic'], row['operands']) == STATIC[row['image_offset']], 'static contract')
    if elf is not None:
        block.check_elf(elf, static)
    require(isinstance(data['interpretation'], str) and bool(data['interpretation'].strip()), 'interpretation')
    return {'calls_verified': 8, 'new_observations_verified': len(expected) * 2,
            'complete_prior_ledger_preserved': True, 'local_logs_verified': probe_dir is not None,
            'elf_bytes_verified': elf is not None, 'libc_artifact_verified': libc_jar is not None,
            'configuration_AES_key_generated_from_observed_MD5_input': True, 'standalone_signer_verified': False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, default=Path(__file__).resolve().parents[1] / 'evidence' / (NAME + '.json'))
    parser.add_argument('--probe-dir', type=Path)
    parser.add_argument('--elf', type=Path)
    parser.add_argument('--libc-jar', type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(json.loads(args.evidence.read_text()), args.evidence.parent,
                            args.probe_dir, args.elf, args.libc_jar), sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
