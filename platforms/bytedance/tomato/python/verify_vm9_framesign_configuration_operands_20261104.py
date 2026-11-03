"""Verify configuration decoding and shared-word digest inputs driving the material chain."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import verify_vm9_framesign_configuration_md5_20261104 as prior
from verify_vm9_framesign_aes_material_20261103 import owner_sha256, ledger_sha256

block = prior.block
NAME = 'vm9_framesign_configuration_operands_20261104'
SOURCE = 'configuration_encoded_source_model_probe'
PARENT = prior.NAME + '.json'
OWNERS = prior.OWNERS
ARTIFACTS = prior.ARTIFACTS
INPUTS = ['observed_encoded_configuration_368_bytes', 'one_observed_shared_word_4_bytes',
          'observed_empty_IV_and_mode_zero', 'observed_twelve_reduction_leaf_bytes',
          'observed_lookup_key_10_bytes', 'fresh_relocated_ELF_tables_and_descriptors',
          'explicit_fixture_allocation_and_warm_singleton_services']
COMPARISONS = ['observed_decoded_configuration_276_bytes', 'observed_MD5_input_12_bytes',
               'observed_SHA1_input_12_bytes', 'observed_configuration_ciphertext_272_bytes',
               'observed_configuration_AES_key_16_bytes', 'observed_native_MD5_output_16_bytes',
               'observed_configuration_plaintext_271_bytes', 'observed_RC4_input_263_bytes',
               'observed_RC4_key_20_bytes', 'observed_decoder_prefix_4_bytes_for_counterexample_only']
CLAIMS = {
    'independent_runs': 2, 'calls': 8, 'encoded_length': 368, 'decoded_length': 276,
    'observed_shared_word_length': 4,
    'existing_configuration_decoder_equals_native_and_independent_base64': True,
    'MD5_input_actually_generated_as_word_decoded_prefix_word': True,
    'SHA1_input_actually_generated_as_plaintext_prefix_word_decoded_prefix': True,
    'ciphertext_actually_generated_from_decoded_slice_4_to_276': True,
    'generated_digest_inputs_keys_plaintext_and_materials_equal_native': True,
    'captured_digest_inputs_ciphertext_and_keys_comparison_only_except_shared_word': True,
    'copy_slices_checked_with_write_event_identity_and_temporal_order': True,
    'MD5_middle_reaches_VM_scalar_store_with_BCP_0x9ab2c': True,
    'MD5_middle_direct_decoder_address_lineage_verified': False,
    'changed_word_changed_prefix_and_wrong_slices_rejected': True,
    'complete_prior_relation_ledger_preserved': True,
    'shared_word_source_generation_identified': False,
    'earlier_encoded_configuration_source_identified': False,
    'reduction_leaf_bytes_independently_generated': False,
    'lookup_key_independently_generated': False,
    'actual_Android_allocator_or_singleton_equivalence_verified': False,
    'general_input_equivalence_verified': False, 'android_equivalence_verified': False,
    'complete_standalone_signer_verified': False, 'online_header_acceptance_verified': False,
}
STATIC = {
    '0x2469a0': ('bl', '#0x347f60'), '0x246c88': ('bl', '#0x348410'),
    '0x248254': ('bl', '#0x347f60'), '0x17208c': ('str', 'w11, [x12, x10]'),
    '0x24599c': ('strb', 'w17, [x16], #1'), '0x2459bc': ('strb', 'w13, [x14, #1]'),
    '0x2459cc': ('strb', 'w15, [x14, #2]'),
}
MODELS = {
    'CONFIGPREFIX_MODEL':dict(process_exit_code=0,encoded_length=368,decoded_length=276,
        existing_decoder_equals_native=True,independent_base64_equals_existing=True,
        generated_MD5_input_equals_native=True,MD5_middle_uses_generated_decoder_prefix=True,
        changed_prefix_key_matches=False,wrong_decoded_slice_key_matches=False),
    'CONFIGOPERAND_SHA1_MODEL':dict(process_exit_code=0,input_length=12,generated_input_equals_native=True,
        first_piece_uses_generated_plaintext=True,last_piece_uses_generated_decoder_prefix=True,
        changed_plaintext_prefix_key_matches=False,wrong_decoder_slice_key_matches=False),
    'CONFIGOPERAND_SHARED_MODEL':dict(process_exit_code=0,observed_word_length=4,word_equals_MD5_first=True,
        word_equals_MD5_last=True,word_equals_SHA1_middle=True,MD5_and_SHA1_actually_use_one_observed_word=True,
        changed_word_MD5_key_matches=False,changed_word_SHA1_key_matches=False),
    'CONFIGOPERAND_CIPHER_MODEL':dict(process_exit_code=0,length=272,generated_ciphertext_equals_native=True,
        cipher_actually_uses_generated_decoder_slice=True,wrong_decoder_slice_plaintext_matches=False),
}
EVENTS = {'KEYCOPY_LINK', 'KEYCOPY_TERMINAL', 'KEYCOPY_PIECE_COMPARE', *MODELS}


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
        if not event.startswith(('KEYCOPY_', 'CONFIGPREFIX_', 'CONFIGOPERAND_')):
            continue
        block.require(event in EVENTS, 'unknown configuration operand event')
        row = {'event': event}
        for token in attributes.split():
            key, value = token.split('=', 1)
            block.require(key not in row, 'duplicate configuration operand attribute')
            row[key] = (value == 'true' if value in ('true', 'false') else
                        int(value) if value.lstrip('-').isdecimal() else value)
        rows.append(row)
    return block.ordered(rows)


def expected_new() -> list[dict]:
    rows = []
    for ordinal in range(1, 5):
        def add(event, **values):
            rows.append({'event': event, 'ordinal': ordinal, **values})
        for piece, length, chain in ((0, 4, ('2469a0', '246c88')),
                                     (4, 4, ('246c88', '248254')), (8, 4, ('246c88',))):
            for depth, site in enumerate(chain):
                add('KEYCOPY_LINK', index=1, piece_offset=piece, piece_length=length, depth=depth,
                    copy_site='metasec+0x'+site, copy_length=4, slice_offset=0, length=4,
                    actual_write_events_equal=True, temporal_order_verified=True, snapshot_equal=True)
        for piece, length, depth, writers, direct, offset in (
            (0, 4, 2, 'unobserved:4', 0, -1),
            (4, 8, 0, f'libc.so+0x1c300/metasec+0x246c8c/outside_modules/{ordinal}:8', 0, -1),
            (4, 4, 2, f'metasec+0x17208c/outside_modules/metasec+0x9ab2c/{ordinal}:4', 1, 0),
            (8, 4, 1, 'unobserved:4', 0, -1)):
            add('KEYCOPY_TERMINAL', index=1, piece_offset=piece, piece_length=length,
                depth=depth, length=length, source_location='outside_modules',
                writers_caller_BCP_at_read=writers, source_inside_decoder=False,
                decoder_direct_matches=direct, decoder_direct_offset=offset, decoder_offset=-1,
                decoder_snapshot_equal=False, decoder_write_events_equal=False)
        for left in range(3):
            for right in range(3):
                add('KEYCOPY_PIECE_COMPARE', MD5_piece=left, SHA1_piece=right,
                    bytes_equal=(left, right) in ((0, 1), (1, 2), (2, 1)))
        for event, attributes in MODELS.items():
            add(event, **attributes)
    return block.ordered(rows)


def prior_ledger(evidence_dir: Path, index: int, log: Path | None = None) -> dict:
    return {'md5': prior.parse_new(log) if log else prior.expected_new(),
            'earlier_ledger': prior.prior_ledger(evidence_dir, index, log)}


def verify(data: dict, evidence_dir: Path, probe_dir: Path | None = None,
           elf: Path | None = None, libc_jar: Path | None = None) -> dict:
    require = block.require
    require(set(data) == {'schema', 'evidence_date', 'input', 'parent_evidence', 'parent_evidence_sha256',
                         'owners', 'owner_hash_format', 'probe', 'runs', 'static_analysis', 'conclusions',
                         'raw_values_retained', 'operand_digests_retained', 'interpretation'}, 'evidence keys')
    require(data['schema'] == 'vm9-framesign-configuration-operands-20261104-v1'
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
             'configuration_decrypt_uses_generated_MD5_key': True,
             'digest_inputs_and_ciphertext_use_generated_configuration': True}
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
        require(same(run['observations'], expected), 'configuration operand relations')
        ledger = prior_ledger(evidence_dir, index)
        require(run['prior_relation_ledger_sha256'] == ledger_sha256(ledger), 'prior ledger identity')
        if probe_dir is not None:
            log = probe_dir / run['local_run_name'] / 'sanitized.log'
            require(block.sha256(log) == run['sanitized_log_sha256'], 'local log identity')
            require(same(parse_new(log), expected), 'local configuration operand relations')
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
            'configuration_pipeline_generated_from_encoded_input_and_one_observed_word': True, 'standalone_signer_verified': False}


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
