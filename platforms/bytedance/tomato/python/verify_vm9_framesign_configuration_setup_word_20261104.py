"""Verify initialization-tag native writes and the shared configuration word clone."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import verify_vm9_framesign_configuration_prefix_sources_20261104 as prior
from verify_vm9_framesign_aes_material_20261103 import owner_sha256, ledger_sha256

block = prior.block
NAME = 'vm9_framesign_configuration_setup_word_20261104'
SOURCE = 'configuration_word_setup_clone_probe'
PARENT = prior.NAME + '.json'
OWNERS = prior.OWNERS
ARTIFACTS = prior.ARTIFACTS
INPUTS = prior.INPUTS
COMPARISONS = prior.COMPARISONS
CLAIMS = {
    'independent_runs': 2, 'calls': 8,
    'earlier_initialization_tag_0x4000001_native_writers_observed': True,
    'all_four_shared_word_bytes_have_observed_setup_writers': True,
    'all_four_last_native_write_low_bytes_match_consumers': True,
    'shared_word_setup_clone_source_joined_by_actual_write_event_identity': True,
    'setup_clone_source_snapshot_and_temporal_order_verified': True,
    'setup_clone_length': 4,
    'earlier_source_writer_returns_to_VM_call_site_0x16aa4c': True,
    'shared_word_source_inside_current_TPIDR_page': False,
    'shared_word_source_inside_manager_first_256_bytes': False,
    'complete_existing_per_call_source_ledger_preserved': True,
    'all_existing_Python_bridges_byte_identical_to_parent': True,
    'generated_MD5_SHA1_decrypt_RC4_and_material_pipeline_preserved': True,
    'shared_word_earlier_VM_copy_input_recovered': False,
    'shared_word_independent_generation_recovered': False,
    'earlier_encoded_configuration_source_identified': False,
    'reduction_leaf_bytes_independently_generated': False,
    'lookup_key_independently_generated': False,
    'actual_Android_allocator_or_singleton_equivalence_verified': False,
    'general_input_equivalence_verified': False, 'android_equivalence_verified': False,
    'complete_standalone_signer_verified': False, 'online_header_acceptance_verified': False,
}
STATIC = {
    '0x24841c': ('str', 'x0, [x21, #0x10]'),
    '0x248430': ('bl', '#0x347f60'),
    '0x248434': ('strb', 'wzr, [x22, x19]'),
    '0x16aa48': ('blr', 'x8'),
    '0x16aa4c': ('ldp', 'x5, x1, [x29, #-0x90]'),
}
EVENTS = {'WORDOWNER_REGION', 'WORDOWNER_EARLY_WRITERS', 'WORDSETUP_COPY', 'WORDSETUP_TERMINAL'}

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
        if not event.startswith(('WORDOWNER_', 'WORDSETUP_')):
            continue
        block.require(event in EVENTS, 'unknown configuration source event')
        row = {'event': event}
        for token in attributes.split():
            key, value = token.split('=', 1)
            block.require(key not in row, 'duplicate configuration source attribute')
            row[key] = value if key == 'source_tag' else (value == 'true' if value in ('true', 'false') else
                        int(value) if value.lstrip('-').isdecimal() else value)
        rows.append(row)
    return block.ordered(rows)


def expected_new() -> list[dict]:
    rows = []
    for ordinal in range(1, 5):
        for role in ('md5_piece_0_4', 'md5_piece_8_4', 'sha1_preimage_offset_4'):
            def add(event, **values):
                rows.append({'event': event, 'ordinal': ordinal, 'role': role, **values})
            add('WORDOWNER_REGION', source_in_TPIDR_page=False, TPIDR_delta=0,
                source_in_manager_first_256=False, manager_offset=-1)
            add('WORDOWNER_EARLY_WRITERS', length=4, byte_coverage=4, low_bytes_checkable=4,
                low_bytes_match_snapshot=4,
                writers='libc.so+0x1c148/metasec+0x248434/outside_modules/tag4000001/ordinal0:4')
            add('WORDSETUP_COPY', depth=0, copy_site='metasec+0x24841c', copy_length=4,
                slice_offset=0, length=4, source_tag='4000001', actual_write_events_equal=True,
                snapshot_equal=True, temporal_order_verified=True)
            add('WORDSETUP_TERMINAL', depth=1, length=4, source_location='outside_modules',
                writers='libc.so+0x1c148/metasec+0x16aa4c/outside_modules/tag4000001/ordinal0:4')
    return block.ordered(rows)


def prior_ledger(evidence_dir: Path, index: int, log: Path | None = None) -> dict:
    return {'prefix_sources': prior.parse_new(log) if log else prior.expected_new(),
            'earlier_ledger': prior.prior_ledger(evidence_dir, index, log)}


def verify(data: dict, evidence_dir: Path, probe_dir: Path | None = None,
           elf: Path | None = None, libc_jar: Path | None = None) -> dict:
    require = block.require
    require(set(data) == {'schema', 'evidence_date', 'input', 'parent_evidence', 'parent_evidence_sha256',
                         'owners', 'owner_hash_format', 'probe', 'runs', 'static_analysis', 'conclusions',
                         'raw_values_retained', 'operand_digests_retained', 'interpretation'}, 'evidence keys')
    require(data['schema'] == 'vm9-framesign-configuration-setup-word-20261104-v1'
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
             'digest_inputs_and_ciphertext_use_generated_configuration': True,
             'existing_Python_bridges_identical_to_parent': True,
             'earlier_JNI_tags_observed_separately_from_existing_per_call_window': True,
             'setup_clone_capture_anchor': 'native_header_store_0x24841c'}
    require(set(probe) == identity_keys | set(fixed), 'probe keys')
    require(same({k: probe[k] for k in fixed}, fixed), 'probe scope')
    for key in identity_keys:
        require(isinstance(probe[key], str) and block.HEX_256.fullmatch(probe[key]), 'probe digest')
    for relative, key in ARTIFACTS:
        if relative.endswith('.py') and relative != 'run_buffer_probe.py':
            require(probe[key] == parent['probe'][key], 'changed existing Python bridge')
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
        require(same(run['observations'], expected), 'configuration source relations')
        ledger = prior_ledger(evidence_dir, index)
        require(run['prior_relation_ledger_sha256'] == ledger_sha256(ledger), 'prior ledger identity')
        if probe_dir is not None:
            log = probe_dir / run['local_run_name'] / 'sanitized.log'
            require(block.sha256(log) == run['sanitized_log_sha256'], 'local log identity')
            require(same(parse_new(log), expected), 'local configuration source relations')
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
            'shared_word_initialization_clone_source_joined': True, 'standalone_signer_verified': False}


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
