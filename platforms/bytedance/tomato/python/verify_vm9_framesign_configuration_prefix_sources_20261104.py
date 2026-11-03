"""Verify signed-load and scalar-store lifetime joins for configuration digest prefixes."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import verify_vm9_framesign_configuration_operands_20261104 as prior
from verify_vm9_framesign_aes_material_20261103 import owner_sha256, ledger_sha256

block = prior.block
NAME = 'vm9_framesign_configuration_prefix_sources_20261104'
SOURCE = 'configuration_word_slot_probe'
PARENT = prior.NAME + '.json'
OWNERS = prior.OWNERS
ARTIFACTS = prior.ARTIFACTS
INPUTS = prior.INPUTS
COMPARISONS = prior.COMPARISONS
CLAIMS = {
    'independent_runs': 2, 'calls': 8,
    'signed_LOAD32_result_and_destination_slot_identity_verified': True,
    'scalar_store_input_slot_write_event_identity_verified': True,
    'MD5_middle_reloads_earlier_scalar_store_BCP_0x9aabc': True,
    'MD5_middle_decoder_prefix_address_and_write_lifetime_joined': True,
    'SHA1_last_decoder_prefix_address_and_write_lifetime_joined': True,
    'SHA1_first_plaintext_prefix_address_and_write_lifetime_joined': True,
    'copy_and_scalar_versions_checked_with_snapshots_and_temporal_order': True,
    'three_shared_word_consumers_have_same_observed_source_address': True,
    'shared_word_source_is_mapped_read_write_nonexecutable': True,
    'shared_word_source_inside_observed_native_stack': False,
    'shared_word_source_inside_current_VM_bank': False,
    'native_writes_to_shared_word_observed_in_per_call_window': False,
    'shared_word_initialization_or_lifetime_proven': False,
    'all_existing_Python_bridges_byte_identical_to_parent': True,
    'generated_MD5_SHA1_decrypt_RC4_and_material_pipeline_preserved': True,
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
    '0x1702f4': ('ldr', 'x10, [x28, x13, lsl #3]'),
    '0x1702f8': ('sxth', 'x11, w9'),
    '0x170308': ('ldrsw', 'x9, [x10, x11]'),
    '0x17030c': ('str', 'x9, [x28, x14, lsl #3]'),
    '0x172060': ('ldr', 'w11, [x28, x11]'),
    '0x17208c': ('str', 'w11, [x12, x10]'),
    '0x248254': ('bl', '#0x347f60'), '0x248430': ('bl', '#0x347f60'),
}
EVENTS = {'SCALARORIGIN_TERMINAL', 'SCALARORIGIN_WORD_RELATION', 'SCALARLOAD_JOIN',
          'SCALARLOAD_SCALAR_RELOAD', 'SCALARLOAD_LINK', 'SCALARLOAD_TERMINAL',
          'SCALARLOAD_TERMINAL_WRITERS', 'SCALARLOAD_WORD_REGION', 'SCALARWORD_VM_BANK'}


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
        if not event.startswith(('SCALARORIGIN_', 'SCALARLOAD_', 'SCALARWORD_')):
            continue
        block.require(event in EVENTS, 'unknown configuration source event')
        row = {'event': event}
        for token in attributes.split():
            key, value = token.split('=', 1)
            block.require(key not in row, 'duplicate configuration source attribute')
            row[key] = (value == 'true' if value in ('true', 'false') else
                        int(value) if value.lstrip('-').isdecimal() else value)
        rows.append(row)
    return block.ordered(rows)


def expected_new() -> list[dict]:
    rows = []
    for ordinal in range(1, 5):
        def add(event, **values):
            rows.append({'event': event, 'ordinal': ordinal, **values})
        roles = [('md5_piece_0_4', 4, None), ('md5_piece_4_8', 8, None),
                 ('md5_piece_4_4', 4, (1, '9ab28')), ('md5_piece_8_4', 4, None),
                 ('sha1_preimage_offset_0', 4, (2, '9ad78')),
                 ('sha1_preimage_offset_4', 4, None), ('sha1_preimage_offset_8', 4, (1, '9aab8'))]
        for role, length, scalar in roles:
            present = scalar is not None
            add('SCALARORIGIN_TERMINAL', role=role, length=length, scalar_record_present=present,
                scalar_store_identity_matches=present, scalar_ordinal_matches=present,
                scalar_store_precedes_read=present, snapshot_equals_stored_low_four=present,
                source_slot=scalar[0] if present else -1,
                slot_writer='metasec+0x17030c' if present else 'unobserved',
                slot_writer_BCP='metasec+0x'+scalar[1] if present else 'unobserved',
                slot_writer_ordinal=ordinal if present else -1, definition_present=False,
                definition_operation='unobserved', definition_relation_matches=False)
            if present:
                add('SCALARLOAD_JOIN', role=role, source_slot=scalar[0], load_record_present=True,
                    load_slot_write_identity_matches=True, signed_load_result_verified=True,
                    load_read_precedes_scalar_store=True, load_snapshot_equals_scalar_low_four=True,
                    load_BCP='metasec+0x'+scalar[1])
        for role in ('md5_piece_0_4', 'md5_piece_8_4'):
            add('SCALARORIGIN_WORD_RELATION', MD5_role=role, same_source_pointer=True, snapshot_equal=True,
                observed_write_events_equal=False, MD5_writer_coverage=0, SHA1_writer_coverage=0,
                MD5_read_precedes_SHA1_read=True)
        for role in ('md5_piece_0_4', 'md5_piece_8_4', 'sha1_preimage_offset_4'):
            add('SCALARLOAD_WORD_REGION', role=role, length=4, inside_native_stack=False,
                mapped=True, readable=True, writable=True, executable=False)
            add('SCALARWORD_VM_BANK', role=role, length=4, source_inside_current_VM_bank=False,
                source_slot=-1, slot_byte_offset=-1, slot_writer_coverage=0)
        add('SCALARLOAD_SCALAR_RELOAD', role='md5_piece_4_4', depth=0,
            earlier_store_BCP='metasec+0x9aabc', earlier_load_BCP='metasec+0x9aab8', source_slot=1,
            length=4, actual_store_write_events_equal=True, load_slot_write_identity_matches=True,
            load_read_precedes_scalar_write=True, scalar_write_precedes_reload=True, snapshot_equal=True)
        for role, depth, site, length in (
            ('md5_piece_4_4', 1, '248254', 276),
            ('sha1_preimage_offset_0', 0, '248430', 271),
            ('sha1_preimage_offset_0', 1, '248254', 271),
            ('sha1_preimage_offset_8', 0, '248254', 276)):
            add('SCALARLOAD_LINK', role=role, depth=depth, copy_site='metasec+0x'+site,
                copy_length=length, slice_offset=0, length=4, snapshot_equal=True,
                actual_write_events_equal=True, temporal_order_verified=True)
        decoder_writers = ','.join(f'metasec+0x{pc}/metasec+0x258ed0/outside_modules/{ordinal}:{count}'
                                  for pc, count in (('24599c', 2), ('2459bc', 1), ('2459cc', 1)))
        plaintext_writers = ','.join(f'metasec+0x{pc}/metasec+0x25ab84/outside_modules/{ordinal}:1'
                                    for pc in ('242928', '24293c', '242968', '242994'))
        for role, depth, decoded in (('md5_piece_4_4', 2, True),
                                      ('sha1_preimage_offset_0', 2, False),
                                      ('sha1_preimage_offset_8', 1, True)):
            add('SCALARLOAD_TERMINAL_WRITERS', role=role, depth=depth, length=4,
                writers=decoder_writers if decoded else plaintext_writers)
            add('SCALARLOAD_TERMINAL', role=role, depth=depth, length=4,
                source_inside_decoder=decoded, decoder_offset=0 if decoded else -1,
                decoder_snapshot_equal=decoded, decoder_write_events_equal=decoded,
                source_inside_plaintext=not decoded, plaintext_offset=-1 if decoded else 0,
                plaintext_snapshot_equal=not decoded, plaintext_write_events_equal=not decoded)
    return block.ordered(rows)


def prior_ledger(evidence_dir: Path, index: int, log: Path | None = None) -> dict:
    return {'operands': prior.parse_new(log) if log else prior.expected_new(),
            'earlier_ledger': prior.prior_ledger(evidence_dir, index, log)}


def verify(data: dict, evidence_dir: Path, probe_dir: Path | None = None,
           elf: Path | None = None, libc_jar: Path | None = None) -> dict:
    require = block.require
    require(set(data) == {'schema', 'evidence_date', 'input', 'parent_evidence', 'parent_evidence_sha256',
                         'owners', 'owner_hash_format', 'probe', 'runs', 'static_analysis', 'conclusions',
                         'raw_values_retained', 'operand_digests_retained', 'interpretation'}, 'evidence keys')
    require(data['schema'] == 'vm9-framesign-configuration-prefix-sources-20261104-v1'
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
             'existing_Python_bridges_identical_to_parent': True}
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
            'configuration_prefix_sources_joined_with_write_lifetime': True, 'standalone_signer_verified': False}


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
