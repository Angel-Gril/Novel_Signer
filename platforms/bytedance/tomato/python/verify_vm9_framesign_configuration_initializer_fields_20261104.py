"""Verify both FrameSign configuration seed fields are generated from initializer JSON."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import verify_vm9_framesign_configuration_initializer_word_20261104 as prior
from verify_vm9_framesign_aes_material_20261103 import owner_sha256, ledger_sha256

block = prior.block
NAME = 'vm9_framesign_configuration_initializer_fields_20261104'
SOURCE = 'configuration_initializer_fields_model_probe2'
PARENT = prior.NAME + '.json'
ARTIFACTS = prior.ARTIFACTS
INPUTS = [item if item != 'observed_encoded_configuration_368_bytes'
          else 'initializer_JSON_configuration_field_three' for item in prior.INPUTS]
COMPARISONS = [*prior.COMPARISONS, 'observed_encoded_configuration_368_bytes_comparison_only']
CLAIMS = {
    'independent_runs': 2, 'calls': 8,
    'initializer_word_field_zero_generated_in_python': True,
    'initializer_configuration_field_three_generated_in_python': True,
    'captured_word_and_configuration_are_comparison_only': True,
    'initializer_encoded_configuration_matches_native_input': True,
    'generated_configuration_drives_digest_decrypt_RC4_and_material_models': True,
    'all_generated_intermediates_and_native_final_ciphertext_match': True,
    'complete_parent_relation_ledger_and_outputs_preserved': True,
    'only_proto_material_model_bridge_changed_from_parent': True,
    'original_initializer_JNI_provider_pointer_joined': False,
    'other_application_ids_or_configuration_values_verified': False,
    'reduction_leaf_bytes_independently_generated': False,
    'lookup_key_independently_generated': False,
    'Android_allocator_or_singleton_equivalence_verified': False,
    'general_input_equivalence_verified': False, 'android_equivalence_verified': False,
    'complete_standalone_signer_verified': False, 'online_header_acceptance_verified': False,
}


def same(left, right):
    return block.canonical(left) == block.canonical(right)


def parse_new(path: Path) -> list[dict]:
    rows = []
    for line in path.read_text(encoding='utf-8-sig').splitlines():
        prefix = '[HookMain] FRAME_BUFFER_FIELDSINITIALIZER_MODEL '
        if not line.startswith(prefix):
            continue
        row = {}
        for token in line[len(prefix):].split():
            key, value = token.split('=', 1)
            block.require(key not in row, 'duplicate initializer field attribute')
            row[key] = value if value not in ('true', 'false') and not value.isdecimal() else (
                value == 'true' if value in ('true', 'false') else int(value))
        block.require(set(row) == {'ordinal', 'configuration_field_index',
                                   'configuration_generated_from_initializer',
                                   'captured_encoded_configuration_comparison_only',
                                   'generated_configuration_equals_captured'}, 'initializer field event keys')
        rows.append(row)
    return block.ordered(rows)


def expected_new() -> list[dict]:
    return [{'ordinal': ordinal, 'configuration_field_index': 3,
             'configuration_generated_from_initializer': True,
             'captured_encoded_configuration_comparison_only': True,
             'generated_configuration_equals_captured': True}
            for ordinal in range(1, 5)]


def verify(data: dict, evidence_dir: Path, probe_dir: Path | None = None,
           elf: Path | None = None, libc_jar: Path | None = None) -> dict:
    require = block.require
    require(set(data) == {'schema', 'evidence_date', 'input', 'parent_evidence',
                          'parent_evidence_sha256', 'owner_hash_format', 'owners', 'probe',
                          'runs', 'parent_static_analysis_sha256', 'conclusions',
                          'raw_values_retained', 'operand_digests_retained', 'interpretation'}, 'evidence keys')
    require(data['schema'] == 'vm9-framesign-configuration-initializer-fields-20261104-v1'
            and data['evidence_date'] == '2026-11-04', 'schema/date')
    require(same(data['input'], block.EXPECTED_INPUT) and same(data['conclusions'], CLAIMS), 'input/conclusions')
    require(data['raw_values_retained'] is False and data['operand_digests_retained'] is False, 'privacy')
    parent_path = evidence_dir / PARENT
    require(data['parent_evidence'] == 'evidence/' + PARENT
            and data['parent_evidence_sha256'] == block.sha256(parent_path), 'parent identity')
    parent_data = json.loads(parent_path.read_text())
    prior.verify(parent_data, evidence_dir, elf=elf, libc_jar=libc_jar)
    require(data['owner_hash_format'] == 'sha256_bytes_CRLF_normalized_to_LF'
            and set(data['owners']) == set(prior.OWNERS), 'owners')
    for owner, digest in data['owners'].items():
        require(digest == owner_sha256(Path(__file__).with_name(owner)), 'owner identity')
    require(data['parent_static_analysis_sha256'] == ledger_sha256(parent_data['static_analysis']),
            'parent static analysis identity')

    probe = data['probe']
    identity_keys = {key for _, key in ARTIFACTS}
    fixed = {'source_relative_path': SOURCE + '/HookMain.java', 'read_only_guest_observation': True,
             'fresh_rootfs_per_run': True, 'synthetic_jni_provider_used': True,
             'setup_rounds_per_run': 1, 'restore_enabled': False, 'run_deadline_seconds': 1200,
             'python_operand_transport': 'private_in_memory_stdin_stdout_pipe',
             'model_inputs': INPUTS, 'comparison_only_inputs': COMPARISONS,
             'initializer_word_generated_in_Python': True,
             'initializer_configuration_generated_in_Python': True,
             'captured_digest_inputs_and_configuration_comparison_only': True,
             'configuration_decrypt_uses_generated_MD5_key': True,
             'digest_inputs_and_ciphertext_use_generated_configuration': True,
             'RC4_uses_model_generated_data_and_key': True,
             'warm_singleton_and_allocator_are_explicit_fixtures': True,
             'existing_Python_bridges_identical_to_parent': False,
             'only_changed_Python_bridge': 'host_proto_material.py',
             'proto_material_request_lines': 15,
             'initializer_JSON_input_bound_bytes': 4096}
    require(set(probe) == identity_keys | set(fixed), 'probe keys')
    require(same({key: probe[key] for key in fixed}, fixed), 'probe scope')
    for key in identity_keys:
        require(isinstance(probe[key], str) and block.HEX_256.fullmatch(probe[key]), 'probe digest')
    for relative, key in ARTIFACTS:
        if relative not in ('HookMain.java', 'classes/HookMain.class', 'run_buffer_probe.py',
                            'host_proto_material.py'):
            require(probe[key] == parent_data['probe'][key], 'changed unrelated model bridge')

    require(isinstance(data['runs'], list) and len(data['runs']) == 2, 'run count')
    for index, run in enumerate(data['runs'], 1):
        require(set(run) == {'local_run_name', 'source_sha256', 'entry_class_sha256',
                            'native_library_sha256', 'python_model_sha256',
                            'preblock_model_sha256', 'configuration_model_sha256',
                            'process_exit_code', 'sanitized_log_sha256', 'repeat_trials',
                            'initializer_field_observations', 'parent_relation_ledger_sha256',
                            'runner_sha256', 'run_deadline_seconds'}, 'run keys')
        require(run['local_run_name'] == SOURCE + '/run' + str(index)
                and type(run['process_exit_code']) is int and run['process_exit_code'] == 0,
                'run terminal')
        require(run['runner_sha256'] == probe['runner_sha256']
                and run['run_deadline_seconds'] == 1200, 'runner identity')
        for key in ('source_sha256', 'entry_class_sha256'):
            require(run[key] == probe[key], 'paired build identity')
        for key in ('native_library_sha256', 'python_model_sha256',
                    'preblock_model_sha256', 'configuration_model_sha256'):
            require(run[key] == parent_data['runs'][index - 1][key], 'native/model identity')
        require(isinstance(run['sanitized_log_sha256'], str)
                and block.HEX_256.fullmatch(run['sanitized_log_sha256']), 'log digest')
        require(same(run['repeat_trials'], parent_data['runs'][index - 1]['repeat_trials']),
                'native outputs changed')
        require(same(run['initializer_field_observations'], expected_new()), 'initializer field relations')
        require(run['parent_relation_ledger_sha256'] == ledger_sha256(prior.prior_ledger(evidence_dir, index)),
                'parent relation ledger')
        if probe_dir is not None:
            log = probe_dir / run['local_run_name'] / 'sanitized.log'
            require(block.sha256(log) == run['sanitized_log_sha256'], 'local log identity')
            require(same(parse_new(log), expected_new()), 'local initializer field relations')
            require(same(prior.parse_new(log), prior.expected_new()), 'prior native relation ledger')
            require(same([{'ordinal': row['ordinal'], 'fields': row['fields']}
                          for row in block.parse_log(log)], run['repeat_trials']), 'local native outputs')
            meta = json.loads(log.with_name('metadata.json').read_text())
            require(type(meta['process_exit_code']) is int and meta['process_exit_code'] == 0
                    and meta['read_only_guest_probe'] is True and meta['raw_values_retained'] is False,
                    'local terminal/privacy')
            for key in ('source_sha256', 'entry_class_sha256', 'native_library_sha256',
                        'python_model_sha256', 'preblock_model_sha256', 'configuration_model_sha256'):
                require(meta[key] == run[key], 'local build identity')
    if probe_dir is not None:
        for relative, key in ARTIFACTS:
            require(block.sha256(probe_dir / SOURCE / relative) == probe[key], 'local artifact identity')
        bridge = (probe_dir / SOURCE / 'host_proto_material.py').read_text()
        require(bridge.count("encoded_configuration=initializer[3].encode('utf-8')") == 1
                and bridge.count('encoded_configuration!=observed_encoded_configuration') == 1
                and bridge.count('observed_encoded_configuration=bytes.fromhex(lines[13])') == 1
                and bridge.count("shared_word=initializer[0].encode('utf-8')") == 1,
                'initializer-generated inputs')
        runner = (probe_dir / SOURCE / 'run_buffer_probe.py').read_text()
        require(runner.count('threading.Timer(1200, proc.kill)') == 1, 'runner deadline')
        roots = [(probe_dir / SOURCE / ('run' + str(i)) / 'rootfs').resolve() for i in (1, 2)]
        require(roots[0] != roots[1] and all(path.is_dir() for path in roots), 'fresh rootfs')
    require(isinstance(data['interpretation'], str) and data['interpretation'].strip(), 'interpretation')
    return {'calls_verified': 8, 'initializer_field_relations_verified': 8,
            'parent_relation_ledger_preserved': True, 'local_logs_verified': probe_dir is not None,
            'elf_bytes_verified': elf is not None, 'libc_artifact_verified': libc_jar is not None,
            'complete_signer_verified': False, 'online_acceptance_verified': False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, default=Path(__file__).resolve().parents[1] /
                        'evidence' / (NAME + '.json'))
    parser.add_argument('--probe-dir', type=Path)
    parser.add_argument('--elf', type=Path)
    parser.add_argument('--libc-jar', type=Path)
    args = parser.parse_args()
    result = verify(json.loads(args.evidence.read_text()), args.evidence.parent,
                    args.probe_dir, args.elf, args.libc_jar)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
