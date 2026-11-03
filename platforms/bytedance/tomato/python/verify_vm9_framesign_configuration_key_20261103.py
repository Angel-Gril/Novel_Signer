"""Verify the observed twelve-byte SHA-1 preimage driving RC4 and AES material."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import verify_vm9_framesign_configuration_stream_20261103 as prior

block = prior.block
NAME = 'vm9_framesign_configuration_key_20261103'
SOURCE = 'aes_configuration_key_model_probe'
RUN_NAMES = ('run1', 'run3')
RUNNERS = (('run_buffer_probe.py', 420), ('run_buffer_probe_calibrated.py', 1200))
PARENT = prior.NAME + '.json'
OWNERS = prior.OWNERS
STATIC = {
    '0x258798': ('mov', 'x19, x8'),
    '0x2587a0': ('mov', 'w20, w1'),
    '0x2587ac': ('ldr', 'x8, [x0, #0x10]'),
    '0x2587b0': ('ldr', 'w1, [x0, #0xc]'),
    '0x2587b4': ('mov', 'x0, x8'),
    '0x2587b8': ('bl', '#0x2451fc'),
    '0x2587c0': ('tbz', 'w20, #0, #0x2587ec'),
    '0x2587ec': ('mov', 'w0, #0x18'),
    '0x2587f4': ('add', 'x1, sp, #0x10'),
    '0x2587f8': ('mov', 'w2, #0x14'),
    '0x258800': ('bl', '#0x2481fc'),
    '0x25880c': ('bl', '#0x162944'),
    '0x2451a4': ('cmp', 'x9, #0x14'),
    '0x2451ac': ('ubfx', 'x10, x9, #2, #0x1e'),
    '0x2451b4': ('and', 'w11, w11, #0x18'),
    '0x2451bc': ('ldr', 'w10, [x20, x10, lsl #2]'),
    '0x2451c0': ('lsr', 'w10, w10, w11'),
    '0x2451c4': ('strb', 'w10, [x19, x9]'),
    '0x246994': ('mov', 'x0, x24'),
    '0x246998': ('mov', 'x1, x21'),
    '0x24699c': ('mov', 'x2, x23'),
    '0x2469a0': ('bl', '#0x347f60'),
    '0x246c78': ('ldr', 'x8, [x20, #8]'),
    '0x246c7c': ('mov', 'x2, x22'),
    '0x246c80': ('ldr', 'x1, [x21, #8]'),
    '0x246c84': ('add', 'x0, x8, x25'),
    '0x246c88': ('bl', '#0x348410'),
}
CLAIMS = {
    'independent_runs': 2, 'calls': 8, 'SHA1_preimage_length': 12, 'derived_RC4_key_length': 20,
    'native_SHA1_raw_output_observed': True,
    'existing_Python_digest_reference_equals_native_key': True,
    'independent_Java_and_hashlib_SHA1_equal_model': True,
    'RC4_actually_uses_model_derived_key': True,
    'Python_generated_Protobuf_and_AES_material_equal_native': True,
    'captured_RC4_key_used_only_for_comparisons': True,
    'hexadecimal_reversed_and_changed_preimage_keys_rejected': True,
    'current_copy_snapshots_equal_RC4_inputs': True,
    'SHA1_preimage_four_plus_eight_writer_shape_observed': True,
    'SHA1_preimage_equals_reduction_leaves': False,
    'reversed_SHA1_preimage_equals_reduction_leaves': False,
    'SHA1_preimage_and_leaves_have_same_multiset': False,
    'SHA1_preimage_XOR_equals_actual_reduction': False,
    'using_SHA1_preimage_for_reduction_reproduces_Protobuf': False,
    'RC4_data_is_a_direct_earlier_decode_slice': False,
    'complete_prior_relation_ledger_preserved': True,
    'SHA1_preimage_independently_generated': False,
    'RC4_data_independently_generated': False,
    'reduction_leaf_bytes_independently_generated': False,
    'lookup_key_independently_generated': False,
    'earlier_configuration_decryption_identified': False,
    'general_input_equivalence_verified': False, 'android_equivalence_verified': False,
    'complete_standalone_signer_verified': False, 'online_header_acceptance_verified': False,
}
EVENTS = {'ORIGIN_SHA1_INPUT', 'ORIGIN_DECODE_JOIN', 'ORIGIN_COPY_JOIN',
          'ORIGIN_SHA1_JOIN', 'RC4_KEY_REDUCTION', 'RC4_KEY_MODEL'}
INPUTS = ['observed_RC4_input_263_bytes', 'observed_SHA1_preimage_12_bytes',
          'observed_twelve_reduction_leaf_bytes', 'observed_lookup_key_10_bytes',
          'fresh_relocated_ELF_descriptors_and_lookup_table', 'explicit_fixture_allocation_services']
ARTIFACTS = (('HookMain.java', 'source_sha256'), ('classes/HookMain.class', 'entry_class_sha256'),
             ('run_buffer_probe.py', 'runner_sha256'),
             ('run_buffer_probe_calibrated.py', 'calibrated_runner_sha256'),
             ('host_proto_material.py', 'python_bridge_sha256'),
             ('host_decode_material.py', 'decoder_bridge_sha256'),
             ('host_plaintext.py', 'plaintext_bridge_sha256'), ('host_constructor.py', 'constructor_bridge_sha256'))


def parse_key(path: Path) -> list[dict]:
    prior.parse_stream(path)
    rows = []
    for line in path.read_text(encoding='utf-8-sig').splitlines():
        prefix = '[HookMain] FRAME_BUFFER_'
        if not line.startswith(prefix):
            continue
        event, _, attributes = line[len(prefix):].partition(' ')
        if not event.startswith(('ORIGIN_', 'RC4_KEY_')):
            continue
        block.require(event in EVENTS, 'unknown key observation')
        row = {'event': event}
        for token in attributes.split():
            key, value = token.split('=', 1)
            block.require(key not in row, 'duplicate key attribute')
            row[key] = (value == 'true' if value in ('true', 'false') else
                        int(value) if value.lstrip('-').isdecimal() else value)
        rows.append(row)
    return block.ordered(rows)


def expected_key() -> list[dict]:
    rows = []
    for ordinal in range(1, 5):
        def add(event, **values):
            rows.append({'event': event, 'ordinal': ordinal, **values})
        add('ORIGIN_SHA1_INPUT', index=1, length=12, raw_output=True,
            writers=f'libc.so+0x1c148/metasec+0x2469a4/{ordinal}:4,libc.so+0x1c300/metasec+0x246c8c/{ordinal}:8')
        add('ORIGIN_DECODE_JOIN', decoded_length=276, data_length=263, matching_slices=0, matched_offset=-1)
        for role, writers in (('data', f'libc.so+0x1c148/metasec+0x248434/{ordinal}:263'),
                              ('key', f'metasec+0x2451c4/metasec+0x24519c/{ordinal}:20')):
            add('ORIGIN_COPY_JOIN', role=role, record_present=True, current_ordinal=True,
                copied_snapshot_equals_input=True, source_inside_decoder=False, source_writers_at_copy=writers)
        add('ORIGIN_SHA1_JOIN', index=1, input_length=12, raw_output=True, independent_SHA1_equals_RC4_key=True)
        add('RC4_KEY_REDUCTION', length=12, same_order=False, reversed_order=False,
            same_multiset=False, XOR_reductions_equal=False)
        add('RC4_KEY_MODEL', process_exit_code=0, preimage_length=12, derived_length=20,
            existing_Python_SHA1_equals_native_key=True, independent_SHA1_equals_existing=True,
            hexadecimal_key_matches=False, reversed_key_matches=False, changed_preimage_matches=False,
            preimage_reduction_payload_matches=False)
    return block.ordered(rows)


def prior_ledger(evidence_dir: Path, index: int, log: Path | None = None) -> dict:
    return {'stream': prior.parse_stream(log) if log else prior.expected_stream(),
            'earlier_ledger': prior.prior_ledger(evidence_dir, index, log)}


def verify(data: dict, evidence_dir: Path, probe_dir: Path | None = None,
           elf: Path | None = None, libc_jar: Path | None = None) -> dict:
    require = block.require
    same = lambda left, right: block.canonical(left) == block.canonical(right)
    require(set(data) == {'schema', 'evidence_date', 'input', 'parent_evidence', 'owners',
                          'owner_hash_format', 'probe', 'runs', 'static_analysis', 'conclusions',
                          'raw_values_retained', 'operand_digests_retained', 'interpretation'}, 'evidence keys')
    require(data['schema'] == 'vm9-framesign-configuration-key-20261103-v1', 'schema')
    require(data['evidence_date'] == '2026-11-03' and same(data['input'], block.EXPECTED_INPUT), 'date/input')
    require(data['parent_evidence'] == 'evidence/' + PARENT, 'parent')
    require(data['raw_values_retained'] is False and data['operand_digests_retained'] is False, 'privacy')
    require(same(data['conclusions'], CLAIMS), 'unsupported conclusion')
    parent = json.loads((evidence_dir / PARENT).read_text())
    prior.verify(parent, evidence_dir, elf=elf, libc_jar=libc_jar)
    require(data['owner_hash_format'] == 'sha256_bytes_CRLF_normalized_to_LF'
            and set(data['owners']) == set(OWNERS), 'owner contract')
    for owner, digest in data['owners'].items():
        require(prior.prior.owner_sha256(Path(__file__).with_name(owner)) == digest, 'owner identity')
    probe = data['probe']
    identities = tuple(key for _, key in ARTIFACTS)
    require(set(probe) == {*identities, 'source_relative_path', 'read_only_guest_observation',
                          'fresh_rootfs_per_run', 'synthetic_jni_provider_used', 'setup_rounds_per_run',
                          'restore_enabled', 'python_operand_transport', 'model_inputs', 'comparison_only_inputs',
                          'RC4_uses_model_derived_key', 'Python_unpacks_derived_payload',
                          'AES_encrypts_using_model_derived_material', 'run_deadlines_seconds'}, 'probe keys')
    require(probe['source_relative_path'] == SOURCE + '/HookMain.java', 'probe path')
    for key in identities:
        require(isinstance(probe[key], str) and block.HEX_256.fullmatch(probe[key]), 'probe digest')
    for key in ('read_only_guest_observation', 'fresh_rootfs_per_run', 'synthetic_jni_provider_used',
                'RC4_uses_model_derived_key', 'Python_unpacks_derived_payload', 'AES_encrypts_using_model_derived_material'):
        require(probe[key] is True, 'probe scope')
    require(type(probe['setup_rounds_per_run']) is int and probe['setup_rounds_per_run'] == 1
            and probe['restore_enabled'] is False, 'setup/restore')
    require(same(probe['run_deadlines_seconds'], [420, 1200]), 'run deadlines')
    require(probe['python_operand_transport'] == 'private_in_memory_stdin_stdout_pipe'
            and probe['model_inputs'] == INPUTS
            and probe['comparison_only_inputs'] == ['observed_RC4_key_20_bytes'], 'model inputs/comparisons')
    require(isinstance(data['runs'], list) and len(data['runs']) == 2, 'run count')
    for index, run in enumerate(data['runs'], 1):
        require(set(run) == {'local_run_name', 'source_sha256', 'entry_class_sha256', 'native_library_sha256',
                            'python_model_sha256', 'preblock_model_sha256', 'configuration_model_sha256',
                            'process_exit_code', 'sanitized_log_sha256', 'repeat_trials',
                            'key_observations', 'prior_relation_ledger_sha256',
                            'runner_relative_path', 'runner_sha256', 'run_deadline_seconds'}, 'run keys')
        runner, deadline = RUNNERS[index - 1]
        require(run['local_run_name'] == SOURCE + '/' + RUN_NAMES[index - 1]
                and type(run['process_exit_code']) is int and run['process_exit_code'] == 0, 'run terminal')
        require(run['runner_relative_path'] == SOURCE + '/' + runner
                and run['runner_sha256'] == probe['runner_sha256' if index == 1 else 'calibrated_runner_sha256']
                and type(run['run_deadline_seconds']) is int and run['run_deadline_seconds'] == deadline, 'run runner/deadline')
        for key in ('source_sha256', 'entry_class_sha256'):
            require(run[key] == probe[key], 'paired build identity')
        for key in ('native_library_sha256', 'python_model_sha256', 'preblock_model_sha256', 'configuration_model_sha256'):
            require(run[key] == parent['runs'][index - 1][key], 'prior artifact identity')
        require(isinstance(run['sanitized_log_sha256'], str)
                and block.HEX_256.fullmatch(run['sanitized_log_sha256']), 'log digest')
        require(same(run['repeat_trials'], parent['runs'][index - 1]['repeat_trials']), 'changed output')
        require(same(run['key_observations'], expected_key()), 'key relation mismatch')
        expected = prior_ledger(evidence_dir, index)
        require(run['prior_relation_ledger_sha256'] == prior.prior.ledger_sha256(expected), 'prior ledger identity')
        if probe_dir:
            log = probe_dir / run['local_run_name'] / 'sanitized.log'
            require(block.sha256(log) == run['sanitized_log_sha256'], 'local log identity')
            require(same(parse_key(log), expected_key()), 'local key relations')
            require(same(prior_ledger(evidence_dir, index, log), expected), 'complete prior ledger')
            meta = json.loads(log.with_name('metadata.json').read_text())
            require(meta['process_exit_code'] == 0 and meta['read_only_guest_probe'] is True
                    and meta['raw_values_retained'] is False, 'local terminal/privacy')
            for key in ('source_sha256', 'entry_class_sha256', 'native_library_sha256',
                        'python_model_sha256', 'preblock_model_sha256', 'configuration_model_sha256'):
                require(meta[key] == run[key], 'local artifact identity')
    if probe_dir:
        for relative, key in ARTIFACTS:
            require(block.sha256(probe_dir / SOURCE / relative) == probe[key], 'local probe identity')
        original = (probe_dir / SOURCE / RUNNERS[0][0]).read_text()
        calibrated = (probe_dir / SOURCE / RUNNERS[1][0]).read_text()
        require(original.count('threading.Timer(420, proc.kill)') == 1
                and calibrated == original.replace('threading.Timer(420, proc.kill)',
                                                     'threading.Timer(1200, proc.kill)', 1), 'runner deadline-only change')
    static = data['static_analysis']
    require(set(static) == {'native_library_sha256', 'instructions'}
            and static['native_library_sha256'] == block.LIBRARY_SHA256, 'static identity')
    require([row['image_offset'] for row in static['instructions']] == list(STATIC), 'static sites')
    for row in static['instructions']:
        require(set(row) == {'image_offset', 'file_offset', 'bytes_hex', 'mnemonic', 'operands'}
                and (row['mnemonic'], row['operands']) == STATIC[row['image_offset']], 'static contract')
    if elf:
        block.check_elf(elf, static)
    return {'calls_verified': 8, 'key_observations_verified': len(expected_key()) * 2,
            'prior_stream_observations_preserved': len(prior.expected_stream()) * 2,
            'complete_prior_ledger_preserved': True, 'local_logs_verified': probe_dir is not None,
            'elf_bytes_verified': elf is not None, 'libc_artifact_verified': libc_jar is not None,
            'SHA1_preimage_generated_independently': False, 'standalone_signer_verified': False}


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
