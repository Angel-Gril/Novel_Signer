"""Verify FrameSign RC4, reverse/XOR, configuration unpacking and AES linkage."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import verify_vm9_framesign_aes_material_20261103 as prior
from vm9_framesign_configuration import reverse_xor_configuration

block = prior.block
NAME = 'vm9_framesign_configuration_stream_20261103'
SOURCE = 'aes_configuration_stream_verified_probe'
PARENT = prior.NAME + '.json'
MODEL = 'vm9_framesign_configuration.py'
OWNERS = (*prior.OWNERS, 'vm9_stream_cipher.py', MODEL)
STATIC = {
    '0x243cac': ('mov', 'x8, xzr'),
    '0x243d50': ('mov', 'w8, w3'),
    '0x243d58': ('ldp', 'w9, w10, [x0]'),
    '0x243d64': ('add', 'w9, w9, #1'),
    '0x243d68': ('and', 'w9, w9, #0xff'),
    '0x243d6c': ('ldrb', 'w12, [x11, w9, uxtw]'),
    '0x243d74': ('and', 'w10, w10, #0xff'),
    '0x243d7c': ('stp', 'w9, w10, [x0]'),
    '0x243d80': ('strb', 'w13, [x11, w9, uxtw]'),
    '0x243d84': ('strb', 'w12, [x11, w10, uxtw]'),
    '0x243d8c': ('ldrb', 'w10, [x1], #1'),
    '0x243d98': ('ldrb', 'w9, [x11, x12]'),
    '0x243d9c': ('eor', 'w9, w9, w10'),
    '0x243da0': ('strb', 'w9, [x2], #1'),
    '0x243dac': ('sub', 'sp, sp, #0x150'),
    '0x243dec': ('bl', '#0x243cac'),
    '0x243e00': ('bl', '#0x243d50'),
    '0x24841c': ('str', 'x0, [x21, #0x10]'),
    '0x248424': ('ldr', 'x1, [x20, #0x10]'),
    '0x248430': ('bl', '#0x347f60'),
    '0x16a7fc': ('eor', 'x11, x12, x11'),
    '0x16a810': ('str', 'x11, [x28, w13, uxtw #3]'),
    '0x1709cc': ('ldrb', 'w11, [x11, x12]'),
    '0x171c18': ('strb', 'w10, [x11, x9]'),
}
CLAIMS = {
    'independent_runs': 2, 'calls': 8, 'stream_input_length': 263, 'stream_key_length': 20,
    'stream_drop': 0, 'reduction_bytes': 12, 'reduction_initial': 0,
    'existing_Python_RC4_equals_native': True, 'independent_ARC4_equals_existing_model': True,
    'all_263_input_loads_descend_without_gaps': True,
    'reduction_starts_at_observed_zero_operand': True,
    'Python_reverse_XOR_equals_actual_Protobuf_input': True,
    'Python_unpacks_its_own_generated_configuration': True,
    'derived_AES_material_encrypts_actual_native_ciphertext': True,
    'no_reverse_no_XOR_and_wrong_mask_rejected': True,
    'complete_prior_relation_ledger_preserved': True,
    'stream_input_and_key_independently_generated': False,
    'reduction_leaf_bytes_independently_generated': False,
    'lookup_key_independently_generated': False,
    'earlier_configuration_decryption_identified': False,
    'general_input_equivalence_verified': False, 'android_equivalence_verified': False,
    'complete_standalone_signer_verified': False, 'online_header_acceptance_verified': False,
}
EVENTS = {'STREAM_INPUT', 'STREAM_RETURN', 'STREAM_MASK', 'STREAM_MODEL',
          'GLOBAL_KEY_REDUCTION', 'UPSTREAM_ORDER'}


def parse_stream(path: Path) -> list[dict]:
    prior.parse_material(path)
    rows = []
    for line in path.read_text(encoding='utf-8-sig').splitlines():
        prefix = '[HookMain] FRAME_BUFFER_'
        if not line.startswith(prefix):
            continue
        event, _, attributes = line[len(prefix):].partition(' ')
        if event.startswith('STREAM_'):
            block.require(event in EVENTS, 'unknown stream observation')
        if event not in EVENTS:
            continue
        row = {'event': event}
        for token in attributes.split():
            key, value = token.split('=', 1)
            block.require(key not in row, 'duplicate stream attribute')
            row[key] = (value == 'true' if value in ('true', 'false') else
                        int(value) if value.lstrip('-').isdecimal() else value)
        rows.append(row)
    return block.ordered(rows)


def expected_stream() -> list[dict]:
    rows = []
    for ordinal in range(1, 5):
        def add(event, **values):
            rows.append({'event': event, 'ordinal': ordinal, **values})
        add('STREAM_INPUT', length=263, key_length=20, drop=0,
            source_writers=f'libc.so+0x1c148/metasec+0x248258/{ordinal}:263',
            key_writers=f'libc.so+0x1c148/metasec+0x248258/{ordinal}:20')
        add('STREAM_RETURN', length=263, calls=1, source_equals_output=False)
        add('STREAM_MASK', leaves=12, initial_zero=True)
        add('STREAM_MODEL', process_exit_code=0, existing_Python_RC4_equals_native=True,
            Python_reverse_XOR_equals_protobuf=True, independent_RC4_equals_existing=True,
            no_reverse_matches=False, no_xor_matches=False, wrong_mask_matches=False)
        add('GLOBAL_KEY_REDUCTION', leaves=12, initial_operand_captured=True, initial_zero=True,
            xor_leaf_bytes_equals_key=True, initial_and_leaf_xor_equals_key=True,
            initial_writer='metasec+0x16db74', initial_bcp='metasec+0x9af00')
        add('UPSTREAM_ORDER', length=263, descending_reads=263, distinct_reads=263, source_span=263)
    return block.ordered(rows)


def prior_ledger(evidence_dir: Path, index: int, log: Path | None = None) -> dict:
    return {'material': prior.parse_material(log) if log else prior.expected_material(),
            'earlier_ledger': prior.prior_ledger(evidence_dir, index, log)}


def verify(data: dict, evidence_dir: Path, probe_dir: Path | None = None,
           elf: Path | None = None, libc_jar: Path | None = None) -> dict:
    require = block.require
    same = lambda left, right: block.canonical(left) == block.canonical(right)
    require(set(data) == {'schema', 'evidence_date', 'input', 'parent_evidence', 'owners',
                          'owner_hash_format', 'probe', 'runs', 'static_analysis', 'conclusions',
                          'raw_values_retained', 'operand_digests_retained', 'interpretation'}, 'evidence keys')
    require(data['schema'] == 'vm9-framesign-configuration-stream-20261103-v1', 'schema')
    require(data['evidence_date'] == '2026-11-03' and same(data['input'], block.EXPECTED_INPUT), 'date/input')
    require(data['parent_evidence'] == 'evidence/' + PARENT, 'parent')
    require(data['raw_values_retained'] is False and data['operand_digests_retained'] is False, 'privacy')
    require(same(data['conclusions'], CLAIMS), 'unsupported conclusion')
    parent = json.loads((evidence_dir / PARENT).read_text())
    prior.verify(parent, evidence_dir, elf=elf, libc_jar=libc_jar)
    require(data['owner_hash_format'] == 'sha256_bytes_CRLF_normalized_to_LF'
            and set(data['owners']) == set(OWNERS), 'owner contract')
    for owner, digest in data['owners'].items():
        require(prior.owner_sha256(Path(__file__).with_name(owner)) == digest, 'owner identity')
    probe = data['probe']
    identities = ('source_sha256', 'entry_class_sha256', 'runner_sha256', 'python_bridge_sha256',
                  'decoder_bridge_sha256', 'plaintext_bridge_sha256', 'constructor_bridge_sha256')
    require(set(probe) == {*identities, 'source_relative_path', 'read_only_guest_observation',
                          'fresh_rootfs_per_run', 'synthetic_jni_provider_used', 'setup_rounds_per_run',
                          'restore_enabled', 'python_operand_transport', 'model_inputs',
                          'Python_unpacks_derived_payload', 'AES_encrypts_using_model_derived_material',
                          'run_deadline_seconds'}, 'probe keys')
    require(probe['source_relative_path'] == SOURCE + '/HookMain.java', 'probe path')
    for key in identities:
        require(isinstance(probe[key], str) and block.HEX_256.fullmatch(probe[key]), 'probe digest')
    for key in ('read_only_guest_observation', 'fresh_rootfs_per_run', 'synthetic_jni_provider_used',
                'Python_unpacks_derived_payload', 'AES_encrypts_using_model_derived_material'):
        require(probe[key] is True, 'probe scope')
    require(type(probe['setup_rounds_per_run']) is int and probe['setup_rounds_per_run'] == 1
            and probe['restore_enabled'] is False, 'setup/restore')
    require(type(probe['run_deadline_seconds']) is int and probe['run_deadline_seconds'] == 420, 'run deadline')
    require(probe['python_operand_transport'] == 'private_in_memory_stdin_stdout_pipe'
            and probe['model_inputs'] == ['observed_RC4_input_263_bytes', 'observed_RC4_key_20_bytes',
                'observed_twelve_reduction_leaf_bytes', 'observed_lookup_key_10_bytes',
                'fresh_relocated_ELF_descriptors_and_lookup_table', 'explicit_fixture_allocation_services'], 'model inputs')
    require(isinstance(data['runs'], list) and len(data['runs']) == 2, 'run count')
    for index, run in enumerate(data['runs'], 1):
        require(set(run) == {'local_run_name', 'source_sha256', 'entry_class_sha256', 'native_library_sha256',
                            'python_model_sha256', 'preblock_model_sha256', 'configuration_model_sha256',
                            'process_exit_code', 'sanitized_log_sha256', 'repeat_trials',
                            'stream_observations', 'prior_relation_ledger_sha256'}, 'run keys')
        require(run['local_run_name'] == SOURCE + f'/run{index}'
                and type(run['process_exit_code']) is int and run['process_exit_code'] == 0, 'run terminal')
        for key in ('source_sha256', 'entry_class_sha256'):
            require(run[key] == probe[key], 'paired build identity')
        for key in ('native_library_sha256', 'python_model_sha256', 'preblock_model_sha256'):
            require(run[key] == parent['runs'][index - 1][key], 'prior artifact identity')
        require(run['configuration_model_sha256'] == data['owners'][MODEL], 'configuration model identity')
        require(isinstance(run['sanitized_log_sha256'], str)
                and block.HEX_256.fullmatch(run['sanitized_log_sha256']), 'log digest')
        require(same(run['repeat_trials'], parent['runs'][index - 1]['repeat_trials']), 'changed output')
        require(same(run['stream_observations'], expected_stream()), 'stream relation mismatch')
        expected = prior_ledger(evidence_dir, index)
        require(run['prior_relation_ledger_sha256'] == prior.ledger_sha256(expected), 'prior ledger identity')
        if probe_dir:
            log = probe_dir / run['local_run_name'] / 'sanitized.log'
            require(block.sha256(log) == run['sanitized_log_sha256'], 'local log identity')
            require(same(parse_stream(log), expected_stream()), 'local stream relations')
            require(same(prior_ledger(evidence_dir, index, log), expected), 'complete prior ledger')
            meta = json.loads(log.with_name('metadata.json').read_text())
            require(meta['process_exit_code'] == 0 and meta['read_only_guest_probe'] is True
                    and meta['raw_values_retained'] is False, 'local terminal/privacy')
            for key in ('source_sha256', 'entry_class_sha256', 'native_library_sha256',
                        'python_model_sha256', 'preblock_model_sha256', 'configuration_model_sha256'):
                require(meta[key] == run[key], 'local artifact identity')
    if probe_dir:
        for relative, key in (('HookMain.java', 'source_sha256'), ('classes/HookMain.class', 'entry_class_sha256'),
                              ('run_buffer_probe.py', 'runner_sha256'), ('host_proto_material.py', 'python_bridge_sha256'),
                              ('host_decode_material.py', 'decoder_bridge_sha256'), ('host_plaintext.py', 'plaintext_bridge_sha256'),
                              ('host_constructor.py', 'constructor_bridge_sha256')):
            require(block.sha256(probe_dir / SOURCE / relative) == probe[key], 'local probe identity')
    static = data['static_analysis']
    require(set(static) == {'native_library_sha256', 'instructions'}
            and static['native_library_sha256'] == block.LIBRARY_SHA256, 'static identity')
    require([row['image_offset'] for row in static['instructions']] == list(STATIC), 'static sites')
    for row in static['instructions']:
        require(set(row) == {'image_offset', 'file_offset', 'bytes_hex', 'mnemonic', 'operands'}
                and (row['mnemonic'], row['operands']) == STATIC[row['image_offset']], 'static contract')
    if elf:
        block.check_elf(elf, static)
    require(reverse_xor_configuration(b'a' * 131 + b'\x09' + b'b' * 131, b'\x5a' + bytes(11))
            == b'8' * 131 + b'S' + b';' * 131, 'synthetic model vector')
    return {'calls_verified': 8, 'stream_observations_verified': len(expected_stream()) * 2,
            'prior_material_observations_preserved': len(prior.expected_material()) * 2,
            'complete_prior_ledger_preserved': True, 'local_logs_verified': probe_dir is not None,
            'elf_bytes_verified': elf is not None, 'libc_artifact_verified': libc_jar is not None,
            'upstream_configuration_decryption_verified': False, 'standalone_signer_verified': False}


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
