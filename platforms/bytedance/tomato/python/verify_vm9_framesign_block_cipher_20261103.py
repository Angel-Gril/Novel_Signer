"""Verify the captured FrameSign XTEA stage, prefix XOR and pointer suffix."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from verify_vm9_framesign_seed_allocation_20261103 import (
    BUFFER, EXPECTED_INPUT, HEX_256, LIBRARY_SHA256, STATIC as SEED_STATIC,
    canonical, check_elf, expected_aes, expected_layout, expected_seed, ordered,
    parse_aes, parse_edges, parse_layout, parse_log, parse_observations, parse_seed,
    require, sha256, verify as verify_seed,
)
from vm9_framesign_block_cipher import observed_plaintext, xtea_cbc

NAME = 'vm9_framesign_block_cipher_20261103'
SOURCE = 'block_cipher_stage_probe'
PARENT = 'vm9_framesign_seed_allocation_20261103.json'
MODEL = 'vm9_framesign_block_cipher.py'
STATIC = {**SEED_STATIC,
    '0x16d870': ('ldr', 'x15, [x28, x11, lsl #3]'),
    '0x16d894': ('add', 'x15, x15, w12, sxth'),
    '0x16d8a4': ('str', 'x15, [x28, x10, lsl #3]'),
    '0x171238': ('ldr', 'x17, [x28, x13, lsl #3]'),
    '0x171240': ('ldr', 'x15, [x28, x14, lsl #3]'),
    '0x171248': ('sxth', 'x16, w11'),
    '0x171268': ('str', 'x15, [x17, x16]'),
    '0x16e5c4': ('ldr', 'x15, [x28, x11, lsl #3]'),
    '0x16e5e0': ('and', 'x10, x12, #0xffff'),
    '0x16e5e4': ('eor', 'x10, x15, x10'),
    '0x16e610': ('str', 'x10, [x28, x14, lsl #3]'),
    '0x170a00': ('str', 'x11, [x28, x14, lsl #3]'),
}
CLAIMS = {
    'independent_runs': 2, 'calls': 8, 'blocks_per_call': 11,
    'native_blocks_matched': 88, 'xtea_rounds': 32,
    'data_word_order': 'big', 'key_word_order': 'little',
    'cbc_chain_verified': True, 'initial_feedback_is_zero': False,
    'prefix_xor_from_first_ciphertext_byte_verified': True,
    'suffix_is_initial_feedback_pointer_low32_little_endian': True,
    'suffix_pointer_ADD64_IMM16_dependency_verified': True,
    'initial_feedback_prefix_equals_suffix': True,
    'python_93_byte_model_with_observed_inputs_verified': True,
    'complete_prior_ledger_preserved': True,
    'key_generation_identified': False, 'complete_feedback_generation_identified': False,
    'allocator_reuse_policy_identified': False, 'general_input_equivalence_verified': False,
    'android_equivalence_verified': False, 'complete_standalone_signer_verified': False,
    'online_header_acceptance_verified': False,
}
EVENTS = {'XTEA_SOURCE', 'XTEA_BLOCK', 'XTEA_JOIN', 'XTEA_COMPARE', 'XTEA_SUFFIX_RELATION',
          'SUFFIX_SOURCE', 'SUFFIX_STORE_LINK', 'BLOCK_JOIN',
          'CIPHER_SUFFIX_DEFINITION', 'CIPHER_FEEDBACK_ASSEMBLY', 'CIPHER_SUFFIX_LINK',
          'CIPHER_PREFIX_DEFINITION', 'CIPHER_PREFIX_SOURCE', 'CIPHER_PREFIX_XOR',
          'CIPHER_PYTHON_LINK', 'CIPHER_PLAINTEXT_LINK'}


def parse_cipher(path: Path) -> list[dict]:
    rows = []
    for line in path.read_text(encoding='utf-8-sig').splitlines():
        prefix = '[HookMain] FRAME_BUFFER_'
        if not line.startswith(prefix):
            continue
        event, _, attributes = line[len(prefix):].partition(' ')
        require(event not in ('ERROR', 'CONSTRUCTOR_WRITE_ERROR'), 'probe observation error')
        if event.startswith(('CIPHER_', 'XTEA_')):
            require(event in EVENTS, 'unknown cipher observation')
        if event not in EVENTS:
            continue
        row = {'event': event}
        for token in attributes.split():
            key, value = token.split('=', 1)
            require(key not in row, 'duplicate cipher attribute')
            row[key] = (value == 'true' if value in ('true', 'false') else
                        int(value) if value.lstrip('-').isdecimal() else value)
        rows.append(row)
    return ordered(rows)


def expected_cipher() -> list[dict]:
    rows = []
    for ordinal in range(1, 5):
        def add(event, **values):
            rows.append({'event': event, 'ordinal': ordinal, **values})
        for block in range(11):
            add('XTEA_SOURCE', block=block, key_length=16, feedback_length=8,
                key_writers=f'metasec+0x17208c/outside_modules/{ordinal}:16',
                feedback_writers=(f'metasec+0x276e18/metasec+0x268538/{ordinal}:4,'
                                  f'metasec+0x276e38/metasec+0x268538/{ordinal}:4' if block == 0 else
                                  f'metasec+0x276c38/metasec+0x276c38/{ordinal}:8'))
            add('XTEA_BLOCK', block=block, length=8, rounds=32, standard_delta=True,
                key_equals_first=True, feedback_equals_previous_output=block > 0,
                xor_feedback_equals_mix=True, xtea_be_data_le_key_matches=True,
                xtea_le_data_matches=False, xtea_be_key_matches=False,
                no_feedback_matches=False, fewer_rounds_matches=False,
                independent_chain_equals_emitted=True)
        add('XTEA_JOIN', length=88, independent_chain_equals_copy_source=True, initial_feedback_zero=False)
        add('BLOCK_JOIN', length=88, all_emitted_equal_copy_source=True)
        for previous in range(1, ordinal):
            add('XTEA_COMPARE', previous_ordinal=previous, key_equal=True, initial_feedback_equal=True)
        add('XTEA_SUFFIX_RELATION', stored_value_equals_feedback_pointer=True)
        add('SUFFIX_SOURCE', length=4, store_record_present=True, store_bcp='metasec+0xa0a40',
            value_slot=21, operand_register_matches=True, source_writer='metasec+0x16d8a4',
            source_bcp='metasec+0xa0a14', source_writer_ordinal=ordinal)
        add('SUFFIX_STORE_LINK', source_equals_stored_low_four=True)
        add('CIPHER_SUFFIX_DEFINITION', store_bcp='metasec+0xa0a40', store_width=8, value_slot=21,
            definition_present=True, operation='ADD64_IMM16', definition_bcp='metasec+0xa0a14',
            source_slot=29, destination_slot=21, architectural_result_matches=True, result_equals_store_operand=True)
        add('CIPHER_FEEDBACK_ASSEMBLY', length=8, copy9_length=4, copy10_length=4,
            copy9_destination_equals_feedback=True, copy10_destination_follows_copy9=True,
            copy9_equals_feedback_pointer_le32=True, copies_equal_initial_feedback=True,
            suffix_definition_equals_feedback_pointer=True)
        add('CIPHER_SUFFIX_LINK', length=4, source_equals_copy9_source=True, bytes_equal_copy9=True,
            feedback_pointer_le32_matches=True, feedback_pointer_be32_matches=False,
            equals_initial_feedback_prefix=True)
        add('CIPHER_PREFIX_DEFINITION', source_writer='metasec+0x16e610', source_bcp='metasec+0xa0bcc',
            operation='XOR64_IMM16', preblock_prefix_equal=False)
        add('CIPHER_PREFIX_SOURCE', store_present=True, store_bcp='metasec+0xa0bd0', value_slot=2,
            register_equals_store_operand=True, stored_byte_equals_prefix=True, prefix_equals_preblock_byte=False)
        add('CIPHER_PREFIX_XOR', operation='XOR64_IMM16', bcp='metasec+0xa0bcc', source_slot=2,
            destination_slot=2, architectural_result_matches=True, input_low_equals_first_ciphertext_byte=True,
            result_low_equals_prefix=True, source_writer='metasec+0x170a00', source_bcp='metasec+0xa0bc8')
        add('CIPHER_PYTHON_LINK', length=93, process_exit_code=0, python_equals_constructor=True, python_equals_aes_data=True)
        add('CIPHER_PLAINTEXT_LINK', length=93, independent_layout_equals_constructor=True,
            independent_layout_equals_aes_data=True, prefix_equals_first_ciphertext_byte=False)
    return ordered(rows)


def check_model() -> None:
    # Public all-zero XTEA vector; this checks the primitive without a target key.
    require(xtea_cbc(bytes(8), bytes(16), bytes(8)).hex() == 'dee9d4d8f7131ed9', 'XTEA zero vector')
    controls = [
        lambda: xtea_cbc(b'', bytes(16), bytes(8)),
        lambda: xtea_cbc(bytes(7), bytes(16), bytes(8)),
        lambda: xtea_cbc(bytearray(8), bytes(16), bytes(8)),
        lambda: xtea_cbc(bytes(8), bytes(15), bytes(8)),
        lambda: xtea_cbc(bytes(8), bytes(16), bytes(7)),
        lambda: xtea_cbc(bytes(0x100008), bytes(16), bytes(8)),
        lambda: observed_plaintext(bytes(80), bytes(16), bytes(8), 1, 0),
        lambda: observed_plaintext(bytes(88), bytes(16), bytes(8), True, 0),
        lambda: observed_plaintext(bytes(88), bytes(16), bytes(8), 0, 0),
        lambda: observed_plaintext(bytes(88), bytes(16), bytes(8), 1 << 64, 0),
        lambda: observed_plaintext(bytes(88), bytes(16), bytes(8), 1, -1),
        lambda: observed_plaintext(bytes(88), bytes(16), bytes(8), 1, 1 << 16),
    ]
    for control in controls:
        try:
            control()
        except ValueError:
            continue
        raise AssertionError('model accepted an invalid operand')


def verify(data: dict, evidence_dir: Path, probe_dir: Path | None = None,
           elf: Path | None = None, libc_jar: Path | None = None) -> dict:
    require(set(data) == {'schema', 'evidence_date', 'input', 'parent_evidence', 'probe', 'runs',
                         'static_analysis', 'conclusions', 'raw_values_retained', 'operand_digests_retained',
                         'interpretation'}, 'evidence keys')
    require(data['schema'] == 'vm9-framesign-block-cipher-20261103-v1', 'schema')
    require(data['evidence_date'] == '2026-11-03' and data['input'] == EXPECTED_INPUT, 'date/input')
    require(data['parent_evidence'] == 'evidence/' + PARENT, 'parent')
    require(data['raw_values_retained'] is False and data['operand_digests_retained'] is False, 'raw values/digests')
    require(canonical(data['conclusions']) == canonical(CLAIMS), 'unsupported conclusion')
    parent = json.loads((evidence_dir / PARENT).read_text())
    verify_seed(parent, evidence_dir, elf=elf, libc_jar=libc_jar)
    baseline = json.loads((evidence_dir / BUFFER).read_text())['runs'][0]['repeat_trials']
    fields = [{'ordinal': r['ordinal'], 'fields': r['fields']} for r in baseline]
    probe = data['probe']
    require(set(probe) == {'source_relative_path', 'source_sha256', 'entry_class_sha256', 'runner_sha256',
                          'python_bridge_sha256', 'python_model_relative_path', 'python_model_sha256',
                          'read_only_guest_observation', 'synthetic_jni_provider_used', 'fresh_rootfs_per_run',
                          'setup_rounds_per_run', 'restore_enabled', 'comparison_scope', 'return_observation_scope',
                          'python_operand_transport'}, 'probe keys')
    require(probe['source_relative_path'] == SOURCE + '/HookMain.java'
            and probe['python_model_relative_path'] == 'python/' + MODEL, 'source/model paths')
    for key in ('source_sha256', 'entry_class_sha256', 'runner_sha256', 'python_bridge_sha256', 'python_model_sha256'):
        require(isinstance(probe[key], str) and HEX_256.fullmatch(probe[key]), 'probe digest')
    require(sha256(Path(__file__).with_name(MODEL)) == probe['python_model_sha256'], 'Python model identity')
    for key in ('read_only_guest_observation', 'synthetic_jni_provider_used', 'fresh_rootfs_per_run'):
        require(probe[key] is True, 'probe scope')
    require(type(probe['setup_rounds_per_run']) is int and probe['setup_rounds_per_run'] == 1
            and probe['restore_enabled'] is False, 'setup/restore')
    require(probe['comparison_scope'] == 'within_each_four_call_run'
            and probe['return_observation_scope'] == 'same_dispatcher_stack_pointer_after_callback'
            and probe['python_operand_transport'] == 'private_in_memory_stdin_stdout_pipe', 'observation scope')
    require(isinstance(data['runs'], list) and len(data['runs']) == 2, 'run count')
    expected = expected_cipher()
    for index, run in enumerate(data['runs'], 1):
        require(set(run) == {'local_run_name', 'source_sha256', 'entry_class_sha256', 'native_library_sha256',
                            'python_model_sha256', 'process_exit_code', 'sanitized_log_sha256',
                            'repeat_trials', 'cipher_observations'}, 'run keys')
        require(run['local_run_name'] == SOURCE + f'/run{index}' and type(run['process_exit_code']) is int
                and run['process_exit_code'] == 0, 'run terminal')
        require(run['native_library_sha256'] == LIBRARY_SHA256 and isinstance(run['sanitized_log_sha256'], str)
                and HEX_256.fullmatch(run['sanitized_log_sha256']), 'run identity')
        for key in ('source_sha256', 'entry_class_sha256', 'python_model_sha256'):
            require(run[key] == probe[key], 'paired build identity')
        require(canonical(run['repeat_trials']) == canonical(fields), 'changed output')
        require(canonical(run['cipher_observations']) == canonical(expected), 'cipher relation mismatch')
        if probe_dir:
            log = probe_dir / run['local_run_name'] / 'sanitized.log'
            require(sha256(log) == run['sanitized_log_sha256'], 'local log identity')
            require(parse_cipher(log) == expected, 'local cipher relations')
            require(parse_seed(log) == expected_seed() and parse_layout(log) == expected_layout(), 'seed/layout ledger')
            require(parse_log(log) == baseline and parse_aes(log) == expected_aes(), 'complete baseline/AES')
            composition = json.loads((evidence_dir / 'vm9_framesign_preimage_composition_20261103.json').read_text())
            require(parse_observations(log) == composition['runs'][index - 1]['composition_observations']
                    and parse_edges(log) == composition['runs'][index - 1]['sha256_edges'], 'preimage/SHA-256')
            meta = json.loads(log.with_name('metadata.json').read_text())
            require(meta['process_exit_code'] == 0 and meta['read_only_guest_probe'] is True
                    and meta['raw_values_retained'] is False, 'local terminal/scope')
            for key in ('source_sha256', 'entry_class_sha256', 'native_library_sha256', 'python_model_sha256'):
                require(meta[key] == run[key], 'local build identity')
    if probe_dir:
        for relative, key in (('HookMain.java', 'source_sha256'), ('classes/HookMain.class', 'entry_class_sha256'),
                              ('run_buffer_probe.py', 'runner_sha256'), ('host_plaintext.py', 'python_bridge_sha256')):
            require(sha256(probe_dir / SOURCE / relative) == probe[key], 'local probe identity')
    static = data['static_analysis']
    require(set(static) == {'native_library_sha256', 'instructions'}
            and static['native_library_sha256'] == LIBRARY_SHA256, 'static identity')
    require([r['image_offset'] for r in static['instructions']] == list(STATIC), 'static sites')
    for row in static['instructions']:
        require(set(row) == {'image_offset', 'file_offset', 'bytes_hex', 'mnemonic', 'operands'}
                and (row['mnemonic'], row['operands']) == STATIC[row['image_offset']], 'static contract')
    if elf:
        check_elf(elf, static)
    check_model()
    return {'recorded_calls_verified': 8, 'native_blocks_matched': 88, 'cipher_observations_verified': len(expected) * 2,
            'python_plaintext_stage_verified': True, 'complete_baseline_preserved': True,
            'model_invalid_inputs_rejected': 12, 'local_logs_verified': probe_dir is not None,
            'elf_bytes_verified': elf is not None, 'libc_artifact_verified': libc_jar is not None,
            'android_equivalence_verified': False, 'standalone_signer_verified': False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, default=Path(__file__).resolve().parents[1] / 'evidence' / (NAME + '.json'))
    parser.add_argument('--probe-dir', type=Path)
    parser.add_argument('--elf', type=Path)
    parser.add_argument('--libc-jar', type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(json.loads(args.evidence.read_text()), args.evidence.parent, args.probe_dir, args.elf, args.libc_jar), sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
