"""Verify the FrameSign CRC16 and allocator-derived pre-block composition."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import verify_vm9_framesign_block_inputs_20261103 as inputs
from vm9_framesign_preblock import crc16_xmodem, observed_preblock

block = inputs.block
NAME = 'vm9_framesign_preblock_20261103'
SOURCE = 'preblock_allocation_probe'
MODEL = 'vm9_framesign_preblock.py'
PARENT = inputs.NAME + '.json'
STATIC = {
    '0x258b94': ('ldr', 'x8, [x0, #0x10]'),
    '0x258b98': ('ldr', 'w1, [x0, #0xc]'),
    '0x258b9c': ('mov', 'x0, x8'),
    '0x258ba0': ('bl', '#0x24b25c'),
    '0x24b25c': ('cmp', 'w1, #0'),
    '0x24b260': ('adrp', 'x10, #0x95000'),
    '0x24b268': ('mov', 'w0, wzr'),
    '0x24b26c': ('csel', 'w9, w1, wzr, gt'),
    '0x24b270': ('add', 'x10, x10, #0xf44'),
    '0x24b278': ('ldrb', 'w11, [x8], #1'),
    '0x24b27c': ('ubfx', 'w12, w0, #8, #8'),
    '0x24b284': ('eor', 'x11, x11, x12'),
    '0x24b288': ('ldrh', 'w11, [x10, x11, lsl #1]'),
    '0x24b28c': ('eor', 'w0, w11, w0, lsl #8'),
    '0x24b290': ('cbnz', 'w9, #0x24b278'),
    '0x268554': ('strh', 'w0, [x19, #0x10]'),
    '0x171e64': ('strh', 'w11, [x13, x10]'),
    '0x17208c': ('str', 'w11, [x12, x10]'),
    '0x246c88': ('bl', '#0x348410'),
}
CLAIMS = {
    'independent_runs': 2, 'calls': 8, 'component_length': 76, 'preblock_length': 88,
    'crc_algorithm': 'CRC16/XMODEM', 'crc_polynomial': '0x1021', 'crc_initial': 0,
    'crc_reflected': False, 'crc_final_xor': 0, 'crc_covers_exact_component': True,
    'crc_written_high_byte_then_low_byte_at_offsets_1_2': True,
    'three_byte_header_equals_allocation_low_three_little_endian': True,
    'retained_header_is_allocation_byte2_at_offset3': True,
    'seed_uses_existing_calloc_expression': True, 'zero_tail_length': 8,
    'component_72_byte_append_at_offset4_observed': True,
    'Python_assembles_preblock_before_actual_encryption': True,
    'Python_93_bytes_equal_native_constructor_and_AES_input': True,
    'four_wrong_compositions_or_CRC_candidates_rejected_per_call': True,
    'complete_prior_ledger_preserved': True,
    'component_generation_identified': False, 'seed_operands_fully_generated': False,
    'AES_key_and_IV_generation_identified': False,
    'allocator_reuse_policy_identified': False, 'general_input_equivalence_verified': False,
    'android_equivalence_verified': False, 'complete_standalone_signer_verified': False,
    'online_header_acceptance_verified': False,
}
EVENTS = {'COPY', 'SOURCE_WRITER', 'APPEND', 'CRC_CALL', 'CRC_RETURN', 'CRC_BYTE',
          'SEED', 'HEADER_SOURCE', 'HEADER_ALLOCATION', 'NEGATIVE', 'JOIN'}


def parse_preblock(path: Path) -> list[dict]:
    block.parse_cipher(path)
    rows = []
    prefix = '[HookMain] FRAME_BUFFER_PREBUILD_'
    for line in path.read_text(encoding='utf-8-sig').splitlines():
        if not line.startswith(prefix):
            continue
        event, _, attributes = line[len(prefix):].partition(' ')
        block.require(event in EVENTS, 'unknown pre-block observation')
        row = {'event': event}
        for token in attributes.split():
            key, value = token.split('=', 1)
            block.require(key not in row, 'duplicate pre-block attribute')
            row[key] = (value == 'true' if value in ('true', 'false') else
                        int(value) if value.lstrip('-').isdecimal() else value)
        rows.append(row)
    return block.ordered(rows)


def expected_preblock() -> list[dict]:
    rows = []
    for ordinal in range(1, 5):
        def add(event, **values):
            rows.append({'event': event, 'ordinal': ordinal, **values})
        for index, length, offset in ((3, 3, 1), (4, 76, 4), (5, 8, 80), (6, 1, 1), (7, 1, 2)):
            add('COPY', index=index, length=length, destination_offset=offset,
                source_equals_destination=index == 5)
        for index, count, writer, bcp in ((3, 3, 'metasec+0x17208c', 'metasec+0xa065c'),
                                         (5, 8, 'libc.so+0x1c640', 'outside_modules'),
                                         (6, 1, 'metasec+0x171e64', 'metasec+0xa0738'),
                                         (7, 1, 'metasec+0x171e64', 'metasec+0xa0738')):
            for offset in range(count):
                add('SOURCE_WRITER', index=index, offset=offset, writer=writer, bcp=bcp)
        add('APPEND', offset=4, length=72, snapshot_equals_component_slice=True)
        add('CRC_CALL', length=76, input_equals_component=True)
        add('CRC_RETURN', return_register_equals_slot=True, xmodem_equals_native=True)
        for index in (6, 7):
            add('CRC_BYTE', index=index, equals_crc_high=index == 6, equals_crc_low=index == 7)
        add('SEED', existing_calloc_expression_equals_preblock=True)
        add('HEADER_SOURCE', record_present=True, value_slot=3,
            source_writer='metasec+0x16f974', source_bcp='metasec+0xa0614')
        add('HEADER_ALLOCATION', store_value_equals_allocation_low32=True,
            copied_three_equal_allocation_low_three=True, retained_byte_equals_allocation_byte2=True)
        add('NEGATIVE', little_endian_crc_matches=False, original_three_header_bytes_match=False,
            crc_initial_ffff_matches=False, crc_other_polynomial_matches=False)
        add('JOIN', length=88, replay_equals_preblock=True, component_slice_equal=True,
            final_header_byte_equal=True, tail_zero=True, prefix_crc_big_endian=True)
    return block.ordered(rows)


def check_model() -> None:
    block.require(crc16_xmodem(b'123456789') == 0x31C3 and crc16_xmodem(b'') == 0, 'CRC known vectors')
    # Public synthetic control: boundaries and independent address-byte influence.
    component = bytes(range(76))
    result = observed_preblock(component, 1, 0, 0)
    shifted = observed_preblock(component, 1 + (1 << 16), 0, 0)
    block.require(len(result) == 88 and result[4:80] == component and result[80:] == bytes(8)
                  and [i for i, pair in enumerate(zip(result, shifted)) if pair[0] != pair[1]] == [3],
                  'synthetic composition boundary')


def verify(data: dict, evidence_dir: Path, probe_dir: Path | None = None,
           elf: Path | None = None, libc_jar: Path | None = None) -> dict:
    require = block.require
    require(set(data) == {'schema', 'evidence_date', 'input', 'parent_evidence', 'probe', 'runs',
                          'static_analysis', 'conclusions', 'raw_values_retained',
                          'operand_digests_retained', 'interpretation'}, 'evidence keys')
    require(data['schema'] == 'vm9-framesign-preblock-20261103-v1', 'schema')
    require(data['evidence_date'] == '2026-11-03' and data['input'] == block.EXPECTED_INPUT, 'date/input')
    require(data['parent_evidence'] == 'evidence/' + PARENT, 'parent')
    require(data['raw_values_retained'] is False and data['operand_digests_retained'] is False, 'raw values/digests')
    require(block.canonical(data['conclusions']) == block.canonical(CLAIMS), 'unsupported conclusion')
    parent = json.loads((evidence_dir / PARENT).read_text())
    inputs.verify(parent, evidence_dir, elf=elf, libc_jar=libc_jar)
    check_model()
    probe = data['probe']
    identity_keys = ('source_sha256', 'entry_class_sha256', 'runner_sha256', 'python_bridge_sha256',
                     'constructor_bridge_sha256', 'preblock_model_sha256')
    require(set(probe) == {*identity_keys, 'source_relative_path', 'model_relative_path',
                          'read_only_guest_observation', 'fresh_rootfs_per_run', 'synthetic_jni_provider_used',
                          'setup_rounds_per_run', 'restore_enabled', 'python_operand_transport',
                          'remaining_observed_algorithm_inputs'}, 'probe keys')
    require(probe['source_relative_path'] == SOURCE + '/HookMain.java'
            and probe['model_relative_path'] == 'python/' + MODEL, 'source/model path')
    for key in identity_keys:
        require(isinstance(probe[key], str) and block.HEX_256.fullmatch(probe[key]), 'probe digest')
    require(block.sha256(Path(__file__).with_name(MODEL)) == probe['preblock_model_sha256'], 'model identity')
    for key in ('read_only_guest_observation', 'fresh_rootfs_per_run', 'synthetic_jni_provider_used'):
        require(probe[key] is True, 'probe scope')
    require(type(probe['setup_rounds_per_run']) is int and probe['setup_rounds_per_run'] == 1
            and probe['restore_enabled'] is False, 'setup/restore')
    require(probe['python_operand_transport'] == 'private_in_memory_stdin_stdout_pipe'
            and probe['remaining_observed_algorithm_inputs'] ==
            ['component_76_bytes', 'calloc_pointer', 'seed_mask', 'seed_right_operand',
             'feedback_pointer', 'prefix_xor_immediate'], 'model inputs/scope')
    require(isinstance(data['runs'], list) and len(data['runs']) == 2, 'run count')
    for index, run in enumerate(data['runs'], 1):
        require(set(run) == {'local_run_name', 'source_sha256', 'entry_class_sha256', 'native_library_sha256',
                            'python_model_sha256', 'preblock_model_sha256', 'process_exit_code',
                            'sanitized_log_sha256', 'repeat_trials', 'preblock_observations',
                            'cipher_observations', 'input_observations'}, 'run keys')
        require(run['local_run_name'] == SOURCE + f'/run{index}' and type(run['process_exit_code']) is int
                and run['process_exit_code'] == 0, 'run terminal')
        for key in ('source_sha256', 'entry_class_sha256', 'preblock_model_sha256'):
            require(run[key] == probe[key], 'paired build identity')
        require(run['native_library_sha256'] == block.LIBRARY_SHA256
                and run['python_model_sha256'] == parent['runs'][index - 1]['python_model_sha256'], 'run artifacts')
        require(isinstance(run['sanitized_log_sha256'], str) and block.HEX_256.fullmatch(run['sanitized_log_sha256']), 'log digest')
        require(run['repeat_trials'] == parent['runs'][index - 1]['repeat_trials'], 'changed output')
        require(run['preblock_observations'] == expected_preblock()
                and run['cipher_observations'] == block.expected_cipher()
                and run['input_observations'] == inputs.expected_inputs(), 'observation mismatch')
        if probe_dir:
            log = probe_dir / run['local_run_name'] / 'sanitized.log'
            require(block.sha256(log) == run['sanitized_log_sha256'], 'local log identity')
            require(parse_preblock(log) == expected_preblock()
                    and inputs.parse_inputs(log) == inputs.expected_inputs()
                    and block.parse_cipher(log) == block.expected_cipher(), 'local preblock/input/cipher')
            require(block.parse_seed(log) == block.expected_seed()
                    and block.parse_layout(log) == block.expected_layout()
                    and block.parse_aes(log) == block.expected_aes(), 'seed/layout/AES ledger')
            baseline = json.loads((evidence_dir / block.BUFFER).read_text())['runs'][0]['repeat_trials']
            require(block.parse_log(log) == baseline, 'complete baseline ledger')
            composition = json.loads((evidence_dir / 'vm9_framesign_preimage_composition_20261103.json').read_text())['runs'][index - 1]
            require(block.parse_observations(log) == composition['composition_observations']
                    and block.parse_edges(log) == composition['sha256_edges'], 'preimage/SHA-256 ledger')
            meta = json.loads(log.with_name('metadata.json').read_text())
            require(meta['process_exit_code'] == 0 and meta['read_only_guest_probe'] is True
                    and meta['raw_values_retained'] is False, 'local terminal/scope')
            for key in ('source_sha256', 'entry_class_sha256', 'preblock_model_sha256',
                        'native_library_sha256', 'python_model_sha256'):
                require(meta[key] == run[key], 'local artifact identity')
    if probe_dir:
        for relative, key in (('HookMain.java', 'source_sha256'), ('classes/HookMain.class', 'entry_class_sha256'),
                              ('run_buffer_probe.py', 'runner_sha256'), ('host_plaintext.py', 'python_bridge_sha256'),
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
        from elftools.elf.elffile import ELFFile
        with elf.open('rb') as stream:
            image = ELFFile(stream)
            segment = next(s for s in image.iter_segments() if s['p_type'] == 'PT_LOAD'
                           and s['p_vaddr'] <= 0x95F44 and 0x96144 <= s['p_vaddr'] + s['p_filesz'])
            stream.seek(segment['p_offset'] + 0x95F44 - segment['p_vaddr'])
            require(stream.read(512) == b''.join(crc16_xmodem(bytes([i])).to_bytes(2, 'little')
                                               for i in range(256)), 'native CRC table')
    return {'calls_verified': 8, 'preblock_observations_verified': len(expected_preblock()) * 2,
            'cipher_observations_preserved': len(block.expected_cipher()) * 2,
            'input_observations_preserved': len(inputs.expected_inputs()) * 2,
            'complete_baseline_preserved': True, 'local_logs_verified': probe_dir is not None,
            'elf_bytes_and_CRC_table_verified': elf is not None, 'libc_artifact_verified': libc_jar is not None,
            'android_equivalence_verified': False, 'standalone_signer_verified': False}


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
