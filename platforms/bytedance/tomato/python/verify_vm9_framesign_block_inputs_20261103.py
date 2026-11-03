"""Join fresh ELF configuration output to FrameSign's key and feedback inputs."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import verify_vm9_framesign_block_cipher_20261103 as block

NAME = 'vm9_framesign_block_inputs_20261103'
SOURCE = 'block_cipher_constructor_source_probe'
PARENT = block.NAME + '.json'
OWNERS = ('vm9_elf_bootstrap.py', 'verify_vm9_elf_configuration_constructor_20261011.py',
          'vm9_registry.py', 'vm9_objects.py', 'vm9_framesign_block_cipher.py')
EVENTS = {'INPUT_CONSTRUCTOR_JOIN', 'INPUT_TWENTY', 'INPUT_TWENTY_SLICE', 'INPUT_KEY_ORDER',
          'INPUT_KEY_ROTATE', 'INPUT_CONVERTED_KEY_WORD'}
CLAIMS = {
    'independent_runs': 2, 'calls': 8, 'source_image_offset': '0x3dec74', 'source_length': 20,
    'source_section': '.bss', 'source_is_ELF_file_payload': False,
    'fresh_Python_configuration_equals_runtime_source': True,
    'key_is_first16_with_each_u32_reversed': True,
    'feedback_tail_is_last4_of_configuration_source': True,
    'feedback_prefix_is_pointer_low32_little_endian': True,
    'Python_encrypts_with_constructor_derived_key_and_feedback': True,
    'full_93_byte_constructor_and_AES_input_match': True,
    'complete_prior_ledger_preserved': True,
    'original_configuration_constructor_observed_in_this_probe': False,
    'general_input_equivalence_verified': False, 'android_equivalence_verified': False,
    'allocator_reuse_policy_identified': False, 'complete_standalone_signer_verified': False,
    'online_header_acceptance_verified': False,
}


def parse_inputs(path: Path) -> list[dict]:
    rows = []
    # The block parser independently rejects all observation errors.
    block.parse_cipher(path)
    for line in path.read_text(encoding='utf-8-sig').splitlines():
        prefix = '[HookMain] FRAME_BUFFER_'
        if not line.startswith(prefix):
            continue
        event, _, attributes = line[len(prefix):].partition(' ')
        if event not in EVENTS:
            continue
        row = {'event': event}
        for token in attributes.split():
            key, value = token.split('=', 1)
            block.require(key not in row, 'duplicate input attribute')
            row[key] = (value == 'true' if value in ('true', 'false') else
                        int(value) if value.lstrip('-').isdecimal() else value)
        # This is a cursor-relative code word, not an operand; it is unnecessary
        # to the retained key-word value relation and is not published here.
        row.pop('code_word', None)
        rows.append(row)
    return block.ordered(rows)


def expected_inputs() -> list[dict]:
    rows = []
    for ordinal in range(1, 5):
        def add(event, **values):
            rows.append({'event': 'INPUT_' + event, 'ordinal': ordinal, **values})
        add('CONSTRUCTOR_JOIN', length=20, process_exit_code=0, fresh_ELF_configuration_equals_copy2=True)
        add('TWENTY', length=20, source_location='metasec+0x3dec74', destination_location='outside_modules')
        for index in (10, 11):
            add('TWENTY_SLICE', copy=index, source_equals_input_slice=True, bytes_equal_input_slice=True)
        add('KEY_ORDER', raw_key_equals_converted=False, reversed_words_equal_converted=True)
        for shift in (8, 16, 24):
            add('KEY_ROTATE', bits=shift, matches=False)
        for offset in (0, 4, 8, 12):
            add('CONVERTED_KEY_WORD', offset=offset, record_present=True, store_ordinal=ordinal,
                store_bcp='metasec+0xa0b4c', value_slot=1, source_writer='metasec+0x16900c',
                source_bcp='metasec+0xa0b48', operation='unobserved', value_equals_key_word=True)
    return block.ordered(rows)


def verify(data: dict, evidence_dir: Path, probe_dir: Path | None = None,
           elf: Path | None = None, libc_jar: Path | None = None) -> dict:
    require = block.require
    require(set(data) == {'schema', 'evidence_date', 'input', 'parent_evidence', 'owners', 'probe',
                         'runs', 'conclusions', 'raw_values_retained', 'operand_digests_retained', 'interpretation'}, 'evidence keys')
    require(data['schema'] == 'vm9-framesign-block-inputs-20261103-v1', 'schema')
    require(data['evidence_date'] == '2026-11-03' and data['input'] == block.EXPECTED_INPUT, 'date/input')
    require(data['parent_evidence'] == 'evidence/' + PARENT, 'parent')
    require(data['raw_values_retained'] is False and data['operand_digests_retained'] is False, 'raw values/digests')
    require(block.canonical(data['conclusions']) == block.canonical(CLAIMS), 'unsupported conclusion')
    parent = json.loads((evidence_dir / PARENT).read_text())
    block.verify(parent, evidence_dir, elf=elf, libc_jar=libc_jar)
    require(set(data['owners']) == set(OWNERS), 'constructor owners')
    for owner, digest in data['owners'].items():
        require(block.sha256(Path(__file__).with_name(owner)) == digest, 'constructor owner identity')
    probe = data['probe']
    require(set(probe) == {'source_relative_path', 'source_sha256', 'entry_class_sha256', 'runner_sha256',
                          'python_bridge_sha256', 'constructor_bridge_sha256', 'read_only_guest_observation',
                          'fresh_rootfs_per_run', 'synthetic_jni_provider_used', 'setup_rounds_per_run',
                          'restore_enabled', 'python_operand_transport', 'constructor_model_inputs',
                          'remaining_observed_algorithm_inputs'}, 'probe keys')
    require(probe['source_relative_path'] == SOURCE + '/HookMain.java', 'source path')
    for key in ('source_sha256', 'entry_class_sha256', 'runner_sha256', 'python_bridge_sha256', 'constructor_bridge_sha256'):
        require(isinstance(probe[key], str) and block.HEX_256.fullmatch(probe[key]), 'probe digest')
    for key in ('read_only_guest_observation', 'fresh_rootfs_per_run', 'synthetic_jni_provider_used'):
        require(probe[key] is True, 'probe scope')
    require(type(probe['setup_rounds_per_run']) is int and probe['setup_rounds_per_run'] == 1
            and probe['restore_enabled'] is False, 'setup/restore')
    require(probe['python_operand_transport'] == 'private_in_memory_stdin_stdout_pipe'
            and probe['constructor_model_inputs'] == 'fresh_relocated_ELF_pages_and_explicit_fixture_services'
            and probe['remaining_observed_algorithm_inputs'] == ['preblock_88_bytes', 'feedback_pointer', 'prefix_xor_immediate'],
            'model inputs/scope')
    require(isinstance(data['runs'], list) and len(data['runs']) == 2, 'run count')
    for index, run in enumerate(data['runs'], 1):
        require(set(run) == {'local_run_name', 'source_sha256', 'entry_class_sha256', 'native_library_sha256',
                            'python_model_sha256', 'process_exit_code', 'sanitized_log_sha256', 'repeat_trials',
                            'cipher_observations', 'input_observations'}, 'run keys')
        require(run['local_run_name'] == SOURCE + f'/run{index}' and type(run['process_exit_code']) is int
                and run['process_exit_code'] == 0, 'run terminal')
        require(run['native_library_sha256'] == block.LIBRARY_SHA256
                and run['python_model_sha256'] == parent['probe']['python_model_sha256'], 'run artifact')
        for key in ('source_sha256', 'entry_class_sha256'):
            require(run[key] == probe[key], 'paired build identity')
        require(isinstance(run['sanitized_log_sha256'], str) and block.HEX_256.fullmatch(run['sanitized_log_sha256']), 'log digest')
        require(run['repeat_trials'] == parent['runs'][index - 1]['repeat_trials'], 'changed output')
        require(run['cipher_observations'] == block.expected_cipher()
                and run['input_observations'] == expected_inputs(), 'input/cipher relation mismatch')
        if probe_dir:
            log = probe_dir / run['local_run_name'] / 'sanitized.log'
            require(block.sha256(log) == run['sanitized_log_sha256'], 'local log identity')
            require(parse_inputs(log) == expected_inputs() and block.parse_cipher(log) == block.expected_cipher(), 'local input/cipher')
            require(block.parse_seed(log) == block.expected_seed() and block.parse_layout(log) == block.expected_layout(), 'seed/layout ledger')
            baseline = json.loads((evidence_dir / block.BUFFER).read_text())['runs'][0]['repeat_trials']
            require(block.parse_log(log) == baseline and block.parse_aes(log) == block.expected_aes(), 'complete baseline/AES')
            composition = json.loads((evidence_dir / 'vm9_framesign_preimage_composition_20261103.json').read_text())['runs'][index - 1]
            require(block.parse_observations(log) == composition['composition_observations']
                    and block.parse_edges(log) == composition['sha256_edges'], 'preimage/SHA-256')
            meta = json.loads(log.with_name('metadata.json').read_text())
            require(meta['process_exit_code'] == 0 and meta['read_only_guest_probe'] is True
                    and meta['raw_values_retained'] is False, 'local terminal/scope')
            for key in ('source_sha256', 'entry_class_sha256', 'native_library_sha256', 'python_model_sha256'):
                require(meta[key] == run[key], 'local build identity')
    if probe_dir:
        for relative, key in (('HookMain.java', 'source_sha256'), ('classes/HookMain.class', 'entry_class_sha256'),
                              ('run_buffer_probe.py', 'runner_sha256'), ('host_plaintext.py', 'python_bridge_sha256'),
                              ('host_constructor.py', 'constructor_bridge_sha256')):
            require(block.sha256(probe_dir / SOURCE / relative) == probe[key], 'local probe identity')
    if elf:
        from elftools.elf.elffile import ELFFile
        with elf.open('rb') as stream:
            image = ELFFile(stream)
            section = image.get_section_by_name('.bss')
            require(section['sh_type'] == 'SHT_NOBITS'
                    and section['sh_addr'] <= 0x3dec74 < 0x3dec88 <= section['sh_addr'] + section['sh_size'], 'source BSS layout')
    return {'calls_verified': 8, 'input_observations_verified': len(expected_inputs()) * 2,
            'cipher_observations_preserved': len(block.expected_cipher()) * 2,
            'constructor_generated_key_and_feedback_verified': True,
            'complete_baseline_preserved': True, 'local_logs_verified': probe_dir is not None,
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
