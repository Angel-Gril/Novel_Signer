"""Verify configuration selection, Base64 AES key/IV material and ciphertext."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import verify_vm9_framesign_preblock_20261103 as prior

block = prior.block
NAME = 'vm9_framesign_aes_material_20261103'
SOURCE = 'aes_protobuf_material_probe'
PARENT = prior.NAME + '.json'
OWNERS = ('vm9_protobuf.py', 'vm9_configuration_init.py', 'vm9_objects.py',
          'verify_vm9_signer_objects.py', 'verify_vm9_strings.py')
GROUPS = {
    'PROTO_': {'QUERY', 'INPUT', 'MODEL', 'FIELD_JOIN', 'MATERIAL_JOIN'},
    'CONFIG_': {'DECODE_INPUT', 'DECODE_RETURN', 'FIELD_COPY', 'MATERIAL_JOIN'},
    'MATERIAL_': {'DECODE_INPUT', 'DECODE_RETURN', 'SPLIT', 'LINEAGE', 'PARENT', 'AES_JOIN'},
}
STATIC = {
    '0x256088': ('mov', 'x8, x0'),
    '0x256090': ('mov', 'x3, x2'),
    '0x256094': ('mov', 'x2, x1'),
    '0x256098': ('add', 'x0, x0, #0xd68'),
    '0x25609c': ('mov', 'x1, x8'),
    '0x2560a0': ('b', '#0x254330'),
    '0x2556b4': ('ldr', 'w9, [x8, #0x10]'),
    '0x2556c4': ('ldrb', 'w10, [x0, #4]'),
    '0x2556c8': ('ldp', 'x22, x20, [x0, #0x10]'),
    '0x2557ac': ('cmp', 'w10, #2'),
    '0x2557b4': ('ldrb', 'w24, [x0, #5]'),
    '0x2557d8': ('sub', 'w22, w22, w24'),
    '0x2557f4': ('add', 'x1, x20, w24, uxtw'),
    '0x2557f8': ('mov', 'x2, x22'),
    '0x2557fc': ('bl', '#0x347f60'),
    '0x255808': ('strb', 'wzr, [x8, w22, uxtw]'),
    '0x258ecc': ('bl', '#0x245814'),
    '0x258ef4': ('bl', '#0x2481fc'),
    '0x248d88': ('ldr', 'x9, [x9, #0x10]'),
    '0x248d90': ('add', 'x9, x9, w10, uxtw'),
    '0x248da0': ('bl', '#0x248448'),
    '0x248494': ('ldr', 'x1, [x20, #8]'),
    '0x248498': ('mov', 'x2, x19'),
    '0x2484a0': ('bl', '#0x347f60'),
}
CLAIMS = {
    'independent_runs': 2, 'calls': 8, 'protobuf_input_length': 263, 'lookup_key_length': 10,
    'configuration_entries': 2, 'matched_entry_index': 0, 'matching_keys': 1,
    'selected_field_length': 44, 'decoded_material_length': 32,
    'existing_Python_unpack_and_key_selection_equal_actual_field': True,
    'actual_field_copy_source_inside_protobuf_input': True,
    'other_same_length_field_rejected': True,
    'Python_decodes_its_own_selected_field': True,
    'AES_key_is_decoded_first16': True, 'AES_IV_is_decoded_last16': True,
    'swapped_halves_rejected': True, 'AES_using_Python_derived_material_equals_native': True,
    'earlier_base64_input_length': 368, 'earlier_base64_output_length': 276,
    'direct_earlier_decode_slice_candidate_rejected': True,
    'complete_prior_ledger_preserved': True,
    'protobuf_input_and_lookup_key_independently_generated': False,
    'earlier_configuration_decryption_identified': False,
    'old_object_constructor_row_proves_current_AES_material_source': False,
    'general_input_equivalence_verified': False, 'android_equivalence_verified': False,
    'complete_standalone_signer_verified': False, 'online_header_acceptance_verified': False,
}


def owner_sha256(path: Path) -> str:
    """Fingerprint source bytes with CRLF normalized to LF for Windows checkouts."""
    return hashlib.sha256(path.read_bytes().replace(b'\r\n', b'\n')).hexdigest()


def parse_material(path: Path) -> list[dict]:
    block.parse_cipher(path)
    rows = []
    for line in path.read_text(encoding='utf-8-sig').splitlines():
        prefix = '[HookMain] FRAME_BUFFER_'
        if not line.startswith(prefix):
            continue
        event, _, attributes = line[len(prefix):].partition(' ')
        group = next((group for group in GROUPS if event.startswith(group)), None)
        if group is None:
            continue
        block.require(event[len(group):] in GROUPS[group], 'unknown material observation')
        row = {'event': event}
        for token in attributes.split():
            key, value = token.split('=', 1)
            block.require(key not in row, 'duplicate material attribute')
            row[key] = (value == 'true' if value in ('true', 'false') else
                        int(value) if value.lstrip('-').isdecimal() else value)
        rows.append(row)
    return block.ordered(rows)


def expected_material() -> list[dict]:
    rows = []
    for ordinal in range(1, 5):
        def add(event, **values):
            rows.append({'event': event, 'ordinal': ordinal, **values})
        add('PROTO_QUERY', length=10)
        add('CONFIG_DECODE_INPUT', length=368, input_location='outside_modules', input_writers='unobserved:368')
        add('CONFIG_DECODE_RETURN', status=0, length=276, same_stack_pointer=True)
        add('PROTO_INPUT', length=263, writers='metasec+0x171c18/metasec+0x9b234:263')
        add('PROTO_MODEL', process_exit_code=0, entries=2, matched_index=0, key_matches=1,
            selected_length=44, decoded_length=32, peer_equals_selected=False)
        for index in (1, 2):
            add('PROTO_FIELD_JOIN', field_copy=index, length=44, source_inside_protobuf_input=True,
                source_equals_protobuf_slice=True, existing_Python_selected_field_equals_copy=index == 1)
            add('CONFIG_FIELD_COPY', length=44, tag=2, kind=14, wire=2, length_prefix_bytes=1,
                source_equals_original_plus_offset=True, source_inside_config_decode=False,
                source_buffer_lineage_present=False, resolved_source_inside_config_decode=False,
                config_slice_matches=0, config_first_match_offset=-1,
                source_writers=f'metasec+0x171c18/outside_modules/{ordinal}:44')
            add('CONFIG_MATERIAL_JOIN', field_copy=index, length=44,
                source_origin_equals_field_destination=index == 1, bytes_equal_copied_field=index == 1)
        add('MATERIAL_DECODE_INPUT', length=44, source_record_present=True, source_origin='outside_modules',
            source_origin_equals_input=True, source_constructor='metasec+0x248388', source_depth=0,
            source_writers=f'libc.so+0x1c148/metasec+0x255800/{ordinal}:44')
        add('PROTO_MATERIAL_JOIN', actual_44_equals_Python_selected_field=True,
            decoder_equals_Python_unpacked_material=True)
        add('MATERIAL_DECODE_RETURN', length=32, native_status=0, process_exit_code=0,
            existing_Python_decoder_equals_native=True)
        add('MATERIAL_SPLIT', decode_calls=1, key_equals_decoded_first16=True,
            iv_equals_decoded_last16=True, swapped_key_matches=False, swapped_iv_matches=False)
        for role, offset, counts in (('key', 0, (6, 5, 5)), ('iv', 16, (5, 6, 5))):
            writers = ','.join(f'metasec+{site}/metasec+0x258ed0/{ordinal}:{count}'
                               for site, count in zip(('0x24599c', '0x2459bc', '0x2459cc'), counts))
            add('MATERIAL_LINEAGE', role=role, record_present=True, length=16, recorded_length=16,
                writer='metasec+0x24848c', depth=1, offset=offset, parent_location='outside_modules',
                origin_location='outside_modules', material_equals_origin_bytes=True, origin_writers=writers)
        add('MATERIAL_PARENT', role='key', length=32, depth=0, origin_location='outside_modules',
            writer='metasec+0x248238')
        add('MATERIAL_AES_JOIN', derived_material_ciphertext_equals_native=True)
    return block.ordered(rows)


def prior_ledger(evidence_dir: Path, index: int, log: Path | None = None) -> dict:
    """Only public relation rows and already retained final-field hashes enter this digest."""
    composition = json.loads((evidence_dir / 'vm9_framesign_preimage_composition_20261103.json').read_text())['runs'][index - 1]
    baseline = json.loads((evidence_dir / block.BUFFER).read_text())['runs'][0]['repeat_trials']
    if log is None:
        return {'baseline': baseline, 'preblock': prior.expected_preblock(), 'cipher': block.expected_cipher(),
                'inputs': prior.inputs.expected_inputs(), 'seed': block.expected_seed(),
                'layout': block.expected_layout(), 'aes': block.expected_aes(),
                'composition': composition['composition_observations'], 'edges': composition['sha256_edges']}
    return {'baseline': block.parse_log(log), 'preblock': prior.parse_preblock(log), 'cipher': block.parse_cipher(log),
            'inputs': prior.inputs.parse_inputs(log), 'seed': block.parse_seed(log),
            'layout': block.parse_layout(log), 'aes': block.parse_aes(log),
            'composition': block.parse_observations(log), 'edges': block.parse_edges(log)}


def ledger_sha256(ledger: dict) -> str:
    return hashlib.sha256(json.dumps(ledger, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def verify(data: dict, evidence_dir: Path, probe_dir: Path | None = None,
           elf: Path | None = None, libc_jar: Path | None = None) -> dict:
    require = block.require
    require(set(data) == {'schema', 'evidence_date', 'input', 'parent_evidence', 'owners', 'owner_hash_format',
                          'probe', 'runs', 'static_analysis', 'conclusions', 'raw_values_retained',
                          'operand_digests_retained', 'interpretation'}, 'evidence keys')
    require(data['schema'] == 'vm9-framesign-aes-material-20261103-v1', 'schema')
    require(data['evidence_date'] == '2026-11-03' and data['input'] == block.EXPECTED_INPUT, 'date/input')
    require(data['parent_evidence'] == 'evidence/' + PARENT, 'parent')
    require(data['raw_values_retained'] is False and data['operand_digests_retained'] is False, 'raw values/digests')
    require(block.canonical(data['conclusions']) == block.canonical(CLAIMS), 'unsupported conclusion')
    parent = json.loads((evidence_dir / PARENT).read_text())
    prior.verify(parent, evidence_dir, elf=elf, libc_jar=libc_jar)
    require(data['owner_hash_format'] == 'sha256_bytes_CRLF_normalized_to_LF'
            and set(data['owners']) == set(OWNERS), 'owner hash contract')
    for owner, digest in data['owners'].items():
        require(owner_sha256(Path(__file__).with_name(owner)) == digest, 'owner identity')
    probe = data['probe']
    identities = ('source_sha256', 'entry_class_sha256', 'runner_sha256', 'python_bridge_sha256',
                  'decoder_bridge_sha256', 'plaintext_bridge_sha256', 'constructor_bridge_sha256')
    require(set(probe) == {*identities, 'source_relative_path', 'read_only_guest_observation',
                          'fresh_rootfs_per_run', 'synthetic_jni_provider_used', 'setup_rounds_per_run',
                          'restore_enabled', 'python_operand_transport', 'model_inputs',
                          'AES_encrypts_using_model_derived_material'}, 'probe keys')
    require(probe['source_relative_path'] == SOURCE + '/HookMain.java', 'source path')
    for key in identities:
        require(isinstance(probe[key], str) and block.HEX_256.fullmatch(probe[key]), 'probe digest')
    for key in ('read_only_guest_observation', 'fresh_rootfs_per_run', 'synthetic_jni_provider_used',
                'AES_encrypts_using_model_derived_material'):
        require(probe[key] is True, 'probe scope')
    require(type(probe['setup_rounds_per_run']) is int and probe['setup_rounds_per_run'] == 1
            and probe['restore_enabled'] is False, 'setup/restore')
    require(probe['python_operand_transport'] == 'private_in_memory_stdin_stdout_pipe'
            and probe['model_inputs'] == ['observed_protobuf_263_bytes', 'observed_lookup_key_10_bytes',
                                         'fresh_relocated_ELF_descriptors_and_lookup_table', 'explicit_fixture_allocation_services'],
            'model inputs')
    require(isinstance(data['runs'], list) and len(data['runs']) == 2, 'run count')
    for index, run in enumerate(data['runs'], 1):
        require(set(run) == {'local_run_name', 'source_sha256', 'entry_class_sha256', 'native_library_sha256',
                            'python_model_sha256', 'preblock_model_sha256', 'process_exit_code',
                            'sanitized_log_sha256', 'repeat_trials', 'material_observations', 'prior_relation_ledger_sha256'}, 'run keys')
        require(run['local_run_name'] == SOURCE + f'/run{index}' and type(run['process_exit_code']) is int
                and run['process_exit_code'] == 0, 'run terminal')
        require(run['source_sha256'] == probe['source_sha256']
                and run['entry_class_sha256'] == probe['entry_class_sha256'], 'paired build identity')
        for key in ('native_library_sha256', 'python_model_sha256', 'preblock_model_sha256'):
            require(run[key] == parent['runs'][index - 1][key], 'run artifacts')
        require(isinstance(run['sanitized_log_sha256'], str) and block.HEX_256.fullmatch(run['sanitized_log_sha256']), 'log digest')
        require(block.canonical(run['repeat_trials']) == block.canonical(parent['runs'][index - 1]['repeat_trials']), 'changed output')
        require(block.canonical(run['material_observations']) == block.canonical(expected_material()), 'material observation mismatch')
        expected = prior_ledger(evidence_dir, index)
        require(run['prior_relation_ledger_sha256'] == ledger_sha256(expected), 'prior ledger identity')
        if probe_dir:
            log = probe_dir / run['local_run_name'] / 'sanitized.log'
            require(block.sha256(log) == run['sanitized_log_sha256'], 'local log identity')
            require(block.canonical(parse_material(log)) == block.canonical(expected_material()), 'local material relations')
            require(block.canonical(prior_ledger(evidence_dir, index, log)) == block.canonical(expected), 'complete prior ledger')
            meta = json.loads(log.with_name('metadata.json').read_text())
            require(meta['process_exit_code'] == 0 and meta['read_only_guest_probe'] is True
                    and meta['raw_values_retained'] is False, 'local terminal/scope')
            for key in ('source_sha256', 'entry_class_sha256', 'native_library_sha256',
                        'python_model_sha256', 'preblock_model_sha256'):
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
    return {'calls_verified': 8, 'material_observations_verified': len(expected_material()) * 2,
            'prior_preblock_relations_preserved': len(prior.expected_preblock()) * 2,
            'prior_cipher_relations_preserved': len(block.expected_cipher()) * 2,
            'prior_input_relations_preserved': len(prior.inputs.expected_inputs()) * 2,
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
