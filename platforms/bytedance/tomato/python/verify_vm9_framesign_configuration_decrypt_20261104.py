"""Verify configuration ECB decryption actually driving the RC4/AES pipeline."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import verify_vm9_framesign_configuration_key_20261103 as prior

block = prior.block
NAME = 'vm9_framesign_configuration_decrypt_20261104'
SOURCE = 'aes_configuration_decrypt_model_probe'
PARENT = prior.NAME + '.json'
OWNERS = (*prior.OWNERS, 'vm9_cipher.py', 'vm9_cipher_callback.py', 'vm9_registry.py')
ARTIFACTS = (('HookMain.java', 'source_sha256'), ('classes/HookMain.class', 'entry_class_sha256'),
             ('run_buffer_probe.py', 'runner_sha256'), ('host_proto_material.py', 'python_bridge_sha256'),
             ('host_decode_material.py', 'decoder_bridge_sha256'),
             ('host_plaintext.py', 'plaintext_bridge_sha256'), ('host_constructor.py', 'constructor_bridge_sha256'))
INPUTS = ['observed_configuration_ciphertext_272_bytes', 'observed_configuration_AES_key_16_bytes',
          'observed_empty_IV_and_mode_zero', 'observed_SHA1_preimage_12_bytes',
          'observed_twelve_reduction_leaf_bytes', 'observed_lookup_key_10_bytes',
          'fresh_relocated_ELF_tables_and_descriptors', 'explicit_fixture_allocation_and_warm_singleton_services']
COMPARISONS = ['observed_configuration_plaintext_271_bytes', 'observed_RC4_input_263_bytes',
               'observed_RC4_key_20_bytes']
CLAIMS = {
    'independent_runs': 2, 'calls': 8, 'cipher_mode': 0, 'ciphertext_length': 272,
    'cipher_key_length': 16, 'plaintext_length': 271, 'RC4_slice_offset': 4, 'RC4_slice_length': 263,
    'existing_Python_configuration_decrypt_callback_equals_native': True,
    'independent_AES_ECB_equals_existing_callback': True,
    'RC4_actually_uses_generated_plaintext_slice': True,
    'captured_RC4_input_used_only_for_comparisons': True,
    'native_ciphertext_descends_from_decoder_slice_4_to_276': True,
    'copy_lineage_checks_actual_write_events_and_temporal_order': True,
    'SHA1_preimage_has_three_four_byte_pieces': True,
    'preimage_first_piece_equals_decrypted_prefix': True,
    'preimage_last_piece_equals_decoded_prefix': True,
    'preimage_last_piece_direct_decoder_address_lineage_verified': False,
    'untrimmed_changed_key_reversed_ciphertext_and_wrong_slice_rejected': True,
    'complete_prior_relation_ledger_preserved': True,
    'AES_key_independently_generated': False, 'SHA1_preimage_independently_generated': False,
    'reduction_leaf_bytes_independently_generated': False, 'lookup_key_independently_generated': False,
    'actual_Android_allocator_or_singleton_equivalence_verified': False,
    'general_input_equivalence_verified': False, 'android_equivalence_verified': False,
    'complete_standalone_signer_verified': False, 'online_header_acceptance_verified': False,
}
STATIC = {
    '0x259ddc': ('str', 'x0, [sp, #0x28]'), '0x259de0': ('mov', 'x22, x8'),
    '0x248238': ('str', 'x0, [x21, #0x10]'), '0x248248': ('mov', 'w2, w19'),
    '0x24824c': ('mov', 'x0, x22'), '0x248250': ('mov', 'x1, x20'),
    '0x248254': ('bl', '#0x347f60'), '0x248258': ('strb', 'wzr, [x22, w19, uxtw]'),
    '0x24841c': ('str', 'x0, [x21, #0x10]'), '0x248424': ('ldr', 'x1, [x20, #0x10]'),
    '0x248428': ('mov', 'x2, x19'), '0x248430': ('bl', '#0x347f60'),
    '0x248434': ('strb', 'wzr, [x22, x19]'), '0x25ab68': ('mov', 'w23, wzr'),
    '0x25ab6c': ('cmp', 'w23, w19'), '0x25ab70': ('b.hs', '#0x25abd0'),
    '0x25ab74': ('add', 'x1, x21, w23, uxtw'), '0x25ab78': ('add', 'x2, x20, w23, uxtw'),
    '0x25ab7c': ('mov', 'x0, x22'), '0x25ab80': ('bl', '#0x242640'),
    '0x25ab84': ('add', 'w23, w23, #0x10'), '0x25ab88': ('b', '#0x25ab6c'),
    '0x17208c': ('str', 'w11, [x12, x10]'),
}
EVENTS = {'SOURCE_CAPTURE', 'SOURCE_COUNTS', 'SOURCE_LINK', 'SOURCE_TERMINAL',
          'PREKEY_COPY_JOIN', 'PREKEY_CLONE_JOIN', 'PREKEY_CLONE_COUNTS', 'PREKEY_COPY_COUNTS',
          'DECRYPT_INPUT', 'DECRYPT_OUTPUT', 'DECRYPT_MODEL', 'DECRYPT_PREIMAGE'}
DECRYPT_STORES = ('242928', '24293c', '242954', '24295c', '242968', '242974', '242980',
                  '242984', '242994', '242998', '24299c', '2429a0', '2429a4', '2429a8', '2429ac', '2429b0')


def same(left, right):
    return block.canonical(left) == block.canonical(right)


def parse_new(path: Path) -> list[dict]:
    prior.parse_key(path)
    rows = []
    for line in path.read_text(encoding='utf-8-sig').splitlines():
        prefix = '[HookMain] FRAME_BUFFER_'
        if not line.startswith(prefix):
            continue
        event, _, attributes = line[len(prefix):].partition(' ')
        block.require(not event.endswith('ERROR'), 'probe observation error')
        if not event.startswith(('SOURCE_', 'PREKEY_', 'DECRYPT_')):
            continue
        block.require(event in EVENTS, 'unknown decrypt/source event')
        row = {'event': event}
        for token in attributes.split():
            key, value = token.split('=', 1)
            block.require(key not in row, 'duplicate decrypt/source attribute')
            row[key] = (value == 'true' if value in ('true', 'false') else
                        int(value) if value.lstrip('-').isdecimal() else value)
        rows.append(row)
    return block.ordered(rows)


def decrypt_writers(ordinal, *, sliced):
    counts = (16, 16, 17, 17, 16, 17, 17, 17, 16, 17, 17, 16, 16, 16, 16, 16) if sliced else (17,) * 15 + (16,)
    return ','.join(f'metasec+0x{pc}/metasec+0x25ab84/{ordinal}:{count}'
                    for pc, count in zip(DECRYPT_STORES, counts))


def expected_new() -> list[dict]:
    rows = []
    for ordinal in range(1, 5):
        def add(event, **values):
            rows.append({'event': event, 'ordinal': ordinal, **values})

        def terminal(role, depth, length, writers, *, inside=False, offset=-1, direct=0, direct_offset=-1):
            add('SOURCE_COUNTS', role=role, depth=depth, length=length, actual_writer_matches=0, dropped=0)
            add('SOURCE_TERMINAL', role=role, depth=depth, length=length, source_location='outside_modules',
                source_writers_at_read=writers, source_inside_decoder=inside, decoder_offset=offset,
                decoder_snapshot_equal=inside, decoder_write_events_equal=inside,
                decoder_direct_matches=direct, decoder_direct_offset=direct_offset,
                decoder_reversed_matches=0, decoder_reversed_offset=-1)

        def links(role, length, chain):
            for depth, (site, size, offset) in enumerate(chain):
                add('SOURCE_COUNTS', role=role, depth=depth, length=length, actual_writer_matches=1, dropped=0)
                add('SOURCE_LINK', role=role, depth=depth, copy_site='metasec+0x' + site,
                    copy_length=size, slice_offset=offset, length=length, snapshot_equal=True,
                    actual_write_events_equal=True, temporal_order_verified=True)

        for site, length in [('248254', 4)] * 4 + [('248254', 272), ('248254', 271), ('248430', 271)]:
            add('SOURCE_CAPTURE', copy_site='metasec+0x' + site, length=length,
                actual_destination_writers_verified=True, source_snapshot_equal=True)
        add('DECRYPT_INPUT', data_length=272, key_length=16, iv_length=0, mode=0,
            data_equals_decoder_after_four=True)
        links('configuration_cipher_input', 272, [('248254', 272, 0), ('248254', 276, 4)])
        decoder_writers = ','.join(f'metasec+0x{pc}/metasec+0x258ed0/{ordinal}:{count}'
                                   for pc, count in [('24599c', 90), ('2459bc', 91), ('2459cc', 91)])
        terminal('configuration_cipher_input', 2, 272, decoder_writers, inside=True, offset=4, direct=1, direct_offset=4)
        add('DECRYPT_OUTPUT', ciphertext_length=272, plaintext_length=271,
            output_writers=decrypt_writers(ordinal, sliced=False))
        links('preimage_offset_0', 4, [('246c88', 4, 0), ('248254', 4, 0)])
        terminal('preimage_offset_0', 2, 4, f'metasec+0x17208c/outside_modules/{ordinal}:4')
        terminal('preimage_offset_4', 0, 4, 'unobserved:4')
        links('preimage_offset_8', 4, [('248254', 4, 0)])
        terminal('preimage_offset_8', 1, 4, f'metasec+0x17208c/outside_modules/{ordinal}:4', direct=1, direct_offset=0)
        links('RC4_data_source', 263, [('248430', 271, 4), ('248254', 271, 4)])
        terminal('RC4_data_source', 2, 263, decrypt_writers(ordinal, sliced=True))
        for offset, site, writers, direct, decoded_at in (
            (0, '2469a0', f'libc.so+0x1c148/metasec+0x246c8c/{ordinal}:4', 0, -1),
            (4, '246c88', 'unobserved:4', 0, -1),
            (8, '246c88', f'libc.so+0x1c148/metasec+0x248258/{ordinal}:4', 1, 0)):
            add('PREKEY_COPY_JOIN', site='metasec+0x' + site, destination_offset=offset, length=4,
                snapshot_equals_preimage=True, source_writers_at_copy=writers,
                decoder_slice_matches=direct, decoder_slice_offset=decoded_at)
            add('PREKEY_CLONE_COUNTS', role='preimage_offset_' + str(offset), matching_snapshots=0)
        add('PREKEY_COPY_COUNTS', preimage_length=12, matching_copies=3)
        add('PREKEY_CLONE_JOIN', role='RC4_data', clone_length=271, slice_offset=4, slice_length=263,
            snapshot_equals_current_source=True,
            original_writers_at_copy=f'libc.so+0x1c148/metasec+0x248258/{ordinal}:271')
        add('PREKEY_CLONE_COUNTS', role='RC4_data', matching_snapshots=1)
        add('DECRYPT_MODEL', process_exit_code=0, plaintext_length=271, RC4_data_length=263,
            existing_Python_callback_equals_native=True, generated_slice_equals_native_RC4_data=True,
            independent_AES_equals_existing=True, fixture_singleton_getter_calls=2,
            untrimmed_plaintext_matches=False, changed_key_matches=False,
            reversed_ciphertext_matches=False, wrong_slice_matches=False)
        add('DECRYPT_PREIMAGE', first_piece_equals_decrypted_prefix=True,
            first_piece_equals_decrypted_suffix=False, last_piece_equals_decoder_prefix=True)
    return block.ordered(rows)


def prior_ledger(evidence_dir: Path, index: int, log: Path | None = None) -> dict:
    return {'key': prior.parse_key(log) if log else prior.expected_key(),
            'earlier_ledger': prior.prior_ledger(evidence_dir, index, log)}


def verify(data: dict, evidence_dir: Path, probe_dir: Path | None = None,
           elf: Path | None = None, libc_jar: Path | None = None) -> dict:
    require = block.require
    require(set(data) == {'schema', 'evidence_date', 'input', 'parent_evidence', 'parent_evidence_sha256',
                         'owners', 'owner_hash_format', 'probe', 'runs', 'static_analysis', 'conclusions',
                         'raw_values_retained', 'operand_digests_retained', 'interpretation'}, 'evidence keys')
    require(data['schema'] == 'vm9-framesign-configuration-decrypt-20261104-v1'
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
        require(digest == prior.prior.prior.owner_sha256(Path(__file__).with_name(owner)), 'owner identity')
    probe = data['probe']
    identity_keys = {key for _, key in ARTIFACTS}
    fixed = {'source_relative_path': SOURCE + '/HookMain.java', 'read_only_guest_observation': True,
             'fresh_rootfs_per_run': True, 'synthetic_jni_provider_used': True, 'setup_rounds_per_run': 1,
             'restore_enabled': False, 'run_deadline_seconds': 1200,
             'python_operand_transport': 'private_in_memory_stdin_stdout_pipe', 'model_inputs': INPUTS,
             'comparison_only_inputs': COMPARISONS, 'RC4_uses_model_generated_data_and_key': True,
             'warm_singleton_and_allocator_are_explicit_fixtures': True}
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
        require(same(run['observations'], expected), 'decrypt/source relations')
        ledger = prior_ledger(evidence_dir, index)
        require(run['prior_relation_ledger_sha256'] == prior.prior.prior.ledger_sha256(ledger), 'prior ledger identity')
        if probe_dir is not None:
            log = probe_dir / run['local_run_name'] / 'sanitized.log'
            require(block.sha256(log) == run['sanitized_log_sha256'], 'local log identity')
            require(same(parse_new(log), expected), 'local decrypt/source relations')
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
            'RC4_data_generated_from_explicit_cipher_inputs': True, 'standalone_signer_verified': False}


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
