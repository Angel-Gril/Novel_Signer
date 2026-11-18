"""Replay ordinary native mode 0x171 through the generic VM prelude.

All inputs, object graphs, TLS and contexts are synthetic. An observation
harness extends the upstream verifier's stop to +0x1684f0 without replacing
original instructions or helper bodies. The upstream zero-VM row is discarded;
this verifier owns the downstream evidence. Local model input is observed
callback-boundary state. Request bytecode and callback return do not execute.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import verify_vm9_native_171_vm_handoff_20261118 as handoff

EVIDENCE = handoff.EVIDENCE.with_name('vm9_native_171_vm_prelude_20261118.json')
PRELUDE = (0x168324, 0x1684F0)
BOUNDARY = dict(entry='0x27ed14', callback='0x2830c4', VM_entry='0x168324',
                stop_before='0x1684f0', mode='0x171', bytecode='0xf7720',
                compared_backing_words=32, compared_PC_and_backing_bytes=0x108)
CLAIMS = dict(synthetic_ordinary_native_path_through_generic_VM_prelude_verified=True,
    all_32_VM_backing_words_match_existing_model=True,
    observed_callback_boundary_state_used_as_model_input=True,
    original_code_and_internal_helpers_preserved=True,
    request_bytecode_executed=False, callback_return_or_success_cleanup_verified=False,
    full_context_state_or_live_object_identity_verified=False,
    whole_request_native_Python_differential_verified=False,
    native_171_and_Java_138_VM_equivalence_verified=False,
    actual_business_callback_execution_verified=False,
    ordinary_cronet_six_heads_verified=False, complete_standalone_signer_verified=False,
    original_signature_runtime_equivalence_verified=False, online_acceptance_verified=False)
LIMITS = [
    'All input and graph/provider limitations of the upstream handoff verifier remain applicable',
    'Only two image bases and four selected graph/context profiles are retained',
    'The model comparison starts at observed local callback state; it is not a fresh whole-request differential',
    'Context objects carry a known handler vtable tag only; full state is not reconstructed or consumed by the generic prelude',
    'Execution stops before +0x1684f0; no request bytecode handler, callback return, serialization or success cleanup executes',
    'The shared reader remains held at the stop; concurrent readers/writers and Android runtime equivalence are unverified',
    'No Android action, new hook, real request, connection detail or network validation is included',
]


def controls():
    cases = handoff.controls()
    return [cases[index] for index in (0, 1, 10, 11)]


def digest(value):
    return handoff.inputs.digest_json(value)


def upstream():
    data = json.loads(handoff.EVIDENCE.read_text(encoding='utf-8'))
    handoff.validate(data)
    return data


def replay(path, libc, *, on_case=None):
    import verify_vm9_signer_objects as oracle
    from unicorn import arm64_const as arm
    from vm9_allocator import _read_span
    from vm9_request_caller import prepare_request_caller
    _, _, read_main = handoff.inputs.load_elf(path)
    proofs = []

    def run_native(library, base, entry, arguments, pages, **kwargs):
        original_observer = kwargs['instruction_observer']
        observed_memory = kwargs['observed_memory']
        expected, trace = [], []

        def observe(cpu, address):
            offset = address - base
            if PRELUDE[0] <= offset < PRELUDE[1]:
                assert bytes(cpu.mem_read(address, 4)) == read_main(offset, 4)
                trace.append(offset)
                return
            original_observer(cpu, address)
            if offset != 0x2830C4:
                return
            def reg(name):
                return cpu.reg_read(getattr(arm, 'UC_ARM64_REG_' + name.upper()))
            before = {page: bytearray(data) for page, data in pages.items()}
            for page in range(handoff.G >> 12, (handoff.G + 0x10000) >> 12):
                before[page] = bytearray(cpu.mem_read(page << 12, 4096))
            frame = prepare_request_caller(before, entry_stack_address=reg('sp'),
                return_address=reg('x30'), thread_pointer=handoff.TLS,
                image_base=base, argument_x0=reg('x0'), argument_x1=reg('x1'),
                argument_x2=reg('x2'), argument_x3=reg('x3'), output_x8=reg('x8'),
                saved_frame_pointer=reg('x29'), saved_x28=reg('x28'), saved_x19=reg('x19'))
            region = (frame.register_backing_address - 8, 0x108)
            expected.append((region, _read_span(before, *region)))
            observed_memory[region] = None

        kwargs['instruction_observer'] = observe
        kwargs['stop_offset'] = PRELUDE[1]
        result = oracle.native(library, base, entry, arguments, pages, **kwargs)
        assert len(expected) == 1 and trace == list(range(*PRELUDE, 4))
        region, payload = expected[0]
        assert observed_memory[region] == payload, 'VM prelude backing differs'
        proofs.append(dict(generic_VM_instructions_executed=len(trace),
            all_32_backing_words_and_PC_match=True, executed_code_unchanged=True,
            generic_VM_trace_sha256=digest(trace),
            PC_and_backing_sha256=hashlib.sha256(payload).hexdigest(),
            request_bytecode_instructions_executed=0))
        return result

    # Upstream checks still verify the entire prefix and wrapper. Its trace
    # intentionally excludes the prelude, whose trace belongs to this owner.
    prefix_rows = handoff.replay(path, libc, case_controls=controls(), _native_runner=run_native)
    assert len(prefix_rows) == len(proofs) == len(controls())
    rows = []
    for prefix, proof, control in zip(prefix_rows, proofs, controls()):
        row = dict(control=control, **proof,
            prefix_instructions_executed=prefix['instructions_executed'],
            prefix_trace_sha256=prefix['trace_sha256'],
            guest_heap_sha256_at_prelude_stop=prefix['guest_heap_sha256'],
            allocation_ledger_sha256=prefix['allocation_ledger_sha256'],
            mutex_ledger_sha256=prefix['mutex_ledger_sha256'],
            mutex_events=prefix['mutex_events'],
            shared_readers_at_stop=prefix['shared_readers_at_VM_entry'],
            callback_context_guest_offset=prefix['callback_context_guest_offset'],
            native_mode=prefix['native_mode'], mode_padding_hex=prefix['mode_padding_hex'],
            wrapper_packed_and_saved_spans_match=prefix['wrapper_packed_and_saved_spans_match'],
            wrapper_VM_call_registers_match=prefix['wrapper_VM_call_registers_match'])
        rows.append(row)
        if on_case is not None:
            on_case(row)
    return rows


def validate(data):
    assert data['schema'] == 'vm9-native-171-vm-prelude-20261118-v1'
    assert data['provenance'] == dict(Metasec_sha256=handoff.inputs.SHA256,
        Bionic_sha256=handoff.inputs.LIBC_SHA256, upstream_handoff_evidence=handoff.EVIDENCE.name)
    assert data['boundary'] == BOUNDARY and data['claims'] == CLAIMS and data['limits'] == LIMITS
    assert data['providers'] == handoff.inputs.PROVIDERS
    assert data['Android_execution'] is False and data['synthetic_memory_only'] is True
    assert data['real_requests_or_connection_details_published'] is False
    code = data['generic_VM_code_range']
    assert code['start'] == hex(PRELUDE[0]) and code['end_exclusive'] == hex(PRELUDE[1])
    assert handoff.inputs.is_digest(code['sha256'])
    assert len(data['case_results']) == len(controls())
    prior_rows = {digest(r['control']): r for r in upstream()['case_results']}
    for row, control in zip(data['case_results'], controls()):
        assert row['control'] == control
        prior = prior_rows[digest(control)]
        assert row['generic_VM_instructions_executed'] == 115
        assert row['generic_VM_trace_sha256'] == digest(list(range(*PRELUDE, 4)))
        assert row['request_bytecode_instructions_executed'] == 0
        assert row['all_32_backing_words_and_PC_match'] is True and row['executed_code_unchanged'] is True
        for key in ('mutex_events', 'callback_context_guest_offset', 'native_mode', 'mode_padding_hex',
                    'wrapper_packed_and_saved_spans_match', 'wrapper_VM_call_registers_match',
                    'allocation_ledger_sha256', 'mutex_ledger_sha256'):
            assert row[key] == prior[key], key
        assert row['prefix_instructions_executed'] == prior['instructions_executed']
        assert row['prefix_trace_sha256'] == prior['trace_sha256']
        assert row['shared_readers_at_stop'] == prior['shared_readers_at_VM_entry']
        for key in ('PC_and_backing_sha256', 'guest_heap_sha256_at_prelude_stop'):
            assert handoff.inputs.is_digest(row[key]), key


def verify_elf(data, path):
    bindings = handoff.verify_elf(upstream(), path)
    _, _, read = handoff.inputs.load_elf(path)
    assert hashlib.sha256(read(PRELUDE[0], PRELUDE[1]-PRELUDE[0])).hexdigest() == data['generic_VM_code_range']['sha256']
    return dict(upstream=bindings, additional_generic_VM_code_ranges=1)


def build(path, libc, *, on_case=None):
    _, _, read = handoff.inputs.load_elf(path)
    data = dict(schema='vm9-native-171-vm-prelude-20261118-v1',
        provenance=dict(Metasec_sha256=handoff.inputs.SHA256,
            Bionic_sha256=handoff.inputs.LIBC_SHA256, upstream_handoff_evidence=handoff.EVIDENCE.name),
        boundary=BOUNDARY, claims=CLAIMS, limits=LIMITS, providers=handoff.inputs.PROVIDERS,
        Android_execution=False, synthetic_memory_only=True,
        real_requests_or_connection_details_published=False,
        generic_VM_code_range=dict(start=hex(PRELUDE[0]), end_exclusive=hex(PRELUDE[1]),
            sha256=hashlib.sha256(read(PRELUDE[0], PRELUDE[1]-PRELUDE[0])).hexdigest()),
        case_results=[])
    verify_elf(data, path)
    data['case_results'] = replay(path, libc, on_case=on_case)
    validate(data)
    return data


def negatives(data):
    bad_records = []
    for key, value in CLAIMS.items():
        bad = deepcopy(data); bad['claims'][key] = not value; bad_records.append(bad)
    for index in range(len(controls())):
        for key, value in (('generic_VM_instructions_executed', 114),
            ('all_32_backing_words_and_PC_match', False), ('request_bytecode_instructions_executed', 1),
            ('native_mode', '0x138'), ('shared_readers_at_stop', 0)):
            bad = deepcopy(data); bad['case_results'][index][key] = value; bad_records.append(bad)
    for bad in bad_records:
        try:
            validate(bad)
        except AssertionError:
            pass
        else:
            raise AssertionError('damaged prelude evidence accepted')
    return len(bad_records)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf', type=Path); parser.add_argument('--libc', type=Path)
    parser.add_argument('--replay', action='store_true'); args = parser.parse_args()
    if args.replay and (not args.elf or not args.libc):
        parser.error('--replay requires --elf and --libc')
    data = json.loads(EVIDENCE.read_text(encoding='utf-8')); validate(data)
    result = dict(retained_synthetic_cases=len(controls()), damaged_evidence_rejected=negatives(data),
                  generic_VM_instructions_per_case=115, request_bytecode_executed=False,
                  complete_standalone_signer_verified=False)
    if args.elf:
        result['Metasec_bindings'] = verify_elf(data, args.elf)
    if args.libc:
        handoff.inputs.libc_image(args.libc); result['matching_Bionic_digest_verified'] = True
    if args.replay:
        assert replay(args.elf, args.libc) == data['case_results'], 'frozen prelude replay differs'
        result['original_code_cases_replayed'] = len(controls())
    print(json.dumps(result))


if __name__ == '__main__':
    main()
