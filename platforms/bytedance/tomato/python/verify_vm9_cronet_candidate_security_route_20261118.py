"""Verify a conditional static security route and retained synthetic ARM64 controls."""
import argparse
from copy import deepcopy
import hashlib
from io import BytesIO
import json
from pathlib import Path

EVIDENCE = Path(__file__).resolve().parents[1] / 'evidence/vm9_cronet_candidate_security_route_20261118.json'
ELF_SHA256 = 'ab0547460f1c06e5111b69826d2277f145aad4f79c7d2b7aea0356dcf25e49ac'
EXPECTED = [
    ('0x38938c', 'mov', 'x19, x2'),
    ('0x3893a0', 'ldr', 'x0, [x20, #0x730]'),
    ('0x3893a4', 'add', 'x3, x20, #0x330'),
    ('0x3893a8', 'add', 'x4, x20, #0x2e8'),
    ('0x3893ac', 'mov', 'x1, x20'),
    ('0x3893b0', 'mov', 'x5, x19'),
    ('0x3893b4', 'mov', 'x2, x21'),
    ('0x3893c8', 'b', '#0x38ed48'),
    ('0x38ed64', 'mov', 'x22, x2'),
    ('0x38ed6c', 'mov', 'x19, x5'),
    ('0x38ed70', 'mov', 'x20, x4'),
    ('0x38ed74', 'mov', 'x21, x3'),
    ('0x38ed88', 'ldr', 'x8, [x23, #0x28]'),
    ('0x38ed8c', 'cbz', 'x8, #0x38eda8'),
    ('0x38ed90', 'ldrb', 'w9, [x23, #0xc1]'),
    ('0x38ed94', 'ldr', 'x8, [x23, #0xf0]'),
    ('0x38ed98', 'cbz', 'w9, #0x38edcc'),
    ('0x38ed9c', 'cmp', 'x8, x24'),
    ('0x38eda0', 'mov', 'x8, x24'),
    ('0x38eda4', 'b.eq', '#0x38edcc'),
    ('0x38edc8', 'b', '#0x38e438'),
    ('0x38edcc', 'cbnz', 'x8, #0x38eddc'),
    ('0x38edd8', 'bl', '#0x38ea5c'),
    ('0x38eddc', 'ldr', 'x0, [x23, #0x30]'),
    ('0x38ede0', 'mov', 'x1, x22'),
    ('0x38ede4', 'mov', 'x2, x21'),
    ('0x38ede8', 'mov', 'x3, x20'),
    ('0x38edec', 'mov', 'x4, x19'),
    ('0x38ee04', 'ldr', 'x16, [x8, #0x38]'),
    ('0x38ee10', 'br', 'x16'),
    ('0x38a010', 'adr', 'x8, #0x389368'),
    ('0x38a01c', 'str', 'x20, [x21, #0x30]'),
    ('0x38a020', 'stp', 'x8, xzr, [x21, #0x20]'),
    ('0x38c4d8', 'ldp', 'x10, x9, [x0, #0x28]'),
    ('0x38c4dc', 'ldr', 'x8, [x0, #0x20]'),
    ('0x38c4e0', 'add', 'x0, x9, x10, asr #1'),
    ('0x38c4e4', 'tbz', 'w10, #0, #0x38c4f0'),
    ('0x38c4ec', 'ldr', 'x8, [x9, x8]'),
    ('0x38c500', 'blr', 'x8'),
]
RANGES = [(0x389368,0x3893cc), (0x2c8788,0x2c87e8), (0x388e28,0x388e44),
          (0x38ed48,0x38ee14), (0x38e9f4,0x38ea5c), (0x21baf8,0x21bb0c), (0x202698,0x202858)]
GATES = [('missing_precondition','fallback'), ('active_current_mismatch','fallback'),
         ('inactive_current_nonzero','bridge'), ('active_current_matches','bridge'),
         ('inactive_current_zero','initialization_boundary'), ('active_current_zero','fallback')]
OUTCOMES = dict(bridge_first_external_call_boundary=6, bridge_null_return=2, fallback=12, initialization_boundary=4)
CLAIMS = dict(candidate_parameter_forwarding_verified=True, bounded_gate_controls_verified=True,
    actual_business_caller_type_or_table_identity_verified=False, actual_business_argument_observed=False,
    actual_security_callback_execution_verified=False, initial_rejection_cause_verified=False,
    ordinary_cronet_six_head_chain_verified=False, whole_request_native_python_differential_verified=False,
    complete_standalone_signer_verified=False, original_signature_runtime_equivalence_verified=False,
    online_header_acceptance_verified=False)


def validate(data):
    assert data['schema'] == 'vm9-cronet-candidate-security-route-20261118-v1'
    assert data['provenance']['original_ELF_sha256'] == ELF_SHA256
    assert data['static_instruction_bindings'] == [dict(offset=o, mnemonic=m, operands=a) for o,m,a in EXPECTED]
    assert data['conditional_route'] == dict(entry_offset='0x389368', intermediate_offset='0x38ed48',
        candidate_object_field='0x30', candidate_virtual_slot='0x38', selected_fixture_target='0x21baf8',
        security_bridge_offset='0x202698', entry_source_register='x2', intermediate_register='x5',
        bridge_destination_register='x4', actual_object_or_slot_target_observed=False)
    assert data['static_callback_setup'] == dict(target_address_instruction='0x38a010',target_function='0x389368',
        bound_target_field='0x20',bound_adjustment_field='0x28',bound_object_field='0x30',
        candidate_trampoline='0x38c4c8',setup_or_trampoline_emulated=False,
        actual_business_registration_or_invocation_observed=False)
    emulation = data['bounded_emulation']
    assert emulation['cases'] == 24 and emulation['outcomes'] == OUTCOMES
    assert emulation['original_helper_entries_per_case'] == 3 and emulation['out_of_scope_calls_executed'] == 0
    for key in ('unchanged_original_code', 'synthetic_objects_and_selected_tables_only', 'no_stubbed_or_replaced_instructions'):
        assert emulation[key] is True
    assert emulation['Android_execution'] is False
    assert len(data['case_controls']) == 24
    for n,case in enumerate(data['case_controls']):
        gate, outcome = GATES[n//4]
        if outcome == 'bridge':
            outcome = 'bridge_null_return' if n%4 == 0 else 'bridge_first_external_call_boundary'
        assert case == dict(gate=gate, source_control_ordinal=n%4, source_argument_is_null=n%4==0,
            outcome=outcome, third_argument_forwarding_verified=gate in ('inactive_current_nonzero','active_current_matches'),
            original_helper_entries_executed=3, out_of_scope_calls_executed=0)
    assert [(int(r['start'],16),int(r['end_exclusive'],16)) for r in data['original_code_ranges']] == RANGES
    assert all(len(r['sha256'])==64 and all(c in '0123456789abcdef' for c in r['sha256']) for r in data['original_code_ranges'])
    assert data['claims'] == CLAIMS
    assert data['privacy']['raw_pointers_requests_headers_or_identifiers_published'] is False


def verify_elf(data, path):
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    from elftools.elf.elffile import ELFFile
    from elftools.elf.relocation import RelocationSection
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == ELF_SHA256
    elf = ELFFile(BytesIO(raw))
    loads = [s for s in elf.iter_segments() if s['p_type']=='PT_LOAD']
    def read(start,end):
        seg = next(s for s in loads if s['p_flags']&1 and s['p_vaddr']<=start and end<=s['p_vaddr']+s['p_filesz'])
        offset = seg['p_offset']+start-seg['p_vaddr']
        return raw[offset:offset+end-start]
    decoder = Cs(CS_ARCH_ARM64,CS_MODE_ARM)
    for offset,mnemonic,operands in EXPECTED:
        address = int(offset,16)
        instruction, = decoder.disasm(read(address,address+4),address)
        assert (instruction.mnemonic,instruction.op_str)==(mnemonic,operands), offset
    for record in data['original_code_ranges']:
        assert hashlib.sha256(read(int(record['start'],16),int(record['end_exclusive'],16))).hexdigest()==record['sha256']
    found = {r['r_offset']:r['r_addend'] for s in elf.iter_sections()
             if isinstance(s,RelocationSection) and s.is_RELA()
             for r in s.iter_relocations() if r['r_info_type']==1027 and r['r_offset'] in (0x5c9860,0x5c90c8)}
    assert found == {0x5c9860:0x21baf8,0x5c90c8:0x202698}
    return dict(original_instructions=len(EXPECTED),original_code_ranges=len(RANGES),relative_relocations=2)


def negatives(data):
    damaged_records = []
    for n in range(24):
        damaged = deepcopy(data)
        damaged['case_controls'][n]['outcome'] = 'unverified_success'
        damaged_records.append(damaged)
    for section,key in [('conditional_route','actual_object_or_slot_target_observed'),
                        ('static_callback_setup','setup_or_trampoline_emulated'),
                        ('static_callback_setup','actual_business_registration_or_invocation_observed'),
                        ('bounded_emulation','Android_execution'),
                        ('privacy','raw_pointers_requests_headers_or_identifiers_published')]:
        damaged = deepcopy(data)
        damaged[section][key] = True
        damaged_records.append(damaged)
    for section,key,value in [('conditional_route','entry_source_register','x3'),
                              ('conditional_route','candidate_virtual_slot','0x30'),
                              ('bounded_emulation','out_of_scope_calls_executed',1)]:
        damaged = deepcopy(data)
        damaged[section][key] = value
        damaged_records.append(damaged)
    for key in CLAIMS:
        damaged = deepcopy(data)
        damaged['claims'][key] = not damaged['claims'][key]
        damaged_records.append(damaged)
    damaged = deepcopy(data)
    damaged['static_instruction_bindings'][0]['operands'] = 'x19, x3'
    damaged_records.append(damaged)
    for damaged in damaged_records:
        try:
            validate(damaged)
        except (AssertionError,KeyError):
            continue
        raise AssertionError('damaged evidence accepted')
    return len(damaged_records)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf',type=Path,help='Optional original libsscronet.so; requires Capstone and pyelftools')
    args = parser.parse_args()
    data = json.loads(EVIDENCE.read_text(encoding='utf-8'))
    validate(data)
    result = dict(candidate_route_evidence_verified=True,damaged_evidence_rejected=negatives(data),
                  retained_emulation_cases=24,actual_business_caller_identity_verified=False)
    if args.elf:
        result['original_ELF_binding'] = verify_elf(data,args.elf)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
