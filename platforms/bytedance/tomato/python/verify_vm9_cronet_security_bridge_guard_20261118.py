"""Verify the bounded static/ARM64-emulation guard evidence; optionally bind the original ELF."""
import argparse
from copy import deepcopy
import hashlib
from io import BytesIO
import json
from pathlib import Path

EVIDENCE = Path(__file__).resolve().parents[1] / 'evidence/vm9_cronet_security_bridge_guard_20261118.json'
ELF_SHA256 = 'ab0547460f1c06e5111b69826d2277f145aad4f79c7d2b7aea0356dcf25e49ac'
EXPECTED = [
    ('0x202698', 'bti', 'c'),
    ('0x20269c', 'cbz', 'x4, #0x202854'),
    ('0x2026bc', 'mov', 'x19, x4'),
    ('0x2026d0', 'bl', '#0x323310'),
    ('0x202744', 'adrp', 'x5, #0x5ef000'),
    ('0x202748', 'add', 'x5, x5, #0x8d8'),
    ('0x20275c', 'bl', '#0x1efffc'),
    ('0x202774', 'bl', '#0x1f46ac'),
    ('0x202854', 'ret', ''),
    ('0x21baf8', 'bti', 'c'),
    ('0x21bafc', 'ldr', 'x0, [x0, #8]'),
    ('0x21bb00', 'ldr', 'x8, [x0]'),
    ('0x21bb04', 'ldr', 'x16, [x8, #0x28]'),
    ('0x21bb08', 'br', 'x16'),
    ('0x219b28', 'adrp', 'x8, #0x5c9000'),
    ('0x219b2c', 'add', 'x8, x8, #0x828'),
    ('0x219b30', 'str', 'x8, [x19]'),
]


def validate(data):
    assert data['schema'] == 'vm9-cronet-security-bridge-guard-20261118-v1'
    assert data['provenance']['original_ELF_sha256'] == ELF_SHA256
    assert data['static_instruction_bindings'] == [dict(offset=o, mnemonic=m, operands=a) for o,m,a in EXPECTED]
    guard = data['bridge_guard']
    assert guard == dict(function_offset='0x202698', tested_register='x4', argument_ordinal=5,
        null_branch_offset='0x20269c', null_return_offset='0x202854',
        first_external_call_offset='0x2026d0', JNI_helper_call_offset='0x202774',
        actual_business_argument_observed=False)
    assert data['static_forwarding'] == dict(function_offset='0x21baf8', owner_delegate_field='0x8',
        delegate_function_slot='0x28', tail_branch=True, preserves_x1_through_x4=True,
        owner_table_base='0x5c9828', owner_table_security_slot='0x38',
        owner_security_relocation_slot='0x5c9860', owner_security_target='0x21baf8',
        delegate_security_relocation_slot='0x5c90c8', delegate_security_target='0x202698',
        observed_business_execution=False)
    emulation = data['bounded_emulation']
    assert emulation['original_prefix_cases'] == 8 and emulation['synthetic_forwarded_cases'] == 4
    assert emulation['null_cases_returned'] == 3 and emulation['nonnull_cases_stopped_before_external_call'] == 9
    assert emulation['external_calls_executed'] == 0
    for field in ('unchanged_original_code', 'synthetic_objects_only', 'forwarded_arguments_preserved'):
        assert emulation[field] is True
    assert emulation['Android_runtime_execution'] is False
    for value in data['claims'].values():
        assert type(value) is bool
    for field in ('static_null_guard_verified', 'bounded_original_prefix_emulation_verified'):
        assert data['claims'][field] is True
    for field in ('actual_business_null_argument_verified', 'actual_security_bridge_execution_verified',
        'initial_rejection_cause_verified', 'ordinary_cronet_six_head_chain_verified',
        'whole_request_native_python_differential_verified', 'complete_standalone_signer_verified',
        'original_signature_runtime_equivalence_verified', 'online_header_acceptance_verified'):
        assert data['claims'][field] is False
    assert data['excluded_analysis']['complete_six_function_Ghidra_batch_verified'] is False
    assert data['excluded_analysis']['owned_analysis_processes_remaining'] == 0
    assert data['privacy']['raw_pointers_request_response_or_header_values_published'] is False


def verify_elf(data, path):
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    from elftools.elf.elffile import ELFFile
    from elftools.elf.relocation import RelocationSection
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == ELF_SHA256
    elf = ELFFile(BytesIO(raw))
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    segments = [s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']
    for offset, mnemonic, operands in EXPECTED:
        address = int(offset,16)
        segment = next(s for s in segments if s['p_flags'] & 1 and
            s['p_vaddr'] <= address and address+4 <= s['p_vaddr']+s['p_filesz'])
        file_offset = segment['p_offset']+address-segment['p_vaddr']
        instruction, = decoder.disasm(raw[file_offset:file_offset+4],address)
        assert (instruction.mnemonic,instruction.op_str) == (mnemonic,operands), (
            offset, (instruction.mnemonic, instruction.op_str), (mnemonic, operands))
    wanted = {0x5c9860:0x21baf8, 0x5c90c8:0x202698, 0x5c9858:0x21ab88}
    found = {}
    for section in elf.iter_sections():
        if isinstance(section,RelocationSection) and section.is_RELA():
            for relocation in section.iter_relocations():
                if relocation['r_offset'] in wanted:
                    assert relocation['r_info_type'] == 1027
                    found[relocation['r_offset']] = relocation['r_addend']
    assert found == wanted
    return dict(original_instruction_bindings=len(EXPECTED),relative_relocation_bindings=len(wanted))


def negatives(data):
    mutations = [
        ('bridge_guard','tested_register','x3'), ('bridge_guard','null_return_offset','0x2026d0'),
        ('bridge_guard','actual_business_argument_observed',True),
        ('static_forwarding','delegate_function_slot','0x20'),
        ('static_forwarding','owner_table_security_slot','0x30'),
        ('static_forwarding','preserves_x1_through_x4',False),
        ('static_forwarding','observed_business_execution',True),
        ('bounded_emulation','original_prefix_cases',7), ('bounded_emulation','synthetic_forwarded_cases',3),
        ('bounded_emulation','null_cases_returned',0), ('bounded_emulation','external_calls_executed',1),
        ('bounded_emulation','unchanged_original_code',False), ('bounded_emulation','Android_runtime_execution',True),
        ('excluded_analysis','complete_six_function_Ghidra_batch_verified',True),
        ('excluded_analysis','owned_analysis_processes_remaining',1),
        ('privacy','raw_pointers_request_response_or_header_values_published',True),
    ]
    mutations.extend(('claims', key, not value) for key,value in data['claims'].items())
    rejected = 0
    for owner,key,value in mutations:
        damaged=deepcopy(data)
        damaged[owner][key]=value
        try:
            validate(damaged)
        except (AssertionError,KeyError):
            rejected+=1
        else:
            raise AssertionError(('damaged evidence accepted',owner,key))
    for index,field,value in ((1,'mnemonic','cbnz'),(1,'operands','x3, #0x202854'),
                              (13,'mnemonic','blr')):
        damaged=deepcopy(data)
        damaged['static_instruction_bindings'][index][field]=value
        try:
            validate(damaged)
        except (AssertionError,KeyError):
            rejected+=1
        else:
            raise AssertionError(('damaged instruction binding accepted',index,field))
    return rejected


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf',type=Path,help='Optional original libsscronet.so; requires capstone and pyelftools')
    args=parser.parse_args()
    data=json.loads(EVIDENCE.read_text(encoding='utf-8'))
    validate(data)
    result=dict(static_guard_evidence_verified=True,damaged_evidence_rejected=negatives(data),
        bounded_emulation_cases=12,actual_business_argument_observed=False)
    if args.elf:
        result['original_ELF_binding']=verify_elf(data,args.elf)
    print(json.dumps(result))


if __name__=='__main__':
    main()
