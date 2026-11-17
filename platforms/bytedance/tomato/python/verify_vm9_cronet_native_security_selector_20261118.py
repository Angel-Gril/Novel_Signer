"""Verify native/JNI selector evidence and independent read-only native callback registration snapshots."""
import argparse
from copy import deepcopy
import hashlib
from io import BytesIO
import json
from pathlib import Path

EVIDENCE=Path(__file__).resolve().parents[1]/'evidence/vm9_cronet_native_security_selector_20261118.json'
CRONET_SHA256='ab0547460f1c06e5111b69826d2277f145aad4f79c7d2b7aea0356dcf25e49ac'
METASEC_SHA256='712384bd0e310fded0ae9b6441c2a264dd356dfaf1ef42d2ebc3c790fdd9269c'
EXPECTED=[
    ('0x472ac0','adrp','x8, #0x5f5000'), ('0x472ac4','add','x8, x8, #0x458'),
    ('0x472ac8','ldar','x23, [x8]'), ('0x472acc','ldrb','w8, [x26]'),
    ('0x472ad0','cbz','x23, #0x472e10'), ('0x472ad4','cbnz','w8, #0x472e34'),
    ('0x472b00','bl','#0x32baf0'), ('0x472b04','str','x0, [x19, #0x1108]'),
    ('0x472b08','mov','x0, x21'), ('0x472b0c','mov','x1, x22'), ('0x472b10','blr','x23'),
    ('0x472b20','cbz','x21, #0x472e34'),
    ('0x472e10','cbnz','w8, #0x472e34'), ('0x472e14','add','x1, sp, #0x70'),
    ('0x472e18','add','x2, sp, #0x58'), ('0x472e1c','mov','x0, x19'),
    ('0x472e20','mov','x3, x20'), ('0x472e24','bl','#0x4077e4'),
    ('0x4077e4','bti','c'), ('0x4077e8','mov','x8, x0'),
    ('0x4077ec','ldr','x0, [x0, #0x530]'), ('0x4077f0','mov','x4, x3'),
    ('0x4077f4','mov','x3, x8'), ('0x4077f8','ldr','x9, [x0]'),
    ('0x4077fc','ldr','x16, [x9, #0x38]'), ('0x407800','br','x16'),
    ('0x472370','mov','x20, x2'), ('0x472374','mov','x19, x1'),
    ('0x472428','mov','w8, #0x11b8'), ('0x472430','add','x26, x19, x8'),
    ('0x26970c','adrp','x8, #0x5f5000'), ('0x269710','add','x8, x8, #0x458'),
    ('0x269714','stlr','x1, [x8]'), ('0x269718','ret',''),
    ('0x47326c','adrp','x8, #0x5f5000'), ('0x473270','add','x8, x8, #0x458'),
    ('0x473274','stlr','x0, [x8]'), ('0x473278','ret',''),
    ('0x405310','mov','x27, x3'), ('0x405404','str','x27, [x20, #0x530]'),
    ('0x21934c','mov','x3, x19'), ('0x219358','bl','#0x408cfc'),
    ('0x408d30','mov','x22, x3'), ('0x408d58','mov','x3, x22'), ('0x408d70','bl','#0x4052dc'),
]
RANGES=[(0x472ac0,0x472b14),(0x472e10,0x472e34),(0x4077e4,0x407804),
        (0x21baf8,0x21bb0c),(0x202698,0x202858)]
WINDOWS=[('0x472ac0',24),('0x4077e4',32),('0x21baf8',20),('0x202698',8)]
OUTCOMES=dict(JNI_bridge_before_external_call=3,JNI_bridge_null_return=1,
              native_selected_before_clock_call=4,processing_skipped=24)
SELECTOR=dict(function_offset='0x472340',native_callback_slot='0x5f5458',
    request_register='x19',skip_byte_field='0x11b8',native_call_offset='0x472b10',
    null_slot_JNI_fallback_call_offset='0x472e24',JNI_forwarder='0x4077e4',
    request_delegate_field='0x530',delegate_virtual_slot='0x38',
    output_source_register='x20',bridge_output_register='x4',
    native_requires_nonnull_slot_and_zero_skip_byte=True,JNI_requires_null_slot_and_zero_skip_byte=True)
SNAPSHOT=dict(independent_windows=2,samples_per_window=2,total_slot_samples=4,
    sample_interval_seconds=3,package_and_UID_reverified=True,arm64_and_pointer_size_reverified=True,
    positive_null_and_unreadable_controls_passed=True,Cronet_code_windows_bound=8,
    native_target_prefix_bound_samples=2,native_target_prefix_bytes=64,
    request_security_JNI_cache_present=False,context_security_JNI_cache_present=False,
    business_or_native_hooks_installed=False,security_callback_or_registration_setter_invoked=False,
    business_UI_actions=0,cleanup_complete=True,same_target_process_survived_each_window=True,
    same_business_response_identity_join_claimed=False)
TARGET=dict(module_name='libmetasec_ml.so',module_offset='0x27d288',executable=True,
            registered_slot_samples=4,original_code_prefix_bytes=64)
CLAIMS=dict(native_callback_registered_at_independent_snapshots_verified=True,
    original_native_JNI_selector_conditions_verified=True,original_request_delegate_forwarder_verified=True,
    actual_business_skip_byte_observed=False,actual_business_branch_execution_verified=False,
    actual_native_callback_execution_verified=False,same_business_response_native_callback_join_verified=False,
    initial_rejection_cause_verified=False,ordinary_cronet_six_head_chain_verified=False,
    whole_request_native_python_differential_verified=False,complete_standalone_signer_verified=False,
    original_signature_runtime_equivalence_verified=False,online_header_acceptance_verified=False)


def validate(data):
    assert data['schema']=='vm9-cronet-native-security-selector-20261118-v1'
    assert data['provenance']['original_Cronet_ELF_sha256']==CRONET_SHA256
    assert data['provenance']['original_Metasec_ELF_sha256']==METASEC_SHA256
    assert data['static_instruction_bindings']==[dict(offset=o,mnemonic=m,operands=a) for o,m,a in EXPECTED]
    assert data['selector']==SELECTOR and data['independent_runtime_snapshots']==SNAPSHOT
    assert data['registered_native_target']==TARGET and data['claims']==CLAIMS
    emulation=data['bounded_emulation']
    assert emulation==dict(cases=32,outcomes=OUTCOMES,unchanged_original_code=True,synthetic_memory_only=True,
        native_callback_invocations=0,JNI_executions=0,Android_execution=False,
        seeded_dispatch_blocks_only=True,frozen_traces_replayed_exactly=True)
    assert len(data['case_controls'])==32
    for n,case in enumerate(data['case_controls']):
        present=n>=16
        flag=(0,1,128,255)[n%16//4]
        null=n%4==0
        outcome='processing_skipped' if flag else 'native_selected_before_clock_call' if present else 'JNI_bridge_null_return' if null else 'JNI_bridge_before_external_call'
        assert case==dict(native_callback_present=present,skip_byte_control=flag,output_control_ordinal=n%4,
            output_argument_is_null=null,outcome=outcome,original_JNI_bridge_reached=not flag and not present,
            out_of_scope_calls_executed=0)
    assert [(int(r['start'],16),int(r['end_exclusive'],16)) for r in data['original_code_ranges']]==RANGES
    assert [(w['offset'],w['size']) for w in data['runtime_Cronet_code_windows']]==WINDOWS
    for record in data['original_code_ranges']+data['runtime_Cronet_code_windows']:
        assert len(record['sha256'])==64 and all(c in '0123456789abcdef' for c in record['sha256'])
    assert len(data['runtime_Metasec_prefix_sha256'])==64
    assert data['privacy']['raw_addresses_requests_headers_UIDs_or_identifiers_published'] is False


def load_elf(path,expected_sha):
    from elftools.elf.elffile import ELFFile
    raw=path.read_bytes()
    assert hashlib.sha256(raw).hexdigest()==expected_sha
    elf=ELFFile(BytesIO(raw))
    loads=[s for s in elf.iter_segments() if s['p_type']=='PT_LOAD']
    def read(address,size):
        seg=next(s for s in loads if s['p_flags']&1 and s['p_vaddr']<=address and address+size<=s['p_vaddr']+s['p_filesz'])
        offset=seg['p_offset']+address-seg['p_vaddr']
        return raw[offset:offset+size]
    return elf,read


def verify_cronet(data,path):
    from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
    from elftools.elf.relocation import RelocationSection
    elf,read=load_elf(path,CRONET_SHA256)
    decoder=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
    for offset,mnemonic,operands in EXPECTED:
        address=int(offset,16)
        instruction,=decoder.disasm(read(address,4),address)
        assert (instruction.mnemonic,instruction.op_str)==(mnemonic,operands),offset
    for row in data['original_code_ranges']:
        start,end=int(row['start'],16),int(row['end_exclusive'],16)
        assert hashlib.sha256(read(start,end-start)).hexdigest()==row['sha256']
    for row in data['runtime_Cronet_code_windows']:
        assert hashlib.sha256(read(int(row['offset'],16),row['size'])).hexdigest()==row['sha256']
    refs={r['r_offset']:r['r_addend'] for section in elf.iter_sections()
        if isinstance(section,RelocationSection) and section.is_RELA() for r in section.iter_relocations()
        if r['r_info_type']==1027 and r['r_offset'] in (0x5c9860,0x5c90c8)}
    assert refs=={0x5c9860:0x21baf8,0x5c90c8:0x202698}
    return dict(instructions=len(EXPECTED),emulated_code_ranges=5,runtime_code_windows=4,relative_relocations=2)


def verify_metasec(data,path):
    _,read=load_elf(path,METASEC_SHA256)
    assert hashlib.sha256(read(0x27d288,64)).hexdigest()==data['runtime_Metasec_prefix_sha256']
    return dict(original_prefix_bytes=64,runtime_prefix_samples_bound=2)


def negatives(data):
    damaged_records=[]
    for n in range(32):
        damaged=deepcopy(data)
        damaged['case_controls'][n]['outcome']='unverified_success'
        damaged_records.append(damaged)
    for key in CLAIMS:
        damaged=deepcopy(data)
        damaged['claims'][key]=not damaged['claims'][key]
        damaged_records.append(damaged)
    mutations=[('registered_native_target','module_name','libsscronet.so'),
        ('registered_native_target','module_offset','0x202698'),
        ('selector','native_requires_nonnull_slot_and_zero_skip_byte',False),
        ('selector','skip_byte_field','0x530'),
        ('independent_runtime_snapshots','business_or_native_hooks_installed',True),
        ('independent_runtime_snapshots','security_callback_or_registration_setter_invoked',True),
        ('independent_runtime_snapshots','cleanup_complete',False),
        ('independent_runtime_snapshots','native_target_prefix_bound_samples',0),
        ('independent_runtime_snapshots','same_business_response_identity_join_claimed',True),
        ('bounded_emulation','native_callback_invocations',1),
        ('privacy','raw_addresses_requests_headers_UIDs_or_identifiers_published',True)]
    for owner,key,value in mutations:
        damaged=deepcopy(data)
        damaged[owner][key]=value
        damaged_records.append(damaged)
    damaged=deepcopy(data)
    damaged['static_instruction_bindings'][4]['mnemonic']='cbnz'
    damaged_records.append(damaged)
    for damaged in damaged_records:
        try:
            validate(damaged)
        except (AssertionError,KeyError):
            continue
        raise AssertionError('damaged evidence accepted')
    return len(damaged_records)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf',type=Path,help='Original libsscronet.so; requires Capstone and pyelftools')
    parser.add_argument('--metasec-elf',type=Path,help='Original libmetasec_ml.so; requires pyelftools')
    args=parser.parse_args()
    data=json.loads(EVIDENCE.read_text(encoding='utf-8'))
    validate(data)
    result=dict(native_registration_snapshot_verified=True,retained_emulation_cases=32,
                damaged_evidence_rejected=negatives(data),actual_native_callback_execution_verified=False)
    if args.elf:
        result['original_Cronet_bindings']=verify_cronet(data,args.elf)
    if args.metasec_elf:
        result['original_Metasec_binding']=verify_metasec(data,args.metasec_elf)
    print(json.dumps(result))


if __name__=='__main__':
    main()
