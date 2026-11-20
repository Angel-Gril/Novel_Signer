"""Frozen receipt for the current native gettimeofday pre-SVC/return-path link.

The capture continues the accepted digest execution with the existing owners,
then stops before the fifth main-image SVC enters its handler. Pinned ELF
instructions bind that pre-SVC state to the static gettimeofday return path.
This does not increase the four-SVC cap or claim dynamic return/suffix completion.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import verify_vm9_native_171_suffix_digest_20261120 as digest

EVIDENCE = digest.EVIDENCE.with_name('vm9_native_171_gettimeofday_return_20261120.json')
SCHEMA = 'vm9-native-171-gettimeofday-return-20261120-v1'
MAX_WINDOW = 400000
MAX_MAIN_SVCS = 4
CONTROL = {'base': 0x122C0000, 'property_profile': 'absent', 'null_at': 'class0'}
SVC_THUNK = [
    (0x271D9C, '00a403d1', 'sub', 'x0, x0, #0xe9'),
    (0x271DA0, 'e80300aa', 'mov', 'x8, x0'),
    (0x271DA4, 'e00301aa', 'mov', 'x0, x1'),
    (0x271DA8, 'e10302aa', 'mov', 'x1, x2'),
    (0x271DAC, 'e20303aa', 'mov', 'x2, x3'),
    (0x271DB0, 'e30304aa', 'mov', 'x3, x4'),
    (0x271DB4, 'e40305aa', 'mov', 'x4, x5'),
    (0x271DB8, 'e50306aa', 'mov', 'x5, x6'),
    (0x271DBC, '010000d4', 'svc', '#0'),
    (0x271DC0, '1f0440b1', 'cmn', 'x0, #1, lsl #12'),
    (0x271DC4, '009480da', 'cneg', 'x0, x0, hi'),
    (0x271DC8, '08fdff54', 'b.hi', '#0x271d68'),
    (0x271DCC, 'c0035fd6', 'ret', ''),
]
GETTIME_RETURN = [
    (0x272920, '1ffdff97', 'bl', '#0x271d9c'),
    (0x272924, 'e80740f9', 'ldr', 'x8, [sp, #8]'),
    (0x272928, '1f0000f1', 'cmp', 'x0, #0'),
    (0x27292C, '00a19fda', 'csinv', 'x0, x8, xzr, ge'),
    (0x272930, '530000b4', 'cbz', 'x19, #0x272938'),
    (0x272934, '600200f9', 'str', 'x0, [x19]'),
    (0x272938, '881640f9', 'ldr', 'x8, [x20, #0x28]'),
    (0x27293C, 'a9835ff8', 'ldur', 'x9, [x29, #-8]'),
    (0x272940, '1f0109eb', 'cmp', 'x8, x9'),
    (0x272944, 'a1000054', 'b.ne', '#0x272958'),
    (0x272948, 'f44f43a9', 'ldp', 'x20, x19, [sp, #0x30]'),
    (0x27294C, 'fd7b42a9', 'ldp', 'x29, x30, [sp, #0x20]'),
    (0x272950, 'ff030191', 'add', 'sp, sp, #0x40'),
    (0x272954, 'c0035fd6', 'ret', ''),
]
CLAIMS = dict(
    retained_suffix_digest_prefix_verified=True,
    original_current_path_continued_after_digest=True,
    fifth_main_image_svc_identified_before_execution=True,
    fifth_main_image_svc_is_gettimeofday_169=True,
    four_existing_main_image_svcs_preserved=True,
    fifth_main_image_svc_handler_not_entered=True,
    post_digest_instruction_window_within_public_limit=True,
    post_digest_allocation_and_service_deltas_recorded=True,
    gettimeofday_return_path_static_binding_verified=True,
    gettimeofday_return_path_dynamically_executed=False,
    native_memory_used_as_python_model_input=False,
    current_native_suffix_return_verified=False,
    complete_configuration_provenance_verified=False,
    ordinary_Cronet_six_headers_verified=False,
    online_acceptance_verified=False,
    complete_standalone_signer_verified=False,
    new_providers=False,
    Android_execution=False,
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_fingerprints() -> dict:
    return {
        'boundary_verifier_sha256': sha256(Path(__file__)),
        'digest_verifier_sha256': sha256(Path(digest.__file__)),
        'context_verifier_sha256': sha256(Path(digest.context.__file__)),
    }


def baseline() -> dict:
    data = json.loads(digest.EVIDENCE.read_text())
    digest.validate(data)
    return data


def providers() -> dict:
    return {
        'inherited_owner': 'verify_vm9_native_171_suffix_digest_20261120.py',
        'independent_model_owner_added': False,
        'OS_JNI_or_internal_helper_providers_added': False,
        'maximum_handler_reads': 2,
        'maximum_main_SVCs': MAX_MAIN_SVCS,
        'public_instruction_window_limit': MAX_WINDOW,
        'original_scope_kept': True,
        'stop_policy': 'before fifth main-image SVC instruction is executed',
    }


def _binding_rows(path: Path, expected: list[tuple]) -> list[dict]:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    _, _, read = digest.graph.inputs.load_elf(path)
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    rows = []
    for offset, raw_hex, mnemonic, operands in expected:
        raw = read(offset, 4)
        instruction, = decoder.disasm(raw, offset)
        assert raw.hex() == raw_hex
        assert (instruction.mnemonic, instruction.op_str) == (mnemonic, operands)
        rows.append(dict(offset=hex(offset), bytes=raw_hex, mnemonic=mnemonic, operands=operands))
    return rows


def _runtime_return_link(row: dict) -> dict:
    boundary = row['svc_boundary']
    regs = boundary['registers']
    base = row['control']['base']
    lr = int(regs['x30'], 16)
    sp = int(boundary['sp'], 16)
    assert boundary['pc_offset'] == '0x271dbc'
    assert boundary['svc_number'] == 169 and regs['x8'] == '0xa9'
    assert lr == base + 0x272924
    assert int(regs['x0'], 16) == sp + 8
    assert regs['x1'] == '0x0'
    return dict(
        svc_pc_offset=boundary['pc_offset'],
        live_syscall_number=boundary['svc_number'],
        live_lr_offset=hex(lr - base),
        timeval_pointer_equals_sp_plus_8=True,
        timezone_pointer_is_null=True,
        syscall_wrapper_bl_returns_to_live_lr=True,
        post_svc_return_path_dynamically_executed=False,
    )


def gettimeofday_return_path(path: Path, row: dict) -> dict:
    return dict(
        evidence_kind='pinned_ELF_static_instructions_linked_to_pre_SVC_registers',
        svc_thunk=_binding_rows(path, SVC_THUNK),
        caller_and_return=_binding_rows(path, GETTIME_RETURN),
        runtime_pre_svc_link=_runtime_return_link(row),
        semantics=dict(
            syscall_number_expression='0x192 - 0xe9 = 0xa9 (169)',
            result_selection='x0 >= 0 selects timeval.tv_sec from [sp+8]; x0 < 0 selects -1',
            optional_output='store selected x0 through x19 when x19 is non-NULL',
            stack_canary='compare saved TLS canary before restoring registers and returning',
        ),
    )


def run(path: Path, libc: Path, inherited: dict | None = None) -> dict:
    inherited = inherited or baseline()
    digest.verify_images(path, libc)
    assert sha256(path) == inherited['provenance']['Metasec_sha256']
    assert sha256(libc) == inherited['provenance']['Bionic_sha256']
    controls = digest.context.controls()
    assert controls[0] == CONTROL
    rows = digest.boundary_replay(path, libc, case_controls=controls[:1])
    assert len(rows) == 1
    return_path = gettimeofday_return_path(path, rows[0])
    return {
        'schema': SCHEMA,
        'claims': dict(CLAIMS),
        'providers': providers(),
        'input_provenance': {
            'inherited_native_provenance': inherited['provenance'],
            'Metasec_sha256': sha256(path),
            'Bionic_sha256': sha256(libc),
        },
        'source_fingerprints': source_fingerprints(),
        'image_bindings': {'instruction_bindings': len(digest.EXPECTED), 'independent_prefix_cases': 16},
        'gettimeofday_return_path': return_path,
        'case_result': rows[0],
    }


def validate(data: dict) -> None:
    inherited = baseline()
    assert data['schema'] == SCHEMA
    assert data['claims'] == CLAIMS
    assert data['providers'] == providers()
    assert data['input_provenance'] == {
        'inherited_native_provenance': inherited['provenance'],
        'Metasec_sha256': inherited['provenance']['Metasec_sha256'],
        'Bionic_sha256': inherited['provenance']['Bionic_sha256'],
    }
    assert data['source_fingerprints'] == source_fingerprints()
    assert data['image_bindings'] == {
        'instruction_bindings': len(digest.EXPECTED), 'independent_prefix_cases': 16}
    static_path = data['gettimeofday_return_path']
    assert static_path['evidence_kind'] == 'pinned_ELF_static_instructions_linked_to_pre_SVC_registers'
    assert static_path['svc_thunk'] == [
        dict(offset=hex(offset), bytes=raw, mnemonic=mnemonic, operands=operands)
        for offset, raw, mnemonic, operands in SVC_THUNK]
    assert static_path['caller_and_return'] == [
        dict(offset=hex(offset), bytes=raw, mnemonic=mnemonic, operands=operands)
        for offset, raw, mnemonic, operands in GETTIME_RETURN]
    assert static_path['semantics'] == dict(
        syscall_number_expression='0x192 - 0xe9 = 0xa9 (169)',
        result_selection='x0 >= 0 selects timeval.tv_sec from [sp+8]; x0 < 0 selects -1',
        optional_output='store selected x0 through x19 when x19 is non-NULL',
        stack_canary='compare saved TLS canary before restoring registers and returning')

    row = data['case_result']
    assert static_path['runtime_pre_svc_link'] == _runtime_return_link(row)
    old = inherited['case_results'][0]
    assert row['control'] == CONTROL
    assert row['retained_constants_prefix_verified'] is True
    for key in ('instruction_observations', 'trace_sha256', 'code_sha256'):
        assert row['retained_prefix_' + key] == old['retained_prefix_' + key]
    assert row['original_scope_kept'] is True
    assert row['original_direct_calls'] == list(map(hex, digest.CALLS))
    assert row['current_mode'] == 0
    assert row['current_native_suffix_return_verified'] is False
    assert row['main_image_SVC_boundaries'] == old['main_image_SVC_boundaries']
    assert row['main_image_svc_count_at_boundary'] == MAX_MAIN_SVCS
    assert len(row['main_image_SVC_boundaries']) == MAX_MAIN_SVCS
    assert row['entered_svc_handler'] is False
    assert row['handler_read_count_delta'] == 0
    assert row['main_image_svc_count_delta'] == 0
    assert row['target_suffix_svc_reached'] is False

    windows = row['instruction_observation_windows']
    assert len(windows) == 2 and all(0 < count < MAX_WINDOW for count in windows)
    assert windows[0] == row['continuation_instruction_observations'] - row['post_digest_instruction_observations']
    assert windows[1] == row['post_digest_instruction_observations']
    assert sum(windows) == row['total_continuation_instruction_observations']
    assert row['total_continuation_instruction_observations'] == row['continuation_instruction_observations']
    assert row['public_instruction_window_limit'] == MAX_WINDOW
    assert row['post_digest_instruction_observations'] == 91729

    boundary = row['svc_boundary']
    assert boundary['kind'] == 'first_unpermitted_main_image_svc'
    assert boundary['pc_offset'] == '0x271dbc'
    assert boundary['instruction'] == '010000d4'
    assert boundary['svc_number'] == 169
    assert boundary['svc_args'][0] != '0x0' and boundary['svc_args'][1:] == ['0x0'] * 3
    assert boundary['registers']['x8'] == '0xa9'
    assert boundary['registers']['x1'] == boundary['registers']['x2'] == boundary['registers']['x3'] == '0x0'
    assert boundary['native_memory_used_as_python_model_input'] is False
    assert row['observation_stop_before_svc'] == boundary['pc_offset']
    assert row['observation_stop_before'] == '0x286e10'
    assert row['post_digest_allocator_event_count'] == 97
    assert len(row['post_digest_allocator_events_sha256']) == 64
    assert row['post_digest_service_delta'] and all(v == 0 for v in row['post_digest_service_delta'].values())
    assert row['post_digest_service_counts'] == row['service_counts']
    assert row['required_main_image_svc_limit'] == MAX_MAIN_SVCS
    for key in ('allocation_ledger_sha256', 'continuation_trace_sha256', 'continuation_code_sha256'):
        assert digest.graph.inputs.is_digest(row[key])


def damaged_evidence_rejected(data: dict) -> int:
    cases = [
        (('claims', 'fifth_main_image_svc_handler_not_entered'), False),
        (('providers', 'maximum_main_SVCs'), 5),
        (('case_result', 'entered_svc_handler'), True),
        (('case_result', 'main_image_svc_count_at_boundary'), 5),
        (('case_result', 'svc_boundary', 'svc_number'), 170),
        (('case_result', 'svc_boundary', 'pc_offset'), '0x286ec8'),
        (('case_result', 'post_digest_instruction_observations'), MAX_WINDOW),
        (('case_result', 'instruction_observation_windows', 1), MAX_WINDOW),
        (('case_result', 'svc_boundary', 'native_memory_used_as_python_model_input'), True),
        (('case_result', 'current_native_suffix_return_verified'), True),
    ]
    for path, value in cases:
        bad = deepcopy(data)
        target = bad
        for part in path[:-1]:
            target = target[part]
        target[path[-1]] = value
        try:
            validate(bad)
        except (AssertionError, KeyError, TypeError, ValueError):
            continue
        raise AssertionError(f'damaged boundary evidence accepted: {path}')
    return len(cases)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf', type=Path)
    parser.add_argument('--libc', type=Path)
    parser.add_argument('--capture', action='store_true', help='run and freeze this boundary once')
    parser.add_argument('--replay', action='store_true', help='re-run and compare with frozen evidence')
    args = parser.parse_args()
    if args.capture and args.replay:
        parser.error('--capture and --replay are mutually exclusive')
    if (args.capture or args.replay) and (not args.elf or not args.libc):
        parser.error('--capture/--replay require --elf and --libc')
    if not args.capture and not EVIDENCE.exists():
        parser.error('frozen boundary evidence is missing; run --capture with --elf and --libc')

    if args.capture:
        if EVIDENCE.exists():
            parser.error('refusing to overwrite frozen boundary evidence')
        data = run(args.elf, args.libc)
        validate(data)
        rejected = damaged_evidence_rejected(data)
        EVIDENCE.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n')
    else:
        data = json.loads(EVIDENCE.read_text())
        validate(data)
        if args.replay:
            actual = run(args.elf, args.libc, baseline())
            assert actual == data, 'fresh native boundary replay differs from frozen evidence'
        rejected = damaged_evidence_rejected(data)

    print(json.dumps({
        'schema': SCHEMA,
        'damaged_evidence_rejected': rejected,
        'fifth_main_image_svc': data['case_result']['svc_boundary']['svc_number'],
        'stopped_before': data['case_result']['observation_stop_before_svc'],
        'instruction_windows': data['case_result']['instruction_observation_windows'],
        'current_native_suffix_return_verified': False,
        'ordinary_Cronet_six_headers_verified': False,
        'complete_standalone_signer_verified': False,
    }))


if __name__ == '__main__':
    main()
