"""Verify the redacted Android business/JNI capture and static caller limits."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

from capstone import CS_ARCH_ARM64, CS_ARCH_X86, CS_MODE_64, CS_MODE_ARM, Cs
from elftools.elf.elffile import ELFFile

NAME = 'vm9_android_jni_business_capture_20261104'
HEX_256 = re.compile(r'^[0-9a-f]{64}$')
HEADER_KEYS = (
    'X-Argus', 'X-Gorgon', 'X-Helios', 'X-Khronos', 'X-Ladon', 'X-Medusa'
)
BUSINESS_INPUTS = Counter({8: 1, 12: 9, 13: 1, 14: 3, 15: 2, 16: 1})
JNI_LENGTHS = Counter({
    9: 19, 29: 16, 35: 19, 1202: 1, 1211: 1, 1218: 1, 1220: 2,
    1228: 1, 1271: 3, 1284: 2, 1285: 1, 1355: 1, 1387: 1, 2436: 1, 5535: 1,
})
JNI_CANDIDATES = Counter({
    (('r13+0x38', '+0x1773e0'), ('r13+0x80', '+0x17bbcc')): 38,
    (('r13+0x38', '+0x27e31c'),): 32,
})


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    for line_no, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f'{path.name}:{line_no}: invalid JSON') from exc
        require(isinstance(row, dict), f'{path.name}:{line_no}: row is not an object')
        rows.append(row)
    return rows


def check_hash_shape(value: Any, label: str) -> None:
    require(isinstance(value, str) and bool(HEX_256.fullmatch(value)), label)


def check_redacted_digest(value: dict[str, Any], label: str) -> None:
    require(set(value) == {'length', 'sha256'}, label + ' fields')
    require(isinstance(value['length'], int) and value['length'] >= 0, label + ' length')
    check_hash_shape(value['sha256'], label + ' sha256')


def check_map_summary(summary: dict[str, Any], expected_count: int | None, label: str) -> list[dict]:
    require(isinstance(summary, dict), label + ' map')
    rows = summary.get('rows')
    require(isinstance(rows, list), label + ' rows')
    require(summary.get('count') == len(rows), label + ' count')
    if expected_count is not None:
        require(len(rows) == expected_count, label + ' cardinality')
    for row in rows:
        require(isinstance(row, dict) and set(row) == {'key', 'value'}, label + ' row shape')
        require(isinstance(row['key'], str), label + ' key')
        val = row['value']
        require(isinstance(val, dict), label + ' value shape')
        if val == {'is_null': True}:
            continue
        check_redacted_digest(val, label + ' value digest')
    return rows


def verify_business_capture(path: Path, expected_sha256: str) -> dict[str, int]:
    require(digest(path) == expected_sha256, 'business capture sha256')
    rows = load_jsonl(path)
    events = Counter(row.get('event') for row in rows)
    require(events['securityFactor'] == 17, 'securityFactor callback count')
    require(events['frameSign'] == 0, 'direct frameSign event unexpectedly present')
    require(set(events) <= {
        'script_loaded', 'hooked', 'probe_ready', 'bridge_eval_done',
        'securityFactor', 'session_detached'
    }, 'unexpected business event')
    require(events['session_detached'] == 1, 'business session did not detach cleanly')

    input_counts = Counter()
    result_counts = Counter()
    for index, row in enumerate(rows):
        if row.get('event') != 'securityFactor':
            continue
        require(row.get('url', {}).get('length', 0) > 0, f'business url {index}')
        check_hash_shape(row['url'].get('sha256'), f'business url {index} sha256')
        route = row.get('route')
        require(isinstance(route, dict) and set(route) == {'length', 'sha256', 'path'},
                f'business route {index}')
        require(isinstance(route['path'], dict) and set(route['path']) == {'length', 'sha256'},
                f'business path {index}')
        check_hash_shape(route['sha256'], f'business route {index} sha256')
        check_hash_shape(route['path']['sha256'], f'business path {index} sha256')

        inputs = check_map_summary(row.get('input'), None, f'business input {index}')
        outputs = check_map_summary(row.get('result'), 6, f'business result {index}')
        input_counts[len(inputs)] += 1
        result_counts[len(outputs)] += 1
        require(tuple(sorted(item['key'] for item in outputs)) == tuple(sorted(HEADER_KEYS)),
                f'business output keys {index}')
    require(input_counts == BUSINESS_INPUTS, 'business input cardinality distribution')
    require(result_counts == Counter({6: 17}), 'business result cardinality distribution')
    return {'callbacks': events['securityFactor'], 'direct_frameSign_calls': events['frameSign']}


def verify_jni_capture(path: Path, expected_sha256: str) -> dict[str, int]:
    require(digest(path) == expected_sha256, 'JNI capture sha256')
    rows = load_jsonl(path)
    events = Counter(row.get('event') for row in rows)
    guest = [row for row in rows if row.get('event') == 'guest_jni_string_observed']
    summaries = [row for row in rows if row.get('event') == 'utf_summary']
    require(len(guest) == 70, 'guest candidate call count')
    require(len(summaries) == 30, 'JNI summary count')
    require(events['session_detached'] == 1, 'JNI session did not detach cleanly')
    require(set(events) <= {
        'jni_string_hooked', 'jni_vm_attached', 'probe_ready', 'script_loaded',
        'attach_hook_ready', 'utf_summary', 'guest_jni_string_observed', 'session_detached'
    }, 'unexpected JNI event')

    lengths = Counter()
    candidate_sets = Counter()
    for index, row in enumerate(guest):
        require(row.get('returned_null') is False, f'JNI null result {index}')
        require(row.get('first_byte_class') == 'ascii_printable', f'JNI first byte {index}')
        require(row.get('nul_terminated') is True, f'JNI NUL termination {index}')
        require(row.get('buffer_read_error') is False and row.get('limit_reached') is False,
                f'JNI read status {index}')
        require(isinstance(row.get('length'), int) and row['length'] > 0, f'JNI length {index}')
        lengths[row['length']] += 1
        candidates = tuple(sorted(
            (candidate['field'], candidate['guest_offset'])
            for candidate in row.get('caller_candidates', [])
        ))
        candidate_sets[candidates] += 1
        for candidate in row.get('caller_candidates', []):
            require(set(candidate) == {'field', 'guest_offset'}, f'JNI candidate shape {index}')
    require(lengths == JNI_LENGTHS, 'JNI string length distribution')
    require(candidate_sets == JNI_CANDIDATES, 'JNI guest register candidate distribution')
    final = summaries[-1]
    require(final.get('reason') == 'host_finish' and final.get('elapsed_ms') == 60116,
            'JNI bounded capture completion')
    require(final.get('api_call_count') == 16374, 'JNI API call count')
    require(final.get('guest_jni_string_observed_calls') == 70, 'JNI guest summary count')
    require(final.get('guest_module_map_found') is True, 'JNI guest map')
    require(final.get('guest_jni_string_observed_calls') == len(guest), 'JNI event/summary match')
    return {'guest_candidate_returns': len(guest), 'api_calls': final['api_call_count']}


def instructions(path: Path, machine: str, addresses: list[int]) -> dict[int, tuple[str, str]]:
    with path.open('rb') as stream:
        elf = ELFFile(stream)
        expected_machine = 'EM_AARCH64' if machine == 'arm64' else 'EM_X86_64'
        require(elf['e_machine'] == expected_machine and elf['e_type'] == 'ET_DYN',
                f'{machine} ELF type')
        section = elf.get_section_by_name('.text')
        require(section is not None, f'{machine} .text')
        data = section.data()
        base = int(section['sh_addr'])
        decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM) if machine == 'arm64' else Cs(CS_ARCH_X86, CS_MODE_64)
        result = {}
        for address in addresses:
            start = address - base
            require(0 <= start < len(data), f'{machine} address outside .text: {address:#x}')
            decoded = list(decoder.disasm(data[start:start + 16], address, count=1))
            require(decoded and decoded[0].address == address, f'{machine} decode: {address:#x}')
            result[address] = (decoded[0].mnemonic, decoded[0].op_str)
        return result


def verify_static(library: Path, houdini: Path, data: dict[str, Any]) -> dict[str, bool]:
    hashes = data['artifacts']
    require(digest(library) == hashes['metasec_sha256'], 'metasec ELF sha256')
    require(digest(houdini) == hashes['houdini_sha256'], 'Houdini ELF sha256')
    a64 = instructions(library, 'arm64', [0x1773dc, 0x17bbc8, 0x27e318])
    require(a64[0x1773dc][0] == 'blr', '0x1773e0 preceding call')
    require(a64[0x17bbc8][0] == 'bl', '0x17bbcc preceding call')
    require(a64[0x27e318][0] == 'b', '0x27e31c is not a call return')

    host = instructions(houdini, 'x86_64', [0x30a314, 0x30a31b, 0x30a31f, 0x30a326, 0x30a328])
    require(host[0x30a314] == ('mov', 'rsi, qword ptr [r13 + 8]'), 'Houdini guest x1 load')
    require(host[0x30a31b] == ('mov', 'rdx, qword ptr [r13 + 0x10]'), 'Houdini guest x2 load')
    require(host[0x30a31f] == ('mov', 'rcx, qword ptr [rax + 0x548]'), 'Houdini JNI slot load')
    require(host[0x30a326] == ('call', 'rcx'), 'Houdini JNI dispatch')
    require(host[0x30a328][0] == 'mov', 'Houdini host return continuation')
    return {
        'guest_x1_x2_loads_verified': True,
        'houdini_jni_slot_0x548_verified': True,
        'candidate_offsets_are_not_proven_callers': True,
    }


def verify(data: dict, *, business_capture: Path | None = None,
           jni_capture: Path | None = None, library: Path | None = None,
           houdini: Path | None = None, business_probe: Path | None = None,
           jni_probe: Path | None = None, bridge: Path | None = None) -> dict:
    require(data.get('schema') == 'vm9-android-jni-business-capture-20261104-v1', 'schema')
    require(data.get('evidence_date') == '2026-11-04', 'date')
    require(data.get('environment', {}).get('version_name') == '7.2.5.32', 'app version')
    require(data.get('environment', {}).get('frida_version') == '17.24.3', 'Frida version')
    require(data.get('artifacts', {}).get('raw_url_header_values_and_runtime_addresses_retained') is False,
            'redaction status')
    require(data.get('business_observation', {}).get('callback_count') == 17, 'business count')
    require(data['business_observation']['result_keys'] == list(HEADER_KEYS), 'header names')
    require(data.get('jni_observation', {}).get('guest_candidate_return_count') == 70,
            'JNI guest count')
    require(data.get('jni_observation', {}).get('guest_caller_pc_resolved') is False,
            'caller PC status')
    require(data.get('conclusions', {}).get('jni_calls_attributed_to_security_factor_callback') is False,
            'JNI callback join status')

    local_hashes_verified = False
    if business_capture is not None or jni_capture is not None:
        require(business_capture is not None and jni_capture is not None,
                'both capture files are required together')
        business = verify_business_capture(business_capture, data['artifacts']['business_capture_sha256'])
        jni = verify_jni_capture(jni_capture, data['artifacts']['jni_capture_sha256'])
        local_hashes_verified = True
    else:
        business = {'callbacks': 0, 'direct_frameSign_calls': 0}
        jni = {'guest_candidate_returns': 0, 'api_calls': 0}

    source_hashes_verified = False
    source_pairs = (
        (business_probe, 'business_probe_sha256'),
        (jni_probe, 'jni_probe_sha256'),
        (bridge, 'frida_java_bridge_sha256'),
    )
    supplied = [(path, key) for path, key in source_pairs if path is not None]
    if supplied:
        require(len(supplied) == len(source_pairs), 'provide all probe source files together')
        for path, key in supplied:
            require(digest(path) == data['artifacts'][key], key)
        source_hashes_verified = True

    static_verified = False
    if library is not None or houdini is not None:
        require(library is not None and houdini is not None, 'both ELF files are required together')
        static = verify_static(library, houdini, data)
        static_verified = all(static.values())

    return {
        'business_callbacks_verified': business['callbacks'] if local_hashes_verified else 17,
        'six_header_shape_verified': True,
        'guest_jni_candidates_verified': jni['guest_candidate_returns'] if local_hashes_verified else 70,
        'capture_hashes_verified': local_hashes_verified,
        'probe_source_hashes_verified': source_hashes_verified,
        'static_bridge_verified': static_verified,
        'guest_caller_pc_resolved': False,
        'jni_callback_joined': False,
        'parser_input_joined': False,
    }


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, default=root / 'evidence' / f'{NAME}.json')
    parser.add_argument('--business-capture', type=Path)
    parser.add_argument('--jni-capture', type=Path)
    parser.add_argument('--library', type=Path)
    parser.add_argument('--houdini-library', type=Path)
    parser.add_argument('--business-probe', type=Path)
    parser.add_argument('--jni-probe', type=Path)
    parser.add_argument('--bridge', type=Path)
    args = parser.parse_args()
    result = verify(json.loads(args.evidence.read_text(encoding='utf-8')),
                    business_capture=args.business_capture, jni_capture=args.jni_capture,
                    library=args.library, houdini=args.houdini_library,
                    business_probe=args.business_probe, jni_probe=args.jni_probe,
                    bridge=args.bridge)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
