"""Verify the redacted Android JNI callback-scope capture and guest instructions."""
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

NAME = 'vm9_android_jni_callback_scope_20261104'
HEX_256 = re.compile(r'^[0-9a-f]{64}$')
EXPECTED_LENGTHS = Counter({
    4: 1, 7: 2, 9: 12, 11: 3, 13: 1, 17: 2, 18: 1, 29: 7, 35: 11,
    86: 1, 110: 1, 1402: 1, 1656: 1, 2007: 1, 2030: 1, 2084: 1,
    2320: 1, 2407: 1,
})


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_capture(path: Path) -> list[dict[str, Any]]:
    rows = []
    for line_number, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f'invalid capture JSON on line {line_number}') from exc
        require(isinstance(row, dict), f'capture row {line_number} is not an object')
        rows.append(row)
    return rows


def decode_at(path: Path, machine: str, addresses: list[int]) -> dict[int, tuple[str, str]]:
    with path.open('rb') as stream:
        elf = ELFFile(stream)
        expected = 'EM_AARCH64' if machine == 'arm64' else 'EM_X86_64'
        require(elf['e_machine'] == expected and elf['e_type'] == 'ET_DYN',
                f'{machine} ELF type')
        section = elf.get_section_by_name('.text')
        require(section is not None, f'{machine} .text')
        base = int(section['sh_addr'])
        data = section.data()
        decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM) if machine == 'arm64' else Cs(CS_ARCH_X86, CS_MODE_64)
        result = {}
        for address in addresses:
            start = address - base
            require(0 <= start < len(data), f'{machine} instruction offset {address:#x}')
            decoded = list(decoder.disasm(data[start:start + 16], address, count=1))
            require(bool(decoded), f'{machine} instruction decode {address:#x}')
            result[address] = (decoded[0].mnemonic, decoded[0].op_str)
        return result


def verify(data: dict[str, Any], *, capture: Path | None = None,
           runner: Path | None = None, jni_probe: Path | None = None,
           bridge: Path | None = None, library: Path | None = None,
           houdini: Path | None = None) -> dict[str, Any]:
    require(data.get('schema') == 'vm9-android-jni-callback-scope-20261104-v1', 'schema')
    require(data.get('evidence_date') == '2026-11-04', 'date')
    artifacts = data['artifacts']
    for key in ('capture_sha256', 'runner_sha256', 'jni_probe_sha256',
                'frida_java_bridge_sha256', 'metasec_sha256', 'houdini_sha256'):
        require(bool(HEX_256.fullmatch(artifacts[key])), key + ' shape')

    capture_verified = False
    if capture is not None:
        require(sha256(capture) == artifacts['capture_sha256'], 'capture hash')
        rows = load_capture(capture)
        events = Counter(row.get('event') for row in rows)
        guest = [row for row in rows if row.get('event') == 'guest_jni_string_observed']
        enters = [row for row in rows if row.get('event') == 'business_scope_enter']
        leaves = [row for row in rows if row.get('event') == 'business_scope_leave']
        require(events['guest_jni_string_observed'] == 49, 'guest JNI count')
        require(events['business_scope_enter'] == events['business_scope_leave'] == 7,
                'business callback count')
        require(events['session_detached'] == 1, 'session detach')
        require(any(row.get('event') == 'business_scope_hooked' for row in rows),
                'business hook readiness')
        require(any(row.get('event') == 'bridge_eval_done' for row in rows),
                'bridge payload readiness')
        require(all(row.get('active_security_factor_depth') == 0 for row in guest),
                'guest JNI occurred inside business callback')
        require(all(row.get('returned_null') is False and row.get('nul_terminated') is True
                    and row.get('buffer_read_error') is False for row in guest),
                'guest string buffer observation')
        require(Counter(row['length'] for row in guest) == EXPECTED_LENGTHS,
                'guest JNI length distribution')
        x30_count = 0
        candidate_counts = Counter()
        for row in guest:
            candidates = row.get('caller_candidates', [])
            x30_count += sum(candidate.get('field') == 'guest_x30' for candidate in candidates)
            candidate_counts[tuple(sorted(
                (candidate.get('field'), candidate.get('guest_offset'))
                for candidate in candidates
            ))] += 1
        require(x30_count == 0, 'guest x30 candidate unexpectedly mapped')
        expected_candidates = Counter({
            (('guest_x16', '+0x17bbcc'), ('guest_x7', '+0x1773e0')): 26,
            (('guest_x16', '+0x17bbcc'),): 4,
            (('guest_x7', '+0x27e31c'),): 17,
            (('guest_x16', '+0x375210'), ('guest_x7', '+0x6e000')): 2,
        })
        require(candidate_counts == expected_candidates, 'candidate distribution')

        thread_events: dict[int, list[tuple[str, int | None]]] = {}
        for index, row in enumerate(rows):
            tid = row.get('thread_id')
            if tid is None:
                continue
            event = row.get('event')
            if event == 'guest_jni_string_observed':
                thread_events.setdefault(tid, []).append(('jni', row['length']))
            elif event == 'business_scope_enter':
                thread_events.setdefault(tid, []).append(('enter', None))
            elif event == 'business_scope_leave':
                thread_events.setdefault(tid, []).append(('leave', None))
        callback_threads = [items for items in thread_events.values()
                           if any(kind == 'enter' for kind, _ in items)]
        require(len(callback_threads) == 7, 'callback thread coverage')
        require(all(any(kind == 'jni' for kind, _ in items[:next(
            i for i, (kind, _) in enumerate(items) if kind == 'enter')])
                    and any(kind == 'jni' for kind, _ in items[next(
                        i for i, (kind, _) in enumerate(items) if kind == 'leave') + 1:])
                    for items in callback_threads), 'same-thread before/after evidence')
        capture_verified = True

    checked_sources = ((runner, 'runner_sha256'), (jni_probe, 'jni_probe_sha256'),
                       (bridge, 'frida_java_bridge_sha256'))
    provided_sources = [(path, key) for path, key in checked_sources if path is not None]
    source_hashes_verified = False
    if provided_sources:
        require(len(provided_sources) == len(checked_sources), 'provide all source paths')
        for path, key in provided_sources:
            require(sha256(path) == artifacts[key], key)
        source_hashes_verified = True

    static_verified = False
    if library is not None or houdini is not None:
        require(library is not None and houdini is not None, 'provide both ELF paths')
        require(sha256(library) == artifacts['metasec_sha256'], 'metasec ELF hash')
        require(sha256(houdini) == artifacts['houdini_sha256'], 'Houdini ELF hash')
        arm = decode_at(library, 'arm64', [0x1773dc, 0x17bbc8, 0x27e318])
        require(arm[0x1773dc][0] == 'blr', '0x1773e0 is not after BLR')
        require(arm[0x17bbc8][0] == 'bl', '0x17bbcc is not after BL')
        require(arm[0x27e318][0] == 'b', '0x27e31c predecessor')
        host = decode_at(houdini, 'x86_64', [0x30a314, 0x30a31b, 0x30a31f, 0x30a326])
        require(host[0x30a314] == ('mov', 'rsi, qword ptr [r13 + 8]'), 'guest x1')
        require(host[0x30a31b] == ('mov', 'rdx, qword ptr [r13 + 0x10]'), 'guest x2')
        require(host[0x30a31f] == ('mov', 'rcx, qword ptr [rax + 0x548]'), 'JNI slot')
        require(host[0x30a326] == ('call', 'rcx'), 'JNI dispatch')
        static_verified = True

    return {
        'capture_verified': capture_verified,
        'source_hashes_verified': source_hashes_verified,
        'static_bridge_verified': static_verified,
        'business_callback_scopes': 7,
        'guest_jni_returns': 49,
        'guest_jni_returns_inside_callback_scope': 0,
        'caller_pc_resolved': False,
        'same_request_dataflow_joined': False,
        'parser_input_joined': False,
    }


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path,
                        default=root / 'evidence' / f'{NAME}.json')
    parser.add_argument('--capture', type=Path)
    parser.add_argument('--runner', type=Path)
    parser.add_argument('--jni-probe', type=Path)
    parser.add_argument('--bridge', type=Path)
    parser.add_argument('--library', type=Path)
    parser.add_argument('--houdini-library', type=Path)
    args = parser.parse_args()
    result = verify(json.loads(args.evidence.read_text(encoding='utf-8')),
                    capture=args.capture, runner=args.runner, jni_probe=args.jni_probe,
                    bridge=args.bridge, library=args.library, houdini=args.houdini_library)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
