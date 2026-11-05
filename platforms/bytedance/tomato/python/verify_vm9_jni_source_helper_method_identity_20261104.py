"""Verify the redacted unidbg method identity observed inside +0x26f650."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


NAME = 'vm9_jni_source_helper_method_identity_20261104'
EXPECTED_LOG_SHA256 = 'a8a737054468dad2479fe30afaaffa66c95fb5d46f21aef51b361ac71f6252e7'
EXPECTED_LIBRARY_SHA256 = '712384bd0e310fded0ae9b6441c2a264dd356dfaf1ef42d2ebc3c790fdd9269c'
EXPECTED_METHOD = 'java/lang/String.getBytes(Ljava/lang/String;)[B'


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def verify_log(path: Path) -> dict[str, int | str]:
    raw = path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == EXPECTED_LOG_SHA256,
            'probe log digest')
    text = raw.decode('utf-8', errors='replace')
    marker = '[HookMain] FRAME_SIGN_TRIAL=0'
    end_marker = '[HookMain] FRAME_SIGN_RESULT_TYPE=null'
    start = text.find(marker)
    require(start >= 0, 'frame-sign marker')
    end = text.find(end_marker, start)
    require(end > start, 'frame-sign terminal marker')
    segment = text[start:end]
    get_pattern = (re.escape('JNIEnv->GetMethodID(') +
                   re.escape(EXPECTED_METHOD) +
                   r'\) => [^\n]*?was called from RX@[^\n]*?0x26f854')
    call_pattern = (re.escape('JNIEnv->CallObjectMethodV(') +
                    r'.*?getBytes\("utf-8"\).*?was called from RX@[^\n]*?0x26f95c')
    get_count = len(re.findall(get_pattern, segment, flags=re.DOTALL))
    call_count = len(re.findall(call_pattern, segment, flags=re.DOTALL))
    require(get_count == 1, 'frame-sign GetMethodID count')
    require(call_count == 1, 'frame-sign CallObjectMethodV count')
    require(segment.count('getBytes("utf-8")') == 1,
            'frame-sign encoding argument count')
    require('Write to write-protected memory' in segment,
            'frame-sign terminal diagnostic')
    return {
        'probe_log_rows': text.count('\n'),
        'frame_sign_get_method_id_events': get_count,
        'frame_sign_call_object_method_v_events': call_count,
    }


def verify(data: dict, log: Path | None = None) -> dict:
    require(data.get('schema') == 'vm9-jni-source-helper-method-identity-20261104-v1',
            'schema')
    require(data.get('evidence_date') == '2026-11-04', 'date')
    require(data.get('environment', {}).get('native_library_sha256') ==
            EXPECTED_LIBRARY_SHA256, 'native library digest')
    artifacts = data.get('artifacts', {})
    require(artifacts.get('probe_log_sha256') == EXPECTED_LOG_SHA256,
            'evidence log digest')
    helper = data.get('helper', {})
    require(helper == {
        'offset': '0x26f650',
        'get_method_id_return_offset': '0x26f854',
        'call_object_method_v_return_offset': '0x26f95c',
        'jni_get_method_id_table_byte_offset': '0x108',
        'jni_call_object_method_v_table_byte_offset': '0x118',
    }, 'helper metadata')
    method = data.get('observed_method', {})
    require(method == {
        'class_name': 'java/lang/String',
        'method_name': 'getBytes',
        'signature': '(Ljava/lang/String;)[B',
        'encoding_argument_observed': 'utf-8',
        'return_object_type': '[B',
        'frame_sign_get_method_id_events': 1,
        'frame_sign_call_object_method_v_events': 1,
    }, 'method metadata')
    require(data.get('capture') == {
        'frame_sign_marker': 'FRAME_SIGN_TRIAL=0',
        'frame_sign_result_type': 'null_after_write_protected_memory_abort',
        'raw_log_retained_in_evidence': False,
        'raw_url_or_byte_array_values_retained': False,
    }, 'capture metadata')
    require(data.get('conclusions') == {
        'source_helper_java_method_identity_verified': True,
        'source_helper_utf8_byte_array_conversion_observed': True,
        'source_helper_provider_method_identity_joined': False,
        'source_helper_return_bytes_joined_to_android_capture': False,
        'complete_standalone_signer_verified': False,
        'online_header_acceptance_verified': False,
    }, 'conclusions')
    observed = verify_log(log) if log is not None else None
    return {
        'schema': data['schema'],
        'source_helper_java_method_identity_verified': True,
        'source_helper_utf8_byte_array_conversion_observed': True,
        'source_helper_provider_method_identity_joined': False,
        'log_observations': observed,
    }


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path,
                        default=root / 'evidence' / f'{NAME}.json')
    parser.add_argument('--log', type=Path)
    args = parser.parse_args()
    data = json.loads(args.evidence.read_text(encoding='utf-8'))
    print(json.dumps(verify(data, log=args.log), sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
