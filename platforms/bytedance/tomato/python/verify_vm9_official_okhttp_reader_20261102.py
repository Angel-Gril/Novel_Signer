"""Verify official-app reader observations without claiming standalone signing."""
from __future__ import annotations

import argparse
import collections
import copy
import hashlib
import json
import re
from pathlib import Path

from verify_vm9_networkparams_runtime_20261031 import HEADERS, check_digest

DEFAULT_RECORD = Path(__file__).parents[1] / 'evidence/vm9_official_okhttp_reader_20261102.json'
APK_SHA256 = '95889d1a1ad0b11ed2451eedf0389516e1382640182026e82eb515e04fbc04fd'


def verify(record: dict) -> dict:
    assert record['schema'] == 'vm9-official-okhttp-reader-20261102-v1'
    assert record['package'] == 'com.dragon.read' and record['version'] == '7.2.5.32/72532'
    assert record['apk_sha256'] == APK_SHA256
    assert record['package_identity'] == 'unchanged_official_apk'
    for name in ('manual_frame_sign_invocation', 'reader_failure_root_cause_identified',
                 'cronet_runtime_branch_observed', 'translated_jni_coverage_fully_verified',
                 'whole_request_native_python_differential_verified',
                 'fresh_standalone_signer_verified', 'online_header_acceptance_verified',
                 'raw_urls_or_header_values_retained', 'raw_response_body_retained'):
        assert record[name] is False, name
    assert record['builtin_signer_six_header_result_observed'] is True
    assert record['official_app_http200_business0_observed'] is True
    assert record['ui_observations']['subsequent_chapter_body_visually_observed'] is True
    check_digest({'length': record['ui_observations']['screenshot_bytes'],
                  'sha256': record['ui_observations']['screenshot_sha256']})
    assert record['ui_observations']['raw_screenshot_retained'] is False
    pairs_count = 0
    errors_count = 0
    assert len(record['runs']) == 2
    for run in record['runs']:
        check_digest({'length': 1, 'sha256': run['capture_sha256']})
        events, indices = run['selected_events'], run['selected_source_indices']
        assert len(indices) == len(events) and indices == sorted(set(indices))
        assert all(isinstance(index, int) and index >= 0 for index in indices)
        counts = run['capture_event_counts']
        assert sum(counts.values()) > max(indices)
        for event in ('frameSign', 'cronetSecurityFactor', 'cronetContextO0',
                      'cronetContextSecurityFactor', 'hook_error', 'install_error',
                      'diagnostic_install_error', 'frida_message', 'bridge_eval_error'):
            assert not counts.get(event), event
        hooks = collections.Counter(x['target'] for x in events if x['event'] == 'hooked')
        assert len(hooks) == 9 and set(hooks.values()) == {1}
        assert events[-1] == {'event': 'session_detached', 'reason': 'application-requested'}
        by_index = dict(zip(indices, events))
        assert run['pairs']
        for pair in run['pairs']:
            si, ri = pair['signature_source_index'], pair['response_source_index']
            assert si < ri
            signature, response = by_index[si], by_index[ri]
            assert signature['event'] == 'securityFactor'
            assert response['event'] == 'response_deserialized'
            for row in (signature, response):
                for digest in (row['url'], row['route'], row['route']['path']):
                    check_digest(digest)
            assert signature['context']['thread_id'] == response['thread_id']
            assert signature['route']['path'] == response['route']['path']
            stack = signature['context']['stack']
            assert stack[0]['class'] == 'ms.bd.c.r4'
            assert any(x['class'] == 'com.bytedance.frameworks.baselib.network.http.ok3.impl.OkHttp3SecurityFactorInterceptor'
                       and x['method'] == 'intercept' for x in stack[:4])
            assert len(stack) <= 24
            result = signature['result']
            assert result['count'] == len(result['rows']) == 6
            assert {x['key'] for x in result['rows']} == HEADERS
            for summary in (signature['input'], result):
                assert summary['count'] == len(summary['rows'])
                for item in summary['rows']:
                    assert set(item) == {'key', 'value'}
                    check_digest(item['value'])
            assert response['response_class'] in (
                'readersaas.com.dragon.read.saas.rpc.model.FullResponse',
                'readersaas.com.dragon.read.saas.rpc.model.BatchFullResponse')
            assert response['http_status'] == 200 and response['business_code'] == 0
            assert response['transport_error_class'] is None
            pairs_count += 1
        for row in events:
            if row['event'] == 'reader_exception_boundary':
                for error in row['errors']:
                    assert error['code_name'] == 'CHAPTER_CONTENT_ERROR' and error['code_value'] == -1002
                    assert error['cause_class'] == 'java.lang.RuntimeException'
                    assert len(error['cause_stack']) <= 32
                    errors_count += 1
            assert not re.search(r'https?://', json.dumps(row)), 'raw URL retained'
        assert run['nested_cause_chain_observed'] is False
    assert errors_count and pairs_count >= 2
    control = record['jni_variants_control']
    assert control['cached_target_method_ids_resolved'] is True
    assert control['sample_count'] > 0 and control['vm_detach_status'] == 0
    assert control['terminal_reason'] == 'application-requested'
    assert set(control['last_sample_counts']) == {'plain', 'V', 'A'}
    assert all(value > 0 for value in control['last_sample_counts'].values())
    assert control['last_sample_target_counts'] == {'plain': 0, 'V': 0, 'A': 0}
    assert control['a_counts_include_active_class_loader_calls'] is True
    return {'status': 'verified_official_app_boundary', 'correlated_reader_responses': pairs_count,
            'initial_reader_errors': errors_count, 'readable_chapter_visually_observed': True,
            'standalone_signer_verified': False, 'cronet_observed': False}


def verify_capture(run: dict, capture: Path) -> None:
    assert hashlib.sha256(capture.read_bytes()).hexdigest() == run['capture_sha256']
    rows = [json.loads(line) for line in capture.read_text(encoding='utf-8').splitlines() if line.strip()]
    assert dict(collections.Counter(row['event'] for row in rows)) == run['capture_event_counts']
    assert [rows[i] for i in run['selected_source_indices']] == run['selected_events']


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--record', type=Path, default=DEFAULT_RECORD)
    parser.add_argument('--capture', type=Path, action='append', default=[])
    args = parser.parse_args()
    record = json.loads(args.record.read_text(encoding='utf-8'))
    result = verify(record)
    if args.capture:
        assert len(args.capture) == len(record['runs']), 'provide one capture per run in record order'
        for run, path in zip(record['runs'], args.capture):
            verify_capture(run, path)
    for kind in ('unknown_apk', 'mismatched_path', 'mismatched_thread', 'response_before_signing',
                 'missing_header', 'rejected_response', 'false_acceptance'):
        invalid = copy.deepcopy(record)
        run = invalid['runs'][0]
        pair = run['pairs'][0]
        rows = dict(zip(run['selected_source_indices'], run['selected_events']))
        signature, response = rows[pair['signature_source_index']], rows[pair['response_source_index']]
        if kind == 'unknown_apk':
            invalid['apk_sha256'] = '0' * 64
        elif kind == 'mismatched_path':
            response['route']['path']['sha256'] = '0' * 64
        elif kind == 'mismatched_thread':
            response['thread_id'] = -1
        elif kind == 'response_before_signing':
            pair['signature_source_index'], pair['response_source_index'] = (
                pair['response_source_index'], pair['signature_source_index'])
        elif kind == 'missing_header':
            signature['result']['rows'].pop()
        elif kind == 'rejected_response':
            response['business_code'] = 110
        else:
            invalid['online_header_acceptance_verified'] = True
        try:
            verify(invalid)
        except AssertionError:
            continue
        raise AssertionError(f'invalid evidence accepted: {kind}')
    result['negative_controls'] = 7
    result['raw_capture_digests_checked'] = len(args.capture)
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
