"""Original emission body probes: move ownership and warm record-vector append.

Controlled synthetic warm logger/CPP-string inputs and explicit allocator
Effects. Matching libc executes uncontended mutexes. Python emission is not
implemented or claimed verified by these native-only probes.
"""
from pathlib import Path
from collections import deque
import argparse, hashlib, json
from verify_vm9_signer_objects import native, image_pages, fresh_pages, GUEST, LIBRARY_SHA256
from verify_vm9_worker_allocator import LIBC_SHA256
from verify_vm9_strings import Effects
from verify_vm9_request_mode_format_fresh_20261007 import imports, services
from vm9_cpp_strings import construct_cpp_string
from vm9_allocator import _read_span, _write_span

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--library', type=Path, required=True)
    ap.add_argument('--libc', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest() == LIBC_SHA256
    lib = args.library
    libc = args.libc
    entries = imports(lib, libc)
    rows = []
    for image in (304873472, 512646729728):
        for spare in (False, True):
            p = {**image_pages(lib, image), **fresh_pages()}
            e = Effects(blocks={})
            inputs = [GUEST + 4352 + 24 * i for i in range(4)]
            for index, (obj, text) in enumerate(zip(inputs, (b'event', b'{"x0":0}', b'{"x1":0,"x2":0,"x3":0,"x4":0}', b'{}'))):
                source = GUEST + 8192 + 128 * index
                _write_span(p, source, text + b'\x00')
                construct_cpp_string(p, object_address=obj, source_address=source, allocate=e.malloc)
            logger = GUEST + 4096
            old = e.malloc(p, 192 if spare else 96)
            _write_span(p, logger, bytes(64))
            _write_span(p, old, bytes(192 if spare else 96))
            _write_span(p, logger + 40, old.to_bytes(8, 'little') + (old + 96).to_bytes(8, 'little') + (old + (192 if spare else 96)).to_bytes(8, 'little'))
            _write_span(p, image + 4070152, logger.to_bytes(8, 'little'))
            before_calls = len(e.calls)
            initial_heap = int.from_bytes(_read_span(p, inputs[2] + 16, 8), 'little')
            initial_objects = [_read_span(p, a, 24) for a in inputs]
            observed = {(logger, 64): None, (GUEST + 60864, 96): None}
            last = deque(maxlen=12)
            try:
                result = native(lib, image, 2686788, inputs, p, libc=libc, real_mutexes=True, host_imports=services(entries, e), malloc_handler=lambda cpu, size: e.native(cpu, 'malloc', size), observed_memory=observed, instruction_observer=lambda cpu, a: last.append(hex(a - image)), instruction_limit=500000)
                memory = result[1]
                fields = observed[logger, 64]
                begin, end, capacity = (int.from_bytes(fields[n:n + 8], 'little') for n in (40, 48, 56))
                source_heads = [memory[a - GUEST:a - GUEST + 2].hex() for a in inputs]
                record = memory[begin - GUEST + 96:begin - GUEST + 192]
                moved_heap = int.from_bytes(record[64:72], 'little')
                print('EMISSION PASS', hex(image), 'spare', spare, 'record-count', (end - begin) // 96, 'capacity', (capacity - begin) // 96, 'source-heads', source_heads, 'same-heap', moved_heap == initial_heap, 'effects', e.calls[before_calls:], 'mutexes', result[3], flush=True)
                assert source_heads == ['0000'] * 4 and moved_heap == initial_heap
                assert (end - begin) // 96 == 2 and (capacity - begin) // 96 == 2
                assert memory[begin - GUEST:begin - GUEST + 96] == bytes(96)
                for address, initial in zip(inputs, initial_objects):
                    assert memory[address - GUEST + 2:address - GUEST + 24] == initial[2:]
                assert result[3] == [['pthread_mutex_lock', logger], ['pthread_mutex_unlock', logger]]
                assert e.calls[before_calls:] == ([] if spare else [['malloc', 192, 0], ['free', old]])
                assert memory[moved_heap - GUEST:moved_heap - GUEST + 29] == b'{"x1":0,"x2":0,"x3":0,"x4":0}'
                rows.append(dict(image_base=hex(image), spare_capacity=spare, record_count=(end - begin) // 96, record_capacity=(capacity - begin) // 96, source_first_two_bytes_zeroed=True, event_json_heap_pointer_moved_unchanged=True, allocation_cleanup_effects=e.calls[before_calls:], matching_libc_mutexes_executed=result[3], original_native_emission_body_returned=True, controlled_warm_singleton_input=True, python_emission_owner_verified=False, whole_request_callback_verified=False))
            except Exception as exc:
                print('FAIL', hex(image), spare, type(exc).__name__, str(exc), 'TAIL', list(last), 'EFFECTS', e.calls[before_calls:], flush=True)
                raise
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(dict(schema='vm9-request-event-emission-native-probe-v1', evidence_date='2026-10-07', sample_sha256=LIBRARY_SHA256, libc_sha256=LIBC_SHA256, controls=len(rows), cases=rows, native_input_snapshot_used=False, controlled_warm_singleton_input=True, explicit_component_allocator_used=True, matching_libc_mutexes_executed=True, matching_libc_allocator_used=False, python_emission_owner_verified=False, whole_request_callback_verified=False, complete_python_medusa=False, fresh_signer_output_verified=False, live_server_matrix_verified=False), indent=2) + '\n', encoding='utf-8')
if __name__ == '__main__':
    main()
