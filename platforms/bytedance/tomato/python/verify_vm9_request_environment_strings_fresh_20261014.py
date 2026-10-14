"""Fresh actual helper StringObject wrappers, from independently built inputs.

Original constructor/destructor instructions execute with explicit malloc/free
services. These controls do not verify the helper return or request signing.
"""
from pathlib import Path
import argparse, hashlib, json, os
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
import vm9_request_environment_vm as model
from vm9_allocator import RefillUnsupported, _read_span, _write_span

BASES = (0x122C0000, 0x775C205000)
G = oracle.GUEST
OWNER = 'apply_request_environment_string_callback'


def fixture(library, image, kind, label):
    pages = oracle.image_pages(library, image); pages.update(oracle.fresh_pages())
    block, obj, source = G + 0x1000, G + 0x1800, G + 0x2800
    if label == 'cross_page_object': obj = G + 0x1FF8
    if label == 'cross_page_source': source = G + 0x2FFD
    if label == 'packed_object_alias': obj = block
    if label == 'packed_source_alias': source = block + 24
    if label == 'object_source_alias': source = obj
    target, wrapper = (0x248344, 0x205064) if kind == 'construct' else (0x2484B8, 0x205094)
    _write_span(pages, block, b''.join(n.to_bytes(8, 'little') for n in (image + target, obj, source)))
    if kind == 'construct':
        data = b'' if label == 'empty' else b'helper-string' if label != 'embedded_NUL' else b'ab\0tail'
        _write_span(pages, source, data + b'\0')
        if label == 'NULL_source': _write_span(pages, block + 16, bytes(8))
        if label == 'custom_empty_descriptor':
            _write_span(pages, block + 16, bytes(8))
            _write_span(pages, image + 0x6E168, (23).to_bytes(4, 'little') + (7).to_bytes(4, 'little'))
    else:
        pointer = 0 if label == 'NULL_payload' else G + 0x4000
        if label == 'payload_object_alias': pointer = obj
        if label == 'payload_packed_alias': pointer = block
        _write_span(pages, obj, b''.join(n.to_bytes(8, 'little') for n in (image + 1, 0x1234567887654321, pointer)))
        if label == 'packed_object_alias':
            _write_span(pages, block, (image + target).to_bytes(8, 'little') + obj.to_bytes(8, 'little'))
        if label == 'custom_empty_descriptor':
            _write_span(pages, image + 0x6E208, (17).to_bytes(4, 'little') + (9).to_bytes(4, 'little'))
    return pages, dict(wrapper_offset=wrapper, argument_block_address=block, image_base=image), obj


def native(library, pages, inputs, obj, label):
    requests, freed = [], []
    def malloc(cpu, size):
        pointer = 0 if label == 'allocation_failure' else G + 0x4000
        requests.append([size, pointer]); return pointer
    def free(cpu):
        pointer = cpu.reg_read(arm.UC_ARM64_REG_X0); freed.append(pointer)
        if label == 'free_mutates_object': cpu.mem_write(obj + 8, bytes(16))
        return 0
    watch = {(G, 0xA000): None}
    _, _, _, services = oracle.native(library, inputs['image_base'], inputs['wrapper_offset'],
        [inputs['argument_block_address']], pages, malloc_handler=malloc,
        host_imports={0x347FA0: free}, observed_memory=watch, instruction_limit=10000)
    assert not services
    return watch[G, 0xA000], requests, freed


def red(library):
    assert not hasattr(model, OWNER), 'RED requires the prior consumer boundary'
    rows = []
    for image in BASES:
        for kind in ('construct', 'destroy'):
            pages, inputs, obj = fixture(library, image, kind, 'normal')
            native(library, pages, inputs, obj, 'normal')
            rows.append(dict(image_base=hex(image), kind=kind, original_wrapper_returned=True,
                prior_consumer_missing=True, native_snapshot_input=False))
    return rows


def compare(library, image, kind, label):
    pages, inputs, obj = fixture(library, image, kind, label)
    initial = {k: bytearray(v) for k, v in pages.items()}; allocated, freed = [], []
    def allocate(p, size):
        pointer = 0 if label == 'allocation_failure' else G + 0x4000
        allocated.append([size, pointer]); return pointer
    def free(p, pointer):
        freed.append(pointer)
        if label == 'free_mutates_object': _write_span(p, obj + 8, bytes(16))
    getattr(model, OWNER)(pages, **inputs, allocate=allocate, free=free)
    memory, requests, native_freed = native(library, initial, inputs, obj, label)
    assert _read_span(pages, G, 0xA000) == memory, (kind, label)
    assert allocated == requests and freed == native_freed, (kind, label)
    print('PASS environment string', hex(image), kind, label, flush=True)
    return dict(image_base=hex(image), kind=kind, case=label,
        actual_wrapper=hex(inputs['wrapper_offset']), original_wrapper_returned=True,
        all_declared_guest_bytes_and_packed_padding_equal=True,
        allocation_requests_and_free_calls_equal=True, native_snapshot_input=False)


def guards(library):
    rows = []
    for label in ('wrong_target', 'wrong_wrapper', 'missing_packed', 'missing_object',
                  'missing_source', 'source_bound', 'allocator_late_failure',
                  'free_late_failure', 'missing_empty_descriptor'):
        kind = 'destroy' if label in ('free_late_failure', 'missing_empty_descriptor') else 'construct'
        pages, inputs, obj = fixture(library, BASES[0], kind, 'normal')
        block = inputs['argument_block_address']; kw = dict(inputs)
        if label == 'wrong_target': _write_span(pages, block, (BASES[0] + 1).to_bytes(8, 'little'))
        elif label == 'wrong_wrapper': kw['wrapper_offset'] = 1
        elif label == 'missing_packed': del pages[block >> 12]
        elif label == 'missing_object': _write_span(pages, block + 8, (G + 0x10000).to_bytes(8, 'little'))
        elif label == 'missing_source': _write_span(pages, block + 16, (G + 0x10000).to_bytes(8, 'little'))
        elif label == 'source_bound': kw['max_source_bytes'] = 2
        elif label == 'missing_empty_descriptor': del pages[(BASES[0] + 0x6E208) >> 12]
        before = {k: bytes(v) for k, v in pages.items()}
        def effect(p, value):
            _write_span(p, G + 0x4000, b'changed')
            if label in ('allocator_late_failure', 'free_late_failure'): raise RefillUnsupported('explicit provider failure')
            return G + 0x4000
        try: getattr(model, OWNER)(pages, **kw, allocate=effect, free=effect)
        except (RefillUnsupported, ValueError): pass
        else: raise AssertionError(label)
        assert before == {k: bytes(v) for k, v in pages.items()}, label
        rows.append(dict(case=label, rejected=True, all_pages_unchanged=True))
    return rows


def entry_guards(library):
    os.environ['TOMATO_LIBMETASEC'] = str(library.resolve())
    import vm_full
    from verify_vm9_request_environment_vm_fresh_20261013 import fixture as frame_fixture, packed
    assert Path(vm_full.__file__).resolve().parent == Path(__file__).resolve().parent
    rows = []
    for label in ('invalid_services', 'missing_free', 'noncallable_allocate'):
        pages, inputs = frame_fixture(library, BASES[0], 'normal'); packed(pages, inputs)
        services = dict(allocate=lambda p,n:G+0x4000, free=lambda p,a:None)
        if label == 'invalid_services': services = []
        elif label == 'missing_free': del services['free']
        else: services['allocate'] = None
        before = {k: bytes(v) for k, v in pages.items()}; previous = vm_full.B
        try: model.execute_request_environment_vm_prefix(pages, vm_module=vm_full,
                consumer_services=services, argument_block_address=G+0x1000, **inputs)
        except RefillUnsupported: pass
        else: raise AssertionError(label)
        assert previous == vm_full.B and before == {k: bytes(v) for k, v in pages.items()}
        rows.append(dict(case=label, rejected=True, all_pages_unchanged=True, module_image_base_restored=True))
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--library', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--group', choices=('red', 'strings', 'guards', 'entry', 'all'), default='all')
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == oracle.LIBRARY_SHA256
    report = dict(schema='vm9-request-environment-strings-fresh-v1', evidence_date='2026-10-14',
        sample_sha256=oracle.LIBRARY_SHA256, cases=[], negative_cases=[], entry_negative_cases=[],
        native_snapshot_input=False, private_names_or_payloads_published=False,
        whole_request_native_differential_verified=False, actual_URL_header_JNI_conversion_verified=False,
        live_Android_JVM_verified=False, complete_python_medusa=False, fresh_signer_output_verified=False,
        live_server_matrix_verified=False, whole_physical_stack_bytes_compared=False,
        allocator_provider_mapping_rollback_verified=False, complete_helper_vm_verified=False,
        complete_child_vm_verified=False, complete_second_vm_verified=False)
    if args.group == 'red': report['red_cases'] = red(args.library)
    if args.group in ('strings', 'all'):
        labels = dict(construct=('NULL_source', 'empty', 'normal', 'embedded_NUL',
            'cross_page_object', 'cross_page_source', 'packed_object_alias', 'packed_source_alias',
            'object_source_alias', 'allocation_failure', 'custom_empty_descriptor'),
            destroy=('normal', 'NULL_payload', 'cross_page_object', 'packed_object_alias',
                'payload_object_alias', 'payload_packed_alias', 'free_mutates_object', 'custom_empty_descriptor'))
        report['cases'] = [compare(args.library, image, kind, label)
            for image in BASES for kind, names in labels.items() for label in names]
    if args.group in ('guards', 'all'): report['negative_cases'] = guards(args.library)
    if args.group in ('entry', 'all'): report['entry_negative_cases'] = entry_guards(args.library)
    report['native_Python_controls'] = len(report['cases']); report['rollback_guards'] = len(report['negative_cases'])
    args.output.write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8', newline='\n')
    print('PASS environment strings', args.group, report['native_Python_controls'], report['rollback_guards'])


if __name__ == '__main__': main()
