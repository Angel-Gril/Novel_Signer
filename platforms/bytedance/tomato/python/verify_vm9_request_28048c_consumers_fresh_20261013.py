"""Fresh actual child-request wrappers; imported memcpy is an explicit boundary.

The local +2a9280 copy executes its original instructions, including overlaps.
No native snapshot is supplied as model input. Complete request/JNI/signing is
outside this component check.
"""
from pathlib import Path
import argparse, hashlib, json, os
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
import vm9_request_28048c_vm as model
from vm9_allocator import RefillUnsupported, _read_span, _write_span

BASES = (0x122C0000, 0x775C205000)
OWNER = 'apply_request_28048c_consumer'
G = oracle.GUEST


def fixture(library, image, kind, label):
    pages = oracle.image_pages(library, image)
    pages.update(oracle.fresh_pages())
    block, obj, source = G + 0x1000, G + 0x1800, G + 0x2800
    wrapper, target = {'filled': (0x281434, 0x248274), 'memset': (0x281448, 0x347F20),
        'memcpy': (0x28145C, 0x347F60), 'copy': (0x281470, 0x2A9280)}[kind]
    if label == 'cross_page_object': obj = G + 0x1FF8
    if label == 'object_packed_alias': obj = block
    _write_span(pages, block, (image + target).to_bytes(8, 'little') +
        obj.to_bytes(8, 'little') + source.to_bytes(8, 'little') + (16).to_bytes(8, 'little'))
    if kind == 'filled':
        length = {'zero': 0, 'one': 1, 'normal': 16, 'medium': 33,
            'negative_W': 0x80000000}.get(label, 16)
        _write_span(pages, block + 16, b'\xc3\x91\x82\x73' + length.to_bytes(4, 'little'))
    if kind in ('copy', 'memcpy'):
        length = int(label.split(':')[0])
        mode = label.split(':')[1]
        source, obj = G + 0x2800, G + 0x3800
        if mode == 'forward_overlap': obj = source - 7
        elif mode == 'backward_overlap': obj = source + 7
        elif mode == 'self': obj = source
        elif mode == 'unaligned': obj += 5; source += 3
        elif mode == 'cross_page': source = G + 0x2FF8; obj = G + 0x3FF9
        elif mode == 'packed_destination': obj = block + 16
        elif mode == 'packed_source': source = block + 16
        elif mode == 'NULL_zero': source = obj = 0
        _write_span(pages, G + 0x2000, bytes((i * 37 + 19) & 255 for i in range(4096)))
        _write_span(pages, block + 8, obj.to_bytes(8, 'little') + source.to_bytes(8, 'little') + length.to_bytes(8, 'little'))
    if kind == 'memset':
        length = int(label.split(':')[0]); mode = label.split(':')[1]
        destination = G + 0x3800; fill = 0xC3
        if mode == 'cross_page': destination = G + 0x3FF9
        elif mode == 'packed_destination': destination = block + 16
        elif mode == 'NULL_zero': destination = 0
        elif mode == 'zero_fill': fill = 0
        elif mode == 'max_fill': fill = 255
        _write_span(pages, block + 8, destination.to_bytes(8, 'little') +
            bytes([fill, 0x91, 0x82, 0x73, 0x64, 0x55, 0x46, 0x37]) + length.to_bytes(8, 'little'))
    return pages, dict(wrapper_offset=wrapper, argument_block_address=block,
        image_base=image), label == 'allocation_failure'


def run_native(library, pages, inputs, failure=False):
    requests, freed = [], []
    def malloc(cpu, size):
        pointer = 0 if failure else G + 0x4000
        requests.append([size, pointer]); return pointer
    def free(cpu):
        freed.append(cpu.reg_read(arm.UC_ARM64_REG_X0)); return 0
    watched = {(G, 0xA000): None}
    result, _, _, services = oracle.native(library, inputs['image_base'],
        inputs['wrapper_offset'], [inputs['argument_block_address']], pages,
        malloc_handler=malloc, host_imports={0x347FA0: free},
        observed_memory=watched, instruction_limit=10000)
    assert not services
    return result, watched[G, 0xA000], requests, freed


def red(library):
    assert not hasattr(model, OWNER), 'RED requires the prior consumer boundary'
    rows = []
    for image in BASES:
        for kind, label in (('filled', 'normal'), ('memset', '17:normal'),
                            ('memcpy', '17:normal'), ('copy', '129:backward_overlap')):
            pages, inputs, failure = fixture(library, image, kind, label)
            run_native(library, pages, inputs, failure)
            rows.append(dict(image_base=hex(image), case=kind,
                original_wrapper_returned=True, prior_consumer_missing=True,
                native_snapshot_input=False))
    return rows


def compare(library, image, kind, label):
    pages, inputs, failure = fixture(library, image, kind, label)
    initial = {k: bytearray(v) for k, v in pages.items()}
    allocated, freed = [], []
    def allocate(p, size):
        pointer = 0 if failure else G + 0x4000
        allocated.append([size, pointer]); return pointer
    def free(p, pointer): freed.append(pointer)
    getattr(model, OWNER)(pages, **inputs, allocate=allocate)
    result, memory, requests, native_freed = run_native(library, initial, inputs, failure)
    assert _read_span(pages, G, 0xA000) == memory, (kind, label)
    assert allocated == requests and freed == native_freed, (kind, label, allocated, requests, freed, native_freed)
    if kind == 'copy':
        assert int.from_bytes(_read_span(pages, inputs['argument_block_address'] + 32, 8), 'little') == result
    print('PASS child consumer', hex(image), kind, label, flush=True)
    return dict(image_base=hex(image), case=label, kind=kind,
        actual_wrapper=hex(inputs['wrapper_offset']), original_wrapper_returned=True,
        all_declared_guest_bytes_and_packed_padding_equal=True,
        allocation_requests_and_free_calls_equal=True,
        imported_memory_service_is_explicit_oracle_boundary=kind in ('memcpy', 'memset'),
        local_copy_instructions_executed=kind == 'copy', native_snapshot_input=False)


def guards(library):
    rows = []
    labels = ('wrong_target', 'wrong_wrapper', 'missing_packed', 'missing_object',
        'allocator_late_failure', 'filled_bound', 'copy_bound', 'memset_Q_bound',
        'missing_copy_source', 'missing_copy_destination', 'missing_copy_result',
        'imported_memcpy_overlap', 'missing_memset_destination')
    for label in labels:
        kind = 'copy' if label.startswith(('copy_', 'missing_copy')) else 'memset' if 'memset' in label else 'memcpy' if label == 'imported_memcpy_overlap' else 'filled'
        pages, inputs, _ = fixture(library, BASES[0], kind, '16:normal' if kind != 'filled' else 'normal')
        block = inputs['argument_block_address']
        if label == 'wrong_target': _write_span(pages, block, (BASES[0] + 1).to_bytes(8, 'little'))
        elif label == 'wrong_wrapper': inputs['wrapper_offset'] = 1
        elif label == 'missing_packed': del pages[block >> 12]
        elif label in ('missing_object', 'missing_copy_destination', 'missing_memset_destination'):
            _write_span(pages, block + 8, (G + 0x10000).to_bytes(8, 'little'))
        elif label == 'filled_bound': _write_span(pages, block + 20, (0x100001).to_bytes(4, 'little'))
        elif label in ('copy_bound', 'memset_Q_bound'):
            _write_span(pages, block + 24, (0x100001 if kind == 'copy' else 1 << 32).to_bytes(8, 'little'))
        elif label == 'missing_copy_source': _write_span(pages, block + 16, (G + 0x10000).to_bytes(8, 'little'))
        elif label == 'missing_copy_result':
            raw = _read_span(pages, block, 32); block = G + 0xFFE0
            _write_span(pages, block, raw); inputs['argument_block_address'] = block
        elif label == 'imported_memcpy_overlap': _write_span(pages, block + 8, (G + 0x2801).to_bytes(8, 'little'))
        before = {k: bytes(v) for k, v in pages.items()}
        def allocate(p, size):
            _write_span(p, G + 0x4000, b'changed')
            if label == 'allocator_late_failure': raise RefillUnsupported('explicit allocation failure')
            return G + 0x4000
        try: getattr(model, OWNER)(pages, **inputs, allocate=allocate)
        except (RefillUnsupported, ValueError): pass
        else: raise AssertionError(label)
        assert before == {k: bytes(v) for k, v in pages.items()}, label
        rows.append(dict(case=label, rejected=True, all_pages_unchanged=True))
    return rows


def entry_guards(library):
    os.environ['TOMATO_LIBMETASEC'] = str(library.resolve())
    import vm_full
    from verify_vm9_request_28048c_vm_fresh_20261013 import fixture as frame_fixture, packed
    assert Path(vm_full.__file__).resolve().parent == Path(__file__).resolve().parent
    rows = []
    for label in ('invalid_services', 'missing_free', 'noncallable_allocate', 'zero_budget', 'bounded_budget'):
        pages, inputs = frame_fixture(library, BASES[0], 'normal'); packed(pages, inputs)
        wrapper_inputs = {k:v for k,v in inputs.items() if k not in ('output_x8','argument_x0','argument_x1','argument_x2')}
        before = {k: bytes(v) for k, v in pages.items()}
        kw = dict(vm_module=vm_full, consumer_services=dict(allocate=lambda p,n:G+0x4000, free=lambda p,a:None))
        if label == 'invalid_services': kw['consumer_services'] = []
        elif label == 'missing_free': del kw['consumer_services']['free']
        elif label == 'noncallable_allocate': kw['consumer_services']['allocate'] = None
        elif label == 'zero_budget': kw['maxsteps'] = 0
        else: kw['maxsteps'] = 1
        previous = vm_full.B
        try: model.execute_request_28048c_vm_prefix(pages, argument_block_address=G+0x1000, **kw, **wrapper_inputs)
        except RefillUnsupported: assert label != 'bounded_budget'
        except RuntimeError as exc: assert label == 'bounded_budget' and str(exc).startswith('step limit @')
        else: raise AssertionError(label)
        assert previous == vm_full.B and before == {k: bytes(v) for k, v in pages.items()}
        rows.append(dict(case=label, rejected=True, all_pages_unchanged=True, module_image_base_restored=True))
    return rows


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--library', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--group', choices=('red', 'lifecycle', 'copy', 'guards', 'entry', 'all'), default='all')
    args = p.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == oracle.LIBRARY_SHA256
    report = dict(schema='vm9-request-28048c-consumers-fresh-v1', evidence_date='2026-10-13',
        sample_sha256=oracle.LIBRARY_SHA256, cases=[], negative_cases=[],
        native_snapshot_input=False, private_names_or_payloads_published=False,
        whole_request_native_differential_verified=False, actual_URL_header_JNI_conversion_verified=False,
        live_Android_JVM_verified=False, complete_python_medusa=False,
        fresh_signer_output_verified=False, live_server_matrix_verified=False,
        whole_physical_stack_bytes_compared=False, allocator_provider_mapping_rollback_verified=False,
        complete_child_vm_verified=False)
    if args.group == 'red': report['red_cases'] = red(args.library)
    if args.group in ('lifecycle', 'all'):
        cases = {'filled': ('zero', 'one', 'normal', 'medium', 'negative_W', 'allocation_failure', 'cross_page_object', 'object_packed_alias'),
            'memset': ('0:NULL_zero', '1:normal', '17:normal', '129:cross_page', '33:packed_destination', '17:zero_fill', '17:max_fill'),
            'memcpy': ('0:NULL_zero', '1:normal', '17:normal', '128:cross_page', '33:packed_destination', '33:packed_source')}
        report['cases'] += [compare(args.library, image, kind, label)
            for image in BASES for kind, labels in cases.items() for label in labels]
    if args.group in ('copy', 'all'):
        labels = [str(n) + ':normal' for n in (0, 3, 16, 33, 65, 97, 129, 257)]
        labels += [str(n) + ':' + mode for n in (17, 129)
            for mode in ('forward_overlap', 'backward_overlap', 'self', 'unaligned')]
        labels += ['0:NULL_zero', '129:cross_page', '97:packed_destination', '97:packed_source']
        report['cases'] += [compare(args.library, image, 'copy', label)
            for image in BASES for label in labels]
    if args.group in ('guards', 'all'): report['negative_cases'] = guards(args.library)
    if args.group in ('entry', 'all'): report['entry_negative_cases'] = entry_guards(args.library)
    report['native_Python_controls'] = len(report['cases'])
    report['rollback_guards'] = len(report['negative_cases'])
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
    print('PASS child consumers', args.group, report['native_Python_controls'], report['rollback_guards'])


if __name__ == '__main__': main()
