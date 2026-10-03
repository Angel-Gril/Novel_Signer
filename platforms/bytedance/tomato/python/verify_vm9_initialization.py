"""Native differential checks; private ARM64 images stay local.

Run with --capture-dir pointing to a trusted same-capture directory containing
vm9_libc.bin, vm9_m0.bin, vm9_m1.bin, vm9_m2.bin and vm9_copy2.bin.
The output contains only case names, hashes, counts and boolean comparisons.
"""
from pathlib import Path
import argparse
import hashlib
import json
import importlib

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_INTR, UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_SP, UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X30, UC_ARM64_REG_TPIDR_EL0
import vm9_allocator as model


REGIONS = ((0x11EC0000, 0x890000), (0x12800000, 0x800000), (0xE4FF0000, 0x10000))
STOP = 0x70000000
TP = 0xE4FFF718


def load_pages(directory):
    pages = {a >> 12: bytearray(4096) for b, n in REGIONS for a in range(b, b + n, 4096)}
    identities = {}
    for base, name in ((0x12100000, 'vm9_libc.bin'), (0x12290000, 'vm9_m0.bin'),
                       (0x12800000, 'vm9_m1.bin'), (0xE4FF0000, 'vm9_m2.bin'),
                       (0x11EC0000, 'vm9_copy2.bin')):
        data = (directory / name).read_bytes()
        assert len(data) % 4096 == 0
        identities[name] = hashlib.sha256(data).hexdigest()
        for off in range(0, len(data), 4096):
            assert (base + off) >> 12 in pages
            pages[(base + off) >> 12][:] = data[off:off + 4096]
    return pages, identities


def native(pages, function, arguments, *, tp=TP, stop_at=STOP, malloc_null=False):
    cpu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    for base, length in REGIONS:
        cpu.mem_map(base, length)
        cpu.mem_write(base, b''.join(bytes(pages[a >> 12]) for a in range(base, base + length, 4096)))
    cpu.mem_map(STOP, 0x100000)
    cpu.reg_write(UC_ARM64_REG_SP, STOP + 0xFF000)
    cpu.reg_write(UC_ARM64_REG_X30, STOP)
    cpu.reg_write(UC_ARM64_REG_TPIDR_EL0, tp)
    for reg, value in zip((UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2), arguments):
        cpu.reg_write(reg, value)
    def reject_syscall(cpu, number, data):
        raise AssertionError('unexpected initialization syscall')
    cpu.hook_add(UC_HOOK_INTR, reject_syscall)
    if malloc_null:
        def fail_malloc(cpu, address, size, data):
            if address == 0x1210BB08:
                cpu.reg_write(UC_ARM64_REG_X0, 0)
                cpu.reg_write(UC_ARM64_REG_PC, cpu.reg_read(UC_ARM64_REG_X30))
        cpu.hook_add(UC_HOOK_CODE, fail_malloc)
    cpu.emu_start(function, stop_at, count=500000)
    assert cpu.reg_read(UC_ARM64_REG_PC) == stop_at, 'native instruction budget exhausted'
    expected = {}
    for base, length in REGIONS:
        data = cpu.mem_read(base, length)
        for off in range(0, length, 4096):
            expected[(base + off) >> 12] = data[off:off + 4096]
    return cpu.reg_read(UC_ARM64_REG_X0), expected


def put(pages, address, value, length=8):
    data = value.to_bytes(length, 'little')
    for i, byte in enumerate(data):
        pages[(address + i) >> 12][(address + i) & 4095] = byte


def run(options):
    baseline, identities = load_pages(options.capture_dir)
    results = []
    negatives = []
    pthread = model.read_u64(baseline, TP + 8)
    key = 0x8000000B
    global_generation = 0x121D0200 + 11 * 16
    slot = pthread + 0xE8 + 11 * 16
    cases = (
        ('get_current', 'get', key, 0, []),
        ('get_stale', 'get', key, 0, [(slot, 0, 8)]),
        ('get_inactive', 'get', key, 0, [(global_generation, 2, 8)]),
        ('get_null', 'get', key, 0, [(slot + 8, 0, 8)]),
        ('get_invalid_positive', 'get', 11, 0, []),
        ('get_invalid_boundary', 'get', 0x8000008D, 0, []),
        ('get_upper_bits', 'get', (1 << 48) | key, 0, []),
        ('set_current', 'set', key, 0x123456789ABCDEF0, []),
        ('set_null', 'set', key, 0, []),
        ('set_stale', 'set', key, 123, [(slot, 0, 8)]),
        ('set_inactive', 'set', key, 123, [(global_generation, 2, 8)]),
        ('set_invalid', 'set', 0xFFFFFFFF, 123, []),
    )
    for label, kind, test_key, value, patches in cases:
        pages = {k: bytearray(v) for k, v in baseline.items()}
        for a, v, n in patches:
            put(pages, a, v, n)
        result, expected = native(pages, 0x12158760 if kind == 'get' else 0x121587C4,
                                  [test_key] if kind == 'get' else [test_key, value])
        if kind == 'get':
            assert hasattr(model, 'pthread_getspecific'), 'TLS lookup behavior is not implemented'
            actual = model.pthread_getspecific(pages, key=test_key, thread_pointer=TP)
        else:
            actual = model.pthread_setspecific(pages, key=test_key, value=value, thread_pointer=TP)
        assert result == actual, label
        assert pages == expected, label
        results.append({'case': label, 'return_match': True, 'final_memory_match': True,
                        'pages_compared': len(pages)})
        print('PASS', label, flush=True)
    # A synthetic pthread placement forces generation and value stores across
    # two pages. The executable code is unchanged and remains the oracle.
    for kind in ('get', 'set'):
        pages = {k: bytearray(v) for k, v in baseline.items()}
        synthetic = 0x12F00E64
        put(pages, TP + 8, synthetic)
        generation = model.read_u64(pages, global_generation)
        put(pages, synthetic + 0xE8 + 11 * 16, generation)
        put(pages, synthetic + 0xF0 + 11 * 16, 42)
        result, expected = native(pages, 0x12158760 if kind == 'get' else 0x121587C4,
                                  [key] if kind == 'get' else [key, 123])
        actual = (model.pthread_getspecific(pages, key=key, thread_pointer=TP) if kind == 'get'
                  else model.pthread_setspecific(pages, key=key, value=123, thread_pointer=TP))
        assert actual == result and pages == expected, ('cross_page', kind)
        results.append({'case': kind + '_cross_page', 'return_match': True, 'final_memory_match': True,
                        'pages_compared': len(pages)})
    pages = {k: bytearray(v) for k, v in baseline.items()}
    put(pages, TP + 8, 0x12F00E64)
    del pages[0x12F01000 >> 12]
    before = {k: bytes(v) for k, v in pages.items()}
    try:
        model.pthread_setspecific(pages, key=key, value=123, thread_pointer=TP)
    except (ValueError, model.RefillUnsupported):
        pass
    else:
        raise AssertionError('missing TLS page accepted')
    assert pages == before, 'TLS publication was not atomic on failure'
    negatives.append({'case': 'tls_missing_page', 'rejected': True, 'unchanged': True})
    for size in (1, 64, 65, 0x1000, 0x1001, 0x66C0):
        pages = {k: bytearray(v) for k, v in baseline.items()}
        result, expected = native(pages, 0x1216D998, [size])
        assert hasattr(model, 'base_allocate'), 'Base extent allocation is not implemented'
        actual = model.base_allocate(pages, request_size=size)
        assert result == actual and pages == expected, ('base', size)
        results.append({'case': f'base_size_{size}', 'return_match': True,
                        'final_memory_match': True, 'pages_compared': len(pages)})
        print('PASS base', size, flush=True)
    for index, fill in ((0, False), (2, False), (31, True)):
        pages = {k: bytearray(v) for k, v in baseline.items()}
        if fill:
            target = model.read_u64(pages, model.read_u64(pages, 0x121D67E8) + 8)
            for offset in range(0x66C0):
                pages[(target + offset) >> 12][(target + offset) & 4095] = 0xA5
        result, expected = native(pages, 0x1216CCE8, [index])
        assert hasattr(model, 'create_arena'), 'Arena field initialization is not implemented'
        actual = model.create_arena(pages, arena_index=index)
        assert result == actual, ('arena_return', index)
        different = [k for k in pages if pages[k] != expected[k]]
        if different:
            for k in different:
                offsets = [i for i in range(4096) if pages[k][i] != expected[k][i]]
                print('arena differences', hex(k << 12), offsets[:24], flush=True)
        assert not different, ('arena', index, fill)
        results.append({'case': f'arena_index_{index}_prefill_{fill}', 'return_match': True,
                        'final_memory_match': True, 'pages_compared': len(pages)})
        print('PASS arena', index, 'prefill', fill, flush=True)
    for request in (8, 0x2C, 0x1C00):
        pages = {k: bytearray(v) for k, v in baseline.items()}
        # W2 is the zero flag; native() accepts the first two arguments only,
        # so its reset register state selects the ordinary nonzeroing path.
        result, expected = native(pages, 0x12169FA4, [0x12240180, request])
        assert hasattr(model, 'allocate_arena_small'), 'Direct arena allocation is not implemented'
        actual = model.allocate_arena_small(pages, arena_address=0x12240180, request_size=request)
        assert actual == result and pages == expected, ('arena_small', request)
        results.append({'case': f'direct_arena_small_{request}', 'return_match': True,
                        'final_memory_match': True, 'pages_compared': len(pages)})
    for class_id in range(36):
        pages = {k: bytearray(v) for k, v in baseline.items()}
        request = model.read_u64(pages, 0x12196C80 + class_id * 8)
        control = 0x12240180 + 0x508 + class_id * 0xE0
        put(pages, control + 0x28, 0)
        put(pages, control + 0x30, control + 0x38)
        result, expected = native(pages, 0x12169FA4, [0x12240180, request, 1])
        actual = model.allocate_arena_small(pages, arena_address=0x12240180, request_size=request, zero=True)
        assert actual == result and pages == expected, ('direct_new_slab_zero', class_id)
        results.append({'case': f'direct_new_slab_zero_class_{class_id}', 'return_match': True,
                        'final_memory_match': True, 'pages_compared': len(pages)})
    for empty in (False, True):
        pages = {k: bytearray(v) for k, v in baseline.items()}
        if empty:
            put(pages, 0x12240180 + 0xA8, 0)
        result, expected = native(pages, 0x12188490, [0x12296008, 0x12240180])
        assert hasattr(model, 'create_tcache'), 'Thread cache creation is not implemented'
        actual = model.create_tcache(pages, arena_address=0x12240180)
        assert actual == result, 'tcache return'
        assert pages == expected, ('tcache', empty)
        results.append({'case': f'tcache_empty_chain_{empty}', 'return_match': True,
                        'final_memory_match': True, 'pages_compared': len(pages)})
        print('PASS tcache', empty, flush=True)
    for stale, fill in ((False, False), (True, False), (False, True)):
        pages = {k: bytearray(v) for k, v in baseline.items()}
        put(pages, slot + 8, 0 if not stale else 0x12345678)
        if stale:
            put(pages, slot, 0)
        if fill:
            for offset in range(128):
                pages[(0x12296680 + offset) >> 12][(0x12296680 + offset) & 4095] = 0xA5
        _, expected = native(pages, 0x1210BB08, [0x2C], stop_at=0x1217F534)
        assert hasattr(model, 'initialize_thread_state'), 'Fresh TSD creation/publication is not implemented'
        actual = model.initialize_thread_state(pages, thread_pointer=TP)
        assert actual == model.read_u64(expected, slot + 8)
        assert pages == expected, ('tsd_initial', stale, fill)
        results.append({'case': f'tsd_initial_stale_{stale}_prefill_{fill}', 'return_match': True,
                        'final_memory_match': True, 'pages_compared': len(pages),
                        'native_boundary': 'Before state 0 to 1 transition in malloc'})
        print('PASS TSD initial', stale, fill, flush=True)
    for single in (False, True):
        pages = {k: bytearray(v) for k, v in baseline.items()}
        put(pages, 0x12296030, 0)
        if single:
            put(pages, 0x121D6970, 1, 4)
        result, expected = native(pages, 0x1217DDA0, [0x12296008])
        assert hasattr(model, 'choose_thread_arena'), 'Thread arena selection is not implemented'
        actual = model.choose_thread_arena(pages, thread_state_address=0x12296000)
        assert actual == result and pages == expected, ('arena_choose', single)
        results.append({'case': f'arena_choose_single_{single}', 'return_match': True,
                        'final_memory_match': True, 'pages_compared': len(pages)})
    pages = {k: bytearray(v) for k, v in baseline.items()}
    put(pages, slot + 8, 0)
    _, expected = native(pages, 0x1210BB08, [0x2C], stop_at=0x1217F350)
    assert hasattr(model, 'prepare_thread_allocator'), 'Combined fresh thread initialization is not implemented'
    actual = model.prepare_thread_allocator(pages, thread_pointer=TP)
    assert actual == model.read_u64(expected, slot + 8)
    different = [k for k in pages if pages[k] != expected[k]]
    if different:
        for k in different:
            offsets = [i for i in range(4096) if pages[k][i] != expected[k][i]]
            print('thread prepare differences', hex(k << 12), offsets[:24], flush=True)
    assert not different, 'thread prepare state'
    results.append({'case': 'fresh_tls_to_tcache_publication', 'return_match': True,
                    'final_memory_match': True, 'pages_compared': len(pages),
                    'native_boundary': 'After tcache publication, before malloc refill'})
    for label, size, extent_size in (('consume_node', 64, 64), ('keep_payload', 4097, 0x4000)):
        pages = {k: bytearray(v) for k, v in baseline.items()}
        node = model.read_u64(pages, 0x121D67E8)
        put(pages, node + 8, 0x12F00040)
        put(pages, node + 0x10, extent_size)
        pages[0x12F00000 >> 12][:] = bytes([0xA5]) * 4096
        result, expected = native(pages, 0x1216D998, [size])
        actual = model.base_allocate(pages, request_size=size)
        assert actual == result and pages == expected, ('base_variant', label)
        results.append({'case': 'base_' + label, 'return_match': True,
                        'final_memory_match': True, 'pages_compared': len(pages)})
    # Build a genuinely different extent tree with native insertions, then
    # compare allocation/removal/reinsertion using the independent Python tree.
    for ordering in ((0, 1, 2, 3), (3, 2, 1, 0), (1, 3, 0, 2)):
        pages = {k: bytearray(v) for k, v in baseline.items()}
        _, pages = native(pages, 0x12179460, [0x121D67E8])
        pages = {k: bytearray(v) for k, v in pages.items()}
        for index in ordering:
            node = 0x12E00000 + index * 0x80
            put(pages, node + 8, 0x12E10000 + index * 0x10000)
            put(pages, node + 0x10, (index + 1) * 0x4000)
            _, pages = native(pages, 0x12179674, [0x121D67E8, node])
            pages = {k: bytearray(v) for k, v in pages.items()}
        for size in (0x8000, 0x2000, 0x3000):
            result, expected = native(pages, 0x1216D998, [size])
            actual = model.base_allocate(pages, request_size=size)
            assert actual == result and pages == expected, ('base_tree', ordering, size)
        results.append({'case': 'base_tree_order_' + ''.join(map(str, ordering)),
                        'operations': 3, 'return_match': True, 'final_memory_match': True,
                        'pages_compared': len(pages)})
    for label, patches, operation in (
        ('base_empty_tree', [(0x121D67E8, 0x121D67F0, 8)], lambda p: model.base_allocate(p, request_size=64)),
        ('base_contended', [(0x121D6860, 1, 2)], lambda p: model.base_allocate(p, request_size=64)),
        ('arena_late_lock', [(0x121D6898, 1, 2)], lambda p: model.create_arena(p, arena_index=2)),
        ('tcache_overflow', [(0x121D6A9C, 0, 4)], lambda p: model.create_tcache(p, arena_address=0x12240180)),
        ('tsd_recursion', [(0x121D6AB8, 0x12F00000, 8), (slot + 8, 0, 8)], lambda p: model.initialize_thread_state(p, thread_pointer=TP)),
        ('tsd_inactive_key', [(global_generation, 2, 8)], lambda p: model.initialize_thread_state(p, thread_pointer=TP)),
        ('cache_disabled', [(slot + 8, 0, 8), (0x121CB6B0, 0, 1)], lambda p: model.prepare_thread_allocator(p, thread_pointer=TP)),
    ):
        pages = {k: bytearray(v) for k, v in baseline.items()}
        for a, v, n in patches:
            put(pages, a, v, n)
        before = {k: bytes(v) for k, v in pages.items()}
        try:
            operation(pages)
        except model.RefillUnsupported:
            pass
        else:
            raise AssertionError(('not rejected', label))
        assert pages == before, ('mutation on rejection', label)
        negatives.append({'case': label, 'rejected': True, 'unchanged': True})
    # Complete initialization succeeds, but a new arena has no OS region.
    # A user allocation must reject rather than secretly invoke native malloc.
    pages = {k: bytearray(v) for k, v in baseline.items()}
    put(pages, slot + 8, 0)
    thread = model.prepare_thread_allocator(pages, thread_pointer=TP)
    before = {k: bytes(v) for k, v in pages.items()}
    try:
        model.allocate_small_object(pages, thread_state_address=thread, request_size=0x2C)
    except model.RefillUnsupported:
        pass
    else:
        raise AssertionError('fresh OS region requirement was hidden')
    assert pages == before
    negatives.append({'case': 'fresh_thread_first_refill_requires_os_region', 'rejected': True, 'unchanged': True})
    for label, payload in (('null', None), ('empty', b''), ('ascii', b'changed-input'),
                           ('utf8', '初始化测试'.encode()), ('cross_page', b'page-boundary-input')):
        for allocation_failure in (False, True):
            pages = {k: bytearray(v) for k, v in baseline.items()}
            obj = 0x12F20FF8
            source = 0 if payload is None else 0x12F10FFC
            if payload is not None:
                for offset, byte in enumerate(payload + b'\0'):
                    pages[(source + offset) >> 12][(source + offset) & 4095] = byte
            for offset in range(24):
                pages[(obj + offset) >> 12][(obj + offset) & 4095] = 0xA5
            result, expected = native(pages, 0x12508344, [obj, source], malloc_null=allocation_failure)
            assert (Path(__file__).parent / 'vm9_objects.py').exists(), 'Input-driven string constructor is not implemented'
            objects = importlib.import_module('vm9_objects')
            def allocate(target, length):
                if allocation_failure:
                    return 0
                return model.allocate_small_object(target, thread_state_address=0x12296000,
                                                   request_size=length).free_list.object_address
            actual = objects.construct_string_object(pages, object_address=obj, source_address=source,
                                                      allocate=allocate)
            assert actual == result and pages == expected, ('constructor', label, allocation_failure)
            results.append({'case': f'constructor_{label}_allocation_failure_{allocation_failure}',
                            'return_match': True, 'final_memory_match': True, 'pages_compared': len(pages)})
            print('PASS constructor', label, allocation_failure, flush=True)
    for label in ('unterminated', 'missing_payload_page'):
        pages = {k: bytearray(v) for k, v in baseline.items()}
        obj, source = 0x12F20000, 0x12F10000
        payload = b'A' * 64 if label == 'unterminated' else b'A' * 44 + b'\0'
        pages[source >> 12][:len(payload)] = payload
        if label == 'missing_payload_page':
            bins = model.read_u64(pages, 0x12296010)
            count = model.read_u32(pages, bins + 3 * 32 + 0x30)
            storage = model.read_u64(pages, bins + 3 * 32 + 0x38)
            put(pages, storage + (count - 1) * 8, 0x12F30000)
            del pages[0x12F30000 >> 12]
        before = {k: bytes(v) for k, v in pages.items()}
        def allocate(target, length):
            return model.allocate_small_object(target, thread_state_address=0x12296000,
                                               request_size=length).free_list.object_address
        try:
            objects.construct_string_object(pages, object_address=obj, source_address=source,
                                            allocate=allocate, max_source_bytes=64)
        except (ValueError, model.RefillUnsupported):
            pass
        else:
            raise AssertionError(('constructor not rejected', label))
        assert pages == before, ('constructor mutated before rejection', label)
        negatives.append({'case': 'constructor_' + label, 'rejected': True, 'unchanged': True})
    output = {'capture_files_sha256': identities, 'model_sha256': hashlib.sha256(Path(model.__file__).read_bytes()).hexdigest(),
              'objects_sha256': hashlib.sha256(Path(objects.__file__).read_bytes()).hexdigest(),
              'verifier_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'cases': results, 'negative_cases': negatives,
              'scope': 'Initialized global configuration; no independent global boot or online signing claim.'}
    options.output.write_text(json.dumps(output, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    run(parser.parse_args())
