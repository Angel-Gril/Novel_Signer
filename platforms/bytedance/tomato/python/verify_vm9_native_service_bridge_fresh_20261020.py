"""Original GetEnv through live provider pages, plus bounded bridge refusals."""
from pathlib import Path
import argparse
import json
import sys

import vm9_native_service_bridge as bridge


def verify(library):
    assert 'unicorn' not in sys.modules and 'verify_vm9_signer_objects' not in sys.modules
    from unicorn import Uc, UcError, UC_ARCH_ARM64, UC_MODE_ARM
    from unicorn import arm64_const as arm
    import verify_vm9_signer_objects as oracle
    import vm9_jni_environment as environment
    from vm9_allocator import RefillUnsupported, _PageTransaction, _read_span, _write_span
    comparisons, guards = [], []
    G, GET = oracle.GUEST, 0x7400F000
    SP, TP, VM, TABLE = (G + n for n in (0xEF00, 0xD000, 0x1100, 0x1200))
    MARKER = G + 0x2FFC
    for index, image in enumerate((0x122C0000, 0x775C205000)):
        p = oracle.image_pages(library, image)
        p.update(oracle.fresh_pages())
        def word(a, v):
            _write_span(p, a, v.to_bytes(8, 'little'))
        word(image + 0x3DEED8, VM)
        word(VM, TABLE)
        word(TABLE + 0x30, GET)
        word(SP - 0x30, 0xBAD0BAD0)
        payload = b'live-cpu-view'
        _write_span(p, MARKER, bytes(len(payload)))
        baseline = {page: bytes(raw) for page, raw in p.items()}
        events = []
        env = G + 0x3380 + index * 16
        def service(pages, fn, args):
            assert fn == GET and args == (VM, SP - 0x30, 0x10006)
            # Original instructions zeroed the scratch slot after input loading.
            assert _read_span(pages, args[1], 8) == bytes(8)
            tx = _PageTransaction(pages)
            _write_span(tx, args[1], env.to_bytes(8, 'little'))
            _write_span(tx, MARKER, payload)
            assert _read_span(pages, MARKER, len(payload)) == bytes(len(payload))
            tx.commit()
            assert _read_span(pages, MARKER, len(payload)) == payload
            events.append((fn, args, env))
            return 0
        model = _PageTransaction(p)
        expected = environment.get_java_environment(model, image_base=image,
            entry_stack_address=SP, invoke_javavm=service)
        model_events = list(events)
        events.clear()
        imports = bridge.make_native_service_imports(
            [bridge.NativeService(GET, 3, service)], image_base=image)
        initial = {page: bytearray(raw) for page, raw in baseline.items()}
        initial[GET >> 12] = bytearray(4096)
        watch = {(SP - 0x30, 8): None, (MARKER, len(payload)): None}
        actual, _, allocations, legacy = oracle.native(library, image, 0x17CAAC, [], initial,
            map_extra_input_pages=True, real_jni_acquisition=True,
            host_imports=imports, observed_memory=watch,
            extra_registers={arm.UC_ARM64_REG_SP: SP, arm.UC_ARM64_REG_TPIDR_EL0: TP})
        assert actual == expected == env and events == model_events
        assert not allocations and not legacy
        assert all(raw == _read_span(model, a, n) for (a, n), raw in watch.items())
        assert baseline == {page: bytes(raw) for page, raw in p.items()}
        comparisons.append(dict(image_base=hex(image), original_GetEnv_return_equal=True,
            current_CPU_scratch_observed=True, nested_transaction_commit_visible=True,
            cross_page_bytes_equal=True, ordered_provider_events_equal=True,
            independent_input_unchanged=True, declared_ranges=len(watch)))
        if index == 0:
            events.clear()
            try:
                oracle.native(library, image, 0x17CAAC, [], initial, host_imports=imports)
            except UcError:
                pass
            else:
                raise AssertionError('extra mapping unexpectedly enabled by default')
            assert not events
            guards.append('default_extra_mapping_disabled')

    cpu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    cpu.mem_map(G, 8192)
    pages = bridge.LiveCpuPages(cpu)
    def rejected(label, call):
        before = bytes(cpu.mem_read(G, 8192)), tuple(cpu.mem_regions())
        try:
            call()
        except (RefillUnsupported, ValueError, KeyError):
            pass
        else:
            raise AssertionError('bridge accepted ' + label)
        assert before == (bytes(cpu.mem_read(G, 8192)), tuple(cpu.mem_regions()))
        guards.append(label)
    good = bridge.NativeService(GET, 3, lambda *args: 0)
    rejected('unaligned_target', lambda: bridge.NativeService(GET + 1, 3, lambda *a: 0))
    rejected('bool_target', lambda: bridge.NativeService(True, 3, lambda *a: 0))
    rejected('oversized_arity', lambda: bridge.NativeService(GET, 9, lambda *a: 0))
    rejected('missing_provider', lambda: bridge.NativeService(GET, 3, None))
    rejected('duplicate_target', lambda: bridge.make_native_service_imports([good, good], image_base=0))
    rejected('unmapped_read', lambda: pages[(G >> 12) + 2])
    rejected('implicit_mapping', lambda: pages.__setitem__((G >> 12) + 2, bytes(4096)))
    rejected('implicit_unmapping', lambda: pages.__delitem__(G >> 12))
    rejected('page_resize', lambda: pages[G >> 12].__setitem__(slice(0, 1), b'ab'))
    bad = bridge.make_native_service_imports(
        [bridge.NativeService(GET, 0, lambda *a: None)], image_base=0)[GET]
    cpu.reg_write(arm.UC_ARM64_REG_PC, GET)
    rejected('invalid_provider_result', lambda: bad(cpu))
    cpu.reg_write(arm.UC_ARM64_REG_PC, GET + 4)
    rejected('hook_target_mismatch', lambda: bad(cpu))
    rejected('non_boolean_mapping_option', lambda: oracle.native(library, 0, 0, [], {},
        map_extra_input_pages=1))
    return dict(native_Python_controls=len(comparisons), refusal_guards=len(guards),
        cases=comparisons, guards=guards, historical_native_groups_replayed=False,
        whole_second_memory_equivalence_verified=False, live_JVM_verified=False,
        external_provider_effect_rollback_verified=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = verify(args.library)
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps({k: v for k, v in result.items() if k not in ('cases', 'guards')}))


if __name__ == '__main__':
    main()
