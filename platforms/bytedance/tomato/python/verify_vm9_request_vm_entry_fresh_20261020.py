"""Fresh Python entry refusals; no historical native groups are replayed."""
from pathlib import Path
import argparse
import importlib
import json
import os
import sys


def verify(library):
    # The production owner must import without the native oracle or interpreter.
    owner = importlib.import_module('vm9_request_vm')
    assert 'verify_vm9_signer_objects' not in sys.modules
    assert 'unicorn' not in sys.modules and 'vm_full' not in sys.modules
    os.environ['TOMATO_LIBMETASEC'] = str(library)
    vm_module = importlib.import_module('vm_full')
    import verify_vm9_signer_objects as oracle
    from vm9_allocator import RefillUnsupported, _read_span, _write_span
    import verify_vm9_request_prefix_fresh_20261007 as legacy
    assert legacy.execute_prefix is owner.execute_request_vm
    assert legacy.PrefixBoundary is owner.PrefixBoundary
    assert legacy.RequestContinuationBoundary is owner.RequestContinuationBoundary
    assert legacy.resolve_request_memory_imports is owner.resolve_request_memory_imports
    assert legacy.apply_request_configuration_set_callback is owner.apply_request_configuration_set_callback
    guards, prefixes = [], []
    for image in (0x122C0000, 0x775C205000):
        pages = oracle.image_pages(library, image)
        pages.update(oracle.fresh_pages())
        owner.resolve_request_memory_imports(pages, library, image)
        inputs = dict(entry_stack_address=oracle.GUEST+0xEF00,
            return_address=oracle.STOP, thread_pointer=oracle.GUEST+0xD000,
            image_base=image, argument_x0=oracle.GUEST+0x2000,
            argument_x1=oracle.GUEST+0x2100, argument_x2=0x138,
            argument_x3=oracle.GUEST+0x2200, output_x8=oracle.GUEST+0x2300)
        _write_span(pages, inputs['argument_x0'], bytes(128))
        _write_span(pages, inputs['argument_x0'], (image+0x35DC50).to_bytes(8, 'little'))
        initial = {k: bytearray(v) for k, v in pages.items()}
        old_base = vm_module.B
        staged, frame, vm, ledger, decoded = legacy.execute_prefix(
            pages, inputs, vm_module, 23, 456)
        assert vm.steps == 599 and vm.pc-image == 0xF8078
        assert len(decoded) == 3 and pages == initial and vm_module.B == old_base
        prefixes.append(dict(image_base=hex(image), vm_steps=vm.steps,
            bytecode_offset=hex(vm.pc-image), decoded_constants=len(decoded),
            caller_pages_unchanged=True, module_base_restored=True))
        args = dict(image_base=image, thread_pointer=inputs['thread_pointer'],
            return_address=inputs['return_address'], vm_module=vm_module,
            seconds=23, nanoseconds=456,
            entry_stack_address=inputs['entry_stack_address'],
            url_reference_address=inputs['argument_x0'],
            header_reference_address=inputs['argument_x1'], mode=0x138,
            context_address=inputs['argument_x3'],
            output_reference_address=inputs['output_x8'],
            allocate=lambda p, n: 0, free=lambda p, a: None,
            diagnostic_scope={})
        cases = [('wrong_callback', {'target': image+0x284F98}),
            ('bool_target', {'target': True}),
            ('missing_diagnostics', {'diagnostic_scope': None}),
            ('missing_allocator', {'allocate': None}),
            ('missing_free', {'free': None}),
            ('bool_mode', {'mode': True}),
            ('overflow_mode', {'mode': 1 << 64}),
            ('unaligned_stack', {'entry_stack_address': inputs['entry_stack_address']+1}),
            ('unmapped_output', {'output_reference_address': 0x1000}),
            ('allocation_service_failure', {}),
            ('failure_with_prior_completion', {'diagnostic_scope': {'request_vm_return': {
                'caller_sentinel_matches': True,
                'request_transaction_committed_to_supplied_pages': True}}})]
        for label, changes in cases:
            kw = dict(args, target=image+0x2830C4)
            kw.update(changes)
            try:
                owner.invoke_request_vm_callback(pages, **kw)
            except (RefillUnsupported, owner.RequestContinuationBoundary):
                pass
            else:
                raise AssertionError('entry accepted '+label)
            assert pages == initial and vm_module.B == old_base, label
            guards.append(dict(image_base=hex(image), case=label,
                rejected=True, page_rollback=True, module_base_restored=True))
        bad = {k: v for k, v in args.items() if k != 'context_address'}
        try:
            owner.invoke_java_request_service(pages, image+0x284F98,
                receiver_address=inputs['argument_x3'], thread_id=137, **bad)
        except RefillUnsupported:
            pass
        else:
            raise AssertionError('handler virtual+20 accepted as child dispatch')
        assert pages == initial and vm_module.B == old_base
        guards.append(dict(image_base=hex(image), case='wrong_facade_target',
            rejected=True, page_rollback=True, module_base_restored=True))
    return dict(native_Python_controls=0, rollback_guards=len(guards),
        Python_prefix_controls=len(prefixes), cases=prefixes, guards=guards,
        legacy_function_and_exception_identity_preserved=True,
        production_imports_oracle_or_unicorn=False, native_groups_replayed=False,
        whole_request_native_differential_verified=False,
        complete_signer_verified=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = verify(args.library)
    if args.output:
        args.output.write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8', newline='\n')
    print(json.dumps({k: v for k, v in result.items() if k not in ('cases', 'guards')}))


if __name__ == '__main__':
    main()
