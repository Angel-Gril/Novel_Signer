"""Fresh B AST slot 160 reserve/move and 176-byte record destructor controls.

The original vtable and +2cc1ec execute naturally. Fixtures are synthetic;
only immutable ELF inputs are cached, and no native input snapshots are used.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import random

from unicorn import arm64_const as arm
import verify_vm9_alternative_ast_20261009 as ast_controls
import verify_vm9_signer_objects as oracle
import vm9_alternative_startup as alternative
from vm9_allocator import RefillUnsupported, _read_span, _write_span

CB, AST, OLD, INPUT, HEAP = (ast_controls.CB, ast_controls.AST,
    ast_controls.OLD, ast_controls.INPUT, ast_controls.HEAP)
DRIVER = ast_controls.DRIVER
put, vector = ast_controls.put, ast_controls.vector


def prepare(library, base, spec):
    pages, sizes = ast_controls.prepare(library, base, spec)
    pointer = max([OLD]+[address+((max(size, 1)+15)&~15)
                            for address, size in sizes.items()])
    def block(size):
        nonlocal pointer
        result = pointer; pointer += (max(size, 1)+15)&~15
        assert pointer < INPUT
        sizes[result] = size
        return result
    def owned(header, stride, count, capacity, marker):
        begin = block(capacity*stride)
        vector(pages, header, begin, count, capacity, stride)
        _write_span(pages, begin, bytes([marker])*capacity*stride)
        return begin
    size, capacity = spec.get('data_vector', (0, 0))
    if capacity or spec.get('nonnull_empty'):
        begin = block(capacity*176)
        vector(pages, AST+0xF0, begin, size, capacity, 176)
        for index in range(size):
            address = begin+index*176
            # Distinct initial bytes catch whole-structure copies and padding writes.
            _write_span(pages, address, bytes([0x91+index])*176)
            for offset in (0, 0x30, 0x48, 0x70, 0x98): vector(pages, address+offset)
            put(pages, address+0x20, base+0x3724F0)
            for offset in (0x18, 0x60, 0x88): put(pages, address+offset, 0xABC00000+index+offset)
            for offset in (0x28, 0x68, 0x90): put(pages, address+offset, 0xDE000000+index+offset, 4)
            mode = spec.get('owned_mode', 'null')
            if mode == 'null': continue
            empty = mode == 'empty'
            for offset, stride, count, cap, marker in ((0,1,9,13,0xD1),
                    (0x30,8,1,2,0xD2),(0x48,8,2,3,0xD3),(0x70,16,2,3,0xD4)):
                owned(address+offset, stride, 0 if empty else count, cap, marker)
            child_count = spec.get('child_count', 2)
            children = owned(address+0x98, 56, child_count, child_count+1, 0xD5)
            for child_index in range(child_count):
                child = children+child_index*56
                put(pages, child, 0x10203040+child_index)
                put(pages, child+8, 0x50607080+child_index, 4)
                put(pages, child+0x28, 0x8090A0B0+child_index)
                put(pages, child+0x30, 0xC0D0E0F0+child_index, 4)
                vector(pages, child+0x10)
                if mode != 'mixed' or child_index%2:
                    owned(child+0x10, 8, 0 if empty else child_index+1, child_index+2, 0xE0+child_index)
    return pages, sizes


def native_case(args, base, spec, *, functions=None, prepare_case=None):
    functions = {0x160:0x31E5B4} if functions is None else functions
    pages, sizes = (prepare_case or prepare)(args.library, base, spec)
    effects, statuses = [], []; allocation_index = 0
    _write_span(pages, DRIVER, bytes.fromhex('00023fd6ffffff17'))
    root, width, kind, started = AST, 0x120, None, False
    def sequence(cpu):
        for slot, arguments in spec.get('callbacks', []): yield 'callback', slot, arguments
        if spec.get('destroy_function'):
            begin = int.from_bytes(cpu.mem_read(AST+0x30, 8), 'little')
            end = int.from_bytes(cpu.mem_read(AST+0x38, 8), 'little')
            for address in range(end-144, begin-1, -144): yield 'function', 0, (address,)
        if spec.get('destroy_data'):
            begin = int.from_bytes(cpu.mem_read(AST+0xF0, 8), 'little')
            end = int.from_bytes(cpu.mem_read(AST+0xF8, 8), 'little')
            for address in range(end-176, begin-1, -176): yield 'record', 0, (address,)
        if spec.get('destroy_element'):
            begin = int.from_bytes(cpu.mem_read(AST+0xD8, 8), 'little')
            end = int.from_bytes(cpu.mem_read(AST+0xE0, 8), 'little')
            for address in range(end-184, begin-1, -184): yield 'element', 0, (address,)
        if spec.get('cleanup'): yield 'cleanup', 0, ()
    iterator = None
    def advance(cpu):
        nonlocal root, width, kind, iterator
        if iterator is None: iterator = sequence(cpu)
        try: kind, slot, values = next(iterator)
        except StopIteration:
            cpu.reg_write(arm.UC_ARM64_REG_PC, oracle.STOP); return
        assert cpu.reg_read(arm.UC_ARM64_REG_SP) == oracle.GUEST+0xEF00
        if kind == 'callback':
            root, width = AST, 0x120
            table = int.from_bytes(cpu.mem_read(CB, 8), 'little')
            target = int.from_bytes(cpu.mem_read(table+slot, 8), 'little')
            assert target == base+functions[slot]
            argv = [CB, *values]
        elif kind == 'record':
            root, width = values[0], 176; target = base+0x2CC1EC; argv = list(values)
        elif kind == 'element':
            root, width = values[0], 184; target = base+0x2CC2B8; argv = list(values)
        elif kind == 'function':
            root, width = values[0], 144; target = base+0x2CC470; argv = [0, values[0]]
        else:
            root, width = CB, 0x108; target = base+0x31B458; argv = [CB]
        for index, value in enumerate(argv):
            cpu.reg_write(getattr(arm, 'UC_ARM64_REG_X'+str(index)), value)
        cpu.reg_write(arm.UC_ARM64_REG_X16, target)
    def effect(cpu, event, address, size):
        effects.append((event, address, size, root, bytes(cpu.mem_read(root, width))))
    def malloc(cpu, size):
        nonlocal allocation_index
        pointer = HEAP+allocation_index; allocation_index += (size+15)&~15
        assert 0 < size and pointer+size <= oracle.GUEST+0xA000
        sizes[pointer] = size; effect(cpu, 'allocate', pointer, size); return pointer
    def free(cpu):
        pointer = cpu.reg_read(arm.UC_ARM64_REG_X0)
        assert pointer in sizes, ('unknown/double free', hex(pointer), spec['label'])
        effect(cpu, 'free', pointer, sizes.pop(pointer)); return 0
    def observe(cpu, address):
        nonlocal started
        if address == DRIVER and not started:
            started = True; advance(cpu)
        elif address == DRIVER+4:
            assert cpu.reg_read(arm.UC_ARM64_REG_SP) == oracle.GUEST+0xEF00
            if kind == 'callback':
                status = cpu.reg_read(arm.UC_ARM64_REG_X0)
                expected = spec.get('callback_statuses')
                assert status == (expected[len(statuses)] if expected is not None else 0)
                statuses.append(status)
            advance(cpu)
        offset = address-base
        if offset == 0x2CC1EC:
            effect(cpu, 'destroy', cpu.reg_read(arm.UC_ARM64_REG_X0), 176)
        elif offset in (0x2CC2B8, 0x2CC470):
            # 108 also calls the stack temporary's real destructor. Its frees
            # remain observed; stack-local destruction is outside guest ownership.
            node = cpu.reg_read(arm.UC_ARM64_REG_X0 if offset == 0x2CC2B8 else arm.UC_ARM64_REG_X1)
            if oracle.GUEST <= node < oracle.GUEST+0xA000:
                effect(cpu, 'destroy', node, 184 if offset == 0x2CC2B8 else 144)
        elif offset in (0x321260, 0x321308, 0x321368):
            node = cpu.reg_read(arm.UC_ARM64_REG_X0)
            table = int.from_bytes(cpu.mem_read(node, 8), 'little')-base
            effect(cpu, 'destroy', node, {0x3724F0:64,0x372518:48,0x372540:40,0x372568:24,0x372590:40}[table])
    _, memory, calls, ledger = oracle.native(args.library, base, DRIVER-base, [], pages,
        malloc_handler=malloc, host_imports={0x347FA0:free}, instruction_observer=observe,
        instruction_limit=500000)
    assert not calls and not ledger
    _write_span(pages, oracle.GUEST, memory)
    return pages, effects, statuses


def model_case(args, base, spec, *, prepare_case=None):
    pages, _ = (prepare_case or prepare)(args.library, base, spec)
    effects, statuses = [], []; allocation_index = 0
    def allocate(size):
        nonlocal allocation_index
        pointer = HEAP+allocation_index; allocation_index += (size+15)&~15; return pointer
    for slot, arguments in spec.get('callbacks', []):
        result = alternative.run_reader_ast_callback(pages, callback_address=CB,
            image_base=base, slot_offset=slot, arguments=arguments, allocate=allocate,
            **({'entry_stack_address':spec['entry_stack_address']} if 'entry_stack_address' in spec else {}))
        effects.extend(result.effects); statuses.append(result.status)
    if spec.get('destroy_function'):
        begin = int.from_bytes(_read_span(pages, AST+0x30, 8), 'little')
        end = int.from_bytes(_read_span(pages, AST+0x38, 8), 'little')
        assert callable(getattr(alternative, 'destroy_reader_ast_function_record', None)), '144-byte function destructor missing'
        for address in range(end-144, begin-1, -144):
            effects.extend(alternative.destroy_reader_ast_function_record(pages, record_address=address,
                image_base=base).effects)
    if spec.get('destroy_data'):
        begin = int.from_bytes(_read_span(pages, AST+0xF0, 8), 'little')
        end = int.from_bytes(_read_span(pages, AST+0xF8, 8), 'little')
        assert callable(getattr(alternative, 'destroy_reader_ast_data_record', None)), '176-byte destructor missing'
        for address in range(end-176, begin-1, -176):
            effects.extend(alternative.destroy_reader_ast_data_record(pages, record_address=address,
                image_base=base).effects)
    if spec.get('destroy_element'):
        begin = int.from_bytes(_read_span(pages, AST+0xD8, 8), 'little')
        end = int.from_bytes(_read_span(pages, AST+0xE0, 8), 'little')
        assert callable(getattr(alternative, 'destroy_reader_ast_element_record', None)), '184-byte destructor missing'
        for address in range(end-184, begin-1, -184):
            effects.extend(alternative.destroy_reader_ast_element_record(pages, record_address=address,
                image_base=base).effects)
    if spec.get('cleanup'):
        effects.extend(alternative.cleanup_reader_callback(pages, callback_address=CB, image_base=base).effects)
    return pages, [(e.kind,e.address,e.size,e.owner_address,e.owner_bytes) for e in effects], statuses


def compare(args, base, spec, *, functions=None, prepare_case=None):
    native, ne, ns = native_case(args, base, spec, functions=functions, prepare_case=prepare_case)
    model, me, ms = model_case(args, base, spec, prepare_case=prepare_case)
    assert ms == ns, (spec['label'], 'statuses')
    assert me == ne, (spec['label'], 'effects and owner state', [e[:4] for e in me], [e[:4] for e in ne])
    nm, mm = (_read_span(p, oracle.GUEST, 0xA000) for p in (native, model))
    if nm != mm:
        first = next(i for i,(a,b) in enumerate(zip(nm,mm)) if a != b)
        raise AssertionError((spec['label'], 'guest memory', hex(oracle.GUEST+first),
            nm[first:first+24].hex(), mm[first:first+24].hex()))
    return dict(label=spec['label'], image_base_hex=hex(base),
        actual_native_vtable_executed=bool(ns), natural_native_return_verified=True,
        native_Python_guest_memory_match=True, allocation_destruction_free_order_match=True,
        owner_memory_at_every_effect_match=True, callback_count=len(ns),
        allocation_count=sum(e[0]=='allocate' for e in ne),
        destructor_count=sum(e[0]=='destroy' for e in ne), free_count=sum(e[0]=='free' for e in ne),
        synthetic_fixture=True, native_input_snapshot_used=False)


def fixtures():
    cases = [dict(label='empty_data_reserve', callbacks=[(0x160,(2,))])]
    for capacity in (1,3,8):
        for size in sorted({0,capacity//2,capacity}):
            for count in sorted({0,capacity-1,capacity,capacity+2}):
                for mode in ('null','rich'):
                    cases.append(dict(label=f'data_reserve_{size}_{capacity}_{count}_{mode}',
                        data_vector=(size,capacity), owned_mode=mode,
                        callbacks=[(0x160,(count,))], destroy_data=True))
    for mode in ('null','empty','rich','mixed'):
        for count in (0,1,3):
            cases.append(dict(label=f'data_destructor_{mode}_{count}', data_vector=(2,3),
                owned_mode=mode, child_count=count, destroy_data=True))
    for count in (0,1,0x100000002,0xFFFFFFFF00000003):
        cases.append(dict(label=f'data_count_u32_{count}', callbacks=[(0x160,(count,))]))
    cases.append(dict(label='nonnull_zero_capacity', nonnull_empty=True, callbacks=[(0x160,(2,))]))
    cases.append(dict(label='repeated_data_reserve', data_vector=(2,2), owned_mode='rich',
        callbacks=[(0x160,(3,)),(0x160,(1,)),(0x160,(6,)),(0x160,(6,)),(0x160,(9,))], destroy_data=True))
    cases.append(dict(label='retained_data_during_callback_cleanup', data_vector=(2,3), owned_mode='rich',
        callbacks=[(0x160,(5,))], cleanup=True, cleanup_count=1, tree_depth=1,
        type_vector=(1,2), start_vector=(1,3), raw_vector=(3,8), rich=True))
    rng = random.Random(0x320FB0)
    for index in range(8):
        capacity = rng.randrange(1,5); size = rng.randrange(capacity+1)
        cases.append(dict(label=f'generated_data_reserve_{index}', data_vector=(size,capacity),
            owned_mode=rng.choice(('empty','rich','mixed')), child_count=rng.randrange(4),
            callbacks=[(0x160,(capacity+rng.randrange(1,4),))], destroy_data=True))
    return cases


def negatives(args):
    base = 0x122C0000; cases = []; records = []
    def u(p, a): return int.from_bytes(_read_span(p,a,8),'little')
    def record(p): return u(p, AST+0xF0)
    def child(p): return u(p, record(p)+0x98)
    def add(label, changes=None, setup=None, operation='callback', spec=None):
        cases.append((label,changes or {},setup,operation,spec or dict(label='guard',data_vector=(2,2),owned_mode='rich')))
    add('slot_160_binding', setup=lambda p:put(p,base+0x372370+0x160,base+0x31D974))
    add('data_partial_record', setup=lambda p:put(p,AST+0xF8,record(p)+1))
    add('data_partial_capacity', setup=lambda p:put(p,AST+0x100,record(p)+353))
    add('data_reversed_end', setup=lambda p:put(p,AST+0xF8,record(p)-176))
    add('data_null_begin', setup=lambda p:put(p,AST+0xF0,0))
    add('data_alias_callback', setup=lambda p:vector(p,AST+0xF0,CB,0,1,176))
    add('data_alias_other_output', setup=lambda p:vector(p,AST,u(p,AST+0xF0),0,1,64))
    add('data_unknown_type', setup=lambda p:put(p,record(p)+0x20,base+0x372518))
    add('data_type_destructor_binding', setup=lambda p:put(p,base+0x3724F0,base+0x321308))
    add('data_child_partial_vector', setup=lambda p:put(p,record(p)+0xA0,child(p)+1))
    add('data_child_partial_payload', setup=lambda p:put(p,child(p)+0x18,u(p,child(p)+0x10)+1))
    add('data_child_alias_parent', setup=lambda p:vector(p,child(p)+0x10,record(p),1,2,8))
    add('data_child_alias_sibling', setup=lambda p:vector(p,child(p)+56+0x10,u(p,child(p)+0x10),1,2,8))
    add('data_child_alias_params', setup=lambda p:vector(p,child(p)+0x10,u(p,record(p)+0x30),1,2,8))
    add('data_child_alias_image', setup=lambda p:vector(p,child(p)+0x10,base+0x375090,1,2,8))
    add('data_unmapped_child', setup=lambda p:vector(p,child(p)+0x10,0x90000000,1,2,8))
    add('data_unaligned_child', setup=lambda p:put(p,child(p)+0x10,u(p,child(p)+0x10)+1))
    add('data_child_budget', dict(max_nodes=2))
    add('data_reserve_budget', dict(arguments=(4097,)))
    add('data_reserve_byte_budget', dict(max_vector_bytes=527))
    add('data_allocate_parent', dict(allocate=lambda size:OLD))
    add('data_allocate_child', setup=None, changes=dict(allocate=lambda size:OLD+352))
    add('data_allocate_retained', dict(allocate=lambda size:INPUT,reserved_regions=((INPUT,INPUT+2048),)))
    add('data_allocate_unmapped', dict(allocate=lambda size:0x90000000))
    add('data_missing_allocator', dict(allocate=None))
    add('data_unmapped_nonnull_zero_capacity', setup=lambda p:vector(p,AST+0xF0,0x90000000,0,0,176),
        spec=dict(label='guard'))
    add('data_destructor_unknown_type', setup=lambda p:put(p,record(p)+0x20,base+0x372518), operation='record')
    add('data_destructor_child_budget', dict(max_nodes=1), operation='record')
    add('data_destructor_shared_payload', setup=lambda p:vector(p,child(p)+0x10,u(p,record(p)),1,2,8), operation='record')
    add('data_retained_cleanup_alias', setup=lambda p:vector(p,CB+0x30,u(p,record(p)),1,13), operation='cleanup')
    for label, changes, setup, operation, spec in cases:
        pages, _ = prepare(args.library,base,spec)
        if setup: setup(pages)
        before = {key:bytes(value) for key,value in pages.items()}
        if operation == 'callback':
            params = dict(callback_address=CB,image_base=base,slot_offset=0x160,
                arguments=(3,),allocate=lambda size:HEAP)
            params.update(changes); run = lambda:alternative.run_reader_ast_callback(pages,**params)
        elif operation == 'record':
            params = dict(record_address=record(pages),image_base=base);params.update(changes)
            run = lambda:alternative.destroy_reader_ast_data_record(pages,**params)
        else:
            run = lambda:alternative.cleanup_reader_callback(pages,callback_address=CB,image_base=base)
        try: run()
        except (RefillUnsupported,ValueError): pass
        else: raise AssertionError('data AST guard accepted: '+label)
        assert before == {key:bytes(value) for key,value in pages.items()},label
        records.append(dict(label=label,rejected=True,all_pages_unchanged=True,
            native_invalid_memory_path_compared=False))
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == oracle.LIBRARY_SHA256
    records = []; specs = fixtures(); rejected = negatives(args)
    for base in (0x122C0000,0x775C205000):
        for index,spec in enumerate(specs,1):
            records.append(compare(args,base,spec))
            if index%32 == 0: print('B data AST:',hex(base),index,'/',len(specs),'passed',flush=True)
    evidence = dict(schema='vm9-alternative-ast-data-fresh-v1',evidence_date='2026-10-09',
        evidence_timezone='Asia/Shanghai',sample_sha256=oracle.LIBRARY_SHA256,generated_fixture_seed=0x320FB0,
        native_Python_AST_data_controls=len(records),rollback_negative_controls=len(rejected),
        recovered_callback_slot_hex='0x160',actual_native_vtable_offset_hex='0x372370',
        reserve_offset_hex='0x320fb0',move_offset_hex='0x320e78',
        record_destructor_offset_hex='0x2cc1ec',record_stride=176,child_record_stride=56,
        pre_change_behavior_RED_controls=2,pre_change_guard_RED_controls=1,allocator_is_explicit_pure_plan=True,
        free_is_logical_no_poison_or_unmap=True,all_fixtures_synthetic=True,
        native_input_snapshot_used=False,private_payloads_published=False,
        data_record_creation_implemented=False,complete_AST_callbacks_implemented=False,
        attached_parser_implemented=False,complete_python_reader_implemented=False,
        independent_Python_factory_implemented=False,complete_python_bootstrap_controls=0,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False,
        cases=records,negative_cases=rejected)
    args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    print('B data AST:',len(records),'native/Python +',len(rejected),'rollback checks passed',flush=True)


if __name__ == '__main__': main()
