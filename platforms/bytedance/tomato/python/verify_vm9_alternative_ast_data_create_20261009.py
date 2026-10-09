"""Fresh actual B AST slot 140 data creation and append controls.

Synthetic inputs are built independently of native snapshots. The original
vtable dispatch, constructors, append/move and cleanup execute naturally.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import random

import verify_vm9_alternative_ast_data_20261009 as data_controls
import verify_vm9_signer_objects as oracle
import vm9_alternative_startup as alternative
from vm9_allocator import RefillUnsupported, _read_span

FUNCTIONS = {0x140:0x31E1D4, 0x160:0x31E5B4}
CB, AST, OLD, INPUT, HEAP = (data_controls.CB,data_controls.AST,
    data_controls.OLD,data_controls.INPUT,data_controls.HEAP)
put, vector = data_controls.put,data_controls.vector
SEED = 0x31E1D4


def red_fixtures():
    return [
        dict(label='create_empty', callbacks=[(0x140,(99,2,3))]),
        dict(label='create_spare', data_vector=(1,3), owned_mode='rich',
             callbacks=[(0x140,(99,2,3))]),
        dict(label='create_full_rich', data_vector=(2,2), owned_mode='rich',
             callbacks=[(0x140,(99,2,3))]),
    ]


def fixtures():
    cases = red_fixtures()
    for flags in range(8):
        for memory_index in (0,7,0xFFFFFFFF,0x100000001):
            cases.append(dict(label=f'create_flags_{flags}_memory_{memory_index}',
                callbacks=[(0x140,(0xFFFFFFFFFFFFFFFF,memory_index,flags))],destroy_data=True))
    for flags in (0x100000003,0xFFFFFFFF00000002,0xFFFFFFFFFFFFFFFF):
        cases.append(dict(label=f'create_flags_u32_{flags}',
            callbacks=[(0x140,(0,0xFFFFFFFFFFFFFFFF,flags))]))
    for size,capacity in ((0,1),(0,4),(1,1),(1,3),(3,3),(3,4)):
        for mode in ('null','empty','rich','mixed'):
            cases.append(dict(label=f'create_{size}_{capacity}_{mode}',
                data_vector=(size,capacity),owned_mode=mode,
                callbacks=[(0x140,(12,9,3))],destroy_data=True))
    cases.append(dict(label='create_nonnull_zero_capacity',nonnull_empty=True,
        callbacks=[(0x140,(0,0,0))],destroy_data=True))
    cases.append(dict(label='repeated_create',callbacks=[(0x140,(i,i+3,i)) for i in range(6)],
        destroy_data=True))
    cases.append(dict(label='reserve_create_reserve_create',data_vector=(1,1),owned_mode='rich',
        callbacks=[(0x160,(3,)),(0x140,(11,2,0)),(0x140,(12,4,1)),
                   (0x140,(13,6,3)),(0x160,(7,)),(0x140,(14,8,2))],destroy_data=True))
    cases.append(dict(label='create_retained_during_callback_cleanup',
        data_vector=(2,2),owned_mode='mixed',callbacks=[(0x140,(0,7,3))],
        cleanup=True,cleanup_count=1,tree_depth=1,type_vector=(1,2),
        start_vector=(1,3),raw_vector=(3,8),rich=True))
    rng = random.Random(SEED)
    for index in range(8):
        capacity = rng.randrange(1,5); size = rng.randrange(capacity+1)
        cases.append(dict(label=f'generated_create_{index}',data_vector=(size,capacity),
            owned_mode=rng.choice(('empty','rich','mixed')),child_count=rng.randrange(4),
            callbacks=[(0x140,(rng.getrandbits(64),rng.getrandbits(64),rng.getrandbits(64)))],
            destroy_data=True))
    return cases


def assert_created_records(pages, base, spec):
    def u(address, size=8): return int.from_bytes(_read_span(pages,address,size),'little')
    begin,end,cap = (u(AST+offset) for offset in (0xF0,0xF8,0x100))
    initial = spec.get('data_vector',(0,0))[0]
    creates = [argv for slot,argv in spec['callbacks'] if slot == 0x140]
    assert (end-begin)//176 == initial+len(creates)
    assert begin <= end <= cap
    for index,(_,memory_index,flags) in enumerate(creates,initial):
        address = begin+index*176
        # This expectation is independent of the model and native snapshots.
        low = (0,1,0,2)[flags&3]
        assert u(address+0x18) == low | ((memory_index&0xFFFFFFFF)<<32)
        assert u(address+0x20) == base+0x3724F0
        assert u(address+0x28,4) == u(address+0x60) == u(address+0x68,4) == u(address+0x90,4) == 0
        assert u(address+0x88) == 0xFFFFFFFF
        for offset in (0,0x30,0x70,0x98): assert _read_span(pages,address+offset,24) == bytes(24)
        result = u(address+0x48)
        assert result and u(result) == 0xFFFFFFFFFFFFFFFF
        assert u(address+0x50) == result+(0 if spec.get('destroy_data') else 8)
        assert u(address+0x58) == result+8


def negatives(args):
    base = 0x122C0000; cases = []; records = []
    def u(p,a): return int.from_bytes(_read_span(p,a,8),'little')
    def record(p): return u(p,AST+0xF0)
    def add(label,changes=None,setup=None,spec=None):
        cases.append((label,changes or {},setup,spec or dict(label='guard',
            data_vector=(2,2),owned_mode='rich')))
    add('slot_140_binding',setup=lambda p:put(p,base+0x372370+0x140,base+0x31E18C))
    add('create_type_GOT_binding',setup=lambda p:put(p,base+0x375090,base+0x3724F0))
    add('create_type_GOT_missing_page',setup=lambda p:p.pop((base+0x375090)>>12))
    add('create_attached_callback',setup=lambda p:put(p,CB+8,INPUT))
    add('create_unknown_record_type',setup=lambda p:put(p,record(p)+0x20,base+0x372518))
    add('create_shared_child',setup=lambda p:vector(p,record(p)+0x30,u(p,record(p)+0x48),1,3,8))
    add('create_partial_record',setup=lambda p:put(p,AST+0xF8,record(p)+1))
    add('create_node_budget',changes=dict(max_nodes=6))
    add('create_size_budget',changes=dict(max_nodes=2),spec=dict(label='guard',data_vector=(2,3)))
    add('create_growth_capacity_budget',changes=dict(max_nodes=3),spec=dict(label='guard',data_vector=(2,2)))
    add('create_growth_byte_budget',changes=dict(max_vector_bytes=703))
    add('create_sentinel_byte_budget',changes=dict(max_vector_bytes=7),spec=dict(label='guard'))
    add('create_missing_allocator',changes=dict(allocate=None))
    add('create_argument_count',changes=dict(arguments=(0,1)))
    add('create_argument_negative',changes=dict(arguments=(0,1,-1)))
    add('create_argument_overflow',changes=dict(arguments=(1<<64,1,0)))
    add('create_unmapped_nonnull_zero_capacity',setup=lambda p:vector(p,AST+0xF0,0x90000000),
        spec=dict(label='guard'))
    for label,changes,setup,spec in cases:
        pages,_ = data_controls.prepare(args.library,base,spec)
        if setup: setup(pages)
        offset = 0
        def plan(size):
            nonlocal offset
            pointer = HEAP+offset; offset += (size+15)&~15; return pointer
        params = dict(callback_address=CB,image_base=base,slot_offset=0x140,
            arguments=(9,3,3),allocate=plan)
        params.update(changes)
        before = {key:bytes(value) for key,value in pages.items()}
        try: alternative.run_reader_ast_callback(pages,**params)
        except (RefillUnsupported,ValueError): pass
        else: raise AssertionError('data create guard accepted: '+label)
        assert before == {key:bytes(value) for key,value in pages.items()},label
        records.append(dict(label=label,rejected=True,all_pages_unchanged=True,
            native_invalid_memory_path_compared=False))
    # Fail each allocation boundary, including E after the D allocation.
    # Existing pages and all temporary sentinel writes must roll back together.
    for mode,spec,count in (('growth',dict(label='guard',data_vector=(2,2),owned_mode='rich'),5),
                            ('spare',dict(label='guard',data_vector=(1,3),owned_mode='rich'),4)):
        for fail_at in range(1,count+1):
            for target in ('unmapped','unaligned','partial','callback','output','record','child',
                           'retained','image','duplicate'):
                if target == 'duplicate' and fail_at == 1: continue
                pages,_ = data_controls.prepare(args.library,base,spec)
                if target == 'partial':
                    partial = oracle.GUEST+0xAFF8
                    if fail_at == 4 and mode == 'growth':
                        pages.pop((oracle.GUEST+0xB000)>>12,None)
                    else:
                        pages[partial>>12] = pages[partial>>12][:4092]
                before = {key:bytes(value) for key,value in pages.items()}
                planned = []; offset = 0
                def allocate(size):
                    nonlocal offset
                    pointer = HEAP+offset; offset += (size+15)&~15
                    if len(planned)+1 == fail_at:
                        pointer = {'unmapped':0x90000000,'unaligned':HEAP+1,'partial':partial if target=='partial' else 0,
                            'callback':CB,'output':AST,'record':record(pages),
                            'child':u(pages,record(pages)+0x98),'retained':INPUT,
                            'image':base+0x375090,'duplicate':planned[0] if planned else 0}.get(target)
                    planned.append(pointer); return pointer
                try:
                    alternative.run_reader_ast_callback(pages,callback_address=CB,image_base=base,
                        slot_offset=0x140,arguments=(0,2,3),allocate=allocate,
                        reserved_regions=((INPUT,INPUT+2048),))
                except (RefillUnsupported,ValueError): pass
                else: raise AssertionError(('allocation guard accepted',mode,fail_at,target))
                assert len(planned) == fail_at,(mode,fail_at,target,len(planned))
                assert before == {key:bytes(value) for key,value in pages.items()},(mode,fail_at,target)
                records.append(dict(label=f'create_{mode}_allocation_{fail_at}_{target}',
                    rejected=True,all_pages_unchanged=True,allocation_plans_before_rejection=len(planned),
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
            row = data_controls.compare(args,base,spec,functions=FUNCTIONS)
            pages,_,_ = data_controls.model_case(args,base,spec)
            assert_created_records(pages,base,spec)
            row['independent_created_record_expectation_match'] = True
            records.append(row)
            if index%24 == 0: print('B data create:',hex(base),index,'/',len(specs),'passed',flush=True)
    evidence = dict(schema='vm9-alternative-ast-data-create-fresh-v1',evidence_date='2026-10-09',
        evidence_timezone='Asia/Shanghai',sample_sha256=oracle.LIBRARY_SHA256,generated_fixture_seed=SEED,
        native_Python_AST_data_create_controls=len(records),rollback_negative_controls=len(rejected),
        pre_change_behavior_RED_controls=1,recovered_callback_slot_hex='0x140',
        actual_native_vtable_offset_hex='0x372370',data_create_offset_hex='0x31e1d4',
        append_growth_offset_hex='0x320c24',record_copy_offset_hex='0x320d5c',
        type_copy_offset_hex='0x31eea4',move_offset_hex='0x320e78',
        record_destructor_offset_hex='0x2cc1ec',record_stride=176,child_record_stride=56,
        all_fixtures_synthetic=True,native_input_snapshot_used=False,private_payloads_published=False,
        data_record_creation_implemented=True,complete_AST_callbacks_implemented=False,
        attached_parser_implemented=False,complete_python_reader_implemented=False,
        independent_Python_factory_implemented=False,complete_python_medusa=False,
        complete_python_bootstrap_controls=0,fresh_signer_output_verified=False,live_server_matrix_verified=False,
        cases=records,negative_cases=rejected)
    args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    print('B data create:',len(records),'native/Python +',len(rejected),'rollback checks passed',flush=True)


if __name__ == '__main__': main()
