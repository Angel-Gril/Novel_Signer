"""Fresh actual B type/start/local-count/raw-word callbacks and cleanup controls.

Original callback and node vtables execute naturally. Only malloc/free and
memcpy/memset are explicit host services; no status callback substitutes AST.
Private ELF payloads and native memory snapshots are never exported.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import random
from functools import lru_cache

from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
import vm9_alternative_startup as alternative
from vm9_allocator import RefillUnsupported, _read_span, _write_span
from verify_vm9_alternative_blob_xor_20261008 import constructor_codec_byte

CB, AST = oracle.GUEST+0x1000, oracle.GUEST+0x1200
OLD, INPUT, HEAP = oracle.GUEST+0x2000, oracle.GUEST+0x6000, oracle.GUEST+0x7000
FUNCTIONS = {0x18: 0x31B6B0, 0x20: 0x31B6D0, 0xA0: 0x31D6D4,
             0xB0: 0x31D974, 0x168: 0x31E5D8}
NODES = {64: (0x3724F0, 0x321260), 48: (0x372518, 0x321368),
         40: (0x372540, 0x321368), 24: (0x372568, 0x321368)}
DRIVER = oracle.GUEST+0xF400


@lru_cache(maxsize=2)
def fresh_image(library,base):
    # Immutable fresh ELF inputs; each case gets independent mutable pages.
    return {key:bytes(value) for key,value in oracle.image_pages(library,base).items()}


def put(pages, address, value, size=8):
    _write_span(pages, address, value.to_bytes(size, 'little'))


def vector(pages, address, pointer=0, size=0, capacity=0, stride=1):
    for offset, value in zip((0, 8, 16), (pointer, pointer+size*stride if pointer else 0,
                                         pointer+capacity*stride if pointer else 0)):
        put(pages, address+offset, value)


def prepare(library, base, spec):
    pages=oracle.fresh_pages(); pages.update({key:bytearray(value) for key,value in fresh_image(library,base).items()})
    _write_span(pages, CB, bytes(0x108)); _write_span(pages, AST, bytes(0x120))
    put(pages, CB, base+0x372370); put(pages, CB+0x18, AST); put(pages, CB+0x20, AST+0x108)
    put(pages, CB+0x48, CB+0x50); put(pages, CB+0x60, CB+0x68)
    if 'type_payloads' in spec:
        for address,values in zip((INPUT,INPUT+0x80),spec['type_payloads']):
            _write_span(pages,address,b''.join(v.to_bytes(8,'little') for v in values))
    sizes={}; pointer=OLD
    def block(size):
        nonlocal pointer
        out=pointer; pointer+=(max(size, 1)+15)&~15; assert pointer<INPUT
        sizes[out]=size; return out
    def node(address, stride, rich=False):
        vtable=NODES[stride][0] if stride != 40 or not rich else 0x372590
        put(pages, address, base+vtable); put(pages, address+8, 0xD00D1234, 4)
        if stride==64 or (stride==40 and rich):
            offsets=(0x10, 0x28) if stride==64 else (0x10,)
            for index, offset in enumerate(offsets):
                count=index+1 if rich else 0
                child=block((count+1)*8) if rich else 0
                vector(pages, address+offset, child, count, count+1 if rich else 0, 8)
                if child: _write_span(pages, child, bytes([0xE1+index])*(count+1)*8)
    size, capacity=spec.get('type_vector', (0, 0))
    if capacity or spec.get('nonnull_empty'):
        begin=block(capacity*64); vector(pages, AST, begin, size, capacity, 64)
        for index in range(size): node(begin+index*64, 64, spec.get('rich', False))
    start_size, start_cap=spec.get('start_vector', (0, 0))
    if start_cap:
        begin=block(start_cap*4); vector(pages, AST+0xC0, begin, start_size, start_cap, 4)
    byte_size, byte_cap=spec.get('raw_vector', (0, 0))
    if byte_cap:
        begin=block(byte_cap); vector(pages, AST+0x108, begin, byte_size, byte_cap)
    if spec.get('cleanup'):
        for offset, stride in ((0x80,64),(0x98,48),(0xB0,40),(0xC8,24),(0xE0,40)):
            count=spec.get('cleanup_count', 2); begin=block((count+1)*stride)
            vector(pages, CB+offset, begin, count, count+1, stride)
            for index in range(count): node(begin+index*stride, stride, offset in (0x80,0xE0))
        def tree(depth):
            if depth==0: return 0
            address=block(64); left=tree(depth-1); right=tree(depth-1)
            put(pages,address,left); put(pages,address+8,right)
            child=block(24) if spec.get('tree_payload',True) else 0
            vector(pages,address+0x28,child,1 if child else 0,3 if child else 0,8)
            return address
        for offset in (0x50,0x68): put(pages,CB+offset,tree(spec.get('tree_depth',2)))
        if spec.get('buffer',True):
            begin=block(21); vector(pages,CB+0x30,begin,7,21)
    return pages,sizes


def steps(spec):
    result=[]
    for slot, arguments in spec.get('callbacks', []):
        result.append(('callback',slot,arguments))
    if spec.get('destroy_types'): result.append(('destroy_types',0,()))
    if spec.get('cleanup'): result.append(('cleanup',0,()))
    return result


def native_case(args, base, spec):
    pages,sizes=prepare(args.library,base,spec); effects=[]; statuses=[]; allocation_index=0
    _write_span(pages,DRIVER,bytes.fromhex('00023fd6ffffff17'))  # blr x16; b -4
    root,width,kind,started=AST,0x120,None,False
    def sequence(cpu):
        for operation,slot,arguments in steps(spec):
            if operation=='destroy_types':
                begin=int.from_bytes(cpu.mem_read(AST,8),'little')
                end=int.from_bytes(cpu.mem_read(AST+8,8),'little')
                for address in range(end-64,begin-1,-64): yield 'node',0,(address,)
            else: yield operation,slot,arguments
    iterator=None
    def advance(cpu):
        nonlocal root,width,kind,iterator
        if iterator is None: iterator=sequence(cpu)
        try:kind,slot,values=next(iterator)
        except StopIteration:
            cpu.reg_write(arm.UC_ARM64_REG_PC,oracle.STOP);return
        assert cpu.reg_read(arm.UC_ARM64_REG_SP)==oracle.GUEST+0xEF00,'native call did not restore SP'
        if kind=='callback':
            root,width=(CB,0x108) if slot==0xB0 else (AST,0x120)
            table=int.from_bytes(cpu.mem_read(CB,8),'little')
            target=int.from_bytes(cpu.mem_read(table+slot,8),'little')
            assert target==base+FUNCTIONS[slot];argv=[CB,*values]
        elif kind=='node':root,width=values[0],64;target=base+0x321260;argv=list(values)
        else:root,width=CB,0x108;target=base+0x31B458;argv=[CB]
        for index,value in enumerate(argv):cpu.reg_write(getattr(arm,'UC_ARM64_REG_X'+str(index)),value)
        cpu.reg_write(arm.UC_ARM64_REG_X16,target)
    def effect(cpu,event,address,size):
        effects.append((event,address,size,root,bytes(cpu.mem_read(root,width))))
    def malloc(cpu,size):
        nonlocal allocation_index
        pointer=HEAP+allocation_index;allocation_index+=(size+15)&~15
        assert 0<size and pointer+size<=oracle.GUEST+0xA000
        sizes[pointer]=size;effect(cpu,'allocate',pointer,size);return pointer
    def free(cpu):
        pointer=cpu.reg_read(arm.UC_ARM64_REG_X0)
        assert pointer in sizes,('unknown/double free',hex(pointer),spec['label'])
        effect(cpu,'free',pointer,sizes.pop(pointer));return 0
    def observe(cpu,address):
        nonlocal started
        if address==DRIVER and not started:
            started=True;advance(cpu)
        elif address==DRIVER+4:
            assert cpu.reg_read(arm.UC_ARM64_REG_SP)==oracle.GUEST+0xEF00
            if kind=='callback':
                status=cpu.reg_read(arm.UC_ARM64_REG_X0);assert status==0;statuses.append(status)
            advance(cpu)
        offset=address-base
        if offset in (0x321260,0x321308):
            effect(cpu,'destroy',cpu.reg_read(arm.UC_ARM64_REG_X0),64 if offset==0x321260 else 40)
        elif offset==0x321368:
            node=cpu.reg_read(arm.UC_ARM64_REG_X0)
            table=int.from_bytes(cpu.mem_read(node,8),'little')-base
            effect(cpu,'destroy',node,{0x372518:48,0x372540:40,0x372568:24}[table])
    _,memory,calls,ledger=oracle.native(args.library,base,DRIVER-base,[],pages,malloc_handler=malloc,
        host_imports={0x347FA0:free},instruction_observer=observe,instruction_limit=500000)
    assert not calls and not ledger
    _write_span(pages,oracle.GUEST,memory)
    return pages,effects,statuses


def model_case(args,base,spec):
    pages,_=prepare(args.library,base,spec); effects=[]; statuses=[]; allocation_index=0
    def allocate(size):
        nonlocal allocation_index
        pointer=HEAP+allocation_index; allocation_index+=(size+15)&~15; return pointer
    for operation,slot,arguments in steps(spec):
        if operation=='callback':
            result=alternative.run_reader_ast_callback(pages,callback_address=CB,image_base=base,
                slot_offset=slot,arguments=arguments,allocate=allocate)
            statuses.append(result.status); effects.extend(result.effects)
        elif operation=='destroy_types':
            begin=int.from_bytes(_read_span(pages,AST,8),'little')
            end=int.from_bytes(_read_span(pages,AST+8,8),'little')
            for address in range(end-64,begin-1,-64):
                effects.extend(alternative.destroy_reader_ast_type_node(pages,node_address=address,
                    image_base=base).effects)
        else:
            effects.extend(alternative.cleanup_reader_callback(pages,callback_address=CB,image_base=base).effects)
    return pages,[(e.kind,e.address,e.size,e.owner_address,e.owner_bytes) for e in effects],statuses


def compare(args,base,spec):
    native,ne,ns=native_case(args,base,spec); model,me,ms=model_case(args,base,spec)
    assert ms==ns,(spec['label'],'statuses')
    assert me==ne,(spec['label'],'allocation/destruction/free order or publication',
                  [(e[:4]) for e in me],[(e[:4]) for e in ne])
    nm,mm=(_read_span(p,oracle.GUEST,0xA000) for p in (native,model))
    if nm!=mm:
        first=next(i for i,(a,b) in enumerate(zip(nm,mm)) if a!=b)
        raise AssertionError((spec['label'],'guest memory',hex(oracle.GUEST+first),nm[first:first+24].hex(),mm[first:first+24].hex()))
    return dict(label=spec['label'],image_base_hex=hex(base),actual_native_vtables_executed=True,
        actual_status_callbacks_substituted=False,natural_native_return_verified=True,
        native_Python_guest_memory_match=True,allocation_destruction_free_order_match=True,
        owner_memory_at_every_effect_match=True,callback_count=len(ns),
        allocation_count=sum(e[0]=='allocate' for e in ne),destructor_count=sum(e[0]=='destroy' for e in ne),
        free_count=sum(e[0]=='free' for e in ne),actual_ELF_type_input=spec.get('actual',False),
        native_input_snapshot_used=False,native_stack_or_TLS_as_a_whole_compared=False)


def fixtures():
    cases=[]
    for capacity in (0,1,3,8):
        for size in sorted({0,capacity//2,capacity}):
            for count in sorted({0,capacity,max(0,capacity-1),capacity+2}):
                cases.append(dict(label=f'type_reserve_{size}_{capacity}_{count}',type_vector=(size,capacity),
                    rich=True,callbacks=[(0x18,(count,))],destroy_types=True))
    for capacity in (0,1,3):
        for size in sorted({0,capacity}):
            for params,results in ((0,0),(2,0),(0,3),(2,3)):
                cases.append(dict(label=f'type_append_{size}_{capacity}_{params}_{results}',
                    type_vector=(size,capacity),rich=True,callbacks=[(0x20,(0xFFFFFFFF,params,INPUT,results,INPUT+0x80))],destroy_types=True))
    for capacity in (0,1,3,8):
        for size in sorted({0,capacity//2,capacity}):
            for value in (0,1,0x80000000,0xFFFFFFFF,0x100000001):
                cases.append(dict(label=f'start_{size}_{capacity}_{value}',start_vector=(size,capacity),callbacks=[(0xA0,(value,))]))
    for size,capacity in ((0,0),(0,8),(3,8),(4,4),(7,8)):
        for value in (0,0xFFFFFFFF,0x100000005):
            cases.append(dict(label=f'raw_word_{size}_{capacity}_{value}',raw_vector=(size,capacity),callbacks=[(0x168,(value,))]))
    for value in (0,1,0xFFFFFFFF,0x100000003):
        cases.append(dict(label=f'local_group_count_{value}',callbacks=[(0xB0,(value,))]))
    cases.append(dict(label='nonnull_empty_type_reserve',nonnull_empty=True,callbacks=[(0x18,(2,))]))
    cases.append(dict(label='type_repeated_append_and_reserve',callbacks=[(0x18,(2,)),(0x20,(9,1,INPUT,2,INPUT+0x80)),
        (0x20,(7,0,0,0,0)),(0x20,(3,2,INPUT,1,INPUT+0x80)),(0x18,(6,))],destroy_types=True))
    for count in (0,1,2):
        for depth in (0,1,2):
            cases.append(dict(label=f'cleanup_{count}_{depth}',cleanup=True,cleanup_count=count,tree_depth=depth))
    cases.append(dict(label='cleanup_tree_without_payload_or_buffer',cleanup=True,tree_depth=3,tree_payload=False,buffer=False))
    rng=random.Random(0x31B6D0)
    for index in range(10):
        callbacks=[(0x20,(rng.randrange(1<<32),rng.randrange(4),INPUT,rng.randrange(4),INPUT+0x80)) for _ in range(rng.randrange(1,5))]
        cases.append(dict(label=f'generated_type_sequence_{index}',callbacks=callbacks,destroy_types=True))
    return cases


def actual_inputs(library):
    pages=oracle.fresh_pages(); base=0x122C0000; pages.update(oracle.image_pages(library,base))
    put(pages,oracle.GUEST+0x4032,constructor_codec_byte(library),1)
    alternative.decode_factory_blob_xor(pages,blob_address=base+0x387D20,blob_size=0x37FD0,
        codec_table_address=oracle.GUEST+0x4000,codec_table_count=3)
    blob=_read_span(pages,base+0x387D20,0x37FD0); cursor=8
    def unsigned():
        nonlocal cursor
        value=0
        for index in range(5):
            byte=blob[cursor];cursor+=1;value|=(byte&127)<<(index*7)
            if byte<128:return value
        raise AssertionError('actual fixture invalid u32')
    while cursor<len(blob):
        number=blob[cursor];cursor+=1;length=unsigned();end=cursor+length
        if number==1:break
        cursor=end
    assert number==1
    count=unsigned(); entries=[]
    def signed():
        nonlocal cursor
        value=0
        for index in range(5):
            byte=blob[cursor];cursor+=1;value|=(byte&127)<<(index*7)
            if byte<128:
                if byte&64:value|=-(1<<((index+1)*7))
                return value&((1<<64)-1)
        raise AssertionError('actual fixture invalid i32')
    for index in range(count):
        assert blob[cursor]==0x60;cursor+=1
        params=[signed() for _ in range(unsigned())];results=[signed() for _ in range(unsigned())]
        entries.append((params,results))
    assert cursor==end
    return [dict(label=f'actual_ELF_type_{index}',actual=True,type_payloads=(params,results),
        callbacks=[(0x18,(1,)),(0x20,(index,len(params),INPUT,len(results),INPUT+0x80))],destroy_types=True)
        for index,(params,results) in enumerate(entries)]


def negatives(args):
    records=[];base=0x122C0000
    standard=dict(label='guard',type_vector=(1,1),rich=True)
    cases=[]
    def add(label,changes=None,setup=None,spec=None,operation='callback'):
        cases.append((label,changes or {},setup,spec or standard,operation))
    add('unsupported_slot',dict(slot_offset=0x148))
    add('noninteger_slot',dict(slot_offset=[]))
    add('wrong_argument_count',dict(arguments=()))
    add('negative_register',dict(arguments=(-1,)))
    add('oversized_register',dict(arguments=(1<<64,)))
    add('unaligned_callback',dict(callback_address=CB+1))
    add('unmapped_callback',dict(callback_address=0x90000000))
    add('invalid_image',dict(image_base=base+1))
    add('zero_node_bound',dict(max_nodes=0))
    add('excessive_node_bound',dict(max_nodes=65537))
    add('zero_byte_bound',dict(max_vector_bytes=0))
    add('excessive_byte_bound',dict(max_vector_bytes=16*1024*1024+1))
    add('wrong_callback_vtable',setup=lambda p:put(p,CB,base+0x372518))
    add('wrong_callback_slot_binding',setup=lambda p:put(p,base+0x372370+0x18,base+0x31D974))
    add('wrong_raw_slot_binding',dict(slot_offset=0x168,arguments=(1,)),
        setup=lambda p:put(p,base+0x372370+0x168,base+0x31D974))
    add('attached_parser_state',setup=lambda p:put(p,CB+8,INPUT+8))
    add('unrecovered_output_container',setup=lambda p:vector(p,AST+24,INPUT,1,2,48))
    add('wrong_move_GOT',setup=lambda p:put(p,base+0x375090,base+0x372530))
    add('wrong_node_destructor',setup=lambda p:put(p,base+0x3724F0,base+0x321308))
    add('wrong_node_vtable',setup=lambda p:put(p,OLD,base+0x372518))
    add('reversed_type_end',setup=lambda p:put(p,AST+8,OLD-64))
    add('partial_type_element',setup=lambda p:put(p,AST+8,OLD+1))
    add('null_type_capacity',setup=lambda p:put(p,AST,0))
    add('unaligned_type_pointer',setup=lambda p:put(p,AST,OLD+1))
    add('type_storage_aliases_callback',setup=lambda p:vector(p,AST,CB,0,1,64))
    add('child_aliases_type_storage',setup=lambda p:vector(p,OLD+0x10,OLD,1,1,8))
    add('children_share_storage',setup=lambda p:vector(p,OLD+0x28,int.from_bytes(_read_span(p,OLD+0x10,8),'little'),1,1,8))
    add('missing_child_page',setup=lambda p:p.pop(OLD>>12))
    add('reserve_exceeds_node_bound',dict(arguments=(4097,)))
    add('reserve_exceeds_byte_bound',dict(max_vector_bytes=64))
    add('missing_allocator',dict(allocate=None))
    for label,pointer in (('null',0),('unaligned',HEAP+1),('overflow',(1<<64)-16),
                          ('callback',CB),('AST',AST),('old_nodes',OLD),
                          ('image_GOT',base+0x375090),('unmapped',0x90000000)):
        add('allocation_'+label,dict(allocate=lambda size,pointer=pointer:pointer))
    add('allocation_reserved_input',dict(allocate=lambda size:INPUT,reserved_regions=((INPUT,INPUT+64),)))
    add('invalid_reserved_region',dict(reserved_regions=((32,16),)))
    add('doubling_exceeds_node_bound',dict(slot_offset=0x20,arguments=(0,0,0,0,0),max_nodes=3),
        spec=dict(label='guard',type_vector=(3,3)))
    add('oversized_type_payload',dict(slot_offset=0x20,arguments=(0,1<<30,INPUT,0,0)))
    add('unmapped_type_payload',dict(slot_offset=0x20,arguments=(0,1,0x90000000,0,0)))
    add('allocation_aliases_type_input',dict(slot_offset=0x20,arguments=(0,2,INPUT,0,0),allocate=lambda size:INPUT))
    add('late_duplicate_allocation',dict(slot_offset=0x20,arguments=(0,2,INPUT,3,INPUT+0x80),allocate=lambda size:HEAP))
    add('wrong_raw_target',dict(slot_offset=0x168,arguments=(1,)),setup=lambda p:put(p,CB+0x20,AST))
    add('raw_word_budget',dict(slot_offset=0x168,arguments=(1,),max_vector_bytes=7),
        spec=dict(label='guard',raw_vector=(4,4)))
    add('cleanup_unknown_node',setup=lambda p:put(p,OLD,base+0x3725B8),
        spec=dict(label='guard',cleanup=True),operation='cleanup')
    def tree_cycle(p):
        root=int.from_bytes(_read_span(p,CB+0x68,8),'little');put(p,root,root)
    add('cleanup_tree_cycle',setup=tree_cycle,spec=dict(label='guard',cleanup=True),operation='cleanup')
    add('cleanup_shared_tree',setup=lambda p:put(p,CB+0x50,int.from_bytes(_read_span(p,CB+0x68,8),'little')),
        spec=dict(label='guard',cleanup=True),operation='cleanup')
    add('cleanup_node_budget',dict(max_nodes=3),spec=dict(label='guard',cleanup=True),operation='cleanup')
    add('cleanup_shared_list',setup=lambda p:vector(p,CB+0xB0,int.from_bytes(_read_span(p,CB+0xE0,8),'little'),0,1,40),
        spec=dict(label='guard',cleanup=True),operation='cleanup')
    add('type_node_unknown_vtable',setup=lambda p:put(p,OLD,base+0x372518),operation='node')
    for label,changes,setup,spec,operation in cases:
        pages,_=prepare(args.library,base,spec)
        if setup:setup(pages)
        before={key:bytes(value) for key,value in pages.items()}
        if operation=='callback':
            params=dict(callback_address=CB,image_base=base,slot_offset=0x18,arguments=(2,),allocate=lambda size:HEAP)
            params.update(changes);run=lambda:alternative.run_reader_ast_callback(pages,**params)
        elif operation=='cleanup':
            params=dict(callback_address=CB,image_base=base);params.update(changes)
            run=lambda:alternative.cleanup_reader_callback(pages,**params)
        else:
            run=lambda:alternative.destroy_reader_ast_type_node(pages,node_address=OLD,image_base=base)
        try:run()
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError('AST guard accepted: '+label)
        assert before=={key:bytes(value) for key,value in pages.items()},label
        records.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_invalid_memory_path_compared=False))
    return records


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--library',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path);args=parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    specs=fixtures()+actual_inputs(args.library);records=[]
    rejected=negatives(args)
    for base in (0x122C0000,0x775C205000):
        for index,spec in enumerate(specs,1):
            records.append(compare(args,base,spec))
            if index%32==0:print('B actual AST:',hex(base),index,'/',len(specs),'passed',flush=True)
    evidence=dict(schema='vm9-alternative-ast-fresh-v1',evidence_date='2026-10-09',evidence_timezone='Asia/Shanghai',
        sample_sha256=oracle.LIBRARY_SHA256,generated_fixture_seed=0x31B6D0,
        native_Python_AST_controls=len(records),rollback_negative_controls=len(rejected),
        actual_ELF_type_controls=sum(r['actual_ELF_type_input'] for r in records),
        recovered_callback_slots_hex=[hex(s) for s in FUNCTIONS],actual_native_vtable_offset_hex='0x372370',
        callback_cleanup_offset_hex='0x31b458',type_node_destructor_offset_hex='0x321260',
        pre_change_status_only_RED_controls=4,allocator_is_explicit_pure_plan=True,
        free_is_logical_no_poison_or_unmap=True,actual_AST_callbacks_executed=True,
        private_types_or_payloads_published=False,native_input_snapshot_used=False,
        complete_AST_callbacks_implemented=False,complete_python_reader_implemented=False,
        independent_Python_factory_implemented=False,complete_python_bootstrap_controls=0,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False,
        cases=records,negative_cases=rejected)
    args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    print('B actual AST:',len(records),'native/Python +',len(rejected),'rollback checks passed',flush=True)


if __name__=='__main__':main()
