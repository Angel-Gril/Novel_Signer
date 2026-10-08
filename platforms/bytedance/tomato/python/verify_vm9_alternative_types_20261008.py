"""Fresh B word-vector and section-1 controls against original native code.

Allocation pointers and status callbacks are explicit services. The original
grow/core/type code runs naturally; actual allocator/AST callbacks stay open.
Actual ELF inputs are independently XORed in Python, without native snapshots.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import random

from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as arm

import verify_vm9_signer_objects as oracle
import vm9_alternative_startup as alternative
import verify_vm9_alternative_sections_20261008 as sections
from verify_vm9_alternative_varuint32_20261008 import encode as u32
from verify_vm9_alternative_varint32_20261008 import encode as i32
from verify_vm9_alternative_blob_xor_20261008 import constructor_codec_byte
from vm9_allocator import RefillUnsupported, _read_span, _write_span

STATE, DATA, OBJECT = sections.STATE, sections.DATA, sections.OBJECT
VTABLE, SCRATCH, CALLBACK = sections.VTABLE, sections.SCRATCH, sections.CALLBACK
OLD_PARAMS, OLD_RESULTS = oracle.GUEST+0x6000, oracle.GUEST+0x6400
HEAP = oracle.GUEST+0x7000
SLOTS = {0x18: 1, 0x20: 5, **sections.SLOTS}


def word_vector(pages, address, begin, size, capacity):
    sections.put(pages, address, begin)
    sections.put(pages, address+8, begin+size*8 if begin else 0)
    sections.put(pages, address+16, begin+capacity*8 if begin else 0)


def words(read, address):
    return tuple(int.from_bytes(read(address+offset, 8), 'little') for offset in (0, 8, 16))


def effect_tuple(effect):
    return (effect.kind, effect.address, effect.size, effect.vector_address, effect.vector_words)


def services():
    """Independent deterministic address plan, with allocation before pointer publication.

    Host malloc/free do not initialize, poison or unmap storage. Explicit
    memset/memcpy PLT services and the Python grow own payload writes.
    """
    allocations, effects = [], []
    current = [STATE+0x28, 0]
    def observe(cpu, address, base):
        if address == base+0x324540:
            vector = cpu.reg_read(arm.UC_ARM64_REG_X0)
            begin, end, cap = words(cpu.mem_read, vector)
            current[:] = [vector, cap-begin]
    def allocate(size, cpu=None):
        pointer = HEAP+len(allocations)*0x200
        assert size <= 0x200 and pointer+size <= oracle.GUEST+0xA000
        allocations.append((size, pointer))
        if cpu is not None:
            effects.append(('allocate', pointer, size, current[0], words(cpu.mem_read, current[0])))
        return pointer
    def free(cpu):
        pointer = cpu.reg_read(arm.UC_ARM64_REG_X0)
        effects.append(('free', pointer, current[1], current[0], words(cpu.mem_read, current[0])))
        return 0
    return allocations, effects, observe, allocate, free


def vector_inputs():
    cases = []
    for capacity in [0, 1, 3, 8, 16]:
        for size in sorted({0, capacity//2, capacity}):
            for extra in sorted({0, 1, max(0, capacity-size), capacity-size+1, capacity+3}):
                cases.append(dict(label=f'vector_{capacity}_{size}_{extra}',
                                  capacity=capacity, size=size, extra=extra,
                                  null=capacity == 0))
    cases.append(dict(label='nonnull_empty_capacity', capacity=0, size=0, extra=1, null=False))
    cases.append(dict(label='nonnull_empty_noop', capacity=0, size=0, extra=0, null=False))
    return cases


def compare_vector(args, base, spec):
    pages = oracle.fresh_pages()
    vector = STATE+0x28
    word_vector(pages, vector, 0 if spec['null'] else OLD_PARAMS, spec['size'], spec['capacity'])
    model = {key: bytearray(value) for key, value in pages.items()}
    native_alloc, native_effects, observe, allocate, free = services()
    _, memory, calls, ledger = oracle.native(args.library, base, 0x324540,
        [vector, spec['extra']], pages, malloc_handler=lambda cpu, size: allocate(size, cpu),
        host_imports={0x347FA0: free}, instruction_observer=lambda cpu, addr: observe(cpu, addr, base),
        instruction_limit=2000)
    assert not calls and not ledger
    model_alloc, _, _, planned, _ = services()
    result = alternative.grow_reader_word_vector(model, vector_address=vector,
        additional_count=spec['extra'], allocate=planned)
    assert model_alloc == native_alloc, spec['label']
    assert [effect_tuple(e) for e in result.effects] == native_effects, spec['label']
    assert _read_span(model, oracle.GUEST, 0xA000) == memory, spec['label']
    return dict(label=spec['label'], image_base_hex=hex(base),
        natural_native_return_verified=True, incidental_void_X0_compared=False,
        guest_input_output_region_match=True, allocation_free_effects_and_publication_match=True,
        allocation_count=len(native_alloc), free_count=sum(e[0]=='free' for e in native_effects),
        native_input_snapshot_used=False)


def function_type(params=(), results=()):
    return b'\x60'+u32(len(params))+b''.join(i32(v) for v in params)+u32(len(results))+b''.join(i32(v) for v in results)


def type_inputs():
    cases = []
    def add(label, payload=b'\0', **options):
        cases.append(dict(label=label, blob=b'A'*8+sections.section(1, payload), **options))
    add('type_empty')
    add('type_empty_callback_failure', failure_slot=0x18)
    add('type_void', b'\1'+function_type())
    add('type_all_accepted_values', b'\1'+function_type([-1,-2,-3,-4,-5,-16,-17], [-17,-16,-5,-1]))
    add('type_count_callback_failure', b'\1'+function_type([-1],[-2]), failure_slot=0x18)
    add('type_entry_callback_failure', b'\1'+function_type([-1],[-2]), failure_slot=0x20, failure_call=1)
    payload=u32(5)+b''.join(function_type(p,r) for p,r in [
        ([-1]*3,[-2]*2), ([-3],[]), ([],[-4]), ([-16]*5,[-17]*4), ([-5],[-1])])
    add('type_grow_shrink_reuse', payload)
    add('type_preallocated_in_capacity', payload, params=(2,8), results=(1,8))
    add('type_preallocated_reallocate', payload, params=(1,2), results=(0,1))
    add('type_zero_shrinks_vectors', b'\1'+function_type(), params=(3,5), results=(2,4))
    add('type_count_too_large', b'\2\x60')
    add('type_count_truncated', b'\x80')
    add('type_missing_form', b'\1\0')
    add('type_invalid_form', b'\1\x61\0\0')
    add('type_missing_parameter_count', b'\1\x60')
    add('type_parameter_count_too_large', b'\1\x60\x05\x7f\0')
    add('type_parameter_truncated', b'\1\x60\x01\x80')
    add('type_missing_result_count', b'\1\x60\0')
    add('type_result_count_too_large', b'\1\x60\0\x05\x7f')
    add('type_result_truncated', b'\1\x60\0\x01\x80')
    add('type_result_invalid_after_parameter', b'\1'+function_type([-1,-2],[0]))
    add('type_second_entry_invalid', b'\2'+function_type([-1],[-2])+function_type([0],[]))
    add('type_trailing_byte', b'\1'+function_type()+b'\0')
    add('type_parameter_fifth_overflow', b'\1\x60\1'+b'\x80'*4+b'\x08\0')
    add('type_result_fifth_overflow', b'\1\x60\0\1'+b'\xff'*4+b'\x77')
    add('type_redundant_signed_values', b'\1\x60\1\xff\x7f\1\xff\xff\xff\xff\x7f')
    for byte in range(128):
        add(f'type_single_terminator_{byte}', b'\1\x60\1'+bytes([byte])+b'\0')
    for value in [0,1,-1,-16,-17,-(1<<31),(1<<31)-1]:
        add(f'type_extended_prefix_parameter_{value}', b'\1\x60\1'+i32(-21)+i32(value)+b'\0')
        add(f'type_extended_prefix_result_{value}', b'\1\x60\0\1'+i32(-21)+i32(value))
    add('type_extended_prefix_missing_secondary', b'\1\x60\1'+i32(-21))
    add('type_extended_prefix_truncated_secondary', b'\1\x60\1'+i32(-21)+b'\x80')
    rng=random.Random(0x32298C)
    valid=[-1,-2,-3,-4,-5,-16,-17]
    for index in range(12):
        count=rng.randrange(1,5)
        payload=u32(count)+b''.join(function_type(
            [rng.choice(valid) for _ in range(rng.randrange(0,8))],
            [rng.choice(valid) for _ in range(rng.randrange(0,4))]) for _ in range(count))
        add(f'type_generated_{index}',payload)
    combo=sections.section(1,b'\1'+function_type([-1],[-2]))+sections.section(3,b'\1\0')+sections.section(7,b'\0')
    cases.append(dict(label='type_then_functions_exports',blob=b'A'*8+combo))
    cases.append(dict(label='type_then_duplicate_type',blob=b'A'*8+sections.section(1,b'\0')*2))
    return cases


def actual_inputs(library):
    pages=oracle.fresh_pages();base=0x122C0000
    pages.update(oracle.image_pages(library,base))
    table=oracle.GUEST+0x4000
    _write_span(pages,table+50,bytes([constructor_codec_byte(library)]))
    alternative.decode_factory_blob_xor(pages,blob_address=base+0x387D20,blob_size=0x37FD0,
        codec_table_address=table,codec_table_count=3)
    blob=_read_span(pages,base+0x387D20,0x37FD0)
    cursor=8;selected={}
    while cursor<len(blob):
        number=blob[cursor];cursor+=1;size=0
        for index in range(5):
            byte=blob[cursor];cursor+=1;size|=(byte&127)<<(index*7)
            if byte<128:break
        else:raise AssertionError('fixture envelope did not terminate')
        end=cursor+size;assert end<=len(blob)
        if number in [1,3,7,12]:
            assert number not in selected
            selected[number]=blob[cursor:end]
        cursor=end
    assert cursor==len(blob) and sorted(selected)==[1,3,7,12]
    return [dict(label='actual_ELF_type_section',blob=b'A'*8+sections.section(1,selected[1]),
                 actual_ELF_section_input=True),
            dict(label='actual_ELF_types_functions_exports_data_count',
                 blob=b'A'*8+b''.join(sections.section(n,p) for n,p in selected.items()),
                 actual_ELF_section_input=True)]


def prepare(args,base,spec):
    pages=sections.prepare(args.library,base,spec)
    for slot in SLOTS:sections.put(pages,VTABLE+slot,CALLBACK+slot)
    for offset,key,pointer in [(0x28,'params',OLD_PARAMS),(0x40,'results',OLD_RESULTS)]:
        size,capacity=spec.get(key,(0,0))
        word_vector(pages,STATE+offset,pointer if capacity else 0,size,capacity)
    return pages


def compare_type(args,base,spec):
    pages=prepare(args,base,spec);model={k:bytearray(v) for k,v in pages.items()}
    native_events=[];model_events=[]
    native_alloc,native_effects,observe,allocate,free=services()
    def status(slot,index):
        return 0xFFFFFFFF if slot==spec.get('failure_slot') and index==spec.get('failure_call',0) else 0
    imports={0x347FA0:free}
    with args.libc.open('rb') as f:
        elf=ELFFile(f)
        memcmp=next(0x51000000+s['st_value'] for sec in elf.iter_sections()
            if sec['sh_type']=='SHT_DYNSYM' for s in sec.iter_symbols() if s.name=='memcmp' and s['st_value'])
    def compare_bytes(cpu):cpu.reg_write(arm.UC_ARM64_REG_PC,memcmp)
    imports[0x347FE0]=compare_bytes
    for slot,argc in SLOTS.items():
        def callback(cpu,slot=slot,argc=argc):
            values=tuple(cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(argc+1))
            assert values[0]==OBJECT
            args_=values[1:];vectors=()
            if slot==0x20:
                vectors=tuple(tuple(int.from_bytes(cpu.mem_read(pointer+i*8,8),'little') for i in range(count))
                              for count,pointer in [(args_[1],args_[2]),(args_[3],args_[4])])
            event=(slot,args_,int.from_bytes(cpu.mem_read(STATE+24,8),'little'),
                   int.from_bytes(cpu.mem_read(STATE,8),'little'),vectors)
            result=status(slot,len(native_events));native_events.append(event);return result
        imports[CALLBACK+slot-base]=callback
    observed={(base+offset,64):None for offset in sections.GLOBALS}
    returned,memory,calls,ledger=oracle.native(args.library,base,0x324188,[STATE],pages,
        host_imports=imports,libc=args.libc,observed_memory=observed,instruction_limit=100000,
        malloc_handler=lambda cpu,size:allocate(size,cpu),
        instruction_observer=lambda cpu,addr:observe(cpu,addr,base))
    assert not calls and not ledger
    model_alloc,_,_,planned,_=services()
    def callback(event):
        result=status(event.slot_offset,len(model_events))
        model_events.append((event.slot_offset,event.arguments,event.cursor,event.section_end,event.type_vectors))
        return result
    result=alternative.run_reader_sections(model,state_address=STATE,image_base=base,
        varuint_scratch_address=SCRATCH,callback=callback,vector_allocate=planned)
    assert result.status==returned,(spec['label'],result.status,returned)
    assert native_events==model_events,(spec['label'],'callback arguments/state/vector cells')
    assert native_alloc==model_alloc,(spec['label'],'allocation plan')
    assert native_effects==[effect_tuple(e) for e in result.vector_effects],(spec['label'],'allocation/free ordering')
    assert _read_span(model,oracle.GUEST,0xA000)==memory,(spec['label'],'guest memory')
    for (address,size),value in observed.items():assert _read_span(model,address,size)==value,(spec['label'],'rank globals')
    return dict(label=spec['label'],image_base_hex=hex(base),status=result.status,
        cursor=result.cursor,last_section=result.last_section,callback_count=len(native_events),
        type_entry_callback_count=sum(e[0]==0x20 for e in native_events),
        allocation_count=len(native_alloc),free_count=sum(e[0]=='free' for e in native_effects),
        native_Python_return_match=True,guest_input_output_region_match=True,
        callback_arguments_state_and_type_cells_match=True,allocation_free_effects_and_publication_match=True,
        rank_global_memory_match=True,actual_ELF_section_input=spec.get('actual_ELF_section_input',False),
        native_input_snapshot_used=False)


def negatives(args):
    rejected=[]
    vector=STATE+0x28
    vector_cases=[
        ('unaligned_header',dict(vector_address=vector+1),None),
        ('overflow_header',dict(vector_address=alternative.MASK64-15),None),
        ('missing_header',dict(vector_address=0x77000000),None),
        ('reversed_size',{},lambda p:sections.put(p,vector+8,OLD_PARAMS-8)),
        ('capacity_before_end',{},lambda p:sections.put(p,vector+16,OLD_PARAMS+8)),
        ('null_storage_nonzero_capacity',{},lambda p:sections.put(p,vector,0)),
        ('unaligned_storage',{},lambda p:sections.put(p,vector,OLD_PARAMS+1)),
        ('storage_aliases_header',{},lambda p:word_vector(p,vector,vector,1,2)),
        ('missing_old_storage',{},lambda p:p.pop(OLD_PARAMS>>12)),
        ('invalid_bound',dict(max_elements=0),None),
        ('initial_capacity_bound',dict(max_elements=1),None),
        ('negative_additional_count',dict(additional_count=-1),None),
        ('append_exceeds_bound',dict(additional_count=4096),None),
        ('doubling_exceeds_bound',dict(max_elements=4),None),
        ('allocation_service_missing',dict(allocate=None),None),
        ('allocation_null',dict(allocate=lambda size:0),None),
        ('allocation_unaligned',dict(allocate=lambda size:HEAP+1),None),
        ('allocation_overflows',dict(allocate=lambda size:alternative.MASK64-7),None),
        ('allocation_aliases_old',dict(allocate=lambda size:OLD_PARAMS),None),
        ('allocation_aliases_header',dict(allocate=lambda size:vector),None),
        ('allocation_aliases_retained_region',dict(allocate=lambda size:DATA,
             reserved_regions=((DATA,DATA+0x100),)),None),
        ('allocation_missing_page',dict(allocate=lambda size:0x77000000),None),
        ('allocation_partly_mapped',dict(allocate=lambda size:oracle.GUEST+oracle.GUEST_SIZE-8),None),
    ]
    for label,change,edit in vector_cases:
        pages=oracle.fresh_pages();word_vector(pages,vector,OLD_PARAMS,2,3)
        if edit:edit(pages)
        before={k:bytes(v) for k,v in pages.items()}
        options=dict(vector_address=vector,additional_count=2,allocate=lambda size:HEAP)
        options.update(change)
        try:alternative.grow_reader_word_vector(pages,**options)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError('vector guard accepted: '+label)
        assert before=={k:bytes(v) for k,v in pages.items()},label
        rejected.append(dict(label=label,owner='word_vector',rejected=True,all_pages_unchanged=True,
                             native_guard_faults_compared=False))
    spec=dict(blob=b'A'*8+sections.section(1,b'\1'+function_type([-1,-2],[-3])),params=(1,2),results=(0,1))
    parser_cases=[
        ('type_service_missing',dict(vector_allocate=None),None),
        ('type_storage_aliases_input',{},lambda p:word_vector(p,STATE+0x28,DATA,1,2)),
        ('type_storage_aliases_scratch',{},lambda p:word_vector(p,STATE+0x28,SCRATCH,1,2)),
        ('type_vector_storage_overlap',{},lambda p:word_vector(p,STATE+0x40,OLD_PARAMS+8,1,2)),
        ('type_vector_storage_missing',{},lambda p:p.pop(OLD_PARAMS>>12)),
        ('type_input_page_missing',{},lambda p:p.pop(DATA>>12)),
        ('type_entry_bound',dict(max_entries=1),None),
        ('type_late_callback_invalid',dict(callback=lambda e:-1 if e.slot_offset==0x20 else 0),None),
        ('type_allocation_aliases_input',dict(vector_allocate=lambda size:DATA),
             lambda p:word_vector(p,STATE+0x28,0,0,0)),
        ('type_allocation_partly_mapped',dict(vector_allocate=lambda size:oracle.GUEST+oracle.GUEST_SIZE-8),
             lambda p:word_vector(p,STATE+0x28,0,0,0)),
        ('type_then_unrecovered_import',{},lambda p:_write_span(p,DATA,
             b'A'*8+sections.section(1,b'\1'+function_type([-1,-2],[-3]))+sections.section(2,b'\0'))),
    ]
    for label,change,edit in parser_cases:
        pages=prepare(args,0x122C0000,spec)
        if edit:edit(pages)
        if label=='type_then_unrecovered_import':
            size=len(spec['blob'])+len(sections.section(2,b'\0'))
            sections.put(pages,STATE,size);sections.put(pages,STATE+16,size)
        before={k:bytes(v) for k,v in pages.items()}
        _,_,_,allocate,_=services()
        options=dict(state_address=STATE,image_base=0x122C0000,varuint_scratch_address=SCRATCH,
                     callback=lambda e:0,vector_allocate=allocate)
        options.update(change)
        try:alternative.run_reader_sections(pages,**options)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError('type guard accepted: '+label)
        assert before=={k:bytes(v) for k,v in pages.items()},label
        rejected.append(dict(label=label,owner='type_section',rejected=True,all_pages_unchanged=True,
                             native_guard_faults_compared=False))
    return rejected


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--library',required=True,type=Path);p.add_argument('--libc',required=True,type=Path)
    p.add_argument('--output',required=True,type=Path);args=p.parse_args()
    sample_hash=hashlib.sha256(args.library.read_bytes()).hexdigest()
    libc_hash=hashlib.sha256(args.libc.read_bytes()).hexdigest()
    assert sample_hash==oracle.LIBRARY_SHA256,'unexpected native sample'
    assert libc_hash=='d2376df6d2ac3e0213f85e3614c4c7ad1d28c84c44926058d5c1b95c855563db','unexpected matching libc'
    rejected=negatives(args)
    print('B vectors/types:',len(rejected),'rejection/rollback controls passed',flush=True)
    vectors=[];types=[];specs=type_inputs()+actual_inputs(args.library)
    for base in [0x122C0000,0x775C205000]:
        for spec in vector_inputs():vectors.append(compare_vector(args,base,spec))
        print('B word vectors:',hex(base),len(vector_inputs()),'controls passed',flush=True)
        for index,spec in enumerate(specs,1):
            try:types.append(compare_type(args,base,spec))
            except Exception as e:raise AssertionError('type control failed: '+spec['label']) from e
            if index%64==0:print('B type section progress:',hex(base),index,'/',len(specs),flush=True)
        print('B type sections:',hex(base),len(specs),'controls passed',flush=True)
    evidence=dict(schema='vm9-alternative-reader-types-fresh-v1',evidence_date='2026-10-08',
        evidence_timezone='UTC',host_trial_label='20261008',sample_sha256=sample_hash,matching_libc_sha256=libc_hash,
        native_vector_function_offset_hex='0x324540',native_type_function_offset_hex='0x32298c',
        native_core_function_offset_hex='0x324188',native_Python_vector_controls=len(vectors),
        native_Python_type_controls=len(types),actual_ELF_selected_section_controls=sum(c['actual_ELF_section_input'] for c in types),
        synthetic_type_controls=sum(not c['actual_ELF_section_input'] for c in types),
        rollback_negative_controls=len(rejected),negative_cases=rejected,
        vector_cases=vectors,type_cases=types,guest_input_output_bytes_compared=0xA000,
        native_input_snapshot_used=False,natural_native_return_verified=True,
        allocation_free_are_explicit_services=True,allocator_boot_implemented=False,
        callbacks_are_explicit_status_services=True,actual_AST_callbacks_executed=False,
        supported_section_ids=[0,1,3,7,8,12],section_2_import_implemented=False,
        reader_AST_native_Python_controls=0,complete_python_reader_implemented=False,
        independent_Python_factory_implemented=False,complete_python_bootstrap_controls=0,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    print('B vectors/types:',len(vectors),len(types),'native/Python +',len(rejected),'rollback controls passed',flush=True)


if __name__=='__main__':main()
