"""Original B constructor/factory publication with explicit host services.

The factory runs natively from ELF inputs; Python lookup consumes the same
run's generated root. That lookup comparison is not independent Python boot.
Reader mode accepts independent Python ELF XOR input; no Python reader or
AST comparison is claimed. No native image/snapshot or selector is exported.
"""
from __future__ import annotations
import argparse,collections,hashlib,json
from pathlib import Path
from elftools.elf.elffile import ELFFile
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
from verify_vm9_signer_objects import fresh_pages,image_pages,GUEST,STOP
from verify_vm9_root_configuration import LIBC_BASE
import verify_vm9_jni_initialization_fresh_20261007 as initialization
import vm9_alternative_startup as alternative
from vm9_allocator import _write_span

STACK=0x78000000
STACK_BYTES=0x200000
ENTRY_SP=STACK+STACK_BYTES-0x1000
PUBLISHED_COUNT=121


def case(args,base,*,mode='factory'):
    assert mode in ('factory','reader')
    pages=fresh_pages();pages.update(image_pages(args.library,base))
    if mode=='reader':
        from verify_vm9_alternative_blob_xor_20261008 import constructor_codec_byte
        _write_span(pages,GUEST+0x1000,bytes(0x180))
        _write_span(pages,GUEST+0x4000+2*24+2,bytes([constructor_codec_byte(args.library)]))
        alternative.decode_factory_blob_xor(pages,blob_address=base+0x387D20,blob_size=0x37FD0,
            codec_table_address=GUEST+0x4000,codec_table_count=3)
    bound=collections.Counter()
    with args.library.open('rb') as stream:
        elf=ELFFile(stream)
        start=0x29F2DC
        segment=next(segment for segment in elf.iter_segments() if segment['p_type']=='PT_LOAD'
            and segment['p_vaddr']<=start<segment['p_vaddr']+segment['p_filesz'])
        raw=segment.data()[start-segment['p_vaddr']:0x2A0018-segment['p_vaddr']]
        disassembler=Cs(CS_ARCH_ARM64,CS_MODE_ARM);disassembler.detail=True
        publication_sites={instruction.address:instruction.operands[1].mem.disp
            for instruction in disassembler.disasm(raw,start)
            if instruction.mnemonic=='str' and instruction.op_str.startswith('x0, [x8')}
        assert len(publication_sites)==PUBLISHED_COUNT
        for section in elf.iter_sections():
            if section['sh_type']!='SHT_RELA':continue
            symbols=elf.get_section(section['sh_link'])
            for relocation in section.iter_relocations():
                symbol=symbols.get_symbol(relocation['r_info_sym'])
                offset={'memcpy':0x347F60,'memset':0x347F20,'strlen':0x347F40}.get(symbol.name)
                if relocation['r_info_type']==257 and offset is not None:
                    assert symbol['st_shndx']=='SHN_UNDEF' and relocation['r_addend']==0
                    _write_span(pages,base+relocation['r_offset'],(base+offset).to_bytes(8,'little'))
                    bound[symbol.name]+=1
    with args.libc.open('rb') as stream:
        elf=ELFFile(stream)
        cmp_entry=next(LIBC_BASE+symbol['st_value'] for section in elf.iter_sections()
            if section['sh_type']=='SHT_DYNSYM' for symbol in section.iter_symbols() if symbol.name=='memcmp')
    captured=[];allocations=[];live={};extents={};next_pointer=0x72000000
    events=[];registrations=[];lookups=[];stores=[];loop_visits=0;progress=[];factory_args=[]
    original_cpu=oracle.Uc
    def observed_cpu(*args,**options):
        cpu=original_cpu(*args,**options);cpu.mem_map(STACK,STACK_BYTES);captured.append(cpu);return cpu
    def read(cpu,address,n=8):return int.from_bytes(cpu.mem_read(address,n),'little')
    def malloc(cpu,size):
        nonlocal next_pointer
        pointer=next_pointer;extent=(max(size,1)+4095)&~4095;next_pointer+=extent
        assert next_pointer<0x76000000
        cpu.mem_map(pointer,extent);cpu.mem_write(pointer,bytes([0xA5])*extent)
        allocations.append([pointer,size]);live[pointer]=size;extents[pointer]=extent;return pointer
    def free(cpu):
        pointer=cpu.reg_read(arm.UC_ARM64_REG_X0)
        if pointer:
            assert pointer in live,'unknown or double free'
            cpu.mem_write(pointer,bytes([0xD7])*live.pop(pointer))
        return 0
    def compare(cpu):cpu.reg_write(arm.UC_ARM64_REG_PC,cmp_entry);return None
    def gettid(cpu):
        assert cpu.reg_read(arm.UC_ARM64_REG_X0)==0xB2
        return 137
    def register(cpu):
        registrations.append([cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(3)])
        return 0
    def observe(cpu,address):
        nonlocal loop_visits
        off=address-base
        if off==0x2CBDC8:
            factory_args.extend(cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(9))
            assert factory_args[:2]==[base+0x387D20,0x37FD0]
            assert factory_args[3:8:2]==[0,16,22]
            events.append('actual_factory_enter')
        if off==0x2A9610:events.append('actual_factory_return')
        if off==0x29F2CC:events.append('factory_wrapper_return')
        if off==0x2A9620 and 'factory_wrapper_return' in events:
            root=cpu.reg_read(arm.UC_ARM64_REG_X0);name=cpu.reg_read(arm.UC_ARM64_REG_X1)
            assert root==read(cpu,base+0x3E1EB0)
            lookups.append(dict(root=root,name=name,sp=cpu.reg_read(arm.UC_ARM64_REG_SP)))
        if off in publication_sites:
            index=len(stores)
            target=cpu.reg_read(arm.UC_ARM64_REG_X8)+publication_sites[off]
            value=cpu.reg_read(arm.UC_ARM64_REG_X0)
            assert base+0x3E1EB8<=target<=base+0x3E2278,(index,hex(target-base))
            stores.append((index,target,value))
        if off==0x2DBF7C:
            loop_visits+=1
            if loop_visits<=3 or loop_visits%4096==0:
                current=cpu.reg_read(arm.UC_ARM64_REG_X22);end=cpu.reg_read(arm.UC_ARM64_REG_X24)
                assert 0<=end-current and (end-current)%12==0
                progress.append(dict(loop_visits=loop_visits,remaining_items=(end-current)//12,
                    controlled_allocation_calls=len(allocations)))
        if off==0x2A0024:events.append('original_B_constructor_ret')
        if mode=='reader' and off==0x31B360:events.append('actual_reader_enter')
        if mode=='reader' and off==0x31B454:events.append('actual_reader_ret')
    oracle.Uc=observed_cpu
    try:
        function=0x29ECAC if mode=='factory' else 0x31B360
        arguments=[] if mode=='factory' else [base+0x6FE64,0,base+0x387D20,0x37FD0,GUEST+0x1000]
        ranges=((base+0x29ECAC,base+0x2A0024),(base+0x2A95E0,base+0x2A9800),
            (base+0x2CBDC8,base+0x2CBE48),(base+0x347E00,base+0x348800),
            (base+0x2DBF7C,base+0x2DBF7C)) if mode=='factory' else (
            (base+0x31B360,base+0x31B458),(base+0x324444,base+0x3244F8),
            (base+0x347E00,base+0x348800))
        oracle.native(args.library,base,function,arguments,pages,libc=args.libc,malloc_handler=malloc,
            host_imports={0x347FA0:free,0x347FE0:compare,0x348310:gettid,0x347EA0:register},
            instruction_observer=observe,real_mutexes=True,
            extra_registers={arm.UC_ARM64_REG_SP:ENTRY_SP},instruction_limit=60000000,
            code_hook_ranges=ranges)
    finally:oracle.Uc=original_cpu
    cpu=captured[0]
    assert cpu.reg_read(arm.UC_ARM64_REG_PC)==STOP
    assert cpu.reg_read(arm.UC_ARM64_REG_SP)==ENTRY_SP
    if mode=='reader':
        assert events==['actual_reader_enter','actual_reader_ret']
        assert cpu.reg_read(arm.UC_ARM64_REG_X0)==0 and not lookups and not stores and not registrations
        assert len(allocations)==1658
        summaries=[]
        for index in range(12):
            begin,end,capacity=(read(cpu,GUEST+0x1000+index*24+j*8) for j in range(3))
            assert (begin==end==capacity==0) or begin<=end<=capacity
            if begin:assert begin in live
            summaries.append(dict(index=index,allocated=bool(begin),used_bytes=end-begin,capacity_bytes=capacity-begin))
        return dict(image_base_hex=hex(base),native_reader_return_verified=True,reader_status=0,
            reader_offset_hex='0x31b360',core_parser_offset_hex='0x324188',
            independent_Python_XOR_prefix_used=True,actual_ELF_blob_used=True,
            controlled_allocation_calls=len(allocations),register_only_exit_calls=0,
            actual_reader_output_vector_summaries=summaries,explicit_allocator_and_stack_used=True,
            reader_invoked_directly=True,native_input_snapshot_used=False,
            Python_reader_implemented=False,Python_AST_output_compared=False,
            independent_Python_factory_implemented=False,B_VM_executed=False,
            complete_python_bootstrap_controls=0,complete_python_medusa=False,
            fresh_signer_output_verified=False,live_server_matrix_verified=False)
    assert events==['actual_factory_enter','actual_factory_return','factory_wrapper_return','original_B_constructor_ret']
    assert len(stores)==len(lookups)==PUBLISHED_COUNT
    assert [row[0] for row in stores]==list(range(PUBLISHED_COUNT))
    # Native generated root is a component input, never a signer bootstrap input.
    model={key:bytearray(cpu.mem_read(key<<12,4096)) for key in pages}
    for address,extent in [*extents.items(),(STACK,STACK_BYTES)]:
        for start in range(address,address+extent,4096):model[start>>12]=bytearray(cpu.mem_read(start,4096))
    final_stores={target:value for _,target,value in stores}
    assert all(read(cpu,target)==value for target,value in final_stores.items())
    comparisons=[]
    for row,(index,target,value) in zip(lookups,stores):
        result=alternative.lookup_short_descriptor(model,root_address=row['root'],name_address=row['name'],
            entry_stack_address=row['sp'])
        assert result.descriptor_address==value and value!=0,(index,hex(result.descriptor_address),hex(value),result.query_length,result.bucket_index,len(result.visited_nodes))
        comparisons.append(dict(index=index,publication_slot_offset_hex=hex(target-base),
            query_length=result.query_length,bucket_index=result.bucket_index,
            visited_nodes=len(result.visited_nodes),native_Python_descriptor_match=True))
    root=lookups[0]['root']
    return dict(image_base_hex=hex(base),native_constructor_return_verified=True,
        native_factory_return_verified=True,actual_ELF_factory_blob_used=True,factory_blob_offset_hex='0x387d20',
        factory_blob_length=0x37FD0,constructor_generated_callback_count=16,constructor_generated_prototype_count=22,
        controlled_allocation_calls=len(allocations),register_only_exit_calls=len(registrations),
        bound_ABS64_import_counts=dict(bound),native_normal_mutexes_used=True,native_memcmp_used=True,
        actual_generated_root_bucket_count=read(cpu,root+0x28),all_121_descriptors_published_nonzero=True,
        generated_root_lookup_controls=len(comparisons),lookup_comparisons=comparisons,
        actual_publication_sites_decoded_from_ELF=True,unique_final_publication_slots=len(final_stores),
        all_final_publication_slots_verified=True,
        vector_stride_bytes=12,vector_loop_visits=loop_visits,bounded_vector_progress=progress,
        native_instruction_budget=60000000,terminal='natural_constructor_return_to_driver_STOP',
        explicit_allocator_gettid_exit_registration_and_stack_used=True,diagnostic_scopes_substituted_by_oracle=True,
        constructor_invoked_directly=True,Android_loader_executed=False,original_JNI_B_run_composed=False,
        native_generated_root_used_as_lookup_component_input=True,native_input_snapshot_used=True,
        Python_factory_implemented=False,complete_Python_B_bootstrap_controls=0,B_VM_executed=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--libc',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==initialization.LIBC_SHA256
    cases=[]
    for base in (0x122C0000,0x775C205000):
        cases.append(case(args,base));print('B original ctor/factory/121 publication:',hex(base),'passed',flush=True)
    evidence=dict(schema='vm9-alternative-factory-native-v1',evidence_date='2026-10-07',evidence_timezone='UTC',
        host_trial_label='20261008',sample_sha256=oracle.LIBRARY_SHA256,matching_libc_sha256=initialization.LIBC_SHA256,
        constructor_factory_publication_observations=len(cases),generated_root_lookup_controls=sum(c['generated_root_lookup_controls'] for c in cases),
        cases=cases,independent_Python_factory_implemented=False,complete_python_bootstrap_controls=0,
        native_generated_root_is_component_input_only=True,complete_python_medusa=False,
        fresh_signer_output_verified=False,live_server_matrix_verified=False)
    args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    print('B factory: 2 native observations and 242 generated-root lookup controls passed',flush=True)


if __name__=='__main__':main()
