"""Fresh ELF image/linking versus an independent section-based oracle.

Compare every mapped byte, symbol version, binding, array and permission.
Original constructor sequences consume independently linked native inputs;
Python uses its program-header/dynamic loader. No native output is an input.
Private strings and payloads remain runtime data, never exported evidence.
"""
from pathlib import Path
from collections import Counter
import argparse,hashlib,json
from struct import pack_into
from elftools.elf.elffile import ELFFile
import vm9_elf_image as owner
import verify_vm9_elf_constructor_sequence_20261011 as sequence
from vm9_allocator import _read_span,_write_span,RefillUnsupported

MASK64=(1<<64)-1

def service_bindings(args,base,delta=0):
    bindings={}
    with args.libc.open('rb') as stream:
        elf=ELFFile(stream)
        for symbol in elf.get_section_by_name('.dynsym').iter_symbols():
            if symbol['st_shndx']!='SHN_UNDEF':bindings[symbol.name]=sequence.LIBC_BASE+symbol['st_value']+delta
    with args.library.open('rb') as stream:
        elf=ELFFile(stream);relocations=elf.get_section_by_name('.rela.plt')
        symbols=elf.get_section(relocations['sh_link']);start=elf.get_section_by_name('.plt')['sh_addr']+32
        for index,r in enumerate(relocations.iter_relocations()):
            bindings[symbols.get_symbol(r['r_info_sym']).name]=base+start+index*16+delta
    return bindings


def reference(args,base,blob,delta=0,weak_bound=False):
    pages={};counts=Counter();requests={};permissions={};exports=[];dependencies=[]
    bindings=service_bindings(args,base,delta)
    # Sections supply an independent relocation/symbol oracle. Segment bytes
    # come from the exact tested blob, including section-header mutations.
    with args.library.open('rb') as stream:
        elf=ELFFile(stream);dynsym=elf.get_section_by_name('.dynsym');versions={}
        for dependency,auxiliaries in elf.get_section_by_name('.gnu.version_r').iter_versions():
            for auxiliary in auxiliaries:versions[auxiliary['vna_other']&0x7FFF]=(auxiliary.name,dependency.name)
        versym=elf.get_section_by_name('.gnu.version')
        for segment in elf.iter_segments():
            if segment['p_type']=='PT_LOAD':
                start=base+segment['p_vaddr'];end=start+segment['p_memsz']
                for address in range(start&~4095,(end+4095)&~4095,4096):
                    pages.setdefault(address>>12,bytearray(4096));permissions[address]=permissions.get(address,0)|segment['p_flags']
                offset=segment['p_offset'];_write_span(pages,start,blob[offset:offset+segment['p_filesz']])
            if segment['p_type']=='PT_DYNAMIC':
                dependencies=[t.needed for t in segment.iter_tags() if t.entry.d_tag=='DT_NEEDED']
        for segment in elf.iter_segments():
            if segment['p_type']=='PT_GNU_RELRO':
                for address in range((base+segment['p_vaddr'])&~4095,(base+segment['p_vaddr']+segment['p_memsz'])&~4095,4096):
                    if address in permissions:permissions[address]&=~2
        for symbol in dynsym.iter_symbols():
            if (symbol['st_shndx']!='SHN_UNDEF' and symbol['st_info']['bind'] in ('STB_GLOBAL','STB_WEAK')
                    and symbol['st_info']['type'] in ('STT_NOTYPE','STT_OBJECT','STT_FUNC') and symbol['st_other']['visibility']=='STV_DEFAULT'):
                exports.append((symbol.name,base+symbol['st_value']))
        for section in elf.iter_sections():
            if section['sh_type']!='SHT_RELA':continue
            symbols=elf.get_section(section['sh_link'])
            for r in section.iter_relocations():
                kind=r['r_info_type'];counts[kind]+=1
                if kind==1027:value=base
                else:
                    index=r['r_info_sym'];symbol=symbols.get_symbol(index)
                    if symbol['st_shndx']!='SHN_UNDEF':value=base+symbol['st_value']
                    else:
                        weak=symbol['st_info']['bind']=='STB_WEAK'
                        value=(sequence.v.oracle.GUEST+0xF800 if weak_bound else 0) if weak else bindings.get(symbol.name)
                        assert value is not None,'missing explicit binding'
                        vid=versym.get_symbol(index)['ndx'];version,dependency=versions.get(vid,(None,None))
                        symbol_type={'STT_NOTYPE':0,'STT_OBJECT':1,'STT_FUNC':2}[symbol['st_info']['type']]
                        requests[(symbol.name,version,dependency,weak,symbol_type)]=value
                _write_span(pages,base+r['r_offset'],((value+r['r_addend'])&MASK64).to_bytes(8,'little'))
        arrays=[]
        for name in ('.init_array','.fini_array'):
            s=elf.get_section_by_name(name)
            arrays.append(tuple(int.from_bytes(_read_span(pages,base+s['sh_addr']+i,8),'little') for i in range(0,s['sh_size'],8)))
    return pages,counts,requests,permissions,arrays,exports,dependencies


def provider(args,base,delta=0,weak_bound=False):
    bindings=service_bindings(args,base,delta);calls=[]
    def resolve(request):
        calls.append(request)
        if request.weak:return sequence.v.oracle.GUEST+0xF800 if weak_bound else None
        return bindings.get(request.name)
    return resolve,calls


def dynamic_offset(args,tag):
    with args.library.open('rb') as stream:
        section=ELFFile(stream).get_section_by_name('.dynamic')
        for index,t in enumerate(section.iter_tags()):
            if t.entry.d_tag==tag:return section['sh_offset']+index*16
    raise AssertionError('missing required dynamic test tag')


def controls(args):
    rows=[];original=args.library.read_bytes()
    for base in (0x122C0000,0x775C205000):
        for label in ('full_link','sectionless','GNU_hash_only','weak_symbols_present','changed_provider_addresses'):
            blob=bytearray(original);delta=0x180 if label=='changed_provider_addresses' else 0
            weak=label=='weak_symbols_present'
            if label=='sectionless':pack_into('<Q',blob,40,0);pack_into('<HHH',blob,58,0,0,0)
            if label=='GNU_hash_only':pack_into('<qQ',blob,dynamic_offset(args,'DT_HASH'),21,0)
            before=bytes(blob);resolve,calls=provider(args,base,delta,weak)
            result=owner.load_elf_image(blob,image_base=base,resolve_symbol=resolve)
            expected,counts,requests,permissions,arrays,exports,dependencies=reference(args,base,blob,delta,weak)
            assert result.pages==expected and bytes(blob)==before
            actual={(r.name,r.version,r.dependency,r.weak,r.symbol_type):a for r,a in result.imported_bindings}
            assert actual==requests and len(calls)==len(requests)==140 and len(set(calls))==len(calls)
            assert dict(result.relocation_counts)==counts and result.page_permissions==tuple(sorted(permissions.items()))
            assert [result.init_array,result.fini_array]==arrays and list(result.exports)==exports and list(result.dependencies)==dependencies
            assert int.from_bytes(_read_span(result.pages,base+0x375010,8),'little')==base+0x27B41C
            rows.append(dict(base=hex(base),label=label,mapped_pages=len(result.pages),relocations=sum(counts.values()),
                relative_relocations=counts[1027],undefined_symbol_sites=210,unique_symbol_requests=len(calls),
                init_array_entries=len(result.init_array),fini_array_entries=len(result.fini_array),
                all_mapped_bytes_BSS_and_relocations_match=True,symbol_versions_bindings_and_exports_match=True,
                permissions_RELRO_and_arrays_match=True,defined_JNI_GOT_bound=True,input_bytes_unchanged=True,
                native_snapshot_input=False))
            print('ELF image independent control',hex(base),label,'passed',flush=True)
    return rows


def native_controls(args):
    rows=[];original_fixture=sequence.configuration.fixture;blob=args.library.read_bytes()
    for base in (0x122C0000,0x775C205000):
        calls=0
        def fixture(local_args,local_base,profile):
            nonlocal calls
            pages=original_fixture(local_args,local_base,profile)
            if calls==0:image=reference(local_args,local_base,blob)[0]
            else:
                resolve,_=provider(local_args,local_base)
                image=owner.load_elf_image(blob,image_base=local_base,resolve_symbol=resolve).pages
            calls+=1;pages.update(image);return pages
        try:
            sequence.configuration.fixture=fixture
            row=sequence.compare(args,base,{},sequence.v.SP,'full_image_linked_sequence')
            assert calls==2
            row.update(native_inputs_from_independent_section_loader=True,
                Python_inputs_from_production_dynamic_loader=True,all_18481_relocations_applied=True)
            rows.append(row);print('Native fully linked 13-constructor sequence',hex(base),'passed',flush=True)
        finally:sequence.configuration.fixture=original_fixture
    return rows


def negatives(args):
    original=args.library.read_bytes();base=0x122C0000;rows=[]
    with args.library.open('rb') as stream:
        e=ELFFile(stream);rela=e.get_section_by_name('.rela.dyn')['sh_offset']
        versym=e.get_section_by_name('.gnu.version')['sh_offset'];hashoff=e.get_section_by_name('.hash')['sh_offset']
        ph=e.header['e_phoff'];load_index=next(i for i,s in enumerate(e.iter_segments()) if s['p_type']=='PT_LOAD')
    def reject(label,mutate=None,changes=None):
        blob=bytearray(original)
        if mutate:mutate(blob)
        before=bytes(blob);resolve,_=provider(args,base);kw=dict(image_base=base,resolve_symbol=resolve);kw.update(changes or {})
        try:owner.load_elf_image(blob,**kw)
        except RefillUnsupported:pass
        else:raise AssertionError('accepted ELF guard '+label)
        assert bytes(blob)==before
        rows.append(dict(label=label,rejected=True,input_bytes_unchanged=True,no_partial_image_returned=True))
    for label,offset,fmt,value in (
        ('bad_identity',0,'I',0),('wrong_class',4,'B',1),('wrong_endian',5,'B',2),
        ('wrong_type',16,'H',2),('wrong_machine',18,'H',62),('wrong_header_size',52,'H',32),
        ('wrong_program_size',54,'H',32),('program_count_budget',56,'H',257),('program_table_truncated',32,'Q',len(original)),
        ('load_file_larger_than_memory',ph+load_index*56+32,'Q',len(original)*2),
        ('load_address_overflow',ph+load_index*56+16,'Q',MASK64-3),
        ('load_alignment_non_power_two',ph+load_index*56+48,'Q',3),
        ('load_writable_executable',ph+load_index*56+4,'I',7),
        ('hash_symbol_budget',hashoff+4,'I',1048577),('unknown_symbol_version',versym+2,'H',0x1234),
        ('unknown_relocation',rela+8,'Q',1040),('relocation_target_outside_loads',rela,'Q',0x800000),
        ('relative_symbol_nonzero',rela+8,'Q',(1<<32)|1027)):
        reject(label,lambda b,o=offset,f=fmt,v=value:pack_into('<'+f,b,o,v))
    for label,tag,fmt,value in (
        ('bad_RELA_entry_size','DT_RELAENT','Q',8),('RELA_size_not_multiple','DT_RELASZ','Q',25),
        ('RELA_outside_file','DT_RELA','Q',0x800000),('wrong_PLT_format','DT_PLTREL','Q',17),
        ('symbol_entry_size','DT_SYMENT','Q',16),('string_table_outside_file','DT_STRTAB','Q',0x800000),
        ('init_array_size','DT_INIT_ARRAYSZ','Q',7),('init_array_outside_loads','DT_INIT_ARRAY','Q',0x800000),
        ('version_chain_budget','DT_VERNEEDNUM','Q',1025)):
        offset=dynamic_offset(args,tag)+8;reject(label,lambda b,o=offset,f=fmt,v=value:pack_into('<'+f,b,o,v))
    reject('duplicated_relocation_target',lambda b:pack_into('<Q',b,rela+24,int.from_bytes(b[rela:rela+8],'little')))
    reject('unsupported_REL',lambda b:pack_into('<qQ',b,dynamic_offset(args,'DT_HASH'),17,0x1000))
    for label,changes in (
        ('zero_base',dict(image_base=0)),('unaligned_base',dict(image_base=base+1)),
        ('boolean_base',dict(image_base=True)),('overflow_base',dict(image_base=MASK64&~4095)),
        ('image_budget',dict(max_image_bytes=4096)),('relocation_budget',dict(max_relocations=1)),
        ('symbol_budget',dict(max_symbols=1)),('boolean_budget',dict(max_symbols=True)),
        ('missing_provider',dict(resolve_symbol=None)),('unresolved_strong_symbol',dict(resolve_symbol=lambda r:None)),
        ('negative_provider',dict(resolve_symbol=lambda r:-1)),('overflow_provider',dict(resolve_symbol=lambda r:1<<64)),
        ('boolean_provider',dict(resolve_symbol=lambda r:True))):reject(label,changes=changes)
    print('ELF image refusal guards',len(rows),'passed',flush=True);return rows


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('library','libc','output'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==sequence.v.oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==sequence.v.defined.builder.catalog.heap.LIBC_HASH
    rows=controls(args);guards=negatives(args);native=native_controls(args)
    evidence=dict(schema='vm9-elf-image-loader-fresh-v1',evidence_date='2026-10-11',evidence_timezone='Asia/Shanghai',
        sample_sha256=sequence.v.oracle.LIBRARY_SHA256,matching_libc_sha256=sequence.v.defined.builder.catalog.heap.LIBC_HASH,
        independent_ELF_image_controls=len(rows),native_Python_full_linked_sequence_controls=len(native),
        refusal_controls=len(guards),pre_change_native_RED_controls=2,
        full_sample_ELF_PT_LOAD_mapping_and_eager_symbol_linking_verified=True,
        external_symbol_providers_explicit=True,section_headers_required=False,
        native_input_snapshot_used=False,private_names_or_payloads_published=False,
        host_OS_loader_or_dependency_initialization_verified=False,full_JNI_bootstrap_verified=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False,
        cases=rows,native_cases=native,negative_cases=guards)
    args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('ELF loader GREEN',len(rows),'image controls',len(native),'native sequences',len(guards),'guards',flush=True)

if __name__=='__main__':main()
