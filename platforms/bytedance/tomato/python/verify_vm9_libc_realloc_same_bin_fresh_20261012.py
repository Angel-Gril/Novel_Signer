"""Matching-libc same small-bin realloc from fresh Python allocator state.

Run original export and je_realloc instructions on the same initial state.
Allocation bootstrap components have separate accepted controls; this does not
repeat their native groups or claim an original whole request prefix comparison.
"""
from pathlib import Path
import argparse,hashlib,json
from elftools.elf.elffile import ELFFile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_INTR
from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X30,UC_ARM64_REG_SP,UC_ARM64_REG_TPIDR_EL0,UC_ARM64_REG_PC
import vm9_allocator as allocator
import vm9_libc_base as boot
import vm9_libc_tcache as cache
from vm9_libc_boot import _u,_w
from verify_vm9_thread_key_cleanup import fresh as initial,WORKER_TLS
from verify_vm9_libc_arena_boot import LIBC
from verify_vm9_libc_mapping import LIBC_SHA256
from verify_vm9_signer_objects import LIBRARY_SHA256,GUEST,STOP

BASES=(0x122C0000,0x775C205000)
PROFILES=((2,6),(16,15),(32,31),(48,47),(128,121),(2048,2041),(8,8),(16,16))

def seed(library,libc,image,size):
    p=initial(library,libc,image);guest_os=allocator.GuestOS(p)
    def os_call(tx,op,*args):return tx.next_address if op=='mmap' else 0
    assert boot.cold_init_until_cpu_query(guest_os,libc_base=LIBC,thread_pointer=WORKER_TLS,
        brk=lambda *args:0x13600000,os_call=os_call)==0x8E41C
    pointer=cache.allocate_public_small(guest_os,request_size=size,libc_base=LIBC,
        thread_pointer=WORKER_TLS,os_call=os_call)
    assert pointer
    class_id=cache.region._size_index(p,LIBC,size)
    width=_u(p,LIBC+0xA6C80+class_id*8)
    allocator._write_span(p,pointer,bytes((i*37+9)&255 for i in range(width)))
    # Apply ELF relocations as loader inputs on both sides, including realloc's
    # dispatch table and internal pthread_getspecific binding.
    with libc.open('rb') as stream:
        elf=ELFFile(stream)
        for section in elf.iter_sections():
            if section['sh_type']!='SHT_RELA':continue
            symbols=elf.get_section(section['sh_link'])
            for r in section.iter_relocations():
                kind=r['r_info_type']
                if kind==1027:target=LIBC+r['r_addend']
                elif kind in (257,1025,1026):
                    symbol=symbols.get_symbol(r['r_info_sym'])
                    if symbol['st_shndx']=='SHN_UNDEF':continue
                    target=LIBC+symbol['st_value']+r['r_addend']
                else:continue
                _w(p,LIBC+r['r_offset'],target)
    return p,pointer,width

def native(p,pointer,size):
    cpu=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
    for page,data in p.items():cpu.mem_map(page<<12,4096);cpu.mem_write(page<<12,bytes(data))
    cpu.reg_write(UC_ARM64_REG_X0,pointer);cpu.reg_write(UC_ARM64_REG_X1,size)
    cpu.reg_write(UC_ARM64_REG_X30,STOP);cpu.reg_write(UC_ARM64_REG_SP,GUEST+0xEF00)
    cpu.reg_write(UC_ARM64_REG_TPIDR_EL0,WORKER_TLS)
    entries=[]
    def hook(c,address,n,u):
        if address-LIBC in (0x1BB88,0x90420,0x7BB80,0x7B2C8):entries.append(hex(address-LIBC))
    def interrupt(*a):raise AssertionError('same-bin realloc unexpectedly issued a syscall')
    cpu.hook_add(UC_HOOK_CODE,hook);cpu.hook_add(UC_HOOK_INTR,interrupt)
    cpu.emu_start(LIBC+0x1BB88,STOP,count=30000)
    assert cpu.reg_read(UC_ARM64_REG_PC)==STOP and entries==['0x1bb88','0x90420','0x7bb80','0x7b2c8']
    observed={page:bytes(cpu.mem_read(page<<12,4096)) for page in p
        if not GUEST+0xE000<=page<<12<GUEST+0xF000}
    return cpu.reg_read(UC_ARM64_REG_X0),observed,entries

def compare(library,libc,image,old_size,new_size,overflow=False):
    p,pointer,width=seed(library,libc,image,old_size)
    assert cache.region._size_index(p,LIBC,new_size)==cache.region._size_index(p,LIBC,old_size)
    if overflow:
        wrapper=LIBC+0xDB6B8;_w(p,wrapper+0x18,(1<<64)-4);_w(p,wrapper+0x20,(1<<64)-3)
    returned,observed,entries=native(p,pointer,new_size)
    result=cache.reallocate_same_small_bin(p,pointer=pointer,request_size=new_size,
        libc_base=LIBC,thread_pointer=WORKER_TLS)
    assert result==returned==pointer
    assert all(bytes(p[k])==data for k,data in observed.items())
    print('PASS same-bin',hex(image),old_size,new_size,overflow,flush=True)
    return dict(image_base=hex(image),old_request=old_size,new_request=new_size,usable_size=width,
        wrapping_statistics=overflow,original_export_and_body_returned=True,
        same_pointer_and_all_non_stack_pages_match=True,payload_and_allocator_metadata_match=True,
        TSD_statistics_match=True,original_body_path=entries,native_snapshot_input=False)

def guards(library,libc):
    rows=[]
    for image in BASES:
        template,pointer,_=seed(library,libc,image,17)
        for label in ('NULL_pointer','zero_size','different_bin','oversized','profiling','missing_TSD',
            'noncurrent_TSD','missing_cache','interior_pointer','wrong_tag','never_issued_slot',
            'already_cached','unmapped_payload','invalid_size'):
            p={k:bytearray(v) for k,v in template.items()};target=pointer;size=24;wrapper=LIBC+0xDB6B8
            if label=='NULL_pointer':target=0
            elif label=='zero_size':size=0
            elif label=='different_bin':size=128
            elif label=='oversized':size=0x4000
            elif label=='profiling':_w(p,LIBC+0xE69C0,1)
            elif label=='missing_TSD':
                key=_u(p,_u(p,LIBC+0xD8F98),4)
                allocator.pthread_setspecific(p,key=key,value=0,thread_pointer=WORKER_TLS,generation_table=LIBC+0xE0200)
            elif label=='noncurrent_TSD':_w(p,wrapper+8,2,4)
            elif label=='missing_cache':_w(p,wrapper+0x10,0)
            elif label=='interior_pointer':target+=1
            elif label in ('wrong_tag','never_issued_slot'):
                chunk=pointer&~_u(p,LIBC+0xE9EC0);page=(pointer-chunk)>>12;bias=_u(p,LIBC+0xE9EB0)
                if label=='wrong_tag':_w(p,chunk+0x68+(page-bias)*8,0)
                else:
                    tag=_u(p,chunk+0x68+(page-bias)*8);slab=chunk+_u(p,LIBC+0xE9EA0)+(page-(tag>>12)-bias)*96+16
                    class_id=(tag>>4)&255;row=LIBC+0xE9120+class_id*96
                    start=chunk+((page-(tag>>12))<<12)+_u(p,row+0x58,4)
                    slot=(pointer-start)//_u(p,row+0x10)
                    _w(p,slab+8+(slot>>6)*8,_u(p,slab+8+(slot>>6)*8)|(1<<(slot&63)))
            elif label=='already_cached':
                class_id=cache.region._size_index(p,LIBC,17);bin_address=_u(p,wrapper+0x10)+class_id*32
                count=_u(p,bin_address+0x30,4);_w(p,_u(p,bin_address+0x38)+count*8,pointer);_w(p,bin_address+0x30,count+1,4)
            elif label=='unmapped_payload':p.pop(pointer>>12)
            else:size=-1
            before={k:bytes(v) for k,v in p.items()}
            try:cache.reallocate_same_small_bin(p,pointer=target,request_size=size,libc_base=LIBC,thread_pointer=WORKER_TLS)
            except (allocator.RefillUnsupported,ValueError):pass
            else:raise AssertionError('same-bin guard accepted '+label)
            assert before=={k:bytes(v) for k,v in p.items()}
            rows.append(dict(image_base=hex(image),case=label,rejected=True,all_pages_unchanged=True))
    return rows

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--library',type=Path,required=True);ap.add_argument('--libc',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True);ap.add_argument('--group',choices=('red','same_bin','guards','all'),default='all');a=ap.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==LIBRARY_SHA256
    assert hashlib.sha256(a.libc.read_bytes()).hexdigest()==LIBC_SHA256
    cases=[];negative=[]
    if a.group=='red':
        assert not hasattr(cache,'reallocate_same_small_bin')
        for image in BASES:
            p,pointer,width=seed(a.library,a.libc,image,19);returned,observed,entries=native(p,pointer,20)
            assert returned==pointer
            cases.append(dict(image_base=hex(image),original_export_and_body_returned=True,
                previous_owner_missing=True,native_snapshot_input=False))
    if a.group in ('same_bin','all'):
        for image in BASES:
            for old,new in PROFILES:cases.append(compare(a.library,a.libc,image,old,new))
            cases.append(compare(a.library,a.libc,image,32,25,True))
    if a.group in ('guards','all'):negative=guards(a.library,a.libc)
    a.output.write_text(json.dumps(dict(component='Matching-libc same small-bin realloc',cases=cases,
        negative_cases=negative,native_Python_controls=len(cases),rollback_guards=len(negative),
        native_input_snapshot_used=False,Python_owned_allocator_state=True,whole_physical_stack_bytes_compared=False,
        cross_bin_realloc_verified=False,NULL_or_zero_realloc_verified=False,
        whole_request_native_differential_verified=False,actual_URL_header_JNI_conversion_verified=False,
        live_Android_JVM_verified=False,complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS',a.group,len(cases),'native controls',len(negative),'rollback guards',flush=True)
if __name__=='__main__':main()
