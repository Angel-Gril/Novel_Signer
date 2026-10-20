"""Original matching dtoa/freedtoa integer path and complete pool pages."""
from pathlib import Path
import sys,json,struct,hashlib
from elftools.elf.elffile import ELFFile
import argparse
parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--library',type=Path,required=True);parser.add_argument('--libc',type=Path,required=True);parser.add_argument('--output',type=Path);args=parser.parse_args()
import verify_vm9_signer_objects as oracle
from vm9_allocator import _read_span,_write_span
from unicorn import arm64_const as arm
from vm9_libc_dtoa import format_bionic_integer
from vm9_outer_allocator import ActualAllocatorSession
assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
assert hashlib.sha256(args.libc.read_bytes()).hexdigest()=='d2376df6d2ac3e0213f85e3614c4c7ad1d28c84c44926058d5c1b95c855563db'
rows=[]
for image in (0x122C0000,0x775C205000):
    L=0x51000000;G=oracle.GUEST
    p=oracle.image_pages(args.libc,L);p.update(oracle.image_pages(args.library,image));p.update(oracle.fresh_pages())
    with (args.libc).open('rb') as stream:
        elf=ELFFile(stream)
        for section in elf.iter_sections():
            if section['sh_type']!='SHT_RELA':continue
            symbols=elf.get_section(section['sh_link'])
            for relocation in section.iter_relocations():
                kind=relocation['r_info_type'];symbol=symbols.get_symbol(relocation['r_info_sym'])
                if kind==1027:target=L+relocation['r_addend']
                elif kind in (257,1025,1026) and symbol['st_shndx']!='SHN_UNDEF':target=L+symbol['st_value']+relocation['r_addend']
                else:continue
                _write_span(p,L+relocation['r_offset'],target.to_bytes(8,'little'))
    _write_span(p,L+0xDF1E0,bytes([0xA5])*2304)
    model={k:bytearray(v) for k,v in p.items()}
    values=[([],v) for v in (0.0,-0.0,1.0,-1.0,16777216.0,123456789.0,999999999.0,-999999999.0)]
    fresh={k:bytes(v) for k,v in p.items()}
    session=ActualAllocatorSession.__new__(ActualAllocatorSession);session.libc_base=L
    def native(offset,native_args,extra=None):
        watch={(L+0xDA000,4096):None,(L+0xDF000,4096):None,(G+0x3000,0x40):None}
        result,_,allocation,ledger=oracle.native(args.library,image,L+offset-image,native_args,p,
            libc=args.libc,extra_registers=extra or {},observed_memory=watch,instruction_limit=100000)
        assert not allocation and not ledger
        for (address,width),data in watch.items():_write_span(p,address,data)
        return result
    for path,value in values:
        expected=session.format_number(model,value,15)
        result=native(0x40888,[2,15,G+0x3000,G+0x3004,G+0x3008],{arm.UC_ARM64_REG_D0:struct.unpack('<Q',struct.pack('<d',value))[0]})
        pointer=result;digits=bytearray()
        while _read_span(p,pointer+len(digits),1)!=b'\0':digits.extend(_read_span(p,pointer+len(digits),1));assert len(digits)<32
        native(0x40708,[pointer])
        sign=int.from_bytes(_read_span(p,G+0x3004,4),'little')
        decpt=int.from_bytes(_read_span(p,G+0x3000,4),'little',signed=True)
        text=(b'-' if sign else b'')+bytes(digits)+b'0'*max(0,decpt-len(digits))
        assert text==expected
        assert all(_read_span(model,L+off,4096)==_read_span(p,L+off,4096) for off in (0xDA000,0xDF000)), 'numeric pool state differs'
        row=dict(image_base=hex(image),value=value,digits=digits.decode(),negative_zero_preserved=value==0 and sign==1,complete_two_pool_pages_equal=True,seeded_pool_padding_preserved=True)
        rows.append(row)
guards=[]
from vm9_allocator import RefillUnsupported

def reject(label,edit=lambda p:None,number=1.0,precision=15,base=L):
    p={k:bytearray(v) for k,v in fresh.items()};edit(p);before={k:bytes(v) for k,v in p.items()}
    try:format_bionic_integer(p,number=number,precision=precision,libc_base=base)
    except (RefillUnsupported,ValueError):pass
    else:raise AssertionError('numeric service accepted '+label)
    assert before=={k:bytes(v) for k,v in p.items()},label
    guards.append(label)
def word(p,a,v,n=8):_write_span(p,a,v.to_bytes(n,'little'))
for label,value in (('bool',True),('integer_type',1),('fraction',1.25),('inf',float('inf')),('nan',float('nan')),('positive_bound',1e9),('negative_bound',-1e9)):
    reject(label,number=value)
reject('precision17',precision=17);reject('boolean_precision',precision=True)
reject('unaligned_base',base=L+1);reject('overflowing_base',base=1<<64)
reject('lock_binding',lambda p:word(p,L+0xD8FC0,L+0xDF190))
reject('held_mutex',lambda p:word(p,L+0xDF188,1,2))
reject('unmapped_pool_cursor',lambda p:word(p,L+0xDA110,0x66000000))
reject('pool_heap_fallback',lambda p:word(p,L+0xDA110,L+0xDFAE0))
reject('foreign_free_block',lambda p:word(p,L+0xDFAE8,0x66000000))
def corrupt_class(p):word(p,L+0xDFAE8,L+0xDF1E0);word(p,L+0xDF1E8,0,4)
reject('free_block_class',corrupt_class)
def cycle(p):
    word(p,L+0xDFAE8,L+0xDF1E0);word(p,L+0xDF1E0,L+0xDF1E0);word(p,L+0xDF1E8,1,4);word(p,L+0xDF1EC,2,4)
reject('cyclic_free_list',cycle)
reject('missing_lock_page',lambda p:p.pop((L+0xD8000)>>12))
reject('missing_pmem_page',lambda p:p.pop((L+0xDA000)>>12))
# New provider failures run through the real JSON printer transaction.
from verify_vm9_json_print_fresh_20261018 import fixture,service,SP
from vm9_json_print import print_json_unformatted
for label,value in (('not_bytes','1'),('empty',b''),('nul',b'1\0'),('nan_text',b'nan'),('leading_plus',b'+1'),('leading_zero',b'01'),('overflow_text',b'1e999')):
    p,root=fixture(args.library,args.libc,image,'number');s=service('number');before={k:bytes(v) for k,v in p.items()}
    def bad(tx,number,precision):_write_span(tx,G+0x5000,b'visible-only-if-committed');return value
    try:print_json_unformatted(p,node_address=root,entry_stack_address=SP,image_base=image,allocate=s.malloc,free=s.free,format_number=bad)
    except RefillUnsupported:pass
    else:raise AssertionError(label)
    assert before=={k:bytes(v) for k,v in p.items()};guards.append('JSON_'+label)
import vm9_request_vm as request
try:request.execute_request_vm({}, {}, None, 0, 0, format_number=False)
except RefillUnsupported:guards.append('public_entry_noncallable_formatter')
else:raise AssertionError('public entry accepted bad formatter')
p,root=fixture(args.library,args.libc,image,'number');s=service('number')
before={k:bytes(v) for k,v in p.items()}
try:print_json_unformatted(p,node_address=root,entry_stack_address=SP,image_base=image,
    allocate=s.malloc,free=s.free,format_number=False)
except RefillUnsupported:guards.append('JSON_noncallable_formatter')
else:raise AssertionError('JSON printer accepted bad formatter')
assert before=={k:bytes(v) for k,v in p.items()} and not s.events
p,root=fixture(args.library,args.libc,image,'precise');s=service('precise')
out=print_json_unformatted(p,node_address=root,entry_stack_address=SP,image_base=image,
    allocate=s.malloc,free=s.free)
assert _read_span(p,out,19)==b'1.2345678901234567\0'
result=dict(native_Python_controls=len(rows),cases=rows,refusal_or_page_rollback_guards=len(guards),guards=guards,
    complete_two_pool_pages_equal=True,native_output_used_as_model_input=False,historical_native_groups_replayed=False,
    default_precise_number_path_preserved=True,complete_physical_ABI_verified=False,external_provider_effect_rollback_verified=False)
if args.output:args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
print(json.dumps({k:v for k,v in result.items() if k not in ('cases','guards')}))
