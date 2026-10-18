"""Exact second VM byte fills against the matching native libc memset."""
from pathlib import Path
import argparse,hashlib,inspect,json
from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
from vm9_allocator import _read_span,_write_span,RefillUnsupported
import vm9_request_287474_vm as second

LIBC_SHA256='d2376df6d2ac3e0213f85e3614c4c7ad1d28c84c44926058d5c1b95c855563db'
G=oracle.GUEST;SP=G+0xEF00;LIBC_BASE=0x51000000;BASES=(0x122C0000,0x775C205000)
LENGTHS=(0,1,15,16,17,31,32,33,63,64,65,127,128,129,192)
PROFILES=tuple('n'+str(n) for n in LENGTHS)+('fill_FF','cross_packed','cross_output',
    'large','max_bound','zero_NULL','zero_unmapped','zero_uint64_max','zero_spill')
GUARDS=('wrong_target','packed_wrap','packed_unmapped','packed_late_missing','packed_truncated',
    'output_NULL','output_wrap','output_unmapped','output_late_missing','output_truncated',
    'packed_alias','packed_spill','output_spill','unaligned_stack','wrapped_stack',
    'size_bound','size_u64_high','invalid_bound_negative','invalid_bound_large','invalid_bound_bool')


def w(p,a,v,n=8):_write_span(p,a,(v&((1<<(n*8))-1)).to_bytes(n,'little'))


def memset_export(libc):
    assert hashlib.sha256(libc.read_bytes()).hexdigest()==LIBC_SHA256
    with libc.open('rb') as stream:
        elf=ELFFile(stream)
        rows=[s for s in elf.get_section_by_name('.dynsym').iter_symbols()
            if s.name=='memset' and s['st_shndx']!='SHN_UNDEF' and s['st_info']['type']=='STT_FUNC']
    assert len(rows)==1 and rows[0]['st_value']==0x1C640
    return LIBC_BASE+rows[0]['st_value']


def native_memset(library,libc,image,block,pages,**kwargs):
    """Disable only the old memset substitution in an isolated oracle copy.

    The exact wrapper tailcalls its PLT boundary, explicitly redirected to
    the ELF-resolved matching libc export. Accepted oracle owners stay intact.
    """
    raw=inspect.getsource(oracle.native)
    old='elif offset == 0x347F20:';assert raw.count(old)==1
    raw=raw.replace(old,'elif False and offset == 0x347F20:')
    marker='    cpu.mem_write(GUEST, flatten(pages))';assert raw.count(marker)==1
    raw=raw.replace(marker,marker+'''
    mapped={page for start,end,prot in cpu.mem_regions() for page in range(start>>12,(end>>12)+1)}
    for page in pages:
        if page not in mapped:cpu.mem_map(page<<12,4096);mapped.add(page)''')
    ns=dict(vars(oracle));exec(compile(raw,'explicit-native-memset-oracle','exec'),ns)
    target=memset_export(libc);imports=dict(kwargs.pop('host_imports',{}))
    def redirect(cpu):cpu.reg_write(arm.UC_ARM64_REG_PC,target)
    imports[0x347F20]=redirect
    return ns['native'](library,image,0x288AB4,[block],pages,libc=libc,host_imports=imports,**kwargs)


def fixture(library,image,label):
    p=oracle.fresh_pages();p.update(oracle.image_pages(library,image))
    block=G+(0x1FF0 if label=='cross_packed' else 0x1000)
    out=G+(0x2FF9 if label=='cross_output' else 0x2103)
    size=int(label[1:]) if label.startswith('n') else 192
    fill=0xFF if label=='fill_FF' else 0x80
    if label=='large':size=8193
    if label=='max_bound':
        out=0x66010000;size=0x100000
        p.update({a>>12:bytearray(b'\x5A'*4096) for a in range(out,out+size,4096)})
    if label.startswith('zero_'):
        size=0;out={'zero_NULL':0,'zero_unmapped':0x66000000,'zero_uint64_max':(1<<64)-1,'zero_spill':SP-1}[label]
    _write_span(p,block,b''.join(v.to_bytes(8,'little') for v in
        (image+0x347F20,out,0xFEDCBA9876543200|fill,size))+b'\x5A'*8)
    return p,block,out,size


def invoke(p,image,block,changes=None):
    kw=dict(argument_block_address=block,entry_stack_address=SP,image_base=image)
    kw.update(changes or {})
    return second.apply_request_287474_memory_fill_callback(p,**kw)


def compare(library,libc,image,label):
    p,block,out,size=fixture(library,image,label);packed=_read_span(p,block,40)
    watch={(a<<12,4096):None for a in p if not G<=a<<12<G+0x10000}
    watch.update({(G,SP-G-0x1000):None,(SP,G+0x10000-SP):None})
    steps=[0];minimum=[SP];seen=set();entry=memset_export(libc)
    def observe(cpu,a):
        steps[0]+=1;minimum[0]=min(minimum[0],cpu.reg_read(arm.UC_ARM64_REG_SP));seen.add(a)
    x0,_,allocations,events=native_memset(library,libc,image,block,p,
        extra_registers={arm.UC_ARM64_REG_SP:SP},observed_memory=watch,
        instruction_observer=observe,instruction_limit=200000)
    result=invoke(p,image,block)
    for (a,n),raw in watch.items():assert _read_span(p,a,n)==raw,(label,hex(a))
    assert result==out==x0 and _read_span(p,block,40)==packed and not allocations and not events
    assert {image+0x288AB4,image+0x347F20,entry}<=seen and minimum[0]==SP
    print('PASS memory fill',hex(image),label,steps[0],flush=True)
    return dict(image_base=hex(image),case=label,steps=steps[0],native_stack_bytes=SP-minimum[0],
        original_wrapper_and_actual_libc_memset_returned=True,oracle_memset_stub_disabled=True,
        declared_nonstack_memory_equal=True,packed_bytes_unchanged=True,no_allocator_or_service_effects=True,
        native_snapshot_input=False,native_physical_X0_compared=True,complete_physical_ABI_verified=False)


def guards(library):
    rows=[];image=BASES[0]
    for label in GUARDS:
        p,block,out,size=fixture(library,image,'n192');changes={}
        if label=='wrong_target':w(p,block,image+1)
        elif label=='packed_wrap':block=(1<<64)-8
        elif label=='packed_unmapped':block=0x66000000
        elif label=='packed_late_missing':block=G+0x1FFF;del p[(G+0x2000)>>12]
        elif label=='packed_truncated':p[block>>12]=p[block>>12][:16]
        elif label in ('output_NULL','output_wrap','output_unmapped'):
            w(p,block+8,{'output_NULL':0,'output_wrap':(1<<64)-2,'output_unmapped':0x66000000}[label])
        elif label=='output_late_missing':w(p,block+8,G+0x2FF0);del p[(G+0x3000)>>12]
        elif label=='output_truncated':p[out>>12]=p[out>>12][:0x200]
        elif label=='packed_alias':w(p,block+8,block)
        elif label=='packed_spill':_write_span(p,SP-32,_read_span(p,block,32));block=SP-32
        elif label=='output_spill':w(p,block+8,SP-0x1000)
        elif label=='unaligned_stack':changes['entry_stack_address']=SP-1
        elif label=='wrapped_stack':changes['entry_stack_address']=1<<64
        elif label=='size_bound':changes['max_bytes']=size-1
        elif label=='size_u64_high':w(p,block+24,1<<32)
        elif label=='invalid_bound_negative':changes['max_bytes']=-1
        elif label=='invalid_bound_large':changes['max_bytes']=0x100001
        elif label=='invalid_bound_bool':changes['max_bytes']=True
        before={k:bytes(v) for k,v in p.items()}
        try:invoke(p,image,block,changes)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError((label,'accepted'))
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
    return rows


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--library',type=Path,required=True);ap.add_argument('--libc',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    memset_export(args.libc)
    rows=[compare(args.library,args.libc,image,label) for image in BASES for label in PROFILES]
    negative=guards(args.library)
    args.output.write_text(json.dumps(dict(component='Second byte-fill wrapper with actual libc memset',
        native_Python_controls=len(rows),rollback_guards=len(negative),cases=rows,negative_cases=negative,
        library_sha256=oracle.LIBRARY_SHA256,matching_libc_sha256=LIBC_SHA256,
        oracle_memset_stub_disabled=True,native_snapshot_input=False,complete_signer_verified=False,
        physical_ABI_verified=False),indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS memory fill',len(rows),'controls',len(negative),'guards',flush=True)


if __name__=='__main__':main()
