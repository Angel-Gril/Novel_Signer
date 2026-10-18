"""Original second-VM wrapper calling the explicit matching-libc lock import."""
from pathlib import Path
import argparse,hashlib,json
from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
import vm9_request_287474_vm as second
from vm9_allocator import _PageTransaction,_read_span,_write_span,RefillUnsupported

G=oracle.GUEST;SP=G+0xEF00;LIBC_BASE=0x51000000
BASES=(0x122C0000,0x775C205000)
PROFILES=('private','shared','cross_packed','page_tail','image_mutex',
    'packed_result_mutex','packed_receiver_mutex')
GUARDS=('missing_binding','NULL_binding','boolean_binding','unaligned_binding','wrapped_binding',
    'wrong_target','NULL_target','NULL_mutex','odd_mutex','wrapped_mutex','unmapped_mutex',
    'locked','contended','recursive','errorcheck','destroyed','unaligned_stack','wrapped_stack',
    'invalid_packed','wrapped_packed','partial_output','packed_spill','mutex_spill','mutex_spill_tail')

def w(p,a,v,n=8):_write_span(p,a,v.to_bytes(n,'little'))

def resolve_lock_import(pages,library,libc,image,libc_base=LIBC_BASE):
    """Explicit fixture loader input from ELF symbol/relocation tables, not execution."""
    with libc.open('rb') as stream:
        elf=ELFFile(stream)
        exports=[libc_base+s['st_value'] for s in elf.get_section_by_name('.dynsym').iter_symbols()
            if s.name=='pthread_mutex_lock' and s['st_shndx']!='SHN_UNDEF']
    assert len(exports)==1
    target=exports[0];rows=[];tx=_PageTransaction(pages)
    with library.open('rb') as stream:
        elf=ELFFile(stream)
        for section in elf.iter_sections():
            if section['sh_type']!='SHT_RELA':continue
            symbols=elf.get_section(section['sh_link'])
            for rel in section.iter_relocations():
                if symbols.get_symbol(rel['r_info_sym']).name!='pthread_mutex_lock':continue
                assert rel['r_info_type'] in (257,1025,1026) and rel['r_addend']==0
                w(tx,image+rel['r_offset'],target)
                rows.append(dict(symbol='pthread_mutex_lock',relocation_offset=hex(rel['r_offset']),
                    relocation_kind=rel['r_info_type'],libc_export_offset=hex(target-libc_base)))
    assert {r['relocation_offset'] for r in rows}>={'0x379748','0x382eb8','0x383350'}
    tx.commit();return {'pthread_mutex_lock':target},rows

def fixture(library,libc,image,label):
    p=oracle.fresh_pages();p.update(oracle.image_pages(library,image))
    bindings,rows=resolve_lock_import(p,library,libc,image)
    block=G+(0x1FF0 if label=='cross_packed' else 0x1000)
    mutex=image+0x3DF1EC if label=='image_mutex' else G+(0x2FFE if label=='page_tail' else 0x2000)
    if label=='packed_result_mutex':mutex=block+16
    elif label=='packed_receiver_mutex':block=G+0x1FF8;mutex=block+8
    _write_span(p,block,b''.join(v.to_bytes(8,'little') for v in (bindings['pthread_mutex_lock'],mutex))+b'\xA5'*24)
    if label!='packed_receiver_mutex':
        w(p,mutex,0x2000 if label=='shared' else 0,2)
    return p,block,mutex,bindings,rows

def original(library,libc,image,p,block,bindings,sp=SP):
    steps=[0];seen=set();minimum_sp=[sp]
    watch={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000}
    def observe(cpu,a):
        steps[0]+=1;seen.add(a);minimum_sp[0]=min(minimum_sp[0],cpu.reg_read(arm.UC_ARM64_REG_SP))
    result,memory,allocations,ledger=oracle.native(library,image,0x2889A8,[block],p,
        libc=libc,real_mutexes=True,instruction_observer=observe,observed_memory=watch,
        extra_registers={arm.UC_ARM64_REG_SP:sp},instruction_limit=1000)
    assert image+0x2889A8 in seen and bindings['pthread_mutex_lock'] in seen and not allocations and not ledger
    assert minimum_sp[0]==sp-48 and result==0,(minimum_sp[0],sp,result)
    return memory,watch,steps[0]

def compare(library,libc,image,label):
    data=fixture(library,libc,image,label)
    assert data is not None
    p,block,mutex,bindings,rows=data
    before=_read_span(p,block,40)
    memory,watch,steps=original(library,libc,image,p,block,bindings)
    callback=getattr(second,'apply_request_287474_mutex_lock_callback',None)
    assert callable(callback),'original pthread_mutex_lock wrapper returned, but the second callback is missing'
    result=callback(p,argument_block_address=block,entry_stack_address=SP,import_bindings=bindings)
    assert result==0 and _read_span(p,G,0xA000)==memory
    assert all(_read_span(p,a,n)==v for (a,n),v in watch.items())
    # Receiver aliases may change loaded input bytes; the original full-memory oracle covers them.
    if label not in ('packed_receiver_mutex',):assert _read_span(p,block,16)==before[:16]
    assert _read_span(p,block+16,4)==bytes(4) and _read_span(p,block+20,20)==before[20:]
    print('PASS mutex lock',hex(image),label,flush=True)
    return dict(image_base=hex(image),case=label,steps=steps,
        original_wrapper_and_matching_libc_lock_returned=True,all_guest_and_image_bytes_equal=True,
        exact_four_byte_result_and_alias_order_equal=True,explicit_ELF_import_input=True,
        minimum_stack_displacement=48,native_snapshot_input=False,
        atomicity_or_host_concurrency_verified=False,complete_physical_ABI_verified=False)

def guards(library,libc):
    rows=[];image=BASES[0]
    for label in GUARDS:
        p,block,mutex,bindings,_=fixture(library,libc,image,'private')
        kw=dict(argument_block_address=block,entry_stack_address=SP,import_bindings=bindings)
        if label=='missing_binding':kw['import_bindings']=None
        elif label in ('NULL_binding','boolean_binding','unaligned_binding','wrapped_binding'):
            kw['import_bindings']={'pthread_mutex_lock':{'NULL_binding':0,'boolean_binding':True,
                'unaligned_binding':bindings['pthread_mutex_lock']+1,'wrapped_binding':1<<64}[label]}
        elif label in ('wrong_target','NULL_target'):w(p,block,0 if label=='NULL_target' else bindings['pthread_mutex_lock']+4)
        elif label in ('NULL_mutex','odd_mutex','wrapped_mutex','unmapped_mutex'):
            w(p,block+8,{'NULL_mutex':0,'odd_mutex':mutex+1,'wrapped_mutex':(1<<64)-1,'unmapped_mutex':0x66000000}[label])
        elif label in ('locked','contended','recursive','errorcheck','destroyed'):
            w(p,mutex,{'locked':1,'contended':2,'recursive':0x4000,'errorcheck':0x8000,'destroyed':0xFFFF}[label],2)
        elif label=='unaligned_stack':kw['entry_stack_address']-=1
        elif label=='wrapped_stack':kw['entry_stack_address']=1<<64
        elif label=='invalid_packed':kw['argument_block_address']=0
        elif label=='wrapped_packed':kw['argument_block_address']=(1<<64)-16
        elif label=='partial_output':
            kw['argument_block_address']=G+0x9FEE;_write_span(p,G+0x9FEE,_read_span(p,block,16));del p[(G+0xA000)>>12]
        elif label=='packed_spill':
            kw['argument_block_address']=SP-16;_write_span(p,SP-16,_read_span(p,block,20))
        elif label in ('mutex_spill','mutex_spill_tail'):
            m=SP-48 if label=='mutex_spill_tail' else SP-2;w(p,block+8,m);w(p,m,0,2)
        before={k:bytes(v) for k,v in p.items()}
        try:second.apply_request_287474_mutex_lock_callback(p,**kw)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_model_pages_unchanged=True))
        print('PASS mutex refusal',label,flush=True)
    return rows

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--library',type=Path,required=True);ap.add_argument('--libc',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True);ap.add_argument('--mode',choices=('red','native','guards'),default='native')
    a=ap.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(a.libc.read_bytes()).hexdigest()=='d2376df6d2ac3e0213f85e3614c4c7ad1d28c84c44926058d5c1b95c855563db'
    e=dict(cases=[],negative_cases=[])
    if a.mode=='guards':e['negative_cases']=guards(a.library,a.libc)
    else:
        for image in BASES:
            for label in (('private',) if a.mode=='red' else PROFILES):
                e['cases'].append(compare(a.library,a.libc,image,label))
                a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
    a.output.write_text(json.dumps(dict(e,native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']),
        native_input_snapshot_used=False,complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8',newline='\n')
if __name__=='__main__':main()
