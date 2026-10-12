"""Fresh matching-libc random state and serialized rand/srand controls.

Both ELF relocation inputs and the PRNG state are independently constructed.
Only offsets, counts and equality results are published; full signing is open.
"""
from pathlib import Path
import argparse,hashlib,json
from elftools.elf.elffile import ELFFile
import verify_vm9_signer_objects as oracle
from verify_vm9_libc_mapping import LIBC_SHA256
from vm9_allocator import _read_span,_write_span,RefillUnsupported

BASES=(0x51000000,0x6112300000)
STATE=oracle.GUEST+0x4000
OWNERS=('step_bionic_random_state','seed_bionic_random_state','bionic_random','bionic_srandom')


def w(p,a,v,n=8):_write_span(p,a,(v&((1<<(8*n))-1)).to_bytes(n,'little'))


def fresh(libc,base,label):
    p=oracle.image_pages(libc,base);p.update(oracle.fresh_pages())
    # Internal ABS64/GLOB_DAT/JUMP_SLOT imports are loader inputs, never native output.
    with libc.open('rb') as stream:
        elf=ELFFile(stream)
        for section in elf.iter_sections():
            if section['sh_type']!='SHT_RELA':continue
            symbols=elf.get_section(section['sh_link'])
            for rel in section.iter_relocations():
                if rel['r_info_type'] not in (257,1025,1026):continue
                symbol=symbols.get_symbol(rel['r_info_sym'])
                if symbol['st_shndx']!='SHN_UNDEF':w(p,base+rel['r_offset'],base+symbol['st_value']+rel['r_addend'])
    degree=31;separation=3;seed=1;state=STATE
    if label=='seed_zero':seed=0
    elif label=='seed_highbit':seed=0x80000000
    elif label=='seed_all_bits':seed=0xFFFFFFFF
    elif label=='wide_seed':seed=0x123456789ABCDEF0
    elif label=='degree_one':degree=1;separation=0
    elif label=='degree_seven':degree=7
    elif label=='degree_fifteen':degree=15;separation=1
    elif label=='degree_sixty_three':degree=63;separation=1
    elif label=='degree_zero':degree=0;separation=0
    elif label=='degree_negative':degree=-1;separation=0
    elif label=='cross_page_state':state=oracle.GUEST+0x4FFC
    kind=0 if label=='type_zero' else 3
    if label=='other_nonzero_type':kind=99
    w(p,base+0xDA178,kind,4);w(p,base+0xDA230,degree,4);w(p,base+0xDA218,separation,4)
    w(p,base+0xDA210,state);w(p,base+0xDA228,state+max(degree,1)*4)
    w(p,base+0xDA220,state+separation*4);w(p,base+0xDA180,state)
    _write_span(p,state,bytes((i*53+7)&255 for i in range(max(degree,1)*4)))
    if label=='front_wrap':w(p,base+0xDA220,state+(degree-1)*4)
    elif label=='rear_wrap':w(p,base+0xDA180,state+(degree-1)*4)
    elif label=='front_rear_alias':w(p,base+0xDA180,state+separation*4)
    elif label=='front_state_pointer_alias':w(p,base+0xDA220,base+0xDA210);w(p,base+0xDA228,base+0xDA240)
    elif label=='shared_mutex':w(p,base+0xDFB30,0x2000,2)
    return p,seed


def original(libc,base,p,operation,seed):
    offsets={'step':0x487A8,'seed':0x4884C,'random':0x48CE8,'srandom':0x48934}
    watch={(page<<12,4096):None for page in p if base<=page<<12<base+0x100000}
    returned,memory,allocations,services=oracle.native(libc,base,offsets[operation],
        [seed] if operation in ('seed','srandom') else [],p,
        observed_memory=watch,instruction_limit=100000)
    assert not allocations and not services
    return returned,memory,watch


def red(libc):
    import importlib.util
    assert importlib.util.find_spec('vm9_request_random') is None
    rows=[]
    for base in BASES:
        p,seed=fresh(libc,base,'seed_highbit')
        returned,memory,watch=original(libc,base,p,'srandom',seed)
        assert _read_span(p,oracle.GUEST,0xA000)!=memory or any(_read_span(p,a,n)!=raw for (a,n),raw in watch.items())
        rows.append(dict(libc_base=hex(base),original_seed_wrapper_returned=True,
            prior_independent_random_owner_missing=True,native_snapshot_input=False))
    return rows


def compare(libc,base,operation,label):
    import vm9_request_random as model
    p,seed=fresh(libc,base,label)
    returned,memory,watch=original(libc,base,p,operation,seed)
    functions={'step':model.step_bionic_random_state,'seed':model.seed_bionic_random_state,
        'random':model.bionic_random,'srandom':model.bionic_srandom}
    kw=dict(libc_base=base)
    if operation in ('seed','srandom'):kw['seed_u32']=seed
    result=functions[operation](p,**kw)
    assert _read_span(p,oracle.GUEST,0xA000)==memory,(operation,label,'guest')
    for (a,n),raw in watch.items():
        current=_read_span(p,a,n)
        if current!=raw:
            i=next(i for i,(x,y) in enumerate(zip(current,raw)) if x!=y)
            raise AssertionError((operation,label,'libc',hex(a-base+i),current[i],raw[i]))
    if operation in ('step','random'):assert returned==result,(label,returned,result)
    print('PASS random',hex(base),operation,label,flush=True)
    return dict(libc_base=hex(base),operation=operation,case=label,original_returned=True,
        full_guest_and_libc_bytes_equal=True,defined_random_return_equal=True,
        cached_pointer_and_live_alias_semantics_equal=True,
        actual_serial_libc_mutexes=operation in ('random','srandom'),native_snapshot_input=False)


def profiles():
    return ([('step',n) for n in ('default','type_zero','other_nonzero_type','front_wrap','rear_wrap',
        'front_rear_alias','front_state_pointer_alias','cross_page_state')]+
        [('seed',n) for n in ('default','seed_zero','seed_highbit','seed_all_bits','wide_seed',
        'degree_one','degree_seven','degree_fifteen','degree_sixty_three','degree_zero','degree_negative','cross_page_state')]+
        [('random',n) for n in ('default','type_zero','front_wrap','shared_mutex')]+
        [('srandom',n) for n in ('default','type_zero','seed_zero','seed_highbit','shared_mutex')])


def guards(libc):
    import vm9_request_random as model
    rows=[]
    for label in ('missing_state','unmapped_pointer','seed_bound','warmup_bound','contended_mutex','bad_bound','invalid_base'):
        p,seed=fresh(libc,BASES[0],'default');operation='seed';kw=dict(libc_base=BASES[0],seed_u32=seed)
        if label=='missing_state':del p[(BASES[0]+0xDA000)>>12]
        elif label=='unmapped_pointer':w(p,BASES[0]+0xDA210,0x66000000)
        elif label=='seed_bound':kw['max_degree']=1
        elif label=='warmup_bound':kw['max_warmup_steps']=1
        elif label=='contended_mutex':operation='srandom';w(p,BASES[0]+0xDFB30,1,2)
        elif label=='bad_bound':kw['max_degree']=0
        elif label=='invalid_base':kw['libc_base']=-1
        before={k:bytes(v) for k,v in p.items()}
        try:(model.bionic_srandom if operation=='srandom' else model.seed_bionic_random_state)(p,**kw)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in p.items()}
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True))
    return rows


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--libc',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--group',choices=('red','native','guards','all'),default='all');args=ap.parse_args()
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==LIBC_SHA256
    e=dict(schema='vm9-request-random-fresh-v1',evidence_date='2026-10-13',libc_sha256=LIBC_SHA256,
        cases=[],negative_cases=[],native_snapshot_input=False,private_names_or_payloads_published=False,
        whole_physical_stack_bytes_compared=False,whole_request_native_differential_verified=False,
        actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False,
        request_random_getter_integrated=False)
    if args.group=='red':e['red_cases']=red(args.libc)
    if args.group in ('native','all'):e['cases']=[compare(args.libc,b,op,n) for b in BASES for op,n in profiles()]
    if args.group in ('guards','all'):e['negative_cases']=guards(args.libc)
    e.update(native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']))
    args.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS random',args.group,e['native_Python_controls'],e['rollback_guards'])


if __name__=='__main__':main()
