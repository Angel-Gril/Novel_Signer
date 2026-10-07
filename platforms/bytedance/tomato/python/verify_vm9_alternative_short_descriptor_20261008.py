"""Fresh short-name hash and descriptor selector versus actual ARM64 bodies.

The root array/hash buckets are synthetic data, not an initialized native
module. The real constructor's two-byte selector comes directly from ELF.
No native output is used as a Python input or exported process snapshot.
"""
from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path
from unicorn import arm64_const as arm
from vm9_allocator import RefillUnsupported, _read_span, _write_span
from verify_vm9_signer_objects import GUEST, LIBRARY_SHA256, fresh_pages, image_pages, native
import vm9_alternative_startup as alternative

SP=GUEST+0xEF00
ROOT, ARRAY, BUCKETS, HEAD, FIRST, SECOND, NAME, HEAP = (GUEST+n for n in (0x2000,0x2200,0x2300,0x2400,0x2500,0x2600,0x2700,0x2800))


def put(p,a,v,n=8):_write_span(p,a,v.to_bytes(n,'little'))


def fixture(library,base,payload,buckets,mode,*,long_key=False):
    p=fresh_pages();p.update(image_pages(library,base))
    _write_span(p,NAME,payload+b'\0')
    put(p,ROOT,ARRAY);put(p,ROOT+0x20,BUCKETS);put(p,ROOT+0x28,buckets)
    for i in range(max(1,buckets)):put(p,BUCKETS+i*8,0)
    descriptor=GUEST+0x2900;put(p,ARRAY,descriptor);put(p,ARRAY+8,0)
    hashed=alternative.hash_short_descriptor_name(payload)
    bucket=hashed%(buckets or 1)
    put(p,HEAD,FIRST)
    def node(address,next_address,key,index=0,hash_word=hashed):
        put(p,address,next_address);put(p,address+8,hash_word)
        if long_key:
            put(p,address+0x10,0x21);put(p,address+0x18,len(key));put(p,address+0x20,HEAP)
            _write_span(p,HEAP,key+b'\0')
        else:
            _write_span(p,address+0x10,bytes([len(key)*2])+key+b'\0')
        put(p,address+0x28,index)
    node(FIRST,0,payload)
    if buckets and mode!='no_head':put(p,BUCKETS+bucket*8,HEAD)
    if mode=='no_node':put(p,HEAD,0)
    elif mode=='wrong_key':node(FIRST,0,bytes([payload[0]^1])+payload[1:])
    elif mode=='collision':
        node(FIRST,SECOND,bytes([payload[0]^1])+payload[1:]);node(SECOND,0,payload)
    elif mode=='different_bucket':
        node(FIRST,SECOND,payload,hash_word=(hashed+1)&((1<<64)-1));node(SECOND,0,payload)
    elif mode=='null_descriptor':put(p,ARRAY,0)
    expected=descriptor if buckets and mode not in ('no_head','no_node','wrong_key','different_bucket','null_descriptor') else 0
    return p,expected


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--libc',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    a=parser.parse_args();assert hashlib.sha256(a.library.read_bytes()).hexdigest()==LIBRARY_SHA256
    hashes=[];lookups=[];negatives=[]
    for base in (0x122C0000,0x775C205000):
        for n,payload in enumerate([bytes(((i*71+131)&255) for i in range(n)) for n in range(9)]+[b'\xff'*4]):
            p=fresh_pages();p.update(image_pages(a.library,base));_write_span(p,NAME,payload)
            value,memory,alloc,ledger=native(a.library,base,0x2AA744,[GUEST+0x2A00,NAME,len(payload)],p)
            modeled=alternative.hash_short_descriptor_name(payload)
            assert value==modeled and not alloc and not ledger and memory==_read_span(p,GUEST,0xA000)
            hashes.append(dict(image_base_hex=hex(base),case=n,input_length=len(payload),native_python_hash_match=True,
                hash_hex=hex(value),raw_bytes_may_contain_NUL=True,allocation_or_JNI_services_used=False))
    for base in (0x122C0000,0x775C205000):
        seed=image_pages(a.library,base);actual_selector=_read_span(seed,base+0x11FB30,4).split(b'\0',1)[0]
        assert len(actual_selector)==2
        profiles=[('empty',b'',1,'hit',False),('one_high',b'\xff',1,'hit',False),
            ('actual_ctor_selector',actual_selector,3,'hit',False),('two_power',b'ab',8,'hit',False),
            ('three_high',b'\xff'*3,3,'hit',False),('four_shift32',b'\xff'*4,3,'hit',False),
            ('eight_high',b'\xff'*8,8,'hit',False),('long_stored_key',b'ab',3,'hit',True),
            ('null_descriptor',b'a',1,'null_descriptor',False),('zero_buckets',b'a',0,'hit',False),
            ('no_head',b'b',8,'no_head',False),('no_node',b'b',3,'no_node',False),
            ('wrong_key_same_cached_hash',b'ab',3,'wrong_key',False),('collision_then_match',b'ab',8,'collision',False),
            ('next_bucket_boundary',b'ab',3,'different_bucket',False)]
        for label,payload,buckets,mode,long_key in profiles:
            p,expected=fixture(a.library,base,payload,buckets,mode,long_key=long_key)
            address=base+0x11FB30 if label=='actual_ctor_selector' else NAME
            observed={(SP-0x58,len(payload)+2):None};memcmp_calls=[]
            from elftools.elf.elffile import ELFFile
            with a.libc.open('rb') as stream:
                elf=ELFFile(stream)
                cmp_entry=next(0x51000000+s['st_value'] for section in elf.iter_sections() if section['sh_type']=='SHT_DYNSYM'
                    for s in section.iter_symbols() if s.name=='memcmp')
            def compare(cpu):
                values=[cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(3)]
                memcmp_calls.append(values);cpu.reg_write(arm.UC_ARM64_REG_PC,cmp_entry);return None
            value,memory,alloc,ledger=native(a.library,base,0x2A9620,[ROOT,address],p,libc=a.libc,
                host_imports={0x347FE0:compare},observed_memory=observed,instruction_limit=50000)
            modeled=alternative.lookup_short_descriptor(p,root_address=ROOT,name_address=address,entry_stack_address=SP)
            assert value==modeled.descriptor_address==expected,(label,hex(value),hex(modeled.descriptor_address),hex(expected))
            assert memory==_read_span(p,GUEST,0xA000) and not alloc and not ledger
            for (pointer,width),data in observed.items():assert data==_read_span(p,pointer,width),(label,hex(pointer))
            assert bool(memcmp_calls)==long_key
            lookups.append(dict(label=label,image_base_hex=hex(base),query_length=len(payload),bucket_count=buckets,
                stored_long_key=long_key,native_python_return_and_guest_match=True,defined_temporary_SSO_writes_match=True,
                native_memcmp_body_executed=bool(memcmp_calls),visited_nodes=len(modeled.visited_nodes),
                descriptor_is_NULL=value==0,actual_constructor_selector_from_ELF=label=='actual_ctor_selector',
                synthetic_root_and_bucket_inputs_used=True,native_input_snapshot_used=False,full_module_constructor_verified=False))
            print('short descriptor:',hex(base),label,'passed',flush=True)
    base=0x122C0000
    for label in ('unaligned_stack','null_root','name_too_long','excessive_buckets','node_cycle','missing_descriptor_array'):
        p,_=fixture(a.library,base,b'ab',3,'hit');options=dict(root_address=ROOT,name_address=NAME,entry_stack_address=SP)
        if label=='unaligned_stack':options['entry_stack_address']=SP-1
        elif label=='null_root':options['root_address']=0
        elif label=='name_too_long':_write_span(p,NAME,b'123456789\0')
        elif label=='excessive_buckets':put(p,ROOT+0x28,4097)
        elif label=='node_cycle':
            _write_span(p,FIRST+0x11,b'ac');put(p,FIRST,FIRST)
        elif label=='missing_descriptor_array':put(p,ROOT,0)
        before={key:bytes(data) for key,data in p.items()}
        try:alternative.lookup_short_descriptor(p,**options)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError('negative accepted '+label)
        assert before=={key:bytes(data) for key,data in p.items()}
        negatives.append(dict(label=label,guest_pages_rolled_back=True,native_CXX_error_or_wait_path_compared=False))
    e=dict(schema='vm9-alternative-short-descriptor-fresh-v1',evidence_date='2026-10-07',evidence_timezone='UTC',host_trial_label='20261008',
        sample_sha256=LIBRARY_SHA256,matching_libc_sha256=hashlib.sha256(a.libc.read_bytes()).hexdigest(),
        short_hash_controls=len(hashes),lookup_controls=len(lookups),negative_controls=len(negatives),
        hash_cases=hashes,lookup_cases=lookups,negative_checks=negatives,query_length_upper_bound=8,
        uint32_left_shift_before_hash_mix_verified=True,synthetic_root_and_bucket_inputs_used=True,
        actual_constructor_selector_from_ELF_verified=True,native_input_snapshot_used=False,
        full_string_hash_recovered=False,module_factory_2CBDC8_recovered=False,
        descriptor_global_publication_recovered=False,full_B_startup_VM_recovered=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False)
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8')
    print('short descriptor:',len(hashes),'hash;',len(lookups),'lookup;',len(negatives),'negative passed')


if __name__=='__main__':main()
