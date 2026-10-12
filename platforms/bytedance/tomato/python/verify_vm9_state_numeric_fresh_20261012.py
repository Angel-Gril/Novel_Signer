"""Fresh native state member lookup and signed-W numeric conversion controls.

Original node traversal, floating-point conversion and matching-libc normal
mutex operations execute on independently built linked-node inputs.
"""
from pathlib import Path
import argparse, hashlib, json, math, struct
from unicorn import arm64_const as arm
import vm9_state as state
import vm9_objects as objects
import verify_vm9_signer_objects as oracle
from verify_vm9_libc_mapping import LIBC_SHA256
from vm9_allocator import _read_span, _write_span, RefillUnsupported

G=oracle.GUEST;SERVICE=G+0x1000;MUTEX=G+0x1400;ROOT=G+0x1800
KEY=G+0x2000;DATA=G+0x2800;NODE=G+0x3000;BASES=(0x122C0000,0x775C205000)


def profiles():
    rows=[(name,dict(value=value)) for name,value in (
        ('zero',0.0),('positive_fraction',17.75),('negative_fraction',-17.75),
        ('negative_one',-1.0),('negative_zero',-0.0),('small_positive',0.999),
        ('small_negative',-0.999),('signed_max',2147483647.0),
        ('signed_min',-2147483648.0),('upper_saturation',2147483648.0),
        ('lower_saturation',-2147483649.0),('huge_positive',1e300),
        ('huge_negative',-1e300),('positive_infinity',float('inf')),
        ('negative_infinity',float('-inf')),('nan',float('nan')))]
    rows.extend((name,dict(value=31.5,**options)) for name,options in (
        ('missing_key',dict(query=b'missing')),('casefold',dict(query=b'SyNtHeTiC')),
        ('empty_key',dict(query=b'',names=(b'',))),
        ('NULL_root',dict(null_root=True)),('NULL_key_payload',dict(null_key=True)),
        ('NULL_node_key',dict(names=(None,b'synthetic'))),
        ('list_tail_hit',dict(names=(b'first',b'second',b'synthetic'))),
        ('first_duplicate',dict(names=(b'synthetic',b'SYNTHETIC'))),
        ('nonnumeric_kind',dict(kind=16)),('combined_kind',dict(kind=9)),
        ('same_key_pointer',dict(same_pointer=True)),
        ('high_bytes',dict(query=b'\xffA',names=(b'\xffa',))),
        ('binary_NUL',dict(query=b'synthetic\0tail')),
        ('existing_readers',dict(readers=7)),
    ))
    return rows


def fresh(library,base,profile):
    p={**oracle.image_pages(library,base),**oracle.fresh_pages()}
    def w(a,v,n=8):_write_span(p,a,v.to_bytes(n,'little'))
    _write_span(p,SERVICE,bytes(48));w(SERVICE+24,0 if profile.get('null_root') else ROOT);w(SERVICE+32,MUTEX)
    objects.construct_mutex_state(p,object_address=MUTEX,image_base=base)
    w(MUTEX+0x90,profile.get('readers',0),4)
    _write_span(p,KEY,bytes(24));w(KEY+16,0 if profile.get('null_key') else DATA)
    _write_span(p,DATA,profile.get('query',b'synthetic')+b'\0')
    names=profile.get('names',(b'synthetic',));_write_span(p,ROOT,bytes(64));w(ROOT+16,NODE)
    for i,name in enumerate(names):
        address=NODE+i*0x80;_write_span(p,address,bytes(64));w(address,NODE+(i+1)*0x80 if i+1<len(names) else 0)
        w(address+24,profile.get('kind',8),1)
        _write_span(p,address+48,struct.pack('<d',profile.get('value',31.5)+i))
        key=0 if name is None else DATA if profile.get('same_pointer') else G+0x4000+i*0x80
        w(address+56,key)
        if name is not None and not profile.get('same_pointer'):_write_span(p,key,name+b'\0')
    return p


def compare(library,libc,base,label,profile,red=False):
    p=fresh(library,base,profile);initial={k:bytearray(v) for k,v in p.items()}
    result,memory,allocations,services=oracle.native(library,base,0x269BF4,[SERVICE,KEY],initial,
        libc=libc,real_mutexes=True,instruction_limit=100000)
    assert not allocations and len(services)==8
    assert all(row==[('pthread_mutex_lock' if i%2==0 else 'pthread_mutex_unlock'),MUTEX+8] for i,row in enumerate(services))
    if red:
        assert not hasattr(state,'read_state_integer_member')
        assert result==17
        print('RED state numeric',hex(base),'original returned',flush=True)
        return dict(image_base=hex(base),case=label,original_numeric_body_returned=True,
            previous_owner_missing=True,original_nested_reader_mutexes_executed=True,native_snapshot_input=False)
    expected=state.read_state_integer_member(p,service_address=SERVICE,key_object_address=KEY)
    assert expected==result,(label,hex(expected),hex(result))
    assert _read_span(p,G,0xA000)==memory,(label,'guest bytes')
    for page,data in initial.items():
        if not G<=page<<12<G+0xA000:assert p[page]==data,(label,'nondata pages')
    print('PASS state numeric',hex(base),label,flush=True)
    return dict(image_base=hex(base),case=label,original_numeric_body_returned=True,
        signed_W_result_matches=True,full_guest_data_and_image_pages_match=True,
        nested_shared_reader_count_restored=True,matching_libc_mutex_calls=8,
        no_allocator_calls=True,native_snapshot_input=False)


def guards(library):
    rows=[]
    for base in BASES:
        for label in ('cycle','node_limit','comparison_limit','unmapped_key','unmapped_node',
            'unmapped_mutex','writer_active','saturated_readers','invalid_bound'):
            profile=dict(value=1.0);p=fresh(library,base,profile);kw={}
            def w(a,v,n=8):_write_span(p,a,v.to_bytes(n,'little'))
            if label=='cycle':w(NODE,NODE);_write_span(p,DATA,b'absent\0')
            elif label=='node_limit':w(NODE,NODE+0x80);_write_span(p,NODE+0x80,bytes(64));_write_span(p,DATA,b'absent\0');kw['max_nodes']=1
            elif label=='comparison_limit':kw['max_comparisons']=1
            elif label=='unmapped_key':w(KEY+16,G+0x100000)
            elif label=='unmapped_node':w(ROOT+16,G+0x100000)
            elif label=='unmapped_mutex':w(SERVICE+32,G+0x100000)
            elif label=='writer_active':w(MUTEX+0x90,0x80000000,4)
            elif label=='saturated_readers':w(MUTEX+0x90,0x7FFFFFFE,4)
            else:kw['max_nodes']=0
            before={k:bytes(v) for k,v in p.items()}
            try:state.read_state_integer_member(p,service_address=SERVICE,key_object_address=KEY,**kw)
            except (RefillUnsupported,ValueError):pass
            else:raise AssertionError('guard accepted '+label)
            assert before=={k:bytes(v) for k,v in p.items()}
            rows.append(dict(image_base=hex(base),case=label,rejected=True,all_pages_unchanged=True))
            print('PASS state numeric guard',hex(base),label,flush=True)
    return rows


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--libc',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--group',choices=('red','native','guards','all'),default='native');args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==LIBC_SHA256
    cases=[];negative=[]
    if args.group=='red':
        for base in BASES:cases.append(compare(args.library,args.libc,base,'positive_fraction',dict(value=17.75),True))
    if args.group in ('native','all'):
        for base in BASES:
            for label,profile in profiles():cases.append(compare(args.library,args.libc,base,label,profile))
    if args.group in ('guards','all'):negative=guards(args.library)
    args.output.write_text(json.dumps(dict(component='State numeric member read',cases=cases,
        native_Python_controls=len(cases) if args.group!='red' else 0,native_RED_controls=len(cases) if args.group=='red' else 0,
        negative_cases=negative,rollback_guards=len(negative),native_input_snapshot_used=False,
        actual_request_callback_restored=False,state_service_cold_initialization_verified=False,
        whole_physical_stack_bytes_compared=False,whole_request_native_differential_verified=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS state numeric',len(cases),'controls',len(negative),'guards',flush=True)


if __name__=='__main__':main()
