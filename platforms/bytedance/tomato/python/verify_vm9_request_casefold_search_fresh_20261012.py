"""Original declared binary search with ASCII case folding and packed W result."""
from pathlib import Path
import argparse,hashlib,json
import vm9_objects as objects
import verify_vm9_signer_objects as oracle
from vm9_allocator import _read_span,_write_span,RefillUnsupported

BASES=(0x122C0000,0x775C205000);G=oracle.GUEST;PACKED=G+0x3800;SP=G+0xEF00
PROFILES=('casefold_binary','last_match','empty_pattern','empty_at_end','negative_start',
    'past_end','negative_receiver_length','negative_pattern_length','NULL_receiver_payload',
    'NULL_pattern_payload','pattern_longer','non_ASCII','miss','identical_pointer_skips_scan',
    'overlap','cross_page','large_length_early_match','punctuation_not_folded')

def fresh(library,base,label,wrapper):
    p={**oracle.image_pages(library,base),**oracle.fresh_pages()}
    first=G+0x1800;needle=G+0x1840;payload=G+0x2000;pattern=G+0x2200
    hay=b'!A\0z?';tail=b'a\0Z';start=0;length=len(hay);pattern_length=len(tail);limit=0x100000
    if label=='last_match':hay=b'abcABC';tail=b'Bc';length=6;pattern_length=2;start=3
    elif label in ('empty_pattern','empty_at_end'):pattern_length=0;start=length if label=='empty_at_end' else 2
    elif label=='negative_start':start=0xFFFFFFFF
    elif label=='past_end':start=10
    elif label=='negative_receiver_length':length=0x80000000;needle=0x66000000
    elif label=='negative_pattern_length':pattern_length=0xFFFFFFFF
    elif label=='NULL_receiver_payload':payload=0;needle=0x66000000
    elif label=='NULL_pattern_payload':pattern=0
    elif label=='pattern_longer':pattern_length=6
    elif label=='non_ASCII':hay=b'\xc0x\xe0';tail=b'\xe0';length=3;pattern_length=1
    elif label=='miss':tail=b'QQQ'
    elif label=='identical_pointer_skips_scan':payload=pattern=0x66000000;length=0x7FFFFFFF;pattern_length=0x7FFFFFF0;limit=0
    elif label=='overlap':hay=b'aaAaaB';tail=b'AAb';length=6
    elif label=='cross_page':first=G+0x1FF8;needle=G+0x2FF8;payload=G+0x3FFF;pattern=G+0x4FFF
    elif label=='large_length_early_match':length=0x7FFFFFFF;hay=b'A\0z';limit=3
    elif label=='punctuation_not_folded':hay=b'[@';tail=b'{`';length=pattern_length=2
    def obj(address,pointer,size):
        _write_span(p,address,(base+0x34F5F8).to_bytes(8,'little')+(0xFFFFFFFF).to_bytes(4,'little')+size.to_bytes(4,'little')+pointer.to_bytes(8,'little'))
    obj(first,payload,length)
    if needle!=0x66000000:obj(needle,pattern,pattern_length)
    if payload and payload!=0x66000000:_write_span(p,payload,hay)
    if pattern and pattern!=0x66000000:_write_span(p,pattern,tail)
    _write_span(p,PACKED,(base+0x248C54).to_bytes(8,'little')+first.to_bytes(8,'little')+needle.to_bytes(8,'little')+start.to_bytes(4,'little')+b'\xa5'*4)
    return p,first,needle,start,SP-16 if wrapper else SP,limit

def compare(library,base,label,wrapper):
    p,first,needle,start,sp,limit=fresh(library,base,label,wrapper)
    before={k:bytes(v) for k,v in p.items()}
    returned,memory,allocations,services=oracle.native(library,base,0x285D10 if wrapper else 0x248C54,
        [PACKED] if wrapper else [first,needle,start],p,instruction_limit=30000)
    value=objects.find_string_object_ascii_case_insensitive(p,object_address=first,
        pattern_object_address=needle,start_u32=start,entry_stack_address=sp,max_comparisons=limit)
    assert before=={k:bytes(v) for k,v in p.items()}
    assert returned==value and not allocations and not services
    if wrapper:_write_span(p,PACKED+28,value.to_bytes(4,'little'))
    assert _read_span(p,G,0xA000)==memory
    print('PASS',hex(base),label,wrapper,flush=True)
    return dict(image_base=hex(base),case=label,actual_wrapper=wrapper,original_returned=True,
        native_W0_and_packed_W_result_match=True,guest_data_region_matches=True,
        Python_search_pages_unchanged=True,no_allocator_or_service_calls=True,native_snapshot_input=False)

def guards(library):
    rows=[]
    for base in BASES:
        for label in ('unmapped_receiver','unmapped_pattern','unmapped_receiver_payload','unmapped_pattern_payload',
            'comparison_bound','invalid_start','invalid_bound','invalid_stack','physical_receiver_alias','physical_payload_alias'):
            p,first,needle,start,sp,limit=fresh(library,base,'casefold_binary',False)
            kw=dict(object_address=first,pattern_object_address=needle,start_u32=start,entry_stack_address=sp,max_comparisons=limit)
            if label=='unmapped_receiver':kw['object_address']=0x66000000
            elif label=='unmapped_pattern':kw['pattern_object_address']=0x66000000
            elif label=='unmapped_receiver_payload':_write_span(p,first+16,(0x66000000).to_bytes(8,'little'))
            elif label=='unmapped_pattern_payload':_write_span(p,needle+16,(0x66000000).to_bytes(8,'little'))
            elif label=='comparison_bound':kw['max_comparisons']=1
            elif label=='invalid_start':kw['start_u32']=1<<32
            elif label=='invalid_bound':kw['max_comparisons']=-1
            elif label=='invalid_stack':kw['entry_stack_address']=3
            elif label=='physical_receiver_alias':kw['object_address']=sp-24
            elif label=='physical_payload_alias':_write_span(p,needle+16,(sp-8).to_bytes(8,'little'))
            before={k:bytes(v) for k,v in p.items()}
            try:objects.find_string_object_ascii_case_insensitive(p,**kw)
            except (RefillUnsupported,ValueError):pass
            else:raise AssertionError('casefold search guard accepted '+label)
            assert before=={k:bytes(v) for k,v in p.items()}
            rows.append(dict(image_base=hex(base),case=label,rejected=True,all_pages_unchanged=True))
    return rows

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--group',choices=('search','guards','all'),default='all');a=ap.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    cases=[];negative=[]
    if a.group in ('search','all'):
        for base in BASES:
            for label in PROFILES:
                for wrapper in (False,True):cases.append(compare(a.library,base,label,wrapper))
    if a.group in ('guards','all'):negative=guards(a.library)
    a.output.write_text(json.dumps(dict(component='Declared StringObject ASCII case-insensitive search',
        cases=cases,negative_cases=negative,native_Python_controls=len(cases),rollback_guards=len(negative),
        guest_data_region_size=0xA000,native_input_snapshot_used=False,whole_physical_stack_bytes_compared=False,
        whole_request_native_differential_verified=False,actual_URL_header_JNI_conversion_verified=False,
        live_Android_JVM_verified=False,complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS',len(cases),'new casefold search controls',len(negative),'guards',flush=True)
if __name__=='__main__':main()
