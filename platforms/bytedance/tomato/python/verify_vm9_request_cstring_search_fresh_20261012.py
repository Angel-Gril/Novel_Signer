"""Original paired CString-pattern search, short circuits and W arithmetic."""
from pathlib import Path
import argparse,hashlib,json
import vm9_objects as objects
import verify_vm9_signer_objects as oracle
from vm9_allocator import _read_span,_write_span,RefillUnsupported

BASES=(0x122C0000,0x775C205000);G=oracle.GUEST;PACKED=G+0x3800;SP=G+0xEF00
PROFILES=('contiguous_after_gap','last_match','first_match','empty_pattern','empty_at_end',
    'empty_high_start','negative_start','past_end','NULL_pattern_skips_receiver','zero_length',
    'one_byte','one_byte_after_NUL','binary_tail','case_sensitive','no_match','overlap',
    'cross_page','high_bit_signed_scan','large_length_early_match')

def fresh(library,base,label,wrapper):
    p={**oracle.image_pages(library,base),**oracle.fresh_pages()}
    obj=G+0x1800;payload=G+0x2000;pattern=G+0x2200;hay=b'a--bab';tail=b'ab\0'
    start=0;length=len(hay);limit=0x100000;physical=payload
    if label=='last_match':hay=b'xyzab';length=5
    elif label=='first_match':hay=b'abxyz';length=5
    elif label in ('empty_pattern','empty_at_end'):tail=b'\0';start=length if label=='empty_at_end' else 2;limit=0
    elif label=='empty_high_start':tail=b'\0';length=0xFFFFFFFF;start=0x80000000;limit=0
    elif label=='negative_start':start=0xFFFFFFFF
    elif label=='past_end':start=10;pattern=0x66000000
    elif label=='NULL_pattern_skips_receiver':pattern=0;obj=0x66000000
    elif label=='zero_length':length=0
    elif label=='one_byte':tail=b'b\0'
    elif label=='one_byte_after_NUL':hay=b'a\0z?';length=4;tail=b'z\0'
    elif label=='binary_tail':hay=b'x\0ab?';length=5
    elif label=='case_sensitive':hay=b'ABab';length=4
    elif label=='no_match':tail=b'QQ\0'
    elif label=='overlap':hay=b'aaaab';length=5;tail=b'aaab\0'
    elif label=='cross_page':obj=G+0x1FF8;payload=physical=G+0x3FFF;pattern=G+0x4FFF
    elif label=='high_bit_signed_scan':length=0x80000003;start=0x80000000;payload=physical+0x80000000;hay=b'ab?';limit=2
    elif label=='large_length_early_match':length=0x7FFFFFFF;hay=b'ab';limit=2
    if obj!=0x66000000:_write_span(p,obj,(base+0x34F5F8).to_bytes(8,'little')+(0xFFFFFFFF).to_bytes(4,'little')+length.to_bytes(4,'little')+payload.to_bytes(8,'little'))
    _write_span(p,physical,hay)
    if pattern and pattern!=0x66000000:_write_span(p,pattern,tail)
    _write_span(p,PACKED,(base+0x248B24).to_bytes(8,'little')+obj.to_bytes(8,'little')+pattern.to_bytes(8,'little')+start.to_bytes(4,'little')+b'\xa5'*4)
    return p,obj,pattern,start,SP-16 if wrapper else SP,limit

def compare(library,base,label,wrapper):
    p,obj,pattern,start,sp,limit=fresh(library,base,label,wrapper)
    before={k:bytes(v) for k,v in p.items()}
    returned,memory,allocations,services=oracle.native(library,base,0x285D34 if wrapper else 0x248B24,
        [PACKED] if wrapper else [obj,pattern,start],p,instruction_limit=30000)
    value=objects.find_string_object_cstring(p,object_address=obj,pattern_address=pattern,
        start_u32=start,entry_stack_address=sp,max_comparisons=limit)
    assert before=={k:bytes(v) for k,v in p.items()}
    assert returned==value and not allocations and not services,(label,returned,value)
    if wrapper:_write_span(p,PACKED+28,value.to_bytes(4,'little'))
    assert _read_span(p,G,0xA000)==memory
    print('PASS',hex(base),label,wrapper,flush=True)
    return dict(image_base=hex(base),case=label,actual_wrapper=wrapper,original_returned=True,
        native_W0_and_packed_W_result_match=True,guest_data_region_matches=True,
        Python_search_pages_unchanged=True,no_allocator_or_service_calls=True,native_snapshot_input=False)

def guards(library):
    rows=[]
    for base in BASES:
        for label in ('unmapped_receiver','unmapped_pattern','unmapped_payload','unmapped_pattern_tail',
            'comparison_bound','one_byte_bound','invalid_start','invalid_bound','invalid_stack',
            'physical_receiver_alias','physical_payload_alias','physical_pattern_alias'):
            p,obj,pattern,start,sp,limit=fresh(library,base,'contiguous_after_gap',False)
            kw=dict(object_address=obj,pattern_address=pattern,start_u32=start,entry_stack_address=sp,max_comparisons=limit)
            if label=='unmapped_receiver':kw['object_address']=0x66000000
            elif label=='unmapped_pattern':kw['pattern_address']=0x66000000
            elif label=='unmapped_payload':_write_span(p,obj+16,(0x66000000).to_bytes(8,'little'))
            elif label=='unmapped_pattern_tail':kw['pattern_address']=G+0xAFFF;_write_span(p,G+0xAFFF,b'a');p.pop((G+0xB000)>>12)
            elif label=='comparison_bound':kw['max_comparisons']=1
            elif label=='one_byte_bound':_write_span(p,pattern,b'b\0');kw['max_comparisons']=1
            elif label=='invalid_start':kw['start_u32']=1<<32
            elif label=='invalid_bound':kw['max_comparisons']=-1
            elif label=='invalid_stack':kw['entry_stack_address']=3
            elif label=='physical_receiver_alias':kw['object_address']=sp-8
            elif label=='physical_payload_alias':_write_span(p,obj+16,sp.to_bytes(8,'little'))
            else:kw['pattern_address']=sp
            before={k:bytes(v) for k,v in p.items()}
            try:objects.find_string_object_cstring(p,**kw)
            except (RefillUnsupported,ValueError):pass
            else:raise AssertionError('CString search guard accepted '+label)
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
    a.output.write_text(json.dumps(dict(component='CString-pattern paired StringObject search',
        cases=cases,negative_cases=negative,native_Python_controls=len(cases),rollback_guards=len(negative),
        guest_data_region_size=0xA000,native_input_snapshot_used=False,whole_physical_stack_bytes_compared=False,
        whole_request_native_differential_verified=False,actual_URL_header_JNI_conversion_verified=False,
        live_Android_JVM_verified=False,complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS',len(cases),'new CString search controls',len(negative),'guards',flush=True)
if __name__=='__main__':main()
