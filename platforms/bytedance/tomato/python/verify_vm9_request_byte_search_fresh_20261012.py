"""Byte search differential checks through the original object/request entries."""
from pathlib import Path
import argparse,hashlib,json
import vm9_objects as objects
import verify_vm9_signer_objects as oracle
from vm9_allocator import _PageTransaction,_read_span,_write_span,RefillUnsupported

BASES=(0x122C0000,0x775C205000);G=oracle.GUEST;OBJECT=G+0x1800;PACKED=G+0x3800
PROFILES=('empty','first','embedded_NUL_tail','last','absent','start_skips',
    'NUL_target','high_target_byte','start_max_positive','negative_start',
    'negative_start_NULL_receiver','negative_length','start_equal_length',
    'start_above_length','early_huge_length','fields_only_mapped','cross_page',
    'receiver_field_alias','packed_result_alias','all_bytes_last')

def fresh(library,base,label):
    p={**oracle.image_pages(library,base),**oracle.fresh_pages()}
    obj=OBJECT;pointer=G+0x2000;data=b'a\0z/?';target=ord('z');start=0;length=len(data);expected=2
    if label=='empty':data=b'';length=0;expected=0xFFFFFFFF
    elif label=='first':target=ord('a');expected=0
    elif label=='last':target=ord('?');expected=4
    elif label=='absent':target=ord('!');expected=0xFFFFFFFF
    elif label=='start_skips':data=b'za\0zz';start=3;expected=3
    elif label=='NUL_target':target=0;expected=1
    elif label=='high_target_byte':data=b'a\x80\xff/?';target=0x1FF;expected=2
    elif label=='start_max_positive':start=0x7FFFFFFF;expected=0xFFFFFFFF;pointer=0
    elif label=='negative_start':start=0x80000000;obj=0x66000000;expected=0xFFFFFFFF
    elif label=='negative_start_NULL_receiver':start=0xFFFFFFFF;obj=0;expected=0xFFFFFFFF
    elif label=='negative_length':length=0x80000000;pointer=0;expected=0xFFFFFFFF
    elif label=='start_equal_length':start=length;pointer=0;expected=0xFFFFFFFF
    elif label=='start_above_length':start=length+1;pointer=0;expected=0xFFFFFFFF
    elif label=='early_huge_length':length=0x7FFFFFFF;data=b'z';expected=0
    elif label=='fields_only_mapped':obj=G-12;length=0;pointer=0;expected=0xFFFFFFFF
    elif label=='cross_page':pointer=G+0x2FFF
    elif label=='receiver_field_alias':pointer=obj+12;target=length;expected=0
    elif label=='packed_result_alias':pointer=PACKED+24;target=0x5A;expected=0
    elif label=='all_bytes_last':data=bytes(range(256));length=256;target=255;expected=255
    if obj==OBJECT:
        _write_span(p,obj,(base+0x34F5F8).to_bytes(8,'little')+bytes([0xCC])*4+
            length.to_bytes(4,'little')+pointer.to_bytes(8,'little'))
    elif label=='fields_only_mapped':
        _write_span(p,obj+12,length.to_bytes(4,'little')+pointer.to_bytes(8,'little'))
    if pointer and label not in ('receiver_field_alias','packed_result_alias'):_write_span(p,pointer,data+b'\xca')
    _write_span(p,PACKED,(base+0x248C1C).to_bytes(8,'little')+obj.to_bytes(8,'little')+
        bytes([target&255])+bytes([0xA5])*3+start.to_bytes(4,'little')+bytes([0x5A])*8)
    return p,obj,target,start,expected

def model(p,obj,target,start,wrapper,**kw):
    staged=_PageTransaction(p)
    value=objects.find_string_object_byte(staged,object_address=obj,
        target_byte=target&255 if wrapper else target,start_u32=start,**kw)
    if wrapper:_write_span(staged,PACKED+24,value.to_bytes(4,'little'))
    staged.commit();return value

def compare(library,base,label,wrapper):
    p,obj,target,start,expected=fresh(library,base,label)
    returned,memory,allocations,services=oracle.native(library,base,
        0x285C5C if wrapper else 0x248C1C,[PACKED] if wrapper else [obj,target,start],p)
    value=model(p,obj,target,start,wrapper)
    assert value==returned==expected and _read_span(p,G,0xA000)==memory
    assert not allocations and not services
    print('PASS',hex(base),'byte search',label,wrapper,flush=True)
    return dict(image_base=hex(base),case=label,actual_wrapper=wrapper,
        original_returned=True,uint32_result_and_all_guest_bytes_match=True,
        unused_packed_padding_preserved=True,no_allocator_or_service_effects=True,
        native_snapshot_input=False)

def guards(library):
    rows=[]
    for base in BASES:
        for label in ('unmapped_receiver','partial_unmapped_payload','scan_bound',
                      'negative_bound','invalid_target','invalid_start'):
            p,obj,target,start,_=fresh(library,base,'absent');kw={}
            if label=='unmapped_receiver':obj=0x66000000
            elif label=='partial_unmapped_payload':
                pointer=G+0xAFFF;p[(G+0xA000)>>12]=bytearray(4096);p.pop((G+0xB000)>>12,None)
                _write_span(p,pointer,b'a');_write_span(p,obj+16,pointer.to_bytes(8,'little'))
            elif label=='scan_bound':kw['max_bytes']=2
            elif label=='negative_bound':kw['max_bytes']=-1
            elif label=='invalid_target':target=-1
            elif label=='invalid_start':start=1<<32
            before={k:bytes(v) for k,v in p.items()}
            try:model(p,obj,target,start,False,**kw)
            except (RefillUnsupported,ValueError):pass
            else:raise AssertionError('byte search guard accepted '+label)
            assert before=={k:bytes(v) for k,v in p.items()}
            rows.append(dict(image_base=hex(base),case=label,rejected=True,
                all_pages_unchanged=True,external_effects_rolled_back=False))
            print('PASS byte search guard',hex(base),label,flush=True)
        for label,bound in (('early_huge_length',1),('embedded_NUL_tail',3),('empty',0),('negative_start',0)):
            p,obj,target,start,expected=fresh(library,base,label)
            assert model(p,obj,target,start,False,max_bytes=bound)==expected
            rows.append(dict(image_base=hex(base),case='bounded_'+label,
                accepted_with_exact_scan_bound=True,result_matches_declared_semantics=True,
                large_declared_length_not_preemptively_rejected=label=='early_huge_length'))
            print('PASS byte search exact bound',hex(base),label,flush=True)
    return rows

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--group',choices=('native','guards','all'),default='all');args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    cases=[];negative=[]
    if args.group in ('native','all'):
        for base in BASES:
            for label in PROFILES:
                for wrapper in (False,True):cases.append(compare(args.library,base,label,wrapper))
    if args.group in ('guards','all'):negative=guards(args.library)
    args.output.write_text(json.dumps(dict(component='Request string byte search',cases=cases,
        negative_cases=[r for r in negative if r.get('rejected')],
        bounded_cases=[r for r in negative if r.get('accepted_with_exact_scan_bound')],
        native_Python_controls=len(cases),rollback_guards=sum(r.get('rejected',False) for r in negative),
        native_input_snapshot_used=False,whole_request_native_differential_verified=False,
        actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False),
        indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS',len(cases),'byte search controls,',len(negative),'bound/guard controls',flush=True)
if __name__=='__main__':main()
