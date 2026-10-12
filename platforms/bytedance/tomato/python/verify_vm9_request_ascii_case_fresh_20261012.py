"""ASCII case conversion through original field/object/request wrappers."""
from pathlib import Path
import argparse,hashlib,json
import vm9_objects as objects
import verify_vm9_signer_objects as oracle
from vm9_allocator import _read_span,_write_span,RefillUnsupported

BASES=(0x122C0000,0x775C205000);G=oracle.GUEST;OBJECT=G+0x1800;PACKED=G+0x3800
PROFILES=('all_bytes','empty','exact_capacity','cross_page')
INVALID=('zero_capacity','negative_capacity','short_capacity','negative_length','NULL_payload','NULL_fields')

def fresh(library,base,label,uppercase):
    p={**oracle.image_pages(library,base),**oracle.fresh_pages()}
    payload={'all_bytes':bytes(range(256)),'empty':b'',
        'exact_capacity':b'aZ\0y','cross_page':b'azAZ\0\xff'}.get(label,b'az')
    length=len(payload);capacity=length+1
    if label=='exact_capacity':capacity=length
    elif label=='zero_capacity':capacity=0
    elif label=='negative_capacity':capacity=0xFFFFFFFF
    elif label=='short_capacity':capacity=1
    elif label=='negative_length':length=0x80000000
    pointer=G+0x2FFD if label=='cross_page' else G+0x2000
    _write_span(p,pointer,payload+b'\xca')
    if label=='NULL_payload':pointer=0
    _write_span(p,OBJECT,(base+0x34F5F8).to_bytes(8,'little')+capacity.to_bytes(4,'little')+
        length.to_bytes(4,'little')+pointer.to_bytes(8,'little'))
    _write_span(p,PACKED,b''.join(v.to_bytes(8,'little') for v in
        (base+(0x248F4C if uppercase else 0x248F54),OBJECT,0xA5A5A5A5A5A5A5A5,0x5A5A5A5A5A5A5A5A)))
    return p,0 if label=='NULL_fields' else OBJECT+8

def compare(library,base,label,uppercase,path):
    p,fields=fresh(library,base,label,uppercase)
    function=(0x246FC0 if uppercase else 0x247028) if path=='fields' else (0x248F4C if uppercase else 0x248F54)
    entry=0x28591C if path=='callback' else function
    args=[PACKED] if path=='callback' else [fields if path=='fields' else OBJECT]
    returned,memory,allocations,services=oracle.native(library,base,entry,args,p,instruction_limit=10000)
    result=objects.transform_string_fields_ascii_case(p,fields_address=fields,uppercase=uppercase)
    expected=0xFFFFFFFF if label in INVALID else 0
    assert result==returned==expected and _read_span(p,G,0xA000)==memory
    assert not allocations and not services
    print('PASS',hex(base),'ASCII','upper' if uppercase else 'lower',label,path,flush=True)
    return dict(image_base=hex(base),case=label,uppercase=uppercase,path=path,
        original_returned=True,status_and_all_guest_bytes_match=True,
        declared_length_including_embedded_NUL_tail_used=True,unused_packed_fields_preserved=True,
        no_allocator_or_service_effects=True,native_snapshot_input=False)

def guards(library):
    rows=[]
    for base in BASES:
        for label in ('partial_unmapped_payload','unmapped_fields','payload_bound','invalid_direction'):
            p,fields=fresh(library,base,'exact_capacity',True)
            kw=dict(fields_address=fields,uppercase=True)
            if label=='partial_unmapped_payload':
                _write_span(p,fields+8,(G+0xAFFF).to_bytes(8,'little'))
                p[(G+0xA000)>>12]=bytearray(4096);_write_span(p,G+0xAFFF,b'a')
                p.pop((G+0xB000)>>12,None)
            elif label=='unmapped_fields':kw['fields_address']=0x66000000
            elif label=='payload_bound':kw['max_bytes']=3
            elif label=='invalid_direction':kw['uppercase']=1
            before={k:bytes(v) for k,v in p.items()}
            try:objects.transform_string_fields_ascii_case(p,**kw)
            except (RefillUnsupported,ValueError):pass
            else:raise AssertionError('ASCII case guard accepted '+label)
            assert before=={k:bytes(v) for k,v in p.items()}
            rows.append(dict(image_base=hex(base),case=label,rejected=True,
                all_pages_unchanged=True,external_effects_rolled_back=False))
            print('PASS ASCII case guard',hex(base),label,flush=True)
    return rows

def flag_case(library,base,label,value,wrapper):
    p={**oracle.image_pages(library,base),**oracle.fresh_pages()}
    receiver=G-0x52 if label=='field_only_mapped' else OBJECT
    _write_span(p,receiver+0x52,bytes([value]))
    _write_span(p,PACKED,(base+0x282A68).to_bytes(8,'little')+
        receiver.to_bytes(8,'little')+bytes([0xA5])*16)
    returned,memory,allocations,services=oracle.native(library,base,
        0x285C3C if wrapper else 0x282A68,[PACKED] if wrapper else [receiver],p)
    result=objects.read_signer_request_flag(p,object_address=receiver)
    if wrapper:_write_span(p,PACKED+16,bytes([result&1]))
    assert result==returned==value and _read_span(p,G,0xA000)==memory
    assert not allocations and not services
    print('PASS',hex(base),'request byte52',label,value,wrapper,flush=True)
    return dict(image_base=hex(base),case=label,returned_byte=value,actual_wrapper=wrapper,
        original_returned=True,full_byte_return_and_bit0_packed_store_match=True,
        all_guest_bytes_and_unused_packed_padding_match=True,native_snapshot_input=False)

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--group',choices=('native','guards','flags','all'),default='all');args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    cases=[];flags=[];negative=[]
    if args.group in ('native','all'):
        for base in BASES:
            for uppercase in (False,True):
                for label in PROFILES:
                    for path in ('fields','object','callback'):cases.append(compare(args.library,base,label,uppercase,path))
                for label in INVALID:cases.append(compare(args.library,base,label,uppercase,'fields'))
    if args.group in ('guards','all'):negative=guards(args.library)
    if args.group in ('flags','all'):
        for base in BASES:
            for label,value in [('byte_'+str(n),n) for n in (0,1,2,255)]+[('field_only_mapped',254)]:
                for wrapper in (False,True):flags.append(flag_case(args.library,base,label,value,wrapper))
    args.output.write_text(json.dumps(dict(component='Request string ASCII case and receiver flag',cases=cases,
        flag_cases=flags,negative_cases=negative,native_Python_controls=len(cases)+len(flags),rollback_guards=len(negative),
        native_input_snapshot_used=False,whole_request_native_differential_verified=False,
        actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False),
        indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS',len(cases),'ASCII case controls,',len(flags),'receiver flag controls,',len(negative),'guards',flush=True)
if __name__=='__main__':main()
