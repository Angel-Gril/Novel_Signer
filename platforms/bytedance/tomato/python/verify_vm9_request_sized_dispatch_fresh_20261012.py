"""Fresh actual request sized-string wrapper checks using the existing owner."""
from pathlib import Path
import argparse,hashlib,json
import vm9_objects as objects
import verify_vm9_signer_objects as oracle
from verify_vm9_reference_scopes_fresh_20261011 import Services
from vm9_allocator import _read_span,_write_span,RefillUnsupported

BASES=(0x122C0000,0x775C205000);G=oracle.GUEST;PACKED=G+0x1400
PROFILES=('empty','binary','long','cross_page','negative_min','negative_all_ones',
          'malloc_NULL_empty','malloc_NULL_nonempty','source_alias')

def fresh(library,base,label):
    p={**oracle.image_pages(library,base),**oracle.fresh_pages()}
    obj=G+0x1FF8 if label=='cross_page' else G+0x1800;source=G+0x2800;data=b'a\0z'
    length=len(data)
    if label in ('empty','malloc_NULL_empty'):data=b'';length=0;source=0x66000000
    elif label=='long':data=bytes(range(240));length=len(data)
    elif label=='cross_page':source=G+0x2FFF;data=bytes(range(256))*16+b'z';length=len(data)
    elif label=='negative_min':length=0x80000000;source=0x66000000
    elif label=='negative_all_ones':length=0xFFFFFFFF;source=0x66000000
    elif label=='malloc_NULL_nonempty':source=0x66000000
    elif label=='source_alias':source=obj+12;length=8
    if source!=0x66000000 and label!='source_alias':_write_span(p,source,data)
    _write_span(p,PACKED,(base+0x2481FC).to_bytes(8,'little')+obj.to_bytes(8,'little')+
        source.to_bytes(8,'little')+length.to_bytes(4,'little')+bytes([0x5A])*4)
    failures=(0,) if label.startswith('malloc_NULL_') else ()
    expected=Services(failures=failures);actual=Services(failures=failures)
    if label=='cross_page':expected.effects.next=actual.effects.next=G+0x4FF8
    return p,obj,source,length,expected,actual

def compare(library,base,label):
    p,obj,source,length,expected,actual=fresh(library,base,label)
    observed={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
    _,memory,_,services=oracle.native(library,base,0x285C80,[PACKED],p,
        malloc_handler=expected.native_malloc,observed_memory=observed,instruction_limit=30000)
    pointer=objects.construct_sized_string_object(p,object_address=obj,source_address=source,
        length=length,image_base=base,allocate=actual.malloc)
    assert pointer==int.from_bytes(_read_span(p,obj+16,8),'little') and _read_span(p,G,0xA000)==memory
    assert all(_read_span(p,a,n)==v for (a,n),v in observed.items())
    assert expected.events==actual.events and expected.effects.calls==actual.effects.calls and expected.effects.blocks==actual.effects.blocks
    assert not services
    print('PASS',hex(base),'request sized string wrapper',label,flush=True)
    return dict(image_base=hex(base),case=label,actual_wrapper=True,original_returned=True,
        all_guest_and_ELF_bytes_match=True,ordered_allocation_and_heap_match=True,
        packed_padding_preserved=True,existing_owner_used=True,
        incidental_native_X0_not_claimed=True,native_snapshot_input=False)

def guards(library):
    rows=[]
    for base in BASES:
        for label in ('unmapped_source','unmapped_object','payload_bound','unmapped_buffer','provider_exception'):
            p,obj,source,length,_,actual=fresh(library,base,'binary')
            kw=dict(object_address=obj,source_address=source,length=length,image_base=base,allocate=actual.malloc)
            if label=='unmapped_source':kw['source_address']=0x66000000
            elif label=='unmapped_object':kw['object_address']=0x66000000
            elif label=='payload_bound':kw['max_payload_bytes']=2
            elif label=='unmapped_buffer':kw['allocate']=lambda p,n:0x66000000
            else:
                def fail(p,n):
                    _write_span(p,PACKED,b'\x11');raise RefillUnsupported('injected sized-string provider failure')
                kw['allocate']=fail
            before={k:bytes(v) for k,v in p.items()}
            try:objects.construct_sized_string_object(p,**kw)
            except (RefillUnsupported,ValueError):pass
            else:raise AssertionError('sized string dispatch guard accepted '+label)
            assert before=={k:bytes(v) for k,v in p.items()}
            rows.append(dict(image_base=hex(base),case=label,rejected=True,
                all_pages_unchanged=True,external_effects_rolled_back=False))
            print('PASS request sized string guard',hex(base),label,flush=True)
    return rows

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--group',choices=('native','guards','all'),default='all');args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    cases=[];negative=[]
    if args.group in ('native','all'):
        for base in BASES:
            for label in PROFILES:cases.append(compare(args.library,base,label))
    if args.group in ('guards','all'):negative=guards(args.library)
    args.output.write_text(json.dumps(dict(component='Request sized string tail-wrapper dispatch',
        cases=cases,negative_cases=negative,native_Python_controls=len(cases),rollback_guards=len(negative),
        accepted_owner_native_groups_not_repeated=True,native_input_snapshot_used=False,
        actual_URL_header_JNI_conversion_verified=False,whole_request_native_differential_verified=False,
        live_Android_JVM_verified=False,complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS',len(cases),'new request wrapper controls,',len(negative),'rollback guards',flush=True)
if __name__=='__main__':main()
