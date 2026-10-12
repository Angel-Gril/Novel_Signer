"""Fresh actual request StringObject hash through the original 64-bit table.

Declared signed length controls consumption, including embedded NUL bytes.
The table is supplied by fresh ELF pages; no standard CRC variant is assumed.
"""
from pathlib import Path
import argparse,hashlib,json,os
import vm9_objects as objects
import verify_vm9_signer_objects as oracle
from vm9_allocator import _PageTransaction,_read_span,_write_span,RefillUnsupported

G=oracle.GUEST;OBJECT=G+0x1800;PACKED=G+0x3800;DATA=G+0x2100
BASES=(0x122C0000,0x775C205000);M64=(1<<64)-1


def fresh(library,base,label):
    p={**oracle.image_pages(library,base),**oracle.fresh_pages()}
    obj=OBJECT;pointer=DATA;payload=b'abc\0def';length=len(payload)
    if label.startswith('length_'):
        length=int(label[7:]);payload=bytes((i*73+19)&255 for i in range(length))
    elif label=='empty_NULL':length=0;pointer=0
    elif label=='negative_length':length=0xFFFFFFFF;pointer=0x66000000
    elif label=='minimum_signed_length':length=0x80000000;pointer=0
    elif label=='fields_only_mapped':obj=G-12;length=0;pointer=0
    elif label=='cross_page':pointer=G+0x2FFD
    elif label=='all_bytes':payload=bytes(range(256));length=256
    elif label=='receiver_fields_alias':pointer=obj+12;length=4
    elif label=='packed_result_alias':pointer=PACKED+16;length=8
    elif label=='changed_table':
        for i in range(256):
            a=base+0x96548+i*8
            _write_span(p,a,(int.from_bytes(_read_span(p,a,8),'little')^0xDACE5EED12345678).to_bytes(8,'little'))
    if obj==OBJECT:_write_span(p,obj,(base+0x34F5F8).to_bytes(8,'little')+b'\xCC'*4+length.to_bytes(4,'little')+pointer.to_bytes(8,'little'))
    else:_write_span(p,obj+12,length.to_bytes(4,'little')+pointer.to_bytes(8,'little'))
    if pointer not in (0,0x66000000,obj+12,PACKED+16):_write_span(p,pointer,payload+b'\xCA')
    _write_span(p,PACKED,(base+0x258BE0).to_bytes(8,'little')+obj.to_bytes(8,'little')+b'\xA5'*16)
    return p,obj


def apply(p,obj,base,**options):
    staged=_PageTransaction(p)
    value=objects.hash_string_object64(staged,object_address=obj,image_base=base,**options)
    _write_span(staged,PACKED+16,value.to_bytes(8,'little'))
    staged.commit();return value


def compare(library,base,label):
    p,obj=fresh(library,base,label);observed={(base+0x96000,4096):None}
    returned,memory,allocations,services=oracle.native(library,base,0x285E38,[PACKED],p,
        observed_memory=observed,instruction_limit=20000)
    value=apply(p,obj,base)
    assert value==returned==int.from_bytes(memory[0x3810:0x3818],'little')
    assert _read_span(p,G,0xA000)==memory
    assert all(_read_span(p,a,n)==data for (a,n),data in observed.items())
    assert not allocations and not services
    print('PASS request hash64',hex(base),label,flush=True)
    return dict(image_base=hex(base),case=label,original_request_wrapper_returned=True,
        uint64_return_packed_result_and_all_guest_bytes_match=True,loaded_guest_table_used=True,
        no_allocator_or_service_effects=True,native_snapshot_input=False)


def profiles():
    return tuple('length_'+str(n) for n in (0,1,2,7,8,9,15,16,17,63,64,65,128,255,256,1024)) + (
        'empty_NULL','negative_length','minimum_signed_length','fields_only_mapped','cross_page',
        'all_bytes','receiver_fields_alias','packed_result_alias','changed_table','embedded_NUL_tail')


def guards(library):
    rows=[]
    for label in ('unmapped_receiver','NULL_payload','partial_payload','unmapped_table','scan_bound','invalid_bound'):
        base=BASES[0];p,obj=fresh(library,base,'embedded_NUL_tail');kw={}
        if label=='unmapped_receiver':obj=0x66000000
        elif label=='NULL_payload':_write_span(p,obj+16,bytes(8))
        elif label=='partial_payload':
            pointer=G+0xAFFF;p[(G+0xA000)>>12]=bytearray(4096);p.pop((G+0xB000)>>12,None)
            _write_span(p,pointer,b'a');_write_span(p,obj+16,pointer.to_bytes(8,'little'))
        elif label=='unmapped_table':del p[(base+0x96000)>>12]
        elif label=='scan_bound':kw['max_bytes']=2
        else:kw['max_bytes']=-1
        before={k:bytes(v) for k,v in p.items()}
        try:apply(p,obj,base,**kw)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError('guard accepted '+label)
        assert before=={k:bytes(v) for k,v in p.items()}
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True))
        print('PASS request hash64 guard',label,flush=True)
    for label in ('empty_NULL','negative_length','minimum_signed_length'):
        p,obj=fresh(library,BASES[0],label)
        assert apply(p,obj,BASES[0],max_bytes=0)==0
    return rows


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--group',choices=('native','guards','all'),default='native');args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    os.environ['TOMATO_LIBMETASEC']=str(args.library.resolve())
    import vm_full
    assert Path(vm_full.__file__).resolve().parent==Path(__file__).resolve().parent
    rows=[];negative=[]
    if args.group in ('native','all'):rows=[compare(args.library,base,label) for base in BASES for label in profiles()]
    if args.group in ('guards','all'):negative=guards(args.library)
    args.output.write_text(json.dumps(dict(component='Actual request StringObject table hash64',cases=rows,
        native_Python_controls=len(rows),negative_cases=negative,rollback_guards=len(negative),
        native_input_snapshot_used=False,whole_physical_stack_bytes_compared=False,
        whole_request_native_differential_verified=False,complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8',newline='\n')


if __name__=='__main__':main()
