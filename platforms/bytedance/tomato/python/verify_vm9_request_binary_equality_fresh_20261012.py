"""Native binary equality and request boolean wrapper on independent inputs."""
from pathlib import Path
import argparse,hashlib,json
import vm9_configuration_init as config
import verify_vm9_signer_objects as oracle
import verify_vm9_outer_signer_native as native_outer
from unicorn import arm64_const as arm
from vm9_allocator import _PageTransaction,_read_span,_write_span,RefillUnsupported

BASES=(0x122C0000,0x775C205000);G=oracle.GUEST;PACKED=G+0x3800
PROFILES=('equal','different_after_NUL','different_length','first_NULL_short',
    'second_NULL_short','first_negative_short','second_negative','empty_unmapped_payloads',
    'same_payload_huge_length','different_length_unmapped_payloads','all_bytes_equal','fields_only_object')

def fresh(library,base,label):
    p={**oracle.image_pages(library,base),**oracle.fresh_pages()}
    first=G+0x1800;second=first+0x40;a=b=3;left=G+0x2800;right=G+0x2900;expected=True
    _write_span(p,left,b'a\0z');_write_span(p,right,b'a\0z')
    if label=='different_after_NUL':_write_span(p,right,b'a\0y');expected=False
    elif label=='different_length':b=2;expected=False
    elif label=='first_NULL_short':first=G-16;left=0;second=0x66000000;expected=False
    elif label=='second_NULL_short':first=G-16;right=0;expected=False
    elif label=='first_negative_short':a=0x80000000;second=G-16;expected=False
    elif label=='second_negative':b=0xFFFFFFFF;expected=False
    elif label=='empty_unmapped_payloads':a=b=0;left=0x66000000;right=0x66100000
    elif label=='same_payload_huge_length':a=b=0x7FFFFFFF;left=right=0x66000000
    elif label=='different_length_unmapped_payloads':a=3;b=4;left=0x66000000;right=0x66100000;expected=False
    elif label=='all_bytes_equal':a=b=256;_write_span(p,left,bytes(range(256)));_write_span(p,right,bytes(range(256)))
    elif label=='fields_only_object':first=G-12
    for obj,length,pointer in ((first,a,left),(second,b,right)):
        if obj==0x66000000:continue
        if obj==G-16:_write_span(p,obj+16,pointer.to_bytes(8,'little'))
        else:_write_span(p,obj+12,length.to_bytes(4,'little')+pointer.to_bytes(8,'little'))
    _write_span(p,PACKED,(base+0x2487E8).to_bytes(8,'little')+first.to_bytes(8,'little')+
        second.to_bytes(8,'little')+bytes([0x5A])*8)
    return p,first,second,expected

def compare(library,libc,base,label,wrapper):
    p,first,second,expected=fresh(library,base,label)
    imports={};memcmp_calls=[]
    def redirect(entry):
        def run(cpu):cpu.reg_write(arm.UC_ARM64_REG_PC,entry)
        return run
    exports=native_outer.bind_native_imports(library,libc,redirect,imports)
    def observe(cpu,address):
        if address==exports['memcmp']:memcmp_calls.append(1)
    returned,memory,allocations,services=oracle.native(library,base,
        0x285C94 if wrapper else 0x2487E8,[PACKED] if wrapper else [first,second],p,
        libc=libc,host_imports=imports,instruction_observer=observe,instruction_limit=30000)
    equal=config.strings_equal(p,first_object=first,second_object=second)
    if wrapper:_write_span(p,PACKED+24,bytes([int(equal)]))
    assert equal==bool(returned)==expected and returned in (0,1) and _read_span(p,G,0xA000)==memory
    assert not allocations and not services
    print('PASS',hex(base),'binary equality',label,wrapper,flush=True)
    return dict(image_base=hex(base),case=label,actual_wrapper=wrapper,original_returned=True,
        boolean_and_all_guest_bytes_match=True,single_byte_packed_store_and_padding_match=True,
        native_short_circuit_order_observed=True,actual_matching_libc_memcmp_calls=len(memcmp_calls),
        memcmp_body_substituted=False,no_allocator_or_service_effects=True,native_snapshot_input=False)

def guards(library):
    rows=[]
    for base in BASES:
        for label in ('unmapped_first_fields','unmapped_second_fields','unmapped_payload','comparison_bound'):
            p,first,second,_=fresh(library,base,'equal');kw={}
            if label=='unmapped_first_fields':first=0x66000000
            elif label=='unmapped_second_fields':second=0x66000000
            elif label=='unmapped_payload':_write_span(p,second+16,(0x66000000).to_bytes(8,'little'))
            else:kw['max_bytes']=2
            before={k:bytes(v) for k,v in p.items()}
            staged=_PageTransaction(p)
            try:
                result=config.strings_equal(staged,first_object=first,second_object=second,**kw)
                _write_span(staged,PACKED+24,bytes([int(result)]));staged.commit()
            except (RefillUnsupported,ValueError):pass
            else:raise AssertionError('binary equality guard accepted '+label)
            assert before=={k:bytes(v) for k,v in p.items()}
            rows.append(dict(image_base=hex(base),case=label,rejected=True,all_pages_unchanged=True,
                external_effects_rolled_back=False))
            print('PASS binary equality guard',hex(base),label,flush=True)
    return rows

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--library',type=Path,required=True);ap.add_argument('--libc',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--group',choices=('native','guards','all'),default='all');args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    from verify_vm9_jni_environment_fresh_20261007 import LIBC_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==LIBC_SHA256
    cases=[];negative=[]
    if args.group in ('native','all'):
        for base in BASES:
            for label in PROFILES:
                for wrapper in (False,True):cases.append(compare(args.library,args.libc,base,label,wrapper))
    if args.group in ('guards','all'):negative=guards(args.library)
    args.output.write_text(json.dumps(dict(component='Request binary string equality',cases=cases,
        negative_cases=negative,native_Python_controls=len(cases),rollback_guards=len(negative),
        native_input_snapshot_used=False,actual_URL_header_JNI_conversion_verified=False,
        whole_request_native_differential_verified=False,live_Android_JVM_verified=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False),
        indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS',len(cases),'binary equality controls,',len(negative),'rollback guards',flush=True)
if __name__=='__main__':main()
