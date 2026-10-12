"""Original StringObject clone followed by live CString append."""
from pathlib import Path
import argparse,hashlib,json
import vm9_objects as objects
import verify_vm9_signer_objects as oracle
from verify_vm9_request_concat_fresh_20261012 import ObservedEffects
from vm9_allocator import _read_span,_write_span,RefillUnsupported
from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X8

BASES=(0x122C0000,0x775C205000);G=oracle.GUEST;PACKED=G+0x3800;SP=G+0xEF00
PROFILES=('binary_first','empty_first','empty_tail','long_tail','same_object',
    'tail_is_first_payload','tail_is_output_fields','tail_is_new_payload','cross_page',
    'reserve_malloc_NULL','reserve_malloc_realloc_NULL','realloc_inplace',
    'reload_first_after_clone_allocation','tail_mutated_during_clone')
GROWTH_PROFILES=('long_first','long_first_realloc_NULL','long_first_realloc_inplace')

def fresh(library,base,label,wrapper):
    p={**oracle.image_pages(library,base),**oracle.fresh_pages()}
    first=G+0x1800;out=G+0x1840;payload=G+0x2200;tail=G+0x2000
    data=b'a\0z\0';length=3;last=b'?\0';failures=();inplace=label=='realloc_inplace'
    if label in GROWTH_PROFILES:
        data=b'0123456789abcdef\0';length=16;last=b'XYZ\0'
        if label=='long_first_realloc_NULL':failures=(1,)
        elif label=='long_first_realloc_inplace':inplace=True
    elif label=='empty_first':data=b'\0';length=0
    elif label=='empty_tail':last=b'\0'
    elif label=='long_tail':last=b'0123456789abcdef\0'
    elif label=='same_object':out=first
    elif label=='tail_is_first_payload':tail=payload
    elif label=='tail_is_output_fields':tail=out+8
    elif label=='tail_is_new_payload':tail=G+0x4000
    elif label=='cross_page':first=G+0x1FF8;out=G+0x2FF8;payload=G+0x3FFF;tail=G+0x27FF
    if label in ('reserve_malloc_NULL','realloc_inplace'):failures=(1,)
    elif label=='reserve_malloc_realloc_NULL':failures=(1,2)
    _write_span(p,first,(base+0x34F5F8).to_bytes(8,'little')+(length+1).to_bytes(4,'little')+length.to_bytes(4,'little')+payload.to_bytes(8,'little'))
    _write_span(p,payload,data)
    if label!='tail_is_first_payload':_write_span(p,tail,last)
    _write_span(p,PACKED,(base+0x2487B4).to_bytes(8,'little')+out.to_bytes(8,'little')+first.to_bytes(8,'little')+tail.to_bytes(8,'little'))
    def mutate(kind,index,read,write):
        if kind=='malloc' and index==0:
            if label=='reload_first_after_clone_allocation':write(first+16,(G+0x2300).to_bytes(8,'little'));write(G+0x2300,b'Z\0Y\0')
            elif label=='tail_mutated_during_clone':write(tail,b'!?\0')
    expected=ObservedEffects(blocks=(),failures=failures,inplace=inplace,mutate=mutate)
    actual=ObservedEffects(blocks=(),failures=failures,inplace=inplace,mutate=mutate)
    if label=='cross_page':expected.next=actual.next=G+0x5FF8
    return p,first,out,tail,SP-16 if wrapper else SP,expected,actual

def compare(library,base,label,wrapper):
    p,first,out,tail,sp,expected,actual=fresh(library,base,label,wrapper)
    observed={(page<<12,4096):None for page in p if not G<=page<<12<G+0x10000}
    returned,memory,_,services=oracle.native(library,base,0x285CF4 if wrapper else 0x2487B4,
        [PACKED] if wrapper else [first,tail],p,extra_registers=None if wrapper else {UC_ARM64_REG_X8:out},
        malloc_handler=lambda cpu,n:expected.native(cpu,'malloc',n),host_imports={
            0x347FA0:lambda cpu:expected.native(cpu,'free',pointer=cpu.reg_read(UC_ARM64_REG_X0)),
            0x348320:lambda cpu:expected.native(cpu,'realloc',cpu.reg_read(UC_ARM64_REG_X1),cpu.reg_read(UC_ARM64_REG_X0))},
        observed_memory=observed,instruction_limit=30000)
    result=objects.construct_string_object_cstring(p,object_address=out,first_object_address=first,
        second_cstring_address=tail,image_base=base,entry_stack_address=sp,
        allocate=actual.malloc,reallocate=actual.realloc,free=actual.free)
    got=_read_span(p,G,0xA000)
    if got!=memory:
        i=next(i for i,(a,b) in enumerate(zip(got,memory)) if a!=b)
        raise AssertionError((label,wrapper,hex(i),got[i],memory[i]))
    assert returned==result==out
    assert expected.calls==actual.calls and expected.blocks==actual.blocks and expected.pre_free==actual.pre_free,(label,'allocator effects')
    assert not services
    for (a,n),data in observed.items():assert _read_span(p,a,n)==data
    print('PASS',hex(base),label,wrapper,flush=True)
    return dict(image_base=hex(base),case=label,actual_wrapper=wrapper,original_returned=True,
        guest_data_region_and_packed_bytes_match=True,all_main_image_pages_match=True,
        ordered_allocation_and_pre_free_bytes_match=True,remaining_heap_matches=True,
        native_X0_output_object_matches=True,native_snapshot_input=False)

def guards(library):
    rows=[]
    for base in BASES:
        for label in ('unmapped_output','unmapped_first','unmapped_tail','clone_bound','tail_bound',
            'unmapped_stack','physical_object_alias','physical_first_payload','physical_tail_alias',
            'clone_malloc_NULL','provider_exception','late_physical_first_payload'):
            p,first,out,tail,sp,_,e=fresh(library,base,'binary_first',False)
            kw=dict(object_address=out,first_object_address=first,second_cstring_address=tail,
                image_base=base,entry_stack_address=sp,allocate=e.malloc,reallocate=e.realloc,free=e.free)
            if label=='unmapped_output':kw['object_address']=0x66000000
            elif label=='unmapped_first':kw['first_object_address']=0x66000000
            elif label=='unmapped_tail':kw['second_cstring_address']=0x66000000
            elif label=='clone_bound':kw['max_payload_bytes']=2
            elif label=='tail_bound':_write_span(p,tail,b'0123456789\0');kw['max_payload_bytes']=5
            elif label=='unmapped_stack':kw['entry_stack_address']=3
            elif label=='physical_object_alias':kw['object_address']=sp-0x20
            elif label=='physical_first_payload':_write_span(p,first+16,(sp-0x30).to_bytes(8,'little'))
            elif label=='physical_tail_alias':kw['second_cstring_address']=sp-0x20
            elif label=='clone_malloc_NULL':kw['allocate']=lambda p,n:0
            else:
                def effect(p,n):
                    pointer=e.malloc(p,n)
                    if label=='provider_exception':_write_span(p,PACKED,b'\x11');raise RefillUnsupported('injected object/CString provider failure')
                    _write_span(p,first+16,(sp-0x30).to_bytes(8,'little'));return pointer
                kw['allocate']=effect
            before={k:bytes(v) for k,v in p.items()}
            try:objects.construct_string_object_cstring(p,**kw)
            except (RefillUnsupported,ValueError):pass
            else:raise AssertionError('object/CString guard accepted '+label)
            assert before=={k:bytes(v) for k,v in p.items()}
            rows.append(dict(image_base=hex(base),case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
            print('PASS guard',hex(base),label,flush=True)
    return rows

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--group',choices=('composition','growth','guards','all'),default='all');args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    cases=[];negative=[]
    if args.group in ('composition','all'):
        for base in BASES:
            for label in PROFILES:
                for wrapper in (False,True):cases.append(compare(args.library,base,label,wrapper))
    if args.group in ('growth','all'):
        for base in BASES:
            for label in GROWTH_PROFILES:
                for wrapper in (False,True):cases.append(compare(args.library,base,label,wrapper))
    if args.group in ('guards','all'):negative=guards(args.library)
    args.output.write_text(json.dumps(dict(component='StringObject clone and CString append construction',
        cases=cases,negative_cases=negative,native_Python_controls=len(cases),rollback_guards=len(negative),
        guest_data_region_size=0xA000,whole_physical_stack_bytes_compared=False,native_input_snapshot_used=False,
        whole_request_native_differential_verified=False,actual_URL_header_JNI_conversion_verified=False,
        live_Android_JVM_verified=False,complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS',len(cases),'new object/CString controls,',len(negative),'rollback guards',flush=True)
if __name__=='__main__':main()
