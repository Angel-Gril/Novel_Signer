"""Original field-clone and X8 substring constructors with fresh guest inputs."""
from pathlib import Path
import argparse,hashlib,json
import vm9_objects as objects
import verify_vm9_signer_objects as oracle
from verify_vm9_reference_scopes_fresh_20261011 import Services
from vm9_allocator import _read_span,_write_span,RefillUnsupported
from unicorn.arm64_const import UC_ARM64_REG_X8

BASES=(0x122C0000,0x775C205000);G=oracle.GUEST;PACKED=G+0x3800;SP=G+0xEF00;TLS=G+0xD000
FIELD_PROFILES=('binary','empty','negative_min','negative_all_ones','NULL_source',
    'malloc_NULL','reload_after_allocate','self_alias','cross_page')
SUB_PROFILES=('middle','negative_start','negative_past_count','past_end','zero_count',
    'negative_count','wrapped_start_count','negative_declared_wrap','same_object',
    'malloc_NULL_positive','malloc_NULL_empty','cross_page','scratch_alias','canary_payload_alias')

def fresh(library,base,label,kind,wrapper):
    p={**oracle.image_pages(library,base),**oracle.fresh_pages()}
    obj=G+0x1800;out=G+0x1840;payload=G+0x2000;fields=G+0x1000;data=b'a\0z/?';length=5;start=1;count=3
    fail=label.startswith('malloc_NULL');expected=Services(failures=(0,) if fail else ());actual=Services(failures=(0,) if fail else ())
    body_sp=SP-16 if wrapper else SP;frame=body_sp-0x40
    if kind=='fields':
        if label=='empty':length=0
        elif label=='negative_min':length=0x80000000
        elif label=='negative_all_ones':length=0xFFFFFFFF
        elif label=='NULL_source':payload=0
        elif label=='self_alias':fields=out+8
        elif label=='cross_page':fields=G+0x2FF8;out=G+0x1FF8;payload=G+0x3FFF
        _write_span(p,fields,(0xFFFFFFFF).to_bytes(4,'little')+length.to_bytes(4,'little')+payload.to_bytes(8,'little'))
    else:
        if label=='negative_start':start=0xFFFFFFFF;count=3
        elif label=='negative_past_count':start=0xFFFFFFFD;count=2
        elif label=='past_end':start=9
        elif label=='zero_count':count=0
        elif label=='negative_count':count=0x80000000
        elif label=='wrapped_start_count':start=0x80000000;count=0xFFFFFFFF
        elif label=='negative_declared_wrap':length=0x80000000;start=1;count=2
        elif label=='same_object':out=obj
        elif label=='malloc_NULL_empty':count=0
        elif label=='cross_page':obj=G+0x1FF8;out=G+0x2FF8;payload=G+0x3FFF
        elif label=='scratch_alias':payload=frame+8;length=12;start=0;count=12
        elif label=='canary_payload_alias':payload=frame+0x18;length=8;start=0;count=8
        _write_span(p,obj,(base+0x34F5F8).to_bytes(8,'little')+(6).to_bytes(4,'little')+length.to_bytes(4,'little')+payload.to_bytes(8,'little'))
    if payload and label not in ('scratch_alias','canary_payload_alias'):_write_span(p,payload,data)
    _write_span(p,PACKED,(base+0x248D3C).to_bytes(8,'little')+out.to_bytes(8,'little')+obj.to_bytes(8,'little')+
        start.to_bytes(4,'little')+count.to_bytes(4,'little'))
    if label=='cross_page':expected.effects.next=actual.effects.next=G+0x5FF8
    return p,obj,out,fields,start,count,body_sp,expected,actual

def compare(library,base,label,kind,wrapper=False):
    p,obj,out,fields,start,count,body_sp,expected,actual=fresh(library,base,label,kind,wrapper)
    def mutate_native(cpu,n):
        pointer=expected.native_malloc(cpu,n)
        if label=='reload_after_allocate':cpu.mem_write(fields+8,(G+0x2100).to_bytes(8,'little'));cpu.mem_write(G+0x2100,b'Z\0Y!?')
        return pointer
    def mutate_model(p,n):
        pointer=actual.malloc(p,n)
        if label=='reload_after_allocate':_write_span(p,fields+8,(G+0x2100).to_bytes(8,'little'));_write_span(p,G+0x2100,b'Z\0Y!?')
        return pointer
    registers={UC_ARM64_REG_X8:out} if kind=='substring' and not wrapper else None
    args=[out,fields] if kind=='fields' else [PACKED] if wrapper else [obj,start,count]
    entry=0x248448 if kind=='fields' else 0x285CB8 if wrapper else 0x248D3C
    returned,memory,_,services=oracle.native(library,base,entry,args,p,
        malloc_handler=mutate_native,extra_registers=registers,instruction_limit=30000)
    if kind=='fields':
        value=objects.construct_string_object_from_fields(p,object_address=out,
            source_fields_address=fields,image_base=base,allocate=mutate_model)
        assert value==returned
    else:
        objects.construct_substring_string_object(p,object_address=out,source_object_address=obj,
            start_u32=start,count_u32=count,image_base=base,entry_stack_address=body_sp,
            thread_pointer=TLS,allocate=mutate_model)
    assert _read_span(p,G,0xA000)==memory,(label,kind,wrapper)
    assert expected.events==actual.events and expected.effects.calls==actual.effects.calls and expected.effects.blocks==actual.effects.blocks
    assert not services
    print('PASS',hex(base),kind,label,wrapper,flush=True)
    return dict(image_base=hex(base),case=label,kind=kind,actual_wrapper=wrapper,
        original_returned=True,guest_data_region_and_packed_bytes_match=True,
        ordered_allocation_and_heap_match=True,field_constructor_X0_verified=kind=='fields',
        substring_incidental_X0_not_claimed=kind=='substring',native_snapshot_input=False)

def guards(library):
    rows=[]
    for base in BASES:
        for label in ('unmapped_source','payload_bound','unmapped_object','unmapped_TLS',
            'unmapped_scratch','invalid_start','physical_spill_alias','output_frame_alias','canary_mutation','provider_exception'):
            p,obj,out,fields,start,count,sp,_,actual=fresh(library,base,'middle','substring',False)
            kw=dict(object_address=out,source_object_address=obj,start_u32=start,count_u32=count,
                image_base=base,entry_stack_address=sp,thread_pointer=TLS,allocate=actual.malloc)
            if label=='unmapped_source':_write_span(p,obj+16,(0x66000000).to_bytes(8,'little'))
            elif label=='payload_bound':kw['max_payload_bytes']=2
            elif label=='unmapped_object':kw['object_address']=0x66000000
            elif label=='unmapped_TLS':kw['thread_pointer']=0x66000000
            elif label=='unmapped_scratch':kw['entry_stack_address']=0x66000100
            elif label=='invalid_start':kw['start_u32']=1<<32
            elif label=='physical_spill_alias':_write_span(p,obj+16,(sp-0x40+0x20).to_bytes(8,'little'))
            elif label=='output_frame_alias':kw['object_address']=sp-0x40+8
            else:
                def effect(p,n):
                    pointer=actual.malloc(p,n)
                    if label=='provider_exception':_write_span(p,PACKED,b'\x11');raise RefillUnsupported('injected substring provider failure')
                    _write_span(p,TLS+0x28,b'\x11');return pointer
                kw['allocate']=effect
            before={k:bytes(v) for k,v in p.items()}
            try:objects.construct_substring_string_object(p,**kw)
            except (RefillUnsupported,ValueError):pass
            else:raise AssertionError('substring guard accepted '+label)
            assert before=={k:bytes(v) for k,v in p.items()}
            rows.append(dict(image_base=hex(base),case=label,rejected=True,all_pages_unchanged=True,
                external_effects_rolled_back=False))
            print('PASS substring guard',hex(base),label,flush=True)
    return rows

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--group',choices=('fields','substring','guards','all'),default='all');args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    cases=[];negative=[]
    if args.group in ('fields','all'):
        for base in BASES:
            for label in FIELD_PROFILES:cases.append(compare(args.library,base,label,'fields'))
    if args.group in ('substring','all'):
        for base in BASES:
            for label in SUB_PROFILES:
                for wrapper in (False,True):cases.append(compare(args.library,base,label,'substring',wrapper))
    if args.group in ('guards','all'):negative=guards(args.library)
    args.output.write_text(json.dumps(dict(component='Request field clone and substring constructors',
        cases=cases,negative_cases=negative,native_Python_controls=len(cases),rollback_guards=len(negative),
        guest_data_region_size=0xA000,whole_physical_stack_bytes_compared=False,native_input_snapshot_used=False,
        whole_request_native_differential_verified=False,actual_URL_header_JNI_conversion_verified=False,
        live_Android_JVM_verified=False,complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS',len(cases),'field/substring controls,',len(negative),'rollback guards',flush=True)
if __name__=='__main__':main()
