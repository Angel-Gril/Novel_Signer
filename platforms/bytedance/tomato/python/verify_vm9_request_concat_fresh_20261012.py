"""Original CString plus declared StringObject composition and temporary cleanup."""
from pathlib import Path
import argparse,hashlib,json
import vm9_objects as objects
import verify_vm9_signer_objects as oracle
from verify_vm9_strings import Effects
from vm9_allocator import _read_span,_write_span,RefillUnsupported
from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X8

BASES=(0x122C0000,0x775C205000);G=oracle.GUEST;PACKED=G+0x3800;SP=G+0xEF00;TLS=G+0xD000
PROFILES=('binary_tail','empty_first','NULL_first','empty_second','NULL_second_payload',
    'negative_second_length','output_is_second','first_is_output','second_is_temporary',
    'output_is_temporary','cross_page','first_malloc_NULL','clone_malloc_NULL',
    'both_constructors_NULL','reserve_malloc_NULL','reserve_malloc_realloc_NULL',
    'realloc_inplace','reload_second_after_clone','reload_second_after_growth',
    'temporary_payload_alias','canary_payload_alias')

class ObservedEffects(Effects):
    def __init__(self,**kw):super().__init__(**kw);self.pre_free=[]
    def operation(self,kind,size,pointer,read,write):
        if kind=='free' and pointer:self.pre_free.append([pointer,read(pointer,self.blocks[pointer]).hex()])
        return super().operation(kind,size,pointer,read,write)

def fresh(library,base,label,wrapper):
    p={**oracle.image_pages(library,base),**oracle.fresh_pages()}
    src=G+0x2000;second=G+0x1800;out=G+0x1840;payload=G+0x2200
    first=b'pre\0';tail=b'a\0z?\0';length=4;body_sp=SP-16 if wrapper else SP;frame=body_sp-0x50
    failures=();inplace=label=='realloc_inplace'
    if label in ('empty_first','first_malloc_NULL'):first=b'\0'
    elif label=='NULL_first':src=0
    elif label=='empty_second':length=0
    elif label=='NULL_second_payload':payload=0
    elif label=='negative_second_length':length=0x80000000
    elif label=='output_is_second':out=second
    elif label=='first_is_output':src=out+8
    elif label=='second_is_temporary':second=frame
    elif label=='output_is_temporary':out=frame
    elif label=='cross_page':src=G+0x3FFF;second=G+0x1FF8;out=G+0x2FF8;payload=G+0x2FFF
    elif label=='temporary_payload_alias':payload=frame+8
    elif label=='canary_payload_alias':payload=frame+0x18;length=8
    if label=='first_malloc_NULL':failures=(0,)
    elif label=='clone_malloc_NULL':failures=(1,)
    elif label=='both_constructors_NULL':failures=(0,1)
    elif label in ('reserve_malloc_NULL','realloc_inplace'):failures=(2,)
    elif label=='reserve_malloc_realloc_NULL':failures=(2,3)
    _write_span(p,second,(base+0x34F5F8).to_bytes(8,'little')+(16).to_bytes(4,'little')+length.to_bytes(4,'little')+payload.to_bytes(8,'little'))
    if src:_write_span(p,src,first)
    if payload and label not in ('temporary_payload_alias','canary_payload_alias'):_write_span(p,payload,tail)
    _write_span(p,PACKED,(base+0x248F5C).to_bytes(8,'little')+out.to_bytes(8,'little')+src.to_bytes(8,'little')+second.to_bytes(8,'little'))
    def mutate(kind,index,read,write):
        if kind=='malloc' and (label=='reload_second_after_clone' and index==1 or label=='reload_second_after_growth' and index==2):
            write(second+16,(G+0x2300).to_bytes(8,'little'));write(G+0x2300,b'Z\0Y!\0')
    expected=ObservedEffects(blocks=(),failures=failures,inplace=inplace,mutate=mutate)
    actual=ObservedEffects(blocks=(),failures=failures,inplace=inplace,mutate=mutate)
    if label=='cross_page':expected.next=actual.next=G+0x5FF8
    return p,src,second,out,body_sp,expected,actual

def compare(library,base,label,wrapper):
    p,src,second,out,sp,expected,actual=fresh(library,base,label,wrapper)
    observed={(page<<12,4096):None for page in p if not G<=page<<12<G+0x10000}
    append_results=[]
    def observer(cpu,address):
        if address==base+0x248FA0:append_results.append(cpu.reg_read(UC_ARM64_REG_X0)&0xFFFFFFFF)
    returned,memory,_,services=oracle.native(library,base,0x285CD8 if wrapper else 0x248F5C,
        [PACKED] if wrapper else [src,second],p,extra_registers=None if wrapper else {UC_ARM64_REG_X8:out},
        malloc_handler=lambda cpu,n:expected.native(cpu,'malloc',n),host_imports={
            0x347FA0:lambda cpu:expected.native(cpu,'free',pointer=cpu.reg_read(UC_ARM64_REG_X0)),
            0x348320:lambda cpu:expected.native(cpu,'realloc',cpu.reg_read(UC_ARM64_REG_X1),cpu.reg_read(UC_ARM64_REG_X0))},
        observed_memory=observed,instruction_observer=observer,instruction_limit=30000)
    status=objects.construct_cstring_string_object(p,object_address=out,first_cstring_address=src,
        second_object_address=second,image_base=base,entry_stack_address=sp,thread_pointer=TLS,
        allocate=actual.malloc,reallocate=actual.realloc,free=actual.free)
    got=_read_span(p,G,0xA000)
    if got!=memory:
        i=next(i for i,(a,b) in enumerate(zip(got,memory)) if a!=b)
        raise AssertionError((label,wrapper,hex(i),got[i],memory[i]))
    assert append_results==[status&0xFFFFFFFF],(label,append_results,status)
    assert expected.calls==actual.calls and expected.blocks==actual.blocks and expected.pre_free==actual.pre_free,(label,'allocator effects')
    assert not services
    for (a,n),data in observed.items():assert _read_span(p,a,n)==data
    print('PASS',hex(base),label,wrapper,flush=True)
    return dict(image_base=hex(base),case=label,actual_wrapper=wrapper,original_returned=True,
        guest_data_region_and_packed_bytes_match=True,all_main_image_pages_match=True,
        allocation_append_free_order_and_pre_free_bytes_match=True,remaining_heap_matches=True,
        internal_append_status_matches=True,outer_incidental_X0_not_claimed=True,native_snapshot_input=False)

def guards(library):
    rows=[]
    for base in BASES:
        for label in ('unmapped_output','unmapped_second','unmapped_first','unmapped_TLS',
            'unmapped_scratch','first_bound','second_bound','physical_payload_alias',
            'physical_object_alias','first_temporary_alias','canary_mutation','provider_exception',
            'first_allocator_mutation','late_physical_payload_alias'):
            p,src,second,out,sp,_,e=fresh(library,base,'binary_tail',False)
            kw=dict(object_address=out,first_cstring_address=src,second_object_address=second,
                image_base=base,entry_stack_address=sp,thread_pointer=TLS,
                allocate=e.malloc,reallocate=e.realloc,free=e.free)
            if label=='unmapped_output':kw['object_address']=0x66000000
            elif label=='unmapped_second':kw['second_object_address']=0x66000000
            elif label=='unmapped_first':kw['first_cstring_address']=0x66000000
            elif label=='unmapped_TLS':kw['thread_pointer']=0x66000000
            elif label=='unmapped_scratch':kw['entry_stack_address']=0x66001000
            elif label=='first_bound':kw['max_payload_bytes']=2
            elif label=='second_bound':_write_span(p,second+12,(200).to_bytes(4,'little'));kw['max_payload_bytes']=100
            elif label=='physical_payload_alias':_write_span(p,second+16,(sp-0x50+0x20).to_bytes(8,'little'))
            elif label=='physical_object_alias':kw['object_address']=sp-0x50+0x20
            elif label=='first_temporary_alias':kw['first_cstring_address']=sp-0x50+8
            else:
                def effect(p,n):
                    pointer=e.malloc(p,n)
                    if label=='canary_mutation':_write_span(p,TLS+0x28,b'\x11')
                    elif label=='provider_exception':_write_span(p,PACKED,b'\x11');raise RefillUnsupported('injected composition provider failure')
                    elif label=='first_allocator_mutation':_write_span(p,src,b'X')
                    elif len([c for c in e.calls if c[0]=='malloc'])==3:_write_span(p,second+16,(sp-0x50+0x20).to_bytes(8,'little'))
                    return pointer
                kw['allocate']=effect
            before={k:bytes(v) for k,v in p.items()}
            try:objects.construct_cstring_string_object(p,**kw)
            except (RefillUnsupported,ValueError):pass
            else:raise AssertionError('composition guard accepted '+label)
            assert before=={k:bytes(v) for k,v in p.items()}
            rows.append(dict(image_base=hex(base),case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
            print('PASS guard',hex(base),label,flush=True)
    return rows

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--group',choices=('composition','guards','all'),default='all');args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    cases=[];negative=[]
    if args.group in ('composition','all'):
        for base in BASES:
            for label in PROFILES:
                for wrapper in (False,True):cases.append(compare(args.library,base,label,wrapper))
    if args.group in ('guards','all'):negative=guards(args.library)
    args.output.write_text(json.dumps(dict(component='CString and StringObject composition with temporary cleanup',
        cases=cases,negative_cases=negative,native_Python_controls=len(cases),rollback_guards=len(negative),
        guest_data_region_size=0xA000,whole_physical_stack_bytes_compared=False,native_input_snapshot_used=False,
        whole_request_native_differential_verified=False,actual_URL_header_JNI_conversion_verified=False,
        live_Android_JVM_verified=False,complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS',len(cases),'new composition controls,',len(negative),'rollback guards',flush=True)
if __name__=='__main__':main()
