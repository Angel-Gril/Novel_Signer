"""Fresh +28861c/+2485a4 assignment, allocator effects and ordered reloads."""
from pathlib import Path
import argparse,hashlib,json
from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X1
import verify_vm9_signer_objects as oracle
from verify_vm9_strings import Effects,fields
import vm9_objects as objects
import vm9_request_287474_vm as model
from vm9_allocator import RefillUnsupported,_read_span,_write_span

BASES=(0x122C0000,0x775C205000);G=oracle.GUEST
OWNER='apply_request_287474_string_assignment_callback'
PROFILES=('empty','binary','shrink','same_object','same_payload','cross_page_fields',
    'cross_page_payload','grow_malloc','grow_realloc','realloc_inplace','malloc_failure_realloc',
    'realloc_fallback','all_growth_fail','NULL_destination_payload','NULL_source_empty',
    'allocator_changes_source_length','copy_changes_destination_length','packed_return_payload_alias')


def fixture(library,image,label):
    p=oracle.image_pages(library,image);p.update(oracle.fresh_pages())
    dest,source,payload,src,block=(G+x for x in (0x1000,0x1800,0x2800,0x3000,0x3800))
    data=b'new';old=b'previous';capacity=64;failures=();inplace=False;mutate=None
    if label=='empty':data=b''
    elif label=='binary':data=b'x\0\x80\xff'
    elif label in ('grow_malloc','grow_realloc','realloc_inplace','malloc_failure_realloc',
            'realloc_fallback','all_growth_fail','allocator_changes_source_length'):
        capacity=8;old=b'12345678' if label in ('grow_realloc','realloc_inplace','realloc_fallback','all_growth_fail') else b'ab'
        data=b'0123456789Z'
        if label=='malloc_failure_realloc':failures=(0,)
        elif label=='realloc_fallback':failures=(0,)
        elif label=='all_growth_fail':failures=(0,1)
        inplace=label=='realloc_inplace'
    elif label=='cross_page_fields':source=G+0x1FF4
    elif label=='cross_page_payload':src=G+0x3FFE
    elif label=='NULL_source_empty':src=0;data=b''
    elif label=='packed_return_payload_alias':payload=block+24
    elif label=='copy_changes_destination_length':payload=dest+12;old=b'';data=bytes(4)
    _write_span(p,payload,old+b'\0')
    if src:_write_span(p,src,data+b'\0')
    _write_span(p,dest,(image+0x34F5F8).to_bytes(8,'little'))
    fields(p,dest+8,capacity,len(old),0 if label=='NULL_destination_payload' else payload)
    _write_span(p,source,(image+0x34F5F8).to_bytes(8,'little'))
    fields(p,source+8,64,len(data),payload if label=='same_payload' else src)
    if label=='same_payload':fields(p,source+8,64,len(old),payload)
    elif label=='same_object':source=dest
    elif label=='allocator_changes_source_length':
        def mutate(kind,index,read,write):
            if kind!='free':write(source+12,(2).to_bytes(4,'little'))
    _write_span(p,block,b''.join(n.to_bytes(8,'little') for n in (image+0x2485A4,dest,source,0xA5A5A5A5A5A5A5A5)))
    kw=dict(wrapper_offset=0x28861C,argument_block_address=block,image_base=image)
    effects=dict(blocks={payload:64},failures=failures,inplace=inplace,mutate=mutate)
    return p,kw,effects


def original(library,image,p,kw,effects):
    steps=[0];seen=set()
    def observe(cpu,address):
        steps[0]+=1
        if address-image in (0x28861C,0x2485A4):seen.add(address-image)
    result,memory,_,ledger=oracle.native(library,image,0x28861C,[kw['argument_block_address']],p,
        malloc_handler=lambda cpu,n:effects.native(cpu,'malloc',n),
        host_imports={0x347FA0:lambda cpu:effects.native(cpu,'free',pointer=cpu.reg_read(UC_ARM64_REG_X0)),
            0x348320:lambda cpu:effects.native(cpu,'realloc',cpu.reg_read(UC_ARM64_REG_X1),cpu.reg_read(UC_ARM64_REG_X0))},
        instruction_observer=observe,instruction_limit=20000)
    assert seen=={0x28861C,0x2485A4} and not ledger
    return result,memory,steps[0]


def red(library):
    assert not hasattr(model,OWNER) and not hasattr(objects,'assign_string_object')
    rows=[]
    for image in BASES:
        p,kw,e=fixture(library,image,'binary');result,memory,steps=original(library,image,p,kw,Effects(**e))
        assert int.from_bytes(memory[kw['argument_block_address']-G+24:kw['argument_block_address']-G+32],'little')==G+0x1000
        rows.append(dict(image_base=hex(image),original_assignment_wrapper_returned=True,
            packed_pointer_result_written=True,previous_owner_and_adapter_missing=True,native_snapshot_input=False))
    return rows


def compare(library,image,label):
    p,kw,e=fixture(library,image,label);initial={k:bytearray(v) for k,v in p.items()}
    actual=Effects(**e);expected=Effects(**e)
    got=getattr(model,OWNER)(p,**kw,allocate=actual.malloc,reallocate=actual.realloc,free=actual.free)
    result,memory,steps=original(library,image,initial,kw,expected)
    assert got==result==G+0x1000 and _read_span(p,G,0xA000)==memory,label
    assert actual.calls==expected.calls and actual.blocks==expected.blocks,(label,'allocator')
    kinds=[call[0] for call in actual.calls]
    expected_kinds={'grow_malloc':['malloc','free'],'grow_realloc':['realloc'],
        'realloc_inplace':['realloc'],'malloc_failure_realloc':['malloc','realloc'],
        'realloc_fallback':['realloc','realloc'],'all_growth_fail':['realloc','realloc'],
        'allocator_changes_source_length':['malloc','free']}.get(label,[])
    assert kinds==expected_kinds,(label,kinds)
    assert all(p[k]==initial[k] for k in p if not G<=k<<12<G+0xA000)
    print('PASS second assignment',hex(image),label,steps,flush=True)
    return dict(image_base=hex(image),case=label,native_instructions=steps,
        actual_wrapper='0x28861c',actual_assignment='0x2485a4',original_wrapper_and_assignment_returned=True,
        all_declared_guest_bytes_equal=True,ordered_allocator_effects_and_state_equal=True,
        pointer_result_and_packed_aliases_equal=True,allocator_effect_kinds=kinds,native_snapshot_input=False)


def guards(library):
    rows=[]
    for label in ('wrong_wrapper','wrong_target','missing_packed','NULL_destination','NULL_source',
            'unmapped_destination','unmapped_source','unmapped_payload','negative_source_length',
            'partial_overlap','operation_bound','missing_reallocate','missing_result_page'):
        p,kw,e=fixture(library,BASES[0],'binary');block=kw['argument_block_address'];effects=Effects(**e)
        def w(a,v,n=8):_write_span(p,a,v.to_bytes(n,'little'))
        if label=='wrong_wrapper':kw['wrapper_offset']+=4
        elif label=='wrong_target':w(block,BASES[0]+1)
        elif label=='missing_packed':del p[block>>12]
        elif label=='NULL_destination':w(block+8,0)
        elif label=='NULL_source':w(block+16,0)
        elif label=='unmapped_destination':w(block+8,0x64000000)
        elif label=='unmapped_source':w(block+16,0x64000000)
        elif label=='unmapped_payload':w(G+0x1810,0x64000000)
        elif label=='negative_source_length':w(G+0x180C,0xFFFFFFFF,4)
        elif label=='partial_overlap':w(G+0x1810,G+0x2801)
        elif label=='operation_bound':kw['max_bytes']=1
        elif label=='missing_result_page':
            tail=G+0x9FE8;_write_span(p,tail,_read_span(p,block,24));kw['argument_block_address']=tail
            del p[(tail+24)>>12]
        kw.update(allocate=effects.malloc,reallocate=None if label=='missing_reallocate' else effects.realloc,free=effects.free)
        before={k:bytes(v) for k,v in p.items()}
        try:getattr(model,OWNER)(p,**kw)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_allocator_effects_rolled_back=False))
    return rows


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--group',choices=('red','assignment','guards','all'),default='all');args=parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    e=dict(schema='vm9-request-second-assignment-fresh-v1',evidence_date='2026-10-15',
        sample_sha256=oracle.LIBRARY_SHA256,cases=[],negative_cases=[],accepted_native_controls_not_repeated=True,
        native_snapshot_input=False,private_names_or_payloads_published=False,complete_second_vm_verified=False,
        whole_request_native_differential_verified=False,actual_URL_header_JNI_conversion_verified=False,
        live_Android_JVM_verified=False,complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False,whole_physical_stack_bytes_compared=False,
        allocator_provider_mapping_rollback_verified=False)
    if args.group=='red':e['red_cases']=red(args.library)
    if args.group in ('assignment','all'):e['cases']=[compare(args.library,b,n) for b in BASES for n in PROFILES]
    if args.group in ('guards','all'):e['negative_cases']=guards(args.library)
    e.update(native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']))
    args.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS second assignment',args.group,e['native_Python_controls'],e['rollback_guards'])
if __name__=='__main__':main()
