"""Fresh +288508/+32a1f0 allocation wrapper; malloc is an explicit provider.

The original operator-new success path executes. NULL/new-handler/throw and
physical ABI/PAC are unproved. Actual owning allocator comparison is separate.
"""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
import vm9_request_287474_vm as model
from vm9_allocator import RefillUnsupported,_read_span,_write_span
G=oracle.GUEST;SP=G+0xEF00;TP=G+0xD000;BLOCK=G+0x1500
BASES=(0x122C0000,0x775C205000)
LIBC_SHA256='d2376df6d2ac3e0213f85e3614c4c7ad1d28c84c44926058d5c1b95c855563db'
PROFILES=('size_zero','size_one','size24','size4097','max_size','high_pointer',
    'cross_page_input','cross_page_result','provider_rewrites_packed','allocation_packed_alias')


def put(p,a,v):_write_span(p,a,v.to_bytes(8,'little'))


def fixture(library,image,label):
    p=oracle.image_pages(library,image);p.update(oracle.fresh_pages())
    block=G+0x2FF8 if label=='cross_page_input' else G+0x2FEC if label=='cross_page_result' else BLOCK
    size={'size_zero':0,'size_one':1,'size4097':4097,'max_size':(1<<64)-1}.get(label,24)
    pointer=0xFEDCBA9876543210 if label=='high_pointer' else block if label=='allocation_packed_alias' else G+0x4500
    _write_span(p,block,b''.join(v.to_bytes(8,'little') for v in (image+0x32A1F0,size,0xA6A6A6A6A6A6A6A6,0xB7B7B7B7B7B7B7B7)))
    return p,dict(argument_block_address=block,entry_stack_address=SP,image_base=image),size,pointer


def provider(block,label,pointer,events,write):
    def allocate(size):
        events.append(['malloc',size,pointer])
        if label=='provider_rewrites_packed':
            write(block,b'\x31'*24)
            write(block+24,b'\x42'*8)
        return pointer
    return allocate


def original(library,libc,image,p,kw,label,pointer):
    events=[];steps=[0];seen=set();block=kw['argument_block_address']
    def observe(cpu,address):
        steps[0]+=1
        if address-image in (0x288508,0x32A1F0,0x347FD0):seen.add(address-image)
    watch={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000}
    watch.update({(G,SP-G-0x1000):None,(SP,G+0x10000-SP):None})
    def malloc(cpu,size):return provider(block,label,pointer,events,cpu.mem_write)(size)
    result,_,allocations,ledger=oracle.native(library,image,0x288508,[block],p,libc=libc,
        malloc_handler=malloc,instruction_observer=observe,observed_memory=watch,instruction_limit=1000,
        extra_registers={arm.UC_ARM64_REG_SP:SP,arm.UC_ARM64_REG_TPIDR_EL0:TP})
    assert seen=={0x288508,0x32A1F0,0x347FD0} and not allocations and not ledger
    return result,watch,events,steps[0]


def red(library,libc):
    assert not hasattr(model,'apply_request_287474_allocation_callback')
    rows=[]
    for image in BASES:
        p,kw,size,pointer=fixture(library,image,'size_zero')
        result,watch,events,steps=original(library,libc,image,p,kw,'size_zero',pointer)
        assert result==pointer and events==[['malloc',1,pointer]]
        assert watch[(G,SP-G-0x1000)][BLOCK-G+16:BLOCK-G+24]==pointer.to_bytes(8,'little')
        rows.append(dict(image_base=hex(image),previous_allocation_callback_missing=True,
            original_wrapper_and_operator_new_returned=True,zero_size_normalized_to_one_observed=True,
            packed_X64_result_store_observed=True,native_instructions=steps,native_snapshot_input=False))
    return rows


def compare(library,libc,image,label):
    p,kw,size,pointer=fixture(library,image,label)
    result,watch,expected,steps=original(library,libc,image,p,kw,label,pointer)
    events=[]
    def allocate(tx,n):return provider(kw['argument_block_address'],label,pointer,events,lambda a,b:_write_span(tx,a,b))(n)
    own=model.apply_request_287474_allocation_callback(p,**kw,allocate=allocate)
    assert result==own==pointer and events==expected==[['malloc',max(size,1),pointer]],label
    assert all(_read_span(p,a,n)==data for (a,n),data in watch.items()),label
    print('PASS allocation',hex(image),label,steps,flush=True)
    return dict(image_base=hex(image),case=label,native_instructions=steps,
        original_wrapper_and_operator_new_returned=True,declared_image_and_guest_bytes_equal=True,
        X64_size_and_result_store_equal=True,ordered_explicit_allocation_effects_equal=True,
        zero_size_normalization_equal=True,no_JNI_lock_file_or_syscall_services=True,
        component_malloc_provider_explicit=True,native_snapshot_input=False,physical_spills_and_PAC_compared=False)


def guards(library):
    rows=[]
    for label in ('wrong_target','missing_packed','missing_result_after_allocation','unaligned_stack',
            'packed_stack_alias','missing_provider','NULL_allocation','invalid_pointer','provider_raises_after_effect'):
        p,kw,size,pointer=fixture(library,BASES[0],'size24');events=[]
        allocate=lambda p,n:pointer
        if label=='wrong_target':put(p,BLOCK,1)
        elif label=='missing_packed':kw['argument_block_address']=G+0x10000
        elif label=='missing_result_after_allocation':
            block=G+0x5FF0;_write_span(p,block,_read_span(p,BLOCK,16));kw['argument_block_address']=block;del p[(G+0x6000)>>12]
            def allocate(p,n):events.append('allocate');_write_span(p,G+0x4100,b'effect');return pointer
        elif label=='unaligned_stack':kw['entry_stack_address']+=1
        elif label=='packed_stack_alias':
            block=SP-0x20;_write_span(p,block,_read_span(p,BLOCK,32));kw['argument_block_address']=block
        elif label=='missing_provider':allocate=None
        elif label=='NULL_allocation':allocate=lambda p,n:0
        elif label=='invalid_pointer':allocate=lambda p,n:1<<64
        elif label=='provider_raises_after_effect':
            def allocate(p,n):events.append('allocate');_write_span(p,G+0x4100,b'effect');raise RuntimeError('allocation provider failure')
        before={k:bytes(v) for k,v in p.items()}
        try:model.apply_request_287474_allocation_callback(p,**kw,allocate=allocate)
        except (RefillUnsupported,ValueError,TypeError,RuntimeError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        if label in ('missing_result_after_allocation','provider_raises_after_effect'):assert events==['allocate']
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_provider_effects_rolled_back=False))
    return rows


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--libc',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--mode',choices=('red','native','guards'),default='native')
    parser.add_argument('--case',action='append',choices=PROFILES);a=parser.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(a.libc.read_bytes()).hexdigest()==LIBC_SHA256
    e=dict(cases=[],negative_cases=[],red_cases=[],native_snapshot_input=False,complete_second_vm_verified=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False,
        actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,
        complete_physical_ABI_verified=False,allocator_provider_mapping_rollback_verified=False)
    if a.mode=='red':e['red_cases']=red(a.library,a.libc)
    elif a.mode=='native':
        for b in BASES:
            for label in a.case or PROFILES:
                e['cases'].append(compare(a.library,a.libc,b,label))
                a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
    else:e['negative_cases']=guards(a.library)
    e.update(native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']))
    a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
if __name__=='__main__':main()
