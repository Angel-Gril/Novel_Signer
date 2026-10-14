"""Fresh actual +205074 logger wrapper with an initialized unavailable file sink.

The original logger/formatter/sink instructions execute. Conversion formats,
live sinks and physical variadic/spill bytes remain outside this contract.
"""
from pathlib import Path
import argparse,hashlib,json,os
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
import verify_vm9_worker_allocator as worker
import vm9_request_environment_vm as model
from vm9_allocator import RefillUnsupported,_read_span,_write_span
BASES=(0x122C0000,0x775C205000);G=oracle.GUEST
OWNER='apply_request_environment_logger_callback'

def fixture(library,image,label):
    pages=oracle.image_pages(library,image);pages.update(oracle.fresh_pages())
    block,obj,tag,fmt=G+0x1000,G+0x1800,G+0x2800,G+0x3800
    if label=='cross_page_format':fmt=G+0x3FFD
    if label=='cross_page_packed':block=G+0x1FE6
    if label=='packed_object_alias':obj=block
    _write_span(pages,obj,b''.join(n.to_bytes(8,'little') for n in (image+0x34F5F8,0x0000000700000008,tag)))
    text=b'' if label=='empty' else b'log\0tail' if label=='embedded_NUL' else b'helper log'
    _write_span(pages,tag,b'generic\0');_write_span(pages,fmt,text+b'\0')
    _write_span(pages,block,b''.join(n.to_bytes(8,'little') for n in (image+0x26E9E0,obj,fmt)))
    _write_span(pages,image+0x382600,(1).to_bytes(4,'little'))
    _write_span(pages,image+0x382610,(image+0x27220C).to_bytes(8,'little'))
    _write_span(pages,image+0x3DF1EC,bytes(40))
    for flag in (0x3DF17C,0x3DF190,0x3DF1A4,0x3DF1B8):_write_span(pages,image+flag,b'\1')
    return pages,dict(argument_block_address=block,image_base=image,entry_stack_address=G+0xEF00)

def native(library,libc,pages,inputs):
    image=inputs['image_base'];sp=inputs['entry_stack_address']-16
    output=sp-0x120-0x30-0x430+0x28;sink=sp-0x120-0x30-0x430-0x70
    watch={(G,0xA000):None,(output,0x400):None,(sink+4,52):None,
        (image+0x382600,0x40):None,(image+0x3DF1EC,40):None}
    def unexpected(*args):raise AssertionError('initialized file sink must not invoke external services')
    result,_,allocations,services=oracle.native(library,image,0x205074,[inputs['argument_block_address']],pages,
        libc=libc,real_mutexes=True,host_imports={},syscall_handler=unexpected,
        malloc_handler=unexpected,extra_registers={arm.UC_ARM64_REG_SP:inputs['entry_stack_address']},
        observed_memory=watch,instruction_limit=100000)
    assert not allocations and not services
    return result,watch

def red(library,libc):
    assert not hasattr(model,OWNER)
    rows=[]
    for image in BASES:
        pages,inputs=fixture(library,image,'normal');native(library,libc,pages,inputs)
        rows.append(dict(image_base=hex(image),original_logger_wrapper_returned=True,prior_consumer_missing=True,native_snapshot_input=False))
    return rows

def compare(library,libc,image,label):
    pages,inputs=fixture(library,image,label);initial={k:bytearray(v) for k,v in pages.items()}
    def unexpected(*args):raise AssertionError('initialized sink requires no property/syscall provider calls')
    result=getattr(model,OWNER)(pages,**inputs,read_property=unexpected,syscall=unexpected,errno_address=G+0xD100)
    _,watch=native(library,libc,initial,inputs)
    for (address,width),data in watch.items():
        assert data==_read_span(pages,address,width),(label,hex(address))
    assert int.from_bytes(_read_span(pages,inputs['argument_block_address']+24,4),'little')==result.return_value==0xFFFFFFFF
    print('PASS environment logger',hex(image),label,flush=True)
    return dict(image_base=hex(image),case=label,actual_wrapper='0x205074',original_logger_formatter_and_sink_returned=True,
        declared_guest_globals_output_and_sink_fields_equal=True,packed_W_result_and_padding_equal=True,
        initialized_unavailable_file_sink=True,no_external_provider_effects=True,native_snapshot_input=False)

def guards(library):
    rows=[]
    for label in ('wrong_target','missing_packed','missing_object','missing_format','conversion_format','truncated_format','unaligned_stack','live_sink','missing_result'):
        pages,inputs=fixture(library,BASES[0],'normal');block=inputs['argument_block_address']
        if label=='wrong_target':_write_span(pages,block,(BASES[0]+1).to_bytes(8,'little'))
        elif label=='missing_packed':del pages[block>>12]
        elif label=='missing_object':_write_span(pages,block+8,(G+0x10000).to_bytes(8,'little'))
        elif label=='missing_format':_write_span(pages,block+16,(G+0x10000).to_bytes(8,'little'))
        elif label=='conversion_format':_write_span(pages,G+0x3800,b'%s\0')
        elif label=='truncated_format':_write_span(pages,G+0x3800,b'a'*0x400+b'\0')
        elif label=='unaligned_stack':inputs['entry_stack_address']+=1
        elif label=='live_sink':_write_span(pages,BASES[0]+0x382610,(BASES[0]+0x272194).to_bytes(8,'little'))
        elif label=='missing_result':
            inputs['argument_block_address']=G+0xFFE8
            _write_span(pages,G+0xFFE8,_read_span(pages,block,24))
        before={k:bytes(v) for k,v in pages.items()}
        def unexpected(*args):raise RefillUnsupported('unexpected logger service')
        try:getattr(model,OWNER)(pages,**inputs,read_property=unexpected,syscall=unexpected,errno_address=G+0xD100)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in pages.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True))
    return rows

def entry_guards(library):
    os.environ['TOMATO_LIBMETASEC']=str(library.resolve())
    import vm_full
    from verify_vm9_request_environment_vm_fresh_20261013 import fixture as frame_fixture,packed
    assert Path(vm_full.__file__).resolve().parent==Path(__file__).resolve().parent
    rows=[]
    for label in ('invalid_logger_services','noncallable_logger_provider','missing_errno_address'):
        pages,inputs=frame_fixture(library,BASES[0],'normal');packed(pages,inputs)
        logger_services=dict(read_property=lambda p,n:None,syscall=lambda p,n,a:0,errno_address=G+0xD100)
        if label=='invalid_logger_services':logger_services=[]
        elif label=='noncallable_logger_provider':logger_services['read_property']=None
        else:del logger_services['errno_address']
        before={k:bytes(v) for k,v in pages.items()};previous=vm_full.B
        try:model.execute_request_environment_vm_prefix(pages,vm_module=vm_full,
            consumer_services=dict(allocate=lambda p,n:0,free=lambda p,a:None,logger_services=logger_services),
            argument_block_address=G+0x1000,**inputs)
        except RefillUnsupported:pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in pages.items()} and previous==vm_full.B
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,module_image_base_restored=True))
    return rows

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--libc',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--group',choices=('red','logger','guards','entry','all'),default='all');args=parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==worker.LIBC_SHA256
    report=dict(schema='vm9-request-environment-logger-fresh-v1',evidence_date='2026-10-14',sample_sha256=oracle.LIBRARY_SHA256,
        libc_sha256=worker.LIBC_SHA256,cases=[],negative_cases=[],entry_negative_cases=[],native_snapshot_input=False,private_names_or_payloads_published=False,
        whole_request_native_differential_verified=False,complete_helper_vm_verified=False,complete_child_vm_verified=False,
        complete_second_vm_verified=False,actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False,
        whole_physical_stack_bytes_compared=False,allocator_provider_mapping_rollback_verified=False)
    if args.group=='red':report['red_cases']=red(args.library,args.libc)
    if args.group in ('logger','all'):report['cases']=[compare(args.library,args.libc,image,label) for image in BASES for label in
        ('normal','empty','embedded_NUL','cross_page_format','cross_page_packed','packed_object_alias')]
    if args.group in ('guards','all'):report['negative_cases']=guards(args.library)
    if args.group in ('entry','all'):report['entry_negative_cases']=entry_guards(args.library)
    report['native_Python_controls']=len(report['cases']);report['rollback_guards']=len(report['negative_cases'])
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS environment logger',args.group,report['native_Python_controls'],report['rollback_guards'])
if __name__=='__main__':main()
