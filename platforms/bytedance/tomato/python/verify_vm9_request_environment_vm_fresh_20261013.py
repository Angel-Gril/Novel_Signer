"""Fresh +204e50/+204ed4 callers, actual +2814c8 wrapper and decode prefixes."""
from pathlib import Path
import argparse,hashlib,json,os
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
import vm9_request_caller as caller
from vm9_allocator import RefillUnsupported,_read_span,_write_span
BASES=(0x122C0000,0x775C205000);G=oracle.GUEST
OWNER='prepare_request_environment_vm_caller'
def fixture(library,image,label):
    pages=oracle.image_pages(library,image);pages.update(oracle.fresh_pages())
    inputs=dict(helper_offset=0x204E50,entry_stack_address=G+0xEF00,return_address=oracle.STOP,
        thread_pointer=G+0xD000,image_base=image,
        saved_frame_pointer=G+0xDE00,saved_x28=0x123456789ABCDEF0,saved_x19=G+0x2200)
    if label=='relocated_stack':inputs['entry_stack_address']=G+0xDF00;inputs['thread_pointer']=G+0xC000
    elif label=='TLS_spill_alias':inputs['thread_pointer']=inputs['entry_stack_address']-0x48
    elif label=='wide_saved_words':inputs.update(saved_frame_pointer=0xFEDCBA9876543210,saved_x28=(1<<64)-1,saved_x19=1<<63)
    elif label=='patterned_stack':
        start=inputs['entry_stack_address']-0xF30
        _write_span(pages,start,bytes((i*37+11)&255 for i in range(0xF30)))
    return pages,inputs
def original(library,pages,inputs,watch,wrapper=False,stop=0x1684F0,observer=None):
    args=[]
    extras={arm.UC_ARM64_REG_SP:inputs['entry_stack_address'],arm.UC_ARM64_REG_X30:inputs['return_address'],
        arm.UC_ARM64_REG_TPIDR_EL0:inputs['thread_pointer'],arm.UC_ARM64_REG_X29:inputs['saved_frame_pointer'],
        arm.UC_ARM64_REG_X28:inputs['saved_x28'],arm.UC_ARM64_REG_X19:inputs['saved_x19']}
    if wrapper:args=[G+0x1000]
    return oracle.native(library,inputs['image_base'],0x2814C8 if wrapper else inputs['helper_offset'],
        args,pages,stop_offset=stop,observed_memory=watch,extra_registers=extras,
        instruction_limit=100000,instruction_observer=observer)
def packed(pages,inputs):
    words=(inputs['image_base']+inputs['helper_offset'],0x12345678DEADBEEF,0xACACACACACACACAC,0x9191919191919191)
    _write_span(pages,G+0x1000,b''.join(v.to_bytes(8,'little') for v in words))
def red(library):
    assert not hasattr(caller,OWNER)
    rows=[]
    for helper in (0x204E50,0x204ED4):
        pages,inputs=fixture(library,BASES[0],'patterned_stack');inputs['helper_offset']=helper
        original(library,pages,inputs,{(inputs['entry_stack_address']-0x510,0x510):None})
        rows.append(dict(helper=hex(helper),original_helper_caller_reached=True,prior_owner_missing=True,native_snapshot_input=False))
    return rows

def frame_control(library,image,helper,label,wrapper=False):
    import vm9_request_environment_vm as model
    pages,inputs=fixture(library,image,label);inputs['helper_offset']=helper
    if wrapper:packed(pages,inputs)
    initial={k:bytearray(v) for k,v in pages.items()}
    if wrapper:
        frame=model.prepare_request_environment_wrapper_caller(pages,argument_block_address=G+0x1000,
            **inputs)
    else:frame=getattr(caller,OWNER)(pages,**inputs)
    watch={(frame.native_stack_address,inputs['entry_stack_address']-frame.native_stack_address):None};entries=[]
    def observe(cpu,address):
        if address==image+0x168324:
            entries.append(tuple(cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(5)))
    _,memory,allocations,services=original(library,initial,inputs,watch,wrapper,observer=observe)
    assert not allocations and not services and entries==[frame.vm_call_registers]
    assert _read_span(pages,G,0xA000)==memory[:0xA000]
    assert _read_span(pages,*next(iter(watch)))==next(iter(watch.values()))
    print('PASS environment helper frame',hex(image),hex(helper),label,'wrapper' if wrapper else 'direct',flush=True)
    return dict(image_base=hex(image),helper=hex(helper),case=label,actual_wrapper_executed=wrapper,
        original_caller_and_generic_prelude_reached=True,complete_caller_frame_and_all_32_backing_words_equal=True,
        five_VM_arguments_equal=True,packed_result_and_padding_preserved=True,native_snapshot_input=False)
def prefix_control(library,image,helper,label,vm_module):
    import vm9_request_environment_vm as model
    pages,inputs=fixture(library,image,label);inputs['helper_offset']=helper;packed(pages,inputs)
    initial={k:bytearray(v) for k,v in pages.items()}
    result=model.execute_request_environment_vm_prefix(pages,vm_module=vm_module,argument_block_address=G+0x1000,
        **inputs)
    watch={(result.frame.register_backing_address,0x100):None,(result.callbacks[-1][2],0x20):None,
        **{(a,n):None for a,n in result.decoded}}
    ledger=[]
    def observe(cpu,address):
        if address-image in (0x205044,0x2050F0):
            a=cpu.reg_read(arm.UC_ARM64_REG_X0)
            words=tuple(int.from_bytes(cpu.mem_read(a+i*8,8),'little') for i in range(4))
            ledger.append((address-image,words[0]-image,a,words))
    returned,_,allocations,services=original(library,initial,inputs,watch,True,result.callbacks[-1][0],observe)
    assert not allocations and not services and ledger==list(result.callbacks[:-1]) and returned==result.callbacks[-1][2]
    words=tuple(int.from_bytes(watch[result.frame.register_backing_address,0x100][i*8:i*8+8],'little') for i in range(32))
    assert words==result.registers
    assert all(_read_span(result.staged,a,n)==data for (a,n),data in watch.items() if a!=result.frame.register_backing_address)
    assert all(pages[k]==initial[k] for k in pages)
    print('PASS environment helper prefix',hex(image),hex(helper),label,result.steps,flush=True)
    return dict(image_base=hex(image),helper=hex(helper),case=label,steps=result.steps,bytecode_offset=hex(result.pc-image),
        callback_ledger_and_packed_and_decoded_ranges_equal=True,all_32_virtual_registers_equal=True,
        supplied_pages_unchanged=True,native_snapshot_input=False,complete_helper_vm_verified=False)
def guards(library):
    rows=[]
    for label in ('unaligned_stack','underflow_stack','tagged_return','wide_saved_word','unknown_helper','missing_TLS','missing_frame','missing_bytecode'):
        pages,inputs=fixture(library,BASES[0],'patterned_stack')
        if label=='unaligned_stack':inputs['entry_stack_address']+=1
        elif label=='underflow_stack':inputs['entry_stack_address']=0x100
        elif label=='tagged_return':inputs['return_address']|=1<<56
        elif label=='wide_saved_word':inputs['saved_x19']=1<<64
        elif label=='unknown_helper':inputs['helper_offset']=1
        elif label=='missing_TLS':del pages[inputs['thread_pointer']>>12]
        elif label=='missing_frame':del pages[(inputs['entry_stack_address']-0x500)>>12]
        elif label=='missing_bytecode':del pages[(BASES[0]+0x8A040)>>12]
        before={k:bytes(v) for k,v in pages.items()}
        try:getattr(caller,OWNER)(pages,**inputs)
        except RefillUnsupported:pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in pages.items()}
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True))
    return rows

def wrapper_guards(library):
    import vm9_request_environment_vm as model
    rows=[]
    for label in ('wrong_wrapper_target','missing_wrapper_packed','tagged_wrapper_return'):
        pages,inputs=fixture(library,BASES[0],'normal');packed(pages,inputs)
        if label=='wrong_wrapper_target':_write_span(pages,G+0x1000,(BASES[0]+1).to_bytes(8,'little'))
        elif label=='missing_wrapper_packed':del pages[(G+0x1000)>>12]
        else:inputs['return_address']|=1<<56
        before={k:bytes(v) for k,v in pages.items()}
        try:model.prepare_request_environment_wrapper_caller(pages,argument_block_address=G+0x1000,
            **inputs)
        except RefillUnsupported:pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in pages.items()}
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True))
    return rows

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--group',choices=('red','frames','prefix','guards','wrapper_guards','all'),default='all');a=p.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    report=dict(schema='vm9-request-environment-vm-fresh-v1',evidence_date='2026-10-13',sample_sha256=oracle.LIBRARY_SHA256,
        frame_cases=[],prefix_cases=[],negative_cases=[],native_snapshot_input=False,private_names_or_payloads_published=False,
        whole_request_native_differential_verified=False,actual_URL_header_JNI_conversion_verified=False,
        live_Android_JVM_verified=False,complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False,
        whole_physical_stack_bytes_compared=False,allocator_provider_mapping_rollback_verified=False,complete_helper_vm_verified=False)
    if a.group=='red':report['red_cases']=red(a.library)
    if a.group in ('frames','all'):
        report['frame_cases']=[frame_control(a.library,image,helper,label,wrapper)
            for image in BASES for helper in (0x204E50,0x204ED4)
            for wrapper,labels in ((False,('normal','relocated_stack','TLS_spill_alias','patterned_stack')),
                (True,('normal','patterned_stack'))) for label in labels]
    if a.group in ('prefix','all'):
        os.environ['TOMATO_LIBMETASEC']=str(a.library.resolve());import vm_full
        assert Path(vm_full.__file__).resolve().parent==Path(__file__).resolve().parent
        report['prefix_cases']=[prefix_control(a.library,image,helper,label,vm_full) for image in BASES for helper in (0x204E50,0x204ED4) for label in ('normal','patterned_stack')]
    if a.group in ('guards','all'):report['negative_cases']=guards(a.library)
    if a.group in ('wrapper_guards','all'):report['negative_cases']+=wrapper_guards(a.library)
    report['native_Python_controls']=len(report['frame_cases'])+len(report['prefix_cases']);report['rollback_guards']=len(report['negative_cases'])
    a.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS environment helper VM',a.group,report['native_Python_controls'],report['rollback_guards'])
if __name__=='__main__':main()
