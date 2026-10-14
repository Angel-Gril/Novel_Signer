"""Fresh child selected-slot VM exit and physical caller/wrapper return."""
from pathlib import Path
import argparse,hashlib,json,os
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
import vm9_request_caller as model
from vm9_allocator import RefillUnsupported,_read_span,_write_span
BASES=(0x122C0000,0x775C205000);G=oracle.GUEST
OWNER='finish_request_28048c_wrapper_caller'
PROFILES=('normal','relocated_stack','patterned_stack','wide_saved_words',
    'TLS_frame_alias','TLS_wrapper_LR_alias','TLS_saved_FP_alias','TLS_saved_X19_alias',
    'TLS_saved_X28_alias','TLS_saved_LR_alias','NULL_saved_words')


def fixture(library,image,label):
    pages=oracle.image_pages(library,image);pages.update(oracle.fresh_pages())
    stack=G+(0xDF00 if label=='relocated_stack' else 0xEF00)
    entry=stack-16;local=entry-0xF20;generic=local-0x60
    thread=G+0xC000;backing=G+0x7000
    if label=='patterned_stack':
        _write_span(pages,generic-0x50,bytes((i*37+19)&255 for i in range(stack-generic+0x50)))
    words=(G+0xCC00,0x123456789ABCDEF0,0xFEDCBA9876543210)
    if label=='NULL_saved_words':words=(0,0,0)
    elif label=='wide_saved_words':words=((1<<64)-1,1<<63,(1<<64)-2)
    for address,value in ((entry-0x20,words[0]),(entry-0x18,image+0x2885C8),
            (entry-0x10,words[1]),(entry-8,words[2]),(stack-16,oracle.STOP)):
        _write_span(pages,address,value.to_bytes(8,'little'))
    aliases={'TLS_frame_alias':entry-0x28,'TLS_wrapper_LR_alias':stack-16,
        'TLS_saved_FP_alias':entry-0x20,'TLS_saved_X19_alias':entry-8,
        'TLS_saved_X28_alias':entry-0x10,'TLS_saved_LR_alias':entry-0x18}
    if label in aliases:thread=aliases[label]-0x28
    _write_span(pages,entry-0x28,_read_span(pages,thread+0x28,8))
    # Generic VM saved physical state is supplied independently of its output.
    for offset,value in ((0,entry-0x20),(8,image+0x2804F0),(16,0x2828),
            (24,0x2727),(32,0x2626),(40,0x2525),(48,0x2424),(56,0x2323),
            (64,0x2222),(72,0x2121),(80,0x2020),(88,thread),(-0x50,image+0x2885C8)):
        _write_span(pages,generic+offset,value.to_bytes(8,'little'))
    _write_span(pages,backing+31*8,(image+0x2885C8).to_bytes(8,'little'))
    return pages,dict(entry_stack_address=stack,thread_pointer=thread,image_base=image,
        callback_sentinel=image+0x281414),local,generic,backing


def original(library,pages,inputs,local,generic,backing):
    registers=[];seen=set();steps=[0];image=inputs['image_base'];stack=inputs['entry_stack_address']
    def observe(cpu,address):
        steps[0]+=1
        if address-image in (0x16A974,0x172440,0x2804F0,0x2885C8):seen.add(address-image)
        if address==image+0x2885CC:
            registers.append(tuple(cpu.reg_read(getattr(arm,'UC_ARM64_REG_'+n)) for n in ('X30','SP','X0','X19','X28','X29','X30')))
    # Generic handler's four W scratch outputs are at G+B000, outside declared
    # guest/caller ranges; the whole physical VM frame is not claimed here.
    watch={(G,0xA000):None,(generic-0x50,stack-generic+0x50):None}
    extras={arm.UC_ARM64_REG_SP:generic-0x100,arm.UC_ARM64_REG_X29:generic,
        arm.UC_ARM64_REG_X28:backing,arm.UC_ARM64_REG_X21:0x07C00791,
        arm.UC_ARM64_REG_X0:inputs['callback_sentinel'],arm.UC_ARM64_REG_TPIDR_EL0:inputs['thread_pointer']}
    extras.update({getattr(arm,'UC_ARM64_REG_X'+str(r)):G+0xB000+(r-22)*4 for r in range(22,26)})
    result,_,allocations,services=oracle.native(library,image,0x16A974,[],pages,
        extra_registers=extras,observed_memory=watch,instruction_observer=observe,instruction_limit=1000)
    assert not allocations and not services and len(registers)==1 and result==registers[0][2]
    assert seen=={0x16A974,0x172440,0x2804F0,0x2885C8}
    return registers[0],watch,steps[0]


def red(library):
    assert not hasattr(model,OWNER)
    rows=[]
    for image in BASES:
        p,inputs,local,generic,backing=fixture(library,image,'patterned_stack')
        registers,_,steps=original(library,p,inputs,local,generic,backing)
        assert registers[0]==oracle.STOP and registers[1]==inputs['entry_stack_address'] and registers[2]==image+0x281414
        rows.append(dict(image_base=hex(image),original_selected_slot_generic_child_wrapper_returned=True,
            steps=steps,physical_X0_is_descriptor_callback=True,previous_return_owner_missing=True,native_snapshot_input=False))
    return rows


def compare(library,image,label):
    pages,inputs,local,generic,backing=fixture(library,image,label)
    initial={k:bytearray(v) for k,v in pages.items()}
    state=getattr(model,OWNER)(pages,**inputs)
    registers,watch,steps=original(library,initial,inputs,local,generic,backing)
    assert registers==tuple(getattr(state,k) for k in ('pc','sp','x0','x19','x28','x29','x30')),(label,registers,state)
    assert all(data==_read_span(pages,address,width) for (address,width),data in watch.items()),label
    assert all(initial[k]==pages[k] for k in pages)
    print('PASS child return',hex(image),label,steps,flush=True)
    return dict(image_base=hex(image),case=label,steps=steps,
        original_selected_slot_generic_child_wrapper_returned=True,all_seven_physical_return_values_equal=True,
        complete_declared_guest_and_caller_stack_bytes_equal=True,physical_X0_is_descriptor_callback=True,
        no_allocation_or_services=True,supplied_pages_unchanged=True,native_snapshot_input=False)


def guards(library):
    rows=[]
    for label in ('unaligned_stack','underflow_stack','wide_image','wide_thread',
            'wrong_callback_sentinel','missing_frame','missing_TLS','canary_mismatch',
            'wrong_child_LR','tagged_wrapper_LR','missing_wrapper_LR'):
        pages,inputs,local,generic,backing=fixture(library,BASES[0],'normal')
        stack=inputs['entry_stack_address'];entry=stack-16
        if label=='unaligned_stack':inputs['entry_stack_address']+=1
        elif label=='underflow_stack':inputs['entry_stack_address']=16
        elif label=='wide_image':inputs['image_base']=1<<64
        elif label=='wide_thread':inputs['thread_pointer']=-1
        elif label=='wrong_callback_sentinel':inputs['callback_sentinel']+=4
        elif label=='missing_frame':del pages[(entry-0x28)>>12]
        elif label=='missing_TLS':inputs['thread_pointer']=G+0x10000
        elif label=='canary_mismatch':_write_span(pages,entry-0x28,bytes(8))
        elif label=='wrong_child_LR':_write_span(pages,entry-0x18,(BASES[0]+1).to_bytes(8,'little'))
        elif label=='tagged_wrapper_LR':_write_span(pages,stack-16,(1<<60).to_bytes(8,'little'))
        elif label=='missing_wrapper_LR':
            # Split the wrapper LR into the next page while retaining all child spills.
            stack=(stack+0xFFF)&~0xFFF;stack+=16;entry=stack-16
            inputs['entry_stack_address']=stack
            _write_span(pages,entry-0x28,_read_span(pages,inputs['thread_pointer']+0x28,8))
            _write_span(pages,entry-0x18,(BASES[0]+0x2885C8).to_bytes(8,'little'))
            del pages[(stack-16)>>12]
        before={k:bytes(v) for k,v in pages.items()}
        try:getattr(model,OWNER)(pages,**inputs)
        except RefillUnsupported:pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in pages.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True))
    return rows


def entry_guards(library):
    os.environ['TOMATO_LIBMETASEC']=str(library.resolve())
    import vm_full,vm9_request_28048c_vm as child
    assert Path(vm_full.__file__).resolve().parent==Path(__file__).resolve().parent
    rows=[]
    for label in ('wrong_exit_pc','wrong_exit_word','wrong_exit_target','short_registers','invalid_continue_option'):
        pages,inputs,*_=fixture(library,BASES[0],'normal')
        kw=dict(image_base=BASES[0],pc=BASES[0]+0xED3DC,registers=[0]*31+[BASES[0]+0x2885C8])
        if label=='wrong_exit_pc':kw['pc']+=4
        elif label=='wrong_exit_word':_write_span(pages,kw['pc'],bytes(4))
        elif label=='wrong_exit_target':kw['registers'][31]+=4
        elif label=='short_registers':kw['registers'].pop()
        before={k:bytes(v) for k,v in pages.items()};previous=vm_full.B
        try:
            if label=='invalid_continue_option':
                child.execute_request_28048c_vm_prefix(pages,vm_module=vm_full,continue_caller_return=1)
            else:model.validate_request_28048c_vm_exit(pages,**kw)
        except RefillUnsupported:pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in pages.items()} and previous==vm_full.B
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,module_image_base_restored=True))
    return rows


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--group',choices=('red','returns','guards','entry','all'),default='all')
    args=parser.parse_args();assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    report=dict(schema='vm9-request-child-return-fresh-v1',evidence_date='2026-10-15',sample_sha256=oracle.LIBRARY_SHA256,
        cases=[],negative_cases=[],entry_negative_cases=[],accepted_native_controls_not_repeated=True,
        native_snapshot_input=False,private_names_or_payloads_published=False,
        whole_request_native_differential_verified=False,whole_child_native_differential_verified=False,
        complete_child_vm_verified=False,complete_second_vm_verified=False,
        actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False,
        whole_physical_stack_bytes_compared=False,allocator_provider_mapping_rollback_verified=False)
    if args.group=='red':report['red_cases']=red(args.library)
    if args.group in ('returns','all'):report['cases']=[compare(args.library,image,label) for image in BASES for label in PROFILES]
    if args.group in ('guards','all'):report['negative_cases']=guards(args.library)
    if args.group in ('entry','all'):report['entry_negative_cases']=entry_guards(args.library)
    report.update(native_Python_controls=len(report['cases']),rollback_guards=len(report['negative_cases'])+len(report['entry_negative_cases']))
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS child return',args.group,report['native_Python_controls'],report['rollback_guards'])
if __name__=='__main__':main()
