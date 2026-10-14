"""Fresh helper/wrapper epilogues from independent stack, TLS and packed words."""
from pathlib import Path
import argparse,hashlib,json,os
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
import vm9_request_caller as model
from vm9_allocator import RefillUnsupported,_read_span,_write_span
BASES=(0x122C0000,0x775C205000);G=oracle.GUEST
OWNER='finish_request_environment_wrapper_caller'

def fixture(library,image,helper,label):
    pages=oracle.image_pages(library,image);pages.update(oracle.fresh_pages())
    stack=G+(0xDF00 if label=='relocated_stack' else 0xEF00);entry=stack-16
    size=0x500 if helper==0x204E50 else 0x3D0;local=entry-size
    packed,thread=G+0x1000,G+0xD000
    value={'zero':0,'one':1,'high_W':0x80000000,'max_W':0xFFFFFFFF}.get(label,0x12345678)
    if label=='cross_page_packed':packed=G+0x1FF6
    elif label=='result_alias_wrapper_lr':packed=stack-0x18;value=oracle.STOP&0xFFFFFFFF
    elif label=='result_alias_wrapper_x19':packed=stack-0x10
    elif label=='result_alias_helper_x28':packed=stack-0x28
    elif label=='result_alias_helper_fp':packed=stack-0x38
    elif label=='TLS_frame_alias':thread=entry-0x50
    elif label=='TLS_result_alias':thread=local+8-0x28
    if label=='patterned_stack':_write_span(pages,stack-0x600,bytes((i*37+19)&255 for i in range(0x600)))
    _write_span(pages,packed+8,bytes.fromhex('1928374655647382'))
    for address,word in ((local+8,0xA1B2C3D400000000|value),(entry-0x20,G+0xCC00),
            (entry-0x18,image+0x2814D8),(entry-0x10,0x123456789ABCDEF0),
            (entry-8,packed),(stack-16,oracle.STOP),(stack-8,0xFEDCBA9876543210)):
        _write_span(pages,address,word.to_bytes(8,'little'))
    _write_span(pages,entry-0x28,_read_span(pages,thread+0x28,8))
    return pages,dict(helper_offset=helper,entry_stack_address=stack,
        thread_pointer=thread,image_base=image),local

def original(library,pages,inputs,local):
    regs=[];image=inputs['image_base'];stack=inputs['entry_stack_address'];entry=stack-16
    def observe(cpu,address):
        if address==image+0x2814E0:
            regs.append(tuple(cpu.reg_read(getattr(arm,'UC_ARM64_REG_'+n)) for n in ('X30','SP','X0','X19','X28','X29','X30')))
    watch={(G,0xA000):None,(stack-0x600,0x600):None}
    result,_,allocations,services=oracle.native(library,image,0x204EAC if inputs['helper_offset']==0x204E50 else 0x204F30,
        [],pages,extra_registers={arm.UC_ARM64_REG_SP:local,arm.UC_ARM64_REG_X29:entry-0x20,
            arm.UC_ARM64_REG_X19:inputs['thread_pointer'],arm.UC_ARM64_REG_TPIDR_EL0:inputs['thread_pointer']},
        observed_memory=watch,instruction_observer=observe,instruction_limit=1000)
    assert not allocations and not services and len(regs)==1 and result==regs[0][2]
    return regs[0],watch

def red(library):
    assert not hasattr(model,OWNER)
    rows=[]
    for image in BASES:
        for helper in (0x204E50,0x204ED4):
            pages,inputs,local=fixture(library,image,helper,'one');original(library,pages,inputs,local)
            rows.append(dict(image_base=hex(image),helper=hex(helper),original_helper_and_wrapper_epilogues_returned=True,
                prior_return_owner_missing=True,native_snapshot_input=False))
    return rows

def compare(library,image,helper,label):
    pages,inputs,local=fixture(library,image,helper,label);initial={k:bytearray(v) for k,v in pages.items()}
    state=getattr(model,OWNER)(pages,**inputs);registers,watch=original(library,initial,inputs,local)
    assert registers==tuple(getattr(state,k) for k in ('pc','sp','x0','x19','x28','x29','x30')),(label,registers,state)
    assert all(data==_read_span(pages,address,width) for (address,width),data in watch.items()),label
    print('PASS environment return',hex(image),hex(helper),label,flush=True)
    return dict(image_base=hex(image),helper=hex(helper),case=label,
        original_helper_and_wrapper_epilogues_returned=True,all_seven_physical_return_values_equal=True,
        complete_declared_guest_and_stack_bytes_equal=True,packed_W_result_and_padding_equal=True,native_snapshot_input=False)

def guards(library):
    rows=[]
    for label in ('wrong_helper','unaligned_stack','missing_frame','missing_TLS','canary_mismatch',
                  'unexpected_helper_LR','tagged_wrapper_LR','missing_result'):
        pages,inputs,local=fixture(library,BASES[0],0x204E50,'one');stack=inputs['entry_stack_address'];entry=stack-16
        if label=='wrong_helper':inputs['helper_offset']=1
        elif label=='unaligned_stack':inputs['entry_stack_address']+=1
        elif label=='missing_frame':del pages[local>>12]
        elif label=='missing_TLS':inputs['thread_pointer']=G+0x10000
        elif label=='canary_mismatch':_write_span(pages,entry-0x28,bytes(8))
        elif label=='unexpected_helper_LR':_write_span(pages,entry-0x18,(BASES[0]+1).to_bytes(8,'little'))
        elif label=='tagged_wrapper_LR':_write_span(pages,stack-16,(1<<60).to_bytes(8,'little'))
        elif label=='missing_result':_write_span(pages,entry-8,(G+0x10000).to_bytes(8,'little'))
        before={k:bytes(v) for k,v in pages.items()}
        try:getattr(model,OWNER)(pages,**inputs)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in pages.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True))
    return rows

def entry_guards(library):
    os.environ['TOMATO_LIBMETASEC']=str(library.resolve())
    import vm_full,vm9_request_environment_vm as environment
    assert Path(vm_full.__file__).resolve().parent==Path(__file__).resolve().parent
    rows=[]
    for label in ('wrong_exit_pc','wrong_exit_word','wrong_exit_target','invalid_continue_option'):
        pages,inputs,_=fixture(library,BASES[0],0x204E50,'one')
        kw=dict(helper_offset=0x204E50,image_base=BASES[0],pc=BASES[0]+0x8A4E8,registers=[0]*31+[BASES[0]+0x2814D8])
        if label=='wrong_exit_pc':kw['pc']+=4
        elif label=='wrong_exit_word':_write_span(pages,kw['pc'],bytes(4))
        elif label=='wrong_exit_target':kw['registers'][31]+=4
        before={k:bytes(v) for k,v in pages.items()};previous=vm_full.B
        try:
            if label=='invalid_continue_option':
                environment.execute_request_environment_vm_prefix(pages,vm_module=vm_full,continue_caller_return=1)
            else:model.validate_request_environment_vm_exit(pages,**kw)
        except RefillUnsupported:pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in pages.items()} and previous==vm_full.B
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,module_image_base_restored=True))
    return rows

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--group',choices=('red','returns','guards','entry','all'),default='all')
    args=parser.parse_args();assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    report=dict(schema='vm9-request-environment-return-fresh-v1',evidence_date='2026-10-15',sample_sha256=oracle.LIBRARY_SHA256,
        cases=[],negative_cases=[],entry_negative_cases=[],native_snapshot_input=False,private_names_or_payloads_published=False,
        whole_request_native_differential_verified=False,complete_helper_vm_verified=False,complete_child_vm_verified=False,
        complete_second_vm_verified=False,actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False,
        whole_physical_stack_bytes_compared=False,allocator_provider_mapping_rollback_verified=False)
    if args.group=='red':report['red_cases']=red(args.library)
    if args.group in ('returns','all'):report['cases']=[compare(args.library,image,helper,label) for image in BASES
        for helper in (0x204E50,0x204ED4) for label in ('zero','one','high_W','max_W','patterned_stack','relocated_stack',
        'cross_page_packed','result_alias_wrapper_lr','result_alias_wrapper_x19','result_alias_helper_x28','result_alias_helper_fp',
        'TLS_frame_alias','TLS_result_alias')]
    if args.group in ('guards','all'):report['negative_cases']=guards(args.library)
    if args.group in ('entry','all'):report['entry_negative_cases']=entry_guards(args.library)
    report['native_Python_controls']=len(report['cases']);report['rollback_guards']=len(report['negative_cases'])
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS environment return',args.group,report['native_Python_controls'],report['rollback_guards'])
if __name__=='__main__':main()
