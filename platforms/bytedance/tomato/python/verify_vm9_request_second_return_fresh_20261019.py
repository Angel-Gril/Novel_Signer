"""Fresh selected-slot second VM return and physical caller epilogue."""
from pathlib import Path
import argparse,hashlib,json,os
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
import vm9_request_caller as model
from vm9_allocator import RefillUnsupported,_read_span,_write_span
BASES=(0x122C0000,0x775C205000);G=oracle.GUEST
OWNER='finish_request_287474_vm_caller'
PROFILES=('normal','relocated_stack','patterned_stack','wide_saved_words','TLS_frame_alias',
    'TLS_saved_FP_alias','TLS_saved_X19_alias','TLS_saved_X28_alias','TLS_saved_LR_alias','NULL_saved_words')
GUARDS=('unaligned_stack','underflow_stack','wide_image','wide_thread','wrong_callback',
    'missing_frame','missing_TLS','canary_mismatch','tagged_caller_LR','invalid_stack_type',
    'wrong_exit_pc','wrong_exit_word','wrong_exit_target','short_registers','invalid_continue_option')

def w(p,a,v):_write_span(p,a,v.to_bytes(8,'little'))

def fixture(library,image,label):
    p=oracle.image_pages(library,image);p.update(oracle.fresh_pages())
    stack=G+(0xDF00 if label=='relocated_stack' else 0xEF00)
    local=stack-0x1A00;generic=local-0x60;thread=G+0xC000;backing=G+0x7000
    if label=='patterned_stack':_write_span(p,generic-0x50,bytes((i*37+19)&255 for i in range(stack-generic+0x50)))
    words=(G+0xCC00,0x123456789ABCDEF0,0xFEDCBA9876543210)
    if label=='NULL_saved_words':words=(0,0,0)
    elif label=='wide_saved_words':words=((1<<64)-1,1<<63,(1<<64)-2)
    for address,value in ((stack-0x20,words[0]),(stack-0x18,oracle.STOP),
            (stack-0x10,words[1]),(stack-8,words[2])):w(p,address,value)
    aliases={'TLS_frame_alias':stack-0x28,'TLS_saved_FP_alias':stack-0x20,
        'TLS_saved_X19_alias':stack-8,'TLS_saved_X28_alias':stack-0x10,'TLS_saved_LR_alias':stack-0x18}
    if label in aliases:thread=aliases[label]-0x28
    _write_span(p,stack-0x28,_read_span(p,thread+0x28,8))
    for offset,value in ((0,stack-0x20),(8,image+0x2874D8),(16,0x2828),
            (24,0x2727),(32,0x2626),(40,0x2525),(48,0x2424),(56,0x2323),
            (64,0x2222),(72,0x2121),(80,0x2020),(88,thread),(-0x50,oracle.STOP)):
        w(p,generic+offset,value)
    w(p,backing+31*8,oracle.STOP)
    return p,dict(entry_stack_address=stack,thread_pointer=thread,image_base=image,
        callback_sentinel=image+0x2884AC),local,generic,backing

def original(library,p,kw,local,generic,backing):
    image=kw['image_base'];stack=kw['entry_stack_address'];registers=[];steps=[0];seen=set()
    def observe(cpu,address):
        steps[0]+=1
        if address-image in (0x16A974,0x172440,0x2874D8):seen.add(address-image)
        if address==image+0x2874F8:
            registers.append(tuple(cpu.reg_read(getattr(arm,'UC_ARM64_REG_'+n)) for n in ('X30','SP','X0','X19','X28','X29','X30')))
    watch={(G,0xA000):None,(generic-0x50,stack-generic+0x50):None}
    extras={arm.UC_ARM64_REG_SP:generic-0x100,arm.UC_ARM64_REG_X29:generic,
        arm.UC_ARM64_REG_X28:backing,arm.UC_ARM64_REG_X21:0x07C00791,
        arm.UC_ARM64_REG_X0:kw['callback_sentinel'],arm.UC_ARM64_REG_TPIDR_EL0:kw['thread_pointer']}
    extras.update({getattr(arm,'UC_ARM64_REG_X'+str(r)):G+0xB000+(r-22)*4 for r in range(22,26)})
    result,_,allocations,services=oracle.native(library,image,0x16A974,[],p,
        extra_registers=extras,observed_memory=watch,instruction_observer=observe,instruction_limit=1000)
    assert not allocations and not services and len(registers)==1 and result==registers[0][2]
    assert seen=={0x16A974,0x172440,0x2874D8}
    return registers[0],watch,steps[0]

def red(library):
    assert not hasattr(model,OWNER);rows=[]
    for image in BASES:
        p,kw,*rest=fixture(library,image,'patterned_stack');registers,_,steps=original(library,p,kw,*rest)
        assert registers[:3]==(oracle.STOP,kw['entry_stack_address'],image+0x2884AC)
        rows.append(dict(image_base=hex(image),steps=steps,original_selected_slot_generic_second_caller_returned=True,
            physical_X0_is_descriptor_callback=True,previous_return_owner_missing=True,native_snapshot_input=False))
    return rows

def compare(library,image,label):
    p,kw,*rest=fixture(library,image,label);initial={k:bytearray(v) for k,v in p.items()}
    state=getattr(model,OWNER)(p,**kw);registers,watch,steps=original(library,initial,kw,*rest)
    assert registers==tuple(getattr(state,k) for k in ('pc','sp','x0','x19','x28','x29','x30')),(label,state,registers)
    assert all(data==_read_span(p,a,n) for (a,n),data in watch.items()) and all(initial[k]==p[k] for k in p)
    print('PASS second return',hex(image),label,steps,flush=True)
    return dict(image_base=hex(image),case=label,steps=steps,original_selected_slot_generic_second_caller_returned=True,
        all_seven_physical_return_values_equal=True,complete_declared_guest_and_caller_stack_bytes_equal=True,
        physical_X0_is_descriptor_callback=True,no_allocation_or_services=True,supplied_pages_unchanged=True,native_snapshot_input=False)

def guards(library):
    import vm_full,vm9_request_287474_vm as second
    rows=[]
    for label in GUARDS:
        p,kw,*_=fixture(library,BASES[0],'normal');stack=kw['entry_stack_address']
        exit_kw=dict(image_base=BASES[0],pc=BASES[0]+0x112434,registers=[0]*31+[oracle.STOP],return_address=oracle.STOP)
        if label=='unaligned_stack':kw['entry_stack_address']+=1
        elif label=='underflow_stack':kw['entry_stack_address']=16
        elif label=='wide_image':kw['image_base']=1<<64
        elif label=='wide_thread':kw['thread_pointer']=-1
        elif label=='wrong_callback':kw['callback_sentinel']+=4
        elif label=='missing_frame':del p[(stack-0x28)>>12]
        elif label=='missing_TLS':kw['thread_pointer']=G+0x10000
        elif label=='canary_mismatch':w(p,stack-0x28,0)
        elif label=='tagged_caller_LR':w(p,stack-0x18,1<<60)
        elif label=='invalid_stack_type':kw['entry_stack_address']=True
        elif label=='wrong_exit_pc':exit_kw['pc']+=4
        elif label=='wrong_exit_word':_write_span(p,exit_kw['pc'],bytes(4))
        elif label=='wrong_exit_target':exit_kw['registers'][31]+=4
        elif label=='short_registers':exit_kw['registers'].pop()
        before={k:bytes(v) for k,v in p.items()};previous=vm_full.B
        try:
            if label=='invalid_continue_option':second.execute_request_287474_vm_prefix(p,vm_module=vm_full,continue_caller_return=1)
            elif label.startswith('wrong_exit') or label=='short_registers':model.validate_request_287474_vm_exit(p,**exit_kw)
            else:getattr(model,OWNER)(p,**kw)
        except RefillUnsupported:pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in p.items()} and previous==vm_full.B
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,module_image_base_restored=True))
    return rows

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True);ap.add_argument('--group',choices=('red','returns','guards','all'),default='all')
    args=ap.parse_args();assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    rows=[];negative=[];r=[]
    if args.group=='red':r=red(args.library)
    if args.group in ('returns','all'):rows=[compare(args.library,b,c) for b in BASES for c in PROFILES]
    if args.group in ('guards','all'):negative=guards(args.library)
    e=dict(red_cases=r,cases=rows,negative_cases=negative,native_Python_controls=len(rows),rollback_guards=len(negative),
        library_sha256=oracle.LIBRARY_SHA256,accepted_native_controls_not_repeated=True,native_snapshot_input=False,
        whole_second_native_differential_verified=False,complete_physical_ABI_verified=False,complete_signer_verified=False)
    args.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS second return',args.group,len(r),len(rows),len(negative),flush=True)
if __name__=='__main__':main()
