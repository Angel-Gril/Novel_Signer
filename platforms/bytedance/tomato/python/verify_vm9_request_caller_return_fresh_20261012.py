"""Original caller, VM callback X0 preservation and native return controls.

Synthetic bytecode is an explicit guest input; native caller/interpreter code
executes unchanged. No native register or memory snapshot seeds Python.
"""
from pathlib import Path
import argparse,hashlib,json,os
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
import vm9_request_caller as model
from vm9_allocator import _read_span,_write_span,RefillUnsupported

G=oracle.GUEST;TP=G+0xD000;CALLBACK=G+0xF680;BASES=(0x122C0000,0x775C205000)


def load64(bse,dst,offset):
    u=offset&65535
    return (24|((bse&15)<<22)|((bse&16)<<27)|((dst&15)<<27)|((dst&16)<<17)
        |((u&31)<<6)|(((u>>5)&31)<<16)|(((u>>10)&31)<<11)|((u>>15)<<26))


def fresh(library,base,top,callback,saved):
    p=oracle.image_pages(library,base);p.update(oracle.fresh_pages())
    p[CALLBACK>>12]=bytearray(4096)
    _write_span(p,TP+0x28,saved[0].to_bytes(8,'little'))
    words=[0x07C00791]
    if callback:
        words=[load64(4,5,16),load64(4,4,8),17|(50<<6)|(2<<17)|(7<<22),0x07C00791]
    _write_span(p,base+0xF7720,b''.join(w.to_bytes(4,'little') for w in words))
    inputs=dict(entry_stack_address=top,return_address=oracle.STOP,thread_pointer=TP,image_base=base,
        argument_x0=CALLBACK,argument_x1=G+0x4000,argument_x2=0,argument_x3=0,output_x8=G+0x5000,
        saved_frame_pointer=saved[1],saved_x28=saved[2],saved_x19=saved[3])
    return p,inputs,len(words)


def compare(library,base,top,callback,profile):
    import vm_full
    saved={'zero':(0,0,0,0),'pattern':(0xFEDCBA9876543210,0x3456,0x2345,0x1234)}[profile]
    initial,inputs,count=fresh(library,base,top,callback,saved)
    p={k:bytearray(v) for k,v in initial.items()};frame=model.prepare_request_caller(p,**inputs)
    observed=[];calls=[]
    def watch(c,address):
        if address==base+0x283154:
            observed.append(dict(pc=c.reg_read(arm.UC_ARM64_REG_X30),sp=c.reg_read(arm.UC_ARM64_REG_SP),
                **{'x'+str(i):c.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in (0,19,28,29,30)}))
    def native_callback(c):
        assert c.reg_read(arm.UC_ARM64_REG_X0)==inputs['argument_x1']
        calls.append(True);return 0xFEDCBA9876543210
    ret=oracle.native(library,base,0x2830C4,[inputs['argument_x'+str(i)] for i in range(4)],initial,
        extra_registers={arm.UC_ARM64_REG_SP:top,arm.UC_ARM64_REG_TPIDR_EL0:TP,arm.UC_ARM64_REG_X8:inputs['output_x8'],
            arm.UC_ARM64_REG_X19:saved[3],arm.UC_ARM64_REG_X28:saved[2],arm.UC_ARM64_REG_X29:saved[1]},
        host_imports={CALLBACK-base:native_callback},instruction_observer=watch,instruction_limit=100000)
    m=vm_full.Mem();m.pages=p;old=vm_full.B;vm_full.B=base
    v=vm_full.VM(m,frame.bytecode_offset,frame.packed_arguments_address,base+0x35E230,base+0x35E690,base+0x28587C,oracle.STOP,maxsteps=count);v.R=list(frame.registers)
    pycalls=[]
    def cb(vm,fn,arg):assert (fn,arg)==(CALLBACK,inputs['argument_x1']);pycalls.append(True)
    v.native_hook=cb
    try:v.run()
    except vm_full.VMExit:pass
    finally:vm_full.B=old
    before={k:bytes(x) for k,x in p.items()}
    result=model.finish_request_caller(p,image_base=base,entry_stack_address=top,thread_pointer=TP,callback_sentinel=v.cb)
    assert calls==pycalls==([True] if callback else []) and ret[0]==result.x0,(calls,pycalls,hex(ret[0]),hex(result.x0),observed)
    assert observed==[dict(vars(result))] and before=={k:bytes(x) for k,x in p.items()}
    print('PASS',hex(base),'caller return',hex(top),callback,profile,flush=True)
    return dict(image_base=hex(base),stack_variant=0 if top==G+0xEF00 else 1,callback_clobbered_native_X0=callback,
        case=profile,original_request_caller_returned=True,callback_sentinel_X0_matches=True,
        saved_PC_SP_X19_X28_X29_X30_match=True,return_owner_does_not_write_pages=True,native_snapshot_input=False)


def guards(library):
    rows=[]
    for base in BASES:
        for label in ('canary_mismatch','unaligned_stack','wrong_callback','unmapped_frame','tagged_return'):
            p,inputs,_=fresh(library,base,G+0xEF00,False,(1,2,3,4));model.prepare_request_caller(p,**inputs)
            kw=dict(image_base=base,entry_stack_address=inputs['entry_stack_address'],thread_pointer=TP,callback_sentinel=base+0x28587C)
            if label=='canary_mismatch':
                _write_span(p,TP+0x28,(2).to_bytes(8,'little'))
                oracle.native(library,base,0x283134,[],p,
                    extra_registers={arm.UC_ARM64_REG_SP:inputs['entry_stack_address']-0x1740,
                        arm.UC_ARM64_REG_X19:TP,arm.UC_ARM64_REG_X29:inputs['entry_stack_address']-0x20},
                    stop_offset=0x347EB0,instruction_limit=20)
            elif label=='unaligned_stack':kw['entry_stack_address']+=1
            elif label=='wrong_callback':kw['callback_sentinel']+=4
            elif label=='unmapped_frame':kw['entry_stack_address']=0x66001000
            elif label=='tagged_return':_write_span(p,inputs['entry_stack_address']-0x18,(1<<63).to_bytes(8,'little'))
            before={k:bytes(x) for k,x in p.items()}
            try:model.finish_request_caller(p,**kw)
            except RefillUnsupported:pass
            else:raise AssertionError('caller return guard accepted '+label)
            assert before=={k:bytes(x) for k,x in p.items()}
            rows.append(dict(image_base=hex(base),case=label,rejected=True,all_pages_unchanged=True,
                original_canary_failure_target_observed=label=='canary_mismatch',external_effects_rolled_back=False))
            print('PASS caller return guard',hex(base),label,flush=True)
    return rows


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--libc',type=Path);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--group',choices=('native','guards','entry','all'),default='all');args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    os.environ['TOMATO_LIBMETASEC']=str(args.library.resolve());import vm_full
    assert Path(vm_full.__file__).resolve().parent==Path(__file__).resolve().parent
    cases=[];negative=[];entries=[]
    if args.group in ('native','all'):
        for base in BASES:
            for top in (G+0xEF00,G+0xEC00):
                for callback in (False,True):
                    for profile in ('zero','pattern'):cases.append(compare(args.library,base,top,callback,profile))
    if args.group in ('guards','all'):negative.extend(guards(args.library))
    if args.group in ('entry','all'):
        if args.libc is None:ap.error('--libc is required for request entry')
        from verify_vm9_request_stack_evaluator_fresh_20261012 import request_entry
        entries,more=request_entry(args.library,args.libc);negative.extend(more)
    args.output.write_text(json.dumps(dict(component='Request native caller return',cases=cases,negative_cases=negative,
        request_entry_cases=entries,native_Python_controls=len(cases),rejection_guards=len(negative),
        rollback_guards=sum(bool(r.get('all_pages_unchanged')) for r in negative),
        allocator_mapping_boundary_guards=sum('new_allocator_mapping_pages' in r for r in negative),
        native_input_snapshot_used=False,physical_caller_epilogue_controls_verified=bool(cases),
        synthetic_bytecode_inputs=True,whole_request_native_differential_verified=False,live_Android_JVM_verified=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS',len(cases),'native caller returns,',len(entries),'request entries,',len(negative),'guards',flush=True)


if __name__=='__main__':main()
