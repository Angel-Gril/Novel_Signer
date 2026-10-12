"""Fresh original VM load and serialized compare/store instruction controls.

Native interpreter instructions execute synthetic bytecode and guest memory.
An explicit intervention changes memory before store for mismatch controls.
This verifies serialized values, not host concurrency or atomic guarantees.
"""
from pathlib import Path
import argparse,hashlib,json,os
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
from vm9_allocator import _read_span,_write_span

G=oracle.GUEST;CODE=G+0x1000;DESC=G+0x2000;TARGET=G+0x3800;TOP=G+0xE000;BACK=TOP-0x118
BASES=(0x122C0000,0x775C205000);MASK=(1<<64)-1


def encode_load(base,destination,offset):
    u=offset&65535
    return (36|((base&15)<<22)|((base&16)<<27)|((destination&15)<<7)|((destination&16)<<17)
        |((u&31)<<16)|(((u>>5)&31)<<26)|(((u>>10)&31)<<11)|((u>>15)<<6))


def encode_store(base,source,offset):
    u=offset&65535
    return (57|((base&15)<<22)|((base&16)<<27)|((source&15)<<27)|((source&16)<<17)
        |((u&31)<<11)|(((u>>5)&31)<<6)|(((u>>10)&31)<<16)|((u>>15)<<26))


def profiles():
    values=[('zero',0,1),('nonzero',0xFEDCBA9876543210,0x123456789ABCDEF0),
        ('same_value',MASK,MASK),('signed_min',1<<63,0),('signed_max',(1<<63)-1,MASK)]
    result=[(n,dict(value=a,new=b)) for n,a,b in values]
    result.extend((n,dict(value=a,new=b,intervene=a^1)) for n,a,b in values)
    result.extend(('offset_'+str(n),dict(value=MASK,new=5,offset=n)) for n in (-32768,-1025,-1,1,31,32,1024,32767))
    result.extend(('register_'+str(n),dict(value=0xFFFFFFFF00000000,new=17,base=n,dst=30 if n!=30 else 15,src=27)) for n in (1,15,16,30))
    result.extend((('different_target_equal',dict(value=19,new=23,other=19)),
        ('different_target_mismatch',dict(value=19,new=23,other=20)),
        ('second_store',dict(value=19,new=23,repeat=True)),
        ('source_is_base',dict(value=13,src=1)),
        ('load_destination_is_base',dict(value=TARGET,dst=1))))
    return result


def fresh(library,base,profile):
    p=oracle.image_pages(library,base);p.update(oracle.fresh_pages())
    def w(a,v):_write_span(p,a,(v&MASK).to_bytes(8,'little'))
    for i in range(35):w(BACK+i*8,0)
    b=profile.get('base',1);d=profile.get('dst',3);s=profile.get('src',8);offset=profile.get('offset',0)
    w(BACK+b*8,TARGET-offset);w(BACK+s*8,profile.get('new',23))
    if s==b:w(BACK+b*8,TARGET-offset)
    w(DESC,base+0x28587C);w(DESC+8,TOP);w(DESC+16,oracle.STOP)
    w(TARGET,profile['value'])
    words=[encode_load(b,d,offset)]
    if 'other' in profile:
        w(TARGET+16,profile['other']);w(BACK+2*8,TARGET+16);words.append(encode_store(2,s,0))
    else:words.append(encode_store(b,s,offset))
    if profile.get('repeat'):words.append(encode_store(b,s,offset))
    words.append(0x07C00791)
    if profile.get('store_only'):words=words[1:]
    _write_span(p,CODE,b''.join(x.to_bytes(4,'little') for x in words))
    regs=[int.from_bytes(_read_span(p,BACK+i*8,8),'little') for i in range(32)]
    regs[0]=0;regs[4]=G+0x5000;regs[5]=base+0x35E230;regs[6]=base+0x35E690
    regs[7]=base+0x28587C;regs[29]=(TOP-0x130)&~15;regs[31]=oracle.STOP
    return p,regs,words


def compare(library,base,label,profile,binding):
    import vm_full
    initial,regs,words=fresh(library,base,profile)
    p={k:bytearray(v) for k,v in initial.items()};observed={(BACK,0x118):None,(TARGET,32):None}
    interventions=[];returns=[]
    def see(c,address):
        if address==base+0x1713C0 and 'intervene' in profile:
            value=profile['intervene'];c.mem_write(TARGET,value.to_bytes(8,'little'));interventions.append(value)
        if address==base+0x172440:returns.append(True)
    _,_,allocations,services=oracle.native(library,base,0x168324,
        [CODE,G+0x5000,base+0x35E230,base+0x35E690,DESC],initial,
        observed_memory=observed,instruction_observer=see,instruction_limit=100000)
    m=vm_full.Mem();m.pages=p;previous=vm_full.B;vm_full.B=base
    vm=vm_full.VM(m,CODE-base,G+0x5000,base+0x35E230,base+0x35E690,base+0x28587C,oracle.STOP,maxsteps=len(words));vm.R=regs
    if binding:
        vm.register_backing_base=BACK
        for i,v in enumerate(regs):m.w64(BACK+i*8,v)
    def before(vm,word,op,sub):
        if op==57 and 'intervene' in profile:m.w64(TARGET,profile['intervene'])
    vm.step_hook=before
    try:vm.run()
    except vm_full.VMExit:pass
    finally:vm_full.B=previous
    actual_regs=[int.from_bytes(observed[BACK,0x118][i*8:i*8+8],'little') for i in range(32)]
    actual_expected=int.from_bytes(observed[BACK,0x118][0x110:0x118],'little')
    assert returns==[True] and not allocations and not services
    assert vm.R==actual_regs,(label,binding,'registers',[(i,hex(a),hex(b)) for i,(a,b) in enumerate(zip(vm.R,actual_regs)) if a!=b])
    assert vm._vm_ll_word==actual_expected,(label,binding,'hidden comparison word')
    assert _read_span(p,TARGET,32)==observed[TARGET,32],(label,binding,'target')
    if binding:assert m.u64(BACK+0x110)==actual_expected
    assert interventions==([profile['intervene']] if 'intervene' in profile else [])
    print('PASS',hex(base),'LL/SC',label,'backed' if binding else 'abstract',flush=True)
    return dict(image_base=hex(base),case=label+'_mismatch' if 'intervene' in profile else label,guest_backing=binding,original_returned=True,
        all_32_registers_match=True,target_bytes_and_hidden_expected_word_match=True,
        serialized_intervention_matches=True,native_snapshot_input=False,host_atomicity_not_claimed=True)


def edges(library):
    import vm_full
    from unicorn import UcError
    cases=[];negative=[]
    for base in BASES:
        for label,value in (('store_only_zero',0),('store_only_mismatch',23),('store_only_high_word',MASK)):
            cases.append(compare(library,base,label,dict(value=value,new=31,store_only=True),True))
        for label in ('unaligned_load','unaligned_store','missing_comparison_word'):
            p,regs,words=fresh(library,base,dict(value=0,new=1))
            if label!='missing_comparison_word':regs[1]=TARGET+1
            if label!='unaligned_load':words=words[1:]
            _write_span(p,CODE,b''.join(x.to_bytes(4,'little') for x in words))
            initial={k:bytearray(v) for k,v in p.items()}
            if label!='missing_comparison_word':
                _write_span(initial,BACK+8,(TARGET+1).to_bytes(8,'little'))
                try:oracle.native(library,base,0x168324,[CODE,G+0x5000,base+0x35E230,base+0x35E690,DESC],initial,instruction_limit=100000)
                except UcError:pass
                else:raise AssertionError('native accepted unaligned ordered load/store')
            m=vm_full.Mem();m.pages=p;old=vm_full.B;vm_full.B=base
            v=vm_full.VM(m,CODE-base,G+0x5000,base+0x35E230,base+0x35E690,base+0x28587C,oracle.STOP,maxsteps=len(words));v.R=regs
            before={k:bytes(x) for k,x in p.items()}
            try:v.run()
            except ValueError as exc:assert 'aligned 64-bit address' in str(exc) if label.startswith('unaligned') else 'preceding op36' in str(exc)
            else:raise AssertionError('invalid ordered load/store accepted')
            finally:vm_full.B=old
            assert before=={k:bytes(x) for k,x in p.items()}
            negative.append(dict(image_base=hex(base),case=label,rejected=True,target_and_all_pages_unchanged=True,
                original_native_alignment_fault_observed=label!='missing_comparison_word'))
            print('PASS LL/SC guard',hex(base),label,flush=True)
    return cases,negative


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--libc',type=Path);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--group',choices=('core','edges','entry','all'),default='core');args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    os.environ['TOMATO_LIBMETASEC']=str(args.library.resolve())
    import vm_full
    assert Path(vm_full.__file__).resolve().parent==Path(__file__).resolve().parent
    cases=[];negative=[];entries=[]
    if args.group in ('core','all'):
        for base in BASES:
            for label,profile in profiles():
                for backed in (False,True):cases.append(compare(args.library,base,label,profile,backed))
    if args.group in ('edges','all'):
        more,negative=edges(args.library);cases.extend(more)
    if args.group in ('entry','all'):
        if args.libc is None:ap.error('--libc is required for request entry controls')
        from verify_vm9_request_stack_evaluator_fresh_20261012 import request_entry
        entries,entry_guards=request_entry(args.library,args.libc);negative.extend(entry_guards)
    args.output.write_text(json.dumps(dict(component='VM serialized LL/SC64',cases=cases,
        native_Python_controls=len(cases),negative_cases=negative,rollback_guards=len(negative),
        request_entry_cases=entries,native_input_snapshot_used=False,concurrent_atomicity_verified=False,
        whole_request_native_differential_verified=False,complete_python_medusa=False,
        fresh_signer_output_verified=False,live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS',len(cases),'native LL/SC controls',flush=True)


if __name__=='__main__':main()
