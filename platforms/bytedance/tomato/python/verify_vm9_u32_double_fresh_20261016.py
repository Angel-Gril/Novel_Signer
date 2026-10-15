"""Fresh native opcode34 operation30: implicit R4 uint32 to R2 double bits.

Only the measured conversion is restored; the other floating operations remain
unsupported. uint32 fits exactly in double, independent of rounding direction.
"""
from pathlib import Path
import argparse,hashlib,json,os
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
from vm9_allocator import _read_span,_write_span
G=oracle.GUEST;CODE=G+0x1000;DESC=G+0x2000;TOP=G+0xE000;BACK=TOP-0x118
BASES=(0x122C0000,0x775C205000);WORD=0x001E0022;MASK=(1<<64)-1
PROFILES=(('zero',0),('one',1),('u31max',0x7FFFFFFF),('signbit',0x80000000),
    ('u32max',0xFFFFFFFF),('high_only',1<<32),('high_mixed',0xFEDCBA988A31C65D),('allones',MASK))
GUARDS=(0,29,31,32,37,38)
def fresh(library,image,value):
    p=oracle.image_pages(library,image);p.update(oracle.fresh_pages())
    regs=[0xA1000000+i for i in range(32)]
    regs[0]=0;regs[4]=value;regs[5]=image+0x35E230;regs[6]=image+0x35E690
    regs[7]=image+0x28587C;regs[29]=(TOP-0x130)&~15;regs[31]=oracle.STOP
    _write_span(p,BACK,b''.join(r.to_bytes(8,'little') for r in regs)+bytes(24))
    _write_span(p,DESC,(image+0x28587C).to_bytes(8,'little')+TOP.to_bytes(8,'little')+oracle.STOP.to_bytes(8,'little'))
    _write_span(p,CODE,WORD.to_bytes(4,'little')+(0x07C00791).to_bytes(4,'little'))
    return p,regs
def original(library,image,value,p):
    watch={(BACK,256):None};seen=set();steps=[0]
    def observe(cpu,address):
        steps[0]+=1
        if address-image in (0x170348,0x170798,0x1707AC,0x1707F4,0x172440):seen.add(address-image)
    _,memory,alloc,ledger=oracle.native(library,image,0x168324,
        [CODE,value,image+0x35E230,image+0x35E690,DESC],p,
        instruction_observer=observe,observed_memory=watch,instruction_limit=10000)
    assert seen=={0x170348,0x170798,0x1707AC,0x1707F4,0x172440} and not alloc and not ledger
    return memory,watch[BACK,256],steps[0]
def run_model(vm_full,image,p,regs,binding):
    m=vm_full.Mem();m.pages=p;previous=vm_full.B;vm_full.B=image
    v=vm_full.VM(m,CODE-image,regs[4],regs[5],regs[6],regs[7],oracle.STOP,maxsteps=2);v.R=list(regs)
    if binding:v.register_backing_base=BACK
    try:v.run()
    finally:vm_full.B=previous
    return v
def red(library,vm_full):
    rows=[]
    for image in BASES:
        p,regs=fresh(library,image,0xFEDCBA98FFFFFFFF);_,expected,steps=original(library,image,regs[4],p)
        try:run_model(vm_full,image,p,regs,False)
        except ValueError as exc:assert str(exc).startswith('op 34 @')
        else:raise AssertionError('previous VM accepted opcode34')
        assert int.from_bytes(expected[16:24],'little')==0x41EFFFFFFFE00000
        rows.append(dict(image_base=hex(image),previous_opcode34_missing=True,
            original_unsigned_conversion_and_exit_returned=True,high_source_bits_ignored=True,steps=steps,native_snapshot_input=False))
    return rows
def compare(library,vm_full,image,label,value,binding):
    p,regs=fresh(library,image,value);memory,expected,steps=original(library,image,value,p)
    m=vm_full.Mem();m.pages=p;old=vm_full.B;vm_full.B=image
    v=vm_full.VM(m,CODE-image,value,regs[5],regs[6],regs[7],oracle.STOP,maxsteps=2);v.R=list(regs)
    if binding:v.register_backing_base=BACK
    try:v.run()
    except vm_full.VMExit:pass
    finally:vm_full.B=old
    actual=b''.join(r.to_bytes(8,'little') for r in v.R)
    assert actual==expected,(label,binding)
    assert _read_span(p,G,0xA000)==memory and v.pc==CODE+4
    if binding:assert _read_span(p,BACK,256)==expected
    print('PASS u32 double',hex(image),label,'backed' if binding else 'abstract',flush=True)
    return dict(image_base=hex(image),case=label,guest_backing=binding,steps=steps,
        original_unsigned_conversion_and_exit_returned=True,all_32_registers_equal=True,
        guest_payload_and_defined_backing_equal=True,high_source_bits_ignored=True,
        exact_uint32_to_double_bits_equal=True,no_allocator_or_native_service_effects=True,
        native_snapshot_input=False,complete_float_family_verified=False)
def guards(library,vm_full):
    rows=[]
    for operation in GUARDS:
        p,regs=fresh(library,BASES[0],0xFFFFFFFF)
        word=34|((operation&31)<<16)|((operation&32)<<1)
        _write_span(p,CODE,word.to_bytes(4,'little'));before={k:bytes(v) for k,v in p.items()}
        m=vm_full.Mem();m.pages=p;old=vm_full.B;vm_full.B=BASES[0]
        v=vm_full.VM(m,CODE-BASES[0],regs[4],regs[5],regs[6],regs[7],oracle.STOP,maxsteps=1);v.R=list(regs)
        try:v.run()
        except ValueError as exc:assert 'unrecovered opcode34 operation' in str(exc)
        else:raise AssertionError('unsupported floating operation accepted')
        finally:vm_full.B=old
        assert v.R==regs and v.pc==CODE and before=={k:bytes(x) for k,x in p.items()}
        rows.append(dict(operation=operation,rejected=True,registers_PC_and_all_pages_unchanged=True))
    return rows
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True);ap.add_argument('--mode',choices=('red','native','guards'),default='native');a=ap.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    os.environ['TOMATO_LIBMETASEC']=str(a.library.resolve());import vm_full
    assert Path(vm_full.__file__).resolve().parent==Path(__file__).resolve().parent
    e=dict(cases=[],negative_cases=[],red_cases=[],native_snapshot_input=False,complete_float_family_verified=False,
        complete_second_vm_verified=False,complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False,actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,complete_physical_ABI_verified=False)
    if a.mode=='red':e['red_cases']=red(a.library,vm_full)
    elif a.mode=='guards':e['negative_cases']=guards(a.library,vm_full)
    else:
        for image in BASES:
            for label,value in PROFILES:
                for binding in (False,True):
                    e['cases'].append(compare(a.library,vm_full,image,label,value,binding))
                    a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
    e.update(native_Python_controls=len(e['cases']),rejection_guards=len(e['negative_cases']))
    a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
if __name__=='__main__':main()
