"""Fresh original interpreter checks for live guest register-array binding."""
from pathlib import Path
import argparse,hashlib,json,os
import verify_vm9_signer_objects as oracle
from vm9_allocator import _read_span,_write_span

G=oracle.GUEST;CODE=G+0x1000;DESC=G+0x2000;MASK=(1<<64)-1
BASES=(0x122C0000,0x775C205000)
EXIT=17|(30<<6)|(31<<22)

def alu(sub,a,b,c,d):return 17|(sub<<6)|(a<<12)|(b<<17)|(c<<22)|(d<<27)
def load(base,dst):return 24|((base&15)<<22)|((base&16)<<27)|((dst&15)<<27)|((dst&16)<<17)
def store(base,src):return 26|((base&15)<<22)|((base&16)<<27)|((src&15)<<27)|((src&16)<<17)
def addi(src,dst,imm):return 15|((src&15)<<22)|((src&16)<<27)|(dst<<17)|((imm&1023)<<6)

def fresh(library,image,top,label):
    p=oracle.image_pages(library,image);p.update(oracle.fresh_pages());back=top-0x118
    regs=[(0xD12A000000000000+i*0x102030405)&MASK for i in range(32)]
    regs[0]=0;regs[4]=G+0x5000;regs[5]=image+0x35E230;regs[6]=image+0x35E690
    regs[7]=image+0x28587C;regs[29]=(top-0x130)&~15;regs[31]=oracle.STOP
    regs[8]=0xFEDCBA9887654321;regs[9]=7
    programs={
        'arithmetic':[alu(44,10,0,9,8),alu(29,8,10,0,11),alu(58,9,11,12,0),addi(12,13,17)],
        'load_backing':[alu(44,10,0,9,8),load(14,11),addi(11,12,1)],
        'store_alias':[store(14,8),alu(44,10,0,9,8)],
        'external_write':[alu(44,10,0,9,8),alu(44,11,0,9,8)],
        'branch':[13|(2<<11),0],
        'conditional_no_write':[alu(32,0,15,8,9)],
        'hidden_product':[alu(53,0,8,9,0),alu(39,10,0,0,0)],
        'double':[34|(34&31)<<16|(34&32)<<1],
        'callback':[alu(50,0,30,7,0),alu(44,11,0,9,8)],
    }
    if label=='load_backing':regs[14]=back+10*8
    if label=='store_alias':regs[14]=back+9*8
    if label=='conditional_no_write':regs[15]=0
    if label=='callback':regs[4]=G+0x9000;regs[5]=back+8*8
    words=programs[label]+[EXIT]
    _write_span(p,back,b''.join(x.to_bytes(8,'little') for x in regs)+bytes.fromhex('314159265358979323846264338327950288419716939937'))
    _write_span(p,back-8,CODE.to_bytes(8,'little'))
    _write_span(p,DESC,regs[7].to_bytes(8,'little')+top.to_bytes(8,'little')+oracle.STOP.to_bytes(8,'little'))
    _write_span(p,CODE,b''.join(x.to_bytes(4,'little') for x in words))
    return p,regs,back,words

def compare(library,model,image,top,label,legacy=False):
    p,regs,back,words=fresh(library,image,top,label)
    register_pages=range((back-8)>>12,(back+0x117>>12)+1)
    observed={(page<<12,4096):None for page in register_pages}
    observed[G,0xA000]=None
    intervention=0x3141592653589793;events=[]
    def observe(cpu,address):
        if label=='external_write' and not events and int.from_bytes(cpu.mem_read(back-8,8),'little')==CODE+4:
            cpu.mem_write(back+64,intervention.to_bytes(8,'little'));events.append('external_write')
    def native_callback(cpu):
        assert cpu.reg_read(oracle.UC_ARM64_REG_X0)==back+64
        cpu.mem_write(back+64,intervention.to_bytes(8,'little'));events.append('callback');return 0
    _,_,alloc,services=oracle.native(library,image,0x168324,
        [CODE,regs[4],regs[5],regs[6],DESC],p,observed_memory=observed,
        instruction_observer=observe,host_imports={G+0x9000-image:native_callback} if label=='callback' else None,
        instruction_limit=100000)
    assert not alloc and not services
    expected_events=['external_write'] if label=='external_write' else ['callback'] if label=='callback' else []
    assert events==expected_events
    own={key:bytearray(value) for key,value in p.items()};m=object.__new__(model.Mem);m.pages=own
    previous=model.B;model.B=image
    try:
        vm=model.VM(m,CODE-image,regs[4],regs[5],regs[6],regs[7],oracle.STOP,maxsteps=len(words));vm.R=list(regs)
        if legacy:vm.register_backing_base=back
        else:vm.bind_registers(back)
        def step(v,word,op,sub):
            if label=='external_write' and v.pc==CODE+4:m.w64(back+64,intervention)
        vm.step_hook=step
        def callback(v,fn,arg):
            assert fn==G+0x9000 and arg==back+64;m.w64(back+64,intervention)
        vm.native_hook=callback
        try:vm.run()
        except model.VMExit:pass
        else:raise AssertionError('VM did not exit')
    finally:model.B=previous
    for (address,size),native in observed.items():
        actual=_read_span(own,address,size)
        if actual!=native:
            mismatch=next(i for i,(a,b) in enumerate(zip(actual,native)) if a!=b)
            raise AssertionError(f'{label}: live register/cursor page differs at {address+mismatch:#x}')
    assert list(vm.R)==[int.from_bytes(_read_span(own,back+i*8,8),'little') for i in range(32)]
    assert vm.pc==CODE+4*(len(words)-1)
    return dict(image_base=hex(image),case=label,cross_page_binding=(back>>12)!=((back+0x117)>>12),
        original_generic_VM_returned=True,complete_register_pages_and_payload_equal=True,
        live_memory_aliases_observed=True,code_cursor_equal=True,native_snapshot_input=False)

def guards(model):
    rows=[]
    for value in (None,True,-1,0,7,G+0x3001,1<<64,(1<<64)-8,G+0xFF80):
        m=object.__new__(model.Mem);m.pages=oracle.fresh_pages()
        vm=model.VM(m,0,0,0,0,0,0);before={k:bytes(v) for k,v in m.pages.items()};regs=vm.R
        try:vm.bind_registers(value)
        except ValueError:pass
        else:raise AssertionError(('invalid binding accepted',value))
        assert vm.R is regs and vm.register_backing_base is None and before=={k:bytes(v) for k,v in m.pages.items()}
        rows.append(dict(case=str(value),rejected_without_memory_or_register_change=True))
    for missing in ('cursor','registers','hidden'):
        m=object.__new__(model.Mem);m.pages=oracle.fresh_pages()
        back={'cursor':G+0x3000,'registers':G+0x3F80,'hidden':G+0x3F00}[missing]
        del m.pages[(back-8 if missing=='cursor' else back+0x80 if missing=='registers' else back+0x110)>>12]
        vm=model.VM(m,0,0,0,0,0,0);before={k:bytes(v) for k,v in m.pages.items()};regs=vm.R
        try:vm.bind_registers(back)
        except ValueError:pass
        else:raise AssertionError(('missing page accepted',missing))
        assert vm.R is regs and vm.register_backing_base is None and before=={k:bytes(v) for k,v in m.pages.items()}
        rows.append(dict(case='missing_'+missing,rejected_without_memory_or_register_change=True))
    m=object.__new__(model.Mem);m.pages=oracle.fresh_pages();back=G+0x3000
    vm=model.VM(m,0,0,0,0,0,0);before={k:bytes(v) for k,v in m.pages.items()};regs=vm.R
    try:vm.bind_registers(back)
    except ValueError as exc:assert 'cursor' in str(exc)
    else:raise AssertionError('mismatched entry cursor accepted')
    assert vm.R is regs and vm.register_backing_base is None and before=={k:bytes(v) for k,v in m.pages.items()}
    rows.append(dict(case='mismatched_cursor',rejected_without_memory_or_register_change=True))
    m.w64(back-8,vm.pc);before={k:bytes(v) for k,v in m.pages.items()};vm.bind_registers(back)
    assert before=={k:bytes(v) for k,v in m.pages.items()} and vm.R[:]==list(vm.R) and vm.R[-1]==vm.R[31]
    for index in (-33,32):
        for write in (False,True):
            try:
                if write:vm.R[index]=7
                else:vm.R[index]
            except IndexError:pass
            else:raise AssertionError('out of range register accepted')
            assert before=={k:bytes(v) for k,v in m.pages.items()}
            rows.append(dict(case=f'index_{index}_'+('write' if write else 'read'),rejected_without_memory_or_register_change=True))
    abstract=object.__new__(model.Mem);abstract.pages=oracle.fresh_pages()
    v=model.VM(abstract,0,0,0,0,0,0);v.register_backing_base=back;v.R[8]=123
    assert isinstance(v.R,list) and abstract.u64(back+64)==0xA5A5A5A5A5A5A5A5
    return rows

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True);ap.add_argument('--legacy-red',action='store_true');a=ap.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    os.environ['TOMATO_LIBMETASEC']=str(a.library.resolve());import vm_full
    labels=('arithmetic','load_backing','store_alias','external_write','branch','conditional_no_write','hidden_product','double','callback')
    cases=[compare(a.library,vm_full,image,G+top,label,a.legacy_red)
        for image in BASES for top in (0xC000,0xB080) for label in labels]
    negative=guards(vm_full)
    report=dict(library_sha256=oracle.LIBRARY_SHA256,native_runs=len(cases),cases=cases,negative_cases=negative,
        abstract_mode_retained=True,native_output_used_as_model_input=False,historical_native_groups_replayed=False,
        complete_physical_ABI_verified=False,whole_second_native_differential_verified=False,complete_signer_verified=False)
    a.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps(dict(native_runs=len(cases),refusal_guards=len(negative),live_register_pages_equal=True)),flush=True)
if __name__=='__main__':main()
