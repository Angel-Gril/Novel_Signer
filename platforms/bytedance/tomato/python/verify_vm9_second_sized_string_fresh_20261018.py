"""Fresh explicit-length strings through the exact second VM tail wrapper."""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
from verify_vm9_reference_scopes_fresh_20261011 import Services
from vm9_allocator import _read_span,_write_span,RefillUnsupported
import vm9_request_287474_vm as second

G=oracle.GUEST;SP=G+0xEF00;BASES=(0x122C0000,0x775C205000)
PROFILES=('empty','short','embedded_NUL','binary','long','negative_min','negative_max',
    'negative_unmapped_source','NULL_empty_source','malloc_NULL','malloc_NULL_unmapped_source',
    'live_source_bytes','cross_packed','cross_output','cross_source','cross_allocation')
GUARDS=('wrong_target','packed_wrap','packed_unmapped','output_NULL','output_unmapped','output_wrap',
    'source_NULL','source_wrap','source_unmapped','output_packed_alias','source_packed_alias','source_output_alias',
    'unaligned_stack','wrapped_stack','packed_spill','output_spill','source_spill',
    'source_bound','invalid_bound','missing_allocate','invalid_allocation','allocation_wrap',
    'allocation_spill','allocation_input_alias','allocation_source_alias','unmapped_allocation',
    'provider_failure','provider_changes_packed')


def w(p,a,v,n=8):_write_span(p,a,(v&((1<<(n*8))-1)).to_bytes(n,'little'))


def fixture(library,image,label):
    p=oracle.fresh_pages();p.update(oracle.image_pages(library,image))
    block=G+(0x1FF0 if label=='cross_packed' else 0x1000)
    out=G+(0x2FF8 if label=='cross_output' else 0x1100)
    source=G+(0x2FFE if label=='cross_source' else 0x2100)
    data={'empty':b'','NULL_empty_source':b'','embedded_NUL':b'a\0b\0c',
        'binary':bytes(range(256)),'long':b'x'*129,'cross_allocation':b'y'*129}.get(label,b'copy')
    _write_span(p,source,data);length=len(data)
    if label.startswith('negative'):length=0xFFFFFFFF if label=='negative_max' else 0x80000000
    if label in ('empty','negative_unmapped_source','malloc_NULL_unmapped_source'):source=0x66000000
    if label=='NULL_empty_source':source=0
    _write_span(p,block,b''.join(v.to_bytes(8,'little') for v in (image+0x2481FC,out,source))+
        length.to_bytes(4,'little')+b'\x5A'*12)
    return p,block,out,source


def services(label,source):
    s=Services(failures=(0,) if label.startswith('malloc_NULL') else ())
    if label=='cross_allocation':s.effects.next=G+0x4FF8
    if label=='live_source_bytes':
        def mutate(kind,index,read,write):
            if kind=='malloc' and index==0:write(source,b'next')
        s.effects.mutate=mutate
    return s


def invoke(p,s,image,block,changes=None):
    kw=dict(argument_block_address=block,entry_stack_address=SP,image_base=image,allocate=s.malloc)
    kw.update(changes or {})
    return second.apply_request_287474_sized_string_callback(p,**kw)


def compare(library,image,label):
    p,block,out,source=fixture(library,image,label);packed=_read_span(p,block,40)
    expected=services(label,source);actual=services(label,source)
    watch={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000}
    watch.update({(G,SP-G-0x1000):None,(SP,G+0x10000-SP):None})
    steps=[0];minimum=[SP];seen=set()
    def observe(cpu,a):
        steps[0]+=1;minimum[0]=min(minimum[0],cpu.reg_read(arm.UC_ARM64_REG_SP));seen.add(a-image)
    _,_,allocations,_=oracle.native(library,image,0x288A74,[block],p,
        extra_registers={arm.UC_ARM64_REG_SP:SP},malloc_handler=expected.native_malloc,
        observed_memory=watch,instruction_observer=observe,instruction_limit=10000)
    result=invoke(p,actual,image,block)
    for (a,n),raw in watch.items():assert _read_span(p,a,n)==raw,(label,hex(a))
    assert actual.events==expected.events and actual.effects.blocks==expected.effects.blocks,label
    assert result==out and _read_span(p,block,40)==packed and not allocations
    assert {0x288A74,0x2481FC}<=seen and SP-0x1000<=minimum[0]<SP
    print('PASS sized string',hex(image),label,steps[0],flush=True)
    return dict(image_base=hex(image),case=label,steps=steps[0],native_stack_bytes=SP-minimum[0],
        original_wrapper_and_sized_string_returned=True,declared_nonstack_memory_equal=True,
        ordered_allocation_effects_equal=True,packed_bytes_unchanged=True,native_snapshot_input=False,
        native_physical_X0_compared=False,complete_physical_ABI_verified=False)


def guards(library):
    rows=[];image=BASES[0]
    for label in GUARDS:
        p,block,out,source=fixture(library,image,'short');s=services('short',source);changes={}
        if label=='wrong_target':w(p,block,image+1)
        elif label=='packed_wrap':block=(1<<64)-8
        elif label=='packed_unmapped':block=0x66000000
        elif label.startswith(('output_','source_')) and label.split('_')[-1] in ('NULL','unmapped','wrap'):
            w(p,block+(8 if label.startswith('output_') else 16),{'NULL':0,'unmapped':0x66000000,'wrap':(1<<64)-2}[label.split('_')[-1]])
        elif label=='output_packed_alias':w(p,block+8,block)
        elif label=='source_packed_alias':w(p,block+16,block)
        elif label=='source_output_alias':w(p,block+16,out)
        elif label=='unaligned_stack':changes['entry_stack_address']=SP-1
        elif label=='wrapped_stack':changes['entry_stack_address']=1<<64
        elif label=='packed_spill':_write_span(p,SP-28,_read_span(p,block,28));block=SP-28
        elif label=='output_spill':w(p,block+8,SP-32)
        elif label=='source_spill':w(p,block+16,SP-0x1000)
        elif label=='source_bound':changes['max_bytes']=3
        elif label=='invalid_bound':changes['max_bytes']=True
        elif label=='missing_allocate':changes['allocate']=None
        elif label=='invalid_allocation':changes['allocate']=lambda tx,n:-1
        elif label=='allocation_wrap':changes['allocate']=lambda tx,n:(1<<64)-2
        elif label=='allocation_spill':changes['allocate']=lambda tx,n:SP-32
        elif label=='allocation_input_alias':changes['allocate']=lambda tx,n:out
        elif label=='allocation_source_alias':changes['allocate']=lambda tx,n:source
        elif label=='unmapped_allocation':changes['allocate']=lambda tx,n:0x66000000
        elif label=='provider_failure':
            def fail(tx,n):s.malloc(tx,n);raise RefillUnsupported('allocator failed after effect')
            changes['allocate']=fail
        elif label=='provider_changes_packed':
            def mutate(kind,index,read,write):write(block+24,bytes(4))
            s.effects.mutate=mutate
        before={k:bytes(v) for k,v in p.items()}
        try:invoke(p,s,image,block,changes)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError((label,'accepted'))
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
    return rows


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    rows=[compare(args.library,image,label) for image in BASES for label in PROFILES];negative=guards(args.library)
    result=dict(component='Second explicit-length string wrapper',native_Python_controls=len(rows),rollback_guards=len(negative),
        cases=rows,negative_cases=negative,library_sha256=oracle.LIBRARY_SHA256,native_snapshot_input=False,
        synthetic_allocation_services=True,complete_signer_verified=False,physical_ABI_verified=False,
        external_effect_rollback_verified=False)
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS sized string',len(rows),'controls',len(negative),'guards',flush=True)


if __name__=='__main__':main()
