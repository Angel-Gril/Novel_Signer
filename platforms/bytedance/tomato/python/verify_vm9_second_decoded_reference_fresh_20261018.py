"""Fresh exact second-wrapper decoded references with real diagnostic scopes."""
from pathlib import Path
import argparse,base64,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
import verify_vm9_reference_scopes_fresh_20261011 as dependency
from verify_vm9_configuration_init import string_object
from vm9_allocator import _read_span,_write_span,RefillUnsupported
import vm9_request_287474_vm as second
import vm9_diagnostics as diagnostics

G=oracle.GUEST;SP=dependency.SP;TP=dependency.TP;BASES=(0x122C0000,0x775C205000)
PROFILES=('empty','one','two','three','binary','invalid','partial','whitespace','padding',
    'NULL_empty_payload','live_source_pointer','cross_packed','cross_output','cross_source','cross_payload')
GUARDS=('wrong_target','packed_wrap','packed_unmapped','output_NULL','output_unmapped','output_wrap',
    'source_NULL','source_unmapped','source_wrap','output_source_alias','output_packed_alias','source_packed_alias',
    'unaligned_stack','wrapped_stack','packed_spill','output_spill','source_spill','payload_spill',
    'payload_input_alias','unmapped_payload','source_bound','negative_length','invalid_bound',
    'missing_allocate','missing_free','invalid_allocation','allocation_spill','allocation_input_alias',
    'allocation_payload_alias','allocation_overlap','provider_failure','provider_changes_packed','free_failure')

def w(p,a,v,n=8):_write_span(p,a,(v&((1<<(n*8))-1)).to_bytes(n,'little'))
def u(p,a,n=8):return int.from_bytes(_read_span(p,a,n),'little')

def fixture(library,image,label):
    p=dependency.fresh(library,image)
    block=G+(0x1FF0 if label=='cross_packed' else 0x1000)
    out=G+(0x2FF8 if label=='cross_output' else 0x1100)
    source=G+(0x2FF8 if label=='cross_source' else 0x1800)
    payload=G+(0x2FFE if label=='cross_payload' else 0x2100)
    data={'empty':b'','NULL_empty_payload':b'','one':b'TQ==','two':b'TWE=',
        'binary':base64.b64encode(bytes(range(64))),'invalid':b'!','partial':b'TWE',
        'whitespace':b' TQ== \r\n','padding':b'=='}.get(label,b'TWFu')
    string_object(p,image,source,data,payload=payload)
    if label=='NULL_empty_payload':w(p,source+16,0)
    _write_span(p,G+0x2800,b'TQ==\0')
    _write_span(p,block,b''.join(v.to_bytes(8,'little') for v in (image+0x258E7C,out,source))+b'\x5A'*16)
    return p,block,out,source

def services(label,source):
    s=dependency.Services()
    if label=='live_source_pointer':
        def mutate(kind,index,read,write):
            if kind=='malloc' and index==0:write(source+16,(G+0x2800).to_bytes(8,'little'))
        s.effects.mutate=mutate
    return s

def invoke(p,s,image,block,changes=None):
    kw=dict(argument_block_address=block,entry_stack_address=SP,image_base=image,
        thread_pointer=TP,thread_id=137,allocate=s.malloc,free=s.free,diagnostic_observer=s.diagnostic)
    kw.update(changes or {})
    return second.apply_request_287474_decoded_reference_callback(p,**kw)

def compare(library,libc,image,label):
    p,block,out,source=fixture(library,image,label);packed=_read_span(p,block,40)
    expected=services(label,source);actual=services(label,source)
    watch={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000}
    watch.update({(G,SP-G-0x1000):None,(SP,G+0x10000-SP):None})
    native_scopes=[];model_scopes=[];steps=[0];minimum=[SP];seen=set()
    def observe(cpu,a):
        off=a-image;steps[0]+=1;minimum[0]=min(minimum[0],cpu.reg_read(arm.UC_ARM64_REG_SP));seen.add(off)
        if off in (0x347F00,0x347F10):expected.diagnostic('pthread_mutex_lock' if off==0x347F00 else 'pthread_mutex_unlock',cpu.reg_read(arm.UC_ARM64_REG_X0))
        if off==0x348310:expected.diagnostic('gettid',137)
        if off==0x26C9D0:
            a=cpu.reg_read(arm.UC_ARM64_REG_X0);raw=bytes(cpu.mem_read(a,24));native_scopes.append((a,raw[:12]+raw[16:]))
    _,_,allocations,_=oracle.native(library,image,0x288A4C,[block],p,libc=libc,
        real_diagnostics=True,real_singletons=True,real_mutexes=True,real_recursive_mutexes=True,
        thread_id=137,extra_registers={arm.UC_ARM64_REG_SP:SP,arm.UC_ARM64_REG_TPIDR_EL0:TP},
        malloc_handler=expected.native_malloc,host_imports={0x347FA0:expected.native_free},
        observed_memory=watch,instruction_observer=observe,instruction_limit=200000)
    leave=diagnostics.leave_diagnostic_scope
    def record(q,**kw):
        a=kw['object_address'];raw=_read_span(q,a,24);model_scopes.append((a,raw[:12]+raw[16:]));return leave(q,**kw)
    try:
        diagnostics.leave_diagnostic_scope=record;result=invoke(p,actual,image,block)
    finally:diagnostics.leave_diagnostic_scope=leave
    for (a,n),raw in watch.items():assert _read_span(p,a,n)==raw,(label,hex(a))
    assert actual.events==expected.events and actual.freed==expected.freed,label
    assert actual.effects.blocks==expected.effects.blocks and native_scopes==model_scopes,label
    assert result==out and _read_span(p,block,40)==packed and not allocations
    assert {0x288A4C,0x258E7C,0x1625A4}<=seen and SP-0x1000<=minimum[0]<SP
    print('PASS decoded reference',hex(image),label,steps[0],flush=True)
    return dict(image_base=hex(image),case=label,steps=steps[0],native_stack_bytes=SP-minimum[0],
        original_wrapper_and_decoded_reference_returned=True,declared_nonstack_memory_equal=True,
        ordered_effects_and_prefree_bytes_equal=True,scope_addresses_and_owned_fields_equal=True,
        packed_bytes_unchanged=True,scope_padding_compared=False,native_snapshot_input=False)

def guards(library):
    rows=[];image=BASES[0]
    for label in GUARDS:
        p,block,out,source=fixture(library,image,'three');s=services('three',source);changes={}
        if label=='wrong_target':w(p,block,image+1)
        elif label=='packed_wrap':block=(1<<64)-8
        elif label=='packed_unmapped':block=0x66000000
        elif label.startswith(('output_','source_')) and label.split('_')[-1] in ('NULL','unmapped','wrap'):
            offset=8 if label.startswith('output_') else 16
            w(p,block+offset,{'NULL':0,'unmapped':0x66000000,'wrap':(1<<64)-8}[label.split('_')[-1]])
        elif label=='output_source_alias':w(p,block+8,source)
        elif label=='output_packed_alias':w(p,block+8,block)
        elif label=='source_packed_alias':w(p,block+16,block)
        elif label=='unaligned_stack':changes['entry_stack_address']=SP-1
        elif label=='wrapped_stack':changes['entry_stack_address']=1<<64
        elif label=='packed_spill':_write_span(p,SP-24,_read_span(p,block,24));block=SP-24
        elif label in ('output_spill','source_spill'):w(p,block+(8 if label=='output_spill' else 16),SP-32)
        elif label=='payload_spill':w(p,source+16,SP-0x1000)
        elif label=='payload_input_alias':w(p,source+16,block)
        elif label=='unmapped_payload':w(p,source+16,0x66000000)
        elif label=='source_bound':changes['max_bytes']=3
        elif label=='negative_length':w(p,source+12,0xFFFFFFFF,4)
        elif label=='invalid_bound':changes['max_bytes']=True
        elif label=='missing_allocate':changes['allocate']=None
        elif label=='missing_free':changes['free']=None
        elif label=='invalid_allocation':changes['allocate']=lambda tx,n:-1
        elif label=='allocation_spill':changes['allocate']=lambda tx,n:SP-32
        elif label=='allocation_input_alias':changes['allocate']=lambda tx,n:source
        elif label=='allocation_payload_alias':changes['allocate']=lambda tx,n:G+0x2100
        elif label=='allocation_overlap':changes['allocate']=lambda tx,n:G+0x4000
        elif label=='provider_failure':
            def fail(tx,n):s.malloc(tx,n);raise RefillUnsupported('allocator failed after effect')
            changes['allocate']=fail
        elif label=='provider_changes_packed':
            def mutate(kind,index,read,write):write(block,bytes(8))
            s.effects.mutate=mutate
        elif label=='free_failure':
            def fail(tx,a):s.free(tx,a);raise RefillUnsupported('free failed after effect')
            changes['free']=fail
        before={k:bytes(v) for k,v in p.items()}
        try:invoke(p,s,image,block,changes)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError((label,'accepted'))
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
    return rows

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--library',type=Path,required=True);ap.add_argument('--libc',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==dependency.LIBC_SHA256
    rows=[compare(args.library,args.libc,image,label) for image in BASES for label in PROFILES]
    negative=guards(args.library)
    result=dict(component='Second decoded configuration reference wrapper',native_Python_controls=len(rows),
        rollback_guards=len(negative),cases=rows,negative_cases=negative,library_sha256=oracle.LIBRARY_SHA256,
        matching_libc_sha256=dependency.LIBC_SHA256,native_snapshot_input=False,synthetic_allocation_services=True,
        complete_signer_verified=False,physical_ABI_verified=False,external_effect_rollback_verified=False)
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS decoded reference',len(rows),'controls',len(negative),'guards',flush=True)
if __name__=='__main__':main()
