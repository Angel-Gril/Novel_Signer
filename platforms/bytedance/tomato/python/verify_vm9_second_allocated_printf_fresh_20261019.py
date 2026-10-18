"""Fresh exact second VM allocated printf wrapper and live input controls.

The original wrapper and guest formatter execute from independent fixtures.
Allocation is explicit synthetic input; historical native groups are not run.
"""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_reference_scopes_fresh_20261011 as dependency
import verify_vm9_signer_objects as oracle
import verify_vm9_request_alloc_format_fresh_20261013 as formatting
from vm9_allocator import _read_span,_write_span,RefillUnsupported
import vm9_request_287474_vm as second

G=oracle.GUEST;SP=dependency.SP;TP=dependency.TP
PACKED=G+0x2400;FMT=formatting.FMT;DATA=formatting.DATA
BASES=(0x122C0000,0x775C205000)
PROFILES=('length_0','length_1','length_32','length_128','empty_format','literal',
    'percent','decimal_min','unsigned_max','embedded_NUL','second_pass_longer',
    'second_pass_shorter','format_changes','NULL_malloc','output_source_alias',
    'output_cross_page','packed_cross_page','packed_result_alias','unsigned_long',
    'unsigned_long_long','signed_minus_one','escaped_literal','source_cross_page','format_cross_page')
GUARDS=('wrong_target','packed_wrap','packed_unmapped','packed_result_unmapped',
    'output_NULL','output_wrap','output_unmapped','format_NULL','format_wrap','format_unmapped',
    'argument_NULL','argument_unmapped','unsupported_conversion','missing_vararg','invalid_bound',
    'input_bound','second_pass_bound','missing_allocate','invalid_allocation','allocation_unmapped',
    'allocation_wrap','allocation_packed_alias','allocation_output_alias','allocation_format_alias',
    'allocation_source_alias','allocation_canary_alias','unaligned_stack','wrapped_stack',
    'packed_spill','output_spill','format_spill','source_spill','allocation_spill',
    'thread_wrap','thread_unmapped','output_TLS_alias','provider_changes_packed',
    'provider_failure','canary_change')

def w(p,a,v,n=8):_write_span(p,a,(v&((1<<(8*n))-1)).to_bytes(n,'little'))

def fixture(library,image,label):
    p,out,args=formatting.fixture(library,image,label);block=PACKED;fmt=FMT
    formats={'unsigned_max':(b'%u',0x12345678FFFFFFFF),
        'unsigned_long':(b'%lu',0xFEDCBA9876543210),
        'unsigned_long_long':(b'%llu',0xFFFFFFFFFFFFFFFF),
        'signed_minus_one':(b'%d',0x12345678FFFFFFFF),
        'escaped_literal':(b'%%s%%',0xDEADBEEF)}
    if label in formats:
        text,arg=formats[label];_write_span(p,fmt,text+b'\0');args=(arg,)
    if label=='packed_cross_page':block=G+0x6FF8
    if label=='packed_result_alias':out=block+32
    if label=='source_cross_page':
        args=(G+0x5FFE,);_write_span(p,args[0],b'cross-source\0')
    if label=='format_cross_page':fmt=G+0x5FFE;_write_span(p,fmt,b'%s\0')
    arg=args[0] if args else 0xDEADBEEF
    _write_span(p,block,b''.join(v.to_bytes(8,'little') for v in
        (image+0x278314,out,fmt,arg,0xA5A5A5A5A5A5A5A5))+b'\x5A'*8)
    return p,block

def invoke(p,s,image,block,changes=None):
    kw=dict(argument_block_address=block,image_base=image,entry_stack_address=SP,
        thread_pointer=TP,allocate=s.malloc);kw.update(changes or {})
    return second.apply_request_287474_allocated_printf_callback(p,**kw)

def compare(library,image,label):
    p,block=fixture(library,image,label);before=_read_span(p,block,48)
    expected=formatting.Services(label);actual=formatting.Services(label)
    watch={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000}
    watch[SP-0x58,8]=None
    steps=[0];minimum=[SP];seen=set();passes=[0]
    def observe(cpu,a):
        steps[0]+=1;minimum[0]=min(minimum[0],cpu.reg_read(arm.UC_ARM64_REG_SP))
        if a-image in (0x288AD4,0x278314):seen.add(a-image)
        if a-image==0x2772A4:passes[0]+=1
    returned,memory,allocations,_=oracle.native(library,image,0x288AD4,[block],p,
        malloc_handler=expected.native_malloc,extra_registers={arm.UC_ARM64_REG_TPIDR_EL0:TP,
            arm.UC_ARM64_REG_SP:SP},observed_memory=watch,instruction_observer=observe,instruction_limit=200000)
    result=invoke(p,actual,image,block)
    own=_read_span(p,G,0xA000)
    assert own==memory,(label,'guest',next(((hex(i),a,b) for i,(a,b) in enumerate(zip(own,memory)) if a!=b),None))
    assert all(_read_span(p,a,n)==raw for (a,n),raw in watch.items()),(label,'ELF/canary')
    assert result==returned&0xFFFFFFFF and actual.events==expected.events
    assert actual.effects.calls==expected.effects.calls and actual.effects.blocks==expected.effects.blocks
    assert seen=={0x288AD4,0x278314} and passes[0]==(1 if label=='NULL_malloc' else 2)
    assert _read_span(p,block,32)==before[:32] and _read_span(p,block+40,8)==before[40:]
    if label!='packed_result_alias':assert _read_span(p,block+36,4)==before[36:40]
    print('PASS second allocated printf',hex(image),label,steps[0],flush=True)
    return dict(image_base=hex(image),case=label,steps=steps[0],native_stack_bytes=SP-minimum[0],
        original_wrapper_and_allocated_printf_returned=True,
        uint32_return_guest_ELF_packed_and_defined_canary_equal=True,
        ordered_allocator_effects_and_live_format_passes_equal=True,
        original_guest_format_passes=passes[0],result_alias_publication_order_verified=label=='packed_result_alias',
        native_snapshot_input=False,physical_register_spills_compared=False)

def guards(library):
    rows=[];image=BASES[0]
    for label in GUARDS:
        p,block=fixture(library,image,'length_32');s=formatting.Services('length_32');changes={}
        if label=='wrong_target':w(p,block,image+1)
        elif label=='packed_wrap':block=(1<<64)-8
        elif label=='packed_unmapped':block=0x66000000
        elif label=='packed_result_unmapped':
            new=G+0xFFE0;_write_span(p,new,_read_span(p,block,32));block=new
        elif label.startswith(('output_','format_','argument_')) and label.split('_')[-1] in ('NULL','wrap','unmapped'):
            offset={'output':8,'format':16,'argument':24}[label.split('_')[0]]
            w(p,block+offset,{'NULL':0,'wrap':(1<<64)-1,'unmapped':0x66000000}[label.split('_')[-1]])
        elif label=='unsupported_conversion':_write_span(p,FMT,b'%x\0')
        elif label=='missing_vararg':_write_span(p,FMT,b'%s/%s\0')
        elif label=='invalid_bound':changes['max_bytes']=True
        elif label=='input_bound':changes['max_bytes']=8
        elif label=='second_pass_bound':s=formatting.Services('second_pass_longer');changes['max_bytes']=16;_write_span(p,DATA,b'ab\0')
        elif label=='missing_allocate':changes['allocate']=None
        elif label.startswith('allocation_'):
            address={'invalid_allocation':-1,'allocation_unmapped':0x66000000,
                'allocation_wrap':(1<<64)-1,'allocation_packed_alias':block,
                'allocation_output_alias':formatting.OUT,'allocation_format_alias':FMT,
                'allocation_source_alias':DATA,'allocation_canary_alias':TP+0x28,
                'allocation_spill':SP-32}[label]
            changes['allocate']=lambda tx,n,a=address:a
        elif label=='invalid_allocation':changes['allocate']=lambda tx,n:True
        elif label=='unaligned_stack':changes['entry_stack_address']=SP-1
        elif label=='wrapped_stack':changes['entry_stack_address']=1<<64
        elif label=='packed_spill':_write_span(p,SP-48,_read_span(p,block,40));block=SP-48
        elif label in ('output_spill','format_spill','source_spill'):
            w(p,block+{'output_spill':8,'format_spill':16,'source_spill':24}[label],SP-32)
        elif label=='thread_wrap':changes['thread_pointer']=(1<<64)-8
        elif label=='thread_unmapped':changes['thread_pointer']=0x66000000
        elif label=='output_TLS_alias':w(p,block+8,TP+0x28)
        elif label in ('provider_changes_packed','provider_failure','canary_change'):
            def change(tx,n,case=label):
                result=s.malloc(tx,n)
                if case=='provider_changes_packed':w(tx,block,0)
                elif case=='canary_change':w(tx,TP+0x28,7)
                else:raise RefillUnsupported('allocator failed after effect')
                return result
            changes['allocate']=change
        before={k:bytes(v) for k,v in p.items()}
        try:invoke(p,s,image,block,changes)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError((label,'accepted'))
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
    return rows

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args();assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    rows=[compare(args.library,b,c) for b in BASES for c in PROFILES];negative=guards(args.library)
    result=dict(component='Second allocated printf wrapper',native_Python_controls=len(rows),
        rollback_guards=len(negative),cases=rows,negative_cases=negative,library_sha256=oracle.LIBRARY_SHA256,
        native_snapshot_input=False,synthetic_allocation_services=True,complete_signer_verified=False,
        physical_ABI_verified=False,external_effect_rollback_verified=False)
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS second allocated printf',len(rows),'controls',len(negative),'guards',flush=True)
if __name__=='__main__':main()
