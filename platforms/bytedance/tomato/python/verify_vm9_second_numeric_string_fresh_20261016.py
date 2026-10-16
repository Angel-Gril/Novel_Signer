"""Original numeric string callback versus independently constructed pages.

Component allocation/free and TLS services are explicit synthetic boundaries.
The separate owning call uses original allocation and matching libc TLS.
"""
from pathlib import Path
import argparse, hashlib, json
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
from verify_vm9_reference_scopes_fresh_20261011 import Services
from vm9_allocator import _read_span, _write_span, RefillUnsupported
import vm9_request_287474_vm as second

G=oracle.GUEST; SP=G+0xEF00; BASES=(0x122C0000,0x775C205000)
PROFILES=('zero','length22','length23','length31','length32','all_bits','high_bits',
    'digit_edges','large_edges','cross_output','cross_packed','junk_output',
    'allocation_changes_global','TLS_changes_global','shrink_source_mutation')
GUARDS=('wrong_target','unaligned_stack','zero_stack','wrapped_stack','wrapped_packed',
    'wrapped_image','unmapped_output','unmapped_globals','missing_allocate','missing_free',
    'missing_TLS','NULL_allocation','bool_allocation','unmapped_allocation','allocation_spill',
    'allocation_output_alias','allocation_packed_alias','allocation_globals_alias',
    'allocation_control_alias','allocation_reuse','allocate_failure','free_failure',
    'TLS_failure','NULL_TLS','bool_TLS','unmapped_TLS','TLS_spill','TLS_output_alias',
    'packed_spill','output_spill','globals_spill','output_packed_alias',
    'output_globals_alias','provider_changes_object')


def w(p,a,v,n=8):_write_span(p,a,v.to_bytes(n,'little'))
def fresh(library,image,label):
    p=oracle.fresh_pages();p.update(oracle.image_pages(library,image))
    block=G+(0x1FF0 if label=='cross_packed' else 0x1000)
    output=G+(0x2FF8 if label=='cross_output' else 0x1800)
    values=[0]*9; tls=0
    if label=='length22':tls=1000
    elif label=='length23':tls=10000
    elif label in ('length31','length32'):
        values[0]=1000000000;tls=1000 if label=='length31' else 10000
    elif label=='all_bits':values=[0xFFFFFFFF]*9;tls=0xFFFFFFFF
    elif label=='high_bits':values=[0x80000000,0x7FFFFFFF,0xFFFFFFFF]*3;tls=0x80000000
    elif label=='digit_edges':values=[0,9,10,99,100,999,1000,9999,10000];tls=99999
    elif label=='large_edges':values=[99999,100000,999999,1000000,9999999,10000000,99999999,100000000,999999999];tls=1000000000
    elif label in ('shrink_source_mutation','allocation_changes_global','TLS_changes_global'):values[0]=0xFFFFFFFF
    _write_span(p,image+0x3D1988,b''.join(v.to_bytes(4,'little') for v in values))
    _write_span(p,output,b'\xA5'*24)
    _write_span(p,block,b''.join(v.to_bytes(8,'little') for v in (image+0x28794C,output,0x66000000))+b'\x5A'*16)
    w(p,G+0x3500,tls,4)
    return p,block,output


def services(label,image):
    s=Services()
    def mutate(kind,index,read,write):
        if kind=='malloc' and index==0 and label=='allocation_changes_global':
            write(image+0x3D1988+16,(0xFFFFFFFF).to_bytes(4,'little'))
        if kind=='malloc' and index==1 and label=='shrink_source_mutation':write(G+0x4000,b'X')
    s.effects.mutate=mutate
    def get_tls(p,control):
        assert control==image+0x382920;s.events.append(['TLS',control])
        if label=='TLS_changes_global':w(p,image+0x3D1988,123,4)
        return G+0x3500
    def native_tls(cpu):
        control=cpu.reg_read(arm.UC_ARM64_REG_X0)
        assert control==image+0x382920;s.events.append(['TLS',control])
        if label=='TLS_changes_global':cpu.mem_write(image+0x3D1988,(123).to_bytes(4,'little'))
        return G+0x3500
    return s,get_tls,native_tls


def original(library,image,p,block,s,native_tls):
    steps=[0];seen=set();observed={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000}
    def observe(cpu,a):
        steps[0]+=1
        if a-image in (0x2888F4,0x28794C,0x32BF14,0x287A38,0x32B16C,0x2254F0,0x32AA70,0x2850A8,0x287A70,0x32AD4C):seen.add(a-image)
    _,memory,allocations,ledger=oracle.native(library,image,0x2888F4,[block],p,
        malloc_handler=s.native_malloc,host_imports={0x347FA0:s.native_free,0x34377C:native_tls},
        instruction_observer=observe,observed_memory=observed,instruction_limit=50000)
    assert seen=={0x2888F4,0x28794C,0x32BF14,0x287A38,0x32B16C,0x2254F0,0x32AA70,0x2850A8,0x287A70,0x32AD4C}
    assert not allocations and not ledger
    return memory,observed,steps[0]


def apply(p,image,block,s,get_tls,**kw):
    callback=getattr(second,'apply_request_287474_numeric_string_callback',None)
    assert callable(callback),'native constructs a numeric string, but the second VM callback is missing'
    return callback(p,argument_block_address=block,entry_stack_address=SP,image_base=image,
        allocate=s.malloc,free=s.free,get_tls=get_tls,**kw)


def compare(library,image,label):
    p,block,output=fresh(library,image,label);packed=_read_span(p,block,40)
    expected,_,native_tls=services(label,image);actual,get_tls,_=services(label,image)
    memory,observed,steps=original(library,image,p,block,expected,native_tls)
    result=apply(p,image,block,actual,get_tls)
    ours=_read_span(p,G,0xA000)
    assert ours==memory,(label,'guest',next((hex(i) for i,(a,b) in enumerate(zip(ours,memory)) if a!=b),None))
    assert all(_read_span(p,a,n)==data for (a,n),data in observed.items()),(label,'image')
    assert actual.events==expected.events and actual.freed==expected.freed,(label,'effects',actual.events,expected.events)
    assert actual.effects.calls==expected.effects.calls and actual.effects.blocks==expected.effects.blocks
    assert result==output and _read_span(p,block,40)==packed
    first=_read_span(p,output,1)[0]
    length=int.from_bytes(_read_span(p,output+8,8),'little') if first&1 else first>>1
    pointer=int.from_bytes(_read_span(p,output+16,8),'little') if first&1 else output+1
    assert _read_span(p,pointer+length,1)==b'\0'
    if label=='all_bits':assert _read_span(p,pointer,length)==b'4294967295|'*9+b'4294967295'
    print('PASS numeric string',hex(image),label,flush=True)
    return dict(image_base=hex(image),case=label,steps=steps,output_length=length,long_string=bool(first&1),
        original_numeric_wrapper_reserve_decimal_append_move_cleanup_shrink_returned=True,
        all_guest_and_image_bytes_equal=True,ordered_TLS_allocation_free_and_prefree_bytes_equal=True,
        packed_bytes_preserved=True,receiver_unmapped=True,native_snapshot_input=False,
        synthetic_allocator_and_TLS_services=True,complete_physical_ABI_verified=False)


def guards(library):
    rows=[];image=BASES[0]
    for label in GUARDS:
        p,block,output=fresh(library,image,'length23');s,get_tls,_=services('zero',image)
        kw=dict(argument_block_address=block,entry_stack_address=SP,image_base=image,
            allocate=s.malloc,free=s.free,get_tls=get_tls)
        if label=='wrong_target':w(p,block,image+0x28794D)
        elif label=='unaligned_stack':kw['entry_stack_address']-=1
        elif label=='zero_stack':kw['entry_stack_address']=0
        elif label=='wrapped_stack':kw['entry_stack_address']=1<<64
        elif label=='wrapped_packed':kw['argument_block_address']=(1<<64)-23
        elif label=='wrapped_image':kw['image_base']=(1<<64)-0x3D19AB
        elif label=='unmapped_output':w(p,block+8,0x66000000)
        elif label=='unmapped_globals':del p[(image+0x3D1988)>>12]
        elif label.startswith('missing_'):kw[{'missing_allocate':'allocate','missing_free':'free','missing_TLS':'get_tls'}[label]]=None
        elif label in ('NULL_allocation','bool_allocation','unmapped_allocation','allocation_spill','allocation_output_alias','allocation_packed_alias','allocation_globals_alias','allocation_control_alias'):
            kw['allocate']=lambda tx,n:{'NULL_allocation':0,'bool_allocation':True,'unmapped_allocation':0x66000000,
                'allocation_spill':SP-0x100,'allocation_output_alias':output,'allocation_packed_alias':block,
                'allocation_globals_alias':image+0x3D1988,'allocation_control_alias':image+0x382920}[label]
        elif label=='allocation_reuse':kw['allocate']=lambda tx,n:G+0x4000
        elif label in ('allocate_failure','free_failure','TLS_failure'):
            def fail(tx,*args):
                _write_span(tx,G+0x5000,b'rollback');raise RefillUnsupported('explicit provider failure')
            kw[{'allocate_failure':'allocate','free_failure':'free','TLS_failure':'get_tls'}[label]]=fail
        elif label in ('NULL_TLS','bool_TLS','unmapped_TLS','TLS_spill','TLS_output_alias'):
            kw['get_tls']=lambda tx,c:{'NULL_TLS':0,'bool_TLS':True,'unmapped_TLS':0x66000000,'TLS_spill':SP-8,'TLS_output_alias':output}[label]
        elif label=='packed_spill':
            kw['argument_block_address']=SP-32;_write_span(p,SP-32,_read_span(p,block,24))
        elif label=='output_spill':w(p,block+8,SP-32)
        elif label=='globals_spill':kw['entry_stack_address']=(image+0x3D1988+0x100)&~15
        elif label=='output_packed_alias':w(p,block+8,block)
        elif label=='output_globals_alias':w(p,block+8,image+0x3D1988)
        elif label=='provider_changes_object':
            def mutate(kind,index,read,write):
                if kind=='malloc':write(output,b'X')
            s.effects.mutate=mutate
        before={k:bytes(v) for k,v in p.items()}
        try:second.apply_request_287474_numeric_string_callback(p,**kw)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError('numeric string guard accepted '+label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_model_pages_unchanged=True,
            external_provider_effect_rollback_verified=False))
    return rows


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True);ap.add_argument('--mode',choices=('native','guards','red'),default='native')
    args=ap.parse_args();assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    e=dict(cases=[],negative_cases=[])
    if args.mode=='guards':e['negative_cases']=guards(args.library)
    else:
        for image in BASES:
            for label in (('all_bits',) if args.mode=='red' else PROFILES):
                e['cases'].append(compare(args.library,image,label))
                args.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
    args.output.write_text(json.dumps(dict(e,component='Second request numeric string',native_Python_controls=len(e['cases']),
        rollback_guards=len(e['negative_cases']),native_input_snapshot_used=False,whole_second_native_differential_verified=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8',newline='\n')


if __name__=='__main__':main()
